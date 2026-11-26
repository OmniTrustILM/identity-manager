//! Certificates in the personal store of the current user. The certificate is tied to its CNG key by the key
//! provider information property, which makes the identity. Intermediates go to the intermediate store of the
//! user; no trust is changed and nothing is added to a root store.

use std::ptr::null_mut;

use im_core::identity::Fingerprint;
use im_core::install::{CertificateInstaller, InstallError};
use im_core::keys::{KeyId, Storage};
use windows::Win32::Foundation::{
    CRYPT_E_NOT_FOUND, ERROR_NO_MORE_FILES, NTE_BAD_KEYSET, NTE_BAD_PUBLIC_KEY,
};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_EXISTING, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC,
    CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_ADD_USE_EXISTING,
    CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
    CRYPT_ACQUIRE_COMPARE_KEY_FLAG, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, CRYPT_ACQUIRE_SILENT_FLAG,
    CRYPT_KEY_FLAGS, CRYPT_KEY_PROV_INFO, CRYPT_MACHINE_KEYSET, CertAddEncodedCertificateToStore,
    CertCloseStore, CertComparePublicKeyInfo, CertCreateCertificateContext,
    CertDeleteCertificateFromStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore,
    CertFindCertificateInStore, CertFreeCertificateContext, CertGetCertificateContextProperty,
    CertOpenStore, CertSetCertificateContextProperty, CryptAcquireCertificatePrivateKey,
    HCERTSTORE, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCryptDeleteKey,
    NCryptFreeObject, X509_ASN_ENCODING,
};
use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR, w};

/// The personal and intermediate stores of the current user.
pub struct PersonalStore;

impl CertificateInstaller for PersonalStore {
    fn install(
        &self,
        key: &KeyId,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        let personal = Store::open(w!("MY"))?;
        let context = personal.add(leaf, CERT_STORE_ADD_REPLACE_EXISTING)?;
        let container: Vec<u16> = key.name.encode_utf16().chain([0]).collect();
        let info = CRYPT_KEY_PROV_INFO {
            pwszContainerName: PWSTR(container.as_ptr().cast_mut()),
            pwszProvName: PWSTR(provider_name(key.storage).0.cast_mut()),
            dwProvType: 0,
            dwFlags: CRYPT_KEY_FLAGS(0),
            cProvParam: 0,
            rgProvParam: null_mut(),
            dwKeySpec: 0,
        };
        context.pair(&info)?;
        drop(context);
        add_intermediates(intermediates)?;
        verify(&personal, leaf)?;
        log::info!("certificate installed: {:?}", key.storage);
        Ok(())
    }

    fn install_beside(
        &self,
        old: &Fingerprint,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        let personal = Store::open(w!("MY"))?;
        let info = personal
            .by_fingerprint(old)?
            .ok_or_else(|| failed_with("install beside", "the old certificate is not installed"))?
            .key_info()?
            .ok_or_else(|| failed_with("install beside", "the old certificate has no key"))?;
        let context = personal.add(leaf, CERT_STORE_ADD_REPLACE_EXISTING)?;
        context.pair(info.get())?;
        drop(context);
        add_intermediates(intermediates)?;
        verify(&personal, leaf)?;
        log::info!(
            "certificate installed beside: {}",
            info.provider().unwrap_or_default()
        );
        Ok(())
    }

    fn remove(&self, fingerprint: &Fingerprint, delete_key: bool) -> Result<(), InstallError> {
        let personal = Store::open(w!("MY"))?;
        let certificates = personal.certificates()?;
        let Some(target) = certificates
            .iter()
            .find(|context| Fingerprint::of(context.der()) == *fingerprint)
        else {
            return Ok(());
        };
        let key_deleted = delete_key && delete_own_key(target, &certificates, fingerprint)?;
        target.duplicate().delete()?;
        if personal.by_fingerprint(fingerprint)?.is_some() {
            return Err(failed_with(
                "verify",
                "the store still holds the certificate",
            ));
        }
        log::info!(
            "certificate removed: personal store, {}",
            if key_deleted {
                "key deleted"
            } else {
                "key kept"
            }
        );
        Ok(())
    }
}

/// Adds the intermediates to the intermediate store of the user.
fn add_intermediates(intermediates: &[Vec<u8>]) -> Result<(), InstallError> {
    if intermediates.is_empty() {
        return Ok(());
    }
    let authorities = Store::open(w!("CA"))?;
    for intermediate in intermediates {
        authorities.add(intermediate, CERT_STORE_ADD_USE_EXISTING)?;
    }
    Ok(())
}

/// Whether the personal store holds the certificate and its key can be reached.
fn verify(personal: &Store, leaf: &[u8]) -> Result<(), InstallError> {
    personal
        .find(leaf)?
        .ok_or_else(|| failed_with("verify", "the store does not hold the certificate"))?
        .reach_key()
}

/// Deletes the key of `target` when it is a key of the current user in the software or platform provider and no
/// other certificate of the store is for the same public key or names the same container; whether it was deleted. A
/// certificate whose key information cannot be read keeps every key, as it may name this one. A smart card key is
/// never deleted.
fn delete_own_key(
    target: &Context,
    certificates: &[Context],
    fingerprint: &Fingerprint,
) -> Result<bool, InstallError> {
    let Some(info) = target.key_info()? else {
        return Ok(false);
    };
    let (Some(provider), Some(container)) = (info.provider(), info.container()) else {
        log::info!("certificate removal keeps the key: its provider or container is not named");
        return Ok(false);
    };
    if !deletable(&provider, info.get().dwFlags) {
        log::info!("certificate removal keeps the key: it is a machine key or in {provider}");
        return Ok(false);
    }
    let shared = certificates.iter().any(|other| {
        Fingerprint::of(other.der()) != *fingerprint
            && (other.same_public_key(target)
                || match other.key_info() {
                    Ok(Some(other)) => match (other.provider(), other.container()) {
                        (Some(other_provider), Some(other_container)) => {
                            other_provider.eq_ignore_ascii_case(&provider)
                                && other_container.eq_ignore_ascii_case(&container)
                        }
                        _ => true,
                    },
                    Ok(None) => false,
                    Err(_) => true,
                })
    });
    if shared {
        log::info!("certificate removal keeps the key: another certificate may use it");
        return Ok(false);
    }
    delete_key(target)
}

/// Whether a key of this provider and these flags is one the application deletes: a key of the current user in the
/// software or the platform provider.
fn deletable(provider: &str, flags: CRYPT_KEY_FLAGS) -> bool {
    !flags.contains(CRYPT_MACHINE_KEYSET)
        && [MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER]
            .iter()
            // SAFETY: the provider names are NUL-terminated static wide strings.
            .filter_map(|name| unsafe { name.to_string() }.ok())
            .any(|name| name.eq_ignore_ascii_case(provider))
}

/// Deletes the key of the certificate through the handle the certificate opens, which the system checks against
/// the certificate's public key; whether it was deleted. A key that is not there is deleted already; a container that
/// holds another key, or a handle the system keeps, keeps the key.
fn delete_key(target: &Context) -> Result<bool, InstallError> {
    let key = match target.acquire_key() {
        Ok(Some(key)) => key,
        Ok(None) => {
            log::info!("certificate removal keeps the key: the system holds its handle");
            return Ok(false);
        }
        Err(error) if error.code() == NTE_BAD_KEYSET => return Ok(true),
        Err(error) if error.code() == NTE_BAD_PUBLIC_KEY => {
            log::info!("certificate removal keeps the key: it is not the certificate's");
            return Ok(false);
        }
        Err(error) => return Err(failed("open key", &error)),
    };
    let handle = NCRYPT_KEY_HANDLE(key.0.0);
    std::mem::forget(key);
    // SAFETY: the key is open and owned here; on success the call frees its handle, which is not used again.
    if let Err(error) = unsafe { NCryptDeleteKey(handle, 0) } {
        drop(Handle(NCRYPT_HANDLE(handle.0)));
        return Err(failed("delete key", &error));
    }
    Ok(true)
}

/// An open CNG object, freed when dropped.
struct Handle(NCRYPT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle belongs to this guard, whose `drop` runs once.
        if let Err(error) = unsafe { NCryptFreeObject(self.0) } {
            log::warn!(
                "key handle not freed: Windows error {:#010x}",
                error.code().0
            );
        }
    }
}

/// The key provider information of a certificate, as the store keeps it: the structure followed by the strings
/// it points at.
struct KeyInfo(Vec<u64>);

impl KeyInfo {
    fn get(&self) -> &CRYPT_KEY_PROV_INFO {
        // SAFETY: the buffer holds the property the store wrote, which starts with the structure; `u64` elements
        // align it.
        unsafe { &*self.0.as_ptr().cast::<CRYPT_KEY_PROV_INFO>() }
    }

    /// The provider name; none when it is not set (the default provider) or cannot be read.
    fn provider(&self) -> Option<String> {
        name(self.get().pwszProvName)
    }

    /// The container name; none when it is not set or cannot be read.
    fn container(&self) -> Option<String> {
        name(self.get().pwszContainerName)
    }
}

/// A name of the key provider information; none when it is null or not valid UTF-16.
fn name(name: PWSTR) -> Option<String> {
    if name.is_null() {
        return None;
    }
    // SAFETY: the store wrote the name, when set, as a NUL-terminated wide string inside the buffer.
    unsafe { name.to_string() }.ok()
}

fn provider_name(storage: Storage) -> PCWSTR {
    match storage {
        Storage::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
        _ => MS_KEY_STORAGE_PROVIDER,
    }
}

/// An open system store of the current user, closed when dropped.
struct Store(HCERTSTORE);

impl Store {
    fn open(name: PCWSTR) -> Result<Self, InstallError> {
        // SAFETY: the provider is the system store provider, which takes the store name as a NUL-terminated wide
        // string that outlives the call.
        unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                Default::default(),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER)
                    | CERT_STORE_ENUM_ARCHIVED_FLAG,
                Some(name.0.cast()),
            )
        }
        .map(Self)
        .map_err(|error| failed("open", &error))
    }

    /// Adds the certificate with the disposition for one that is already there, and returns the stored one.
    fn add(&self, der: &[u8], disposition: u32) -> Result<Context, InstallError> {
        let mut stored: *mut CERT_CONTEXT = null_mut();
        // SAFETY: the store is open; `der` is a live slice that the call copies; the context is written on
        // success.
        unsafe {
            CertAddEncodedCertificateToStore(
                Some(self.0),
                X509_ASN_ENCODING,
                der,
                disposition,
                Some(&mut stored),
            )
        }
        .map_err(|error| failed("add", &error))?;
        Ok(Context(stored))
    }

    /// The certificates of the store, archived ones included.
    fn certificates(&self) -> Result<Vec<Context>, InstallError> {
        let mut found = Vec::new();
        let mut previous: *const CERT_CONTEXT = null_mut();
        loop {
            // SAFETY: the store is open; `previous` is null or the context the last call returned, which this call
            // frees.
            let next = unsafe { CertEnumCertificatesInStore(self.0, Some(previous)) };
            if next.is_null() {
                let error = windows::core::Error::from_thread();
                let code = error.code();
                if code == CRYPT_E_NOT_FOUND || code == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) {
                    return Ok(found);
                }
                return Err(failed("list", &error));
            }
            // SAFETY: `next` is a live context of the store; the copy is freed by its guard.
            found.push(Context(unsafe {
                CertDuplicateCertificateContext(Some(next))
            }));
            previous = next;
        }
    }

    /// The certificate of the store with this fingerprint, if there is one.
    fn by_fingerprint(&self, fingerprint: &Fingerprint) -> Result<Option<Context>, InstallError> {
        Ok(self
            .certificates()?
            .into_iter()
            .find(|context| Fingerprint::of(context.der()) == *fingerprint))
    }

    /// The certificate of the store that is `der`, if there is one.
    fn find(&self, der: &[u8]) -> Result<Option<Context>, InstallError> {
        let wanted = Context::create(der)?;
        // SAFETY: the store is open; `wanted.0` is a live certificate context, which is what an existing-certificate
        // search takes.
        let found = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_EXISTING,
                Some(wanted.0.cast()),
                None,
            )
        };
        if !found.is_null() {
            return Ok(Some(Context(found)));
        }
        let error = windows::core::Error::from_thread();
        if error.code() == CRYPT_E_NOT_FOUND {
            Ok(None)
        } else {
            Err(failed("find", &error))
        }
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the store belongs to this guard, whose `drop` runs once.
        if let Err(error) = unsafe { CertCloseStore(Some(self.0), 0) } {
            log::warn!(
                "certificate store not closed: Windows error {:#010x}",
                error.code().0
            );
        }
    }
}

/// A certificate context, freed when dropped.
struct Context(*const CERT_CONTEXT);

impl Context {
    /// A context of the certificate that belongs to no store.
    fn create(der: &[u8]) -> Result<Self, InstallError> {
        // SAFETY: `der` is a live slice that the call copies.
        let created = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        if created.is_null() {
            Err(failed("read", &windows::core::Error::from_thread()))
        } else {
            Ok(Self(created))
        }
    }

    /// The DER of the certificate.
    fn der(&self) -> &[u8] {
        // SAFETY: the context is held by `self`; its encoded certificate lives as long as the context.
        unsafe {
            let context = &*self.0;
            std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
        }
    }

    /// Whether both certificates are for the same public key.
    fn same_public_key(&self, other: &Self) -> bool {
        // SAFETY: both contexts are held; their certificate information lives as long as they do.
        unsafe {
            CertComparePublicKeyInfo(
                X509_ASN_ENCODING,
                &(*(*self.0).pCertInfo).SubjectPublicKeyInfo,
                &(*(*other.0).pCertInfo).SubjectPublicKeyInfo,
            )
        }
        .as_bool()
    }

    fn duplicate(&self) -> Self {
        // SAFETY: the context is held by `self`; the copy is freed by its own guard.
        Self(unsafe { CertDuplicateCertificateContext(Some(self.0)) })
    }

    /// The key provider information of the certificate; none when it has no key.
    fn key_info(&self) -> Result<Option<KeyInfo>, InstallError> {
        let mut size = 0u32;
        // SAFETY: the context is held by `self`; a size query writes only `size`.
        let sized = unsafe {
            CertGetCertificateContextProperty(self.0, CERT_KEY_PROV_INFO_PROP_ID, None, &mut size)
        };
        match sized {
            Ok(()) => {}
            Err(error) if error.code() == CRYPT_E_NOT_FOUND => return Ok(None),
            Err(error) => return Err(failed("read key", &error)),
        }
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        // SAFETY: the buffer holds at least `size` bytes, which the call writes.
        unsafe {
            CertGetCertificateContextProperty(
                self.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            )
        }
        .map_err(|error| failed("read key", &error))?;
        Ok(Some(KeyInfo(buffer)))
    }

    /// Ties the certificate to the key `info` names.
    fn pair(&self, info: &CRYPT_KEY_PROV_INFO) -> Result<(), InstallError> {
        // SAFETY: the context is held by `self`; `info` and the strings it points at outlive the call, which copies
        // them.
        unsafe {
            CertSetCertificateContextProperty(
                self.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                0,
                Some(std::ptr::from_ref(info).cast()),
            )
        }
        .map_err(|error| failed("pair", &error))
    }

    /// Deletes the certificate from its store. The call frees the context, also when it fails.
    fn delete(self) -> Result<(), InstallError> {
        let context = self.0;
        std::mem::forget(self);
        // SAFETY: the context came from a store; the call frees it.
        unsafe { CertDeleteCertificateFromStore(context) }.map_err(|error| failed("remove", &error))
    }

    /// Whether the key of the certificate can be reached without asking the user and is the certificate's key.
    fn reach_key(&self) -> Result<(), InstallError> {
        self.acquire_key()
            .map(drop)
            .map_err(|error| failed("verify", &error))
    }

    /// The key of the certificate, opened without asking the user and checked against the certificate's public key;
    /// none when the system hands out a handle it keeps, which this code must not free or delete.
    fn acquire_key(&self) -> windows::core::Result<Option<Handle>> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC(0);
        let mut release = BOOL(0);
        // SAFETY: the context is held by `self`; the outputs are live locals.
        unsafe {
            CryptAcquireCertificatePrivateKey(
                self.0,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
                    | CRYPT_ACQUIRE_SILENT_FLAG
                    | CRYPT_ACQUIRE_COMPARE_KEY_FLAG,
                None,
                &mut handle,
                Some(&mut spec),
                Some(&mut release),
            )
        }?;
        Ok(release.as_bool().then(|| Handle(NCRYPT_HANDLE(handle.0))))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context belongs to this guard, whose `drop` runs once.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0)) };
    }
}

fn failed(step: &str, error: &windows::core::Error) -> InstallError {
    log::warn!(
        "certificate install failed at {step}: Windows error {:#010x}",
        error.code().0
    );
    InstallError::Failed(format!("{step}: Windows error {:#010x}", error.code().0))
}

fn failed_with(step: &str, reason: &str) -> InstallError {
    log::warn!("certificate install failed at {step}: {reason}");
    InstallError::Failed(format!("{step}: {reason}"))
}

/// Removes a certificate from the personal and intermediate stores, for the test that installed it.
#[cfg(test)]
pub(super) fn remove(der: &[u8]) {
    for name in [w!("MY"), w!("CA")] {
        if let Ok(store) = Store::open(name)
            && let Ok(Some(found)) = store.find(der)
        {
            let _ = found.delete();
        }
    }
}

/// Whether the intermediate store of the current user holds this certificate, for the test that installed it.
#[cfg(test)]
pub(super) fn holds(der: &[u8]) -> bool {
    Store::open(w!("CA")).is_ok_and(|store| matches!(store.find(der), Ok(Some(_))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_user_keys_of_the_software_and_platform_provider_are_deleted() {
        let user = CRYPT_KEY_FLAGS(0);
        assert!(deletable("Microsoft Software Key Storage Provider", user));
        assert!(deletable("microsoft platform crypto provider", user));
        assert!(!deletable(
            "Microsoft Smart Card Key Storage Provider",
            user
        ));
        assert!(!deletable(
            "Microsoft Enhanced RSA and AES Cryptographic Provider",
            user
        ));
        assert!(!deletable("", user));
        assert!(!deletable(
            "Microsoft Software Key Storage Provider",
            CRYPT_MACHINE_KEYSET
        ));
    }
}
