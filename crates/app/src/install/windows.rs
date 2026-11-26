//! Certificates in the personal store of the current user. The certificate is tied to its CNG key by the key
//! provider information property, which makes the identity. Intermediates go to the intermediate store of the
//! user; no trust is changed and nothing is added to a root store.

use std::ptr::null_mut;

use im_core::identity::Fingerprint;
use im_core::install::{CertificateInstaller, InstallError};
use im_core::keys::{KeyId, Storage};
use windows::Win32::Foundation::CRYPT_E_NOT_FOUND;
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_EXISTING, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC,
    CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_ADD_USE_EXISTING,
    CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
    CRYPT_ACQUIRE_SILENT_FLAG, CRYPT_KEY_FLAGS, CRYPT_KEY_PROV_INFO,
    CertAddEncodedCertificateToStore, CertCloseStore, CertCreateCertificateContext,
    CertFindCertificateInStore, CertFreeCertificateContext, CertOpenStore,
    CertSetCertificateContextProperty, CryptAcquireCertificatePrivateKey, HCERTSTORE,
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, MS_KEY_STORAGE_PROVIDER, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_HANDLE, NCryptFreeObject, X509_ASN_ENCODING,
};
use windows::core::{BOOL, PCWSTR, PWSTR, w};

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
        // SAFETY: the context is held by `context`; `info` and the strings it points at outlive the call, which
        // copies them.
        unsafe {
            CertSetCertificateContextProperty(
                context.0,
                CERT_KEY_PROV_INFO_PROP_ID,
                0,
                Some(std::ptr::from_ref(&info).cast()),
            )
        }
        .map_err(|error| failed("pair", &error))?;
        drop(context);

        if !intermediates.is_empty() {
            let authorities = Store::open(w!("CA"))?;
            for intermediate in intermediates {
                authorities.add(intermediate, CERT_STORE_ADD_USE_EXISTING)?;
            }
        }

        let stored = personal
            .find(leaf)?
            .ok_or_else(|| failed_with("verify", "the store does not hold the certificate"))?;
        stored.reach_key()?;
        log::info!("certificate installed: {:?}", key.storage);
        Ok(())
    }

    fn install_beside(&self, _: &Fingerprint, _: &[u8], _: &[Vec<u8>]) -> Result<(), InstallError> {
        Err(failed_with("install beside", "not supported yet"))
    }

    fn remove(&self, _: &Fingerprint, _: bool) -> Result<(), InstallError> {
        Err(failed_with("remove", "not supported yet"))
    }
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
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
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

    /// Whether the key of the certificate can be reached without asking the user.
    fn reach_key(&self) -> Result<(), InstallError> {
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut spec = CERT_KEY_SPEC(0);
        let mut release = BOOL(0);
        // SAFETY: the context is held by `self`; the outputs are live locals.
        let reached = unsafe {
            CryptAcquireCertificatePrivateKey(
                self.0,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                None,
                &mut handle,
                Some(&mut spec),
                Some(&mut release),
            )
        };
        reached.map_err(|error| failed("verify", &error))?;
        if release.as_bool() {
            // SAFETY: the call handed the key to this code, which frees it once and does not use it again.
            if let Err(error) = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) } {
                log::warn!(
                    "key handle not freed: Windows error {:#010x}",
                    error.code().0
                );
            }
        }
        Ok(())
    }

    /// Deletes the certificate from its store. The call frees the context, also when it fails.
    #[cfg(test)]
    fn delete(self) {
        use windows::Win32::Security::Cryptography::CertDeleteCertificateFromStore;

        let context = self.0;
        std::mem::forget(self);
        // SAFETY: the context came from a store search; the call frees it.
        let _ = unsafe { CertDeleteCertificateFromStore(context) };
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
            found.delete();
        }
    }
}

/// Whether the intermediate store of the current user holds this certificate, for the test that installed it.
#[cfg(test)]
pub(super) fn holds(der: &[u8]) -> bool {
    Store::open(w!("CA")).is_ok_and(|store| matches!(store.find(der), Ok(Some(_))))
}
