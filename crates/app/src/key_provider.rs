//! The key storage provider of a certificate in the personal store of the current user, and the name of the
//! smart card when the key is on one, which the store itself does not tell.

use std::mem::size_of;
use std::ptr::NonNull;

use im_core::identity::{Fingerprint, KeyLocation, KeyOrigin, KeyOrigins};
use windows::Win32::Foundation::CRYPT_E_NOT_FOUND;
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_EXISTING, CERT_KEY_PROV_INFO_PROP_ID, CERT_KEY_SPEC,
    CERT_NCRYPT_KEY_SPEC, CERT_OPEN_STORE_FLAGS, CERT_STORE_PROV_SYSTEM_W,
    CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_KEY_PROV_INFO, CertCloseStore,
    CertCreateCertificateContext, CertFindCertificateInStore, CertFreeCertificateContext,
    CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE,
    MS_SMART_CARD_KEY_STORAGE_PROVIDER, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
    NCRYPT_READER_PROPERTY, NCRYPT_SILENT_FLAG, NCryptFreeObject, NCryptGetProperty, NCryptOpenKey,
    NCryptOpenStorageProvider, X509_ASN_ENCODING,
};
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows::core::{Error, PCWSTR, Result, w};

/// Reads the provider and the card of a key from the `My` store of the current user.
pub struct WindowsKeyOrigins;

impl KeyOrigins for WindowsKeyOrigins {
    fn origins(&self, ders: &[&[u8]]) -> Vec<KeyOrigin> {
        let store = match Store::open_personal() {
            Ok(store) => store,
            Err(error) => {
                log::warn!(
                    "key providers not read: Windows error {:#010x}",
                    error.code().0
                );
                return vec![KeyOrigin::default(); ders.len()];
            }
        };
        ders.iter().map(|der| store.origin(der)).collect()
    }
}

/// The key of a certificate as the store names it.
struct KeyInfo {
    provider: String,
    container: Option<String>,
    key_spec: u32,
}

/// An open certificate store, closed when dropped.
struct Store(HCERTSTORE);

impl Store {
    fn open_personal() -> Result<Self> {
        // SAFETY: the provider, flags and name are constants; the name is a NUL-terminated wide string that
        // outlives the call.
        let handle = unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                X509_ASN_ENCODING,
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER) | CERT_STORE_READONLY_FLAG,
                Some(w!("My").as_ptr().cast()),
            )
        }?;
        Ok(Self(handle))
    }

    /// The provider of the key of the certificate with this DER, as the store's copy of it names, and the card
    /// when the provider is a smart card's.
    fn origin(&self, der: &[u8]) -> KeyOrigin {
        let found = Context::from_der(der).and_then(|given| self.find(&given)?.key_info());
        let info = match found {
            Ok(Some(info)) => info,
            Ok(None) => {
                log::debug!("key provider of certificate {}: none", Fingerprint::of(der));
                return KeyOrigin::default();
            }
            Err(error) => {
                log::warn!(
                    "key provider of certificate {} not read: Windows error {:#010x}",
                    Fingerprint::of(der),
                    error.code().0
                );
                return KeyOrigin::default();
            }
        };
        log::debug!(
            "key provider of certificate {}: {}",
            Fingerprint::of(der),
            info.provider
        );
        let card = (KeyLocation::from_windows_provider(&info.provider) == KeyLocation::SmartCard)
            .then(|| card_name(&info, der))
            .flatten();
        KeyOrigin {
            provider: Some(info.provider),
            card,
        }
    }

    /// The copy of `given` that the store holds.
    fn find(&self, given: &Context) -> Result<Context> {
        // SAFETY: the store is open, and `given` is a live context that the call only reads.
        let found = unsafe {
            CertFindCertificateInStore(
                self.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_EXISTING,
                Some(given.0.as_ptr().cast()),
                None,
            )
        };
        Context::owning(found)
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: the handle came from `CertOpenStore` and is closed only here.
        if let Err(error) = unsafe { CertCloseStore(Some(self.0), 0) } {
            log::warn!(
                "certificate store not closed: Windows error {:#010x}",
                error.code().0
            );
        }
    }
}

/// A certificate context that this code owns, freed when dropped.
struct Context(NonNull<CERT_CONTEXT>);

impl Context {
    fn from_der(der: &[u8]) -> Result<Self> {
        // SAFETY: `der` is a valid slice that the call copies.
        let created = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
        Self::owning(created)
    }

    /// Takes over a context the system returned, or the error it left when there is none.
    fn owning(raw: *mut CERT_CONTEXT) -> Result<Self> {
        NonNull::new(raw).map(Self).ok_or_else(Error::from_thread)
    }

    /// The key of the certificate as the store names it, or none for a certificate without a private key.
    fn key_info(&self) -> Result<Option<KeyInfo>> {
        let mut size = 0;
        // SAFETY: without a buffer the call only reports the size; the context is live.
        let sized = unsafe {
            CertGetCertificateContextProperty(
                self.0.as_ptr(),
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut size,
            )
        };
        match sized {
            // A certificate without a private key has no provider.
            Err(error) if error.code() == CRYPT_E_NOT_FOUND => return Ok(None),
            other => other?,
        }
        let size_in_bytes = size as usize;
        if size_in_bytes < size_of::<CRYPT_KEY_PROV_INFO>() {
            return Ok(None);
        }
        // Eight-byte units keep the buffer aligned for the structure the call writes into it.
        let mut buffer = vec![0u64; size_in_bytes.div_ceil(size_of::<u64>())];
        // SAFETY: the buffer holds at least `size` bytes, and the call writes no more than it said.
        unsafe {
            CertGetCertificateContextProperty(
                self.0.as_ptr(),
                CERT_KEY_PROV_INFO_PROP_ID,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            )
        }?;
        let info = buffer.as_ptr().cast::<CRYPT_KEY_PROV_INFO>();
        // SAFETY: the buffer is aligned and at least as large as the structure, which the call filled in.
        let (provider, container, key_spec) = unsafe {
            (
                (*info).pwszProvName,
                (*info).pwszContainerName,
                (*info).dwKeySpec,
            )
        };
        // SAFETY: each name is null or points into `buffer`, which is alive, and ends with a NUL the call wrote.
        let text = |name: windows::core::PWSTR| {
            (!name.is_null())
                .then(|| unsafe { name.to_string() }.ok())
                .flatten()
                .filter(|name| !name.is_empty())
        };
        Ok(text(provider).map(|provider| KeyInfo {
            provider,
            container: text(container),
            key_spec,
        }))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context is owned by this value and freed only here.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0.as_ptr())) };
    }
}

/// The name of the reader of the smart card that holds the key, or none when the card does not tell it silently.
fn card_name(info: &KeyInfo, der: &[u8]) -> Option<String> {
    let container = info.container.as_deref()?;
    match reader_name(container, info.key_spec) {
        Ok(name) => name,
        Err(error) => {
            log::debug!(
                "card of certificate {} not read: Windows error {:#010x}",
                Fingerprint::of(der),
                error.code().0
            );
            None
        }
    }
}

/// Opens the key without asking for a PIN and reads the reader it is in.
fn reader_name(container: &str, key_spec: u32) -> Result<Option<String>> {
    let mut provider = NCRYPT_PROV_HANDLE::default();
    // SAFETY: the name is a constant NUL-terminated wide string; the handle is written on success.
    unsafe { NCryptOpenStorageProvider(&mut provider, MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0) }?;
    let _provider_guard = Handle(provider.into());
    let wide: Vec<u16> = container.encode_utf16().chain([0]).collect();
    // A CNG key names no legacy key spec.
    let legacy_spec = if key_spec == CERT_NCRYPT_KEY_SPEC.0 {
        CERT_KEY_SPEC(0)
    } else {
        CERT_KEY_SPEC(key_spec)
    };
    let mut key = NCRYPT_KEY_HANDLE::default();
    // SAFETY: the provider is open; the name is a NUL-terminated wide string that outlives the call; the
    // silent flag makes the provider fail instead of asking for a PIN.
    unsafe {
        NCryptOpenKey(
            provider,
            &mut key,
            PCWSTR(wide.as_ptr()),
            legacy_spec,
            NCRYPT_SILENT_FLAG,
        )
    }?;
    let _key_guard = Handle(key.into());
    let name = reader_property(key.into())?;
    Ok(Some(name).filter(|name| !name.trim().is_empty()))
}

/// An NCrypt handle, freed when dropped.
struct Handle(NCRYPT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: the handle came from NCrypt and is freed only here.
        if let Err(error) = unsafe { NCryptFreeObject(self.0) } {
            log::warn!(
                "key handle not freed: Windows error {:#010x}",
                error.code().0
            );
        }
    }
}

/// The reader property of an open key, without its terminator.
fn reader_property(handle: NCRYPT_HANDLE) -> Result<String> {
    let name = NCRYPT_READER_PROPERTY;
    let mut size = 0;
    // SAFETY: without an output buffer the call only reports the size.
    unsafe {
        NCryptGetProperty(
            handle,
            name,
            None,
            &mut size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }?;
    let mut value = vec![0u8; size as usize];
    // SAFETY: the buffer is `size` bytes long, as the call asked.
    unsafe {
        NCryptGetProperty(
            handle,
            name,
            Some(&mut value),
            &mut size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }?;
    value.truncate(size as usize);
    let units: Vec<u16> = value
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use im_core::identity::{Fingerprint, KeyLocation, system_store};

    use super::WindowsKeyOrigins;

    #[test]
    #[ignore = "reads the personal certificate store of the computer it runs on"]
    fn key_provider_names_the_software_provider() {
        let expected: Fingerprint = std::env::var("IM_IDENTITY_FINGERPRINT")
            .expect("IM_IDENTITY_FINGERPRINT names the certificate imported with a software key")
            .parse()
            .expect("IM_IDENTITY_FINGERPRINT is a fingerprint");
        let store = system_store(Arc::new(WindowsKeyOrigins));
        let found = store.certificates().expect("the store can be read");
        let imported = found
            .iter()
            .find(|certificate| certificate.fingerprint == expected)
            .expect("the store lists the imported certificate");
        assert_eq!(imported.location, KeyLocation::Software);
    }
}
