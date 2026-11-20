//! The name of the key storage provider of a certificate in the personal store of the current user, which the
//! store itself does not tell.

use std::mem::size_of;
use std::ptr::NonNull;

use im_core::identity::{Fingerprint, KeyProviders};
use windows::Win32::Foundation::CRYPT_E_NOT_FOUND;
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_EXISTING, CERT_KEY_PROV_INFO_PROP_ID, CERT_OPEN_STORE_FLAGS,
    CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER,
    CRYPT_KEY_PROV_INFO, CertCloseStore, CertCreateCertificateContext, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGetCertificateContextProperty, CertOpenStore, HCERTSTORE,
    X509_ASN_ENCODING,
};
use windows::core::{Error, Result, w};

/// Reads the provider of a key from the `My` store of the current user.
pub struct WindowsKeyProviders;

impl KeyProviders for WindowsKeyProviders {
    fn provider_name(&self, der: &[u8]) -> Option<String> {
        match lookup(der) {
            Ok(name) => {
                log::debug!(
                    "key provider of certificate {}: {}",
                    Fingerprint::of(der),
                    name.as_deref().unwrap_or("none")
                );
                name
            }
            Err(error) => {
                log::warn!(
                    "key provider of certificate {} not read: Windows error {:#010x}",
                    Fingerprint::of(der),
                    error.code().0
                );
                None
            }
        }
    }
}

fn lookup(der: &[u8]) -> Result<Option<String>> {
    let store = Store::open_personal()?;
    let given = Context::from_der(der)?;
    store.find(&given)?.provider_name()
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

    fn provider_name(&self) -> Result<Option<String>> {
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
        let name = unsafe { (*info).pwszProvName };
        if name.is_null() {
            return Ok(None);
        }
        // SAFETY: the name points into `buffer`, which is alive, and ends with a NUL the call wrote.
        Ok(unsafe { name.to_string() }
            .ok()
            .filter(|name| !name.is_empty()))
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: the context is owned by this value and freed only here.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0.as_ptr())) };
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use im_core::identity::{Fingerprint, KeyLocation, system_store};

    use super::WindowsKeyProviders;

    #[test]
    #[ignore = "reads the personal certificate store of the computer it runs on"]
    fn key_provider_names_the_software_provider() {
        let expected: Fingerprint = std::env::var("IM_IDENTITY_FINGERPRINT")
            .expect("IM_IDENTITY_FINGERPRINT names the certificate imported with a software key")
            .parse()
            .expect("IM_IDENTITY_FINGERPRINT is a fingerprint");
        let store = system_store(Arc::new(WindowsKeyProviders));
        let found = store.certificates().expect("the store can be read");
        let imported = found
            .iter()
            .find(|certificate| certificate.fingerprint == expected)
            .expect("the store lists the imported certificate");
        assert_eq!(imported.location, KeyLocation::Software);
    }
}
