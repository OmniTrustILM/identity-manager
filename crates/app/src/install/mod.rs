//! Installing the certificate ILM issued where the system keeps it.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use std::sync::Arc;

use im_core::install::CertificateInstaller;
#[cfg(not(any(target_os = "macos", windows)))]
use im_core::install::NoInstaller;

/// The installer of this computer: the default keychain on macOS, the personal store of the user on Windows,
/// none elsewhere.
pub fn system() -> Arc<dyn CertificateInstaller> {
    #[cfg(target_os = "macos")]
    return Arc::new(macos::Keychain);
    #[cfg(windows)]
    return Arc::new(windows::PersonalStore);
    #[cfg(not(any(target_os = "macos", windows)))]
    return Arc::new(NoInstaller);
}

#[cfg(test)]
mod tests {
    use im_core::identity::{Fingerprint, KeyLocation, system_store};
    use im_core::keys::{
        AlternativeName, KeyId, KeyType, NameType, RequestSubject, Storage, signing_request,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    };
    use rustls::SignatureScheme;
    use rustls::pki_types::CertificateSigningRequestDer;

    use super::*;
    use crate::key_storage;

    /// Removes what the test installed, also when an assertion fails.
    struct Cleanup {
        ders: Vec<Vec<u8>>,
        key: KeyId,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            for der in &self.ders {
                remove(der);
            }
            let _ = key_storage::system().delete(&self.key);
        }
    }

    #[cfg(windows)]
    use super::windows::remove;
    #[cfg(target_os = "macos")]
    use macos::remove;
    #[cfg(not(any(target_os = "macos", windows)))]
    fn remove(_: &[u8]) {}

    fn location_of(storage: Storage) -> KeyLocation {
        match storage {
            Storage::Keychain => KeyLocation::Keychain,
            Storage::Software => KeyLocation::Software,
            Storage::Tpm => KeyLocation::Tpm,
        }
    }

    fn authority(name: &str) -> (CertificateParams, KeyPair) {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        (
            params,
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("authority key"),
        )
    }

    /// Installs a certificate for a key of each offered storage into the real certificate store of this
    /// computer, so it runs only on request: `cargo test -p identity-manager -- --ignored installer_installs`.
    #[test]
    #[ignore = "uses the certificate store of this computer"]
    fn installer_installs_identity() {
        let storage = key_storage::system();
        let store = system_store(crate::certificates::origins());
        let subject = RequestSubject {
            names: vec![(NameType::CommonName, "installer check".into())],
            alternative_names: vec![AlternativeName::Dns("check.example.test".into())],
        };
        for offer in storage.offered() {
            let key_type = if offer.types.contains(&KeyType::EcP256) {
                KeyType::EcP256
            } else {
                offer.types[0]
            };
            let what = format!("{:?} {key_type:?}", offer.storage);
            let key = storage
                .create(offer.storage, key_type)
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            let mut cleanup = Cleanup {
                ders: Vec::new(),
                key: key.id().clone(),
            };
            let request = signing_request(key.as_ref(), &subject).expect(&what);

            let (root_params, root_key) = authority("installer check root");
            let root = Issuer::new(root_params, root_key);
            let (intermediate_params, intermediate_key) = authority("installer check intermediate");
            let intermediate = intermediate_params
                .signed_by(&intermediate_key, &root)
                .expect(&what);
            let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);
            let mut signing = CertificateSigningRequestParams::from_der(
                &CertificateSigningRequestDer::from(request.as_slice()),
            )
            .expect(&what);
            signing.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let leaf = signing.signed_by(&intermediate_issuer).expect(&what);

            let installer = system();
            let intermediates = vec![intermediate.der().to_vec()];
            cleanup.ders = vec![leaf.der().to_vec(), intermediate.der().to_vec()];
            installer
                .install(key.id(), leaf.der(), &intermediates)
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            installer
                .install(key.id(), leaf.der(), &intermediates)
                .unwrap_or_else(|error| panic!("{what} again: {error}"));

            let fingerprint = Fingerprint::of(leaf.der());
            let listed = store.certificates().expect(&what);
            assert!(
                listed.iter().any(|found| found.fingerprint == fingerprint
                    && found.location == location_of(offer.storage)),
                "{what}: the identity is not listed"
            );
            let identity = store.open(&fingerprint).expect(&what);
            let signer = identity
                .signing_key()
                .choose_scheme(&[
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA256,
                ])
                .expect(&what);
            assert!(!signer.sign(b"message").expect(&what).is_empty(), "{what}");
        }
    }
}
