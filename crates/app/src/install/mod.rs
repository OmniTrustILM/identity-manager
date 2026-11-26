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

#[cfg(all(test, any(target_os = "macos", windows)))]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use im_core::identity::{Fingerprint, IdentityStore, KeyLocation, system_store};
    use im_core::keys::{
        AlternativeName, KeyId, KeyType, NameType, RequestSubject, Storage, StoredKey,
        signing_request,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256, SerialNumber,
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
    use super::windows::{holds, remove};
    #[cfg(target_os = "macos")]
    use macos::{holds, remove};

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
        for offer in storage.offered() {
            let key_type = key_type_of(&offer.types);
            let what = format!("{:?} {key_type:?}", offer.storage);
            let key = storage
                .create(offer.storage, key_type)
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            let mut cleanup = Cleanup {
                ders: Vec::new(),
                key: key.id().clone(),
            };

            let (root_params, root_key) = authority("installer check root");
            let root = Issuer::new(root_params, root_key);
            let (intermediate_params, intermediate_key) = authority("installer check intermediate");
            let intermediate = intermediate_params
                .signed_by(&intermediate_key, &root)
                .expect(&what);
            let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);
            let leaf = leaf_for(key.as_ref(), &intermediate_issuer, &what);

            let installer = system();
            let intermediates = vec![intermediate.der().to_vec()];
            cleanup.ders = vec![leaf.clone(), intermediate.der().to_vec()];
            installer
                .install(key.id(), &leaf, &intermediates)
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            installer
                .install(key.id(), &leaf, &intermediates)
                .unwrap_or_else(|error| panic!("{what} again: {error}"));

            assert!(
                holds(intermediate.der()),
                "{what}: the intermediate is not installed"
            );
            assert_signs(store.as_ref(), &leaf, offer.storage, &what);
        }
    }

    /// Installs a certificate for a new key of each offered storage, a second one for the same key beside it, removes
    /// the first while the second still uses the key, then the second with its key, in the real certificate store of
    /// this computer, so it runs only on request: `cargo test -p identity-manager -- --ignored installer_renews`.
    #[test]
    #[ignore = "uses the certificate store of this computer"]
    fn installer_renews_and_removes() {
        let storage = key_storage::system();
        let store = system_store(crate::certificates::origins());
        let installer = system();
        for offer in storage.offered() {
            let what = format!("{:?}", offer.storage);
            let key = storage
                .create(offer.storage, key_type_of(&offer.types))
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            let mut cleanup = Cleanup {
                ders: Vec::new(),
                key: key.id().clone(),
            };
            let (root_params, root_key) = authority("installer renewal root");
            let root = Issuer::new(root_params, root_key);
            let old = leaf_for(key.as_ref(), &root, &what);
            let renewed = leaf_for(key.as_ref(), &root, &what);
            cleanup.ders = vec![old.clone(), renewed.clone()];
            let (old_fingerprint, renewed_fingerprint) =
                (Fingerprint::of(&old), Fingerprint::of(&renewed));

            installer
                .install(key.id(), &old, &[])
                .unwrap_or_else(|error| panic!("{what}: {error}"));
            installer
                .install_beside(&old_fingerprint, &renewed, &[])
                .unwrap_or_else(|error| panic!("{what} beside: {error}"));
            assert_signs(store.as_ref(), &old, offer.storage, &what);
            assert_signs(store.as_ref(), &renewed, offer.storage, &what);

            installer
                .remove(&old_fingerprint, true)
                .unwrap_or_else(|error| panic!("{what} remove old: {error}"));
            assert!(
                !listed(store.as_ref(), &old_fingerprint),
                "{what}: the old one is listed"
            );
            assert_signs(store.as_ref(), &renewed, offer.storage, &what);

            installer
                .remove(&renewed_fingerprint, true)
                .unwrap_or_else(|error| panic!("{what} remove renewed: {error}"));
            installer
                .remove(&renewed_fingerprint, true)
                .unwrap_or_else(|error| panic!("{what} remove again: {error}"));
            assert!(
                !listed(store.as_ref(), &renewed_fingerprint),
                "{what}: the renewed one is listed"
            );
            assert!(
                storage.open(key.id()).expect(&what).is_none(),
                "{what}: the key is left"
            );
        }
    }

    fn key_type_of(offered: &[KeyType]) -> KeyType {
        if offered.contains(&KeyType::EcP256) {
            KeyType::EcP256
        } else {
            offered[0]
        }
    }

    /// A client certificate for the key with a new serial, signed by `issuer`. Without one, rcgen derives the serial
    /// from the public key, and two certificates for one key would be the same item to the keychain.
    fn leaf_for(key: &dyn StoredKey, issuer: &Issuer<'_, KeyPair>, what: &str) -> Vec<u8> {
        static ISSUED: AtomicU64 = AtomicU64::new(0);
        let subject = RequestSubject {
            names: vec![(NameType::CommonName, "installer check".into())],
            alternative_names: vec![AlternativeName::Dns("check.example.test".into())],
        };
        let request = signing_request(key, &subject).expect(what);
        let mut signing = CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(request.as_slice()),
        )
        .expect(what);
        signing.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect(what)
            .as_secs();
        let serial = (now << 16) | ISSUED.fetch_add(1, Ordering::Relaxed);
        signing.params.serial_number = Some(SerialNumber::from(serial));
        signing.signed_by(issuer).expect(what).der().to_vec()
    }

    fn listed(store: &dyn IdentityStore, fingerprint: &Fingerprint) -> bool {
        store
            .certificates()
            .expect("the store can be read")
            .iter()
            .any(|found| found.fingerprint == *fingerprint)
    }

    /// The certificate is listed with its key in the storage and signs.
    fn assert_signs(store: &dyn IdentityStore, leaf: &[u8], storage: Storage, what: &str) {
        let fingerprint = Fingerprint::of(leaf);
        let listed = store.certificates().expect(what);
        assert!(
            listed
                .iter()
                .any(|found| found.fingerprint == fingerprint
                    && found.location == location_of(storage)),
            "{what}: the identity is not listed"
        );
        let identity = store.open(&fingerprint).expect(what);
        let signer = identity
            .signing_key()
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ])
            .expect(what);
        assert!(!signer.sign(b"message").expect(what).is_empty(), "{what}");
    }
}
