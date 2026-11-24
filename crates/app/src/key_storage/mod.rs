//! The key storage of this system.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

use im_core::keys::KeyStorage;
#[cfg(not(any(target_os = "macos", windows)))]
use im_core::keys::NoKeyStorage;

/// The key storage of this computer: the keychain on macOS, the CNG providers on Windows, none elsewhere.
pub fn system() -> Box<dyn KeyStorage> {
    #[cfg(target_os = "macos")]
    return Box::new(macos::Keychain);
    #[cfg(windows)]
    return Box::new(windows::Cng);
    #[cfg(not(any(target_os = "macos", windows)))]
    return Box::new(NoKeyStorage);
}

#[cfg(test)]
mod tests {
    use im_core::keys::testing::verify;
    use im_core::keys::{AlternativeName, NameType, RequestSubject, Storage, signing_request};

    use super::*;

    /// On Windows the offers probe the providers with real keys, so they are checked by the ignored test.
    #[cfg(not(windows))]
    #[test]
    fn the_system_offers_only_what_it_can_create() {
        let offers = system().offered();
        if cfg!(target_os = "macos") {
            assert_eq!(offers.len(), 1);
            assert_eq!(offers[0].storage, Storage::Keychain);
            assert!(!offers[0].types.is_empty());
        } else {
            assert!(offers.is_empty());
        }
    }

    /// Creates a key of every offered type in the real key storage of this computer, so it runs only on
    /// request: `cargo test -p identity-manager -- --ignored key_storage`.
    #[test]
    #[ignore = "uses the key storage of this computer"]
    fn key_storage_creates_signs_and_deletes() {
        let storage = system();
        let offers = storage.offered();
        println!("offered: {offers:?}");
        #[cfg(windows)]
        {
            let storages: Vec<_> = offers.iter().map(|offer| offer.storage).collect();
            assert!(storages.contains(&Storage::Software));
            assert!(offers.iter().all(|offer| !offer.types.is_empty()));
            println!(
                "platform crypto provider: {}",
                if storages.contains(&Storage::Tpm) {
                    "offered"
                } else {
                    "not offered"
                }
            );
        }
        let subject = RequestSubject {
            names: vec![(NameType::CommonName, "key storage check".into())],
            alternative_names: vec![AlternativeName::Dns("check.example.test".into())],
        };
        for offer in offers {
            for key_type in offer.types {
                let what = format!("{:?} {key_type:?}", offer.storage);
                let key = storage
                    .create(offer.storage, key_type)
                    .unwrap_or_else(|error| panic!("{what}: {error}"));
                let id = key.id().clone();
                let signed = signing_request(key.as_ref(), &subject)
                    .unwrap_or_else(|error| panic!("{what}: {error}"));
                assert!(!signed.is_empty(), "{what}");
                // The CI job checks this request with openssl; the file holds the DER of the first one.
                if let Some(path) = std::env::var_os("IM_KEY_REQUEST_OUT")
                    .filter(|path| !std::path::Path::new(path).exists())
                {
                    std::fs::write(path, &signed).expect(&what);
                }
                let signature = key.sign(b"message").expect(&what);
                assert!(verify(key.as_ref(), b"message", &signature), "{what}");
                #[cfg(target_os = "macos")]
                assert_eq!(macos::extractable(&id), Some(false), "{what}");
                #[cfg(windows)]
                assert_eq!(windows::export_policy(&id), Some(0), "{what}");
                let opened = storage.open(&id).expect(&what).expect(&what);
                assert_eq!(opened.public_key(), key.public_key(), "{what}");
                storage.delete(&id).expect(&what);
                assert!(storage.open(&id).expect(&what).is_none(), "{what}");
            }
        }
    }
}
