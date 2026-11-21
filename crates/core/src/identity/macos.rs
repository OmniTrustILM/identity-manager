//! The default keychain and smart cards: identities (certificate and key) of the person, signed with through
//! `SecKey`.

use std::fmt;
use std::sync::Arc;
use std::time::SystemTime;

use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;
use rustls::sign::{Signer, SigningKey};
use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::policy::SecPolicy;
use security_framework::trust::SecTrust;

use super::certificate::{KeyLocation, describe_all, read_logged};
use super::{
    ClientIdentity, Fingerprint, IdentityStore, KeyKind, LocalCertificate, StoreUnreadable,
    signing_refused, usable,
};

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

pub struct KeychainStore;

impl IdentityStore for KeychainStore {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        read_logged("the keychain", || {
            let identities = identities()?;
            Ok(describe_all(
                identities
                    .iter()
                    .map(|(der, location, _)| (der.as_slice(), *location)),
                SystemTime::now(),
            ))
        })
    }

    fn der(&self, fingerprint: &Fingerprint) -> Option<Vec<u8>> {
        identities()
            .ok()?
            .into_iter()
            .map(|(der, _, _)| der)
            .find(|der| Fingerprint::of(der) == *fingerprint)
    }

    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        let identities = match identities() {
            Ok(identities) => identities,
            Err(error) => {
                log::warn!("cannot read the keychain: {error}");
                return None;
            }
        };
        let found = usable(
            identities
                .into_iter()
                .map(|(der, _, identity)| (der, identity)),
            SystemTime::now(),
        )
        .into_iter()
        .find(|found| found.assessed.candidate.fingerprint == *fingerprint)?;
        let key = match found.item.private_key() {
            Ok(key) => key,
            Err(error) => {
                log::warn!("cannot reach the key of certificate {fingerprint}: {error}");
                return None;
            }
        };
        let chain = chain(&found.item)?;
        let key = KeychainKey {
            key,
            kind: found.assessed.key,
        };
        Some(ClientIdentity::new(chain, Arc::new(key)))
    }
}

/// The identities of the default keychain (keys in the keychain) and of the smart cards, with the DER of their
/// certificate and where the key is, each certificate once. No other keychain is searched, so not the System
/// keychain. Smart cards that cannot be read leave the keychain's list intact.
fn identities() -> Result<Vec<(Vec<u8>, KeyLocation, SecIdentity)>, StoreUnreadable> {
    let default = SecKeychain::default()
        .map_err(|error| StoreUnreadable(format!("no default keychain: {error}")))?;
    let mut found = search(
        ItemSearchOptions::new().keychains(&[default]),
        KeyLocation::Keychain,
    )?;
    let cards = search(
        ItemSearchOptions::new().access_group_token(),
        KeyLocation::SmartCard,
    )
    .unwrap_or_else(|error| {
        log::warn!("cannot read the smart cards: {error}");
        Vec::new()
    });
    for card in cards {
        if !found.iter().any(|(der, _, _)| *der == card.0) {
            found.push(card);
        }
    }
    Ok(found)
}

/// The identities one search finds. Nothing found is not a failure.
fn search(
    options: &mut ItemSearchOptions,
    location: KeyLocation,
) -> Result<Vec<(Vec<u8>, KeyLocation, SecIdentity)>, StoreUnreadable> {
    let results = options
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All)
        .search();
    match results {
        Ok(results) => Ok(results
            .into_iter()
            .filter_map(|result| match result {
                SearchResult::Ref(Reference::Identity(identity)) => Some(identity),
                _ => None,
            })
            .filter_map(|identity| {
                Some((identity.certificate().ok()?.to_der(), location, identity))
            })
            .collect()),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
        Err(error) => Err(StoreUnreadable(error.to_string())),
    }
}

/// The certificate and the intermediates the keychain knows, leaf first.
fn chain(identity: &SecIdentity) -> Option<Vec<CertificateDer<'static>>> {
    let leaf: SecCertificate = identity.certificate().ok()?;
    let leaf_der = leaf.to_der();
    let built = SecTrust::create_with_certificates(&[leaf], &[SecPolicy::create_x509()])
        .ok()
        .map(|mut trust| {
            // The chain is built whether or not the system trusts it; trust is ILM's to judge.
            let _ = trust.set_network_fetch_allowed(false);
            let _ = trust.evaluate_with_error();
            trust.chain()
        })
        .unwrap_or_default();
    let mut chain: Vec<CertificateDer<'static>> = built
        .iter()
        .map(|cert| CertificateDer::from(cert.to_der()))
        .collect();
    if chain.first().map(|der| der.as_ref()) != Some(leaf_der.as_slice()) {
        chain.insert(0, CertificateDer::from(leaf_der));
    }
    Some(chain)
}

struct KeychainKey {
    key: SecKey,
    kind: KeyKind,
}

impl fmt::Debug for KeychainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainKey")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl SigningKey for KeychainKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.kind.choose(offered)?;
        Some(Box::new(KeychainSigner {
            key: self.key.clone(),
            scheme,
        }))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.kind.algorithm()
    }
}

struct KeychainSigner {
    key: SecKey,
    scheme: SignatureScheme,
}

impl fmt::Debug for KeychainSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl Signer for KeychainSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let algorithm = algorithm(self.scheme).ok_or(signing_refused())?;
        self.key
            .create_signature(algorithm, message)
            .map_err(|error| {
                log::warn!("the keychain did not sign: {error}");
                signing_refused()
            })
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// The keychain's algorithm for a TLS signature scheme; the keychain hashes the message itself.
fn algorithm(scheme: SignatureScheme) -> Option<Algorithm> {
    Some(match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Algorithm::ECDSASignatureMessageX962SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384 => Algorithm::ECDSASignatureMessageX962SHA384,
        SignatureScheme::RSA_PKCS1_SHA256 => Algorithm::RSASignatureMessagePKCS1v15SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => Algorithm::RSASignatureMessagePKCS1v15SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => Algorithm::RSASignatureMessagePKCS1v15SHA512,
        SignatureScheme::RSA_PSS_SHA256 => Algorithm::RSASignatureMessagePSSSHA256,
        SignatureScheme::RSA_PSS_SHA384 => Algorithm::RSASignatureMessagePSSSHA384,
        SignatureScheme::RSA_PSS_SHA512 => Algorithm::RSASignatureMessagePSSSHA512,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scheme_of_the_table_has_a_keychain_algorithm() {
        for kind in [KeyKind::Rsa, KeyKind::EcdsaP256, KeyKind::EcdsaP384] {
            for scheme in kind.schemes() {
                assert!(algorithm(*scheme).is_some(), "{scheme:?}");
            }
        }
    }

    #[tokio::test]
    #[ignore = "reads the real keychain; runs in the system-store job only"]
    async fn system_store_lists_and_signs() {
        super::super::testing::check_system_store(&KeychainStore).await;
    }
}
