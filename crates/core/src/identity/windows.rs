//! The personal store of the current user: certificates with a key, signed with through CNG.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::CertificateDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls_cng::signer::CngSigningKey;
use rustls_cng::store::{CertStore, CertStoreType};

use super::{Candidate, ClientIdentity, Fingerprint, IdentityStore, signing_refused, usable};

pub struct PersonalStore;

impl IdentityStore for PersonalStore {
    fn candidates(&self) -> Vec<Candidate> {
        usable(certificates(), SystemTime::now())
            .into_iter()
            .map(|found| found.assessed.candidate)
            .collect()
    }

    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        let found = usable(certificates(), SystemTime::now())
            .into_iter()
            .find(|found| found.assessed.candidate.fingerprint == *fingerprint)?;
        let context = found.item;
        let key = match context.acquire_key(false).and_then(CngSigningKey::new) {
            Ok(key) => key,
            Err(error) => {
                log::warn!("cannot reach the key of certificate {fingerprint}: {error}");
                return None;
            }
        };
        let chain = match context.as_chain_der() {
            Ok(chain) if !chain.is_empty() => chain,
            _ => vec![context.as_der().to_vec()],
        };
        let chain = chain.into_iter().map(CertificateDer::from).collect();
        Some(ClientIdentity::new(chain, Arc::new(PersonalKey(key))))
    }
}

/// The certificates of `CurrentUser\My` that have a private key, with the DER of each.
fn certificates() -> Vec<(Vec<u8>, rustls_cng::cert::CertContext)> {
    let store = match CertStore::open(CertStoreType::CurrentUser, "My") {
        Ok(store) => store,
        Err(error) => {
            log::warn!("cannot open the personal certificate store: {error}");
            return Vec::new();
        }
    };
    let all = match store.find_all() {
        Ok(all) => all,
        Err(error) => {
            log::warn!("cannot read the personal certificate store: {error}");
            return Vec::new();
        }
    };
    all.into_iter()
        .filter(|context| context.acquire_key(true).is_ok())
        .map(|context| (context.as_der().to_vec(), context))
        .collect()
}

/// A CNG key whose refusals are reported as [`super::SigningRefused`].
#[derive(Debug)]
struct PersonalKey(CngSigningKey);

impl SigningKey for PersonalKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|inner| Box::new(PersonalSigner(inner)) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct PersonalSigner(Box<dyn Signer>);

impl Signer for PersonalSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.sign(message).map_err(|error| {
            log::warn!("the certificate store did not sign: {error}");
            signing_refused()
        })
    }

    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "reads the real certificate store; runs in the system-store job only"]
    fn system_store_lists_and_signs() {
        super::super::testing::check_system_store(&PersonalStore);
    }
}
