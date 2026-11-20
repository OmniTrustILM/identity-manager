//! The personal store of the current user: certificates with a key, signed with through CNG.

use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::CertificateDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};
use rustls_cng::signer::CngSigningKey;
use rustls_cng::store::{CertStore, CertStoreType};

use super::certificate::{KeyLocation, describe_all, mark_unreachable, read_logged};
use super::{
    ClientIdentity, Fingerprint, IdentityStore, KeyProviders, LocalCertificate, StoreUnreadable,
    signing_refused, usable,
};

pub struct PersonalStore {
    pub providers: Arc<dyn KeyProviders>,
}

impl IdentityStore for PersonalStore {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        read_logged("the personal certificate store", || {
            let all = all_certificates()?;
            let ders: Vec<&[u8]> = all.iter().map(|(der, _)| der.as_slice()).collect();
            let providers = self.providers.provider_names(&ders);
            let mut located = Vec::new();
            let mut unreachable = Vec::new();
            for ((der, context), provider) in all.iter().zip(providers) {
                if context.acquire_key(true).is_err() {
                    let Some(name) = &provider else {
                        continue;
                    };
                    log::debug!(
                        "certificate {} has its key with {name}, which cannot be reached silently",
                        Fingerprint::of(der)
                    );
                    unreachable.push(Fingerprint::of(der));
                }
                located.push((der.as_slice(), location(der, provider)));
            }
            let mut listed = describe_all(located, SystemTime::now());
            mark_unreachable(&mut listed, &unreachable);
            Ok(listed)
        })
    }

    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        let found = match all_certificates() {
            Ok(found) => found,
            Err(error) => {
                log::warn!("cannot read the personal certificate store: {error}");
                return None;
            }
        };
        let reachable = found
            .into_iter()
            .filter(|(_, context)| context.acquire_key(true).is_ok());
        let found = usable(reachable, SystemTime::now())
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

/// Where the key of the certificate with this DER is kept, as far as the provider lookup tells.
fn location(der: &[u8], provider: Option<String>) -> KeyLocation {
    let Some(name) = provider else {
        return KeyLocation::Unknown;
    };
    log::debug!(
        "certificate {} has its key with {name}",
        Fingerprint::of(der)
    );
    KeyLocation::from_windows_provider(&name)
}

/// Every certificate of `CurrentUser\My`, with its DER. Which of them have a key is decided by the caller: a key
/// that a silent lookup finds, or a key the store names a provider for.
fn all_certificates() -> Result<Vec<(Vec<u8>, rustls_cng::cert::CertContext)>, StoreUnreadable> {
    let store = CertStore::open(CertStoreType::CurrentUser, "My")
        .map_err(|error| StoreUnreadable(format!("cannot open the store: {error}")))?;
    let all = store
        .find_all()
        .map_err(|error| StoreUnreadable(format!("cannot list the store: {error}")))?;
    Ok(all
        .into_iter()
        .map(|context| (context.as_der().to_vec(), context))
        .collect())
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

    #[tokio::test]
    #[ignore = "reads the real certificate store; runs in the system-store job only"]
    async fn system_store_lists_and_signs() {
        let store = PersonalStore {
            providers: Arc::new(super::super::NoProviders),
        };
        super::super::testing::check_system_store(&store).await;
    }
}
