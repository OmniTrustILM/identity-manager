//! TLS for a certificate sign-in: the chosen identity is offered to whichever server asks, whatever CA names
//! the server hints, and the client remembers whether the server asked at all.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::client::ResolvesClientCert;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, SignatureScheme};
use rustls_platform_verifier::Verifier;

use super::ClientIdentity;

/// Whether a server has asked for a client certificate on a connection of the client it belongs to.
#[derive(Clone, Default)]
pub struct CertificateAsked(Arc<AtomicBool>);

impl CertificateAsked {
    pub fn get(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for CertificateAsked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CertificateAsked({})", self.get())
    }
}

/// Offers one identity to every server that asks for a client certificate.
struct OfferIdentity {
    identity: ClientIdentity,
    asked: CertificateAsked,
}

impl fmt::Debug for OfferIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OfferIdentity")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl ResolvesClientCert for OfferIdentity {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.asked.0.store(true, Ordering::SeqCst);
        let key = self.identity.signing_key();
        if key.choose_scheme(sigschemes).is_none() {
            log::warn!("the server accepts no signature scheme the certificate's key supports");
            return None;
        }
        Some(Arc::new(CertifiedKey::new(
            self.identity.chain().to_vec(),
            key,
        )))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// The server is checked against the certificate store of the system.
pub fn client_config(identity: ClientIdentity) -> (ClientConfig, CertificateAsked) {
    let provider = Arc::new(default_provider());
    let verifier = Verifier::new(Arc::clone(&provider))
        .expect("the platform certificate verifier is available");
    config(provider, Arc::new(verifier), identity)
}

/// Like [`client_config`] but trusting `root` alone, for servers of tests.
#[cfg(test)]
pub fn client_config_trusting(
    root: &rustls::pki_types::CertificateDer<'static>,
    identity: ClientIdentity,
) -> (ClientConfig, CertificateAsked) {
    let provider = Arc::new(default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).expect("a valid root certificate");
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::clone(&provider),
    )
    .build()
    .expect("a verifier for the root");
    config(provider, verifier, identity)
}

fn config(
    provider: Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
    identity: ClientIdentity,
) -> (ClientConfig, CertificateAsked) {
    let asked = CertificateAsked::default();
    let resolver = OfferIdentity {
        identity,
        asked: asked.clone(),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the default protocol versions are supported")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    (config, asked)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{ClientCerts, Issue, KeyAlg, TestCa, TestServer};
    use crate::http::{client_trusting, client_with_identity_trusting};

    async fn get_profile(client: &reqwest::Client, server: &TestServer) -> reqwest::Result<u16> {
        let response = client.get(server.profile_url()).send().await?;
        Ok(response.status().as_u16())
    }

    #[tokio::test]
    async fn the_server_sees_the_fingerprint_of_the_leaf() {
        let ca = TestCa::new();
        let person = ca.issue(Issue::client("Jane"));
        let server = TestServer::start(&ca, ClientCerts::Required, person.fingerprint()).await;
        let (client, asked) = client_with_identity_trusting(ca.der(), person.client_identity());

        assert_eq!(get_profile(&client, &server).await.unwrap(), 200);

        assert!(asked.get());
        let seen = server.requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].fingerprint, Some(person.fingerprint()));
        assert!(!seen[0].authorization);
    }

    #[tokio::test]
    async fn an_rsa_key_signs_the_handshake_too() {
        let ca = TestCa::new();
        let person = ca.issue(Issue::client("Jane").key(KeyAlg::Rsa2048));
        let server = TestServer::start(&ca, ClientCerts::Required, person.fingerprint()).await;
        let (client, _) = client_with_identity_trusting(ca.der(), person.client_identity());

        assert_eq!(get_profile(&client, &server).await.unwrap(), 200);
    }

    #[tokio::test]
    async fn another_certificate_is_known_but_unauthorized() {
        let ca = TestCa::new();
        let person = ca.issue(Issue::client("Jane"));
        let other = ca.issue(Issue::client("John"));
        let server = TestServer::start(&ca, ClientCerts::Required, other.fingerprint()).await;
        let (client, _) = client_with_identity_trusting(ca.der(), person.client_identity());

        let response = client.get(server.profile_url()).send().await.unwrap();

        assert_eq!(response.status(), 401);
        assert!(
            response
                .headers()
                .get("www-authenticate")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Bearer resource_metadata="))
        );
    }

    #[tokio::test]
    async fn a_server_that_does_not_ask_is_recorded_and_still_answers() {
        let ca = TestCa::new();
        let person = ca.issue(Issue::client("Jane"));
        let server = TestServer::start(&ca, ClientCerts::NotRequested, person.fingerprint()).await;
        let (client, asked) = client_with_identity_trusting(ca.der(), person.client_identity());

        assert_eq!(get_profile(&client, &server).await.unwrap(), 401);

        assert!(!asked.get());
        assert_eq!(server.requests()[0].fingerprint, None);
    }

    #[tokio::test]
    async fn a_server_that_rejects_the_issuer_fails_the_handshake() {
        let server_ca = TestCa::new();
        let stranger = TestCa::new().issue(Issue::client("Jane"));
        let server =
            TestServer::start(&server_ca, ClientCerts::Required, stranger.fingerprint()).await;
        let (client, asked) =
            client_with_identity_trusting(server_ca.der(), stranger.client_identity());

        assert!(get_profile(&client, &server).await.is_err());

        assert!(asked.get());
        assert!(server.requests().is_empty());
    }

    #[tokio::test]
    async fn the_plain_client_presents_no_certificate() {
        let ca = TestCa::new();
        let person = ca.issue(Issue::client("Jane"));
        let server = TestServer::start(&ca, ClientCerts::Required, person.fingerprint()).await;

        assert!(
            get_profile(&client_trusting(ca.der()), &server)
                .await
                .is_err()
        );
        assert!(server.requests().is_empty());
    }
}
