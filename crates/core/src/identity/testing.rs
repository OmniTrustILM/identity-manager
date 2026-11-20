//! Certificates made with rcgen and a store that holds their keys, for tests of this crate.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
    PKCS_ED25519, PKCS_RSA_SHA256, RsaKeySize, SanType, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::sign::{Signer, SigningKey};
use rustls::{RootCertStore, ServerConfig, SignatureAlgorithm, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::certificate::{KeyLocation, describe_all};
use super::{
    ClientIdentity, Fingerprint, IdentityStore, LocalCertificate, StoreUnreadable, usable,
};

/// A calendar date as year, month, day.
pub type Date = (i32, u8, u8);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    ClientAuth,
    ServerAuth,
    ClientAndServerAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    /// An extended key usage that has no name, 1.2.3.4.
    Unnamed,
    Any,
    /// No extended key usage extension.
    Unrestricted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    P256,
    P384,
    P521,
    Rsa2048,
    Rsa3072,
    Ed25519,
}

/// What a certificate issued by [`TestCa`] looks like.
#[derive(Clone)]
pub struct Issue {
    /// The common name; empty for a subject with an organization only.
    pub name: String,
    pub usage: Usage,
    pub not_before: Date,
    pub not_after: Date,
    pub key: KeyAlg,
    /// Names for the subject alternative name extension.
    pub dns_names: Vec<String>,
    /// E-mail addresses for the subject alternative name extension.
    pub emails: Vec<String>,
    /// User principal names for the subject alternative name extension.
    pub principal_names: Vec<String>,
}

impl Issue {
    /// A client certificate that is valid from 2020 to 2099.
    pub fn client(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            usage: Usage::ClientAuth,
            not_before: (2020, 1, 1),
            not_after: (2099, 1, 1),
            key: KeyAlg::P256,
            dns_names: Vec::new(),
            emails: Vec::new(),
            principal_names: Vec::new(),
        }
    }

    /// A server certificate for `localhost`, valid from 2020 to 2099.
    pub fn server(name: &str) -> Self {
        Self {
            usage: Usage::ServerAuth,
            dns_names: vec!["localhost".to_owned()],
            ..Self::client(name)
        }
    }

    pub fn usage(self, usage: Usage) -> Self {
        Self { usage, ..self }
    }

    pub fn emails(self, emails: &[&str]) -> Self {
        let emails = emails.iter().map(|email| (*email).to_owned()).collect();
        Self { emails, ..self }
    }

    pub fn principal_names(self, names: &[&str]) -> Self {
        let principal_names = names.iter().map(|name| (*name).to_owned()).collect();
        Self {
            principal_names,
            ..self
        }
    }

    pub fn dns_names(self, dns_names: &[&str]) -> Self {
        let dns_names = dns_names.iter().map(|name| (*name).to_owned()).collect();
        Self { dns_names, ..self }
    }

    pub fn key(self, key: KeyAlg) -> Self {
        Self { key, ..self }
    }

    pub fn valid(self, not_before: Date, not_after: Date) -> Self {
        Self {
            not_before,
            not_after,
            ..self
        }
    }
}

/// A certificate with its chain and a key held in memory.
#[derive(Clone)]
pub struct TestIdentity {
    /// Leaf first, then the CA that issued it.
    pub chain: Vec<CertificateDer<'static>>,
    pub key: Arc<dyn SigningKey>,
    key_der: Vec<u8>,
}

impl TestIdentity {
    pub fn leaf(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(self.leaf())
    }

    /// The private key as PKCS#8, for the server side of a test.
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }

    pub fn client_identity(&self) -> ClientIdentity {
        ClientIdentity::new(self.chain.clone(), Arc::clone(&self.key))
    }

    /// The same identity with a key that refuses to sign, as the system store does when the person chose Deny.
    pub fn denied_identity(&self) -> ClientIdentity {
        let key = Arc::new(DeniedKey(Arc::clone(&self.key)));
        ClientIdentity::new(self.chain.clone(), key)
    }
}

#[derive(Debug)]
struct DeniedKey(Arc<dyn SigningKey>);

impl SigningKey for DeniedKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let scheme = self.0.choose_scheme(offered)?.scheme();
        Some(Box::new(DeniedSigner(scheme)))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct DeniedSigner(SignatureScheme);

impl Signer for DeniedSigner {
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Err(super::signing_refused())
    }

    fn scheme(&self) -> SignatureScheme {
        self.0
    }
}

/// A self-signed CA that issues test certificates.
pub struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    der: CertificateDer<'static>,
}

impl TestCa {
    pub fn new() -> Self {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("a CA key");
        let der = params
            .self_signed(&key)
            .expect("a CA certificate")
            .der()
            .clone();
        Self { params, key, der }
    }

    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// A CA certificate with this CA's subject, signed by this CA with a new key: a key rollover that is self-issued
    /// but not self-signed.
    pub fn rollover(&self) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.distinguished_name = self.params.distinguished_name.clone();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("a CA key");
        let issuer = Issuer::from_params(&self.params, &self.key);
        params
            .signed_by(&key, &issuer)
            .expect("a CA certificate")
            .der()
            .clone()
    }

    pub fn issue(&self, issue: Issue) -> TestIdentity {
        let key_pair = match issue.key {
            KeyAlg::P256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
            KeyAlg::P384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
            KeyAlg::P521 => KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512),
            KeyAlg::Rsa2048 => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048),
            KeyAlg::Rsa3072 => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072),
            KeyAlg::Ed25519 => KeyPair::generate_for(&PKCS_ED25519),
        }
        .expect("a key pair");
        let mut params = CertificateParams::new(issue.dns_names).expect("valid names");
        for email in issue.emails {
            let email = Ia5String::try_from(email).expect("an e-mail address");
            params.subject_alt_names.push(SanType::Rfc822Name(email));
        }
        for name in issue.principal_names {
            params.subject_alt_names.push(SanType::OtherName((
                vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
                name.into(),
            )));
        }
        params.distinguished_name = DistinguishedName::new();
        if issue.name.is_empty() {
            params
                .distinguished_name
                .push(DnType::OrganizationName, "No Common Name");
        } else {
            params
                .distinguished_name
                .push(DnType::CommonName, issue.name);
        }
        params.not_before =
            date_time_ymd(issue.not_before.0, issue.not_before.1, issue.not_before.2);
        params.not_after = date_time_ymd(issue.not_after.0, issue.not_after.1, issue.not_after.2);
        use ExtendedKeyUsagePurpose as Purpose;
        let purposes: &[Purpose] = match issue.usage {
            Usage::ClientAuth => &[Purpose::ClientAuth],
            Usage::ServerAuth => &[Purpose::ServerAuth],
            Usage::ClientAndServerAuth => &[Purpose::ServerAuth, Purpose::ClientAuth],
            Usage::CodeSigning => &[Purpose::CodeSigning],
            Usage::EmailProtection => &[Purpose::EmailProtection],
            Usage::TimeStamping => &[Purpose::TimeStamping],
            Usage::OcspSigning => &[Purpose::OcspSigning],
            Usage::Unnamed => &[Purpose::Other(vec![1, 2, 3, 4])],
            Usage::Any => &[Purpose::Any],
            Usage::Unrestricted => &[],
        };
        for purpose in purposes {
            params.insert_extended_key_usage(purpose.clone());
        }
        let issuer = Issuer::from_params(&self.params, &self.key);
        let leaf = params.signed_by(&key_pair, &issuer).expect("a certificate");
        let key_der = key_pair.serialize_der();
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(key_der.clone()),
        ))
        .expect("a key rustls can sign with");
        TestIdentity {
            chain: vec![leaf.der().clone(), self.der.clone()],
            key,
            key_der,
        }
    }
}

/// An [`IdentityStore`] that holds its keys in memory.
pub struct StandInStore {
    identities: Vec<TestIdentity>,
    now: SystemTime,
    location: KeyLocation,
}

impl StandInStore {
    pub fn new(identities: Vec<TestIdentity>) -> Self {
        Self {
            identities,
            now: SystemTime::now(),
            location: KeyLocation::Unknown,
        }
    }

    /// The same store with another idea of the time, to judge validity.
    pub fn at(self, now: SystemTime) -> Self {
        Self { now, ..self }
    }

    /// The same store with the private keys somewhere else.
    pub fn located(self, location: KeyLocation) -> Self {
        Self { location, ..self }
    }

    fn usable(&self) -> Vec<super::Usable<&TestIdentity>> {
        usable(
            self.identities
                .iter()
                .map(|identity| (identity.leaf().to_vec(), identity)),
            self.now,
        )
    }
}

impl IdentityStore for StandInStore {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        Ok(describe_all(
            self.identities
                .iter()
                .map(|identity| (identity.leaf().as_ref(), self.location)),
            self.now,
        ))
    }

    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        self.usable()
            .into_iter()
            .find(|found| found.assessed.candidate.fingerprint == *fingerprint)
            .map(|found| found.item.client_identity())
    }
}

/// Whether a [`TestServer`] asks for a client certificate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClientCerts {
    /// Requires one issued by the CA of the test.
    Required,
    NotRequested,
}

/// What a [`TestServer`] saw of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenRequest {
    pub path: String,
    /// The leaf the client presented, if any.
    pub fingerprint: Option<Fingerprint>,
    pub authorization: bool,
}

/// An HTTPS server on `localhost` whose certificate is issued by the CA of the test. `GET /api/v1/auth/profile`
/// answers 200 with a profile when the client presented the allowed leaf, else 401 with a bearer challenge.
pub struct TestServer {
    port: u16,
    allowed: Arc<Mutex<Fingerprint>>,
    failing: Arc<Mutex<Option<u16>>>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
    task: JoinHandle<()>,
}

impl TestServer {
    pub async fn start(ca: &TestCa, client_certs: ClientCerts, allowed: Fingerprint) -> Self {
        let client_root = (client_certs == ClientCerts::Required).then(|| ca.der());
        Self::serve(ca, client_root, allowed).await
    }

    /// A server that requires a client certificate issued by `client_root`, a CA other than `ca`.
    #[cfg(any(target_os = "macos", windows))]
    pub async fn requiring(
        ca: &TestCa,
        client_root: &CertificateDer<'static>,
        allowed: Fingerprint,
    ) -> Self {
        Self::serve(ca, Some(client_root), allowed).await
    }

    async fn serve(
        ca: &TestCa,
        client_root: Option<&CertificateDer<'static>>,
        allowed: Fingerprint,
    ) -> Self {
        let identity = ca.issue(Issue::server("localhost"));
        let builder = ServerConfig::builder();
        let builder = match client_root {
            Some(root) => {
                let mut roots = RootCertStore::empty();
                roots.add(root.clone()).expect("a valid root");
                let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .expect("a client verifier");
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(identity.chain.clone(), identity.private_key())
            .expect("a server certificate");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port");
        let port = listener.local_addr().expect("an address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let allowed = Arc::new(Mutex::new(allowed));
        let permitted = Arc::clone(&allowed);
        let failing = Arc::new(Mutex::new(None));
        let failure = Arc::clone(&failing);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, recorded) = (acceptor.clone(), Arc::clone(&recorded));
                let permitted = Arc::clone(&permitted);
                let failure = Arc::clone(&failure);
                tokio::spawn(async move {
                    // A client that fails the handshake is not recorded.
                    if let Ok(stream) = acceptor.accept(stream).await {
                        answer(stream, &permitted, &failure, port, &recorded).await;
                    }
                });
            }
        });
        Self {
            port,
            allowed,
            failing,
            seen,
            task,
        }
    }

    /// From now on the profile is for `fingerprint` alone.
    pub fn allow(&self, fingerprint: Fingerprint) {
        *self.allowed.lock().expect("the allowed leaf") = fingerprint;
    }

    /// From now on every request is answered with `status`, or as before with none.
    pub fn fail_with(&self, status: Option<u16>) {
        *self.failing.lock().expect("the failure") = status;
    }

    pub fn url(&self) -> String {
        format!("https://localhost:{}", self.port)
    }

    pub fn profile_url(&self) -> String {
        format!("{}/api/v1/auth/profile", self.url())
    }

    pub fn requests(&self) -> Vec<SeenRequest> {
        self.seen.lock().expect("the record").clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Connection = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

async fn answer(
    mut stream: Connection,
    allowed: &Mutex<Fingerprint>,
    failing: &Mutex<Option<u16>>,
    port: u16,
    seen: &Mutex<Vec<SeenRequest>>,
) {
    let fingerprint = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .map(|leaf| Fingerprint::of(leaf));
    let mut head = Vec::new();
    let mut buffer = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&buffer[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).to_lowercase();
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    seen.lock().expect("the record").push(SeenRequest {
        path,
        fingerprint,
        authorization: head.contains("\r\nauthorization:"),
    });
    let allowed = *allowed.lock().expect("the allowed leaf");
    let failing = *failing.lock().expect("the failure");
    let response = if let Some(status) = failing {
        format!("HTTP/1.1 {status} Failure\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    } else if fingerprint == Some(allowed) {
        let body = profile_json();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    } else {
        format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer resource_metadata=\"https://localhost:{port}/.well-known/oauth-protected-resource\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// The profile ILM answers with: the person is `jdoe`, Jane Doe.
fn profile_json() -> String {
    serde_json::json!({
        "uuid": "5d3a4c3e-0000-4000-8000-000000000001",
        "username": "jdoe",
        "firstName": "Jane",
        "lastName": "Doe",
        "permissions": {
            "allowedListings": ["certificates"],
            "allowedActions": [{"resource": "certificates", "actions": ["list"]}]
        }
    })
    .to_string()
}

/// The check of the ignored test of each system: the store holds the certificate named by
/// `IM_IDENTITY_FINGERPRINT` and a CA certificate without a key named by `IM_IDENTITY_KEYLESS_FINGERPRINT`, lists the
/// first (and not the second) as a certificate that can sign in and as a candidate, opens it, signs with
/// its key and completes a handshake with a server that requires a certificate issued by the CA in the PEM file `IM_IDENTITY_CA`.
/// An identity in a keychain on the search list that is not the default one, named by
/// `IM_IDENTITY_ELSEWHERE_FINGERPRINT`, is neither listed, nor offered for sign-in, nor opened.
#[cfg(target_os = "macos")]
fn check_other_keychain_left_out(
    store: &dyn IdentityStore,
    listed: &[LocalCertificate],
    candidates: &[super::Candidate],
) {
    let elsewhere: Fingerprint = std::env::var("IM_IDENTITY_ELSEWHERE_FINGERPRINT")
        .expect("IM_IDENTITY_ELSEWHERE_FINGERPRINT names the identity in another keychain")
        .parse()
        .expect("IM_IDENTITY_ELSEWHERE_FINGERPRINT is a fingerprint");
    assert!(
        listed
            .iter()
            .all(|certificate| certificate.fingerprint != elsewhere),
        "the store lists an identity from a keychain that is not the default one"
    );
    assert!(
        candidates.iter().all(|c| c.fingerprint != elsewhere),
        "sign-in offers an identity from a keychain that is not the default one"
    );
    assert!(store.open(&elsewhere).is_none());
}

#[cfg(any(target_os = "macos", windows))]
pub async fn check_system_store(store: &dyn IdentityStore) {
    let expected: Fingerprint = std::env::var("IM_IDENTITY_FINGERPRINT")
        .expect("IM_IDENTITY_FINGERPRINT names the certificate in the store")
        .parse()
        .expect("IM_IDENTITY_FINGERPRINT is a fingerprint");
    let listed = store.certificates().expect("the store is readable");
    let found = listed
        .iter()
        .find(|certificate| certificate.fingerprint == expected)
        .expect("the store lists the certificate it signs with");
    assert_eq!(found.sign_in, Ok(()));
    #[cfg(target_os = "macos")]
    assert_eq!(found.location, KeyLocation::Keychain);
    let keyless: Fingerprint = std::env::var("IM_IDENTITY_KEYLESS_FINGERPRINT")
        .expect("IM_IDENTITY_KEYLESS_FINGERPRINT names the certificate without a key")
        .parse()
        .expect("IM_IDENTITY_KEYLESS_FINGERPRINT is a fingerprint");
    assert!(
        listed
            .iter()
            .all(|certificate| certificate.fingerprint != keyless),
        "the store lists a certificate that has no private key"
    );
    let candidates = store.candidates();
    assert!(
        candidates.iter().any(|c| c.fingerprint == expected),
        "the store lists {} certificates, none with the expected fingerprint",
        candidates.len()
    );
    #[cfg(target_os = "macos")]
    check_other_keychain_left_out(store, &listed, &candidates);
    let identity = store.open(&expected).expect("the certificate opens");
    assert_eq!(identity.fingerprint(), Some(expected));
    let offered = [
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
    ];
    let signer = identity
        .signing_key()
        .choose_scheme(&offered)
        .expect("the key supports one of the schemes");
    let signature = signer.sign(b"identity manager").expect("the key signs");
    assert!(!signature.is_empty());

    let ca_file =
        std::env::var("IM_IDENTITY_CA").expect("IM_IDENTITY_CA is the PEM file of the CA");
    let client_root =
        <CertificateDer<'static> as rustls::pki_types::pem::PemObject>::from_pem_file(&ca_file)
            .expect("IM_IDENTITY_CA holds a certificate");
    let server_ca = TestCa::new();
    let server = TestServer::requiring(&server_ca, &client_root, expected).await;
    let (client, _) = crate::http::client_with_identity_trusting(server_ca.der(), identity);
    let response = client
        .get(server.profile_url())
        .send()
        .await
        .expect("the handshake with the system identity completes");
    assert_eq!(response.status(), 200);
    let seen = server.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].fingerprint, Some(expected));
}
