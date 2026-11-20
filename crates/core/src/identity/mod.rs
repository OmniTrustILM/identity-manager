//! The certificates of the person with a private key, those that can sign in to ILM, and the keys, which stay in
//! the system store.

pub mod certificate;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
pub(crate) mod testing;
pub mod tls;
#[cfg(windows)]
mod windows;

pub use certificate::{KeyAlgorithm, KeyLocation, LocalCertificate, LocalCertificateView, Use};

use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;
use rustls::sign::SigningKey;
use sha2::{Digest, Sha256};
use x509_parser::der_parser::oid;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

const MIN_RSA_BITS: usize = 2048;

/// SHA-256 of a certificate's DER encoding, as ILM identifies the certificate of a person.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn of(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// The first four bytes as uppercase hex pairs separated by colons, to tell certificates apart on screen.
    pub fn short(&self) -> String {
        let text = self.to_string();
        text[..11].to_owned()
    }
}

/// Uppercase hex pairs separated by colons.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidFingerprint;

impl fmt::Display for InvalidFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a fingerprint is 32 bytes in hex, with or without colons")
    }
}

impl Error for InvalidFingerprint {}

impl FromStr for Fingerprint {
    type Err = InvalidFingerprint;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|byte| *byte != b':')
            .map(|byte| (byte as char).to_digit(16).map(|digit| digit as u8))
            .collect::<Option<_>>()
            .ok_or(InvalidFingerprint)?;
        if digits.len() != 64 {
            return Err(InvalidFingerprint);
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(digits.chunks(2)) {
            *byte = pair[0] << 4 | pair[1];
        }
        Ok(Self(bytes))
    }
}

/// A certificate that can sign in, as the person sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub fingerprint: Fingerprint,
    /// The common name, else the whole name.
    pub subject: String,
    /// The common name, else the whole name.
    pub issuer: String,
    pub not_after: SystemTime,
}

/// The kinds of keys ILM sign-in accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    EcdsaP256,
    EcdsaP384,
}

impl KeyKind {
    /// The TLS signature schemes the store can produce with a key of this kind.
    pub fn schemes(self) -> &'static [SignatureScheme] {
        match self {
            Self::Rsa => &[
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
            ],
            Self::EcdsaP256 => &[SignatureScheme::ECDSA_NISTP256_SHA256],
            Self::EcdsaP384 => &[SignatureScheme::ECDSA_NISTP384_SHA384],
        }
    }

    /// The first of `offered` that this kind of key supports.
    pub fn choose(self, offered: &[SignatureScheme]) -> Option<SignatureScheme> {
        let supported = self.schemes();
        offered
            .iter()
            .copied()
            .find(|scheme| supported.contains(scheme))
    }

    pub fn algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::Rsa => SignatureAlgorithm::RSA,
            Self::EcdsaP256 | Self::EcdsaP384 => SignatureAlgorithm::ECDSA,
        }
    }
}

/// Why a certificate is not offered for sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Unparsable,
    NotYetValid,
    Expired,
    NotForClientAuth,
    UnsupportedKey,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unparsable => "cannot be parsed",
            Self::NotYetValid => "is not valid yet",
            Self::Expired => "has expired",
            Self::NotForClientAuth => "is not for client authentication",
            Self::UnsupportedKey => "has a key that is not RSA 2048 or more, P-256 or P-384",
        })
    }
}

/// A certificate that passed the filter, with what the reader needs to sign with its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessed {
    pub candidate: Candidate,
    pub key: KeyKind,
}

/// Applies the sign-in filter to one certificate: valid at `now`, client authentication allowed when the
/// extended key usage is present, and a key of a supported kind. Nothing else is checked, since the issuing
/// CA that ILM trusts is not known before the handshake.
pub fn assess(der: &[u8], now: SystemTime) -> Result<Assessed, Rejection> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| Rejection::Unparsable)?;
    let now = unix_seconds(now);
    let validity = cert.validity();
    if now < validity.not_before.timestamp() {
        return Err(Rejection::NotYetValid);
    }
    if now > validity.not_after.timestamp() {
        return Err(Rejection::Expired);
    }
    match cert.extended_key_usage() {
        Ok(None) => {}
        Ok(Some(usage)) if usage.value.client_auth => {}
        Ok(Some(_)) => return Err(Rejection::NotForClientAuth),
        Err(_) => return Err(Rejection::Unparsable),
    }
    let key = key_kind(&cert).ok_or(Rejection::UnsupportedKey)?;
    let not_after = UNIX_EPOCH + Duration::from_secs(validity.not_after.timestamp().max(0) as u64);
    Ok(Assessed {
        candidate: Candidate {
            fingerprint: Fingerprint::of(der),
            subject: display_name(cert.subject()),
            issuer: display_name(cert.issuer()),
            not_after,
        },
        key,
    })
}

fn unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

fn display_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    name.iter_common_name()
        .next()
        .and_then(|common| common.as_str().ok())
        .map_or_else(|| name.to_string(), str::to_owned)
}

fn key_kind(cert: &X509Certificate<'_>) -> Option<KeyKind> {
    let info = cert.public_key();
    match info.parsed().ok()? {
        PublicKey::RSA(rsa) if rsa.key_size() >= MIN_RSA_BITS => Some(KeyKind::Rsa),
        PublicKey::EC(_) => {
            let curve = info.algorithm.parameters.as_ref()?.as_oid().ok()?;
            if curve == oid!(1.2.840.10045.3.1.7) {
                Some(KeyKind::EcdsaP256)
            } else if curve == oid!(1.3.132.0.34) {
                Some(KeyKind::EcdsaP384)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A certificate a reader found, kept with the store's own handle to it.
pub struct Usable<T> {
    pub assessed: Assessed,
    pub item: T,
}

/// The items whose certificate can sign in, the latest expiry first. Others are skipped with a debug log.
pub fn usable<T>(items: impl IntoIterator<Item = (Vec<u8>, T)>, now: SystemTime) -> Vec<Usable<T>> {
    let mut found: Vec<Usable<T>> = items
        .into_iter()
        .filter_map(|(der, item)| match assess(&der, now) {
            Ok(assessed) => Some(Usable { assessed, item }),
            Err(reason) => {
                log::debug!(
                    "certificate {} {reason}; not offered for sign-in",
                    Fingerprint::of(&der)
                );
                None
            }
        })
        .collect();
    found.sort_by(|a, b| {
        let (a, b) = (&a.assessed.candidate, &b.assessed.candidate);
        b.not_after
            .cmp(&a.not_after)
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    found
}

/// Drops the self-issued root at the end of a chain, and only that one: a self-issued key rollover before it is
/// an intermediate. A lone self-issued certificate stays.
fn trim_chain(mut chain: Vec<CertificateDer<'static>>) -> Vec<CertificateDer<'static>> {
    if chain.len() > 1 && chain.last().is_some_and(is_self_signed) {
        chain.pop();
    }
    chain
}

fn is_self_signed(der: &CertificateDer<'_>) -> bool {
    X509Certificate::from_der(der)
        .is_ok_and(|(_, cert)| cert.subject().as_raw() == cert.issuer().as_raw())
}

/// A certificate chain to present and a signer whose key is in the system store.
#[derive(Clone)]
pub struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: Arc<dyn SigningKey>,
}

impl ClientIdentity {
    /// `chain` starts with the leaf; a self-signed root at its end is dropped.
    pub fn new(chain: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            chain: trim_chain(chain),
            key,
        }
    }

    /// The certificates to send, leaf first.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }

    pub fn signing_key(&self) -> Arc<dyn SigningKey> {
        Arc::clone(&self.key)
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        self.chain.first().map(|leaf| Fingerprint::of(leaf))
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("fingerprint", &self.fingerprint())
            .field("chain_length", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// The system store refused to sign, for example because the person chose Deny when it asked to use the key.
#[derive(Debug)]
pub struct SigningRefused;

impl fmt::Display for SigningRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the system did not allow the use of the certificate's key")
    }
}

impl Error for SigningRefused {}

/// The error a store's signer returns to rustls when the store cannot sign.
pub fn signing_refused() -> rustls::Error {
    rustls::Error::Other(rustls::OtherError(Arc::new(SigningRefused)))
}

/// Whether `error`, or something it wraps, is [`SigningRefused`].
pub fn is_signing_refused(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if is_refusal(error) {
            return true;
        }
        current = error.source();
    }
    false
}

/// `io::Error` hides the error it wraps from `source`, and rustls reports the errors of a signer as `Other`
/// without exposing them as a source, so both are opened here.
fn is_refusal(error: &(dyn Error + 'static)) -> bool {
    if error.is::<SigningRefused>() {
        return true;
    }
    if let Some(rustls::Error::Other(other)) = error.downcast_ref::<rustls::Error>() {
        return other
            .source()
            .is_some_and(|inner| inner.is::<SigningRefused>());
    }
    error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
        .is_some_and(|inner| is_signing_refused(inner))
}

/// The store could not be read; the reason is for the log, not for the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreUnreadable(pub String);

impl fmt::Display for StoreUnreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for StoreUnreadable {}

/// The certificates of the person in the system store and their keys.
pub trait IdentityStore: Send + Sync {
    /// The certificates with a private key, by name, then the latest expiry, then fingerprint. Reading never uses
    /// a private key.
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable>;

    /// The certificates that can sign in (see [`assess`]), the latest expiry first.
    fn candidates(&self) -> Vec<Candidate> {
        let listed = match self.certificates() {
            Ok(listed) => listed,
            Err(error) => {
                log::warn!("no certificates to sign in with: {error}");
                return Vec::new();
            }
        };
        let mut candidates: Vec<Candidate> = listed
            .into_iter()
            .filter(|found| found.sign_in.is_ok())
            .map(|found| Candidate {
                fingerprint: found.fingerprint,
                subject: found.name,
                issuer: found.issuer,
                not_after: found.not_after,
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.not_after
                .cmp(&a.not_after)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });
        candidates
    }

    /// The certificate with `fingerprint`, ready to sign, when the store has it and it can still sign in.
    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity>;
}

/// A store without certificates, for systems that have no reader yet.
pub struct EmptyStore;

impl IdentityStore for EmptyStore {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        Ok(Vec::new())
    }

    fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        None
    }
}

/// Where the key of a certificate is kept, where the store itself cannot tell.
pub trait KeyProviders: Send + Sync {
    /// The name of the key storage provider of the certificate with this DER, when it is known.
    fn provider_name(&self, der: &[u8]) -> Option<String>;
}

/// No lookup: every key location the store cannot tell is unknown.
pub struct NoProviders;

impl KeyProviders for NoProviders {
    fn provider_name(&self, _der: &[u8]) -> Option<String> {
        None
    }
}

/// The store of this system: the default keychain and smart cards on macOS, the personal store of the current
/// user on Windows, none on Linux. `providers` names the key providers on Windows and is not used elsewhere.
#[cfg_attr(not(windows), allow(unused_variables))]
pub fn system_store(providers: Arc<dyn KeyProviders>) -> Arc<dyn IdentityStore> {
    #[cfg(target_os = "macos")]
    return Arc::new(macos::KeychainStore);
    #[cfg(windows)]
    return Arc::new(windows::PersonalStore { providers });
    #[cfg(not(any(target_os = "macos", windows)))]
    return Arc::new(EmptyStore);
}

#[cfg(test)]
mod tests;
