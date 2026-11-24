//! A certificate of the person as the list shows it, and where its private key lives.

use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use x509_parser::der_parser::asn1_rs::Any;
use x509_parser::der_parser::oid;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use super::{Fingerprint, Rejection, StoreUnreadable, assess, display_name};

/// What a certificate is for, from its extended key usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, tag = "kind", content = "value", rename_all = "camelCase")
)]
pub enum Use {
    ClientAuth,
    ServerAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    /// anyExtendedKeyUsage.
    Any,
    /// A purpose without a name here, as its dotted OID.
    Other(String),
}

/// The algorithm of a certificate's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, tag = "kind", content = "value", rename_all = "camelCase")
)]
pub enum KeyAlgorithm {
    Rsa {
        bits: usize,
    },
    /// `curve` is `P-256`, `P-384` or `P-521`, else the dotted OID.
    Ec {
        curve: String,
    },
    Ed25519,
    /// The dotted OID of the algorithm.
    Other(String),
}

/// Where the private key of a certificate is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum KeyLocation {
    Keychain,
    SmartCard,
    SecureEnclave,
    Software,
    Tpm,
    Unknown,
}

/// The legacy cryptographic providers and the software key storage provider of Windows.
const SOFTWARE_PROVIDERS: &[&str] = &[
    "Microsoft Software Key Storage Provider",
    "Microsoft Enhanced RSA and AES Cryptographic Provider",
    "Microsoft Enhanced Cryptographic Provider v1.0",
    "Microsoft Base Cryptographic Provider v1.0",
    "Microsoft Strong Cryptographic Provider",
    "Microsoft Base DSS Cryptographic Provider",
    "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
    "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
    "Microsoft DH SChannel Cryptographic Provider",
    "Microsoft RSA SChannel Cryptographic Provider",
];

impl KeyLocation {
    /// The location a Windows key storage provider stands for; a provider that is not known is `Unknown`.
    pub fn from_windows_provider(name: &str) -> Self {
        let name = name.trim();
        if name.eq_ignore_ascii_case("Microsoft Platform Crypto Provider") {
            Self::Tpm
        } else if name.to_ascii_lowercase().contains("smart card") {
            Self::SmartCard
        } else if SOFTWARE_PROVIDERS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
        {
            Self::Software
        } else {
            Self::Unknown
        }
    }
}

/// A certificate with a private key in the store of the person, as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCertificate {
    pub fingerprint: Fingerprint,
    /// The common name, else the whole name.
    pub name: String,
    pub subject: String,
    /// The common name, else the whole name.
    pub issuer: String,
    pub issuer_name: String,
    /// Uppercase hex pairs separated by colons.
    pub serial: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// Empty when the certificate does not restrict its use.
    pub uses: Vec<Use>,
    pub alternative_names: Vec<String>,
    pub key: KeyAlgorithm,
    pub location: KeyLocation,
    /// The smart card that holds the key, when the location is a smart card and the card is named.
    pub card: Option<String>,
    /// Whether the certificate can sign in to ILM at the time of the description, else why not.
    pub sign_in: Result<(), Rejection>,
}

/// A certificate of the person as the interface shows it: no certificate bytes and no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct LocalCertificateView {
    pub fingerprint: String,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub issuer_name: String,
    pub serial: String,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub not_before: i64,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub not_after: i64,
    pub uses: Vec<Use>,
    pub alternative_names: Vec<String>,
    pub key: KeyAlgorithm,
    pub location: KeyLocation,
    pub card_name: Option<String>,
    pub can_sign_in: bool,
    /// Why the certificate cannot sign in, else none.
    pub sign_in_problem: Option<String>,
}

impl From<&LocalCertificate> for LocalCertificateView {
    fn from(found: &LocalCertificate) -> Self {
        Self {
            fingerprint: found.fingerprint.to_string(),
            name: found.name.clone(),
            subject: found.subject.clone(),
            issuer: found.issuer.clone(),
            issuer_name: found.issuer_name.clone(),
            serial: found.serial.clone(),
            not_before: epoch_millis(found.not_before),
            not_after: epoch_millis(found.not_after),
            uses: found.uses.clone(),
            alternative_names: found.alternative_names.clone(),
            key: found.key.clone(),
            location: found.location,
            card_name: found.card.clone(),
            can_sign_in: found.sign_in.is_ok(),
            sign_in_problem: found.sign_in.err().map(|reason| reason.to_string()),
        }
    }
}

/// Milliseconds since 1970 (UTC), as the interface counts time.
pub(crate) fn epoch_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => {
            i64::try_from(before.duration().as_millis()).map_or(i64::MIN, |millis| -millis)
        }
    }
}

/// Describes one certificate, or `None` when `der` cannot be parsed.
pub fn describe(der: &[u8], location: KeyLocation, now: SystemTime) -> Option<LocalCertificate> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let validity = cert.validity();
    Some(LocalCertificate {
        fingerprint: Fingerprint::of(der),
        name: display_name(cert.subject()),
        subject: cert.subject().to_string(),
        issuer: display_name(cert.issuer()),
        issuer_name: cert.issuer().to_string(),
        serial: serial(cert.raw_serial()),
        not_before: instant(validity.not_before.timestamp()),
        not_after: instant(validity.not_after.timestamp()),
        uses: uses(&cert),
        alternative_names: alternative_names(&cert),
        key: key_algorithm(&cert),
        location,
        card: None,
        sign_in: assess(der, now).map(|_| ()),
    })
}

/// Marks the listed certificates whose key the store cannot hand over without asking the person: they are
/// shown, but not offered for sign-in. A certificate that already cannot sign in keeps its first reason.
#[cfg(any(windows, test))]
pub(crate) fn mark_unreachable(listed: &mut [LocalCertificate], unreachable: &[Fingerprint]) {
    for certificate in listed
        .iter_mut()
        .filter(|certificate| unreachable.contains(&certificate.fingerprint))
    {
        if certificate.sign_in.is_ok() {
            certificate.sign_in = Err(Rejection::KeyUnreachable);
        }
    }
}

/// Describes each certificate of `items` with where its key is and, for a smart card, the card's name, in list
/// order: by name, then the latest expiry, then fingerprint. A certificate that cannot be parsed is skipped with a
/// debug log.
pub fn describe_all<'a>(
    items: impl IntoIterator<Item = (&'a [u8], KeyLocation, Option<String>)>,
    now: SystemTime,
) -> Vec<LocalCertificate> {
    let mut listed: Vec<LocalCertificate> = items
        .into_iter()
        .filter_map(|(der, location, card)| {
            let Some(mut described) = describe(der, location, now) else {
                log::debug!(
                    "certificate {} cannot be parsed; not listed",
                    Fingerprint::of(der)
                );
                return None;
            };
            if location == KeyLocation::SmartCard {
                if let Some(name) = &card {
                    log::debug!(
                        "certificate {} is on the card {name}",
                        described.fingerprint
                    );
                }
                described.card = card;
            }
            Some(described)
        })
        .collect();
    listed.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then_with(|| b.not_after.cmp(&a.not_after))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    listed
}

/// Runs `read` and logs what it found: the count, `store` and the time it took, or why the store is unreadable.
pub fn read_logged(
    store: &str,
    read: impl FnOnce() -> Result<Vec<LocalCertificate>, StoreUnreadable>,
) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
    let started = Instant::now();
    let read = read();
    match &read {
        Ok(found) => log::info!(
            "certificates read: {} in {store}, {} ms",
            found.len(),
            started.elapsed().as_millis()
        ),
        Err(error) => log::warn!("cannot read {store}: {error}"),
    }
    read
}

fn instant(seconds: i64) -> SystemTime {
    let distance = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        UNIX_EPOCH - distance
    } else {
        UNIX_EPOCH + distance
    }
}

/// Uppercase hex pairs with colons, without the leading zero bytes that only keep the number positive.
fn serial(raw: &[u8]) -> String {
    let start = raw
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(raw.len().saturating_sub(1));
    let pairs: Vec<String> = raw[start..]
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    pairs.join(":")
}

fn uses(cert: &X509Certificate<'_>) -> Vec<Use> {
    let Ok(Some(usage)) = cert.extended_key_usage() else {
        return Vec::new();
    };
    let usage = usage.value;
    let named = [
        (usage.client_auth, Use::ClientAuth),
        (usage.server_auth, Use::ServerAuth),
        (usage.code_signing, Use::CodeSigning),
        (usage.email_protection, Use::EmailProtection),
        (usage.time_stamping, Use::TimeStamping),
        (usage.ocsp_signing, Use::OcspSigning),
        (usage.any, Use::Any),
    ];
    named
        .into_iter()
        .filter_map(|(present, kind)| present.then_some(kind))
        .chain(usage.other.iter().map(|oid| Use::Other(oid.to_id_string())))
        .collect()
}

fn alternative_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(names)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(text) | GeneralName::RFC822Name(text) | GeneralName::URI(text) => {
                Some((*text).to_owned())
            }
            GeneralName::IPAddress(bytes) => ip_address(bytes),
            GeneralName::OtherName(kind, value) if *kind == oid!(1.3.6.1.4.1.311.20.2.3) => {
                principal_name(value)
            }
            _ => None,
        })
        .collect()
}

/// The user principal name of a Windows sign-in certificate: a UTF-8 string inside an explicit tag.
fn principal_name(value: &[u8]) -> Option<String> {
    let (_, tagged) = Any::from_der(value).ok()?;
    let (_, name) = <&str>::from_der(tagged.data).ok()?;
    Some(name.to_owned())
}

fn ip_address(bytes: &[u8]) -> Option<String> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        Some(IpAddr::from(octets).to_string())
    } else {
        <[u8; 16]>::try_from(bytes)
            .ok()
            .map(|octets| IpAddr::from(octets).to_string())
    }
}

fn key_algorithm(cert: &X509Certificate<'_>) -> KeyAlgorithm {
    let info = cert.public_key();
    let algorithm = &info.algorithm.algorithm;
    if *algorithm == oid!(1.3.101.112) {
        return KeyAlgorithm::Ed25519;
    }
    match info.parsed() {
        Ok(PublicKey::RSA(rsa)) => KeyAlgorithm::Rsa {
            bits: rsa.key_size(),
        },
        Ok(PublicKey::EC(_)) => info
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .map_or_else(
                || KeyAlgorithm::Other(algorithm.to_id_string()),
                |curve| KeyAlgorithm::Ec {
                    curve: curve_name(&curve),
                },
            ),
        _ => KeyAlgorithm::Other(algorithm.to_id_string()),
    }
}

fn curve_name(curve: &x509_parser::der_parser::oid::Oid<'_>) -> String {
    if *curve == oid!(1.2.840.10045.3.1.7) {
        "P-256".to_owned()
    } else if *curve == oid!(1.3.132.0.34) {
        "P-384".to_owned()
    } else if *curve == oid!(1.3.132.0.35) {
        "P-521".to_owned()
    } else {
        curve.to_id_string()
    }
}
