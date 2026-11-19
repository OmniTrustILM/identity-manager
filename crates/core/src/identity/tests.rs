use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;

use super::testing::{Issue, KeyAlg, StandInStore, TestCa, Usage};
use super::*;

/// 2027-01-01, inside the validity of the certificates of [`Issue::client`].
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_798_761_600)
}

fn rejection(der: &[u8]) -> Option<Rejection> {
    assess(der, now()).err()
}

fn der_of(issue: Issue) -> Vec<u8> {
    TestCa::new().issue(issue).leaf().to_vec()
}

#[test]
fn fingerprint_is_uppercase_hex_with_colons() {
    let fingerprint = Fingerprint::of(b"certificate");
    let text = fingerprint.to_string();
    assert_eq!(text.len(), 32 * 3 - 1);
    assert!(
        text.split(':')
            .all(|pair| pair.len() == 2 && pair.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')))
    );
    assert_eq!(
        Fingerprint::of(b"").to_string(),
        "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
    );
}

#[test]
fn short_fingerprint_is_the_first_four_bytes() {
    assert_eq!(Fingerprint::of(b"").short(), "E3:B0:C4:42");
}

#[test]
fn fingerprint_parses_with_or_without_colons_in_any_case() {
    let fingerprint = Fingerprint::of(b"certificate");
    let plain = fingerprint.to_string().replace(':', "").to_lowercase();
    assert_eq!(fingerprint.to_string().parse(), Ok(fingerprint));
    assert_eq!(plain.parse(), Ok(fingerprint));
    for bad in [
        "",
        "AB:CD",
        "zz",
        &plain[..63],
        &format!("{plain}0"),
        &format!("{plain}00"),
    ] {
        assert_eq!(bad.parse::<Fingerprint>(), Err(InvalidFingerprint), "{bad}");
    }
}

#[test]
fn a_good_certificate_passes_with_its_names_and_expiry() {
    let ca = TestCa::new();
    let identity = ca.issue(Issue::client("Roman"));
    let assessed = assess(identity.leaf(), now()).unwrap();
    assert_eq!(assessed.key, KeyKind::EcdsaP256);
    assert_eq!(assessed.candidate.fingerprint, identity.fingerprint());
    assert_eq!(assessed.candidate.subject, "Roman");
    assert_eq!(assessed.candidate.issuer, "Test Root CA");
    assert_eq!(
        assessed.candidate.not_after,
        UNIX_EPOCH + Duration::from_secs(4_070_908_800)
    );
}

#[test]
fn a_name_without_common_name_is_shown_whole() {
    let assessed = assess(&der_of(Issue::client("")), now()).unwrap();
    assert_eq!(assessed.candidate.subject, "O=No Common Name");
}

#[test]
fn expired_and_not_yet_valid_certificates_are_rejected() {
    let expired = der_of(Issue::client("a").valid((2000, 1, 1), (2001, 1, 1)));
    let early = der_of(Issue::client("a").valid((2098, 1, 1), (2099, 1, 1)));
    assert_eq!(rejection(&expired), Some(Rejection::Expired));
    assert_eq!(rejection(&early), Some(Rejection::NotYetValid));
}

#[test]
fn extended_key_usage_must_allow_client_authentication_when_present() {
    let server = der_of(Issue::server("a"));
    let none = der_of(Issue::client("a").usage(Usage::Unrestricted));
    let any = der_of(Issue::client("a").usage(Usage::Any));
    assert_eq!(rejection(&server), Some(Rejection::NotForClientAuth));
    assert_eq!(rejection(&none), None);
    assert_eq!(rejection(&any), Some(Rejection::NotForClientAuth));
}

#[test]
fn only_rsa_2048_or_more_and_p256_p384_keys_pass() {
    let kind = |alg| assess(&der_of(Issue::client("a").key(alg)), now()).map(|found| found.key);
    assert_eq!(kind(KeyAlg::P256), Ok(KeyKind::EcdsaP256));
    assert_eq!(kind(KeyAlg::P384), Ok(KeyKind::EcdsaP384));
    assert_eq!(kind(KeyAlg::Rsa2048), Ok(KeyKind::Rsa));
    assert_eq!(kind(KeyAlg::P521), Err(Rejection::UnsupportedKey));
    let weak = rustls_pemfile_free_pem(include_str!("testdata/rsa1024.pem"));
    assert_eq!(rejection(&weak), Some(Rejection::UnsupportedKey));
}

/// The DER inside a PEM block with one certificate.
fn rustls_pemfile_free_pem(pem: &str) -> Vec<u8> {
    use base64::Engine;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}

#[test]
fn bytes_that_are_not_a_certificate_are_rejected() {
    assert_eq!(rejection(b"not a certificate"), Some(Rejection::Unparsable));
}

#[test]
fn the_store_lists_what_can_sign_in_latest_expiry_first_and_skips_the_rest() {
    let ca = TestCa::new();
    let soon = ca.issue(Issue::client("soon").valid((2020, 1, 1), (2028, 1, 1)));
    let late = ca.issue(Issue::client("late").valid((2020, 1, 1), (2090, 1, 1)));
    let middle = ca.issue(Issue::client("middle").valid((2020, 1, 1), (2050, 1, 1)));
    let expired = ca.issue(Issue::client("expired").valid((2000, 1, 1), (2001, 1, 1)));
    let server = ca.issue(Issue::client("server").usage(Usage::ServerAuth));
    let store = StandInStore::new(vec![
        soon.clone(),
        expired.clone(),
        late.clone(),
        server,
        middle.clone(),
    ])
    .at(now());
    let names: Vec<String> = store
        .candidates()
        .into_iter()
        .map(|candidate| candidate.subject)
        .collect();
    assert_eq!(names, ["late", "middle", "soon"]);
    assert!(store.open(&middle.fingerprint()).is_some());
    assert!(store.open(&expired.fingerprint()).is_none());
    assert!(store.open(&Fingerprint::of(b"unknown")).is_none());
}

#[test]
fn an_opened_identity_drops_the_root_and_signs() {
    let ca = TestCa::new();
    let identity = ca.issue(Issue::client("a"));
    assert_eq!(identity.chain.len(), 2);
    let opened = identity.client_identity();
    assert_eq!(opened.chain(), [identity.leaf().clone()]);
    assert_eq!(opened.fingerprint(), Some(identity.fingerprint()));
    let signer = opened
        .signing_key()
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .unwrap();
    assert!(!signer.sign(b"message").unwrap().is_empty());
}

#[test]
fn trimming_keeps_the_leaf_and_intermediates_and_a_lone_self_signed_certificate() {
    let ca = TestCa::new();
    let leaf = ca.issue(Issue::client("a")).leaf().clone();
    let other = ca.issue(Issue::client("b")).leaf().clone();
    let root = ca.der().clone();
    let trim = |chain: Vec<CertificateDer<'static>>| trim_chain(chain).len();
    assert_eq!(trim(vec![leaf.clone(), root.clone()]), 1);
    assert_eq!(trim(vec![leaf.clone(), other, root.clone()]), 2);
    assert_eq!(trim(vec![leaf.clone()]), 1);
    assert_eq!(trim(vec![root.clone()]), 1);
    assert_eq!(trim(Vec::new()), 0);
    let rollover = ca.rollover();
    assert!(is_self_signed(&rollover) && is_self_signed(&root));
    assert_eq!(trim(vec![leaf, rollover, root]), 2);
}

#[test]
fn the_scheme_table_lists_schemes_by_key_kind() {
    use SignatureScheme as S;
    assert_eq!(KeyKind::EcdsaP256.schemes(), [S::ECDSA_NISTP256_SHA256]);
    assert_eq!(KeyKind::EcdsaP384.schemes(), [S::ECDSA_NISTP384_SHA384]);
    assert_eq!(KeyKind::Rsa.schemes().len(), 6);
    assert!(KeyKind::Rsa.schemes().contains(&S::RSA_PSS_SHA256));
    assert_eq!(KeyKind::Rsa.algorithm(), rustls::SignatureAlgorithm::RSA);
    assert_eq!(
        KeyKind::EcdsaP384.algorithm(),
        rustls::SignatureAlgorithm::ECDSA
    );
}

#[test]
fn a_kind_chooses_the_first_offered_scheme_it_supports() {
    use SignatureScheme as S;
    let offered = [S::ED25519, S::RSA_PKCS1_SHA256, S::RSA_PSS_SHA384];
    assert_eq!(KeyKind::Rsa.choose(&offered), Some(S::RSA_PKCS1_SHA256));
    assert_eq!(KeyKind::EcdsaP256.choose(&offered), None);
    assert_eq!(KeyKind::EcdsaP384.choose(&[S::ECDSA_NISTP256_SHA256]), None);
}

#[test]
fn a_refusal_is_recognised_through_the_error_chain() {
    let refused = signing_refused();
    assert!(is_signing_refused(&refused));
    let wrapped = std::io::Error::other(refused);
    assert!(is_signing_refused(&wrapped));
    assert!(!is_signing_refused(&std::io::Error::other("other")));
    assert!(Error::source(&SigningRefused).is_none());
}

#[test]
fn debug_output_names_the_certificate_and_nothing_of_the_key() {
    let identity = TestCa::new().issue(Issue::client("a"));
    let text = format!("{:?}", identity.client_identity());
    assert!(text.contains(&identity.fingerprint().to_string()));
    assert!(!text.contains("key"));
}

#[test]
fn the_empty_store_has_nothing() {
    assert!(EmptyStore.candidates().is_empty());
    assert!(EmptyStore.open(&Fingerprint::of(b"a")).is_none());
}

#[test]
fn the_system_store_can_be_asked() {
    let _ = Arc::strong_count(&system_store());
}
