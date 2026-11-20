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
    let _ = Arc::strong_count(&system_store(Arc::new(NoProviders)));
}

mod listing {
    use super::super::certificate::{
        KeyAlgorithm, KeyLocation, LocalCertificate, LocalCertificateView, Use, describe,
        describe_all,
    };
    use super::*;

    fn described(issue: Issue) -> LocalCertificate {
        describe(&der_of(issue), KeyLocation::Keychain, now()).expect("a described certificate")
    }

    fn uses(usage: Usage) -> Vec<Use> {
        described(Issue::client("a").usage(usage)).uses
    }

    #[test]
    fn a_certificate_is_described_with_names_validity_and_where_its_key_is() {
        let ca = TestCa::new();
        let identity = ca.issue(Issue::client("Roman").valid((2020, 1, 1), (2099, 1, 1)));
        let found = describe(identity.leaf(), KeyLocation::SmartCard, now()).unwrap();
        assert_eq!(found.fingerprint, identity.fingerprint());
        assert_eq!(found.name, "Roman");
        assert_eq!(found.subject, "CN=Roman");
        assert_eq!(found.issuer, "Test Root CA");
        assert_eq!(found.issuer_name, "CN=Test Root CA");
        assert_eq!(
            found.not_before,
            UNIX_EPOCH + Duration::from_secs(1_577_836_800)
        );
        assert_eq!(
            found.not_after,
            UNIX_EPOCH + Duration::from_secs(4_070_908_800)
        );
        assert_eq!(found.location, KeyLocation::SmartCard);
        assert_eq!(found.sign_in, Ok(()));
    }

    #[test]
    fn a_name_without_common_name_is_shown_whole_and_the_subject_is_the_full_name() {
        let found = described(Issue::client(""));
        assert_eq!(found.name, "O=No Common Name");
        assert_eq!(found.subject, "O=No Common Name");
    }

    #[test]
    fn the_extended_key_usage_gives_the_uses() {
        assert_eq!(uses(Usage::ClientAuth), [Use::ClientAuth]);
        assert_eq!(uses(Usage::ServerAuth), [Use::ServerAuth]);
        assert_eq!(
            uses(Usage::ClientAndServerAuth),
            [Use::ClientAuth, Use::ServerAuth]
        );
        assert_eq!(uses(Usage::CodeSigning), [Use::CodeSigning]);
        assert_eq!(uses(Usage::EmailProtection), [Use::EmailProtection]);
        assert_eq!(uses(Usage::TimeStamping), [Use::TimeStamping]);
        assert_eq!(uses(Usage::OcspSigning), [Use::OcspSigning]);
        assert_eq!(uses(Usage::Any), [Use::Any]);
        assert_eq!(uses(Usage::Unnamed), [Use::Other("1.2.3.4".to_owned())]);
        assert_eq!(uses(Usage::Unrestricted), []);
    }

    #[test]
    fn alternative_names_are_the_dns_names_and_e_mail_addresses() {
        let found = described(
            Issue::client("a")
                .dns_names(&["a.example.com", "b.example.com"])
                .emails(&["jane@example.com"]),
        );
        assert_eq!(
            found.alternative_names,
            ["a.example.com", "b.example.com", "jane@example.com"]
        );
        assert!(described(Issue::client("a")).alternative_names.is_empty());
    }

    #[test]
    fn a_user_principal_name_is_an_alternative_name() {
        let found = described(Issue::client("a").principal_names(&["jane@corp.example"]));
        assert_eq!(found.alternative_names, ["jane@corp.example"]);
    }

    #[test]
    fn a_validity_before_1970_is_kept() {
        let found = described(Issue::client("a").valid((1960, 1, 1), (2099, 1, 1)));
        assert_eq!(
            found.not_before,
            UNIX_EPOCH - Duration::from_secs(315_619_200)
        );
        assert_eq!(
            LocalCertificateView::from(&found).not_before,
            -315_619_200_000
        );
    }

    #[test]
    fn the_key_algorithm_comes_from_the_certificate() {
        let key = |alg| described(Issue::client("a").key(alg)).key;
        let ec = |curve: &str| KeyAlgorithm::Ec {
            curve: curve.to_owned(),
        };
        assert_eq!(key(KeyAlg::Rsa2048), KeyAlgorithm::Rsa { bits: 2048 });
        assert_eq!(key(KeyAlg::Rsa3072), KeyAlgorithm::Rsa { bits: 3072 });
        assert_eq!(key(KeyAlg::P256), ec("P-256"));
        assert_eq!(key(KeyAlg::P384), ec("P-384"));
        assert_eq!(key(KeyAlg::P521), ec("P-521"));
        assert_eq!(key(KeyAlg::Ed25519), KeyAlgorithm::Ed25519);
    }

    #[test]
    fn the_serial_is_uppercase_hex_pairs_with_colons() {
        let serial = described(Issue::client("a")).serial;
        assert!(!serial.is_empty());
        assert!(
            serial
                .split(':')
                .all(|pair| pair.len() == 2
                    && pair.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F'))),
            "{serial}"
        );
    }

    #[test]
    fn the_sign_in_check_is_the_one_of_the_reader() {
        let sign_in = |issue: Issue| described(issue).sign_in;
        assert_eq!(sign_in(Issue::client("a")), Ok(()));
        assert_eq!(
            sign_in(Issue::client("a").valid((2000, 1, 1), (2001, 1, 1))),
            Err(Rejection::Expired)
        );
        assert_eq!(
            sign_in(Issue::client("a").valid((2098, 1, 1), (2099, 1, 1))),
            Err(Rejection::NotYetValid)
        );
        assert_eq!(
            sign_in(Issue::client("a").usage(Usage::CodeSigning)),
            Err(Rejection::NotForClientAuth)
        );
        assert_eq!(
            sign_in(Issue::client("a").key(KeyAlg::Ed25519)),
            Err(Rejection::UnsupportedKey)
        );
    }

    #[test]
    fn bytes_that_are_not_a_certificate_are_not_described() {
        assert_eq!(
            describe(b"not a certificate", KeyLocation::Unknown, now()),
            None
        );
    }

    fn view_of(found: &LocalCertificate) -> serde_json::Value {
        serde_json::to_value(LocalCertificateView::from(found)).unwrap()
    }

    #[test]
    fn the_view_has_the_text_of_the_list_and_nothing_of_the_certificate_itself() {
        let identity = TestCa::new().issue(
            Issue::client("Ada")
                .emails(&["ada@example.com"])
                .valid((2020, 1, 1), (2099, 1, 1)),
        );
        let found = describe(identity.leaf(), KeyLocation::Tpm, now()).unwrap();
        let view = view_of(&found);
        let mut keys: Vec<&str> = view
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "alternativeNames",
                "canSignIn",
                "fingerprint",
                "issuer",
                "issuerName",
                "key",
                "location",
                "name",
                "notAfter",
                "notBefore",
                "serial",
                "signInProblem",
                "subject",
                "uses"
            ]
        );
        assert_eq!(view["fingerprint"], identity.fingerprint().to_string());
        assert_eq!(view["name"], "Ada");
        assert_eq!(view["subject"], "CN=Ada");
        assert_eq!(view["issuer"], "Test Root CA");
        assert_eq!(view["issuerName"], "CN=Test Root CA");
        assert_eq!(view["notBefore"], 1_577_836_800_000_i64);
        assert_eq!(view["notAfter"], 4_070_908_800_000_i64);
        assert_eq!(
            view["alternativeNames"],
            serde_json::json!(["ada@example.com"])
        );
        assert_eq!(view["location"], "tpm");
        assert_eq!(view["canSignIn"], true);
        assert_eq!(view["signInProblem"], serde_json::Value::Null);
    }

    #[test]
    fn the_view_names_why_a_certificate_cannot_sign_in() {
        let found = described(Issue::client("old").valid((2000, 1, 1), (2001, 1, 1)));
        let view = view_of(&found);
        assert_eq!(view["canSignIn"], false);
        assert_eq!(view["signInProblem"], "has expired");
    }

    #[test]
    fn the_view_tells_uses_and_key_algorithms_apart_by_kind() {
        let found = described(Issue::client("a").usage(Usage::Unnamed));
        let view = view_of(&found);
        assert_eq!(
            view["uses"],
            serde_json::json!([{ "kind": "other", "value": "1.2.3.4" }])
        );
        assert_eq!(view["key"]["kind"], "ec");
        assert_eq!(view["key"]["value"]["curve"], "P-256");
        assert_eq!(
            serde_json::to_value(Use::ClientAuth).unwrap(),
            serde_json::json!({ "kind": "clientAuth" })
        );
        assert_eq!(
            serde_json::to_value(KeyAlgorithm::Rsa { bits: 3072 }).unwrap(),
            serde_json::json!({ "kind": "rsa", "value": { "bits": 3072 } })
        );
        assert_eq!(
            serde_json::to_value(KeyLocation::SecureEnclave).unwrap(),
            "secureEnclave"
        );
    }

    #[test]
    fn windows_providers_stand_for_their_locations() {
        use KeyLocation as L;
        for (name, expected) in [
            ("Microsoft Platform Crypto Provider", L::Tpm),
            ("Microsoft Smart Card Key Storage Provider", L::SmartCard),
            ("Microsoft Base Smart Card Crypto Provider", L::SmartCard),
            ("Vendor Smart Card Provider", L::SmartCard),
            ("Microsoft Software Key Storage Provider", L::Software),
            ("microsoft software key storage provider", L::Software),
            (
                "Microsoft Enhanced RSA and AES Cryptographic Provider",
                L::Software,
            ),
            (
                "Microsoft Enhanced Cryptographic Provider v1.0",
                L::Software,
            ),
            ("Microsoft Base Cryptographic Provider v1.0", L::Software),
            ("Microsoft Strong Cryptographic Provider", L::Software),
            ("Microsoft Base DSS Cryptographic Provider", L::Software),
            ("Microsoft DH SChannel Cryptographic Provider", L::Software),
            ("Some Vendor HSM Provider", L::Unknown),
            ("", L::Unknown),
        ] {
            assert_eq!(L::from_windows_provider(name), expected, "{name}");
        }
    }

    #[test]
    fn the_list_is_ordered_by_name_without_case_then_latest_expiry_then_fingerprint() {
        let ca = TestCa::new();
        let issue = |name: &str, until: i32| {
            ca.issue(Issue::client(name).valid((2020, 1, 1), (until, 1, 1)))
        };
        let (zed, beta, alpha_late, alpha_soon, alpha_twin) = (
            issue("zed", 2090),
            issue("beta", 2090),
            issue("Alpha", 2090),
            issue("alpha", 2050),
            issue("alpha", 2050),
        );
        let all = [&zed, &beta, &alpha_soon, &alpha_late, &alpha_twin];
        let store =
            StandInStore::new(all.iter().map(|identity| (*identity).clone()).collect()).at(now());
        let listed = store.certificates().unwrap();
        let names: Vec<&str> = listed.iter().map(|found| found.name.as_str()).collect();
        assert_eq!(names, ["Alpha", "alpha", "alpha", "beta", "zed"]);
        let (first, second) = (listed[1].fingerprint, listed[2].fingerprint);
        assert!(first < second);
        let twins = [alpha_soon.fingerprint(), alpha_twin.fingerprint()];
        assert!(twins.contains(&first) && twins.contains(&second));
    }

    #[test]
    fn certificates_that_are_listed_but_cannot_sign_in_are_not_candidates() {
        let ca = TestCa::new();
        let good = ca.issue(Issue::client("good"));
        let server = ca.issue(Issue::client("server").usage(Usage::ServerAuth));
        let expired = ca.issue(Issue::client("expired").valid((2000, 1, 1), (2001, 1, 1)));
        let store = StandInStore::new(vec![server, expired, good.clone()]).at(now());
        assert_eq!(store.certificates().unwrap().len(), 3);
        let candidates = store.candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].fingerprint, good.fingerprint());
        assert_eq!(candidates[0].subject, "good");
        assert_eq!(candidates[0].issuer, "Test Root CA");
    }

    #[test]
    fn candidates_follow_the_list_but_with_the_latest_expiry_first() {
        let ca = TestCa::new();
        let identity = |name: &str, until: i32| {
            ca.issue(Issue::client(name).valid((2020, 1, 1), (until, 1, 1)))
        };
        let store = StandInStore::new(vec![
            identity("a", 2050),
            identity("b", 2090),
            identity("c", 2070),
        ])
        .at(now());
        let listed: Vec<String> = store
            .certificates()
            .unwrap()
            .into_iter()
            .map(|c| c.name)
            .collect();
        let offered: Vec<String> = store.candidates().into_iter().map(|c| c.subject).collect();
        assert_eq!(listed, ["a", "b", "c"]);
        assert_eq!(offered, ["b", "c", "a"]);
    }

    struct Unreadable;

    impl IdentityStore for Unreadable {
        fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
            Err(StoreUnreadable("the store is locked".to_owned()))
        }

        fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
            None
        }
    }

    #[test]
    fn an_unreadable_store_offers_no_candidates() {
        assert!(Unreadable.candidates().is_empty());
        assert_eq!(
            Unreadable.certificates().unwrap_err().to_string(),
            "the store is locked"
        );
    }

    #[test]
    fn the_stand_in_store_reports_where_the_keys_are() {
        let identity = TestCa::new().issue(Issue::client("a"));
        let store = StandInStore::new(vec![identity]).at(now());
        assert_eq!(
            store.certificates().unwrap()[0].location,
            KeyLocation::Unknown
        );
        let store = store.located(KeyLocation::Tpm);
        assert_eq!(store.certificates().unwrap()[0].location, KeyLocation::Tpm);
    }

    #[test]
    fn the_empty_store_lists_nothing_and_no_provider_knows_a_key() {
        assert_eq!(EmptyStore.certificates(), Ok(Vec::new()));
        assert_eq!(NoProviders.provider_name(b"der"), None);
    }

    #[test]
    fn describing_a_list_skips_what_cannot_be_parsed() {
        let identity = TestCa::new().issue(Issue::client("a"));
        let items: [(&[u8], KeyLocation); 2] = [
            (b"junk", KeyLocation::Unknown),
            (identity.leaf().as_ref(), KeyLocation::Keychain),
        ];
        let listed = describe_all(items, now());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].fingerprint, identity.fingerprint());
    }
}
