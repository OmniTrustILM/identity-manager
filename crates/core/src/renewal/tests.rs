use std::time::UNIX_EPOCH;

use super::*;
use crate::identity::Fingerprint;
use crate::ilm::certificates::{RaProfile, Related, Relation, RenewalInfo, ValidationStatus};

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn now() -> SystemTime {
    UNIX_EPOCH + DAY * 1_000
}

fn local(expires_in_days: u32, location: KeyLocation, key: KeyAlgorithm) -> LocalCertificate {
    LocalCertificate {
        fingerprint: Fingerprint::of(b"certificate"),
        name: "Ada".to_owned(),
        subject: "CN=Ada".to_owned(),
        issuer: "Root".to_owned(),
        issuer_name: "CN=Root".to_owned(),
        serial: "01".to_owned(),
        not_before: now() - DAY,
        not_after: now() + DAY * expires_in_days,
        uses: Vec::new(),
        alternative_names: Vec::new(),
        key,
        location,
        card: None,
        sign_in: Ok(()),
    }
}

fn keychain_ec(expires_in_days: u32) -> LocalCertificate {
    local(
        expires_in_days,
        KeyLocation::Keychain,
        KeyAlgorithm::Ec {
            curve: "P-384".to_owned(),
        },
    )
}

fn ilm() -> IlmCertificate {
    IlmCertificate {
        uuid: "c-1".to_owned(),
        name: "Ada".to_owned(),
        subject_dn: None,
        issuer_name: None,
        serial: None,
        not_before: None,
        not_after: None,
        fingerprint: None,
        key: None,
        state: State::Issued,
        validation_status: ValidationStatus::Valid,
        ra_profile: Some(RaProfile {
            uuid: "r-1".to_owned(),
            name: "People".to_owned(),
            authority_uuid: None,
        }),
        owner: None,
        groups: Vec::new(),
        archived: false,
    }
}

fn allowed() -> Vec<String> {
    vec!["renew".to_owned(), "revoke".to_owned()]
}

fn detail() -> IssuedState {
    IssuedState {
        state: State::Issued,
        content: None,
        subject_dn: None,
        alternative_names: Vec::new(),
        request_attached: false,
        registration: None,
        renewal: None,
        related: Vec::new(),
        source_certificate: None,
        ra_profile: None,
    }
}

fn related(uuid: &str, state: State, relation: Relation) -> Related {
    Related {
        uuid: uuid.to_owned(),
        state,
        relation,
    }
}

fn facts(installed: &HashSet<String>) -> Facts<'_> {
    Facts {
        now: now(),
        warn_days: WarnDays::new(30).unwrap(),
        choice: Choice::NewKey,
        waiting: false,
        installed,
        last_failure: None,
    }
}

fn window(due: bool) -> Option<RenewalInfo> {
    Some(RenewalInfo {
        window_start: None,
        window_end: None,
        due,
    })
}

#[test]
fn an_issued_certificate_with_a_profile_and_the_renew_action_is_a_candidate() {
    assert_eq!(candidate(&ilm(), &allowed()), Ok(()));
}

#[test]
fn each_candidate_rule_names_what_fails() {
    let mut not_issued = ilm();
    not_issued.state = State::Revoked;
    assert_eq!(candidate(&not_issued, &allowed()), Err(Skip::NotIssued));
    let mut archived = ilm();
    archived.archived = true;
    assert_eq!(candidate(&archived, &allowed()), Err(Skip::Archived));
    let mut bare = ilm();
    bare.ra_profile = None;
    assert_eq!(candidate(&bare, &allowed()), Err(Skip::NoRaProfile));
    assert_eq!(
        candidate(&ilm(), &["revoke".to_owned()]),
        Err(Skip::RenewNotAllowed)
    );
    assert_eq!(candidate(&ilm(), &[]), Err(Skip::RenewNotAllowed));
}

#[test]
fn ilm_saying_due_makes_the_certificate_due_whatever_the_expiry() {
    let installed = HashSet::new();
    let mut found = detail();
    found.renewal = window(true);
    assert_eq!(due(&keychain_ec(300), &found, &facts(&installed)), Due::Yes);
}

#[test]
fn ilm_saying_not_due_overrules_a_near_expiry() {
    let installed = HashSet::new();
    let mut found = detail();
    found.renewal = window(false);
    assert_eq!(due(&keychain_ec(2), &found, &facts(&installed)), Due::Not);
}

#[test]
fn without_a_renewal_window_the_warning_days_decide() {
    let installed = HashSet::new();
    let facts = facts(&installed);
    assert_eq!(due(&keychain_ec(31), &detail(), &facts), Due::Not);
    assert_eq!(due(&keychain_ec(30), &detail(), &facts), Due::Yes);
    assert_eq!(due(&keychain_ec(1), &detail(), &facts), Due::Yes);
    assert_eq!(due(&keychain_ec(0), &detail(), &facts), Due::Yes);
}

#[test]
fn a_due_certificate_is_skipped_for_each_reason() {
    let installed = HashSet::new();
    let mut found = detail();
    found.renewal = window(true);
    let skipped = |facts: Facts| due(&keychain_ec(5), &found, &facts);

    assert_eq!(
        skipped(Facts {
            choice: Choice::Off,
            ..facts(&installed)
        }),
        Due::Skipped(Skip::Off)
    );
    assert_eq!(
        skipped(Facts {
            waiting: true,
            ..facts(&installed)
        }),
        Due::Skipped(Skip::Waiting)
    );
    assert_eq!(
        skipped(Facts {
            last_failure: Some(now() - DAY / 2),
            ..facts(&installed)
        }),
        Due::Skipped(Skip::RecentFailure)
    );
}

#[test]
fn a_failed_attempt_is_forgotten_after_24_hours() {
    let installed = HashSet::new();
    let mut found = detail();
    found.renewal = window(true);
    let after = |ago: Duration| {
        due(
            &keychain_ec(5),
            &found,
            &Facts {
                last_failure: Some(now() - ago),
                ..facts(&installed)
            },
        )
    };
    assert_eq!(
        after(RETRY_AFTER - Duration::from_secs(1)),
        Due::Skipped(Skip::RecentFailure)
    );
    assert_eq!(after(RETRY_AFTER), Due::Yes);
    assert_eq!(after(DAY * 2), Due::Yes);
}

#[test]
fn a_failure_after_now_counts_as_recent() {
    let installed = HashSet::new();
    let mut found = detail();
    found.renewal = window(true);
    let due_with = Facts {
        last_failure: Some(now() + Duration::from_secs(3600)),
        ..facts(&installed)
    };

    assert_eq!(
        due(&keychain_ec(5), &found, &due_with),
        Due::Skipped(Skip::RecentFailure)
    );
}

#[test]
fn a_successor_in_flight_in_ilm_skips_the_renewal() {
    let installed = HashSet::new();
    for state in [
        State::Requested,
        State::PendingApproval,
        State::PendingIssue,
    ] {
        let mut found = detail();
        found.renewal = window(true);
        found.related = vec![related("c-2", state, Relation::Pending)];
        assert_eq!(
            due(&keychain_ec(5), &found, &facts(&installed)),
            Due::Skipped(Skip::SuccessorPending)
        );
    }
    let mut finished = detail();
    finished.renewal = window(true);
    finished.related = vec![
        related("c-2", State::Failed, Relation::Renewal),
        related("c-3", State::Rejected, Relation::Rekey),
    ];
    assert_eq!(
        due(&keychain_ec(5), &finished, &facts(&installed)),
        Due::Yes
    );
}

#[test]
fn a_successor_installed_here_means_replaced_even_when_not_due() {
    let installed = HashSet::from(["c-2".to_owned()]);
    for relation in [Relation::Renewal, Relation::Rekey, Relation::Replacement] {
        let mut found = detail();
        found.renewal = window(true);
        found.related = vec![related("c-2", State::Issued, relation)];
        assert_eq!(
            due(&keychain_ec(5), &found, &facts(&installed)),
            Due::Skipped(Skip::Replaced)
        );
    }
    let mut quiet = detail();
    quiet.related = vec![related("c-2", State::Issued, Relation::Renewal)];
    assert_eq!(
        due(&keychain_ec(300), &quiet, &facts(&installed)),
        Due::Skipped(Skip::Replaced)
    );
}

#[test]
fn a_successor_not_installed_here_does_not_replace() {
    let installed = HashSet::from(["other".to_owned()]);
    let mut found = detail();
    found.renewal = window(true);
    found.related = vec![related("c-2", State::Issued, Relation::Renewal)];
    assert_eq!(due(&keychain_ec(5), &found, &facts(&installed)), Due::Yes);
}

fn offer(storage: Storage, types: &[KeyType]) -> Offer {
    Offer {
        storage,
        types: types.to_vec(),
    }
}

fn everything() -> Vec<Offer> {
    let all = [
        KeyType::Rsa { bits: 3072 },
        KeyType::EcP256,
        KeyType::EcP384,
    ];
    vec![
        offer(Storage::Keychain, &all),
        offer(Storage::Software, &all),
        offer(Storage::Tpm, &all),
    ]
}

fn chosen(
    location: KeyLocation,
    key: KeyAlgorithm,
    choice: Choice,
    offers: &[Offer],
    reproducible: bool,
) -> Method {
    method(
        &local(5, location, key),
        choice,
        offers,
        reproducible,
        Platform::Windows,
    )
    .unwrap()
}

fn ec(curve: &str) -> KeyAlgorithm {
    KeyAlgorithm::Ec {
        curve: curve.to_owned(),
    }
}

#[test]
fn a_new_key_goes_to_the_storage_of_the_old_one() {
    for (location, storage) in [
        (KeyLocation::Keychain, Storage::Keychain),
        (KeyLocation::Software, Storage::Software),
        (KeyLocation::Tpm, Storage::Tpm),
    ] {
        assert_eq!(
            chosen(location, ec("P-384"), Choice::NewKey, &everything(), true),
            Method::NewKey {
                storage,
                key_type: KeyType::EcP384
            }
        );
    }
}

#[test]
fn the_key_type_is_the_old_one_else_p256_else_the_first_offered() {
    let rsa = KeyAlgorithm::Rsa { bits: 3072 };
    let only = |types: &[KeyType]| vec![offer(Storage::Software, types)];
    let new_key = |key: KeyAlgorithm, offers: &[Offer]| {
        chosen(KeyLocation::Software, key, Choice::NewKey, offers, true)
    };
    let software = |key_type| Method::NewKey {
        storage: Storage::Software,
        key_type,
    };
    assert_eq!(
        new_key(
            rsa.clone(),
            &only(&[KeyType::EcP256, KeyType::Rsa { bits: 3072 }])
        ),
        software(KeyType::Rsa { bits: 3072 })
    );
    assert_eq!(
        new_key(rsa.clone(), &only(&[KeyType::EcP384, KeyType::EcP256])),
        software(KeyType::EcP256)
    );
    assert_eq!(
        new_key(rsa, &only(&[KeyType::EcP521, KeyType::EcP384])),
        software(KeyType::EcP521)
    );
    assert_eq!(
        new_key(
            KeyAlgorithm::Ed25519,
            &only(&[KeyType::EcP384, KeyType::EcP256])
        ),
        software(KeyType::EcP256)
    );
    assert_eq!(
        new_key(ec("P-521"), &only(&[KeyType::Rsa { bits: 2048 }])),
        software(KeyType::Rsa { bits: 2048 })
    );
}

#[test]
fn the_same_key_is_used_when_nothing_else_can_be() {
    let offers = everything();
    let renew = |location, choice, offers: &[Offer], reproducible| {
        chosen(location, ec("P-256"), choice, offers, reproducible)
    };
    assert_eq!(
        renew(KeyLocation::Keychain, Choice::SameKey, &offers, true),
        Method::SameKey
    );
    assert_eq!(
        renew(KeyLocation::Keychain, Choice::Off, &offers, true),
        Method::SameKey
    );
    assert_eq!(
        renew(KeyLocation::Keychain, Choice::NewKey, &offers, false),
        Method::SameKey
    );
    for location in [
        KeyLocation::SmartCard,
        KeyLocation::SecureEnclave,
        KeyLocation::Unknown,
    ] {
        assert_eq!(
            renew(location, Choice::NewKey, &offers, true),
            Method::SameKey
        );
    }
}

#[test]
fn a_storage_policy_or_the_computer_does_not_offer_means_the_same_key() {
    let without_keychain = vec![
        offer(Storage::Software, &[KeyType::EcP256]),
        offer(Storage::Tpm, &[KeyType::EcP256]),
    ];
    assert_eq!(
        chosen(
            KeyLocation::Keychain,
            ec("P-256"),
            Choice::NewKey,
            &without_keychain,
            true
        ),
        Method::SameKey
    );
    let empty = vec![offer(Storage::Keychain, &[])];
    assert_eq!(
        chosen(
            KeyLocation::Keychain,
            ec("P-256"),
            Choice::NewKey,
            &empty,
            true
        ),
        Method::SameKey
    );
    assert_eq!(
        chosen(
            KeyLocation::Keychain,
            ec("P-256"),
            Choice::NewKey,
            &[],
            true
        ),
        Method::SameKey
    );
}

#[test]
fn a_smart_card_certificate_on_macos_needs_the_person() {
    let card = local(5, KeyLocation::SmartCard, ec("P-256"));
    for choice in [Choice::NewKey, Choice::SameKey] {
        assert_eq!(
            method(&card, choice, &everything(), true, Platform::Macos),
            Err(NeedsYou::SmartCardOnMacos)
        );
    }
    assert_eq!(
        method(
            &card,
            Choice::NewKey,
            &everything(),
            true,
            Platform::Windows
        ),
        Ok(Method::SameKey)
    );
    let enclave = local(5, KeyLocation::SecureEnclave, ec("P-256"));
    assert_eq!(
        method(
            &enclave,
            Choice::NewKey,
            &everything(),
            true,
            Platform::Macos
        ),
        Ok(Method::SameKey)
    );
}

#[test]
fn every_skip_has_its_own_code() {
    let all = [
        Skip::NotIssued,
        Skip::Archived,
        Skip::NoRaProfile,
        Skip::RenewNotAllowed,
        Skip::Replaced,
        Skip::Off,
        Skip::Waiting,
        Skip::SuccessorPending,
        Skip::RecentFailure,
    ];
    let codes: HashSet<&str> = all.iter().map(|skip| skip.code()).collect();
    assert_eq!(codes.len(), all.len());
}

fn layer(renewal: Option<Choice>) -> Layer {
    Layer {
        automatic_renewal: renewal,
        ..Layer::default()
    }
}

#[test]
fn the_choice_is_a_new_key_unless_someone_sets_it() {
    let none = layer(None);
    assert_eq!(choice(&none, &none, false), Choice::NewKey);
    assert_eq!(
        choice(&none, &layer(Some(Choice::SameKey)), false),
        Choice::SameKey
    );
    assert_eq!(choice(&none, &layer(Some(Choice::Off)), false), Choice::Off);
}

#[test]
fn a_switched_off_certificate_is_off_whatever_the_setting() {
    for setting in [Choice::NewKey, Choice::SameKey] {
        assert_eq!(
            choice(&layer(None), &layer(Some(setting)), true),
            Choice::Off
        );
    }
}

#[test]
fn policy_off_turns_everything_off_and_the_other_policies_fix_the_method_only() {
    let off = layer(Some(Choice::Off));
    assert_eq!(
        choice(&off, &layer(Some(Choice::SameKey)), false),
        Choice::Off
    );
    assert!(!permitted(&off));
    for policy in [Choice::NewKey, Choice::SameKey] {
        let fixed = layer(Some(policy));
        assert!(permitted(&fixed));
        assert_eq!(choice(&fixed, &layer(Some(Choice::SameKey)), false), policy);
        assert_eq!(choice(&fixed, &layer(None), true), Choice::Off);
    }
    assert!(permitted(&layer(None)));
}

#[test]
fn renewing_now_keeps_the_preferred_method_when_automatic_renewal_is_off() {
    assert_eq!(
        manual_choice(&layer(None), &layer(Some(Choice::Off))),
        Choice::NewKey
    );
    assert_eq!(
        manual_choice(&layer(None), &layer(Some(Choice::SameKey))),
        Choice::SameKey
    );
    assert_eq!(
        manual_choice(&layer(Some(Choice::SameKey)), &layer(Some(Choice::NewKey))),
        Choice::SameKey
    );
    assert_eq!(
        manual_choice(&layer(Some(Choice::NewKey)), &layer(Some(Choice::SameKey))),
        Choice::NewKey
    );
}
