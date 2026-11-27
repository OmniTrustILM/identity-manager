use tempfile::tempdir;

use crate::ilm::IlmUrl;

use super::*;
use crate::ilm::certificates::{RaProfile, RegistrationState};
use crate::ilm::issue::Registration;
use crate::ilm::profile::ResourceActions;
use crate::ilm::upload::RaProfileChoice;
use crate::inventory::{Prepared, SubjectKind, SubjectPart};
use crate::keys::{Offer, Storage};
use crate::requests::{Purpose, Waiting};
use crate::session::SignedInAs;
use crate::settings::Layer;

const NOW: i64 = 10 * DAY_MS;

fn ilm() -> IlmUrl {
    IlmUrl::parse("ilm.example.com").unwrap()
}

#[test]
fn nothing_is_known_without_a_file() {
    let dir = tempdir().unwrap();
    let standing = Enrolments::new(dir.path())
        .standing(&ilm(), "jdoe")
        .unwrap();

    assert_eq!(standing, Standing::default());
}

#[test]
fn what_is_done_and_what_failed_survive_a_new_instance() {
    let dir = tempdir().unwrap();
    let store = Enrolments::new(dir.path());
    store.mark_done(&ilm(), "jdoe", "ra-1").unwrap();
    store.mark_done(&ilm(), "jdoe", "ra-1").unwrap();
    store
        .record_failure(&ilm(), "jdoe", &prepared_key("c-1"), 5)
        .unwrap();

    let standing = Enrolments::new(dir.path())
        .standing(&ilm(), "jdoe")
        .unwrap();
    assert!(standing.is_done("ra-1"));
    assert!(!standing.is_done("ra-2"));
    assert!(standing.failed_within_a_day(&prepared_key("c-1"), 5 + DAY_MS - 1));
}

#[test]
fn the_file_is_versioned_and_names_the_failure_keys() {
    let dir = tempdir().unwrap();
    let store = Enrolments::new(dir.path());
    store.mark_done(&ilm(), "jdoe", "ra-1").unwrap();
    store
        .record_failure(&ilm(), "jdoe", &profile_key("ra-2"), 7)
        .unwrap();
    store
        .record_failure(&ilm(), "jdoe", &sign_in_key("c-3"), 8)
        .unwrap();

    let text = std::fs::read_to_string(dir.path().join("enrolment.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["people"][0]["ilm"], "https://ilm.example.com");
    assert_eq!(json["people"][0]["username"], "jdoe");
    assert_eq!(json["people"][0]["done"], serde_json::json!(["ra-1"]));
    assert_eq!(
        json["people"][0]["failed"],
        serde_json::json!([
            { "key": "profile:ra-2", "at": 7, "count": 1 },
            { "key": "sign-in:c-3", "at": 8, "count": 1 }
        ])
    );
}

#[test]
fn other_people_and_other_ilms_are_kept() {
    let dir = tempdir().unwrap();
    let store = Enrolments::new(dir.path());
    let other = IlmUrl::parse("other.example.com").unwrap();
    store.mark_done(&ilm(), "jdoe", "ra-1").unwrap();
    store.mark_done(&ilm(), "ada", "ra-2").unwrap();
    store.mark_done(&other, "jdoe", "ra-3").unwrap();

    assert!(store.standing(&ilm(), "jdoe").unwrap().is_done("ra-1"));
    assert!(!store.standing(&ilm(), "jdoe").unwrap().is_done("ra-2"));
    assert!(store.standing(&ilm(), "ada").unwrap().is_done("ra-2"));
    assert!(store.standing(&other, "jdoe").unwrap().is_done("ra-3"));
    assert!(!store.standing(&other, "ada").unwrap().is_done("ra-3"));
}

#[test]
fn a_failure_replaces_the_earlier_one_for_the_same_key_and_can_be_cleared() {
    let dir = tempdir().unwrap();
    let store = Enrolments::new(dir.path());
    store
        .record_failure(&ilm(), "jdoe", &profile_key("ra-1"), 1)
        .unwrap();
    store
        .record_failure(&ilm(), "jdoe", &profile_key("ra-1"), 3 * DAY_MS)
        .unwrap();
    store
        .record_failure(&ilm(), "jdoe", &profile_key("ra-2"), 3 * DAY_MS)
        .unwrap();

    let standing = store.standing(&ilm(), "jdoe").unwrap();
    assert_eq!(standing.failed.len(), 2);
    assert!(!standing.failed_within_a_day(&profile_key("ra-1"), 4 * DAY_MS));
    assert!(standing.failed_within_a_day(&profile_key("ra-1"), 3 * DAY_MS + 1));

    store
        .clear_failure(&ilm(), "jdoe", &profile_key("ra-1"))
        .unwrap();
    store
        .clear_failure(&ilm(), "jdoe", &profile_key("absent"))
        .unwrap();
    let standing = store.standing(&ilm(), "jdoe").unwrap();
    assert!(!standing.failed_within_a_day(&profile_key("ra-1"), 3 * DAY_MS + 1));
    assert!(standing.failed_within_a_day(&profile_key("ra-2"), 3 * DAY_MS + 1));
}

#[test]
fn a_failure_counts_for_exactly_a_day() {
    let standing = Standing {
        failed: vec![Failure {
            key: profile_key("ra-1"),
            at: 1_000,
            count: 1,
        }],
        ..Standing::default()
    };

    assert!(standing.failed_within_a_day(&profile_key("ra-1"), 1_000 + DAY_MS - 1));
    assert!(!standing.failed_within_a_day(&profile_key("ra-1"), 1_000 + DAY_MS));
    assert!(!standing.failed_within_a_day(&profile_key("ra-2"), 1_000));
}

#[test]
fn a_file_that_cannot_be_trusted_is_never_written_over() {
    for text in [r#"{"version": 2, "people": []}"#, "{", r#"{"version": 1}"#] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("enrolment.json");
        std::fs::write(&path, text).unwrap();
        let store = Enrolments::new(dir.path());

        assert!(store.standing(&ilm(), "jdoe").is_err());
        assert!(store.mark_done(&ilm(), "jdoe", "ra-1").is_err());
        assert!(
            store
                .record_failure(&ilm(), "jdoe", &profile_key("ra-1"), 1)
                .is_err()
        );
        assert!(
            store
                .clear_failure(&ilm(), "jdoe", &profile_key("ra-1"))
                .is_err()
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}

#[test]
fn a_file_is_read_again_once_it_can_be_read() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("enrolment.json");
    std::fs::write(&path, "{").unwrap();
    let store = Enrolments::new(dir.path());
    assert!(store.mark_done(&ilm(), "jdoe", "ra-1").is_err());

    std::fs::remove_file(&path).unwrap();

    store.mark_done(&ilm(), "jdoe", "ra-1").unwrap();
    assert!(store.standing(&ilm(), "jdoe").unwrap().is_done("ra-1"));
}

// The plan.

fn profile(uuid: &str, name: &str) -> RaProfileChoice {
    RaProfileChoice {
        uuid: uuid.to_owned(),
        name: name.to_owned(),
        description: None,
        authority: Some("Authority".to_owned()),
        authority_uuid: Some("auth-1".to_owned()),
    }
}

fn prepared(uuid: &str, registration: Option<(RegistrationState, Option<i64>)>) -> Prepared {
    Prepared {
        uuid: uuid.to_owned(),
        name: format!("name of {uuid}"),
        ra_profile: RaProfile {
            uuid: "ra-1".to_owned(),
            name: "Servers".to_owned(),
            authority_uuid: Some("auth-1".to_owned()),
        },
        registration: registration.map(|(state, expires_at)| Registration { state, expires_at }),
        subject: vec![SubjectPart::new(SubjectKind::CommonName, "demo")],
    }
}

fn waiting_for(uuid: Option<&str>, ra_profile: &str) -> Waiting {
    Waiting {
        ilm: ilm(),
        username: "jdoe".to_owned(),
        uuid: uuid.map(str::to_owned),
        ra_profile: ra_profile.to_owned(),
        authority: "auth-1".to_owned(),
        key: None,
        label: "label".to_owned(),
        since: 1,
        prepared: false,
        purpose: Purpose::Issue,
        enrolled: false,
    }
}

fn can_create(create: bool) -> SignedInAs {
    SignedInAs {
        ilm: ilm(),
        username: "jdoe".to_owned(),
        allowed_listings: Vec::new(),
        allowed_actions: vec![ResourceActions {
            resource: "certificates".to_owned(),
            actions: if create {
                vec!["create".to_owned()]
            } else {
                vec![]
            },
        }],
    }
}

/// Everything `plan` reads, set to the case where it plans everything.
struct Case {
    policy: Layer,
    conditions: Conditions,
    who: SignedInAs,
    prepared: Vec<Prepared>,
    profiles: Vec<RaProfileChoice>,
    waiting: Vec<Waiting>,
    standing: Standing,
    offers: Vec<Offer>,
}

impl Case {
    fn new() -> Self {
        Self {
            policy: Layer {
                complete_prepared: Some(true),
                request_profiles: Some(vec!["Servers".to_owned(), "Laptops".to_owned()]),
                ..Layer::default()
            },
            conditions: Conditions {
                linux: false,
                locked: false,
                signed_in: true,
                fresh: true,
            },
            who: can_create(true),
            prepared: vec![prepared("c-1", None)],
            profiles: vec![profile("ra-1", "Servers"), profile("ra-2", "Laptops")],
            waiting: Vec::new(),
            standing: Standing::default(),
            offers: vec![Offer {
                storage: Storage::Software,
                types: Vec::new(),
            }],
        }
    }

    fn plan(&self) -> Plan {
        plan(
            NOW,
            &self.policy,
            &self.conditions,
            &self.who,
            &self.prepared,
            &self.profiles,
            &self.waiting,
            &self.standing,
            self.offers.clone(),
        )
    }

    fn completes(&self) -> Vec<String> {
        self.plan().complete.into_iter().map(|c| c.uuid).collect()
    }

    fn requests(&self) -> Vec<String> {
        self.plan().request.into_iter().map(|p| p.uuid).collect()
    }
}

fn failed(key: String, at: i64) -> Standing {
    Standing {
        failed: vec![Failure { key, at, count: 1 }],
        ..Standing::default()
    }
}

#[test]
fn everything_asked_for_is_planned() {
    let case = Case::new();

    assert_eq!(case.completes(), ["c-1"]);
    assert_eq!(case.requests(), ["ra-1", "ra-2"]);
}

#[test]
fn nothing_is_completed_with_the_switch_off() {
    for switch in [None, Some(false)] {
        let mut case = Case::new();
        case.policy.complete_prepared = switch;

        assert!(case.completes().is_empty());
        assert_eq!(case.requests(), ["ra-1", "ra-2"]);
    }
}

#[test]
fn a_registration_that_asks_for_the_challenge_stays_with_the_person() {
    let mut case = Case::new();
    case.prepared = vec![
        prepared("with", Some((RegistrationState::Active, None))),
        prepared("without", None),
        prepared("closed", Some((RegistrationState::Closed, None))),
    ];

    assert_eq!(case.completes(), ["without", "closed"]);
}

#[test]
fn an_expired_or_locked_registration_is_not_completed() {
    let mut case = Case::new();
    case.prepared = vec![
        prepared("expired", Some((RegistrationState::Expired, None))),
        prepared("locked", Some((RegistrationState::Locked, None))),
        prepared("late", Some((RegistrationState::Closed, Some(NOW - 1)))),
        prepared("open", Some((RegistrationState::Closed, Some(NOW + 1)))),
    ];

    assert_eq!(case.completes(), ["open"]);
}

#[test]
fn a_certificate_already_begun_is_not_completed_again() {
    let mut case = Case::new();
    case.prepared = vec![prepared("c-1", None), prepared("c-2", None)];
    case.waiting = vec![waiting_for(Some("c-1"), "ra-1")];

    assert_eq!(case.completes(), ["c-2"]);
}

#[test]
fn a_failed_completion_is_tried_again_after_a_day() {
    let mut case = Case::new();
    case.standing = failed(prepared_key("c-1"), NOW - DAY_MS + 1);
    assert!(case.completes().is_empty());

    case.standing = failed(prepared_key("c-1"), NOW - DAY_MS);
    assert_eq!(case.completes(), ["c-1"]);

    case.standing = failed(prepared_key("other"), NOW);
    assert_eq!(case.completes(), ["c-1"]);
}

#[test]
fn a_failed_request_is_tried_again_after_a_day() {
    let mut case = Case::new();
    case.standing = failed(profile_key("ra-1"), NOW - DAY_MS + 1);
    assert_eq!(case.requests(), ["ra-2"]);

    case.standing = failed(profile_key("ra-1"), NOW - DAY_MS);
    assert_eq!(case.requests(), ["ra-1", "ra-2"]);
}

#[test]
fn a_profile_requested_once_is_not_requested_again() {
    let mut case = Case::new();
    case.standing.done = vec!["ra-1".to_owned()];

    assert_eq!(case.requests(), ["ra-2"]);
}

#[test]
fn a_profile_with_only_a_waiting_revocation_is_still_requested() {
    let mut case = Case::new();
    let mut revocation = waiting_for(Some("c-9"), "ra-1");
    revocation.purpose = Purpose::Revoke {
        certificate: "c-9".to_owned(),
        fingerprint: crate::identity::Fingerprint::of(b"old"),
        remove: false,
    };
    case.waiting = vec![revocation];

    assert_eq!(case.requests(), ["ra-1", "ra-2"]);
}

#[test]
fn a_profile_with_a_waiting_request_is_not_requested_again() {
    let mut case = Case::new();
    case.waiting = vec![waiting_for(None, "ra-2")];

    assert_eq!(case.requests(), ["ra-1"]);
}

#[test]
fn only_the_profiles_ilm_lists_are_requested_and_matched_by_exact_name() {
    let mut case = Case::new();
    case.policy.request_profiles = Some(vec![
        "Servers".to_owned(),
        "servers".to_owned(),
        "Unknown".to_owned(),
    ]);

    assert_eq!(case.requests(), ["ra-1"]);
}

#[test]
fn a_profile_named_twice_is_requested_once() {
    let mut case = Case::new();
    case.policy.request_profiles = Some(vec!["Servers".to_owned(), "Servers".to_owned()]);

    assert_eq!(case.requests(), ["ra-1"]);
}

#[test]
fn nothing_is_requested_without_the_permission_to_create_certificates() {
    let mut case = Case::new();
    case.who = can_create(false);

    assert!(case.requests().is_empty());
    assert_eq!(case.completes(), ["c-1"]);
}

#[test]
fn nothing_is_requested_when_policy_names_no_profile() {
    let mut case = Case::new();
    case.policy.request_profiles = None;

    assert!(case.requests().is_empty());
    assert_eq!(case.completes(), ["c-1"]);
}

#[test]
fn nothing_enrols_where_it_cannot_run() {
    let broken: [fn(&mut Case); 5] = [
        |case| case.conditions.linux = true,
        |case| case.conditions.locked = true,
        |case| case.conditions.signed_in = false,
        |case| case.conditions.fresh = false,
        |case| case.offers.clear(),
    ];
    for breaks in broken {
        let mut case = Case::new();
        breaks(&mut case);

        assert_eq!(case.plan(), Plan::default());
    }
}

#[test]
fn no_storage_allowed_by_policy_stops_enrolment() {
    let mut case = Case::new();
    case.policy.key_storages = Some(vec![Storage::Tpm]);

    assert_eq!(case.plan(), Plan::default());

    case.policy.key_storages = Some(vec![Storage::Software]);
    assert_eq!(case.completes(), ["c-1"]);
}

#[test]
fn failures_are_counted_until_cleared_and_installed_certificates_are_kept_once() {
    let dir = tempdir().unwrap();
    let store = Enrolments::new(dir.path());
    let key = sign_in_key("c-1");
    for at in [1, 2] {
        store.record_failure(&ilm(), "jdoe", &key, at).unwrap();
    }
    store.mark_installed(&ilm(), "jdoe", "c-1").unwrap();
    store.mark_installed(&ilm(), "jdoe", "c-1").unwrap();

    let standing = store.standing(&ilm(), "jdoe").unwrap();
    assert_eq!(standing.failures(&key), 2);
    assert_eq!(standing.installed, vec!["c-1".to_owned()]);

    store.clear_failure(&ilm(), "jdoe", &key).unwrap();
    store.clear_installed(&ilm(), "jdoe", "c-1").unwrap();
    let standing = store.standing(&ilm(), "jdoe").unwrap();
    assert_eq!(standing.failures(&key), 0);
    assert!(standing.installed.is_empty());
}
