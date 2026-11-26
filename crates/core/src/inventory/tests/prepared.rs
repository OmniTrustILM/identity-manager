use super::*;
use crate::ilm::certificates::{RaProfile, RegistrationState};
use crate::ilm::issue::Registration;
use crate::inventory::prepared::{Prepared, SubjectKind, SubjectPart, drop_completed};
use crate::requests::Waiting;
use crate::session::{EndReason, Followed, Outcome};

const DETAIL: &str = "/api/v1/certificates/c-1";

fn registered(uuid: &str, name: &str) -> Value {
    json!({
        "uuid": uuid,
        "displayName": name,
        "state": "registered",
        "validationStatus": "not_checked",
        "owner": "jdoe",
        "raProfile": { "uuid": "ra-1", "name": "Servers", "authorityInstanceUuid": "a-1" },
    })
}

fn detail() -> Value {
    json!({
        "state": "registered",
        "subjectDn": "CN=demo220,O=Example",
        "subjectAlternativeNames": { "dNSName": ["demo220.example.com"] },
        "registration": {
            "state": "active",
            "expiresAt": "2026-12-01T10:00:00.000+00:00",
            "failedAttempts": 0
        },
    })
}

impl Setup {
    /// The registered search answers with `items`; a detail is served as `detail()` unless a test says otherwise.
    async fn registered(&self, items: Vec<Value>) {
        let total = items.len() as u64;
        self.mock("POST", SEARCH)
            .and(body_string_contains("CERTIFICATE_STATE"))
            .respond_with(page(items, total))
            .with_priority(1)
            .mount(&self.world.ilm)
            .await;
    }

    pub(super) async fn detail(&self, tail: &str, response: ResponseTemplate) {
        self.mock("GET", tail)
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }
}

fn prepared_of(setup: &Setup) -> Vec<Prepared> {
    setup.inventory.snapshot().unwrap().prepared
}

#[tokio::test]
async fn a_check_lists_the_certificates_registered_for_the_person_with_their_registration_and_subject()
 {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(detail()))
        .await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert_eq!(
        prepared_of(&setup),
        [Prepared {
            uuid: "c-1".to_owned(),
            name: "demo220".to_owned(),
            ra_profile: RaProfile {
                uuid: "ra-1".to_owned(),
                name: "Servers".to_owned(),
                authority_uuid: Some("a-1".to_owned()),
            },
            registration: Some(Registration {
                state: RegistrationState::Active,
                expires_at: Some(1_796_119_200_000),
            }),
            subject: vec![
                SubjectPart::new(SubjectKind::Organization, "Example"),
                SubjectPart::new(SubjectKind::CommonName, "demo220"),
                SubjectPart::new(SubjectKind::Dns, "demo220.example.com"),
            ],
        }]
    );
    let search = setup.requests("POST", SEARCH).await;
    let asked: Value = search.last().unwrap().body_json().unwrap();
    assert_eq!(asked["filters"][0]["fieldIdentifier"], "CERTIFICATE_STATE");
    assert_eq!(asked["filters"][1]["value"], json!(["jdoe"]));
    assert_eq!(asked["itemsPerPage"], 100);
}

#[tokio::test]
async fn the_names_of_a_subject_keep_their_kinds_and_other_attributes_keep_their_oid() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    let mut body = detail();
    body["subjectDn"] = json!("E=b@example.com,2.5.4.5=42,C=CZ,1.2.3.4=x,CN=a");
    body["subjectAlternativeNames"] = json!({
        "rfc822Name": ["a@example.com"],
        "iPAddress": ["10.0.0.1"],
        "uniformResourceIdentifier": ["https://a.example.com"],
        "otherName": ["1.3.6.1.4.1.311.20.2.3=a@corp"]
    });
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(body))
        .await;

    setup.check(&[]).await;

    let found = prepared_of(&setup);
    let kinds: Vec<_> = found[0]
        .subject
        .iter()
        .map(|part| (part.kind, part.value.as_str(), part.oid.as_deref()))
        .collect();
    assert_eq!(
        kinds,
        [
            (SubjectKind::CommonName, "a", None),
            (SubjectKind::Other, "x", Some("1.2.3.4")),
            (SubjectKind::Country, "CZ", None),
            (SubjectKind::SerialNumber, "42", None),
            (
                SubjectKind::Email,
                "b@example.com",
                Some("1.2.840.113549.1.9.1"),
            ),
            (SubjectKind::Ip, "10.0.0.1", None),
            (SubjectKind::Upn, "a@corp", None),
            (SubjectKind::Email, "a@example.com", None),
            (SubjectKind::Uri, "https://a.example.com", None),
        ]
    );
}

#[tokio::test]
async fn a_certificate_whose_subject_cannot_be_written_is_left_out() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    let mut body = detail();
    body["subjectAlternativeNames"] = json!({ "x400Address": ["x"] });
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(body))
        .await;

    setup.check(&[]).await;

    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn a_search_ilm_forbids_leaves_the_prepared_certificates_out_without_failing_the_check() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("CERTIFICATE_STATE"))
        .respond_with(ResponseTemplate::new(403))
        .with_priority(1)
        .mount(&setup.world.ilm)
        .await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn a_certificate_whose_detail_ilm_forbids_or_lacks_is_left_out() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .registered(vec![
            registered("c-1", "demo220"),
            registered("c-2", "gone"),
        ])
        .await;
    setup.detail(DETAIL, ResponseTemplate::new(403)).await;
    setup
        .detail("/api/v1/certificates/c-2", ResponseTemplate::new(404))
        .await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn a_certificate_no_longer_registered_when_it_is_read_is_left_out() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    let mut issued = detail();
    issued["state"] = json!("issued");
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(issued))
        .await;

    setup.check(&[]).await;

    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn a_detail_that_fails_fails_the_check_and_keeps_the_last_answer() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.check(&[]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    setup.detail(DETAIL, ResponseTemplate::new(503)).await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Offline { .. }));
    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn a_registered_certificate_without_an_ra_profile_or_its_authority_is_left_out() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    let mut item = registered("c-1", "demo220");
    item.as_object_mut().unwrap().remove("raProfile");
    let mut unknown = registered("c-2", "no authority");
    unknown["raProfile"]
        .as_object_mut()
        .unwrap()
        .remove("authorityInstanceUuid");
    setup.registered(vec![item, unknown]).await;

    setup.check(&[]).await;

    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn without_the_listing_the_registered_certificates_are_not_searched() {
    let setup = Setup::new().await;
    setup.profile(&["keys"]).await;
    setup
        .mock("POST", SEARCH)
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&setup.world.ilm)
        .await;

    setup.check(&[]).await;

    assert!(prepared_of(&setup).is_empty());
}

#[tokio::test]
async fn the_cache_keeps_the_prepared_certificates_and_an_old_file_without_them_still_reads_and_none_is_ready_from_it()
 {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.registered(vec![registered("c-1", "demo220")]).await;
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(detail()))
        .await;
    setup.check(&[]).await;
    let kept = setup.inventory.snapshot().unwrap();
    assert_eq!(kept.prepared.len(), 1);

    let restarted = Inventory::new(setup.folder.path());
    restarted.adopt(&setup.world.session);
    assert_eq!(restarted.snapshot().unwrap(), kept);
    assert!(restarted.ready_to_issue(&[]).is_empty());

    rewrite_cache(&setup, |written| {
        written.as_object_mut().unwrap().remove("prepared");
    })
    .await;
    let old = Inventory::new(setup.folder.path());
    old.adopt(&setup.world.session);
    assert_eq!(old.snapshot().unwrap().prepared, []);
}

#[tokio::test]
async fn the_log_counts_the_prepared_certificates_and_holds_nothing_of_them() {
    capture_logs();
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .registered(vec![registered("c-1", "Unique-Name-Q7")])
        .await;
    let mut body = detail();
    body["subjectDn"] = json!("CN=Unique-Subject-Q7");
    setup
        .detail(DETAIL, ResponseTemplate::new(200).set_body_json(body))
        .await;

    setup.check(&[]).await;

    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("1 prepared"), "{log}");
    for private in ["Unique-Name-Q7", "Unique-Subject-Q7", "demo220.example.com"] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}

#[test]
fn only_an_unexpired_unlocked_registration_can_still_be_completed() {
    let prepared = |registration: Option<Registration>| Prepared {
        uuid: "c-1".to_owned(),
        name: "demo".to_owned(),
        ra_profile: RaProfile {
            uuid: "ra-1".to_owned(),
            name: "Servers".to_owned(),
            authority_uuid: None,
        },
        registration,
        subject: Vec::new(),
    };
    let registration = |code: &str, expires_at| {
        Some(Registration {
            state: RegistrationState::from_code(code),
            expires_at,
        })
    };

    assert!(prepared(None).is_open_at(100));
    assert!(prepared(registration("active", None)).is_open_at(100));
    assert!(prepared(registration("active", Some(101))).is_open_at(100));
    assert!(prepared(registration("closed", None)).is_open_at(100));
    assert!(prepared(registration("suspended", None)).is_open_at(100));
    assert!(!prepared(registration("active", Some(100))).is_open_at(100));
    assert!(!prepared(registration("expired", None)).is_open_at(100));
    assert!(!prepared(registration("locked", Some(500))).is_open_at(100));
}

#[tokio::test]
async fn the_certificates_ready_to_issue_are_the_open_ones_the_person_has_not_begun_to_complete() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .registered(vec![
            registered("c-1", "open"),
            registered("c-2", "begun"),
            registered("c-3", "locked"),
        ])
        .await;
    let body = |state: &str| {
        let mut body = detail();
        body["registration"] = json!({ "state": state });
        ResponseTemplate::new(200).set_body_json(body)
    };
    setup.detail(DETAIL, body("active")).await;
    setup
        .detail("/api/v1/certificates/c-2", body("active"))
        .await;
    setup
        .detail("/api/v1/certificates/c-3", body("locked"))
        .await;
    setup.check(&[]).await;
    let begun = Waiting {
        ilm: setup.world.address(),
        username: "jdoe".to_owned(),
        uuid: Some("c-2".to_owned()),
        ra_profile: "ra-1".to_owned(),
        authority: "a-1".to_owned(),
        key: Some(crate::keys::KeyId {
            storage: crate::keys::Storage::Software,
            name: "k".to_owned(),
        }),
        label: "begun".to_owned(),
        since: 1,
        prepared: true,
        purpose: crate::requests::Purpose::Issue,
    };

    let ready = setup.inventory.ready_to_issue(&[begun]);

    let uuids: Vec<_> = ready.iter().map(|found| found.uuid.as_str()).collect();
    assert_eq!(uuids, ["c-1"]);
}

#[test]
fn a_followed_request_that_completed_a_certificate_leaves_it_out_unless_it_waits_or_is_registered_again()
 {
    let prepared = |uuid: &str| Prepared {
        uuid: uuid.to_owned(),
        name: uuid.to_owned(),
        ra_profile: RaProfile {
            uuid: "ra-1".to_owned(),
            name: "Servers".to_owned(),
            authority_uuid: Some("a-1".to_owned()),
        },
        registration: None,
        subject: Vec::new(),
    };
    let followed = |uuid: &str, outcome| Followed {
        uuid: Some(uuid.to_owned()),
        label: uuid.to_owned(),
        outcome,
        replaces: None,
    };
    let mut list = vec![
        prepared("c-1"),
        prepared("c-2"),
        prepared("c-3"),
        prepared("c-4"),
    ];
    let found = [
        followed("c-1", Outcome::Ended(EndReason::ReturnedToRegistered)),
        followed("c-2", Outcome::Ended(EndReason::Rejected)),
        followed("c-4", Outcome::Waiting(State::Registered)),
    ];

    assert!(drop_completed(&mut list, &found));
    assert!(!drop_completed(&mut list, &found));

    let uuids: Vec<_> = list.iter().map(|found| found.uuid.as_str()).collect();
    assert_eq!(uuids, ["c-1", "c-3", "c-4"]);
}
