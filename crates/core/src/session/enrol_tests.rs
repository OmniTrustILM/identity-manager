//! Enrolment by policy: certificates prepared in advance are completed and RA Profiles requested without the
//! person, while nothing that needs the person is sent.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use super::request_tests::{der_of, issued_for};
use super::tests::{LOG, World, capture_logs};
use super::{Enrolled, RequestError, SessionView};
use crate::Platform;
use crate::attributes::Needs;
use crate::attributes::fixtures::{default_request_set, definition, demo_request_set};
use crate::enrolment::{Conditions, plan, sign_in_key};
use crate::enrolment::{Enrolments, Plan, prepared_key, profile_key};
use crate::http::client_for_tests;
use crate::identity::testing::{Issue, StandInStore, TestCa, TestIdentity};
use crate::identity::tls::CertificateAsked;
use crate::ilm::certificates::{RaProfile, search_text};
use crate::ilm::profile::ResourceActions;
use crate::ilm::upload::RaProfileChoice;
use crate::install::RecordingInstaller;
use crate::inventory::{
    AskedProfile, Inventory, InventoryView, Kind, Prepared, SubjectKind, SubjectPart, Trigger,
};
use crate::keys::testing::InMemoryStorage;
use crate::keys::{KeyStorage, KeyType, Storage};
use crate::requests::{Purpose, Requests, Waiting};
use crate::settings::Layer;

const STAFF_ISSUE_ATTRIBUTES: &str =
    "/api/v2/operations/authorities/auth-1/raProfiles/ra-3/attributes/issue";
const STAFF_ISSUE: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-3/certificates";
const ASKED_ISSUE_ATTRIBUTES: &str =
    "/api/v2/operations/authorities/auth-1/raProfiles/ra-2/attributes/issue";

const REQUEST_ATTRIBUTES: &str = "/api/v1/certificates/csr/attributes";
const ISSUE_ATTRIBUTES: &str =
    "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/attributes/issue";
const CUSTOM: &str = "/api/v1/attributes/custom/resources/certificates";
const ISSUE: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/certificates";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn choice() -> RaProfileChoice {
    RaProfileChoice {
        uuid: "ra-1".into(),
        name: "Servers".into(),
        description: None,
        authority: Some("Corporate CA".into()),
        authority_uuid: Some("auth-1".into()),
    }
}

fn prepared(uuid: &str) -> Prepared {
    Prepared {
        uuid: uuid.into(),
        name: "Prepared name".into(),
        ra_profile: RaProfile {
            uuid: "ra-1".into(),
            name: "Servers".into(),
            authority_uuid: Some("auth-1".into()),
        },
        registration: None,
        subject: vec![
            SubjectPart::new(SubjectKind::Organization, "Example"),
            SubjectPart::new(SubjectKind::CommonName, "demo220"),
            SubjectPart::new(SubjectKind::Dns, "demo220.example.com"),
        ],
    }
}

fn completing(uuids: &[&str]) -> Plan {
    Plan {
        complete: uuids.iter().map(|uuid| prepared(uuid)).collect(),
        request: Vec::new(),
    }
}

fn requesting_profile() -> Plan {
    Plan {
        complete: Vec::new(),
        request: vec![choice()],
    }
}

fn issue_path(uuid: &str) -> String {
    format!("{ISSUE}/{uuid}/issue")
}

/// Flips `stop` when the request arrives, as a person locking the application meanwhile.
struct Stops {
    stop: Arc<AtomicBool>,
}

impl Respond for Stops {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.stop.store(true, Ordering::SeqCst);
        let uuid = request.url.path().split('/').rev().nth(1).unwrap();
        ResponseTemplate::new(200).set_body_json(json!({ "uuid": uuid }))
    }
}

struct Enrolling {
    world: World,
    keys: Arc<InMemoryStorage>,
    installer: Arc<RecordingInstaller>,
    requests: Arc<Requests>,
    enrolments: Arc<Enrolments>,
    jane: TestIdentity,
    _folder: TempDir,
}

impl Enrolling {
    async fn new() -> Self {
        Self::with(demo_request_set()).await
    }

    async fn with(request_set: Vec<Value>) -> Self {
        let folder = tempfile::tempdir().unwrap();
        let requests = Arc::new(Requests::new(folder.path()));
        let enrolments = Arc::new(Enrolments::new(folder.path()));
        let keys = Arc::new(InMemoryStorage::new(&[Storage::Software]));
        let installer = Arc::new(RecordingInstaller::new());
        let jane = TestCa::new().issue(Issue::client("Jane"));
        let mut world = World::new()
            .await
            .with_identities(StandInStore::new(vec![jane.clone()]));
        world.session = world
            .session
            .with_certificate_client(Box::new(|_| {
                (client_for_tests(), CertificateAsked::offered_for_tests())
            }))
            .with_key_storage(keys.clone())
            .with_installer(installer.clone())
            .with_requests(requests.clone())
            .with_enrolments(enrolments.clone());
        world.code_grant("access", Some("refresh"), 3600).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-1",
                "username": "jdoe",
                "firstName": "Jane",
                "lastName": "Doe",
                "permissions": {
                    "allowedListings": ["certificates"],
                    "allowedActions": [{ "resource": "certificates", "actions": ["list", "create"] }],
                },
            })))
            .mount(&world.ilm)
            .await;
        for (route, body) in [
            (REQUEST_ATTRIBUTES, request_set),
            (
                ISSUE_ATTRIBUTES,
                vec![definition(
                    3,
                    "data",
                    "validity",
                    "string",
                    json!({ "required": false }),
                )],
            ),
            (
                CUSTOM,
                vec![definition(
                    3,
                    "custom",
                    "department",
                    "string",
                    json!({ "required": false }),
                )],
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&world.ilm)
                .await;
        }
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        Self {
            world,
            keys,
            installer,
            requests,
            enrolments,
            jane,
            _folder: folder,
        }
    }

    async fn enrol(&self, plan: &Plan) -> Vec<Enrolled> {
        self.enrol_while(plan, &|| true).await
    }

    async fn enrol_while(&self, plan: &Plan, proceed: &(dyn Fn() -> bool + Sync)) -> Vec<Enrolled> {
        self.world
            .session
            .enrol(plan, &Layer::default(), proceed)
            .await
    }

    async fn answer(&self, verb: &str, route: &str, response: impl Respond + 'static) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    async fn registered(&self, uuid: &str) {
        self.answer(
            "GET",
            &format!("/api/v1/certificates/{uuid}"),
            ResponseTemplate::new(200).set_body_json(json!({
                "state": "registered",
                "subjectDn": "CN=demo220,O=Example",
                "subjectAlternativeNames": { "dNSName": ["demo220.example.com"], "iPAddress": [] }
            })),
        )
        .await;
    }

    async fn accepting(&self, route: &str, uuid: &str) {
        self.answer(
            "POST",
            route,
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": uuid })),
        )
        .await;
    }

    async fn posted(&self, route: &str) -> Vec<Value> {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "POST" && request.url.path() == route)
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }

    fn standing(&self) -> crate::enrolment::Standing {
        self.enrolments
            .standing(&self.world.address(), "jdoe")
            .unwrap()
    }

    /// ILM lists the RA Profile `Servers` for the person and has nothing else to say at a check.
    async fn listing_profiles(&self) {
        self.answer(
            "GET",
            "/api/v1/raProfiles",
            ResponseTemplate::new(200).set_body_json(json!([{
                "uuid": "ra-1",
                "name": "Servers",
                "enabled": true,
                "authorityInstanceName": "Corporate CA",
                "authorityInstanceUuid": "auth-1",
            }])),
        )
        .await;
        self.answer(
            "POST",
            "/api/v1/certificates",
            ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [],
                "pageNumber": 1,
                "totalPages": 1,
                "totalItems": 0,
            })),
        )
        .await;
    }

    /// A check of ILM that succeeds, in a new inventory.
    async fn checked(&self) -> Arc<Inventory> {
        let inventory = Arc::new(Inventory::new(self._folder.path()));
        inventory.attach(&self.world.session);
        inventory
            .check(&self.world.session, Trigger::SyncNow, &[])
            .await;
        inventory
    }

    async fn enrol_due(
        &self,
        inventory: &Inventory,
        policy: &Layer,
        platform: Platform,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Vec<Enrolled> {
        inventory
            .enrol_due(&self.world.session, policy, platform, proceed)
            .await
    }

    fn seed_waiting(&self, uuid: Option<&str>) {
        let key = self
            .keys
            .create(Storage::Software, KeyType::EcP256)
            .unwrap();
        self.requests
            .add(Waiting {
                ilm: self.world.address(),
                username: "jdoe".into(),
                uuid: uuid.map(str::to_owned),
                ra_profile: "ra-1".into(),
                authority: "auth-1".into(),
                key: Some(key.id().clone()),
                label: "seeded".into(),
                since: now(),
                prepared: false,
                purpose: Purpose::Issue,
                enrolled: false,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn a_prepared_certificate_is_completed_with_the_registered_subject_and_no_challenge() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    enrolling.accepting(&issue_path("c-9"), "c-9").await;

    let outcome = enrolling.enrol(&completing(&["c-9"])).await;

    assert_eq!(
        outcome,
        [Enrolled::Sent {
            key: prepared_key("c-9"),
            uuid: "c-9".into()
        }]
    );
    let body = &enrolling.posted(&issue_path("c-9")).await[0];
    assert!(body.get("authorizationSecret").is_none());
    let waiting = enrolling.requests.all();
    assert_eq!(waiting.len(), 1);
    assert!(waiting[0].enrolled && waiting[0].prepared);
    assert_eq!(waiting[0].uuid.as_deref(), Some("c-9"));
    assert_eq!(enrolling.keys.count(), 1);
}

#[tokio::test]
async fn a_profile_is_requested_with_the_defaults_and_is_done_once_ilm_answers() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert_eq!(
        outcome,
        [Enrolled::Sent {
            key: profile_key("ra-1"),
            uuid: "c-1".into()
        }]
    );
    assert_eq!(enrolling.posted(ISSUE).await.len(), 1);
    assert!(enrolling.standing().is_done("ra-1"));
    let waiting = enrolling.requests.all();
    assert_eq!(waiting.len(), 1);
    assert!(waiting[0].enrolled && !waiting[0].prepared);
    assert_eq!(waiting[0].uuid.as_deref(), Some("c-1"));
}

#[tokio::test]
async fn a_profile_that_needs_the_person_is_asked_and_nothing_is_created() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.accepting(ISSUE, "c-1").await;

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert_eq!(
        outcome,
        [Enrolled::Asked {
            profile: choice(),
            reason: Needs::Required
        }]
    );
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
    assert!(!enrolling.standing().is_done("ra-1"));
}

#[tokio::test]
async fn a_refused_request_deletes_its_key_and_entry_and_records_the_failure() {
    let enrolling = Enrolling::new().await;
    enrolling
        .answer(
            "POST",
            ISSUE,
            ResponseTemplate::new(400).set_body_json(json!({ "message": "Not for you." })),
        )
        .await;

    let outcome = enrolling.enrol(&requesting_profile()).await;

    let [Enrolled::Failed { key, name, error }] = &outcome[..] else {
        panic!("{outcome:?}");
    };
    assert_eq!(key, &profile_key("ra-1"));
    assert_eq!(name, "Servers");
    assert!(matches!(error, RequestError::Refused(_)));
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
    assert!(enrolling.standing().failed_within_a_day(key, now()));
    assert!(!enrolling.standing().is_done("ra-1"));
}

#[tokio::test]
async fn a_refusal_by_ilm_is_a_failure_that_says_it_does_not_allow_this() {
    let enrolling = Enrolling::new().await;
    enrolling
        .answer("POST", ISSUE, ResponseTemplate::new(403))
        .await;

    let outcome = enrolling.enrol(&requesting_profile()).await;

    let [Enrolled::Failed { error, .. }] = &outcome[..] else {
        panic!("{outcome:?}");
    };
    assert_eq!(error, &RequestError::NotAllowed);
    assert_eq!(error.to_string(), "ILM does not allow this.");
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
}

#[tokio::test]
async fn a_refused_completion_deletes_its_key_and_entry_and_records_the_failure() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    enrolling
        .answer("POST", &issue_path("c-9"), ResponseTemplate::new(403))
        .await;

    let outcome = enrolling.enrol(&completing(&["c-9"])).await;

    assert!(matches!(&outcome[..], [Enrolled::Failed { .. }]));
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
    assert!(
        enrolling
            .standing()
            .failed_within_a_day(&prepared_key("c-9"), now())
    );
}

#[tokio::test]
async fn a_lost_answer_to_a_completion_keeps_the_key_and_the_entry() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    enrolling
        .answer("POST", &issue_path("c-9"), ResponseTemplate::new(500))
        .await;

    let outcome = enrolling.enrol(&completing(&["c-9"])).await;

    assert!(matches!(
        &outcome[..],
        [Enrolled::Failed {
            error: RequestError::Unexpected(500),
            ..
        }]
    ));
    assert_eq!(enrolling.keys.count(), 1);
    let waiting = enrolling.requests.all();
    assert_eq!(waiting.len(), 1);
    assert!(waiting[0].enrolled);
    assert!(
        enrolling
            .standing()
            .failed_within_a_day(&prepared_key("c-9"), now())
    );
}

#[tokio::test]
async fn a_success_clears_the_failure_an_earlier_attempt_recorded() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    enrolling
        .enrolments
        .record_failure(
            &enrolling.world.address(),
            "jdoe",
            &profile_key("ra-1"),
            now() - 2 * crate::enrolment::DAY_MS,
        )
        .unwrap();

    enrolling.enrol(&requesting_profile()).await;

    assert!(enrolling.standing().failed.is_empty());
}

#[tokio::test]
async fn nothing_is_sent_once_proceed_says_no() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-8").await;
    enrolling.registered("c-9").await;
    let stop = Arc::new(AtomicBool::new(false));
    enrolling
        .answer("POST", &issue_path("c-8"), Stops { stop: stop.clone() })
        .await;
    enrolling.accepting(&issue_path("c-9"), "c-9").await;
    let proceed = {
        let stop = stop.clone();
        move || !stop.load(Ordering::SeqCst)
    };

    let outcome = enrolling
        .enrol_while(&completing(&["c-8", "c-9"]), &proceed)
        .await;

    assert!(matches!(
        &outcome[..],
        [Enrolled::Sent { .. }, Enrolled::Stopped]
    ));
    assert!(enrolling.posted(&issue_path("c-9")).await.is_empty());
    assert_eq!(enrolling.keys.count(), 1);
}

#[tokio::test]
async fn nothing_is_sent_when_proceed_says_no_from_the_start() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;

    let outcome = enrolling
        .enrol_while(&requesting_profile(), &|| false)
        .await;

    assert_eq!(outcome, [Enrolled::Stopped]);
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
}

#[tokio::test]
async fn a_profile_with_a_waiting_request_is_not_requested_again() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    enrolling.seed_waiting(Some("c-0"));

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 1);
    assert_eq!(enrolling.requests.all().len(), 1);
    assert!(!enrolling.standing().is_done("ra-1"));
}

#[tokio::test]
async fn no_key_storage_means_nothing_is_enrolled() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let layer = Layer {
        key_storages: Some(Vec::new()),
        ..Layer::default()
    };

    let outcome = enrolling
        .world
        .session
        .enrol(&requesting_profile(), &layer, &|| true)
        .await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
}

#[tokio::test]
async fn the_log_of_a_managed_first_run_names_no_value() {
    capture_logs();
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    enrolling.accepting(&issue_path("c-9"), "c-9").await;
    enrolling.accepting(STAFF_ISSUE, "u-staff").await;
    for (route, required) in [
        (ASKED_ISSUE_ATTRIBUTES, true),
        (STAFF_ISSUE_ATTRIBUTES, false),
    ] {
        enrolling
            .answer(
                "GET",
                route,
                ResponseTemplate::new(200).set_body_json(vec![definition(
                    3,
                    "data",
                    "ticket",
                    "string",
                    json!({ "required": required }),
                )]),
            )
            .await;
    }
    let session = &enrolling.world.session;
    let mut who = session.signed_in_as().unwrap();
    who.allowed_actions = vec![ResourceActions {
        resource: "certificates".into(),
        actions: vec!["create".into()],
    }];
    let asked = RaProfileChoice {
        uuid: "ra-2".into(),
        name: "Others".into(),
        ..choice()
    };
    let staff = RaProfileChoice {
        uuid: "ra-3".into(),
        name: "Staff".into(),
        ..choice()
    };
    let policy = Layer {
        complete_prepared: Some(true),
        request_profiles: Some(vec!["Staff".into(), "Others".into()]),
        sign_in_certificate_profile: Some("Staff".into()),
        ..Layer::default()
    };
    let conditions = Conditions {
        linux: false,
        locked: false,
        signed_in: true,
        fresh: true,
    };
    let standing = enrolling.standing();
    let planned = plan(
        now(),
        &policy,
        &conditions,
        &who,
        &[prepared("c-9")],
        &[staff, asked],
        &[],
        &standing,
        session.key_offers().await,
    );

    let done = session.enrol(&planned, &policy, &|| true).await;

    assert_eq!(done.len(), 3);
    let found = enrolling.jane.fingerprint();
    for (route, body) in [
        (
            "/api/v1/certificates",
            json!({
                "certificates": [{
                    "uuid": "u-staff",
                    "commonName": "Jane",
                    "state": "issued",
                    "validationStatus": "valid",
                    "fingerprint": search_text(&found),
                    "raProfile": { "uuid": "ra-3", "name": "Staff" },
                }],
                "pageNumber": 1,
                "totalPages": 1,
                "totalItems": 1,
            }),
        ),
        (
            "/api/v1/resources/certificates/objects/allowed-actions",
            json!({ "items": [] }),
        ),
    ] {
        enrolling
            .answer(
                "POST",
                route,
                ResponseTemplate::new(200).set_body_json(body),
            )
            .await;
    }
    enrolling
        .answer(
            "PUT",
            "/api/v1/auth/profile",
            ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-1",
                "username": "jdoe",
                "firstName": "Jane",
                "lastName": "Doe",
                "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
            })),
        )
        .await;
    let inventory = Arc::new(Inventory::new(enrolling._folder.path()));
    inventory.attach(session);
    inventory.check(session, Trigger::SyncNow, &[found]).await;
    enrolling
        .enrolments
        .mark_installed(&who.ilm, &who.username, "u-staff")
        .unwrap();
    let changed = session
        .sign_in_by_policy(&inventory, &policy, &|| true)
        .await;
    assert_eq!(changed.len(), 1);
    assert!(
        !enrolling
            .standing()
            .failed_within_a_day(&sign_in_key("u-staff"), now())
    );

    let log = LOG.lock().unwrap().join("\n");
    for line in [
        "enrolment planned: 1 prepared, 2 requested",
        "enrolment sent: c-9",
        "enrolment sent: ra-3",
        "enrolment asked: RA Profile ra-2, required",
        "enrolment done for the RA Profile ra-3",
        "sign-in certificate set by policy: u-staff",
    ] {
        assert!(log.contains(line), "{line} is not logged: {log}");
    }
    for (index, secret) in ["demo220", "Example", "Jane Doe", "ticket"]
        .iter()
        .enumerate()
    {
        assert!(!log.contains(secret), "forbidden value {index} is logged");
    }
}

#[tokio::test]
async fn the_log_of_an_enrolment_names_no_value() {
    capture_logs();
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    enrolling.accepting(&issue_path("c-9"), "c-9").await;
    enrolling.accepting(ISSUE, "c-1").await;
    let plan = Plan {
        complete: vec![prepared("c-9")],
        request: vec![choice()],
    };

    enrolling.enrol(&plan).await;

    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("enrolment sent"));
    assert!(!log.contains("demo220"));
    assert!(!log.contains("Example"));
}

#[tokio::test]
async fn a_lost_answer_to_a_profile_request_is_never_requested_again() {
    let enrolling = Enrolling::new().await;
    enrolling
        .answer("POST", ISSUE, ResponseTemplate::new(500))
        .await;

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert!(matches!(
        &outcome[..],
        [Enrolled::Failed {
            error: RequestError::Unexpected(500),
            ..
        }]
    ));
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
    assert!(enrolling.standing().is_done("ra-1"));
}

/// Answers a request after noting whether the RA Profile was already written down as done.
struct SeesDone {
    enrolments: Arc<Enrolments>,
    ilm: crate::ilm::IlmUrl,
    done: Arc<AtomicBool>,
}

impl Respond for SeesDone {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let standing = self.enrolments.standing(&self.ilm, "jdoe").unwrap();
        self.done.store(standing.is_done("ra-1"), Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" }))
    }
}

#[tokio::test]
async fn a_profile_is_written_down_as_done_before_it_is_sent() {
    let enrolling = Enrolling::new().await;
    let done = Arc::new(AtomicBool::new(false));
    enrolling
        .answer(
            "POST",
            ISSUE,
            SeesDone {
                enrolments: enrolling.enrolments.clone(),
                ilm: enrolling.world.address(),
                done: done.clone(),
            },
        )
        .await;

    enrolling.enrol(&requesting_profile()).await;

    assert!(done.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_profile_done_meanwhile_is_not_requested_by_an_earlier_plan() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    enrolling
        .enrolments
        .mark_done(&enrolling.world.address(), "jdoe", "ra-1")
        .unwrap();

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
}

#[tokio::test]
async fn a_completion_that_ilm_returned_to_registered_waits_a_day() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-9").await;
    let key = enrolling
        .keys
        .create(Storage::Software, KeyType::EcP256)
        .unwrap();
    enrolling
        .requests
        .add(Waiting {
            ilm: enrolling.world.address(),
            username: "jdoe".into(),
            uuid: Some("c-9".into()),
            ra_profile: "ra-1".into(),
            authority: "auth-1".into(),
            key: Some(key.id().clone()),
            label: "seeded".into(),
            since: now() - 10 * 60_000,
            prepared: true,
            purpose: Purpose::Issue,
            enrolled: true,
        })
        .unwrap();

    enrolling.world.session.follow().await;

    assert!(enrolling.requests.all().is_empty());
    assert!(
        enrolling
            .standing()
            .failed_within_a_day(&prepared_key("c-9"), now())
    );
}

#[tokio::test]
async fn a_run_stops_when_another_sign_in_takes_over() {
    let enrolling = Enrolling::new().await;
    enrolling.registered("c-8").await;
    enrolling.registered("c-9").await;
    enrolling
        .answer(
            "POST",
            &issue_path("c-8"),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "uuid": "c-8" }))
                .set_delay(std::time::Duration::from_millis(500)),
        )
        .await;
    enrolling.accepting(&issue_path("c-9"), "c-9").await;
    let plan = completing(&["c-8", "c-9"]);

    let (outcome, ()) = tokio::join!(enrolling.enrol(&plan), async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        enrolling.world.session.sign_out().await;
        assert!(matches!(
            enrolling.world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
    });

    assert!(
        enrolling.posted(&issue_path("c-9")).await.is_empty(),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_profile_whose_request_never_left_is_not_kept_as_done() {
    use super::{Credential, State, lock};

    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    enrolling
        .world
        .grant("refresh_token", ResponseTemplate::new(500), None)
        .await;
    Mock::given(method("GET"))
        .and(path(CUSTOM))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(Vec::<Value>::new())
                .set_delay(std::time::Duration::from_millis(1500)),
        )
        .with_priority(1)
        .mount(&enrolling.world.ilm)
        .await;
    if let State::SignedIn(active) = &mut *lock(&enrolling.world.session.state)
        && let Credential::OAuth(oauth) = &mut active.credential
    {
        oauth.expires_at = std::time::Instant::now() + std::time::Duration::from_secs(61);
    }

    let outcome = enrolling.enrol(&requesting_profile()).await;

    assert!(
        matches!(
            &outcome[..],
            [Enrolled::Failed {
                error: RequestError::Offline,
                ..
            }]
        ),
        "{outcome:?}"
    );
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert!(!enrolling.standing().is_done("ra-1"));
}

fn asking_for_servers() -> Layer {
    Layer {
        request_profiles: Some(vec!["Servers".into()]),
        ..Layer::default()
    }
}

#[tokio::test]
async fn the_check_after_a_sign_in_requests_the_profiles_policy_names() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert_eq!(
        outcome,
        [Enrolled::Sent {
            key: profile_key("ra-1"),
            uuid: "c-1".into()
        }]
    );
    assert_eq!(enrolling.posted(ISSUE).await.len(), 1);
    assert!(inventory.asked().is_empty());
}

#[tokio::test]
async fn two_enrolments_started_together_run_one_after_the_other() {
    let delay = std::time::Duration::from_millis(300);
    let enrolling = Enrolling::new().await;
    enrolling
        .answer(
            "GET",
            "/api/v1/raProfiles",
            ResponseTemplate::new(200)
                .set_body_json(json!([{
                    "uuid": "ra-1",
                    "name": "Servers",
                    "enabled": true,
                    "authorityInstanceName": "Corporate CA",
                    "authorityInstanceUuid": "auth-1",
                }]))
                .set_delay(delay),
        )
        .await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;
    let policy = asking_for_servers();

    let started = std::time::Instant::now();
    let (first, second) = tokio::join!(
        enrolling.enrol_due(&inventory, &policy, Platform::Macos, &|| true),
        enrolling.enrol_due(&inventory, &policy, Platform::Macos, &|| true),
    );

    assert!(started.elapsed() >= delay * 2);
    assert_eq!(first.len() + second.len(), 1);
    assert_eq!(enrolling.posted(ISSUE).await.len(), 1);
}

#[tokio::test]
async fn nothing_is_enrolled_while_the_application_is_locked() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| {
            false
        })
        .await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
}

#[tokio::test]
async fn nothing_is_enrolled_on_linux() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Linux, &|| true)
        .await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
}

#[tokio::test]
async fn nothing_is_enrolled_before_a_check_of_ilm_succeeded() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = Inventory::new(enrolling._folder.path());

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert!(outcome.is_empty());
    assert!(enrolling.posted(ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_profile_is_requested_once_across_a_sign_out_and_a_sign_in_and_a_restart() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let policy = asking_for_servers();
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &policy, Platform::Macos, &|| true)
        .await;
    assert_eq!(enrolling.posted(ISSUE).await.len(), 1);
    // The certificate was installed and its entry is gone, so only what the store keeps stops a second request.
    for entry in enrolling.requests.all() {
        enrolling.requests.remove(&entry.key.unwrap()).unwrap();
    }

    enrolling.world.session.sign_out().await;
    assert!(matches!(
        enrolling.world.sign_in().await,
        SessionView::SignedIn { .. }
    ));
    let again = enrolling.checked().await;
    let outcome = enrolling
        .enrol_due(&again, &policy, Platform::Macos, &|| true)
        .await;

    assert!(outcome.is_empty());
    assert_eq!(enrolling.posted(ISSUE).await.len(), 1);
    let restarted = Enrolments::new(enrolling._folder.path());
    assert!(
        restarted
            .standing(&enrolling.world.address(), "jdoe")
            .unwrap()
            .is_done("ra-1")
    );
}

#[tokio::test]
async fn a_profile_that_needs_the_person_is_asked_until_it_is_requested() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;
    let asked = || {
        vec![AskedProfile {
            uuid: "ra-1".into(),
            name: "Servers".into(),
        }]
    };

    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert_eq!(inventory.asked(), asked());
    let view = InventoryView::new(
        inventory.status(),
        inventory.snapshot().as_ref(),
        false,
        true,
        true,
    )
    .with_asked(inventory.asked())
    .with_requests(&[], &[]);
    assert_eq!(view.asked, asked());
    inventory.set_local(&[]);
    let summary = inventory.summary().unwrap();
    assert_eq!(
        summary
            .attention
            .iter()
            .map(|item| item.kind.clone())
            .collect::<Vec<_>>(),
        [Kind::Asked {
            uuid: "ra-1".into()
        }]
    );
    assert_eq!(summary.attention[0].name, "Servers");
    assert!(!summary.needs_attention());
    // A request that waits for ILM is not asked any more, and neither is one the person has sent.
    enrolling.seed_waiting(Some("c-0"));
    let waiting = enrolling.requests.all();
    let view = InventoryView::new(
        inventory.status(),
        inventory.snapshot().as_ref(),
        false,
        true,
        true,
    )
    .with_asked(inventory.asked())
    .with_requests(&waiting, &[]);
    assert!(view.asked.is_empty());
    inventory.unask("ra-1");
    assert!(inventory.asked().is_empty());
    assert!(inventory.summary().unwrap().attention.is_empty());
}

#[tokio::test]
async fn the_asked_profiles_stay_when_the_ra_profiles_cannot_be_listed() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;
    assert_eq!(inventory.asked().len(), 1);
    Mock::given(method("GET"))
        .and(path("/api/v1/raProfiles"))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&enrolling.world.ilm)
        .await;

    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert_eq!(inventory.asked().len(), 1);
}

#[tokio::test]
async fn an_asked_profile_stays_asked_when_its_forms_cannot_be_loaded() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;
    assert_eq!(inventory.asked().len(), 1);
    Mock::given(method("GET"))
        .and(path(ISSUE_ATTRIBUTES))
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&enrolling.world.ilm)
        .await;

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert!(
        matches!(&outcome[..], [Enrolled::Failed { .. }]),
        "{outcome:?}"
    );
    assert_eq!(inventory.asked().len(), 1);
}

#[tokio::test]
async fn an_asked_profile_that_policy_no_longer_names_is_not_kept() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;
    assert_eq!(inventory.asked().len(), 1);
    let other = Layer {
        request_profiles: Some(vec!["Staff".into()]),
        ..Layer::default()
    };

    enrolling
        .enrol_due(&inventory, &other, Platform::Macos, &|| true)
        .await;

    assert!(inventory.asked().is_empty());
}

#[tokio::test]
async fn a_profile_requested_while_the_check_ran_is_not_asked_again() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/raProfiles"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{
                    "uuid": "ra-1",
                    "name": "Servers",
                    "enabled": true,
                    "authorityInstanceName": "Corporate CA",
                    "authorityInstanceUuid": "auth-1",
                }]))
                .set_delay(std::time::Duration::from_millis(400)),
        )
        .with_priority(1)
        .mount(&enrolling.world.ilm)
        .await;
    let requested = async {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        enrolling
            .enrolments
            .mark_done(&enrolling.world.address(), "jdoe", "ra-1")
            .unwrap();
    };

    let policy = asking_for_servers();

    tokio::join!(
        enrolling.enrol_due(&inventory, &policy, Platform::Macos, &|| true),
        requested
    );

    assert!(inventory.asked().is_empty());
}

#[tokio::test]
async fn a_request_from_certificates_takes_the_profile_out_of_the_summary_at_the_next_follow() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;
    inventory.set_local(&[]);
    assert_eq!(inventory.summary().unwrap().attention.len(), 1);
    enrolling.seed_waiting(Some("c-0"));

    let (_, changed) = inventory.follow(&enrolling.world.session).await;

    assert!(changed);
    assert!(inventory.summary().unwrap().attention.is_empty());
    assert!(inventory.asked().is_empty());
}

#[tokio::test]
async fn the_asked_profiles_leave_with_the_sign_in() {
    let enrolling = Enrolling::with(default_request_set()).await;
    enrolling.listing_profiles().await;
    let inventory = enrolling.checked().await;
    enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;
    assert_eq!(inventory.asked().len(), 1);

    enrolling.world.session.sign_out().await;

    assert!(inventory.asked().is_empty());
}

#[tokio::test]
async fn a_profile_requested_from_the_asked_item_is_marked_enrolled_and_done() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let session = &enrolling.world.session;
    let forms = session
        .open_request_forms("auth-1", "ra-1", false)
        .await
        .unwrap();
    let request = session.unattended_forms(&forms).unwrap();

    let sent = session
        .request_asked(&choice(), request, Storage::Software, KeyType::EcP256)
        .await;

    let waiting = sent.unwrap();
    assert_eq!(waiting.uuid.as_deref(), Some("c-1"));
    assert!(waiting.enrolled);
    assert!(enrolling.standing().is_done("ra-1"));
    assert!(enrolling.requests.all()[0].enrolled);
}

#[tokio::test]
async fn a_hand_request_that_ilm_refuses_does_not_make_the_profile_done() {
    let enrolling = Enrolling::new().await;
    enrolling
        .answer(
            "POST",
            ISSUE,
            ResponseTemplate::new(400).set_body_json(json!({ "message": "No." })),
        )
        .await;
    let session = &enrolling.world.session;

    let sent = session
        .request_asked(
            &choice(),
            crate::session::RequestInput::default(),
            Storage::Software,
            KeyType::EcP256,
        )
        .await;

    assert!(sent.is_err());
    assert!(!enrolling.standing().is_done("ra-1"));
    assert!(enrolling.requests.all().is_empty());
}

#[tokio::test]
async fn a_sign_out_and_a_sign_in_while_the_profiles_are_listed_send_nothing() {
    let enrolling = Enrolling::new().await;
    enrolling
        .answer(
            "GET",
            "/api/v1/raProfiles",
            ResponseTemplate::new(200)
                .set_body_json(json!([{
                    "uuid": "ra-1",
                    "name": "Servers",
                    "enabled": true,
                    "authorityInstanceName": "Corporate CA",
                    "authorityInstanceUuid": "auth-1",
                }]))
                .set_delay(std::time::Duration::from_millis(500)),
        )
        .await;
    enrolling.listing_profiles().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let inventory = enrolling.checked().await;
    let policy = asking_for_servers();

    let (outcome, ()) = tokio::join!(
        enrolling.enrol_due(&inventory, &policy, Platform::Macos, &|| true),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            enrolling.world.session.sign_out().await;
            assert!(matches!(
                enrolling.world.sign_in().await,
                SessionView::SignedIn { .. }
            ));
        },
    );

    assert!(outcome.iter().all(|done| *done == Enrolled::Stopped));
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
}

type Made = Arc<Mutex<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>>>;

/// ILM issuing at once: the request makes the certificate, and the state and the chain tell it.
enum Issues {
    Request(Made),
    State(Made),
    Chain(Made),
}

impl Respond for Issues {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let encode = |der: &[u8]| STANDARD.encode(der);
        match self {
            Self::Request(made) => {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                *made.lock().unwrap() = Some(issued_for(&der_of(&body)));
                ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" }))
            }
            Self::State(made) => {
                let (leaf, _, _) = made.lock().unwrap().clone().unwrap();
                ResponseTemplate::new(200).set_body_json(
                    json!({ "state": "issued", "certificateContent": encode(&leaf) }),
                )
            }
            Self::Chain(made) => {
                let (_, authority, root) = made.lock().unwrap().clone().unwrap();
                ResponseTemplate::new(200).set_body_json(json!({
                    "completeChain": true,
                    "certificates": [
                        { "certificateContent": encode(&authority) },
                        { "certificateContent": encode(&root) },
                    ],
                }))
            }
        }
    }
}

#[tokio::test]
async fn a_certificate_ilm_issues_at_once_is_installed_when_the_enrolment_returns() {
    let enrolling = Enrolling::new().await;
    enrolling.listing_profiles().await;
    let made = Made::default();
    enrolling
        .answer("POST", ISSUE, Issues::Request(made.clone()))
        .await;
    enrolling
        .answer(
            "GET",
            "/api/v1/certificates/c-1",
            Issues::State(made.clone()),
        )
        .await;
    enrolling
        .answer("GET", "/api/v1/certificates/c-1/chain", Issues::Chain(made))
        .await;
    let inventory = enrolling.checked().await;

    let outcome = enrolling
        .enrol_due(&inventory, &asking_for_servers(), Platform::Macos, &|| true)
        .await;

    assert_eq!(outcome.len(), 1, "{outcome:?}");
    assert_eq!(enrolling.installer.calls().len(), 1);
    assert!(enrolling.requests.all().is_empty());
}

#[tokio::test]
async fn a_profile_is_requested_from_the_asked_item_while_a_revocation_for_it_waits() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    enrolling
        .requests
        .add(Waiting {
            ilm: enrolling.world.address(),
            username: "jdoe".into(),
            uuid: Some("c-0".into()),
            ra_profile: "ra-1".into(),
            authority: "auth-1".into(),
            key: None,
            label: "old".into(),
            since: now(),
            prepared: false,
            purpose: Purpose::Revoke {
                certificate: "c-0".into(),
                fingerprint: crate::identity::Fingerprint::of(b"old"),
                remove: false,
            },
            enrolled: false,
        })
        .unwrap();
    let session = &enrolling.world.session;
    let forms = session
        .open_request_forms("auth-1", "ra-1", false)
        .await
        .unwrap();
    let request = session.unattended_forms(&forms).unwrap();

    let sent = session
        .request_asked(&choice(), request, Storage::Software, KeyType::EcP256)
        .await;

    assert!(sent.is_ok(), "{sent:?}");
}

#[tokio::test]
async fn a_profile_already_done_is_not_requested_again_from_the_asked_item() {
    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let session = &enrolling.world.session;
    let forms = session
        .open_request_forms("auth-1", "ra-1", false)
        .await
        .unwrap();
    let request = session.unattended_forms(&forms).unwrap();
    enrolling
        .enrolments
        .mark_done(&enrolling.world.address(), "jdoe", "ra-1")
        .unwrap();

    let sent = session
        .request_asked(&choice(), request, Storage::Software, KeyType::EcP256)
        .await;

    assert!(
        matches!(sent, Err(RequestError::AlreadyRequested)),
        "{sent:?}"
    );
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert_eq!(enrolling.keys.count(), 0);
    assert!(enrolling.requests.all().is_empty());
}

#[tokio::test]
async fn a_hand_request_that_never_left_does_not_make_the_profile_done() {
    use super::{Credential, State, lock};

    let enrolling = Enrolling::new().await;
    enrolling.accepting(ISSUE, "c-1").await;
    let session = &enrolling.world.session;
    let forms = session
        .open_request_forms("auth-1", "ra-1", false)
        .await
        .unwrap();
    let request = session.unattended_forms(&forms).unwrap();
    enrolling
        .world
        .grant("refresh_token", ResponseTemplate::new(500), None)
        .await;
    if let State::SignedIn(active) = &mut *lock(&session.state)
        && let Credential::OAuth(oauth) = &mut active.credential
    {
        oauth.expires_at = std::time::Instant::now() + std::time::Duration::from_secs(61);
    }
    // The token has less than a minute left by the time the request is sent, so it is renewed first.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let sent = session
        .request_asked(&choice(), request, Storage::Software, KeyType::EcP256)
        .await;

    assert!(matches!(sent, Err(RequestError::Offline)), "{sent:?}");
    assert!(enrolling.posted(ISSUE).await.is_empty());
    assert!(!enrolling.standing().is_done("ra-1"));
}
