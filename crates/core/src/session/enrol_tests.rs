//! Enrolment by policy: certificates prepared in advance are completed and RA Profiles requested without the
//! person, while nothing that needs the person is sent.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use super::tests::{LOG, World, capture_logs};
use super::{Enrolled, RequestError, SessionView};
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
use crate::inventory::{Inventory, Prepared, SubjectKind, SubjectPart, Trigger};
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
            .with_installer(Arc::new(RecordingInstaller::new()))
            .with_requests(requests.clone())
            .with_enrolments(enrolments.clone());
        world.code_grant("access", Some("refresh"), 3600).await;
        world.profile_for("access").await;
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

    let [Enrolled::Failed { key, error }] = &outcome[..] else {
        panic!("{outcome:?}");
    };
    assert_eq!(key, &profile_key("ra-1"));
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
    for secret in ["demo220", "Example", "Jane Doe", "ticket"] {
        assert!(!log.contains(secret), "{secret} is logged");
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
