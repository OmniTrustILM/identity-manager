//! Making a certificate of this computer the person's sign-in certificate in ILM, with a provider sign-in.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::tests::{LOG, World, capture_logs};
use super::{ChangeError, ConnectionSettings, SessionView, SignInByPolicy};
use crate::enrolment::{DAY_MS, Enrolments, sign_in_key};
use crate::http::client_for_tests;
use crate::identity::testing::{Issue, StandInStore, TestCa, TestIdentity};
use crate::identity::tls::CertificateAsked;
use crate::identity::{
    ClientIdentity, Fingerprint, IdentityStore, LocalCertificate, StoreUnreadable,
};
use crate::ilm::certificates::search_text;
use crate::inventory::{Inventory, Status, Trigger};
use crate::requests::{PendingSwitch, Purpose, Requests, Waiting};
use crate::session::request::now_ms;
use crate::settings::{Layer, SignInMethod};

const PROFILE: &str = "/api/v1/auth/profile";
const SEARCH: &str = "/api/v1/certificates";
const ALLOWED: &str = "/api/v1/resources/certificates/objects/allowed-actions";
const UUID: &str = "u-jane";

fn old_sign_in() -> Fingerprint {
    Fingerprint::of(b"the certificate ILM knows the person by")
}

/// ILM's profile of the person, who signs in with `old_sign_in`.
fn profile() -> Value {
    json!({
        "uuid": "u-1",
        "username": "jdoe",
        "firstName": "Zelda",
        "lastName": "Unique-Surname",
        "email": "log.holder@example.com",
        "description": "Unique-Description-1",
        "certificate": { "uuid": "sign-in", "fingerprint": search_text(&old_sign_in()) },
        "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
    })
}

struct Change {
    world: World,
    inventory: Arc<Inventory>,
    enrolments: Arc<Enrolments>,
    jane: TestIdentity,
    _folder: TempDir,
}

impl Change {
    async fn new() -> Self {
        Self::with(json!({}), SystemTime::now()).await
    }

    /// ILM's matched certificate takes the fields of `overrides`; the store judges validity at `now`.
    async fn with(overrides: Value, now: SystemTime) -> Self {
        let jane = TestCa::new().issue(Issue::client("Jane"));
        Self::on(
            overrides,
            jane.clone(),
            StandInStore::new(vec![jane]).at(now),
        )
        .await
    }

    async fn on(overrides: Value, jane: TestIdentity, store: impl IdentityStore + 'static) -> Self {
        let folder = tempfile::tempdir().unwrap();
        let enrolments = Arc::new(Enrolments::new(folder.path()));
        let mut world = World::new().await.with_identities(store);
        world.session = world
            .session
            .with_certificate_client(Box::new(|_| {
                (client_for_tests(), CertificateAsked::offered_for_tests())
            }))
            .with_enrolments(enrolments.clone());
        world.code_grant("access", Some("refresh"), 3600).await;
        Mock::given(method("GET"))
            .and(path(PROFILE))
            .respond_with(ResponseTemplate::new(200).set_body_json(profile()))
            .with_priority(2)
            .mount(&world.ilm)
            .await;
        let mut found = json!({
            "uuid": UUID,
            "commonName": "Jane",
            "state": "issued",
            "validationStatus": "valid",
            "fingerprint": search_text(&jane.fingerprint()),
        });
        found.as_object_mut().unwrap().extend(
            overrides
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        Mock::given(method("POST"))
            .and(path(SEARCH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [found],
                "pageNumber": 1,
                "totalPages": 1,
                "totalItems": 1,
            })))
            .mount(&world.ilm)
            .await;
        Mock::given(method("POST"))
            .and(path(ALLOWED))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "items": [] })))
            .mount(&world.ilm)
            .await;
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        let inventory = Arc::new(Inventory::new(folder.path()));
        inventory.attach(&world.session);
        let change = Self {
            world,
            inventory,
            enrolments,
            jane,
            _folder: folder,
        };
        change.check().await;
        change
    }

    async fn check(&self) -> Status {
        self.inventory
            .check(
                &self.world.session,
                Trigger::SyncNow,
                &[self.jane.fingerprint()],
            )
            .await
    }

    async fn make(&self) -> Result<(), ChangeError> {
        self.make_of(&self.jane.fingerprint().to_string()).await
    }

    async fn make_of(&self, fingerprint: &str) -> Result<(), ChangeError> {
        self.make_if(fingerprint, || true).await
    }

    async fn make_if(
        &self,
        fingerprint: &str,
        proceed: impl Fn() -> bool + Sync,
    ) -> Result<(), ChangeError> {
        self.world
            .session
            .make_sign_in_certificate(&self.inventory, fingerprint, proceed)
            .await
    }

    async fn updates(&self) -> usize {
        self.count("PUT", PROFILE).await
    }

    async fn count(&self, verb: &str, tail: &str) -> usize {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == verb && request.url.path() == tail)
            .count()
    }

    async fn answer_update(&self, response: ResponseTemplate) {
        Mock::given(method("PUT"))
            .and(path(PROFILE))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }
}

#[tokio::test]
async fn the_profile_values_and_the_matched_uuid_are_sent() {
    let change = Change::new().await;
    Mock::given(method("PUT"))
        .and(path(PROFILE))
        .and(body_json(json!({
            "firstName": "Zelda",
            "lastName": "Unique-Surname",
            "email": "log.holder@example.com",
            "description": "Unique-Description-1",
            "certificateUuid": UUID,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile()))
        .expect(1)
        .mount(&change.world.ilm)
        .await;

    assert_eq!(change.make().await, Ok(()));

    assert_eq!(change.updates().await, 1);
}

#[tokio::test]
async fn a_check_follows_the_change() {
    let change = Change::new().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;
    let before = change.count("POST", SEARCH).await;

    change.make().await.unwrap();

    assert!(change.count("POST", SEARCH).await > before);
}

#[tokio::test]
async fn a_provider_sign_in_changes_nothing_local() {
    let change = Change::new().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;
    let view = change.world.session.view();

    change.make().await.unwrap();

    assert_eq!(change.world.session.view(), view);
    assert_eq!(change.world.settings.connection().certificate, None);
}

#[tokio::test]
async fn the_messages_of_a_rejection_come_back() {
    for status in [400, 422] {
        let change = Change::new().await;
        change
            .answer_update(ResponseTemplate::new(status).set_body_json(
                json!({ "message": ["The email is not valid.", "The name is too long."] }),
            ))
            .await;

        let error = change.make().await.unwrap_err();

        assert_eq!(
            error,
            ChangeError::Rejected(vec![
                "The email is not valid.".to_owned(),
                "The name is too long.".to_owned()
            ])
        );
        assert_eq!(
            error.to_string(),
            "The email is not valid. The name is too long."
        );
    }
}

#[tokio::test]
async fn a_rejection_with_one_message_or_none_is_said_in_plain_words() {
    let change = Change::new().await;
    change
        .answer_update(
            ResponseTemplate::new(422)
                .set_body_json(json!({ "message": "Certificate is revoked." })),
        )
        .await;
    assert_eq!(
        change.make().await.unwrap_err().to_string(),
        "Certificate is revoked."
    );

    let change = Change::new().await;
    change
        .answer_update(ResponseTemplate::new(422).set_body_string("not json"))
        .await;
    assert_eq!(
        change.make().await.unwrap_err().to_string(),
        "ILM did not accept the change."
    );
}

/// Lists the certificates of `StandInStore` but cannot open any.
struct Unopenable(StandInStore);

impl IdentityStore for Unopenable {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        self.0.certificates()
    }

    fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        None
    }
}

#[tokio::test]
async fn nothing_is_sent_when_the_caller_withdraws_before_ilm_is_changed() {
    let change = Change::new().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    let result = change
        .make_if(&change.jane.fingerprint().to_string(), || false)
        .await;

    assert_eq!(result, Err(ChangeError::Withdrawn));
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn nothing_is_sent_again_when_the_caller_withdraws_while_the_token_is_renewed() {
    let change = Change::new().await;
    change
        .world
        .grant(
            "refresh_token",
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "renewed",
                "refresh_token": "refresh",
                "expires_in": 3600,
                "token_type": "Bearer",
            })),
            None,
        )
        .await;
    change.answer_update(ResponseTemplate::new(401)).await;
    let asked = std::sync::atomic::AtomicUsize::new(0);

    let result = change
        .make_if(&change.jane.fingerprint().to_string(), || {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        })
        .await;

    assert_eq!(result, Err(ChangeError::Withdrawn));
    assert_eq!(change.updates().await, 1);
}

#[tokio::test]
async fn a_provider_sign_in_refuses_a_certificate_this_computer_cannot_open() {
    let jane = TestCa::new().issue(Issue::client("Jane"));
    let store = Unopenable(StandInStore::new(vec![jane.clone()]));
    let change = Change::on(json!({}), jane, store).await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    assert_eq!(change.make().await, Err(ChangeError::CannotSignIn));
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn a_provider_sign_in_refuses_a_certificate_that_cannot_be_presented_to_ilm() {
    let mut change = Change::new().await;
    change.world.session = change.world.session.with_certificate_client(Box::new(|_| {
        let unreachable = reqwest::Client::builder().https_only(true).build().unwrap();
        (unreachable, Default::default())
    }));
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    assert_eq!(change.make().await, Err(ChangeError::CannotSignIn));
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn a_403_says_ilm_does_not_allow_it() {
    let change = Change::new().await;
    change.answer_update(ResponseTemplate::new(403)).await;

    let error = change.make().await.unwrap_err();

    assert_eq!(error, ChangeError::NotAllowed);
    assert_eq!(error.to_string(), "ILM does not allow this.");
}

#[tokio::test]
async fn another_answer_of_ilm_is_reported_by_its_status() {
    let change = Change::new().await;
    change.answer_update(ResponseTemplate::new(500)).await;

    assert_eq!(change.make().await, Err(ChangeError::Unexpected(500)));
}

async fn refused(change: &Change, fingerprint: &str, expected: ChangeError) {
    assert_eq!(change.make_of(fingerprint).await, Err(expected));
    assert_eq!(change.updates().await, 0, "ILM was asked for nothing");
}

#[tokio::test]
async fn a_certificate_ilm_does_not_know_is_refused() {
    let change = Change::new().await;
    let other = Fingerprint::of(b"another").to_string();

    refused(&change, &other, ChangeError::NotInIlm).await;
    refused(&change, "not a fingerprint", ChangeError::NotInIlm).await;
}

#[tokio::test]
async fn a_certificate_that_is_not_issued_is_refused() {
    let change = Change::with(json!({ "state": "revoked" }), SystemTime::now()).await;

    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::NotIssued,
    )
    .await;
}

#[tokio::test]
async fn an_archived_certificate_is_refused() {
    let change = Change::with(json!({ "archived": true }), SystemTime::now()).await;

    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::Archived,
    )
    .await;
}

#[tokio::test]
async fn a_certificate_that_cannot_sign_in_here_is_refused() {
    let later = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * 100);
    let change = Change::with(json!({}), later).await;

    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::CannotSignIn,
    )
    .await;
}

#[tokio::test]
async fn the_sign_in_certificate_itself_is_refused() {
    let change = Change::new().await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "u-1",
            "username": "jdoe",
            "certificate": { "uuid": UUID, "fingerprint": search_text(&change.jane.fingerprint()) },
            "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
        })))
        .with_priority(1)
        .mount(&change.world.ilm)
        .await;
    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::AlreadySignIn,
    )
    .await;
}

#[tokio::test]
async fn nothing_is_changed_while_ilm_is_offline() {
    let change = Change::new().await;
    change.world.ilm.reset().await;
    assert!(matches!(change.check().await, Status::Offline { .. }));

    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::Offline,
    )
    .await;
}

#[tokio::test]
async fn nothing_is_changed_when_signed_out() {
    let change = Change::new().await;
    change.world.session.sign_out().await;

    refused(
        &change,
        &change.jane.fingerprint().to_string(),
        ChangeError::SignedOut,
    )
    .await;
    assert_eq!(ChangeError::SignedOut.to_string(), "You are not signed in.");
}

#[tokio::test]
async fn nothing_is_sent_when_another_sign_in_takes_over_during_the_change() {
    let change = Change::new().await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(profile())
                .set_delay(Duration::from_secs(1)),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&change.world.ilm)
        .await;
    let reads = change.count("GET", PROFILE).await;

    let (result, _) = tokio::join!(change.make(), async {
        while change.count("GET", PROFILE).await == reads {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        change.world.session.sign_out().await;
        change.world.sign_in().await;
    });

    assert_eq!(result, Err(ChangeError::SignedOut));
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn two_changes_at_once_do_not_interleave() {
    let change = Change::new().await;
    change
        .answer_update(
            ResponseTemplate::new(200)
                .set_body_json(profile())
                .set_delay(Duration::from_millis(300)),
        )
        .await;
    let before = change.count("GET", PROFILE).await + change.count("PUT", PROFILE).await;

    let (first, second) = tokio::join!(change.make(), change.make());

    assert_eq!((first, second), (Ok(()), Ok(())));
    let profile_calls: Vec<String> = change
        .world
        .ilm
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|request| request.url.path() == PROFILE)
        .map(|request| request.method.to_string())
        .skip(before)
        .collect();
    assert_eq!(profile_calls[..3], ["GET", "GET", "PUT"]);
}

#[tokio::test]
async fn a_change_waiting_behind_another_is_not_made_by_a_sign_in_that_started_meanwhile() {
    let change = Change::new().await;
    change
        .answer_update(
            ResponseTemplate::new(200)
                .set_body_json(profile())
                .set_delay(Duration::from_millis(500)),
        )
        .await;

    let (_, second, _) = tokio::join!(change.make(), change.make(), async {
        while change.updates().await == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        change.world.session.sign_out().await;
        change.world.sign_in().await;
    });

    assert_eq!(second, Err(ChangeError::SignedOut));
    assert_eq!(change.updates().await, 1);
}

#[tokio::test]
async fn the_log_of_a_change_holds_the_short_fingerprints_and_no_profile_text() {
    capture_logs();
    let change = Change::new().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;
    change.make().await.unwrap();
    let again = Change::new().await;
    again
        .answer_update(
            ResponseTemplate::new(422).set_body_json(json!({ "message": "Secret-Message-1." })),
        )
        .await;
    again.make().await.unwrap_err();

    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains(&format!(
            "INFO: sign-in certificate changed from {} to {}",
            old_sign_in().short(),
            change.jane.fingerprint().short()
        )),
        "{log}"
    );
    for (index, secret) in [
        "Zelda",
        "Unique-Surname",
        "log.holder@example.com",
        "Unique-Description-1",
        "Secret-Message-1.",
        UUID,
        &change.jane.fingerprint().to_string(),
        &old_sign_in().to_string(),
    ]
    .iter()
    .enumerate()
    {
        assert!(!log.contains(secret), "forbidden value {index} is logged");
    }
}

#[tokio::test]
async fn a_change_with_a_renewal_waiting_to_move_the_sign_in_completes() {
    let mut change = Change::new().await;
    let requests = Arc::new(Requests::new(change._folder.path()));
    change.world.session = change.world.session.with_requests(requests.clone());
    requests
        .add(Waiting {
            ilm: change.world.address(),
            username: "jdoe".into(),
            uuid: Some("c-new".into()),
            ra_profile: "ra-1".into(),
            authority: "auth-1".into(),
            key: None,
            label: "web".into(),
            since: 1,
            prepared: false,
            purpose: Purpose::Renew {
                replaces: "sign-in".into(),
                replaces_fingerprint: old_sign_in(),
                sign_in: true,
                same_key: true,
                automatic: false,
                switch: Some(PendingSwitch {
                    fingerprint: Fingerprint::of(b"new"),
                    failures: 1,
                }),
            },
            enrolled: false,
        })
        .unwrap();
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(json!({})))
        .await;

    let made = tokio::time::timeout(Duration::from_secs(10), change.make()).await;

    assert_eq!(made.expect("the change does not hang"), Ok(()));
}

// By policy: the certificate that enrolment installed becomes the sign-in certificate.

const ENROLLED: &str = "u-staff";
const STAFF: &str = r#"{ "uuid": "ra-staff", "name": "Staff" }"#;

fn staff() -> Value {
    serde_json::from_str(STAFF).unwrap()
}

fn naming(profile: &str) -> Layer {
    Layer {
        sign_in_certificate_profile: Some(profile.to_owned()),
        ..Layer::default()
    }
}

impl Change {
    /// ILM's matched certificate is from the RA Profile "Staff"; enrolment installed it.
    async fn enrolled() -> Self {
        let change = Self::with(
            json!({ "uuid": ENROLLED, "raProfile": staff() }),
            SystemTime::now(),
        )
        .await;
        change.installed();
        change
    }

    fn installed(&self) {
        self.enrolments
            .mark_installed(&self.ilm(), "jdoe", ENROLLED)
            .unwrap();
    }

    fn ilm(&self) -> crate::ilm::IlmUrl {
        self.world.session.signed_in_as().unwrap().ilm
    }

    async fn by_policy(&self, policy: &Layer) -> Vec<SignInByPolicy> {
        self.world
            .session
            .sign_in_by_policy(&self.inventory, policy, &|| true)
            .await
    }

    fn standing(&self) -> crate::enrolment::Standing {
        self.enrolments.standing(&self.ilm(), "jdoe").unwrap()
    }

    fn failed_at(&self, at: i64) {
        self.enrolments
            .record_failure(&self.ilm(), "jdoe", &sign_in_key(ENROLLED), at)
            .unwrap();
    }
}

#[tokio::test]
async fn an_installed_enrolled_certificate_of_the_named_profile_becomes_the_sign_in_certificate() {
    let change = Change::enrolled().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    let done = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        done,
        vec![SignInByPolicy::Set {
            uuid: ENROLLED.into()
        }]
    );
    assert_eq!(change.updates().await, 1);
    assert!(change.standing().installed.is_empty());
}

#[tokio::test]
async fn a_certificate_of_another_profile_is_left_as_it_is() {
    let change = Change::enrolled().await;

    let done = change.by_policy(&naming("Servers")).await;

    assert!(done.is_empty());
    assert_eq!(change.updates().await, 0);
    assert!(change.standing().installed.is_empty());
}

#[tokio::test]
async fn a_certificate_issued_outside_enrolment_is_left_as_it_is() {
    let change = Change::with(
        json!({ "uuid": ENROLLED, "raProfile": staff() }),
        SystemTime::now(),
    )
    .await;

    let done = change.by_policy(&naming("Staff")).await;

    assert!(done.is_empty());
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn no_profile_named_or_an_oauth_only_policy_changes_nothing() {
    let change = Change::enrolled().await;
    let oauth = Layer {
        sign_in_method: Some(SignInMethod::Oauth),
        ..naming("Staff")
    };

    assert!(change.by_policy(&Layer::default()).await.is_empty());
    assert!(change.by_policy(&oauth).await.is_empty());
    assert_eq!(change.updates().await, 0);
}

#[tokio::test]
async fn a_certificate_that_already_is_the_sign_in_certificate_changes_nothing() {
    let change = Change::enrolled().await;
    let mut held = profile();
    held["certificate"] =
        json!({ "uuid": ENROLLED, "fingerprint": search_text(&change.jane.fingerprint()) });
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(held))
        .with_priority(1)
        .mount(&change.world.ilm)
        .await;
    change.check().await;

    let done = change.by_policy(&naming("Staff")).await;

    assert!(done.is_empty());
    assert_eq!(change.updates().await, 0);
    assert!(change.standing().installed.is_empty());
}

#[tokio::test]
async fn a_failed_change_is_recorded_and_not_retried_within_a_day() {
    let change = Change::enrolled().await;
    change.answer_update(ResponseTemplate::new(500)).await;

    let first = change.by_policy(&naming("Staff")).await;
    let second = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        first,
        vec![SignInByPolicy::Failed {
            uuid: ENROLLED.into(),
            failures: 1
        }]
    );
    assert!(second.is_empty());
    assert_eq!(change.updates().await, 1);
    assert_eq!(change.standing().installed, vec![ENROLLED.to_owned()]);
    assert!(
        change
            .standing()
            .failed_within_a_day(&sign_in_key(ENROLLED), now_ms())
    );
}

#[tokio::test]
async fn a_failed_change_is_retried_after_a_day() {
    let change = Change::enrolled().await;
    change.answer_update(ResponseTemplate::new(500)).await;
    change.failed_at(now_ms() - 2 * DAY_MS);

    let done = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        done,
        vec![SignInByPolicy::Failed {
            uuid: ENROLLED.into(),
            failures: 2
        }]
    );
    assert!(!done[0].needs_notice());
    assert_eq!(change.updates().await, 1);
}

#[tokio::test]
async fn the_third_failure_is_the_one_to_tell_the_person_about() {
    let change = Change::enrolled().await;
    change.answer_update(ResponseTemplate::new(500)).await;
    change.failed_at(now_ms() - 2 * DAY_MS);
    change.failed_at(now_ms() - 2 * DAY_MS);

    let done = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        done,
        vec![SignInByPolicy::Failed {
            uuid: ENROLLED.into(),
            failures: 3
        }]
    );
    assert!(done[0].needs_notice());
}

#[tokio::test]
async fn a_success_clears_the_failures() {
    let change = Change::enrolled().await;
    change.failed_at(now_ms() - 2 * DAY_MS);
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    change.by_policy(&naming("Staff")).await;

    assert!(
        !change
            .standing()
            .failed_within_a_day(&sign_in_key(ENROLLED), now_ms())
    );
    assert_eq!(change.standing().failures(&sign_in_key(ENROLLED)), 0);
}

#[tokio::test]
async fn the_log_of_the_change_names_no_certificate_content() {
    capture_logs();
    let change = Change::enrolled().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;

    change.by_policy(&naming("Staff")).await;

    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains(&format!("sign-in certificate set by policy: {ENROLLED}")));
    assert!(!log.contains("Zelda"));
    assert!(!log.contains("Unique-Surname"));
}

#[tokio::test]
async fn a_lost_answer_to_the_change_of_a_certificate_sign_in_is_reconciled_at_once() {
    use std::sync::atomic::AtomicBool;

    use super::renew_tests::{MovesWithTheUpdate, TakesTheUpdate};
    use super::{Credential, State, lock};

    let change = Change::enrolled().await;
    if let State::SignedIn(active) = &mut *lock(&change.world.session.state) {
        active.credential = Credential::Certificate {
            fingerprint: old_sign_in(),
            client: client_for_tests(),
            generation: Arc::new(()),
            not_after: None,
        };
    }
    let moved = Arc::new(AtomicBool::new(false));
    let mut new = profile();
    new["certificate"] =
        json!({ "uuid": ENROLLED, "fingerprint": search_text(&change.jane.fingerprint()) });
    Mock::given(method("PUT"))
        .and(path(PROFILE))
        .respond_with(TakesTheUpdate {
            moved: moved.clone(),
            status: 500,
        })
        .mount(&change.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(MovesWithTheUpdate {
            moved,
            old: profile(),
            new,
        })
        .with_priority(1)
        .mount(&change.world.ilm)
        .await;

    let done = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        done,
        vec![SignInByPolicy::Set {
            uuid: ENROLLED.into()
        }]
    );
    assert_eq!(
        change.world.settings.connection().certificate,
        Some(change.jane.fingerprint())
    );
}

#[tokio::test]
async fn a_lost_answer_to_the_change_of_a_provider_sign_in_is_learned_from_the_profile() {
    use std::sync::atomic::AtomicBool;

    use super::renew_tests::{MovesWithTheUpdate, TakesTheUpdate};
    use super::{State, lock};

    let change = Change::enrolled().await;
    let moved = Arc::new(AtomicBool::new(false));
    let mut new = profile();
    new["certificate"] =
        json!({ "uuid": ENROLLED, "fingerprint": search_text(&change.jane.fingerprint()) });
    Mock::given(method("PUT"))
        .and(path(PROFILE))
        .respond_with(TakesTheUpdate {
            moved: moved.clone(),
            status: 500,
        })
        .mount(&change.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(MovesWithTheUpdate {
            moved,
            old: profile(),
            new,
        })
        .with_priority(1)
        .mount(&change.world.ilm)
        .await;

    let done = change.by_policy(&naming("Staff")).await;

    assert_eq!(
        done,
        vec![SignInByPolicy::Set {
            uuid: ENROLLED.into()
        }]
    );
    match &*lock(&change.world.session.state) {
        State::SignedIn(active) => assert_eq!(
            active
                .person
                .sign_in
                .as_ref()
                .map(|held| held.uuid.as_str()),
            Some(ENROLLED)
        ),
        _ => panic!("signed out"),
    }
}

#[tokio::test]
async fn a_policy_batch_stops_once_another_sign_in_takes_over() {
    use super::{State, lock};

    let change = Change::enrolled().await;
    change
        .answer_update(ResponseTemplate::new(200).set_body_json(profile()))
        .await;
    let session = &change.world.session;
    let replaced = || {
        if let State::SignedIn(active) = &mut *lock(&session.state) {
            active.id = Arc::new(());
        }
        true
    };

    let done = session
        .sign_in_by_policy(&change.inventory, &naming("Staff"), &replaced)
        .await;

    assert!(done.is_empty(), "{done:?}");
    assert_eq!(change.updates().await, 0);
}
