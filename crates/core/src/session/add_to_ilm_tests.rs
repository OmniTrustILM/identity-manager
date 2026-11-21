//! Adding certificates of this computer to ILM.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::add_to_ilm::WITHDRAWN;
use super::tests::{LOG, World, capture_logs};
use super::{AddOutcome, AddResult, ChangeError, SessionView};
use crate::http::client_for_tests;
use crate::identity::Fingerprint;
use crate::identity::testing::{Issue, StandInStore, TestCa, TestIdentity};
use crate::identity::tls::CertificateAsked;
use crate::ilm::certificates::search_text;
use crate::ilm::upload::{GroupChoice, RaProfileChoice};
use crate::inventory::{Inventory, Status, Trigger};

const PROFILE: &str = "/api/v1/auth/profile";
const SEARCH: &str = "/api/v1/certificates";
const ALLOWED: &str = "/api/v1/resources/certificates/objects/allowed-actions";
const UPLOAD: &str = "/api/v1/certificates/upload";
const UPLOADED: &str = "/api/v1/certificates/u-new";
const GROUPS: &str = "/api/v1/groups";
const RA_PROFILES: &str = "/api/v1/raProfiles";

struct Adding {
    world: World,
    inventory: Arc<Inventory>,
    jane: TestIdentity,
    john: TestIdentity,
    _folder: TempDir,
}

impl Adding {
    /// ILM matches none of the two local certificates.
    async fn new() -> Self {
        Self::matching(&[]).await
    }

    /// ILM matches the local certificates named in `matched`.
    async fn matching(matched: &[&str]) -> Self {
        let ca = TestCa::new();
        let jane = ca.issue(Issue::client("Jane"));
        let john = ca.issue(Issue::client("John"));
        let store = StandInStore::new(vec![jane.clone(), john.clone()]).at(SystemTime::now());
        let mut world = World::new().await.with_identities(store);
        world.session = world.session.with_certificate_client(Box::new(|_| {
            (client_for_tests(), CertificateAsked::offered_for_tests())
        }));
        world.code_grant("access", Some("refresh"), 3600).await;
        Mock::given(method("GET"))
            .and(path(PROFILE))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-person",
                "username": "jdoe",
                "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
            })))
            .mount(&world.ilm)
            .await;
        let found: Vec<Value> = [("Jane", &jane), ("John", &john)]
            .iter()
            .filter(|(name, _)| matched.contains(name))
            .map(|(name, identity)| {
                json!({
                    "uuid": format!("u-{name}"),
                    "commonName": name,
                    "state": "issued",
                    "validationStatus": "valid",
                    "fingerprint": search_text(&identity.fingerprint()),
                })
            })
            .collect();
        Mock::given(method("POST"))
            .and(path(SEARCH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "certificates": found,
                "pageNumber": 1,
                "totalPages": 1,
                "totalItems": found.len(),
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
        let folder = tempfile::tempdir().unwrap();
        let inventory = Arc::new(Inventory::new(folder.path()));
        inventory.attach(&world.session);
        let adding = Self {
            world,
            inventory,
            jane,
            john,
            _folder: folder,
        };
        adding.check().await;
        adding
    }

    async fn check(&self) -> Status {
        self.inventory
            .check(
                &self.world.session,
                Trigger::SyncNow,
                &[self.jane.fingerprint(), self.john.fingerprint()],
            )
            .await
    }

    async fn add(
        &self,
        fingerprints: &[String],
        group: Option<&str>,
        ra_profile: Option<&str>,
    ) -> Result<Vec<AddResult>, ChangeError> {
        self.add_if(fingerprints, group, ra_profile, || true).await
    }

    async fn add_if(
        &self,
        fingerprints: &[String],
        group: Option<&str>,
        ra_profile: Option<&str>,
        proceed: impl Fn() -> bool + Sync,
    ) -> Result<Vec<AddResult>, ChangeError> {
        self.world
            .session
            .add_to_ilm(
                &self.inventory,
                fingerprints.to_vec(),
                group.map(str::to_owned),
                ra_profile.map(str::to_owned),
                proceed,
            )
            .await
    }

    async fn add_one(&self, who: &TestIdentity) -> AddOutcome {
        let results = self
            .add(&[who.fingerprint().to_string()], None, None)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        results.into_iter().next().unwrap().outcome
    }

    async fn answer_upload(&self, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path(UPLOAD))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    async fn upload_ok(&self) {
        self.answer_upload(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "u-new" })))
            .await;
    }

    async fn answer_update(&self, response: ResponseTemplate) {
        Mock::given(method("PATCH"))
            .and(path(UPLOADED))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
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

    async fn bodies(&self, verb: &str, tail: &str) -> Vec<Value> {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == verb && request.url.path() == tail)
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }
}

#[tokio::test]
async fn the_upload_carries_exactly_the_der_of_the_chosen_fingerprint() {
    let adding = Adding::new().await;
    Mock::given(method("POST"))
        .and(path(UPLOAD))
        .and(body_json(json!({
            "certificate": STANDARD.encode(adding.john.leaf().as_ref()),
            "customAttributes": [],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "u-new" })))
        .expect(1)
        .mount(&adding.world.ilm)
        .await;
    adding.answer_update(ResponseTemplate::new(200)).await;

    assert_eq!(adding.add_one(&adding.john).await, AddOutcome::Added);

    assert_eq!(adding.count("POST", UPLOAD).await, 1);
}

#[tokio::test]
async fn the_owner_is_the_person_of_the_profile_and_the_choices_are_sent_when_made() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let jane = adding.jane.fingerprint().to_string();
    let john = adding.john.fingerprint().to_string();

    adding.add(&[jane], None, None).await.unwrap();
    adding
        .add(&[john], Some("g-1"), Some("ra-1"))
        .await
        .unwrap();

    assert_eq!(
        adding.bodies("PATCH", UPLOADED).await,
        vec![
            json!({ "ownerUuid": "u-person" }),
            json!({ "ownerUuid": "u-person", "groupUuids": ["g-1"], "raProfileUuid": "ra-1" }),
        ]
    );
}

#[tokio::test]
async fn several_certificates_are_added_in_order_and_a_check_follows() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let before = adding.count("POST", SEARCH).await;
    let asked = vec![
        adding.john.fingerprint().to_string(),
        adding.jane.fingerprint().to_string(),
    ];

    let results = adding.add(&asked, None, None).await.unwrap();

    assert_eq!(
        results,
        vec![
            AddResult {
                fingerprint: asked[0].clone(),
                outcome: AddOutcome::Added
            },
            AddResult {
                fingerprint: asked[1].clone(),
                outcome: AddOutcome::Added
            },
        ]
    );
    let uploads = adding.bodies("POST", UPLOAD).await;
    assert_eq!(
        uploads[0]["certificate"],
        STANDARD.encode(adding.john.leaf().as_ref())
    );
    assert_eq!(
        uploads[1]["certificate"],
        STANDARD.encode(adding.jane.leaf().as_ref())
    );
    assert!(adding.count("POST", SEARCH).await > before);
}

#[tokio::test]
async fn a_certificate_ilm_holds_already_counts_as_added() {
    let adding = Adding::new().await;
    adding.answer_upload(ResponseTemplate::new(409)).await;

    assert_eq!(adding.add_one(&adding.jane).await, AddOutcome::AlreadyInIlm);
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);
}

#[tokio::test]
async fn a_refused_upload_says_why() {
    let adding = Adding::new().await;
    adding.answer_upload(ResponseTemplate::new(403)).await;
    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::NotAdded("ILM does not allow this.".to_owned())
    );

    let adding = Adding::new().await;
    adding
        .answer_upload(
            ResponseTemplate::new(422)
                .set_body_json(json!({ "message": ["Not a certificate.", "Too old."] })),
        )
        .await;
    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::NotAdded("Not a certificate. Too old.".to_owned())
    );
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);

    let adding = Adding::new().await;
    adding.answer_upload(ResponseTemplate::new(500)).await;
    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::NotAdded("ILM answered with an error (500).".to_owned())
    );
}

#[tokio::test]
async fn a_refused_update_after_a_good_upload_is_added_not_managed() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding
        .answer_update(
            ResponseTemplate::new(422).set_body_json(json!({ "message": "No such group." })),
        )
        .await;

    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::AddedNotManaged(vec!["No such group.".to_owned()])
    );
    assert_eq!(adding.count("POST", UPLOAD).await, 1);

    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(403)).await;
    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::AddedNotManaged(vec!["ILM does not allow this.".to_owned()])
    );
}

#[tokio::test]
async fn a_conflict_on_the_update_after_a_good_upload_is_added_not_managed() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(409)).await;

    assert_eq!(
        adding.add_one(&adding.jane).await,
        AddOutcome::AddedNotManaged(Vec::new())
    );
}

#[tokio::test]
async fn nothing_is_sent_when_the_gate_says_no_before_the_start() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    let before = adding.count("GET", PROFILE).await;

    let result = adding
        .add_if(&[adding.jane.fingerprint().to_string()], None, None, || {
            false
        })
        .await;

    assert_eq!(result, Err(ChangeError::Withdrawn));
    assert_eq!(adding.count("GET", PROFILE).await, before);
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
}

#[tokio::test]
async fn a_gate_that_turns_no_after_the_upload_leaves_the_certificate_not_managed() {
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let asked = AtomicUsize::new(0);
    // The profile and the upload are let through, and the update is not.
    let gate = || asked.fetch_add(1, Ordering::SeqCst) < 3;

    let results = adding
        .add_if(
            &[
                adding.jane.fingerprint().to_string(),
                adding.john.fingerprint().to_string(),
            ],
            None,
            None,
            gate,
        )
        .await
        .unwrap();

    assert_eq!(
        results[0].outcome,
        AddOutcome::AddedNotManaged(vec![WITHDRAWN.to_owned()])
    );
    assert_eq!(
        results[1].outcome,
        AddOutcome::NotAdded(WITHDRAWN.to_owned())
    );
    assert_eq!(adding.count("POST", UPLOAD).await, 1);
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);
}

#[tokio::test]
async fn the_check_after_an_add_counts_only_the_certificates_on_this_computer_now() {
    let adding = Adding::new().await;
    let mut held = adding
        .world
        .session
        .in_identities(|store| store.certificates())
        .await
        .unwrap();
    let mut gone = held[0].clone();
    gone.fingerprint = Fingerprint::of(&[9]);
    held.push(gone);
    adding.inventory.set_local(&held);
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;

    adding.add_one(&adding.jane).await;

    let counts = adding.inventory.summary().unwrap().counts;
    assert_eq!(counts.valid + counts.expiring + counts.expired, 2);
}

#[tokio::test]
async fn a_matched_or_unknown_fingerprint_is_refused_and_nothing_is_sent() {
    let adding = Adding::matching(&["Jane"]).await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let unknown = Adding::new().await.jane.fingerprint().to_string();
    let asked = vec![
        adding.jane.fingerprint().to_string(),
        unknown,
        "not a fingerprint".to_owned(),
    ];

    let results = adding.add(&asked, None, None).await.unwrap();

    assert_eq!(
        results
            .iter()
            .map(|result| result.outcome.clone())
            .collect::<Vec<_>>(),
        vec![
            AddOutcome::NotAdded("ILM has this certificate already.".to_owned()),
            AddOutcome::NotAdded("This certificate is not on this computer.".to_owned()),
            AddOutcome::NotAdded("This certificate is not on this computer.".to_owned()),
        ]
    );
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);
}

#[tokio::test]
async fn nothing_is_added_while_ilm_is_offline() {
    let adding = Adding::new().await;
    adding.world.ilm.reset().await;
    assert!(matches!(adding.check().await, Status::Offline { .. }));

    let result = adding
        .add(&[adding.jane.fingerprint().to_string()], None, None)
        .await;

    assert_eq!(result, Err(ChangeError::Offline));
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
}

#[tokio::test]
async fn nothing_is_added_when_signed_out() {
    let adding = Adding::new().await;
    adding.world.session.sign_out().await;

    let result = adding
        .add(&[adding.jane.fingerprint().to_string()], None, None)
        .await;

    assert_eq!(result, Err(ChangeError::SignedOut));
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
}

#[tokio::test]
async fn the_choices_are_the_groups_and_the_enabled_ra_profiles() {
    let adding = Adding::new().await;
    Mock::given(method("GET"))
        .and(path(GROUPS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "uuid": "g-1", "name": "Web", "description": "ignored" }
        ])))
        .mount(&adding.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(RA_PROFILES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "uuid": "ra-1", "name": "Staff", "enabled": true, "authorityInstanceName": "Corporate CA" },
            { "uuid": "ra-2", "name": "Off", "enabled": false }
        ])))
        .mount(&adding.world.ilm)
        .await;

    let choices = adding.world.session.add_to_ilm_choices().await.unwrap();

    assert_eq!(
        choices.groups,
        Some(vec![GroupChoice {
            uuid: "g-1".to_owned(),
            name: "Web".to_owned()
        }])
    );
    assert_eq!(
        choices.ra_profiles,
        Some(vec![RaProfileChoice {
            uuid: "ra-1".to_owned(),
            name: "Staff".to_owned(),
            authority: Some("Corporate CA".to_owned())
        }])
    );
}

#[tokio::test]
async fn a_listing_that_fails_leaves_only_its_own_choice_out() {
    let groups = json!([{ "uuid": "g-1", "name": "Web" }]);
    let profiles = json!([{ "uuid": "ra-1", "name": "Staff", "enabled": true }]);
    for failing in [GROUPS, RA_PROFILES] {
        let adding = Adding::new().await;
        for (tail, body) in [(GROUPS, &groups), (RA_PROFILES, &profiles)] {
            let answer = if tail == failing {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(body)
            };
            Mock::given(method("GET"))
                .and(path(tail))
                .respond_with(answer)
                .mount(&adding.world.ilm)
                .await;
        }

        let choices = adding.world.session.add_to_ilm_choices().await.unwrap();

        assert_eq!(choices.groups.is_none(), failing == GROUPS);
        assert_eq!(choices.ra_profiles.is_none(), failing == RA_PROFILES);
    }
}

#[tokio::test]
async fn a_list_the_person_may_not_see_or_ilm_lacks_is_none() {
    for (groups, ra_profiles) in [(403, 404), (404, 403)] {
        let adding = Adding::new().await;
        for (tail, status) in [(GROUPS, groups), (RA_PROFILES, ra_profiles)] {
            Mock::given(method("GET"))
                .and(path(tail))
                .respond_with(ResponseTemplate::new(status))
                .mount(&adding.world.ilm)
                .await;
        }

        let choices = adding.world.session.add_to_ilm_choices().await.unwrap();

        assert_eq!((choices.groups, choices.ra_profiles), (None, None));
    }
}

#[tokio::test]
async fn the_choices_are_refused_when_signed_out() {
    let adding = Adding::new().await;
    adding.world.session.sign_out().await;

    assert_eq!(
        adding.world.session.add_to_ilm_choices().await,
        Err(ChangeError::SignedOut)
    );
}

#[tokio::test]
async fn the_log_says_what_happened_without_names_or_messages() {
    capture_logs();
    let adding = Adding::new().await;
    adding.upload_ok().await;
    adding
        .answer_update(
            ResponseTemplate::new(422).set_body_json(json!({ "message": "Unique-Message-Z9" })),
        )
        .await;

    adding
        .add(
            &[adding.jane.fingerprint().to_string()],
            Some("Unique-Group-Z9"),
            None,
        )
        .await
        .unwrap();

    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains("adding 1 certificates to ILM (group chosen: yes, RA Profile chosen: no)")
    );
    assert!(log.contains("added, not managed"));
    assert!(log.contains("ILM refused the update (400 or 422)"));
    for private in [
        "Unique-Message-Z9",
        "Unique-Group-Z9",
        "Jane",
        "u-person",
        "u-new",
    ] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}
