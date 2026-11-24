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
use super::{AddOutcome, AddResult, ChangeError, FormInput, SessionView};
use crate::attributes::{FieldProblem, FormView, Problem};
use crate::http::client_for_tests;
use crate::identity::testing::{Issue, StandInStore, TestCa, TestIdentity};
use crate::identity::tls::CertificateAsked;
use crate::identity::{
    ClientIdentity, Fingerprint, IdentityStore, LocalCertificate, StoreUnreadable,
};
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
const CUSTOM: &str = "/api/v1/attributes/custom/resources/certificates";

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
                None,
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
async fn a_matched_fingerprint_counts_as_added_and_an_unknown_one_is_refused_without_sending_anything()
 {
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
            AddOutcome::AlreadyInIlm,
            AddOutcome::NotAdded("This certificate is not on this computer.".to_owned()),
            AddOutcome::NotAdded("This certificate is not on this computer.".to_owned()),
        ]
    );
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);
}

/// A store of this computer that cannot be read.
struct UnreadableStore;

impl IdentityStore for UnreadableStore {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        Err(StoreUnreadable("the keychain is locked".to_owned()))
    }

    fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        None
    }
}

#[tokio::test]
async fn nothing_is_added_when_the_store_of_this_computer_cannot_be_read() {
    let mut adding = Adding::new().await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let searches = adding.count("POST", SEARCH).await;
    adding.world.session = adding
        .world
        .session
        .with_identities(Arc::new(UnreadableStore));
    let asked = vec![
        adding.jane.fingerprint().to_string(),
        adding.john.fingerprint().to_string(),
    ];

    let results = adding.add(&asked, None, None).await.unwrap();

    let unreadable =
        AddOutcome::NotAdded("The certificates on this computer cannot be read.".to_owned());
    assert_eq!(
        results
            .iter()
            .map(|result| result.outcome.clone())
            .collect::<Vec<_>>(),
        vec![unreadable.clone(), unreadable]
    );
    assert_eq!(adding.count("POST", UPLOAD).await, 0);
    assert_eq!(adding.count("PATCH", UPLOADED).await, 0);
    assert_eq!(adding.count("POST", SEARCH).await, searches);
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
            { "uuid": "ra-1", "name": "Staff", "enabled": true, "authorityInstanceName": "Corporate CA", "authorityInstanceUuid": "auth-1" },
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
            description: None,
            authority: Some("Corporate CA".to_owned()),
            authority_uuid: Some("auth-1".to_owned())
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
        log.contains("adding 1 certificates to ILM (group chosen: yes, RA Profile chosen: no, custom attributes: 0)")
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

fn definition(name: &str, properties: Value) -> Value {
    let mut properties = properties;
    properties["label"] = json!(format!("{name} label"));
    json!({
        "uuid": format!("u-{name}"),
        "name": name,
        "version": 3,
        "schemaVersion": "v3",
        "type": "custom",
        "contentType": "string",
        "properties": properties,
    })
}

/// A required attribute to fill in, an optional one and a required read-only one.
fn custom_definitions() -> Vec<Value> {
    let mut fixed = definition("fixed", json!({ "required": true, "readOnly": true }));
    fixed["content"] = json!([{ "data": "Fixed-Content", "contentType": "string" }]);
    vec![
        definition("dept", json!({ "required": true })),
        definition("note", json!({})),
        fixed,
    ]
}

fn request_attributes(dept: &str) -> Value {
    json!([
        {
            "uuid": "u-dept",
            "name": "dept",
            "contentType": "string",
            "version": "v3",
            "content": [{ "data": dept, "contentType": "string" }],
        },
        {
            "uuid": "u-fixed",
            "name": "fixed",
            "contentType": "string",
            "version": "v3",
            "content": [{ "data": "Fixed-Content", "contentType": "string" }],
        },
    ])
}

impl Adding {
    async fn serve_custom(&self, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(CUSTOM))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    /// Opens the custom form of `definitions` through the choices.
    async fn open_custom(&self, definitions: Vec<Value>) -> FormView {
        self.serve_custom(ResponseTemplate::new(200).set_body_json(definitions))
            .await;
        self.world
            .session
            .add_to_ilm_choices()
            .await
            .unwrap()
            .custom_attributes
            .expect("the custom form is open")
    }

    async fn add_form(
        &self,
        fingerprints: &[String],
        id: &str,
        values: Value,
    ) -> Result<Vec<AddResult>, ChangeError> {
        self.world
            .session
            .add_to_ilm(
                &self.inventory,
                fingerprints.to_vec(),
                None,
                None,
                Some(FormInput {
                    id: id.to_owned(),
                    values,
                }),
                || true,
            )
            .await
    }

    async fn expect_no_upload(&self) {
        Mock::given(method("POST"))
            .and(path(UPLOAD))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "u-new" })))
            .expect(0)
            .mount(&self.world.ilm)
            .await;
    }
}

#[tokio::test]
async fn the_choices_carry_the_custom_form() {
    let adding = Adding::new().await;

    let form = adding.open_custom(custom_definitions()).await;

    let names: Vec<&str> = form
        .groups
        .iter()
        .flat_map(|group| group.fields.iter().map(|field| field.name.as_str()))
        .collect();
    assert_eq!(names, ["dept", "note", "fixed"]);
}

#[tokio::test]
async fn a_custom_listing_that_is_missing_leaves_the_form_out() {
    for status in [403, 404] {
        let adding = Adding::new().await;
        adding.serve_custom(ResponseTemplate::new(status)).await;

        let choices = adding.world.session.add_to_ilm_choices().await.unwrap();

        assert_eq!(choices.custom_attributes, None, "status {status}");
    }
}

#[tokio::test]
async fn a_custom_listing_that_fails_fails_the_choices() {
    let adding = Adding::new().await;
    adding.serve_custom(ResponseTemplate::new(500)).await;

    let choices = adding.world.session.add_to_ilm_choices().await;

    assert_eq!(choices, Err(ChangeError::Unexpected(500)));
}

#[tokio::test]
async fn every_upload_carries_the_request_attributes_of_the_form() {
    let adding = Adding::new().await;
    let form = adding.open_custom(custom_definitions()).await;
    for who in [&adding.jane, &adding.john] {
        Mock::given(method("POST"))
            .and(path(UPLOAD))
            .and(body_json(json!({
                "certificate": STANDARD.encode(who.leaf().as_ref()),
                "customAttributes": request_attributes("Sales"),
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "u-new" })))
            .expect(1)
            .mount(&adding.world.ilm)
            .await;
    }
    adding.answer_update(ResponseTemplate::new(200)).await;
    let asked = vec![
        adding.jane.fingerprint().to_string(),
        adding.john.fingerprint().to_string(),
    ];
    let values = json!({
        "dept": { "kind": "text", "value": "Sales" },
        "fixed": { "kind": "text", "value": "Ignored" },
    });

    let results = adding.add_form(&asked, &form.id, values).await.unwrap();

    assert!(
        results
            .iter()
            .all(|result| result.outcome == AddOutcome::Added)
    );
}

#[tokio::test]
async fn a_form_with_problems_sends_nothing_and_stays_open() {
    let adding = Adding::new().await;
    let form = adding.open_custom(custom_definitions()).await;
    adding.expect_no_upload().await;
    let asked = vec![adding.jane.fingerprint().to_string()];

    let refused = adding.add_form(&asked, &form.id, json!({})).await;

    assert_eq!(
        refused,
        Err(ChangeError::FormProblems(vec![FieldProblem {
            name: "dept".to_owned(),
            problem: Problem::Required
        }]))
    );
    assert!(
        adding
            .world
            .session
            .check_form(&form.id, &json!({}))
            .is_ok()
    );
}

#[tokio::test]
async fn a_form_with_an_unsupported_required_attribute_sends_nothing() {
    let adding = Adding::new().await;
    let mut odd = definition("odd", json!({ "required": true }));
    odd["contentType"] = json!("quaternion");
    let form = adding.open_custom(vec![odd]).await;
    adding.expect_no_upload().await;
    let asked = vec![adding.jane.fingerprint().to_string()];

    let refused = adding.add_form(&asked, &form.id, json!({})).await;

    assert_eq!(refused, Err(ChangeError::FormBlocked));
}

#[tokio::test]
async fn a_form_that_is_gone_is_refused() {
    let adding = Adding::new().await;
    adding.expect_no_upload().await;
    let asked = vec![adding.jane.fingerprint().to_string()];

    let refused = adding.add_form(&asked, "no-such-form", json!({})).await;

    assert_eq!(refused, Err(ChangeError::FormGone));
    assert_eq!(
        ChangeError::FormGone.to_string(),
        "This form is no longer open. Open Add to ILM again."
    );
}

#[tokio::test]
async fn the_form_is_closed_by_the_add() {
    let adding = Adding::new().await;
    let form = adding.open_custom(custom_definitions()).await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let asked = vec![adding.jane.fingerprint().to_string()];
    let values = json!({ "dept": { "kind": "text", "value": "Sales" } });

    adding
        .add_form(&asked, &form.id, values.clone())
        .await
        .unwrap();
    let again = adding.add_form(&asked, &form.id, values).await;

    assert_eq!(again, Err(ChangeError::FormGone));
    assert_eq!(adding.count("POST", UPLOAD).await, 1);
}

#[tokio::test]
async fn a_form_a_callback_changes_while_ilm_is_asked_is_checked_again_and_stays_open() {
    let adding = Adding::new().await;
    let attribute = |name: &str, properties: Value| {
        let mut properties = properties;
        properties["label"] = json!(format!("{name} label"));
        json!({
            "uuid": format!("u-{name}"),
            "name": name,
            "version": 3,
            "schemaVersion": "v3",
            "type": "data",
            "contentType": "string",
            "properties": properties,
        })
    };
    let mut region = attribute("region", json!({ "list": true }));
    region["content"] = json!([{ "data": "eu", "contentType": "string" }]);
    let extras = json!({
        "uuid": "u-extras",
        "name": "extras",
        "type": "group",
        "attributeCallback": { "dependsOn": ["region"] },
    });
    adding.world.ilm.reset().await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "uuid": "u-person",
                    "username": "jdoe",
                    "permissions": { "allowedListings": [], "allowedActions": [] },
                }))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&adding.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/attributes/issue",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([region, extras])))
        .mount(&adding.world.ilm)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/certificates/ra-1/callback"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([attribute("email", json!({ "required": true }))])),
        )
        .mount(&adding.world.ilm)
        .await;
    adding.expect_no_upload().await;
    let session = &adding.world.session;
    let form = session
        .open_form(crate::attributes::FormContext::Issue {
            authority: "auth-1".into(),
            ra_profile: "ra-1".into(),
        })
        .await
        .unwrap()
        .unwrap();
    let eu = crate::attributes::option_key(&json!({ "data": "eu", "contentType": "string" }));
    let values = json!({ "region": { "kind": "option", "value": eu } });
    let asked = vec![adding.jane.fingerprint().to_string()];

    let adding_to_ilm = adding.add_form(&asked, &form.id, values.clone());
    let changing = async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        session
            .run_callback(&form.id, "extras", &values, 1)
            .await
            .unwrap();
    };
    let (refused, ()) = tokio::join!(adding_to_ilm, changing);

    assert_eq!(
        refused,
        Err(ChangeError::FormProblems(vec![FieldProblem {
            name: "email".to_owned(),
            problem: Problem::Required
        }]))
    );
    assert!(session.check_form(&form.id, &values).is_ok());
}

#[tokio::test]
async fn the_log_counts_the_custom_attributes_and_never_shows_their_values() {
    capture_logs();
    let adding = Adding::new().await;
    let form = adding.open_custom(custom_definitions()).await;
    adding.upload_ok().await;
    adding.answer_update(ResponseTemplate::new(200)).await;
    let asked = vec![adding.jane.fingerprint().to_string()];
    let values = json!({ "dept": { "kind": "text", "value": "Unique-Value-Z9" } });

    adding.add_form(&asked, &form.id, values).await.unwrap();

    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("custom attributes: 2)"));
    for private in ["Unique-Value-Z9", "Fixed-Content"] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}

#[tokio::test]
async fn the_log_of_a_form_with_a_secret_a_callback_and_an_add_holds_no_value_option_file_name_or_message()
 {
    capture_logs();
    let adding = Adding::new().await;
    let attribute = |name: &str, content_type: &str, version: u8, properties: Value| {
        let mut properties = properties;
        properties["label"] = json!(format!("{name} label"));
        json!({
            "uuid": format!("u-{name}"),
            "name": name,
            "version": version,
            "type": "data",
            "contentType": content_type,
            "properties": properties,
        })
    };
    let mut chooser = attribute("region", "string", 3, json!({ "list": true }));
    chooser["schemaVersion"] = json!("v3");
    chooser["content"] = json!([{ "data": "Unique-Default-Z9", "contentType": "string" }]);
    chooser["attributeCallback"] = json!({ "dependsOn": [] });
    Mock::given(method("GET"))
        .and(path(
            "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/attributes/issue",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            attribute("password", "secret", 2, json!({ "required": true })),
            attribute("keystore", "file", 2, json!({})),
            chooser,
        ])))
        .mount(&adding.world.ilm)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/certificates/ra-1/callback"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "reference": "Unique-Option-Z9", "data": "Unique-Option-Z9", "contentType": "string" }
        ])))
        .mount(&adding.world.ilm)
        .await;
    adding
        .answer_upload(
            ResponseTemplate::new(422).set_body_json(json!({ "message": "Unique-Message-Z9" })),
        )
        .await;
    let form = adding
        .world
        .session
        .open_form(crate::attributes::FormContext::Issue {
            authority: "auth-1".into(),
            ra_profile: "ra-1".into(),
        })
        .await
        .unwrap()
        .unwrap();
    let values = json!({
        "password": { "kind": "text", "value": "Unique-Secret-Z9" },
        "keystore": { "kind": "file", "value": {
            "name": "Unique-File-Z9.p12", "mime": "application/x-pkcs12", "content": "VW5pcXVlLUJ5dGVzLVo5"
        } },
        "region": { "kind": "option", "value": crate::attributes::option_key(
            &json!({ "reference": "Unique-Option-Z9", "data": "Unique-Option-Z9", "contentType": "string" })
        ) },
    });

    adding
        .world
        .session
        .run_callback(&form.id, "region", &values, 1)
        .await
        .unwrap();
    let asked = vec![adding.jane.fingerprint().to_string()];
    let results = adding.add_form(&asked, &form.id, values).await.unwrap();

    assert!(matches!(results[0].outcome, AddOutcome::NotAdded(_)));
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("callback run for region: answered (200)"));
    assert!(log.contains("custom attributes: "));
    for private in [
        "Unique-Secret-Z9",
        "Unique-File-Z9",
        "VW5pcXVlLUJ5dGVzLVo5",
        "Unique-Default-Z9",
        "Unique-Option-Z9",
        "Unique-Message-Z9",
    ] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}

#[tokio::test]
async fn a_lock_during_the_groups_listing_registers_no_form() {
    let adding = Adding::new().await;
    Mock::given(method("GET"))
        .and(path(GROUPS))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([]))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .mount(&adding.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(RA_PROFILES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&adding.world.ilm)
        .await;
    adding
        .serve_custom(ResponseTemplate::new(200).set_body_json(custom_definitions()))
        .await;
    let session = &adding.world.session;

    let choosing = session.add_to_ilm_choices();
    let locking = async {
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        session.close_forms();
    };
    let (choices, ()) = tokio::join!(choosing, locking);

    assert_eq!(choices, Err(ChangeError::Withdrawn));
}
