//! Asking ILM for certificates with keys of this computer, completing registered ones, and following them.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyPair,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::prelude::FromDer;

use super::tests::{LOG, World, capture_logs};
use super::{
    EndReason, Followed, Installed, Outcome, RequestError, RequestForms, RequestInput, SessionView,
};
use crate::attributes::fixtures::{
    default_request_set, definition, demo_request_set, mapped, upn_request_set, with,
};
use crate::attributes::{FormView, Needs};
use crate::enrolment::Enrolments;
use crate::ilm::IlmUrl;
use crate::ilm::certificates::State;
use crate::ilm::issue::Challenge;
use crate::ilm::upload::RaProfileChoice;
use crate::install::{Installation, RecordingInstaller};
use crate::inventory::{Inventory, SubjectKind, SubjectPart, Trigger, subject_parts};
use crate::keys::testing::InMemoryStorage;
use crate::keys::{
    KeyError, KeyStorage, KeyType, NameType, RequestSubject, Storage, Unmappable, signing_request,
};
use crate::requests::{Purpose, Requests, Waiting};
use crate::session::{Completion, FormInput};

const REQUEST_ATTRIBUTES: &str = "/api/v1/certificates/csr/attributes";
const ISSUE_ATTRIBUTES: &str =
    "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/attributes/issue";
const CUSTOM: &str = "/api/v1/attributes/custom/resources/certificates";
const ISSUE: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/certificates";
const DAY: i64 = 86_400_000;
const MINUTES: i64 = 10 * 60_000;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn text(value: &str) -> Value {
    json!({ "kind": "text", "value": value })
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

fn leaf_not_after(leaf: &[u8]) -> i64 {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(leaf).unwrap();
    parsed.validity().not_after.timestamp() * 1000
}

fn state_path(uuid: &str) -> String {
    format!("/api/v1/certificates/{uuid}")
}

pub(super) fn der_of(body: &Value) -> Vec<u8> {
    STANDARD.decode(body["request"].as_str().unwrap()).unwrap()
}

fn subject_of(der: &[u8]) -> String {
    let (_, request) = X509CertificationRequest::from_der(der).unwrap();
    request.certification_request_info.subject.to_string()
}

fn authority(name: &str) -> (CertificateParams, KeyPair) {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    (params, KeyPair::generate().unwrap())
}

/// A certificate for the key that signed `csr`, the certificate of the authority that issued it, and the
/// self-signed root above that authority.
pub(super) fn issued_for(csr: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (root_params, root_key) = authority("Test Root");
    let root = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);
    let (params, authority_key) = authority("Test CA");
    let intermediate = params.signed_by(&authority_key, &root_issuer).unwrap();
    let request = CertificateSigningRequestParams::from_der(&csr.to_vec().into()).unwrap();
    let issuer = Issuer::new(params, authority_key);
    let leaf = request.signed_by(&issuer).unwrap();
    (
        leaf.der().to_vec(),
        intermediate.der().to_vec(),
        root.der().to_vec(),
    )
}

/// Answers the issue request and tells what was on disk when it arrived.
struct SeesEntry {
    file: PathBuf,
    seen: Arc<Mutex<Option<String>>>,
}

impl Respond for SeesEntry {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        *self.seen.lock().unwrap() = std::fs::read_to_string(&self.file).ok();
        ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" }))
    }
}

struct Requesting {
    world: World,
    keys: Arc<InMemoryStorage>,
    installer: Arc<RecordingInstaller>,
    requests: Arc<Requests>,
    enrolments: Arc<Enrolments>,
    folder: TempDir,
}

impl Requesting {
    async fn new() -> Self {
        Self::with(
            InMemoryStorage::new(&[Storage::Software]),
            default_request_set(),
        )
        .await
    }

    async fn with(keys: InMemoryStorage, request_set: Vec<Value>) -> Self {
        let folder = tempfile::tempdir().unwrap();
        let requests = Arc::new(Requests::new(folder.path()));
        Self::built(keys, request_set, folder, requests).await
    }

    async fn built(
        keys: InMemoryStorage,
        request_set: Vec<Value>,
        folder: TempDir,
        requests: Arc<Requests>,
    ) -> Self {
        let keys = Arc::new(keys);
        let installer = Arc::new(RecordingInstaller::new());
        let enrolments = Arc::new(Enrolments::new(folder.path()));
        let mut world = World::new().await;
        world.session = world
            .session
            .with_key_storage(keys.clone())
            .with_installer(installer.clone())
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
            installer,
            requests,
            enrolments,
            folder,
        }
    }

    async fn open(&self, prepared: bool) -> RequestForms {
        self.world
            .session
            .open_request_forms("auth-1", "ra-1", prepared)
            .await
            .unwrap()
    }

    fn input(form: &Option<FormView>, values: Value) -> Option<FormInput> {
        form.as_ref().map(|form| FormInput {
            id: form.id.clone(),
            values,
        })
    }

    /// The three forms of a new request, filled in.
    async fn forms(&self, common_name: &str) -> RequestInput {
        let forms = self.open(false).await;
        RequestInput {
            request: Self::input(&forms.request, json!({ "commonName": text(common_name) })),
            issue: Self::input(&forms.issue, json!({ "validity": text("one year") })),
            custom: Self::input(&forms.custom, json!({ "department": text("Sales") })),
        }
    }

    async fn request_with(&self, forms: RequestInput) -> Result<Waiting, RequestError> {
        self.world
            .session
            .request(&choice(), forms, Storage::Software, KeyType::EcP256)
            .await
    }

    async fn request(&self) -> Result<Waiting, RequestError> {
        let forms = self.forms("web.example.com").await;
        self.request_with(forms).await
    }

    async fn answer(&self, verb: &str, route: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    async fn issue_answers(&self, response: ResponseTemplate) {
        self.answer("POST", ISSUE, response).await;
    }

    async fn issue_accepted(&self) {
        self.issue_answers(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" })))
            .await;
    }

    async fn state_is(&self, uuid: &str, body: Value) {
        self.answer(
            "GET",
            &state_path(uuid),
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
    }

    async fn state_code(&self, uuid: &str, code: &str) {
        self.state_is(uuid, json!({ "state": code })).await;
    }

    async fn chain_is(&self, uuid: &str, certificates: &[&[u8]]) {
        let items: Vec<Value> = certificates
            .iter()
            .map(|der| json!({ "certificateContent": STANDARD.encode(der) }))
            .collect();
        self.answer(
            "GET",
            &format!("{}/chain", state_path(uuid)),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "completeChain": true, "certificates": items })),
        )
        .await;
    }

    async fn received(&self, verb: &str, route: &str) -> Vec<Request> {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == verb && request.url.path() == route)
            .collect()
    }

    async fn bodies(&self, route: &str) -> Vec<Value> {
        self.received("POST", route)
            .await
            .iter()
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }

    /// A key of this computer with a request for `certificate`, as an earlier run of the application left them.
    fn seed(&self, uuid: Option<&str>, prepared: bool, since: i64) -> Waiting {
        let key = self
            .keys
            .create(Storage::Software, KeyType::EcP256)
            .unwrap();
        let entry = Waiting {
            ilm: self.world.address(),
            username: "jdoe".into(),
            uuid: uuid.map(str::to_owned),
            ra_profile: "ra-1".into(),
            authority: "auth-1".into(),
            key: Some(key.id().clone()),
            label: "seeded".into(),
            since,
            prepared,
            purpose: Purpose::Issue,
            enrolled: false,
        };
        self.requests.add(entry.clone()).unwrap();
        entry
    }

    /// A certificate and its chain for the key of `entry`, served as what ILM issued for `uuid`.
    async fn serve_issued(&self, uuid: &str, entry: &Waiting) -> (Vec<u8>, Vec<u8>) {
        let key = self
            .keys
            .open(entry.key.as_ref().unwrap())
            .unwrap()
            .unwrap();
        let subject = RequestSubject {
            names: vec![(NameType::CommonName, "web".into())],
            alternative_names: Vec::new(),
        };
        let csr = signing_request(key.as_ref(), &subject).unwrap();
        let (leaf, authority, root) = issued_for(&csr);
        self.state_is(
            uuid,
            json!({ "state": "issued", "certificateContent": STANDARD.encode(&leaf) }),
        )
        .await;
        self.chain_is(uuid, &[&authority, &root]).await;
        (leaf, authority)
    }

    async fn follow(&self) -> Vec<Followed> {
        self.world.session.follow().await
    }

    fn outcomes(found: &[Followed]) -> Vec<Outcome> {
        found
            .iter()
            .map(|followed| followed.outcome.clone())
            .collect()
    }

    fn nothing_left(&self) {
        assert_eq!(self.keys.count(), 0, "a key is left");
        assert!(self.requests.all().is_empty(), "a request is left");
    }

    fn only_a_request_is_left(&self) {
        assert_eq!(self.keys.count(), 1, "the key is gone");
        assert_eq!(self.requests.all().len(), 1, "the request is gone");
    }
}

// The forms.

#[tokio::test]
async fn a_new_request_opens_the_request_issue_and_custom_forms_and_a_prepared_one_only_the_last_two()
 {
    let requesting = Requesting::new().await;

    let new = requesting.open(false).await;
    let prepared = requesting.open(true).await;

    assert!(new.request.is_some() && new.issue.is_some() && new.custom.is_some());
    assert!(prepared.request.is_none() && prepared.issue.is_some() && prepared.custom.is_some());
    assert!(new.request.unwrap().web.unwrap().contains("ra-1"));
    assert_eq!(
        requesting
            .received("GET", REQUEST_ATTRIBUTES)
            .await
            .iter()
            .map(|request| request.url.query().unwrap().to_owned())
            .collect::<Vec<_>>(),
        ["raProfileUuid=ra-1"]
    );
}

#[tokio::test]
async fn a_required_request_attribute_that_cannot_be_written_blocks_the_form() {
    let blocked = mapped(
        definition(3, "data", "tls", "string", json!({ "required": true })),
        json!([{ "fieldType": "extension", "extensionOid": "1.3.6.1.5.5.7.1.24", "criticalOverridable": false }]),
    );
    let requesting =
        Requesting::with(InMemoryStorage::new(&[Storage::Software]), vec![blocked]).await;

    let forms = requesting.open(false).await;

    assert_eq!(forms.request.unwrap().unsupported, ["tls label"]);
}

#[tokio::test]
async fn an_optional_request_attribute_that_cannot_be_written_does_not_block_the_form() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]),
        demo_request_set(),
    )
    .await;

    let forms = requesting.open(false).await;

    assert!(forms.request.unwrap().unsupported.is_empty());
}

#[tokio::test]
async fn an_optional_request_attribute_that_cannot_be_written_is_not_in_the_form() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]),
        demo_request_set(),
    )
    .await;

    let forms = requesting.open(false).await;

    let names: Vec<String> = forms
        .request
        .unwrap()
        .groups
        .into_iter()
        .flat_map(|group| group.fields)
        .map(|field| field.name)
        .collect();
    assert_eq!(names, ["common-name", "san"]);
}

// The profiles to ask.

#[tokio::test]
async fn the_profiles_to_ask_are_the_enabled_ones_with_an_authority() {
    let requesting = Requesting::new().await;
    requesting
        .answer(
            "GET",
            "/api/v1/raProfiles",
            ResponseTemplate::new(200).set_body_json(json!([
                { "uuid": "ra-1", "name": "Servers", "description": "For servers", "enabled": true,
                  "authorityInstanceName": "Corporate CA", "authorityInstanceUuid": "auth-1" },
                { "uuid": "ra-2", "name": "Bare", "enabled": true },
                { "uuid": "ra-3", "name": "Off", "enabled": false, "authorityInstanceUuid": "auth-1" }
            ])),
        )
        .await;

    let listed = requesting.world.session.request_profiles().await.unwrap();

    assert_eq!(
        listed,
        [RaProfileChoice {
            description: Some("For servers".into()),
            ..choice()
        }]
    );
}

#[tokio::test]
async fn a_list_the_person_may_not_see_is_empty_and_a_refused_sign_in_is_an_error() {
    let requesting = Requesting::new().await;
    requesting
        .answer("GET", "/api/v1/raProfiles", ResponseTemplate::new(403))
        .await;
    assert_eq!(
        requesting.world.session.request_profiles().await,
        Ok(Vec::new())
    );
    let requesting = Requesting::new().await;
    requesting
        .answer("GET", "/api/v1/raProfiles", ResponseTemplate::new(500))
        .await;
    assert_eq!(
        requesting.world.session.request_profiles().await,
        Err(RequestError::Unexpected(500))
    );
}

#[test]
fn a_person_asks_for_certificates_only_with_create_allowed_on_certificates() {
    use crate::ilm::profile::ResourceActions;
    let allowed = |resource: &str, actions: &[&str]| super::SignedInAs {
        ilm: IlmUrl::for_tests("https://ilm.example.com"),
        username: "jdoe".into(),
        allowed_listings: Vec::new(),
        allowed_actions: vec![ResourceActions {
            resource: resource.into(),
            actions: actions.iter().map(|action| (*action).into()).collect(),
        }],
    };
    assert!(allowed("certificates", &["list", "create"]).creates_certificates());
    assert!(!allowed("certificates", &["list"]).creates_certificates());
    assert!(!allowed("groups", &["create"]).creates_certificates());
}

// A new request.

#[tokio::test]
async fn the_request_goes_to_ilm_with_the_subject_of_the_form_and_the_attributes_and_no_csr_attributes()
 {
    let requesting = Requesting::new().await;
    requesting.issue_accepted().await;

    let waiting = requesting.request().await.unwrap();

    let bodies = requesting.bodies(ISSUE).await;
    assert_eq!(bodies.len(), 1);
    let body = &bodies[0];
    assert_eq!(body["format"], "pkcs10");
    assert_eq!(subject_of(&der_of(body)), "CN=web.example.com");
    assert_eq!(body["attributes"][0]["name"], "validity");
    assert_eq!(body["customAttributes"][0]["name"], "department");
    assert!(body.get("csrAttributes").is_none());
    assert!(body.get("authorizationSecret").is_none());
    assert_eq!(waiting.uuid.as_deref(), Some("c-1"));
    assert_eq!(waiting.label, "web.example.com");
    assert!(!waiting.prepared);
    assert_eq!(waiting.ra_profile, "ra-1");
    assert_eq!(waiting.authority, "auth-1");
    assert_eq!(waiting.username, "jdoe");
    assert_eq!(requesting.requests.all(), std::slice::from_ref(&waiting));
    assert_eq!(requesting.keys.count(), 1);
    assert!(
        requesting
            .keys
            .open(waiting.key.as_ref().unwrap())
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn the_request_is_written_before_ilm_receives_it_and_has_no_certificate_yet() {
    let requesting = Requesting::new().await;
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path(ISSUE))
        .respond_with(SeesEntry {
            file: requesting.folder.path().join("requests.json"),
            seen: seen.clone(),
        })
        .mount(&requesting.world.ilm)
        .await;

    requesting.request().await.unwrap();

    let written: Value =
        serde_json::from_str(seen.lock().unwrap().as_deref().expect("a file")).unwrap();
    assert_eq!(written["waiting"].as_array().unwrap().len(), 1);
    assert_eq!(written["waiting"][0]["certificate"], Value::Null);
    assert_eq!(written["waiting"][0]["prepared"], false);
}

#[tokio::test]
async fn without_a_request_form_the_subject_is_empty_and_the_label_is_the_ra_profile() {
    let requesting = Requesting::new().await;
    requesting.issue_accepted().await;
    let mut forms = requesting.forms("ignored").await;
    forms.request = None;

    let waiting = requesting.request_with(forms).await.unwrap();

    let body = &requesting.bodies(ISSUE).await[0];
    assert_eq!(subject_of(&der_of(body)), "");
    assert_eq!(waiting.label, "Servers");
}

#[tokio::test]
async fn a_name_that_two_attributes_would_fill_creates_no_key() {
    let twice = vec![
        mapped(
            definition(3, "data", "first", "string", json!({})),
            json!([{ "fieldType": "rdn", "rdn": "CN" }]),
        ),
        mapped(
            definition(3, "data", "second", "string", json!({})),
            json!([{ "fieldType": "rdn", "rdn": "CN" }]),
        ),
    ];
    let requesting = Requesting::with(InMemoryStorage::new(&[Storage::Software]), twice).await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;
    let input = RequestInput {
        request: Requesting::input(
            &forms.request,
            json!({ "first": text("a"), "second": text("b") }),
        ),
        ..RequestInput::default()
    };

    let error = requesting.request_with(input).await.unwrap_err();

    assert!(matches!(
        error,
        RequestError::Unmappable(Unmappable::Repeated { .. })
    ));
    requesting.nothing_left();
    assert!(requesting.received("POST", ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_value_the_subject_cannot_hold_leaves_the_forms_open_to_be_corrected() {
    let address = vec![mapped(
        definition(3, "data", "address", "string", json!({})),
        json!([{ "fieldType": "san", "generalNameType": "ip" }]),
    )];
    let requesting = Requesting::with(InMemoryStorage::new(&[Storage::Software]), address).await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;
    let given = |value: &str| RequestInput {
        request: Requesting::input(&forms.request, json!({ "address": text(value) })),
        ..RequestInput::default()
    };

    let error = requesting.request_with(given("not an address")).await;

    assert!(matches!(
        error,
        Err(RequestError::Unmappable(Unmappable::Invalid { .. }))
    ));
    requesting.nothing_left();
    requesting.request_with(given("192.0.2.1")).await.unwrap();
}

#[tokio::test]
async fn a_dns_name_outside_ia5_leaves_the_forms_open_to_be_corrected() {
    let dns = vec![mapped(
        definition(3, "data", "host", "string", json!({})),
        json!([{ "fieldType": "san", "generalNameType": "dns" }]),
    )];
    let requesting = Requesting::with(InMemoryStorage::new(&[Storage::Software]), dns).await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;
    let given = |value: &str| RequestInput {
        request: Requesting::input(&forms.request, json!({ "host": text(value) })),
        ..RequestInput::default()
    };

    let error = requesting.request_with(given("münich.example")).await;

    assert!(matches!(
        error,
        Err(RequestError::Unmappable(Unmappable::Invalid { .. }))
    ));
    requesting.nothing_left();
    requesting
        .request_with(given("munich.example"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_broken_store_stops_the_request_before_a_key_is_made() {
    let folder = tempfile::tempdir().unwrap();
    std::fs::write(folder.path().join("requests.json"), "{").unwrap();
    let requests = Arc::new(Requests::new(folder.path()));
    let requesting = Requesting::built(
        InMemoryStorage::new(&[Storage::Software]),
        default_request_set(),
        folder,
        requests,
    )
    .await;
    requesting.issue_accepted().await;

    let error = requesting.request().await.unwrap_err();

    assert_eq!(error, RequestError::Store);
    assert_eq!(requesting.keys.count(), 0);
    assert!(requesting.received("POST", ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_form_with_problems_or_a_block_creates_no_key_and_stays_open() {
    let requesting = Requesting::new().await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;
    let missing = RequestInput {
        request: Requesting::input(&forms.request, json!({})),
        issue: Requesting::input(&forms.issue, json!({})),
        custom: Requesting::input(&forms.custom, json!({})),
    };

    let error = requesting.request_with(missing).await.unwrap_err();

    assert!(matches!(&error, RequestError::FormProblems(problems) if problems.len() == 1));
    requesting.nothing_left();
    assert!(requesting.received("POST", ISSUE).await.is_empty());
    let again = RequestInput {
        request: Requesting::input(&forms.request, json!({ "commonName": text("a.example") })),
        issue: Requesting::input(&forms.issue, json!({})),
        custom: Requesting::input(&forms.custom, json!({})),
    };
    requesting.request_with(again).await.unwrap();

    let blocked = mapped(
        definition(3, "data", "tls", "string", json!({ "required": true })),
        json!([{ "fieldType": "extension", "extensionOid": "1.3.6.1.5.5.7.1.24", "criticalOverridable": false }]),
    );
    let requesting =
        Requesting::with(InMemoryStorage::new(&[Storage::Software]), vec![blocked]).await;
    let forms = requesting.open(false).await;
    let input = RequestInput {
        request: Requesting::input(&forms.request, json!({})),
        ..RequestInput::default()
    };
    assert_eq!(
        requesting.request_with(input).await.unwrap_err(),
        RequestError::FormBlocked
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_form_that_is_gone_or_has_unreadable_values_creates_no_key() {
    let requesting = Requesting::new().await;
    let forms = requesting.open(false).await;
    let input = RequestInput {
        request: Some(FormInput {
            id: "gone".into(),
            values: json!({}),
        }),
        ..RequestInput::default()
    };
    assert_eq!(
        requesting.request_with(input).await.unwrap_err(),
        RequestError::FormGone
    );
    let input = RequestInput {
        request: Requesting::input(&forms.request, json!("not an object")),
        ..RequestInput::default()
    };
    assert_eq!(
        requesting.request_with(input).await.unwrap_err(),
        RequestError::FormValues
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_problem_in_a_later_form_takes_none_of_the_forms() {
    let requesting = Requesting::new().await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;
    let input = RequestInput {
        request: Requesting::input(&forms.request, json!({ "commonName": text("a.example") })),
        issue: Requesting::input(&forms.issue, json!("not an object")),
        custom: None,
    };

    assert_eq!(
        requesting.request_with(input).await.unwrap_err(),
        RequestError::FormValues
    );

    assert!(
        requesting
            .world
            .session
            .check_form(
                &forms.request.unwrap().id,
                &json!({ "commonName": text("a") })
            )
            .is_ok()
    );
}

#[tokio::test]
async fn a_request_that_fails_leaves_its_forms_open_to_be_sent_again() {
    let requesting = Requesting::new().await;
    Mock::given(method("POST"))
        .and(path(ISSUE))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!(["The name is taken."])))
        .up_to_n_times(1)
        .mount(&requesting.world.ilm)
        .await;
    let forms = requesting.forms("web.example.com").await;

    let error = requesting.request_with(forms.clone()).await.unwrap_err();
    assert_eq!(
        error,
        RequestError::Refused(vec!["The name is taken.".into()])
    );

    requesting.issue_accepted().await;
    assert!(requesting.request_with(forms).await.is_ok());
}

#[tokio::test]
async fn a_form_that_cannot_be_taken_leaves_the_forms_taken_before_it_open() {
    let requesting = Requesting::new().await;
    requesting.issue_accepted().await;
    let forms = requesting.forms("web.example.com").await;
    let twice = RequestInput {
        issue: forms.request.clone(),
        ..forms.clone()
    };

    assert_eq!(
        requesting.request_with(twice).await.unwrap_err(),
        RequestError::FormGone
    );

    assert!(requesting.request_with(forms).await.is_ok());
}

#[tokio::test]
async fn forms_closed_while_a_request_fails_stay_closed() {
    let requesting = Requesting::new().await;
    requesting
        .issue_answers(ResponseTemplate::new(500).set_delay(Duration::from_millis(300)))
        .await;
    let forms = requesting.forms("web.example.com").await;
    let closing = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        requesting.world.session.close_forms();
    };

    let (sent, ()) = tokio::join!(requesting.request_with(forms.clone()), closing);

    assert_eq!(sent.unwrap_err(), RequestError::Unexpected(500));

    assert_eq!(
        requesting.request_with(forms).await.unwrap_err(),
        RequestError::FormGone
    );
}

#[tokio::test]
async fn every_failure_after_the_key_exists_deletes_the_key_and_the_request() {
    for (answer, expected) in [
        (
            ResponseTemplate::new(422).set_body_json(json!(["The name is taken."])),
            RequestError::Refused(vec!["The name is taken.".into()]),
        ),
        (ResponseTemplate::new(403), RequestError::NotAllowed),
        (ResponseTemplate::new(500), RequestError::Unexpected(500)),
        (
            ResponseTemplate::new(200).set_body_string("{"),
            RequestError::Malformed,
        ),
    ] {
        let requesting = Requesting::new().await;
        requesting.issue_answers(answer).await;

        let error = requesting.request().await.unwrap_err();

        assert_eq!(error, expected);
        requesting.nothing_left();
        assert_eq!(requesting.received("POST", ISSUE).await.len(), 1);
    }
}

#[tokio::test]
async fn an_unreachable_ilm_deletes_the_key_and_the_request() {
    let mut requesting = Requesting::new().await;
    let forms = requesting.forms("web.example.com").await;
    requesting.world.ilm = MockServer::builder().start().await;

    let error = requesting.request_with(forms).await.unwrap_err();

    assert_eq!(error, RequestError::Offline);
    requesting.nothing_left();
}

#[tokio::test]
async fn a_storage_that_refuses_to_sign_leaves_no_key_and_nothing_is_sent() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]).refusing_to_sign(),
        default_request_set(),
    )
    .await;
    requesting.issue_accepted().await;

    let error = requesting.request().await.unwrap_err();

    assert_eq!(error, RequestError::Key(KeyError::Refused));
    assert_eq!(error.to_string(), "The key storage refused.");
    requesting.nothing_left();
    assert!(requesting.received("POST", ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_key_type_the_storage_does_not_offer_fails_before_anything_exists() {
    let requesting = Requesting::new().await;
    let forms = requesting.forms("web.example.com").await;

    let error = requesting
        .world
        .session
        .request(&choice(), forms, Storage::Tpm, KeyType::EcP256)
        .await
        .unwrap_err();

    assert_eq!(error, RequestError::Key(KeyError::NotOffered));
    assert_eq!(error.to_string(), "The key could not be created.");
    requesting.nothing_left();
}

#[tokio::test]
async fn a_request_that_cannot_be_written_deletes_the_key_and_is_not_sent() {
    let folder = tempfile::tempdir().unwrap();
    std::fs::create_dir(folder.path().join("requests.json")).unwrap();
    let requests = Arc::new(Requests::new(folder.path()));
    let requesting = Requesting::built(
        InMemoryStorage::new(&[Storage::Software]),
        default_request_set(),
        folder,
        requests,
    )
    .await;
    requesting.issue_accepted().await;

    let error = requesting.request().await.unwrap_err();

    assert_eq!(error, RequestError::Store);
    assert_eq!(requesting.keys.count(), 0);
    assert!(requesting.received("POST", ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_profile_without_an_authority_a_missing_store_and_a_sign_out_are_refused() {
    let requesting = Requesting::new().await;
    let forms = requesting.forms("web.example.com").await;
    let mut profile = choice();
    profile.authority_uuid = None;
    assert_eq!(
        requesting
            .world
            .session
            .request(&profile, forms, Storage::Software, KeyType::EcP256)
            .await
            .unwrap_err(),
        RequestError::NoAuthority
    );

    let world = World::new().await;
    let keys = Arc::new(InMemoryStorage::new(&[Storage::Software]));
    let session = world.session.with_key_storage(keys.clone());
    assert_eq!(
        session
            .request(
                &choice(),
                RequestInput::default(),
                Storage::Software,
                KeyType::EcP256
            )
            .await
            .unwrap_err(),
        RequestError::SignedOut
    );
    assert_eq!(keys.count(), 0);

    let mut world = World::new().await;
    let keys = Arc::new(InMemoryStorage::new(&[Storage::Software]));
    world.session = world.session.with_key_storage(keys.clone());
    world.code_grant("access", Some("refresh"), 3600).await;
    world.profile_for("access").await;
    world.sign_in().await;
    assert_eq!(
        world
            .session
            .request(
                &choice(),
                RequestInput::default(),
                Storage::Software,
                KeyType::EcP256
            )
            .await
            .unwrap_err(),
        RequestError::NoStore
    );
    assert_eq!(keys.count(), 0);
}

// Completing a certificate registered in advance.

async fn registered(requesting: &Requesting, uuid: &str) {
    requesting
        .state_is(
            uuid,
            json!({
                "state": "registered",
                "subjectDn": "CN=demo220,O=Example",
                "subjectAlternativeNames": { "dNSName": ["demo220.example.com"], "iPAddress": [] }
            }),
        )
        .await;
}

/// The subject `registered` gives, as the person reviewed it.
fn reviewed() -> Vec<SubjectPart> {
    vec![
        SubjectPart::new(SubjectKind::Organization, "Example"),
        SubjectPart::new(SubjectKind::CommonName, "demo220"),
        SubjectPart::new(SubjectKind::Dns, "demo220.example.com"),
    ]
}

async fn complete(
    requesting: &Requesting,
    uuid: &str,
    challenge: Option<&str>,
) -> Result<Waiting, RequestError> {
    complete_reviewed(requesting, uuid, challenge, &reviewed()).await
}

async fn complete_reviewed(
    requesting: &Requesting,
    uuid: &str,
    challenge: Option<&str>,
    subject: &[SubjectPart],
) -> Result<Waiting, RequestError> {
    let forms = requesting.open(true).await;
    let input = RequestInput {
        request: None,
        issue: Requesting::input(&forms.issue, json!({ "validity": text("one year") })),
        custom: Requesting::input(&forms.custom, json!({ "department": text("IT") })),
    };
    requesting
        .world
        .session
        .complete(
            Completion {
                uuid,
                name: "Prepared name",
                ra_profile: &choice(),
                subject,
            },
            input,
            Storage::Software,
            KeyType::EcP256,
            challenge.map(|challenge| Challenge::new(challenge.to_owned())),
        )
        .await
}

#[tokio::test]
async fn a_registered_certificate_is_completed_with_the_subject_ilm_registered_and_the_challenge() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })),
        )
        .await;

    let waiting = complete(&requesting, "c-9", Some("S3CRET-challenge"))
        .await
        .unwrap();

    let body = &requesting.bodies(&format!("{ISSUE}/c-9/issue")).await[0];
    assert_eq!(body["authorizationSecret"], "S3CRET-challenge");
    assert_eq!(body["format"], "pkcs10");
    assert_eq!(subject_of(&der_of(body)), "O=Example, CN=demo220");
    assert_eq!(body["attributes"][0]["name"], "validity");
    assert_eq!(body["customAttributes"][0]["name"], "department");
    assert!(body.get("csrAttributes").is_none());
    assert_eq!(waiting.uuid.as_deref(), Some("c-9"));
    assert!(waiting.prepared);
    assert_eq!(waiting.label, "demo220");
    assert_eq!(requesting.requests.all(), [waiting]);
    let stored = std::fs::read_to_string(requesting.folder.path().join("requests.json")).unwrap();
    assert!(!stored.contains("S3CRET-challenge"));
}

#[tokio::test]
async fn a_completion_without_a_challenge_sends_none() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })),
        )
        .await;

    complete(&requesting, "c-9", None).await.unwrap();

    let body = &requesting.bodies(&format!("{ISSUE}/c-9/issue")).await[0];
    assert!(body.get("authorizationSecret").is_none());
}

#[tokio::test]
async fn a_wrong_challenge_leaves_nothing_and_ilms_text_is_returned() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(422).set_body_json(json!([
                "The certificate registration challenge is invalid."
            ])),
        )
        .await;

    let error = complete(&requesting, "c-9", Some("wrong"))
        .await
        .unwrap_err();

    assert_eq!(
        error,
        RequestError::Refused(vec![
            "The certificate registration challenge is invalid.".into()
        ])
    );
    assert_eq!(
        error.to_string(),
        "The certificate registration challenge is invalid."
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_completion_whose_answer_was_lost_is_kept_and_followed() {
    for answer in [
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string("{"),
    ] {
        let requesting = Requesting::new().await;
        registered(&requesting, "c-9").await;
        requesting
            .answer("POST", &format!("{ISSUE}/c-9/issue"), answer)
            .await;

        let error = complete(&requesting, "c-9", Some("challenge"))
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            RequestError::Unexpected(500) | RequestError::Malformed
        ));
        requesting.only_a_request_is_left();
        let kept = requesting.requests.all();
        assert_eq!(kept[0].uuid.as_deref(), Some("c-9"));
        assert!(kept[0].prepared);
    }
}

#[tokio::test]
async fn a_completion_whose_answer_was_lost_is_not_sent_again() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(500),
        )
        .await;
    complete(&requesting, "c-9", None).await.unwrap_err();

    assert_eq!(
        complete(&requesting, "c-9", None).await.unwrap_err(),
        RequestError::NotRegistered
    );

    requesting.only_a_request_is_left();
    assert_eq!(
        requesting
            .received("POST", &format!("{ISSUE}/c-9/issue"))
            .await
            .len(),
        1
    );
}

#[tokio::test]
async fn a_request_of_someone_else_for_the_same_certificate_does_not_stop_a_completion() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })),
        )
        .await;
    let earlier = Waiting {
        ilm: requesting.world.address(),
        username: "someone-else".to_owned(),
        uuid: Some("c-9".to_owned()),
        ra_profile: "ra-1".to_owned(),
        authority: "a-1".to_owned(),
        key: Some(crate::keys::KeyId {
            storage: Storage::Software,
            name: "k-other".to_owned(),
        }),
        label: "theirs".to_owned(),
        since: 1,
        prepared: true,
        purpose: Purpose::Issue,
        enrolled: false,
    };
    requesting.requests.add(earlier).unwrap();

    complete(&requesting, "c-9", None).await.unwrap();

    assert_eq!(requesting.requests.all().len(), 2);
}

#[tokio::test]
async fn only_a_registered_certificate_is_completed() {
    for code in ["requested", "issued", "pending_approval"] {
        let requesting = Requesting::new().await;
        requesting.state_code("c-9", code).await;
        requesting
            .answer(
                "POST",
                &format!("{ISSUE}/c-9/issue"),
                ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })),
            )
            .await;

        assert_eq!(
            complete(&requesting, "c-9", None).await.unwrap_err(),
            RequestError::NotRegistered,
            "{code}"
        );

        requesting.nothing_left();
        assert!(
            requesting
                .received("POST", &format!("{ISSUE}/c-9/issue"))
                .await
                .is_empty()
        );
    }
    let requesting = Requesting::new().await;
    requesting
        .answer("GET", &state_path("c-9"), ResponseTemplate::new(404))
        .await;
    assert_eq!(
        complete(&requesting, "c-9", None).await.unwrap_err(),
        RequestError::NotRegistered
    );
}

#[tokio::test]
async fn a_registered_identity_that_cannot_be_written_creates_no_key() {
    let requesting = Requesting::new().await;
    requesting
        .state_is(
            "c-9",
            json!({ "state": "registered", "subjectDn": "CN=a,STREET=b" }),
        )
        .await;

    let error = complete(&requesting, "c-9", None).await.unwrap_err();

    assert!(matches!(
        error,
        RequestError::Unmappable(Unmappable::Unsupported { .. })
    ));
    requesting.nothing_left();
}

#[tokio::test]
async fn a_registered_certificate_without_a_common_name_is_labelled_with_the_name_it_was_given() {
    let requesting = Requesting::new().await;
    requesting.state_code("c-9", "registered").await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-9/issue"),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })),
        )
        .await;

    assert_eq!(
        complete_reviewed(&requesting, "c-9", None, &[])
            .await
            .unwrap()
            .label,
        "Prepared name"
    );
}

#[tokio::test]
async fn an_email_moved_from_the_name_to_the_alternative_names_is_a_changed_subject() {
    let requesting = Requesting::new().await;
    requesting
        .state_is(
            "c-9",
            json!({
                "state": "registered",
                "subjectDn": "CN=demo220",
                "subjectAlternativeNames": { "rfc822Name": ["a@example.com"] }
            }),
        )
        .await;
    let before = crate::keys::registered_subject(Some("E=a@example.com,CN=demo220"), &[]).unwrap();
    let seen = subject_parts(&before);

    assert_eq!(
        complete_reviewed(&requesting, "c-9", None, &seen)
            .await
            .unwrap_err(),
        RequestError::SubjectChanged
    );
}

#[tokio::test]
async fn a_subject_changed_in_ilm_since_the_review_is_not_sent_and_leaves_nothing() {
    let requesting = Requesting::new().await;
    registered(&requesting, "c-9").await;
    let mut seen = reviewed();
    seen[0] = SubjectPart::new(SubjectKind::Organization, "Other");

    assert_eq!(
        complete_reviewed(&requesting, "c-9", None, &seen)
            .await
            .unwrap_err(),
        RequestError::SubjectChanged
    );

    requesting.nothing_left();
    assert!(
        requesting
            .received("POST", &format!("{ISSUE}/c-9/issue"))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn the_waiting_requests_are_those_of_the_person_signed_in() {
    let requesting = Requesting::new().await;
    let mine = requesting.seed(Some("c-1"), false, now());
    let mut other = requesting.seed(Some("c-2"), false, now());
    other.username = "someone-else".into();
    requesting.requests.add(other).unwrap();

    assert_eq!(requesting.world.session.waiting_requests(), [mine]);

    let signed_out = World::new().await;
    assert!(signed_out.session.waiting_requests().is_empty());
}

// Following.

#[tokio::test]
async fn an_issued_certificate_is_installed_with_its_chain_and_the_request_ends_with_the_key_kept()
{
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    let (leaf, authority) = requesting.serve_issued("c-1", &entry).await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Installed(Installed {
            fingerprint: crate::identity::Fingerprint::of(&leaf),
            storage: Some(Storage::Software),
            not_after: leaf_not_after(&leaf),
        })]
    );
    assert_eq!(found[0].uuid.as_deref(), Some("c-1"));
    assert_eq!(found[0].label, "seeded");
    assert_eq!(
        requesting.installer.calls(),
        [Installation {
            key: entry.key.clone().unwrap(),
            leaf,
            intermediates: 1
        }]
    );
    let _ = authority;
    assert!(requesting.requests.all().is_empty());
    assert_eq!(requesting.keys.count(), 1);
    assert!(requesting.follow().await.is_empty());
}

#[tokio::test]
async fn an_installed_certificate_of_an_enrolment_is_noted_and_one_of_the_person_is_not() {
    for (enrolled, noted) in [(true, vec!["c-1".to_owned()]), (false, Vec::new())] {
        let requesting = Requesting::new().await;
        let mut entry = requesting.seed(Some("c-1"), false, now());
        entry.enrolled = enrolled;
        requesting.requests.add(entry.clone()).unwrap();
        requesting.serve_issued("c-1", &entry).await;

        requesting.follow().await;

        let who = requesting.world.session.signed_in_as().unwrap();
        let standing = requesting
            .enrolments
            .standing(&who.ilm, &who.username)
            .unwrap();
        assert_eq!(standing.installed, noted);
    }
}

#[tokio::test]
async fn a_certificate_of_another_key_is_a_mismatch_and_nothing_is_installed_or_removed() {
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    let other = requesting.seed(Some("c-other"), false, now());
    let (leaf_of_other, authority) = requesting.serve_issued("c-other", &other).await;
    requesting
        .state_is(
            "c-1",
            json!({ "state": "issued", "certificateContent": STANDARD.encode(&leaf_of_other) }),
        )
        .await;
    requesting.chain_is("c-1", &[&authority]).await;

    let found = requesting.follow().await;

    let mismatched: Vec<_> = found
        .iter()
        .filter(|followed| followed.uuid.as_deref() == Some("c-1"))
        .map(|followed| followed.outcome.clone())
        .collect();
    assert_eq!(mismatched, [Outcome::Mismatch]);
    assert!(
        requesting
            .installer
            .calls()
            .iter()
            .all(|call| Some(&call.key) != entry.key.as_ref())
    );
    assert!(
        requesting
            .requests
            .all()
            .iter()
            .any(|kept| kept.key == entry.key)
    );
    assert!(
        requesting
            .keys
            .open(entry.key.as_ref().unwrap())
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_installer_that_fails_keeps_the_key_and_the_request() {
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    requesting.serve_issued("c-1", &entry).await;
    requesting.installer.fail(true);

    let found = requesting.follow().await;

    assert_eq!(Requesting::outcomes(&found), [Outcome::InstallFailed]);
    requesting.only_a_request_is_left();
    requesting.installer.fail(false);
    assert!(matches!(
        Requesting::outcomes(&requesting.follow().await)[..],
        [Outcome::Installed(_)]
    ));
}

#[tokio::test]
async fn an_issued_certificate_whose_key_is_gone_ends_the_request() {
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    requesting.serve_issued("c-1", &entry).await;
    requesting.keys.delete(entry.key.as_ref().unwrap()).unwrap();

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Ended(EndReason::KeyGone)]
    );
    assert!(requesting.requests.all().is_empty());
    assert!(requesting.installer.calls().is_empty());
}

#[tokio::test]
async fn a_chain_that_cannot_be_read_leaves_everything_as_it_is() {
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    let key = requesting
        .keys
        .open(entry.key.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let csr = signing_request(key.as_ref(), &RequestSubject::default()).unwrap();
    let (leaf, _, _) = issued_for(&csr);
    requesting
        .state_is(
            "c-1",
            json!({ "state": "issued", "certificateContent": STANDARD.encode(&leaf) }),
        )
        .await;
    requesting
        .answer(
            "GET",
            "/api/v1/certificates/c-1/chain",
            ResponseTemplate::new(500),
        )
        .await;

    assert!(requesting.follow().await.is_empty());

    requesting.only_a_request_is_left();
    assert!(requesting.installer.calls().is_empty());
}

#[tokio::test]
async fn an_issued_certificate_without_content_is_still_waiting() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "issued").await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Waiting(State::Issued)]
    );
    requesting.only_a_request_is_left();
}

#[tokio::test]
async fn a_request_that_ilm_ended_is_removed_with_its_key() {
    for (code, reason) in [
        ("failed", EndReason::Failed),
        ("rejected", EndReason::Rejected),
        ("revoked", EndReason::Other("revoked".into())),
    ] {
        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now());
        requesting.state_code("c-1", code).await;

        let found = requesting.follow().await;

        assert_eq!(
            Requesting::outcomes(&found),
            [Outcome::Ended(reason)],
            "{code}"
        );
        requesting.nothing_left();
    }
}

#[tokio::test]
async fn a_state_that_is_not_known_to_be_the_end_keeps_the_request() {
    for (code, state) in [
        ("pending_revoke", State::PendingRevoke),
        ("quantum", State::Other("quantum".into())),
    ] {
        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now() - DAY);
        requesting.state_code("c-1", code).await;

        let found = requesting.follow().await;

        assert_eq!(
            Requesting::outcomes(&found),
            [Outcome::Waiting(state)],
            "{code}"
        );
        requesting.only_a_request_is_left();
    }
}

#[tokio::test]
async fn a_prepared_certificate_with_its_request_attached_keeps_waiting_however_old() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), true, now() - DAY);
    requesting
        .state_is(
            "c-1",
            json!({ "state": "registered", "certificateRequest": { "content": "AQID" } }),
        )
        .await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Waiting(State::Registered)]
    );
    requesting.only_a_request_is_left();
}

#[tokio::test]
async fn a_request_whose_key_cannot_be_deleted_is_kept_and_not_reported_until_it_can() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "failed").await;
    requesting.keys.fail_deleting(true);

    assert!(requesting.follow().await.is_empty());
    requesting.only_a_request_is_left();

    requesting.keys.fail_deleting(false);
    assert_eq!(
        Requesting::outcomes(&requesting.follow().await),
        [Outcome::Ended(EndReason::Failed)]
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_failed_request_whose_key_cannot_be_deleted_stays_written_down() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]).refusing_to_sign(),
        default_request_set(),
    )
    .await;
    requesting.keys.fail_deleting(true);

    let error = requesting.request().await.unwrap_err();

    assert_eq!(error, RequestError::Key(KeyError::Refused));
    requesting.only_a_request_is_left();
    assert!(requesting.received("POST", ISSUE).await.is_empty());
}

#[tokio::test]
async fn a_certificate_that_cannot_be_written_down_is_still_followed() {
    let requesting = Requesting::new().await;
    let file = requesting.folder.path().join("requests.json");
    let forms = requesting.forms("web.example.com").await;
    // The file is replaced once the request is written, so the next write fails.
    Mock::given(method("POST"))
        .and(path(ISSUE))
        .respond_with(move |_: &Request| {
            std::fs::remove_file(&file).unwrap();
            std::fs::create_dir(&file).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" }))
        })
        .mount(&requesting.world.ilm)
        .await;

    let waiting = requesting.request_with(forms).await.unwrap();

    assert_eq!(waiting.uuid.as_deref(), Some("c-1"));
    assert_eq!(requesting.keys.count(), 1);
    let kept = requesting.requests.all();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].uuid.as_deref(), Some("c-1"));
}

#[tokio::test]
async fn a_certificate_kept_only_in_memory_is_written_by_the_next_follow() {
    let requesting = Requesting::new().await;
    let file = requesting.folder.path().join("requests.json");
    let forms = requesting.forms("web.example.com").await;
    let broken = file.clone();
    Mock::given(method("POST"))
        .and(path(ISSUE))
        .respond_with(move |_: &Request| {
            std::fs::remove_file(&broken).unwrap();
            std::fs::create_dir(&broken).unwrap();
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" }))
        })
        .mount(&requesting.world.ilm)
        .await;
    requesting.request_with(forms).await.unwrap();
    requesting.state_code("c-1", "pending_issue").await;
    std::fs::remove_dir(&file).unwrap();

    requesting.follow().await;

    let written: Value = serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(written["waiting"][0]["uuid"], "c-1");
}

#[tokio::test]
async fn a_prepared_certificate_that_is_registered_again_ends_the_request_after_it_has_settled() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), true, now() - MINUTES);
    requesting.state_code("c-1", "registered").await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Ended(EndReason::ReturnedToRegistered)]
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_prepared_certificate_just_sent_is_still_registered_for_a_moment() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), true, now());
    requesting.state_code("c-1", "registered").await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Waiting(State::Registered)]
    );
    requesting.only_a_request_is_left();
}

#[tokio::test]
async fn a_request_that_is_not_prepared_waits_while_it_is_registered() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now() - MINUTES);
    requesting.state_code("c-1", "registered").await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Waiting(State::Registered)]
    );
    requesting.only_a_request_is_left();
}

#[tokio::test]
async fn the_pending_states_keep_the_request() {
    for (code, state) in [
        ("requested", State::Requested),
        ("pending_approval", State::PendingApproval),
        ("pending_issue", State::PendingIssue),
        ("pending_registration", State::PendingRegistration),
    ] {
        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now());
        requesting.state_code("c-1", code).await;

        let found = requesting.follow().await;

        assert_eq!(
            Requesting::outcomes(&found),
            [Outcome::Waiting(state)],
            "{code}"
        );
        requesting.only_a_request_is_left();
    }
}

#[tokio::test]
async fn a_certificate_ilm_does_not_list_yet_is_waited_for_and_given_up_after_a_day() {
    for status in [404, 403] {
        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now());
        requesting
            .answer("GET", &state_path("c-1"), ResponseTemplate::new(status))
            .await;
        assert!(requesting.follow().await.is_empty(), "{status}");
        requesting.only_a_request_is_left();

        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now() - DAY - 1);
        requesting
            .answer("GET", &state_path("c-1"), ResponseTemplate::new(status))
            .await;
        assert_eq!(
            Requesting::outcomes(&requesting.follow().await),
            [Outcome::Ended(EndReason::Gone)],
            "{status}"
        );
        requesting.nothing_left();
    }
}

#[tokio::test]
async fn a_request_that_was_never_sent_is_skipped_for_a_day_and_then_cleaned() {
    let requesting = Requesting::new().await;
    requesting.seed(None, false, now());
    assert!(requesting.follow().await.is_empty());
    requesting.only_a_request_is_left();

    let requesting = Requesting::new().await;
    requesting.seed(None, false, now() - DAY - 1);
    assert_eq!(
        Requesting::outcomes(&requesting.follow().await),
        [Outcome::Ended(EndReason::NotSent)]
    );
    requesting.nothing_left();
}

#[tokio::test]
async fn a_call_that_fails_or_an_unexpected_answer_changes_nothing_and_reports_nothing() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now() - 2 * DAY);
    requesting
        .answer("GET", &state_path("c-1"), ResponseTemplate::new(500))
        .await;
    assert!(requesting.follow().await.is_empty());
    requesting.only_a_request_is_left();

    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now() - 2 * DAY);
    requesting
        .answer(
            "GET",
            &state_path("c-1"),
            ResponseTemplate::new(200).set_body_string("{"),
        )
        .await;
    assert!(requesting.follow().await.is_empty());
    requesting.only_a_request_is_left();

    let mut requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now() - 2 * DAY);
    requesting.world.ilm = MockServer::builder().start().await;
    assert!(requesting.follow().await.is_empty());
    requesting.only_a_request_is_left();
}

#[tokio::test]
async fn only_the_requests_of_the_person_signed_in_at_this_ilm_are_followed() {
    let requesting = Requesting::new().await;
    let mine = requesting.seed(Some("c-1"), false, now() - 2 * DAY);
    let key = requesting
        .keys
        .create(Storage::Software, KeyType::EcP256)
        .unwrap();
    let other_person = Waiting {
        username: "someone-else".into(),
        key: Some(key.id().clone()),
        uuid: Some("c-2".into()),
        ..mine.clone()
    };
    let key = requesting
        .keys
        .create(Storage::Software, KeyType::EcP256)
        .unwrap();
    let other_ilm = Waiting {
        ilm: IlmUrl::parse("other.example.com").unwrap(),
        key: Some(key.id().clone()),
        uuid: Some("c-3".into()),
        ..mine.clone()
    };
    requesting.requests.add(other_person.clone()).unwrap();
    requesting.requests.add(other_ilm.clone()).unwrap();
    requesting.state_code("c-1", "failed").await;
    requesting.state_code("c-2", "failed").await;
    requesting.state_code("c-3", "failed").await;

    let found = requesting.follow().await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Ended(EndReason::Failed)]
    );
    assert_eq!(requesting.requests.all(), [other_person, other_ilm]);
    assert_eq!(requesting.keys.count(), 2);
    assert!(
        requesting
            .received("GET", &state_path("c-2"))
            .await
            .is_empty()
    );
    assert!(
        requesting
            .received("GET", &state_path("c-3"))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn nobody_signed_in_or_no_store_follows_nothing() {
    let world = World::new().await;
    let session = world
        .session
        .with_requests(Arc::new(Requests::new(tempfile::tempdir().unwrap().path())));
    assert!(session.follow().await.is_empty());

    let world = World::new().await;
    world.code_grant("access", Some("refresh"), 3600).await;
    world.profile_for("access").await;
    world.sign_in().await;
    assert!(world.session.follow().await.is_empty());
}

#[tokio::test]
async fn two_follows_never_run_at_once() {
    let requesting = Requesting::new().await;
    let entry = requesting.seed(Some("c-1"), false, now());
    requesting.serve_issued("c-1", &entry).await;

    let (first, second) = tokio::join!(requesting.follow(), requesting.follow());

    assert_eq!(requesting.installer.calls().len(), 1);
    assert_eq!(first.len() + second.len(), 1);
}

#[tokio::test]
async fn a_follow_started_while_a_request_is_being_sent_waits_until_the_send_is_over() {
    let requesting = Requesting::new().await;
    requesting
        .issue_answers(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "uuid": "c-1" }))
                .set_delay(Duration::from_millis(300)),
        )
        .await;
    let forms = requesting.forms("web.example.com").await;

    let (sent, followed) = tokio::join!(
        async {
            let sent = requesting.request_with(forms).await;
            (sent, Instant::now())
        },
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let followed = requesting.follow().await;
            (followed, Instant::now())
        }
    );

    assert!(sent.0.is_ok());
    assert!(followed.0.is_empty());
    assert!(followed.1 >= sent.1, "the follow ran during the send");
}

#[tokio::test]
async fn a_request_that_has_no_installer_keeps_waiting_to_be_installed() {
    let folder = tempfile::tempdir().unwrap();
    let requests = Arc::new(Requests::new(folder.path()));
    let keys = Arc::new(InMemoryStorage::new(&[Storage::Software]));
    let mut world = World::new().await;
    world.session = world
        .session
        .with_key_storage(keys.clone())
        .with_requests(requests.clone());
    world.code_grant("access", Some("refresh"), 3600).await;
    world.profile_for("access").await;
    world.sign_in().await;
    let key = keys.create(Storage::Software, KeyType::EcP256).unwrap();
    let subject = RequestSubject::default();
    let csr = signing_request(key.as_ref(), &subject).unwrap();
    let (leaf, authority, _) = issued_for(&csr);
    requests
        .add(Waiting {
            ilm: world.address(),
            username: "jdoe".into(),
            uuid: Some("c-1".into()),
            ra_profile: "ra-1".into(),
            authority: "auth-1".into(),
            key: Some(key.id().clone()),
            label: "x".into(),
            since: now(),
            prepared: false,
            purpose: Purpose::Issue,
            enrolled: false,
        })
        .unwrap();
    for (route, body) in [
        (
            state_path("c-1"),
            json!({ "state": "issued", "certificateContent": STANDARD.encode(&leaf) }),
        ),
        (
            format!("{}/chain", state_path("c-1")),
            json!({ "certificates": [{ "certificateContent": STANDARD.encode(&authority) }] }),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&world.ilm)
            .await;
    }

    let found = world.session.follow().await;

    assert_eq!(Requesting::outcomes(&found), [Outcome::InstallFailed]);
    assert_eq!(requests.all().len(), 1);
}

// Following at each check of ILM.

#[tokio::test]
async fn every_check_of_ilm_follows_the_requests_and_forgetting_clears_what_it_found() {
    for trigger in [
        Trigger::Start,
        Trigger::Interval,
        Trigger::SyncNow,
        Trigger::Action,
    ] {
        let requesting = Requesting::new().await;
        requesting.seed(Some("c-1"), false, now());
        requesting.state_code("c-1", "pending_issue").await;
        requesting
            .answer(
                "POST",
                "/api/v1/certificates",
                ResponseTemplate::new(200).set_body_json(json!({
                    "certificates": [], "pageNumber": 1, "totalPages": 1, "totalItems": 0
                })),
            )
            .await;
        let folder = tempfile::tempdir().unwrap();
        let inventory = Inventory::new(folder.path());
        assert!(inventory.followed().is_empty());

        inventory
            .check(&requesting.world.session, trigger, &[])
            .await;

        assert_eq!(
            Requesting::outcomes(&inventory.followed()),
            [Outcome::Waiting(State::PendingIssue)],
            "{trigger}"
        );
        inventory.forget();
        assert!(inventory.followed().is_empty());
    }
}

#[tokio::test]
async fn the_summary_lists_the_requests_still_waiting_and_drops_them_when_they_are_done() {
    use crate::inventory::{Kind, WaitingState};
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "pending_approval").await;
    requesting
        .answer(
            "POST",
            "/api/v1/certificates",
            ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [], "pageNumber": 1, "totalPages": 1, "totalItems": 0
            })),
        )
        .await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());
    inventory.set_local(&[]);
    let session = &requesting.world.session;

    inventory.check(session, Trigger::Interval, &[]).await;

    let summary = inventory.summary().unwrap();
    assert_eq!(summary.attention.len(), 1);
    assert_eq!(
        summary.attention[0].kind,
        Kind::Waiting {
            state: WaitingState::PendingApproval
        }
    );
    assert_eq!(summary.attention[0].name, "seeded");
    assert!(!summary.needs_attention());
    inventory.forget();
    assert!(inventory.summary().is_none());
}

#[tokio::test]
async fn following_on_its_own_puts_the_request_in_the_summary_at_once() {
    use crate::inventory::{Kind, WaitingState};
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "pending_approval").await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());
    let session = &requesting.world.session;
    inventory.adopt(session);
    inventory.set_local(&[]);
    assert!(inventory.summary().unwrap().attention.is_empty());

    let (found, changed) = inventory.follow(session).await;

    assert_eq!(
        Requesting::outcomes(&found),
        [Outcome::Waiting(State::PendingApproval)]
    );
    assert!(changed);
    assert_eq!(
        inventory.summary().unwrap().attention[0].kind,
        Kind::Waiting {
            state: WaitingState::PendingApproval
        }
    );
    let (_, again) = inventory.follow(session).await;
    assert!(!again, "nothing changed");
}

#[tokio::test]
async fn a_follow_that_cannot_ask_ilm_keeps_the_requests_found_waiting_before() {
    use crate::inventory::Kind;
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    Mock::given(method("GET"))
        .and(path(state_path("c-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "state": "pending_issue" })))
        .up_to_n_times(1)
        .mount(&requesting.world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path(state_path("c-1")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&requesting.world.ilm)
        .await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());
    let session = &requesting.world.session;
    inventory.adopt(session);
    inventory.set_local(&[]);
    inventory.follow(session).await;

    let (found, changed) = inventory.follow(session).await;

    assert!(found.is_empty());
    assert!(!changed);
    assert!(matches!(
        inventory.summary().unwrap().attention[0].kind,
        Kind::Waiting { .. }
    ));
    assert_eq!(inventory.followed().len(), 1);
}

#[tokio::test]
async fn a_request_that_is_issued_is_listed_as_being_issued() {
    use crate::inventory::{Kind, WaitingState};
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "pending_issue").await;
    requesting
        .answer(
            "POST",
            "/api/v1/certificates",
            ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [], "pageNumber": 1, "totalPages": 1, "totalItems": 0
            })),
        )
        .await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());
    inventory.set_local(&[]);

    inventory
        .check(&requesting.world.session, Trigger::Interval, &[])
        .await;

    assert_eq!(
        inventory.summary().unwrap().attention[0].kind,
        Kind::Waiting {
            state: WaitingState::BeingIssued
        }
    );
}

#[tokio::test]
async fn a_check_follows_once_even_when_another_call_takes_its_answer() {
    let requesting = Requesting::new().await;
    requesting.seed(Some("c-1"), false, now());
    requesting.state_code("c-1", "pending_issue").await;
    requesting
        .answer(
            "POST",
            "/api/v1/certificates",
            ResponseTemplate::new(200).set_body_json(json!({
                "certificates": [], "pageNumber": 1, "totalPages": 1, "totalItems": 0
            })),
        )
        .await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());
    let session = &requesting.world.session;

    tokio::join!(
        inventory.check(session, Trigger::Interval, &[]),
        inventory.check(session, Trigger::Interval, &[])
    );

    assert_eq!(
        requesting.received("GET", &state_path("c-1")).await.len(),
        1
    );
}

// What the log holds.

#[tokio::test]
async fn the_log_of_requests_holds_no_challenge_value_or_message_of_ilm() {
    capture_logs();
    let requesting = Requesting::new().await;
    requesting
        .state_is(
            "c-reg",
            json!({ "state": "registered", "subjectDn": "CN=Unique-Subject-Z9" }),
        )
        .await;
    Mock::given(method("POST"))
        .and(path(format!("{ISSUE}/c-reg/issue")))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!(["Unique-Refusal-Z9"])))
        .up_to_n_times(1)
        .mount(&requesting.world.ilm)
        .await;
    requesting
        .answer(
            "POST",
            &format!("{ISSUE}/c-reg/issue"),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-reg" })),
        )
        .await;
    requesting
        .answer(
            "POST",
            ISSUE,
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-wait" })),
        )
        .await;
    requesting.state_code("c-wait", "pending_approval").await;
    requesting.state_code("c-rej", "rejected").await;
    let issued = requesting.seed(Some("c-ok"), false, now());
    requesting.seed(Some("c-rej"), false, now());
    requesting.serve_issued("c-ok", &issued).await;

    let reviewed = [SubjectPart::new(
        SubjectKind::CommonName,
        "Unique-Subject-Z9",
    )];
    let refused =
        complete_reviewed(&requesting, "c-reg", Some("Unique-Challenge-Z9"), &reviewed).await;
    assert!(matches!(refused, Err(RequestError::Refused(_))));
    complete_reviewed(&requesting, "c-reg", Some("Unique-Challenge-Z9"), &reviewed)
        .await
        .unwrap();
    let forms = requesting.forms("Unique-Cn-Z9").await;
    let forms = RequestInput {
        issue: forms.issue.map(|form| FormInput {
            values: json!({ "validity": text("Unique-Issue-Z9") }),
            ..form
        }),
        ..forms
    };
    requesting.request_with(forms).await.unwrap();
    let found = requesting.follow().await;

    assert_eq!(found.len(), 4);
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("INFO: request sent"), "{log}");
    assert!(log.contains("prepared: yes"));
    assert!(log.contains("prepared: no"));
    assert!(log.contains("request c-wait: sent → pending_approval"));
    assert!(log.contains("certificate installed: c-ok, Software, 1 intermediates"));
    assert!(log.contains("request c-rej ended"));
    assert!(log.contains("rejected"));
    for private in [
        "Unique-Challenge-Z9",
        "Unique-Subject-Z9",
        "Unique-Cn-Z9",
        "Unique-Issue-Z9",
        "Unique-Refusal-Z9",
    ] {
        assert!(!log.contains(private), "{private} is in the log");
    }
    for line in log.lines().filter(|line| {
        ["c-ok", "c-rej", "c-wait", "c-reg"]
            .iter()
            .any(|uuid| line.contains(uuid))
    }) {
        assert!(!line.contains("key-"), "{line}");
    }
}

#[test]
fn the_errors_speak_plainly() {
    for (error, text) in [
        (RequestError::Offline, "ILM cannot be reached."),
        (RequestError::NotAllowed, "ILM does not allow this."),
        (
            RequestError::Key(KeyError::Refused),
            "The key storage refused.",
        ),
        (
            RequestError::Key(KeyError::Failed("x".into())),
            "The key could not be created.",
        ),
        (
            RequestError::Store,
            "The request could not be recorded on this computer.",
        ),
        (
            RequestError::Refused(vec!["One.".into(), "Two.".into()]),
            "One. Two.",
        ),
        (
            RequestError::Unexpected(502),
            "ILM answered with an error (502).",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

#[tokio::test]
async fn the_session_offers_the_key_types_of_its_key_storage() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software, Storage::Tpm]),
        default_request_set(),
    )
    .await;
    let offers = requesting.world.session.key_offers().await;
    assert_eq!(
        offers.iter().map(|offer| offer.storage).collect::<Vec<_>>(),
        [Storage::Software, Storage::Tpm]
    );
    assert!(offers[0].types.contains(&KeyType::EcP256));

    let world = World::new().await;
    assert!(world.session.key_offers().await.is_empty());
}

// Forms sent without the person.

#[tokio::test]
async fn forms_whose_definitions_give_every_value_are_sent_as_they_are() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]),
        demo_request_set(),
    )
    .await;
    requesting.issue_accepted().await;
    let forms = requesting.open(false).await;

    let input = requesting.world.session.unattended_forms(&forms).unwrap();
    requesting.request_with(input).await.unwrap();

    let bodies = requesting.bodies(ISSUE).await;
    assert_eq!(subject_of(&der_of(&bodies[0])), "CN=demo220");
}

#[tokio::test]
async fn a_form_the_person_would_have_to_fill_is_not_sent_unattended() {
    let requesting = Requesting::new().await;
    let forms = requesting.open(false).await;

    let needs = requesting
        .world
        .session
        .unattended_forms(&forms)
        .unwrap_err();

    assert_eq!(needs, Needs::Required);
}

#[tokio::test]
async fn a_request_form_that_names_nothing_is_not_sent_unattended() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]),
        upn_request_set(),
    )
    .await;
    let forms = requesting.open(false).await;

    let needs = requesting
        .world
        .session
        .unattended_forms(&forms)
        .unwrap_err();

    assert_eq!(needs, Needs::Subject);
}

#[tokio::test]
async fn a_value_with_nowhere_to_go_in_the_request_is_not_sent_unattended() {
    let unmapped = mapped(
        with(
            definition(3, "data", "field", "string", json!({})),
            "content",
            json!([{ "data": "x", "contentType": "string" }]),
        ),
        json!([{ "fieldType": "extension", "extensionOid": "1.2.3" }]),
    );
    let requesting =
        Requesting::with(InMemoryStorage::new(&[Storage::Software]), vec![unmapped]).await;
    let forms = requesting.open(false).await;

    let needs = requesting
        .world
        .session
        .unattended_forms(&forms)
        .unwrap_err();

    assert_eq!(needs, Needs::Subject);
}

#[tokio::test]
async fn a_certificate_registered_in_advance_has_no_request_form_to_name_a_subject() {
    let requesting = Requesting::new().await;
    let forms = requesting.open(true).await;

    let input = requesting.world.session.unattended_forms(&forms).unwrap();

    assert!(input.request.is_none());
    assert!(input.issue.is_some() && input.custom.is_some());
}

#[tokio::test]
async fn a_form_that_is_no_longer_open_is_not_sent_unattended() {
    let requesting = Requesting::with(
        InMemoryStorage::new(&[Storage::Software]),
        demo_request_set(),
    )
    .await;
    let forms = requesting.open(false).await;
    requesting.world.session.close_forms();

    let needs = requesting
        .world
        .session
        .unattended_forms(&forms)
        .unwrap_err();

    assert_eq!(needs, Needs::Gone);
}
