//! Renewing a certificate of the person, and following the renewal until its certificate is installed.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, Issuer, KeyPair, OtherNameValue, SanType,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, Respond, ResponseTemplate};

use super::tests::{LOG, World, capture_logs};
use super::{
    ConnectionSettings, Credential, EndReason, Followed, Outcome, RenewalTarget, RequestError,
    SessionView, State, lock,
};
use crate::http::client_for_tests;
use crate::identity::certificate::{KeyLocation, describe};
use crate::identity::testing::{Issue, TestCa};
use crate::identity::tls::CertificateAsked;
use crate::identity::{
    ClientIdentity, Fingerprint, IdentityStore, LocalCertificate, StoreUnreadable,
};
use crate::ilm::IlmUrl;
use crate::ilm::certificates::search_text;
use crate::ilm::profile::SignInCertificate;
use crate::ilm::renew::Reason;
use crate::install::{RecordingInstaller, Removal};
use crate::inventory::RevokingStage;
use crate::keys::testing::InMemoryStorage;
use crate::keys::{KeyType, Storage};
use crate::renewal::Method;
use crate::renewal::store::Renewals;
use crate::requests::{PendingSwitch, Purpose, Requests, Waiting};

const PROFILE: &str = "/api/v1/auth/profile";
const OPERATIONS: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/certificates";
const NEW_KEY: Method = Method::NewKey {
    storage: Storage::Software,
    key_type: KeyType::EcP256,
};

fn state_path(uuid: &str) -> String {
    format!("/api/v1/certificates/{uuid}")
}

fn operation(verb: &str) -> String {
    format!("{OPERATIONS}/c-old/{verb}")
}

fn authority(name: &str) -> (CertificateParams, KeyPair) {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    (params, KeyPair::generate().unwrap())
}

/// A certificate for `key` from a test authority, then the authority's own certificate and its root.
fn issued(name: &str, key: &KeyPair) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (root_params, root_key) = authority("Test Root");
    let root = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);
    let (params, authority_key) = authority("Test CA");
    let intermediate = params.signed_by(&authority_key, &root_issuer).unwrap();
    let issuer = Issuer::new(params, authority_key);
    let mut leaf = CertificateParams::default();
    leaf.distinguished_name = DistinguishedName::new();
    leaf.distinguished_name.push(DnType::CommonName, name);
    let leaf = leaf.signed_by(key, &issuer).unwrap();
    (
        leaf.der().to_vec(),
        intermediate.der().to_vec(),
        root.der().to_vec(),
    )
}

/// A certificate for the key that signed `csr`.
fn issued_for(csr: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
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

/// Answers a send with the new certificate and tells what was on disk when it arrived.
struct SeesEntry {
    file: PathBuf,
    seen: Arc<Mutex<Option<String>>>,
}

impl Respond for SeesEntry {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        *self.seen.lock().unwrap() = std::fs::read_to_string(&self.file).ok();
        ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-new" }))
    }
}

struct SeesRevocation {
    file: PathBuf,
    seen: Arc<Mutex<Option<String>>>,
}

impl Respond for SeesRevocation {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        *self.seen.lock().unwrap() = std::fs::read_to_string(&self.file).ok();
        ResponseTemplate::new(204)
    }
}

/// A store that opens any certificate asked for, as the one holding the installed successor.
struct OpensAny(
    crate::identity::testing::TestIdentity,
    Vec<u8>,
    Mutex<Vec<Vec<u8>>>,
    AtomicBool,
);

impl IdentityStore for OpensAny {
    /// The certificates put on the computer with `Renewing::installs`.
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        Ok(self
            .2
            .lock()
            .unwrap()
            .iter()
            .filter_map(|der| describe(der, KeyLocation::Software, SystemTime::now()))
            .collect())
    }

    fn der(&self, fingerprint: &Fingerprint) -> Option<Vec<u8>> {
        (Fingerprint::of(&self.1) == *fingerprint).then(|| self.1.clone())
    }

    fn open(&self, _: &Fingerprint) -> Option<ClientIdentity> {
        (!self.3.load(Ordering::SeqCst)).then(|| self.0.client_identity())
    }
}

/// A store that holds the given certificates, or cannot be read, and cannot read the DER of `unreadable`.
struct Holds(Option<Vec<Vec<u8>>>, Vec<Fingerprint>);

impl IdentityStore for Holds {
    fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
        let held = self.0.as_ref().ok_or(StoreUnreadable("broken".into()))?;
        Ok(held
            .iter()
            .filter_map(|der| describe(der, KeyLocation::Software, SystemTime::now()))
            .collect())
    }

    fn der(&self, fingerprint: &Fingerprint) -> Option<Vec<u8>> {
        if self.1.contains(fingerprint) {
            return None;
        }
        self.0
            .as_ref()?
            .iter()
            .find(|der| Fingerprint::of(der) == *fingerprint)
            .cloned()
    }

    fn open(&self, _: &Fingerprint) -> Option<ClientIdentity> {
        None
    }
}

/// ILM's profile of the person: it names `old` until the first change of the profile reaches ILM, then `new`.
struct MovesWithTheUpdate {
    moved: Arc<AtomicBool>,
    old: Value,
    new: Value,
}

impl Respond for MovesWithTheUpdate {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let moved = self.moved.load(Ordering::SeqCst);
        ResponseTemplate::new(200).set_body_json(if moved { &self.new } else { &self.old })
    }
}

/// Takes the change of the profile and answers `status`.
struct TakesTheUpdate {
    moved: Arc<AtomicBool>,
    status: u16,
}

impl Respond for TakesTheUpdate {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.moved.store(true, Ordering::SeqCst);
        ResponseTemplate::new(self.status)
    }
}

struct Renewing {
    identities: Arc<OpensAny>,
    world: World,
    keys: Arc<InMemoryStorage>,
    installer: Arc<RecordingInstaller>,
    requests: Arc<Requests>,
    renewals: Arc<Renewals>,
    folder: TempDir,
    old_key: KeyPair,
    old: Vec<u8>,
    fingerprint: Fingerprint,
}

impl Renewing {
    async fn new() -> Self {
        Self::with_subject(&["web.example.com"], Vec::new()).await
    }

    async fn with_subject(names: &[&str], alternative_names: Vec<SanType>) -> Self {
        Self::build(names, alternative_names, false).await
    }

    /// The person signs in with the certificate that is renewed: ILM's profile names it.
    async fn signing_in_with_the_old_certificate() -> Self {
        Self::build(&["web.example.com"], Vec::new(), true).await
    }

    async fn build(
        names: &[&str],
        alternative_names: Vec<SanType>,
        signs_in_with_old: bool,
    ) -> Self {
        let folder = tempfile::tempdir().unwrap();
        let keys = Arc::new(InMemoryStorage::new(&[Storage::Software]));
        let installer = Arc::new(RecordingInstaller::new());
        let requests = Arc::new(Requests::new(folder.path()));
        let renewals = Arc::new(Renewals::new(folder.path()));
        let old_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        for name in names {
            params.distinguished_name.push(DnType::CommonName, *name);
        }
        params.subject_alt_names = alternative_names;
        let (root_params, root_key) = authority("Test CA");
        let issuer = Issuer::new(root_params, root_key);
        let old = params.signed_by(&old_key, &issuer).unwrap().der().to_vec();
        let fingerprint = Fingerprint::of(&old);
        let identities = Arc::new(OpensAny(
            TestCa::new().issue(Issue::client("Jane")),
            old.clone(),
            Mutex::new(Vec::new()),
            AtomicBool::new(false),
        ));
        let mut world = World::new().await;
        world.session = world
            .session
            .with_key_storage(keys.clone())
            .with_installer(installer.clone())
            .with_requests(requests.clone())
            .with_renewals(renewals.clone())
            .with_identities(identities.clone())
            .with_certificate_client(Box::new(|_| {
                (client_for_tests(), CertificateAsked::offered_for_tests())
            }));
        world.code_grant("access", Some("refresh"), 3600).await;
        if signs_in_with_old {
            Mock::given(method("GET"))
                .and(path(PROFILE))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "uuid": "u-1",
                    "username": "jdoe",
                    "firstName": "Jane",
                    "lastName": "Doe",
                    "certificate": { "uuid": "c-old", "fingerprint": search_text(&fingerprint) },
                    "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
                })))
                .mount(&world.ilm)
                .await;
        } else {
            world.profile_for("access").await;
        }
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        let renewing = Self {
            identities,
            world,
            keys,
            installer,
            requests,
            renewals,
            folder,
            old_key,
            old,
            fingerprint,
        };
        renewing.serve_old(json!([]), 5).await;
        renewing
    }

    async fn answer(&self, verb: &str, route: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    /// Serves the old certificate with `related`; a lower `priority` number wins over an earlier answer.
    async fn serve_old(&self, related: Value, priority: u8) {
        Mock::given(method("GET"))
            .and(path(state_path("c-old")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "state": "issued",
                "certificateContent": STANDARD.encode(&self.old),
                "raProfile": { "uuid": "ra-1", "name": "Servers", "authorityInstanceUuid": "auth-1" },
                "relatedCertificates": related,
            })))
            .with_priority(priority)
            .mount(&self.world.ilm)
            .await;
    }

    async fn accepts(&self, verb: &str) {
        self.answer(
            "POST",
            &operation(verb),
            ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-new" })),
        )
        .await;
    }

    async fn refuses(&self, verb: &str) {
        self.answer(
            "POST",
            &operation(verb),
            ResponseTemplate::new(422).set_body_json(json!(["Unique-Refusal-Z9"])),
        )
        .await;
    }

    fn target(&self) -> RenewalTarget<'_> {
        RenewalTarget {
            uuid: "c-old",
            fingerprint: &self.fingerprint,
            name: "web",
        }
    }

    async fn renew(
        &self,
        method: Method,
        automatic: bool,
    ) -> Result<crate::requests::Waiting, RequestError> {
        self.renew_while(method, automatic, &|| true).await
    }

    async fn renew_while(
        &self,
        method: Method,
        automatic: bool,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Result<crate::requests::Waiting, RequestError> {
        self.world
            .session
            .renew(self.target(), method, automatic, proceed)
            .await
    }

    async fn bodies(&self, verb: &str) -> Vec<Value> {
        let route = operation(verb);
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

    /// Serves `leaf` and its chain as what ILM made for `c-new`.
    async fn serves_new(&self, leaf: &[u8], intermediate: &[u8], root: &[u8]) {
        self.answer(
            "GET",
            &state_path("c-new"),
            ResponseTemplate::new(200).set_body_json(
                json!({ "state": "issued", "certificateContent": STANDARD.encode(leaf) }),
            ),
        )
        .await;
        let items: Vec<Value> = [intermediate, root]
            .iter()
            .map(|der| json!({ "certificateContent": STANDARD.encode(der) }))
            .collect();
        self.answer(
            "GET",
            &format!("{}/chain", state_path("c-new")),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "completeChain": true, "certificates": items })),
        )
        .await;
    }

    async fn serves_state(&self, code: &str) {
        self.answer(
            "GET",
            &state_path("c-new"),
            ResponseTemplate::new(200).set_body_json(json!({ "state": code })),
        )
        .await;
    }

    /// Serves the certificate ILM makes for the request the new-key renewal sent.
    async fn serves_new_key_certificate(&self) -> Vec<u8> {
        let body = self.bodies("rekey").await.remove(0);
        let csr = STANDARD.decode(body["request"].as_str().unwrap()).unwrap();
        let (leaf, intermediate, root) = issued_for(&csr);
        self.serves_new(&leaf, &intermediate, &root).await;
        leaf
    }

    fn ilm(&self) -> IlmUrl {
        self.world.address()
    }

    fn off(&self, fingerprint: &Fingerprint) -> bool {
        self.renewals.is_off(&self.ilm(), "jdoe", fingerprint)
    }

    fn failure(&self) -> Option<SystemTime> {
        self.renewals
            .last_failure(&self.ilm(), "jdoe", &self.fingerprint)
    }

    fn outcomes(found: &[Followed]) -> Vec<Outcome> {
        found
            .iter()
            .map(|followed| followed.outcome.clone())
            .collect()
    }
}

// Sending.

#[tokio::test]
async fn a_new_key_renewal_is_written_down_before_the_send_and_rekeys_with_the_old_subject() {
    let renewing = Renewing::new().await;
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path(operation("rekey")))
        .respond_with(SeesEntry {
            file: renewing.folder.path().join("requests.json"),
            seen: seen.clone(),
        })
        .mount(&renewing.world.ilm)
        .await;

    let waiting = renewing.renew(NEW_KEY, false).await.unwrap();

    let written: Value =
        serde_json::from_str(seen.lock().unwrap().as_deref().expect("written first")).unwrap();
    assert_eq!(written["waiting"][0]["purpose"]["kind"], "renew");
    assert_eq!(written["waiting"][0]["purpose"]["replaces"], "c-old");
    assert_eq!(written["waiting"][0]["uuid"], Value::Null);
    assert_eq!(waiting.uuid.as_deref(), Some("c-new"));
    assert!(waiting.key.is_some());
    assert_eq!(
        waiting.purpose,
        Purpose::Renew {
            replaces: "c-old".into(),
            replaces_fingerprint: renewing.fingerprint,
            sign_in: false,
            same_key: false,
            automatic: false,
            switch: None,
        }
    );
    assert_eq!(renewing.requests.all(), [waiting]);
    assert_eq!(renewing.keys.count(), 1);
    let bodies = renewing.bodies("rekey").await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["replaceInLocations"], false);
    assert_eq!(bodies[0]["format"], "pkcs10");
}

#[tokio::test]
async fn a_same_key_renewal_makes_no_key_and_sends_no_request() {
    let renewing = Renewing::new().await;
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path(operation("renew")))
        .respond_with(SeesEntry {
            file: renewing.folder.path().join("requests.json"),
            seen: seen.clone(),
        })
        .mount(&renewing.world.ilm)
        .await;

    let waiting = renewing.renew(Method::SameKey, true).await.unwrap();

    assert!(seen.lock().unwrap().is_some(), "written before the send");
    assert_eq!(waiting.key, None);
    assert_eq!(waiting.uuid.as_deref(), Some("c-new"));
    assert!(matches!(
        waiting.purpose,
        Purpose::Renew {
            same_key: true,
            automatic: true,
            ..
        }
    ));
    assert_eq!(renewing.keys.count(), 0);
    assert_eq!(renewing.requests.all(), [waiting]);
    assert_eq!(
        renewing.bodies("renew").await,
        [json!({ "replaceInLocations": false })]
    );
}

#[tokio::test]
async fn a_subject_a_request_cannot_carry_falls_back_to_the_same_key() {
    let renewing = Renewing::with_subject(
        &["web.example.com"],
        vec![SanType::OtherName((
            vec![1, 2, 3, 4],
            OtherNameValue::Utf8String("v".to_owned()),
        ))],
    )
    .await;
    renewing.accepts("renew").await;

    let waiting = renewing.renew(NEW_KEY, false).await.unwrap();

    assert_eq!(waiting.key, None);
    assert_eq!(renewing.keys.count(), 0);
    assert_eq!(renewing.bodies("renew").await.len(), 1);
    assert!(renewing.bodies("rekey").await.is_empty());
}

#[tokio::test]
async fn a_refused_rekey_deletes_the_new_key_and_the_entry_and_records_an_automatic_attempt() {
    let renewing = Renewing::new().await;
    renewing.refuses("rekey").await;

    let refused = renewing.renew(NEW_KEY, true).await;

    assert_eq!(
        refused,
        Err(RequestError::Refused(vec!["Unique-Refusal-Z9".into()]))
    );
    assert_eq!(renewing.keys.count(), 0, "a key is left");
    assert!(renewing.requests.all().is_empty(), "a request is left");
    assert!(renewing.failure().is_some());
}

#[tokio::test]
async fn a_refused_renewal_of_the_person_is_not_held_against_the_automatic_ones() {
    let renewing = Renewing::new().await;
    renewing.refuses("renew").await;

    assert!(renewing.renew(Method::SameKey, false).await.is_err());

    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn a_second_renewal_is_not_sent_while_one_is_in_flight() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();

    let again = renewing.renew(NEW_KEY, true).await;

    assert_eq!(again, Err(RequestError::AlreadyRenewing));
    assert_eq!(renewing.bodies("rekey").await.len(), 1);
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(renewing.keys.count(), 1);
}

#[tokio::test]
async fn no_renewal_is_sent_while_a_revocation_of_the_certificate_waits() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(false).await.unwrap();
    renewing.accepts("rekey").await;
    renewing.accepts("renew").await;

    for automatic in [false, true] {
        let refused = renewing.renew(NEW_KEY, automatic).await;

        assert_eq!(
            refused,
            Err(RequestError::AlreadyRevoking),
            "automatic: {automatic}"
        );
    }
    assert!(renewing.bodies("rekey").await.is_empty());
    assert!(renewing.bodies("renew").await.is_empty());
    assert_eq!(renewing.keys.count(), 0);
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn nothing_is_sent_while_ilm_lists_a_successor_that_is_not_issued() {
    let renewing = Renewing::new().await;
    renewing
        .serve_old(
            json!([{ "uuid": "c-9", "state": "pending_approval", "relationType": "renewal" }]),
            1,
        )
        .await;
    renewing.accepts("rekey").await;

    let refused = renewing.renew(NEW_KEY, false).await;

    assert_eq!(refused, Err(RequestError::AlreadyRenewing));
    assert!(renewing.bodies("rekey").await.is_empty());
    assert_eq!(renewing.keys.count(), 0);
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn an_automatic_renewal_is_not_sent_when_ilm_lists_an_issued_successor() {
    let renewing = Renewing::new().await;
    renewing
        .serve_old(
            json!([{ "uuid": "c-9", "state": "issued", "relationType": "renewal" }]),
            1,
        )
        .await;
    renewing.accepts("rekey").await;

    let refused = renewing.renew(NEW_KEY, true).await;

    assert_eq!(refused, Err(RequestError::AlreadyRenewing));
    assert!(renewing.bodies("rekey").await.is_empty());
    assert_eq!(renewing.keys.count(), 0);
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn a_renewal_of_the_person_is_sent_although_ilm_lists_an_issued_successor() {
    let renewing = Renewing::new().await;
    renewing
        .serve_old(
            json!([{ "uuid": "c-9", "state": "issued", "relationType": "renewal" }]),
            1,
        )
        .await;
    renewing.accepts("rekey").await;

    renewing.renew(NEW_KEY, false).await.unwrap();

    assert_eq!(renewing.bodies("rekey").await.len(), 1);
}

#[tokio::test]
async fn an_automatic_renewal_waits_when_an_attempt_failed_less_than_a_day_ago() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    renewing
        .renewals
        .record_failure(
            &renewing.ilm(),
            "jdoe",
            &renewing.fingerprint,
            SystemTime::now(),
        )
        .unwrap();

    let refused = renewing.renew(NEW_KEY, true).await;

    assert_eq!(refused, Err(RequestError::AlreadyRenewing));
    assert!(renewing.bodies("rekey").await.is_empty());
    assert_eq!(renewing.keys.count(), 0);
}

#[tokio::test]
async fn a_renewal_of_the_person_is_sent_although_an_attempt_failed_a_moment_ago() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    renewing
        .renewals
        .record_failure(
            &renewing.ilm(),
            "jdoe",
            &renewing.fingerprint,
            SystemTime::now(),
        )
        .unwrap();

    renewing.renew(NEW_KEY, false).await.unwrap();

    assert_eq!(renewing.bodies("rekey").await.len(), 1);
}

#[tokio::test]
async fn an_automatic_renewal_of_a_certificate_that_cannot_be_renewed_is_noted_as_failed() {
    let renewing = Renewing::new().await;
    let other = Fingerprint::of(b"another certificate");
    let target = RenewalTarget {
        fingerprint: &other,
        ..renewing.target()
    };

    let refused = renewing
        .world
        .session
        .renew(target, NEW_KEY, true, &|| true)
        .await;

    assert_eq!(refused, Err(RequestError::NotRenewable));
    assert!(
        renewing
            .renewals
            .last_failure(&renewing.ilm(), "jdoe", &other)
            .is_some()
    );
}

#[tokio::test]
async fn an_automatic_renewal_refused_for_a_running_renewal_is_not_noted_as_failed() {
    let renewing = Renewing::new().await;
    renewing
        .serve_old(
            json!([{ "uuid": "c-9", "state": "pending_issue", "relationType": "renewal" }]),
            1,
        )
        .await;

    let refused = renewing.renew(NEW_KEY, true).await;

    assert_eq!(refused, Err(RequestError::AlreadyRenewing));
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn an_automatic_renewal_that_cannot_read_the_waiting_requests_is_noted_as_failed() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    std::fs::write(renewing.folder.path().join("requests.json"), "not json").unwrap();

    let refused = renewing.renew(NEW_KEY, true).await;

    assert_eq!(refused, Err(RequestError::Store));
    assert!(renewing.failure().is_some());
    assert!(renewing.bodies("rekey").await.is_empty());
}

#[tokio::test]
async fn nothing_is_sent_when_the_application_is_locked_and_nothing_is_left_behind() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;

    let refused = renewing.renew_while(NEW_KEY, true, &|| false).await;

    assert_eq!(refused, Err(RequestError::Withdrawn));
    assert!(renewing.bodies("rekey").await.is_empty());
    assert_eq!(renewing.keys.count(), 0, "a key is left");
    assert!(renewing.requests.all().is_empty(), "a request is left");
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn nothing_is_revoked_when_the_application_is_locked_and_nothing_is_left_behind() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;

    let refused = renewing
        .world
        .session
        .revoke(renewing.target(), Reason::KeyCompromise, true, &|| false)
        .await;

    assert_eq!(refused, Err(RequestError::Withdrawn));
    assert!(renewing.bodies("revoke").await.is_empty());
    assert!(renewing.requests.all().is_empty(), "a revocation is left");
}

#[tokio::test]
async fn a_certificate_that_is_not_the_one_in_ilm_is_not_renewed() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    let other = Fingerprint::of(b"another certificate");
    let target = RenewalTarget {
        fingerprint: &other,
        ..renewing.target()
    };

    let refused = renewing
        .world
        .session
        .renew(target, NEW_KEY, false, &|| true)
        .await;

    assert_eq!(refused, Err(RequestError::NotRenewable));
    assert!(renewing.bodies("rekey").await.is_empty());
    assert_eq!(renewing.keys.count(), 0);
}

#[tokio::test]
async fn a_certificate_without_an_ra_profile_is_not_renewed() {
    let renewing = Renewing::new().await;
    Mock::given(method("GET"))
        .and(path(state_path("c-old")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "issued",
            "certificateContent": STANDARD.encode(&renewing.old),
        })))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;

    assert_eq!(
        renewing.renew(Method::SameKey, false).await,
        Err(RequestError::NotRenewable)
    );
}

// Following.

#[tokio::test]
async fn a_new_key_successor_is_installed_with_its_key_and_takes_over_the_switch() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    let waiting = renewing.renew(NEW_KEY, true).await.unwrap();
    renewing
        .renewals
        .set_off(&renewing.ilm(), "jdoe", &renewing.fingerprint, true)
        .unwrap();
    renewing
        .renewals
        .record_failure(
            &renewing.ilm(),
            "jdoe",
            &renewing.fingerprint,
            SystemTime::now(),
        )
        .unwrap();
    let leaf = renewing.serves_new_key_certificate().await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert_eq!(found[0].replaces, Some(renewing.fingerprint));
    assert_eq!(found[0].failed_notice_key(), None);
    let calls = renewing.installer.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(Some(&calls[0].key), waiting.key.as_ref());
    assert_eq!(calls[0].leaf, leaf);
    assert_eq!(calls[0].intermediates, 1);
    assert!(renewing.installer.beside_calls().is_empty());
    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.keys.count(), 1, "the new key stays");
    assert!(!renewing.off(&renewing.fingerprint));
    assert!(renewing.off(&Fingerprint::of(&leaf)));
    assert_eq!(renewing.failure(), None);
}

#[tokio::test]
async fn a_same_key_successor_is_installed_beside_the_old_certificate() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, false).await.unwrap();
    let (leaf, intermediate, root) = issued("web", &renewing.old_key);
    renewing.serves_new(&leaf, &intermediate, &root).await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert!(renewing.installer.calls().is_empty());
    let beside = renewing.installer.beside_calls();
    assert_eq!(beside.len(), 1);
    assert_eq!(beside[0].old, renewing.fingerprint);
    assert_eq!(beside[0].leaf, leaf);
    assert_eq!(beside[0].intermediates, 1);
    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.keys.count(), 0);
}

#[tokio::test]
async fn a_same_key_successor_for_another_key_is_not_installed() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, true).await.unwrap();
    let (leaf, intermediate, root) = issued("web", &KeyPair::generate().unwrap());
    renewing.serves_new(&leaf, &intermediate, &root).await;

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::Mismatch]);
    assert!(renewing.installer.beside_calls().is_empty());
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(
        found[0].failed_notice_key().unwrap(),
        format!("renewal:failed:{}", renewing.fingerprint)
    );
}

#[tokio::test]
async fn a_failed_or_rejected_renewal_ends_with_the_failed_notice_and_a_new_key_goes() {
    for (code, reason) in [
        ("failed", EndReason::Failed),
        ("rejected", EndReason::Rejected),
    ] {
        let renewing = Renewing::new().await;
        renewing.accepts("rekey").await;
        renewing.renew(NEW_KEY, true).await.unwrap();
        renewing.serves_state(code).await;

        let found = renewing.world.session.follow().await;

        assert_eq!(Renewing::outcomes(&found), [Outcome::Ended(reason)]);
        assert_eq!(
            found[0].failed_notice_key().unwrap(),
            format!("renewal:failed:{}", renewing.fingerprint)
        );
        assert_eq!(renewing.keys.count(), 0, "a key is left");
        assert!(renewing.requests.all().is_empty());
        assert!(renewing.failure().is_some(), "{code}");
    }
}

#[tokio::test]
async fn a_same_key_renewal_that_failed_leaves_no_entry() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, false).await.unwrap();
    renewing.serves_state("failed").await;

    let found = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&found),
        [Outcome::Ended(EndReason::Failed)]
    );
    assert!(renewing.requests.all().is_empty());
    assert_eq!(
        renewing.failure(),
        None,
        "the person's attempt is not held against it"
    );
}

#[tokio::test]
async fn a_certificate_that_cannot_be_installed_keeps_the_entry_and_gives_the_failed_notice() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.installer.fail(true);

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::InstallFailed]);
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(renewing.keys.count(), 1);
    assert_eq!(
        found[0].failed_notice_key().unwrap(),
        format!("renewal:failed:{}", renewing.fingerprint)
    );
}

#[tokio::test]
async fn a_renewal_still_being_made_is_reported_as_waiting() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, false).await.unwrap();
    renewing.serves_state("pending_approval").await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Waiting(_)]
    ));
    assert_eq!(found[0].failed_notice_key(), None);
    assert_eq!(renewing.requests.all().len(), 1);
}

// Moving the sign-in over.

impl Renewing {
    async fn updates(&self) -> Vec<Value> {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == "PUT" && request.url.path() == PROFILE)
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect()
    }

    /// Lets ILM take the new sign-in certificate; a lower `priority` number wins over an earlier answer.
    async fn takes_the_update(&self, status: u16, priority: u8) {
        Mock::given(method("PUT"))
            .and(path(PROFILE))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({})))
            .with_priority(priority)
            .mount(&self.world.ilm)
            .await;
    }

    /// The certificate ILM knows the person by, as the session has it.
    fn sign_in_uuid(&self) -> Option<String> {
        match &*lock(&self.world.session.state) {
            State::SignedIn(active) => active.person.sign_in.as_ref().map(|held| held.uuid.clone()),
            _ => None,
        }
    }

    /// The person signs in with the old certificate as a certificate sign-in.
    fn signs_in_with_a_certificate(&self) {
        if let State::SignedIn(active) = &mut *lock(&self.world.session.state) {
            active.credential = Credential::Certificate {
                fingerprint: self.fingerprint,
                client: client_for_tests(),
                generation: Arc::new(()),
                not_after: None,
            };
        }
        self.world
            .settings
            .save_certificate(&self.ilm(), &self.fingerprint)
            .unwrap();
    }

    /// Whether the computer cannot open any certificate to sign in with.
    fn cannot_open(&self, cannot: bool) {
        self.identities.3.store(cannot, Ordering::SeqCst);
    }

    /// The certificate `der` is on this computer from now on.
    fn installs(&self, der: &[u8]) {
        self.identities.2.lock().unwrap().push(der.to_vec());
    }

    fn remembered(&self) -> Option<Fingerprint> {
        self.world.settings.connection().certificate
    }

    fn pending(&self) -> Option<PendingSwitch> {
        self.requests
            .all()
            .first()
            .and_then(Waiting::pending_switch)
    }
}

#[tokio::test]
async fn the_sign_in_certificate_moves_to_its_successor_after_the_install() {
    capture_logs();
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    let waiting = renewing.renew(NEW_KEY, false).await.unwrap();
    assert!(matches!(
        waiting.purpose,
        Purpose::Renew { sign_in: true, .. }
    ));
    renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert_eq!(renewing.installer.calls().len(), 1);
    let updates = renewing.updates().await;
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0]["certificateUuid"], "c-new");
    assert_eq!(updates[0]["firstName"], "Jane");
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-new"));
    assert!(renewing.requests.all().is_empty());
    assert_eq!(found[0].needs_notice_key(), None);
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("sign-in moved to c-new"), "{log}");
}

#[tokio::test]
async fn a_sign_in_ilm_already_moved_is_taken_over_without_a_second_change() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    let leaf = renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "u-1",
            "username": "jdoe",
            "firstName": "Jane",
            "lastName": "Doe",
            "certificate": { "uuid": "c-new", "fingerprint": search_text(&Fingerprint::of(&leaf)) },
            "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
        })))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found).len(), 1);
    assert!(renewing.updates().await.is_empty());
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-new"));
    assert_eq!(renewing.remembered(), Some(Fingerprint::of(&leaf)));
    assert!(renewing.requests.all().is_empty());
    match &*lock(&renewing.world.session.state) {
        State::SignedIn(active) => assert!(matches!(
            &active.credential,
            Credential::Certificate { fingerprint, .. } if *fingerprint == Fingerprint::of(&leaf)
        )),
        _ => panic!("signed out"),
    }
}

fn profile_naming(certificate: &str, fingerprint: &Fingerprint, username: &str) -> Value {
    json!({
        "uuid": "u-1",
        "username": username,
        "firstName": "Jane",
        "lastName": "Doe",
        "certificate": { "uuid": certificate, "fingerprint": search_text(fingerprint) },
        "permissions": { "allowedListings": ["certificates"], "allowedActions": [] },
    })
}

#[tokio::test]
async fn a_profile_of_another_person_is_not_adopted() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    let leaf = renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_naming(
            "c-new",
            &Fingerprint::of(&leaf),
            "someone-else",
        )))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;

    renewing.world.session.follow().await;

    assert_eq!(renewing.remembered(), Some(renewing.fingerprint));
    match &*lock(&renewing.world.session.state) {
        State::SignedIn(active) => assert!(matches!(
            &active.credential,
            Credential::Certificate { fingerprint, .. } if *fingerprint == renewing.fingerprint
        )),
        _ => panic!("signed out"),
    }
}

#[tokio::test]
async fn a_lost_answer_to_the_profile_change_is_reconciled_at_once() {
    for status in [503, 500] {
        let renewing = Renewing::signing_in_with_the_old_certificate().await;
        renewing.signs_in_with_a_certificate();
        renewing.accepts("rekey").await;
        renewing.renew(NEW_KEY, false).await.unwrap();
        let leaf = renewing.serves_new_key_certificate().await;
        let moved = Arc::new(AtomicBool::new(false));
        Mock::given(method("PUT"))
            .and(path(PROFILE))
            .respond_with(TakesTheUpdate {
                moved: moved.clone(),
                status,
            })
            .with_priority(1)
            .mount(&renewing.world.ilm)
            .await;
        Mock::given(method("GET"))
            .and(path(PROFILE))
            .respond_with(MovesWithTheUpdate {
                moved,
                old: profile_naming("c-old", &renewing.fingerprint, "jdoe"),
                new: profile_naming("c-new", &Fingerprint::of(&leaf), "jdoe"),
            })
            .with_priority(1)
            .mount(&renewing.world.ilm)
            .await;

        renewing.world.session.follow().await;

        assert_eq!(renewing.updates().await.len(), 1, "{status}");
        assert_eq!(
            renewing.sign_in_uuid().as_deref(),
            Some("c-new"),
            "{status}"
        );
        assert_eq!(renewing.remembered(), Some(Fingerprint::of(&leaf)));
        assert!(renewing.requests.all().is_empty(), "{status}");
    }
}

#[tokio::test]
async fn a_sign_in_ilm_names_another_certificate_for_stays() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_naming(
            "c-other",
            &Fingerprint::of(b"other"),
            "jdoe",
        )))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert!(renewing.updates().await.is_empty());
    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-old"));
}

#[tokio::test]
async fn a_lost_answer_to_an_oauth_sign_in_move_is_learned_from_the_profile() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    let leaf = renewing.serves_new_key_certificate().await;
    let leaf_fingerprint = Fingerprint::of(&leaf);
    renewing.installs(&leaf);
    renewing.takes_the_update(503, 5).await;
    renewing.world.session.follow().await;
    assert!(renewing.pending().is_some());
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_naming(
            "c-new",
            &leaf_fingerprint,
            "jdoe",
        )))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::SignInMoved]);
    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-new"));
    assert!(
        renewing
            .world
            .session
            .signs_in_with("c-new", &leaf_fingerprint)
    );
}

// A rekey whose answer may have arrived.

impl Renewing {
    /// The rekey is answered with `status`; the renewal is sent with a new key.
    async fn renew_with_rekey_answered(&self, status: u16) -> Result<Waiting, RequestError> {
        self.answer("POST", &operation("rekey"), ResponseTemplate::new(status))
            .await;
        self.renew(NEW_KEY, false).await
    }

    fn age_the_renewal(&self, hours: i64) {
        let mut entry = self.requests.all().remove(0);
        entry.since -= hours * 3_600_000;
        self.requests.add(entry).unwrap();
    }
}

#[tokio::test]
async fn a_rekey_that_may_have_arrived_keeps_the_key_and_adopts_the_certificate_ilm_made() {
    let renewing = Renewing::new().await;

    let sent = renewing.renew_with_rekey_answered(503).await;

    assert_eq!(sent, Err(RequestError::Unexpected(503)));
    assert_eq!(renewing.keys.count(), 1);
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(renewing.requests.all()[0].uuid, None);
    renewing
        .serve_old(
            json!([
                { "uuid": "c-bad", "state": "failed", "relationType": "rekey" },
                { "uuid": "c-new", "state": "issued", "relationType": "rekey" },
            ]),
            1,
        )
        .await;
    renewing.serves_new_key_certificate().await;
    let (other, _, _) = issued("web", &KeyPair::generate().unwrap());
    renewing
        .answer(
            "GET",
            &state_path("c-bad"),
            ResponseTemplate::new(200).set_body_json(
                json!({ "state": "issued", "certificateContent": STANDARD.encode(other) }),
            ),
        )
        .await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert_eq!(found[0].uuid.as_deref(), Some("c-new"));
    assert_eq!(renewing.installer.calls().len(), 1);
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_rekey_that_may_have_arrived_and_made_nothing_ends_after_a_day_and_deletes_the_key() {
    let renewing = Renewing::new().await;
    renewing.renew_with_rekey_answered(503).await.unwrap_err();

    let waiting = renewing.world.session.follow().await;

    assert!(waiting.is_empty());
    assert_eq!(renewing.keys.count(), 1);
    renewing.age_the_renewal(25);

    let ended = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&ended),
        [Outcome::Ended(EndReason::NotSent)]
    );
    assert_eq!(renewing.keys.count(), 0);
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_move_ilm_already_made_waits_until_the_new_certificate_can_be_presented() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    let leaf = renewing.serves_new_key_certificate().await;
    renewing.installs(&leaf);
    renewing.takes_the_update(200, 5).await;
    Mock::given(method("GET"))
        .and(path(PROFILE))
        .respond_with(ResponseTemplate::new(200).set_body_json(profile_naming(
            "c-new",
            &Fingerprint::of(&leaf),
            "jdoe",
        )))
        .with_priority(1)
        .mount(&renewing.world.ilm)
        .await;
    renewing.cannot_open(true);

    renewing.world.session.follow().await;
    let waiting = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&waiting),
        [Outcome::SwitchPending { failures: 0 }]
    );
    assert_eq!(renewing.requests.all().len(), 1);
    assert_eq!(renewing.remembered(), Some(renewing.fingerprint));
    assert!(renewing.updates().await.is_empty());

    renewing.cannot_open(false);
    let moved = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&moved), [Outcome::SignInMoved]);
    assert_eq!(renewing.remembered(), Some(Fingerprint::of(&leaf)));
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_sign_in_certificate_the_person_chose_meanwhile_stays() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;
    if let State::SignedIn(active) = &mut *lock(&renewing.world.session.state) {
        active.person.sign_in = Some(SignInCertificate {
            uuid: "c-other".into(),
            fingerprint: Fingerprint::of(b"other"),
        });
    }

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Installed(_)]
    ));
    assert!(renewing.updates().await.is_empty());
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-other"));
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_certificate_that_is_not_the_sign_in_leaves_the_profile_alone() {
    let renewing = Renewing::new().await;
    renewing.accepts("rekey").await;
    let waiting = renewing.renew(NEW_KEY, false).await.unwrap();
    assert!(matches!(
        waiting.purpose,
        Purpose::Renew { sign_in: false, .. }
    ));
    renewing.serves_new_key_certificate().await;

    renewing.world.session.follow().await;

    assert!(renewing.updates().await.is_empty());
}

#[tokio::test]
async fn the_remembered_certificate_follows_the_renewal_once_it_is_installed() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.accepts("rekey").await;
    let waiting = renewing.renew(NEW_KEY, false).await.unwrap();
    assert!(matches!(
        waiting.purpose,
        Purpose::Renew { sign_in: true, .. }
    ));
    let leaf = renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(200, 5).await;
    assert_eq!(renewing.remembered(), Some(renewing.fingerprint));

    renewing.world.session.follow().await;

    assert_eq!(renewing.remembered(), Some(Fingerprint::of(&leaf)));
    assert_eq!(renewing.updates().await.len(), 1);
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_failed_switch_keeps_the_old_sign_in_and_is_retried_until_it_works() {
    capture_logs();
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    let leaf = renewing.serves_new_key_certificate().await;
    renewing.installs(&leaf);
    renewing.takes_the_update(500, 5).await;

    let first = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&first)[..],
        [Outcome::Installed(_)]
    ));
    assert_eq!(renewing.installer.calls().len(), 1);
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-old"));
    let pending = PendingSwitch {
        fingerprint: Fingerprint::of(&leaf),
        failures: 1,
    };
    assert_eq!(renewing.pending(), Some(pending));
    let written: Value = serde_json::from_str(
        &std::fs::read_to_string(renewing.folder.path().join("requests.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(written["waiting"][0]["purpose"]["switch"]["failures"], 1);

    let second = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&second),
        [Outcome::SwitchPending { failures: 2 }]
    );
    assert_eq!(second[0].needs_notice_key(), None);

    let third = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&third),
        [Outcome::SwitchPending { failures: 3 }]
    );
    assert_eq!(
        third[0].needs_notice_key().unwrap(),
        format!("renewal:needs:{}", renewing.fingerprint)
    );
    assert_eq!(renewing.installer.calls().len(), 1, "installed once");
    assert_eq!(renewing.requests.all().len(), 1);
    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains("WARN: the sign-in cannot move to c-new"),
        "{log}"
    );

    renewing.takes_the_update(200, 1).await;

    let last = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&last), [Outcome::SignInMoved]);
    assert_eq!(last[0].needs_notice_key(), None);
    assert_eq!(renewing.sign_in_uuid().as_deref(), Some("c-new"));
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn the_remembered_certificate_is_not_changed_while_the_switch_fails() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(500, 5).await;

    renewing.world.session.follow().await;

    assert_eq!(renewing.remembered(), Some(renewing.fingerprint));
    assert_eq!(renewing.pending().map(|pending| pending.failures), Some(1));
}

#[tokio::test]
async fn a_pending_move_to_a_certificate_no_longer_on_the_computer_is_dropped() {
    capture_logs();
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.takes_the_update(500, 5).await;
    renewing.world.session.follow().await;
    assert!(renewing.pending().is_some());

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::SignInMoved]);
    assert!(renewing.requests.all().is_empty());
    assert_eq!(renewing.updates().await.len(), 1, "no second try");
    assert_eq!(renewing.keys.count(), 1, "no key is deleted");
    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains("the renewed certificate c-new is no longer on this computer"),
        "{log}"
    );
    assert!(renewing.renew(NEW_KEY, false).await.is_ok());
}

#[tokio::test]
async fn nothing_moves_when_the_certificate_cannot_be_installed() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.accepts("rekey").await;
    renewing.renew(NEW_KEY, false).await.unwrap();
    renewing.serves_new_key_certificate().await;
    renewing.installer.fail(true);

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::InstallFailed]);
    assert!(renewing.updates().await.is_empty());
    assert_eq!(renewing.pending(), None);
}

impl Renewing {
    /// A request of another person of this computer for the certificate `c-old`.
    fn other_person_waits(&self, purpose: Purpose) {
        self.requests
            .add(Waiting {
                ilm: self.ilm(),
                username: "other".into(),
                uuid: Some("c-old".into()),
                ra_profile: "ra-1".into(),
                authority: "auth-1".into(),
                key: None,
                label: "web".into(),
                since: 1,
                prepared: false,
                purpose,
            })
            .unwrap();
    }
}

#[tokio::test]
async fn a_renewal_another_person_waits_for_is_not_sent_again() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.other_person_waits(Purpose::Renew {
        replaces: "c-old".into(),
        replaces_fingerprint: renewing.fingerprint,
        sign_in: false,
        same_key: true,
        automatic: false,
        switch: None,
    });

    let again = renewing.renew(Method::SameKey, false).await;

    assert_eq!(again, Err(RequestError::AlreadyRenewing));
    assert!(renewing.bodies("renew").await.is_empty());
    assert_eq!(renewing.requests.all().len(), 1);
}

// Revoking.

impl Renewing {
    async fn revoke(&self, remove: bool) -> Result<crate::requests::Waiting, RequestError> {
        self.world
            .session
            .revoke(self.target(), Reason::KeyCompromise, remove, &|| true)
            .await
    }

    async fn takes_the_revocation(&self) {
        Mock::given(method("POST"))
            .and(path(operation("revoke")))
            .respond_with(ResponseTemplate::new(204))
            .with_priority(1)
            .mount(&self.world.ilm)
            .await;
    }

    /// ILM says the certificate is in `code` from now on.
    async fn serves_old_in(&self, code: &str) {
        Mock::given(method("GET"))
            .and(path(state_path("c-old")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "state": code })))
            .with_priority(1)
            .mount(&self.world.ilm)
            .await;
    }

    fn removals(&self) -> Vec<Removal> {
        self.installer.removals()
    }
}

#[tokio::test]
async fn a_revocation_is_written_down_before_the_send_and_sends_the_reason() {
    let renewing = Renewing::new().await;
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path(operation("revoke")))
        .respond_with(SeesRevocation {
            file: renewing.folder.path().join("requests.json"),
            seen: seen.clone(),
        })
        .mount(&renewing.world.ilm)
        .await;

    let waiting = renewing.revoke(true).await.unwrap();

    let written: Value =
        serde_json::from_str(seen.lock().unwrap().as_deref().expect("written first")).unwrap();
    assert_eq!(written["waiting"][0]["purpose"]["kind"], "revoke");
    assert_eq!(written["waiting"][0]["purpose"]["remove"], true);
    assert_eq!(
        waiting.purpose,
        Purpose::Revoke {
            certificate: "c-old".into(),
            fingerprint: renewing.fingerprint,
            remove: true,
        }
    );
    assert_eq!(waiting.uuid.as_deref(), Some("c-old"));
    assert!(waiting.key.is_none());
    assert_eq!(renewing.requests.all(), [waiting]);
    let bodies = renewing.bodies("revoke").await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["reason"], "keyCompromise");
    assert_eq!(renewing.keys.count(), 0);
    assert!(
        renewing.removals().is_empty(),
        "nothing is removed at the send"
    );
}

#[tokio::test]
async fn a_refused_revocation_leaves_no_entry_and_is_reported() {
    let renewing = Renewing::new().await;
    renewing
        .answer(
            "POST",
            &operation("revoke"),
            ResponseTemplate::new(422).set_body_json(json!(["Unique-Refusal-Z9"])),
        )
        .await;

    let refused = renewing.revoke(false).await;

    assert_eq!(
        refused,
        Err(RequestError::Refused(vec!["Unique-Refusal-Z9".into()]))
    );
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_revocation_whose_answer_is_unknown_stays_so_a_follow_can_tell() {
    let renewing = Renewing::new().await;
    renewing
        .answer("POST", &operation("revoke"), ResponseTemplate::new(500))
        .await;

    let sent = renewing.revoke(false).await;

    assert_eq!(sent, Err(RequestError::Unexpected(500)));
    assert_eq!(renewing.requests.all().len(), 1);
}

#[tokio::test]
async fn a_second_revocation_is_not_sent_while_one_is_in_flight() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(false).await.unwrap();

    let again = renewing.revoke(false).await;

    assert_eq!(again, Err(RequestError::AlreadyRevoking));
    assert_eq!(renewing.bodies("revoke").await.len(), 1);
}

#[tokio::test]
async fn a_revocation_another_person_waits_for_is_not_sent_again() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.other_person_waits(Purpose::Revoke {
        certificate: "c-old".into(),
        fingerprint: renewing.fingerprint,
        remove: false,
    });

    let again = renewing.revoke(false).await;

    assert_eq!(again, Err(RequestError::AlreadyRevoking));
    assert!(renewing.bodies("revoke").await.is_empty());
}

#[tokio::test]
async fn a_revoked_certificate_is_removed_with_its_key_when_asked() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;

    let found = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&found),
        [Outcome::Revoked {
            fingerprint: renewing.fingerprint
        }]
    );
    assert_eq!(found[0].uuid.as_deref(), Some("c-old"));
    assert_eq!(
        found[0].revoked_notice_key().unwrap(),
        format!("certificate:revoked:{}", renewing.fingerprint)
    );
    assert_eq!(found[0].failed_notice_key(), None);
    assert_eq!(
        renewing.removals(),
        [Removal {
            fingerprint: renewing.fingerprint,
            delete_key: true
        }]
    );
    assert!(renewing.requests.all().is_empty());
    assert!(renewing.world.session.follow().await.is_empty());
}

impl Renewing {
    /// Revokes the old certificate with removal and lets ILM revoke it.
    async fn revoke_and_remove(&self) {
        self.takes_the_revocation().await;
        self.revoke(true).await.unwrap();
        self.serves_old_in("revoked").await;
        self.world.session.follow().await;
    }
}

#[tokio::test]
async fn the_key_stays_when_a_successor_on_the_computer_uses_it() {
    capture_logs();
    let mut renewing = Renewing::new().await;
    let (successor, _, _) = issued("web", &renewing.old_key);
    let held = vec![renewing.old.clone(), successor];

    renewing.world.session = renewing
        .world
        .session
        .with_identities(Arc::new(Holds(Some(held), Vec::new())));
    renewing.revoke_and_remove().await;

    assert_eq!(
        renewing.removals(),
        [Removal {
            fingerprint: renewing.fingerprint,
            delete_key: false
        }]
    );
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("key kept"), "{log}");
}

#[tokio::test]
async fn the_key_is_deleted_when_no_other_certificate_uses_it() {
    let mut renewing = Renewing::new().await;
    let (other, _, _) = issued("web", &KeyPair::generate().unwrap());
    let held = vec![renewing.old.clone(), other];

    renewing.world.session = renewing
        .world
        .session
        .with_identities(Arc::new(Holds(Some(held), Vec::new())));
    renewing.revoke_and_remove().await;

    assert_eq!(
        renewing.removals(),
        [Removal {
            fingerprint: renewing.fingerprint,
            delete_key: true
        }]
    );
}

#[tokio::test]
async fn the_key_stays_when_a_certificate_cannot_be_compared() {
    for (unreadable_is_old, name) in [(true, "the revoked one"), (false, "another one")] {
        let mut renewing = Renewing::new().await;
        let (other, _, _) = issued("web", &KeyPair::generate().unwrap());
        let hidden = if unreadable_is_old {
            renewing.fingerprint
        } else {
            Fingerprint::of(&other)
        };
        let held = vec![renewing.old.clone(), other];
        renewing.world.session = renewing
            .world
            .session
            .with_identities(Arc::new(Holds(Some(held), vec![hidden])));
        renewing.revoke_and_remove().await;

        assert_eq!(
            renewing.removals(),
            [Removal {
                fingerprint: renewing.fingerprint,
                delete_key: false
            }],
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_key_stays_when_the_certificates_of_the_computer_cannot_be_read() {
    let mut renewing = Renewing::new().await;

    renewing.world.session = renewing
        .world
        .session
        .with_identities(Arc::new(Holds(None, Vec::new())));
    renewing.revoke_and_remove().await;

    assert_eq!(
        renewing.removals(),
        [Removal {
            fingerprint: renewing.fingerprint,
            delete_key: false
        }]
    );
}

#[tokio::test]
async fn a_revoked_certificate_with_a_renewal_waiting_is_removed_once_the_renewal_is_gone() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;
    renewing.other_person_waits(Purpose::Renew {
        replaces: "c-old".into(),
        replaces_fingerprint: renewing.fingerprint,
        sign_in: false,
        same_key: true,
        automatic: false,
        switch: None,
    });

    let waiting = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&waiting),
        [Outcome::Revoking(RevokingStage::BeingRevoked)]
    );
    assert!(renewing.removals().is_empty());
    assert_eq!(renewing.requests.all().len(), 2);

    renewing.requests.remove_renewal("c-old").unwrap();
    let done = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&done)[..],
        [Outcome::Revoked { .. }]
    ));
    assert_eq!(renewing.removals().len(), 1);
    assert!(renewing.requests.all().is_empty());
}

impl Renewing {
    /// ILM says the old certificate is revoked and lists `related`.
    async fn serves_old_revoked_with(&self, related: Value) {
        Mock::given(method("GET"))
            .and(path(state_path("c-old")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "state": "revoked", "relatedCertificates": related })),
            )
            .with_priority(1)
            .mount(&self.world.ilm)
            .await;
    }
}

#[tokio::test]
async fn the_key_stays_when_ilm_lists_a_successor_that_may_share_it() {
    for relation in ["renewal", "replacement", "pending", "renewalViaAcme"] {
        let renewing = Renewing::new().await;
        renewing.takes_the_revocation().await;
        renewing.revoke(true).await.unwrap();
        renewing
            .serves_old_revoked_with(
                json!([{ "uuid": "c-new", "state": "issued", "relationType": relation }]),
            )
            .await;

        renewing.world.session.follow().await;

        assert_eq!(
            renewing.removals(),
            [Removal {
                fingerprint: renewing.fingerprint,
                delete_key: false
            }],
            "{relation}"
        );
    }
}

#[tokio::test]
async fn the_key_is_deleted_when_ilm_lists_only_a_rekeyed_or_failed_successor() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing
        .serves_old_revoked_with(json!([
            { "uuid": "c-new", "state": "issued", "relationType": "rekey" },
            { "uuid": "c-bad", "state": "failed", "relationType": "renewal" },
            { "uuid": "c-no", "state": "rejected", "relationType": "replacement" },
        ]))
        .await;

    renewing.world.session.follow().await;

    assert_eq!(
        renewing.removals(),
        [Removal {
            fingerprint: renewing.fingerprint,
            delete_key: true
        }]
    );
}

#[tokio::test]
async fn removing_the_sign_in_certificate_ends_the_certificate_sign_in_and_forgets_it() {
    let renewing = Renewing::signing_in_with_the_old_certificate().await;
    renewing.signs_in_with_a_certificate();
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;

    renewing.world.session.follow().await;

    match &*lock(&renewing.world.session.state) {
        State::SignedOut { problem, .. } => assert_eq!(
            problem.as_deref(),
            Some("Your sign-in certificate was revoked and removed from this computer.")
        ),
        _ => panic!("still signed in"),
    }
    assert_eq!(renewing.remembered(), None);
}

#[tokio::test]
async fn removing_another_certificate_leaves_the_remembered_one_and_the_session() {
    let renewing = Renewing::new().await;
    let other = Fingerprint::of(b"other");
    renewing
        .world
        .settings
        .save_certificate(&renewing.ilm(), &other)
        .unwrap();
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;

    renewing.world.session.follow().await;

    assert_eq!(renewing.removals().len(), 1);
    assert_eq!(renewing.remembered(), Some(other));
    assert!(matches!(
        &*lock(&renewing.world.session.state),
        State::SignedIn(_)
    ));
}

#[tokio::test]
async fn a_removal_waits_for_a_sign_in_change_and_then_completes() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;

    let changing = renewing.world.session.changing.lock().await;
    let following = renewing.world.session.follow();
    tokio::pin!(following);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut following)
            .await
            .is_err(),
        "the removal waits while a sign-in change is under way"
    );
    assert!(renewing.removals().is_empty());
    drop(changing);

    let found = tokio::time::timeout(std::time::Duration::from_secs(10), following)
        .await
        .expect("the follow completes");
    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Revoked { .. }]
    ));
}

#[tokio::test]
async fn a_revoked_certificate_stays_on_the_computer_when_not_asked_to_go() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(false).await.unwrap();
    renewing.serves_old_in("revoked").await;

    let found = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&found)[..],
        [Outcome::Revoked { .. }]
    ));
    assert!(renewing.removals().is_empty());
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_removal_that_fails_is_tried_again_and_the_entry_stays() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;
    renewing.installer.fail(true);

    let first = renewing.world.session.follow().await;

    assert!(first.is_empty());
    assert_eq!(renewing.requests.all().len(), 1);

    renewing.installer.fail(false);
    let second = renewing.world.session.follow().await;

    assert!(matches!(
        Renewing::outcomes(&second)[..],
        [Outcome::Revoked { .. }]
    ));
    assert_eq!(renewing.removals().len(), 2);
    assert!(renewing.requests.all().is_empty());
}

/// A revocation that ILM holds in `code` waits, and nothing is removed.
async fn assert_revocation_waits(code: &str, stage: RevokingStage) {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in(code).await;

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::Revoking(stage)]);
    assert_eq!(found[0].failed_notice_key(), None);
    assert_eq!(found[0].revoked_notice_key(), None);
    assert_eq!(found[0].revoke_failed_notice_key(), None);
    assert!(renewing.removals().is_empty());
    assert_eq!(renewing.requests.all().len(), 1);
}

#[tokio::test]
async fn a_revocation_ilm_is_making_waits_as_being_revoked_and_removes_nothing() {
    assert_revocation_waits("pending_revoke", RevokingStage::BeingRevoked).await;
}

#[tokio::test]
async fn a_revocation_waiting_for_approval_waits_as_such_and_removes_nothing() {
    assert_revocation_waits("pending_approval", RevokingStage::PendingApproval).await;
}

impl Renewing {
    /// Makes the written revocation `minutes` older than it is.
    fn age_the_revocation(&self, minutes: i64) {
        let mut entry = self.requests.all().remove(0);
        entry.since -= minutes * 60_000;
        self.requests.add(entry).unwrap();
    }
}

#[tokio::test]
async fn a_certificate_still_issued_just_after_the_send_is_still_being_revoked() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.age_the_revocation(9);

    let found = renewing.world.session.follow().await;

    assert_eq!(
        Renewing::outcomes(&found),
        [Outcome::Revoking(RevokingStage::BeingRevoked)]
    );
    assert_eq!(found[0].revoke_failed_notice_key(), None);
    assert!(renewing.removals().is_empty());
    assert_eq!(renewing.requests.all().len(), 1);
}

#[tokio::test]
async fn a_certificate_issued_again_after_the_settling_period_is_a_failed_revocation() {
    let renewing = Renewing::new().await;
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.age_the_revocation(11);

    let found = renewing.world.session.follow().await;

    assert_eq!(Renewing::outcomes(&found), [Outcome::NotRevoked]);
    assert_eq!(
        found[0].revoke_failed_notice_key().unwrap(),
        "revoke:failed:c-old"
    );
    assert_eq!(found[0].failed_notice_key(), None);
    assert!(renewing.removals().is_empty(), "removed before revoked");
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_certificate_that_is_not_the_one_in_ilm_is_not_revoked() {
    let renewing = Renewing::new().await;
    let other = Fingerprint::of(&[9]);
    let target = RenewalTarget {
        uuid: "c-old",
        fingerprint: &other,
        name: "web",
    };

    let refused = renewing
        .world
        .session
        .revoke(target, Reason::Unspecified, false, &|| true)
        .await;

    assert_eq!(refused, Err(RequestError::NotRevocable));
    assert!(!RequestError::NotRevocable.to_string().contains("renew"));
    assert!(renewing.requests.all().is_empty());
}

#[tokio::test]
async fn a_revocation_does_not_disturb_a_renewal_of_the_same_certificate() {
    let renewing = Renewing::new().await;
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, false).await.unwrap();
    renewing.takes_the_revocation().await;

    renewing.revoke(false).await.unwrap();

    assert_eq!(renewing.requests.all().len(), 2);
}

// The log.

#[tokio::test]
async fn the_log_of_a_renewal_with_a_sign_in_switch_and_a_revocation_holds_no_private_value() {
    capture_logs();
    let renewing = Renewing::build(&["Unique-Subject-Z9"], Vec::new(), true).await;
    renewing.refuses("rekey").await;
    assert!(renewing.renew(NEW_KEY, false).await.is_err());
    renewing.accepts("renew").await;
    renewing.renew(Method::SameKey, true).await.unwrap();
    let (leaf, intermediate, root) = issued("Unique-Subject-Z9", &renewing.old_key);
    renewing.serves_new(&leaf, &intermediate, &root).await;
    renewing.takes_the_update(200, 1).await;
    renewing.world.session.follow().await;
    renewing
        .answer(
            "POST",
            &operation("revoke"),
            ResponseTemplate::new(422).set_body_json(json!(["Unique-Refusal-Z9"])),
        )
        .await;
    assert!(renewing.revoke(true).await.is_err());
    renewing.takes_the_revocation().await;
    renewing.revoke(true).await.unwrap();
    renewing.serves_old_in("revoked").await;
    renewing.world.session.follow().await;

    let log = LOG.lock().unwrap().join("\n");

    assert!(log.contains("renewal sent"), "{log}");
    assert!(log.contains("renewal installed"), "{log}");
    assert!(log.contains("sign-in moved to c-new"), "{log}");
    assert!(log.contains("WARN: ILM refused the renewal"), "{log}");
    assert!(
        log.contains("INFO: revocation sent: c-old, KeyCompromise, remove: yes"),
        "{log}"
    );
    assert!(log.contains("WARN: ILM refused the revocation"), "{log}");
    assert!(log.contains("INFO: certificate c-old revoked"), "{log}");
    assert!(log.contains("INFO: certificate removed"), "{log}");
    for private in ["Unique-Subject-Z9", "Unique-Refusal-Z9"] {
        assert!(!log.contains(private), "{private} is in the log");
    }
    for line in log
        .lines()
        .filter(|line| line.contains("c-old") || line.contains("c-new"))
    {
        assert!(!line.contains("key-"), "{line}");
    }
}
