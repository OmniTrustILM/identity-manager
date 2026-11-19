use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::PrivateKeyDer;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::tests::{LOG, TestSettings, World, capture_logs};
use super::*;
use crate::http::client_with_identity_trusting;
use crate::identity::Candidate as FoundCertificate;
use crate::identity::testing::{
    ClientCerts, Issue, StandInStore, TestCa, TestIdentity, TestServer,
};
use crate::oauth::token::RefreshToken;

const ENTRY: &str = "Certificate on this computer";
const NOT_ASKED: &str = "This ILM's gateway is not set up for certificate sign-in.";
const REFUSED: &str = "The gateway did not accept this certificate.";
const UNKNOWN: &str =
    "ILM does not know this certificate. It must be your sign-in certificate in ILM.";
const KEY_DENIED: &str = "The system did not allow the use of this certificate's key.";
const GONE: &str = "The certificate you signed in with is no longer on this computer.";

fn entry() -> ProviderChoice {
    ProviderChoice {
        id: "certificate".into(),
        name: ENTRY.into(),
    }
}

fn names(choices: Vec<ProviderChoice>) -> Vec<String> {
    choices.into_iter().map(|choice| choice.name).collect()
}

async fn until(done: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the awaited state came");
}

/// Forwards connections to `upstream` once it is opened, so a request can be held in flight.
struct Gate {
    port: u16,
    open: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl Gate {
    async fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (open, opened) = watch::channel(false);
        let task = tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let mut opened = opened.clone();
                tokio::spawn(async move {
                    if opened.wait_for(|open| *open).await.is_err() {
                        return;
                    }
                    if let Ok(mut server) =
                        tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await
                    {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
        Self { port, open, task }
    }

    fn release(&self) {
        self.open.send_replace(true);
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A store that finds the certificate but whose key refuses to sign, as when the person chose Deny.
struct DeniedStore {
    inner: StandInStore,
    person: TestIdentity,
}

impl IdentityStore for DeniedStore {
    fn candidates(&self) -> Vec<FoundCertificate> {
        self.inner.candidates()
    }

    fn open(&self, fingerprint: &Fingerprint) -> Option<ClientIdentity> {
        self.inner
            .open(fingerprint)
            .map(|_| self.person.denied_identity())
    }
}

/// An ILM that is a test server asking for client certificates, and a session whose clients trust its CA.
struct CertWorld {
    server: TestServer,
    settings: Arc<TestSettings>,
    items: Arc<MemoryStore>,
    views: Arc<Mutex<Vec<SessionView>>>,
    session: Session,
}

impl CertWorld {
    /// Policy fixes the method to `certificate`, so the server needs to publish nothing.
    async fn start(
        ca: &TestCa,
        client_certs: ClientCerts,
        allowed: &TestIdentity,
        store: impl IdentityStore + 'static,
    ) -> Self {
        let server = TestServer::start(ca, client_certs, allowed.fingerprint()).await;
        let settings = Arc::new(TestSettings::new(Connection {
            address: IlmUrl::parse(&server.url()).ok(),
            locked: true,
            method: Some(SignInMethod::Certificate),
            ..Connection::default()
        }));
        let items = Arc::new(MemoryStore::default());
        let views = Arc::new(Mutex::new(Vec::new()));
        let recorded = views.clone();
        let root = ca.der().clone();
        let session = Session::new(
            crate::http::client_for_tests(),
            settings.clone(),
            items.clone(),
            move |view| recorded.lock().unwrap().push(view.clone()),
        )
        .with_identities(Arc::new(store))
        .with_certificate_client(Box::new(move |identity| {
            client_with_identity_trusting(&root, identity)
        }));
        Self {
            server,
            settings,
            items,
            views,
            session,
        }
    }

    /// The common case: `person` is known to ILM and held by the store.
    async fn of(ca: &TestCa, person: &TestIdentity) -> Self {
        Self::start(
            ca,
            ClientCerts::Required,
            person,
            StandInStore::new(vec![person.clone()]),
        )
        .await
    }

    async fn sign_in(&self, person: &TestIdentity) -> SessionView {
        self.session.connect("").await.unwrap();
        self.session
            .sign_in_with_certificate(&person.fingerprint().to_string())
            .await
    }

    fn remembered(&self) -> Option<Fingerprint> {
        self.settings.connection().certificate
    }

    fn remember(&self, person: &TestIdentity) {
        self.settings.connection.lock().unwrap().certificate = Some(person.fingerprint());
    }

    fn address(&self) -> String {
        self.settings.connection().address.unwrap().to_string()
    }

    fn server_port(&self) -> u16 {
        self.server
            .url()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn signed_in(&self, client: &TestIdentity) -> SessionView {
        SessionView::SignedIn {
            address: self.address(),
            person: PersonView {
                name: "Jane Doe".into(),
                username: "jdoe".into(),
            },
            allowed_listings: vec!["certificates".into()],
            certificate: Some(client.fingerprint().short()),
        }
    }

    fn signed_out(&self, problem: Option<&str>) -> SessionView {
        SessionView::SignedOut {
            address: Some(self.address()),
            locked: true,
            problem: problem.map(str::to_owned),
        }
    }

    async fn call_things(&self) -> Result<u16, CallError> {
        self.session
            .call_ilm(|client, ilm| client.get(format!("{}/v1/things", ilm.api())))
            .await
            .map(|response| response.status().as_u16())
    }

    fn requests_for(&self, path: &str) -> usize {
        self.server
            .requests()
            .iter()
            .filter(|seen| seen.path == path)
            .count()
    }

    /// The server goes away.
    async fn stop_server(&mut self, ca: &TestCa, person: &TestIdentity) {
        let stopped = std::mem::replace(
            &mut self.server,
            TestServer::start(ca, ClientCerts::Required, person.fingerprint()).await,
        );
        let address = IlmUrl::parse(&stopped.url()).ok();
        drop(stopped);
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.settings.connection.lock().unwrap().address = address;
    }

    /// Sends the session's requests through `gate` instead of straight to the server.
    fn through(&self, gate: &Gate) {
        self.settings.connection.lock().unwrap().address =
            IlmUrl::parse(&format!("https://localhost:{}", gate.port)).ok();
    }

    fn signed_in_views(&self) -> usize {
        self.views
            .lock()
            .unwrap()
            .iter()
            .filter(|view| matches!(view, SessionView::SignedIn { .. }))
            .count()
    }
}

fn two_certificates(ca: &TestCa) -> (TestIdentity, TestIdentity) {
    (
        ca.issue(Issue::client("Jane").valid((2020, 1, 1), (2060, 1, 1))),
        ca.issue(Issue::client("John").valid((2020, 1, 1), (2090, 1, 1))),
    )
}

#[tokio::test]
async fn the_certificate_is_offered_after_the_providers() {
    let ca = TestCa::new();
    let world = World::new()
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));

    let choices = world.session.connect(&world.ilm.uri()).await.unwrap();

    assert_eq!(names(choices.clone()), ["Corporate", ENTRY]);
    assert_eq!(choices[1], entry());
}

#[tokio::test]
async fn an_ilm_without_providers_offers_only_the_certificate() {
    let ca = TestCa::new();
    let world = World::publishing(&[])
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));

    assert_eq!(
        world.session.connect(&world.ilm.uri()).await.unwrap(),
        [entry()]
    );
}

#[tokio::test]
async fn without_providers_and_certificates_connect_says_so() {
    let world = World::publishing(&[]).await;

    let error = world.session.connect(&world.ilm.uri()).await.unwrap_err();

    assert_eq!(
        error,
        "This ILM offers no identity provider that this application can use, and this computer has no certificate that can sign in."
    );
}

#[tokio::test]
async fn policy_that_asks_for_the_certificate_reads_no_provider() {
    let ca = TestCa::new();
    let world = World::new()
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Certificate);

    let choices = world.session.connect(&world.ilm.uri()).await.unwrap();

    assert_eq!(choices, [entry()]);
    assert!(world.ilm.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn policy_that_asks_for_the_certificate_needs_one_on_the_computer() {
    let world = World::new().await;
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Certificate);

    let error = world.session.connect(&world.ilm.uri()).await.unwrap_err();

    assert_eq!(error, "This computer has no certificate that can sign in.");
}

#[tokio::test]
async fn policy_that_asks_for_oauth_hides_the_certificate() {
    let ca = TestCa::new();
    let world = World::new()
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Oauth);

    let choices = world.session.connect(&world.ilm.uri()).await.unwrap();

    assert_eq!(names(choices), ["Corporate"]);
    assert!(world.session.certificates().await.is_empty());
}

#[tokio::test]
async fn policy_that_asks_for_oauth_with_no_provider_keeps_the_provider_message() {
    let ca = TestCa::new();
    let world = World::publishing(&[])
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Oauth);

    let error = world.session.connect(&world.ilm.uri()).await.unwrap_err();

    assert_eq!(
        error,
        "This ILM offers no identity provider that this application can use."
    );
}

#[tokio::test]
async fn the_certificates_are_listed_with_the_remembered_one_marked() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &jane,
        StandInStore::new(vec![jane.clone(), john.clone()]),
    )
    .await;
    world.remember(&jane);

    let listed = world.session.certificates().await;

    let subjects: Vec<_> = listed
        .iter()
        .map(|choice| choice.subject.as_str())
        .collect();
    assert_eq!(subjects, ["John", "Jane"]);
    assert_eq!(listed[0].fingerprint, john.fingerprint().to_string());
    assert_eq!(listed[0].issuer, listed[1].issuer);
    assert!(listed[0].not_after > listed[1].not_after);
    assert!(listed[1].not_after > 0);
    assert_eq!(
        listed
            .iter()
            .map(|choice| choice.remembered)
            .collect::<Vec<_>>(),
        [false, true]
    );
}

#[tokio::test]
async fn a_certificate_signs_in_without_a_token_and_is_remembered() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;

    let view = world.sign_in(&jane).await;

    assert_eq!(view, world.signed_in(&jane));
    assert_eq!(world.session.view(), world.signed_in(&jane));
    assert!(
        world
            .views
            .lock()
            .unwrap()
            .contains(&SessionView::SigningIn {
                provider: ENTRY.into(),
                method: SignInKind::Certificate,
            })
    );
    assert_eq!(world.remembered(), Some(jane.fingerprint()));
    let seen = world.server.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/api/v1/auth/profile");
    assert_eq!(seen[0].fingerprint, Some(jane.fingerprint()));
    assert!(!seen[0].authorization);
    assert_eq!(world.session.browser_url(), None);
}

#[tokio::test]
async fn the_sign_in_lasts_when_the_certificate_cannot_be_remembered() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world
        .settings
        .broken
        .store(true, std::sync::atomic::Ordering::SeqCst);

    assert_eq!(world.sign_in(&jane).await, world.signed_in(&jane));
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn a_server_that_does_not_ask_for_a_certificate_is_said_not_to_be_set_up() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::start(
        &ca,
        ClientCerts::NotRequested,
        &jane,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;

    assert_eq!(
        world.sign_in(&jane).await,
        world.signed_out(Some(NOT_ASKED))
    );
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn a_gateway_that_refuses_the_handshake_is_said_to_refuse_the_certificate() {
    let ca = TestCa::new();
    let stranger = TestCa::new().issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &stranger).await;

    assert_eq!(
        world.sign_in(&stranger).await,
        world.signed_out(Some(REFUSED))
    );
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn a_certificate_ilm_does_not_know_is_said_so() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &john,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;

    assert_eq!(world.sign_in(&jane).await, world.signed_out(Some(UNKNOWN)));
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn a_certificate_remembered_before_is_kept_when_another_is_refused() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &john,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;
    world.remember(&john);

    world.sign_in(&jane).await;

    assert_eq!(world.remembered(), Some(john.fingerprint()));
}

#[tokio::test]
async fn a_key_the_system_will_not_use_is_said_so() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let store = DeniedStore {
        inner: StandInStore::new(vec![jane.clone()]),
        person: jane.clone(),
    };
    let world = CertWorld::start(&ca, ClientCerts::Required, &jane, store).await;

    assert_eq!(
        world.sign_in(&jane).await,
        world.signed_out(Some(KEY_DENIED))
    );
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn an_ilm_that_cannot_be_reached_is_said_so_as_for_a_provider() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let mut world = CertWorld::of(&ca, &jane).await;
    world.stop_server(&ca, &jane).await;

    assert_eq!(
        world.sign_in(&jane).await,
        world.signed_out(Some("ILM cannot be reached."))
    );
}

#[tokio::test]
async fn a_certificate_that_is_not_on_the_computer_is_refused() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::of(&ca, &jane).await;
    world.session.connect("").await.unwrap();
    let message = Some("This certificate is not on this computer.");

    let absent = world
        .session
        .sign_in_with_certificate(&john.fingerprint().to_string())
        .await;
    let invalid = world
        .session
        .sign_in_with_certificate("not a fingerprint")
        .await;

    assert_eq!(absent, world.signed_out(message));
    assert_eq!(invalid, world.signed_out(message));
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn policy_that_asks_for_oauth_refuses_the_certificate_sign_in() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.session.connect("").await.unwrap();
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Oauth);

    let view = world
        .session
        .sign_in_with_certificate(&jane.fingerprint().to_string())
        .await;

    let problem = "Your organization does not allow signing in with a certificate.";
    assert_eq!(view, world.signed_out(Some(problem)));
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn a_certificate_sign_in_needs_the_address_to_be_connected_first() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;

    let view = world
        .session
        .sign_in_with_certificate(&jane.fingerprint().to_string())
        .await;

    assert_eq!(
        view,
        world.signed_out(Some("Enter the address of your ILM first."))
    );
}

#[tokio::test]
async fn cancelling_while_ilm_has_not_answered_leaves_nothing_behind() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    let gate = Gate::start(world.server_port()).await;
    world.through(&gate);
    world.session.connect("").await.unwrap();
    let session = &world.session;
    let fingerprint = jane.fingerprint().to_string();

    let (view, ()) = tokio::join!(session.sign_in_with_certificate(&fingerprint), async {
        until(|| matches!(session.view(), SessionView::SigningIn { .. })).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        session.cancel();
    });
    gate.release();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert!(matches!(view, SessionView::SignedOut { problem: None, .. }));
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { problem: None, .. }
    ));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.signed_in_views(), 0);
}

#[tokio::test]
async fn signing_out_while_ilm_has_not_answered_is_not_undone() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    let gate = Gate::start(world.server_port()).await;
    world.through(&gate);
    world.session.connect("").await.unwrap();
    let session = &world.session;
    let fingerprint = jane.fingerprint().to_string();

    tokio::join!(session.sign_in_with_certificate(&fingerprint), async {
        until(|| matches!(session.view(), SessionView::SigningIn { .. })).await;
        session.sign_out().await;
    });
    gate.release();
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(world.session.view(), world.signed_out(None));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.signed_in_views(), 0);
}

#[tokio::test]
async fn calls_present_the_certificate_and_send_no_token() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;

    assert_eq!(world.call_things().await, Ok(200));

    let seen = world.server.requests();
    let call = seen.last().unwrap();
    assert_eq!(call.path, "/api/v1/things");
    assert_eq!(call.fingerprint, Some(jane.fingerprint()));
    assert!(!call.authorization);
}

#[tokio::test]
async fn a_401_signs_out_after_one_request() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &jane,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;
    world.sign_in(&jane).await;
    world.server.allow(john.fingerprint());

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.requests_for("/api/v1/things"), 1);
    assert_eq!(world.session.view(), world.signed_out(Some(UNKNOWN)));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.call_things().await, Err(CallError::SignedOut));
    assert_eq!(world.requests_for("/api/v1/things"), 1);
}

#[tokio::test]
async fn a_401_of_an_earlier_sign_in_does_not_end_a_newer_one() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;
    let Some(earlier) = (match &*lock(&world.session.state) {
        State::SignedIn(active) => active.credential.certificate(),
        _ => None,
    }) else {
        panic!("signed in with a certificate");
    };
    world.session.sign_out().await;
    world.sign_in(&jane).await;
    world.server.allow(john.fingerprint());

    world
        .session
        .end_certificate(&earlier.generation, UNKNOWN, &earlier.fingerprint)
        .await;

    assert_eq!(world.session.view(), world.signed_in(&jane));
    assert_eq!(world.remembered(), Some(jane.fingerprint()));
}

#[tokio::test]
async fn a_network_failure_keeps_the_session() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let mut world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;
    let before = world.address();
    world.stop_server(&ca, &jane).await;

    assert_eq!(world.call_things().await, Err(CallError::Unreachable));

    assert_eq!(
        world.session.view(),
        SessionView::SignedIn {
            address: before,
            person: PersonView {
                name: "Jane Doe".into(),
                username: "jdoe".into(),
            },
            allowed_listings: vec!["certificates".into()],
            certificate: Some(jane.fingerprint().short()),
        }
    );
    assert_eq!(world.remembered(), Some(jane.fingerprint()));
}

#[tokio::test]
async fn signing_out_drops_the_client_and_forgets_the_certificate() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;

    let view = world.session.sign_out().await;

    assert_eq!(view, world.signed_out(None));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.call_things().await, Err(CallError::SignedOut));
    assert_eq!(world.requests_for("/api/v1/things"), 0);
}

#[tokio::test]
async fn a_certificate_that_cannot_be_forgotten_is_reported_at_sign_out() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;
    world
        .settings
        .broken
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let view = world.session.sign_out().await;

    let SessionView::SignedOut {
        problem: Some(problem),
        ..
    } = view
    else {
        panic!("signed out with a problem");
    };
    assert!(problem.contains("remembered certificate could not be removed"));
}

#[tokio::test]
async fn start_signs_in_again_with_the_remembered_certificate() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.remember(&jane);

    let view = world.session.start().await;

    assert_eq!(view, world.signed_in(&jane));
    assert_eq!(world.remembered(), Some(jane.fingerprint()));
    assert_eq!(world.server.requests().len(), 1);
    assert_eq!(world.signed_in_views(), 1);
    assert!(
        !world
            .views
            .lock()
            .unwrap()
            .iter()
            .any(|view| matches!(view, SessionView::SigningIn { .. }))
    );
}

#[tokio::test]
async fn start_without_a_remembered_certificate_is_signed_out() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;

    assert_eq!(world.session.start().await, world.signed_out(None));
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn start_does_not_use_the_certificate_when_policy_asks_for_oauth() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.remember(&jane);
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Oauth);

    assert_eq!(world.session.start().await, world.signed_out(None));
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn start_prefers_a_saved_provider_sign_in() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.settings.connection.lock().unwrap().method = None;
    world.remember(&jane);
    let address = world.settings.connection().address.unwrap();
    world
        .items
        .save(&Item {
            ilm: address,
            issuer: "http://127.0.0.1:1".into(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("r1"),
        })
        .unwrap();

    let view = world.session.start().await;

    let SessionView::SignedOut {
        problem: Some(problem),
        ..
    } = view
    else {
        panic!("the provider sign-in was tried and failed");
    };
    assert!(
        problem.starts_with("Could not renew the sign-in"),
        "{problem}"
    );
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn start_with_a_certificate_that_is_gone_says_so_and_forgets_it() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world =
        CertWorld::start(&ca, ClientCerts::Required, &jane, StandInStore::new(vec![])).await;
    world.remember(&jane);

    assert_eq!(world.session.start().await, world.signed_out(Some(GONE)));
    assert_eq!(world.remembered(), None);
    assert!(world.server.requests().is_empty());
}

#[tokio::test]
async fn start_with_a_certificate_that_has_expired_says_so_and_forgets_it() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let later = SystemTime::now() + Duration::from_secs(80 * 365 * 24 * 3600);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &jane,
        StandInStore::new(vec![jane.clone()]).at(later),
    )
    .await;
    world.remember(&jane);

    assert_eq!(world.session.start().await, world.signed_out(Some(GONE)));
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn start_with_a_certificate_ilm_no_longer_knows_forgets_it() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &john,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;
    world.remember(&jane);

    assert_eq!(world.session.start().await, world.signed_out(Some(UNKNOWN)));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.server.requests().len(), 1);
}

#[tokio::test]
async fn start_keeps_the_certificate_when_ilm_cannot_be_reached() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let mut world = CertWorld::of(&ca, &jane).await;
    world.remember(&jane);
    world.stop_server(&ca, &jane).await;

    let view = world.session.start().await;

    assert_eq!(view, world.signed_out(Some("ILM cannot be reached.")));
    assert_eq!(world.remembered(), Some(jane.fingerprint()));
}

#[tokio::test]
async fn a_sign_out_while_the_start_waits_is_not_undone() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.remember(&jane);
    let gate = Gate::start(world.server_port()).await;
    world.through(&gate);
    let session = &world.session;

    let (view, ()) = tokio::join!(session.start(), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.sign_out().await;
        gate.release();
    });

    assert!(matches!(view, SessionView::SignedOut { .. }));
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { .. }
    ));
    assert_eq!(world.remembered(), None);
    assert_eq!(world.signed_in_views(), 0);
}

fn secret_der(key: PrivateKeyDer<'static>) -> Vec<u8> {
    match key {
        PrivateKeyDer::Pkcs8(der) => der.secret_pkcs8_der().to_vec(),
        _ => panic!("the test keys are PKCS#8"),
    }
}

#[tokio::test]
async fn the_log_of_a_certificate_flow_holds_no_key_or_body() {
    capture_logs();
    let ca = TestCa::new();
    let holder = ca.issue(Issue::client("Certificate Holder"));
    let world = CertWorld::of(&ca, &holder).await;
    world.sign_in(&holder).await;
    world.call_things().await.unwrap();
    world.session.sign_out().await;
    world.remember(&holder);
    world.session.start().await;

    let log = LOG.lock().unwrap().join("\n");
    let key = secret_der(holder.private_key());
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(log.contains("Certificate Holder"), "the subject is logged");
    assert!(log.contains(&holder.fingerprint().to_string()));
    assert!(log.contains("asked for a client certificate"));
    assert!(log.contains("as jdoe with a certificate"));
    assert!(log.contains("signed out"));
    for (index, secret) in [
        STANDARD.encode(&key),
        hex,
        STANDARD.encode(holder.leaf().as_ref()),
        "5d3a4c3e-0000-4000-8000-000000000001".to_owned(),
        "allowedListings".to_owned(),
    ]
    .iter()
    .enumerate()
    {
        assert!(
            !log.contains(secret.as_str()),
            "the log holds secret number {index}"
        );
    }
}

#[tokio::test]
async fn start_under_certificate_policy_ignores_a_saved_provider_sign_in() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.remember(&jane);
    let address = world.settings.connection().address.unwrap();
    world
        .items
        .save(&Item {
            ilm: address,
            issuer: "http://127.0.0.1:1".into(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("r1"),
        })
        .unwrap();

    assert_eq!(world.session.start().await, world.signed_in(&jane));
}

#[tokio::test]
async fn policy_that_asks_for_the_certificate_refuses_the_provider_sign_in() {
    let world = World::new().await;
    world.session.connect(&world.ilm.uri()).await.unwrap();
    world.settings.connection.lock().unwrap().method = Some(SignInMethod::Certificate);

    let view = world
        .session
        .sign_in("0", |_| panic!("no browser opens"))
        .await;

    assert_eq!(
        view,
        super::tests::signed_out(
            &world,
            Some("Your organization does not allow signing in with an identity provider.")
        )
    );
}

#[tokio::test]
async fn a_certificate_that_expired_during_the_session_ends_it_without_a_request() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;
    if let State::SignedIn(active) = &mut *lock(&world.session.state)
        && let Credential::Certificate { not_after, .. } = &mut active.credential
    {
        *not_after = Some(UNIX_EPOCH + Duration::from_secs(1));
    }

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.requests_for("/api/v1/things"), 0);
    assert_eq!(
        world.session.view(),
        world.signed_out(Some("The certificate you signed in with has expired."))
    );
    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn a_certificate_refused_with_a_server_that_asked_is_forgotten_after_an_interactive_sign_in()
{
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::start(
        &ca,
        ClientCerts::Required,
        &john,
        StandInStore::new(vec![jane.clone()]),
    )
    .await;
    world.remember(&jane);

    world.sign_in(&jane).await;

    assert_eq!(world.remembered(), None);
}

#[tokio::test]
async fn ending_the_sign_in_with_one_certificate_keeps_a_newer_remembered_one() {
    let ca = TestCa::new();
    let (jane, john) = two_certificates(&ca);
    let world = CertWorld::of(&ca, &jane).await;
    world.sign_in(&jane).await;
    let Some(held) = (match &*lock(&world.session.state) {
        State::SignedIn(active) => active.credential.certificate(),
        _ => None,
    }) else {
        panic!("signed in with a certificate");
    };
    world.remember(&john);

    world
        .session
        .end_certificate(&held.generation, UNKNOWN, &held.fingerprint)
        .await;

    assert_eq!(world.session.view(), world.signed_out(Some(UNKNOWN)));
    assert_eq!(world.remembered(), Some(john.fingerprint()));
}

#[tokio::test]
async fn a_failed_provider_discovery_does_not_hide_the_certificate() {
    let ca = TestCa::new();
    let world = World::new()
        .await
        .with_identities(StandInStore::new(vec![ca.issue(Issue::client("Jane"))]));

    let choices = world.session.connect("http://127.0.0.1:1").await.unwrap();

    assert_eq!(choices, [entry()]);
}

#[tokio::test]
async fn a_failed_provider_discovery_is_the_error_when_no_certificate_can_sign_in() {
    let world = World::new().await;

    let error = world
        .session
        .connect("http://127.0.0.1:1")
        .await
        .unwrap_err();

    assert_eq!(error, "ILM cannot be reached.");
}

#[tokio::test]
async fn a_chooser_opened_for_an_address_that_has_since_changed_does_not_present_the_certificate() {
    let ca = TestCa::new();
    let jane = ca.issue(Issue::client("Jane"));
    let world = CertWorld::of(&ca, &jane).await;
    world.session.connect("").await.unwrap();
    world.settings.connection.lock().unwrap().address =
        IlmUrl::parse("https://other.example.com").ok();

    let view = world
        .session
        .sign_in_with_certificate(&jane.fingerprint().to_string())
        .await;

    assert!(matches!(
        view,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
    assert!(world.server.requests().is_empty());
}
