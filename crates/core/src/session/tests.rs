use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};

use log::LevelFilter;
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;
use crate::http::client_for_tests;
use crate::oauth::token::RefreshToken;

pub(crate) struct TestSettings {
    pub(super) connection: Mutex<Connection>,
    /// Saving the remembered certificate fails while this is set.
    pub(super) broken: AtomicBool,
}

impl TestSettings {
    pub(super) fn new(connection: Connection) -> Self {
        Self {
            connection: Mutex::new(connection),
            broken: AtomicBool::new(false),
        }
    }
}

impl ConnectionSettings for TestSettings {
    fn connection(&self) -> Connection {
        self.connection.lock().unwrap().clone()
    }

    fn save_address(&self, address: &IlmUrl) -> Result<(), String> {
        self.connection.lock().unwrap().address = Some(address.clone());
        Ok(())
    }

    fn save_certificate(&self, _: &IlmUrl, fingerprint: &Fingerprint) -> Result<(), String> {
        if self.broken.load(Ordering::SeqCst) {
            return Err("the settings file is read-only".to_owned());
        }
        self.connection.lock().unwrap().certificate = Some(*fingerprint);
        Ok(())
    }

    fn forget_certificate(&self, failed: Option<&Fingerprint>) -> Result<(), String> {
        if self.broken.load(Ordering::SeqCst) {
            return Err("the settings file is read-only".to_owned());
        }
        let mut connection = self.connection.lock().unwrap();
        if failed.is_none_or(|failed| connection.certificate.as_ref() == Some(failed)) {
            connection.certificate = None;
        }
        Ok(())
    }
}

/// A memory store whose saves and deletes fail while `broken` is set.
#[derive(Default)]
struct TestStore {
    items: MemoryStore,
    broken: AtomicBool,
}

impl TestStore {
    fn check(&self) -> Result<(), StoreError> {
        if self.broken.load(Ordering::SeqCst) {
            return Err(StoreError::for_tests("the keychain is locked"));
        }
        Ok(())
    }
}

impl RefreshStore for TestStore {
    fn load(&self, ilm: &IlmUrl) -> Result<Option<Item>, StoreError> {
        self.items.load(ilm)
    }

    fn save(&self, item: &Item) -> Result<(), StoreError> {
        self.check()?;
        self.items.save(item)
    }

    fn delete(&self, ilm: &IlmUrl) -> Result<(), StoreError> {
        self.check()?;
        self.items.delete(ilm)
    }
}

pub(crate) struct World {
    pub(crate) ilm: MockServer,
    idp: MockServer,
    store: Arc<TestStore>,
    pub(crate) settings: Arc<TestSettings>,
    views: Arc<Mutex<Vec<SessionView>>>,
    pub(crate) session: Session,
}

impl World {
    pub(crate) async fn new() -> Self {
        Self::publishing(&[("Corporate", Some("app"))]).await
    }

    /// The same world, whose session also offers the certificates of `identities`.
    pub(super) fn with_identities(mut self, identities: impl IdentityStore + 'static) -> Self {
        let recorded = self.views.clone();
        self.session = Session::new(
            client_for_tests(),
            self.settings.clone(),
            self.store.clone(),
            move |view| recorded.lock().unwrap().push(view.clone()),
        )
        .with_identities(Arc::new(identities));
        self
    }

    pub(super) async fn publishing(providers: &[(&str, Option<&str>)]) -> Self {
        // Not from the pool, so a test can close it by replacing it.
        let ilm = MockServer::builder().start().await;
        let idp = MockServer::start().await;
        let store = Arc::new(TestStore::default());
        let settings = Arc::new(TestSettings::new(Connection::default()));
        let views = Arc::new(Mutex::new(Vec::new()));
        let recorded = views.clone();
        let session = Session::new(
            client_for_tests(),
            settings.clone(),
            store.clone(),
            move |view| {
                recorded.lock().unwrap().push(view.clone());
            },
        );
        let world = World {
            ilm,
            idp,
            store,
            settings,
            views,
            session,
        };
        world.publish(providers).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&world.ilm)
            .await;
        world
    }

    pub(crate) async fn at_address() -> Self {
        let world = Self::new().await;
        world.settings.connection.lock().unwrap().address = Some(world.address());
        world
    }

    pub(crate) fn address(&self) -> IlmUrl {
        IlmUrl::for_tests(&self.ilm.uri())
    }

    fn api(&self, tail: &str) -> String {
        format!("{}/api{tail}", self.ilm.uri())
    }

    async fn publish(&self, providers: &[(&str, Option<&str>)]) {
        let issuer = self.idp.uri();
        let entries: Vec<_> = providers
            .iter()
            .map(|(name, client_id)| {
                json!({"issuer": issuer, "name": name, "client_id": client_id, "scopes": ["openid"]})
            })
            .collect();
        Mock::given(method("GET"))
            .and(path("/.well-known/oauth-protected-resource/api"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "resource": self.api(""),
                "authorization_servers": [issuer],
                "otilm_authorization_servers": entries,
            })))
            .mount(&self.ilm)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/auth"),
                "token_endpoint": format!("{issuer}/token"),
                "revocation_endpoint": format!("{issuer}/revoke"),
            })))
            .mount(&self.idp)
            .await;
    }

    pub(crate) async fn profile_for(&self, access: &str) {
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .and(header("authorization", format!("Bearer {access}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-1",
                "username": "jdoe",
                "firstName": "Jane",
                "lastName": "Doe",
                "permissions": {"allowedListings": ["certificates"], "allowedActions": []},
            })))
            .mount(&self.ilm)
            .await;
    }

    pub(crate) async fn grant(&self, kind: &str, response: ResponseTemplate, times: Option<u64>) {
        let mock = Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(format!("grant_type={kind}")))
            .respond_with(response);
        match times {
            Some(times) => mock.up_to_n_times(times).mount(&self.idp).await,
            None => mock.mount(&self.idp).await,
        }
    }

    pub(crate) async fn code_grant(&self, access: &str, refresh: Option<&str>, expires_in: u64) {
        self.grant(
            "authorization_code",
            tokens(access, refresh, expires_in),
            None,
        )
        .await;
    }

    async fn serve_things(&self, accepted: Option<&str>) {
        let mock = Mock::given(method("GET")).and(path("/api/v1/things"));
        match accepted {
            Some(access) => {
                mock.and(header("authorization", format!("Bearer {access}").as_str()))
                    .respond_with(ResponseTemplate::new(200))
                    .mount(&self.ilm)
                    .await;
            }
            None => {
                mock.respond_with(ResponseTemplate::new(401))
                    .mount(&self.ilm)
                    .await;
            }
        }
    }

    pub(crate) async fn sign_in(&self) -> SessionView {
        self.session.connect(&self.ilm.uri()).await.unwrap();
        self.session.sign_in("0", browser("the-code")).await
    }

    async fn call_things(&self) -> Result<u16, CallError> {
        self.session
            .call_ilm(|client, ilm| client.get(format!("{}/v1/things", ilm.api())))
            .await
            .map(|response| response.status().as_u16())
    }

    async fn requests(&self, server: &MockServer, tail: &str) -> Vec<Request> {
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.url.path() == tail)
            .collect()
    }

    pub(crate) fn put_item(&self, refresh: &str) {
        self.store
            .save(&Item {
                ilm: self.address(),
                issuer: self.idp.uri(),
                client_id: "app".into(),
                resource: None,
                refresh_token: RefreshToken::new(refresh),
            })
            .unwrap();
    }

    fn stored_refresh(&self) -> Option<String> {
        self.store
            .load(&self.address())
            .unwrap()
            .map(|item| item.refresh_token.as_str().to_owned())
    }
}

fn tokens(access: &str, refresh: Option<&str>, expires_in: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
        "token_type": "Bearer",
    }))
}

fn invalid_grant() -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"}))
}

fn browser(code: &'static str) -> impl Fn(&Url) + Send + 'static {
    browser_answering(code, None)
}

fn browser_answering(
    code: &'static str,
    state: Option<&'static str>,
) -> impl Fn(&Url) + Send + 'static {
    move |url| {
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let state = state.map_or_else(|| query["state"].clone(), str::to_owned);
        let answer = format!("{}?code={code}&state={state}", query["redirect_uri"]);
        tokio::spawn(async move { client_for_tests().get(answer).send().await });
    }
}

pub(super) fn signed_out(world: &World, problem: Option<&str>) -> SessionView {
    SessionView::SignedOut {
        address: Some(world.ilm.uri()),
        locked: false,
        problem: problem.map(str::to_owned),
        again: false,
    }
}

fn is_signed_in(view: &SessionView) -> bool {
    matches!(view, SessionView::SignedIn { .. })
}

#[tokio::test]
async fn a_new_session_is_starting() {
    let world = World::new().await;
    assert_eq!(world.session.view(), SessionView::Starting);
}

#[tokio::test]
async fn holding_the_sends_keeps_the_next_hold_waiting_until_it_is_dropped() {
    let world = World::new().await;
    let held = world.session.hold_sends().await;
    let waiting = tokio::time::timeout(Duration::from_millis(50), world.session.hold_sends()).await;
    assert!(waiting.is_err());
    drop(held);
    let free = tokio::time::timeout(Duration::from_secs(5), world.session.hold_sends()).await;
    assert!(free.is_ok());
}

#[tokio::test]
async fn holding_the_sends_waits_for_the_saved_sign_in_to_be_renewed() {
    let world = World::new().await;
    let renewing = world.session.renewing.lock().await;
    let waiting = tokio::time::timeout(Duration::from_millis(50), world.session.hold_sends()).await;
    assert!(waiting.is_err());
    drop(renewing);
    let free = tokio::time::timeout(Duration::from_secs(5), world.session.hold_sends()).await;
    assert!(free.is_ok());
}

#[tokio::test]
async fn holding_the_sends_waits_for_a_claimed_profile_to_be_sent() {
    let world = World::new().await;
    let claiming = world.session.claiming.read().await;
    let waiting = tokio::time::timeout(Duration::from_millis(50), world.session.hold_sends()).await;
    assert!(waiting.is_err());
    drop(claiming);
    let free = tokio::time::timeout(Duration::from_secs(5), world.session.hold_sends()).await;
    assert!(free.is_ok());
}

#[tokio::test]
async fn holding_the_sends_waits_for_a_change_of_the_sign_in_certificate() {
    let world = World::new().await;
    let changing = world.session.changing.lock().await;
    let waiting = tokio::time::timeout(Duration::from_millis(50), world.session.hold_sends()).await;
    assert!(waiting.is_err());
    drop(changing);
    let free = tokio::time::timeout(Duration::from_secs(5), world.session.hold_sends()).await;
    assert!(free.is_ok());
}

#[tokio::test]
async fn connect_lists_the_published_provider_and_remembers_the_address() {
    let world = World::new().await;

    let choices = world.session.connect(&world.ilm.uri()).await.unwrap();

    assert_eq!(
        choices,
        [ProviderChoice {
            id: "0".into(),
            name: "Corporate".into()
        }]
    );
    assert_eq!(world.settings.connection().address, Some(world.address()));
}

#[tokio::test]
async fn connect_refuses_a_bad_address_and_an_ilm_that_publishes_nothing() {
    let world = World::new().await;
    let silent = MockServer::start().await;

    let bad = world.session.connect("http://ilm.example.com").await;
    assert_eq!(bad.unwrap_err(), "The address must use https.");
    assert_eq!(world.settings.connection().address, None);

    let missing = world.session.connect(&silent.uri()).await.unwrap_err();
    assert!(missing.contains("does not publish how to sign in"));
}

#[tokio::test]
async fn connect_says_so_when_no_provider_can_be_used() {
    let world = World::new().await;
    world.idp.reset().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&world.idp)
        .await;

    let error = world.session.connect(&world.ilm.uri()).await.unwrap_err();

    assert!(error.contains("no identity provider"), "{error}");
}

#[tokio::test]
async fn policy_names_the_provider_to_use_and_an_unknown_name_leaves_the_choice() {
    let world = World::publishing(&[("First", Some("app")), ("Second", Some("app"))]).await;
    let names = |choices: Vec<ProviderChoice>| -> Vec<String> {
        choices.into_iter().map(|choice| choice.name).collect()
    };

    let both = world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(names(both), ["First", "Second"]);

    world.settings.connection.lock().unwrap().provider = Some("Second".into());
    let chosen = world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].name, "Second");

    world.settings.connection.lock().unwrap().provider = Some("Nobody".into());
    let unknown = world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(unknown.len(), 2);
}

#[tokio::test]
async fn a_locked_address_is_used_whatever_is_typed() {
    let world = World::at_address().await;
    world.settings.connection.lock().unwrap().locked = true;

    let choices = world.session.connect("https://other.example.com").await;

    assert_eq!(choices.unwrap().len(), 1);
    assert_eq!(world.settings.connection().address, Some(world.address()));
}

#[tokio::test]
async fn a_full_sign_in_ends_signed_in_with_the_person_and_keeps_only_the_refresh_token() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;

    let view = world.sign_in().await;

    let expected = SessionView::SignedIn {
        address: world.ilm.uri(),
        person: PersonView {
            name: "Jane Doe".into(),
            username: "jdoe".into(),
        },
        allowed_listings: vec!["certificates".into()],
        certificate: None,
        unreachable: false,
    };
    assert_eq!(view, expected);
    assert_eq!(world.session.view(), expected);
    let views = world.views.lock().unwrap().clone();
    assert!(views.contains(&SessionView::SigningIn {
        provider: "Corporate".into(),
        method: SignInKind::Browser
    }));
    let item = world.store.load(&world.address()).unwrap().unwrap();
    assert_eq!(item.refresh_token.as_str(), "r1");
    assert_eq!(item.issuer, world.idp.uri());
    assert_eq!(item.client_id, "app");
}

#[tokio::test]
async fn the_browser_address_is_known_while_waiting_and_cancel_ends_the_wait() {
    let world = World::new().await;
    world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(world.session.browser_url(), None);
    let opened = Arc::new(Mutex::new(None));
    let seen = opened.clone();
    let session = &world.session;

    let (view, waited_for) = tokio::join!(
        session.sign_in("0", move |url| {
            *seen.lock().unwrap() = Some(url.clone());
        }),
        async {
            let mut url = session.browser_url();
            while url.is_none() {
                tokio::task::yield_now().await;
                url = session.browser_url();
            }
            session.cancel();
            url
        }
    );

    assert_eq!(view, signed_out(&world, None));
    assert_eq!(waited_for, *opened.lock().unwrap());
    assert_eq!(world.session.browser_url(), None);
}

#[tokio::test]
async fn an_answer_that_does_not_match_the_request_gives_a_problem() {
    let world = World::new().await;
    world.session.connect(&world.ilm.uri()).await.unwrap();

    let view = world
        .session
        .sign_in("0", browser_answering("the-code", Some("forged")))
        .await;

    match view {
        SessionView::SignedOut {
            problem: Some(problem),
            ..
        } => assert!(problem.contains("did not match"), "{problem}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn signing_in_with_an_unknown_provider_asks_to_connect_first() {
    let world = World::new().await;
    let view = world.session.sign_in("7", browser("c")).await;
    assert!(matches!(
        view,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
}

#[tokio::test]
async fn a_refused_code_or_a_refused_token_gives_a_problem_and_saves_nothing() {
    let world = World::new().await;
    world
        .grant("authorization_code", invalid_grant(), Some(1))
        .await;
    assert!(matches!(
        world.sign_in().await,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));

    world.code_grant("a1", Some("r1"), 3600).await;
    let view = world.sign_in().await;
    assert!(
        matches!(&view, SessionView::SignedOut { problem: Some(p), .. } if p.contains("did not accept"))
    );
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn without_a_refresh_token_the_access_token_is_used_until_it_expires() {
    let world = World::new().await;
    world.code_grant("a1", None, 30).await;
    world.profile_for("a1").await;
    world.serve_things(Some("a1")).await;

    assert!(is_signed_in(&world.sign_in().await));
    assert_eq!(world.stored_refresh(), None);

    assert_eq!(world.call_things().await, Ok(200));
    assert!(is_signed_in(&world.session.view()));
}

#[tokio::test]
async fn without_a_refresh_token_the_session_ends_with_the_access_token() {
    let world = World::new().await;
    world.code_grant("a1", None, 0).await;
    world.profile_for("a1").await;
    world.serve_things(Some("a1")).await;
    assert!(is_signed_in(&world.sign_in().await));

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
}

#[tokio::test]
async fn a_start_with_a_stored_item_renews_silently_and_reads_the_profile() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", tokens("a1", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;

    let view = world.session.start().await;

    assert!(is_signed_in(&view), "{view:?}");
    assert!(world.requests(&world.idp, "/auth").await.is_empty());
}

#[tokio::test]
async fn a_start_without_an_address_or_an_item_shows_signed_out() {
    let world = World::new().await;
    assert_eq!(
        world.session.start().await,
        SessionView::SignedOut {
            address: None,
            locked: false,
            problem: None,
            again: false,
        }
    );

    let world = World::at_address().await;
    assert_eq!(world.session.start().await, signed_out(&world, None));
}

#[tokio::test]
async fn a_stored_item_for_another_address_is_ignored() {
    let world = World::at_address().await;
    world
        .store
        .save(&Item {
            ilm: IlmUrl::parse("other.example.com").unwrap(),
            issuer: world.idp.uri(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("r-other"),
        })
        .unwrap();

    assert_eq!(world.session.start().await, signed_out(&world, None));
    assert!(world.requests(&world.idp, "/token").await.is_empty());
}

#[tokio::test]
async fn a_start_refused_by_the_provider_deletes_the_item() {
    let world = World::at_address().await;
    world.put_item("r1");
    world.grant("refresh_token", invalid_grant(), None).await;

    let view = world.session.start().await;

    assert!(matches!(
        view,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_start_refused_by_the_provider_runs_the_sign_out_hook() {
    let world = World::at_address().await;
    world.put_item("r1");
    world.grant("refresh_token", invalid_grant(), None).await;
    let ran = Arc::new(AtomicBool::new(false));
    let seen = ran.clone();
    world
        .session
        .on_signed_out(move || seen.store(true, Ordering::SeqCst));

    world.session.start().await;

    assert!(ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_failed_sign_in_runs_the_sign_out_hook() {
    let world = World::new().await;
    *lock(&world.session.state) = State::SignedOut {
        problem: None,
        again: Some(Again::Certificate),
    };
    let ran = Arc::new(AtomicBool::new(false));
    let seen = ran.clone();
    world
        .session
        .on_signed_out(move || seen.store(true, Ordering::SeqCst));

    world.session.sign_in_again(browser("the-code")).await;

    assert!(ran.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_start_that_cannot_reach_the_provider_keeps_the_item_and_says_so() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), None)
        .await;

    let view = world.session.start().await;

    assert!(matches!(view, SessionView::Unreachable { .. }));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
}

#[tokio::test]
async fn a_start_with_an_unreadable_provider_or_store_keeps_the_item_and_says_so() {
    let world = World::at_address().await;
    world.put_item("r1");
    world.idp.reset().await;

    let view = world.session.start().await;

    assert!(matches!(view, SessionView::Unreachable { .. }));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
}

#[tokio::test]
async fn a_start_whose_profile_is_refused_is_signed_out_and_the_item_removed() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", tokens("a-unknown", Some("r1"), 3600), None)
        .await;

    let view = world.session.start().await;

    assert!(matches!(
        &view,
        SessionView::SignedOut { problem: Some(p), .. } if p.contains("did not accept")
    ));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn an_access_token_that_expires_within_a_minute_is_renewed_before_the_call() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.serve_things(Some("a2")).await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Ok(200));
    assert_eq!(world.call_things().await, Ok(200));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 2);
    assert_eq!(world.requests(&world.ilm, "/api/v1/things").await.len(), 2);
}

#[tokio::test]
async fn a_valid_access_token_is_not_renewed() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.serve_things(Some("a1")).await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Ok(200));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 1);
}

#[tokio::test]
async fn a_401_renews_once_and_retries_once() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.serve_things(Some("a2")).await;
    world.serve_things(None).await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Ok(200));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 2);
    assert_eq!(world.requests(&world.ilm, "/api/v1/things").await.len(), 2);
}

#[tokio::test]
async fn a_second_401_is_returned_without_another_renewal() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.serve_things(None).await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Ok(401));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 2);
    assert_eq!(world.requests(&world.ilm, "/api/v1/things").await.len(), 2);
    assert!(is_signed_in(&world.session.view()));
}

struct ChecksTheStore {
    store: Arc<TestStore>,
    address: IlmUrl,
    saw_rotated: Arc<AtomicBool>,
}

impl Respond for ChecksTheStore {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let item = self.store.load(&self.address).unwrap().unwrap();
        self.saw_rotated
            .store(item.refresh_token.as_str() == "r2", Ordering::SeqCst);
        ResponseTemplate::new(200)
    }
}

#[tokio::test]
async fn a_rotated_refresh_token_is_saved_before_the_call_goes_on() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world
        .grant("refresh_token", tokens("a2", Some("r2"), 3600), None)
        .await;
    world.profile_for("a1").await;
    let saw_rotated = Arc::new(AtomicBool::new(false));
    Mock::given(method("GET"))
        .and(path("/api/v1/things"))
        .respond_with(ChecksTheStore {
            store: world.store.clone(),
            address: world.address(),
            saw_rotated: saw_rotated.clone(),
        })
        .mount(&world.ilm)
        .await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Ok(200));

    assert!(saw_rotated.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_refused_renewal_deletes_the_item_and_signs_out() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world.grant("refresh_token", invalid_grant(), None).await;
    world.profile_for("a1").await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.stored_refresh(), None);
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { .. }
    ));
    assert_eq!(world.call_things().await, Err(CallError::SignedOut));
}

#[tokio::test]
async fn an_unreachable_provider_keeps_the_item_and_the_next_call_tries_again() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.serve_things(Some("a2")).await;
    world.sign_in().await;

    assert_eq!(world.call_things().await, Err(CallError::Unreachable));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
    assert!(is_signed_in(&world.session.view()));

    assert_eq!(world.call_things().await, Ok(200));
}

#[tokio::test]
async fn an_unreachable_ilm_is_reported() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;

    let result = world
        .session
        .call_ilm(|client, _| client.get("http://127.0.0.1:1/"))
        .await;

    assert_eq!(result.err(), Some(CallError::Unreachable));
    assert!(is_signed_in(&world.session.view()));
}

struct RevokeSeesTheStore {
    store: Arc<TestStore>,
    address: IlmUrl,
    item_was_gone: Arc<AtomicBool>,
    status: u16,
}

impl Respond for RevokeSeesTheStore {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let gone = self.store.load(&self.address).unwrap().is_none();
        self.item_was_gone.store(gone, Ordering::SeqCst);
        ResponseTemplate::new(self.status)
    }
}

async fn sign_out_with_revocation(status: u16) {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    let item_was_gone = Arc::new(AtomicBool::new(false));
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .and(body_string_contains("token=r1"))
        .respond_with(RevokeSeesTheStore {
            store: world.store.clone(),
            address: world.address(),
            item_was_gone: item_was_gone.clone(),
            status,
        })
        .mount(&world.idp)
        .await;

    let view = world.session.sign_out().await;

    assert_eq!(view, signed_out(&world, None));
    assert_eq!(world.stored_refresh(), None);
    assert_eq!(world.requests(&world.idp, "/revoke").await.len(), 1);
    assert!(item_was_gone.load(Ordering::SeqCst));
    assert_eq!(world.call_things().await, Err(CallError::SignedOut));
}

#[tokio::test]
async fn sign_out_deletes_the_item_and_then_revokes_the_refresh_token() {
    sign_out_with_revocation(200).await;
}

#[tokio::test]
async fn a_failing_revocation_does_not_stop_the_sign_out() {
    sign_out_with_revocation(500).await;
}

#[tokio::test]
async fn signing_out_when_nothing_is_stored_is_harmless() {
    let world = World::at_address().await;
    assert_eq!(world.session.sign_out().await, signed_out(&world, None));
}

#[tokio::test]
async fn changing_the_address_signs_out_of_the_old_one() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    let other = MockServer::start().await;

    let result = world.session.connect(&other.uri()).await;

    assert!(result.is_err());
    assert_eq!(world.stored_refresh(), None);
    assert_eq!(world.requests(&world.idp, "/revoke").await.len(), 1);
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { .. }
    ));
    assert_eq!(
        world.settings.connection().address,
        Some(IlmUrl::for_tests(&other.uri()))
    );
}

#[tokio::test]
async fn a_sign_in_without_a_refresh_token_replaces_the_saved_one() {
    let world = World::new().await;
    world.put_item("of-someone-else");
    world.code_grant("a1", None, 3600).await;
    world.profile_for("a1").await;

    assert!(is_signed_in(&world.sign_in().await));

    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_browser_sign_in_forgets_the_remembered_certificate() {
    let world = World::new().await;
    world.settings.connection.lock().unwrap().certificate = Some(Fingerprint::of(b"earlier"));
    world.code_grant("a1", None, 3600).await;
    world.profile_for("a1").await;

    assert!(is_signed_in(&world.sign_in().await));

    assert_eq!(world.settings.connection().certificate, None);
}

#[tokio::test]
async fn a_rotated_refresh_token_the_store_cannot_save_is_used_from_memory() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world.profile_for("a1").await;
    for (refresh, access, rotated) in [("r1", "a2", "r2"), ("r2", "a3", "r3")] {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(format!("refresh_token={refresh}")))
            .respond_with(tokens(access, Some(rotated), 30))
            .mount(&world.idp)
            .await;
    }
    world.serve_things(Some("a2")).await;
    world.serve_things(Some("a3")).await;
    world.sign_in().await;
    world.store.broken.store(true, Ordering::SeqCst);

    assert_eq!(world.call_things().await, Ok(200));
    assert_eq!(world.call_things().await, Ok(200));

    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
    assert!(is_signed_in(&world.session.view()));
}

#[tokio::test]
async fn a_sign_out_that_cannot_delete_the_saved_item_says_so() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    world.store.broken.store(true, Ordering::SeqCst);

    let view = world.session.sign_out().await;

    assert!(
        matches!(&view, SessionView::SignedOut { problem: Some(p), .. } if p.contains("could not be removed")),
        "{view:?}"
    );
    assert_eq!(world.requests(&world.idp, "/revoke").await.len(), 1);
}

#[tokio::test]
async fn sign_out_revokes_a_saved_item_of_another_provider_at_that_provider() {
    let world = World::new().await;
    let other = MockServer::start().await;
    let issuer = other.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "revocation_endpoint": format!("{issuer}/revoke"),
        })))
        .mount(&other)
        .await;
    Mock::given(method("POST"))
        .and(path("/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&other)
        .await;
    world
        .store
        .save(&Item {
            ilm: world.address(),
            issuer: issuer.clone(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("theirs"),
        })
        .unwrap();
    world.code_grant("a1", None, 3600).await;
    world.profile_for("a1").await;
    world.store.broken.store(true, Ordering::SeqCst);
    assert!(is_signed_in(&world.sign_in().await));
    world.store.broken.store(false, Ordering::SeqCst);

    world.session.sign_out().await;

    assert!(world.requests(&world.idp, "/revoke").await.is_empty());
    assert_eq!(world.requests(&other, "/revoke").await.len(), 1);
}

#[tokio::test]
async fn a_provider_keeps_its_id_after_an_attempt_with_it() {
    let world = World::publishing(&[("A", Some("a")), ("B", Some("b"))]).await;
    world.session.connect(&world.ilm.uri()).await.unwrap();

    for _ in 0..2 {
        let (_, candidate) = world.session.candidate("0").unwrap();
        assert_eq!(candidate.client_id.as_str(), "a");
    }
}

#[tokio::test]
async fn a_token_is_given_only_for_the_ilm_signed_in_to() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;

    let other = IlmUrl::for_tests("http://127.0.0.1:1");

    assert_eq!(
        world.session.usable_token(&other, None).await,
        Err(CallError::SignedOut)
    );
}

#[tokio::test]
async fn a_saved_item_of_another_provider_is_never_sent_for_renewal() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    world
        .store
        .save(&Item {
            ilm: world.address(),
            issuer: "http://127.0.0.1:1".into(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("theirs"),
        })
        .unwrap();

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 1);
}

#[tokio::test]
async fn a_sign_in_without_a_refresh_token_never_renews_with_an_older_saved_one() {
    let world = World::new().await;
    world.put_item("of-someone-else");
    world.code_grant("a1", None, 0).await;
    world.profile_for("a1").await;
    world.store.broken.store(true, Ordering::SeqCst);
    world.sign_in().await;
    world.store.broken.store(false, Ordering::SeqCst);

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 1);
}

#[tokio::test]
async fn a_late_failure_of_a_cancelled_attempt_leaves_a_newer_sign_in_alone() {
    let world = World::new().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(invalid_grant().set_delay(Duration::from_millis(300)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&world.idp)
        .await;
    world.code_grant("a2", Some("r2"), 3600).await;
    world.profile_for("a2").await;
    world.session.connect(&world.ilm.uri()).await.unwrap();
    let session = &world.session;

    let (late, newer) = tokio::join!(session.sign_in("0", browser("first")), async {
        while world.requests(&world.idp, "/token").await.is_empty() {
            tokio::task::yield_now().await;
        }
        session.cancel();
        session.sign_in("0", browser("second")).await
    });

    assert!(is_signed_in(&newer));
    assert!(is_signed_in(&late));
    assert!(is_signed_in(&world.session.view()));
}

#[tokio::test]
async fn a_new_address_is_saved_before_the_signed_out_view_is_told_and_its_failure_shows_there() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    let other = MockServer::start().await;

    let answer = world.session.connect(&other.uri()).await;

    let views = world.views.lock().unwrap().clone();
    let [.., signed_out, failed] = views.as_slice() else {
        panic!("{views:?}");
    };
    assert!(
        matches!(signed_out, SessionView::SignedOut { address: Some(address), problem: None, .. } if *address == other.uri()),
        "{signed_out:?}"
    );
    assert_eq!(
        *failed,
        SessionView::SignedOut {
            address: Some(other.uri()),
            locked: false,
            problem: answer.err(),
            again: false,
        }
    );
}

#[tokio::test]
async fn a_cancelled_attempt_that_ends_late_leaves_a_newer_sign_in_alone() {
    let world = World::new().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(tokens("a1", Some("r1"), 3600).set_delay(Duration::from_millis(300)))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&world.idp)
        .await;
    world.code_grant("a2", Some("r2"), 3600).await;
    world.profile_for("a1").await;
    world.profile_for("a2").await;
    world.session.connect(&world.ilm.uri()).await.unwrap();
    let session = &world.session;

    let (_, newer) = tokio::join!(session.sign_in("0", browser("first")), async {
        while world.requests(&world.idp, "/token").await.is_empty() {
            tokio::task::yield_now().await;
        }
        session.cancel();
        session.sign_in("0", browser("second")).await
    });

    assert!(is_signed_in(&newer));
    assert!(is_signed_in(&world.session.view()));
    assert_eq!(world.stored_refresh().as_deref(), Some("r2"));
}

/// Ends the sign-in with `end` once the code is being exchanged, before ILM has answered.
async fn end_during_the_exchange(end: impl AsyncFnOnce(&Session)) {
    let world = World::new().await;
    world
        .grant(
            "authorization_code",
            tokens("a1", Some("r1"), 3600).set_delay(Duration::from_millis(300)),
            None,
        )
        .await;
    world.profile_for("a1").await;
    world.session.connect(&world.ilm.uri()).await.unwrap();

    let (view, ()) = tokio::join!(world.session.sign_in("0", browser("the-code")), async {
        while world.requests(&world.idp, "/token").await.is_empty() {
            tokio::task::yield_now().await;
        }
        end(&world.session).await;
    });

    assert_eq!(view, signed_out(&world, None));
    assert_eq!(world.session.view(), signed_out(&world, None));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_sign_in_cancelled_during_the_exchange_is_not_kept() {
    end_during_the_exchange(async |session| session.cancel()).await;
}

#[tokio::test]
async fn a_sign_out_during_the_exchange_is_not_undone() {
    end_during_the_exchange(async |session| {
        session.sign_out().await;
    })
    .await;
}

pub(crate) static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if record.target().starts_with("im_core") {
            LOG.lock()
                .unwrap()
                .push(format!("{}: {}", record.level(), record.args()));
        }
    }

    fn flush(&self) {}
}

pub(crate) fn capture_logs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        log::set_logger(&Capture).unwrap();
        log::set_max_level(LevelFilter::Trace);
    });
}

#[tokio::test]
async fn the_log_of_a_full_flow_holds_no_secret() {
    capture_logs();
    let world = World::new().await;
    world
        .code_grant("ACCESS-SECRET-1", Some("REFRESH-SECRET-1"), 30)
        .await;
    world
        .grant(
            "refresh_token",
            tokens("ACCESS-SECRET-2", Some("REFRESH-SECRET-2"), 3600),
            None,
        )
        .await;
    world.profile_for("ACCESS-SECRET-1").await;
    world.serve_things(Some("ACCESS-SECRET-2")).await;
    world.session.connect(&world.ilm.uri()).await.unwrap();
    let state = Arc::new(Mutex::new(String::new()));
    let seen = state.clone();
    let open = browser("CODE-SECRET");
    world
        .session
        .sign_in("0", move |url| {
            *seen.lock().unwrap() = url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1
                .into_owned();
            open(url);
        })
        .await;
    world.call_things().await.unwrap();
    world.session.sign_out().await;

    let verifier = world
        .requests(&world.idp, "/token")
        .await
        .iter()
        .find_map(|request| {
            request
                .url
                .query_pairs()
                .chain(url::form_urlencoded::parse(&request.body))
                .find(|(key, _)| key == "code_verifier")
                .map(|(_, value)| value.into_owned())
        })
        .expect("the exchange sent a verifier");
    let state = state.lock().unwrap().clone();
    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("signed in"), "the flow logs what it does");
    for (index, secret) in [
        "ACCESS-SECRET-1",
        "ACCESS-SECRET-2",
        "REFRESH-SECRET-1",
        "REFRESH-SECRET-2",
        "CODE-SECRET",
        verifier.as_str(),
        state.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(!secret.is_empty());
        assert!(!log.contains(secret), "the log holds secret number {index}");
    }
}

impl World {
    /// ILM answers the profile of the token `access` with `listings`, ahead of the profile of `profile_for`.
    async fn listings_for(&self, access: &str, listings: &[&str]) {
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .and(header("authorization", format!("Bearer {access}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-1",
                "username": "jdoe",
                "firstName": "Jane",
                "lastName": "Doe",
                "permissions": {"allowedListings": listings, "allowedActions": []},
            })))
            .with_priority(1)
            .mount(&self.ilm)
            .await;
    }

    fn ended(&self, problem: &str) -> SessionView {
        SessionView::SignedOut {
            address: Some(self.ilm.uri()),
            locked: false,
            problem: Some(problem.to_owned()),
            again: true,
        }
    }

    fn unreachable_view(&self) -> bool {
        matches!(
            self.session.view(),
            SessionView::SignedIn {
                unreachable: true,
                ..
            }
        )
    }
}

#[test]
fn the_views_of_a_locked_unreachable_and_ended_session_have_their_shapes() {
    let shape = |view: SessionView| serde_json::to_value(view).unwrap();

    assert_eq!(shape(SessionView::Locked {}), json!({"state": "locked"}));
    assert_eq!(
        shape(SessionView::Unreachable {
            address: "https://ilm.example.com".into(),
            problem: "ILM cannot be reached.".into(),
        }),
        json!({
            "state": "unreachable",
            "address": "https://ilm.example.com",
            "problem": "ILM cannot be reached.",
        })
    );
    assert_eq!(
        shape(SessionView::SignedOut {
            address: None,
            locked: false,
            problem: None,
            again: true,
        }),
        json!({"state": "signedOut", "address": null, "locked": false, "problem": null, "again": true})
    );
    assert_eq!(
        shape(SessionView::SignedIn {
            address: "a".into(),
            person: PersonView {
                name: "n".into(),
                username: "u".into()
            },
            allowed_listings: vec![],
            certificate: None,
            unreachable: true,
        })["unreachable"],
        json!(true)
    );
}

#[tokio::test]
async fn a_check_reads_the_profile_again_and_updates_the_listings() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    world.listings_for("a1", &["certificates", "keys"]).await;

    let view = world.session.check().await;

    assert!(matches!(
        &view,
        SessionView::SignedIn { allowed_listings, unreachable: false, .. }
            if allowed_listings == &["certificates", "keys"]
    ));
    assert_eq!(world.views.lock().unwrap().last(), Some(&view));
}

#[tokio::test]
async fn a_check_that_changes_nothing_tells_nobody() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    let told = world.views.lock().unwrap().len();

    world.session.check().await;

    assert_eq!(world.views.lock().unwrap().len(), told);
}

#[tokio::test]
async fn a_check_while_not_signed_in_does_nothing() {
    let world = World::at_address().await;

    assert_eq!(world.session.check().await, SessionView::Starting);
}

#[tokio::test]
async fn a_check_that_cannot_reach_a_service_flags_the_sign_in_and_the_next_one_clears_it() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.profile_for("a2").await;
    world.sign_in().await;

    world.session.check().await;
    assert!(world.unreachable_view());
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));

    world.session.check().await;
    assert!(!world.unreachable_view());
    assert!(is_signed_in(&world.session.view()));
}

#[tokio::test]
async fn a_check_that_gets_no_useful_answer_from_ilm_flags_the_sign_in() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .respond_with(ResponseTemplate::new(502))
        .with_priority(1)
        .mount(&world.ilm)
        .await;

    world.session.check().await;

    assert!(world.unreachable_view());
}

#[tokio::test]
async fn a_check_that_ilm_refuses_ends_the_sign_in_with_a_way_to_repeat_it() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&world.ilm)
        .await;

    let view = world.session.check().await;

    assert_eq!(view, world.ended("ILM did not accept the sign-in."));
    assert_eq!(world.session.check().await, view);
}

#[tokio::test]
async fn a_check_whose_renewal_is_refused_ends_the_sign_in_with_a_way_to_repeat_it() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 30).await;
    world.grant("refresh_token", invalid_grant(), None).await;
    world.profile_for("a1").await;
    world.sign_in().await;

    let view = world.session.check().await;

    assert_eq!(view, world.ended(SIGN_IN_ENDED));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_check_after_the_last_token_ended_ends_the_sign_in_with_a_way_to_repeat_it() {
    let world = World::new().await;
    world.code_grant("a1", None, 0).await;
    world.profile_for("a1").await;
    world.sign_in().await;

    assert_eq!(world.session.check().await, world.ended(SIGN_IN_ENDED));
}

#[tokio::test]
async fn a_start_refused_by_the_provider_or_by_ilm_can_be_repeated() {
    let world = World::at_address().await;
    world.put_item("r1");
    world.grant("refresh_token", invalid_grant(), None).await;
    assert_eq!(world.session.start().await, world.ended(SIGN_IN_ENDED));

    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", tokens("a-unknown", Some("r1"), 3600), None)
        .await;
    assert_eq!(
        world.session.start().await,
        world.ended("ILM did not accept the sign-in.")
    );
}

#[tokio::test]
async fn a_start_that_cannot_reach_ilm_keeps_the_item_and_retries_to_signed_in() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", tokens("a1", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.settings.connection.lock().unwrap().address =
        Some(IlmUrl::for_tests("http://127.0.0.1:1"));
    world
        .store
        .save(&Item {
            ilm: IlmUrl::for_tests("http://127.0.0.1:1"),
            issuer: world.idp.uri(),
            client_id: "app".into(),
            resource: None,
            refresh_token: RefreshToken::new("r1"),
        })
        .unwrap();

    let view = world.session.start().await;

    assert!(
        matches!(&view, SessionView::Unreachable { address, problem }
            if address.contains("127.0.0.1:1") && problem == "ILM cannot be reached."),
    );
    assert_eq!(world.session.retry().await, view);

    *world.settings.connection.lock().unwrap() = Connection {
        address: Some(world.address()),
        ..Connection::default()
    };
    world.put_item("r1");
    assert!(is_signed_in(&world.session.retry().await));
}

#[tokio::test]
async fn a_retry_signs_in_once_the_provider_answers_and_keeps_the_saved_item() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world
        .grant("refresh_token", tokens("a1", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    assert!(matches!(
        world.session.start().await,
        SessionView::Unreachable { .. }
    ));

    let view = world.session.retry().await;

    assert!(is_signed_in(&view));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
}

#[tokio::test]
async fn a_retry_that_the_provider_refuses_ends_the_sign_in_with_a_way_to_repeat_it() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world.grant("refresh_token", invalid_grant(), None).await;
    world.session.start().await;

    assert_eq!(world.session.retry().await, world.ended(SIGN_IN_ENDED));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_retry_outside_the_unreachable_state_changes_nothing() {
    let world = World::at_address().await;
    world.session.start().await;
    let told = world.views.lock().unwrap().len();

    assert_eq!(world.session.retry().await, signed_out(&world, None));
    assert_eq!(world.views.lock().unwrap().len(), told);
}

async fn ended_by_a_refused_renewal() -> World {
    let world = World::at_address().await;
    world.put_item("r1");
    world.grant("refresh_token", invalid_grant(), None).await;
    world.session.start().await;
    world
}

#[tokio::test]
async fn signing_in_again_starts_the_browser_flow_with_the_provider_of_the_ended_sign_in() {
    let world = ended_by_a_refused_renewal().await;
    world.code_grant("a2", Some("r2"), 3600).await;
    world.profile_for("a2").await;

    let again = world.session.sign_in_again(browser("the-code")).await;

    assert!(
        matches!(&again, SignInAgain::View(view) if is_signed_in(view)),
        "{again:?}"
    );
    assert_eq!(world.stored_refresh().as_deref(), Some("r2"));
}

#[tokio::test]
async fn signing_in_again_goes_to_the_choice_when_the_provider_is_gone() {
    let world = ended_by_a_refused_renewal().await;
    *lock(&world.session.state) = State::SignedOut {
        problem: None,
        again: Some(Again::Provider("https://gone.example.com".into())),
    };

    let again = world.session.sign_in_again(browser("the-code")).await;

    assert_eq!(
        again,
        SignInAgain::Choose(vec![ProviderChoice {
            id: "0".into(),
            name: "Corporate".into()
        }])
    );
    assert!(world.requests(&world.idp, "/auth").await.is_empty());
}

#[tokio::test]
async fn signing_in_again_does_nothing_unless_a_sign_in_ended() {
    let world = World::at_address().await;
    world.session.start().await;

    let again = world.session.sign_in_again(browser("the-code")).await;

    assert_eq!(again, SignInAgain::View(signed_out(&world, None)));
}

#[tokio::test]
async fn signing_in_again_says_so_when_the_ilm_publishes_nothing_or_has_no_address() {
    let world = ended_by_a_refused_renewal().await;
    world.ilm.reset().await;
    let again = world.session.sign_in_again(browser("the-code")).await;
    assert!(matches!(
        &again,
        SignInAgain::View(SessionView::SignedOut {
            problem: Some(_),
            again: false,
            ..
        })
    ));

    let world = World::new().await;
    *lock(&world.session.state) = State::SignedOut {
        problem: None,
        again: Some(Again::Certificate),
    };
    let again = world.session.sign_in_again(browser("the-code")).await;
    assert!(matches!(
        &again,
        SignInAgain::View(SessionView::SignedOut { problem: Some(p), .. }) if p == CONNECT_FIRST
    ));
}

#[tokio::test]
async fn signing_out_and_changing_the_address_forget_how_to_sign_in_again() {
    let world = ended_by_a_refused_renewal().await;
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { again: true, .. }
    ));
    assert_eq!(world.session.sign_out().await, signed_out(&world, None));

    let world = ended_by_a_refused_renewal().await;
    let other = MockServer::start().await;
    assert!(world.session.connect(&other.uri()).await.is_err());
    assert!(matches!(
        world.session.view(),
        SessionView::SignedOut { again: false, .. }
    ));
}

/// The profile of a person other than `jdoe`.
fn profile_of(username: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "uuid": "u-1",
        "username": username,
        "firstName": "Other",
        "lastName": "Person",
        "permissions": {"allowedListings": ["keys"], "allowedActions": []},
    }))
}

#[tokio::test]
async fn two_retries_at_once_renew_the_saved_sign_in_once() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world
        .grant(
            "refresh_token",
            tokens("a1", Some("r2"), 3600).set_delay(std::time::Duration::from_millis(200)),
            None,
        )
        .await;
    world.profile_for("a1").await;
    assert!(matches!(
        world.session.start().await,
        SessionView::Unreachable { .. }
    ));

    let (first, second) = tokio::join!(world.session.retry(), world.session.retry());

    assert!(is_signed_in(&first), "{first:?}");
    assert_eq!(first, second);
    assert_eq!(world.requests(&world.idp, "/token").await.len(), 2);
    assert!(world.stored_refresh().is_some());
}

#[tokio::test]
async fn a_start_that_gets_no_useful_answer_from_ilm_keeps_the_item_and_retries_to_signed_in() {
    for failure in [
        ResponseTemplate::new(502),
        ResponseTemplate::new(200).set_body_string("not a profile"),
    ] {
        let world = World::at_address().await;
        world.put_item("r1");
        world
            .grant("refresh_token", tokens("a1", Some("r1"), 3600), None)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .respond_with(failure)
            .with_priority(1)
            .up_to_n_times(1)
            .mount(&world.ilm)
            .await;
        world.profile_for("a1").await;

        let view = world.session.start().await;

        assert!(matches!(view, SessionView::Unreachable { .. }));
        assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
        assert!(is_signed_in(&world.session.retry().await));
    }
}

#[tokio::test]
async fn signing_in_again_does_nothing_when_the_sign_in_changed_while_ilm_was_asked() {
    let world = ended_by_a_refused_renewal().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "resource": world.api(""),
                    "authorization_servers": [world.idp.uri()],
                    "otilm_authorization_servers": [
                        {"issuer": world.idp.uri(), "name": "Corporate", "client_id": "app", "scopes": ["openid"]}
                    ],
                }))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .with_priority(1)
        .mount(&world.ilm)
        .await;
    let opened = AtomicBool::new(false);

    let (again, _) = tokio::join!(
        world
            .session
            .sign_in_again(|_| opened.store(true, Ordering::SeqCst)),
        async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            world.session.sign_out().await
        }
    );

    assert_eq!(again, SignInAgain::View(signed_out(&world, None)));
    assert!(!opened.load(Ordering::SeqCst));
}

/// A check of the person signed in first, whose answer comes only after that person signed out and another
/// signed in to the same ILM.
async fn late_answer_of_an_earlier_person(answer: ResponseTemplate) -> (World, SessionView) {
    let world = World::new().await;
    world
        .grant(
            "authorization_code",
            tokens("a1", Some("r1"), 3600),
            Some(1),
        )
        .await;
    world.code_grant("a2", Some("r2"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .and(header("authorization", "Bearer a1"))
        .respond_with(answer.set_delay(std::time::Duration::from_millis(600)))
        .with_priority(1)
        .mount(&world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .and(header("authorization", "Bearer a2"))
        .respond_with(profile_of("second"))
        .mount(&world.ilm)
        .await;

    let (_, signed_in) = tokio::join!(world.session.check(), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.sign_out().await;
        world.sign_in().await
    });
    assert!(is_signed_in(&signed_in), "{signed_in:?}");
    (world, signed_in)
}

#[tokio::test]
async fn a_late_profile_of_an_earlier_person_does_not_change_the_person_signed_in_since() {
    let (world, signed_in) = late_answer_of_an_earlier_person(profile_of("first")).await;

    assert_eq!(world.session.view(), signed_in);
    assert!(matches!(
        signed_in,
        SessionView::SignedIn { person, .. } if person.username == "second"
    ));
}

#[tokio::test]
async fn a_late_refusal_of_an_earlier_sign_in_does_not_end_the_sign_in_made_since() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    let earlier = Arc::new(());
    let current = match &*lock(&world.session.state) {
        State::SignedIn(active) => active.id.clone(),
        _ => panic!("signed in"),
    };

    world
        .session
        .end_active(&earlier, "ILM did not accept the sign-in.")
        .await;
    assert!(is_signed_in(&world.session.view()));

    world
        .session
        .end_active(&current, "ILM did not accept the sign-in.")
        .await;
    assert_eq!(
        world.session.view(),
        world.ended("ILM did not accept the sign-in.")
    );
}

#[tokio::test]
async fn a_retry_after_a_401_is_not_sent_as_a_sign_in_made_meanwhile() {
    let world = World::new().await;
    world
        .grant(
            "authorization_code",
            tokens("a1", Some("r1"), 3600),
            Some(1),
        )
        .await;
    world.code_grant("a2", Some("r2"), 3600).await;
    world.profile_for("a1").await;
    world.profile_for("a2").await;
    world.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/things"))
        .and(header("authorization", "Bearer a1"))
        .respond_with(ResponseTemplate::new(401).set_delay(std::time::Duration::from_millis(500)))
        .mount(&world.ilm)
        .await;
    world.serve_things(Some("a2")).await;

    let (called, _) = tokio::join!(world.call_things(), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.sign_out().await;
        world.sign_in().await;
    });

    assert_eq!(called, Err(CallError::SignedOut));
    assert!(
        world
            .requests(&world.ilm, "/api/v1/things")
            .await
            .iter()
            .all(|request| request.headers.get("authorization").unwrap() == "Bearer a1")
    );
    assert!(is_signed_in(&world.session.view()));
}

#[tokio::test]
async fn a_slow_offer_for_an_address_that_changed_leaves_the_newer_providers_in_place() {
    let world = ended_by_a_refused_renewal().await;
    let other = World::new().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/api"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "resource": world.api(""),
                    "authorization_servers": [world.idp.uri()],
                    "otilm_authorization_servers": [
                        {"issuer": world.idp.uri(), "name": "Corporate", "client_id": "app", "scopes": ["openid"]}
                    ],
                }))
                .set_delay(std::time::Duration::from_millis(300)),
        )
        .with_priority(1)
        .mount(&world.ilm)
        .await;

    let (_, connected) = tokio::join!(world.session.sign_in_again(|_| ()), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.connect(&other.ilm.uri()).await
    });

    assert!(connected.is_ok(), "{connected:?}");
    let (chosen, _) = world.session.candidate("0").expect("a provider is offered");
    assert_eq!(chosen, other.address());
}

#[tokio::test]
async fn a_slow_offer_that_fails_after_the_sign_in_changed_sets_no_problem() {
    let world = ended_by_a_refused_renewal().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/api"))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(300)))
        .with_priority(1)
        .mount(&world.ilm)
        .await;

    let (again, _) = tokio::join!(world.session.sign_in_again(|_| ()), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.sign_out().await
    });

    assert_eq!(again, SignInAgain::View(signed_out(&world, None)));
    assert_eq!(world.session.view(), signed_out(&world, None));
}

#[tokio::test]
async fn a_slow_connect_that_fails_after_another_address_was_signed_in_leaves_that_sign_in_alone() {
    let world = World::at_address().await;
    let slow = World::new().await;
    let newer = World::new().await;
    newer.code_grant("a1", Some("r1"), 3600).await;
    newer.profile_for("a1").await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/api"))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(400)))
        .with_priority(1)
        .mount(&slow.ilm)
        .await;

    let (slow_address, newer_address) = (slow.ilm.uri(), newer.ilm.uri());
    let (slow_connect, _) = tokio::join!(world.session.connect(&slow_address), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.connect(&newer_address).await.unwrap();
        world.session.sign_in("0", browser("the-code")).await
    });

    assert!(slow_connect.is_err());
    assert!(
        is_signed_in(&world.session.view()),
        "{:?}",
        world.session.view()
    );
}

#[tokio::test]
async fn a_slow_connect_that_fails_after_a_second_connect_signed_in_leaves_that_sign_in_alone() {
    let world = World::at_address().await;
    let target = World::new().await;
    target.code_grant("a1", Some("r1"), 3600).await;
    target.profile_for("a1").await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-protected-resource/api"))
        .respond_with(ResponseTemplate::new(500).set_delay(std::time::Duration::from_millis(400)))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&target.ilm)
        .await;
    let address = target.ilm.uri();

    let (first, _) = tokio::join!(world.session.connect(&address), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.connect(&address).await.unwrap();
        world.session.sign_in("0", browser("the-code")).await
    });

    assert!(first.is_err());
    assert!(
        is_signed_in(&world.session.view()),
        "{:?}",
        world.session.view()
    );
}

#[tokio::test]
async fn a_check_that_ilm_refuses_removes_the_saved_sign_in_so_a_restart_does_not_restore_it() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world
        .grant("refresh_token", tokens("a2", Some("r1"), 3600), None)
        .await;
    world.profile_for("a1").await;
    world.sign_in().await;
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&world.ilm)
        .await;

    let view = world.session.check().await;

    assert_eq!(view, world.ended("ILM did not accept the sign-in."));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn signing_out_while_the_saved_sign_in_waits_for_ilm_removes_it() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), None)
        .await;
    assert!(matches!(
        world.session.start().await,
        SessionView::Unreachable { .. }
    ));

    let view = world.session.sign_out().await;

    assert_eq!(view, signed_out(&world, None));
    assert_eq!(world.stored_refresh(), None);
}

#[tokio::test]
async fn a_sign_out_during_a_retry_leaves_nothing_stored() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), Some(1))
        .await;
    world
        .grant(
            "refresh_token",
            tokens("a1", Some("r2"), 3600).set_delay(std::time::Duration::from_millis(400)),
            None,
        )
        .await;
    world.profile_for("a1").await;
    assert!(matches!(
        world.session.start().await,
        SessionView::Unreachable { .. }
    ));

    tokio::join!(world.session.retry(), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.sign_out().await
    });

    assert_eq!(world.stored_refresh(), None);
    assert_eq!(world.session.view(), signed_out(&world, None));
}

#[tokio::test]
async fn a_restore_that_finishes_after_a_replacement_sign_in_leaves_its_saved_sign_in_alone() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant(
            "refresh_token",
            tokens("a1", Some("r1"), 3600).set_delay(std::time::Duration::from_millis(400)),
            None,
        )
        .await;
    world.code_grant("a2", Some("r-new"), 3600).await;
    world.profile_for("a1").await;
    world.profile_for("a2").await;

    tokio::join!(world.session.start(), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.sign_in().await
    });

    assert!(is_signed_in(&world.session.view()));
    assert_eq!(world.stored_refresh().as_deref(), Some("r-new"));
}

#[tokio::test]
async fn a_slower_older_check_does_not_overwrite_a_newer_answer() {
    let world = World::new().await;
    world.code_grant("a1", Some("r1"), 3600).await;
    world.profile_for("a1").await;
    world.sign_in().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .respond_with(profile_of("older").set_delay(std::time::Duration::from_millis(400)))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&world.ilm)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/profile"))
        .respond_with(profile_of("newer"))
        .with_priority(2)
        .mount(&world.ilm)
        .await;

    tokio::join!(world.session.check(), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        world.session.check().await
    });

    assert!(matches!(
        world.session.view(),
        SessionView::SignedIn { person, .. } if person.username == "newer"
    ));
}
