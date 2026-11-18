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

struct TestSettings(Mutex<Connection>);

impl ConnectionSettings for TestSettings {
    fn connection(&self) -> Connection {
        self.0.lock().unwrap().clone()
    }

    fn save_address(&self, address: &IlmUrl) -> Result<(), String> {
        self.0.lock().unwrap().address = Some(address.clone());
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

struct World {
    ilm: MockServer,
    idp: MockServer,
    store: Arc<TestStore>,
    settings: Arc<TestSettings>,
    views: Arc<Mutex<Vec<SessionView>>>,
    session: Session,
}

impl World {
    async fn new() -> Self {
        Self::publishing(&[("Corporate", Some("app"))]).await
    }

    async fn publishing(providers: &[(&str, Option<&str>)]) -> Self {
        let ilm = MockServer::start().await;
        let idp = MockServer::start().await;
        let store = Arc::new(TestStore::default());
        let settings = Arc::new(TestSettings(Mutex::new(Connection::default())));
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

    async fn at_address() -> Self {
        let world = Self::new().await;
        world.settings.0.lock().unwrap().address = Some(world.address());
        world
    }

    fn address(&self) -> IlmUrl {
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
                "scopes_supported": ["openid", "offline_access"],
            })))
            .mount(&self.idp)
            .await;
    }

    async fn profile_for(&self, access: &str) {
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .and(header("authorization", format!("Bearer {access}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "username": "jdoe",
                "firstName": "Jane",
                "lastName": "Doe",
                "permissions": {"allowedListings": ["certificates"], "allowedActions": []},
            })))
            .mount(&self.ilm)
            .await;
    }

    async fn grant(&self, kind: &str, response: ResponseTemplate, times: Option<u64>) {
        let mock = Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains(format!("grant_type={kind}")))
            .respond_with(response);
        match times {
            Some(times) => mock.up_to_n_times(times).mount(&self.idp).await,
            None => mock.mount(&self.idp).await,
        }
    }

    async fn code_grant(&self, access: &str, refresh: Option<&str>, expires_in: u64) {
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

    async fn sign_in(&self) -> SessionView {
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

    fn put_item(&self, refresh: &str) {
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

fn signed_out(world: &World, problem: Option<&str>) -> SessionView {
    SessionView::SignedOut {
        address: Some(world.ilm.uri()),
        locked: false,
        problem: problem.map(str::to_owned),
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

    world.settings.0.lock().unwrap().provider = Some("Second".into());
    let chosen = world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(chosen.len(), 1);
    assert_eq!(chosen[0].name, "Second");

    world.settings.0.lock().unwrap().provider = Some("Nobody".into());
    let unknown = world.session.connect(&world.ilm.uri()).await.unwrap();
    assert_eq!(unknown.len(), 2);
}

#[tokio::test]
async fn a_locked_address_is_used_whatever_is_typed() {
    let world = World::at_address().await;
    world.settings.0.lock().unwrap().locked = true;

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
    };
    assert_eq!(view, expected);
    assert_eq!(world.session.view(), expected);
    let views = world.views.lock().unwrap().clone();
    assert!(views.contains(&SessionView::SigningIn {
        provider: "Corporate".into()
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
async fn without_a_refresh_token_the_session_lasts_as_long_as_the_access_token() {
    let world = World::new().await;
    world.code_grant("a1", None, 30).await;
    world.profile_for("a1").await;
    world.serve_things(Some("a1")).await;

    assert!(is_signed_in(&world.sign_in().await));
    assert_eq!(world.stored_refresh(), None);

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
            problem: None
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
async fn a_start_that_cannot_reach_the_provider_keeps_the_item_and_says_so() {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), None)
        .await;

    let view = world.session.start().await;

    assert!(matches!(
        view,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
}

#[tokio::test]
async fn a_start_with_an_unreadable_provider_or_store_keeps_the_item_and_says_so() {
    let world = World::at_address().await;
    world.put_item("r1");
    world.idp.reset().await;

    let view = world.session.start().await;

    assert!(matches!(
        view,
        SessionView::SignedOut {
            problem: Some(_),
            ..
        }
    ));
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
}

#[tokio::test]
async fn a_start_whose_profile_is_refused_is_signed_out_with_the_item_kept() {
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
    assert_eq!(world.stored_refresh().as_deref(), Some("r1"));
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
    world.code_grant("a1", None, 30).await;
    world.profile_for("a1").await;
    world.store.broken.store(true, Ordering::SeqCst);
    world.sign_in().await;
    world.store.broken.store(false, Ordering::SeqCst);

    assert_eq!(world.call_things().await, Err(CallError::SignedOut));

    assert_eq!(world.requests(&world.idp, "/token").await.len(), 1);
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

static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

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

fn capture_logs() {
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
