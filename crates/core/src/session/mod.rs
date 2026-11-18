//! The sign-in of the person: connecting to an ILM, the browser flow, silent renewal and sign-out.

mod store;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use tokio::sync::Notify;
use url::Url;

use crate::ilm::profile::{Person, profile};
use crate::ilm::resource::{PublishedProvider, discover};
use crate::ilm::{AddressError, IlmUrl};
use crate::oauth::client::{ClientId, client_identity};
use crate::oauth::loopback::{AuthorizationRequest, FLOW_TIMEOUT, wait_for_code};
use crate::oauth::metadata::{ProviderMetadata, provider_metadata};
use crate::oauth::token::{TokenError, Tokens, exchange, refresh, revoke};
use crate::token::AccessToken;
pub use store::{Item, KeyringStore, MemoryStore, RefreshStore, StoreError};

/// An access token that expires sooner than this is renewed before it is used.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

const NO_PROVIDER: &str = "This ILM offers no identity provider that this application can use.";
const SIGN_IN_ENDED: &str = "Your sign-in has ended. Sign in again.";
const CONNECT_FIRST: &str = "Enter the address of your ILM first.";

/// What the session needs to know about the connection, from the settings of the person and of the
/// organization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connection {
    pub address: Option<IlmUrl>,
    /// Policy fixes the address.
    pub locked: bool,
    /// The name of the provider policy asks for.
    pub provider: Option<String>,
}

pub trait ConnectionSettings: Send + Sync {
    fn connection(&self) -> Connection;
    fn save_address(&self, address: &IlmUrl) -> Result<(), String>;
}

/// An identity provider the person can sign in with. The id is only meaningful to the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct ProviderChoice {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct PersonView {
    pub name: String,
    pub username: String,
}

/// What the interface shows. It never holds a token, a code or an address of the identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(
        export,
        tag = "state",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum SessionView {
    Starting,
    SignedOut {
        address: Option<String>,
        locked: bool,
        problem: Option<String>,
    },
    SigningIn {
        provider: String,
    },
    SignedIn {
        address: String,
        person: PersonView,
        allowed_listings: Vec<String>,
    },
}

/// Why a call to ILM was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    SignedOut,
    Unreachable,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CallError::SignedOut => "You are not signed in.",
            CallError::Unreachable => "ILM or the identity provider cannot be reached.",
        })
    }
}

impl std::error::Error for CallError {}

#[derive(Clone)]
struct Candidate {
    published: PublishedProvider,
    metadata: ProviderMetadata,
    client_id: ClientId,
}

struct Pending {
    ilm: IlmUrl,
    candidates: Vec<Candidate>,
}

/// Where the tokens of a new sign-in come from.
enum Origin {
    /// The saved refresh token, renewed at start.
    Saved,
    /// The browser flow `attempt`; its refresh token, or none, replaces the saved one.
    Browser {
        attempt: Arc<Notify>,
        item: Option<Item>,
    },
}

impl Origin {
    fn attempt(&self) -> Option<&Arc<Notify>> {
        match self {
            Origin::Saved => None,
            Origin::Browser { attempt, .. } => Some(attempt),
        }
    }
}

/// What a sign-in with one provider rests on.
#[derive(Clone)]
struct Grant {
    metadata: ProviderMetadata,
    client_id: ClientId,
    resource: Option<String>,
}

struct Active {
    ilm: IlmUrl,
    person: Person,
    access: AccessToken,
    expires_at: Instant,
    grant: Grant,
    /// Whether a refresh token belongs to this sign-in; without one it ends with the access token.
    refreshable: bool,
}

enum State {
    Starting,
    SignedOut {
        problem: Option<String>,
    },
    SigningIn {
        provider: String,
        url: Url,
        cancel: Arc<Notify>,
    },
    SignedIn(Box<Active>),
}

/// The sign-in of the person. The access token lives here, in memory; the refresh token only in the store.
pub struct Session {
    client: Client,
    settings: Arc<dyn ConnectionSettings>,
    store: Arc<dyn RefreshStore>,
    on_change: Box<dyn Fn(&SessionView) + Send + Sync>,
    state: Mutex<State>,
    pending: Mutex<Option<Pending>>,
    /// Held while the saved refresh token or the signed-in state changes, so those changes do not interleave.
    renewing: tokio::sync::Mutex<()>,
    /// The latest refresh token when the store could not save it.
    unsaved: Mutex<Option<Item>>,
}

/// Whether the browser sign-in `attempt`, or with none the renewal at start, is still the one under way.
fn is_current(state: &State, attempt: Option<&Arc<Notify>>) -> bool {
    match (state, attempt) {
        (State::Starting, None) => true,
        (State::SigningIn { cancel, .. }, Some(attempt)) => Arc::ptr_eq(cancel, attempt),
        _ => false,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn parse_address(text: &str) -> Result<IlmUrl, AddressError> {
    #[cfg(test)]
    if text.starts_with("http://127.0.0.1") {
        return Ok(IlmUrl::for_tests(text.trim()));
    }
    IlmUrl::parse(text)
}

impl Session {
    /// `on_change` runs after every change of the view, so the application can tell its windows.
    pub fn new(
        client: Client,
        settings: Arc<dyn ConnectionSettings>,
        store: Arc<dyn RefreshStore>,
        on_change: impl Fn(&SessionView) + Send + Sync + 'static,
    ) -> Self {
        Self {
            client,
            settings,
            store,
            on_change: Box::new(on_change),
            state: Mutex::new(State::Starting),
            pending: Mutex::new(None),
            renewing: tokio::sync::Mutex::new(()),
            unsaved: Mutex::new(None),
        }
    }

    pub fn view(&self) -> SessionView {
        let connection = self.settings.connection();
        match &*lock(&self.state) {
            State::Starting => SessionView::Starting,
            State::SignedOut { problem } => SessionView::SignedOut {
                address: connection.address.map(|address| address.to_string()),
                locked: connection.locked,
                problem: problem.clone(),
            },
            State::SigningIn { provider, .. } => SessionView::SigningIn {
                provider: provider.clone(),
            },
            State::SignedIn(active) => SessionView::SignedIn {
                address: active.ilm.to_string(),
                person: PersonView {
                    name: active.person.display_name.clone(),
                    username: active.person.username.clone(),
                },
                allowed_listings: active.person.allowed_listings.clone(),
            },
        }
    }

    /// The address that is open in the browser while the person signs in, to open it again.
    pub fn browser_url(&self) -> Option<Url> {
        match &*lock(&self.state) {
            State::SigningIn { url, .. } => Some(url.clone()),
            _ => None,
        }
    }

    fn set(&self, state: State) -> SessionView {
        *lock(&self.state) = state;
        self.publish()
    }

    fn publish(&self) -> SessionView {
        let view = self.view();
        (self.on_change)(&view);
        view
    }

    fn fail(&self, problem: impl Into<String>) -> SessionView {
        let problem = problem.into();
        log::warn!("{problem}");
        self.set(State::SignedOut {
            problem: Some(problem),
        })
    }

    /// Ends the sign-in `attempt` with `problem`, unless something else has ended it meanwhile.
    fn fail_attempt(
        &self,
        attempt: Option<&Arc<Notify>>,
        problem: impl Into<String>,
    ) -> SessionView {
        let problem = problem.into();
        log::warn!("{problem}");
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, attempt);
            if current {
                *state = State::SignedOut {
                    problem: Some(problem),
                };
            }
            current
        };
        if current { self.publish() } else { self.view() }
    }

    async fn in_store<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn RefreshStore) -> T + Send + 'static,
    ) -> T {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || work(store.as_ref()))
            .await
            .expect("the storage task does not panic")
    }

    async fn load_item(&self, ilm: &IlmUrl) -> Result<Option<Item>, StoreError> {
        if let Some(item) = lock(&self.unsaved).as_ref().filter(|item| item.ilm == *ilm) {
            return Ok(Some(item.clone()));
        }
        let ilm = ilm.clone();
        self.in_store(move |store| store.load(&ilm)).await
    }

    /// A refresh token the store cannot save is kept in memory, so the sign-in lasts until the application quits.
    async fn save_item(&self, item: Item) {
        let kept = item.clone();
        match self.in_store(move |store| store.save(&item)).await {
            Ok(()) => *lock(&self.unsaved) = None,
            Err(error) => {
                log::warn!(
                    "the sign-in could not be saved and lasts until the application quits: {error}"
                );
                *lock(&self.unsaved) = Some(kept);
            }
        }
    }

    async fn delete_item(&self, ilm: &IlmUrl) -> Result<(), StoreError> {
        lock(&self.unsaved).take_if(|item| item.ilm == *ilm);
        let ilm = ilm.clone();
        let result = self.in_store(move |store| store.delete(&ilm)).await;
        if let Err(error) = &result {
            log::warn!("the saved sign-in could not be deleted: {error}");
        }
        result
    }

    /// Signs in again from the saved refresh token, when there is one for the current address.
    pub async fn start(&self) -> SessionView {
        let Some(ilm) = self.settings.connection().address else {
            return self.set(State::SignedOut { problem: None });
        };
        let item = match self.load_item(&ilm).await {
            Ok(Some(item)) => item,
            Ok(None) => return self.set(State::SignedOut { problem: None }),
            Err(error) => {
                return self.fail(format!("Your saved sign-in could not be read: {error}"));
            }
        };
        log::info!("renewing the saved sign-in for {ilm}");
        let provider = match provider_metadata(&self.client, &item.issuer).await {
            Ok(metadata) => client_identity(Some(&item.client_id), &metadata)
                .map(|client_id| (metadata, client_id))
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        let (metadata, client_id) = match provider {
            Ok(provider) => provider,
            Err(error) => return self.fail(format!("Could not renew the sign-in: {error}.")),
        };
        let grant = Grant {
            metadata,
            client_id,
            resource: item.resource.clone(),
        };
        match self.renew_item(&item, &grant).await {
            Ok(tokens) => self.establish(ilm, tokens, grant, Origin::Saved).await,
            Err(TokenError::Refused) => self.fail(SIGN_IN_ENDED),
            Err(TokenError::Unreachable) => {
                self.fail("Could not renew the sign-in: the identity provider cannot be reached.")
            }
        }
    }

    /// Takes the ILM address, signs out of another ILM when it changes, and lists the providers to sign in with.
    pub async fn connect(&self, address: &str) -> Result<Vec<ProviderChoice>, String> {
        let connection = self.settings.connection();
        let ilm = match (&connection.address, connection.locked) {
            (Some(locked), true) => locked.clone(),
            _ => parse_address(address).map_err(|error| error.to_string())?,
        };
        if connection.address.as_ref() != Some(&ilm) {
            self.settings.save_address(&ilm)?;
            if connection.address.is_some() {
                self.sign_out_of(connection.address).await;
            }
        }
        let published = discover(&self.client, &ilm)
            .await
            .map_err(|error| error.to_string())?;
        let mut candidates = Vec::new();
        for provider in published.providers {
            let usable = provider_metadata(&self.client, &provider.issuer)
                .await
                .ok()
                .and_then(|metadata| {
                    client_identity(provider.client_id.as_deref(), &metadata)
                        .ok()
                        .map(|client_id| (metadata, client_id))
                });
            if let Some((metadata, client_id)) = usable {
                candidates.push(Candidate {
                    published: provider,
                    metadata,
                    client_id,
                });
            }
        }
        if candidates.is_empty() {
            return Err(NO_PROVIDER.to_owned());
        }
        if let Some(name) = &connection.provider {
            match candidates
                .iter()
                .position(|candidate| candidate.published.name == *name)
            {
                Some(chosen) => candidates = vec![candidates.swap_remove(chosen)],
                None => log::warn!("policy names the provider {name}, which {ilm} does not offer"),
            }
        }
        let choices = candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| ProviderChoice {
                id: index.to_string(),
                name: candidate.published.name.clone(),
            })
            .collect();
        *lock(&self.pending) = Some(Pending { ilm, candidates });
        Ok(choices)
    }

    /// Opens the browser through `open` and waits until the person has signed in, cancelled or run out of time.
    pub async fn sign_in(&self, provider_id: &str, open: impl Fn(&Url) + Send) -> SessionView {
        let Some((ilm, candidate)) = self.candidate(provider_id) else {
            return self.fail(CONNECT_FIRST);
        };
        let request = match AuthorizationRequest::new(
            &candidate.metadata,
            &candidate.client_id,
            &candidate.published,
        )
        .await
        {
            Ok(request) => request,
            Err(error) => return self.fail(error.to_string()),
        };
        let cancel = Arc::new(Notify::new());
        let name = candidate.published.name.clone();
        self.set(State::SigningIn {
            provider: name.clone(),
            url: request.url.clone(),
            cancel: cancel.clone(),
        });
        log::info!("sign-in with {name} started");
        open(&request.url);
        let issuer = candidate.metadata.issuer.as_str();
        let code = tokio::select! {
            code = wait_for_code(request.listener, &request.state, issuer, FLOW_TIMEOUT) => code,
            () = cancel.notified() => return self.view(),
        };
        let code = match code {
            Ok(code) => code,
            Err(error) => return self.fail_attempt(Some(&cancel), error.to_string()),
        };
        let resource = candidate.published.resource.clone();
        let tokens = match exchange(
            &self.client,
            &candidate.metadata,
            &candidate.client_id,
            &code,
            &request.verifier,
            &request.redirect_uri,
            resource.as_deref(),
        )
        .await
        {
            Ok(tokens) => tokens,
            Err(error) => {
                return self.fail_attempt(Some(&cancel), format!("Sign-in failed: {error}."));
            }
        };
        let item = tokens.refresh.as_ref().map(|refresh_token| Item {
            ilm: ilm.clone(),
            issuer: candidate.metadata.issuer.clone(),
            client_id: candidate.client_id.as_str().to_owned(),
            resource: resource.clone(),
            refresh_token: refresh_token.clone(),
        });
        if item.is_none() {
            log::info!(
                "the provider issued no refresh token; the sign-in lasts until the access token expires"
            );
        }
        let grant = Grant {
            metadata: candidate.metadata,
            client_id: candidate.client_id,
            resource,
        };
        self.establish(
            ilm,
            tokens,
            grant,
            Origin::Browser {
                attempt: cancel,
                item,
            },
        )
        .await
    }

    fn candidate(&self, id: &str) -> Option<(IlmUrl, Candidate)> {
        let pending = lock(&self.pending);
        let pending = pending.as_ref()?;
        let candidate = pending.candidates.get(id.parse::<usize>().ok()?)?;
        Some((pending.ilm.clone(), candidate.clone()))
    }

    /// Ends the sign-in in the browser; a sign-in that has already left the browser is not kept.
    pub fn cancel(&self) {
        {
            let mut state = lock(&self.state);
            let State::SigningIn { cancel, .. } = &*state else {
                return;
            };
            cancel.notify_one();
            *state = State::SignedOut { problem: None };
        }
        log::info!("sign-in cancelled");
        self.publish();
    }

    /// Reads the profile with the new access token; the person counts as signed in, and the refresh token
    /// is saved, only after ILM answers and only while nothing has ended the sign-in meanwhile.
    async fn establish(
        &self,
        ilm: IlmUrl,
        tokens: Tokens,
        grant: Grant,
        origin: Origin,
    ) -> SessionView {
        let person = match profile(&self.client, &ilm, &tokens.access).await {
            Ok(person) => person,
            Err(error) => return self.fail_attempt(origin.attempt(), error.to_string()),
        };
        let _renewing = self.renewing.lock().await;
        if !is_current(&lock(&self.state), origin.attempt()) {
            log::info!("the sign-in ended before ILM answered and is not kept");
            if let Origin::Saved = origin {
                _ = self.delete_item(&ilm).await;
            }
            return self.view();
        }
        if let Origin::Browser { item, .. } = &origin {
            match item {
                Some(item) => self.save_item(item.clone()).await,
                None => _ = self.delete_item(&ilm).await,
            }
        }
        let refreshable = match &origin {
            Origin::Saved => true,
            Origin::Browser { item, .. } => item.is_some(),
        };
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, origin.attempt());
            if current {
                *state = State::SignedIn(Box::new(Active {
                    ilm: ilm.clone(),
                    person,
                    access: tokens.access,
                    expires_at: tokens.expires_at,
                    grant,
                    refreshable,
                }));
            }
            current
        };
        if !current {
            log::info!("the sign-in ended before ILM answered and is not kept");
            _ = self.delete_item(&ilm).await;
            return self.view();
        }
        log::info!("signed in to {ilm}");
        self.publish()
    }

    /// Forgets the access token, deletes the saved refresh token and then revokes it at the provider.
    pub async fn sign_out(&self) -> SessionView {
        self.sign_out_of(self.settings.connection().address).await
    }

    /// Signs out; `address` names the saved sign-in to remove when nobody is signed in.
    async fn sign_out_of(&self, address: Option<IlmUrl>) -> SessionView {
        let _renewing = self.renewing.lock().await;
        let (ilm, known) = match std::mem::replace(&mut *lock(&self.state), State::Starting) {
            State::SignedIn(active) => (Some(active.ilm.clone()), Some(active.grant)),
            State::SigningIn { cancel, .. } => {
                cancel.notify_one();
                (address, None)
            }
            _ => (address, None),
        };
        let item = match &ilm {
            Some(ilm) => self.load_item(ilm).await.ok().flatten(),
            None => None,
        };
        let problem = match &ilm {
            Some(ilm) => self.delete_item(ilm).await.err().map(|error| {
                format!("You are signed out, but your saved sign-in could not be removed: {error}")
            }),
            None => None,
        };
        let view = self.set(State::SignedOut { problem });
        if let Some(item) = item {
            self.revoke_item(&item, known).await;
        }
        log::info!("signed out");
        view
    }

    async fn revoke_item(&self, item: &Item, known: Option<Grant>) {
        let known = known.filter(|grant| {
            grant.metadata.issuer == item.issuer && grant.client_id.as_str() == item.client_id
        });
        let grant = match known {
            Some(grant) => Some(grant),
            None => match provider_metadata(&self.client, &item.issuer).await {
                Ok(metadata) => {
                    client_identity(Some(&item.client_id), &metadata)
                        .ok()
                        .map(|client_id| Grant {
                            metadata,
                            client_id,
                            resource: None,
                        })
                }
                Err(_) => None,
            },
        };
        let Some(grant) = grant else {
            log::warn!("the refresh token could not be revoked: no provider metadata");
            return;
        };
        if revoke(
            &self.client,
            &grant.metadata,
            &grant.client_id,
            &item.refresh_token,
        )
        .await
        .is_err()
        {
            log::warn!("the refresh token could not be revoked at {}", item.issuer);
        }
    }

    /// Sends the request `build` makes with the access token. A token about to expire is renewed first; a
    /// 401 renews once and sends the request once more, and that answer is returned whatever it is.
    pub async fn call_ilm(
        &self,
        build: impl Fn(&Client, &IlmUrl) -> RequestBuilder + Sync,
    ) -> Result<Response, CallError> {
        let ilm = match &*lock(&self.state) {
            State::SignedIn(active) => active.ilm.clone(),
            _ => return Err(CallError::SignedOut),
        };
        let token = self.usable_token(&ilm, None).await?;
        let response = self.send(&build, &ilm, &token).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        log::info!("ILM refused the access token; renewing it once");
        let token = self.usable_token(&ilm, Some(&token)).await?;
        self.send(&build, &ilm, &token).await
    }

    async fn send(
        &self,
        build: &impl Fn(&Client, &IlmUrl) -> RequestBuilder,
        ilm: &IlmUrl,
        token: &AccessToken,
    ) -> Result<Response, CallError> {
        build(&self.client, ilm)
            .bearer_auth(token.as_str())
            .send()
            .await
            .map_err(|error| {
                log::warn!("ILM could not be reached: {}", error.without_url());
                CallError::Unreachable
            })
    }

    /// The access token for `ilm` to use: the current one while it is good, else a renewed one. `refused` is
    /// the token ILM just turned down, which another caller may already have replaced.
    async fn usable_token(
        &self,
        ilm: &IlmUrl,
        refused: Option<&AccessToken>,
    ) -> Result<AccessToken, CallError> {
        let _renewing = self.renewing.lock().await;
        let grant = match &*lock(&self.state) {
            State::SignedIn(active) if active.ilm == *ilm => {
                let margin = if active.refreshable {
                    RENEW_MARGIN
                } else {
                    Duration::ZERO
                };
                if refused != Some(&active.access) && active.expires_at > Instant::now() + margin {
                    return Ok(active.access.clone());
                }
                active.refreshable.then(|| active.grant.clone())
            }
            _ => return Err(CallError::SignedOut),
        };
        let Some(grant) = grant else {
            log::info!("the access token has ended and no refresh token belongs to this sign-in");
            self.fail(SIGN_IN_ENDED);
            return Err(CallError::SignedOut);
        };
        let item = match self.load_item(ilm).await {
            Ok(Some(item))
                if item.issuer == grant.metadata.issuer
                    && item.client_id == grant.client_id.as_str() =>
            {
                item
            }
            Ok(_) => {
                log::info!(
                    "no refresh token is saved for this sign-in; it ends with the access token"
                );
                self.fail(SIGN_IN_ENDED);
                return Err(CallError::SignedOut);
            }
            Err(error) => {
                log::warn!("the saved sign-in could not be read: {error}");
                return Err(CallError::Unreachable);
            }
        };
        match self.renew_item(&item, &grant).await {
            Ok(tokens) => {
                let access = tokens.access.clone();
                if let State::SignedIn(active) = &mut *lock(&self.state) {
                    active.access = tokens.access;
                    active.expires_at = tokens.expires_at;
                }
                Ok(access)
            }
            Err(TokenError::Refused) => {
                self.fail(SIGN_IN_ENDED);
                Err(CallError::SignedOut)
            }
            Err(TokenError::Unreachable) => Err(CallError::Unreachable),
        }
    }

    /// Renews with the saved refresh token. A rotated one replaces the saved one before this returns; a
    /// refusal deletes the saved item.
    async fn renew_item(&self, item: &Item, grant: &Grant) -> Result<Tokens, TokenError> {
        let tokens = match refresh(
            &self.client,
            &grant.metadata,
            &grant.client_id,
            &item.refresh_token,
            grant.resource.as_deref(),
        )
        .await
        {
            Ok(tokens) => tokens,
            Err(TokenError::Refused) => {
                _ = self.delete_item(&item.ilm).await;
                return Err(TokenError::Refused);
            }
            Err(error) => return Err(error),
        };
        if let Some(rotated) = tokens
            .refresh
            .as_ref()
            .filter(|new| new.as_str() != item.refresh_token.as_str())
        {
            self.save_item(Item {
                refresh_token: rotated.clone(),
                ..item.clone()
            })
            .await;
        }
        Ok(tokens)
    }
}
