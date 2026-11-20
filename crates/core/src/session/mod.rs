//! The sign-in of the person: connecting to an ILM, the browser flow, silent renewal and sign-out.

mod certificate;
#[cfg(test)]
mod certificate_tests;
#[cfg(test)]
mod sign_in_certificate_tests;
mod store;
#[cfg(test)]
pub(crate) mod tests;

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use tokio::sync::Notify;
use url::Url;

use crate::identity::tls::CertificateAsked;
use crate::identity::{ClientIdentity, EmptyStore, Fingerprint, IdentityStore};
use crate::ilm::profile::{IlmError, Person, profile, profile_request, read_profile};
use crate::ilm::resource::{PublishedProvider, discover};
use crate::ilm::{AddressError, IlmUrl};
use crate::oauth::client::{ClientId, client_identity};
use crate::oauth::loopback::{AuthorizationRequest, FLOW_TIMEOUT, wait_for_code};
use crate::oauth::metadata::{MetadataError, ProviderMetadata, provider_metadata};
use crate::oauth::token::{TokenError, Tokens, exchange, refresh, revoke};
use crate::settings::SignInMethod;
use crate::token::AccessToken;
pub use certificate::ChangeError;
use certificate::certificate_choice;
pub use store::{Item, KeyringStore, MemoryStore, RefreshStore, StoreError};

/// An access token that expires sooner than this is renewed before it is used.
const RENEW_MARGIN: Duration = Duration::from_secs(60);

const NO_PROVIDER: &str = "This ILM offers no identity provider that this application can use.";
const NO_PROVIDER_OR_CERTIFICATE: &str = "This ILM offers no identity provider that this application can use, and this computer has no certificate that can sign in.";
const NO_PROVIDER_ALLOWED: &str =
    "Your organization does not allow signing in with an identity provider.";
const NO_CERTIFICATE: &str = "This computer has no certificate that can sign in.";
const SIGN_IN_ENDED: &str = "Your sign-in has ended. Sign in again.";
const CONNECT_FIRST: &str = "Enter the address of your ILM first.";
const ADDRESS_CHANGED: &str = "The ILM address changed. Connect again.";

/// What the session needs to know about the connection, from the settings of the person and of the
/// organization.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connection {
    pub address: Option<IlmUrl>,
    /// Policy fixes the address.
    pub locked: bool,
    /// The name of the provider policy asks for.
    pub provider: Option<String>,
    /// The way of signing in policy allows; none allows both.
    pub method: Option<SignInMethod>,
    /// The certificate the person last signed in with at this address.
    pub certificate: Option<Fingerprint>,
}

pub trait ConnectionSettings: Send + Sync {
    fn connection(&self) -> Connection;
    fn save_address(&self, address: &IlmUrl) -> Result<(), String>;
    /// Remembers the certificate the person signed in with at an ILM address.
    fn save_certificate(&self, ilm: &IlmUrl, fingerprint: &Fingerprint) -> Result<(), String>;
    /// Forgets the remembered certificate, whatever its address: any of them when `failed` is none, else only
    /// that one.
    fn forget_certificate(&self, failed: Option<&Fingerprint>) -> Result<(), String>;
}

/// An identity provider the person can sign in with. The id is only meaningful to the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct ProviderChoice {
    pub id: String,
    pub name: String,
}

/// A certificate on this computer that can sign in, as the person sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct CertificateChoice {
    pub fingerprint: String,
    pub subject: String,
    pub issuer: String,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub not_after: i64,
    /// The certificate the person signed in with last.
    pub remembered: bool,
}

/// How the person signs in while a sign-in is under way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum SignInKind {
    Browser,
    Certificate,
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
    /// The application is locked and shows nothing about the sign-in; the application, not the session, says so.
    Locked {},
    SignedOut {
        address: Option<String>,
        locked: bool,
        problem: Option<String>,
        /// The sign-in ended without the person signing out, and can be repeated.
        again: bool,
    },
    SigningIn {
        provider: String,
        method: SignInKind,
    },
    /// A saved sign-in that could not be renewed because ILM or the identity provider cannot be reached.
    Unreachable {
        address: String,
        problem: String,
    },
    SignedIn {
        address: String,
        person: PersonView,
        allowed_listings: Vec<String>,
        /// Short fingerprint of the certificate of a certificate sign-in, `None` for a sign-in with a provider.
        certificate: Option<String>,
        /// The last check could not reach ILM.
        unreachable: bool,
    },
}

/// Who is signed in to which ILM, and what that person may list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedInAs {
    pub ilm: IlmUrl,
    pub username: String,
    pub allowed_listings: Vec<String>,
}

impl SignedInAs {
    /// Whether ILM lets the person list its certificates.
    pub fn lists_certificates(&self) -> bool {
        self.allowed_listings
            .iter()
            .any(|listing| listing == "certificates")
    }
}

/// What the person signed in with, kept in memory after the sign-in ended on its own, to repeat it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Again {
    /// The issuer of the identity provider.
    Provider(String),
    Certificate,
}

/// Where a sign-in that ended continues.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInAgain {
    /// The state after the attempt: waiting for the browser, or signed out with the reason.
    View(SessionView),
    /// The same sign-in is not possible any more: the person chooses among these, as after `connect`.
    Choose(Vec<ProviderChoice>),
}

/// Why a call to ILM was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallError {
    SignedOut,
    Unreachable,
    /// The caller's `proceed` said no, so nothing was sent.
    Withdrawn,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CallError::SignedOut => "You are not signed in.",
            CallError::Unreachable => "ILM or the identity provider cannot be reached.",
            CallError::Withdrawn => "The request was not sent.",
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

/// Builds the client that presents a certificate; the interface also tells whether the server asked for one.
type CertificateClient = Box<dyn Fn(ClientIdentity) -> (Client, CertificateAsked) + Send + Sync>;

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

/// The access token of a sign-in with a provider.
struct OAuthCredential {
    access: AccessToken,
    expires_at: Instant,
    grant: Grant,
    /// Whether a refresh token belongs to this sign-in; without one it ends with the access token.
    refreshable: bool,
}

/// What proves the person to ILM. The two never mix: the OAuth client has no certificate and the
/// certificate client sends no token.
enum Credential {
    OAuth(OAuthCredential),
    Certificate {
        fingerprint: Fingerprint,
        /// Presents the certificate in every handshake.
        client: Client,
        /// Tells this sign-in from a later one with the same certificate.
        generation: Arc<()>,
        /// When the certificate expires, when the sign-in could read it.
        not_after: Option<SystemTime>,
    },
}

struct Active {
    /// Tells this sign-in from a later one to the same ILM.
    id: Arc<()>,
    ilm: IlmUrl,
    person: Person,
    credential: Credential,
    /// The last check could not reach ILM.
    unreachable: bool,
}

impl Active {
    fn again(&self) -> Again {
        match &self.credential {
            Credential::OAuth(oauth) => Again::Provider(oauth.grant.metadata.issuer.clone()),
            Credential::Certificate { .. } => Again::Certificate,
        }
    }
}

enum State {
    Starting,
    SignedOut {
        problem: Option<String>,
        again: Option<Again>,
    },
    /// The saved sign-in is kept while ILM or the identity provider cannot be reached.
    Unreachable {
        ilm: IlmUrl,
        problem: String,
    },
    SigningIn {
        provider: String,
        method: SignInKind,
        /// Where the browser is, for a sign-in with a provider.
        url: Option<Url>,
        cancel: Arc<Notify>,
    },
    SignedIn(Box<Active>),
}

impl State {
    fn signed_out(problem: Option<String>) -> Self {
        State::SignedOut {
            problem,
            again: None,
        }
    }
}

/// The sign-in of the person. The access token lives here, in memory; the refresh token only in the store.
pub struct Session {
    client: Client,
    settings: Arc<dyn ConnectionSettings>,
    store: Arc<dyn RefreshStore>,
    identities: Arc<dyn IdentityStore>,
    certificate_client: CertificateClient,
    on_change: Box<dyn Fn(&SessionView) + Send + Sync>,
    state: Mutex<State>,
    pending: Mutex<Option<Pending>>,
    /// Held while the saved refresh token or the signed-in state changes, so those changes do not interleave.
    renewing: tokio::sync::Mutex<()>,
    /// Held while the saved sign-in is tried again, so two retries do not renew the same refresh token.
    restoring: tokio::sync::Mutex<()>,
    /// Held for a whole check, so an older answer never overwrites a newer one.
    checking: tokio::sync::Mutex<()>,
    /// Held for a whole change of the sign-in certificate, so two changes do not interleave.
    changing: tokio::sync::Mutex<()>,
    /// The latest refresh token when the store could not save it.
    unsaved: Mutex<Option<Item>>,
    /// Runs when a sign-in has ended, whoever ended it, before the view changes.
    on_signed_out: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Whether the browser sign-in `attempt`, or with none the renewal at start, is still the one under way.
fn is_current(state: &State, attempt: Option<&Arc<Notify>>) -> bool {
    match (state, attempt) {
        (State::Starting | State::Unreachable { .. }, None) => true,
        (State::SigningIn { cancel, .. }, Some(attempt)) => Arc::ptr_eq(cancel, attempt),
        _ => false,
    }
}

/// What a call needs of a certificate sign-in.
struct CertificateCall {
    client: Client,
    generation: Arc<()>,
    fingerprint: Fingerprint,
    not_after: Option<SystemTime>,
}

impl Credential {
    fn certificate(&self) -> Option<CertificateCall> {
        match self {
            Credential::Certificate {
                client,
                generation,
                fingerprint,
                not_after,
            } => Some(CertificateCall {
                client: client.clone(),
                generation: generation.clone(),
                fingerprint: *fingerprint,
                not_after: *not_after,
            }),
            Credential::OAuth(_) => None,
        }
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
            identities: Arc::new(EmptyStore),
            certificate_client: Box::new(crate::http::client_with_identity),
            on_change: Box::new(on_change),
            state: Mutex::new(State::Starting),
            pending: Mutex::new(None),
            renewing: tokio::sync::Mutex::new(()),
            restoring: tokio::sync::Mutex::new(()),
            checking: tokio::sync::Mutex::new(()),
            changing: tokio::sync::Mutex::new(()),
            unsaved: Mutex::new(None),
            on_signed_out: Mutex::new(None),
        }
    }

    /// Runs `hook` whenever a sign-in ends: the person signs out, changes the address, or ILM ends the sign-in.
    /// A later hook replaces an earlier one.
    pub fn on_signed_out(&self, hook: impl Fn() + Send + Sync + 'static) {
        *lock(&self.on_signed_out) = Some(Arc::new(hook));
    }

    fn signed_out(&self) {
        let hook = lock(&self.on_signed_out).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Who is signed in, or none while nobody is.
    pub fn signed_in_as(&self) -> Option<SignedInAs> {
        match &*lock(&self.state) {
            State::SignedIn(active) => Some(SignedInAs {
                ilm: active.ilm.clone(),
                username: active.person.username.clone(),
                allowed_listings: active.person.allowed_listings.clone(),
            }),
            _ => None,
        }
    }

    /// The address of ILM while a saved sign-in cannot be renewed because ILM or the identity provider cannot be
    /// reached.
    pub fn unreachable_at(&self) -> Option<IlmUrl> {
        match &*lock(&self.state) {
            State::Unreachable { ilm, .. } => Some(ilm.clone()),
            _ => None,
        }
    }

    /// The certificates of the person the sign-in can offer; by default there are none.
    #[must_use]
    pub fn with_identities(mut self, identities: Arc<dyn IdentityStore>) -> Self {
        self.identities = identities;
        self
    }

    /// Builds the certificate clients with `build`, to trust the servers of a test.
    #[cfg(test)]
    #[must_use]
    fn with_certificate_client(mut self, build: CertificateClient) -> Self {
        self.certificate_client = build;
        self
    }

    pub fn view(&self) -> SessionView {
        let connection = self.settings.connection();
        match &*lock(&self.state) {
            State::Starting => SessionView::Starting,
            State::SignedOut { problem, again } => SessionView::SignedOut {
                address: connection.address.map(|address| address.to_string()),
                locked: connection.locked,
                problem: problem.clone(),
                again: again.is_some(),
            },
            State::Unreachable { ilm, problem } => SessionView::Unreachable {
                address: ilm.to_string(),
                problem: problem.clone(),
            },
            State::SigningIn {
                provider, method, ..
            } => SessionView::SigningIn {
                provider: provider.clone(),
                method: *method,
            },
            State::SignedIn(active) => SessionView::SignedIn {
                address: active.ilm.to_string(),
                person: PersonView {
                    name: active.person.display_name.clone(),
                    username: active.person.username.clone(),
                },
                allowed_listings: active.person.allowed_listings.clone(),
                certificate: active
                    .credential
                    .certificate()
                    .map(|held| held.fingerprint.short()),
                unreachable: active.unreachable,
            },
        }
    }

    /// The address that is open in the browser while the person signs in, to open it again.
    pub fn browser_url(&self) -> Option<Url> {
        match &*lock(&self.state) {
            State::SigningIn { url, .. } => url.clone(),
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
        *lock(&self.state) = State::signed_out(Some(problem));
        self.signed_out();
        self.publish()
    }

    /// Like `fail`, but only while the person is still signed out: a sign-in made meanwhile is left alone.
    fn fail_if_signed_out(&self, problem: &str) {
        let replaced = {
            let mut state = lock(&self.state);
            let signed_out = matches!(&*state, State::SignedOut { .. });
            if signed_out {
                *state = State::signed_out(Some(problem.to_owned()));
            }
            signed_out
        };
        if replaced {
            log::warn!("{problem}");
            self.publish();
        }
    }

    /// Ends the sign-in the person did not end, so it can be repeated, with `problem`.
    fn end_sign_in(&self, problem: &str, again: Again) -> SessionView {
        log::info!("the sign-in ended: {problem}");
        *lock(&self.state) = State::SignedOut {
            problem: Some(problem.to_owned()),
            again: Some(again),
        };
        self.signed_out();
        self.publish()
    }

    /// Ends the sign-in `attempt` with `problem`, unless something else has ended it meanwhile.
    fn fail_attempt(
        &self,
        attempt: Option<&Arc<Notify>>,
        problem: impl Into<String>,
    ) -> SessionView {
        self.end_attempt(attempt, problem, None)
    }

    /// Like `fail_attempt`; `again` is how the sign-in can be repeated when it ended on its own.
    fn end_attempt(
        &self,
        attempt: Option<&Arc<Notify>>,
        problem: impl Into<String>,
        again: Option<Again>,
    ) -> SessionView {
        let problem = problem.into();
        if again.is_some() {
            log::info!("the sign-in ended: {problem}");
        } else {
            log::warn!("{problem}");
        }
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, attempt);
            if current {
                *state = State::SignedOut {
                    problem: Some(problem),
                    again,
                };
            }
            current
        };
        if !current {
            return self.view();
        }
        self.signed_out();
        self.publish()
    }

    /// The saved sign-in of the start, or of a retry, is kept: ILM or the identity provider cannot be reached.
    fn unreachable_at_start(&self, ilm: &IlmUrl, problem: impl Into<String>) -> SessionView {
        let problem = problem.into();
        log::warn!("the saved sign-in is kept, {problem}");
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, None);
            if current {
                *state = State::Unreachable {
                    ilm: ilm.clone(),
                    problem,
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
        let connection = self.settings.connection();
        let Some(ilm) = connection.address.clone() else {
            return self.set(State::signed_out(None));
        };
        if connection.method == Some(SignInMethod::Certificate) {
            return self.start_with_certificate(ilm, &connection).await;
        }
        let item = match self.load_item(&ilm).await {
            Ok(Some(item)) => item,
            Ok(None) => return self.start_with_certificate(ilm, &connection).await,
            Err(error) => {
                return self.fail(format!("Your saved sign-in could not be read: {error}"));
            }
        };
        log::info!("renewing the saved sign-in for {ilm}");
        let metadata = match provider_metadata(&self.client, &item.issuer).await {
            Ok(metadata) => metadata,
            Err(MetadataError::Unreachable) => {
                return self.unreachable_at_start(
                    &ilm,
                    "Could not renew the sign-in: the identity provider cannot be reached.",
                );
            }
            Err(error) => return self.fail(format!("Could not renew the sign-in: {error}.")),
        };
        let client_id = match client_identity(Some(&item.client_id), &metadata) {
            Ok(client_id) => client_id,
            Err(error) => return self.fail(format!("Could not renew the sign-in: {error}.")),
        };
        let grant = Grant {
            metadata,
            client_id,
            resource: item.resource.clone(),
        };
        let renewed = {
            let _renewing = self.renewing.lock().await;
            if !is_current(&lock(&self.state), None) {
                log::info!("the sign-in changed before the saved one was renewed");
                return self.view();
            }
            self.renew_item(&item, &grant).await
        };
        match renewed {
            Ok(tokens) => self.establish(ilm, tokens, grant, Origin::Saved).await,
            Err(TokenError::Refused) => {
                self.end_attempt(None, SIGN_IN_ENDED, Some(Again::Provider(item.issuer)))
            }
            Err(TokenError::Unreachable) => self.unreachable_at_start(
                &ilm,
                "Could not renew the sign-in: the identity provider cannot be reached.",
            ),
        }
    }

    /// Tries the saved sign-in again while it is unreachable.
    pub async fn retry(&self) -> SessionView {
        let _restoring = self.restoring.lock().await;
        if !matches!(&*lock(&self.state), State::Unreachable { .. }) {
            return self.view();
        }
        log::info!("trying the saved sign-in again");
        self.start().await
    }

    /// While signed in, reads the profile of the person: this renews the access token as needed, updates the
    /// person and tells whether ILM can be reached.
    pub async fn check(&self) -> SessionView {
        let _checking = self.checking.lock().await;
        let signed_in = match &*lock(&self.state) {
            State::SignedIn(active) => Some((active.ilm.clone(), active.id.clone())),
            _ => None,
        };
        let Some((ilm, id)) = signed_in else {
            return self.view();
        };
        let answer = self.call_ilm(profile_request).await;
        let profile = match answer {
            Ok(response) if response.status() == StatusCode::UNAUTHORIZED => {
                self.end_active(&id, "ILM did not accept the sign-in.")
                    .await;
                return self.view();
            }
            Ok(response) => read_profile(&ilm, response).await,
            Err(CallError::SignedOut) => return self.view(),
            Err(CallError::Unreachable | CallError::Withdrawn) => Err(IlmError::Unreachable),
        };
        let before = self.view();
        if let State::SignedIn(active) = &mut *lock(&self.state)
            && Arc::ptr_eq(&active.id, &id)
        {
            match profile {
                Ok(person) => {
                    log::info!("the check of the sign-in succeeded");
                    active.person = person;
                    active.unreachable = false;
                }
                Err(error) => {
                    log::info!("the check of the sign-in found ILM unreachable: {error}");
                    active.unreachable = true;
                }
            }
        }
        let view = self.view();
        if view != before {
            (self.on_change)(&view);
        }
        view
    }

    /// Ends the sign-in `id` that ILM no longer accepts, unless it has ended already; a saved refresh token goes too.
    async fn end_active(&self, id: &Arc<()>, problem: &str) {
        let _renewing = self.renewing.lock().await;
        let (again, saved) = match &*lock(&self.state) {
            State::SignedIn(active) if Arc::ptr_eq(&active.id, id) => (
                active.again(),
                matches!(active.credential, Credential::OAuth(_)).then(|| active.ilm.clone()),
            ),
            _ => return,
        };
        // A restart must not restore a sign-in that ILM has refused.
        if let Some(ilm) = saved {
            _ = self.delete_item(&ilm).await;
        }
        self.end_sign_in(problem, again);
    }

    /// Repeats the sign-in that ended on its own: with the same identity provider when ILM still offers it,
    /// else the person chooses. A sign-in with a certificate goes to the choice, which lists the certificates.
    /// Any other state is left as it is.
    pub async fn sign_in_again(&self, open: impl Fn(&Url) + Send) -> SignInAgain {
        let ended = match &*lock(&self.state) {
            State::SignedOut { again, .. } => again.clone(),
            _ => None,
        };
        let Some(again) = ended else {
            return SignInAgain::View(self.view());
        };
        let connection = self.settings.connection();
        let Some(ilm) = connection.address.clone() else {
            return SignInAgain::View(self.fail(CONNECT_FIRST));
        };
        log::info!("signing in again to {ilm}");
        let offered = self.offer(ilm, &connection).await;
        if !matches!(&*lock(&self.state), State::SignedOut { again: Some(_), .. }) {
            return SignInAgain::View(self.view());
        }
        let choices = match offered {
            Ok(choices) => choices,
            Err(problem) => return SignInAgain::View(self.fail(problem)),
        };
        if let Again::Provider(issuer) = again
            && let Some(index) = self.provider_index(&issuer)
        {
            return SignInAgain::View(self.sign_in(&index.to_string(), open).await);
        }
        SignInAgain::Choose(choices)
    }

    fn provider_index(&self, issuer: &str) -> Option<usize> {
        lock(&self.pending)
            .as_ref()?
            .candidates
            .iter()
            .position(|candidate| candidate.metadata.issuer == issuer)
    }

    /// Takes the ILM address, signs out of another ILM when it changes, and lists the providers to sign in with.
    pub async fn connect(&self, address: &str) -> Result<Vec<ProviderChoice>, String> {
        let connection = self.settings.connection();
        let ilm = match (&connection.address, connection.locked) {
            (Some(locked), true) => locked.clone(),
            _ => parse_address(address).map_err(|error| error.to_string())?,
        };
        let mut signed_out = false;
        if connection.address.as_ref() != Some(&ilm) {
            self.settings.save_address(&ilm)?;
            if connection.address.is_some() {
                self.sign_out_of(connection.address.clone()).await;
                signed_out = true;
            }
        }
        let offered = self.offer(ilm.clone(), &connection).await;
        // Signing out closes the window that asked, so the sign-in screen has to show why the new address failed,
        // unless the person has moved on to another address since.
        if let Err(problem) = &offered
            && signed_out
            && self.settings.connection().address.as_ref() == Some(&ilm)
        {
            self.fail_if_signed_out(problem);
        }
        offered
    }

    /// Lists the providers `ilm` publishes that can be used, or only the one policy names when it is among them,
    /// and last the certificate on this computer when one can sign in.
    async fn offer(
        &self,
        ilm: IlmUrl,
        connection: &Connection,
    ) -> Result<Vec<ProviderChoice>, String> {
        let method = connection.method;
        let mut discovery_error = None;
        let candidates = if method == Some(SignInMethod::Certificate) {
            Vec::new()
        } else {
            match self
                .provider_candidates(&ilm, connection.provider.as_deref())
                .await
            {
                Ok(candidates) => candidates,
                Err(error) if method.is_none() => {
                    log::warn!("the identity providers of {ilm} could not be listed: {error}");
                    discovery_error = Some(error);
                    Vec::new()
                }
                Err(error) => return Err(error),
            }
        };
        let mut choices: Vec<ProviderChoice> = candidates
            .iter()
            .enumerate()
            .map(|(index, candidate)| ProviderChoice {
                id: index.to_string(),
                name: candidate.published.name.clone(),
            })
            .collect();
        if method != Some(SignInMethod::Oauth) && self.certificate_candidates().await > 0 {
            choices.push(certificate_choice());
        }
        if choices.is_empty() {
            return Err(discovery_error.unwrap_or_else(|| {
                match method {
                    Some(SignInMethod::Oauth) => NO_PROVIDER,
                    Some(SignInMethod::Certificate) => NO_CERTIFICATE,
                    None => NO_PROVIDER_OR_CERTIFICATE,
                }
                .to_owned()
            }));
        }
        if self.settings.connection().address.as_ref() != Some(&ilm) {
            return Err(ADDRESS_CHANGED.to_owned());
        }
        *lock(&self.pending) = Some(Pending { ilm, candidates });
        Ok(choices)
    }

    /// The providers `ilm` publishes that can be used, or only `chosen` when it is one of them.
    async fn provider_candidates(
        &self,
        ilm: &IlmUrl,
        chosen: Option<&str>,
    ) -> Result<Vec<Candidate>, String> {
        let published = discover(&self.client, ilm)
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
        if let Some(name) = chosen
            && !candidates.is_empty()
        {
            match candidates
                .iter()
                .position(|candidate| candidate.published.name == *name)
            {
                Some(chosen) => candidates = vec![candidates.swap_remove(chosen)],
                None => log::warn!("policy names the provider {name}, which {ilm} does not offer"),
            }
        }
        Ok(candidates)
    }

    /// Opens the browser through `open` and waits until the person has signed in, cancelled or run out of time.
    pub async fn sign_in(&self, provider_id: &str, open: impl Fn(&Url) + Send) -> SessionView {
        if self.settings.connection().method == Some(SignInMethod::Certificate) {
            return self.fail(NO_PROVIDER_ALLOWED);
        }
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
            method: SignInKind::Browser,
            url: Some(request.url.clone()),
            cancel: cancel.clone(),
        });
        log::info!("sign-in with {name} started");
        open(&request.url);
        let code = tokio::select! {
            code = wait_for_code(request.listener, &request.state, &candidate.metadata, FLOW_TIMEOUT) => code,
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
            *state = State::signed_out(None);
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
            Err(IlmError::Unauthorized) if matches!(origin, Origin::Saved) => {
                let again = Again::Provider(grant.metadata.issuer);
                // A restart must not retry a sign-in that ILM has refused.
                let _renewing = self.renewing.lock().await;
                if is_current(&lock(&self.state), None) {
                    _ = self.delete_item(&ilm).await;
                }
                return self.end_attempt(None, IlmError::Unauthorized.to_string(), Some(again));
            }
            Err(error) if matches!(origin, Origin::Saved) => {
                return self.unreachable_at_start(&ilm, error.to_string());
            }
            Err(error) => return self.fail_attempt(origin.attempt(), error.to_string()),
        };
        let _renewing = self.renewing.lock().await;
        if !is_current(&lock(&self.state), origin.attempt()) {
            log::info!("the sign-in ended before ILM answered and is not kept");
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
                    id: Arc::new(()),
                    ilm: ilm.clone(),
                    person,
                    unreachable: false,
                    credential: Credential::OAuth(OAuthCredential {
                        access: tokens.access,
                        expires_at: tokens.expires_at,
                        grant,
                        refreshable,
                    }),
                }));
            }
            current
        };
        if !current {
            log::info!("the sign-in ended before ILM answered and is not kept");
            if let Origin::Browser { .. } = origin {
                _ = self.delete_item(&ilm).await;
            }
            return self.view();
        }
        if let Origin::Browser { .. } = origin {
            _ = self.forget_certificate();
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
            State::SignedIn(active) => {
                let grant = match active.credential {
                    Credential::OAuth(oauth) => Some(oauth.grant),
                    Credential::Certificate { .. } => None,
                };
                (Some(active.ilm), grant)
            }
            State::SigningIn { cancel, .. } => {
                cancel.notify_one();
                (address, None)
            }
            _ => (address, None),
        };
        self.signed_out();
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
        let problem = problem.or(self.forget_certificate().err());
        let view = self.set(State::signed_out(problem));
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
        self.call_ilm_as(None, None, build).await
    }

    /// Like `call_ilm`; with `expected`, only as that sign-in, so a request is never sent as one that replaced it.
    /// `proceed` is asked just before each send, the one after a renewal included; when it says no, nothing is sent.
    pub(super) async fn call_ilm_as(
        &self,
        expected: Option<&Arc<()>>,
        proceed: Option<&(dyn Fn() -> bool + Sync)>,
        build: impl Fn(&Client, &IlmUrl) -> RequestBuilder + Sync,
    ) -> Result<Response, CallError> {
        let allowed = || proceed.is_none_or(|proceed| proceed());
        let (ilm, certificate, id) = match &*lock(&self.state) {
            State::SignedIn(active) if expected.is_none_or(|id| Arc::ptr_eq(id, &active.id)) => (
                active.ilm.clone(),
                active.credential.certificate(),
                active.id.clone(),
            ),
            _ => return Err(CallError::SignedOut),
        };
        if let Some(certificate) = certificate {
            if !allowed() {
                return Err(CallError::Withdrawn);
            }
            return self.call_with_certificate(&build, &ilm, &certificate).await;
        }
        let token = self.token_of(&ilm, &id, None).await?;
        if !allowed() {
            return Err(CallError::Withdrawn);
        }
        let response = self.send(&build, &ilm, &token).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        log::info!("ILM refused the access token; renewing it once");
        let token = self.token_of(&ilm, &id, Some(&token)).await?;
        if !allowed() {
            return Err(CallError::Withdrawn);
        }
        self.send(&build, &ilm, &token).await
    }

    /// Like `usable_token`, but only while the sign-in `id` lasts: a token of a sign-in that started meanwhile is
    /// never used for a request of an earlier one.
    async fn token_of(
        &self,
        ilm: &IlmUrl,
        id: &Arc<()>,
        refused: Option<&AccessToken>,
    ) -> Result<AccessToken, CallError> {
        let token = self.usable_token(ilm, refused).await?;
        if self.is_sign_in(id) {
            Ok(token)
        } else {
            Err(CallError::SignedOut)
        }
    }

    /// Whether the sign-in `id` is the one signed in now.
    fn is_sign_in(&self, id: &Arc<()>) -> bool {
        matches!(&*lock(&self.state), State::SignedIn(active) if Arc::ptr_eq(&active.id, id))
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
        let (grant, refreshable) = match &*lock(&self.state) {
            State::SignedIn(active) if active.ilm == *ilm => {
                let Credential::OAuth(oauth) = &active.credential else {
                    return Err(CallError::SignedOut);
                };
                let margin = if oauth.refreshable {
                    RENEW_MARGIN
                } else {
                    Duration::ZERO
                };
                if refused != Some(&oauth.access) && oauth.expires_at > Instant::now() + margin {
                    return Ok(oauth.access.clone());
                }
                (oauth.grant.clone(), oauth.refreshable)
            }
            _ => return Err(CallError::SignedOut),
        };
        let ended = || Again::Provider(grant.metadata.issuer.clone());
        if !refreshable {
            log::info!("the access token has ended and no refresh token belongs to this sign-in");
            self.end_sign_in(SIGN_IN_ENDED, ended());
            return Err(CallError::SignedOut);
        }
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
                self.end_sign_in(SIGN_IN_ENDED, ended());
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
                if let State::SignedIn(active) = &mut *lock(&self.state)
                    && let Credential::OAuth(oauth) = &mut active.credential
                {
                    oauth.access = tokens.access;
                    oauth.expires_at = tokens.expires_at;
                }
                Ok(access)
            }
            Err(TokenError::Refused) => {
                self.end_sign_in(SIGN_IN_ENDED, ended());
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
