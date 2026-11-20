//! Signing in with a certificate of this computer: the list, the proof in the handshake, the silent start.

use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::SystemTime;

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tokio::sync::Notify;

use super::{
    Active, Again, CONNECT_FIRST, CallError, CertificateCall, CertificateChoice, Connection,
    Credential, Session, SessionView, SignInKind, State, is_current, lock,
};
use crate::identity::certificate::epoch_millis;
use crate::identity::{self, Fingerprint, IdentityStore, is_signing_refused};
use crate::ilm::IlmUrl;
use crate::ilm::certificates::State as IlmState;
use crate::ilm::profile::{
    IlmError, SignInCertificate, profile_request, read_profile, read_rejection, update_request,
};
use crate::inventory::{Inventory, Trigger};
use crate::session::ProviderChoice;
use crate::settings::SignInMethod;

const CERTIFICATE_ID: &str = "certificate";
const CERTIFICATE_NAME: &str = "Certificate on this computer";

const NOT_ALLOWED: &str = "Your organization does not allow signing in with a certificate.";
const NOT_ASKED: &str = "This ILM's gateway is not set up for certificate sign-in.";
const HANDSHAKE_REFUSED: &str = "The gateway did not accept this certificate.";
const NOT_KNOWN: &str =
    "ILM does not know this certificate. It must be your sign-in certificate in ILM.";
const KEY_REFUSED: &str = "The system did not allow the use of this certificate's key.";
const GONE: &str = "The certificate you signed in with cannot be found, has expired or cannot be opened on this computer.";
const EXPIRED: &str = "The certificate you signed in with has expired.";
const NOT_ON_COMPUTER: &str = "This certificate is not on this computer.";

/// Why a certificate did not become the person's sign-in certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    SignedOut,
    /// ILM cannot be reached, or the last check could not reach it.
    Offline,
    NotInIlm,
    NotIssued,
    Archived,
    /// The certificate is not on this computer or cannot sign in here.
    CannotSignIn,
    AlreadySignIn,
    /// ILM answered 403.
    NotAllowed,
    /// ILM answered 400 or 422 with these messages.
    Rejected(Vec<String>),
    Unexpected(u16),
    Malformed,
    /// The caller withdrew before ILM was asked to change anything.
    Withdrawn,
}

impl std::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeError::SignedOut => CallError::SignedOut.fmt(f),
            ChangeError::Offline => f.write_str("ILM cannot be reached."),
            ChangeError::NotInIlm => f.write_str("ILM does not know this certificate."),
            ChangeError::NotIssued => f.write_str("ILM has not issued this certificate."),
            ChangeError::Archived => f.write_str("This certificate is archived in ILM."),
            ChangeError::CannotSignIn => {
                f.write_str("This certificate cannot sign in on this computer.")
            }
            ChangeError::AlreadySignIn => f.write_str("This is already your sign-in certificate."),
            ChangeError::NotAllowed => f.write_str("ILM does not allow this."),
            ChangeError::Rejected(messages) if messages.is_empty() => {
                f.write_str("ILM did not accept the change.")
            }
            ChangeError::Rejected(messages) => f.write_str(&messages.join(" ")),
            ChangeError::Unexpected(status) => write!(f, "ILM answered with an error ({status})."),
            ChangeError::Withdrawn => f.write_str("The change was not made."),
            ChangeError::Malformed => {
                f.write_str("ILM answered in a way this application does not understand.")
            }
        }
    }
}

impl Error for ChangeError {}

impl From<CallError> for ChangeError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::SignedOut => ChangeError::SignedOut,
            CallError::Unreachable => ChangeError::Offline,
            CallError::Withdrawn => ChangeError::Withdrawn,
        }
    }
}

/// The sign-in a change of the sign-in certificate started from.
struct Departing {
    id: Arc<()>,
    /// The generation of a certificate sign-in; none with a provider.
    generation: Option<Arc<()>>,
}

pub(super) fn certificate_choice() -> ProviderChoice {
    ProviderChoice {
        id: CERTIFICATE_ID.to_owned(),
        name: CERTIFICATE_NAME.to_owned(),
    }
}

/// What to tell the person when the request was refused, or none when ILM could not be reached. A connection that
/// fails, other than by timing out, after the server asked for the certificate counts as a refusal: some systems
/// report the gateway's alert as a reset connection.
fn refusal(error: &(dyn Error + 'static), asked: bool) -> Option<&'static str> {
    if is_signing_refused(error) {
        Some(KEY_REFUSED)
    } else if asked || handshake_refused(error) {
        Some(HANDSHAKE_REFUSED)
    } else {
        None
    }
}

/// Whether the server ended the handshake with an alert, as a gateway does for a certificate it does not accept.
fn handshake_refused(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        let tls = error.downcast_ref::<rustls::Error>().or_else(|| {
            error
                .downcast_ref::<io::Error>()
                .and_then(io::Error::get_ref)
                .and_then(<dyn Error + Send + Sync>::downcast_ref::<rustls::Error>)
        });
        if matches!(tls, Some(rustls::Error::AlertReceived(_))) {
            return true;
        }
        current = error.source();
    }
    false
}

impl Session {
    async fn in_identities<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn IdentityStore) -> T + Send + 'static,
    ) -> T {
        let store = self.identities.clone();
        tokio::task::spawn_blocking(move || work(store.as_ref()))
            .await
            .expect("the certificate store task does not panic")
    }

    /// How many certificates of this computer can sign in.
    pub(super) async fn certificate_candidates(&self) -> usize {
        let found = self.in_identities(|store| store.candidates().len()).await;
        log::info!("{found} certificate(s) on this computer can sign in");
        found
    }

    /// The certificates of this computer that can sign in, the latest expiry first.
    pub async fn certificates(&self) -> Vec<CertificateChoice> {
        let connection = self.settings.connection();
        if connection.method == Some(SignInMethod::Oauth) {
            return Vec::new();
        }
        let found = self.in_identities(|store| store.candidates()).await;
        found
            .into_iter()
            .map(|found| CertificateChoice {
                fingerprint: found.fingerprint.to_string(),
                subject: found.subject,
                issuer: found.issuer,
                not_after: epoch_millis(found.not_after),
                remembered: connection.certificate == Some(found.fingerprint),
            })
            .collect()
    }

    /// Proves the person to ILM with the certificate `fingerprint` and waits for the answer, until the person
    /// cancels.
    pub async fn sign_in_with_certificate(&self, fingerprint: &str) -> SessionView {
        let connection = self.settings.connection();
        let Some(ilm) = lock(&self.pending)
            .as_ref()
            .map(|pending| pending.ilm.clone())
            .filter(|ilm| connection.address.as_ref() == Some(ilm))
        else {
            return self.fail(CONNECT_FIRST);
        };
        if connection.method == Some(SignInMethod::Oauth) {
            return self.fail(NOT_ALLOWED);
        }
        let Ok(fingerprint) = fingerprint.parse::<Fingerprint>() else {
            return self.fail(NOT_ON_COMPUTER);
        };
        let cancel = Arc::new(Notify::new());
        self.set(State::SigningIn {
            provider: CERTIFICATE_NAME.to_owned(),
            method: SignInKind::Certificate,
            url: None,
            cancel: cancel.clone(),
        });
        tokio::select! {
            view = self.certificate_sign_in(&ilm, fingerprint, Some(&cancel)) => view,
            () = cancel.notified() => self.view(),
        }
    }

    /// Makes the certificate of this computer with `fingerprint` the person's sign-in certificate in ILM. The
    /// certificate must be the one the latest check of `inventory` matched, issued and not archived, and able to
    /// sign in here. The person's names, email and description are read again and sent back unchanged. With a
    /// certificate sign-in the remembered certificate and the client follow the new one in the same step; a
    /// check follows. `proceed` is asked just before each time ILM is asked to change it; when it says no, nothing is sent.
    pub async fn make_sign_in_certificate(
        &self,
        inventory: &Inventory,
        fingerprint: &str,
        proceed: impl Fn() -> bool + Sync,
    ) -> Result<(), ChangeError> {
        let requested = self.departing()?.id;
        let _changing = self.changing.lock().await;
        let departing = self.departing()?;
        if !Arc::ptr_eq(&departing.id, &requested) {
            return Err(ChangeError::SignedOut);
        }
        let who = self.signed_in_as().ok_or(ChangeError::SignedOut)?;
        if matches!(inventory.status(), crate::inventory::Status::Offline { .. }) {
            return Err(ChangeError::Offline);
        }
        let fingerprint = fingerprint
            .parse::<Fingerprint>()
            .map_err(|_| ChangeError::NotInIlm)?;
        let matched = inventory
            .snapshot()
            .and_then(|snapshot| snapshot.matches.get(&fingerprint).cloned())
            .ok_or(ChangeError::NotInIlm)?;
        if matched.state != IlmState::Issued {
            return Err(ChangeError::NotIssued);
        }
        if matched.archived {
            return Err(ChangeError::Archived);
        }
        let local = self
            .in_identities(|store| store.certificates())
            .await
            .unwrap_or_default();
        if !local
            .iter()
            .any(|found| found.fingerprint == fingerprint && found.sign_in.is_ok())
        {
            return Err(ChangeError::CannotSignIn);
        }
        let response = self
            .call_ilm_as(Some(&departing.id), None, profile_request)
            .await?;
        let person = read_profile(&who.ilm, response)
            .await
            .map_err(|error| match error {
                IlmError::Unreachable => ChangeError::Offline,
                IlmError::Unexpected(status) => ChangeError::Unexpected(status),
                IlmError::Unauthorized => ChangeError::SignedOut,
                IlmError::Malformed => ChangeError::Malformed,
            })?;
        let old = person.sign_in.as_ref();
        if old.is_some_and(|held| held.uuid == matched.uuid || held.fingerprint == fingerprint) {
            return Err(ChangeError::AlreadySignIn);
        }
        let replacement = self
            .prepare_switch(&who.ilm, &departing, fingerprint)
            .await?;
        let response = self
            .call_ilm_as(Some(&departing.id), Some(&proceed), |client, ilm| {
                update_request(client, ilm, &person, &matched.uuid)
            })
            .await?;
        match response.status() {
            status if status.is_success() => {}
            StatusCode::FORBIDDEN => return Err(ChangeError::NotAllowed),
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                return Err(ChangeError::Rejected(read_rejection(response).await));
            }
            status => {
                log::warn!("ILM answered the sign-in certificate change with {status}");
                return Err(ChangeError::Unexpected(status.as_u16()));
            }
        }
        log::info!(
            "sign-in certificate changed from {} to {}",
            old.map_or_else(|| "none".to_owned(), |held| held.fingerprint.short()),
            fingerprint.short()
        );
        self.switch(
            &who.ilm,
            departing,
            replacement,
            SignInCertificate {
                uuid: matched.uuid.clone(),
                fingerprint,
            },
        )
        .await;
        let locals: Vec<Fingerprint> = local.iter().map(|found| found.fingerprint).collect();
        inventory.check(self, Trigger::Action, &locals).await;
        Ok(())
    }

    /// Notes the sign-in the change starts from, so a later sign-in is never changed with what was read for it.
    fn departing(&self) -> Result<Departing, ChangeError> {
        match &*lock(&self.state) {
            State::SignedIn(active) => Ok(Departing {
                id: active.id.clone(),
                generation: match &active.credential {
                    Credential::Certificate { generation, .. } => Some(generation.clone()),
                    Credential::OAuth(_) => None,
                },
            }),
            _ => Err(ChangeError::SignedOut),
        }
    }

    /// Opens `fingerprint` and presents it to ILM in a handshake before ILM is asked to change anything, so a
    /// certificate that cannot be opened or presented changes nothing; with a certificate sign-in it also keeps
    /// the client for it. Any HTTP answer will do: ILM does not know the certificate as the sign-in one yet.
    async fn prepare_switch(
        &self,
        ilm: &IlmUrl,
        departing: &Departing,
        fingerprint: Fingerprint,
    ) -> Result<Option<(Client, Option<SystemTime>)>, ChangeError> {
        let identity = self
            .in_identities(move |store| store.open(&fingerprint))
            .await
            .ok_or(ChangeError::CannotSignIn)?;
        let not_after = identity::assess(identity.chain()[0].as_ref(), SystemTime::now())
            .ok()
            .map(|found| found.candidate.not_after);
        let (client, _) = (self.certificate_client)(identity);
        if let Err(error) = profile_request(&client, ilm).send().await {
            let kind = if error.is_timeout() {
                "timeout"
            } else if error.is_connect() {
                "connect"
            } else {
                "other"
            };
            log::info!("the new sign-in certificate could not be presented to ILM ({kind})");
            return Err(ChangeError::CannotSignIn);
        }
        if departing.generation.is_none() {
            return Ok(None);
        }
        Ok(Some((client, not_after)))
    }

    /// ILM now knows the person by `certificate`: a certificate sign-in remembers it and presents it from now on.
    async fn switch(
        &self,
        ilm: &IlmUrl,
        departing: Departing,
        replacement: Option<(Client, Option<SystemTime>)>,
        certificate: SignInCertificate,
    ) {
        let _renewing = self.renewing.lock().await;
        let switched = {
            let mut state = lock(&self.state);
            match &mut *state {
                State::SignedIn(active) if Arc::ptr_eq(&active.id, &departing.id) => {
                    active.person.sign_in = Some(certificate.clone());
                    match (&mut active.credential, replacement, departing.generation) {
                        (
                            Credential::Certificate {
                                fingerprint,
                                client,
                                generation,
                                not_after,
                            },
                            Some((new_client, new_end)),
                            Some(old),
                        ) if Arc::ptr_eq(generation, &old) => {
                            *fingerprint = certificate.fingerprint;
                            *client = new_client;
                            *generation = Arc::new(());
                            *not_after = new_end;
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            }
        };
        if !switched {
            return;
        }
        if let Err(error) = self
            .settings
            .save_certificate(ilm, &certificate.fingerprint)
        {
            log::warn!("the certificate could not be remembered for the next start: {error}");
        }
        self.publish();
    }

    /// At start: signs in again with the certificate of the last sign-in, when this computer still has it.
    pub(super) async fn start_with_certificate(
        &self,
        ilm: IlmUrl,
        connection: &Connection,
    ) -> SessionView {
        let Some(fingerprint) = connection
            .certificate
            .filter(|_| connection.method != Some(SignInMethod::Oauth))
        else {
            return self.set(State::signed_out(None));
        };
        log::info!("signing in again with the remembered certificate");
        self.certificate_sign_in(&ilm, fingerprint, None).await
    }

    /// Asks ILM who the person is with the certificate `fingerprint`. `attempt` is the sign-in under way, or none
    /// at start; the person counts as signed in only while that attempt is still the current one.
    async fn certificate_sign_in(
        &self,
        ilm: &IlmUrl,
        fingerprint: Fingerprint,
        attempt: Option<&Arc<Notify>>,
    ) -> SessionView {
        let silent = attempt.is_none();
        let Some(identity) = self
            .in_identities(move |store| store.open(&fingerprint))
            .await
        else {
            if silent {
                return self.fail_attempt(attempt, GONE);
            }
            return self.fail_attempt(attempt, NOT_ON_COMPUTER);
        };
        let not_after = identity::assess(identity.chain()[0].as_ref(), SystemTime::now())
            .ok()
            .map(|found| found.candidate.not_after);
        log::info!("signing in to {ilm} with a certificate");
        let (client, asked) = (self.certificate_client)(identity);
        let response = match profile_request(&client, ilm).send().await {
            Ok(response) => response,
            Err(error) => {
                let problem = match refusal(&error, asked.get() && !error.is_timeout()) {
                    Some(problem) => problem.to_owned(),
                    None if silent => {
                        return self.unreachable_at_start(ilm, IlmError::Unreachable.to_string());
                    }
                    None => IlmError::Unreachable.to_string(),
                };
                return self.fail_attempt(attempt, problem);
            }
        };
        log::info!(
            "the server {} a client certificate",
            if asked.get() {
                "asked for"
            } else {
                "did not ask for"
            }
        );
        if response.status() == StatusCode::UNAUTHORIZED {
            if !asked.get() {
                return self.fail_attempt(attempt, NOT_ASKED);
            }
            let _renewing = self.renewing.lock().await;
            if is_current(&lock(&self.state), attempt) {
                _ = self.forget_certificate_if(&fingerprint);
            }
            return self.end_attempt(attempt, NOT_KNOWN, silent.then_some(Again::Certificate));
        }
        let person = match read_profile(ilm, response).await {
            Ok(person) => person,
            Err(error) if silent => return self.unreachable_at_start(ilm, error.to_string()),
            Err(error) => return self.fail_attempt(attempt, error.to_string()),
        };
        let _renewing = self.renewing.lock().await;
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, attempt);
            if current {
                *state = State::SignedIn(Box::new(Active {
                    id: Arc::new(()),
                    ilm: ilm.clone(),
                    person,
                    unreachable: false,
                    credential: Credential::Certificate {
                        fingerprint,
                        client,
                        generation: Arc::new(()),
                        not_after,
                    },
                }));
            }
            current
        };
        if !current {
            log::info!("the sign-in ended before ILM answered and is not kept");
            return self.view();
        }
        if let Err(error) = self.settings.save_certificate(ilm, &fingerprint) {
            log::warn!("the certificate could not be remembered for the next start: {error}");
        }
        _ = self.delete_item(ilm).await;
        log::info!("signed in to {ilm} with a certificate");
        self.publish()
    }

    /// Sends the request `build` makes with the certificate client, which sends no token. A 401 means ILM no
    /// longer accepts the certificate, and so does its expiry: the person is signed out, with no second try.
    pub(super) async fn call_with_certificate(
        &self,
        build: &(impl Fn(&Client, &IlmUrl) -> RequestBuilder + Sync),
        ilm: &IlmUrl,
        certificate: &CertificateCall,
    ) -> Result<Response, CallError> {
        let CertificateCall {
            client,
            generation,
            fingerprint,
            not_after,
        } = certificate;
        if not_after.is_some_and(|end| SystemTime::now() > end) {
            log::warn!("the certificate has expired");
            self.end_certificate(generation, EXPIRED, fingerprint).await;
            return Err(CallError::SignedOut);
        }
        let response = build(client, ilm).send().await.map_err(|error| {
            log::warn!("ILM could not be reached: {}", error.without_url());
            CallError::Unreachable
        })?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        log::warn!("ILM no longer accepts the certificate");
        self.end_certificate(generation, NOT_KNOWN, fingerprint)
            .await;
        Err(CallError::SignedOut)
    }

    /// Signs out of the certificate sign-in `generation` with `problem`, unless it has ended already, and forgets
    /// `fingerprint` when it is the remembered one.
    pub(super) async fn end_certificate(
        &self,
        generation: &Arc<()>,
        problem: &str,
        fingerprint: &Fingerprint,
    ) {
        let _renewing = self.renewing.lock().await;
        let ended = {
            let mut state = lock(&self.state);
            let current = matches!(
                &*state,
                State::SignedIn(active) if matches!(
                    &active.credential,
                    Credential::Certificate { generation: held, .. } if Arc::ptr_eq(held, generation)
                )
            );
            if current {
                *state = State::SignedOut {
                    problem: Some(problem.to_owned()),
                    again: Some(Again::Certificate),
                };
            }
            current
        };
        if ended {
            log::warn!("{problem}");
            _ = self.forget_certificate_if(fingerprint);
            self.signed_out();
            self.publish();
        }
    }

    /// Forgets the remembered certificate, so the next start does not sign in with it.
    pub(super) fn forget_certificate(&self) -> Result<(), String> {
        self.forgetting(None)
    }

    /// Forgets the remembered certificate when it is `failed`; one remembered since then stays.
    fn forget_certificate_if(&self, failed: &Fingerprint) -> Result<(), String> {
        self.forgetting(Some(failed))
    }

    fn forgetting(&self, failed: Option<&Fingerprint>) -> Result<(), String> {
        self.settings.forget_certificate(failed).map_err(|error| {
            log::warn!("the remembered certificate could not be removed: {error}");
            format!(
                "You are signed out, but the remembered certificate could not be removed: {error}"
            )
        })
    }
}
