//! Signing in with a certificate of this computer: the list, the proof in the handshake, the silent start.

use std::error::Error;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tokio::sync::Notify;

use super::{
    Active, CONNECT_FIRST, CallError, CertificateCall, CertificateChoice, Connection, Credential,
    Session, SessionView, SignInKind, State, is_current, lock,
};
use crate::identity::{self, Fingerprint, IdentityStore, is_signing_refused};
use crate::ilm::IlmUrl;
use crate::ilm::profile::{IlmError, profile_request, read_profile};
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

pub(super) fn certificate_choice() -> ProviderChoice {
    ProviderChoice {
        id: CERTIFICATE_ID.to_owned(),
        name: CERTIFICATE_NAME.to_owned(),
    }
}

fn epoch_millis(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |after| {
        i64::try_from(after.as_millis()).unwrap_or(i64::MAX)
    })
}

/// What to tell the person when the request could not be answered. A connection that fails after the server
/// asked for the certificate counts as a refusal: some systems report the gateway's alert as a reset connection.
fn request_problem(error: &(dyn Error + 'static), asked: bool) -> String {
    if is_signing_refused(error) {
        KEY_REFUSED.to_owned()
    } else if asked || handshake_refused(error) {
        HANDSHAKE_REFUSED.to_owned()
    } else {
        IlmError::Unreachable.to_string()
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
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
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
            return self.set(State::SignedOut { problem: None });
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
            Err(error) => return self.fail_attempt(attempt, request_problem(&error, asked.get())),
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
            return self.fail_attempt(attempt, NOT_KNOWN);
        }
        let person = match read_profile(ilm, response).await {
            Ok(person) => person,
            Err(error) => return self.fail_attempt(attempt, error.to_string()),
        };
        let _renewing = self.renewing.lock().await;
        let current = {
            let mut state = lock(&self.state);
            let current = is_current(&state, attempt);
            if current {
                *state = State::SignedIn(Box::new(Active {
                    ilm: ilm.clone(),
                    person,
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
                };
            }
            current
        };
        if ended {
            log::warn!("{problem}");
            _ = self.forget_certificate_if(fingerprint);
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
