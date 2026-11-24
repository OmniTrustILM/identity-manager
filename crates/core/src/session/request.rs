//! Asking ILM for a certificate with a key made in a key storage of this computer, completing a certificate
//! registered in advance, and following what is asked until it is installed or has ended.
//!
//! The request is written down before ILM is asked, so a key never outlives the knowledge of why it exists. No
//! value of a form, no challenge and no text of ILM goes to the log.

use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::add_to_ilm::sendable;
use super::{CallError, ChangeError, FormError, FormInput, Session, State as SignIn, lock};
use crate::attributes::{Definitions, FieldProblem, FormContext, FormView, Values, request};
use crate::ilm::IlmUrl;
use crate::ilm::certificates::State;
use crate::ilm::issue::{
    Challenge, IssueBody, IssueError, StateError, chain_request, complete_request, issue_request,
    read_chain, read_issued, read_state, state_request,
};
use crate::ilm::profile::IlmError;
use crate::ilm::upload::RaProfileChoice;
use crate::keys::{
    KeyError, KeyId, KeyStorage, KeyType, NameType, RequestSubject, Storage, Unmappable,
    registered_subject, signing_request, subject,
};
use crate::requests::{Requests, Waiting};

const DAY_MS: i64 = 86_400_000;
/// How long ILM may take to attach a request to a certificate registered in advance that it was just given one
/// for.
const SETTLING_MS: i64 = 5 * 60_000;
const NOT_ALLOWED: &str = "ILM does not allow this.";

/// The forms of one request for a certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestForms {
    /// The request attributes; none for a certificate registered in advance, whose subject is ILM's, or when ILM
    /// does not give any.
    pub request: Option<FormView>,
    pub issue: Option<FormView>,
    pub custom: Option<FormView>,
}

/// The forms the person filled in.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RequestInput {
    pub request: Option<FormInput>,
    pub issue: Option<FormInput>,
    pub custom: Option<FormInput>,
}

/// Why a request for a certificate was not made. The text is for the person.
#[derive(Debug, PartialEq, Eq)]
pub enum RequestError {
    SignedOut,
    Offline,
    /// This application has nowhere to keep the requests.
    NoStore,
    /// ILM did not say which authority the RA Profile belongs to.
    NoAuthority,
    FormGone,
    FormBlocked,
    FormValues,
    FormProblems(Vec<FieldProblem>),
    Unmappable(Unmappable),
    Key(KeyError),
    /// The certificate is not one registered in advance and waiting to be completed.
    NotRegistered,
    NotAllowed,
    /// ILM refused the request and says why.
    Refused(Vec<String>),
    Unexpected(u16),
    Malformed,
    /// The request could not be written down.
    Store,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignedOut => CallError::SignedOut.fmt(f),
            Self::Offline => f.write_str("ILM cannot be reached."),
            Self::NoStore => f.write_str("Requests cannot be kept on this computer."),
            Self::NoAuthority => {
                f.write_str("ILM did not say which authority this RA Profile is of.")
            }
            Self::FormGone => f.write_str("This form is no longer open. Open it again."),
            Self::FormBlocked => f.write_str("This form needs ILM's web interface."),
            Self::FormValues => f.write_str("The values of this form cannot be read."),
            Self::FormProblems(_) => {
                f.write_str("The form has problems. Correct them and try again.")
            }
            Self::Unmappable(reason) => reason.fmt(f),
            Self::Key(KeyError::Refused) => f.write_str("The key storage refused."),
            Self::Key(_) => f.write_str("The key could not be created."),
            Self::NotRegistered => f.write_str("This certificate is not waiting to be completed."),
            Self::NotAllowed => f.write_str(NOT_ALLOWED),
            Self::Refused(messages) if messages.is_empty() => {
                f.write_str("ILM did not accept the request.")
            }
            Self::Refused(messages) => f.write_str(&messages.join(" ")),
            Self::Unexpected(status) => write!(f, "ILM answered with an error ({status})."),
            Self::Malformed => {
                f.write_str("ILM answered in a way this application does not understand.")
            }
            Self::Store => f.write_str("The request could not be recorded on this computer."),
        }
    }
}

impl std::error::Error for RequestError {}

impl From<ChangeError> for RequestError {
    fn from(error: ChangeError) -> Self {
        match error {
            ChangeError::SignedOut => Self::SignedOut,
            ChangeError::Offline | ChangeError::Withdrawn => Self::Offline,
            ChangeError::FormGone => Self::FormGone,
            ChangeError::FormBlocked => Self::FormBlocked,
            ChangeError::FormValues => Self::FormValues,
            ChangeError::FormProblems(problems) => Self::FormProblems(problems),
            ChangeError::NotAllowed => Self::NotAllowed,
            ChangeError::Rejected(messages) => Self::Refused(messages),
            ChangeError::Unexpected(status) => Self::Unexpected(status),
            // The other changes are about certificates and never come from a form.
            _ => Self::Malformed,
        }
    }
}

impl From<CallError> for RequestError {
    fn from(error: CallError) -> Self {
        match error {
            CallError::SignedOut => Self::SignedOut,
            CallError::Unreachable | CallError::Withdrawn => Self::Offline,
        }
    }
}

impl From<IlmError> for RequestError {
    fn from(error: IlmError) -> Self {
        match error {
            IlmError::Unauthorized => Self::SignedOut,
            IlmError::Unreachable => Self::Offline,
            IlmError::Unexpected(status) => Self::Unexpected(status),
            IlmError::Malformed => Self::Malformed,
        }
    }
}

impl From<IssueError> for RequestError {
    fn from(error: IssueError) -> Self {
        match error {
            IssueError::Refused(messages) => Self::Refused(messages),
            IssueError::NotAllowed => Self::NotAllowed,
            IssueError::Failed(error) => error.into(),
        }
    }
}

impl From<KeyError> for RequestError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<Unmappable> for RequestError {
    fn from(error: Unmappable) -> Self {
        Self::Unmappable(error)
    }
}

/// Why a request ended without a certificate on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndReason {
    Rejected,
    Failed,
    /// The certificate registered in advance is waiting again, so the request is gone.
    ReturnedToRegistered,
    /// ILM does not list the certificate, a day after the request.
    Gone,
    /// The request never reached ILM.
    NotSent,
    /// The key of the request is not in the storage any more.
    KeyGone,
    /// A state this application does not wait for; its code.
    Other(String),
}

impl EndReason {
    /// What the log calls it.
    fn text(&self) -> &str {
        match self {
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::ReturnedToRegistered => "registered again",
            Self::Gone => "gone from ILM",
            Self::NotSent => "not sent",
            Self::KeyGone => "key gone",
            Self::Other(code) => code,
        }
    }
}

/// How a request stands after a follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// ILM is still working on it.
    Waiting(State),
    /// The certificate is installed and the request is done.
    Installed,
    Ended(EndReason),
    /// ILM issued a certificate for another key; nothing is installed.
    Mismatch,
    /// The installation failed; the request stays, and the next follow tries again.
    InstallFailed,
}

/// A request that was followed, and how it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followed {
    pub certificate: Option<String>,
    pub label: String,
    pub outcome: Outcome,
}

/// What a request or a completion asks of ILM.
struct Order<'a> {
    ra_profile: &'a RaProfileChoice,
    authority: &'a str,
    storage: Storage,
    key_type: KeyType,
    subject: RequestSubject,
    /// For a certificate registered in advance: its UUID and the challenge, if it has one.
    registered: Option<(&'a str, Option<&'a Challenge>)>,
    /// The label when the subject has no common name.
    label: &'a str,
}

/// The attributes of the forms that were sent.
struct Attributes {
    issue: Vec<Value>,
    custom: Vec<Value>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

fn yes_no(chosen: bool) -> &'static str {
    if chosen { "yes" } else { "no" }
}

impl Session {
    /// Opens the forms of a request to the RA Profile `ra_profile` of `authority`. A certificate registered in
    /// advance (`prepared`) has no request form, because its subject is ILM's.
    pub async fn open_request_forms(
        &self,
        authority: &str,
        ra_profile: &str,
        prepared: bool,
    ) -> Result<RequestForms, FormError> {
        let generation = self.forms.generation();
        let mut opened = RequestForms {
            request: None,
            issue: None,
            custom: None,
        };
        let result = self
            .open_into(&mut opened, authority, ra_profile, prepared, generation)
            .await;
        if let Err(error) = result {
            for form in [&opened.request, &opened.issue, &opened.custom]
                .into_iter()
                .flatten()
            {
                self.close_form(&form.id);
            }
            return Err(error);
        }
        Ok(opened)
    }

    async fn open_into(
        &self,
        opened: &mut RequestForms,
        authority: &str,
        ra_profile: &str,
        prepared: bool,
        generation: u64,
    ) -> Result<(), FormError> {
        let in_profile = |context: fn(String, String) -> FormContext| {
            context(authority.to_owned(), ra_profile.to_owned())
        };
        if !prepared {
            let context = in_profile(|authority, ra_profile| FormContext::Request {
                authority,
                ra_profile,
            });
            opened.request = self.open_form_since(context, generation).await?;
        }
        let context = in_profile(|authority, ra_profile| FormContext::Issue {
            authority,
            ra_profile,
        });
        opened.issue = self.open_form_since(context, generation).await?;
        opened.custom = self
            .open_form_since(FormContext::Custom, generation)
            .await?;
        Ok(())
    }

    /// Asks `ra_profile` for a new certificate with a key made in `storage`. The forms are checked before
    /// anything is made; then the key is made, the request signed and written down, and ILM asked. When anything
    /// after the key fails, the key and the written request are removed.
    pub async fn request(
        &self,
        ra_profile: &RaProfileChoice,
        forms: RequestInput,
        storage: Storage,
        key_type: KeyType,
    ) -> Result<Waiting, RequestError> {
        let authority = ra_profile
            .authority_uuid
            .as_deref()
            .ok_or(RequestError::NoAuthority)?;
        let id = self.departing()?.id;
        let requests = self.requests.clone().ok_or(RequestError::NoStore)?;
        self.check_forms(&[
            forms.request.as_ref(),
            forms.issue.as_ref(),
            forms.custom.as_ref(),
        ])?;
        let from_request = self.take(forms.request.as_ref())?;
        let attributes = self.take_attributes(&forms)?;
        let subject = match &from_request {
            Some((definitions, values)) => subject(&definitions.fields, values)?,
            None => RequestSubject::default(),
        };
        let order = Order {
            ra_profile,
            authority,
            storage,
            key_type,
            subject,
            registered: None,
            label: &ra_profile.name,
        };
        self.submit(&id, &requests, &order, &attributes).await
    }

    /// Completes the certificate registered in advance with a new key. Its subject is what ILM registered. A
    /// challenge ILM asks for is held for this call only.
    pub async fn complete(
        &self,
        certificate: &str,
        ra_profile: &RaProfileChoice,
        forms: RequestInput,
        storage: Storage,
        key_type: KeyType,
        challenge: Option<Challenge>,
    ) -> Result<Waiting, RequestError> {
        let authority = ra_profile
            .authority_uuid
            .as_deref()
            .ok_or(RequestError::NoAuthority)?;
        let id = self.departing()?.id;
        let requests = self.requests.clone().ok_or(RequestError::NoStore)?;
        self.check_forms(&[forms.issue.as_ref(), forms.custom.as_ref()])?;
        let registered = self.registered(&id, certificate).await?;
        let subject = registered_subject(
            registered.subject_dn.as_deref(),
            &registered.alternative_names,
        )?;
        let attributes = self.take_attributes(&forms)?;
        let order = Order {
            ra_profile,
            authority,
            storage,
            key_type,
            subject,
            registered: Some((certificate, challenge.as_ref())),
            label: certificate,
        };
        self.submit(&id, &requests, &order, &attributes).await
    }

    /// Whether every form given can be sent; none is closed.
    fn check_forms(&self, forms: &[Option<&FormInput>]) -> Result<(), RequestError> {
        for form in forms.iter().flatten() {
            self.checked_form(form)?;
        }
        Ok(())
    }

    /// Closes the form and gives out its definitions and values, when it can be sent.
    fn take(
        &self,
        form: Option<&FormInput>,
    ) -> Result<Option<(Definitions, Values)>, RequestError> {
        form.map(|form| {
            self.take_form_if(&form.id, ChangeError::FormGone, |definitions| {
                sendable(definitions, form)
            })
            .map_err(RequestError::from)
        })
        .transpose()
    }

    fn take_attributes(&self, forms: &RequestInput) -> Result<Attributes, RequestError> {
        let attributes = |taken: Option<(Definitions, Values)>| {
            taken.map_or_else(Vec::new, |(definitions, values)| {
                request(&definitions.fields, &values)
            })
        };
        Ok(Attributes {
            issue: attributes(self.take(forms.issue.as_ref())?),
            custom: attributes(self.take(forms.custom.as_ref())?),
        })
    }

    /// The identity ILM registered for `certificate`, which must be waiting to be completed.
    async fn registered(
        &self,
        id: &Arc<()>,
        certificate: &str,
    ) -> Result<crate::ilm::issue::IssuedState, RequestError> {
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, certificate)
            })
            .await?;
        let found = read_state(response).await.map_err(|error| match error {
            StateError::Gone => RequestError::NotRegistered,
            StateError::NotAllowed => RequestError::NotAllowed,
            StateError::Failed(error) => error.into(),
        })?;
        if found.state == State::Registered {
            Ok(found)
        } else {
            Err(RequestError::NotRegistered)
        }
    }

    /// Makes the key, then signs and sends the request; anything that fails after the key exists removes the key
    /// and the written request, except a completion whose answer was lost: its certificate is known, so it is
    /// followed. No follow runs meanwhile, so it never takes up a request still being sent.
    async fn submit(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        order: &Order<'_>,
        attributes: &Attributes,
    ) -> Result<Waiting, RequestError> {
        let _following = self.following.lock().await;
        let who = self
            .current_sign_in()
            .filter(|who| Arc::ptr_eq(&who.id, id))
            .ok_or(RequestError::SignedOut)?;
        let (storage, key_type) = (order.storage, order.key_type);
        let key = self
            .in_keys(move |keys| keys.create(storage, key_type))
            .await?;
        let key_id = key.id().clone();
        let sent = self
            .sign_and_send(id, who, requests, order, attributes, key)
            .await;
        match &sent {
            Err(error) if order.registered.is_some() && may_have_arrived(error) => {
                log::info!("the answer to a completion was lost; the request is followed");
            }
            Err(_) => self.discard(requests, &key_id).await,
            Ok(_) => {}
        }
        sent
    }

    async fn sign_and_send(
        &self,
        id: &Arc<()>,
        who: SignedIn,
        requests: &Requests,
        order: &Order<'_>,
        attributes: &Attributes,
        key: Box<dyn crate::keys::StoredKey>,
    ) -> Result<Waiting, RequestError> {
        let key_id = key.id().clone();
        let label = order
            .subject
            .names
            .iter()
            .find(|(kind, _)| *kind == NameType::CommonName)
            .map_or_else(|| order.label.to_owned(), |(_, name)| name.clone());
        let entry = Waiting {
            ilm: who.ilm,
            username: who.username,
            certificate: order
                .registered
                .map(|(certificate, _)| certificate.to_owned()),
            ra_profile: order.ra_profile.uuid.clone(),
            authority: order.authority.to_owned(),
            key: key_id.clone(),
            label,
            since: now_ms(),
            prepared: order.registered.is_some(),
        };
        requests.add(entry.clone()).map_err(|error| {
            log::warn!("the request cannot be written down: {error}");
            RequestError::Store
        })?;
        let subject = order.subject.clone();
        let request_der =
            tokio::task::spawn_blocking(move || signing_request(key.as_ref(), &subject))
                .await
                .expect("the key storage task does not panic")?;
        let body = IssueBody {
            request_der,
            attributes: attributes.issue.clone(),
            custom_attributes: attributes.custom.clone(),
        };
        let ra_profile = &order.ra_profile.uuid;
        let response = match order.registered {
            None => {
                self.call_ilm_as(Some(id), None, |client, ilm| {
                    issue_request(client, ilm, order.authority, ra_profile, &body)
                })
                .await?
            }
            Some((certificate, challenge)) => {
                self.call_ilm_as(Some(id), None, |client, ilm| {
                    complete_request(
                        client,
                        ilm,
                        order.authority,
                        ra_profile,
                        certificate,
                        &body,
                        challenge,
                    )
                })
                .await?
            }
        };
        let uuid = read_issued(response).await.inspect_err(|error| {
            log::info!("ILM did not take the request ({})", refusal(error));
        })?;
        log::info!(
            "request sent: RA Profile {ra_profile}, {:?}, {:?}, prepared: {}",
            order.storage,
            order.key_type,
            yes_no(order.registered.is_some())
        );
        if let Err(error) = requests.set_certificate(&key_id, &uuid) {
            log::warn!("the certificate of the request cannot be written down: {error}");
        }
        Ok(Waiting {
            certificate: Some(uuid),
            ..entry
        })
    }

    /// Deletes the key and the written request of one that did not come about. The written request stays when
    /// the key cannot be deleted, so a later follow tries again.
    async fn discard(&self, requests: &Requests, key: &KeyId) {
        self.forget(requests, key, "a request that failed").await;
    }

    /// Deletes `key`, and the written request of it only when the key is gone. Whether it is, is the answer.
    async fn forget(&self, requests: &Requests, key: &KeyId, what: &str) -> bool {
        let id = key.clone();
        if let Err(error) = self.in_keys(move |keys| keys.delete(&id)).await {
            log::warn!("the key of {what} could not be deleted: {error}");
            return false;
        }
        if let Err(error) = requests.remove(key) {
            log::warn!("{what} could not be removed: {error}");
        }
        true
    }

    /// Who is signed in, and the sign-in they are, read together.
    fn current_sign_in(&self) -> Option<SignedIn> {
        match &*lock(&self.state) {
            SignIn::SignedIn(active) => Some(SignedIn {
                ilm: active.ilm.clone(),
                username: active.person.username.clone(),
                id: active.id.clone(),
            }),
            _ => None,
        }
    }

    /// Runs `work` on the key storage where it may block.
    pub(super) async fn in_keys<T: Send + 'static>(
        &self,
        work: impl FnOnce(&dyn KeyStorage) -> T + Send + 'static,
    ) -> T {
        let keys = self.keys.clone();
        tokio::task::spawn_blocking(move || work(keys.as_ref()))
            .await
            .expect("the key storage task does not panic")
    }

    /// Follows every request of the person signed in: asks ILM how each stands, installs the certificate of one
    /// that is issued, and removes the key and the request of one that has ended. A request ILM cannot be asked
    /// about now is left as it is and not reported. Two follows never run at once.
    pub async fn follow(&self) -> Vec<Followed> {
        let _following = self.following.lock().await;
        let (Some(requests), Some(who)) = (self.requests.clone(), self.current_sign_in()) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in requests.of(&who.ilm, &who.username) {
            if let Some(outcome) = self.follow_one(&who.id, &requests, &entry).await {
                found.push(Followed {
                    certificate: entry.certificate,
                    label: entry.label,
                    outcome,
                });
            }
        }
        found
    }

    async fn follow_one(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
    ) -> Option<Outcome> {
        let age = now_ms() - entry.since;
        let Some(certificate) = entry.certificate.as_deref() else {
            return if age >= DAY_MS {
                self.end(requests, entry, EndReason::NotSent).await
            } else {
                None
            };
        };
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, certificate)
            })
            .await
            .ok()?;
        let found = match read_state(response).await {
            Ok(found) => found,
            Err(StateError::Gone | StateError::NotAllowed) => {
                return if age >= DAY_MS {
                    self.end(requests, entry, EndReason::Gone).await
                } else {
                    None
                };
            }
            Err(StateError::Failed(_)) => return None,
        };
        match found.state {
            State::Issued => match found.content {
                Some(leaf) => self.install(id, requests, entry, certificate, leaf).await,
                None => Some(self.waiting(certificate, State::Issued)),
            },
            State::Failed => self.end(requests, entry, EndReason::Failed).await,
            State::Rejected => self.end(requests, entry, EndReason::Rejected).await,
            State::Revoked => {
                let reason = EndReason::Other(State::Revoked.code().to_owned());
                self.end(requests, entry, reason).await
            }
            State::Registered
                if entry.prepared && !found.request_attached && age >= SETTLING_MS =>
            {
                self.end(requests, entry, EndReason::ReturnedToRegistered)
                    .await
            }
            other => Some(self.waiting(certificate, other)),
        }
    }

    /// Notes the state of a certificate that is still being made, and logs it when it changed.
    fn waiting(&self, certificate: &str, state: State) -> Outcome {
        let to = state.code().to_owned();
        let from = lock(&self.seen).insert(certificate.to_owned(), to.clone());
        if from.as_deref() != Some(to.as_str()) {
            log::info!(
                "request {certificate}: {} → {to}",
                from.as_deref().unwrap_or("sent")
            );
        }
        Outcome::Waiting(state)
    }

    /// The request is over: its key and its record go. When the key cannot be deleted the record stays, nothing
    /// is reported, and a later follow tries again.
    async fn end(
        &self,
        requests: &Requests,
        entry: &Waiting,
        reason: EndReason,
    ) -> Option<Outcome> {
        let uuid = entry.certificate.as_deref().unwrap_or("not sent");
        if !self
            .forget(requests, &entry.key, &format!("request {uuid}"))
            .await
        {
            return None;
        }
        log::info!("request {uuid} ended: {}", reason.text());
        if let Some(certificate) = &entry.certificate {
            lock(&self.seen).remove(certificate);
        }
        Some(Outcome::Ended(reason))
    }

    /// Installs the certificate ILM issued, when it is the one for the key of the request.
    async fn install(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
        certificate: &str,
        leaf: Vec<u8>,
    ) -> Option<Outcome> {
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                chain_request(client, ilm, certificate)
            })
            .await
            .ok()?;
        let chain = read_chain(response).await.ok()?;
        let key_id = entry.key.clone();
        let opened = self.in_keys(move |keys| keys.open(&key_id)).await;
        let key = match opened {
            Ok(Some(key)) => key,
            Ok(None) => return self.end(requests, entry, EndReason::KeyGone).await,
            Err(error) => {
                log::warn!("the key of request {certificate} cannot be opened: {error}");
                return None;
            }
        };
        let Ok((_, parsed)) = X509Certificate::from_der(&leaf) else {
            log::warn!("the certificate of request {certificate} cannot be read");
            return None;
        };
        if parsed.public_key().raw != key.public_key() {
            log::warn!("the certificate {certificate} is not for the key of its request");
            return Some(Outcome::Mismatch);
        }
        let intermediates = chain.len();
        let installer = self.installer.clone();
        let key_id = entry.key.clone();
        let installed =
            tokio::task::spawn_blocking(move || installer.install(&key_id, &leaf, &chain))
                .await
                .expect("the installer task does not panic");
        if let Err(error) = installed {
            log::warn!("the certificate {certificate} could not be installed: {error}");
            return Some(Outcome::InstallFailed);
        }
        log::info!(
            "certificate installed: {certificate}, {:?}, {intermediates} intermediates",
            entry.key.storage
        );
        lock(&self.seen).remove(certificate);
        if let Err(error) = requests.remove(&entry.key) {
            log::warn!("request {certificate} could not be removed: {error}");
        }
        Some(Outcome::Installed)
    }
}

/// Who is signed in, with the sign-in they are.
struct SignedIn {
    ilm: IlmUrl,
    username: String,
    id: Arc<()>,
}

/// Whether ILM may have taken a request although its answer did not say so.
fn may_have_arrived(error: &RequestError) -> bool {
    matches!(
        error,
        RequestError::Offline | RequestError::Unexpected(_) | RequestError::Malformed
    )
}

/// The status behind a refusal, for the log; never ILM's text.
fn refusal(error: &IssueError) -> String {
    match error {
        IssueError::Refused(_) => "refused".to_owned(),
        IssueError::NotAllowed => "403".to_owned(),
        IssueError::Failed(IlmError::Unexpected(status)) => status.to_string(),
        IssueError::Failed(_) => "no answer".to_owned(),
    }
}
