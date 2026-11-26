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
use super::attributes::Form;
use super::{CallError, ChangeError, FormError, FormInput, Session, State as SignIn, lock};
use crate::attributes::{Definitions, FieldProblem, FormContext, FormView, Values, request};
use crate::identity::Fingerprint;
use crate::ilm::IlmUrl;
use crate::ilm::certificates::State;
use crate::ilm::issue::{
    Challenge, IssueBody, IssueError, StateError, chain_request, complete_request, issue_request,
    read_chain, read_issued, read_state, state_request,
};
use crate::ilm::profile::IlmError;
use crate::ilm::upload::{RaProfileChoice, ra_profiles_request, read_ra_profiles};
use crate::install::{intermediates, is_for_key};
use crate::inventory::{SubjectPart, subject_parts};
use crate::keys::{
    KeyError, KeyId, KeyStorage, KeyType, NameType, RequestSubject, Storage, Unmappable,
    registered_subject, signing_request, subject,
};
use crate::requests::{Purpose, Requests, Waiting};

const DAY_MS: i64 = 86_400_000;
/// How long ILM may take to attach a request to a certificate registered in advance that it was just given one
/// for.
const SETTLING_MS: i64 = 5 * 60_000;
/// How long ILM may take to start a revocation it has accepted.
pub(super) const REVOKE_SETTLING_MS: i64 = 10 * 60_000;
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

/// The certificate registered in advance that is completed, and the RA Profile it is completed under.
pub struct Completion<'a> {
    pub uuid: &'a str,
    /// The name to show the request by when the subject has no common name.
    pub name: &'a str,
    pub ra_profile: &'a RaProfileChoice,
    /// The subject the person reviewed; the request is not sent when ILM now registers another one.
    pub subject: &'a [SubjectPart],
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
    /// ILM registered another subject for the certificate than the one the person reviewed.
    SubjectChanged,
    /// The certificate cannot be renewed: ILM does not know it as this one, or it has no RA Profile.
    NotRenewable,
    /// A renewal of the certificate is under way already.
    AlreadyRenewing,
    /// The certificate cannot be revoked: ILM does not know it as this one, or it has no RA Profile.
    NotRevocable,
    /// A revocation of the certificate is under way already.
    AlreadyRevoking,
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
            Self::SubjectChanged => {
                f.write_str("Your administrator changed this certificate in ILM. Open it again.")
            }
            Self::NotRenewable => f.write_str("This certificate cannot be renewed."),
            Self::AlreadyRenewing => f.write_str("This certificate is being renewed already."),
            Self::NotRevocable => f.write_str("This certificate cannot be revoked."),
            Self::AlreadyRevoking => f.write_str("This certificate is being revoked already."),
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
    Installed(Installed),
    Ended(EndReason),
    /// ILM issued a certificate for another key; nothing is installed.
    Mismatch,
    /// The installation failed; the request stays, and the next follow tries again.
    InstallFailed,
    /// A renewed certificate is installed but the sign-in has not moved over to it; each follow tries again.
    SwitchPending {
        failures: u8,
    },
    /// The sign-in has moved over to the renewed certificate that an earlier follow installed.
    SignInMoved,
    /// ILM has not finished revoking the certificate, or waits for an approval.
    Revoking,
    /// ILM revoked the certificate, and it is removed from this computer when that was asked.
    Revoked {
        fingerprint: Fingerprint,
    },
    /// The certificate is issued again after the revocation was sent: ILM did not revoke it.
    NotRevoked,
}

/// How many failures to move the sign-in over make the person's help needed.
pub const SWITCH_FAILURES_BEFORE_NOTICE: u8 = 3;

/// What an installed certificate is: where its key is kept, and until when it is valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// Where the key is kept; none when the renewal kept the key of the old certificate.
    pub storage: Option<Storage>,
    /// Milliseconds since 1970 UTC.
    pub not_after: i64,
}

/// A request that was followed, and how it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Followed {
    pub uuid: Option<String>,
    pub label: String,
    pub outcome: Outcome,
    /// The installed certificate a renewal replaces.
    pub replaces: Option<Fingerprint>,
}

impl Followed {
    /// The key of the notice that a renewal failed, when this renewal did: it ended without a certificate or the
    /// certificate cannot be installed. The notice is cleared when a later renewal of the certificate succeeds.
    pub fn failed_notice_key(&self) -> Option<String> {
        let failed = matches!(
            self.outcome,
            Outcome::Ended(_) | Outcome::Mismatch | Outcome::InstallFailed
        );
        self.replaces
            .filter(|_| failed)
            .map(|old| format!("renewal:failed:{old}"))
    }

    /// The key of the notice that a renewal cannot renew itself, when the sign-in could not move over to its
    /// certificate often enough.
    pub fn needs_notice_key(&self) -> Option<String> {
        let stuck = matches!(
            self.outcome,
            Outcome::SwitchPending { failures } if failures >= SWITCH_FAILURES_BEFORE_NOTICE
        );
        self.replaces
            .filter(|_| stuck)
            .map(|old| format!("renewal:needs:{old}"))
    }
}

impl Followed {
    /// The key of the notice that a revocation failed, when it did.
    pub fn revoke_failed_notice_key(&self) -> Option<String> {
        match (&self.outcome, &self.uuid) {
            (Outcome::NotRevoked, Some(uuid)) => Some(format!("revoke:failed:{uuid}")),
            _ => None,
        }
    }

    /// The key of the notice that a certificate was revoked in ILM, when this follow saw a revocation made here: the
    /// person asked for it, so the notice is not needed.
    pub fn revoked_notice_key(&self) -> Option<String> {
        match &self.outcome {
            Outcome::Revoked { fingerprint } => Some(format!("certificate:revoked:{fingerprint}")),
            _ => None,
        }
    }
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

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

fn yes_no(chosen: bool) -> &'static str {
    if chosen { "yes" } else { "no" }
}

impl Session {
    /// The enabled RA Profiles the person may ask for a certificate; those without an authority are left out,
    /// because ILM's issuing paths name it.
    pub async fn request_profiles(&self) -> Result<Vec<RaProfileChoice>, RequestError> {
        let id = self.departing()?.id;
        let response = self
            .call_ilm_as(Some(&id), None, ra_profiles_request)
            .await?;
        let listed = read_ra_profiles(response).await?;
        Ok(listed
            .unwrap_or_default()
            .into_iter()
            .filter(|profile| profile.authority_uuid.is_some())
            .collect())
    }

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
        let subject = self.request_subject(forms.request.as_ref())?;
        let generation = self.forms.generation();
        let mut taken = Vec::new();
        let attributes = self
            .take(forms.request.as_ref(), &mut taken)
            .and_then(|_| self.take_attributes(&forms, &mut taken));
        let attributes = self.reopen_on_error(attributes, &mut taken, generation)?;
        let order = Order {
            ra_profile,
            authority,
            storage,
            key_type,
            subject,
            registered: None,
            label: &ra_profile.name,
        };
        let sent = self.submit(&id, &requests, &order, &attributes).await;
        self.reopen_on_error(sent, &mut taken, generation)
    }

    /// Completes the certificate registered in advance with a new key. Its subject is what ILM registered. A
    /// challenge ILM asks for is held for this call only.
    pub async fn complete(
        &self,
        completion: Completion<'_>,
        forms: RequestInput,
        storage: Storage,
        key_type: KeyType,
        challenge: Option<Challenge>,
    ) -> Result<Waiting, RequestError> {
        let Completion {
            uuid,
            name,
            ra_profile,
            subject: reviewed,
        } = completion;
        let authority = ra_profile
            .authority_uuid
            .as_deref()
            .ok_or(RequestError::NoAuthority)?;
        let id = self.departing()?.id;
        let requests = self.requests.clone().ok_or(RequestError::NoStore)?;
        self.check_forms(&[forms.issue.as_ref(), forms.custom.as_ref()])?;
        let registered = self.registered(&id, uuid).await?;
        let subject = registered_subject(
            registered.subject_dn.as_deref(),
            &registered.alternative_names,
        )?;
        if subject_parts(&subject) != reviewed {
            return Err(RequestError::SubjectChanged);
        }
        let generation = self.forms.generation();
        let mut taken = Vec::new();
        let attributes = self.take_attributes(&forms, &mut taken);
        let attributes = self.reopen_on_error(attributes, &mut taken, generation)?;
        let order = Order {
            ra_profile,
            authority,
            storage,
            key_type,
            subject,
            registered: Some((uuid, challenge.as_ref())),
            label: name,
        };
        let sent = self.submit(&id, &requests, &order, &attributes).await;
        self.reopen_on_error(sent, &mut taken, generation)
    }

    /// The subject the request form gives, read without closing the form; empty without one.
    fn request_subject(&self, form: Option<&FormInput>) -> Result<RequestSubject, RequestError> {
        let Some(form) = form else {
            return Ok(RequestSubject::default());
        };
        let definitions = self
            .form_definitions(&form.id)
            .map_err(|_| ChangeError::FormGone)?;
        let values = sendable(&definitions, form)?;
        Ok(subject(&definitions.fields, &values)?)
    }

    /// Whether every form given can be sent; none is closed.
    fn check_forms(&self, forms: &[Option<&FormInput>]) -> Result<(), RequestError> {
        for form in forms.iter().flatten() {
            self.checked_form(form)?;
        }
        Ok(())
    }

    /// Closes the form and gives out its definitions and values, when it can be sent; the closed form is added to
    /// `taken`.
    fn take(
        &self,
        form: Option<&FormInput>,
        taken: &mut Vec<Form>,
    ) -> Result<Option<(Definitions, Values)>, RequestError> {
        form.map(|form| {
            let (closed, definitions, values) = self
                .take_form_if(&form.id, ChangeError::FormGone, |definitions| {
                    sendable(definitions, form)
                })
                .map_err(RequestError::from)?;
            taken.push(closed);
            Ok((definitions, values))
        })
        .transpose()
    }

    /// Opens the `taken` forms again when `result` is a failure, so the person can correct the request and send it
    /// again; not when every form was closed meanwhile, as by a lock.
    fn reopen_on_error<T>(
        &self,
        result: Result<T, RequestError>,
        taken: &mut Vec<Form>,
        generation: u64,
    ) -> Result<T, RequestError> {
        if result.is_err() {
            self.forms.restore(std::mem::take(taken), generation);
        }
        result
    }

    fn take_attributes(
        &self,
        forms: &RequestInput,
        taken: &mut Vec<Form>,
    ) -> Result<Attributes, RequestError> {
        let attributes = |taken: Option<(Definitions, Values)>| {
            taken.map_or_else(Vec::new, |(definitions, values)| {
                request(&definitions.fields, &values)
            })
        };
        Ok(Attributes {
            issue: attributes(self.take(forms.issue.as_ref(), taken)?),
            custom: attributes(self.take(forms.custom.as_ref(), taken)?),
        })
    }

    /// The identity ILM registered for `certificate`, which must be waiting to be completed.
    async fn registered(
        &self,
        id: &Arc<()>,
        uuid: &str,
    ) -> Result<crate::ilm::issue::IssuedState, RequestError> {
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, uuid)
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
    /// followed. No follow runs meanwhile, so it never takes up a request still being sent. A certificate an earlier
    /// request of the person is still completing is not sent again.
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
        requests.readable().map_err(|error| {
            log::warn!("the waiting requests cannot be read: {error}");
            RequestError::Store
        })?;
        if let Some((uuid, _)) = order.registered
            && requests
                .of(&who.ilm, &who.username)
                .iter()
                .any(|entry| entry.uuid.as_deref() == Some(uuid))
        {
            return Err(RequestError::NotRegistered);
        }
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
            uuid: order.registered.map(|(uuid, _)| uuid.to_owned()),
            ra_profile: order.ra_profile.uuid.clone(),
            authority: order.authority.to_owned(),
            key: Some(key_id.clone()),
            label,
            since: now_ms(),
            prepared: order.registered.is_some(),
            purpose: Purpose::Issue,
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
            Some((uuid, challenge)) => {
                self.call_ilm_as(Some(id), None, |client, ilm| {
                    complete_request(
                        client,
                        ilm,
                        order.authority,
                        ra_profile,
                        uuid,
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
        if let Err(error) = requests.set_uuid(&key_id, &uuid) {
            log::warn!("the certificate of the request cannot be written down: {error}");
        }
        Ok(Waiting {
            uuid: Some(uuid),
            ..entry
        })
    }

    /// Deletes the key and the written request of one that did not come about. The written request stays when
    /// the key cannot be deleted, so a later follow tries again.
    async fn discard(&self, requests: &Requests, key: &KeyId) {
        self.forget(requests, key, "a request that failed").await;
    }

    /// Deletes the key of `entry`, if it has one, and then its written request; a request without a key is only
    /// removed.
    async fn forget_entry(&self, requests: &Requests, entry: &Waiting, what: &str) -> bool {
        match (&entry.key, entry.renews()) {
            (Some(key), _) => self.forget(requests, key, what).await,
            (None, Some(replaces)) => {
                if let Err(error) = requests.remove_renewal(replaces) {
                    log::warn!("{what} could not be removed: {error}");
                }
                true
            }
            (None, None) => true,
        }
    }

    /// Deletes `key`, and the written request of it only when the key is gone. Whether it is, is the answer.
    pub(super) async fn forget(&self, requests: &Requests, key: &KeyId, what: &str) -> bool {
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
    pub(super) fn current_sign_in(&self) -> Option<SignedIn> {
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

    /// The requests of the person signed in that wait for ILM; none while nobody is signed in.
    pub fn waiting_requests(&self) -> Vec<Waiting> {
        match (&self.requests, self.current_sign_in()) {
            (Some(requests), Some(who)) => requests.of(&who.ilm, &who.username),
            _ => Vec::new(),
        }
    }

    /// Follows every request of the person signed in: asks ILM how each stands, installs the certificate of one
    /// that is issued, and removes the key and the request of one that has ended. A request ILM cannot be asked
    /// about now is left as it is and not reported. Two follows never run at once.
    pub async fn follow(&self) -> Vec<Followed> {
        let _following = self.following.lock().await;
        let (Some(requests), Some(who)) = (self.requests.clone(), self.current_sign_in()) else {
            return Vec::new();
        };
        requests.save_pending();
        let mut found = Vec::new();
        for mut entry in requests.of(&who.ilm, &who.username) {
            let followed = if matches!(entry.purpose, Purpose::Revoke { .. }) {
                self.follow_revocation(&who.id, &requests, &entry).await
            } else {
                self.follow_one(&who.id, &requests, &mut entry).await
            };
            if let Some(outcome) = followed {
                found.push(Followed {
                    replaces: entry.replaces_fingerprint(),
                    uuid: entry.uuid,
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
        entry: &mut Waiting,
    ) -> Option<Outcome> {
        if let Some(pending) = entry.pending_switch() {
            return Some(self.retry_switch(id, requests, entry, pending).await);
        }
        let age = now_ms() - entry.since;
        if entry.uuid.is_none() {
            entry.uuid = self.find_successor(id, requests, entry).await;
        }
        let entry = &*entry;
        let Some(uuid) = entry.uuid.as_deref() else {
            return if age >= DAY_MS {
                self.end(requests, entry, EndReason::NotSent).await
            } else {
                None
            };
        };
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, uuid)
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
                Some(leaf) => self.install(id, requests, entry, uuid, leaf).await,
                None => Some(self.waiting(uuid, State::Issued)),
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
            other => Some(self.waiting(uuid, other)),
        }
    }

    /// Notes the state of a certificate that is still being made, and logs it when it changed.
    fn waiting(&self, uuid: &str, state: State) -> Outcome {
        let to = state.code().to_owned();
        let from = lock(&self.seen).insert(uuid.to_owned(), to.clone());
        if from.as_deref() != Some(to.as_str()) {
            log::info!(
                "request {uuid}: {} → {to}",
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
        let uuid = entry.uuid.as_deref().unwrap_or("not sent");
        if !self
            .forget_entry(requests, entry, &format!("request {uuid}"))
            .await
        {
            return None;
        }
        log::info!("request {uuid} ended: {}", reason.text());
        self.note_failed_attempt(entry);
        if let Some(uuid) = &entry.uuid {
            lock(&self.seen).remove(uuid);
        }
        Some(Outcome::Ended(reason))
    }

    /// Installs the certificate ILM issued, when it is the one for the key of the request.
    async fn install(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
        uuid: &str,
        leaf: Vec<u8>,
    ) -> Option<Outcome> {
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                chain_request(client, ilm, uuid)
            })
            .await
            .ok()?;
        let chain = read_chain(response).await.ok()?;
        let Ok((_, parsed)) = X509Certificate::from_der(&leaf) else {
            log::warn!("the certificate of request {uuid} cannot be read");
            return None;
        };
        let not_after = parsed.validity().not_after.timestamp() * 1000;
        let target = match &entry.key {
            Some(key_id) => {
                let key_id = key_id.clone();
                let opened = self.in_keys(move |keys| keys.open(&key_id)).await;
                let key = match opened {
                    Ok(Some(key)) => key,
                    Ok(None) => return self.end(requests, entry, EndReason::KeyGone).await,
                    Err(error) => {
                        log::warn!("the key of request {uuid} cannot be opened: {error}");
                        return None;
                    }
                };
                if !is_for_key(&leaf, key.public_key()) {
                    log::warn!("the certificate {uuid} is not for the key of its request");
                    return Some(Outcome::Mismatch);
                }
                Target::Key(entry.key.clone()?)
            }
            None => match self.beside_target(id, entry, &leaf).await {
                Ok(target) => target,
                Err(outcome) => return outcome,
            },
        };
        let chain = intermediates(chain);
        let count = chain.len();
        let installer = self.installer.clone();
        let installed_leaf = leaf.clone();
        let installed = tokio::task::spawn_blocking(move || match &target {
            Target::Key(key_id) => installer.install(key_id, &installed_leaf, &chain),
            Target::Beside(old) => installer.install_beside(old, &installed_leaf, &chain),
        })
        .await
        .expect("the installer task does not panic");
        if let Err(error) = installed {
            log::warn!("the certificate {uuid} could not be installed: {error}");
            return Some(Outcome::InstallFailed);
        }
        let storage = entry.key.as_ref().map(|key| key.storage);
        let place = storage.map_or_else(|| "same key".to_owned(), |storage| format!("{storage:?}"));
        log::info!("certificate installed: {uuid}, {place}, {count} intermediates");
        lock(&self.seen).remove(uuid);
        let new = Fingerprint::of(&leaf);
        self.renewed(entry, &new);
        if self.move_over(id, requests, entry, new, 0).await.is_ok()
            && let Err(error) = self.remove_entry(requests, entry)
        {
            log::warn!("request {uuid} could not be removed: {error}");
        }
        Some(Outcome::Installed(Installed { storage, not_after }))
    }

    pub(super) fn remove_entry(&self, requests: &Requests, entry: &Waiting) -> std::io::Result<()> {
        match (&entry.key, entry.renews()) {
            (Some(key), _) => requests.remove(key),
            (None, Some(replaces)) => requests.remove_renewal(replaces),
            (None, None) => entry.revokes().map_or(Ok(()), |certificate| {
                requests.remove_revocation(certificate)
            }),
        }
    }
}

/// Where an issued certificate is installed.
pub(super) enum Target {
    /// With the key of the request.
    Key(KeyId),
    /// Beside the installed certificate, whose key it shares.
    Beside(Fingerprint),
}

/// Who is signed in, with the sign-in they are.
pub(super) struct SignedIn {
    pub(super) ilm: IlmUrl,
    pub(super) username: String,
    pub(super) id: Arc<()>,
}

/// Whether ILM may have taken a request although its answer did not say so.
pub(super) fn may_have_arrived(error: &RequestError) -> bool {
    matches!(
        error,
        RequestError::Offline | RequestError::Unexpected(_) | RequestError::Malformed
    )
}

/// The status behind a refusal, for the log; never ILM's text.
pub(super) fn refusal(error: &IssueError) -> String {
    match error {
        IssueError::Refused(_) => "refused".to_owned(),
        IssueError::NotAllowed => "403".to_owned(),
        IssueError::Failed(IlmError::Unexpected(status)) => status.to_string(),
        IssueError::Failed(_) => "no answer".to_owned(),
    }
}
