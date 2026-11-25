//! The certificates ILM registered for the person in advance, which the person completes with a key of this
//! computer: what ILM says of each, kept with the snapshot.

use serde::{Deserialize, Serialize};

use super::{Failure, read_search, send};
use crate::ilm::certificates::{RaProfile, RegistrationState, Search, State};
use crate::ilm::issue::{Registration, StateError, read_state, state_request};
use crate::ilm::profile::IlmError;
use crate::keys::{AlternativeName, NameType, RequestSubject, registered_subject};
use crate::requests::Waiting;
use crate::session::{EndReason, Followed, Outcome, Session};

/// What a name of a subject is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum SubjectKind {
    CommonName,
    Organization,
    OrganizationalUnit,
    Country,
    State,
    Locality,
    Email,
    SerialNumber,
    DomainComponent,
    /// Any other attribute type; its OBJECT IDENTIFIER is in the part.
    Other,
    Dns,
    Ip,
    Uri,
    Upn,
}

/// One name of the subject or of the alternative names of a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct SubjectPart {
    pub kind: SubjectKind,
    pub value: String,
    /// The OBJECT IDENTIFIER, as dotted numbers, of an attribute of kind `other` and of an email in the subject
    /// name, which tells it from an email among the alternative names.
    pub oid: Option<String>,
}

impl SubjectPart {
    pub fn new(kind: SubjectKind, value: &str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
            oid: None,
        }
    }
}

/// A certificate registered in advance for the person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prepared {
    pub uuid: String,
    pub name: String,
    pub ra_profile: RaProfile,
    /// None when ILM did not say, or the person may not read the certificate.
    pub registration: Option<Registration>,
    /// What ILM registered, from the most general name down, then the alternative names.
    pub subject: Vec<SubjectPart>,
}

impl Prepared {
    /// Whether the registration still allows the certificate to be completed at `now`, milliseconds since 1970
    /// UTC: ILM refuses an expired or a locked one.
    pub fn is_open_at(&self, now: i64) -> bool {
        self.registration.as_ref().is_none_or(|registration| {
            !matches!(
                registration.state,
                RegistrationState::Expired | RegistrationState::Locked
            ) && registration.expires_at.is_none_or(|expiry| expiry > now)
        })
    }
}

/// The attribute type of an email in a subject name (PKCS #9 emailAddress).
const EMAIL_ADDRESS: &str = "1.2.840.113549.1.9.1";

/// The names of `subject` as the interface shows them, in order: the subject first, then the alternative names.
pub fn subject_parts(subject: &RequestSubject) -> Vec<SubjectPart> {
    let names = subject.names.iter().map(|(kind, value)| {
        let (kind, oid) = match kind {
            NameType::CommonName => (SubjectKind::CommonName, None),
            NameType::Organization => (SubjectKind::Organization, None),
            NameType::OrganizationalUnit => (SubjectKind::OrganizationalUnit, None),
            NameType::Country => (SubjectKind::Country, None),
            NameType::State => (SubjectKind::State, None),
            NameType::Locality => (SubjectKind::Locality, None),
            NameType::Email => (SubjectKind::Email, Some(EMAIL_ADDRESS.to_owned())),
            NameType::SerialNumber => (SubjectKind::SerialNumber, None),
            NameType::DomainComponent => (SubjectKind::DomainComponent, None),
            NameType::Other(arcs) => (
                SubjectKind::Other,
                Some(
                    arcs.iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join("."),
                ),
            ),
        };
        SubjectPart {
            kind,
            value: value.clone(),
            oid,
        }
    });
    let alternatives = subject.alternative_names.iter().map(|name| {
        let (kind, value) = match name {
            AlternativeName::Dns(value) => (SubjectKind::Dns, value.clone()),
            AlternativeName::Email(value) => (SubjectKind::Email, value.clone()),
            AlternativeName::Upn(value) => (SubjectKind::Upn, value.clone()),
            AlternativeName::Ip(address) => (SubjectKind::Ip, address.to_string()),
            AlternativeName::Uri(value) => (SubjectKind::Uri, value.clone()),
        };
        SubjectPart::new(kind, &value)
    });
    names.chain(alternatives).collect()
}

/// Whether one of the requests `waiting` completes the certificate `uuid` registered in advance.
pub(super) fn is_begun(uuid: &str, waiting: &[Waiting]) -> bool {
    waiting
        .iter()
        .any(|entry| entry.uuid.as_deref() == Some(uuid))
}

/// Leaves out of `prepared` the certificates a request `found` by a follow has completed, not one still waiting or
/// registered again; the next check of ILM lists them anew. Gives whether any was left out.
pub(super) fn drop_completed(prepared: &mut Vec<Prepared>, found: &[Followed]) -> bool {
    let before = prepared.len();
    prepared.retain(|certificate| {
        !found.iter().any(|request| {
            request.uuid.as_deref() == Some(certificate.uuid.as_str())
                && !matches!(
                    request.outcome,
                    Outcome::Waiting(_) | Outcome::Ended(EndReason::ReturnedToRegistered)
                )
        })
    });
    prepared.len() != before
}

/// The certificates registered in advance for `username`: the first page of ILM's search, each read for its
/// registration and subject. Only what the person can issue is kept: a certificate the person may not read, ILM
/// does not know any more, is no longer registered when it is read, or whose subject this application cannot write
/// into a request is left out.
pub(super) async fn read(session: &Session, username: &str) -> Result<Vec<Prepared>, Failure> {
    let search = Search::registered(username);
    let page = match read_search(session, &search).await {
        Ok(page) => page,
        Err(Failure::Ilm(IlmError::Unexpected(403))) => {
            log::debug!("registered certificates are not listed for this person");
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut found = Vec::new();
    for certificate in page.certificates {
        let Some(ra_profile) = certificate
            .ra_profile
            .filter(|profile| profile.authority_uuid.is_some())
        else {
            continue;
        };
        let uuid = certificate.uuid;
        let response = send(session, |client, ilm| state_request(client, ilm, &uuid)).await?;
        let (registration, subject) = match read_state(response).await {
            Ok(state) if state.state != State::Registered => continue,
            Ok(state) => {
                match registered_subject(state.subject_dn.as_deref(), &state.alternative_names) {
                    Ok(subject) => (state.registration, subject_parts(&subject)),
                    Err(_) => {
                        log::debug!("the subject of a registered certificate cannot be written");
                        continue;
                    }
                }
            }
            Err(StateError::Gone | StateError::NotAllowed) => continue,
            Err(StateError::Failed(error)) => return Err(error.into()),
        };
        found.push(Prepared {
            uuid,
            name: certificate.name,
            ra_profile,
            registration,
            subject,
        });
    }
    Ok(found)
}
