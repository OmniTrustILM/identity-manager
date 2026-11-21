//! Adding certificates of this computer to ILM: the upload of the certificate alone, then the update that makes
//! the person its owner and gives it the group and RA Profile they chose.

use std::sync::Arc;

use super::{CallError, ChangeError, Session};
use crate::identity::Fingerprint;
use crate::ilm::profile::profile_request;
use crate::ilm::profile::{IlmError, read_profile};
use crate::ilm::upload::{
    AddError, GroupChoice, RaProfileChoice, groups_request, ra_profiles_request, read_groups,
    read_ra_profiles, read_update, read_upload, update_request, upload_request,
};
use crate::inventory::{Inventory, Status, Trigger};

const NOT_ON_COMPUTER: &str = "This certificate is not on this computer.";
const UNREADABLE: &str = "The certificates on this computer cannot be read.";
const NOT_ALLOWED: &str = "ILM does not allow this.";
const NOT_ACCEPTED: &str = "ILM did not accept the certificate.";
const UNREACHABLE: &str = "ILM cannot be reached.";
/// What a certificate that was not started or not finished says when the application locked meanwhile.
pub(super) const WITHDRAWN: &str = "Unlock Identity Manager first.";
const NOT_SIGNED_IN: &str = "You are not signed in.";

/// How the add of one certificate ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddOutcome {
    /// ILM holds the certificate, owned by the person and with the group and RA Profile chosen.
    Added,
    /// ILM held the certificate already (409); the next check matches it.
    AlreadyInIlm,
    /// ILM holds the certificate, but refused to give it an owner, group or RA Profile; its messages, if any.
    AddedNotManaged(Vec<String>),
    /// Nothing was added; why, in words for the person.
    NotAdded(String),
}

/// The outcome for one fingerprint the person asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddResult {
    pub fingerprint: String,
    pub outcome: AddOutcome,
}

/// What the person may choose from; none when ILM does not let them list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddChoices {
    pub groups: Option<Vec<GroupChoice>>,
    pub ra_profiles: Option<Vec<RaProfileChoice>>,
}

fn not_added(reason: &str) -> AddOutcome {
    AddOutcome::NotAdded(reason.to_owned())
}

fn failure(error: &AddError) -> AddOutcome {
    match error {
        AddError::AlreadyInIlm => AddOutcome::AlreadyInIlm,
        AddError::NotAllowed => not_added(NOT_ALLOWED),
        AddError::Rejected(messages) if messages.is_empty() => not_added(NOT_ACCEPTED),
        AddError::Rejected(messages) => AddOutcome::NotAdded(messages.join(" ")),
        AddError::Failed(IlmError::Unreachable) => not_added(UNREACHABLE),
        AddError::Failed(IlmError::Unauthorized) => not_added(NOT_SIGNED_IN),
        AddError::Failed(IlmError::Unexpected(status)) => {
            AddOutcome::NotAdded(format!("ILM answered with an error ({status})."))
        }
        AddError::Failed(IlmError::Malformed) => {
            not_added("ILM answered in a way this application does not understand.")
        }
    }
}

fn call_failure(error: &CallError) -> AddError {
    AddError::Failed(match error {
        CallError::SignedOut => IlmError::Unauthorized,
        CallError::Unreachable | CallError::Withdrawn => IlmError::Unreachable,
    })
}

/// A call that ended before ILM answered: only an unreachable ILM leaves its choice out, anything else fails the
/// command.
fn call_failure_ilm(error: CallError) -> Result<IlmError, ChangeError> {
    match error {
        CallError::Unreachable => Ok(IlmError::Unreachable),
        other => Err(other.into()),
    }
}

/// The choice read, or none when its listing failed; only a sign-in that ILM does not accept fails the command.
fn choice<T>(read: Result<Option<T>, IlmError>, what: &str) -> Result<Option<T>, ChangeError> {
    match read {
        Ok(choice) => Ok(choice),
        Err(IlmError::Unauthorized) => Err(ChangeError::SignedOut),
        Err(error) => {
            let reason = match error {
                IlmError::Unexpected(status) => format!("status {status}"),
                IlmError::Malformed => "an answer it does not understand".to_owned(),
                _ => "no answer".to_owned(),
            };
            log::warn!("the {what} cannot be listed: {reason}");
            Ok(None)
        }
    }
}

/// The status code behind a failure, for the log.
fn code(error: &AddError) -> String {
    match error {
        AddError::AlreadyInIlm => "409".to_owned(),
        AddError::NotAllowed => "403".to_owned(),
        AddError::Rejected(_) => "400 or 422".to_owned(),
        AddError::Failed(IlmError::Unexpected(status)) => status.to_string(),
        AddError::Failed(_) => "no answer".to_owned(),
    }
}

fn yes_no(chosen: bool) -> &'static str {
    if chosen { "yes" } else { "no" }
}

impl Session {
    /// Adds the certificates of this computer with `fingerprints` to ILM, one at a time. A certificate must be on
    /// this computer; its DER is read from the store of this computer, never taken from the caller. When that
    /// store cannot be read, every certificate ends as `NotAdded` and nothing is sent. ILM is asked as the sign-in that asked, and the person in its profile
    /// becomes the owner of every certificate. `group` and `ra_profile` are UUIDs from [`Session::add_to_ilm_choices`].
    /// A check follows when something was added. A certificate matched by the latest check of `inventory`, or one
    /// ILM already holds (409), ends as `AlreadyInIlm`, which counts as added. `proceed` is asked before each certificate and before each time ILM is asked to
    /// change anything; when it says no, nothing more is sent and the certificates left end as `NotAdded`.
    pub async fn add_to_ilm(
        &self,
        inventory: &Inventory,
        fingerprints: Vec<String>,
        group: Option<String>,
        ra_profile: Option<String>,
        proceed: impl Fn() -> bool + Sync,
    ) -> Result<Vec<AddResult>, ChangeError> {
        let requested = self.departing()?.id;
        let _changing = self.changing.lock().await;
        let id = self.departing()?.id;
        if !Arc::ptr_eq(&id, &requested) {
            return Err(ChangeError::SignedOut);
        }
        let who = self.signed_in_as().ok_or(ChangeError::SignedOut)?;
        if matches!(inventory.status(), Status::Offline { .. }) {
            return Err(ChangeError::Offline);
        }
        let response = self
            .call_ilm_as(Some(&id), Some(&proceed), profile_request)
            .await?;
        let owner = read_profile(&who.ilm, response)
            .await
            .map_err(|error| match error {
                IlmError::Unreachable => ChangeError::Offline,
                IlmError::Unexpected(status) => ChangeError::Unexpected(status),
                IlmError::Unauthorized => ChangeError::SignedOut,
                IlmError::Malformed => ChangeError::Malformed,
            })?
            .uuid;
        log::info!(
            "adding {} certificates to ILM (group chosen: {}, RA Profile chosen: {})",
            fingerprints.len(),
            yes_no(group.is_some()),
            yes_no(ra_profile.is_some())
        );
        let local = match self.in_identities(|store| store.certificates()).await {
            Ok(local) => local,
            Err(error) => {
                log::warn!("the certificates on this computer cannot be read: {error}");
                return Ok(fingerprints
                    .into_iter()
                    .map(|fingerprint| AddResult {
                        fingerprint,
                        outcome: not_added(UNREADABLE),
                    })
                    .collect());
            }
        };
        let locals: Vec<Fingerprint> = local.iter().map(|found| found.fingerprint).collect();
        let snapshot = inventory.snapshot();
        let mut results = Vec::with_capacity(fingerprints.len());
        for text in fingerprints {
            let outcome = match text.parse::<Fingerprint>() {
                _ if !proceed() => not_added(WITHDRAWN),
                Ok(fingerprint) if !locals.contains(&fingerprint) => not_added(NOT_ON_COMPUTER),
                Ok(fingerprint)
                    if snapshot
                        .as_ref()
                        .is_some_and(|snapshot| snapshot.matches.contains_key(&fingerprint)) =>
                {
                    AddOutcome::AlreadyInIlm
                }
                Ok(fingerprint) => {
                    self.add_one(
                        &id,
                        fingerprint,
                        &owner,
                        group.as_deref(),
                        ra_profile.as_deref(),
                        &proceed,
                    )
                    .await
                }
                Err(_) => not_added(NOT_ON_COMPUTER),
            };
            log::info!("a certificate was added to ILM: {}", describe(&outcome));
            results.push(AddResult {
                fingerprint: text,
                outcome,
            });
        }
        if results
            .iter()
            .any(|result| !matches!(result.outcome, AddOutcome::NotAdded(_)))
        {
            inventory.check_local(self, Trigger::Action, &local).await;
        }
        Ok(results)
    }

    async fn add_one(
        &self,
        id: &Arc<()>,
        fingerprint: Fingerprint,
        owner: &str,
        group: Option<&str>,
        ra_profile: Option<&str>,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> AddOutcome {
        let Some(der) = self
            .in_identities(move |store| store.der(&fingerprint))
            .await
        else {
            return not_added(NOT_ON_COMPUTER);
        };
        let response = match self
            .call_ilm_as(Some(id), Some(proceed), |client, ilm| {
                upload_request(client, ilm, &der)
            })
            .await
        {
            Ok(response) => response,
            Err(CallError::Withdrawn) => return not_added(WITHDRAWN),
            Err(error) => return failure(&call_failure(&error)),
        };
        let uuid = match read_upload(response).await {
            Ok(uuid) => uuid,
            Err(error) => {
                log::info!("ILM refused the upload ({})", code(&error));
                return failure(&error);
            }
        };
        let response = match self
            .call_ilm_as(Some(id), Some(proceed), |client, ilm| {
                update_request(client, ilm, &uuid, Some(owner), group, ra_profile)
            })
            .await
        {
            Ok(response) => response,
            Err(CallError::Withdrawn) => {
                return AddOutcome::AddedNotManaged(vec![WITHDRAWN.to_owned()]);
            }
            Err(_) => return AddOutcome::AddedNotManaged(vec![UNREACHABLE.to_owned()]),
        };
        match read_update(response).await {
            Ok(()) => AddOutcome::Added,
            Err(error) => {
                log::info!("ILM refused the update ({})", code(&error));
                match failure(&error) {
                    AddOutcome::NotAdded(reason) => AddOutcome::AddedNotManaged(vec![reason]),
                    _ => AddOutcome::AddedNotManaged(Vec::new()),
                }
            }
        }
    }

    /// The groups and enabled RA Profiles the person may choose from, read now as the person.
    pub async fn add_to_ilm_choices(&self) -> Result<AddChoices, ChangeError> {
        let id = self.departing()?.id;
        let groups = match self.call_ilm_as(Some(&id), None, groups_request).await {
            Ok(response) => read_groups(response).await,
            Err(error) => Err(call_failure_ilm(error)?),
        };
        let ra_profiles = match self.call_ilm_as(Some(&id), None, ra_profiles_request).await {
            Ok(response) => read_ra_profiles(response).await,
            Err(error) => Err(call_failure_ilm(error)?),
        };
        let groups = choice(groups, "groups")?;
        let ra_profiles = choice(ra_profiles, "RA Profiles")?;
        Ok(AddChoices {
            groups,
            ra_profiles,
        })
    }
}

/// The outcome as the log says it: the kind only, never ILM's messages.
fn describe(outcome: &AddOutcome) -> &'static str {
    match outcome {
        AddOutcome::Added => "added",
        AddOutcome::AlreadyInIlm => "already in ILM (409)",
        AddOutcome::AddedNotManaged(_) => "added, not managed",
        AddOutcome::NotAdded(_) => "not added",
    }
}
