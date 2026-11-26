//! Renewing a certificate of the person through ILM, with a new key or the key the certificate has, and the
//! parts of following a renewal that differ from following a request for a new certificate.
//!
//! The renewal is written down before ILM is asked, so a new key never outlives the knowledge of why it exists.
//! No subject, no key handle and no text of ILM goes to the log.

use std::sync::Arc;
use std::time::SystemTime;

use x509_parser::prelude::{FromDer, X509Certificate};

use super::request::{Outcome, SignedIn, Target, may_have_arrived, now_ms, refusal};
use super::{ChangeError, Credential, RequestError, Session, State as SignIn, lock};
use crate::identity::Fingerprint;
use crate::ilm::certificates::{Relation, State};
use crate::ilm::issue::{IssueError, StateError, read_issued, read_state, state_request};
use crate::ilm::renew::{rekey_request, renew_request};
use crate::install::is_for_key;
use crate::keys::{KeyId, RequestSubject, rekey_subject, signing_request};
use crate::renewal::{Method, RETRY_AFTER};
use crate::requests::{PendingSwitch, Purpose, Requests, Waiting};

/// The installed certificate to renew, as the application knows it.
#[derive(Debug, Clone, Copy)]
pub struct RenewalTarget<'a> {
    /// The UUID ILM gave the certificate.
    pub uuid: &'a str,
    pub fingerprint: &'a Fingerprint,
    /// What the certificate is called.
    pub name: &'a str,
}

/// The certificate to renew as ILM has it.
pub(super) struct Old {
    pub(super) authority: String,
    pub(super) ra_profile: String,
    der: Vec<u8>,
    /// Whether ILM lists a successor that is not issued yet.
    successor_pending: bool,
    /// Whether ILM lists a successor that is issued.
    successor_issued: bool,
}

impl Session {
    /// Renews the certificate with a new key made as `method` says, or with the key it has. The renewal is written
    /// down, then sent; when ILM does not take it, the new key and the written renewal are removed and, for an
    /// `automatic` renewal, the failed attempt is noted so the next one waits. Nothing is sent while a renewal of
    /// the certificate is under way, here or in ILM.
    pub async fn renew(
        &self,
        target: RenewalTarget<'_>,
        method: Method,
        automatic: bool,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Result<Waiting, RequestError> {
        let id = self.departing()?.id;
        let requests = self.requests.clone().ok_or(RequestError::NoStore)?;
        let _following = self.following.lock().await;
        let who = self
            .current_sign_in()
            .filter(|who| Arc::ptr_eq(&who.id, &id))
            .ok_or(RequestError::SignedOut)?;
        let (ilm, username) = (who.ilm.clone(), who.username.clone());
        if automatic && self.failed_recently(&ilm, &username, target.fingerprint) {
            return Err(RequestError::AlreadyRenewing);
        }
        let sent = self
            .renew_locked(&id, who, &requests, &target, method, automatic, proceed)
            .await;
        if let Err(error) = &sent
            && automatic
            && !matches!(
                error,
                RequestError::AlreadyRenewing
                    | RequestError::AlreadyRevoking
                    | RequestError::SignedOut
                    | RequestError::Offline
                    | RequestError::Withdrawn
            )
        {
            self.record_failure(&ilm, &username, target.fingerprint);
        }
        sent
    }

    /// Checks that the certificate may be renewed, then sends the renewal.
    #[allow(clippy::too_many_arguments)]
    async fn renew_locked(
        &self,
        id: &Arc<()>,
        who: SignedIn,
        requests: &Requests,
        target: &RenewalTarget<'_>,
        method: Method,
        automatic: bool,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Result<Waiting, RequestError> {
        let old = self.read_old(id, target).await?;
        if old.successor_pending || (automatic && old.successor_issued) {
            return Err(RequestError::AlreadyRenewing);
        }
        requests.readable().map_err(|error| {
            log::warn!("the waiting requests cannot be read: {error}");
            RequestError::Store
        })?;
        let waiting = requests.all();
        if waiting
            .iter()
            .any(|entry| entry.renews() == Some(target.uuid))
        {
            return Err(RequestError::AlreadyRenewing);
        }
        if waiting
            .iter()
            .any(|entry| entry.revokes() == Some(target.uuid))
        {
            return Err(RequestError::AlreadyRevoking);
        }
        self.send_renewal(id, who, requests, &old, target, method, automatic, proceed)
            .await
    }

    /// The certificate as ILM has it, when ILM and this computer agree that it is the one to renew or revoke.
    pub(super) async fn read_old(
        &self,
        id: &Arc<()>,
        target: &RenewalTarget<'_>,
    ) -> Result<Old, RequestError> {
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, target.uuid)
            })
            .await?;
        let found = read_state(response).await.map_err(|error| match error {
            StateError::Gone => RequestError::NotRenewable,
            StateError::NotAllowed => RequestError::NotAllowed,
            StateError::Failed(error) => error.into(),
        })?;
        let (Some(der), Some(profile)) = (found.content, found.ra_profile) else {
            return Err(RequestError::NotRenewable);
        };
        let Some(authority) = profile.authority_uuid else {
            return Err(RequestError::NotRenewable);
        };
        if found.state != State::Issued || Fingerprint::of(&der) != *target.fingerprint {
            return Err(RequestError::NotRenewable);
        }
        let successor_pending = found.related.iter().any(|related| {
            matches!(
                related.state,
                State::Requested | State::PendingApproval | State::PendingIssue
            )
        });
        let successor_issued = found
            .related
            .iter()
            .any(|related| related.state == State::Issued && related.relation != Relation::Pending);
        Ok(Old {
            authority,
            ra_profile: profile.uuid,
            der,
            successor_pending,
            successor_issued,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_renewal(
        &self,
        id: &Arc<()>,
        who: SignedIn,
        requests: &Requests,
        old: &Old,
        target: &RenewalTarget<'_>,
        method: Method,
        automatic: bool,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Result<Waiting, RequestError> {
        let subject = match method {
            Method::NewKey { .. } => rekey_subject(&old.der),
            Method::SameKey => None,
        };
        let new_key = match (method, subject) {
            (Method::NewKey { storage, key_type }, Some(subject)) => {
                let key = self
                    .in_keys(move |keys| keys.create(storage, key_type))
                    .await?;
                Some((key, subject))
            }
            (Method::NewKey { .. }, None) => {
                log::info!(
                    "certificate {} cannot be renewed with a new key; the key it has is kept",
                    target.uuid
                );
                None
            }
            (Method::SameKey, _) => None,
        };
        let key_id = new_key.as_ref().map(|(key, _)| key.id().clone());
        let entry = Waiting {
            ilm: who.ilm,
            username: who.username,
            uuid: None,
            ra_profile: old.ra_profile.clone(),
            authority: old.authority.clone(),
            key: key_id.clone(),
            label: target.name.to_owned(),
            since: now_ms(),
            prepared: false,
            purpose: Purpose::Renew {
                replaces: target.uuid.to_owned(),
                replaces_fingerprint: *target.fingerprint,
                sign_in: self.signs_in_with(target.uuid, target.fingerprint),
                switch: None,
                same_key: key_id.is_none(),
                automatic,
            },
        };
        let sent = self
            .deliver(id, requests, old, target.uuid, entry, new_key, proceed)
            .await;
        match &sent {
            Err(error) if key_id.is_some() && may_have_arrived(error) => {
                log::info!(
                    "the renewal of {} may have reached ILM; its key is kept for a follow",
                    target.uuid
                );
            }
            Err(_) => {
                self.drop_renewal(requests, target.uuid, key_id.as_ref())
                    .await;
            }
            Ok(_) => {}
        }
        sent
    }

    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        old: &Old,
        replaces: &str,
        entry: Waiting,
        new_key: Option<(Box<dyn crate::keys::StoredKey>, RequestSubject)>,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Result<Waiting, RequestError> {
        requests.add(entry.clone()).map_err(|error| {
            log::warn!("the renewal cannot be written down: {error}");
            RequestError::Store
        })?;
        let same_key = new_key.is_none();
        let response = match new_key {
            Some((key, subject)) => {
                let request_der =
                    tokio::task::spawn_blocking(move || signing_request(key.as_ref(), &subject))
                        .await
                        .expect("the key storage task does not panic")?;
                self.call_ilm_as(Some(id), Some(proceed), |client, ilm| {
                    rekey_request(
                        client,
                        ilm,
                        &old.authority,
                        &old.ra_profile,
                        replaces,
                        &request_der,
                    )
                })
                .await?
            }
            None => {
                self.call_ilm_as(Some(id), Some(proceed), |client, ilm| {
                    renew_request(client, ilm, &old.authority, &old.ra_profile, replaces)
                })
                .await?
            }
        };
        let uuid = read_issued(response).await.inspect_err(log_refusal)?;
        log::info!(
            "renewal sent: {replaces} → {uuid}, {}",
            if same_key { "same key" } else { "new key" }
        );
        let written = match &entry.key {
            Some(key) => requests.set_uuid(key, &uuid),
            None => requests.set_renewal_uuid(replaces, &uuid),
        };
        if let Err(error) = written {
            log::warn!("the certificate of the renewal cannot be written down: {error}");
        }
        Ok(Waiting {
            uuid: Some(uuid),
            ..entry
        })
    }

    /// Deletes the new key and the written renewal of one that did not come about. The written renewal stays when
    /// the key cannot be deleted, so a later follow tries again.
    async fn drop_renewal(&self, requests: &Requests, replaces: &str, key: Option<&KeyId>) {
        match key {
            Some(key) => {
                self.forget(requests, key, "a renewal that failed").await;
            }
            None => {
                if let Err(error) = requests.remove_renewal(replaces) {
                    log::warn!("a renewal that failed could not be removed: {error}");
                }
            }
        }
    }

    /// Whether the person signs in with the certificate: ILM knows the person by it, or this sign-in presents it.
    pub(super) fn signs_in_with(&self, uuid: &str, fingerprint: &Fingerprint) -> bool {
        match &*lock(&self.state) {
            SignIn::SignedIn(active) => {
                active
                    .person
                    .sign_in
                    .as_ref()
                    .is_some_and(|held| held.uuid == uuid || held.fingerprint == *fingerprint)
                    || matches!(
                        &active.credential,
                        Credential::Certificate { fingerprint: held, .. } if held == fingerprint
                    )
            }
            _ => false,
        }
    }

    /// Moves the sign-in to the installed certificate `new` of a renewal that asks for it. `Err` holds the number
    /// of failures so far, `failures` and this one; the renewal then stays, with the move pending. A failure of
    /// ILM or of this computer to take part counts; being signed out or offline does not.
    pub(super) async fn move_over(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
        new: Fingerprint,
        failures: u8,
    ) -> Result<(), u8> {
        let Purpose::Renew {
            replaces,
            replaces_fingerprint,
            sign_in: true,
            ..
        } = &entry.purpose
        else {
            return Ok(());
        };
        let Some(uuid) = entry.uuid.as_deref() else {
            return Ok(());
        };
        let error = match self
            .move_sign_in(id, uuid, new, (replaces, replaces_fingerprint))
            .await
        {
            Ok(()) => {
                log::info!("sign-in moved to {uuid}");
                return Ok(());
            }
            Err(ChangeError::AlreadySignIn) => return Ok(()),
            Err(error) => error,
        };
        let counted = !matches!(error, ChangeError::SignedOut | ChangeError::Offline);
        let failures = failures.saturating_add(u8::from(counted));
        log::warn!(
            "the sign-in cannot move to {uuid} ({}), failure {failures}",
            match &error {
                ChangeError::Rejected(_) => "ILM did not accept it".to_owned(),
                other => other.to_string(),
            }
        );
        let pending = PendingSwitch {
            fingerprint: new,
            failures,
        };
        if let Err(error) = requests.set_switch(replaces, pending) {
            log::warn!("the pending sign-in move cannot be written down: {error}");
        }
        Err(failures)
    }

    /// Tries again to move the sign-in to the renewed certificate an earlier follow installed.
    pub(super) async fn retry_switch(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
        pending: PendingSwitch,
    ) -> Outcome {
        let fingerprint = pending.fingerprint;
        let gone = self
            .in_identities(move |store| {
                store
                    .certificates()
                    .is_ok_and(|held| held.iter().all(|found| found.fingerprint != fingerprint))
            })
            .await;
        if gone {
            log::info!(
                "the renewed certificate {} is no longer on this computer; its sign-in move is dropped",
                entry.uuid.as_deref().unwrap_or("unknown")
            );
            if let Err(error) = self.remove_entry(requests, entry) {
                log::warn!("a renewal could not be removed: {error}");
            }
            return Outcome::SignInMoved;
        }
        match self
            .move_over(id, requests, entry, pending.fingerprint, pending.failures)
            .await
        {
            Ok(()) => {
                if let Err(error) = self.remove_entry(requests, entry) {
                    log::warn!("a renewal could not be removed: {error}");
                }
                Outcome::SignInMoved
            }
            Err(failures) => Outcome::SwitchPending { failures },
        }
    }

    /// The certificate ILM made for the new key of a renewal whose answer was lost: among the successors of the
    /// old certificate that are not over, the one that is for the key. Its UUID is written down.
    pub(super) async fn find_successor(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
    ) -> Option<String> {
        let (Purpose::Renew { replaces, .. }, Some(key)) = (&entry.purpose, &entry.key) else {
            return None;
        };
        let key_id = key.clone();
        let public_key = self
            .in_keys(move |keys| keys.open(&key_id))
            .await
            .ok()??
            .public_key()
            .to_vec();
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, replaces)
            })
            .await
            .ok()?;
        let old = read_state(response).await.ok()?;
        for related in old.related.iter().filter(|related| {
            !matches!(
                related.state,
                State::Failed | State::Rejected | State::Revoked
            )
        }) {
            let response = self
                .call_ilm_as(Some(id), None, |client, ilm| {
                    state_request(client, ilm, &related.uuid)
                })
                .await
                .ok()?;
            let Some(leaf) = read_state(response)
                .await
                .ok()
                .and_then(|found| found.content)
            else {
                continue;
            };
            if is_for_key(&leaf, &public_key) {
                log::info!(
                    "the renewal of {replaces} was taken by ILM as {}",
                    related.uuid
                );
                if let Err(error) = requests.set_uuid(key, &related.uuid) {
                    log::warn!("the certificate of the renewal cannot be written down: {error}");
                }
                return Some(related.uuid.clone());
            }
        }
        None
    }

    /// Decides where the certificate of a renewal with the key it has is installed: beside the old one, when it
    /// is for the key of the old one. `Err` is what the follow reports; none when it can only try again later.
    pub(super) async fn beside_target(
        &self,
        id: &Arc<()>,
        entry: &Waiting,
        leaf: &[u8],
    ) -> Result<Target, Option<Outcome>> {
        let Purpose::Renew {
            replaces,
            replaces_fingerprint,
            ..
        } = &entry.purpose
        else {
            return Err(None);
        };
        let Ok(response) = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, replaces)
            })
            .await
        else {
            return Err(None);
        };
        let Some(old) = read_state(response)
            .await
            .ok()
            .and_then(|found| found.content)
        else {
            return Err(None);
        };
        let same_key = Fingerprint::of(&old) == *replaces_fingerprint
            && X509Certificate::from_der(&old)
                .is_ok_and(|(_, parsed)| is_for_key(leaf, parsed.public_key().raw));
        if same_key {
            Ok(Target::Beside(*replaces_fingerprint))
        } else {
            log::warn!("the certificate {replaces} was renewed with another key than its own");
            Err(Some(Outcome::Mismatch))
        }
    }

    /// The new certificate of a renewal is installed: the switch of automatic renewal moves to it, and the
    /// failed attempt of the old one is forgotten.
    pub(super) fn renewed(&self, entry: &Waiting, new: &Fingerprint) {
        let Purpose::Renew {
            replaces,
            replaces_fingerprint,
            ..
        } = &entry.purpose
        else {
            return;
        };
        log::info!("renewal installed: {replaces}");
        if let Some(renewals) = &self.renewals
            && let Err(error) =
                renewals.carry(&entry.ilm, &entry.username, replaces_fingerprint, new)
        {
            log::warn!("the renewal switch cannot be moved: {error}");
        }
    }

    /// An automatic renewal ended without a certificate: the next automatic attempt waits.
    pub(super) fn note_failed_attempt(&self, entry: &Waiting) {
        if let Purpose::Renew {
            replaces_fingerprint,
            automatic: true,
            ..
        } = &entry.purpose
        {
            self.record_failure(&entry.ilm, &entry.username, replaces_fingerprint);
        }
    }

    /// Whether an automatic attempt on the certificate failed less than [`RETRY_AFTER`] ago.
    fn failed_recently(
        &self,
        ilm: &crate::ilm::IlmUrl,
        username: &str,
        certificate: &Fingerprint,
    ) -> bool {
        self.renewals
            .as_ref()
            .and_then(|renewals| renewals.last_failure(ilm, username, certificate))
            .is_some_and(|failed| {
                SystemTime::now()
                    .duration_since(failed)
                    .map_or(true, |ago| ago < RETRY_AFTER)
            })
    }

    fn record_failure(&self, ilm: &crate::ilm::IlmUrl, username: &str, certificate: &Fingerprint) {
        if let Some(renewals) = &self.renewals
            && let Err(error) =
                renewals.record_failure(ilm, username, certificate, SystemTime::now())
        {
            log::warn!("the failed renewal cannot be noted: {error}");
        }
    }
}

fn log_refusal(error: &IssueError) {
    let messages = match error {
        IssueError::Refused(messages) => messages.len(),
        _ => 0,
    };
    log::warn!(
        "ILM refused the renewal ({}, {messages} messages)",
        refusal(error)
    );
}
