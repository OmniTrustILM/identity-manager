//! Revoking a certificate of the person through ILM, and following the revocation until ILM has revoked it.
//!
//! The revocation is written down before ILM is asked. The certificate and its key leave this computer only once
//! ILM says the certificate is revoked, and only when the person asked for that. No subject and no text of ILM
//! goes to the log.

use std::sync::Arc;

use x509_parser::prelude::{FromDer, X509Certificate};

use super::renew::RenewalTarget;
use super::request::{Outcome, REVOKE_SETTLING_MS, may_have_arrived, now_ms, refusal};
use super::{RequestError, Session, lock};
use crate::identity::{Fingerprint, IdentityStore};
use crate::ilm::certificates::{Relation, State};
use crate::ilm::issue::{IssueError, StateError, read_state, state_request};
use crate::ilm::renew::{Reason, read_revoked, revoke_request};
use crate::install::is_for_key;
use crate::requests::{Purpose, Requests, Waiting};

impl Session {
    /// Asks ILM to revoke the certificate for `reason`. The revocation is written down, then sent; when ILM
    /// refuses it, the written revocation is removed. When ILM may have taken it although its answer did not say
    /// so, the written revocation stays and a follow tells. `remove` says whether the certificate and its key are
    /// removed from this computer once ILM has revoked it.
    pub async fn revoke(
        &self,
        target: RenewalTarget<'_>,
        reason: Reason,
        remove: bool,
    ) -> Result<Waiting, RequestError> {
        let id = self.departing()?.id;
        let requests = self.requests.clone().ok_or(RequestError::NoStore)?;
        let old = self
            .read_old(&id, &target)
            .await
            .map_err(|error| match error {
                RequestError::NotRenewable => RequestError::NotRevocable,
                other => other,
            })?;
        let _following = self.following.lock().await;
        let who = self
            .current_sign_in()
            .filter(|who| Arc::ptr_eq(&who.id, &id))
            .ok_or(RequestError::SignedOut)?;
        requests.readable().map_err(|error| {
            log::warn!("the waiting requests cannot be read: {error}");
            RequestError::Store
        })?;
        if requests
            .all()
            .iter()
            .any(|entry| entry.revokes() == Some(target.uuid))
        {
            return Err(RequestError::AlreadyRevoking);
        }
        let entry = Waiting {
            ilm: who.ilm,
            username: who.username,
            uuid: Some(target.uuid.to_owned()),
            ra_profile: old.ra_profile.clone(),
            authority: old.authority.clone(),
            key: None,
            label: target.name.to_owned(),
            since: now_ms(),
            prepared: false,
            purpose: Purpose::Revoke {
                certificate: target.uuid.to_owned(),
                fingerprint: *target.fingerprint,
                remove,
            },
        };
        requests.add(entry.clone()).map_err(|error| {
            log::warn!("the revocation cannot be written down: {error}");
            RequestError::Store
        })?;
        let response = self
            .call_ilm_as(Some(&id), None, |client, ilm| {
                revoke_request(
                    client,
                    ilm,
                    &old.authority,
                    &old.ra_profile,
                    target.uuid,
                    reason,
                )
            })
            .await;
        let sent = match response {
            Ok(response) => read_revoked(response)
                .await
                .inspect_err(log_refusal)
                .map_err(RequestError::from),
            Err(error) => Err(error.into()),
        };
        match sent {
            Ok(()) => {
                log::info!(
                    "revocation sent: {}, {reason:?}, remove: {}",
                    target.uuid,
                    if remove { "yes" } else { "no" }
                );
                Ok(entry)
            }
            Err(error) => {
                if !may_have_arrived(&error)
                    && let Err(error) = requests.remove_revocation(target.uuid)
                {
                    log::warn!("a revocation that failed could not be removed: {error}");
                }
                Err(error)
            }
        }
    }

    /// Asks ILM how the revocation of the certificate of `entry` stands. Once ILM has revoked it, the certificate
    /// and its key are removed from this computer when that was asked; when that fails, nothing is reported and a
    /// later follow tries again. A certificate ILM cannot be asked about now is left as it is.
    pub(super) async fn follow_revocation(
        &self,
        id: &Arc<()>,
        requests: &Requests,
        entry: &Waiting,
    ) -> Option<Outcome> {
        let Purpose::Revoke {
            certificate,
            fingerprint,
            remove,
        } = &entry.purpose
        else {
            return None;
        };
        let response = self
            .call_ilm_as(Some(id), None, |client, ilm| {
                state_request(client, ilm, certificate)
            })
            .await
            .ok()?;
        let found = match read_state(response).await {
            Ok(found) => found,
            Err(StateError::Gone) => {
                log::info!("certificate {certificate} is gone from ILM, its revocation is dropped");
                self.drop_revocation(requests, certificate);
                return None;
            }
            Err(StateError::NotAllowed | StateError::Failed(_)) => return None,
        };
        match found.state {
            State::Revoked => {
                log::info!("certificate {certificate} revoked");
                if *remove
                    && requests
                        .all()
                        .iter()
                        .any(|other| other.renews() == Some(certificate))
                {
                    log::info!("certificate {certificate} stays while a renewal of it waits");
                    return Some(Outcome::Revoking);
                }
                let successor = found.related.iter().any(|related| {
                    matches!(
                        related.relation,
                        Relation::Pending | Relation::Renewal | Relation::Replacement
                    ) && !matches!(related.state, State::Failed | State::Rejected)
                });
                if *remove && !self.remove_revoked(fingerprint, successor).await {
                    return None;
                }
                self.drop_revocation(requests, certificate);
                Some(Outcome::Revoked {
                    fingerprint: *fingerprint,
                })
            }
            State::Issued if now_ms() - entry.since >= REVOKE_SETTLING_MS => {
                log::warn!(
                    "certificate {certificate} is issued again after its revocation was sent"
                );
                self.drop_revocation(requests, certificate);
                Some(Outcome::NotRevoked)
            }
            other => {
                let to = other.code().to_owned();
                let from = lock(&self.seen).insert(certificate.clone(), to.clone());
                if from.as_deref() != Some(to.as_str()) {
                    log::info!("revocation of {certificate}: {to}");
                }
                Some(Outcome::Revoking)
            }
        }
    }

    /// Removes the revoked certificate from this computer, and its key unless another certificate here may be for
    /// it, ILM lists a successor that may share it, or the certificates here cannot be compared; whether it is gone.
    async fn remove_revoked(&self, fingerprint: &Fingerprint, successor: bool) -> bool {
        let _changing = self.changing.lock().await;
        let installer = self.installer.clone();
        let fingerprint = *fingerprint;
        let shared = self
            .in_identities(move |store| key_is_shared(store, &fingerprint))
            .await
            || successor;
        let removed = tokio::task::spawn_blocking(move || installer.remove(&fingerprint, !shared))
            .await
            .expect("the installer task does not panic");
        match removed {
            Ok(()) => {
                log::info!(
                    "certificate removed: {fingerprint}, {}",
                    if shared { "key kept" } else { "key deleted" }
                );
                self.certificate_removed(&fingerprint).await;
                true
            }
            Err(error) => {
                log::warn!("the revoked certificate {fingerprint} cannot be removed: {error}");
                false
            }
        }
    }

    fn drop_revocation(&self, requests: &Requests, certificate: &str) {
        lock(&self.seen).remove(certificate);
        if let Err(error) = requests.remove_revocation(certificate) {
            log::warn!("a revocation could not be removed: {error}");
        }
    }
}

/// Whether another certificate in `store` may be for the key of the certificate `fingerprint`: also when the
/// store, or the certificate of any of them, cannot be read.
fn key_is_shared(store: &dyn IdentityStore, fingerprint: &Fingerprint) -> bool {
    let Ok(held) = store.certificates() else {
        return true;
    };
    let Some(der) = store.der(fingerprint) else {
        return true;
    };
    let Ok((_, parsed)) = X509Certificate::from_der(&der) else {
        return true;
    };
    held.iter()
        .filter(|other| other.fingerprint != *fingerprint)
        .any(|other| {
            store.der(&other.fingerprint).is_none_or(|der| {
                X509Certificate::from_der(&der).is_err()
                    || is_for_key(&der, parsed.public_key().raw)
            })
        })
}

fn log_refusal(error: &IssueError) {
    let messages = match error {
        IssueError::Refused(messages) => messages.len(),
        _ => 0,
    };
    log::warn!(
        "ILM refused the revocation ({}, {messages} messages)",
        refusal(error)
    );
}
