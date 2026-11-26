//! Renewal at each check of ILM: which certificates are renewed now, what the person has to be told about the
//! others, and what the screens show of it. Nothing of this happens where the system has no installer.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use super::view::RenewalView;
use super::{Held, Status, held};
use crate::app_info::Platform;
use crate::identity::{Fingerprint, LocalCertificate};
use crate::ilm::IlmUrl;
use crate::ilm::certificates::{IlmCertificate, Relation, State};
use crate::ilm::issue::IssuedState;
use crate::keys::{Offer, rekey_subject};
use crate::renewal::store::Renewals;
use crate::renewal::{self, Choice, Due, Facts, Method, NeedsYou, Skip};
use crate::requests::Waiting;
use crate::session::{RenewalTarget, RequestError, Session};
use crate::settings::Layer;

/// What the application knows about renewal that the inventory does not.
pub struct Renewing {
    pub platform: Platform,
    pub policy: Layer,
    pub person: Layer,
    /// The key types this computer offers for a new key, as policy allows them.
    pub offers: Vec<Offer>,
    pub switches: Arc<Renewals>,
}

/// Why a certificate cannot renew itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// ILM does not let the person renew it.
    NotAllowed,
    /// The key is on a smart card, which this system cannot pair with a new certificate.
    SmartCard,
}

/// A certificate that is due and cannot renew itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Needs {
    pub fingerprint: Fingerprint,
    pub name: String,
    pub reason: Reason,
}

impl Needs {
    /// The key of its notice.
    pub fn key(&self) -> String {
        format!("renewal:needs:{}", self.fingerprint)
    }
}

/// A certificate that would renew itself but is due while nobody is signed in or the application is locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignIn {
    pub fingerprint: Fingerprint,
    pub name: String,
}

impl SignIn {
    /// The key of its notice.
    pub fn key(&self) -> String {
        format!("renewal:sign-in:{}", self.fingerprint)
    }
}

/// An automatic renewal that ILM or this computer did not take, with the words for the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub fingerprint: Fingerprint,
    pub name: String,
    pub message: String,
}

impl Refused {
    /// The key of its notice.
    pub fn key(&self) -> String {
        format!("renewal:failed:{}", self.fingerprint)
    }
}

/// A certificate on this computer that ILM knows, with what decides about its renewal.
struct Entry<'a> {
    local: &'a LocalCertificate,
    ilm: &'a IlmCertificate,
    allowed: &'a [String],
    replaced: bool,
    choice: Choice,
    person: &'a (IlmUrl, String),
}

/// The certificates of this computer that ILM knows. None where the system has no installer.
fn entries<'a>(held: &'a Held, plan: &Renewing) -> Vec<Entry<'a>> {
    let (Some(person), Some(snapshot), Some(local)) = (&held.bound, &held.snapshot, &held.local)
    else {
        return Vec::new();
    };
    if plan.platform == Platform::Linux {
        return Vec::new();
    }
    local
        .iter()
        .filter_map(|local| {
            let ilm = snapshot.matches.get(&local.fingerprint)?;
            let switched_off = plan
                .switches
                .is_off(&person.0, &person.1, &local.fingerprint);
            Some(Entry {
                local,
                ilm,
                allowed: snapshot.allowed.get(&ilm.uuid).map_or(&[], Vec::as_slice),
                replaced: snapshot.replaced.contains(&local.fingerprint),
                choice: renewal::choice(&plan.policy, &plan.person, switched_off),
                person,
            })
        })
        .collect()
}

enum Verdict {
    Renew(Method),
    Needs(Reason),
    Skipped(Skip),
    NotDue,
    /// The details of ILM were not read at the latest check.
    Unread,
}

fn judge(
    held: &Held,
    entry: &Entry<'_>,
    plan: &Renewing,
    waiting: &[Waiting],
    now: SystemTime,
) -> Verdict {
    let Some(snapshot) = &held.snapshot else {
        return Verdict::Unread;
    };
    match renewal::candidate(entry.ilm, entry.allowed) {
        Err(Skip::RenewNotAllowed)
            if !snapshot.allowed.is_empty()
                && !entry.replaced
                && entry.choice != Choice::Off
                && renewal::expiring(entry.local, held.days, now) =>
        {
            Verdict::Needs(Reason::NotAllowed)
        }
        Err(skip) => Verdict::Skipped(skip),
        Ok(()) => {
            let Some(detail) = held.details.get(&entry.local.fingerprint) else {
                return Verdict::Unread;
            };
            let installed: HashSet<String> = snapshot
                .matches
                .values()
                .map(|found| found.uuid.clone())
                .collect();
            let facts = Facts {
                now,
                warn_days: held.days,
                choice: entry.choice,
                waiting: waiting
                    .iter()
                    .any(|found| found.renews() == Some(entry.ilm.uuid.as_str())),
                installed: &installed,
                last_failure: plan.switches.last_failure(
                    &entry.person.0,
                    &entry.person.1,
                    &entry.local.fingerprint,
                ),
            };
            match renewal::due(entry.local, detail, &facts) {
                Due::Not => Verdict::NotDue,
                Due::Skipped(skip) => Verdict::Skipped(skip),
                Due::Yes => {
                    match renewal::method(
                        entry.local,
                        entry.choice,
                        &plan.offers,
                        subject_reproducible(Some(detail)),
                        plan.platform,
                    ) {
                        Ok(method) => Verdict::Renew(method),
                        Err(NeedsYou::SmartCardOnMacos) => Verdict::Needs(Reason::SmartCard),
                    }
                }
            }
        }
    }
}

/// Whether a request can carry the subject of the certificate as ILM has it; true when ILM gave no content.
fn subject_reproducible(detail: Option<&IssuedState>) -> bool {
    detail
        .and_then(|detail| detail.content.as_deref())
        .is_none_or(|der| rekey_subject(der).is_some())
}

fn key_of(method: &Method) -> &'static str {
    match method {
        Method::NewKey { .. } => "new key",
        Method::SameKey => "same key",
    }
}

impl super::Inventory {
    /// Renews the certificates that are due, as the latest check of ILM found them, with the details it read. Only
    /// the answer of a check that succeeded is acted on. A renewal that is not taken is kept for the person to be
    /// told, until a later one of the same certificate is. What was sent is followed at once, so the screens show
    /// it waiting. The batch stops when `proceed` says no or the sign-in ends.
    pub async fn renew_due(
        &self,
        session: &Session,
        plan: &Renewing,
        proceed: &(dyn Fn() -> bool + Sync),
    ) {
        let now = SystemTime::now();
        let waiting = session.waiting_requests();
        let (epoch, due) = {
            let held = held(&self.held);
            if !matches!(held.status, Status::Fresh { .. }) {
                return;
            }
            let mut due = Vec::new();
            for entry in entries(&held, plan) {
                match judge(&held, &entry, plan, &waiting, now) {
                    Verdict::Renew(method) => due.push((
                        entry.local.fingerprint,
                        entry.ilm.uuid.clone(),
                        entry.local.name.clone(),
                        method,
                    )),
                    Verdict::Skipped(skip) => log_skip(&entry.ilm.uuid, skip),
                    Verdict::Needs(_) | Verdict::NotDue | Verdict::Unread => {}
                }
            }
            (held.epoch, due)
        };
        let mut refused = Vec::new();
        let mut sent = Vec::new();
        for (fingerprint, uuid, name, method) in due {
            if !proceed() || held(&self.held).epoch != epoch {
                log::info!(
                    "the renewals of this check stop: the application locked or the sign-in ended"
                );
                break;
            }
            log::info!("renewal due: {uuid} ({}, automatic)", key_of(&method));
            let target = RenewalTarget {
                uuid: &uuid,
                fingerprint: &fingerprint,
                name: &name,
            };
            match session.renew(target, method, true, proceed).await {
                Ok(_) => sent.push(fingerprint),
                Err(RequestError::AlreadyRenewing) => log_skip(&uuid, Skip::Waiting),
                Err(
                    error @ (RequestError::SignedOut
                    | RequestError::Offline
                    | RequestError::Withdrawn),
                ) => {
                    log::info!("renewal of {uuid} was not sent: {error}");
                }
                Err(error) => {
                    log::warn!("renewal of {uuid} was not sent");
                    refused.push(Refused {
                        fingerprint,
                        name,
                        message: error.to_string(),
                    });
                }
            }
        }
        let followed = !sent.is_empty();
        self.keep_refused(epoch, &sent, refused);
        if followed {
            self.follow(session).await;
        }
    }

    /// Keeps the refusals of this round, unless a newer check replaced what it judged.
    fn keep_refused(&self, epoch: u64, sent: &[Fingerprint], refused: Vec<Refused>) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            return;
        }
        let here: HashSet<Fingerprint> = held
            .local
            .iter()
            .flatten()
            .map(|found| found.fingerprint)
            .collect();
        held.refused.retain(|before| {
            here.contains(&before.fingerprint)
                && !sent.contains(&before.fingerprint)
                && !refused
                    .iter()
                    .any(|now| now.fingerprint == before.fingerprint)
        });
        held.refused.extend(refused);
    }

    /// The certificates that are due and cannot renew itself, as the latest answer of ILM stands.
    pub fn renewal_needs(&self, plan: &Renewing, waiting: &[Waiting]) -> Vec<Needs> {
        let now = SystemTime::now();
        let held = held(&self.held);
        entries(&held, plan)
            .into_iter()
            .filter_map(|entry| match judge(&held, &entry, plan, waiting, now) {
                Verdict::Needs(reason) => Some(Needs {
                    fingerprint: entry.local.fingerprint,
                    name: entry.local.name.clone(),
                    reason,
                }),
                _ => None,
            })
            .collect()
    }

    /// The automatic renewals that were not taken and not made good since.
    pub fn renewal_refused(&self) -> Vec<Refused> {
        held(&self.held).refused.clone()
    }

    /// The certificates that renew themselves and expire within the warning days, so the person has to sign in or
    /// unlock for it. Only what the latest answer of ILM said is used.
    pub fn renewal_sign_in(&self, plan: &Renewing) -> Vec<SignIn> {
        let now = SystemTime::now();
        let held = held(&self.held);
        entries(&held, plan)
            .into_iter()
            .filter(|entry| {
                !entry.replaced
                    && entry.choice != Choice::Off
                    && renewal::candidate(entry.ilm, entry.allowed).is_ok()
                    && renewal::expiring(entry.local, held.days, now)
            })
            .map(|entry| SignIn {
                fingerprint: entry.local.fingerprint,
                name: entry.local.name.clone(),
            })
            .collect()
    }

    /// What the screens show of the renewal of each certificate, by fingerprint: those ILM lets the person renew,
    /// revoke, or that a successor has replaced. `waiting` are the requests of the person that wait for ILM.
    pub fn renewal_views(
        &self,
        plan: &Renewing,
        waiting: &[Waiting],
    ) -> HashMap<String, RenewalView> {
        let held = held(&self.held);
        let Some(snapshot) = &held.snapshot else {
            return HashMap::new();
        };
        let setting = renewal::manual_choice(&plan.policy, &plan.person);
        let locked = !renewal::permitted(&plan.policy);
        entries(&held, plan)
            .into_iter()
            .filter_map(|entry| {
                let renewable =
                    !entry.replaced && renewal::candidate(entry.ilm, entry.allowed).is_ok();
                let can_revoke = entry.allowed.iter().any(|action| action == "revoke");
                if !(renewable || entry.replaced || can_revoke) {
                    return None;
                }
                let detail = held.details.get(&entry.local.fingerprint);
                let successor = detail.filter(|_| entry.replaced).and_then(|detail| {
                    detail.related.iter().find_map(|related| {
                        let issued =
                            related.state == State::Issued && related.relation != Relation::Pending;
                        snapshot
                            .matches
                            .iter()
                            .find(|(_, found)| issued && found.uuid == related.uuid)
                    })
                });
                Some((
                    entry.local.fingerprint.to_string(),
                    RenewalView {
                        renewable,
                        automatic: entry.choice != Choice::Off,
                        locked,
                        days_before: renewal::days_before(entry.local, held.days),
                        from: detail
                            .and_then(|detail| detail.renewal.as_ref())
                            .and_then(|info| info.window_start),
                        new_key: matches!(
                            renewal::method(
                                entry.local,
                                setting,
                                &plan.offers,
                                subject_reproducible(detail),
                                plan.platform
                            ),
                            Ok(Method::NewKey { .. })
                        ),
                        replaced: entry.replaced,
                        replaced_on: successor.and_then(|(_, found)| found.not_before),
                        replaced_by: successor.map(|(fingerprint, _)| fingerprint.to_string()),
                        can_revoke,
                        waiting: waiting
                            .iter()
                            .any(|found| found.renews() == Some(entry.ilm.uuid.as_str()))
                            || detail.is_some_and(|detail| {
                                detail.related.iter().any(|related| {
                                    matches!(
                                        related.state,
                                        State::Requested
                                            | State::PendingApproval
                                            | State::PendingIssue
                                    )
                                })
                            }),
                    },
                ))
            })
            .collect()
    }
}

fn log_skip(uuid: &str, skip: Skip) {
    match skip {
        Skip::Off | Skip::Waiting | Skip::SuccessorPending | Skip::RecentFailure => {
            log::info!("renewal of {uuid} skipped ({})", skip.code());
        }
        _ => log::debug!("renewal of {uuid} skipped ({})", skip.code()),
    }
}
