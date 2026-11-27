//! What ILM says about the certificates on this computer: one check, one snapshot, kept in a cache file.

mod approvals;
mod cache;
mod enrol;
mod prepared;
mod renew;
mod summary;
#[cfg(test)]
mod tests;
mod view;

pub use approvals::Approval;
pub(crate) use prepared::is_begun;
pub use prepared::{Prepared, SubjectKind, SubjectPart, subject_parts};
pub use renew::{Needs, Reason, Refused, Renewing, SignIn};
pub use summary::{Counts, Item, Kind, Summary, WaitingState, summarize};
pub use view::{
    AddChoicesView, AddResultView, ApprovalView, AskedProfile, AttentionItemView, CountsView,
    IlmCertificateView, IlmPageView, IlmRaProfileView, InventoryView, MyRequestView, PreparedView,
    RegistrationView, RenewalView, RevokingStage, SummaryView, WaitingStateView,
};
use view::{is_requested, listed_by};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};

use crate::identity::{Fingerprint, LocalCertificate};
use crate::ilm::IlmUrl;
use crate::ilm::actions::{self, MAX_UUIDS, Outcome};
use crate::ilm::approvals::{DecideError, Decision, decide_request, read_decision};
use crate::ilm::certificates::{self, CertificatePage, IlmCertificate, MATCH_LIMIT, Search, State};
use crate::ilm::issue::{IssuedState, StateError, read_state, state_request};
use crate::ilm::profile::{IlmError, SignInCertificate, profile_request, read_profile};
use crate::renewal;
use crate::requests::Waiting;
use crate::session::{CallError, Followed, Outcome as FollowOutcome, Session, SignedInAs};
use crate::settings::WarnDays;

const UNREACHABLE: &str = "ILM cannot be reached.";
const UNEXPECTED: &str = "ILM gave an unexpected answer.";
const NOT_CHECKED_YET: &str = "ILM has not been checked since the application started.";

/// What started a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    Start,
    Interval,
    SyncNow,
    Action,
}

impl fmt::Display for Trigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Trigger::Start => "start",
            Trigger::Interval => "interval",
            Trigger::SyncNow => "sync now",
            Trigger::Action => "action",
        })
    }
}

/// ILM's answer to one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Milliseconds since 1970 (UTC).
    pub checked_at: i64,
    /// Whether ILM let the person list certificates when this was asked.
    pub listed: bool,
    /// The fingerprints of the certificates on this computer that were looked up in ILM: one of them without a
    /// match is not in ILM, one that is not here was not looked up. None when ILM was not searched.
    pub checked: Vec<Fingerprint>,
    /// The certificates on this computer that ILM knows, by fingerprint.
    pub matches: HashMap<Fingerprint, IlmCertificate>,
    /// The certificate ILM knows the person by.
    pub sign_in: Option<SignInCertificate>,
    /// The first page of ILM's list; none when the person may not list certificates.
    pub first_page: Option<CertificatePage>,
    /// What the person may do, by certificate UUID, for the matched certificates and the first page.
    pub allowed: HashMap<String, Vec<String>>,
    /// The certificates registered in advance for the person; empty when ILM was not searched for them or the
    /// person may not list them.
    #[serde(default)]
    pub prepared: Vec<Prepared>,
    /// The requests for certificates that wait for the person's approval; empty when ILM has none or could not say.
    #[serde(default)]
    pub approvals: Vec<Approval>,
    /// The certificates on this computer that a successor installed here has replaced.
    #[serde(default)]
    pub replaced: HashSet<Fingerprint>,
}

/// How far the snapshot can be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
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
        rename = "InventoryStatus",
        tag = "state",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum Status {
    /// ILM has not been checked, and nothing is kept.
    #[default]
    Never,
    Fresh {
        /// Milliseconds since 1970 (UTC).
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        checked_at: i64,
    },
    /// The last check did not succeed; the snapshot, when there is one, is older.
    Offline {
        /// When the snapshot was taken, milliseconds since 1970 (UTC).
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
        since: Option<i64>,
        reason: String,
        /// Whether ILM could not be reached, as opposed to answering in a way that was not expected.
        unreachable: bool,
    },
}

/// Why ILM could not be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    SignedOut,
    /// The person may not list certificates.
    NotAllowed,
    Unreachable,
    Ilm(IlmError),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::SignedOut => CallError::SignedOut.fmt(f),
            Failure::NotAllowed => f.write_str("ILM does not let you list certificates."),
            Failure::Unreachable => f.write_str(UNREACHABLE),
            Failure::Ilm(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Failure {}

impl From<CallError> for Failure {
    fn from(error: CallError) -> Self {
        match error {
            CallError::SignedOut => Failure::SignedOut,
            CallError::Unreachable | CallError::Withdrawn => Failure::Unreachable,
        }
    }
}

impl From<IlmError> for Failure {
    fn from(error: IlmError) -> Self {
        match error {
            IlmError::Unreachable => Failure::Unreachable,
            error => Failure::Ilm(error),
        }
    }
}

#[derive(Default)]
struct Held {
    /// The sign-in the snapshot belongs to.
    bound: Option<(IlmUrl, String)>,
    snapshot: Option<Snapshot>,
    status: Status,
    /// Changes whenever the snapshot is dropped, so a check that started before is not kept.
    epoch: u64,
    /// The certificates on this computer as the latest check or the start read them: no DER.
    /// None until a check or the start has read them.
    local: Option<Vec<LocalCertificate>>,
    days: WarnDays,
    summary: Option<Summary>,
    /// How the requests for certificates stood at the latest check.
    followed: Vec<Followed>,
    /// The approvals decided in this sign-in, or that ILM said no longer wait: a check that read ILM before the
    /// decision, or ILM listing an approval again for another step, must not bring them back.
    decided: HashSet<String>,
    /// What ILM said of each matched certificate at the latest check, for the renewal of it. Not kept in the cache.
    details: HashMap<Fingerprint, IssuedState>,
    /// The automatic renewals that were not taken.
    refused: Vec<Refused>,
    /// The RA Profiles the latest enrolment found to need the person. Not kept in the cache.
    asked: Vec<AskedProfile>,
}

impl Held {
    /// The approvals that wait for the person as the latest check found them; none unless it succeeded, as a kept
    /// list may name approvals decided since.
    fn approvals(&self) -> &[Approval] {
        match (&self.status, &self.snapshot) {
            (Status::Fresh { .. }, Some(snapshot)) => &snapshot.approvals,
            _ => &[],
        }
    }

    /// The requests the latest check found still waiting for ILM, by label.
    fn waiting(&self) -> Vec<(String, WaitingState)> {
        self.followed
            .iter()
            .filter_map(|followed| match &followed.outcome {
                FollowOutcome::Waiting(State::PendingApproval) => {
                    Some((followed.label.clone(), WaitingState::PendingApproval))
                }
                FollowOutcome::Waiting(_) => {
                    Some((followed.label.clone(), WaitingState::BeingIssued))
                }
                _ => None,
            })
            .collect()
    }

    /// Builds the summary again from what is held; none while nobody's sign-in is bound or the certificates on
    /// this computer are not known yet.
    fn rebuild(&mut self, zone: Zone) {
        self.summary = self.bound.as_ref().and(self.local.as_ref()).map(|local| {
            summarize(local, self.snapshot.as_ref(), self.days, now(), zone)
                .with_waiting(self.waiting())
                .with_approvals(self.approvals().iter().map(|found| {
                    (
                        found.uuid.clone(),
                        found
                            .certificate_name
                            .clone()
                            .unwrap_or_else(|| "Certificate".to_owned()),
                        found.action,
                    )
                }))
                .with_asked(
                    self.asked
                        .iter()
                        .map(|profile| (profile.uuid.clone(), profile.name.clone())),
                )
        });
        if let Some(summary) = &self.summary {
            let counts = &summary.counts;
            log::info!(
                "summary built: {} valid, {} expiring, {} expired, {} not in ILM, {} need attention",
                counts.valid,
                counts.expiring,
                counts.expired,
                counts
                    .not_in_ilm
                    .map_or_else(|| "unknown".to_owned(), |count| count.to_string()),
                summary.needing_attention()
            );
        }
    }
}

/// The local time zone's offset from UTC in seconds, east positive, at an instant in milliseconds since 1970 (UTC).
pub type Zone = fn(i64) -> i32;

/// The latest answer of ILM about the certificates on this computer, and how it came to be.
pub struct Inventory {
    cache: PathBuf,
    zone: Zone,
    held: Mutex<Held>,
    /// Held for a whole check: a call that arrives meanwhile waits and takes that check's answer.
    running: tokio::sync::Mutex<()>,
    /// Held while a follow runs and its result is kept, so an older result never replaces a newer one.
    following: tokio::sync::Mutex<()>,
    /// Held for a whole enrolment and for a whole change of the sign-in certificate by policy, so two runs never
    /// plan and request the same RA Profile, or retry a failed change, at once.
    enrolling: tokio::sync::Mutex<()>,
    completed: AtomicU64,
    /// What the latest check asked: whose sign-in and which local certificates.
    asked: Mutex<Option<Asked>>,
}

/// The sign-in and the local certificates a check was made for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Asked {
    ilm: IlmUrl,
    username: String,
    local: HashSet<Fingerprint>,
}

impl Asked {
    fn new(who: &SignedInAs, local: &[Fingerprint]) -> Self {
        Self {
            ilm: who.ilm.clone(),
            username: who.username.clone(),
            local: local.iter().copied().collect(),
        }
    }
}

fn held(mutex: &Mutex<Held>) -> MutexGuard<'_, Held> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as i64)
}

async fn send(
    session: &Session,
    build: impl Fn(&Client, &IlmUrl) -> RequestBuilder + Sync,
) -> Result<Response, Failure> {
    Ok(session.call_ilm(build).await?)
}

/// What a check found out.
struct Found {
    snapshot: Snapshot,
    details: HashMap<Fingerprint, IssuedState>,
    local: usize,
    actions: &'static str,
}

impl Inventory {
    /// `folder` holds the cache file. The time zone is UTC until [`Inventory::with_zone`] gives another.
    pub fn new(folder: &std::path::Path) -> Self {
        Self {
            cache: folder.join(cache::FILE),
            zone: |_| 0,
            held: Mutex::default(),
            running: tokio::sync::Mutex::new(()),
            following: tokio::sync::Mutex::new(()),
            enrolling: tokio::sync::Mutex::new(()),
            completed: AtomicU64::new(0),
            asked: Mutex::new(None),
        }
    }

    /// The local time zone the calendar months and days of the summary follow.
    #[must_use]
    pub fn with_zone(mut self, zone: Zone) -> Self {
        self.zone = zone;
        self
    }

    /// Drops the snapshot and the cache file whenever a sign-in of `session` ends.
    pub fn attach(self: &Arc<Self>, session: &Session) {
        let inventory = self.clone();
        session.on_signed_out(move || inventory.forget());
    }

    /// Drops the snapshot and deletes the cache file.
    pub fn forget(&self) {
        let mut held = held(&self.held);
        *held = Held {
            epoch: held.epoch + 1,
            days: held.days,
            ..Held::default()
        };
        cache::delete(&self.cache);
    }

    pub fn status(&self) -> Status {
        held(&self.held).status.clone()
    }

    /// The requests for certificates the latest check followed, and how each stood. A failed renewal of a
    /// certificate that is no longer on this computer is left out.
    pub fn followed(&self) -> Vec<Followed> {
        let held = held(&self.held);
        let Some(local) = &held.local else {
            return held.followed.clone();
        };
        held.followed
            .iter()
            .filter(|entry| {
                (entry.failed_notice_key().is_none() && entry.needs_notice_key().is_none())
                    || entry
                        .replaces
                        .is_some_and(|old| local.iter().any(|found| found.fingerprint == old))
            })
            .cloned()
            .collect()
    }

    /// Whether a certificate a follow installed is not among the certificates read from this computer, or may not
    /// be: a renewal whose sign-in has not moved over yet does not name its certificate.
    pub fn installed_elsewhere(&self) -> bool {
        let held = held(&self.held);
        let Some(local) = &held.local else {
            return false;
        };
        held.followed.iter().any(|entry| match &entry.outcome {
            FollowOutcome::Installed(installed) => !local
                .iter()
                .any(|found| found.fingerprint == installed.fingerprint),
            FollowOutcome::SwitchPending { .. } => true,
            _ => false,
        })
    }

    /// Waits for the enrolment that is running, and keeps any other from starting while the guard lives.
    pub(crate) async fn alone(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.enrolling.lock().await
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        held(&self.held).snapshot.clone()
    }

    /// The certificates registered in advance that the person can still complete and, as the requests `waiting`
    /// show, has not begun to complete; none unless the latest check succeeded, as a kept list may name certificates
    /// completed since.
    pub fn ready_to_issue(&self, waiting: &[Waiting]) -> Vec<Prepared> {
        let now = now();
        let held = held(&self.held);
        if !matches!(held.status, Status::Fresh { .. }) {
            return Vec::new();
        }
        held.snapshot
            .iter()
            .flat_map(|snapshot| &snapshot.prepared)
            .filter(|found| found.is_open_at(now) && !prepared::is_begun(&found.uuid, waiting))
            .cloned()
            .collect()
    }

    /// The requests for certificates that wait for the person's approval; none unless the latest check succeeded.
    pub fn approvals(&self) -> Vec<Approval> {
        held(&self.held).approvals().to_vec()
    }

    /// Takes `decision` on the approval `uuid`, with an optional `comment` that goes to ILM and nowhere else. The
    /// approval leaves the snapshot once ILM took the decision or says it no longer waits.
    pub async fn decide(
        &self,
        session: &Session,
        uuid: &str,
        decision: Decision,
        comment: Option<&str>,
        proceed: impl Fn() -> bool + Sync,
    ) -> Result<(), DecideError> {
        let epoch = held(&self.held).epoch;
        let response = session
            .call_ilm_as(None, Some(&proceed), |client, ilm| {
                decide_request(client, ilm, uuid, decision, comment)
            })
            .await
            .map_err(|error| match error {
                CallError::SignedOut => DecideError::Failed(IlmError::Unauthorized),
                CallError::Unreachable | CallError::Withdrawn => {
                    DecideError::Failed(IlmError::Unreachable)
                }
            })?;
        let answer = read_decision(response).await;
        match &answer {
            Ok(()) => log::info!("approval decided: {uuid} {decision}"),
            Err(DecideError::NoLongerWaiting) => log::info!("approval no longer waits: {uuid}"),
            Err(_) => return answer,
        }
        self.leave(epoch, uuid);
        answer
    }

    /// Takes the approval `uuid` out of the snapshot and the cache file, unless the sign-in ended meanwhile.
    fn leave(&self, epoch: u64, uuid: &str) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            return;
        }
        held.decided.insert(uuid.to_owned());
        let Some((ilm, username)) = held.bound.clone() else {
            return;
        };
        let Some(snapshot) = held.snapshot.as_mut() else {
            return;
        };
        snapshot.approvals.retain(|found| found.uuid != uuid);
        if let Err(error) = cache::write(&self.cache, &ilm, &username, snapshot) {
            log::warn!("the ILM cache could not be written: {error}");
        }
        held.rebuild(self.zone);
    }

    /// The RA Profiles the latest enrolment found to need the person.
    pub fn asked(&self) -> Vec<AskedProfile> {
        held(&self.held).asked.clone()
    }

    /// Takes the RA Profile `uuid` out of the asked ones, as the person has requested from it.
    pub fn unask(&self, uuid: &str) {
        let mut held = held(&self.held);
        let before = held.asked.len();
        held.asked.retain(|profile| profile.uuid != uuid);
        if held.asked.len() != before {
            held.rebuild(self.zone);
        }
    }

    /// How the certificates on this computer stand, as of the latest check, or of the start before the first one;
    /// none while nobody is signed in.
    pub fn summary(&self) -> Option<Summary> {
        held(&self.held).summary.clone()
    }

    /// Holds `local`, the certificates on this computer, and builds the summary again.
    pub fn set_local(&self, local: &[LocalCertificate]) {
        let mut held = held(&self.held);
        held.local = Some(local.to_vec());
        held.rebuild(self.zone);
    }

    /// The fingerprints of the certificates on this computer that `set_local` holds.
    pub fn local_fingerprints(&self) -> Vec<Fingerprint> {
        held(&self.held)
            .local
            .iter()
            .flatten()
            .map(|found| found.fingerprint)
            .collect()
    }

    /// The fingerprints of the certificates on this computer that ILM knows, as of the latest answer; none before
    /// the first one.
    pub fn matched_fingerprints(&self) -> Vec<Fingerprint> {
        held(&self.held)
            .snapshot
            .iter()
            .flat_map(|snapshot| snapshot.matches.keys().copied())
            .collect()
    }

    /// Sets the warning days and builds the summary again when they changed. ILM is not asked.
    pub fn configure(&self, days: WarnDays) {
        let mut held = held(&self.held);
        if held.days == days {
            return;
        }
        log::info!("the warning before expiry is {} days", days.get());
        held.days = days;
        held.rebuild(self.zone);
    }

    /// Holds `snapshot` as if a check had found it.
    #[cfg(test)]
    pub(crate) fn seed(&self, snapshot: Snapshot) {
        held(&self.held).snapshot = Some(snapshot);
    }

    /// Takes the cache file of the person who is signed in, when it is theirs; it shows as offline until a check
    /// succeeds. A file of anyone else is deleted. While a saved sign-in cannot be renewed, the person is not
    /// known yet: the file is taken when it is for that address, and dropped again when the sign-in turns out to be
    /// of another person.
    pub fn adopt(&self, session: &Session) {
        if let Some(who) = session.signed_in_as() {
            self.adopt_for(&who);
        } else if let Some(ilm) = session.unreachable_at() {
            self.adopt_unreachable(&ilm);
        }
    }

    fn adopt_unreachable(&self, ilm: &IlmUrl) {
        let mut held = held(&self.held);
        if held.bound.as_ref().is_some_and(|(bound, _)| bound == ilm) {
            return;
        }
        held.snapshot = None;
        held.status = Status::Never;
        held.bound = None;
        if let Some((username, snapshot)) = cache::read_at(&self.cache, ilm) {
            held.status = Status::Offline {
                since: Some(snapshot.checked_at),
                reason: UNREACHABLE.to_owned(),
                unreachable: true,
            };
            held.snapshot = Some(snapshot);
            held.bound = Some((ilm.clone(), username));
        }
        held.rebuild(self.zone);
    }

    fn adopt_for(&self, who: &SignedInAs) {
        let mut held = held(&self.held);
        let key = (who.ilm.clone(), who.username.clone());
        if held.bound.as_ref() == Some(&key) {
            return;
        }
        held.snapshot = None;
        held.status = Status::Never;
        if let Some(snapshot) = cache::read(&self.cache, &who.ilm, &who.username) {
            held.status = Status::Offline {
                since: Some(snapshot.checked_at),
                reason: NOT_CHECKED_YET.to_owned(),
                unreachable: false,
            };
            held.snapshot = Some(snapshot);
        }
        held.bound = Some(key);
        held.rebuild(self.zone);
    }

    /// Like [`Inventory::check`], for the certificates `local` as they are described now: they are kept for the
    /// summary, which is built again from the answer.
    pub async fn check_local(
        &self,
        session: &Session,
        trigger: Trigger,
        local: &[LocalCertificate],
    ) -> Status {
        held(&self.held).local = Some(local.to_vec());
        let fingerprints: Vec<Fingerprint> = local.iter().map(|found| found.fingerprint).collect();
        self.check(session, trigger, &fingerprints).await
    }

    /// Asks ILM about `local`, the fingerprints of the certificates on this computer, and replaces the snapshot when
    /// every question is answered. A call that arrives during a check waits for it and does not ask again, unless it
    /// follows an action, whose effect the running check may have missed, or the running check was for another
    /// sign-in or other certificates.
    pub async fn check(
        &self,
        session: &Session,
        trigger: Trigger,
        local: &[Fingerprint],
    ) -> Status {
        let seen = self.completed.load(Ordering::SeqCst);
        let wanted = session.signed_in_as().map(|who| Asked::new(&who, local));
        let _running = self.running.lock().await;
        if trigger != Trigger::Action
            && self.completed.load(Ordering::SeqCst) != seen
            && wanted.is_some()
            && *self.asked.lock().unwrap_or_else(PoisonError::into_inner) == wanted
        {
            return self.status();
        }
        let asked = self.run(session, trigger, local).await;
        self.follow(session).await;
        *self.asked.lock().unwrap_or_else(PoisonError::into_inner) = asked;
        self.completed.fetch_add(1, Ordering::SeqCst);
        self.status()
    }

    /// Follows the requests for certificates and keeps how they stand. What `session` could not ask ILM about
    /// stays as it stood before. Gives what the follow found, and whether the standing of the requests changed.
    pub async fn follow(&self, session: &Session) -> (Vec<Followed>, bool) {
        let _following = self.following.lock().await;
        let epoch = held(&self.held).epoch;
        let found = session.follow().await;
        let mut held = held(&self.held);
        if held.epoch != epoch {
            return (found, false);
        }
        let mut kept = found.clone();
        kept.extend(
            held.followed
                .iter()
                .filter(|before| {
                    !found
                        .iter()
                        .any(|now| now.uuid.is_some() && now.uuid == before.uuid)
                })
                .cloned(),
        );
        let renewed: HashSet<Fingerprint> = kept
            .iter()
            .filter(|entry| matches!(entry.outcome, FollowOutcome::Installed(_)))
            .filter_map(|entry| entry.replaces)
            .collect();
        kept.retain(|entry| {
            entry.failed_notice_key().is_none()
                || entry.replaces.is_none_or(|old| !renewed.contains(&old))
        });
        let refused = held.refused.len();
        held.refused
            .retain(|before| !renewed.contains(&before.fingerprint));
        let dropped = held
            .snapshot
            .as_mut()
            .is_some_and(|snapshot| prepared::drop_completed(&mut snapshot.prepared, &found));
        let asked = held.asked.len();
        let waiting = session.waiting_requests();
        held.asked
            .retain(|profile| !is_requested(&profile.uuid, &waiting));
        let changed = kept != held.followed
            || dropped
            || held.refused.len() != refused
            || held.asked.len() != asked;
        held.followed = kept;
        if changed {
            held.rebuild(self.zone);
        }
        (found, changed)
    }

    async fn run(
        &self,
        session: &Session,
        trigger: Trigger,
        local: &[Fingerprint],
    ) -> Option<Asked> {
        let epoch = held(&self.held).epoch;
        let Some(who) = session.signed_in_as() else {
            log::debug!("ILM is not checked: nobody is signed in");
            return None;
        };
        self.adopt_for(&who);
        log::info!("checking ILM ({trigger})");
        let started = Instant::now();
        match collect(session, local).await {
            Ok(found) => {
                let page_total = found
                    .snapshot
                    .first_page
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |page| page.total_items.to_string());
                log::info!(
                    "checked ILM: {} on this computer, {} matched, {page_total} in ILM, {} prepared, {} approvals, actions {}, {} ms",
                    found.local,
                    found.snapshot.matches.len(),
                    found.snapshot.prepared.len(),
                    found.snapshot.approvals.len(),
                    found.actions,
                    started.elapsed().as_millis()
                );
                self.keep(&who, epoch, found.snapshot, found.details);
            }
            Err(Failure::SignedOut) => log::debug!("ILM was not checked: the sign-in ended"),
            Err(Failure::Unreachable) => self.offline(epoch, UNREACHABLE, true),
            Err(error) => {
                log::warn!("the check of ILM failed: {error}");
                self.offline(epoch, UNEXPECTED, false);
            }
        }
        Some(Asked::new(&who, local))
    }

    /// Keeps `snapshot` unless the sign-in it was asked for has ended meanwhile.
    fn keep(
        &self,
        who: &SignedInAs,
        epoch: u64,
        mut snapshot: Snapshot,
        details: HashMap<Fingerprint, IssuedState>,
    ) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            log::debug!("the answer of ILM is dropped: the sign-in ended");
            return;
        }
        snapshot
            .approvals
            .retain(|found| !held.decided.contains(&found.uuid));
        match cache::write(&self.cache, &who.ilm, &who.username, &snapshot) {
            Ok(()) => log::info!("the ILM cache is written"),
            Err(error) => log::warn!("the ILM cache could not be written: {error}"),
        }
        held.status = Status::Fresh {
            checked_at: snapshot.checked_at,
        };
        held.snapshot = Some(snapshot);
        held.details = details;
        held.rebuild(self.zone);
    }

    fn offline(&self, epoch: u64, reason: &str, unreachable: bool) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            return;
        }
        log::info!("ILM is offline: {reason}");
        held.status = Status::Offline {
            since: held.snapshot.as_ref().map(|snapshot| snapshot.checked_at),
            reason: reason.to_owned(),
            unreachable,
        };
        held.rebuild(self.zone);
    }

    /// One page of ILM's list, as it is now. It is not kept.
    pub async fn page(
        &self,
        session: &Session,
        page_number: u32,
        search: Option<&str>,
    ) -> Result<CertificatePage, Failure> {
        if session.unreachable_at().is_some() {
            return Err(Failure::Unreachable);
        }
        let session_lists = session
            .signed_in_as()
            .is_some_and(|who| who.lists_certificates());
        if !listed_by(self.snapshot().as_ref(), session_lists) {
            return Err(Failure::NotAllowed);
        }
        read_search(session, &Search::page(page_number, search)).await
    }
}

async fn read_search(session: &Session, search: &Search) -> Result<CertificatePage, Failure> {
    let response = send(session, |client, ilm| search.request(client, ilm)).await?;
    Ok(certificates::read_page(response).await?)
}

async fn collect(session: &Session, local: &[Fingerprint]) -> Result<Found, Failure> {
    let response = send(session, profile_request).await?;
    let who = session.signed_in_as().ok_or(Failure::SignedOut)?;
    let person = read_profile(&who.ilm, response).await?;
    let listed = person
        .allowed_listings
        .iter()
        .any(|name| name == "certificates");
    let mut snapshot = Snapshot {
        checked_at: now(),
        listed,
        checked: Vec::new(),
        matches: HashMap::new(),
        sign_in: person.sign_in,
        first_page: None,
        allowed: HashMap::new(),
        prepared: Vec::new(),
        approvals: Vec::new(),
        replaced: Default::default(),
    };
    snapshot.approvals = approvals::read(session, &person.uuid).await?;
    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for fingerprint in local {
        if seen.insert(*fingerprint) {
            unique.push(*fingerprint);
        }
    }
    if !listed {
        log::debug!("certificates are not listed for this person; ILM is not searched");
        return Ok(Found {
            snapshot,
            details: HashMap::new(),
            local: unique.len(),
            actions: "not asked",
        });
    }
    for (chunk, search) in unique.chunks(MATCH_LIMIT).zip(Search::matching(&unique)) {
        let mut skipped = 0;
        let mut number = 1;
        loop {
            let page = read_search(session, &search.at_page(number)).await?;
            skipped += page.skipped;
            for certificate in page.certificates {
                let Some(fingerprint) =
                    certificate.fingerprint.filter(|print| seen.contains(print))
                else {
                    continue;
                };
                let better = snapshot
                    .matches
                    .get(&fingerprint)
                    .is_none_or(|known| known.archived && !certificate.archived);
                if better {
                    snapshot.matches.insert(fingerprint, certificate);
                }
            }
            if number >= page.total_pages {
                break;
            }
            number += 1;
        }
        if skipped == 0 {
            snapshot.checked.extend_from_slice(chunk);
        } else {
            log::warn!(
                "{skipped} certificates of ILM could not be read: what was not matched is not judged"
            );
            let found = &snapshot.matches;
            let matched: Vec<Fingerprint> = chunk
                .iter()
                .filter(|print| found.contains_key(print))
                .copied()
                .collect();
            snapshot.checked.extend(matched);
        }
    }
    let first_page = read_search(session, &Search::page(1, None)).await?;
    let mut uuids: Vec<String> = snapshot
        .matches
        .values()
        .chain(&first_page.certificates)
        .map(|certificate| certificate.uuid.clone())
        .collect();
    uuids.sort();
    uuids.dedup();
    snapshot.first_page = Some(first_page);
    let actions = match allowed_actions(session, &uuids, &mut snapshot.allowed).await {
        Ok(actions) => actions,
        Err(Failure::SignedOut | Failure::Ilm(IlmError::Unauthorized)) => {
            return Err(Failure::SignedOut);
        }
        Err(Failure::Unreachable) => return Err(Failure::Unreachable),
        Err(error) => {
            log::warn!("the allowed actions are not available: {error}");
            snapshot.allowed.clear();
            "unavailable"
        }
    };
    snapshot.prepared = prepared::read(session, &who.username).await?;
    let details = details(session, &snapshot.matches).await?;
    let installed: HashSet<String> = snapshot
        .matches
        .values()
        .map(|certificate| certificate.uuid.clone())
        .collect();
    snapshot.replaced = details
        .iter()
        .filter(|(_, detail)| renewal::replaced(detail, &installed))
        .map(|(fingerprint, _)| *fingerprint)
        .collect();
    Ok(Found {
        snapshot,
        details,
        local: unique.len(),
        actions,
    })
}

/// What ILM says of each issued matched certificate: its successors and renewal window. A certificate whose
/// details ILM does not tell is left out, and counts as not replaced.
async fn details(
    session: &Session,
    matches: &HashMap<Fingerprint, IlmCertificate>,
) -> Result<HashMap<Fingerprint, IssuedState>, Failure> {
    let mut found = HashMap::new();
    for (fingerprint, certificate) in matches {
        if certificate.state != State::Issued || certificate.archived {
            continue;
        }
        let response = send(session, |client, ilm| {
            state_request(client, ilm, &certificate.uuid)
        })
        .await?;
        match read_state(response).await {
            Ok(detail) => {
                found.insert(*fingerprint, detail);
            }
            Err(StateError::Failed(IlmError::Unauthorized)) => return Err(Failure::SignedOut),
            Err(error) => log::debug!("the successors of a certificate are not known: {error}"),
        }
    }
    Ok(found)
}

/// Fills `allowed` for `uuids` and tells how ILM answered. Nothing is kept unless ILM answers every chunk.
async fn allowed_actions(
    session: &Session,
    uuids: &[String],
    allowed: &mut HashMap<String, Vec<String>>,
) -> Result<&'static str, Failure> {
    if uuids.is_empty() {
        return Ok("not asked");
    }
    for chunk in uuids.chunks(MAX_UUIDS) {
        let response = send(session, |client, ilm| actions::request(client, ilm, chunk)).await?;
        let answer = actions::read(response).await?;
        match answer.outcome {
            Outcome::Used => allowed.extend(answer.actions),
            Outcome::Unsupported => {
                allowed.clear();
                return Ok("unsupported");
            }
            Outcome::Refused => {
                allowed.clear();
                return Ok("empty");
            }
        }
    }
    Ok(if allowed.is_empty() { "empty" } else { "used" })
}
