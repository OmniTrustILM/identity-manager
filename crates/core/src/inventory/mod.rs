//! What ILM says about the certificates on this computer: one check, one snapshot, kept in a cache file.

mod cache;
#[cfg(test)]
mod tests;
mod view;

pub use view::{IlmCertificateView, IlmPageView, IlmRaProfileView, InventoryView};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};

use crate::identity::Fingerprint;
use crate::ilm::IlmUrl;
use crate::ilm::actions::{self, MAX_UUIDS, Outcome};
use crate::ilm::certificates::{self, CertificatePage, IlmCertificate, Search};
use crate::ilm::profile::{IlmError, SignInCertificate, profile_request, read_profile};
use crate::session::{CallError, Session, SignedInAs};

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
            CallError::Unreachable => Failure::Unreachable,
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
}

/// The latest answer of ILM about the certificates on this computer, and how it came to be.
pub struct Inventory {
    cache: PathBuf,
    held: Mutex<Held>,
    /// Held for a whole check: a call that arrives meanwhile waits and takes that check's answer.
    running: tokio::sync::Mutex<()>,
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
    local: usize,
    actions: &'static str,
}

impl Inventory {
    /// `folder` holds the cache file.
    pub fn new(folder: &std::path::Path) -> Self {
        Self {
            cache: folder.join(cache::FILE),
            held: Mutex::default(),
            running: tokio::sync::Mutex::new(()),
            completed: AtomicU64::new(0),
            asked: Mutex::new(None),
        }
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
            ..Held::default()
        };
        cache::delete(&self.cache);
    }

    pub fn status(&self) -> Status {
        held(&self.held).status.clone()
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        held(&self.held).snapshot.clone()
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
            };
            held.snapshot = Some(snapshot);
            held.bound = Some((ilm.clone(), username));
        }
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
            };
            held.snapshot = Some(snapshot);
        }
        held.bound = Some(key);
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
        *self.asked.lock().unwrap_or_else(PoisonError::into_inner) = asked;
        self.completed.fetch_add(1, Ordering::SeqCst);
        self.status()
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
                    "checked ILM: {} on this computer, {} matched, {page_total} in ILM, actions {}, {} ms",
                    found.local,
                    found.snapshot.matches.len(),
                    found.actions,
                    started.elapsed().as_millis()
                );
                self.keep(&who, epoch, found.snapshot);
            }
            Err(Failure::SignedOut) => log::debug!("ILM was not checked: the sign-in ended"),
            Err(Failure::Unreachable) => self.offline(epoch, UNREACHABLE),
            Err(error) => {
                log::warn!("the check of ILM failed: {error}");
                self.offline(epoch, UNEXPECTED);
            }
        }
        Some(Asked::new(&who, local))
    }

    /// Keeps `snapshot` unless the sign-in it was asked for has ended meanwhile.
    fn keep(&self, who: &SignedInAs, epoch: u64, snapshot: Snapshot) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            log::debug!("the answer of ILM is dropped: the sign-in ended");
            return;
        }
        match cache::write(&self.cache, &who.ilm, &who.username, &snapshot) {
            Ok(()) => log::info!("the ILM cache is written"),
            Err(error) => log::warn!("the ILM cache could not be written: {error}"),
        }
        held.status = Status::Fresh {
            checked_at: snapshot.checked_at,
        };
        held.snapshot = Some(snapshot);
    }

    fn offline(&self, epoch: u64, reason: &str) {
        let mut held = held(&self.held);
        if held.epoch != epoch {
            return;
        }
        log::info!("ILM is offline: {reason}");
        held.status = Status::Offline {
            since: held.snapshot.as_ref().map(|snapshot| snapshot.checked_at),
            reason: reason.to_owned(),
        };
    }

    /// One page of ILM's list, as it is now. It is not kept.
    pub async fn page(
        session: &Session,
        page_number: u32,
        search: Option<&str>,
    ) -> Result<CertificatePage, Failure> {
        if session.unreachable_at().is_some() {
            return Err(Failure::Unreachable);
        }
        if !session
            .signed_in_as()
            .is_some_and(|who| who.lists_certificates())
        {
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
    };
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
            local: unique.len(),
            actions: "not asked",
        });
    }
    for search in Search::matching(&unique) {
        let mut number = 1;
        loop {
            let page = read_search(session, &search.at_page(number)).await?;
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
    }
    snapshot.checked = unique.clone();
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
    Ok(Found {
        snapshot,
        local: unique.len(),
        actions,
    })
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
