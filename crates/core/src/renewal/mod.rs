//! Which certificates are due for renewal, and how each is renewed. Nothing here reads ILM or the computer.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use crate::app_info::Platform;
use crate::identity::{KeyAlgorithm, KeyLocation, LocalCertificate};
use crate::ilm::certificates::{IlmCertificate, Relation, State};
use crate::ilm::issue::IssuedState;
use crate::keys::{KeyType, Offer, Storage};
use crate::settings::{Layer, WarnDays, automatic_renewal};

/// How long after a failed automatic attempt on this computer the next one waits.
pub const RETRY_AFTER: Duration = DAY;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// What automatic renewal is set to, with policy and the person's choice already merged.
pub use crate::settings::AutomaticRenewal as Choice;

/// Whether policy leaves renewing to the application.
pub fn permitted(policy: &Layer) -> bool {
    policy.automatic_renewal != Some(Choice::Off)
}

/// What an automatic renewal does: policy off turns everything off, a certificate the person switched off is off,
/// and else the setting decides, policy over the person's choice.
pub fn choice(policy: &Layer, person: &Layer, switched_off: bool) -> Choice {
    if !permitted(policy) || switched_off {
        Choice::Off
    } else {
        automatic_renewal(policy, person)
    }
}

/// The method preferred when the person renews a certificate now: automatic renewal being off does not stop it,
/// and then a new key is made.
pub fn manual_choice(policy: &Layer, person: &Layer) -> Choice {
    match automatic_renewal(policy, person) {
        Choice::Off => Choice::NewKey,
        method => method,
    }
}

/// Why a certificate is not renewed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    NotIssued,
    Archived,
    NoRaProfile,
    RenewNotAllowed,
    /// A successor issued from it is installed on this computer.
    Replaced,
    /// Automatic renewal is off by setting, policy or the certificate's switch.
    Off,
    /// A waiting entry of this computer already renews or revokes it.
    Waiting,
    /// ILM lists a successor that is not issued yet.
    SuccessorPending,
    /// ILM lists an issued successor, installed elsewhere or about to be installed here.
    SuccessorIssued,
    /// The last automatic attempt here failed less than [`RETRY_AFTER`] ago.
    RecentFailure,
}

impl Skip {
    /// A short code for the log.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotIssued => "not-issued",
            Self::Archived => "archived",
            Self::NoRaProfile => "no-ra-profile",
            Self::RenewNotAllowed => "renew-not-allowed",
            Self::Replaced => "replaced",
            Self::Off => "off",
            Self::Waiting => "waiting",
            Self::SuccessorPending => "successor-pending",
            Self::SuccessorIssued => "successor-issued",
            Self::RecentFailure => "recent-failure",
        }
    }
}

/// Whether a candidate is to be renewed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    Not,
    Yes,
    Skipped(Skip),
}

/// What is known about the computer and the moment, besides the certificate itself.
pub struct Facts<'a> {
    pub now: SystemTime,
    pub warn_days: WarnDays,
    pub choice: Choice,
    /// A waiting entry of this computer renews or revokes the certificate.
    pub waiting: bool,
    /// The ILM uuids of the certificates installed here.
    pub installed: &'a HashSet<String>,
    /// When the last automatic attempt on this certificate failed.
    pub last_failure: Option<SystemTime>,
}

/// Whether the certificate may be renewed at all: issued, not archived, with an RA Profile, and `renew` among
/// what ILM allows the person.
pub fn candidate(ilm: &IlmCertificate, allowed: &[String]) -> Result<(), Skip> {
    if ilm.state != State::Issued {
        Err(Skip::NotIssued)
    } else if ilm.archived {
        Err(Skip::Archived)
    } else if ilm.ra_profile.is_none() {
        Err(Skip::NoRaProfile)
    } else if !allowed.iter().any(|action| action == "renew") {
        Err(Skip::RenewNotAllowed)
    } else {
        Ok(())
    }
}

/// Whether a successor issued from the certificate is installed here, `installed` being the ILM uuids of the
/// certificates installed here.
pub fn replaced(detail: &IssuedState, installed: &HashSet<String>) -> bool {
    detail.related.iter().any(|related| {
        related.state == State::Issued
            && related.relation != Relation::Pending
            && installed.contains(&related.uuid)
    })
}

/// Whether the certificate is close enough to its expiry to be renewed: within the warning days, and within half
/// its validity, so that a certificate valid for less than the warning days is not due again as soon as it arrives.
pub fn expiring(local: &LocalCertificate, warn_days: WarnDays, now: SystemTime) -> bool {
    local.not_after <= now + lead(local, warn_days)
}

/// How many whole days before its expiry the certificate becomes due, without a renewal window of ILM.
pub fn days_before(local: &LocalCertificate, warn_days: WarnDays) -> u32 {
    u32::try_from(lead(local, warn_days).as_secs() / DAY.as_secs()).unwrap_or(u32::MAX)
}

fn lead(local: &LocalCertificate, warn_days: WarnDays) -> Duration {
    let warning = DAY * u32::from(warn_days.get());
    let half = local
        .not_after
        .duration_since(local.not_before)
        .unwrap_or_default()
        / 2;
    warning.min(half)
}

/// Whether a candidate is due, from the details ILM gives for it. A certificate with an installed successor is
/// reported as replaced whether it is due or not.
pub fn due(local: &LocalCertificate, detail: &IssuedState, facts: &Facts) -> Due {
    if replaced(detail, facts.installed) {
        return Due::Skipped(Skip::Replaced);
    }
    let expiring = expiring(local, facts.warn_days, facts.now);
    if !detail.renewal.as_ref().map_or(expiring, |info| info.due) {
        return Due::Not;
    }
    if facts.choice == Choice::Off {
        Due::Skipped(Skip::Off)
    } else if facts.waiting {
        Due::Skipped(Skip::Waiting)
    } else if detail.related.iter().any(|related| {
        matches!(
            related.state,
            State::Requested | State::PendingApproval | State::PendingIssue
        )
    }) {
        Due::Skipped(Skip::SuccessorPending)
    } else if detail
        .related
        .iter()
        .any(|related| related.state == State::Issued && related.relation != Relation::Pending)
    {
        Due::Skipped(Skip::SuccessorIssued)
    } else if facts.last_failure.is_some_and(|failed| {
        facts
            .now
            .duration_since(failed)
            .map_or(true, |ago| ago < RETRY_AFTER)
    }) {
        Due::Skipped(Skip::RecentFailure)
    } else {
        Due::Yes
    }
}

/// How a certificate is renewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// A key made in `storage`, with the request carrying the subject of the old certificate.
    NewKey { storage: Storage, key_type: KeyType },
    /// The stored request, with the key the certificate already has.
    SameKey,
}

/// A certificate the application cannot renew by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsYou {
    /// The macOS login keychain does not pair a new certificate with a key on a smart card.
    SmartCardOnMacos,
}

/// The method for a certificate. `offers` are the key types the storages offer that policy allows, and
/// `reproducible` tells whether a request can carry the subject of the old certificate.
pub fn method(
    local: &LocalCertificate,
    choice: Choice,
    offers: &[Offer],
    reproducible: bool,
    platform: Platform,
) -> Result<Method, NeedsYou> {
    if local.location == KeyLocation::SmartCard && platform == Platform::Macos {
        return Err(NeedsYou::SmartCardOnMacos);
    }
    if choice != Choice::NewKey || !reproducible {
        return Ok(Method::SameKey);
    }
    Ok(new_key(local, offers).unwrap_or(Method::SameKey))
}

fn new_key(local: &LocalCertificate, offers: &[Offer]) -> Option<Method> {
    let storage = match local.location {
        KeyLocation::Keychain => Storage::Keychain,
        KeyLocation::Software => Storage::Software,
        KeyLocation::Tpm => Storage::Tpm,
        _ => return None,
    };
    let types = &offers.iter().find(|offer| offer.storage == storage)?.types;
    let key_type = key_type_of(&local.key)
        .filter(|old| types.contains(old))
        .or_else(|| types.contains(&KeyType::EcP256).then_some(KeyType::EcP256))
        .or_else(|| types.first().copied())?;
    Some(Method::NewKey { storage, key_type })
}

fn key_type_of(algorithm: &KeyAlgorithm) -> Option<KeyType> {
    match algorithm {
        KeyAlgorithm::Rsa { bits } => Some(KeyType::Rsa {
            bits: u32::try_from(*bits).ok()?,
        }),
        KeyAlgorithm::Ec { curve } => match curve.as_str() {
            "P-256" => Some(KeyType::EcP256),
            "P-384" => Some(KeyType::EcP384),
            "P-521" => Some(KeyType::EcP521),
            _ => None,
        },
        KeyAlgorithm::Ed25519 | KeyAlgorithm::Other(_) => None,
    }
}

pub mod store;
#[cfg(test)]
mod tests;
