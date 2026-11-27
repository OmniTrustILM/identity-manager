//! What enrolment by policy does for the person, decided from what ILM and policy say. Nothing here reads ILM or
//! the computer.

mod store;
#[cfg(test)]
mod tests;

use std::collections::HashSet;

pub use store::{DAY_MS, Enrolments, Failure, Standing, prepared_key, profile_key, sign_in_key};

use crate::ilm::upload::RaProfileChoice;
use crate::inventory::{Prepared, is_begun};
use crate::keys::Offer;
use crate::requests::Waiting;
use crate::session::SignedInAs;
use crate::settings::{Layer, allowed_offers, complete_prepared, request_profiles};

/// What stops enrolment where it stands, read from the application and the computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conditions {
    pub linux: bool,
    pub locked: bool,
    pub signed_in: bool,
    /// Whether the latest check of ILM succeeded.
    pub fresh: bool,
}

impl Conditions {
    fn allow(&self) -> bool {
        !self.linux && !self.locked && self.signed_in && self.fresh
    }
}

/// What to enrol now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// The certificates prepared in ILM to complete.
    pub complete: Vec<Prepared>,
    /// The RA Profiles to request.
    pub request: Vec<RaProfileChoice>,
}

/// What to enrol at `now`, milliseconds since 1970 UTC: the open prepared certificates whose registration does not
/// ask for the challenge, when policy completes them, and the RA Profiles policy names that ILM lists for the
/// person. A certificate or profile that failed in the last day, a profile done once or requested and not yet
/// installed, and a certificate begun are left out.
#[allow(clippy::too_many_arguments)]
pub fn plan(
    now: i64,
    policy: &Layer,
    conditions: &Conditions,
    who: &SignedInAs,
    prepared: &[Prepared],
    profiles: &[RaProfileChoice],
    waiting: &[Waiting],
    standing: &Standing,
    offers: Vec<Offer>,
) -> Plan {
    if !conditions.allow() || allowed_offers(offers, policy).0.is_empty() {
        return Plan::default();
    }
    let complete = if complete_prepared(policy) {
        prepared
            .iter()
            .filter(|found| {
                found.is_open_at(now)
                    && !asks_for_challenge(found)
                    && !is_begun(&found.uuid, waiting)
                    && !standing.failed_within_a_day(&prepared_key(&found.uuid), now)
            })
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let request = requested(now, policy, who, profiles, waiting, standing);
    if !complete.is_empty() || !request.is_empty() {
        log::info!(
            "enrolment planned: {} prepared, {} requested",
            complete.len(),
            request.len()
        );
    }
    Plan { complete, request }
}

fn asks_for_challenge(found: &Prepared) -> bool {
    found.registration.as_ref().is_some_and(|registration| {
        registration.state == crate::ilm::certificates::RegistrationState::Active
    })
}

fn requested(
    now: i64,
    policy: &Layer,
    who: &SignedInAs,
    profiles: &[RaProfileChoice],
    waiting: &[Waiting],
    standing: &Standing,
) -> Vec<RaProfileChoice> {
    let names = request_profiles(policy);
    if names.is_empty() {
        return Vec::new();
    }
    if !who.creates_certificates() {
        log::warn!(
            "policy names RA Profiles to request from, but ILM does not let the person create certificates"
        );
        return Vec::new();
    }
    let mut seen = HashSet::new();
    let mut chosen = Vec::new();
    for name in names.iter().filter(|name| seen.insert(name.as_str())) {
        let Some(profile) = profiles.iter().find(|profile| &profile.name == name) else {
            log::warn!(
                "policy names the RA Profile {name}, which ILM does not list for the person"
            );
            continue;
        };
        let held_back = standing.is_done(&profile.uuid)
            || waiting.iter().any(|entry| entry.ra_profile == profile.uuid)
            || standing.failed_within_a_day(&profile_key(&profile.uuid), now);
        if !held_back {
            chosen.push(profile.clone());
        }
    }
    chosen
}
