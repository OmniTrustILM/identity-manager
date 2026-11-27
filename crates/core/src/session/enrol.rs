//! Enrolment by policy: completing certificates registered in advance and requesting from RA Profiles without the
//! person, when ILM's own definitions give every value.
//!
//! Each request goes through the same paths as the person's own, so a key never outlives the knowledge of why it
//! exists. No value, subject, request, certificate or key handle goes to the log.

use std::sync::atomic::{AtomicBool, Ordering};

use super::request::{Origin, SignedIn};
use super::{ChangeError, RequestError, RequestForms, Session, SignedInAs};
use crate::attributes::Needs;
use crate::enrolment::{Plan, Standing, prepared_key, profile_key, sign_in_key};
use crate::ilm::upload::RaProfileChoice;
use crate::inventory::{Inventory, Prepared};
use crate::keys::{KeyType, Storage, preferred};
use crate::requests::Waiting;
use crate::session::Completion;
use crate::settings::{Layer, SignInMethod, allowed_offers, sign_in_certificate_profile};

use super::request::{may_have_arrived, now_ms};

/// What became of one item of a plan.
#[derive(Debug, PartialEq, Eq)]
pub enum Enrolled {
    /// ILM took the request; `key` is the enrolment key of the item and `uuid` the certificate ILM is making.
    Sent { key: String, uuid: String },
    /// The RA Profile needs the person; nothing was created.
    Asked {
        profile: RaProfileChoice,
        reason: Needs,
    },
    /// The certificate registered in advance needs the person; nothing was created.
    PreparedAsked { uuid: String, reason: Needs },
    /// The request failed and the failure is recorded; the key and the written request are gone, except for a
    /// completion whose answer was lost.
    Failed { key: String, error: RequestError },
    /// The caller's `proceed` said no, or the sign-in ended; the rest of the plan is left.
    Stopped,
}

/// How many failed attempts at making a certificate the sign-in certificate the person is told about.
const SIGN_IN_FAILURES_BEFORE_NOTICE: u32 = 3;

/// What became of a certificate that enrolment installed and policy wants as the sign-in certificate.
#[derive(Debug, PartialEq, Eq)]
pub enum SignInByPolicy {
    /// The certificate `uuid` is the sign-in certificate now.
    Set { uuid: String },
    /// ILM did not take the change; the certificate `uuid` stays installed and the change is tried again after
    /// a day. `failures` counts the attempts that failed since the last success.
    Failed { uuid: String, failures: u32 },
}

impl SignInByPolicy {
    /// Whether this is the failure the person is told about, which happens once.
    pub fn needs_notice(&self) -> bool {
        matches!(
            self,
            Self::Failed { failures, .. } if *failures == SIGN_IN_FAILURES_BEFORE_NOTICE
        )
    }
}

/// One item of a plan.
enum Item<'a> {
    Prepared(&'a Prepared),
    Profile(&'a RaProfileChoice),
}

/// What every item of one run shares.
struct Run<'a> {
    who: SignedIn,
    storage: Storage,
    key_type: KeyType,
    proceed: &'a (dyn Fn() -> bool + Sync),
}

impl Run<'_> {
    fn origin(&self) -> Origin<'_> {
        Origin {
            enrolled: true,
            proceed: Some(self.proceed),
        }
    }
}

impl Session {
    /// Enrols what `plan` says, one item after the other, in the key storage `policy` chooses (its default, else
    /// the first it allows) with its preferred key type. Items are sent with `proceed` asked before each; when it
    /// says no, or the sign-in ends, the run stops. An item the person is needed for, and one already waiting, creates nothing.
    pub async fn enrol(
        &self,
        plan: &Plan,
        policy: &Layer,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Vec<Enrolled> {
        let (Some(who), Some(_)) = (self.current_sign_in(), &self.enrolments) else {
            return Vec::new();
        };
        let (offers, storage) = allowed_offers(self.key_offers().await, policy);
        let Some((storage, key_type)) = offers
            .iter()
            .find(|offer| Some(offer.storage) == storage)
            .and_then(|offer| preferred(offer).map(|key_type| (offer.storage, key_type)))
        else {
            return Vec::new();
        };
        let id = who.id.clone();
        let still_signed_in = || proceed() && self.is_sign_in(&id);
        let run = Run {
            who,
            storage,
            key_type,
            proceed: &still_signed_in,
        };
        let items = plan
            .complete
            .iter()
            .map(Item::Prepared)
            .chain(plan.request.iter().map(Item::Profile));
        let mut done = Vec::new();
        for item in items {
            let outcome = if (run.proceed)() {
                match item {
                    Item::Prepared(found) => self.enrol_prepared(&run, found).await,
                    Item::Profile(profile) => self.enrol_profile(&run, profile).await,
                }
            } else {
                Some(Enrolled::Stopped)
            };
            let Some(outcome) = outcome else { continue };
            let stopped = outcome == Enrolled::Stopped;
            done.push(outcome);
            if stopped {
                break;
            }
        }
        done
    }

    async fn enrol_prepared(&self, run: &Run<'_>, found: &Prepared) -> Option<Enrolled> {
        let key = prepared_key(&found.uuid);
        let Some(authority) = found.ra_profile.authority_uuid.as_deref() else {
            return self.failed(run, key, RequestError::NoAuthority);
        };
        let forms = match self
            .open_request_forms(authority, &found.ra_profile.uuid, true)
            .await
        {
            Ok(forms) => forms,
            Err(error) => return self.failed(run, key, ChangeError::from(error).into()),
        };
        let outcome = match self.unattended_forms(&forms) {
            Err(reason) => {
                log::info!(
                    "enrolment asked: certificate {}, {}",
                    found.uuid,
                    reason.code()
                );
                Some(Enrolled::PreparedAsked {
                    uuid: found.uuid.clone(),
                    reason,
                })
            }
            Ok(input) => {
                let choice = RaProfileChoice {
                    uuid: found.ra_profile.uuid.clone(),
                    name: found.ra_profile.name.clone(),
                    description: None,
                    authority: None,
                    authority_uuid: Some(authority.to_owned()),
                };
                let sent = self
                    .complete_from(
                        Completion {
                            uuid: &found.uuid,
                            name: &found.name,
                            ra_profile: &choice,
                            subject: &found.subject,
                        },
                        input,
                        run.storage,
                        run.key_type,
                        None,
                        run.origin(),
                    )
                    .await;
                self.sent(run, key, &found.uuid, true, sent)
            }
        };
        self.close_request_forms(&forms);
        outcome
    }

    async fn enrol_profile(&self, run: &Run<'_>, profile: &RaProfileChoice) -> Option<Enrolled> {
        let key = profile_key(&profile.uuid);
        let Some(authority) = profile.authority_uuid.as_deref() else {
            return self.failed(run, key, RequestError::NoAuthority);
        };
        let forms = match self
            .open_request_forms(authority, &profile.uuid, false)
            .await
        {
            Ok(forms) => forms,
            Err(error) => return self.failed(run, key, ChangeError::from(error).into()),
        };
        let outcome = match self.unattended_forms(&forms) {
            Err(reason) => {
                log::info!(
                    "enrolment asked: RA Profile {}, {}",
                    profile.uuid,
                    reason.code()
                );
                Some(Enrolled::Asked {
                    profile: profile.clone(),
                    reason,
                })
            }
            Ok(input) => match self.claim(run, &profile.uuid) {
                Err(error) => {
                    log::warn!("the enrolment cannot be written down: {error}");
                    self.failed(run, key, RequestError::Store)
                }
                Ok(false) => None,
                Ok(true) => {
                    let leaving = AtomicBool::new(false);
                    let proceed = || {
                        let go = (run.proceed)();
                        leaving.fetch_or(go, Ordering::SeqCst);
                        go
                    };
                    let origin = Origin {
                        enrolled: true,
                        proceed: Some(&proceed),
                    };
                    let sent = self
                        .request_from(profile, input, run.storage, run.key_type, origin)
                        .await;
                    let left = leaving.load(Ordering::SeqCst);
                    self.release_unless_sent(run, &profile.uuid, left, &sent);
                    self.sent(run, key, &profile.uuid, false, sent)
                }
            },
        };
        self.close_request_forms(&forms);
        outcome
    }

    /// Notes the RA Profile as done before its request is sent, so that it is never sent twice; whether it was not
    /// done yet.
    fn claim(&self, run: &Run<'_>, ra_profile: &str) -> std::io::Result<bool> {
        match &self.enrolments {
            Some(enrolments) => enrolments.mark_done(&run.who.ilm, &run.who.username, ra_profile),
            None => Ok(false),
        }
    }

    /// Forgets that the RA Profile is done when ILM surely did not get its request: nothing `left` for ILM, or ILM
    /// answered that it did not take it. One whose answer was lost may have arrived and stays done: the person can
    /// still request it.
    fn release_unless_sent(
        &self,
        run: &Run<'_>,
        ra_profile: &str,
        left: bool,
        sent: &Result<Waiting, RequestError>,
    ) {
        match sent {
            Err(error) if left && may_have_arrived(error) => {
                log::warn!(
                    "the answer to the request of the RA Profile {ra_profile} was lost; it is not requested again"
                );
            }
            Err(_) => {
                if let Some(enrolments) = &self.enrolments
                    && let Err(error) =
                        enrolments.unmark_done(&run.who.ilm, &run.who.username, ra_profile)
                {
                    log::warn!("the enrolment cannot be written down: {error}");
                }
            }
            Ok(_) => {}
        }
    }

    /// Records a failure of the certificate prepared in ILM when its completion by enrolment ended without a
    /// certificate here, so it is not completed again for a day.
    pub(super) fn note_failed_enrolment(&self, entry: &Waiting) {
        if let (true, true, Some(uuid), Some(enrolments)) = (
            entry.enrolled,
            entry.prepared,
            &entry.uuid,
            &self.enrolments,
        ) && let Err(error) =
            enrolments.record_failure(&entry.ilm, &entry.username, &prepared_key(uuid), now_ms())
        {
            log::warn!("the enrolment cannot be written down: {error}");
        }
    }

    /// What the answer to a request or completion means for the item `key` is of; `what` is the UUID the log names.
    fn sent(
        &self,
        run: &Run<'_>,
        key: String,
        what: &str,
        prepared: bool,
        sent: Result<Waiting, RequestError>,
    ) -> Option<Enrolled> {
        match sent {
            Ok(Waiting {
                uuid: Some(uuid), ..
            }) => {
                log::info!(
                    "enrolment sent: {what}, {:?}, {:?}, prepared: {}",
                    run.storage,
                    run.key_type,
                    if prepared { "yes" } else { "no" }
                );
                if let Some(enrolments) = &self.enrolments
                    && let Err(error) =
                        enrolments.clear_failure(&run.who.ilm, &run.who.username, &key)
                {
                    log::warn!("the enrolment cannot be written down: {error}");
                }
                Some(Enrolled::Sent { key, uuid })
            }
            Ok(_) => self.failed(run, key, RequestError::Malformed),
            Err(RequestError::AlreadyRequested) => None,
            Err(RequestError::SignedOut | RequestError::Withdrawn) => Some(Enrolled::Stopped),
            Err(error) => self.failed(run, key, error),
        }
    }

    /// Records that the attempt at `key` failed, so it is not made again for a day.
    fn failed(&self, run: &Run<'_>, key: String, error: RequestError) -> Option<Enrolled> {
        let (status, texts) = match &error {
            RequestError::NotAllowed => ("403".to_owned(), 0),
            RequestError::Unexpected(status) => (status.to_string(), 0),
            RequestError::Refused(texts) => ("refused".to_owned(), texts.len()),
            _ => ("not sent".to_owned(), 0),
        };
        log::warn!("enrolment failed ({status}), {texts} texts");
        if let Some(enrolments) = &self.enrolments
            && let Err(error) =
                enrolments.record_failure(&run.who.ilm, &run.who.username, &key, now_ms())
        {
            log::warn!("the enrolment cannot be written down: {error}");
        }
        Some(Enrolled::Failed { key, error })
    }

    fn close_request_forms(&self, forms: &RequestForms) {
        for form in [&forms.request, &forms.issue, &forms.custom]
            .into_iter()
            .flatten()
        {
            self.close_form(&form.id);
        }
    }

    /// Makes the certificates enrolment installed, and only those from the RA Profile policy names for the
    /// sign-in certificate, the person's sign-in certificate in ILM. It needs the latest check of `inventory` to
    /// have matched the certificate here. Nothing changes under a provider-only policy, for a certificate that is
    /// not installed here with its key or already signs in. A change that failed waits a day.
    pub async fn sign_in_by_policy(
        &self,
        inventory: &Inventory,
        policy: &Layer,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Vec<SignInByPolicy> {
        let Some(id) = self.current_sign_in().map(|signed_in| signed_in.id) else {
            return Vec::new();
        };
        let (Some(profile), Some(who), Some(enrolments)) = (
            sign_in_certificate_profile(policy),
            self.signed_in_as(),
            &self.enrolments,
        ) else {
            return Vec::new();
        };
        if policy.sign_in_method == Some(SignInMethod::Oauth) {
            return Vec::new();
        }
        let (Ok(standing), Some(snapshot)) = (
            enrolments.standing(&who.ilm, &who.username),
            inventory.snapshot(),
        ) else {
            return Vec::new();
        };
        let still_signed_in = || proceed() && self.is_sign_in(&id);
        let mut done = Vec::new();
        for uuid in &standing.installed {
            if !still_signed_in() {
                break;
            }
            let Some((fingerprint, certificate)) = snapshot
                .matches
                .iter()
                .find(|(_, certificate)| &certificate.uuid == uuid)
            else {
                continue;
            };
            let named = certificate
                .ra_profile
                .as_ref()
                .is_some_and(|found| found.name == profile);
            let signs_in = snapshot
                .sign_in
                .as_ref()
                .is_some_and(|held| &held.uuid == uuid);
            if !named || signs_in {
                self.settle(&who, uuid);
                continue;
            }
            if standing.failed_within_a_day(&sign_in_key(uuid), now_ms()) {
                continue;
            }
            let outcome = self
                .make_sign_in_certificate(inventory, &fingerprint.to_string(), still_signed_in)
                .await;
            match outcome {
                Ok(()) | Err(ChangeError::AlreadySignIn) => {
                    log::info!("sign-in certificate set by policy: {uuid}");
                    self.settle(&who, uuid);
                    done.push(SignInByPolicy::Set { uuid: uuid.clone() });
                }
                Err(ChangeError::SignedOut | ChangeError::Offline | ChangeError::Withdrawn) => {
                    break;
                }
                Err(_) => done.push(self.sign_in_failed(&who, &standing, uuid)),
            }
        }
        done
    }

    /// The certificate `uuid` is settled: it is the sign-in certificate or never will be, and what failed is
    /// forgotten.
    fn settle(&self, who: &SignedInAs, uuid: &str) {
        if let Some(enrolments) = &self.enrolments
            && let Err(error) = enrolments
                .clear_installed(&who.ilm, &who.username, uuid)
                .and_then(|()| {
                    enrolments.clear_failure(&who.ilm, &who.username, &sign_in_key(uuid))
                })
        {
            log::warn!("the enrolment cannot be written down: {error}");
        }
    }

    fn sign_in_failed(&self, who: &SignedInAs, standing: &Standing, uuid: &str) -> SignInByPolicy {
        let key = sign_in_key(uuid);
        if let Some(enrolments) = &self.enrolments
            && let Err(error) = enrolments.record_failure(&who.ilm, &who.username, &key, now_ms())
        {
            log::warn!("the enrolment cannot be written down: {error}");
        }
        let failures = standing.failures(&key).saturating_add(1);
        log::warn!("the sign-in certificate {uuid} could not be set by policy ({failures} failed)");
        SignInByPolicy::Failed {
            uuid: uuid.to_owned(),
            failures,
        }
    }
}
