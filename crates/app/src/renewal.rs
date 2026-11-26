//! The commands of renewal: renewing a certificate now, and switching its automatic renewal on or off. Both
//! refuse while the application is locked and while nobody is signed in. Renewing also needs ILM to let the
//! person renew the certificate, and the switch is the person's to change only where policy leaves it.

use im_core::Platform;
use im_core::identity::Fingerprint;
use im_core::inventory::{InventoryView, Snapshot};
use im_core::renewal::{self, NeedsYou, Skip};
use im_core::session::RenewalTarget;
use im_core::settings::Layer;
use tauri::{AppHandle, Runtime, Window};

use crate::certificates::{Ilm, ilm};
use crate::request::{RequestFailure, RequestedView, requested, signed_in, told_by_notification};
use crate::summary;

const NOT_ALLOWED: &str = "ILM does not allow this.";
const NOT_RENEWABLE: &str = "This certificate cannot be renewed.";
const NOT_HERE: &str = "This certificate is not on this computer.";
const SMART_CARD: &str = "A certificate with its key on a smart card cannot be renewed here.";
const NOT_AVAILABLE: &str = "Renewing is not available on this system.";
const LOCKED_BY_POLICY: &str = "Automatic renewal is managed by your organization.";

fn parse(fingerprint: &str) -> Result<Fingerprint, String> {
    fingerprint.parse().map_err(|_| NOT_HERE.to_owned())
}

/// The UUID of the certificate, when ILM lets the person renew it: it is known in ILM as an issued certificate
/// with an RA Profile and `renew` is among what ILM allows.
fn renewable(snapshot: Option<&Snapshot>, fingerprint: &Fingerprint) -> Result<String, String> {
    let (snapshot, found) = snapshot
        .and_then(|snapshot| Some((snapshot, snapshot.matches.get(fingerprint)?)))
        .ok_or_else(|| NOT_RENEWABLE.to_owned())?;
    let allowed = snapshot
        .allowed
        .get(&found.uuid)
        .map_or(&[][..], Vec::as_slice);
    renewal::candidate(found, allowed).map_err(|skip| match skip {
        Skip::RenewNotAllowed => NOT_ALLOWED.to_owned(),
        _ => NOT_RENEWABLE.to_owned(),
    })?;
    Ok(found.uuid.clone())
}

/// Whether the person may change the switch: policy that turns renewal off fixes every switch.
fn switchable(policy: &Layer) -> Result<(), String> {
    if renewal::permitted(policy) {
        Ok(())
    } else {
        Err(LOCKED_BY_POLICY.to_owned())
    }
}

impl<R: Runtime> Ilm<R> {
    /// Renews the certificate now with the method the setting gives, a new key where the setting is off. The
    /// switch and the wait after a failed attempt do not count; what ILM allows does.
    async fn renew_now(
        &self,
        app: &AppHandle<R>,
        from_summary: bool,
        fingerprint: &str,
    ) -> Result<RequestedView, RequestFailure> {
        self.unlocked()?;
        signed_in(self.session().signed_in_as())?;
        let plan = self.renewing(self.session().key_offers().await);
        if plan.platform == Platform::Linux {
            return Err(NOT_AVAILABLE.to_owned().into());
        }
        let fingerprint = parse(fingerprint)?;
        let local = self
            .local_certificates()
            .await?
            .into_iter()
            .find(|found| found.fingerprint == fingerprint)
            .ok_or_else(|| NOT_HERE.to_owned())?;
        let snapshot = self.inventory.snapshot();
        let uuid = renewable(snapshot.as_ref(), &fingerprint)?;
        let method = renewal::method(
            &local,
            renewal::manual_choice(&plan.policy, &plan.person),
            &plan.offers,
            true,
            plan.platform,
        )
        .map_err(|NeedsYou::SmartCardOnMacos| SMART_CARD.to_owned())?;
        self.unlocked()?;
        let target = RenewalTarget {
            uuid: &uuid,
            fingerprint: &fingerprint,
            name: &local.name,
        };
        let waiting = self
            .working(self.session().renew(target, method, false))
            .await;
        self.unlocked()?;
        let waiting = waiting?;
        // The tray summary can be dismissed while the renewal waits, so it leaves the end to a notification.
        Ok(if from_summary {
            told_by_notification(waiting)
        } else {
            requested(app, self, waiting)
        })
    }

    /// Switches the automatic renewal of a certificate on this computer on or off.
    async fn switch_renewal(&self, fingerprint: &str, on: bool) -> Result<InventoryView, String> {
        self.unlocked()?;
        let who = signed_in(self.session().signed_in_as())?;
        let fingerprint = parse(fingerprint)?;
        if !self.inventory.local_fingerprints().contains(&fingerprint) {
            return Err(NOT_HERE.to_owned());
        }
        switchable(&self.renewing(Vec::new()).policy)?;
        self.renewals()
            .set_off(&who.ilm, &who.username, &fingerprint, !on)
            .map_err(|error| {
                log::warn!("the renewal switch cannot be saved: {error}");
                "The switch could not be saved.".to_owned()
            })?;
        log::info!(
            "automatic renewal switched {}",
            if on { "on" } else { "off" }
        );
        self.changed();
        self.locked_view().await
    }
}

#[tauri::command]
pub async fn renew_now<R: Runtime>(
    app: AppHandle<R>,
    window: Window<R>,
    fingerprint: String,
) -> Result<RequestedView, RequestFailure> {
    let from_summary = window.label() == summary::LABEL;
    ilm(&app).renew_now(&app, from_summary, &fingerprint).await
}

#[tauri::command]
pub async fn set_renewal_switch<R: Runtime>(
    app: AppHandle<R>,
    fingerprint: String,
    on: bool,
) -> Result<InventoryView, String> {
    ilm(&app).switch_renewal(&fingerprint, on).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use im_core::ilm::certificates::{IlmCertificate, RaProfile, State, ValidationStatus};
    use im_core::settings::AutomaticRenewal;

    use super::*;

    fn certificate(state: State, managed: bool) -> IlmCertificate {
        IlmCertificate {
            uuid: "u-1".to_owned(),
            name: "Ada".to_owned(),
            subject_dn: None,
            issuer_name: None,
            serial: None,
            not_before: None,
            not_after: None,
            fingerprint: Some(Fingerprint::of(b"a")),
            key: None,
            state,
            validation_status: ValidationStatus::Valid,
            ra_profile: managed.then(|| RaProfile {
                uuid: "ra-1".to_owned(),
                name: "Servers".to_owned(),
                authority_uuid: None,
            }),
            owner: None,
            groups: Vec::new(),
            archived: false,
        }
    }

    fn snapshot(found: IlmCertificate, actions: &[&str]) -> Snapshot {
        let print = Fingerprint::of(b"a");
        Snapshot {
            checked_at: 1,
            listed: true,
            checked: vec![print],
            matches: HashMap::from([(print, found)]),
            sign_in: None,
            first_page: None,
            allowed: HashMap::from([(
                "u-1".to_owned(),
                actions.iter().map(|action| (*action).to_owned()).collect(),
            )]),
            prepared: Vec::new(),
            approvals: Vec::new(),
            replaced: Default::default(),
        }
    }

    #[test]
    fn a_certificate_is_renewed_only_where_ilm_allows_renew() {
        let print = Fingerprint::of(b"a");
        let allowed = snapshot(certificate(State::Issued, true), &["detail", "renew"]);
        assert_eq!(renewable(Some(&allowed), &print), Ok("u-1".to_owned()));

        let without = snapshot(certificate(State::Issued, true), &["detail", "revoke"]);
        assert_eq!(
            renewable(Some(&without), &print),
            Err(NOT_ALLOWED.to_owned())
        );
    }

    #[test]
    fn a_certificate_that_is_unknown_unmanaged_or_not_issued_is_not_renewable() {
        let print = Fingerprint::of(b"a");
        let unmanaged = snapshot(certificate(State::Issued, false), &["renew"]);
        let revoked = snapshot(certificate(State::Revoked, true), &["renew"]);
        let found = snapshot(certificate(State::Issued, true), &["renew"]);

        assert_eq!(renewable(None, &print), Err(NOT_RENEWABLE.to_owned()));
        assert_eq!(
            renewable(Some(&unmanaged), &print),
            Err(NOT_RENEWABLE.to_owned())
        );
        assert_eq!(
            renewable(Some(&revoked), &print),
            Err(NOT_RENEWABLE.to_owned())
        );
        assert_eq!(
            renewable(Some(&found), &Fingerprint::of(b"other")),
            Err(NOT_RENEWABLE.to_owned())
        );
    }

    #[test]
    fn only_policy_that_turns_renewal_off_fixes_the_switch() {
        let with = |value| Layer {
            automatic_renewal: value,
            ..Layer::default()
        };

        assert!(switchable(&with(None)).is_ok());
        assert!(switchable(&with(Some(AutomaticRenewal::SameKey))).is_ok());
        assert_eq!(
            switchable(&with(Some(AutomaticRenewal::Off))),
            Err(LOCKED_BY_POLICY.to_owned())
        );
    }
}
