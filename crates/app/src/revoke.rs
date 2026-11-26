//! The command that revokes a certificate of the person through ILM. It refuses while the application is locked
//! and while nobody is signed in, and when ILM does not let the person revoke the certificate.

use im_core::Platform;
use im_core::identity::{Fingerprint, KeyLocation};
use im_core::ilm::renew::Reason;
use im_core::inventory::Snapshot;
use im_core::session::RenewalTarget;
use tauri::{AppHandle, Runtime};

use crate::certificates::{Ilm, ilm};
use crate::renewal::{NOT_ALLOWED, NOT_HERE, parse};
use crate::request::{RequestFailure, RequestedView, requested, signed_in};

const NOT_REVOCABLE: &str = "This certificate cannot be revoked.";
const NOT_REMOVABLE: &str = "This certificate cannot be removed from this computer.";
const NOT_AVAILABLE: &str = "Revoking is not available on this system.";

/// The UUID of the certificate, when ILM lets the person revoke it: the latest check of ILM matched it and
/// `revoke` is among what ILM allows.
fn revocable(snapshot: Option<&Snapshot>, fingerprint: &Fingerprint) -> Result<String, String> {
    let (snapshot, found) = snapshot
        .and_then(|snapshot| Some((snapshot, snapshot.matches.get(fingerprint)?)))
        .ok_or_else(|| NOT_REVOCABLE.to_owned())?;
    let allowed = snapshot
        .allowed
        .get(&found.uuid)
        .is_some_and(|actions| actions.iter().any(|action| action == "revoke"));
    if allowed {
        Ok(found.uuid.clone())
    } else {
        Err(NOT_ALLOWED.to_owned())
    }
}

/// Whether the certificate may be removed from this computer once revoked: not when its key is in the Secure
/// Enclave or where it is not known, and not a smart-card certificate on macOS, which is on the card only.
fn removable(location: KeyLocation, platform: Platform, remove: bool) -> Result<(), String> {
    let fixed = match location {
        KeyLocation::SecureEnclave | KeyLocation::Unknown => true,
        KeyLocation::SmartCard => platform == Platform::Macos,
        _ => false,
    };
    if fixed && remove {
        Err(NOT_REMOVABLE.to_owned())
    } else {
        Ok(())
    }
}

impl<R: Runtime> Ilm<R> {
    /// Asks ILM to revoke the certificate for `reason`, and removes it from this computer once ILM has revoked it
    /// when `remove` says so.
    async fn revoke_certificate(
        &self,
        app: &AppHandle<R>,
        fingerprint: &str,
        reason: Reason,
        remove: bool,
    ) -> Result<RequestedView, RequestFailure> {
        self.unlocked()?;
        signed_in(self.session().signed_in_as())?;
        let platform = self.renewing(Vec::new()).platform;
        if platform == Platform::Linux {
            return Err(NOT_AVAILABLE.to_owned().into());
        }
        let fingerprint = parse(fingerprint)?;
        let local = self
            .local_certificates()
            .await?
            .into_iter()
            .find(|found| found.fingerprint == fingerprint)
            .ok_or_else(|| NOT_HERE.to_owned())?;
        let uuid = revocable(self.inventory.snapshot().as_ref(), &fingerprint)?;
        removable(local.location, platform, remove)?;
        self.unlocked()?;
        let target = RenewalTarget {
            uuid: &uuid,
            fingerprint: &fingerprint,
            name: &local.name,
        };
        let waiting = self
            .working(
                self.session()
                    .revoke(target, reason, remove, &|| self.unlocked().is_ok()),
            )
            .await;
        self.unlocked()?;
        Ok(requested(app, self, waiting?))
    }
}

#[tauri::command]
pub async fn revoke_certificate<R: Runtime>(
    app: AppHandle<R>,
    fingerprint: String,
    reason: Reason,
    remove: bool,
) -> Result<RequestedView, RequestFailure> {
    ilm(&app)
        .revoke_certificate(&app, &fingerprint, reason, remove)
        .await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use im_core::ilm::certificates::{IlmCertificate, RaProfile, State, ValidationStatus};

    use super::*;

    fn certificate(state: State) -> IlmCertificate {
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
            ra_profile: Some(RaProfile {
                uuid: "ra-1".to_owned(),
                name: "Servers".to_owned(),
                authority_uuid: None,
            }),
            owner: None,
            groups: Vec::new(),
            archived: false,
        }
    }

    fn snapshot(actions: &[&str]) -> Snapshot {
        let print = Fingerprint::of(b"a");
        Snapshot {
            checked_at: 1,
            listed: true,
            checked: vec![print],
            matches: HashMap::from([(print, certificate(State::Issued))]),
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
    fn a_certificate_is_revoked_only_where_ilm_allows_revoke() {
        let print = Fingerprint::of(b"a");
        let allowed = snapshot(&["detail", "revoke"]);
        assert_eq!(revocable(Some(&allowed), &print), Ok("u-1".to_owned()));

        let without = snapshot(&["detail", "renew"]);
        assert_eq!(
            revocable(Some(&without), &print),
            Err(NOT_ALLOWED.to_owned())
        );
    }

    #[test]
    fn a_certificate_that_is_unknown_to_the_latest_check_is_not_revocable() {
        let print = Fingerprint::of(b"a");
        let found = snapshot(&["revoke"]);

        assert_eq!(revocable(None, &print), Err(NOT_REVOCABLE.to_owned()));
        assert_eq!(
            revocable(Some(&found), &Fingerprint::of(b"other")),
            Err(NOT_REVOCABLE.to_owned())
        );
    }

    #[test]
    fn a_certificate_is_removed_only_from_a_key_location_the_app_can_remove_it_from() {
        for (location, platform) in [
            (KeyLocation::Keychain, Platform::Macos),
            (KeyLocation::Software, Platform::Windows),
            (KeyLocation::Tpm, Platform::Windows),
            (KeyLocation::SmartCard, Platform::Windows),
        ] {
            assert_eq!(removable(location, platform, true), Ok(()), "{location:?}");
        }
        for (location, platform) in [
            (KeyLocation::SecureEnclave, Platform::Macos),
            (KeyLocation::Unknown, Platform::Windows),
            (KeyLocation::SmartCard, Platform::Macos),
        ] {
            assert_eq!(
                removable(location, platform, true),
                Err(NOT_REMOVABLE.to_owned()),
                "{location:?} on {platform:?}"
            );
            assert_eq!(removable(location, platform, false), Ok(()), "{location:?}");
        }
    }
}
