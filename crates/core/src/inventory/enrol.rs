//! Enrolment by policy at each check of ILM: what the policy asks for is completed and requested, and the RA
//! Profiles that need the person are kept for the screens.

use super::{AskedProfile, Inventory, Status, held, now};
use crate::app_info::Platform;
use crate::enrolment::{Conditions, plan};
use crate::session::{Enrolled, Session};
use crate::settings::{Layer, request_profiles};

impl Inventory {
    /// Enrols what `policy` asks for, in the way `Session::enrol` does, once the latest check of ILM succeeded.
    /// Nothing is enrolled on Linux, while nobody is signed in, or once `proceed` says no. The RA Profiles that
    /// need the person replace the ones kept before.
    pub async fn enrol_due(
        &self,
        session: &Session,
        policy: &Layer,
        platform: Platform,
        proceed: &(dyn Fn() -> bool + Sync),
    ) -> Vec<Enrolled> {
        let _alone = self.alone().await;
        let Some(who) = session.signed_in_as() else {
            return Vec::new();
        };
        let (epoch, fresh, prepared) = {
            let held = held(&self.held);
            (
                held.epoch,
                matches!(held.status, Status::Fresh { .. }),
                held.snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.prepared.clone())
                    .unwrap_or_default(),
            )
        };
        let conditions = Conditions {
            linux: platform == Platform::Linux,
            locked: !proceed(),
            signed_in: true,
            fresh,
        };
        if !conditions.allow() {
            return Vec::new();
        }
        let Some(standing) = session.standing() else {
            return Vec::new();
        };
        let profiles = if request_profiles(policy).is_empty() {
            Vec::new()
        } else {
            session.request_profiles().await.unwrap_or_else(|error| {
                log::warn!("the RA Profiles to enrol cannot be listed: {error}");
                Vec::new()
            })
        };
        let planned = plan(
            now(),
            policy,
            &conditions,
            &who,
            &prepared,
            &profiles,
            &session.waiting_requests(),
            &standing,
            session.key_offers().await,
        );
        let same_sign_in = || proceed() && held(&self.held).epoch == epoch;
        let done = session.enrol(&planned, policy, &same_sign_in).await;
        let asked = done
            .iter()
            .filter_map(|outcome| match outcome {
                Enrolled::Asked { profile, .. } => Some(AskedProfile {
                    uuid: profile.uuid.clone(),
                    name: profile.name.clone(),
                }),
                _ => None,
            })
            .collect();
        self.keep_asked(epoch, asked);
        if done
            .iter()
            .any(|outcome| matches!(outcome, Enrolled::Sent { .. }))
        {
            self.follow(session).await;
        }
        done
    }

    /// Keeps `asked` unless the sign-in ended meanwhile.
    fn keep_asked(&self, epoch: u64, asked: Vec<AskedProfile>) {
        let mut held = held(&self.held);
        if held.epoch != epoch || held.asked == asked {
            return;
        }
        held.asked = asked;
        held.rebuild(self.zone);
    }
}
