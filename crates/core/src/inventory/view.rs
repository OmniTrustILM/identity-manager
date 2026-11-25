//! The inventory as the interface sees it: camelCase, times in milliseconds, no allowed actions.

use std::collections::HashMap;

use serde::Serialize;

use super::prepared::is_begun;
use super::{Counts, Item, Kind, Prepared, Snapshot, Status, SubjectPart, Summary, WaitingState};
use crate::attributes::FormView;
use crate::ilm::certificates::{CertificatePage, IlmCertificate, State};
use crate::ilm::upload::{GroupChoice, RaProfileChoice};
use crate::requests::Waiting;
use crate::session::{AddChoices, AddOutcome, AddResult, EndReason, Followed, Outcome};

/// The RA Profile that manages a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "IlmRaProfileView")
)]
pub struct IlmRaProfileView {
    pub uuid: String,
    pub name: String,
}

/// A certificate in ILM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct IlmCertificateView {
    pub uuid: String,
    pub name: String,
    pub subject_dn: Option<String>,
    pub issuer_name: Option<String>,
    pub serial: Option<String>,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
    pub not_before: Option<i64>,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
    pub not_after: Option<i64>,
    /// Uppercase hex pairs separated by colons, as in the local list.
    pub fingerprint: Option<String>,
    /// The public key as text, such as "RSA 2048".
    pub key: Option<String>,
    /// ILM's code, such as "issued"; a code this application does not know is passed on as it is.
    pub state: String,
    /// ILM's code, such as "valid"; a code this application does not know is passed on as it is.
    pub validation_status: String,
    pub ra_profile: Option<IlmRaProfileView>,
    pub owner: Option<String>,
    pub groups: Vec<String>,
    pub archived: bool,
}

impl From<&IlmCertificate> for IlmCertificateView {
    fn from(found: &IlmCertificate) -> Self {
        Self {
            uuid: found.uuid.clone(),
            name: found.name.clone(),
            subject_dn: found.subject_dn.clone(),
            issuer_name: found.issuer_name.clone(),
            serial: found.serial.clone(),
            not_before: found.not_before,
            not_after: found.not_after,
            fingerprint: found.fingerprint.map(|print| print.to_string()),
            key: found.key.clone(),
            state: found.state.code().to_owned(),
            validation_status: found.validation_status.code().to_owned(),
            ra_profile: found.ra_profile.as_ref().map(|profile| IlmRaProfileView {
                uuid: profile.uuid.clone(),
                name: profile.name.clone(),
            }),
            owner: found.owner.clone(),
            groups: found.groups.clone(),
            archived: found.archived,
        }
    }
}

/// One page of ILM's list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct IlmPageView {
    pub certificates: Vec<IlmCertificateView>,
    /// Starts at 1.
    pub page_number: u32,
    pub total_pages: u32,
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub total_items: u64,
}

impl From<&CertificatePage> for IlmPageView {
    fn from(page: &CertificatePage) -> Self {
        Self {
            certificates: page.certificates.iter().map(Into::into).collect(),
            page_number: page.page_number,
            total_pages: page.total_pages,
            total_items: page.total_items,
        }
    }
}

/// How ILM lets a certificate registered in advance be completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct RegistrationView {
    /// ILM's code: "active", "expired", "locked" or "closed"; a code this application does not know is passed on
    /// as it is.
    pub state: String,
    /// Milliseconds since 1970 (UTC); none when the registration does not expire.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
    pub expires_at: Option<i64>,
}

/// A certificate ILM registered for the person in advance, to complete with a key of this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct PreparedView {
    pub uuid: String,
    pub name: String,
    pub ra_profile: IlmRaProfileView,
    /// None when ILM does not say.
    pub registration: Option<RegistrationView>,
    /// What ILM registered; empty when it does not say.
    pub subject: Vec<SubjectPart>,
}

impl From<&Prepared> for PreparedView {
    fn from(found: &Prepared) -> Self {
        Self {
            uuid: found.uuid.clone(),
            name: found.name.clone(),
            ra_profile: IlmRaProfileView {
                uuid: found.ra_profile.uuid.clone(),
                name: found.ra_profile.name.clone(),
            },
            registration: found
                .registration
                .as_ref()
                .map(|registration| RegistrationView {
                    state: registration.state.code().to_owned(),
                    expires_at: registration.expires_at,
                }),
            subject: found.subject.clone(),
        }
    }
}

/// A request of the person that ILM has not finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct MyRequestView {
    /// The certificate ILM made for it; none while the request is not sent.
    pub uuid: Option<String>,
    pub label: String,
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub since: i64,
    pub state: WaitingStateView,
}

/// What ILM is known to say about the certificates on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct InventoryView {
    pub status: Status,
    /// A check is running now.
    pub checking: bool,
    /// When the snapshot was taken, milliseconds since 1970 (UTC); none before the first check.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
    pub checked_at: Option<i64>,
    /// Whether the signed-in person may list certificates in ILM: as the last check found out, else as ILM said
    /// at sign-in. When not, there are no matches and no first page.
    pub listed: bool,
    /// The fingerprints of the certificates on this computer that the last check looked up in ILM, as in the local
    /// list; empty before the first check and when ILM was not searched. A certificate here that is not among
    /// them was not looked up; one that is among them without a match is not in ILM.
    pub checked: Vec<String>,
    /// The certificates on this computer that ILM knows, by fingerprint.
    pub matches: HashMap<String, IlmCertificateView>,
    /// The fingerprint of the certificate ILM knows the person by.
    pub sign_in: Option<String>,
    pub first_page: Option<IlmPageView>,
    /// Whether the signed-in person may ask ILM for a certificate.
    pub can_request: bool,
    /// The certificates registered for the person in advance that they are not completing yet.
    pub prepared: Vec<PreparedView>,
    /// The requests of the person that ILM has not finished; given by `with_requests`.
    pub requests: Vec<MyRequestView>,
}

/// Whether the person may list certificates: what the latest check read, else what the session knows.
pub fn listed_by(snapshot: Option<&Snapshot>, session_lists: bool) -> bool {
    snapshot.map_or(session_lists, |snapshot| snapshot.listed)
}

impl InventoryView {
    /// `listed` is what the session knows, used while there is no snapshot.
    pub fn new(
        status: Status,
        snapshot: Option<&Snapshot>,
        checking: bool,
        listed: bool,
        can_request: bool,
    ) -> Self {
        Self {
            status,
            checking,
            checked_at: snapshot.map(|snapshot| snapshot.checked_at),
            listed: listed_by(snapshot, listed),
            checked: snapshot.map_or_else(Vec::new, |snapshot| {
                snapshot.checked.iter().map(ToString::to_string).collect()
            }),
            matches: snapshot.map_or_else(HashMap::new, |snapshot| {
                snapshot
                    .matches
                    .iter()
                    .map(|(print, found)| (print.to_string(), found.into()))
                    .collect()
            }),
            sign_in: snapshot
                .and_then(|snapshot| snapshot.sign_in.as_ref())
                .map(|certificate| certificate.fingerprint.to_string()),
            first_page: snapshot
                .and_then(|snapshot| snapshot.first_page.as_ref())
                .map(Into::into),
            can_request,
            prepared: snapshot.map_or_else(Vec::new, |snapshot| {
                snapshot.prepared.iter().map(Into::into).collect()
            }),
            requests: Vec::new(),
        }
    }

    /// Lists the requests `waiting` of the person, each as the latest `followed` check found it: the ones that
    /// ended are left out; one still waiting after its certificate was registered again is a new request. A
    /// certificate one of them completes, or completed, is not offered as prepared any more, unless ILM registered it
    /// again.
    #[must_use]
    pub fn with_requests(mut self, waiting: &[Waiting], followed: &[Followed]) -> Self {
        self.prepared
            .retain(|found| !is_begun(&found.uuid, waiting, followed));
        self.requests = waiting
            .iter()
            .filter_map(|entry| {
                let outcome = followed
                    .iter()
                    .find(|found| found.uuid.is_some() && found.uuid == entry.uuid)
                    .map(|found| &found.outcome);
                let state = match outcome {
                    Some(Outcome::Ended(EndReason::ReturnedToRegistered)) => {
                        WaitingStateView::BeingIssued
                    }
                    Some(Outcome::Installed(_) | Outcome::Ended(_)) => return None,
                    Some(Outcome::Waiting(State::PendingApproval)) => {
                        WaitingStateView::PendingApproval
                    }
                    _ => WaitingStateView::BeingIssued,
                };
                Some(MyRequestView {
                    uuid: entry.uuid.clone(),
                    label: entry.label.clone(),
                    since: entry.since,
                    state,
                })
            })
            .collect();
        self
    }
}

/// How the add of one certificate ended, as the interface shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct AddResultView {
    pub fingerprint: String,
    /// "added", "alreadyInIlm", "addedNotManaged" or "notAdded".
    pub outcome: String,
    /// ILM's messages for "addedNotManaged", the reason for "notAdded", else none.
    pub messages: Vec<String>,
}

impl From<AddResult> for AddResultView {
    fn from(result: AddResult) -> Self {
        let (outcome, messages) = match result.outcome {
            AddOutcome::Added => ("added", Vec::new()),
            AddOutcome::AlreadyInIlm => ("alreadyInIlm", Vec::new()),
            AddOutcome::AddedNotManaged(messages) => ("addedNotManaged", messages),
            AddOutcome::NotAdded(reason) => ("notAdded", vec![reason]),
        };
        Self {
            fingerprint: result.fingerprint,
            outcome: outcome.to_owned(),
            messages,
        }
    }
}

/// What the person may choose a group and an RA Profile from; none when ILM does not let them list it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct AddChoicesView {
    pub groups: Option<Vec<GroupChoice>>,
    pub ra_profiles: Option<Vec<RaProfileChoice>>,
    pub custom_attributes: Option<FormView>,
}

impl From<AddChoices> for AddChoicesView {
    fn from(choices: AddChoices) -> Self {
        Self {
            groups: choices.groups,
            ra_profiles: choices.ra_profiles,
            custom_attributes: choices.custom_attributes,
        }
    }
}

/// How many certificates are in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "SummaryCounts", rename_all = "camelCase")
)]
pub struct CountsView {
    pub valid: u32,
    pub expiring: u32,
    pub expired: u32,
    /// None when certificates are not listed or ILM has not been checked.
    pub not_in_ilm: Option<u32>,
}

impl From<Counts> for CountsView {
    fn from(counts: Counts) -> Self {
        Self {
            valid: counts.valid,
            expiring: counts.expiring,
            expired: counts.expired,
            not_in_ilm: counts.not_in_ilm,
        }
    }
}

/// One thing that needs attention; the certificate's fingerprint is as in the local list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(
        export,
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum AttentionItemView {
    Expiring {
        fingerprint: String,
        name: String,
        /// Days left, counting a started day as one.
        days: u32,
        /// Milliseconds since 1970 (UTC).
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        on: i64,
    },
    Expired {
        fingerprint: String,
        name: String,
        /// Milliseconds since 1970 (UTC).
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        on: i64,
    },
    Revoked {
        fingerprint: String,
        name: String,
    },
    /// Certificates on this computer that ILM does not know.
    NotInIlm {
        count: u32,
    },
    /// A request that ILM has not finished yet.
    Waiting {
        label: String,
        state: WaitingStateView,
    },
}

/// What ILM is doing with a request that is not yet a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum WaitingStateView {
    PendingApproval,
    BeingIssued,
}

impl From<&Item> for AttentionItemView {
    fn from(item: &Item) -> Self {
        let fingerprint = || {
            item.fingerprint
                .map(|print| print.to_string())
                .unwrap_or_default()
        };
        let name = || item.name.clone();
        match item.kind {
            Kind::Expiring { days, on } => Self::Expiring {
                fingerprint: fingerprint(),
                name: name(),
                days,
                on,
            },
            Kind::Expired { on } => Self::Expired {
                fingerprint: fingerprint(),
                name: name(),
                on,
            },
            Kind::Revoked => Self::Revoked {
                fingerprint: fingerprint(),
                name: name(),
            },
            Kind::NotInIlm { count } => Self::NotInIlm { count },
            Kind::Waiting { state } => Self::Waiting {
                label: name(),
                state: match state {
                    WaitingState::PendingApproval => WaitingStateView::PendingApproval,
                    WaitingState::BeingIssued => WaitingStateView::BeingIssued,
                },
            },
        }
    }
}

/// How the certificates on this computer stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct SummaryView {
    /// Milliseconds since 1970 (UTC).
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub computed_at: i64,
    /// When ILM was last checked, milliseconds since 1970 (UTC); none before the first check.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
    pub checked_at: Option<i64>,
    /// Whether the person may list certificates in ILM.
    pub listed: bool,
    pub counts: CountsView,
    pub attention: Vec<AttentionItemView>,
    /// Certificates expiring in each calendar month, the current one first.
    pub months: [u32; 12],
}

impl From<&Summary> for SummaryView {
    fn from(summary: &Summary) -> Self {
        Self {
            computed_at: summary.computed_at,
            checked_at: summary.checked_at,
            listed: summary.listed,
            counts: summary.counts.into(),
            attention: summary.attention.iter().map(Into::into).collect(),
            months: summary.months,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Fingerprint;
    use crate::ilm::IlmUrl;
    use crate::ilm::certificates::{RaProfile, RegistrationState, State, ValidationStatus};
    use crate::ilm::issue::Registration;
    use crate::ilm::profile::SignInCertificate;
    use crate::inventory::{SubjectKind, SubjectPart};
    use crate::keys::{KeyId, Storage};
    use crate::requests::Waiting;
    use crate::session::{EndReason, Followed, Outcome};
    use serde_json::json;

    fn certificate(fingerprint: Fingerprint) -> IlmCertificate {
        IlmCertificate {
            uuid: "u-1".to_owned(),
            name: "Ada".to_owned(),
            subject_dn: None,
            issuer_name: None,
            serial: None,
            not_before: Some(1),
            not_after: Some(2),
            fingerprint: Some(fingerprint),
            key: None,
            state: State::Issued,
            validation_status: ValidationStatus::Other("odd".to_owned()),
            ra_profile: None,
            owner: None,
            groups: Vec::new(),
            archived: false,
        }
    }

    fn snapshot(first_page: Option<CertificatePage>) -> Snapshot {
        let print = Fingerprint::of(b"a");
        Snapshot {
            checked_at: 5,
            listed: first_page.is_some(),
            checked: vec![print],
            matches: HashMap::from([(print, certificate(print))]),
            sign_in: Some(SignInCertificate {
                uuid: "u-1".to_owned(),
                fingerprint: print,
            }),
            first_page,
            allowed: HashMap::from([("u-1".to_owned(), vec!["renew".to_owned()])]),
            prepared: Vec::new(),
        }
    }

    #[test]
    fn a_request_in_progress_is_an_attention_item_with_its_label_and_state() {
        let item = Item {
            kind: Kind::Waiting {
                state: WaitingState::PendingApproval,
            },
            fingerprint: None,
            name: "User mTLS".to_owned(),
        };

        let json = serde_json::to_value(AttentionItemView::from(&item)).unwrap();

        assert_eq!(
            json,
            json!({ "kind": "waiting", "label": "User mTLS", "state": "pendingApproval" })
        );
    }

    #[test]
    fn a_snapshot_shows_its_matches_codes_and_sign_in_but_no_actions() {
        let page = CertificatePage {
            certificates: vec![certificate(Fingerprint::of(b"b"))],
            page_number: 1,
            total_pages: 1,
            total_items: 1,
            skipped: 0,
        };
        let view = InventoryView::new(
            Status::Fresh { checked_at: 5 },
            Some(&snapshot(Some(page))),
            true,
            true,
            true,
        );
        let json = serde_json::to_value(&view).unwrap();
        let key = Fingerprint::of(b"a").to_string();

        assert_eq!(json["checking"], true);
        assert_eq!(json["checkedAt"], 5);
        assert_eq!(json["listed"], true);
        assert_eq!(json["canRequest"], true);
        assert_eq!(json["checked"], json!([key]));
        assert_eq!(json["signIn"], key);
        assert_eq!(json["matches"][&key]["state"], "issued");
        assert_eq!(json["matches"][&key]["validationStatus"], "odd");
        assert_eq!(json["matches"][&key]["fingerprint"], key);
        assert_eq!(json["firstPage"]["totalItems"], 1);
        assert!(!json.to_string().contains("renew"));
    }

    #[test]
    fn without_a_first_page_certificates_are_not_listed() {
        let view = InventoryView::new(Status::Never, Some(&snapshot(None)), false, false, false);
        assert!(!view.listed);
        assert!(view.first_page.is_none());
    }

    #[test]
    fn the_snapshot_decides_whether_certificates_are_listed_not_the_session() {
        let listing = snapshot(None);
        let mut listing = Snapshot {
            listed: true,
            ..listing
        };
        assert!(InventoryView::new(Status::Never, Some(&listing), false, false, false).listed);
        listing.listed = false;
        assert!(!InventoryView::new(Status::Never, Some(&listing), false, true, false).listed);
    }

    #[test]
    fn before_the_first_check_there_is_nothing() {
        let view = InventoryView::new(Status::Never, None, false, true, false);
        assert!(view.listed);
        assert_eq!(view.checked_at, None);
        assert!(view.matches.is_empty() && view.sign_in.is_none() && view.checked.is_empty());
    }
    fn prepared(uuid: &str, state: Option<(&str, Option<i64>)>) -> Prepared {
        Prepared {
            uuid: uuid.to_owned(),
            name: format!("name of {uuid}"),
            ra_profile: RaProfile {
                uuid: "ra-1".to_owned(),
                name: "Servers".to_owned(),
                authority_uuid: Some("a-1".to_owned()),
            },
            registration: state.map(|(code, expires_at)| Registration {
                state: RegistrationState::from_code(code),
                expires_at,
            }),
            subject: vec![
                SubjectPart::new(SubjectKind::CommonName, "demo"),
                SubjectPart {
                    kind: SubjectKind::Other,
                    value: "x".to_owned(),
                    oid: Some("1.2.3".to_owned()),
                },
            ],
        }
    }

    fn waiting(uuid: Option<&str>, key: &str, since: i64) -> Waiting {
        Waiting {
            ilm: IlmUrl::parse("ilm.example.com").unwrap(),
            username: "jdoe".to_owned(),
            uuid: uuid.map(str::to_owned),
            ra_profile: "ra-1".to_owned(),
            authority: "a-1".to_owned(),
            key: KeyId {
                storage: Storage::Software,
                name: key.to_owned(),
            },
            label: format!("label of {key}"),
            since,
            prepared: false,
        }
    }

    fn followed(uuid: &str, outcome: Outcome) -> Followed {
        Followed {
            uuid: Some(uuid.to_owned()),
            label: "x".to_owned(),
            outcome,
        }
    }

    #[test]
    fn a_prepared_certificate_is_shown_with_its_registration_and_subject() {
        let mut held = snapshot(None);
        held.prepared = vec![
            prepared("c-1", Some(("active", Some(9)))),
            prepared("c-2", Some(("locked", None))),
            prepared("c-3", None),
        ];

        let view = InventoryView::new(Status::Never, Some(&held), false, true, true);

        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json["prepared"][0],
            json!({
                "uuid": "c-1",
                "name": "name of c-1",
                "raProfile": { "uuid": "ra-1", "name": "Servers" },
                "registration": { "state": "active", "expiresAt": 9 },
                "subject": [
                    { "kind": "commonName", "value": "demo", "oid": null },
                    { "kind": "other", "value": "x", "oid": "1.2.3" }
                ]
            })
        );
        assert_eq!(
            json["prepared"][1]["registration"],
            json!({ "state": "locked", "expiresAt": null })
        );
        assert_eq!(json["prepared"][2]["registration"], json!(null));
        assert_eq!(json["requests"], json!([]));
    }

    #[test]
    fn a_prepared_certificate_the_person_is_completing_is_not_listed() {
        let mut held = snapshot(None);
        held.prepared = vec![prepared("c-1", None), prepared("c-2", None)];

        let view = InventoryView::new(Status::Never, Some(&held), false, true, true)
            .with_requests(&[waiting(Some("c-2"), "k-2", 5)], &[]);

        let uuids: Vec<_> = view
            .prepared
            .iter()
            .map(|found| found.uuid.as_str())
            .collect();
        assert_eq!(uuids, ["c-1"]);
    }

    #[test]
    fn a_prepared_certificate_a_request_completed_is_listed_only_when_registered_again() {
        let mut held = snapshot(None);
        held.prepared = vec![
            prepared("c-1", None),
            prepared("c-2", None),
            prepared("c-3", None),
        ];
        let followed = [
            followed("c-1", Outcome::Ended(EndReason::ReturnedToRegistered)),
            followed("c-2", Outcome::Ended(EndReason::Rejected)),
            followed("c-3", Outcome::Mismatch),
        ];

        let view = InventoryView::new(Status::Never, Some(&held), false, true, true)
            .with_requests(&[], &followed);

        let uuids: Vec<_> = view
            .prepared
            .iter()
            .map(|found| found.uuid.as_str())
            .collect();
        assert_eq!(uuids, ["c-1"]);
    }

    #[test]
    fn the_requests_of_the_person_show_how_they_stand_and_those_that_ended_are_not_listed() {
        let followed = [
            followed("c-1", Outcome::Waiting(State::PendingApproval)),
            followed("c-2", Outcome::Waiting(State::PendingIssue)),
            followed("c-3", Outcome::Ended(EndReason::Rejected)),
            followed("c-4", Outcome::Mismatch),
            followed("c-5", Outcome::Ended(EndReason::ReturnedToRegistered)),
        ];
        let waiting = [
            waiting(Some("c-1"), "k-1", 10),
            waiting(Some("c-2"), "k-2", 20),
            waiting(Some("c-3"), "k-3", 30),
            waiting(Some("c-4"), "k-4", 40),
            waiting(Some("c-5"), "k-5", 50),
            waiting(None, "k-6", 60),
        ];

        let view = InventoryView::new(Status::Never, None, false, true, true)
            .with_requests(&waiting, &followed);

        assert_eq!(
            serde_json::to_value(&view.requests).unwrap(),
            json!([
                { "uuid": "c-1", "label": "label of k-1", "since": 10, "state": "pendingApproval" },
                { "uuid": "c-2", "label": "label of k-2", "since": 20, "state": "beingIssued" },
                { "uuid": "c-4", "label": "label of k-4", "since": 40, "state": "beingIssued" },
                { "uuid": "c-5", "label": "label of k-5", "since": 50, "state": "beingIssued" },
                { "uuid": null, "label": "label of k-6", "since": 60, "state": "beingIssued" }
            ])
        );
    }
}
