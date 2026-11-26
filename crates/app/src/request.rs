//! The commands of the request wizard: the RA Profiles to ask, the forms of a request, the key storages this
//! computer and the organization offer, the request itself, and following it until the certificate is installed.
//! Every command refuses while the application is locked and while nobody is signed in; asking for a certificate
//! also needs ILM to allow it. Values come from the interface only as typed by the person.

use im_core::attributes::{FieldProblem, FormView};
use im_core::ilm::certificates::State;
use im_core::ilm::issue::Challenge;
use im_core::ilm::upload::RaProfileChoice;
use im_core::inventory::{Prepared, SubjectPart};
use im_core::keys::{KeyType, Offer, Storage};
use im_core::session::{
    CallError, Completion, EndReason, Followed, Installed, Outcome, RequestError, RequestInput,
    SignedInAs,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, Runtime};

use im_core::requests::Waiting;

use crate::certificates::{Ilm, ilm};
use crate::settings::Settings;

const NOT_ALLOWED: &str = "ILM does not allow this.";

/// A key storage of this computer, named as the interface and the policy name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum StorageId {
    Keychain,
    Software,
    Tpm,
}

impl From<Storage> for StorageId {
    fn from(storage: Storage) -> Self {
        match storage {
            Storage::Keychain => Self::Keychain,
            Storage::Software => Self::Software,
            Storage::Tpm => Self::Tpm,
        }
    }
}

impl From<StorageId> for Storage {
    fn from(id: StorageId) -> Self {
        match id {
            StorageId::Keychain => Self::Keychain,
            StorageId::Software => Self::Software,
            StorageId::Tpm => Self::Tpm,
        }
    }
}

/// A kind of key as the interface names it: `rsa2048`, `rsa3072`, `rsa4096`, `ecP256`, `ecP384`, `ecP521`,
/// `mlDsa44`, `mlDsa65` or `mlDsa87`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, type = "string"))]
pub struct KeyTypeId(KeyType);

impl KeyTypeId {
    fn name(self) -> String {
        match self.0 {
            KeyType::Rsa { bits } => format!("rsa{bits}"),
            KeyType::EcP256 => "ecP256".to_owned(),
            KeyType::EcP384 => "ecP384".to_owned(),
            KeyType::EcP521 => "ecP521".to_owned(),
            KeyType::MlDsa44 => "mlDsa44".to_owned(),
            KeyType::MlDsa65 => "mlDsa65".to_owned(),
            KeyType::MlDsa87 => "mlDsa87".to_owned(),
        }
    }

    fn parse(name: &str) -> Option<Self> {
        let key_type = match name {
            "ecP256" => KeyType::EcP256,
            "ecP384" => KeyType::EcP384,
            "ecP521" => KeyType::EcP521,
            "mlDsa44" => KeyType::MlDsa44,
            "mlDsa65" => KeyType::MlDsa65,
            "mlDsa87" => KeyType::MlDsa87,
            other => KeyType::Rsa {
                bits: other.strip_prefix("rsa")?.parse().ok()?,
            },
        };
        Some(Self(key_type))
    }
}

impl Serialize for KeyTypeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name())
    }
}

impl<'de> Deserialize<'de> for KeyTypeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::parse(&name).ok_or_else(|| serde::de::Error::custom("unknown key type"))
    }
}

/// A key storage the person may choose, with the key types it creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub struct StorageOffer {
    pub storage: StorageId,
    pub key_types: Vec<KeyTypeId>,
}

/// What this computer and the organization let the person keep a new key in. Without a storage, nothing is
/// allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub struct RequestOffers {
    pub storages: Vec<StorageOffer>,
    /// The storage to preselect and mark as recommended: the organization's choice, else the first offered.
    pub default_storage: Option<StorageId>,
}

fn offers_view(allowed: Vec<Offer>, preselected: Option<Storage>) -> RequestOffers {
    RequestOffers {
        storages: allowed
            .into_iter()
            .map(|offer| StorageOffer {
                storage: offer.storage.into(),
                key_types: offer.types.into_iter().map(KeyTypeId).collect(),
            })
            .collect(),
        default_storage: preselected.map(Into::into),
    }
}

/// The three forms of a request, each as the attribute form component shows it; none when ILM has no attributes
/// of that kind for the person. The request form is the subject; the other two are what ILM asks of the RA
/// Profile and of every certificate.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct RequestFormsView {
    pub request: Option<FormView>,
    pub issue: Option<FormView>,
    pub custom: Option<FormView>,
}

/// The request ILM took: the certificate it made, to follow, and the name to show it by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub struct RequestedView {
    pub certificate: String,
    pub label: String,
}

/// Why a request was not made. Nothing is left on this computer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(
        export,
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum RequestFailure {
    /// The words for the person.
    Message { message: String },
    /// ILM's messages, to show as they are.
    Refused { messages: Vec<String> },
    /// The fields of the forms that have a problem; nothing was sent.
    Problems { problems: Vec<FieldProblem> },
}

impl From<String> for RequestFailure {
    fn from(message: String) -> Self {
        Self::Message { message }
    }
}

impl From<RequestError> for RequestFailure {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Refused(messages) if !messages.is_empty() => Self::Refused { messages },
            RequestError::FormProblems(problems) => Self::Problems { problems },
            other => other.to_string().into(),
        }
    }
}

/// What ILM is doing with a request that is not yet a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum WaitingStage {
    PendingApproval,
    BeingIssued,
}

/// Why a request ended without a certificate on this computer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum EndedReason {
    Rejected,
    Failed,
    /// Anything else: ILM no longer has the request, its key is gone, or the like.
    Other,
}

/// Why an issued certificate is not installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum NotInstalledCause {
    /// ILM issued a certificate for another key.
    OtherKey,
    /// The system refused the certificate; the next check tries again.
    InstallFailed,
}

/// How a request stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(
        export,
        tag = "state",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum FollowView {
    /// The certificate is in the store of this computer.
    Installed {
        storage: StorageId,
        /// Milliseconds since 1970 (UTC).
        #[cfg_attr(test, ts(type = "number"))]
        valid_until: i64,
    },
    Waiting {
        stage: WaitingStage,
    },
    Ended {
        reason: EndedReason,
    },
    NotInstalled {
        cause: NotInstalledCause,
    },
    /// Nothing is known of the request now: ILM did not answer, or another check has finished it.
    Unknown,
}

impl From<&Outcome> for FollowView {
    fn from(outcome: &Outcome) -> Self {
        match outcome {
            Outcome::Installed(Installed {
                storage: Some(storage),
                not_after,
            }) => Self::Installed {
                storage: (*storage).into(),
                valid_until: *not_after,
            },
            // A renewal that kept its key has no storage to name; the wizard follows new requests only.
            Outcome::Installed(_)
            | Outcome::SwitchPending { .. }
            | Outcome::SignInMoved
            | Outcome::Revoking
            | Outcome::Revoked { .. }
            | Outcome::NotRevoked => Self::Unknown,
            Outcome::Waiting(State::PendingApproval) => Self::Waiting {
                stage: WaitingStage::PendingApproval,
            },
            Outcome::Waiting(_) => Self::Waiting {
                stage: WaitingStage::BeingIssued,
            },
            Outcome::Ended(reason) => Self::Ended {
                reason: match reason {
                    EndReason::Rejected => EndedReason::Rejected,
                    EndReason::Failed => EndedReason::Failed,
                    _ => EndedReason::Other,
                },
            },
            Outcome::Mismatch => Self::NotInstalled {
                cause: NotInstalledCause::OtherKey,
            },
            Outcome::InstallFailed => Self::NotInstalled {
                cause: NotInstalledCause::InstallFailed,
            },
        }
    }
}

/// How `certificate` stands among the requests that were followed.
fn standing(followed: &[Followed], certificate: &str) -> FollowView {
    followed
        .iter()
        .find(|followed| followed.uuid.as_deref() == Some(certificate))
        .map_or(FollowView::Unknown, |followed| (&followed.outcome).into())
}

/// How `certificate` stands after a follow of its own, else as the latest check of ILM found it: a check that ran
/// first has already finished the request, and the follow of its own then knows nothing of it. While a request of
/// `certificate` is still `waiting`, an installed or ended outcome the latest check found belongs to an earlier one.
fn standing_or_latest(
    own: &[Followed],
    latest: &[Followed],
    waiting: &[Waiting],
    certificate: &str,
) -> FollowView {
    match standing(own, certificate) {
        FollowView::Unknown => match standing(latest, certificate) {
            found @ (FollowView::Waiting { .. } | FollowView::NotInstalled { .. }) => found,
            _ if waiting
                .iter()
                .any(|entry| entry.uuid.as_deref() == Some(certificate)) =>
            {
                FollowView::Unknown
            }
            found => found,
        },
        known => known,
    }
}

/// The person who is signed in.
pub(crate) fn signed_in(who: Option<SignedInAs>) -> Result<SignedInAs, String> {
    who.ok_or_else(|| CallError::SignedOut.to_string())
}

/// The person who is signed in and may ask ILM for a certificate.
fn may_request(who: Option<SignedInAs>) -> Result<SignedInAs, String> {
    let who = signed_in(who)?;
    if who.creates_certificates() {
        Ok(who)
    } else {
        Err(NOT_ALLOWED.to_owned())
    }
}

/// Whether the organization and this computer offer `key_type` in `storage`.
fn offered(allowed: &[Offer], storage: Storage, key_type: KeyType) -> Result<(), String> {
    let offer = allowed
        .iter()
        .find(|offer| offer.storage == storage)
        .ok_or("This key storage is not available.")?;
    if offer.types.contains(&key_type) {
        Ok(())
    } else {
        Err("This key type is not available in this key storage.".to_owned())
    }
}

/// The offers of this computer as policy allows them now, read from the storages again.
async fn allowed_offers<R: Runtime>(app: &AppHandle<R>) -> (Vec<Offer>, Option<Storage>) {
    let offers = ilm(app).session().key_offers().await;
    app.state::<std::sync::Arc<Settings>>()
        .allowed_offers(offers)
}

/// The RA Profile ILM lists for the person under `uuid`.
async fn profile<R: Runtime>(ilm: &Ilm<R>, uuid: &str) -> Result<RaProfileChoice, String> {
    let profiles = ilm
        .session()
        .request_profiles()
        .await
        .map_err(|error| error.to_string())?;
    profiles
        .into_iter()
        .find(|profile| profile.uuid == uuid)
        .ok_or_else(|| "ILM does not offer this RA Profile.".to_owned())
}

/// The RA Profile a certificate registered in advance is completed under.
fn choice_of(prepared: &Prepared) -> RaProfileChoice {
    RaProfileChoice {
        uuid: prepared.ra_profile.uuid.clone(),
        name: prepared.ra_profile.name.clone(),
        description: None,
        authority: None,
        authority_uuid: prepared.ra_profile.authority_uuid.clone(),
    }
}

/// The certificate registered in advance that the latest check of ILM found under `uuid`.
fn prepared<R: Runtime>(ilm: &Ilm<R>, uuid: &str) -> Result<Prepared, String> {
    ilm.prepared(uuid)
        .ok_or_else(|| "This certificate is not waiting to be completed.".to_owned())
}

/// What the wizard is told of a request ILM took; the wizard tells how it ends when the window is visible.
fn requested<R: Runtime>(app: &AppHandle<R>, ilm: &Ilm<R>, waiting: Waiting) -> RequestedView {
    let shown = app
        .get_webview_window("main")
        .is_some_and(|window| window.is_visible().unwrap_or(false));
    if let Some(certificate) = waiting.uuid.as_ref().filter(|_| shown) {
        ilm.notices().wizard_shows(certificate);
    }
    RequestedView {
        certificate: waiting.uuid.unwrap_or_default(),
        label: waiting.label,
    }
}

#[tauri::command]
pub async fn request_choices<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Vec<RaProfileChoice>, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    may_request(ilm.session().signed_in_as())?;
    let profiles = ilm.session().request_profiles().await;
    ilm.unlocked()?;
    profiles.map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn open_request_forms<R: Runtime>(
    app: AppHandle<R>,
    ra_profile: String,
) -> Result<RequestFormsView, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    may_request(ilm.session().signed_in_as())?;
    let chosen = profile(&ilm, &ra_profile).await?;
    let authority = chosen.authority_uuid.as_deref().unwrap_or_default();
    let opened = ilm
        .session()
        .open_request_forms(authority, &chosen.uuid, false)
        .await;
    ilm.unlocked()?;
    let forms = opened.map_err(|error| error.to_string())?;
    Ok(RequestFormsView {
        request: forms.request,
        issue: forms.issue,
        custom: forms.custom,
    })
}

#[tauri::command]
pub async fn request_offers<R: Runtime>(app: AppHandle<R>) -> Result<RequestOffers, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    signed_in(ilm.session().signed_in_as())?;
    let (allowed, preselected) = allowed_offers(&app).await;
    ilm.unlocked()?;
    Ok(offers_view(allowed, preselected))
}

#[tauri::command]
pub async fn request_certificate<R: Runtime>(
    app: AppHandle<R>,
    ra_profile: String,
    forms: RequestInput,
    storage: StorageId,
    key_type: KeyTypeId,
) -> Result<RequestedView, RequestFailure> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    may_request(ilm.session().signed_in_as())?;
    let (storage, KeyTypeId(key_type)) = (Storage::from(storage), key_type);
    offered(&allowed_offers(&app).await.0, storage, key_type)?;
    let chosen = profile(&ilm, &ra_profile).await?;
    ilm.unlocked()?;
    let waiting = ilm
        .working(ilm.session().request(&chosen, forms, storage, key_type))
        .await;
    ilm.unlocked()?;
    Ok(requested(&app, &ilm, waiting?))
}

/// Opens the issue and custom forms of a certificate registered in advance; its subject is ILM's, so there is no
/// request form.
#[tauri::command]
pub async fn open_prepared_forms<R: Runtime>(
    app: AppHandle<R>,
    uuid: String,
) -> Result<RequestFormsView, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    signed_in(ilm.session().signed_in_as())?;
    let chosen = choice_of(&prepared(&ilm, &uuid)?);
    let authority = chosen.authority_uuid.as_deref().unwrap_or_default();
    let opened = ilm
        .session()
        .open_request_forms(authority, &chosen.uuid, true)
        .await;
    ilm.unlocked()?;
    let forms = opened.map_err(|error| error.to_string())?;
    Ok(RequestFormsView {
        request: forms.request,
        issue: forms.issue,
        custom: forms.custom,
    })
}

/// Completes a certificate registered in advance with a new key, when ILM still registers the `subject` the person
/// reviewed. The challenge, when ILM asks for one, goes to ILM and nowhere else; a challenge can stand in for the
/// right to create certificates.
#[tauri::command]
pub async fn complete_certificate<R: Runtime>(
    app: AppHandle<R>,
    uuid: String,
    forms: RequestInput,
    storage: StorageId,
    key_type: KeyTypeId,
    challenge: Option<String>,
    subject: Vec<SubjectPart>,
) -> Result<RequestedView, RequestFailure> {
    let challenge = challenge
        .filter(|text| !text.is_empty())
        .map(Challenge::new);
    let ilm = ilm(&app);
    ilm.unlocked()?;
    signed_in(ilm.session().signed_in_as())?;
    let (storage, KeyTypeId(key_type)) = (Storage::from(storage), key_type);
    offered(&allowed_offers(&app).await.0, storage, key_type)?;
    let found = prepared(&ilm, &uuid)?;
    ilm.unlocked()?;
    let waiting = ilm
        .working(ilm.session().complete(
            Completion {
                uuid: &uuid,
                name: &found.name,
                ra_profile: &choice_of(&found),
                subject: &subject,
            },
            forms,
            storage,
            key_type,
            challenge,
        ))
        .await;
    ilm.unlocked()?;
    Ok(requested(&app, &ilm, waiting?))
}

#[tauri::command]
pub async fn follow_request<R: Runtime>(
    app: AppHandle<R>,
    certificate: String,
) -> Result<FollowView, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    signed_in(ilm.session().signed_in_as())?;
    let followed = ilm.follow().await;
    ilm.unlocked()?;
    Ok(standing_or_latest(
        &followed,
        &ilm.followed(),
        &ilm.session().waiting_requests(),
        &certificate,
    ))
}

/// The wizard no longer shows the request of `certificate`: how it ends is told by a notification from now on.
#[tauri::command]
pub async fn stop_following_request<R: Runtime>(
    app: AppHandle<R>,
    certificate: String,
) -> Result<(), String> {
    ilm(&app).notices().wizard_closed(&certificate);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use im_core::ilm::IlmUrl;
    use im_core::ilm::profile::ResourceActions;
    use im_core::session::Installed;
    use serde_json::json;

    fn person(resource: &str, actions: &[&str]) -> Option<SignedInAs> {
        Some(SignedInAs {
            ilm: IlmUrl::parse("ilm.example.com").unwrap(),
            username: "ada".to_owned(),
            allowed_listings: Vec::new(),
            allowed_actions: vec![ResourceActions {
                resource: resource.to_owned(),
                actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            }],
        })
    }

    fn offer(storage: Storage, types: &[KeyType]) -> Offer {
        Offer {
            storage,
            types: types.to_vec(),
        }
    }

    #[test]
    fn a_follow_that_knows_nothing_falls_back_to_the_latest_check() {
        let installed = Outcome::Installed(Installed {
            storage: Some(Storage::Software),
            not_after: 7,
        });
        let latest = [followed(Some("c-1"), installed)];
        let waiting = [followed(
            Some("c-1"),
            Outcome::Waiting(State::PendingApproval),
        )];

        assert_eq!(
            standing_or_latest(&[], &latest, &[], "c-1"),
            FollowView::Installed {
                storage: StorageId::Software,
                valid_until: 7
            }
        );
        assert_eq!(
            standing_or_latest(&waiting, &latest, &[], "c-1"),
            FollowView::Waiting {
                stage: WaitingStage::PendingApproval
            }
        );
        assert_eq!(
            standing_or_latest(&[], &latest, &[], "c-2"),
            FollowView::Unknown
        );
    }

    #[test]
    fn a_follow_that_knows_nothing_of_a_request_still_waiting_is_not_told_how_an_earlier_one_ended()
    {
        let latest = [followed(
            Some("c-1"),
            Outcome::Ended(EndReason::ReturnedToRegistered),
        )];
        let again = Waiting {
            ilm: IlmUrl::parse("ilm.example.com").unwrap(),
            username: "jdoe".to_owned(),
            uuid: Some("c-1".to_owned()),
            ra_profile: "ra-1".to_owned(),
            authority: "a-1".to_owned(),
            key: Some(im_core::keys::KeyId {
                storage: Storage::Software,
                name: "k-1".to_owned(),
            }),
            label: "again".to_owned(),
            since: 1,
            prepared: true,
            purpose: im_core::requests::Purpose::Issue,
        };

        assert_eq!(
            standing_or_latest(&[], &latest, std::slice::from_ref(&again), "c-1"),
            FollowView::Unknown
        );
        let approval = [followed(
            Some("c-1"),
            Outcome::Waiting(State::PendingApproval),
        )];
        assert_eq!(
            standing_or_latest(&[], &approval, std::slice::from_ref(&again), "c-1"),
            FollowView::Waiting {
                stage: WaitingStage::PendingApproval
            }
        );
        let failed = [followed(Some("c-1"), Outcome::InstallFailed)];
        assert_eq!(
            standing_or_latest(&[], &failed, &[again], "c-1"),
            FollowView::NotInstalled {
                cause: NotInstalledCause::InstallFailed
            }
        );
    }

    #[test]
    fn a_prepared_certificate_is_completed_under_its_ra_profile_and_authority() {
        let prepared = Prepared {
            uuid: "c-1".to_owned(),
            name: "demo".to_owned(),
            ra_profile: im_core::ilm::certificates::RaProfile {
                uuid: "ra-1".to_owned(),
                name: "Servers".to_owned(),
                authority_uuid: Some("a-1".to_owned()),
            },
            registration: None,
            subject: Vec::new(),
        };

        let choice = choice_of(&prepared);

        assert_eq!(
            (choice.uuid.as_str(), choice.authority_uuid.as_deref()),
            ("ra-1", Some("a-1"))
        );
    }

    #[test]
    fn every_key_type_has_a_stable_name_that_reads_back() {
        let names = [
            (KeyType::Rsa { bits: 2048 }, "rsa2048"),
            (KeyType::Rsa { bits: 3072 }, "rsa3072"),
            (KeyType::Rsa { bits: 4096 }, "rsa4096"),
            (KeyType::EcP256, "ecP256"),
            (KeyType::EcP384, "ecP384"),
            (KeyType::EcP521, "ecP521"),
            (KeyType::MlDsa44, "mlDsa44"),
            (KeyType::MlDsa65, "mlDsa65"),
            (KeyType::MlDsa87, "mlDsa87"),
        ];
        for (key_type, name) in names {
            assert_eq!(serde_json::to_value(KeyTypeId(key_type)).unwrap(), name);
            let read: KeyTypeId = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(read, KeyTypeId(key_type));
        }
        for unknown in ["", "rsa", "rsaX", "ec", "ecP257", "RSA2048"] {
            assert!(serde_json::from_value::<KeyTypeId>(json!(unknown)).is_err());
        }
    }

    #[test]
    fn a_storage_is_named_in_lower_case_and_reads_back() {
        for (storage, name) in [
            (Storage::Keychain, "keychain"),
            (Storage::Software, "software"),
            (Storage::Tpm, "tpm"),
        ] {
            assert_eq!(
                serde_json::to_value(StorageId::from(storage)).unwrap(),
                name
            );
            let read: StorageId = serde_json::from_value(json!(name)).unwrap();
            assert_eq!(Storage::from(read), storage);
        }
    }

    #[test]
    fn the_offers_are_the_allowed_storages_with_their_key_types_and_the_default() {
        let view = offers_view(
            vec![
                offer(
                    Storage::Software,
                    &[KeyType::EcP256, KeyType::Rsa { bits: 3072 }],
                ),
                offer(Storage::Tpm, &[KeyType::EcP256]),
            ],
            Some(Storage::Tpm),
        );
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({
                "storages": [
                    { "storage": "software", "keyTypes": ["ecP256", "rsa3072"] },
                    { "storage": "tpm", "keyTypes": ["ecP256"] }
                ],
                "defaultStorage": "tpm"
            })
        );
        let none = offers_view(Vec::new(), None);
        assert_eq!(
            serde_json::to_value(&none).unwrap(),
            json!({ "storages": [], "defaultStorage": null })
        );
    }

    #[test]
    fn only_a_key_type_a_storage_offers_is_accepted() {
        let allowed = [offer(Storage::Software, &[KeyType::EcP256])];
        assert!(offered(&allowed, Storage::Software, KeyType::EcP256).is_ok());
        assert_eq!(
            offered(&allowed, Storage::Software, KeyType::EcP384).unwrap_err(),
            "This key type is not available in this key storage."
        );
        assert_eq!(
            offered(&allowed, Storage::Tpm, KeyType::EcP256).unwrap_err(),
            "This key storage is not available."
        );
    }

    #[test]
    fn asking_for_a_certificate_needs_a_sign_in_and_create_on_certificates() {
        assert!(may_request(person("certificates", &["list", "create"])).is_ok());
        assert_eq!(
            may_request(person("certificates", &["list"])).unwrap_err(),
            "ILM does not allow this."
        );
        assert_eq!(
            may_request(person("groups", &["create"])).unwrap_err(),
            "ILM does not allow this."
        );
        assert_eq!(may_request(None).unwrap_err(), "You are not signed in.");
        assert_eq!(signed_in(None).unwrap_err(), "You are not signed in.");
        assert!(signed_in(person("certificates", &[])).is_ok());
    }

    #[test]
    fn a_refusal_of_ilm_is_shown_as_it_is_and_the_form_problems_stay_fields() {
        let refused = RequestFailure::from(RequestError::Refused(vec![
            "Common name too long".to_owned(),
            "Country unknown".to_owned(),
        ]));
        assert_eq!(
            serde_json::to_value(refused).unwrap(),
            json!({ "kind": "refused", "messages": ["Common name too long", "Country unknown"] })
        );
        let empty = RequestFailure::from(RequestError::Refused(Vec::new()));
        assert_eq!(
            serde_json::to_value(empty).unwrap(),
            json!({ "kind": "message", "message": "ILM did not accept the request." })
        );
        let problems = RequestFailure::from(RequestError::FormProblems(Vec::new()));
        assert_eq!(
            serde_json::to_value(problems).unwrap(),
            json!({ "kind": "problems", "problems": [] })
        );
        for (error, text) in [
            (RequestError::NotAllowed, "ILM does not allow this."),
            (RequestError::SignedOut, "You are not signed in."),
            (RequestError::Offline, "ILM cannot be reached."),
        ] {
            assert_eq!(
                serde_json::to_value(RequestFailure::from(error)).unwrap(),
                json!({ "kind": "message", "message": text })
            );
        }
    }

    fn followed(uuid: Option<&str>, outcome: Outcome) -> Followed {
        Followed {
            uuid: uuid.map(str::to_owned),
            label: "web".to_owned(),
            outcome,
            replaces: None,
        }
    }

    #[test]
    fn every_outcome_of_a_follow_has_a_state_for_the_interface() {
        let installed = Outcome::Installed(Installed {
            storage: Some(Storage::Keychain),
            not_after: 4_000,
        });
        let cases = [
            (
                installed,
                json!({ "state": "installed", "storage": "keychain", "validUntil": 4000 }),
            ),
            (
                Outcome::Waiting(State::PendingApproval),
                json!({ "state": "waiting", "stage": "pendingApproval" }),
            ),
            (
                Outcome::Waiting(State::PendingIssue),
                json!({ "state": "waiting", "stage": "beingIssued" }),
            ),
            (
                Outcome::Waiting(State::Requested),
                json!({ "state": "waiting", "stage": "beingIssued" }),
            ),
            (
                Outcome::Ended(EndReason::Rejected),
                json!({ "state": "ended", "reason": "rejected" }),
            ),
            (
                Outcome::Ended(EndReason::Failed),
                json!({ "state": "ended", "reason": "failed" }),
            ),
            (
                Outcome::Ended(EndReason::Gone),
                json!({ "state": "ended", "reason": "other" }),
            ),
            (
                Outcome::Mismatch,
                json!({ "state": "notInstalled", "cause": "otherKey" }),
            ),
            (
                Outcome::InstallFailed,
                json!({ "state": "notInstalled", "cause": "installFailed" }),
            ),
        ];
        for (outcome, expected) in cases {
            let found = [followed(Some("c-1"), outcome)];
            assert_eq!(
                serde_json::to_value(standing(&found, "c-1")).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_follow_tells_only_of_the_certificate_asked_about() {
        let found = [
            followed(Some("c-1"), Outcome::Mismatch),
            followed(None, Outcome::Ended(EndReason::NotSent)),
            followed(Some("c-2"), Outcome::Waiting(State::PendingApproval)),
        ];
        assert_eq!(
            standing(&found, "c-2"),
            FollowView::Waiting {
                stage: WaitingStage::PendingApproval
            }
        );
        assert_eq!(standing(&found, "c-3"), FollowView::Unknown);
        assert_eq!(
            serde_json::to_value(FollowView::Unknown).unwrap(),
            json!({ "state": "unknown" })
        );
    }
}
