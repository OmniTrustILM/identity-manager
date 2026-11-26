//! The certificates of the person on this computer, for the Certificates section.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use im_core::attributes::FieldProblem;
#[cfg(not(any(windows, target_os = "macos")))]
use im_core::identity::NoOrigins;
use im_core::identity::{
    EmptyStore, Fingerprint, IdentityStore, KeyOrigins, LocalCertificate, LocalCertificateView,
    StoreUnreadable, system_store,
};
use im_core::ilm::approvals::{DecideError, Decision};
use im_core::inventory::{
    AddChoicesView, AddResultView, IlmPageView, Inventory, InventoryView, Prepared, Renewing,
    Status, Summary, SummaryView, Trigger,
};
use im_core::keys::Offer;
use im_core::renewal::store::Renewals;
use im_core::requests::Waiting;
use im_core::session::{
    ChangeError, Followed, FormInput, Outcome, Session, SessionView, SignedInAs,
};
use im_core::{AppInfo, Platform};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::keep_alive::{Checks, renew};
use crate::lock::Guard;
use crate::notice::Notices;
use crate::settings::Settings;
use crate::tray;

/// Sent to the windows, without data, after each change of the inventory or of whether a check runs.
const CHANGED: &str = "inventory-changed";

/// The store the list is read from.
pub struct Local(pub Arc<dyn IdentityStore>);

/// The certificates of this computer. Unit tests see none, so they never reach the real store.
pub fn system_identities() -> Arc<dyn IdentityStore> {
    if cfg!(test) {
        Arc::new(EmptyStore)
    } else {
        system_store(origins())
    }
}

#[cfg(windows)]
pub(crate) fn origins() -> Arc<dyn KeyOrigins> {
    Arc::new(crate::key_provider::WindowsKeyOrigins)
}

#[cfg(target_os = "macos")]
pub(crate) fn origins() -> Arc<dyn KeyOrigins> {
    Arc::new(crate::key_origin_macos::TokenKeyOrigins)
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) fn origins() -> Arc<dyn KeyOrigins> {
    Arc::new(NoOrigins)
}

/// `summary` without the certificates that ILM does not know: only the others are notified.
fn known_in_ilm(summary: &Summary, matched: &[Fingerprint]) -> Summary {
    let mut known = summary.clone();
    known.attention.retain(|item| {
        item.fingerprint
            .is_none_or(|print| matched.contains(&print))
    });
    known
}

/// Whether the person may ask ILM for a certificate and this computer has a key storage to keep its key in; what
/// the organization's policy allows of that storage is told at the step that chooses it.
fn can_request(who: Option<&SignedInAs>, stores_keys: bool) -> bool {
    stores_keys && who.is_some_and(SignedInAs::creates_certificates)
}

/// What the person is told when the store cannot be read; the reason goes to the log.
fn unreadable_message(keychain: bool) -> &'static str {
    if keychain {
        "Cannot read the keychain."
    } else {
        "Cannot read the certificate store."
    }
}

/// The certificates with a private key in the store of the person, unless the application is locked, now or
/// by the time the store has been read.
async fn list(
    guard: &Guard,
    store: Arc<dyn IdentityStore>,
    keychain: bool,
) -> Result<Vec<LocalCertificateView>, String> {
    guard.ensure_unlocked()?;
    let read = tokio::task::spawn_blocking(move || store.certificates())
        .await
        .expect("the certificate store task does not panic");
    guard.ensure_unlocked()?;
    match read {
        Ok(found) => Ok(found.iter().map(LocalCertificateView::from).collect()),
        Err(StoreUnreadable(reason)) => {
            log::warn!("the certificates cannot be listed: {reason}");
            Err(unreadable_message(keychain).to_owned())
        }
    }
}

/// What the interface gets when an add is refused: ILM's or the application's words, or the problems of the form,
/// with which nothing was sent.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum AddToIlmError {
    Refused(String),
    Problems(FormProblems),
}

/// The fields of the form that have a problem.
#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct FormProblems {
    pub problems: Vec<FieldProblem>,
}

impl From<ChangeError> for AddToIlmError {
    fn from(error: ChangeError) -> Self {
        match error {
            ChangeError::FormProblems(problems) => Self::Problems(FormProblems { problems }),
            other => Self::Refused(other.to_string()),
        }
    }
}

impl From<String> for AddToIlmError {
    fn from(message: String) -> Self {
        Self::Refused(message)
    }
}

/// What ILM says about the certificates on this computer: the checks, and the views of the answer.
pub struct Ilm<R: Runtime> {
    app: AppHandle<R>,
    session: Arc<Session>,
    pub(crate) inventory: Arc<Inventory>,
    guard: Arc<Guard>,
    settings: Arc<Settings>,
    local: Arc<dyn IdentityStore>,
    notices: Arc<Notices>,
    /// The switches of automatic renewal and the failed attempts, the same the session writes.
    renewals: Arc<Renewals>,
    platform: Platform,
    /// How many checks, or changes that end in a check, are running.
    working: AtomicUsize,
    /// Held from reading the warning days to giving them to the inventory, so days read before a change cannot
    /// replace the changed ones.
    configuring: Mutex<()>,
}

impl<R: Runtime> Ilm<R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: &AppHandle<R>,
        session: Arc<Session>,
        inventory: Arc<Inventory>,
        guard: Arc<Guard>,
        settings: Arc<Settings>,
        local: Arc<dyn IdentityStore>,
        notices: Arc<Notices>,
        renewals: Arc<Renewals>,
    ) -> Self {
        Self {
            app: app.clone(),
            session,
            inventory,
            guard,
            settings,
            local,
            notices,
            renewals,
            platform: AppInfo::current().platform,
            working: AtomicUsize::new(0),
            configuring: Mutex::new(()),
        }
    }

    pub(crate) async fn view(&self) -> InventoryView {
        let who = self.session.signed_in_as();
        let offers = self.session.key_offers().await;
        let stores_keys = !offers.is_empty();
        let waiting = self.session.waiting_requests();
        let renewals = self
            .inventory
            .renewal_views(&self.renewing(offers.clone()), &waiting);
        InventoryView::new(
            self.inventory.status(),
            self.inventory.snapshot().as_ref(),
            self.working.load(Ordering::SeqCst) > 0,
            who.as_ref().is_some_and(SignedInAs::lists_certificates),
            can_request(who.as_ref(), stores_keys),
        )
        .with_requests(&waiting, &self.inventory.followed())
        .with_renewals(renewals)
    }

    /// What decides about renewal now: the settings, the switches and, of the key types `offers` name, those policy
    /// lets a new key have.
    pub(crate) fn renewing(&self, offers: Vec<Offer>) -> Renewing {
        let (policy, person) = self.settings.layers();
        Renewing {
            platform: self.platform,
            policy,
            person,
            offers: self.settings.allowed_offers(offers).0,
            switches: self.renewals.clone(),
        }
    }

    pub(crate) fn renewals(&self) -> &Renewals {
        &self.renewals
    }

    /// The certificate registered in advance that the latest check of ILM found under `uuid`.
    pub(crate) fn prepared(&self, uuid: &str) -> Option<Prepared> {
        self.inventory
            .snapshot()?
            .prepared
            .into_iter()
            .find(|found| found.uuid == uuid)
    }

    /// Takes `decision` on the approval `uuid`, with an optional `comment`.
    pub(crate) async fn decide(
        &self,
        uuid: &str,
        decision: Decision,
        comment: Option<&str>,
    ) -> Result<(), DecideError> {
        self.inventory
            .decide(&self.session, uuid, decision, comment, || {
                !self.guard.is_locked()
            })
            .await
    }

    /// Tells the windows that the inventory changed; what changed is read with `ilm_status`, which refuses while
    /// the application is locked.
    pub(crate) fn changed(&self) {
        if let Err(error) = self.app.emit(CHANGED, ()) {
            log::warn!("the inventory change could not be sent to the windows: {error}");
        }
    }

    /// Runs `work`, tells the windows when it starts and when it ends, and takes the summary it leaves to the tray
    /// and the notifications.
    pub(crate) async fn working<T>(&self, work: impl Future<Output = T>) -> T {
        self.working.fetch_add(1, Ordering::SeqCst);
        self.changed();
        let done = work.await;
        self.working.fetch_sub(1, Ordering::SeqCst);
        self.publish_summary();
        self.changed();
        done
    }

    /// Gives the inventory the warning days of the settings, which rebuilds the summary when they changed. ILM is
    /// not asked.
    fn configure(&self) {
        let _configuring = self
            .configuring
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.inventory.configure(self.settings.warn_days());
    }

    /// The person changed the warning days: the summary follows at once.
    pub(crate) fn warn_days_changed(&self) {
        self.configure();
        self.publish_summary();
        self.changed();
    }

    /// Whether the summary has certificates that are expiring, expired or revoked.
    pub(crate) fn needs_attention(&self) -> bool {
        self.inventory
            .summary()
            .is_some_and(|summary| summary.needs_attention())
    }

    /// Shows the tray whether certificates need attention and tells the person about new ones, unless the
    /// application is locked: those wait for the next summary after the unlock.
    pub(crate) fn publish_summary(&self) {
        let summary = self.inventory.summary();
        tray::set_attention(
            &self.app,
            summary.as_ref().is_some_and(Summary::needs_attention),
        );
        if let Some(summary) = summary {
            let current = || self.inventory.summary().as_ref() == Some(&summary);
            let waiting = self.session.waiting_requests();
            self.notices
                .followed(&self.inventory.followed(), current, || {
                    current() && !self.guard.is_locked()
                });
            self.notices.revoking(&waiting, current);
            self.notices.summary(
                &known_in_ilm(&summary, &self.inventory.matched_fingerprints()),
                &self.inventory.local_fingerprints(),
                current,
                || current() && !self.guard.is_locked(),
            );
            self.tell_renewals(&waiting, current);
            // Linux has no key storage to issue a prepared certificate with, and no Requests section to decide in.
            if !cfg!(target_os = "linux") {
                self.notices.prepared(
                    &self
                        .inventory
                        .ready_to_issue(&self.session.waiting_requests()),
                    current,
                    || current() && !self.guard.is_locked(),
                );
                self.notices
                    .approvals(&self.inventory.approvals(), current, || {
                        current() && !self.guard.is_locked()
                    });
            }
            if self.inventory.summary().is_none() {
                // Signed out meanwhile: the write above must not leave the notices file behind.
                self.notices.forget();
            }
        }
    }

    /// Tells the person what automatic renewal could not do: what needs them and what was refused while signed in,
    /// and what is due while signed out or locked.
    fn tell_renewals(&self, waiting: &[Waiting], current: impl Fn() -> bool) {
        let plan = self.renewing(Vec::new());
        let (needs, refused, sign_in) =
            if self.session.signed_in_as().is_some() && !self.guard.is_locked() {
                (
                    self.inventory.renewal_needs(&plan, waiting),
                    self.inventory.renewal_refused(),
                    Vec::new(),
                )
            } else {
                (
                    Vec::new(),
                    Vec::new(),
                    self.inventory.renewal_sign_in(&plan),
                )
            };
        self.notices
            .renewals(&needs, &refused, &sign_in, &current, || {
                current() && !self.guard.is_locked()
            });
    }

    /// A sign-in ended: what was kept about its certificates and notifications goes.
    pub(crate) fn signed_out(&self) {
        self.inventory.forget();
        self.notices.forget();
        tray::set_attention(&self.app, false);
    }

    pub(crate) async fn local_certificates(&self) -> Result<Vec<LocalCertificate>, String> {
        let store = self.local.clone();
        let read = tokio::task::spawn_blocking(move || store.certificates())
            .await
            .expect("the certificate store task does not panic");
        read.map_err(|StoreUnreadable(reason)| {
            log::warn!("the certificates cannot be matched with ILM: {reason}");
            unreadable_message(cfg!(target_os = "macos")).to_owned()
        })
    }

    /// Asks ILM about the certificates on this computer. Nothing happens while nobody is signed in, and the
    /// last answer stays when the store cannot be read. While a saved sign-in cannot be renewed, the summary is
    /// built from the saved answer.
    async fn check_inventory(&self, trigger: Trigger) -> Result<(), String> {
        self.configure();
        self.inventory.adopt(&self.session);
        let signed_in = self.session.signed_in_as().is_some();
        if !signed_in && self.session.unreachable_at().is_none() {
            return Ok(());
        }
        let local = self.local_certificates().await?;
        self.inventory.set_local(&local);
        if signed_in {
            self.forget_removed_switches(&local);
            self.working(async {
                self.inventory
                    .check_local(&self.session, trigger, &local)
                    .await;
                self.read_installed().await;
                self.renew_due().await;
                self.read_installed().await;
            })
            .await;
        } else {
            self.publish_summary();
            self.changed();
        }
        Ok(())
    }

    /// Reads the store again when a follow installed a certificate after it was read, so the summary counts it.
    async fn read_installed(&self) {
        if self.inventory.installed_elsewhere()
            && let Ok(local) = self.local_certificates().await
        {
            self.inventory.set_local(&local);
        }
    }

    /// Forgets the switches and failed attempts of certificates that are no longer on this computer.
    fn forget_removed_switches(&self, local: &[LocalCertificate]) {
        let Some(who) = self.session.signed_in_as() else {
            return;
        };
        let present: Vec<Fingerprint> = local.iter().map(|found| found.fingerprint).collect();
        if let Err(error) = self.renewals.prune(&who.ilm, &who.username, &present) {
            log::warn!("the renewal switches cannot be pruned: {error}");
        }
    }

    /// Renews the certificates the latest check found due, unless the application is locked.
    async fn renew_due(&self) {
        if self.guard.is_locked() {
            return;
        }
        let offers = self.session.key_offers().await;
        let plan = self.renewing(offers);
        self.inventory
            .renew_due(&self.session, &plan, || !self.guard.is_locked())
            .await;
    }

    /// Takes the saved answer of the person who signed in, then checks ILM.
    pub async fn start(&self) {
        self.configure();
        self.inventory.adopt(&self.session);
        self.changed();
        if let Err(error) = self.check_inventory(Trigger::Start).await {
            log::warn!("ILM is not checked: {error}");
        }
    }

    /// Starts the check that follows a sign-in, in the background.
    pub fn after_sign_in(self: &Arc<Self>, view: &SessionView) {
        if matches!(view, SessionView::SignedIn { .. }) {
            let ilm = self.clone();
            tauri::async_runtime::spawn(async move { ilm.start().await });
        }
    }

    pub(crate) fn unlocked(&self) -> Result<(), String> {
        self.guard.ensure_unlocked()
    }

    pub(crate) fn session(&self) -> &Session {
        &self.session
    }

    /// How the requests stood at the latest check of ILM.
    pub(crate) fn followed(&self) -> Vec<Followed> {
        self.inventory.followed()
    }

    /// Follows the requests for certificates, and tells the windows and the tray when how they stand changed. An
    /// installed certificate is read from the store at once, so the summary counts it.
    pub(crate) async fn follow(&self) -> Vec<Followed> {
        let (found, changed) = self.inventory.follow(&self.session).await;
        if changed {
            if found
                .iter()
                .any(|followed| matches!(followed.outcome, Outcome::Installed(_)))
                && let Ok(local) = self.local_certificates().await
            {
                self.inventory.set_local(&local);
            }
            self.publish_summary();
            self.changed();
        }
        found
    }

    pub(crate) fn notices(&self) -> &Notices {
        &self.notices
    }

    async fn page(&self, number: u32, search: Option<String>) -> Result<IlmPageView, String> {
        self.unlocked()?;
        let page = self
            .inventory
            .page(&self.session, number, search.as_deref())
            .await;
        self.unlocked()?;
        Ok((&page.map_err(|error| error.to_string())?).into())
    }

    /// The inventory, unless the application locked while it was read.
    pub(crate) async fn locked_view(&self) -> Result<InventoryView, String> {
        let view = self.view().await;
        self.unlocked()?;
        Ok(view)
    }

    async fn sync(&self) -> Result<InventoryView, String> {
        self.unlocked()?;
        if matches!(renew(self).await, SessionView::SignedIn { .. }) {
            self.check_inventory(Trigger::SyncNow).await?;
        }
        self.locked_view().await
    }

    fn overview(&self) -> Result<Option<SummaryView>, String> {
        self.unlocked()?;
        let summary = self.inventory.summary();
        self.unlocked()?;
        let renewals = self
            .inventory
            .renewal_views(&self.renewing(Vec::new()), &self.session.waiting_requests());
        Ok(summary
            .as_ref()
            .map(|summary| SummaryView::from(summary).with_renewable(&renewals)))
    }

    async fn add_choices(&self) -> Result<AddChoicesView, String> {
        self.unlocked()?;
        let choices = self.session.add_to_ilm_choices().await;
        self.unlocked()?;
        choices
            .map(AddChoicesView::from)
            .map_err(|error| error.to_string())
    }

    async fn add(
        &self,
        fingerprints: Vec<String>,
        group: Option<String>,
        ra_profile: Option<String>,
        form: Option<FormInput>,
    ) -> Result<Vec<AddResultView>, AddToIlmError> {
        self.unlocked()?;
        let added = self
            .working(self.session.add_to_ilm(
                &self.inventory,
                fingerprints,
                group,
                ra_profile,
                form,
                || !self.guard.is_locked(),
            ))
            .await;
        self.unlocked()?;
        let results = added?;
        Ok(results.into_iter().map(AddResultView::from).collect())
    }

    async fn make_sign_in_certificate(&self, fingerprint: &str) -> Result<InventoryView, String> {
        self.unlocked()?;
        let changed =
            self.working(self.session.make_sign_in_certificate(
                &self.inventory,
                fingerprint,
                || !self.guard.is_locked(),
            ))
            .await;
        self.unlocked()?;
        changed.map_err(|error| error.to_string())?;
        self.locked_view().await
    }
}

impl<R: Runtime> Checks for Ilm<R> {
    fn view(&self) -> SessionView {
        self.session.view()
    }

    fn check(&self) -> impl Future<Output = SessionView> + Send {
        self.session.check()
    }

    fn retry(&self) -> impl Future<Output = SessionView> + Send {
        self.session.retry()
    }

    fn interval(&self) -> Duration {
        self.settings.check_interval()
    }

    async fn inventory(&self, trigger: Trigger) {
        if let Err(error) = self.check_inventory(trigger).await {
            log::warn!("ILM is not checked: {error}");
        }
    }

    fn inventory_unreachable(&self) -> bool {
        matches!(
            self.inventory.status(),
            Status::Offline {
                unreachable: true,
                ..
            }
        )
    }
}

#[cfg(test)]
impl<R: Runtime> Ilm<R> {
    pub(crate) fn inventory(&self) -> &Inventory {
        &self.inventory
    }
}

pub fn ilm<R: Runtime>(app: &AppHandle<R>) -> Arc<Ilm<R>> {
    app.state::<Arc<Ilm<R>>>().inner().clone()
}

#[tauri::command]
pub async fn ilm_status<R: Runtime>(app: AppHandle<R>) -> Result<InventoryView, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    ilm.locked_view().await
}

#[tauri::command]
pub async fn ilm_certificates<R: Runtime>(
    app: AppHandle<R>,
    page: u32,
    search: Option<String>,
) -> Result<IlmPageView, String> {
    ilm(&app).page(page, search).await
}

#[tauri::command]
pub async fn sync_now<R: Runtime>(app: AppHandle<R>) -> Result<InventoryView, String> {
    ilm(&app).sync().await
}

#[tauri::command]
pub async fn make_sign_in_certificate<R: Runtime>(
    app: AppHandle<R>,
    fingerprint: String,
) -> Result<InventoryView, String> {
    ilm(&app).make_sign_in_certificate(&fingerprint).await
}

#[tauri::command]
pub fn overview<R: Runtime>(app: AppHandle<R>) -> Result<Option<SummaryView>, String> {
    ilm(&app).overview()
}

#[tauri::command]
pub async fn add_to_ilm_choices<R: Runtime>(app: AppHandle<R>) -> Result<AddChoicesView, String> {
    ilm(&app).add_choices().await
}

#[tauri::command]
pub async fn add_to_ilm<R: Runtime>(
    app: AppHandle<R>,
    fingerprints: Vec<String>,
    group: Option<String>,
    ra_profile: Option<String>,
    form: Option<FormInput>,
) -> Result<Vec<AddResultView>, AddToIlmError> {
    ilm(&app).add(fingerprints, group, ra_profile, form).await
}

#[tauri::command]
pub async fn local_certificates<R: Runtime>(
    app: AppHandle<R>,
) -> Result<Vec<LocalCertificateView>, String> {
    let guard = app.state::<Arc<Guard>>().inner().clone();
    let store = app.state::<Local>().0.clone();
    list(&guard, store, cfg!(target_os = "macos")).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{NoPrompt, NoState, Surface};
    use im_core::attributes::Problem;
    use im_core::identity::{
        ClientIdentity, Fingerprint, KeyAlgorithm, KeyLocation, LocalCertificate,
    };
    use im_core::ilm::IlmUrl;
    use im_core::ilm::profile::ResourceActions;
    use im_core::session::SessionView;
    use std::time::UNIX_EPOCH;

    fn person(actions: &[&str]) -> SignedInAs {
        SignedInAs {
            ilm: IlmUrl::parse("ilm.example.com").unwrap(),
            username: "ada".to_owned(),
            allowed_listings: Vec::new(),
            allowed_actions: vec![ResourceActions {
                resource: "certificates".to_owned(),
                actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            }],
        }
    }

    #[test]
    fn a_request_needs_the_right_in_ilm_and_a_key_storage_on_this_computer() {
        let may = person(&["list", "create"]);
        assert!(can_request(Some(&may), true));
        assert!(!can_request(Some(&may), false));
        assert!(!can_request(Some(&person(&["list"])), true));
        assert!(!can_request(None, true));
    }

    struct Nowhere;

    impl Surface for Nowhere {
        fn show(&self, _view: &SessionView) {}
        fn hide_summary(&self) {}
    }

    fn unlocked() -> Guard {
        Guard::new(Arc::new(Nowhere), Arc::new(NoState), NoPrompt)
    }

    struct Fixed(Result<Vec<LocalCertificate>, StoreUnreadable>);

    impl IdentityStore for Fixed {
        fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
            self.0.clone()
        }

        fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
            None
        }
    }

    fn certificate() -> LocalCertificate {
        LocalCertificate {
            fingerprint: Fingerprint::of(b"der"),
            name: "Ada".to_owned(),
            subject: "CN=Ada".to_owned(),
            issuer: "Root".to_owned(),
            issuer_name: "CN=Root".to_owned(),
            serial: "01".to_owned(),
            not_before: UNIX_EPOCH,
            not_after: UNIX_EPOCH,
            uses: Vec::new(),
            alternative_names: Vec::new(),
            key: KeyAlgorithm::Ed25519,
            location: KeyLocation::Keychain,
            card: None,
            sign_in: Ok(()),
        }
    }

    fn read(
        store: Result<Vec<LocalCertificate>, StoreUnreadable>,
        keychain: bool,
    ) -> Result<Vec<LocalCertificateView>, String> {
        tauri::async_runtime::block_on(list(&unlocked(), Arc::new(Fixed(store)), keychain))
    }

    #[test]
    fn an_add_refused_for_its_form_carries_the_problems_and_any_other_refusal_stays_text() {
        let problem = FieldProblem {
            name: "dept".to_owned(),
            problem: Problem::Required,
        };
        let with_problems = AddToIlmError::from(ChangeError::FormProblems(vec![problem.clone()]));
        assert_eq!(
            serde_json::to_value(with_problems).unwrap(),
            serde_json::json!({ "problems": [serde_json::to_value(problem).unwrap()] })
        );
        let other = AddToIlmError::from(ChangeError::NotAllowed);
        assert_eq!(
            serde_json::to_value(other).unwrap(),
            serde_json::json!("ILM does not allow this.")
        );
        assert_eq!(
            serde_json::to_value(AddToIlmError::from(
                "Unlock Identity Manager first.".to_owned()
            ))
            .unwrap(),
            serde_json::json!("Unlock Identity Manager first.")
        );
    }

    #[test]
    fn the_list_is_the_store_as_views_in_the_order_read() {
        let mut second = certificate();
        second.name = "Bob".to_owned();
        let listed = read(Ok(vec![certificate(), second]), true).unwrap();
        let names: Vec<&str> = listed.iter().map(|view| view.name.as_str()).collect();
        assert_eq!(names, ["Ada", "Bob"]);
    }

    #[test]
    fn an_unreadable_store_is_told_per_system_and_the_reason_stays_in_the_log() {
        let unreadable = || Err(StoreUnreadable("errSecAuthFailed 12345".to_owned()));
        assert_eq!(
            read(unreadable(), true).unwrap_err(),
            "Cannot read the keychain."
        );
        assert_eq!(
            read(unreadable(), false).unwrap_err(),
            "Cannot read the certificate store."
        );
    }
}
