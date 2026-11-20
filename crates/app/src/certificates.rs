//! The certificates of the person on this computer, for the Certificates section.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[cfg(not(windows))]
use im_core::identity::NoProviders;
use im_core::identity::{
    EmptyStore, Fingerprint, IdentityStore, KeyProviders, LocalCertificateView, StoreUnreadable,
    system_store,
};
use im_core::inventory::{IlmPageView, Inventory, InventoryView, Status, Trigger};
use im_core::session::{Session, SessionView};
use tauri::{AppHandle, Emitter, Manager, Runtime};

use crate::keep_alive::{Checks, renew};
use crate::lock::Guard;
use crate::settings::Settings;

/// Sent to the windows, without data, after each change of the inventory or of whether a check runs.
const CHANGED: &str = "inventory-changed";

/// The store the list is read from.
pub struct Local(pub Arc<dyn IdentityStore>);

/// The certificates of this computer. Unit tests see none, so they never reach the real store.
pub fn system_identities() -> Arc<dyn IdentityStore> {
    if cfg!(test) {
        Arc::new(EmptyStore)
    } else {
        system_store(providers())
    }
}

#[cfg(windows)]
fn providers() -> Arc<dyn KeyProviders> {
    Arc::new(crate::key_provider::WindowsKeyProviders)
}

#[cfg(not(windows))]
fn providers() -> Arc<dyn KeyProviders> {
    Arc::new(NoProviders)
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

/// What ILM says about the certificates on this computer: the checks, and the views of the answer.
pub struct Ilm<R: Runtime> {
    app: AppHandle<R>,
    session: Arc<Session>,
    inventory: Arc<Inventory>,
    guard: Arc<Guard>,
    settings: Arc<Settings>,
    local: Arc<dyn IdentityStore>,
    /// How many checks, or changes that end in a check, are running.
    working: AtomicUsize,
}

impl<R: Runtime> Ilm<R> {
    pub fn new(
        app: &AppHandle<R>,
        session: Arc<Session>,
        inventory: Arc<Inventory>,
        guard: Arc<Guard>,
        settings: Arc<Settings>,
        local: Arc<dyn IdentityStore>,
    ) -> Self {
        Self {
            app: app.clone(),
            session,
            inventory,
            guard,
            settings,
            local,
            working: AtomicUsize::new(0),
        }
    }

    pub(crate) fn view(&self) -> InventoryView {
        InventoryView::new(
            self.inventory.status(),
            self.inventory.snapshot().as_ref(),
            self.working.load(Ordering::SeqCst) > 0,
            self.session
                .signed_in_as()
                .is_some_and(|who| who.lists_certificates()),
        )
    }

    /// Tells the windows that the inventory changed; what changed is read with `ilm_status`, which refuses while
    /// the application is locked.
    fn changed(&self) {
        if let Err(error) = self.app.emit(CHANGED, ()) {
            log::warn!("the inventory change could not be sent to the windows: {error}");
        }
    }

    /// Runs `work` and tells the windows when it starts and when it ends.
    pub(crate) async fn working<T>(&self, work: impl Future<Output = T>) -> T {
        self.working.fetch_add(1, Ordering::SeqCst);
        self.changed();
        let done = work.await;
        self.working.fetch_sub(1, Ordering::SeqCst);
        self.changed();
        done
    }

    async fn local_fingerprints(&self) -> Result<Vec<Fingerprint>, String> {
        let store = self.local.clone();
        let read = tokio::task::spawn_blocking(move || store.certificates())
            .await
            .expect("the certificate store task does not panic");
        match read {
            Ok(found) => Ok(found.iter().map(|found| found.fingerprint).collect()),
            Err(StoreUnreadable(reason)) => {
                log::warn!("the certificates cannot be matched with ILM: {reason}");
                Err(unreadable_message(cfg!(target_os = "macos")).to_owned())
            }
        }
    }

    /// Asks ILM about the certificates on this computer. Nothing happens while nobody is signed in, and the
    /// last answer stays when the store cannot be read.
    async fn check_inventory(&self, trigger: Trigger) -> Result<(), String> {
        if self.session.signed_in_as().is_none() {
            return Ok(());
        }
        self.inventory.adopt(&self.session);
        let local = self.local_fingerprints().await?;
        self.working(self.inventory.check(&self.session, trigger, &local))
            .await;
        Ok(())
    }

    /// Takes the saved answer of the person who signed in, then checks ILM.
    pub async fn start(&self) {
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

    fn unlocked(&self) -> Result<(), String> {
        self.guard.ensure_unlocked()
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

    async fn sync(&self) -> Result<InventoryView, String> {
        self.unlocked()?;
        if matches!(renew(self).await, SessionView::SignedIn { .. }) {
            self.check_inventory(Trigger::SyncNow).await?;
        }
        self.unlocked()?;
        Ok(self.view())
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
        Ok(self.view())
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

pub fn ilm<R: Runtime>(app: &AppHandle<R>) -> Arc<Ilm<R>> {
    app.state::<Arc<Ilm<R>>>().inner().clone()
}

#[tauri::command]
pub fn ilm_status<R: Runtime>(app: AppHandle<R>) -> Result<InventoryView, String> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    Ok(ilm.view())
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
    use im_core::identity::{
        ClientIdentity, Fingerprint, KeyAlgorithm, KeyLocation, LocalCertificate,
    };
    use im_core::session::SessionView;
    use std::time::UNIX_EPOCH;

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
