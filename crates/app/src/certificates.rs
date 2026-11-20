//! The certificates of the person on this computer, for the Certificates section.

use std::sync::Arc;

#[cfg(not(windows))]
use im_core::identity::NoProviders;
use im_core::identity::{
    EmptyStore, IdentityStore, KeyProviders, LocalCertificateView, StoreUnreadable, system_store,
};
use tauri::{AppHandle, Manager, Runtime};

use crate::lock::Guard;

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
