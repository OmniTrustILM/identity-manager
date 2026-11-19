use std::sync::Arc;

use im_core::http;
use im_core::identity::{EmptyStore, IdentityStore, system_store};
use im_core::session::{
    CertificateChoice, KeyringStore, MemoryStore, ProviderChoice, RefreshStore, Session,
    SessionView,
};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use tauri_plugin_opener::OpenerExt;
use url::Url;

use crate::Mode;
use crate::settings::Settings;

const CHANGED: &str = "session-changed";

/// Opens the sign-in page of the identity provider in the system browser.
pub trait Opener: Send + Sync {
    fn open(&self, url: &Url);
}

pub struct SystemOpener<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SystemOpener<R> {
    pub fn new(app: &AppHandle<R>) -> Self {
        Self(app.clone())
    }
}

impl<R: Runtime> Opener for SystemOpener<R> {
    fn open(&self, url: &Url) {
        // The address carries the request of the sign-in, and the opener's error may hold it, so neither is
        // logged.
        if self
            .0
            .opener()
            .open_url(url.as_str(), None::<&str>)
            .is_err()
        {
            log::warn!("the browser could not be opened");
        }
    }
}

/// The sign-in of the person and the way to the browser.
pub struct SignIn {
    session: Arc<Session>,
    opener: Arc<dyn Opener>,
}

/// Builds the session, tells every window about each change of it and, outside self-check mode, renews a
/// stored sign-in once in the background.
pub fn manage<R: Runtime>(
    app: &AppHandle<R>,
    mode: Mode,
    settings: Arc<Settings>,
    store: Arc<dyn RefreshStore>,
    opener: Arc<dyn Opener>,
) {
    let events = app.clone();
    let session = Arc::new(
        Session::new(http::client(), settings, store, move |view| {
            if let Err(error) = events.emit(CHANGED, view) {
                log::warn!("the sign-in state could not be sent to the windows: {error}");
            }
        })
        .with_identities(identities()),
    );
    app.manage(SignIn {
        session: session.clone(),
        opener,
    });
    if mode != Mode::SelfCheck {
        tauri::async_runtime::spawn(async move {
            session.start().await;
        });
    }
}

/// The system's protected storage for the refresh token. Where it is unavailable, and in unit tests, the
/// sign-in lasts until the application quits.
pub fn protected_store() -> Arc<dyn RefreshStore> {
    if cfg!(test) {
        return Arc::new(MemoryStore::default());
    }
    match KeyringStore::system() {
        Ok(store) => Arc::new(store),
        Err(error) => {
            log::warn!("the protected storage is unavailable, the sign-in is not kept: {error}");
            Arc::new(MemoryStore::default())
        }
    }
}

/// The certificates of this computer. Unit tests see none, so they never reach the real store.
fn identities() -> Arc<dyn IdentityStore> {
    if cfg!(test) {
        Arc::new(EmptyStore)
    } else {
        system_store()
    }
}

/// Gives a mock app a session that reads no real settings, so a command that its capability allows can run.
#[cfg(test)]
pub fn manage_for_tests<R: Runtime>(app: &AppHandle<R>) {
    let settings = Arc::new(Settings::new(
        std::env::temp_dir().join("identity-manager-no-settings.json"),
        Default::default,
        crate::settings::SystemEffects::new(app, false),
        false,
    ));
    app.manage(settings.clone());
    manage(
        app,
        Mode::SelfCheck,
        settings,
        Arc::new(MemoryStore::default()),
        Arc::new(SystemOpener::new(app)),
    );
}

fn state<R: Runtime>(app: &AppHandle<R>) -> State<'_, SignIn> {
    app.state::<SignIn>()
}

#[tauri::command]
pub fn session(state: State<'_, SignIn>) -> SessionView {
    state.session.view()
}

#[tauri::command]
pub async fn connect<R: Runtime>(
    app: AppHandle<R>,
    address: String,
) -> Result<Vec<ProviderChoice>, String> {
    let session = state(&app).session.clone();
    session.connect(&address).await
}

#[tauri::command]
pub async fn sign_in<R: Runtime>(app: AppHandle<R>, provider_id: String) -> SessionView {
    let (session, opener) = {
        let state = state(&app);
        (state.session.clone(), state.opener.clone())
    };
    session
        .sign_in(&provider_id, move |url| opener.open(url))
        .await
}

#[tauri::command]
pub async fn certificates<R: Runtime>(app: AppHandle<R>) -> Vec<CertificateChoice> {
    let session = state(&app).session.clone();
    session.certificates().await
}

#[tauri::command]
pub async fn sign_in_with_certificate<R: Runtime>(
    app: AppHandle<R>,
    fingerprint: String,
) -> SessionView {
    let session = state(&app).session.clone();
    session.sign_in_with_certificate(&fingerprint).await
}

#[tauri::command]
pub fn reopen_browser(state: State<'_, SignIn>) {
    if let Some(url) = state.session.browser_url() {
        state.opener.open(&url);
    }
}

#[tauri::command]
pub fn cancel_sign_in(state: State<'_, SignIn>) {
    state.session.cancel();
}

#[tauri::command]
pub async fn sign_out<R: Runtime>(app: AppHandle<R>) -> SessionView {
    let session = state(&app).session.clone();
    session.sign_out().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver, channel};
    use std::time::Duration;
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::webview::InvokeRequest;
    use tauri::{Listener, WebviewUrl, WebviewWindowBuilder, ipc::CallbackFn};

    #[derive(Default)]
    struct Browser(Mutex<Vec<String>>);

    impl Opener for Arc<Browser> {
        fn open(&self, url: &Url) {
            self.0.lock().unwrap().push(url.to_string());
        }
    }

    struct Fixture {
        app: tauri::App<MockRuntime>,
        window: tauri::WebviewWindow<MockRuntime>,
        browser: Arc<Browser>,
        events: Receiver<String>,
        _folder: tempfile::TempDir,
    }

    fn fixture(mode: Mode) -> Fixture {
        let folder = tempfile::tempdir().unwrap();
        let app = mock_builder()
            .invoke_handler(tauri::generate_handler![
                session,
                connect,
                sign_in,
                certificates,
                sign_in_with_certificate,
                reopen_browser,
                cancel_sign_in,
                sign_out
            ])
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        let (sender, events) = channel();
        app.listen(CHANGED, move |event| {
            sender.send(event.payload().to_string()).unwrap();
        });
        let settings = Arc::new(Settings::new(
            folder.path().join("settings.json"),
            Default::default,
            crate::settings::SystemEffects::new(app.handle(), false),
            false,
        ));
        let browser = Arc::new(Browser::default());
        manage(
            app.handle(),
            mode,
            settings,
            Arc::new(MemoryStore::default()),
            Arc::new(browser.clone()),
        );
        let window = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
            .build()
            .unwrap();
        Fixture {
            app,
            window,
            browser,
            events,
            _folder: folder,
        }
    }

    impl Fixture {
        fn call(
            &self,
            command: &str,
            body: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            tauri::test::get_ipc_response(
                &self.window,
                InvokeRequest {
                    cmd: command.into(),
                    callback: CallbackFn(0),
                    error: CallbackFn(1),
                    url: crate::bridge::LOCAL_ORIGIN.parse().unwrap(),
                    body: tauri::ipc::InvokeBody::Json(body),
                    headers: Default::default(),
                    invoke_key: self.app.invoke_key().to_string(),
                },
            )
            .map(|response| response.deserialize().expect("the response is JSON"))
            .map_err(|error| error.to_string())
        }

        fn next_event(&self) -> serde_json::Value {
            let payload = self.events.recv_timeout(Duration::from_secs(5)).unwrap();
            serde_json::from_str(&payload).unwrap()
        }
    }

    #[test]
    fn start_up_renews_once_outside_self_check_mode() {
        let normal = fixture(Mode::Normal);
        assert_eq!(normal.next_event()["state"], "signedOut");
        assert!(
            normal
                .events
                .recv_timeout(Duration::from_millis(300))
                .is_err()
        );

        let check = fixture(Mode::SelfCheck);
        assert!(
            check
                .events
                .recv_timeout(Duration::from_millis(500))
                .is_err()
        );
        assert_eq!(
            check.call("session", serde_json::json!({})).unwrap()["state"],
            "starting"
        );
    }

    #[test]
    fn the_session_command_gives_the_view() {
        let fixture = fixture(Mode::SelfCheck);
        let view = fixture.call("session", serde_json::json!({})).unwrap();
        assert_eq!(view, serde_json::json!({ "state": "starting" }));
    }

    #[test]
    fn connect_refuses_an_address_that_is_not_https() {
        let fixture = fixture(Mode::SelfCheck);
        let answer = fixture.call(
            "connect",
            serde_json::json!({ "address": "http://ilm.example.com" }),
        );
        assert!(answer.is_err(), "{answer:?}");
    }

    #[test]
    fn sign_in_without_a_connection_reports_a_problem_and_opens_nothing() {
        let fixture = fixture(Mode::SelfCheck);

        let view = fixture
            .call("sign_in", serde_json::json!({ "providerId": "0" }))
            .unwrap();

        assert_eq!(view["state"], "signedOut");
        assert!(view["problem"].is_string());
        assert_eq!(fixture.next_event(), view);
        assert!(fixture.browser.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_computer_without_certificates_offers_none() {
        let fixture = fixture(Mode::SelfCheck);

        let answer = fixture.call("certificates", serde_json::json!({})).unwrap();

        assert_eq!(answer, serde_json::json!([]));
    }

    #[test]
    fn sign_in_with_a_certificate_without_a_connection_reports_a_problem() {
        let fixture = fixture(Mode::SelfCheck);

        let view = fixture
            .call(
                "sign_in_with_certificate",
                serde_json::json!({ "fingerprint": "00" }),
            )
            .unwrap();

        assert_eq!(view["state"], "signedOut");
        assert!(view["problem"].is_string());
        assert_eq!(fixture.next_event(), view);
        assert!(fixture.browser.0.lock().unwrap().is_empty());
    }

    #[test]
    fn sign_out_gives_the_signed_out_view_and_tells_the_windows() {
        let fixture = fixture(Mode::SelfCheck);

        let view = fixture.call("sign_out", serde_json::json!({})).unwrap();

        assert_eq!(view["state"], "signedOut");
        assert_eq!(fixture.next_event(), view);
    }

    #[test]
    fn reopening_and_cancelling_without_a_sign_in_do_nothing() {
        let fixture = fixture(Mode::SelfCheck);

        assert!(
            fixture
                .call("reopen_browser", serde_json::json!({}))
                .is_ok()
        );
        assert!(
            fixture
                .call("cancel_sign_in", serde_json::json!({}))
                .is_ok()
        );

        assert!(fixture.browser.0.lock().unwrap().is_empty());
    }

    #[test]
    fn what_the_windows_receive_holds_no_secret_field() {
        let fixture = fixture(Mode::SelfCheck);
        let view = fixture.call("sign_out", serde_json::json!({})).unwrap();
        let keys: Vec<_> = view.as_object().unwrap().keys().cloned().collect();
        for key in keys {
            assert!(
                ["state", "address", "locked", "problem"].contains(&key.as_str()),
                "{key}"
            );
        }
    }
}
