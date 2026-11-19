use std::future::Future;
use std::sync::Arc;

use im_core::identity::{EmptyStore, IdentityStore, system_store};
use im_core::session::{
    CertificateChoice, KeyringStore, MemoryStore, ProviderChoice, RefreshStore, Session,
    SessionView, SignInAgain,
};
use im_core::{AppInfo, http};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use tauri_plugin_opener::OpenerExt;
use url::Url;

use crate::keep_alive;
use crate::lock::{self, Guard, Surface};
use crate::notice::{Notices, Notifier};
use crate::settings::Settings;
use crate::{Mode, summary};

const CHANGED: &str = "session-changed";
/// Sent to the main window when signing in again needs the person to choose a provider.
const CHOICES: &str = "sign-in-choices";

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

/// The windows of the application.
struct Windows<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Surface for Windows<R> {
    fn show(&self, view: &SessionView) {
        if let Err(error) = self.0.emit(CHANGED, view) {
            log::warn!("the sign-in state could not be sent to the windows: {error}");
        }
    }

    fn hide_summary(&self) {
        summary::hide(&self.0);
    }
}

/// The lock of this system. In self-check mode, and in unit tests, it reads nothing and never locks.
pub fn system_guard<R: Runtime>(app: &AppHandle<R>, mode: Mode) -> Guard {
    let windows = Arc::new(Windows(app.clone()));
    if mode == Mode::SelfCheck || cfg!(test) {
        Guard::new(windows, Arc::new(lock::NoState), lock::NoPrompt)
    } else {
        Guard::new(windows, lock::system_state(), lock::authenticator(app))
    }
}

/// The sign-in of the person, the way to the browser and the lock in front of both.
pub struct SignIn {
    session: Arc<Session>,
    opener: Arc<dyn Opener>,
    guard: Arc<Guard>,
}

/// Builds the session, tells the windows about each change of it, hidden while the application is locked,
/// and, outside self-check mode, renews a stored sign-in in the background and keeps it checked.
pub fn manage<R: Runtime>(
    app: &AppHandle<R>,
    mode: Mode,
    settings: Arc<Settings>,
    store: Arc<dyn RefreshStore>,
    opener: Arc<dyn Opener>,
    notifier: Box<dyn Notifier>,
    guard: Guard,
) {
    let notices = Notices::new(notifier, AppInfo::current().platform);
    let guard = Arc::new(guard);
    let views = guard.clone();
    let session = Arc::new(
        Session::new(http::client(), settings.clone(), store, move |view| {
            views.publish(view);
            notices.view(view);
        })
        .with_identities(identities()),
    );
    let session_for_timers = session.clone();
    app.manage(SignIn {
        session: session.clone(),
        opener,
        guard: guard.clone(),
    });
    app.manage(guard.clone());
    tauri::async_runtime::spawn({
        let guard = guard.clone();
        async move {
            // The lock knows what the system can do before the first view arrives.
            guard.adopt(|| settings.view()).await;
            if mode != Mode::SelfCheck {
                session.start().await;
            }
        }
    });
    if mode != Mode::SelfCheck {
        tauri::async_runtime::spawn(lock::watch(guard));
        tauri::async_runtime::spawn(keep_alive::run(session_for_timers));
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
        Box::new(crate::notice::Silent),
        system_guard(app, Mode::SelfCheck),
    );
}

fn state<R: Runtime>(app: &AppHandle<R>) -> State<'_, SignIn> {
    app.state::<SignIn>()
}

#[tauri::command]
pub fn session(state: State<'_, SignIn>) -> SessionView {
    state.guard.visible(state.guard.real())
}

/// The session and the lock, when the application is unlocked.
fn unlocked<R: Runtime>(app: &AppHandle<R>) -> Result<(Arc<Session>, Arc<Guard>), String> {
    let state = state(app);
    state.guard.ensure_unlocked()?;
    Ok((state.session.clone(), state.guard.clone()))
}

#[tauri::command]
pub async fn connect<R: Runtime>(
    app: AppHandle<R>,
    address: String,
) -> Result<Vec<ProviderChoice>, String> {
    let (session, _) = unlocked(&app)?;
    session.connect(&address).await
}

#[tauri::command]
pub async fn sign_in<R: Runtime>(
    app: AppHandle<R>,
    provider_id: String,
) -> Result<SessionView, String> {
    let (session, guard) = unlocked(&app)?;
    let opener = state(&app).opener.clone();
    let view = session
        .sign_in(&provider_id, move |url| opener.open(url))
        .await;
    Ok(guard.visible(view))
}

#[tauri::command]
pub async fn certificates<R: Runtime>(app: AppHandle<R>) -> Result<Vec<CertificateChoice>, String> {
    let (session, guard) = unlocked(&app)?;
    unlocked_afterwards(&guard, session.certificates()).await
}

/// The answer of `work`, unless the application locked while it ran.
async fn unlocked_afterwards<T>(guard: &Guard, work: impl Future<Output = T>) -> Result<T, String> {
    let answer = work.await;
    guard.ensure_unlocked()?;
    Ok(answer)
}

#[tauri::command]
pub async fn sign_in_with_certificate<R: Runtime>(
    app: AppHandle<R>,
    fingerprint: String,
) -> Result<SessionView, String> {
    let (session, guard) = unlocked(&app)?;
    let view = session.sign_in_with_certificate(&fingerprint).await;
    Ok(guard.visible(view))
}

#[tauri::command]
pub fn reopen_browser<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    unlocked(&app)?;
    let state = state(&app);
    if let Some(url) = state.session.browser_url() {
        state.opener.open(&url);
    }
    Ok(())
}

#[tauri::command]
pub fn cancel_sign_in(state: State<'_, SignIn>) {
    state.session.cancel();
}

#[tauri::command]
pub async fn sign_out<R: Runtime>(app: AppHandle<R>) -> Result<SessionView, String> {
    let (session, _) = unlocked(&app)?;
    Ok(session.sign_out().await)
}

/// Asks the system to confirm the person. When it does, the windows get the sign-in again and ILM is asked
/// whether the sign-in still holds. When it does not, the answer is the reason, and the application stays locked.
#[tauri::command]
pub async fn unlock<R: Runtime>(app: AppHandle<R>) -> Result<SessionView, String> {
    let (session, guard) = {
        let state = state(&app);
        (state.session.clone(), state.guard.clone())
    };
    let view = guard.unlock().await?;
    tauri::async_runtime::spawn(async move { keep_alive::refresh(&*session).await });
    Ok(view)
}

/// Shows the main window and repeats the sign-in that ended on its own. The new state reaches the windows as
/// `session-changed`; when the person has to choose a provider, the main window gets `sign-in-choices` and the
/// choices are also returned, none when the sign-in was started. The tray menu calls this too.
pub async fn begin_sign_in_again<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Vec<ProviderChoice>, String> {
    let (session, _) = unlocked(app)?;
    let opener = state(app).opener.clone();
    crate::show_main_window(app);
    match session.sign_in_again(move |url| opener.open(url)).await {
        SignInAgain::View(_) => Ok(Vec::new()),
        SignInAgain::Choose(choices) => {
            if let Err(error) = app.emit_to("main", CHOICES, &choices) {
                log::warn!("the choice of providers could not be sent to the main window: {error}");
            }
            Ok(choices)
        }
    }
}

#[tauri::command]
pub async fn sign_in_again<R: Runtime>(app: AppHandle<R>) -> Result<Vec<ProviderChoice>, String> {
    begin_sign_in_again(&app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{Availability, Confirmation, ScriptedAuthenticator, ScriptedState};
    use im_core::session::PersonView;
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
        state: Arc<ScriptedState>,
        prompt: Arc<ScriptedAuthenticator>,
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
                sign_out,
                unlock,
                sign_in_again,
                crate::settings::settings,
                crate::settings::set_setting
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
        let state = Arc::new(ScriptedState::default());
        state.set(Some(false), Some(Duration::ZERO));
        let prompt = Arc::new(ScriptedAuthenticator::new(Availability::Available));
        app.manage(settings.clone());
        manage(
            app.handle(),
            mode,
            settings,
            Arc::new(MemoryStore::default()),
            Arc::new(browser.clone()),
            Box::new(crate::notice::Silent),
            Guard::new(
                Arc::new(Windows(app.handle().clone())),
                state.clone(),
                prompt.clone(),
            ),
        );
        let window = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
            .build()
            .unwrap();
        Fixture {
            app,
            window,
            browser,
            events,
            state,
            prompt,
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

        fn guard(&self) -> Arc<Guard> {
            self.app.state::<Arc<Guard>>().inner().clone()
        }

        /// Locks the application as a computer lock does while the person is signed in.
        fn lock(&self) {
            let guard = self.guard();
            let settings = self.app.state::<Arc<Settings>>().inner().clone();
            tauri::async_runtime::block_on(guard.adopt(|| settings.view()));
            guard.publish(&SessionView::SignedOut {
                address: None,
                locked: false,
                problem: None,
                again: false,
            });
            guard.publish(&SessionView::SignedIn {
                address: "https://ilm.example.com".to_owned(),
                person: PersonView {
                    name: "Ada".to_owned(),
                    username: "ada".to_owned(),
                },
                allowed_listings: Vec::new(),
                certificate: None,
                unreachable: false,
            });
            self.state.set(Some(true), Some(Duration::from_secs(4242)));
            guard.sample();
            assert!(guard.is_locked());
        }

        fn drain_events(&self) {
            while self.events.try_recv().is_ok() {}
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
    fn the_session_command_gives_only_what_the_lock_has_seen() {
        let fixture = fixture(Mode::SelfCheck);
        let guard = fixture.guard();
        guard.publish(&SessionView::SignedOut {
            address: None,
            locked: false,
            problem: None,
            again: false,
        });

        let view = fixture.call("session", serde_json::json!({})).unwrap();

        assert_eq!(view["state"], "signedOut");
    }

    #[test]
    fn a_list_that_was_read_while_the_application_locked_is_not_given() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();
        let guard = fixture.guard();

        let answer = tauri::async_runtime::block_on(unlocked_afterwards(&guard, async { 1 }));

        assert_eq!(answer, Err(LOCKED.to_owned()));
    }

    #[test]
    fn a_list_that_was_read_while_the_application_stays_unlocked_is_given() {
        let fixture = fixture(Mode::SelfCheck);
        let guard = fixture.guard();

        let answer = tauri::async_runtime::block_on(unlocked_afterwards(&guard, async { 1 }));

        assert_eq!(answer, Ok(1));
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
    fn signing_in_again_without_an_ended_sign_in_chooses_nothing_and_opens_nothing() {
        let fixture = fixture(Mode::SelfCheck);

        let choices = fixture
            .call("sign_in_again", serde_json::json!({}))
            .unwrap();

        assert_eq!(choices, serde_json::json!([]));
        assert!(fixture.browser.0.lock().unwrap().is_empty());
    }

    const LOCKED: &str = "Unlock Identity Manager first.";

    fn refused_as_locked(answer: Result<serde_json::Value, String>, command: &str) {
        match answer {
            Err(error) => assert!(error.contains(LOCKED), "{command}: {error}"),
            Ok(value) => panic!("{command} was not refused: {value}"),
        }
    }

    #[test]
    fn while_locked_the_windows_get_the_locked_view_and_every_sign_in_command_refuses() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();

        assert_eq!(
            fixture.call("session", serde_json::json!({})).unwrap(),
            serde_json::json!({ "state": "locked" })
        );
        let commands = [
            (
                "connect",
                serde_json::json!({ "address": "ilm.example.com" }),
            ),
            ("sign_in", serde_json::json!({ "providerId": "0" })),
            ("certificates", serde_json::json!({})),
            (
                "sign_in_with_certificate",
                serde_json::json!({ "fingerprint": "00" }),
            ),
            ("sign_out", serde_json::json!({})),
            ("sign_in_again", serde_json::json!({})),
            ("reopen_browser", serde_json::json!({})),
        ];
        for (command, body) in commands {
            refused_as_locked(fixture.call(command, body), command);
        }
        assert!(fixture.browser.0.lock().unwrap().is_empty());
        assert!(fixture.call("settings", serde_json::json!({})).is_ok());
        assert!(
            fixture
                .call("cancel_sign_in", serde_json::json!({}))
                .is_ok()
        );
    }

    #[test]
    fn locking_tells_the_windows() {
        let fixture = fixture(Mode::SelfCheck);
        WebviewWindowBuilder::new(&fixture.app, summary::LABEL, WebviewUrl::default())
            .build()
            .unwrap();

        fixture.lock();

        let told: Vec<_> = (0..3)
            .map(|_| fixture.next_event()["state"].clone())
            .collect();
        assert_eq!(told, ["signedOut", "signedIn", "locked"]);
    }

    #[test]
    fn unlock_confirmed_shows_the_sign_in_to_the_windows_and_returns_it() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();
        fixture.drain_events();
        fixture.prompt.queue(Confirmation::Confirmed);

        let view = fixture.call("unlock", serde_json::json!({})).unwrap();

        assert_eq!(view["state"], "signedIn");
        assert_eq!(fixture.next_event()["state"], "signedIn");
        assert!(!fixture.guard().is_locked());
        assert_eq!(
            fixture.call("session", serde_json::json!({})).unwrap()["state"],
            "signedIn"
        );
    }

    #[test]
    fn unlock_cancelled_or_failed_returns_the_problem_and_stays_locked() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();
        fixture.prompt.queue(Confirmation::Cancelled);
        fixture
            .prompt
            .queue(Confirmation::Failed("The system refused.".to_owned()));

        let cancelled = fixture.call("unlock", serde_json::json!({}));
        let failed = fixture.call("unlock", serde_json::json!({}));

        assert!(cancelled.unwrap_err().contains("Unlock was cancelled."));
        assert!(failed.unwrap_err().contains("The system refused."));
        assert!(fixture.guard().is_locked());
        assert_eq!(
            fixture.call("session", serde_json::json!({})).unwrap()["state"],
            "locked"
        );
    }

    #[test]
    fn the_settings_commands_carry_what_the_system_can_do_and_follow_the_setting() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();

        let view = fixture.call("settings", serde_json::json!({})).unwrap();
        assert_eq!(view["unlock"], "available");

        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.call("unlock", serde_json::json!({})).unwrap();
        let off = fixture.call("set_setting", turn_unlock_off()).unwrap();
        assert_eq!(off["requireUnlock"]["value"], false);
        assert!(!fixture.guard().is_locked());
    }

    fn turn_unlock_off() -> serde_json::Value {
        serde_json::json!({ "change": { "key": "requireUnlock", "value": false } })
    }

    #[test]
    fn a_setting_cannot_be_changed_while_locked_and_nothing_is_saved() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();

        refused_as_locked(
            fixture.call("set_setting", turn_unlock_off()),
            "set_setting",
        );

        assert!(fixture.guard().is_locked());
        let view = fixture.call("settings", serde_json::json!({})).unwrap();
        assert_eq!(view["requireUnlock"]["value"], true);
    }

    #[test]
    fn the_log_of_a_lock_and_an_ended_sign_in_holds_no_personal_data() {
        let lines = capture_logs();
        let fixture = fixture(Mode::SelfCheck);
        fixture.lock();
        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.call("unlock", serde_json::json!({})).unwrap();
        let notices = Notices::new(Box::new(crate::notice::Silent), im_core::Platform::Macos);
        notices.view(&SessionView::SignedOut {
            address: Some("https://ada.example.com".to_owned()),
            locked: false,
            problem: Some("The sign-in has ended.".to_owned()),
            again: true,
        });

        let log = lines.lock().unwrap().join("\n");
        assert!(log.contains("locked: computer"), "{log}");
        assert!(log.contains("unlocked"), "{log}");
        assert!(log.contains("notified that the sign-in has ended"), "{log}");
        for (index, secret) in ["4242", "Ada", "ada.example.com"].into_iter().enumerate() {
            assert!(!log.contains(secret), "the log holds secret number {index}");
        }
    }

    #[test]
    fn what_the_windows_receive_holds_no_secret_field() {
        let fixture = fixture(Mode::SelfCheck);
        let view = fixture.call("sign_out", serde_json::json!({})).unwrap();
        let keys: Vec<_> = view.as_object().unwrap().keys().cloned().collect();
        for key in keys {
            assert!(
                ["state", "address", "locked", "problem", "again"].contains(&key.as_str()),
                "{key}"
            );
        }
    }

    /// Captures the log lines of every test in the process; the logger can be installed only once.
    fn capture_logs() -> &'static Mutex<Vec<String>> {
        use std::sync::OnceLock;

        static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());
        struct Capture;
        impl log::Log for Capture {
            fn enabled(&self, _: &log::Metadata) -> bool {
                true
            }
            fn log(&self, record: &log::Record) {
                LINES.lock().unwrap().push(record.args().to_string());
            }
            fn flush(&self) {}
        }
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            log::set_logger(&Capture).expect("no other logger is installed in tests");
            log::set_max_level(log::LevelFilter::Info);
        });
        &LINES
    }
}
