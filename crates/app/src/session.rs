use std::future::Future;
use std::sync::Arc;

use im_core::identity::IdentityStore;
use im_core::ilm::IlmUrl;
use im_core::ilm::attributes::{WebTarget, web_url};
use im_core::inventory::{Inventory, Trigger};
use im_core::session::{
    CertificateChoice, FormError, KeyringStore, MemoryStore, ProviderChoice, RefreshStore, Session,
    SessionView, SignInAgain,
};
use im_core::{AppInfo, http};
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use tauri_plugin_opener::OpenerExt;
use url::Url;

use crate::certificates::{Ilm, Local, ilm};
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
    fn open(&self, url: &Url) -> Result<(), String>;
}

const BROWSER_UNAVAILABLE: &str = "The browser could not be opened.";

pub struct SystemOpener<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SystemOpener<R> {
    pub fn new(app: &AppHandle<R>) -> Self {
        Self(app.clone())
    }
}

impl<R: Runtime> Opener for SystemOpener<R> {
    fn open(&self, url: &Url) -> Result<(), String> {
        // The address carries the request of the sign-in, and the opener's error may hold it, so neither is
        // logged or returned.
        self.0
            .opener()
            .open_url(url.as_str(), None::<&str>)
            .map_err(|_| {
                log::warn!("{}", BROWSER_UNAVAILABLE);
                BROWSER_UNAVAILABLE.to_owned()
            })
    }
}

/// The windows of the application.
struct Windows<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Surface for Windows<R> {
    fn show(&self, view: &SessionView) {
        if let Err(error) = self.0.emit(CHANGED, view) {
            log::warn!("the sign-in state could not be sent to the windows: {error}");
        }
        crate::tray::set_locked(&self.0, matches!(view, SessionView::Locked {}));
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
/// and, outside self-check mode, renews a stored sign-in in the background and keeps it checked. Sign-in and
/// the Certificates section read the same store. The answer of ILM about the certificates is kept in a file beside
/// the settings, which the application has already given to `app`.
pub fn manage<R: Runtime>(
    app: &AppHandle<R>,
    mode: Mode,
    store: Arc<dyn RefreshStore>,
    opener: Arc<dyn Opener>,
    notifier: Box<dyn Notifier>,
    guard: Guard,
    identities: Arc<dyn IdentityStore>,
) {
    let settings = app.state::<Arc<Settings>>().inner().clone();
    let notices = Arc::new(Notices::new(
        notifier,
        AppInfo::current().platform,
        settings.folder().to_owned(),
    ));
    let guard = Arc::new(guard);
    let views = guard.clone();
    let announcing = notices.clone();
    let session = Arc::new(
        Session::new(http::client(), settings.clone(), store, move |view| {
            views.publish(view);
            announcing.view(view);
        })
        .with_identities(identities.clone()),
    );
    let inventory =
        Arc::new(Inventory::new(settings.folder()).with_zone(crate::local_time::utc_offset_at));
    let ilm = Arc::new(Ilm::new(
        app,
        session.clone(),
        inventory,
        guard.clone(),
        settings.clone(),
        identities.clone(),
        notices,
    ));
    session.on_signed_out({
        let ilm = ilm.clone();
        move || ilm.signed_out()
    });
    guard.on_lock({
        let session = session.clone();
        move || session.close_forms()
    });
    app.manage(ilm.clone());
    app.manage(SignIn {
        session: session.clone(),
        opener,
        guard: guard.clone(),
    });
    app.manage(guard.clone());
    app.manage(Local(identities));
    tauri::async_runtime::spawn({
        let guard = guard.clone();
        let ilm = ilm.clone();
        async move {
            // The lock knows what the system can do before the first view arrives.
            guard.adopt(|| settings.view()).await;
            if mode != Mode::SelfCheck {
                session.start().await;
                ilm.start().await;
            }
        }
    });
    if mode != Mode::SelfCheck {
        tauri::async_runtime::spawn(lock::watch(guard));
        tauri::async_runtime::spawn(keep_alive::run(ilm));
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
        Arc::new(MemoryStore::default()),
        Arc::new(SystemOpener::new(app)),
        Box::new(crate::notice::Silent),
        system_guard(app, Mode::SelfCheck),
        crate::certificates::system_identities(),
    );
}

impl SignIn {
    /// Opens the page of ILM's web interface that `target` names, in the browser.
    pub(crate) fn open_in_ilm(&self, target: &WebTarget) -> Result<(), String> {
        self.guard.ensure_unlocked()?;
        let who = self
            .session
            .signed_in_as()
            .ok_or_else(|| FormError::SignedOut.to_string())?;
        self.open_page(&who.ilm, target)
    }

    fn open_page(&self, ilm: &IlmUrl, target: &WebTarget) -> Result<(), String> {
        let url = Url::parse(&web_url(ilm, target))
            .map_err(|_| "ILM's web interface cannot be opened.".to_owned())?;
        self.opener
            .open(&url)
            .map_err(|_| BROWSER_UNAVAILABLE.to_owned())
    }
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
    let (session, guard) = unlocked(&app)?;
    unlocked_afterwards(&guard, session.connect(&address)).await?
}

#[tauri::command]
pub async fn sign_in<R: Runtime>(
    app: AppHandle<R>,
    provider_id: String,
) -> Result<SessionView, String> {
    let (session, guard) = unlocked(&app)?;
    let opener = state(&app).opener.clone();
    let view = session
        .sign_in(&provider_id, move |url| {
            let _ = opener.open(url);
        })
        .await;
    ilm(&app).after_sign_in(&view);
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
    ilm(&app).after_sign_in(&view);
    Ok(guard.visible(view))
}

#[tauri::command]
pub fn reopen_browser<R: Runtime>(app: AppHandle<R>) -> Result<(), String> {
    unlocked(&app)?;
    let state = state(&app);
    if let Some(url) = state.session.browser_url() {
        let _ = state.opener.open(&url);
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
    let guard = state(&app).guard.clone();
    let view = guard.unlock().await?;
    let ilm = ilm(&app);
    tauri::async_runtime::spawn(async move { keep_alive::refresh(&*ilm, Trigger::Start).await });
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
    match session
        .sign_in_again(move |url| {
            let _ = opener.open(url);
        })
        .await
    {
        SignInAgain::View(view) => {
            ilm(app).after_sign_in(&view);
            Ok(Vec::new())
        }
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
    use crate::certificates::system_identities;
    use crate::lock::{Availability, Confirmation, ScriptedAuthenticator, ScriptedState};
    use im_core::identity::{
        ClientIdentity, Fingerprint, KeyAlgorithm, KeyLocation, LocalCertificate, StoreUnreadable,
    };
    use im_core::ilm::IlmUrl;
    use im_core::oauth::token::RefreshToken;
    use im_core::session::{ConnectionSettings, Item, PersonView};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, channel};
    use std::time::{Duration, SystemTime};
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::webview::InvokeRequest;
    use tauri::{Listener, WebviewUrl, WebviewWindowBuilder, ipc::CallbackFn};

    #[derive(Default)]
    struct Browser(Mutex<Vec<String>>, AtomicBool);

    impl Opener for Arc<Browser> {
        fn open(&self, url: &Url) -> Result<(), String> {
            if self.1.load(Ordering::SeqCst) {
                return Err("no browser".to_owned());
            }
            self.0.lock().unwrap().push(url.to_string());
            Ok(())
        }
    }

    /// The notifications that were shown.
    #[derive(Default)]
    struct Shown(Mutex<Vec<(String, String)>>);

    impl crate::notice::Notifier for Arc<Shown> {
        fn notify(&self, title: &str, body: &str) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push((title.to_owned(), body.to_owned()));
            Ok(())
        }
    }

    struct Fixture {
        app: tauri::App<MockRuntime>,
        notified: Arc<Shown>,
        window: tauri::WebviewWindow<MockRuntime>,
        browser: Arc<Browser>,
        events: Receiver<String>,
        state: Arc<ScriptedState>,
        prompt: Arc<ScriptedAuthenticator>,
        _folder: tempfile::TempDir,
    }

    fn fixture(mode: Mode) -> Fixture {
        fixture_with(mode, None, system_identities())
    }

    /// A fixture whose settings have a saved sign-in at `saved`, with an ILM answer kept for it.
    fn fixture_with(
        mode: Mode,
        saved: Option<&IlmUrl>,
        identities: Arc<dyn IdentityStore>,
    ) -> Fixture {
        let folder = tempfile::tempdir().unwrap();
        let app = mock_builder()
            .manage(crate::bridge::PendingNavigation::default())
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
                crate::settings::set_setting,
                crate::certificates::local_certificates,
                crate::certificates::ilm_status,
                crate::certificates::ilm_certificates,
                crate::certificates::sync_now,
                crate::certificates::make_sign_in_certificate,
                crate::certificates::overview,
                crate::certificates::add_to_ilm_choices,
                crate::certificates::add_to_ilm,
                crate::attributes::attribute_callback,
                crate::attributes::check_attributes,
                crate::attributes::close_form,
                crate::attributes::open_in_ilm
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
        let store = Arc::new(MemoryStore::default());
        if let Some(address) = saved {
            settings.save_address(address).unwrap();
            store
                .save(&Item {
                    ilm: address.clone(),
                    issuer: "https://idp.invalid".to_owned(),
                    client_id: "app".to_owned(),
                    resource: None,
                    refresh_token: RefreshToken::new("saved"),
                })
                .unwrap();
            std::fs::write(
                folder.path().join("ilm-cache.json"),
                serde_json::json!({
                    "version": 1, "ilm": address.as_str(), "username": "ada", "checkedAt": 5,
                    "listed": true, "checked": [], "matches": {
                        Fingerprint::of(&[1]).to_string(): {
                            "uuid": "u-1", "name": "Ada", "subjectDn": null, "issuerName": null,
                            "serial": null, "notBefore": null, "notAfter": null, "fingerprint": null,
                            "key": null, "state": "issued", "validationStatus": "valid",
                            "raProfile": null, "owner": null, "groups": [], "archived": false
                        }
                    }, "signIn": null, "firstPage": null, "allowed": {}
                })
                .to_string(),
            )
            .unwrap();
        }
        let browser = Arc::new(Browser::default());
        let notified = Arc::new(Shown::default());
        let state = Arc::new(ScriptedState::default());
        state.set(Some(false), Some(Duration::ZERO));
        let prompt = Arc::new(ScriptedAuthenticator::new(Availability::Available));
        app.manage(settings.clone());
        manage(
            app.handle(),
            mode,
            store,
            Arc::new(browser.clone()),
            Box::new(notified.clone()),
            Guard::new(
                Arc::new(Windows(app.handle().clone())),
                state.clone(),
                prompt.clone(),
            ),
            identities,
        );
        let window = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
            .build()
            .unwrap();
        Fixture {
            app,
            notified,
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
            self.sign_in_shown();
            self.engage_lock();
            assert!(self.guard().is_locked());
        }

        fn engage_lock(&self) {
            self.state.set(Some(true), Some(Duration::from_secs(4242)));
            self.guard().sample();
        }

        /// The guard has seen a signed-in view, so a computer lock will lock the application.
        fn sign_in_shown(&self) {
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
    fn a_start_that_cannot_reach_ilm_shows_the_kept_answer_once_unlocked() {
        let address = IlmUrl::parse("ilm.invalid").unwrap();
        let fixture = fixture_with(Mode::SelfCheck, Some(&address), system_identities());
        let view = tauri::async_runtime::block_on(async {
            let started = fixture.app.state::<SignIn>().session.start().await;
            ilm(fixture.app.handle()).start().await;
            started
        });
        assert!(matches!(view, SessionView::Unreachable { .. }), "{view:?}");
        refused_as_locked(
            fixture.call("ilm_status", serde_json::json!({})),
            "ilm_status",
        );
        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.call("unlock", serde_json::json!({})).unwrap();

        let shown = fixture.call("ilm_status", serde_json::json!({})).unwrap();

        assert_eq!(shown["checkedAt"], 5);
        assert_eq!(shown["listed"], true);
        assert_eq!(shown["status"]["state"], "offline");
        assert_eq!(shown["status"]["reason"], "ILM cannot be reached.");
        let page = fixture.call(
            "ilm_certificates",
            serde_json::json!({ "page": 1, "search": null }),
        );
        assert!(page.unwrap_err().contains("ILM cannot be reached."));
        assert!(
            fixture
                .call("local_certificates", serde_json::json!({}))
                .is_ok()
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
    fn the_certificates_are_not_listed_while_locked() {
        let fixture = fixture(Mode::SelfCheck);
        assert_eq!(
            fixture
                .call("local_certificates", serde_json::json!({}))
                .unwrap(),
            serde_json::json!([])
        );

        fixture.lock();

        refused_as_locked(
            fixture.call("local_certificates", serde_json::json!({})),
            "local_certificates",
        );
    }

    #[test]
    fn the_inventory_commands_refuse_while_locked_and_answer_otherwise() {
        let fixture = fixture(Mode::SelfCheck);
        let page = serde_json::json!({ "page": 1, "search": null });
        let fingerprint = serde_json::json!({ "fingerprint": "00" });
        let status = fixture.call("ilm_status", serde_json::json!({})).unwrap();
        assert_eq!(status["status"]["state"], "never");
        assert_eq!(status["checking"], false);
        assert_eq!(status["listed"], false);
        assert!(
            fixture
                .call("sync_now", serde_json::json!({}))
                .is_ok_and(|view| view["status"]["state"] == "never")
        );

        fixture.lock();

        refused_as_locked(
            fixture.call("ilm_status", serde_json::json!({})),
            "ilm_status",
        );
        refused_as_locked(fixture.call("ilm_certificates", page), "ilm_certificates");
        refused_as_locked(fixture.call("sync_now", serde_json::json!({})), "sync_now");
        refused_as_locked(
            fixture.call("make_sign_in_certificate", fingerprint),
            "make_sign_in_certificate",
        );
    }

    fn form_commands() -> [(&'static str, serde_json::Value); 4] {
        [
            (
                "attribute_callback",
                serde_json::json!({ "id": "x", "field": "f", "values": {}, "seq": 1 }),
            ),
            (
                "check_attributes",
                serde_json::json!({ "id": "x", "values": {} }),
            ),
            ("close_form", serde_json::json!({ "id": "x" })),
            ("open_in_ilm", serde_json::json!({ "target": "addToIlm" })),
        ]
    }

    #[test]
    fn the_form_commands_refuse_while_locked_and_answer_otherwise() {
        let fixture = fixture(Mode::SelfCheck);
        let answers: Vec<_> = form_commands()
            .into_iter()
            .map(|(command, body)| fixture.call(command, body))
            .collect();
        assert!(answers[0].as_ref().unwrap_err().contains("not signed in"));
        assert!(answers[1].as_ref().unwrap_err().contains("not open"));
        assert!(answers[2].is_ok());
        assert!(answers[3].as_ref().unwrap_err().contains("not signed in"));

        fixture.lock();

        for (command, body) in form_commands() {
            refused_as_locked(fixture.call(command, body), command);
        }
        assert!(fixture.browser.0.lock().unwrap().is_empty());
    }

    #[test]
    fn open_in_ilm_opens_the_page_of_the_target_at_the_origin_of_the_ilm_address() {
        let fixture = fixture(Mode::SelfCheck);
        let ilm = IlmUrl::parse("ilm.example.com:8443/core/api").unwrap();

        fixture
            .app
            .state::<SignIn>()
            .open_page(&ilm, &crate::attributes::IlmTarget::AddToIlm.web())
            .unwrap();

        assert_eq!(
            *fixture.browser.0.lock().unwrap(),
            ["https://ilm.example.com:8443/administrator/#/certificates"]
        );
    }

    #[test]
    fn open_in_ilm_reports_a_browser_that_cannot_be_opened() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.browser.1.store(true, Ordering::SeqCst);
        let ilm = IlmUrl::parse("ilm.example.com/core/api").unwrap();

        let error = fixture
            .app
            .state::<SignIn>()
            .open_page(&ilm, &crate::attributes::IlmTarget::AddToIlm.web())
            .unwrap_err();

        assert_eq!(error, "The browser could not be opened.");
    }

    #[test]
    fn a_change_that_ends_after_the_lock_came_says_it_is_locked_and_not_why_it_failed() {
        let fixture = fixture(Mode::SelfCheck);
        fixture.sign_in_shown();
        let state = fixture.state.clone();
        let guard = fixture.guard();
        let events = AtomicUsize::new(0);
        fixture.app.listen("inventory-changed", move |_| {
            if events.fetch_add(1, Ordering::SeqCst) == 1 {
                state.set(Some(true), Some(Duration::from_secs(4242)));
                guard.sample();
            }
        });

        refused_as_locked(
            fixture.call(
                "make_sign_in_certificate",
                serde_json::json!({ "fingerprint": "00" }),
            ),
            "make_sign_in_certificate",
        );
    }

    #[test]
    fn a_check_tells_the_windows_when_it_starts_and_when_it_ends_without_data() {
        let app = mock_builder()
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        manage_for_tests(app.handle());
        let (sender, events) = channel();
        app.listen("inventory-changed", move |event| {
            sender.send(event.payload().to_string()).unwrap();
        });
        let ilm = ilm(app.handle());

        let done = tauri::async_runtime::block_on(async {
            ilm.working(async {
                assert!(ilm.view().checking);
                7
            })
            .await
        });

        assert_eq!(done, 7);
        assert!(!ilm.view().checking);
        for _ in 0..2 {
            assert_eq!(events.recv_timeout(Duration::from_secs(5)).unwrap(), "null");
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
        let notices = Notices::new(
            Box::new(crate::notice::Silent),
            im_core::Platform::Macos,
            fixture._folder.path().to_owned(),
        );
        notices.view(&SessionView::SignedOut {
            address: Some("https://ada.example.com".to_owned()),
            locked: false,
            problem: Some("The sign-in has ended.".to_owned()),
            again: true,
        });

        notices.summary(
            &im_core::inventory::summarize(
                &[sample("Grace Hopper", 7, 5)],
                None,
                im_core::settings::WarnDays::new(30).unwrap(),
                now_millis(),
                |_| 0,
            ),
            &[im_core::identity::Fingerprint::of(&[7])],
            || true,
            || true,
        );

        let log = lines.lock().unwrap().join("\n");
        assert!(log.contains("notification sent (expiring)"), "{log}");
        assert!(log.contains("locked: computer"), "{log}");
        assert!(log.contains("unlocked"), "{log}");
        assert!(log.contains("notified that the sign-in has ended"), "{log}");
        for (index, secret) in ["4242", "Ada", "ada.example.com", "Grace"]
            .into_iter()
            .enumerate()
        {
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

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn sample(name: &str, number: u8, days: u64) -> LocalCertificate {
        LocalCertificate {
            fingerprint: Fingerprint::of(&[number]),
            name: name.to_owned(),
            subject: format!("CN={name}"),
            issuer: "Root".to_owned(),
            issuer_name: "CN=Root".to_owned(),
            serial: "01".to_owned(),
            not_before: SystemTime::UNIX_EPOCH,
            not_after: SystemTime::now() + Duration::from_secs(days * 86_400),
            uses: Vec::new(),
            alternative_names: Vec::new(),
            key: KeyAlgorithm::Ed25519,
            location: KeyLocation::Keychain,
            sign_in: Ok(()),
        }
    }

    /// The certificates of this computer, as the check that follows an unlock reads them again.
    struct Certificates(Vec<LocalCertificate>);

    impl IdentityStore for Certificates {
        fn certificates(&self) -> Result<Vec<LocalCertificate>, StoreUnreadable> {
            Ok(self.0.clone())
        }

        fn open(&self, _fingerprint: &Fingerprint) -> Option<ClientIdentity> {
            None
        }
    }

    /// A saved sign-in whose ILM cannot be reached, with its saved answer, and `certificates` on this computer:
    /// the summary is built from them. The application starts locked.
    fn offline(certificates: Vec<LocalCertificate>) -> Fixture {
        let address = IlmUrl::parse("ilm.invalid").unwrap();
        let fixture = fixture_with(
            Mode::SelfCheck,
            Some(&address),
            Arc::new(Certificates(certificates)),
        );
        tauri::async_runtime::block_on(async {
            fixture.app.state::<SignIn>().session.start().await;
            ilm(fixture.app.handle()).start().await;
        });
        assert!(fixture.guard().is_locked());
        fixture
    }

    fn confirm_unlock(fixture: &Fixture) {
        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.call("unlock", serde_json::json!({})).unwrap();
    }

    fn told(fixture: &Fixture) -> Vec<(String, String)> {
        fixture.notified.0.lock().unwrap().clone()
    }

    #[test]
    fn the_overview_and_add_to_ilm_commands_refuse_while_locked_and_answer_otherwise() {
        let fixture = fixture(Mode::SelfCheck);
        let add = serde_json::json!({ "fingerprints": [], "group": null, "raProfile": null });
        assert_eq!(
            fixture.call("overview", serde_json::json!({})).unwrap(),
            serde_json::Value::Null
        );
        for (command, body) in [
            ("add_to_ilm_choices", serde_json::json!({})),
            ("add_to_ilm", add.clone()),
        ] {
            let error = fixture.call(command, body).unwrap_err();
            assert!(!error.contains(LOCKED), "{command}: {error}");
        }

        fixture.lock();

        refused_as_locked(fixture.call("overview", serde_json::json!({})), "overview");
        refused_as_locked(
            fixture.call("add_to_ilm_choices", serde_json::json!({})),
            "add_to_ilm_choices",
        );
        refused_as_locked(fixture.call("add_to_ilm", add), "add_to_ilm");
    }

    #[test]
    fn the_overview_is_the_summary_of_the_saved_answer_and_the_local_certificates() {
        let fixture = offline(vec![sample("Ada", 1, 20)]);
        confirm_unlock(&fixture);

        let summary = fixture.call("overview", serde_json::json!({})).unwrap();

        assert_eq!(summary["counts"]["expiring"], 1);
        assert_eq!(summary["attention"][0]["kind"], "expiring");
        assert_eq!(summary["attention"][0]["name"], "Ada");
        assert_eq!(summary["checkedAt"], 5);
    }

    #[test]
    fn a_change_of_the_warning_days_rebuilds_the_summary_at_once() {
        let fixture = offline(vec![sample("Ada", 1, 20)]);
        confirm_unlock(&fixture);
        let counts = |fixture: &Fixture| {
            fixture.call("overview", serde_json::json!({})).unwrap()["counts"].clone()
        };
        assert_eq!(counts(&fixture)["expiring"], 1);

        fixture
            .call(
                "set_setting",
                serde_json::json!({ "change": { "key": "warnDays", "value": 7 } }),
            )
            .unwrap();

        let after = counts(&fixture);
        assert_eq!(after["expiring"], 0);
        assert_eq!(after["valid"], 1);
    }

    #[test]
    fn nothing_is_told_while_locked_and_the_next_summary_after_the_unlock_tells_once() {
        let fixture = offline(vec![sample("Ada", 1, 5)]);
        let ilm = ilm(fixture.app.handle());

        ilm.publish_summary();
        assert!(told(&fixture).is_empty());

        confirm_unlock(&fixture);
        ilm.publish_summary();
        ilm.publish_summary();

        let told = told(&fixture);
        assert_eq!(told.len(), 1);
        assert_eq!(told[0].0, "Certificate expires soon");
        assert!(told[0].1.starts_with("Ada expires on "), "{}", told[0].1);
    }

    #[test]
    fn a_certificate_that_ilm_does_not_know_is_not_told_but_stays_in_the_summary() {
        let fixture = offline(vec![sample("Ada", 1, 5), sample("Bob", 2, 5)]);
        let ilm = ilm(fixture.app.handle());
        confirm_unlock(&fixture);

        ilm.publish_summary();

        let told = told(&fixture);
        assert_eq!(told.len(), 1);
        assert!(told[0].1.starts_with("Ada expires on "), "{}", told[0].1);
        assert_eq!(ilm.inventory().summary().unwrap().attention.len(), 2);
    }

    #[test]
    fn a_sign_out_deletes_what_was_remembered_and_the_summary() {
        let fixture = offline(vec![sample("Ada", 1, 5)]);
        let ilm = ilm(fixture.app.handle());
        confirm_unlock(&fixture);
        ilm.publish_summary();
        let record = fixture._folder.path().join("notified.json");
        assert!(record.exists());

        fixture.call("sign_out", serde_json::json!({})).unwrap();

        assert!(!record.exists());
        assert_eq!(
            fixture.call("overview", serde_json::json!({})).unwrap(),
            serde_json::Value::Null
        );
    }

    /// Asks the main window to open `target` and returns how many times it was woken for it.
    fn asked_to_navigate(fixture: &Fixture, target: Option<&str>) -> usize {
        let (sender, received) = channel();
        let id = fixture.window.listen("navigate", move |event| {
            sender.send(event.payload().to_owned()).unwrap();
        });
        crate::bridge::open_main_window(
            fixture.app.handle().clone(),
            fixture.app.state(),
            target.map(str::to_owned),
        );
        fixture.window.unlisten(id);
        received.try_iter().count()
    }

    fn taken(fixture: &Fixture) -> Option<serde_json::Value> {
        crate::bridge::pending_navigation(fixture.app.handle().clone(), fixture.app.state())
            .map(|place| serde_json::to_value(place).unwrap())
    }

    #[test]
    fn the_main_window_is_woken_and_takes_the_overview_or_a_certificate_once() {
        let fixture = fixture(Mode::SelfCheck);
        let print = Fingerprint::of(b"der").to_string();

        assert_eq!(asked_to_navigate(&fixture, Some("overview")), 1);
        assert_eq!(
            taken(&fixture),
            Some(serde_json::json!({ "to": "overview" }))
        );
        assert_eq!(taken(&fixture), None);
        assert_eq!(asked_to_navigate(&fixture, Some(&print)), 1);
        assert_eq!(
            taken(&fixture),
            Some(serde_json::json!({ "to": "certificate", "fingerprint": print }))
        );
        assert_eq!(asked_to_navigate(&fixture, None), 0);
        assert_eq!(asked_to_navigate(&fixture, Some("something else")), 0);
        assert_eq!(taken(&fixture), None);
    }

    #[test]
    fn a_request_made_before_the_interface_listens_is_kept_until_taken() {
        let fixture = fixture(Mode::SelfCheck);

        asked_to_navigate(&fixture, Some("overview"));

        assert_eq!(
            taken(&fixture),
            Some(serde_json::json!({ "to": "overview" }))
        );
    }

    #[test]
    fn while_locked_nothing_is_asked_or_kept_and_a_kept_request_is_not_handed_out() {
        let fixture = fixture(Mode::SelfCheck);
        asked_to_navigate(&fixture, Some("overview"));
        fixture.lock();

        assert_eq!(taken(&fixture), None);
        assert_eq!(asked_to_navigate(&fixture, Some("overview")), 0);
        assert_eq!(taken(&fixture), None);
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
