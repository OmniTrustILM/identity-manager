use std::borrow::Cow;
use std::sync::{Arc, Mutex, PoisonError};

use im_core::session::SessionView;
use im_core::{AppInfo, Platform};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::certificates::Ilm;
use crate::lock::Guard;
use crate::{session, settings_window, show_main_window, summary, update};

const TRAY_ID: &str = "main";

/// What the tray icon says about the sign-in and the certificates. A signed-out person, or one who cannot reach ILM,
/// is told that before certificates that need attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Fine,
    Attention,
    SignedOut,
    Unreachable,
}

/// Everything the tray shows: the state, whether a signed-out person can repeat the sign-in that ended, and the
/// version of an update that can be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Look {
    state: State,
    again: bool,
    update: Option<String>,
}

impl Look {
    const START: Look = Look {
        state: State::SignedOut,
        again: false,
        update: None,
    };

    /// The tray shows the real sign-in, never the lock; a locked view carries nothing and counts as signed out.
    fn of(view: &SessionView) -> Look {
        let (state, again) = match view {
            SessionView::SignedIn {
                unreachable: false, ..
            } => (State::Fine, false),
            SessionView::SignedIn {
                unreachable: true, ..
            }
            | SessionView::Unreachable { .. } => (State::Unreachable, false),
            SessionView::SignedOut { again, .. } => (State::SignedOut, *again),
            SessionView::Starting | SessionView::SigningIn { .. } | SessionView::Locked {} => {
                (State::SignedOut, false)
            }
        };
        Look {
            state,
            again,
            update: None,
        }
    }

    /// The look with the certificates that need attention (or not) taken into account.
    fn with_attention(self, attention: bool) -> Look {
        match self.state {
            State::Fine if attention => Look {
                state: State::Attention,
                ..self
            },
            _ => self,
        }
    }

    /// The look with the update that can be installed (or none).
    fn with_update(self, update: Option<String>) -> Look {
        Look { update, ..self }
    }
}

/// What the tray was told, and what it shows.
struct Seen {
    view: Look,
    attention: bool,
    locked: bool,
    update: Option<String>,
    shown: Look,
}

/// Remembers what the tray shows, so that it is touched only when that changes.
struct Shown(Mutex<Seen>);

impl Shown {
    fn new() -> Self {
        Self(Mutex::new(Seen {
            view: Look::START,
            attention: false,
            locked: false,
            update: None,
            shown: Look::START,
        }))
    }

    fn change(&self, tell: impl FnOnce(&mut Seen)) -> Option<Look> {
        let mut seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        tell(&mut seen);
        let next = seen
            .view
            .clone()
            .with_attention(seen.attention && !seen.locked)
            .with_update(seen.update.clone());
        (seen.shown != next).then(|| {
            seen.shown = next.clone();
            next
        })
    }

    /// What the tray was last told to show.
    fn latest(&self) -> Look {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .shown
            .clone()
    }

    /// The new look when the view changes what the tray shows.
    fn update(&self, view: &SessionView) -> Option<Look> {
        self.change(|seen| seen.view = Look::of(view))
    }

    /// The new look when locking or unlocking changes what the tray shows: attention is not shown while locked.
    fn locked(&self, locked: bool) -> Option<Look> {
        self.change(|seen| seen.locked = locked)
    }

    /// The new look when whether certificates need attention changes what the tray shows.
    fn attention(&self, attention: bool) -> Option<Look> {
        self.change(|seen| seen.attention = attention)
    }

    /// The new look when the version of the update that can be installed changes what the tray shows.
    fn update_offered(&self, update: Option<String>) -> Option<Look> {
        self.change(|seen| seen.update = update)
    }
}

pub fn tooltip(state: State) -> &'static str {
    match state {
        State::Fine => "Identity Manager \u{2014} Signed in",
        State::Attention => "Identity Manager \u{2014} Needs attention",
        State::SignedOut => "Identity Manager \u{2014} Signed out",
        State::Unreachable => "Identity Manager \u{2014} Cannot reach ILM",
    }
}

/// The icon of a state: a template image on macOS, so that the state is in the shape, colour elsewhere.
fn icon_bytes(state: State, template: bool) -> &'static [u8] {
    match (state, template) {
        (State::Fine, true) => include_bytes!("../icons/tray-template.png"),
        (State::Fine, false) => include_bytes!("../icons/tray-color.png"),
        (State::Attention, true) => include_bytes!("../icons/tray-attention-template.png"),
        (State::Attention, false) => include_bytes!("../icons/tray-attention-color.png"),
        (State::SignedOut, true) => include_bytes!("../icons/tray-signed-out-template.png"),
        (State::SignedOut, false) => include_bytes!("../icons/tray-signed-out-color.png"),
        (State::Unreachable, true) => include_bytes!("../icons/tray-unreachable-template.png"),
        (State::Unreachable, false) => include_bytes!("../icons/tray-unreachable-color.png"),
    }
}

/// The tray menu entries (id, label) of a system, with the way to sign in first while signed out.
fn menu_for(platform: Platform, look: &Look) -> Vec<(&'static str, Cow<'static, str>)> {
    let open = ("open", "Open Identity Manager");
    let sign_in = match (look.state, look.again) {
        (State::SignedOut, true) => Some(("sign-in-again", "Sign in again")),
        (State::SignedOut, false) => Some(("sign-in", "Sign in\u{2026}")),
        _ => None,
    };
    // Linux's tray reports no clicks, so the menu is the only way to the summary.
    let summary = (platform == Platform::Linux).then_some(("summary", "Show summary"));
    let install = look.update.as_ref().map(|version| {
        (
            "install-update",
            format!("Install update {version}\u{2026}"),
        )
    });
    let (settings, quit) = match platform {
        Platform::Linux => (("settings", "Preferences"), ("quit", "Quit")),
        Platform::Macos => (
            ("settings", "Settings\u{2026}"),
            ("quit", "Quit Identity Manager"),
        ),
        Platform::Windows => (("settings", "Settings"), ("quit", "Exit")),
    };
    summary
        .into_iter()
        .chain(sign_in)
        .chain([open])
        .map(|(id, label)| (id, Cow::Borrowed(label)))
        .chain(install.map(|(id, label)| (id, Cow::Owned(label))))
        .chain([settings, quit].map(|(id, label)| (id, Cow::Borrowed(label))))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Summary,
    SignIn,
    SignInAgain,
    InstallUpdate,
    Open,
    Settings,
    Quit,
}

pub fn action_for(id: &str) -> Option<Action> {
    match id {
        "summary" => Some(Action::Summary),
        "sign-in" => Some(Action::SignIn),
        "sign-in-again" => Some(Action::SignInAgain),
        "install-update" => Some(Action::InstallUpdate),
        "open" => Some(Action::Open),
        "settings" => Some(Action::Settings),
        "quit" => Some(Action::Quit),
        _ => None,
    }
}

fn run_action<R: Runtime>(app: &AppHandle<R>, action: Action) {
    match action {
        Action::Summary => summary::show_in_corner(app),
        Action::Open | Action::SignIn => show_main_window(app),
        Action::SignInAgain => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = session::begin_sign_in_again(&app).await {
                    log::warn!("signing in again from the tray failed: {error}");
                }
            });
        }
        Action::InstallUpdate => update::install(app),
        Action::Settings => settings_window::open(app),
        Action::Quit => app.exit(0),
    }
}

fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: Platform,
    look: &Look,
) -> tauri::Result<Menu<R>> {
    let items = menu_for(platform, look)
        .into_iter()
        .map(|(id, label)| MenuItem::with_id(app, id, label, true, None::<&str>))
        .collect::<tauri::Result<Vec<_>>>()?;
    let entries: Vec<&dyn tauri::menu::IsMenuItem<R>> = items
        .iter()
        .map(|item| item as &dyn tauri::menu::IsMenuItem<R>)
        .collect();
    Menu::with_items(app, &entries)
}

fn apply<R: Runtime>(app: &AppHandle<R>, look: &Look) -> tauri::Result<()> {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return Ok(());
    };
    let platform = AppInfo::current().platform;
    let macos = platform == Platform::Macos;
    tray.set_icon(Some(Image::from_bytes(icon_bytes(look.state, macos))?))?;
    tray.set_icon_as_template(macos)?;
    tray.set_tooltip(Some(tooltip(look.state)))?;
    tray.set_menu(Some(build_menu(app, platform, look)?))
}

fn show<R: Runtime>(app: &AppHandle<R>, look: Look) {
    let handle = app.clone();
    // Menus are built on the main thread only.
    // Updates may run in another order than they were made, so each applies the latest look.
    let scheduled = app.run_on_main_thread(move || {
        let look = handle
            .try_state::<Arc<Shown>>()
            .map_or(look, |shown| shown.latest());
        if let Err(error) = apply(&handle, &look) {
            log::warn!("updating the tray failed: {error}");
        }
    });
    if let Err(error) = scheduled {
        log::warn!("scheduling the tray update failed: {error}");
    }
}

/// Tells the tray whether certificates need attention. It shows that only while the sign-in is fine and the
/// application is not locked.
pub fn set_attention<R: Runtime>(app: &AppHandle<R>, attention: bool) {
    let Some(shown) = app.try_state::<Arc<Shown>>() else {
        return;
    };
    if let Some(look) = shown.attention(attention) {
        show(app, look);
    }
}

/// Tells the tray which version of the application can be installed, or none, which adds or removes the entry.
pub fn set_update<R: Runtime>(app: &AppHandle<R>, version: Option<String>) {
    let Some(shown) = app.try_state::<Arc<Shown>>() else {
        return;
    };
    if let Some(look) = shown.update_offered(version) {
        show(app, look);
    }
}

/// Tells the tray whether the application is locked, which hides the attention until the unlock.
pub fn set_locked<R: Runtime>(app: &AppHandle<R>, locked: bool) {
    let Some(shown) = app.try_state::<Arc<Shown>>() else {
        return;
    };
    if let Some(look) = shown.locked(locked) {
        show(app, look);
    }
}

/// Shows the sign-in the person has now and follows it, whichever thread reports it.
fn follow<R: Runtime>(app: &AppHandle<R>) {
    let shown = Arc::new(Shown::new());
    app.manage(shown.clone());
    let guard = app.state::<Arc<Guard>>();
    let handle = app.clone();
    let refresh = move |view: &SessionView| {
        if let Some(look) = shown.update(view) {
            show(&handle, look);
        }
    };
    guard.listen(refresh.clone());
    // A view published before the listener existed is not lost, and neither is a summary built before the tray.
    refresh(&guard.real());
    set_locked(app, guard.is_locked());
    if let Some(ilm) = app.try_state::<Arc<Ilm<R>>>() {
        set_attention(app, ilm.needs_attention());
    }
}

pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let platform = AppInfo::current().platform;
    let macos = platform == Platform::Macos;
    let look = Look::START;
    let menu = build_menu(app, platform, &look)?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(Image::from_bytes(icon_bytes(look.state, macos))?)
        .icon_as_template(macos)
        .tooltip(tooltip(look.state))
        .menu(&menu)
        // A left click opens the summary where the system reports clicks; Linux has no click, only the menu.
        .show_menu_on_left_click(platform == Platform::Linux)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state,
                rect,
                ..
            } = event
            {
                match button_state {
                    MouseButtonState::Down => summary::press(tray.app_handle()),
                    MouseButtonState::Up => {
                        summary::release(tray.app_handle(), Some(summary::physical(rect)));
                    }
                }
            }
        })
        .on_menu_event(|app, event| {
            if let Some(action) = action_for(event.id().as_ref()) {
                run_action(app, action);
            }
        })
        .build(app)?;
    follow(app);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use im_core::session::PersonView;

    const SIGNED_OUT: Look = Look::START;
    const SIGNED_OUT_AGAIN: Look = Look {
        state: State::SignedOut,
        again: true,
        update: None,
    };
    const FINE: Look = Look {
        state: State::Fine,
        again: false,
        update: None,
    };
    const UNREACHABLE: Look = Look {
        state: State::Unreachable,
        again: false,
        update: None,
    };
    const ATTENTION: Look = Look {
        state: State::Attention,
        again: false,
        update: None,
    };
    const PLATFORMS: [Platform; 3] = [Platform::Linux, Platform::Macos, Platform::Windows];

    fn ids(platform: Platform, look: &Look) -> Vec<&'static str> {
        menu_for(platform, look)
            .into_iter()
            .map(|(id, _)| id)
            .collect()
    }

    fn pairs<'a>(menu: &'a [(&'static str, Cow<'static, str>)]) -> Vec<(&'a str, &'a str)> {
        menu.iter()
            .map(|(id, label)| (*id, label.as_ref()))
            .collect()
    }

    fn with_update(look: Look, version: &str) -> Look {
        look.with_update(Some(version.to_owned()))
    }

    fn signed_in(unreachable: bool) -> SessionView {
        SessionView::SignedIn {
            address: "https://ilm.example".into(),
            person: PersonView {
                name: "Ada".into(),
                username: "ada".into(),
            },
            allowed_listings: Vec::new(),
            certificate: None,
            unreachable,
        }
    }

    fn signed_out(again: bool) -> SessionView {
        SessionView::SignedOut {
            address: None,
            locked: false,
            problem: None,
            again,
        }
    }

    #[test]
    fn the_state_follows_the_real_view() {
        let unreachable = SessionView::Unreachable {
            address: "https://ilm.example".into(),
            problem: "offline".into(),
        };
        let signing_in = SessionView::SigningIn {
            provider: "idp".into(),
            method: im_core::session::SignInKind::Browser,
        };
        let state = |view: &SessionView| Look::of(view).state;
        assert_eq!(state(&signed_in(false)), State::Fine);
        assert_eq!(state(&signed_in(true)), State::Unreachable);
        assert_eq!(state(&unreachable), State::Unreachable);
        assert_eq!(state(&SessionView::Starting), State::SignedOut);
        assert_eq!(state(&signing_in), State::SignedOut);
        assert_eq!(state(&signed_out(false)), State::SignedOut);
        assert_eq!(state(&SessionView::Locked {}), State::SignedOut);
    }

    #[test]
    fn attention_is_shown_only_over_a_fine_sign_in() {
        let unreachable = SessionView::Unreachable {
            address: "https://ilm.example".into(),
            problem: "offline".into(),
        };
        let signing_in = SessionView::SigningIn {
            provider: "idp".into(),
            method: im_core::session::SignInKind::Browser,
        };
        let state = |view: &SessionView| Look::of(view).with_attention(true).state;
        assert_eq!(state(&signed_in(false)), State::Attention);
        assert_eq!(state(&signed_in(true)), State::Unreachable);
        assert_eq!(state(&unreachable), State::Unreachable);
        assert_eq!(state(&signed_out(false)), State::SignedOut);
        assert_eq!(state(&signed_out(true)), State::SignedOut);
        assert_eq!(state(&signing_in), State::SignedOut);
        assert_eq!(state(&SessionView::Starting), State::SignedOut);
        assert_eq!(state(&SessionView::Locked {}), State::SignedOut);
        assert_eq!(
            Look::of(&signed_in(false)).with_attention(false).state,
            State::Fine
        );
    }

    #[test]
    fn the_look_follows_the_view_and_the_attention_together() {
        let shown = Shown::new();
        assert_eq!(shown.attention(true), None);
        assert_eq!(shown.update(&signed_in(false)), Some(ATTENTION));
        assert_eq!(shown.attention(true), None);
        assert_eq!(shown.update(&signed_in(true)), Some(UNREACHABLE));
        assert_eq!(shown.attention(false), None);
        assert_eq!(shown.attention(true), None);
        assert_eq!(shown.update(&signed_in(false)), Some(ATTENTION));
        assert_eq!(shown.update(&SessionView::Locked {}), Some(SIGNED_OUT));
        assert_eq!(shown.attention(false), None);
        assert_eq!(shown.update(&signed_in(false)), Some(FINE));
        assert_eq!(shown.attention(true), Some(ATTENTION));
        assert_eq!(shown.attention(false), Some(FINE));
    }

    #[test]
    fn attention_is_hidden_while_locked_and_returns_with_the_unlock() {
        let shown = Shown::new();
        shown.update(&signed_in(false));
        assert_eq!(shown.attention(true), Some(ATTENTION));

        assert_eq!(shown.locked(true), Some(FINE));
        assert_eq!(shown.attention(true), None);
        assert_eq!(shown.attention(false), None);
        assert_eq!(shown.attention(true), None);
        assert_eq!(shown.locked(true), None);
        assert_eq!(shown.locked(false), Some(ATTENTION));
    }

    #[test]
    fn the_latest_look_is_the_last_one_told_whatever_order_updates_run_in() {
        let shown = Shown::new();
        shown.update(&signed_in(false));
        let attention = shown.attention(true);
        let locked = shown.locked(true);

        assert_eq!((attention, locked), (Some(ATTENTION), Some(FINE)));
        assert_eq!(shown.latest(), FINE);
    }

    #[test]
    fn locking_changes_nothing_else_the_tray_shows() {
        let shown = Shown::new();
        shown.update(&signed_in(true));

        assert_eq!(shown.locked(true), None);
        assert_eq!(shown.update(&signed_in(false)), Some(FINE));
        assert_eq!(shown.locked(false), None);
    }

    #[test]
    fn a_view_seen_before_the_tray_existed_changes_the_first_look() {
        let shown = Shown::new();
        assert_eq!(shown.update(&signed_in(false)), Some(FINE));
    }

    #[test]
    fn again_is_kept_only_while_signed_out() {
        assert!(Look::of(&signed_out(true)).again);
        assert!(!Look::of(&signed_out(false)).again);
        assert!(!Look::of(&signed_in(false)).again);
    }

    #[test]
    fn the_tooltip_says_the_state_and_nothing_else() {
        assert_eq!(
            tooltip(State::Attention),
            "Identity Manager \u{2014} Needs attention"
        );
        assert_eq!(tooltip(State::Fine), "Identity Manager \u{2014} Signed in");
        assert_eq!(
            tooltip(State::SignedOut),
            "Identity Manager \u{2014} Signed out"
        );
        assert_eq!(
            tooltip(State::Unreachable),
            "Identity Manager \u{2014} Cannot reach ILM"
        );
    }

    #[test]
    fn every_state_has_an_icon_for_both_kinds() {
        for state in [
            State::Fine,
            State::Attention,
            State::SignedOut,
            State::Unreachable,
        ] {
            for template in [true, false] {
                assert!(Image::from_bytes(icon_bytes(state, template)).is_ok());
            }
        }
    }

    #[test]
    fn the_icon_changes_only_when_the_look_does() {
        let shown = Shown::new();
        assert_eq!(shown.update(&SessionView::Starting), None);
        assert_eq!(shown.update(&signed_in(false)), Some(FINE));
        assert_eq!(shown.update(&signed_in(false)), None);
        assert_eq!(shown.update(&signed_in(true)), Some(UNREACHABLE));
        assert_eq!(shown.update(&signed_out(false)), Some(SIGNED_OUT));
        assert_eq!(shown.update(&signed_out(true)), Some(SIGNED_OUT_AGAIN));
        assert_eq!(shown.update(&signed_out(true)), None);
    }

    #[test]
    fn linux_lists_show_summary_open_preferences_then_quit() {
        assert_eq!(
            pairs(&menu_for(Platform::Linux, &FINE)),
            [
                ("summary", "Show summary"),
                ("open", "Open Identity Manager"),
                ("settings", "Preferences"),
                ("quit", "Quit")
            ]
        );
    }

    #[test]
    fn macos_lists_open_settings_then_quit_identity_manager() {
        assert_eq!(
            pairs(&menu_for(Platform::Macos, &FINE)),
            [
                ("open", "Open Identity Manager"),
                ("settings", "Settings\u{2026}"),
                ("quit", "Quit Identity Manager")
            ]
        );
    }

    #[test]
    fn windows_lists_open_settings_then_exit() {
        assert_eq!(
            pairs(&menu_for(Platform::Windows, &UNREACHABLE)),
            [
                ("open", "Open Identity Manager"),
                ("settings", "Settings"),
                ("quit", "Exit")
            ]
        );
    }

    #[test]
    fn signed_out_adds_a_sign_in_entry_before_open_on_every_system() {
        for platform in PLATFORMS {
            let plain = menu_for(platform, &SIGNED_OUT);
            let again = menu_for(platform, &SIGNED_OUT_AGAIN);
            let position = |menu: &[(&str, Cow<str>)], id| menu.iter().position(|e| e.0 == id);
            assert_eq!(
                plain[position(&plain, "sign-in").unwrap()].1,
                "Sign in\u{2026}"
            );
            assert_eq!(
                again[position(&again, "sign-in-again").unwrap()].1,
                "Sign in again"
            );
            assert!(position(&plain, "sign-in") < position(&plain, "open"));
            assert!(position(&again, "sign-in-again") < position(&again, "open"));
            assert_eq!(position(&plain, "sign-in-again"), None);
            assert_eq!(position(&again, "sign-in"), None);
        }
    }

    #[test]
    fn signed_in_and_unreachable_have_no_sign_in_entry() {
        for platform in PLATFORMS {
            for look in [FINE, ATTENTION, UNREACHABLE] {
                let ids = ids(platform, &look);
                assert!(!ids.contains(&"sign-in") && !ids.contains(&"sign-in-again"));
            }
        }
    }

    #[test]
    fn show_summary_is_on_linux_only() {
        assert!(ids(Platform::Linux, &FINE).contains(&"summary"));
        assert!(!ids(Platform::Macos, &FINE).contains(&"summary"));
        assert!(!ids(Platform::Windows, &FINE).contains(&"summary"));
    }

    #[test]
    fn every_menu_id_has_an_action() {
        for platform in PLATFORMS {
            for look in [FINE, UNREACHABLE, SIGNED_OUT, SIGNED_OUT_AGAIN] {
                for id in ids(platform, &look) {
                    assert!(action_for(id).is_some(), "{id} on {platform:?}");
                }
            }
        }
        assert_eq!(action_for("sign-in"), Some(Action::SignIn));
        assert_eq!(action_for("sign-in-again"), Some(Action::SignInAgain));
        assert_eq!(action_for("summary"), Some(Action::Summary));
        assert_eq!(action_for("install-update"), Some(Action::InstallUpdate));
        assert_eq!(action_for("open"), Some(Action::Open));
        assert_eq!(action_for("settings"), Some(Action::Settings));
        assert_eq!(action_for("quit"), Some(Action::Quit));
    }

    #[test]
    fn an_offered_update_adds_an_entry_with_its_version_just_above_settings() {
        for platform in PLATFORMS {
            let menu = menu_for(platform, &with_update(FINE, "0.2.0"));
            let entries = pairs(&menu);
            let install = entries.iter().position(|e| e.0 == "install-update");
            let settings = entries.iter().position(|e| e.0 == "settings");
            assert_eq!(entries[install.unwrap()].1, "Install update 0.2.0\u{2026}");
            assert_eq!(install.unwrap() + 1, settings.unwrap());
            assert!(!ids(platform, &FINE).contains(&"install-update"));
        }
    }

    #[test]
    fn the_update_entry_comes_and_goes_with_the_offer() {
        let shown = Shown::new();
        assert_eq!(shown.update(&signed_in(false)), Some(FINE));
        let offered = shown.update_offered(Some("0.2.0".to_owned())).unwrap();
        assert_eq!(offered.update.as_deref(), Some("0.2.0"));
        assert_eq!(shown.update_offered(Some("0.2.0".to_owned())), None);
        assert_eq!(
            shown.update(&signed_in(true)).unwrap().update,
            offered.update
        );
        assert_eq!(shown.update_offered(None).unwrap().update, None);
        assert_eq!(shown.latest().update, None);
    }

    #[test]
    fn unknown_id_has_no_action() {
        assert_eq!(action_for("other"), None);
    }
}
