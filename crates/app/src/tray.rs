use std::sync::{Arc, Mutex};

use im_core::session::SessionView;
use im_core::{AppInfo, Platform};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Runtime};

use crate::lock::Guard;
use crate::{session, settings_window, show_main_window, summary};

const TRAY_ID: &str = "main";

/// What the tray icon says about the sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Fine,
    SignedOut,
    Unreachable,
}

/// Everything the tray shows: the state, and whether a signed-out person can repeat the sign-in that ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Look {
    state: State,
    again: bool,
}

impl Look {
    const START: Look = Look {
        state: State::SignedOut,
        again: false,
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
        Look { state, again }
    }
}

/// Remembers what the tray shows, so that it is touched only when that changes.
struct Shown(Mutex<Look>);

impl Shown {
    /// The new look when the view changes what the tray shows.
    fn update(&self, view: &SessionView) -> Option<Look> {
        let next = Look::of(view);
        let mut shown = self.0.lock().unwrap_or_else(|e| e.into_inner());
        (*shown != next).then(|| {
            *shown = next;
            next
        })
    }
}

pub fn tooltip(state: State) -> &'static str {
    match state {
        State::Fine => "Identity Manager \u{2014} Signed in",
        State::SignedOut => "Identity Manager \u{2014} Signed out",
        State::Unreachable => "Identity Manager \u{2014} Cannot reach ILM",
    }
}

/// The icon of a state: a template image on macOS, so that the state is in the shape, colour elsewhere.
fn icon_bytes(state: State, template: bool) -> &'static [u8] {
    match (state, template) {
        (State::Fine, true) => include_bytes!("../icons/tray-template.png"),
        (State::Fine, false) => include_bytes!("../icons/tray-color.png"),
        (State::SignedOut, true) => include_bytes!("../icons/tray-signed-out-template.png"),
        (State::SignedOut, false) => include_bytes!("../icons/tray-signed-out-color.png"),
        (State::Unreachable, true) => include_bytes!("../icons/tray-unreachable-template.png"),
        (State::Unreachable, false) => include_bytes!("../icons/tray-unreachable-color.png"),
    }
}

/// The tray menu entries (id, label) of a system, with the way to sign in first while signed out.
fn menu_for(platform: Platform, look: Look) -> Vec<(&'static str, &'static str)> {
    let open = ("open", "Open Identity Manager");
    let sign_in = match (look.state, look.again) {
        (State::SignedOut, true) => Some(("sign-in-again", "Sign in again")),
        (State::SignedOut, false) => Some(("sign-in", "Sign in\u{2026}")),
        _ => None,
    };
    // Linux's tray reports no clicks, so the menu is the only way to the summary.
    let summary = (platform == Platform::Linux).then_some(("summary", "Show summary"));
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
        .chain([open, settings, quit])
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Summary,
    SignIn,
    SignInAgain,
    Open,
    Settings,
    Quit,
}

pub fn action_for(id: &str) -> Option<Action> {
    match id {
        "summary" => Some(Action::Summary),
        "sign-in" => Some(Action::SignIn),
        "sign-in-again" => Some(Action::SignInAgain),
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
        Action::Settings => settings_window::open(app),
        Action::Quit => app.exit(0),
    }
}

fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    platform: Platform,
    look: Look,
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

fn apply<R: Runtime>(app: &AppHandle<R>, look: Look) -> tauri::Result<()> {
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

/// Shows the sign-in the person has now and follows it, whichever thread reports it.
fn follow<R: Runtime>(app: &AppHandle<R>) {
    let shown = Arc::new(Shown(Mutex::new(Look::START)));
    let guard = app.state::<Arc<Guard>>();
    let handle = app.clone();
    let refresh = move |view: &SessionView| {
        if let Some(look) = shown.update(view) {
            let app = handle.clone();
            // Menus are built on the main thread only.
            let scheduled = handle.run_on_main_thread(move || {
                if let Err(error) = apply(&app, look) {
                    log::warn!("updating the tray failed: {error}");
                }
            });
            if let Err(error) = scheduled {
                log::warn!("scheduling the tray update failed: {error}");
            }
        }
    };
    guard.listen(refresh.clone());
    // A view published before the listener existed is not lost.
    refresh(&guard.real());
}

pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let platform = AppInfo::current().platform;
    let macos = platform == Platform::Macos;
    let look = Look::START;
    let menu = build_menu(app, platform, look)?;

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
    };
    const FINE: Look = Look {
        state: State::Fine,
        again: false,
    };
    const UNREACHABLE: Look = Look {
        state: State::Unreachable,
        again: false,
    };
    const PLATFORMS: [Platform; 3] = [Platform::Linux, Platform::Macos, Platform::Windows];

    fn ids(platform: Platform, look: Look) -> Vec<&'static str> {
        menu_for(platform, look)
            .into_iter()
            .map(|(id, _)| id)
            .collect()
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
    fn a_view_seen_before_the_tray_existed_changes_the_first_look() {
        let shown = Shown(Mutex::new(Look::START));
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
        for state in [State::Fine, State::SignedOut, State::Unreachable] {
            for template in [true, false] {
                assert!(Image::from_bytes(icon_bytes(state, template)).is_ok());
            }
        }
    }

    #[test]
    fn the_icon_changes_only_when_the_look_does() {
        let shown = Shown(Mutex::new(Look::START));
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
            menu_for(Platform::Linux, FINE),
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
            menu_for(Platform::Macos, FINE),
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
            menu_for(Platform::Windows, UNREACHABLE),
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
            let plain = menu_for(platform, SIGNED_OUT);
            let again = menu_for(platform, SIGNED_OUT_AGAIN);
            let position = |menu: &[(&str, &str)], id| menu.iter().position(|e| e.0 == id);
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
            for look in [FINE, UNREACHABLE] {
                let ids = ids(platform, look);
                assert!(!ids.contains(&"sign-in") && !ids.contains(&"sign-in-again"));
            }
        }
    }

    #[test]
    fn show_summary_is_on_linux_only() {
        assert!(ids(Platform::Linux, FINE).contains(&"summary"));
        assert!(!ids(Platform::Macos, FINE).contains(&"summary"));
        assert!(!ids(Platform::Windows, FINE).contains(&"summary"));
    }

    #[test]
    fn every_menu_id_has_an_action() {
        for platform in PLATFORMS {
            for look in [FINE, UNREACHABLE, SIGNED_OUT, SIGNED_OUT_AGAIN] {
                for id in ids(platform, look) {
                    assert!(action_for(id).is_some(), "{id} on {platform:?}");
                }
            }
        }
        assert_eq!(action_for("sign-in"), Some(Action::SignIn));
        assert_eq!(action_for("sign-in-again"), Some(Action::SignInAgain));
        assert_eq!(action_for("summary"), Some(Action::Summary));
        assert_eq!(action_for("open"), Some(Action::Open));
        assert_eq!(action_for("settings"), Some(Action::Settings));
        assert_eq!(action_for("quit"), Some(Action::Quit));
    }

    #[test]
    fn unknown_id_has_no_action() {
        assert_eq!(action_for("other"), None);
    }
}
