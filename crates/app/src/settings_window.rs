//! Opening Settings: a window of its own on macOS, a page of the main window elsewhere.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};

use tauri::{AppHandle, Manager, Runtime, State};

/// The section the main window was asked to open and has not taken yet.
#[derive(Default)]
pub struct PendingSection(Mutex<Option<String>>);

impl PendingSection {
    #[cfg(any(not(target_os = "macos"), test))]
    fn set(&self, section: &str) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(section.to_owned());
    }

    fn take(&self) -> Option<String> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

/// Set while a new Settings window waits for the height of its content, so it does not show at the wrong size.
#[derive(Default)]
pub struct AwaitingHeight(AtomicBool);

/// Shows the Settings window once its content has its height, if it is waiting for it.
pub fn reveal<R: Runtime>(app: &AppHandle<R>) {
    if !app
        .state::<AwaitingHeight>()
        .0
        .swap(false, Ordering::SeqCst)
    {
        return;
    }
    if let Some(window) = app.get_webview_window("settings") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Hands the main window the section it was asked to open, once. The event alone can be lost while its
/// interface is still starting.
#[tauri::command]
pub fn pending_section(pending: State<'_, PendingSection>) -> Option<String> {
    pending.take()
}

/// Shows the main window and asks its interface to open the Settings page.
#[cfg(any(not(target_os = "macos"), test))]
fn open_in_main<R: Runtime>(app: &AppHandle<R>) {
    use tauri::Emitter;

    app.state::<PendingSection>().set("settings");
    crate::show_main_window(app);
    if let Err(error) = app.emit_to("main", "open-section", "settings") {
        log::warn!("asking the main window to open Settings failed: {error}");
    }
}

/// Opens Settings the way the system does it.
pub fn open<R: Runtime>(app: &AppHandle<R>) {
    #[cfg(target_os = "macos")]
    window::show(app);
    #[cfg(not(target_os = "macos"))]
    open_in_main(app);
}

/// Opens Settings from the sidebar of the main window, which on macOS is a window of its own.
#[tauri::command]
pub fn open_settings<R: Runtime>(app: AppHandle<R>) {
    open(&app);
}

#[cfg(target_os = "macos")]
const SETTINGS_ITEM: &str = "settings";

/// Tauri's default application menu with "Settings…" (Cmd-,) after "About".
#[cfg(target_os = "macos")]
pub fn app_menu<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<tauri::menu::Menu<R>> {
    use tauri::menu::{Menu, MenuItem, MenuItemKind, PredefinedMenuItem};

    let menu = Menu::default(app)?;
    if let Some(MenuItemKind::Submenu(application)) = menu.items()?.into_iter().next() {
        let settings =
            MenuItem::with_id(app, SETTINGS_ITEM, "Settings\u{2026}", true, Some("Cmd+,"))?;
        application.insert(&PredefinedMenuItem::separator(app)?, 1)?;
        application.insert(&settings, 2)?;
    }
    Ok(menu)
}

#[cfg(target_os = "macos")]
pub fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: tauri::menu::MenuEvent) {
    if event.id().as_ref() == SETTINGS_ITEM {
        open(app);
    }
}

#[cfg(target_os = "macos")]
mod window {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use tauri::{
        AppHandle, Manager, Runtime, TitleBarStyle, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    };

    use super::AwaitingHeight;
    use crate::dock;

    const WIDTH: f64 = 520.0;
    const HEIGHT: f64 = 300.0;
    /// How long a new window waits for the height of its content before it shows anyway.
    const HEIGHT_TIMEOUT: Duration = Duration::from_secs(1);

    fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<WebviewWindow<R>> {
        WebviewWindowBuilder::new(app, "settings", WebviewUrl::default())
            .title("Settings")
            .inner_size(WIDTH, HEIGHT)
            .resizable(false)
            .maximizable(false)
            .title_bar_style(TitleBarStyle::Overlay)
            .visible(false)
            .build()
    }

    /// Leaves a new window hidden until its content reports its height, or until the timeout.
    fn show_when_fitted<R: Runtime>(app: &AppHandle<R>) {
        app.state::<AwaitingHeight>()
            .0
            .store(true, Ordering::SeqCst);
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(HEIGHT_TIMEOUT);
            super::reveal(&app);
        });
    }

    /// Shows the Settings window, creating it on first use. Closing it only hides it.
    pub fn show<R: Runtime>(app: &AppHandle<R>) {
        // The Dock icon must exist before the window is shown and focused, or the window cannot take focus.
        dock::activate(app);
        let window = match app.get_webview_window("settings") {
            Some(window) => {
                // Shown now, so a height that comes later must not show it again once it is closed.
                app.state::<AwaitingHeight>()
                    .0
                    .store(false, Ordering::SeqCst);
                window
            }
            None => match create(app) {
                Ok(_) => {
                    show_when_fitted(app);
                    return;
                }
                Err(error) => {
                    log::warn!("creating the Settings window failed: {error}");
                    dock::refresh(app);
                    return;
                }
            },
        };
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tauri::test::{mock_builder, mock_context, noop_assets};

        fn mock_app() -> tauri::App<tauri::test::MockRuntime> {
            mock_builder()
                .manage(AwaitingHeight::default())
                .build(mock_context(noop_assets()))
                .expect("the mock app builds")
        }

        #[test]
        fn the_window_is_created_once_and_kept_across_opens() {
            let app = mock_app();
            assert!(app.get_webview_window("settings").is_none());
            show(app.handle());
            show(app.handle());
            let window = app.get_webview_window("settings").expect("created");
            assert!(!window.is_resizable().unwrap());
            assert!(window.is_visible().unwrap());
        }

        fn waiting(app: &tauri::App<tauri::test::MockRuntime>) -> bool {
            app.state::<AwaitingHeight>().0.load(Ordering::SeqCst)
        }

        #[test]
        fn a_new_window_waits_for_the_height_of_its_content_once() {
            let app = mock_app();
            super::super::open_settings(app.handle().clone());
            assert!(app.get_webview_window("settings").is_some());
            assert!(waiting(&app));

            super::super::reveal(app.handle());
            assert!(!waiting(&app));
            super::super::reveal(app.handle());
            assert!(!waiting(&app));
        }

        #[test]
        fn a_new_window_stops_waiting_after_the_timeout() {
            let app = mock_app();
            show(app.handle());
            std::thread::sleep(HEIGHT_TIMEOUT * 2);
            assert!(!waiting(&app));
        }

        #[test]
        fn opening_a_waiting_window_again_shows_it_and_stops_the_wait() {
            let app = mock_app();
            show(app.handle());
            assert!(waiting(&app));

            show(app.handle());
            assert!(!waiting(&app));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tauri::test::{MockRuntime, mock_builder, mock_context, noop_assets};
    use tauri::{Listener, Manager, WebviewUrl, WebviewWindowBuilder};

    #[test]
    fn opening_in_the_main_window_shows_it_and_asks_for_the_settings_page() {
        let app = mock_builder()
            .manage(PendingSection::default())
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        let window =
            WebviewWindowBuilder::<MockRuntime, _>::new(&app, "main", WebviewUrl::default())
                .visible(false)
                .build()
                .expect("the main window is created");
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        window.listen("open-section", move |event| {
            sink.lock().unwrap().push(event.payload().to_string());
        });
        open_in_main(app.handle());
        assert!(
            app.get_webview_window("main")
                .unwrap()
                .is_visible()
                .unwrap()
        );
        assert_eq!(*received.lock().unwrap(), ["\"settings\""]);
    }

    #[test]
    fn the_requested_section_is_stored_and_taken_once() {
        let app = mock_builder()
            .manage(PendingSection::default())
            .build(mock_context(noop_assets()))
            .expect("the mock app builds");
        assert_eq!(pending_section(app.state()), None);

        open_in_main(app.handle());

        assert_eq!(pending_section(app.state()), Some("settings".to_owned()));
        assert_eq!(pending_section(app.state()), None);
    }
}
