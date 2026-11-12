//! Opening Settings: a window of its own on macOS, a page of the main window elsewhere.

use std::sync::{Mutex, PoisonError};

use tauri::{AppHandle, Runtime, State};

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

/// Hands the main window the section it was asked to open, once. The event alone can be lost while its
/// interface is still starting.
#[tauri::command]
pub fn pending_section(pending: State<'_, PendingSection>) -> Option<String> {
    pending.take()
}

/// Shows the main window and asks its interface to open the Settings page.
#[cfg(any(not(target_os = "macos"), test))]
fn open_in_main<R: Runtime>(app: &AppHandle<R>) {
    use tauri::{Emitter, Manager};

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
    use tauri::{AppHandle, Manager, Runtime, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    use crate::dock;

    const WIDTH: f64 = 520.0;
    const HEIGHT: f64 = 300.0;

    fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<WebviewWindow<R>> {
        WebviewWindowBuilder::new(app, "settings", WebviewUrl::default())
            .title("Settings")
            .inner_size(WIDTH, HEIGHT)
            .resizable(false)
            .maximizable(false)
            .visible(false)
            .build()
    }

    /// Shows the Settings window, creating it on first use. Closing it only hides it.
    pub fn show<R: Runtime>(app: &AppHandle<R>) {
        // The Dock icon must exist before the window is shown and focused, or the window cannot take focus.
        dock::activate(app);
        let window = match app.get_webview_window("settings") {
            Some(window) => window,
            None => match create(app) {
                Ok(window) => window,
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

        #[test]
        fn the_window_is_created_once_and_kept_across_opens() {
            let app = mock_builder()
                .build(mock_context(noop_assets()))
                .expect("the mock app builds");
            assert!(app.get_webview_window("settings").is_none());
            show(app.handle());
            show(app.handle());
            let window = app.get_webview_window("settings").expect("created");
            assert!(!window.is_resizable().unwrap());
            assert!(window.is_visible().unwrap());
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
