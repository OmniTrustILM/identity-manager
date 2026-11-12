use im_core::{AppInfo, Platform};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Runtime};

use crate::{show_main_window, summary};

/// The tray menu entries (id, label) of a system.
pub fn menu_for(platform: Platform) -> Vec<(&'static str, &'static str)> {
    let open = ("open", "Open Identity Manager");
    match platform {
        // Linux's tray reports no clicks, so the menu is the only way to the summary.
        Platform::Linux => vec![("summary", "Show summary"), open, ("quit", "Quit")],
        Platform::Macos => vec![open, ("quit", "Quit Identity Manager")],
        Platform::Windows => vec![open, ("quit", "Exit")],
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Summary,
    Open,
    Quit,
}

pub fn action_for(id: &str) -> Option<Action> {
    match id {
        "summary" => Some(Action::Summary),
        "open" => Some(Action::Open),
        "quit" => Some(Action::Quit),
        _ => None,
    }
}

fn run_action<R: Runtime>(app: &AppHandle<R>, action: Action) {
    match action {
        Action::Summary => summary::show_in_corner(app),
        Action::Open => show_main_window(app),
        Action::Quit => app.exit(0),
    }
}

pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let platform = AppInfo::current().platform;
    let items = menu_for(platform)
        .into_iter()
        .map(|(id, label)| MenuItem::with_id(app, id, label, true, None::<&str>))
        .collect::<tauri::Result<Vec<_>>>()?;
    let entries: Vec<&dyn tauri::menu::IsMenuItem<R>> = items
        .iter()
        .map(|item| item as &dyn tauri::menu::IsMenuItem<R>)
        .collect();
    let menu = Menu::with_items(app, &entries)?;

    let macos = platform == Platform::Macos;
    let icon = if macos {
        include_bytes!("../icons/tray-template.png").as_slice()
    } else {
        include_bytes!("../icons/tray-color.png").as_slice()
    };

    TrayIconBuilder::new()
        .icon(Image::from_bytes(icon)?)
        .icon_as_template(macos)
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(platform: Platform) -> Vec<&'static str> {
        menu_for(platform).into_iter().map(|(id, _)| id).collect()
    }

    #[test]
    fn linux_lists_show_summary_open_then_quit() {
        assert_eq!(
            menu_for(Platform::Linux),
            [
                ("summary", "Show summary"),
                ("open", "Open Identity Manager"),
                ("quit", "Quit")
            ]
        );
    }

    #[test]
    fn macos_lists_open_then_quit_identity_manager() {
        assert_eq!(
            menu_for(Platform::Macos),
            [
                ("open", "Open Identity Manager"),
                ("quit", "Quit Identity Manager")
            ]
        );
    }

    #[test]
    fn windows_lists_open_then_exit() {
        assert_eq!(
            menu_for(Platform::Windows),
            [("open", "Open Identity Manager"), ("quit", "Exit")]
        );
    }

    #[test]
    fn show_summary_is_on_linux_only() {
        assert!(ids(Platform::Linux).contains(&"summary"));
        assert!(!ids(Platform::Macos).contains(&"summary"));
        assert!(!ids(Platform::Windows).contains(&"summary"));
    }

    #[test]
    fn every_menu_id_has_an_action() {
        for platform in [Platform::Linux, Platform::Macos, Platform::Windows] {
            for id in ids(platform) {
                assert!(action_for(id).is_some(), "{id} on {platform:?}");
            }
        }
        assert_eq!(action_for("summary"), Some(Action::Summary));
        assert_eq!(action_for("open"), Some(Action::Open));
        assert_eq!(action_for("quit"), Some(Action::Quit));
    }

    #[test]
    fn unknown_id_has_no_action() {
        assert_eq!(action_for("other"), None);
    }
}
