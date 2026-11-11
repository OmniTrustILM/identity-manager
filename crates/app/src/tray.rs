use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Runtime};

use crate::show_main_window;

pub const MENU: [(&str, &str); 2] = [("open", "Open Identity Manager"), ("quit", "Quit")];

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    Quit,
}

pub fn action_for(id: &str) -> Option<Action> {
    match id {
        "open" => Some(Action::Open),
        "quit" => Some(Action::Quit),
        _ => None,
    }
}

fn run_action<R: Runtime>(app: &AppHandle<R>, action: Action) {
    match action {
        Action::Open => show_main_window(app),
        Action::Quit => app.exit(0),
    }
}

pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let items = MENU
        .iter()
        .map(|(id, label)| MenuItem::with_id(app, *id, *label, true, None::<&str>))
        .collect::<tauri::Result<Vec<_>>>()?;
    let entries: Vec<&dyn tauri::menu::IsMenuItem<R>> = items
        .iter()
        .map(|item| item as &dyn tauri::menu::IsMenuItem<R>)
        .collect();
    let menu = Menu::with_items(app, &entries)?;

    let macos = cfg!(target_os = "macos");
    let icon = if macos {
        include_bytes!("../icons/tray-template.png").as_slice()
    } else {
        include_bytes!("../icons/tray-color.png").as_slice()
    };

    TrayIconBuilder::new()
        .icon(Image::from_bytes(icon)?)
        .icon_as_template(macos)
        .menu(&menu)
        .show_menu_on_left_click(true)
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

    #[test]
    fn menu_lists_open_then_quit() {
        assert_eq!(MENU, [("open", "Open Identity Manager"), ("quit", "Quit")]);
    }

    #[test]
    fn every_menu_id_has_an_action() {
        assert_eq!(action_for("open"), Some(Action::Open));
        assert_eq!(action_for("quit"), Some(Action::Quit));
    }

    #[test]
    fn unknown_id_has_no_action() {
        assert_eq!(action_for("other"), None);
    }
}
