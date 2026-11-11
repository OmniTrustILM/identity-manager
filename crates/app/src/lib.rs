mod bridge;
mod mode;
mod self_check;
mod tray;

use im_core::AppInfo;
use log::LevelFilter;
use tauri::{AppHandle, Manager, Runtime, WindowEvent};
use tauri_plugin_log::{RotationStrategy, Target, TargetKind};

pub use mode::Mode;

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

const LOG_FILE_SIZE: u128 = 1_000_000;
const LOG_FILES_KEPT: usize = 3;

fn logging<R: Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri_plugin_log::Builder::new()
        .level(LevelFilter::Info)
        .targets([
            Target::new(TargetKind::Stdout),
            Target::new(TargetKind::LogDir { file_name: None }),
        ])
        .max_file_size(LOG_FILE_SIZE)
        .rotation_strategy(RotationStrategy::KeepSome(LOG_FILES_KEPT))
        .build()
}

fn builder<R: Runtime>(mode: Mode) -> tauri::Builder<R> {
    let mut builder = tauri::Builder::<R>::new();
    // The single-instance lock is system-wide, so unit tests would hand over to a running copy and exit.
    if mode == Mode::Normal && !cfg!(test) {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            log::info!("second start handed over to the running instance");
            show_main_window(app);
        }));
    }
    // The logger is process-wide, so it can be installed only once; unit tests build many apps.
    if !cfg!(test) {
        builder = builder.plugin(logging());
    }
    builder
        .manage(mode)
        .invoke_handler(tauri::generate_handler![
            bridge::app_info,
            bridge::report_ready
        ])
        // macOS menus can only be built on the main thread, which unit tests do not run on.
        .enable_macos_default_menu(!cfg!(test))
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(move |app| {
            let info = AppInfo::current();
            log::info!("starting {} {} in {mode:?} mode", info.name, info.version);
            if mode == Mode::SelfCheck {
                self_check::start_timer(app.handle().clone());
            }
            // Same main-thread limit as the default menu above.
            if !cfg!(test) {
                tray::create(app.handle())?;
                log::info!("tray icon created");
            }
            Ok(())
        })
}

fn context<R: Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

pub fn run() {
    let mode = Mode::from_args(std::env::args().skip(1));
    builder::<tauri::Wry>(mode)
        .run(context())
        .expect("the application failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tauri::test::{MockRuntime, mock_context, noop_assets};
    use tauri::{WebviewUrl, WebviewWindowBuilder};

    fn build(mode: Mode) -> tauri::App<MockRuntime> {
        builder::<MockRuntime>(mode)
            .build(mock_context(noop_assets()))
            .expect("the mock app builds")
    }

    fn add_main_window(app: &tauri::App<MockRuntime>) {
        WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
            .build()
            .expect("the main window is created");
    }

    #[test]
    fn builds_with_a_main_window_in_both_modes() {
        for mode in [Mode::Normal, Mode::SelfCheck] {
            let app = build(mode);
            add_main_window(&app);
            assert!(app.get_webview_window("main").is_some());
        }
    }

    #[test]
    fn show_main_window_keeps_an_existing_window() {
        let app = build(Mode::SelfCheck);
        add_main_window(&app);
        show_main_window(app.handle());
        assert!(app.get_webview_window("main").is_some());
    }

    #[test]
    fn show_main_window_without_a_window_does_nothing() {
        let app = build(Mode::SelfCheck);
        show_main_window(app.handle());
    }
}
