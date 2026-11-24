mod attributes;
mod bridge;
mod certificates;
mod color_scheme;
mod dock;
mod install;
mod keep_alive;
#[cfg(target_os = "macos")]
mod key_origin_macos;
#[cfg(windows)]
mod key_provider;
mod key_storage;
mod local_time;
mod lock;
#[cfg(any(windows, test))]
mod main_window;
mod mode;
mod notice;
mod request;
mod self_check;
mod session;
mod settings;
mod settings_window;
mod summary;
mod tray;

use im_core::AppInfo;
use log::LevelFilter;
use std::process::ExitCode;
use std::sync::Arc;

use tauri::{AppHandle, Manager, Runtime, WindowEvent};
use tauri_plugin_log::{RotationStrategy, Target, TargetKind};

pub use mode::Mode;

fn show_main_window<R: Runtime>(app: &AppHandle<R>) {
    // The Dock icon must exist before the window is shown and focused, or the window cannot take focus.
    #[cfg(target_os = "macos")]
    dock::activate(app);
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
        .level(LevelFilter::Debug)
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
    // Only the Rust side opens the browser; no window is granted the plugin's permissions.
    builder = builder.plugin(tauri_plugin_opener::init());
    // Only the Rust side notifies; no window is granted the plugin's permissions.
    builder = builder.plugin(tauri_plugin_notification::init());
    #[cfg(target_os = "macos")]
    if !cfg!(test) {
        builder = builder
            .menu(settings_window::app_menu)
            .on_menu_event(settings_window::on_menu_event);
    }
    builder
        .manage(mode)
        .manage(color_scheme::Current::default())
        .manage(summary::VisibleAtPress::default())
        .manage(summary::HiddenOnFocusLoss::default())
        .manage(self_check::Reports::default())
        .manage(settings_window::PendingSection::default())
        .manage(bridge::PendingNavigation::default())
        .manage(settings_window::AwaitingHeight::default())
        .invoke_handler(tauri::generate_handler![
            bridge::app_info,
            bridge::report_ready,
            bridge::open_main_window,
            bridge::pending_navigation,
            bridge::hide_summary,
            color_scheme::color_scheme,
            settings::settings,
            settings::set_setting,
            settings_window::pending_section,
            settings_window::open_settings,
            session::session,
            session::connect,
            session::sign_in,
            session::certificates,
            session::sign_in_with_certificate,
            session::reopen_browser,
            session::cancel_sign_in,
            session::sign_out,
            session::unlock,
            session::sign_in_again,
            certificates::local_certificates,
            certificates::ilm_status,
            certificates::ilm_certificates,
            certificates::sync_now,
            certificates::make_sign_in_certificate,
            certificates::overview,
            certificates::add_to_ilm_choices,
            certificates::add_to_ilm,
            attributes::attribute_callback,
            attributes::check_attributes,
            attributes::close_form,
            attributes::open_in_ilm,
            request::request_choices,
            request::open_request_forms,
            request::request_offers,
            request::request_certificate,
            request::follow_request,
            request::stop_following_request
        ])
        // macOS menus can only be built on the main thread, which unit tests do not run on.
        .enable_macos_default_menu(false)
        .on_window_event(|window, event| {
            summary::hide_on_focus_loss(window, event);
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                #[cfg(target_os = "macos")]
                if matches!(window.label(), "main" | "settings") {
                    dock::refresh(window.app_handle());
                }
            }
        })
        .setup(move |app| {
            let info = AppInfo::current();
            let person_file = app.path().app_config_dir()?.join("settings.json");
            let autostart =
                settings::autostart_applies(mode == Mode::SelfCheck, cfg!(debug_assertions));
            let effects = settings::SystemEffects::new(app.handle(), autostart);
            let settings = Arc::new(settings::Settings::new(
                person_file,
                im_core::policy::read,
                effects,
                autostart,
            ));
            settings.start();
            app.manage(settings.clone());
            let notifier: Box<dyn notice::Notifier> = if mode == Mode::SelfCheck {
                Box::new(notice::Silent)
            } else {
                Box::new(notice::SystemNotifier::new(app.handle()))
            };
            session::manage(
                app.handle(),
                mode,
                session::protected_store(),
                Arc::new(session::SystemOpener::new(app.handle())),
                notifier,
                session::system_guard(app.handle(), mode),
                certificates::system_identities(),
            );
            log::info!("starting {} {} in {mode:?} mode", info.name, info.version);
            if mode == Mode::SelfCheck {
                self_check::start_timer(app.handle().clone());
                // A hidden web view may never load its page, so the summary is shown to let it report.
                summary::show_in_corner(app.handle());
            }
            #[cfg(target_os = "linux")]
            if !cfg!(test) {
                color_scheme::watch(app.handle().clone());
            }
            // Same main-thread limit as the default menu above.
            if !cfg!(test) {
                tray::create(app.handle())?;
                log::info!("tray icon created");
                #[cfg(windows)]
                main_window::fit_to_work_area(app.handle());
            }
            Ok(())
        })
}

fn context<R: Runtime>() -> tauri::Context<R> {
    tauri::generate_context!()
}

/// Runs the app and returns its exit code; returning from `main` lets coverage data reach the disk on Windows.
pub fn run() -> ExitCode {
    let mode = Mode::from_args(std::env::args().skip(1));
    let code = builder::<tauri::Wry>(mode)
        .build(context())
        .expect("the application failed to start")
        .run_return(|app, event| {
            // Opening the running app again on macOS, from the Dock or Finder, reopens it instead of starting a copy.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Reopen { .. } = event {
                show_main_window(app);
            }
            #[cfg(not(target_os = "macos"))]
            let _ = (app, event);
        });
    ExitCode::from(u8::try_from(code).unwrap_or(1))
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
