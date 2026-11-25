use std::sync::{Arc, Mutex, PoisonError};

use im_core::identity::Fingerprint;
use im_core::{AppInfo, Platform};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, LogicalSize, Manager, Runtime, State, Window};

use crate::lock::Guard;
use crate::{Mode, self_check, summary};

/// Sent to the main window when another window has asked it to show something; the request waits in
/// [`PendingNavigation`].
const NAVIGATE: &str = "navigate";

/// What the main window is asked to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "to", rename_all = "camelCase")]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(export, tag = "to", rename_all = "camelCase")
)]
pub enum Navigation {
    Overview,
    /// The certificate on this computer with this fingerprint.
    Certificate {
        fingerprint: String,
    },
}

/// The place the main window was asked to show and has not taken yet.
#[derive(Default)]
pub struct PendingNavigation(Mutex<Option<Navigation>>);

impl PendingNavigation {
    fn set(&self, place: Navigation) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(place);
    }

    fn take(&self) -> Option<Navigation> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
}

impl Navigation {
    /// The place `target` names: "overview" or the fingerprint of a certificate; none for anything else.
    fn of(target: &str) -> Option<Self> {
        if target == "overview" {
            return Some(Self::Overview);
        }
        let fingerprint = target.parse::<Fingerprint>().ok()?;
        Some(Self::Certificate {
            fingerprint: fingerprint.to_string(),
        })
    }
}

/// What an interface says it has shown.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Shown {
    pub name: String,
    pub version: String,
    pub platform: Platform,
    /// The natural height of the content in CSS pixels, sent by the tray summary and the macOS Settings window so
    /// their windows can fit it.
    #[serde(default)]
    #[cfg_attr(test, ts(optional))]
    pub height: Option<u32>,
}

/// A window's account of what it has shown; the window is the one that sent it.
#[derive(Debug)]
pub struct ReadyReport {
    pub name: String,
    pub version: String,
    pub platform: Platform,
    pub window: String,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo::current()
}

/// The tallest a window may grow to fit its content, in logical pixels; none for a window that keeps its size.
fn max_fitted_height(label: &str) -> Option<u32> {
    match label {
        summary::LABEL => Some(600),
        "settings" => Some(700),
        _ => None,
    }
}

/// A reported content height as a window height: at least one pixel, at most `max`.
fn fitted_height(height: u32, max: u32) -> u32 {
    height.clamp(1, max)
}

/// Fits the window to the content height it reported, keeping its width.
fn fit_to_content<R: Runtime>(window: &Window<R>, height: u32, max: u32) {
    let Ok(size) = window.inner_size() else {
        return;
    };
    let width = f64::from(size.width) / window.scale_factor().unwrap_or(1.0);
    let _ = window.set_size(LogicalSize::new(
        width,
        f64::from(fitted_height(height, max)),
    ));
}

#[tauri::command]
pub fn report_ready<R: Runtime>(window: Window<R>, mode: State<'_, Mode>, report: Shown) {
    if let (Some(max), Some(height)) = (max_fitted_height(window.label()), report.height) {
        fit_to_content(&window, height, max);
        if window.label() == "settings" {
            crate::settings_window::reveal(window.app_handle());
        }
    }
    let report = ReadyReport {
        name: report.name,
        version: report.version,
        platform: report.platform,
        window: window.label().to_string(),
    };
    log::info!(
        "interface ready in {}: {} {}",
        report.window,
        report.name,
        report.version
    );
    if *mode == Mode::SelfCheck {
        self_check::receive(window.app_handle(), report);
    }
}

fn is_unlocked<R: Runtime>(app: &AppHandle<R>) -> bool {
    app.try_state::<Arc<Guard>>()
        .is_none_or(|guard| !guard.is_locked())
}

/// Shows the main window and, unless the application is locked, asks it to show `target`: "overview" or the
/// fingerprint of a certificate on this computer. While locked the window shows the lock and nothing else. The
/// request is kept until the interface takes it, because the event alone can be lost while the interface is
/// still starting.
#[tauri::command]
pub fn open_main_window<R: Runtime>(
    app: AppHandle<R>,
    pending: State<'_, PendingNavigation>,
    target: Option<String>,
) {
    crate::show_main_window(&app);
    hide_window(&app, "summary");
    let place = target.as_deref().and_then(Navigation::of);
    if let (true, Some(place)) = (is_unlocked(&app), place) {
        pending.set(place);
        if let Err(error) = app.emit_to("main", NAVIGATE, ()) {
            log::warn!("the main window could not be asked to navigate: {error}");
        }
    }
}

/// Hands the main window the place it was asked to show, once; nothing while locked.
#[tauri::command]
pub fn pending_navigation<R: Runtime>(
    app: AppHandle<R>,
    pending: State<'_, PendingNavigation>,
) -> Option<Navigation> {
    pending.take().filter(|_| is_unlocked(&app))
}

#[tauri::command]
pub fn hide_summary<R: Runtime>(app: AppHandle<R>) {
    hide_window(&app, "summary");
}

fn hide_window<R: Runtime>(app: &AppHandle<R>, label: &str) {
    if let Some(window) = app.get_webview_window(label) {
        let _ = window.hide();
    }
}

/// The origin of the app's own pages, as the IPC sees it on this system.
#[cfg(test)]
pub(crate) const LOCAL_ORIGIN: &str = if cfg!(windows) {
    "http://tauri.localhost"
} else {
    "tauri://localhost"
};

#[cfg(test)]
mod tests {
    use super::{LOCAL_ORIGIN, Navigation};
    use crate::{Mode, builder};
    use tauri::test::MockRuntime;
    use tauri::webview::InvokeRequest;
    use tauri::{WebviewUrl, WebviewWindowBuilder, ipc::CallbackFn};

    fn call(
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        call_in("main", LOCAL_ORIGIN, command, body)
    }

    fn call_from(
        origin: &str,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        call_in("main", origin, command, body)
    }

    fn call_in(
        label: &str,
        origin: &str,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        let app = builder::<MockRuntime>(Mode::Normal)
            .build(crate::context())
            .expect("the mock app builds");
        crate::session::manage_for_tests(app.handle());
        let window = WebviewWindowBuilder::new(&app, label, WebviewUrl::default())
            .build()
            .expect("the main window is created");
        tauri::test::get_ipc_response(
            &window,
            InvokeRequest {
                cmd: command.into(),
                callback: CallbackFn(0),
                error: CallbackFn(1),
                url: origin.parse().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: app.invoke_key().to_string(),
            },
        )
        .map(|response| response.deserialize().expect("the response is JSON"))
    }

    #[test]
    fn app_info_returns_the_core_identity() {
        let answer = call("app_info", serde_json::json!({})).expect("the command succeeds");
        assert_eq!(
            answer,
            serde_json::to_value(im_core::AppInfo::current()).unwrap()
        );
    }

    #[test]
    fn report_ready_accepts_a_report() {
        let report = serde_json::json!({ "report": { "name": "Identity Manager", "version": "0.1.0", "platform": "macos" } });
        let answer = call("report_ready", report);
        assert!(answer.is_ok(), "{answer:?}");
    }

    #[test]
    fn report_ready_accepts_a_height_from_the_summary_and_ignores_it_from_main() {
        let report = serde_json::json!({ "report": { "name": "Identity Manager", "version": "0.1.0", "platform": "linux", "height": 118 } });
        assert!(call_in("summary", LOCAL_ORIGIN, "report_ready", report.clone()).is_ok());
        assert!(call_in("main", LOCAL_ORIGIN, "report_ready", report).is_ok());
    }

    #[test]
    fn report_ready_accepts_a_height_from_the_settings_window_on_macos_only() {
        let report = serde_json::json!({ "report": { "name": "Identity Manager", "version": "0.1.0", "platform": "macos", "height": 420 } });
        let answer = call_in("settings", LOCAL_ORIGIN, "report_ready", report);
        assert_eq!(answer.is_ok(), cfg!(target_os = "macos"), "{answer:?}");
    }

    #[test]
    fn only_the_summary_and_settings_windows_fit_their_content() {
        assert_eq!(super::max_fitted_height("summary"), Some(600));
        assert_eq!(super::max_fitted_height("settings"), Some(700));
        assert_eq!(super::max_fitted_height("main"), None);
    }

    #[test]
    fn a_reported_height_is_kept_within_the_limits() {
        assert_eq!(super::fitted_height(0, 600), 1);
        assert_eq!(super::fitted_height(118, 600), 118);
        assert_eq!(super::fitted_height(10_000, 600), 600);
    }

    #[test]
    fn report_ready_refuses_a_malformed_report() {
        assert!(
            call(
                "report_ready",
                serde_json::json!({ "report": { "name": 1 } })
            )
            .is_err()
        );
    }

    #[test]
    fn a_remote_page_is_refused() {
        assert!(call_from("https://example.com", "app_info", serde_json::json!({})).is_err());
    }

    #[test]
    fn an_unknown_command_is_refused() {
        assert!(call("read_file", serde_json::json!({})).is_err());
    }

    fn summary(command: &str) -> Result<serde_json::Value, serde_json::Value> {
        call_in("summary", LOCAL_ORIGIN, command, serde_json::json!({}))
    }

    fn capability_permissions(file: &str) -> serde_json::Value {
        let file: serde_json::Value = serde_json::from_str(file).expect("the capability is JSON");
        file["permissions"].clone()
    }

    #[test]
    fn the_summary_may_call_its_four_commands() {
        let report = serde_json::json!({
            "report": { "name": "Identity Manager", "version": "0.1.0", "platform": "linux" }
        });
        assert!(summary("app_info").is_ok());
        assert!(call_in("summary", LOCAL_ORIGIN, "report_ready", report).is_ok());
        assert!(summary("open_main_window").is_ok());
        assert!(summary("hide_summary").is_ok());
    }

    #[test]
    fn the_summary_is_refused_the_main_window_command_from_a_remote_origin() {
        let answer = call_in(
            "summary",
            "https://example.com",
            "open_main_window",
            serde_json::json!({}),
        );
        assert!(answer.is_err());
    }

    #[test]
    fn the_summary_is_refused_a_command_that_is_not_listed() {
        assert!(summary("read_file").is_err());
    }

    #[test]
    fn the_main_window_is_refused_the_summary_commands() {
        assert!(call("hide_summary", serde_json::json!({})).is_err());
        assert!(call("open_main_window", serde_json::json!({})).is_err());
    }

    #[test]
    fn the_colour_scheme_command_is_granted_on_linux_only() {
        let answer = call("color_scheme", serde_json::json!({}));
        assert_eq!(answer.is_ok(), cfg!(target_os = "linux"), "{answer:?}");
    }

    #[test]
    fn the_main_capability_grants_only_the_two_app_commands() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json"))
                .expect("the capability is JSON");
        assert_eq!(file["windows"], serde_json::json!(["main"]));
        assert_eq!(
            file["permissions"],
            serde_json::json!(["allow-app-info", "allow-report-ready"])
        );
    }

    #[test]
    fn the_summary_capability_grants_only_its_four_commands() {
        let file = include_str!("../capabilities/summary.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["summary"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-app-info",
                "allow-report-ready",
                "allow-open-main-window",
                "allow-hide-summary"
            ])
        );
    }

    #[test]
    fn the_colour_scheme_capability_is_for_linux_and_grants_only_the_scheme_and_event_listening() {
        let file = include_str!("../capabilities/color-scheme.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["linux"]));
        assert_eq!(parsed["windows"], serde_json::json!(["main", "summary"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-color-scheme",
                "core:event:allow-listen",
                "core:event:allow-unlisten"
            ])
        );
    }

    /// Whether the call was refused by the capabilities rather than failing in the command.
    fn refused_by_capabilities(answer: &Result<serde_json::Value, serde_json::Value>) -> bool {
        matches!(answer, Err(error) if error.to_string().contains("not allowed"))
    }

    const SETTINGS_COMMANDS: [&str; 2] = ["settings", "set_setting"];

    #[test]
    fn the_summary_is_refused_the_settings_commands() {
        for command in SETTINGS_COMMANDS {
            assert!(refused_by_capabilities(&summary(command)), "{command}");
        }
    }

    #[test]
    fn only_the_settings_window_on_macos_and_only_main_elsewhere_may_call_the_settings_commands() {
        for command in SETTINGS_COMMANDS {
            // An empty body is no valid change, so an allowed `set_setting` fails inside the command.
            let main = call_in("main", LOCAL_ORIGIN, command, serde_json::json!({}));
            let settings = call_in("settings", LOCAL_ORIGIN, command, serde_json::json!({}));
            assert_eq!(
                refused_by_capabilities(&main),
                cfg!(target_os = "macos"),
                "{command} from main: {main:?}"
            );
            assert_eq!(
                refused_by_capabilities(&settings),
                !cfg!(target_os = "macos"),
                "{command} from settings: {settings:?}"
            );
        }
    }

    #[test]
    fn set_setting_refuses_the_ilm_address() {
        let window = if cfg!(target_os = "macos") {
            "settings"
        } else {
            "main"
        };
        let change = serde_json::json!({ "change": { "key": "ilmUrl", "value": "https://ilm.example.com" } });

        let answer = call_in(window, LOCAL_ORIGIN, "set_setting", change);

        assert!(
            matches!(&answer, Err(error) if error.to_string().contains("through Connect")),
            "{answer:?}"
        );
    }

    #[test]
    fn a_remote_page_is_refused_the_settings_commands() {
        for label in ["main", "settings"] {
            let answer = call_in(
                label,
                "https://example.com",
                "settings",
                serde_json::json!({}),
            );
            assert!(refused_by_capabilities(&answer), "{label}: {answer:?}");
        }
    }

    #[test]
    fn only_main_and_not_on_macos_may_take_the_pending_section() {
        let summary = summary("pending_section");
        assert!(refused_by_capabilities(&summary), "{summary:?}");
        for label in ["main", "settings"] {
            let answer = call_in(
                label,
                LOCAL_ORIGIN,
                "pending_section",
                serde_json::json!({}),
            );
            assert_eq!(
                refused_by_capabilities(&answer),
                cfg!(target_os = "macos") || label == "settings",
                "{label}: {answer:?}"
            );
        }
    }

    #[test]
    fn the_settings_window_capability_is_for_macos_and_grants_only_the_settings() {
        let file = include_str!("../capabilities/settings-window.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["macOS"]));
        assert_eq!(parsed["windows"], serde_json::json!(["settings"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-app-info",
                "allow-report-ready",
                "allow-settings",
                "allow-set-setting",
                "core:window:allow-set-title",
                "core:window:allow-start-dragging"
            ])
        );
    }

    #[test]
    fn the_settings_entry_capability_is_for_the_main_window_on_macos_and_grants_only_opening_settings()
     {
        let file = include_str!("../capabilities/settings-entry.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["macOS"]));
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!(["allow-open-settings"])
        );
    }

    #[test]
    fn only_the_main_window_on_macos_may_open_the_settings_window() {
        for label in ["main", "summary", "settings"] {
            let answer = call_in(label, LOCAL_ORIGIN, "open_settings", serde_json::json!({}));
            assert_eq!(
                refused_by_capabilities(&answer),
                !(cfg!(target_os = "macos") && label == "main"),
                "{label}: {answer:?}"
            );
        }
    }

    #[test]
    fn the_title_bar_capability_is_for_the_main_window_on_macos_and_grants_only_moving_and_zooming()
    {
        let file = include_str!("../capabilities/title-bar.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["macOS"]));
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "core:window:allow-start-dragging",
                "core:window:allow-internal-toggle-maximize"
            ])
        );
    }

    #[test]
    fn on_macos_main_and_settings_may_move_their_window_and_only_main_may_zoom() {
        for label in ["main", "summary", "settings"] {
            for (command, windows) in [
                ("plugin:window|start_dragging", &["main", "settings"][..]),
                ("plugin:window|internal_toggle_maximize", &["main"][..]),
                ("plugin:window|set_title", &["settings"][..]),
            ] {
                let answer = call_in(label, LOCAL_ORIGIN, command, serde_json::json!({}));
                assert_eq!(
                    refused_by_capabilities(&answer),
                    !(cfg!(target_os = "macos") && windows.contains(&label)),
                    "{label} {command}: {answer:?}"
                );
            }
        }
    }

    #[test]
    fn the_settings_page_capability_is_for_windows_and_linux_and_grants_only_the_settings_and_event_listening()
     {
        let file = include_str!("../capabilities/settings-page.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["windows", "linux"]));
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-settings",
                "allow-set-setting",
                "allow-pending-section",
                "core:event:allow-listen",
                "core:event:allow-unlisten"
            ])
        );
    }

    const SESSION_COMMANDS: [&str; 10] = [
        "session",
        "connect",
        "sign_in",
        "certificates",
        "sign_in_with_certificate",
        "reopen_browser",
        "cancel_sign_in",
        "sign_out",
        "unlock",
        "sign_in_again",
    ];
    const SETTINGS_WINDOW_SESSION_COMMANDS: [&str; 3] = ["session", "sign_out", "unlock"];
    const SUMMARY_SESSION_COMMANDS: [&str; 3] = ["session", "unlock", "sign_in_again"];

    #[test]
    fn the_summary_may_call_only_the_session_unlock_and_sign_in_again_commands() {
        for command in SESSION_COMMANDS {
            let answer = summary(command);
            assert_eq!(
                refused_by_capabilities(&answer),
                !SUMMARY_SESSION_COMMANDS.contains(&command),
                "{command}: {answer:?}"
            );
        }
    }

    #[test]
    fn the_main_window_may_call_every_session_command() {
        for command in SESSION_COMMANDS {
            let answer = call(command, serde_json::json!({}));
            assert!(!refused_by_capabilities(&answer), "{command}: {answer:?}");
        }
    }

    #[test]
    fn the_settings_window_may_call_only_the_session_sign_out_and_unlock_commands_and_only_on_macos()
     {
        for command in SESSION_COMMANDS {
            let answer = call_in("settings", LOCAL_ORIGIN, command, serde_json::json!({}));
            let granted =
                cfg!(target_os = "macos") && SETTINGS_WINDOW_SESSION_COMMANDS.contains(&command);
            assert_eq!(
                refused_by_capabilities(&answer),
                !granted,
                "{command}: {answer:?}"
            );
        }
    }

    #[test]
    fn a_remote_page_is_refused_every_session_command() {
        for label in ["main", "settings"] {
            for command in SESSION_COMMANDS {
                let answer = call_in(label, "https://example.com", command, serde_json::json!({}));
                assert!(
                    refused_by_capabilities(&answer),
                    "{label} {command}: {answer:?}"
                );
            }
        }
    }

    #[test]
    fn the_session_capability_grants_only_the_session_commands_and_event_listening() {
        let file = include_str!("../capabilities/session.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-session",
                "allow-connect",
                "allow-sign-in",
                "allow-certificates",
                "allow-sign-in-with-certificate",
                "allow-reopen-browser",
                "allow-cancel-sign-in",
                "allow-sign-out",
                "allow-unlock",
                "allow-sign-in-again",
                "core:event:allow-listen",
                "core:event:allow-unlisten"
            ])
        );
    }

    #[test]
    fn the_summary_session_capability_grants_three_session_commands_and_event_listening() {
        let file = include_str!("../capabilities/summary-session.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["summary"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-session",
                "allow-unlock",
                "allow-sign-in-again",
                "core:event:allow-listen",
                "core:event:allow-unlisten"
            ])
        );
    }

    #[test]
    fn the_certificates_capability_grants_only_the_certificate_commands_to_the_main_window() {
        let file = include_str!("../capabilities/certificates.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-local-certificates",
                "allow-ilm-status",
                "allow-ilm-certificates",
                "allow-sync-now",
                "allow-make-sign-in-certificate",
                "allow-add-to-ilm-choices",
                "allow-add-to-ilm"
            ])
        );
    }

    const CERTIFICATE_COMMANDS: [(&str, &str); 7] = [
        ("local_certificates", "{}"),
        ("ilm_status", "{}"),
        ("ilm_certificates", r#"{"page":1,"search":null}"#),
        ("sync_now", "{}"),
        ("make_sign_in_certificate", r#"{"fingerprint":"00"}"#),
        ("add_to_ilm_choices", "{}"),
        (
            "add_to_ilm",
            r#"{"fingerprints":[],"group":null,"raProfile":null}"#,
        ),
    ];

    #[test]
    fn only_the_main_window_may_use_the_certificate_commands() {
        for (command, body) in CERTIFICATE_COMMANDS {
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            for label in ["main", "summary", "settings"] {
                let answer = call_in(label, LOCAL_ORIGIN, command, body.clone());
                assert_eq!(
                    refused_by_capabilities(&answer),
                    label != "main",
                    "{label} {command}: {answer:?}"
                );
            }
            let answer = call_from("https://example.com", command, body);
            assert!(refused_by_capabilities(&answer), "{command}: {answer:?}");
        }
    }

    #[test]
    fn the_attributes_capability_grants_only_the_form_commands_to_the_main_window() {
        let file = include_str!("../capabilities/attributes.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-attribute-callback",
                "allow-check-attributes",
                "allow-close-form",
                "allow-open-in-ilm"
            ])
        );
    }

    const FORM_COMMANDS: [(&str, &str); 4] = [
        (
            "attribute_callback",
            r#"{"id":"x","field":"f","values":{},"seq":1}"#,
        ),
        ("check_attributes", r#"{"id":"x","values":{}}"#),
        ("close_form", r#"{"id":"x"}"#),
        ("open_in_ilm", r#"{"target":"addToIlm"}"#),
    ];

    #[test]
    fn only_the_main_window_may_use_the_form_commands() {
        for (command, body) in FORM_COMMANDS {
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            for label in ["main", "summary", "settings"] {
                let answer = call_in(label, LOCAL_ORIGIN, command, body.clone());
                assert_eq!(
                    refused_by_capabilities(&answer),
                    label != "main",
                    "{label} {command}: {answer:?}"
                );
            }
            let answer = call_from("https://example.com", command, body);
            assert!(refused_by_capabilities(&answer), "{command}: {answer:?}");
        }
    }

    #[test]
    fn the_request_capability_grants_only_the_request_commands_to_the_main_window() {
        let file = include_str!("../capabilities/request.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-request-choices",
                "allow-open-request-forms",
                "allow-request-offers",
                "allow-request-certificate",
                "allow-follow-request",
                "allow-stop-following-request",
                "allow-open-prepared-forms",
                "allow-complete-certificate"
            ])
        );
    }

    const REQUEST_COMMANDS: [(&str, &str); 8] = [
        ("request_choices", "{}"),
        ("open_request_forms", r#"{"raProfile":"ra-1"}"#),
        ("request_offers", "{}"),
        (
            "request_certificate",
            r#"{"raProfile":"ra-1","forms":{},"storage":"software","keyType":"ecP256"}"#,
        ),
        ("follow_request", r#"{"certificate":"c-1"}"#),
        ("stop_following_request", r#"{"certificate":"c-1"}"#),
        ("open_prepared_forms", r#"{"uuid":"c-1"}"#),
        (
            "complete_certificate",
            r#"{"uuid":"c-1","forms":{},"storage":"software","keyType":"ecP256","challenge":null}"#,
        ),
    ];

    #[test]
    fn only_the_main_window_may_use_the_request_commands() {
        for (command, body) in REQUEST_COMMANDS {
            let body: serde_json::Value = serde_json::from_str(body).unwrap();
            for label in ["main", "summary", "settings"] {
                let answer = call_in(label, LOCAL_ORIGIN, command, body.clone());
                assert_eq!(
                    refused_by_capabilities(&answer),
                    label != "main",
                    "{label} {command}: {answer:?}"
                );
            }
            let answer = call_from("https://example.com", command, body);
            assert!(refused_by_capabilities(&answer), "{command}: {answer:?}");
        }
    }

    #[test]
    fn the_overview_capability_grants_only_the_overview_to_the_main_window_and_the_summary() {
        let file = include_str!("../capabilities/overview.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main", "summary"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!(["allow-overview"])
        );
    }

    #[test]
    fn only_the_main_window_and_the_summary_may_read_the_overview() {
        for label in ["main", "summary", "settings"] {
            let answer = call_in(label, LOCAL_ORIGIN, "overview", serde_json::json!({}));
            assert_eq!(
                refused_by_capabilities(&answer),
                label == "settings",
                "{label}: {answer:?}"
            );
        }
        for label in ["main", "summary"] {
            let answer = call_in(
                label,
                "https://example.com",
                "overview",
                serde_json::json!({}),
            );
            assert!(refused_by_capabilities(&answer), "{label}: {answer:?}");
        }
    }

    #[test]
    fn the_navigation_capability_grants_only_taking_the_place_to_the_main_window() {
        let file = include_str!("../capabilities/navigation.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["windows"], serde_json::json!(["main"]));
        assert!(parsed.get("platforms").is_none());
        assert_eq!(
            capability_permissions(file),
            serde_json::json!(["allow-pending-navigation"])
        );
    }

    #[test]
    fn only_the_main_window_may_take_the_pending_navigation() {
        for label in ["main", "summary", "settings"] {
            let answer = call_in(
                label,
                LOCAL_ORIGIN,
                "pending_navigation",
                serde_json::json!({}),
            );
            assert_eq!(
                refused_by_capabilities(&answer),
                label != "main",
                "{label}: {answer:?}"
            );
        }
        let answer = call_in(
            "main",
            "https://example.com",
            "pending_navigation",
            serde_json::json!({}),
        );
        assert!(refused_by_capabilities(&answer), "{answer:?}");
    }

    #[test]
    fn a_target_names_the_overview_or_a_certificate_and_nothing_else() {
        let print = im_core::identity::Fingerprint::of(b"der").to_string();
        assert_eq!(Navigation::of("overview"), Some(Navigation::Overview));
        assert_eq!(
            Navigation::of(&print),
            Some(Navigation::Certificate { fingerprint: print })
        );
        for other in ["", "Overview", "settings", "00", "../etc"] {
            assert_eq!(Navigation::of(other), None, "{other:?}");
        }
    }

    #[test]
    fn the_settings_window_session_capability_is_for_macos_and_grants_only_two_commands_and_event_listening()
     {
        let file = include_str!("../capabilities/settings-window-session.json");
        let parsed: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(parsed["platforms"], serde_json::json!(["macOS"]));
        assert_eq!(parsed["windows"], serde_json::json!(["settings"]));
        assert_eq!(
            capability_permissions(file),
            serde_json::json!([
                "allow-session",
                "allow-sign-out",
                "allow-unlock",
                "core:event:allow-listen",
                "core:event:allow-unlisten"
            ])
        );
    }
}
