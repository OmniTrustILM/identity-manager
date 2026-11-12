use im_core::{AppInfo, Platform};
use serde::Deserialize;
use tauri::{AppHandle, LogicalSize, Manager, Runtime, State, Window};

use crate::{Mode, self_check, summary};

/// What an interface says it has shown.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct Shown {
    pub name: String,
    pub version: String,
    pub platform: Platform,
    /// The natural height of the content in CSS pixels, sent by the tray summary so its window can fit it.
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

/// The tallest the summary may grow, in logical pixels.
const MAX_SUMMARY_HEIGHT: u32 = 600;

/// A reported content height as a window height: at least one pixel, at most `MAX_SUMMARY_HEIGHT`.
fn fitted_height(height: u32) -> u32 {
    height.clamp(1, MAX_SUMMARY_HEIGHT)
}

/// Fits the summary window to the content height it reported, keeping the width from its configuration.
fn fit_summary<R: Runtime>(window: &Window<R>, height: u32) {
    let Ok(size) = window.inner_size() else {
        return;
    };
    let width = f64::from(size.width) / window.scale_factor().unwrap_or(1.0);
    let _ = window.set_size(LogicalSize::new(width, f64::from(fitted_height(height))));
}

#[tauri::command]
pub fn report_ready<R: Runtime>(window: Window<R>, mode: State<'_, Mode>, report: Shown) {
    if let (summary::LABEL, Some(height)) = (window.label(), report.height) {
        fit_summary(&window, height);
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

#[tauri::command]
pub fn open_main_window<R: Runtime>(app: AppHandle<R>) {
    crate::show_main_window(&app);
    hide_window(&app, "summary");
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

#[cfg(test)]
mod tests {
    use crate::{Mode, builder};
    use tauri::test::MockRuntime;
    use tauri::webview::InvokeRequest;
    use tauri::{WebviewUrl, WebviewWindowBuilder, ipc::CallbackFn};

    const LOCAL_ORIGIN: &str = if cfg!(windows) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };

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
    fn a_reported_height_is_kept_within_the_summary_limits() {
        assert_eq!(super::fitted_height(0), 1);
        assert_eq!(super::fitted_height(118), 118);
        assert_eq!(super::fitted_height(10_000), super::MAX_SUMMARY_HEIGHT);
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
}
