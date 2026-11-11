use im_core::AppInfo;
use serde::Deserialize;
use tauri::{AppHandle, Runtime, State};

use crate::{Mode, self_check};

/// What the interface reports it has shown.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct ReadyReport {
    pub name: String,
    pub version: String,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo::current()
}

#[tauri::command]
pub fn report_ready<R: Runtime>(app: AppHandle<R>, mode: State<'_, Mode>, report: ReadyReport) {
    log::info!("interface ready: {} {}", report.name, report.version);
    if *mode == Mode::SelfCheck {
        self_check::conclude(&app, &report);
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
        call_from(LOCAL_ORIGIN, command, body)
    }

    fn call_from(
        origin: &str,
        command: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, serde_json::Value> {
        let app = builder::<MockRuntime>(Mode::Normal)
            .build(crate::context())
            .expect("the mock app builds");
        let window = WebviewWindowBuilder::new(&app, "main", WebviewUrl::default())
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
        let report =
            serde_json::json!({ "report": { "name": "Identity Manager", "version": "0.1.0" } });
        let answer = call("report_ready", report);
        assert!(answer.is_ok(), "{answer:?}");
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

    #[test]
    fn the_capability_grants_only_the_two_app_commands() {
        let file: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/main.json"))
                .expect("the capability is JSON");
        assert_eq!(file["windows"], serde_json::json!(["main"]));
        assert_eq!(
            file["permissions"],
            serde_json::json!(["allow-app-info", "allow-report-ready"])
        );
    }
}
