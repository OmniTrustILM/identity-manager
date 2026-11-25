use std::env;
use std::path::Path;

use tauri_build::{AppManifest, Attributes, WindowsAttributes};

fn main() {
    // The Windows manifest is linked into every target, so unit tests load Common Controls 6 like the app does.
    let windows_msvc = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows_msvc {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
    tauri_build::try_build(
        Attributes::new()
            .windows_attributes(WindowsAttributes::new_without_app_manifest())
            .app_manifest(AppManifest::new().commands(&[
                "app_info",
                "report_ready",
                "open_main_window",
                "pending_navigation",
                "hide_summary",
                "color_scheme",
                "settings",
                "set_setting",
                "pending_section",
                "open_settings",
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
                "local_certificates",
                "ilm_status",
                "ilm_certificates",
                "sync_now",
                "make_sign_in_certificate",
                "overview",
                "add_to_ilm_choices",
                "add_to_ilm",
                "attribute_callback",
                "check_attributes",
                "close_form",
                "open_in_ilm",
                "request_choices",
                "open_request_forms",
                "request_offers",
                "request_certificate",
                "follow_request",
                "stop_following_request",
                "open_prepared_forms",
                "complete_certificate",
            ])),
    )
    .expect("the Tauri build failed");
}
