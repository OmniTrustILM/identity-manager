use tauri_build::{AppManifest, Attributes};

fn main() {
    tauri_build::try_build(
        Attributes::new().app_manifest(AppManifest::new().commands(&["app_info", "report_ready"])),
    )
    .expect("the Tauri build failed");
}
