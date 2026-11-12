use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use im_core::AppInfo;
use tauri::{AppHandle, Manager, Runtime};

use crate::bridge::ReadyReport;

pub const TIMEOUT: Duration = Duration::from_secs(60);

/// The windows that must report before the run can pass.
const WINDOWS: [&str; 2] = ["main", "summary"];

/// Compares what a window showed with the core's own identity.
fn differences(report: &ReadyReport, core: AppInfo) -> Vec<String> {
    let mut differences = Vec::new();
    if report.name != core.name {
        differences.push(format!(
            "name: interface showed {:?}, core has {:?}",
            report.name, core.name
        ));
    }
    if report.version != core.version {
        differences.push(format!(
            "version: interface showed {:?}, core has {:?}",
            report.version, core.version
        ));
    }
    if report.platform != core.platform {
        differences.push(format!(
            "platform: interface showed {:?}, core has {:?}",
            report.platform, core.platform
        ));
    }
    differences
}

/// Judges the reports so far: `Some(Err)` on a bad report, `Some(Ok)` once every window in [`WINDOWS`] has
/// reported, `None` while one is missing.
pub fn verdict(reports: &[ReadyReport], core: AppInfo) -> Option<Result<(), String>> {
    let mut problems = Vec::new();
    for report in reports {
        if !WINDOWS.contains(&report.window.as_str()) {
            problems.push(format!("report from unknown window {:?}", report.window));
        }
        let wrong = differences(report, core);
        if !wrong.is_empty() {
            problems.push(format!("{}: {}", report.window, wrong.join("; ")));
        }
    }
    if !problems.is_empty() {
        return Some(Err(problems.join("; ")));
    }
    missing(reports).is_empty().then_some(Ok(()))
}

/// The windows in [`WINDOWS`] that have not reported.
fn missing(reports: &[ReadyReport]) -> Vec<&'static str> {
    WINDOWS
        .into_iter()
        .filter(|label| !reports.iter().any(|report| report.window == *label))
        .collect()
}

pub fn exit_code(result: &Result<(), String>) -> i32 {
    if result.is_ok() { 0 } else { 1 }
}

fn announce(result: &Result<(), String>, core: AppInfo) {
    match result {
        Ok(()) => {
            println!("self-check passed: {} {}", core.name, core.version);
            log::info!("self-check passed");
        }
        Err(difference) => {
            eprintln!("self-check failed: {difference}");
            log::error!("self-check failed: {difference}");
        }
    }
}

/// What the windows have reported so far.
#[derive(Default)]
pub struct Reports(Mutex<Vec<ReadyReport>>);

impl Reports {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<ReadyReport>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps the window's latest report and judges all of them.
    fn add(&self, report: ReadyReport, core: AppInfo) -> Option<Result<(), String>> {
        let mut reports = self.lock();
        reports.retain(|earlier| earlier.window != report.window);
        reports.push(report);
        verdict(&reports, core)
    }

    fn missing_message(&self, after: Duration) -> String {
        let missing = missing(&self.lock());
        format!(
            "no report within {} s from: {}",
            after.as_secs(),
            missing.join(", ")
        )
    }
}

/// Takes a window's report and, once the run can be judged, prints the outcome and ends it.
pub fn receive<R: Runtime>(app: &AppHandle<R>, report: ReadyReport) {
    let core = AppInfo::current();
    if let Some(result) = app.state::<Reports>().add(report, core) {
        announce(&result, core);
        app.exit(exit_code(&result));
    }
}

/// Ends the run as failed if the windows have not all reported within `after`.
pub fn expire<R: Runtime>(app: &AppHandle<R>, after: Duration) {
    std::thread::sleep(after);
    let message = format!(
        "self-check failed: {}",
        app.state::<Reports>().missing_message(after)
    );
    eprintln!("{message}");
    log::error!("{message}");
    app.exit(1);
}

pub fn start_timer<R: Runtime>(app: AppHandle<R>) {
    std::thread::spawn(move || expire(&app, TIMEOUT));
}

#[cfg(test)]
mod tests {
    use super::*;
    use im_core::Platform;

    fn from(window: &str) -> ReadyReport {
        let core = AppInfo::current();
        ReadyReport {
            name: core.name.into(),
            version: core.version.into(),
            platform: core.platform,
            window: window.into(),
        }
    }

    fn other_platform() -> Platform {
        if AppInfo::current().platform == Platform::Linux {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }

    fn failure(reports: &[ReadyReport]) -> String {
        verdict(reports, AppInfo::current())
            .expect("the verdict is decided")
            .unwrap_err()
    }

    #[test]
    fn matching_reports_from_both_windows_pass_in_either_order() {
        let core = AppInfo::current();
        assert_eq!(
            verdict(&[from("main"), from("summary")], core),
            Some(Ok(()))
        );
        assert_eq!(
            verdict(&[from("summary"), from("main")], core),
            Some(Ok(()))
        );
    }

    #[test]
    fn a_single_window_is_not_enough_yet() {
        let core = AppInfo::current();
        assert_eq!(verdict(&[], core), None);
        assert_eq!(verdict(&[from("main")], core), None);
        assert_eq!(verdict(&[from("summary")], core), None);
    }

    #[test]
    fn a_wrong_name_is_named_with_its_window() {
        let mut main = from("main");
        main.name = "Other".into();
        let message = failure(&[main, from("summary")]);
        assert!(message.contains("main") && message.contains("name") && message.contains("Other"));
        assert!(!message.contains("version") && !message.contains("platform"));
    }

    #[test]
    fn a_wrong_version_is_named_with_its_window() {
        let mut summary = from("summary");
        summary.version = "9.9.9".into();
        let message = failure(&[from("main"), summary]);
        assert!(
            message.contains("summary") && message.contains("version") && message.contains("9.9.9")
        );
        assert!(!message.contains("name") && !message.contains("platform"));
    }

    #[test]
    fn a_wrong_platform_in_the_summary_fails_even_when_main_is_right() {
        let mut summary = from("summary");
        summary.platform = other_platform();
        let message = failure(&[from("main"), summary]);
        assert!(message.contains("summary") && message.contains("platform"));
        assert!(!message.contains("main"));
    }

    #[test]
    fn a_wrong_platform_in_main_fails() {
        let mut main = from("main");
        main.platform = other_platform();
        let message = failure(&[main, from("summary")]);
        assert!(message.contains("main") && message.contains("platform"));
    }

    #[test]
    fn a_wrong_report_fails_before_the_other_window_reports() {
        let mut main = from("main");
        main.name = "Other".into();
        assert!(failure(&[main]).contains("main"));
    }

    #[test]
    fn a_report_from_an_unknown_window_fails_even_with_both_known_windows() {
        let message = failure(&[from("main"), from("summary"), from("popup")]);
        assert!(message.contains("unknown window") && message.contains("popup"));
    }

    #[test]
    fn every_problem_is_named() {
        let mut main = from("main");
        main.name = "Other".into();
        main.version = "9.9.9".into();
        let message = failure(&[main, from("popup")]);
        assert!(
            message.contains("name") && message.contains("version") && message.contains("popup")
        );
    }

    #[test]
    fn the_exit_code_is_zero_for_a_pass_and_one_for_a_failure() {
        assert_eq!(exit_code(&Ok(())), 0);
        assert_eq!(exit_code(&Err("differs".into())), 1);
    }

    #[test]
    fn the_limit_is_sixty_seconds() {
        assert_eq!(TIMEOUT, Duration::from_secs(60));
    }

    #[test]
    fn collected_reports_are_judged_when_the_second_window_arrives() {
        let core = AppInfo::current();
        let reports = Reports::default();
        assert_eq!(reports.add(from("summary"), core), None);
        assert_eq!(reports.add(from("main"), core), Some(Ok(())));
    }

    #[test]
    fn a_window_reporting_twice_counts_once_and_the_latest_wins() {
        let core = AppInfo::current();
        let reports = Reports::default();
        assert_eq!(reports.add(from("main"), core), None);
        assert_eq!(reports.add(from("main"), core), None);
        let mut wrong = from("main");
        wrong.name = "Other".into();
        assert!(matches!(reports.add(wrong, core), Some(Err(_))));
    }

    #[test]
    fn the_timeout_message_names_what_is_missing() {
        let core = AppInfo::current();
        let reports = Reports::default();
        let after = Duration::from_secs(60);
        assert_eq!(
            reports.missing_message(after),
            "no report within 60 s from: main, summary"
        );
        reports.add(from("main"), core);
        assert_eq!(
            reports.missing_message(after),
            "no report within 60 s from: summary"
        );
        reports.add(from("summary"), core);
        assert_eq!(
            reports.missing_message(after),
            "no report within 60 s from: "
        );
    }
}
