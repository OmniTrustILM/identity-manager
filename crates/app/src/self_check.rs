use std::time::Duration;

use im_core::AppInfo;
use tauri::{AppHandle, Runtime};

use crate::bridge::ReadyReport;

pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Compares what the interface showed with the core's own identity.
pub fn verdict(report: &ReadyReport, core: AppInfo) -> Result<(), String> {
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
    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences.join("; "))
    }
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

/// Judges the interface's report, prints the outcome and returns the exit code.
fn judge(report: &ReadyReport) -> i32 {
    let core = AppInfo::current();
    let result = verdict(report, core);
    announce(&result, core);
    exit_code(&result)
}

/// Judges the interface's report and ends the run with the outcome.
pub fn conclude<R: Runtime>(app: &AppHandle<R>, report: &ReadyReport) {
    app.exit(judge(report));
}

/// Ends the run as failed if the interface has not reported within `after`.
pub fn expire<R: Runtime>(app: &AppHandle<R>, after: Duration) {
    std::thread::sleep(after);
    let message = format!(
        "self-check failed: no report from the interface within {} s",
        after.as_secs()
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

    fn report(name: &str, version: &str) -> ReadyReport {
        ReadyReport {
            name: name.into(),
            version: version.into(),
        }
    }

    #[test]
    fn equal_name_and_version_pass() {
        let core = AppInfo::current();
        assert_eq!(verdict(&report(core.name, core.version), core), Ok(()));
    }

    #[test]
    fn a_different_name_fails_and_is_named() {
        let core = AppInfo::current();
        let message = verdict(&report("Other", core.version), core).unwrap_err();
        assert!(message.contains("name"));
        assert!(message.contains("Other"));
        assert!(message.contains(core.name));
        assert!(!message.contains("version"));
    }

    #[test]
    fn a_different_version_fails_and_is_named() {
        let core = AppInfo::current();
        let message = verdict(&report(core.name, "9.9.9"), core).unwrap_err();
        assert!(message.contains("version"));
        assert!(message.contains("9.9.9"));
        assert!(message.contains(core.version));
        assert!(!message.contains("name"));
    }

    #[test]
    fn both_differences_are_named() {
        let message = verdict(&report("Other", "9.9.9"), AppInfo::current()).unwrap_err();
        assert!(message.contains("name") && message.contains("version"));
    }

    #[test]
    fn judge_returns_the_exit_code_of_the_verdict() {
        let core = AppInfo::current();
        assert_eq!(judge(&report(core.name, core.version)), 0);
        assert_eq!(judge(&report(core.name, "9.9.9")), 1);
    }

    #[test]
    fn exit_code_is_zero_for_a_pass_and_one_for_a_failure() {
        assert_eq!(exit_code(&Ok(())), 0);
        assert_eq!(exit_code(&Err("differs".into())), 1);
    }
}
