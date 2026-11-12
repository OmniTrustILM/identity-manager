/// Operating system family this build targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "lowercase")
)]
pub enum Platform {
    Macos,
    Windows,
    Linux,
}

impl Platform {
    #[cfg(target_os = "macos")]
    const CURRENT: Platform = Platform::Macos;
    #[cfg(target_os = "windows")]
    const CURRENT: Platform = Platform::Windows;
    #[cfg(target_os = "linux")]
    const CURRENT: Platform = Platform::Linux;
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    compile_error!("Identity Manager builds for macOS, Windows and Linux only");
}

/// Product name, version and platform of this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(ts_rs::TS), ts(export))]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub platform: Platform,
}

impl AppInfo {
    /// Returns the identity of the running build.
    pub const fn current() -> AppInfo {
        AppInfo {
            name: "Identity Manager",
            version: env!("CARGO_PKG_VERSION"),
            platform: Platform::CURRENT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_reports_the_product_name() {
        assert_eq!(AppInfo::current().name, "Identity Manager");
    }

    #[test]
    fn current_reports_the_crate_version() {
        assert_eq!(AppInfo::current().version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn current_reports_this_builds_platform() {
        let expected = match std::env::consts::OS {
            "macos" => Platform::Macos,
            "windows" => Platform::Windows,
            "linux" => Platform::Linux,
            other => panic!("unsupported test platform {other}"),
        };
        assert_eq!(AppInfo::current().platform, expected);
    }

    #[test]
    fn platform_serialises_in_lower_case() {
        let names: Vec<String> = [Platform::Macos, Platform::Windows, Platform::Linux]
            .iter()
            .map(|platform| serde_json::to_string(platform).unwrap())
            .collect();
        assert_eq!(names, [r#""macos""#, r#""windows""#, r#""linux""#]);
    }

    #[test]
    fn version_is_three_numbers() {
        let parts: Vec<&str> = AppInfo::current().version.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.parse::<u64>().is_ok()));
    }
}
