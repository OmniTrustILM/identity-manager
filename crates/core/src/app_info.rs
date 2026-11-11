/// Product name and version of this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl AppInfo {
    /// Returns the identity of the running build.
    pub const fn current() -> AppInfo {
        AppInfo {
            name: "Identity Manager",
            version: env!("CARGO_PKG_VERSION"),
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
    fn version_is_three_numbers() {
        let parts: Vec<&str> = AppInfo::current().version.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.parse::<u64>().is_ok()));
    }
}
