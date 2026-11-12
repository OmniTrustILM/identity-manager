//! Reads the policy a CI runner has installed (`scripts/verify.sh policy-system` writes it).

use im_core::policy;
use im_core::settings::{self, Layer, LogLevel};

#[test]
#[ignore = "needs the policy installed by scripts/verify.sh policy-system"]
fn the_installed_policy_is_read_and_locks_the_settings() {
    let policy = policy::read();
    let view = settings::view(&policy, &Layer::default());

    assert!(!view.start_at_login.value);
    assert!(view.start_at_login.locked);
    assert_eq!(view.log_level.value, LogLevel::Debug);
    assert!(view.log_level.locked);
}

/// The script installs a root-owned file that group members may write, at the path in
/// `IM_POLICY_UNTRUSTED`; it holds a valid policy that must not count.
#[cfg(unix)]
#[test]
#[ignore = "needs the untrusted file installed by scripts/verify.sh policy-system"]
fn an_untrusted_copy_is_ignored() {
    use std::path::PathBuf;

    #[cfg(target_os = "macos")]
    let parse = policy::macos::parse_plist;
    #[cfg(not(target_os = "macos"))]
    let parse = policy::linux::parse_json;

    let path = PathBuf::from(std::env::var_os("IM_POLICY_UNTRUSTED").expect("IM_POLICY_UNTRUSTED"));
    let bytes = std::fs::read(&path).expect("the untrusted file is readable");
    assert!(
        !parse(&bytes, "test").is_empty(),
        "the file holds a valid policy"
    );

    assert_eq!(policy::read_file(&path, parse), Layer::default());
}
