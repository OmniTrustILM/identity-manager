//! The macOS Dock icon and application menu exist only while the main or Settings window is visible.

#[cfg(target_os = "macos")]
use tauri::{ActivationPolicy, AppHandle, Manager, Runtime};

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
pub enum Policy {
    Regular,
    Accessory,
}

/// The policy that goes with the main and Settings windows being visible or hidden.
#[cfg(any(target_os = "macos", test))]
pub fn policy(main_visible: bool, settings_visible: bool) -> Policy {
    if main_visible || settings_visible {
        Policy::Regular
    } else {
        Policy::Accessory
    }
}

#[cfg(target_os = "macos")]
fn set<R: Runtime>(app: &AppHandle<R>, policy: Policy) {
    let policy = match policy {
        Policy::Regular => ActivationPolicy::Regular,
        Policy::Accessory => ActivationPolicy::Accessory,
    };
    if let Err(error) = app.set_activation_policy(policy) {
        log::warn!("setting the activation policy failed: {error}");
    }
}

/// Gives the app its Dock icon and menu, before a window is shown.
#[cfg(target_os = "macos")]
pub fn activate<R: Runtime>(app: &AppHandle<R>) {
    set(app, Policy::Regular);
}

/// Applies the policy that goes with the windows as they are now.
#[cfg(target_os = "macos")]
pub fn refresh<R: Runtime>(app: &AppHandle<R>) {
    let visible = |label: &str| {
        app.get_webview_window(label)
            .is_some_and(|window| window.is_visible().unwrap_or(false))
    };
    set(app, policy(visible("main"), visible("settings")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_visible_window_gets_the_regular_policy() {
        assert_eq!(policy(true, false), Policy::Regular);
        assert_eq!(policy(false, true), Policy::Regular);
        assert_eq!(policy(true, true), Policy::Regular);
    }

    #[test]
    fn both_windows_hidden_gets_the_accessory_policy() {
        assert_eq!(policy(false, false), Policy::Accessory);
    }
}
