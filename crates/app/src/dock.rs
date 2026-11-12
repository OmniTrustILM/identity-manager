//! The macOS Dock icon and application menu exist only while the main window is visible.

#[cfg(target_os = "macos")]
use tauri::{ActivationPolicy, AppHandle, Runtime};

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, PartialEq, Eq)]
pub enum Policy {
    Regular,
    Accessory,
}

/// The policy that goes with the main window being visible or hidden.
#[cfg(any(target_os = "macos", test))]
pub fn policy(main_visible: bool) -> Policy {
    if main_visible {
        Policy::Regular
    } else {
        Policy::Accessory
    }
}

/// Sets the activation policy for the main window being visible or hidden.
#[cfg(target_os = "macos")]
pub fn apply<R: Runtime>(app: &AppHandle<R>, main_visible: bool) {
    let policy = match policy(main_visible) {
        Policy::Regular => ActivationPolicy::Regular,
        Policy::Accessory => ActivationPolicy::Accessory,
    };
    if let Err(error) = app.set_activation_policy(policy) {
        log::warn!("setting the activation policy failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_visible_main_window_gets_the_regular_policy() {
        assert_eq!(policy(true), Policy::Regular);
    }

    #[test]
    fn a_hidden_main_window_gets_the_accessory_policy() {
        assert_eq!(policy(false), Policy::Accessory);
    }
}
