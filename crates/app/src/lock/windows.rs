//! Windows: the session flags and the last input time for sensing, Windows Hello for the system prompt.

use std::ffi::c_void;
use std::mem::size_of;
use std::time::Duration;

use tauri::{AppHandle, Manager, Runtime};
use tokio::sync::oneshot;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SESSION, WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK, WTSFreeMemory, WTSINFOEXW,
    WTSQuerySessionInformationW, WTSSessionInfoEx,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::WinRT::{
    IUserConsentVerifierInterop, RO_INIT_MULTITHREADED, RoInitialize,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
use windows::core::{HSTRING, PWSTR, factory};
use windows_future::IAsyncOperation;

use super::{Authenticator, Availability, Confirmation, SystemState};

const MAIN_WINDOW: &str = "main";
const INFO_LEVEL_1: u32 = 1;

pub struct Session;

impl SystemState for Session {
    fn screen_locked(&self) -> Option<bool> {
        let mut buffer = PWSTR::null();
        let mut bytes = 0u32;
        // SAFETY: both out parameters are valid for writes; on success the system allocates the buffer.
        unsafe {
            WTSQuerySessionInformationW(
                None,
                WTS_CURRENT_SESSION,
                WTSSessionInfoEx,
                &mut buffer,
                &mut bytes,
            )
        }
        .ok()?;
        let flags = session_flags(buffer, bytes);
        // SAFETY: the buffer came from the query above and is freed exactly once.
        unsafe { WTSFreeMemory(buffer.0.cast()) };
        flags.and_then(locked_from_flags)
    }

    fn idle(&self) -> Option<Duration> {
        let mut input = LASTINPUTINFO {
            cbSize: size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        // SAFETY: `input` is a valid structure with its size set.
        let read = unsafe { GetLastInputInfo(&mut input) }.as_bool();
        // SAFETY: the call has no preconditions.
        let now = unsafe { GetTickCount64() };
        read.then(|| idle_since(now, input.dwTime))
    }
}

/// The session flags of a `WTSINFOEXW` buffer returned by the system, when it is a level 1 answer.
fn session_flags(buffer: PWSTR, bytes: u32) -> Option<i32> {
    if buffer.is_null() || (bytes as usize) < size_of::<WTSINFOEXW>() {
        return None;
    }
    // SAFETY: the buffer holds at least a `WTSINFOEXW`, as the size above shows, and the system aligns it.
    let info = unsafe { &*buffer.0.cast::<WTSINFOEXW>() };
    if info.Level != INFO_LEVEL_1 {
        return None;
    }
    // SAFETY: level 1 means the level 1 member of the union is the one that is filled.
    Some(unsafe { info.Data.WTSInfoExLevel1.SessionFlags })
}

fn locked_from_flags(flags: i32) -> Option<bool> {
    match u32::try_from(flags).ok()? {
        WTS_SESSIONSTATE_LOCK => Some(true),
        WTS_SESSIONSTATE_UNLOCK => Some(false),
        _ => None,
    }
}

/// The time since the last input. The last input time is a 32-bit tick count that wraps every 49 days, so the
/// difference is taken on the low 32 bits of the 64-bit tick count.
fn idle_since(now_ticks: u64, last_input: u32) -> Duration {
    Duration::from_millis(u64::from((now_ticks as u32).wrapping_sub(last_input)))
}

pub struct Prompt<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> Prompt<R> {
    pub fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

impl<R: Runtime> Authenticator for Prompt<R> {
    async fn available(&self) -> Availability {
        on_winrt_thread(check_availability)
            .await
            .unwrap_or(Availability::Unsupported)
    }

    async fn confirm(&self, reason: &str) -> Confirmation {
        let Some(window) = self.app.get_webview_window(MAIN_WINDOW) else {
            return failed("Identity Manager has no window to show the prompt over.");
        };
        let Ok(handle) = window.hwnd() else {
            return failed("Identity Manager has no window to show the prompt over.");
        };
        // The handle crosses to the prompt's thread as a number; the window outlives the prompt.
        let handle = handle.0 as isize;
        let reason = reason.to_owned();
        on_winrt_thread(move || verify(handle, &reason))
            .await
            .unwrap_or_else(|| failed("The prompt could not be shown."))
    }
}

/// Runs `work` on a thread of its own that is set up for Windows Runtime calls, so the caller never blocks and the
/// main thread is not involved.
async fn on_winrt_thread<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (sender, receiver) = oneshot::channel();
    std::thread::spawn(move || {
        // SAFETY: initialising the Windows Runtime for this new thread has no preconditions; a failure only
        // means it is already initialised.
        let _ = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        let _ = sender.send(work());
    });
    receiver.await.ok()
}

fn check_availability() -> Availability {
    let result =
        UserConsentVerifier::CheckAvailabilityAsync().and_then(|operation| operation.join());
    availability_for(result)
}

/// A busy device is set up and only momentarily unavailable, so it still counts as available.
fn availability_for(
    result: windows::core::Result<UserConsentVerifierAvailability>,
) -> Availability {
    match result {
        Ok(
            UserConsentVerifierAvailability::Available
            | UserConsentVerifierAvailability::DeviceBusy,
        ) => Availability::Available,
        Ok(UserConsentVerifierAvailability::NotConfiguredForUser) => Availability::NotSetUp,
        Ok(_) => Availability::Unsupported,
        Err(error) => {
            log::warn!("cannot check Windows Hello: {:?}", error.code());
            Availability::Unsupported
        }
    }
}

fn verify(handle: isize, reason: &str) -> Confirmation {
    let outcome = factory::<UserConsentVerifier, IUserConsentVerifierInterop>().and_then(|interop| {
        let window = HWND(handle as *mut c_void);
        // SAFETY: the handle belongs to the main window, which is alive while the app runs, and the message is a
        // valid string.
        let operation: windows::core::Result<IAsyncOperation<UserConsentVerificationResult>> =
            unsafe { interop.RequestVerificationForWindowAsync(window, &HSTRING::from(reason)) };
        operation?.join()
    });
    match outcome {
        Ok(result) => confirmation_for(result),
        Err(error) => {
            log::warn!("Windows Hello prompt failed: {:?}", error.code());
            failed("The system could not confirm you.")
        }
    }
}

fn confirmation_for(result: UserConsentVerificationResult) -> Confirmation {
    match result {
        UserConsentVerificationResult::Verified => Confirmation::Confirmed,
        UserConsentVerificationResult::Canceled => Confirmation::Cancelled,
        UserConsentVerificationResult::DeviceNotPresent
        | UserConsentVerificationResult::NotConfiguredForUser => {
            failed("Windows Hello is not set up.")
        }
        UserConsentVerificationResult::DisabledByPolicy => {
            failed("Windows Hello is turned off by your organization.")
        }
        UserConsentVerificationResult::DeviceBusy => failed("Windows Hello is busy. Try again."),
        UserConsentVerificationResult::RetriesExhausted => {
            failed("Too many attempts. Try again later.")
        }
        _ => failed("The system could not confirm you."),
    }
}

fn failed(reason: &str) -> Confirmation {
    Confirmation::Failed(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_flags_tell_locked_from_unlocked() {
        assert_eq!(locked_from_flags(WTS_SESSIONSTATE_LOCK as i32), Some(true));
        assert_eq!(
            locked_from_flags(WTS_SESSIONSTATE_UNLOCK as i32),
            Some(false)
        );
        assert_eq!(locked_from_flags(-1), None);
        assert_eq!(locked_from_flags(7), None);
    }

    #[test]
    fn idle_time_survives_the_tick_wrap() {
        assert_eq!(idle_since(10_000, 4_000), Duration::from_millis(6_000));
        let wrapped_now = (1u64 << 32) + 500;
        assert_eq!(
            idle_since(wrapped_now, u32::MAX - 499),
            Duration::from_millis(1_000)
        );
    }

    #[test]
    fn results_map_to_confirmations() {
        assert_eq!(
            confirmation_for(UserConsentVerificationResult::Verified),
            Confirmation::Confirmed
        );
        assert_eq!(
            confirmation_for(UserConsentVerificationResult::Canceled),
            Confirmation::Cancelled
        );
        assert_eq!(
            confirmation_for(UserConsentVerificationResult::DeviceBusy),
            failed("Windows Hello is busy. Try again.")
        );
    }

    #[test]
    fn a_busy_device_still_counts_as_available() {
        for (found, expected) in [
            (
                UserConsentVerifierAvailability::Available,
                Availability::Available,
            ),
            (
                UserConsentVerifierAvailability::DeviceBusy,
                Availability::Available,
            ),
            (
                UserConsentVerifierAvailability::NotConfiguredForUser,
                Availability::NotSetUp,
            ),
            (
                UserConsentVerifierAvailability::DisabledByPolicy,
                Availability::Unsupported,
            ),
            (
                UserConsentVerifierAvailability::DeviceNotPresent,
                Availability::Unsupported,
            ),
        ] {
            assert_eq!(availability_for(Ok(found)), expected);
        }
        let error =
            windows::core::Error::from_hresult(windows::core::HRESULT(0x8000_4005_u32 as i32));
        assert_eq!(availability_for(Err(error)), Availability::Unsupported);
    }
}
