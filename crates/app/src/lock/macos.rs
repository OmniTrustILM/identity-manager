//! macOS: the session dictionary and the event source for sensing, `LAContext` for the system prompt.

use std::sync::Mutex;
use std::time::Duration;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_core_foundation::{CFBoolean, CFDictionary, CFRetained, CFString, CFType};
use objc2_core_graphics::{
    CGEventSource, CGEventSourceStateID, CGEventType, CGSessionCopyCurrentDictionary,
};
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAError, LAPolicy};
use tokio::sync::oneshot;

use super::{Authenticator, Availability, Confirmation, SystemState};

const SCREEN_IS_LOCKED: &str = "CGSSessionScreenIsLocked";
/// `kCGAnyInputEventType`: every kind of input event.
const ANY_INPUT: CGEventType = CGEventType(u32::MAX);
const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthentication;

pub struct Session;

impl SystemState for Session {
    fn screen_locked(&self) -> Option<bool> {
        let dictionary = CGSessionCopyCurrentDictionary()?;
        // SAFETY: the session dictionary maps CFString keys to CFType values; the value is checked before use.
        let dictionary =
            unsafe { CFRetained::cast_unchecked::<CFDictionary<CFString, CFType>>(dictionary) };
        let flag = dictionary.get(&CFString::from_static_str(SCREEN_IS_LOCKED));
        Some(flag.is_some_and(|value| {
            value
                .downcast_ref::<CFBoolean>()
                .is_some_and(CFBoolean::as_bool)
        }))
    }

    fn idle(&self) -> Option<Duration> {
        let seconds = CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID::CombinedSessionState,
            ANY_INPUT,
        );
        (seconds.is_finite() && seconds >= 0.0).then(|| Duration::from_secs_f64(seconds))
    }
}

pub struct Prompt;

/// Holds the context while the prompt is open: releasing it cancels the evaluation.
struct Context(Retained<LAContext>);

// SAFETY: LAContext can be used from any thread; this wrapper only starts one evaluation and releases the context.
unsafe impl Send for Context {}

impl Authenticator for Prompt {
    async fn available(&self) -> Availability {
        // SAFETY: creating a context has no preconditions.
        let context = unsafe { LAContext::new() };
        // SAFETY: `canEvaluatePolicy:error:` has no preconditions beyond a valid context.
        match unsafe { context.canEvaluatePolicy_error(POLICY) } {
            Ok(()) => Availability::Available,
            Err(error) => availability_for(error.code()),
        }
    }

    async fn confirm(&self, reason: &str) -> Confirmation {
        let (context, receiver) = start(reason);
        let outcome = receiver.await.unwrap_or_else(|_| failed(None));
        drop(context);
        outcome
    }
}

/// Starts the evaluation and returns the context, which must stay alive until the reply arrives, with the reply.
/// Nothing that is not `Send` outlives this function, so the caller can await the reply on any thread.
fn start(reason: &str) -> (Context, oneshot::Receiver<Confirmation>) {
    let (sender, receiver) = oneshot::channel();
    // SAFETY: creating a context has no preconditions.
    let context = Context(unsafe { LAContext::new() });
    let sender = Mutex::new(Some(sender));
    let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
        // SAFETY: the framework passes either null or a valid error that lives during this call.
        let error = unsafe { error.as_ref() };
        let outcome = if success.as_bool() {
            Confirmation::Confirmed
        } else {
            error.map_or_else(|| failed(None), |error| confirmation_for(error.code()))
        };
        // The framework calls the block once; the guard keeps a second call harmless.
        if let Some(sender) = sender.lock().ok().and_then(|mut slot| slot.take()) {
            let _ = sender.send(outcome);
        }
    });
    let reason = NSString::from_str(reason);
    // SAFETY: the reply block owns only a mutex around a oneshot sender, so it may run on any thread; the framework
    // copies the block, and the caller keeps the context alive until the reply arrives.
    unsafe {
        context
            .0
            .evaluatePolicy_localizedReason_reply(POLICY, &reason, &reply);
    }
    (context, receiver)
}

fn availability_for(code: isize) -> Availability {
    match LAError(code) {
        LAError::PasscodeNotSet | LAError::BiometryNotEnrolled => Availability::NotSetUp,
        _ => Availability::Unsupported,
    }
}

fn confirmation_for(code: isize) -> Confirmation {
    match LAError(code) {
        LAError::UserCancel | LAError::AppCancel | LAError::SystemCancel => Confirmation::Cancelled,
        error => failed(Some(error)),
    }
}

/// A plain reason that never carries what the system says about the person.
fn failed(error: Option<LAError>) -> Confirmation {
    let reason = match error {
        Some(LAError::PasscodeNotSet) => "No password is set on this Mac.",
        Some(LAError::BiometryLockout) => "Touch ID is locked. Use your password.",
        Some(LAError::NotInteractive) => "The system cannot ask right now.",
        _ => "The system could not confirm you.",
    };
    Confirmation::Failed(reason.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_codes_are_cancelled() {
        for code in [
            LAError::UserCancel,
            LAError::AppCancel,
            LAError::SystemCancel,
        ] {
            assert_eq!(confirmation_for(code.0), Confirmation::Cancelled);
        }
    }

    #[test]
    fn other_codes_fail_with_a_plain_reason() {
        let cases = [
            (
                LAError::AuthenticationFailed,
                "The system could not confirm you.",
            ),
            (LAError::PasscodeNotSet, "No password is set on this Mac."),
            (
                LAError::BiometryLockout,
                "Touch ID is locked. Use your password.",
            ),
            (LAError::NotInteractive, "The system cannot ask right now."),
        ];
        for (code, reason) in cases {
            assert_eq!(
                confirmation_for(code.0),
                Confirmation::Failed(reason.to_owned())
            );
        }
        assert_eq!(
            failed(None),
            Confirmation::Failed("The system could not confirm you.".to_owned())
        );
    }

    #[test]
    fn availability_follows_the_error() {
        assert_eq!(
            availability_for(LAError::PasscodeNotSet.0),
            Availability::NotSetUp
        );
        assert_eq!(
            availability_for(LAError::BiometryNotEnrolled.0),
            Availability::NotSetUp
        );
        assert_eq!(
            availability_for(LAError::NotInteractive.0),
            Availability::Unsupported
        );
    }
}
