//! What the computer says about the person being present, and the system prompt that confirms them.
//!
//! This module only senses and asks; the decisions are in `im_core::lock`.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Runtime};

mod guard;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

pub use guard::{Guard, Surface, watch};

/// Samples of the computer, read without asking the person anything. `None` means the answer cannot be read.
pub trait SystemState: Send + Sync {
    fn screen_locked(&self) -> Option<bool>;
    fn idle(&self) -> Option<Duration>;
}

/// Whether the system can confirm the person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))] // only the native prompts produce these
pub enum Availability {
    Available,
    NotSetUp,
    Unsupported,
}

/// How the system prompt ended.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))] // only the native prompts produce these
pub enum Confirmation {
    Confirmed,
    Cancelled,
    Failed(String),
}

/// The system prompt (Touch ID or password, Windows Hello). Used through generics, so the futures stay `Send`
/// without a boxed trait object.
pub trait Authenticator: Send + Sync {
    fn available(&self) -> impl Future<Output = Availability> + Send;
    fn confirm(&self, reason: &str) -> impl Future<Output = Confirmation> + Send;
}

/// A state that cannot read anything: it never locks the app.
pub struct NoState;

impl SystemState for NoState {
    fn screen_locked(&self) -> Option<bool> {
        None
    }

    fn idle(&self) -> Option<Duration> {
        None
    }
}

/// An authenticator for systems without unlock and for the self-check.
pub struct NoPrompt;

impl Authenticator for NoPrompt {
    async fn available(&self) -> Availability {
        Availability::Unsupported
    }

    async fn confirm(&self, _reason: &str) -> Confirmation {
        Confirmation::Failed("Unlock is not available on this system.".to_owned())
    }
}

/// The samples of this system.
pub fn system_state() -> Arc<dyn SystemState> {
    #[cfg(target_os = "macos")]
    return Arc::new(macos::Session);
    #[cfg(windows)]
    return Arc::new(windows::Session);
    #[cfg(not(any(target_os = "macos", windows)))]
    return Arc::new(NoState);
}

/// The prompt of this system; on Windows it sits over the main window of `app`.
#[cfg_attr(not(windows), allow(unused_variables))]
pub fn authenticator<R: Runtime>(app: &AppHandle<R>) -> impl Authenticator + use<R> {
    #[cfg(target_os = "macos")]
    return macos::Prompt;
    #[cfg(windows)]
    return windows::Prompt::new(app.clone());
    #[cfg(not(any(target_os = "macos", windows)))]
    return NoPrompt;
}

#[cfg(test)]
pub use scripted::{ScriptedAuthenticator, ScriptedState};

/// Stand-ins that answer what a test queued.
#[cfg(test)]
mod scripted {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct ScriptedState {
        sample: Mutex<(Option<bool>, Option<Duration>)>,
    }

    impl ScriptedState {
        pub fn set(&self, screen_locked: Option<bool>, idle: Option<Duration>) {
            *self.sample.lock().unwrap() = (screen_locked, idle);
        }
    }

    impl SystemState for ScriptedState {
        fn screen_locked(&self) -> Option<bool> {
            self.sample.lock().unwrap().0
        }

        fn idle(&self) -> Option<Duration> {
            self.sample.lock().unwrap().1
        }
    }

    pub struct ScriptedAuthenticator {
        availability: Mutex<Availability>,
        results: Mutex<VecDeque<Confirmation>>,
        reasons: Mutex<Vec<String>>,
    }

    impl ScriptedAuthenticator {
        pub fn new(availability: Availability) -> Self {
            Self {
                availability: Mutex::new(availability),
                results: Mutex::default(),
                reasons: Mutex::default(),
            }
        }

        pub fn set_availability(&self, availability: Availability) {
            *self.availability.lock().unwrap() = availability;
        }

        /// Queues what the next `confirm` answers.
        pub fn queue(&self, result: Confirmation) {
            self.results.lock().unwrap().push_back(result);
        }

        /// The reasons the prompt was asked with, oldest first.
        pub fn reasons(&self) -> Vec<String> {
            self.reasons.lock().unwrap().clone()
        }
    }

    impl Authenticator for Arc<ScriptedAuthenticator> {
        fn available(&self) -> impl Future<Output = Availability> + Send {
            ScriptedAuthenticator::available(self)
        }

        fn confirm(&self, reason: &str) -> impl Future<Output = Confirmation> + Send {
            ScriptedAuthenticator::confirm(self, reason)
        }
    }

    impl Authenticator for ScriptedAuthenticator {
        async fn available(&self) -> Availability {
            *self.availability.lock().unwrap()
        }

        async fn confirm(&self, reason: &str) -> Confirmation {
            self.reasons.lock().unwrap().push(reason.to_owned());
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Confirmation::Failed("nothing was queued".to_owned()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_state_reads_nothing() {
        assert_eq!(NoState.screen_locked(), None);
        assert_eq!(NoState.idle(), None);
    }

    #[tokio::test]
    async fn no_prompt_is_unsupported_and_never_confirms() {
        assert_eq!(NoPrompt.available().await, Availability::Unsupported);
        assert!(matches!(
            NoPrompt.confirm("unlock").await,
            Confirmation::Failed(_)
        ));
    }

    #[test]
    fn scripted_state_answers_what_was_set() {
        let state = ScriptedState::default();
        assert_eq!(state.screen_locked(), None);
        state.set(Some(true), Some(Duration::from_secs(7)));
        assert_eq!(state.screen_locked(), Some(true));
        assert_eq!(state.idle(), Some(Duration::from_secs(7)));
    }

    #[tokio::test]
    async fn scripted_authenticator_answers_in_order_and_records_reasons() {
        let authenticator = ScriptedAuthenticator::new(Availability::Available);
        authenticator.queue(Confirmation::Cancelled);
        authenticator.queue(Confirmation::Confirmed);
        assert_eq!(
            authenticator.confirm("first").await,
            Confirmation::Cancelled
        );
        assert_eq!(
            authenticator.confirm("second").await,
            Confirmation::Confirmed
        );
        assert!(matches!(
            authenticator.confirm("third").await,
            Confirmation::Failed(_)
        ));
        assert_eq!(authenticator.reasons(), ["first", "second", "third"]);
        authenticator.set_availability(Availability::NotSetUp);
        assert_eq!(authenticator.available().await, Availability::NotSetUp);
    }
}
