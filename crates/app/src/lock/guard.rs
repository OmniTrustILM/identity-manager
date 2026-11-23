//! The lock of the application: it follows the computer, hides the sign-in from the windows while locked and
//! asks the system to confirm the person before showing it again.

use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use im_core::lock::{Change, Config, Lock, Reason, Sample};
use im_core::session::SessionView;
use im_core::settings::{SettingsView, Unlock};

use super::{Authenticator, Availability, Confirmation, SystemState};

/// What a command that needs the person's sign-in answers while the application is locked.
pub const LOCKED_MESSAGE: &str = "Unlock Identity Manager first.";
const UNLOCK_REASON: &str = "unlock Identity Manager";
const CANCELLED_MESSAGE: &str = "Unlock was cancelled.";
/// How often the computer is read.
const SAMPLE_EVERY: Duration = Duration::from_secs(5);

type Boxed<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// What the guard changes on screen.
pub trait Surface: Send + Sync {
    /// Tells every window what to show of the sign-in.
    fn show(&self, view: &SessionView);
    fn hide_summary(&self);
}

/// The system prompt in a form that can be kept behind a pointer.
trait Prompt: Send + Sync {
    fn available(&self) -> Boxed<'_, Availability>;
    fn confirm<'a>(&'a self, reason: &'a str) -> Boxed<'a, Confirmation>;
}

impl<A: Authenticator> Prompt for A {
    fn available(&self) -> Boxed<'_, Availability> {
        Box::pin(Authenticator::available(self))
    }

    fn confirm<'a>(&'a self, reason: &'a str) -> Boxed<'a, Confirmation> {
        Box::pin(Authenticator::confirm(self, reason))
    }
}

type Listener = Box<dyn Fn(&SessionView) + Send + Sync>;

struct State {
    lock: Lock,
    require_unlock: bool,
    idle_limit: Option<Duration>,
    availability: Option<Availability>,
    /// The latest sign-in view, as the session reported it.
    real: SessionView,
    /// Whether the first view after the start has been seen: it tells whether a saved sign-in exists.
    started: bool,
}

impl State {
    fn set_availability(&mut self, availability: Availability) {
        if self.availability != Some(availability) {
            log::info!("unlock is {availability:?}");
        }
        self.availability = Some(availability);
    }

    fn config(&self) -> Config {
        Config {
            require_unlock: self.require_unlock,
            idle_limit: self.idle_limit,
            available: self.availability == Some(Availability::Available),
        }
    }
}

pub struct Guard {
    surface: Arc<dyn Surface>,
    system: Arc<dyn SystemState>,
    prompt: Box<dyn Prompt>,
    state: Mutex<State>,
    /// Held while the system prompt is open, so there is one prompt at a time.
    prompting: tokio::sync::Mutex<()>,
    /// Held while the lock changes and the windows are told, so a view never reaches them after the lock that
    /// should have hidden it.
    shown: Mutex<()>,
    listeners: Mutex<Vec<Listener>>,
    /// Called each time the application locks.
    on_lock: Mutex<Vec<Box<dyn Fn() + Send + Sync>>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether there is a sign-in that the lock protects: signed in, or a saved one that waits for ILM.
fn has_sign_in(view: &SessionView) -> bool {
    matches!(
        view,
        SessionView::SignedIn { .. } | SessionView::Unreachable { .. }
    )
}

fn reason_name(reason: Reason) -> &'static str {
    match reason {
        Reason::Start => "start",
        Reason::Computer => "computer",
        Reason::Idle => "idle",
    }
}

impl Guard {
    pub fn new(
        surface: Arc<dyn Surface>,
        system: Arc<dyn SystemState>,
        prompt: impl Authenticator + 'static,
    ) -> Self {
        let config = Config {
            require_unlock: false,
            idle_limit: None,
            available: false,
        };
        Self {
            surface,
            system,
            prompt: Box::new(prompt),
            state: Mutex::new(State {
                lock: Lock::new(config),
                require_unlock: false,
                idle_limit: None,
                availability: None,
                real: SessionView::Starting,
                started: false,
            }),
            prompting: tokio::sync::Mutex::new(()),
            shown: Mutex::new(()),
            listeners: Mutex::default(),
            on_lock: Mutex::default(),
        }
    }

    pub fn is_locked(&self) -> bool {
        locked(&self.state).lock.is_locked()
    }

    /// Fails while locked, for the commands that work with the sign-in.
    pub fn ensure_unlocked(&self) -> Result<(), String> {
        if self.is_locked() {
            Err(LOCKED_MESSAGE.to_owned())
        } else {
            Ok(())
        }
    }

    /// What a window may see of `real`.
    pub fn visible(&self, real: SessionView) -> SessionView {
        if self.is_locked() {
            SessionView::Locked {}
        } else {
            real
        }
    }

    /// Calls `listener` with every sign-in view as the session reported it, locked or not.
    pub fn listen(&self, listener: impl Fn(&SessionView) + Send + Sync + 'static) {
        locked(&self.listeners).push(Box::new(listener));
    }

    /// Calls `action` each time the application locks, for what must not outlive the person's presence.
    pub fn on_lock(&self, action: impl Fn() + Send + Sync + 'static) {
        locked(&self.on_lock).push(Box::new(action));
    }

    /// The last view the session reported, locked or not.
    pub fn real(&self) -> SessionView {
        locked(&self.state).real.clone()
    }

    /// Takes a view from the session: tells the listeners and, masked while locked, the windows.
    pub fn publish(&self, real: &SessionView) {
        for listener in locked(&self.listeners).iter() {
            listener(real);
        }
        let _shown = locked(&self.shown);
        let changes = {
            let mut state = locked(&self.state);
            state.real = real.clone();
            let mut changes = Vec::new();
            if !state.started && !matches!(real, SessionView::Starting) {
                state.started = true;
                changes.extend(state.lock.started(has_sign_in(real)));
            }
            if matches!(real, SessionView::SignedOut { .. }) {
                changes.extend(state.lock.signed_out());
            }
            changes
        };
        // An unlock shows the view itself; while locked the windows keep what they show.
        let shown = changes.contains(&Change::Unlocked);
        self.apply(changes, real);
        if !shown && !self.is_locked() {
            self.surface.show(real);
        }
    }

    fn read_system(&self) -> Sample {
        Sample {
            screen_locked: self.system.screen_locked(),
            idle: self.system.idle(),
        }
    }

    /// Reads the computer and locks when it says the person is away.
    pub fn sample(&self) {
        let sample = self.read_system();
        let _shown = locked(&self.shown);
        let (change, real) = {
            let mut state = locked(&self.state);
            let signed_in = has_sign_in(&state.real);
            (state.lock.observe(sample, signed_in), state.real.clone())
        };
        self.apply(change, &real);
    }

    /// Reads what the system can do, then reads the settings and applies them, so the last reader decides; returns
    /// the view with the availability.
    pub async fn adopt(&self, read: impl FnOnce() -> SettingsView + Send) -> SettingsView {
        let availability = self.prompt.available().await;
        let _shown = locked(&self.shown);
        let mut view = read();
        let (change, real) = {
            let mut state = locked(&self.state);
            state.set_availability(availability);
            state.require_unlock = view.require_unlock.value;
            state.idle_limit = view
                .lock_after_idle
                .value
                .map(|minutes| Duration::from_secs(u64::from(minutes) * 60));
            let config = state.config();
            (state.lock.configure(config), state.real.clone())
        };
        self.apply(change, &real);
        view.unlock = match availability {
            Availability::Available => Unlock::Available,
            Availability::NotSetUp => Unlock::NotSetUp,
            Availability::Unsupported => Unlock::Unsupported,
        };
        view
    }

    /// Asks the system to confirm the person and, when it does, shows the sign-in again. Returns the view shown.
    /// A call that waits for another prompt asks again only if the application is still locked afterwards.
    pub async fn unlock(&self) -> Result<SessionView, String> {
        let _prompting = self.prompting.lock().await;
        if !self.is_locked() {
            return Ok(locked(&self.state).real.clone());
        }
        // The system may have lost what confirms the person since it was last read; the application never
        // stays locked without it.
        let availability = self.prompt.available().await;
        {
            let _shown = locked(&self.shown);
            let (change, real) = {
                let mut state = locked(&self.state);
                state.set_availability(availability);
                let config = state.config();
                (state.lock.configure(config), state.real.clone())
            };
            self.apply(change, &real);
            if !self.is_locked() {
                return Ok(real);
            }
        }
        match self.prompt.confirm(UNLOCK_REASON).await {
            Confirmation::Confirmed => {
                let _shown = locked(&self.shown);
                let sample = self.read_system();
                let real = {
                    let mut state = locked(&self.state);
                    state.lock.unlocked(sample);
                    state.real.clone()
                };
                log::info!("unlocked");
                self.surface.show(&real);
                Ok(real)
            }
            Confirmation::Cancelled => {
                log::info!("unlock was cancelled");
                Err(CANCELLED_MESSAGE.to_owned())
            }
            Confirmation::Failed(reason) => {
                log::info!("unlock failed: {reason}");
                Err(reason)
            }
        }
    }

    /// Does what `changes` call for: hides the sign-in, or shows it again after an unlock.
    fn apply(&self, changes: impl IntoIterator<Item = Change>, real: &SessionView) {
        for change in changes {
            match change {
                Change::Locked(reason) => {
                    log::info!("locked: {}", reason_name(reason));
                    for action in locked(&self.on_lock).iter() {
                        action();
                    }
                    self.surface.hide_summary();
                    self.surface.show(&SessionView::Locked {});
                }
                Change::Unlocked => {
                    log::info!("unlocked");
                    self.surface.show(real);
                }
            }
        }
    }
}

/// Reads the computer every few seconds for as long as the application runs.
pub async fn watch(guard: Arc<Guard>) {
    let mut ticker = tokio::time::interval(SAMPLE_EVERY);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        guard.sample();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{ScriptedAuthenticator, ScriptedState};
    use im_core::session::PersonView;
    use im_core::settings::{self, Layer};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, PartialEq)]
    enum Shown {
        Real(&'static str),
        Locked,
        SummaryHidden,
    }

    #[derive(Default)]
    struct Windows(Mutex<Vec<Shown>>);

    impl Surface for Arc<Windows> {
        fn show(&self, view: &SessionView) {
            let shown = match view {
                SessionView::Locked {} => Shown::Locked,
                SessionView::SignedIn { .. } => Shown::Real("signedIn"),
                SessionView::SignedOut { .. } => Shown::Real("signedOut"),
                SessionView::Unreachable { .. } => Shown::Real("unreachable"),
                _ => Shown::Real("other"),
            };
            self.0.lock().unwrap().push(shown);
        }

        fn hide_summary(&self) {
            self.0.lock().unwrap().push(Shown::SummaryHidden);
        }
    }

    impl Windows {
        fn take(&self) -> Vec<Shown> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    struct Fixture {
        guard: Arc<Guard>,
        windows: Arc<Windows>,
        state: Arc<ScriptedState>,
        prompt: Arc<ScriptedAuthenticator>,
    }

    fn signed_in(unreachable: bool) -> SessionView {
        SessionView::SignedIn {
            address: "https://ilm.example.com".to_owned(),
            person: PersonView {
                name: "Ada".to_owned(),
                username: "ada".to_owned(),
            },
            allowed_listings: Vec::new(),
            certificate: None,
            unreachable,
        }
    }

    fn signed_out() -> SessionView {
        SessionView::SignedOut {
            address: None,
            locked: false,
            problem: None,
            again: false,
        }
    }

    fn unreachable_at_start() -> SessionView {
        SessionView::Unreachable {
            address: "https://ilm.example.com".to_owned(),
            problem: "offline".to_owned(),
        }
    }

    fn settings_view(require_unlock: bool, idle_minutes: Option<u16>) -> SettingsView {
        let mut view = settings::view(&Layer::default(), &Layer::default());
        view.require_unlock.value = require_unlock;
        view.lock_after_idle.value = idle_minutes;
        view
    }

    async fn fixture(availability: Availability) -> Fixture {
        let windows = Arc::new(Windows::default());
        let state = Arc::new(ScriptedState::default());
        state.set(Some(false), Some(Duration::ZERO));
        let prompt = Arc::new(ScriptedAuthenticator::new(availability));
        let guard = Arc::new(Guard::new(
            Arc::new(windows.clone()),
            state.clone(),
            prompt.clone(),
        ));
        guard.adopt(|| settings_view(true, None)).await;
        Fixture {
            guard,
            windows,
            state,
            prompt,
        }
    }

    /// A fixture that is signed in, unlocked and past its start.
    async fn signed_in_fixture() -> Fixture {
        let fixture = fixture(Availability::Available).await;
        fixture.guard.publish(&SessionView::Starting);
        fixture.guard.publish(&signed_out());
        fixture.guard.publish(&signed_in(false));
        fixture.windows.take();
        fixture
    }

    #[tokio::test]
    async fn a_saved_sign_in_starts_locked_and_the_windows_never_see_it() {
        let fixture = fixture(Availability::Available).await;
        fixture.guard.publish(&SessionView::Starting);

        fixture.guard.publish(&signed_in(false));

        assert!(fixture.guard.is_locked());
        assert_eq!(
            fixture.windows.take(),
            [Shown::Real("other"), Shown::SummaryHidden, Shown::Locked]
        );
    }

    #[tokio::test]
    async fn a_saved_sign_in_that_waits_for_ilm_starts_locked_too() {
        let fixture = fixture(Availability::Available).await;

        fixture.guard.publish(&unreachable_at_start());

        assert!(fixture.guard.is_locked());
    }

    #[tokio::test]
    async fn without_a_saved_sign_in_the_application_starts_unlocked() {
        let fixture = fixture(Availability::Available).await;

        fixture.guard.publish(&signed_out());
        fixture.guard.publish(&signed_in(false));

        assert!(!fixture.guard.is_locked());
        assert_eq!(
            fixture.windows.take(),
            [Shown::Real("signedOut"), Shown::Real("signedIn")]
        );
    }

    #[tokio::test]
    async fn a_system_that_cannot_confirm_the_person_never_locks() {
        for availability in [Availability::NotSetUp, Availability::Unsupported] {
            let fixture = fixture(availability).await;
            fixture.guard.publish(&signed_in(false));
            fixture
                .state
                .set(Some(true), Some(Duration::from_secs(9999)));

            fixture.guard.sample();

            assert!(!fixture.guard.is_locked(), "{availability:?}");
        }
    }

    #[tokio::test]
    async fn a_locked_computer_locks_the_application_and_hides_the_summary() {
        let fixture = signed_in_fixture().await;

        fixture.state.set(Some(true), Some(Duration::ZERO));
        fixture.guard.sample();

        assert!(fixture.guard.is_locked());
        assert_eq!(
            fixture.windows.take(),
            [Shown::SummaryHidden, Shown::Locked]
        );
        assert_eq!(
            fixture.guard.visible(signed_in(false)),
            SessionView::Locked {}
        );
    }

    #[tokio::test]
    async fn the_idle_time_of_the_settings_locks_the_application() {
        let fixture = signed_in_fixture().await;
        fixture.guard.adopt(|| settings_view(true, Some(5))).await;

        fixture
            .state
            .set(Some(false), Some(Duration::from_secs(299)));
        fixture.guard.sample();
        assert!(!fixture.guard.is_locked());

        fixture
            .state
            .set(Some(false), Some(Duration::from_secs(300)));
        fixture.guard.sample();
        assert!(fixture.guard.is_locked());
    }

    #[tokio::test]
    async fn a_reading_that_failed_does_not_lock() {
        let fixture = signed_in_fixture().await;
        fixture.state.set(None, None);

        fixture.guard.sample();

        assert!(!fixture.guard.is_locked());
    }

    #[tokio::test(start_paused = true)]
    async fn the_watcher_reads_the_computer_every_five_seconds() {
        let fixture = signed_in_fixture().await;
        tokio::spawn(watch(fixture.guard.clone()));
        tokio::task::yield_now().await;
        assert!(!fixture.guard.is_locked());

        fixture.state.set(Some(true), Some(Duration::ZERO));
        tokio::time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;
        assert!(!fixture.guard.is_locked());

        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(fixture.guard.is_locked());
        assert_eq!(
            fixture.windows.take(),
            [Shown::SummaryHidden, Shown::Locked]
        );
    }

    #[tokio::test]
    async fn real_is_the_last_view_published() {
        let fixture = fixture(Availability::Available).await;
        assert!(matches!(fixture.guard.real(), SessionView::Starting));
        fixture.guard.publish(&signed_out());
        assert!(matches!(
            fixture.guard.real(),
            SessionView::SignedOut { .. }
        ));
    }

    #[tokio::test]
    async fn views_while_locked_reach_the_listeners_but_not_the_windows() {
        let fixture = signed_in_fixture().await;
        let heard = Arc::new(AtomicUsize::new(0));
        let counter = heard.clone();
        fixture.guard.listen(move |view| {
            assert!(matches!(view, SessionView::SignedIn { .. }));
            counter.fetch_add(1, Ordering::SeqCst);
        });
        fixture.state.set(Some(true), None);
        fixture.guard.sample();
        fixture.windows.take();

        fixture.guard.publish(&signed_in(true));

        assert_eq!(heard.load(Ordering::SeqCst), 1);
        assert!(fixture.windows.take().is_empty());
    }

    #[tokio::test]
    async fn signing_out_unlocks_and_shows_the_signed_out_view() {
        let fixture = signed_in_fixture().await;
        fixture.state.set(Some(true), None);
        fixture.guard.sample();
        fixture.windows.take();

        fixture.guard.publish(&signed_out());

        assert!(!fixture.guard.is_locked());
        assert_eq!(fixture.windows.take(), [Shown::Real("signedOut")]);
    }

    #[tokio::test]
    async fn turning_the_setting_off_unlocks_and_shows_the_sign_in() {
        let fixture = signed_in_fixture().await;
        fixture.state.set(Some(true), None);
        fixture.guard.sample();
        fixture.windows.take();

        fixture.guard.adopt(|| settings_view(false, None)).await;

        assert!(!fixture.guard.is_locked());
        assert_eq!(fixture.windows.take(), [Shown::Real("signedIn")]);
    }

    #[tokio::test]
    async fn the_settings_view_carries_what_the_system_can_do() {
        for (availability, expected) in [
            (Availability::Available, Unlock::Available),
            (Availability::NotSetUp, Unlock::NotSetUp),
            (Availability::Unsupported, Unlock::Unsupported),
        ] {
            let fixture = fixture(Availability::Unsupported).await;
            fixture.prompt.set_availability(availability);

            let view = fixture.guard.adopt(|| settings_view(true, None)).await;

            assert_eq!(view.unlock, expected);
        }
    }

    #[tokio::test]
    async fn what_must_not_outlive_the_person_is_dropped_at_each_lock_and_not_at_an_unlock() {
        let fixture = signed_in_fixture().await;
        let locks = Arc::new(AtomicUsize::new(0));
        let counted = locks.clone();
        fixture.guard.on_lock(move || {
            counted.fetch_add(1, Ordering::SeqCst);
        });

        fixture.state.set(Some(true), Some(Duration::ZERO));
        fixture.guard.sample();
        assert_eq!(locks.load(Ordering::SeqCst), 1);

        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.guard.unlock().await.unwrap();
        assert_eq!(locks.load(Ordering::SeqCst), 1);

        fixture.state.set(Some(false), Some(Duration::ZERO));
        fixture.guard.sample();
        fixture.state.set(Some(true), Some(Duration::ZERO));
        fixture.guard.sample();
        assert_eq!(locks.load(Ordering::SeqCst), 2);
    }

    async fn locked_fixture() -> Fixture {
        let fixture = signed_in_fixture().await;
        fixture.state.set(Some(true), Some(Duration::ZERO));
        fixture.guard.sample();
        fixture.windows.take();
        fixture
    }

    #[tokio::test]
    async fn confirming_unlocks_and_shows_the_sign_in() {
        let fixture = locked_fixture().await;
        fixture.prompt.queue(Confirmation::Confirmed);

        let view = fixture.guard.unlock().await;

        assert_eq!(view, Ok(signed_in(false)));
        assert!(!fixture.guard.is_locked());
        assert_eq!(fixture.windows.take(), [Shown::Real("signedIn")]);
        assert_eq!(fixture.prompt.reasons(), ["unlock Identity Manager"]);
        // The screen is still locked, and that does not lock the application again.
        fixture.guard.sample();
        assert!(!fixture.guard.is_locked());
    }

    #[tokio::test]
    async fn an_unlock_that_the_system_can_no_longer_confirm_unlocks_without_a_prompt() {
        let fixture = locked_fixture().await;
        fixture.prompt.set_availability(Availability::NotSetUp);

        let view = fixture.guard.unlock().await;

        assert_eq!(view, Ok(signed_in(false)));
        assert!(!fixture.guard.is_locked());
        assert!(fixture.prompt.reasons().is_empty());
        assert_eq!(fixture.windows.take(), [Shown::Real("signedIn")]);
    }

    #[tokio::test]
    async fn the_computer_locking_right_after_an_unlock_locks_the_application_again() {
        let fixture = locked_fixture().await;
        fixture.state.set(Some(false), Some(Duration::ZERO));
        fixture.prompt.queue(Confirmation::Confirmed);
        fixture.guard.unlock().await.unwrap();

        fixture.state.set(Some(true), Some(Duration::ZERO));
        fixture.guard.sample();

        assert!(fixture.guard.is_locked());
    }

    #[tokio::test]
    async fn cancelling_keeps_the_application_locked_and_says_so() {
        let fixture = locked_fixture().await;
        fixture.prompt.queue(Confirmation::Cancelled);

        let answer = fixture.guard.unlock().await;

        assert_eq!(answer, Err("Unlock was cancelled.".to_owned()));
        assert!(fixture.guard.is_locked());
        assert!(fixture.windows.take().is_empty());
    }

    #[tokio::test]
    async fn a_failed_prompt_keeps_the_application_locked_and_gives_its_reason() {
        let fixture = locked_fixture().await;
        fixture
            .prompt
            .queue(Confirmation::Failed("The system refused.".to_owned()));

        let answer = fixture.guard.unlock().await;

        assert_eq!(answer, Err("The system refused.".to_owned()));
        assert!(fixture.guard.is_locked());
    }

    #[tokio::test]
    async fn unlocking_an_application_that_is_not_locked_asks_nothing() {
        let fixture = signed_in_fixture().await;

        assert_eq!(fixture.guard.unlock().await, Ok(signed_in(false)));
        assert!(fixture.prompt.reasons().is_empty());
    }

    #[tokio::test]
    async fn refusals_name_the_lock_only_while_locked() {
        let fixture = signed_in_fixture().await;
        assert_eq!(fixture.guard.ensure_unlocked(), Ok(()));
        fixture.state.set(Some(true), None);
        fixture.guard.sample();
        assert_eq!(
            fixture.guard.ensure_unlocked(),
            Err("Unlock Identity Manager first.".to_owned())
        );
    }

    /// Locks the application while a personal view is being shown, the way the watcher can at any moment.
    struct Racing {
        shown: Mutex<Vec<Shown>>,
        guard: std::sync::OnceLock<Arc<Guard>>,
        watcher: Mutex<Option<std::thread::JoinHandle<()>>>,
    }

    impl Surface for Arc<Racing> {
        fn show(&self, view: &SessionView) {
            let shown = match view {
                SessionView::Locked {} => Shown::Locked,
                _ => Shown::Real("signedIn"),
            };
            if shown == Shown::Real("signedIn") {
                let guard = self.guard.get().unwrap().clone();
                *self.watcher.lock().unwrap() = Some(std::thread::spawn(move || guard.sample()));
                std::thread::sleep(Duration::from_millis(200));
            }
            self.shown.lock().unwrap().push(shown);
        }

        fn hide_summary(&self) {}
    }

    #[tokio::test]
    async fn a_lock_that_comes_while_a_view_is_shown_is_the_last_thing_the_windows_get() {
        let racing = Arc::new(Racing {
            shown: Mutex::default(),
            guard: std::sync::OnceLock::new(),
            watcher: Mutex::default(),
        });
        let state = Arc::new(ScriptedState::default());
        state.set(Some(false), Some(Duration::ZERO));
        let guard = Arc::new(Guard::new(
            Arc::new(racing.clone()),
            state.clone(),
            Arc::new(ScriptedAuthenticator::new(Availability::Available)),
        ));
        racing.guard.set(guard.clone()).ok();
        guard.adopt(|| settings_view(true, None)).await;
        guard.publish(&signed_out());
        guard.sample();
        state.set(Some(true), Some(Duration::ZERO));
        racing.shown.lock().unwrap().clear();

        guard.publish(&signed_in(false));
        let watcher = racing.watcher.lock().unwrap().take().unwrap();
        watcher.join().unwrap();

        assert!(guard.is_locked());
        assert_eq!(racing.shown.lock().unwrap().last(), Some(&Shown::Locked));
    }

    #[tokio::test]
    async fn the_settings_that_are_applied_are_the_ones_read_after_the_system_answered() {
        let fixture = fixture(Availability::Available).await;
        fixture.guard.publish(&signed_out());
        fixture.guard.publish(&signed_in(false));
        fixture.state.set(Some(true), None);
        let read = AtomicUsize::new(0);

        let view = fixture
            .guard
            .adopt(|| {
                read.fetch_add(1, Ordering::SeqCst);
                settings_view(false, None)
            })
            .await;

        assert_eq!(read.load(Ordering::SeqCst), 1);
        assert!(!view.require_unlock.value);
        fixture.guard.sample();
        assert!(!fixture.guard.is_locked());
    }

    /// Answers a prompt only when the test says so, and counts the prompts.
    struct Gated {
        opened: AtomicUsize,
        release: tokio::sync::Notify,
    }

    impl Authenticator for Arc<Gated> {
        async fn available(&self) -> Availability {
            Availability::Available
        }

        async fn confirm(&self, _reason: &str) -> Confirmation {
            self.opened.fetch_add(1, Ordering::SeqCst);
            self.release.notified().await;
            Confirmation::Confirmed
        }
    }

    #[tokio::test]
    async fn a_second_unlock_waits_for_the_open_prompt_and_gets_its_outcome() {
        let gate = Arc::new(Gated {
            opened: AtomicUsize::new(0),
            release: tokio::sync::Notify::new(),
        });
        let state = Arc::new(ScriptedState::default());
        state.set(Some(false), None);
        let guard = Arc::new(Guard::new(
            Arc::new(Arc::new(Windows::default())),
            state.clone(),
            gate.clone(),
        ));
        guard.adopt(|| settings_view(true, None)).await;
        guard.publish(&signed_out());
        guard.publish(&signed_in(false));
        state.set(Some(true), None);
        guard.sample();

        let first = tokio::spawn({
            let guard = guard.clone();
            async move { guard.unlock().await }
        });
        tokio::task::yield_now().await;
        let second = tokio::spawn({
            let guard = guard.clone();
            async move { guard.unlock().await }
        });
        tokio::task::yield_now().await;
        assert_eq!(gate.opened.load(Ordering::SeqCst), 1);

        gate.release.notify_one();

        assert_eq!(first.await.unwrap(), Ok(signed_in(false)));
        assert_eq!(second.await.unwrap(), Ok(signed_in(false)));
        assert_eq!(gate.opened.load(Ordering::SeqCst), 1);
    }
}
