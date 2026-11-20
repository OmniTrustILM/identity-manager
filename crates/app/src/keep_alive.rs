//! Keeps a sign-in alive and the inventory current: each check of the sign-in is followed by one of the inventory.
//! The sign-in is checked as often as the setting says, and every minute while ILM cannot be reached, whether the
//! sign-in or the inventory found out.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use im_core::inventory::Trigger;
use im_core::session::SessionView;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

const RETRY_EVERY: Duration = Duration::from_secs(60);

/// What the timers need of the session and the inventory.
pub trait Checks: Send + Sync {
    fn view(&self) -> SessionView;
    fn check(&self) -> impl Future<Output = SessionView> + Send;
    fn retry(&self) -> impl Future<Output = SessionView> + Send;
    /// How often a signed-in session is checked; read at each tick.
    fn interval(&self) -> Duration;
    fn inventory(&self, trigger: Trigger) -> impl Future<Output = ()> + Send;
    /// Whether the last check of the inventory could not reach ILM.
    fn inventory_unreachable(&self) -> bool;
}

/// Whether ILM could not be reached the last time.
fn unreachable(view: &SessionView) -> bool {
    matches!(
        view,
        SessionView::Unreachable { .. }
            | SessionView::SignedIn {
                unreachable: true,
                ..
            }
    )
}

/// One `renew`; while the person is signed in, the inventory is checked after it.
pub async fn refresh(checks: &impl Checks, trigger: Trigger) {
    if matches!(renew(checks).await, SessionView::SignedIn { .. }) {
        checks.inventory(trigger).await;
    }
}

/// One check of a signed-in session, or one more try of a saved sign-in that could not be renewed; the view after.
pub async fn renew(checks: &impl Checks) -> SessionView {
    match checks.view() {
        SessionView::SignedIn { .. } => checks.check().await,
        SessionView::Unreachable { .. } => checks.retry().await,
        view => view,
    }
}

/// Runs the timers for as long as the application runs.
pub async fn run<C: Checks>(checks: Arc<C>) {
    let mut last = Instant::now();
    let mut ticker = interval_at(last + RETRY_EVERY, RETRY_EVERY);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let view = checks.view();
        let signed_in = matches!(view, SessionView::SignedIn { .. });
        if unreachable(&view)
            || (signed_in
                && (checks.inventory_unreachable() || last.elapsed() >= checks.interval()))
        {
            refresh(&*checks, Trigger::Interval).await;
            last = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Scripted {
        view: Mutex<SessionView>,
        checks: AtomicUsize,
        retries: AtomicUsize,
        minutes: AtomicUsize,
        inventory_down: AtomicBool,
        /// What was asked, in order.
        calls: Mutex<Vec<String>>,
    }

    impl Scripted {
        fn new(view: SessionView) -> Arc<Self> {
            Arc::new(Self {
                view: Mutex::new(view),
                checks: AtomicUsize::new(0),
                retries: AtomicUsize::new(0),
                minutes: AtomicUsize::new(15),
                inventory_down: AtomicBool::new(false),
                calls: Mutex::default(),
            })
        }

        fn set(&self, view: SessionView) {
            *self.view.lock().unwrap() = view;
        }

        fn counts(&self) -> (usize, usize) {
            (
                self.checks.load(Ordering::SeqCst),
                self.retries.load(Ordering::SeqCst),
            )
        }
    }

    impl Checks for Scripted {
        fn view(&self) -> SessionView {
            self.view.lock().unwrap().clone()
        }

        async fn check(&self) -> SessionView {
            self.checks.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().unwrap().push("check".to_owned());
            self.view()
        }

        async fn retry(&self) -> SessionView {
            self.retries.fetch_add(1, Ordering::SeqCst);
            self.calls.lock().unwrap().push("retry".to_owned());
            self.view()
        }

        fn interval(&self) -> Duration {
            Duration::from_secs(self.minutes.load(Ordering::SeqCst) as u64 * 60)
        }

        async fn inventory(&self, trigger: Trigger) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("inventory {trigger}"));
        }

        fn inventory_unreachable(&self) -> bool {
            self.inventory_down.load(Ordering::SeqCst)
        }
    }

    fn signed_in(unreachable: bool) -> SessionView {
        SessionView::SignedIn {
            address: "https://ilm.example.com".to_owned(),
            person: im_core::session::PersonView {
                name: "Ada".to_owned(),
                username: "ada".to_owned(),
            },
            allowed_listings: Vec::new(),
            certificate: None,
            unreachable,
        }
    }

    fn unreachable_at_start() -> SessionView {
        SessionView::Unreachable {
            address: "https://ilm.example.com".to_owned(),
            problem: "offline".to_owned(),
        }
    }

    async fn pass(time: Duration) {
        tokio::time::advance(time).await;
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
    }

    async fn started(view: SessionView) -> Arc<Scripted> {
        let scripted = Scripted::new(view);
        tokio::spawn(run(scripted.clone()));
        pass(Duration::ZERO).await;
        scripted
    }

    #[tokio::test(start_paused = true)]
    async fn a_signed_in_session_is_checked_every_fifteen_minutes() {
        let scripted = started(signed_in(false)).await;

        for _ in 0..14 {
            pass(Duration::from_secs(60)).await;
        }
        assert_eq!(scripted.counts(), (0, 0));

        pass(Duration::from_secs(60)).await;
        assert_eq!(scripted.counts(), (1, 0));

        for _ in 0..15 {
            pass(Duration::from_secs(60)).await;
        }
        assert_eq!(scripted.counts(), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreachable_sign_in_is_checked_every_minute() {
        let scripted = started(signed_in(true)).await;

        for _ in 0..3 {
            pass(Duration::from_secs(60)).await;
        }

        assert_eq!(scripted.counts(), (3, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_signed_in_session_whose_inventory_could_not_reach_ilm_is_checked_every_minute() {
        let scripted = started(signed_in(false)).await;
        scripted.inventory_down.store(true, Ordering::SeqCst);

        for _ in 0..3 {
            pass(Duration::from_secs(60)).await;
        }
        assert_eq!(scripted.counts(), (3, 0));

        scripted.inventory_down.store(false, Ordering::SeqCst);
        pass(Duration::from_secs(60)).await;
        assert_eq!(scripted.counts(), (3, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_saved_sign_in_that_could_not_be_renewed_is_retried_every_minute() {
        let scripted = started(unreachable_at_start()).await;

        pass(Duration::from_secs(60)).await;
        pass(Duration::from_secs(60)).await;
        assert_eq!(scripted.counts(), (0, 2));

        scripted.set(SessionView::Starting);
        pass(Duration::from_secs(60)).await;
        assert_eq!(scripted.counts(), (0, 2));
    }

    #[tokio::test]
    async fn refreshing_checks_or_retries_by_state_and_otherwise_does_nothing() {
        let scripted = Scripted::new(signed_in(false));
        refresh(&*scripted, Trigger::Start).await;
        scripted.set(unreachable_at_start());
        refresh(&*scripted, Trigger::Start).await;
        scripted.set(SessionView::Starting);
        refresh(&*scripted, Trigger::Start).await;

        assert_eq!(scripted.counts(), (1, 1));
    }

    #[tokio::test]
    async fn renewing_returns_the_view_after_a_check_a_retry_or_nothing() {
        let scripted = Scripted::new(signed_in(false));
        assert!(matches!(
            renew(&*scripted).await,
            SessionView::SignedIn { .. }
        ));
        scripted.set(unreachable_at_start());
        assert!(matches!(
            renew(&*scripted).await,
            SessionView::Unreachable { .. }
        ));
        scripted.set(SessionView::Starting);
        assert!(matches!(renew(&*scripted).await, SessionView::Starting));

        assert_eq!(scripted.counts(), (1, 1));
        assert!(
            scripted
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call != "inventory start")
        );
    }

    #[tokio::test]
    async fn the_inventory_is_checked_after_the_session_with_the_trigger_and_only_while_signed_in()
    {
        let scripted = Scripted::new(signed_in(false));
        refresh(&*scripted, Trigger::Start).await;
        scripted.set(unreachable_at_start());
        refresh(&*scripted, Trigger::Interval).await;
        scripted.set(SessionView::Starting);
        refresh(&*scripted, Trigger::Interval).await;

        assert_eq!(
            *scripted.calls.lock().unwrap(),
            ["check", "inventory start", "retry"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_interval_is_read_at_each_tick_so_a_change_applies_without_a_restart() {
        let scripted = started(signed_in(false)).await;
        scripted.minutes.store(5, Ordering::SeqCst);
        for _ in 0..5 {
            pass(Duration::from_secs(60)).await;
        }
        assert_eq!(
            *scripted.calls.lock().unwrap(),
            ["check", "inventory interval"]
        );

        scripted.minutes.store(30, Ordering::SeqCst);
        for _ in 0..29 {
            pass(Duration::from_secs(60)).await;
        }
        assert_eq!(scripted.counts(), (1, 0));
        pass(Duration::from_secs(60)).await;
        assert_eq!(scripted.counts(), (2, 0));
    }
}
