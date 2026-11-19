//! Keeps a sign-in alive: it reads the profile every 15 minutes, and every minute while ILM cannot be reached.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use im_core::session::{Session, SessionView};
use tokio::time::{Instant, MissedTickBehavior, interval_at};

const CHECK_EVERY: Duration = Duration::from_secs(15 * 60);
const RETRY_EVERY: Duration = Duration::from_secs(60);

/// What the timers need of the session.
pub trait Checks: Send + Sync {
    fn view(&self) -> SessionView;
    fn check(&self) -> impl Future<Output = SessionView> + Send;
    fn retry(&self) -> impl Future<Output = SessionView> + Send;
}

impl Checks for Session {
    fn view(&self) -> SessionView {
        Session::view(self)
    }

    fn check(&self) -> impl Future<Output = SessionView> + Send {
        Session::check(self)
    }

    fn retry(&self) -> impl Future<Output = SessionView> + Send {
        Session::retry(self)
    }
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

/// One check of a signed-in session, or one more try of a saved sign-in that could not be renewed.
pub async fn refresh(checks: &impl Checks) {
    match checks.view() {
        SessionView::SignedIn { .. } => {
            checks.check().await;
        }
        SessionView::Unreachable { .. } => {
            checks.retry().await;
        }
        _ => {}
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
        if unreachable(&view)
            || (matches!(view, SessionView::SignedIn { .. }) && last.elapsed() >= CHECK_EVERY)
        {
            refresh(&*checks).await;
            last = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Scripted {
        view: Mutex<SessionView>,
        checks: AtomicUsize,
        retries: AtomicUsize,
    }

    impl Scripted {
        fn new(view: SessionView) -> Arc<Self> {
            Arc::new(Self {
                view: Mutex::new(view),
                checks: AtomicUsize::new(0),
                retries: AtomicUsize::new(0),
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
            self.view()
        }

        async fn retry(&self) -> SessionView {
            self.retries.fetch_add(1, Ordering::SeqCst);
            self.view()
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
        refresh(&*scripted).await;
        scripted.set(unreachable_at_start());
        refresh(&*scripted).await;
        scripted.set(SessionView::Starting);
        refresh(&*scripted).await;

        assert_eq!(scripted.counts(), (1, 1));
    }
}
