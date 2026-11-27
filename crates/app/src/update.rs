//! Looking for a newer version of the application, telling the person about it, and installing it when the person
//! chooses to.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use im_core::AppInfo;
use im_core::session::Session;
use im_core::update::{due, newer};
use jiff::Timestamp;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::certificates::Ilm;
use crate::mode::Mode;
use crate::settings::Settings;
use crate::{session, tray};

/// How often the loop looks at whether a check is due: the first check is made after one turn, and a person who
/// turns updates on is not kept waiting for long.
const TURN: Duration = Duration::from_secs(60);

/// How long a check may take before it is given up.
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the download may take before it is given up, so that sends to ILM are not held for ever.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10 * 60);

type Boxed<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A version of the application that can be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub version: String,
}

/// Where updates come from. Errors say what went wrong in a few plain words, never where or with what.
pub trait Updates: Send + Sync {
    /// The version on offer, or none when the running one is the latest.
    fn check(&self) -> Boxed<'_, Result<Option<Offer>, String>>;
    /// Downloads and installs `version` if the last check offered it when this is called, then restarts the
    /// application.
    fn install(&self, version: &str) -> Boxed<'_, Result<(), String>>;
}

/// What the updater changes around it.
pub trait Host: Send + Sync {
    /// Whether the person or the organization has automatic updates on.
    fn enabled(&self) -> bool;
    /// Shows the version that can be installed, or none, in the tray.
    fn offered(&self, version: Option<&str>);
    /// Tells the person that `version` can be installed.
    fn available(&self, version: &str);
    /// Tells the person that the update could not be installed.
    fn failed(&self);
    /// Runs `install` while nothing is being sent to ILM, and keeps sends waiting until it has ended.
    fn exclusive<'a>(
        &'a self,
        install: Boxed<'a, Result<(), String>>,
    ) -> Boxed<'a, Result<(), String>>;
}

/// Whether updates are looked for: never in self-check mode, in debug builds or on Linux, where the package
/// manager updates the application.
pub fn applies(self_check: bool, debug_build: bool, linux: bool) -> bool {
    !self_check && !debug_build && !linux
}

/// The log line for the result of a check.
fn offer_line(current: &str, offered: Option<&str>) -> String {
    match offered {
        Some(offered) => format!("update {offered} offered, running {current}"),
        None => "no update offered".to_owned(),
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Checks on a schedule, remembers what is on offer, and installs it on request.
pub struct Updater {
    updates: Arc<dyn Updates>,
    host: Arc<dyn Host>,
    current: String,
    now: Box<dyn Fn() -> Timestamp + Send + Sync>,
    /// When the last check was made; kept in memory only.
    last: Mutex<Option<Timestamp>>,
    /// The version on offer that is newer than the running one.
    offered: Mutex<Option<String>>,
    installing: AtomicBool,
}

impl Updater {
    pub fn new(updates: Arc<dyn Updates>, host: Arc<dyn Host>, current: &str) -> Self {
        Self {
            updates,
            host,
            current: current.to_owned(),
            now: Box::new(Timestamp::now),
            last: Mutex::new(None),
            offered: Mutex::new(None),
            installing: AtomicBool::new(false),
        }
    }

    /// Takes one turn after another for as long as the application runs.
    pub async fn run(&self) {
        loop {
            tokio::time::sleep(TURN).await;
            self.turn().await;
        }
    }

    async fn turn(&self) {
        let enabled = self.host.enabled();
        if !enabled {
            self.withdraw();
            return;
        }
        if self.installing.load(Ordering::SeqCst) {
            return;
        }
        let now = (self.now)();
        if !due(now, *lock(&self.last), enabled) {
            return;
        }
        *lock(&self.last) = Some(now);
        log::info!("checking for an update");
        let answer = self.updates.check().await;
        if !self.host.enabled() {
            self.withdraw();
            return;
        }
        match answer {
            Ok(Some(offer)) if newer(&self.current, &offer.version) => {
                log::info!("{}", offer_line(&self.current, Some(&offer.version)));
                self.offer(offer.version);
            }
            Ok(other) => {
                log::info!(
                    "{}",
                    offer_line(&self.current, other.as_ref().map(|o| o.version.as_str()))
                );
                self.withdraw();
            }
            Err(kind) => log::warn!("the check for an update failed: {kind}"),
        }
    }

    fn offer(&self, version: String) {
        let previous = lock(&self.offered).replace(version.clone());
        if previous.as_ref() != Some(&version) {
            self.host.offered(Some(&version));
            self.host.available(&version);
        }
    }

    fn withdraw(&self) {
        if lock(&self.offered).take().is_some() {
            self.host.offered(None);
        }
    }

    /// Installs the version on offer once nothing is being sent to ILM, and restarts. Does nothing while updates
    /// are off, no version is on offer or an installation is already running. When it fails, the person is told
    /// and the application keeps running.
    pub async fn install(&self) {
        if !self.host.enabled() {
            return;
        }
        let Some(version) = lock(&self.offered).clone() else {
            return;
        };
        if self.installing.swap(true, Ordering::SeqCst) {
            return;
        }
        log::info!("installing update {version}");
        let install = self.updates.install(&version);
        let installed = self.host.exclusive(Box::pin(async move {
            if !self.host.enabled() {
                log::info!("updates were turned off before the installation started");
                return Ok(());
            }
            install.await
        }));
        if let Err(kind) = installed.await {
            log::warn!("the update could not be installed: {kind}");
            self.host.failed();
        }
        self.installing.store(false, Ordering::SeqCst);
    }
}

fn check_failed(error: &tauri_plugin_updater::Error) -> &'static str {
    use tauri_plugin_updater::Error;
    match error {
        Error::Reqwest(_)
        | Error::Network(_)
        | Error::ReleaseNotFound
        | Error::TargetNotFound(_)
        | Error::TargetsNotFound(_) => "the update server could not be read",
        _ => "the answer of the update server could not be used",
    }
}

fn install_failed(error: &tauri_plugin_updater::Error) -> &'static str {
    use tauri_plugin_updater::Error;
    match error {
        Error::Reqwest(_) | Error::Network(_) => "the update could not be downloaded",
        Error::Minisign(_)
        | Error::Base64(_)
        | Error::SignatureUtf8(_)
        | Error::MissingSignedVersion
        | Error::SignedVersionMismatch { .. } => "the signature of the update was refused",
        _ => "the update could not be put in place",
    }
}

/// The updater of Tauri, which keeps what the last check offered for the installation.
pub struct SystemUpdates<R: Runtime> {
    app: AppHandle<R>,
    found: Mutex<Option<Update>>,
}

impl<R: Runtime> SystemUpdates<R> {
    pub fn new(app: &AppHandle<R>) -> Self {
        Self {
            app: app.clone(),
            found: Mutex::new(None),
        }
    }
}

impl<R: Runtime> Updates for SystemUpdates<R> {
    fn check(&self) -> Boxed<'_, Result<Option<Offer>, String>> {
        Box::pin(async {
            let updater = self
                .app
                .updater_builder()
                .timeout(CHECK_TIMEOUT)
                .build()
                .map_err(|e| check_failed(&e))?;
            let found = updater.check().await.map_err(|e| check_failed(&e))?;
            let offer = found.as_ref().map(|update| Offer {
                version: update.version.clone(),
            });
            *lock(&self.found) = found;
            Ok(offer)
        })
    }

    fn install(&self, version: &str) -> Boxed<'_, Result<(), String>> {
        let found = lock(&self.found)
            .clone()
            .filter(|update| update.version == version);
        Box::pin(async move {
            let mut update = found.ok_or("the update on offer changed".to_owned())?;
            update.timeout = Some(DOWNLOAD_TIMEOUT);
            update
                .download_and_install(|_, _| {}, || {})
                .await
                .map_err(|e| install_failed(&e))?;
            log::info!("restarting after the update");
            self.app.restart()
        })
    }
}

/// The application around the updater: the settings, the tray, the notifications and the session.
pub struct SystemHost<R: Runtime> {
    app: AppHandle<R>,
    session: Option<Arc<Session>>,
}

impl<R: Runtime> SystemHost<R> {
    pub fn new(app: &AppHandle<R>) -> Self {
        Self {
            app: app.clone(),
            session: session::shared(app),
        }
    }
}

impl<R: Runtime> Host for SystemHost<R> {
    fn enabled(&self) -> bool {
        self.app
            .state::<Arc<Settings>>()
            .view()
            .automatic_updates
            .value
    }

    fn offered(&self, version: Option<&str>) {
        tray::set_update(&self.app, version.map(str::to_owned));
    }

    fn available(&self, version: &str) {
        self.app
            .state::<Arc<Ilm<R>>>()
            .notices()
            .update_available(version);
    }

    fn failed(&self) {
        self.app.state::<Arc<Ilm<R>>>().notices().update_failed();
    }

    fn exclusive<'a>(
        &'a self,
        install: Boxed<'a, Result<(), String>>,
    ) -> Boxed<'a, Result<(), String>> {
        Box::pin(async move {
            let _sends = match &self.session {
                Some(session) => Some(session.hold_sends().await),
                None => None,
            };
            install.await
        })
    }
}

/// Starts looking for updates, where that applies.
pub fn start<R: Runtime>(app: &AppHandle<R>, mode: Mode) {
    if !applies(
        mode == Mode::SelfCheck,
        cfg!(debug_assertions),
        cfg!(target_os = "linux"),
    ) {
        return;
    }
    let updater = Arc::new(Updater::new(
        Arc::new(SystemUpdates::new(app)),
        Arc::new(SystemHost::new(app)),
        AppInfo::current().version,
    ));
    app.manage(updater.clone());
    tauri::async_runtime::spawn(async move { updater.run().await });
}

/// Installs the update on offer, as the person chose in the tray.
pub fn install<R: Runtime>(app: &AppHandle<R>) {
    let Some(updater) = app.try_state::<Arc<Updater>>() else {
        return;
    };
    let updater = updater.inner().clone();
    tauri::async_runtime::spawn(async move { updater.install().await });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    use jiff::SignedDuration;
    use tokio::time::{Instant, sleep};

    struct Scripted {
        answer: Mutex<Result<Option<String>, String>>,
        checks: AtomicUsize,
        installed: Mutex<Vec<String>>,
        install_result: Mutex<Result<(), String>>,
        answering: tokio::sync::Mutex<()>,
    }

    impl Scripted {
        fn new(answer: Result<Option<&str>, &str>) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer.map(|v| v.map(str::to_owned)).map_err(str::to_owned)),
                checks: AtomicUsize::new(0),
                installed: Mutex::default(),
                install_result: Mutex::new(Ok(())),
                answering: tokio::sync::Mutex::new(()),
            })
        }

        fn offer(&self, version: Option<&str>) {
            *lock(&self.answer) = Ok(version.map(str::to_owned));
        }

        fn checks(&self) -> usize {
            self.checks.load(Ordering::SeqCst)
        }

        fn installs(&self) -> usize {
            lock(&self.installed).len()
        }
    }

    impl Updates for Arc<Scripted> {
        fn check(&self) -> Boxed<'_, Result<Option<Offer>, String>> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            let answer = lock(&self.answer).clone();
            Box::pin(async move {
                let _answering = self.answering.lock().await;
                answer.map(|version| version.map(|version| Offer { version }))
            })
        }

        fn install(&self, version: &str) -> Boxed<'_, Result<(), String>> {
            let version = version.to_owned();
            Box::pin(async move {
                lock(&self.installed).push(version);
                lock(&self.install_result).clone()
            })
        }
    }

    struct Around {
        enabled: AtomicBool,
        shown: Mutex<VecDeque<Option<String>>>,
        told: Mutex<Vec<String>>,
        failures: AtomicUsize,
        sends: tokio::sync::Mutex<()>,
    }

    impl Around {
        fn new(enabled: bool) -> Arc<Self> {
            Arc::new(Self {
                enabled: AtomicBool::new(enabled),
                shown: Mutex::default(),
                told: Mutex::default(),
                failures: AtomicUsize::new(0),
                sends: tokio::sync::Mutex::new(()),
            })
        }

        fn shown(&self) -> Vec<Option<String>> {
            lock(&self.shown).iter().cloned().collect()
        }

        fn told(&self) -> Vec<String> {
            lock(&self.told).clone()
        }
    }

    impl Host for Arc<Around> {
        fn enabled(&self) -> bool {
            self.enabled.load(Ordering::SeqCst)
        }

        fn offered(&self, version: Option<&str>) {
            lock(&self.shown).push_back(version.map(str::to_owned));
        }

        fn available(&self, version: &str) {
            lock(&self.told).push(version.to_owned());
        }

        fn failed(&self) {
            self.failures.fetch_add(1, Ordering::SeqCst);
        }

        fn exclusive<'a>(
            &'a self,
            install: Boxed<'a, Result<(), String>>,
        ) -> Boxed<'a, Result<(), String>> {
            Box::pin(async move {
                let _sends = self.sends.lock().await;
                install.await
            })
        }
    }

    /// An updater at 0.1.0 whose clock follows the paused time of the test.
    fn updater(updates: &Arc<Scripted>, around: &Arc<Around>) -> Arc<Updater> {
        let mut updater =
            Updater::new(Arc::new(updates.clone()), Arc::new(around.clone()), "0.1.0");
        let start = Instant::now();
        let anchor: Timestamp = "2026-03-02T12:00:00Z".parse().unwrap();
        updater.now = Box::new(move || {
            let elapsed = SignedDuration::try_from(Instant::now() - start).unwrap();
            anchor.checked_add(elapsed).unwrap()
        });
        Arc::new(updater)
    }

    fn running(updater: &Arc<Updater>) {
        let updater = updater.clone();
        tokio::spawn(async move { updater.run().await });
    }

    async fn after(seconds: u64) {
        sleep(Duration::from_secs(seconds)).await;
    }

    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[test]
    fn updates_apply_only_outside_self_check_debug_builds_and_linux() {
        assert!(applies(false, false, false));
        assert!(!applies(true, false, false));
        assert!(!applies(false, true, false));
        assert!(!applies(false, false, true));
    }

    #[test]
    fn the_log_line_names_the_offered_and_the_running_version() {
        assert_eq!(
            offer_line("0.1.0", Some("0.2.0")),
            "update 0.2.0 offered, running 0.1.0"
        );
        assert_eq!(offer_line("0.1.0", None), "no update offered");
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_check_comes_after_a_minute_and_then_one_every_day() {
        let updates = Scripted::new(Ok(None));
        let around = Around::new(true);
        running(&updater(&updates, &around));

        after(59).await;
        assert_eq!(updates.checks(), 0);
        after(2).await;
        assert_eq!(updates.checks(), 1);
        after(23 * 3600).await;
        assert_eq!(updates.checks(), 1);
        after(3600).await;
        assert_eq!(updates.checks(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_checked_while_updates_are_off_and_the_offer_is_withdrawn() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        running(&updater(&updates, &around));
        after(61).await;
        assert_eq!(around.shown(), [Some("0.2.0".to_owned())]);

        around.enabled.store(false, Ordering::SeqCst);
        after(3 * 24 * 3600).await;
        assert_eq!(updates.checks(), 1);
        assert_eq!(around.shown(), [Some("0.2.0".to_owned()), None]);

        around.enabled.store(true, Ordering::SeqCst);
        after(61).await;
        assert_eq!(updates.checks(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_comes_after_updates_were_turned_off_is_dropped() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        let updater = updater(&updates, &around);
        let answering = updates.answering.lock().await;

        let checking = tokio::spawn({
            let updater = updater.clone();
            async move { updater.turn().await }
        });
        settle().await;
        around.enabled.store(false, Ordering::SeqCst);
        drop(answering);
        checking.await.unwrap();

        assert_eq!(updates.checks(), 1);
        assert!(around.shown().is_empty());
        assert!(around.told().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_older_or_the_same_version_is_ignored() {
        let updates = Scripted::new(Ok(Some("0.1.0")));
        let around = Around::new(true);
        running(&updater(&updates, &around));

        after(61).await;
        updates.offer(Some("0.0.9"));
        after(24 * 3600).await;

        assert_eq!(updates.checks(), 2);
        assert!(around.shown().is_empty());
        assert!(around.told().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_version_is_told_once_and_a_newer_one_again() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        running(&updater(&updates, &around));

        after(61).await;
        after(24 * 3600).await;
        assert_eq!(updates.checks(), 2);
        assert_eq!(around.told(), ["0.2.0"]);

        updates.offer(Some("0.3.0"));
        after(24 * 3600).await;
        assert_eq!(around.told(), ["0.2.0", "0.3.0"]);
        assert_eq!(
            around.shown(),
            [Some("0.2.0".to_owned()), Some("0.3.0".to_owned())]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_offer_goes_when_the_next_check_offers_nothing() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        running(&updater(&updates, &around));

        after(61).await;
        updates.offer(None);
        after(24 * 3600).await;

        assert_eq!(around.shown(), [Some("0.2.0".to_owned()), None]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_check_changes_nothing() {
        let updates = Scripted::new(Err("the update server could not be read"));
        let around = Around::new(true);
        running(&updater(&updates, &around));

        after(61).await;

        assert_eq!(updates.checks(), 1);
        assert!(around.shown().is_empty());
        assert_eq!(around.failures.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn installing_waits_for_the_sends_and_a_second_click_does_nothing() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        let updater = updater(&updates, &around);
        updater.turn().await;
        let sending = around.sends.lock().await;

        let first = tokio::spawn({
            let updater = updater.clone();
            async move { updater.install().await }
        });
        settle().await;
        assert_eq!(updates.installs(), 0);
        updater.install().await;

        drop(sending);
        first.await.unwrap();
        assert_eq!(*lock(&updates.installed), ["0.2.0"]);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_installed_once_updates_are_turned_off() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        let updater = updater(&updates, &around);
        updater.turn().await;

        around.enabled.store(false, Ordering::SeqCst);
        updater.install().await;

        assert_eq!(updates.installs(), 0);
        assert_eq!(around.failures.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn an_installation_waiting_for_the_sends_stops_when_updates_are_turned_off() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        let around = Around::new(true);
        let updater = updater(&updates, &around);
        updater.turn().await;
        let sending = around.sends.lock().await;

        let installing = tokio::spawn({
            let updater = updater.clone();
            async move { updater.install().await }
        });
        settle().await;
        around.enabled.store(false, Ordering::SeqCst);
        updater.turn().await;
        assert_eq!(around.shown(), [Some("0.2.0".to_owned()), None]);
        drop(sending);
        installing.await.unwrap();

        assert_eq!(updates.installs(), 0);
        assert_eq!(around.failures.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn nothing_is_installed_without_an_offer() {
        let updates = Scripted::new(Ok(None));
        let around = Around::new(true);
        let updater = updater(&updates, &around);

        updater.turn().await;
        updater.install().await;

        assert_eq!(updates.installs(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_installation_is_told_and_can_be_tried_again() {
        let updates = Scripted::new(Ok(Some("0.2.0")));
        *lock(&updates.install_result) = Err("the signature of the update was refused".to_owned());
        let around = Around::new(true);
        let updater = updater(&updates, &around);
        updater.turn().await;

        updater.install().await;
        updater.install().await;

        assert_eq!(updates.installs(), 2);
        assert_eq!(around.failures.load(Ordering::SeqCst), 2);
        assert_eq!(around.shown(), [Some("0.2.0".to_owned())]);
    }
}
