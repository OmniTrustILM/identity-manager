use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use auto_launch::{AutoLaunch, AutoLaunchBuilder, WindowsEnableMode};
use im_core::ilm::IlmUrl;
use im_core::session::{Connection, ConnectionSettings};
use im_core::settings::{self, Change, Layer, LogLevel, SettingsView, store};
use log::LevelFilter;
#[cfg(target_os = "linux")]
use tauri::Manager;
use tauri::{AppHandle, Runtime, State};

/// What the effective settings do to the system.
pub trait Effects: Send + Sync {
    fn set_autostart(&self, on: bool) -> Result<(), String>;
    fn set_log_level(&self, level: LevelFilter);
}

/// The effects on the running system: the login item and the log filter. The login item is absent when it
/// is not applied in this run or could not be built.
pub struct SystemEffects(Option<AutoLaunch>);

impl SystemEffects {
    pub fn new<R: Runtime>(app: &AppHandle<R>, autostart: bool) -> Self {
        if !autostart {
            return Self(None);
        }
        let launcher = launcher(app)
            .inspect_err(|error| log::warn!("start at login is unavailable: {error}"))
            .ok();
        Self(launcher)
    }
}

/// Builds the login item. Its name and path must not change, or login items made by earlier versions stop
/// working. On Windows it is for the current user only: the default mode writes for every user when the
/// process may.
fn launcher<R: Runtime>(app: &AppHandle<R>) -> Result<AutoLaunch, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    #[cfg(target_os = "macos")]
    let exe = exe.canonicalize().map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    let exe = app.env().appimage.map_or(exe, PathBuf::from);
    AutoLaunchBuilder::new()
        .set_app_name(&app.package_info().name)
        .set_app_path(&exe.to_string_lossy())
        .set_windows_enable_mode(WindowsEnableMode::CurrentUser)
        .build()
        .map_err(|error| error.to_string())
}

impl Effects for SystemEffects {
    fn set_autostart(&self, on: bool) -> Result<(), String> {
        let launcher = self.0.as_ref().ok_or("no login item is available")?;
        if launcher.is_enabled().map_err(|error| error.to_string())? == on {
            return Ok(());
        }
        let result = if on {
            launcher.enable()
        } else {
            launcher.disable()
        };
        result.map_err(|error| error.to_string())
    }

    fn set_log_level(&self, level: LevelFilter) {
        log::set_max_level(level);
    }
}

/// Whether the login item is touched: never in self-check mode or in debug builds, so CI runners and
/// development runs do not register one.
pub fn autostart_applies(self_check: bool, debug_build: bool) -> bool {
    !self_check && !debug_build
}

/// The settings of the person and of the organization, and what they change on the system.
pub struct Settings {
    person_file: PathBuf,
    policy: Box<dyn Fn() -> Layer + Send + Sync>,
    effects: Box<dyn Effects>,
    autostart: bool,
    saving: Mutex<()>,
}

impl Settings {
    pub fn new(
        person_file: PathBuf,
        policy: impl Fn() -> Layer + Send + Sync + 'static,
        effects: impl Effects + 'static,
        autostart: bool,
    ) -> Self {
        Settings {
            person_file,
            policy: Box::new(policy),
            effects: Box::new(effects),
            autostart,
            saving: Mutex::new(()),
        }
    }

    fn layers(&self) -> (Layer, Layer) {
        ((self.policy)(), store::load(&self.person_file))
    }

    /// Logs where each setting comes from and brings the system to the effective values.
    pub fn start(&self) {
        let (policy, person) = self.layers();
        for line in start_lines(&policy, &person) {
            log::info!("{line}");
        }
        self.apply_effects(&settings::view(&policy, &person));
    }

    /// The merged settings; the system follows them, so a policy change that arrived while the
    /// application runs takes effect here.
    pub fn view(&self) -> SettingsView {
        let (policy, person) = self.layers();
        let view = settings::view(&policy, &person);
        self.apply_effects(&view);
        view
    }

    pub fn change(&self, change: Change) -> Result<SettingsView, String> {
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let (policy, mut person) = self.layers();
        settings::apply(change, &policy, &mut person).map_err(|locked| {
            log::warn!("refused a change to a setting that policy fixes");
            locked.to_string()
        })?;
        store::save(&self.person_file, &person).map_err(|error| {
            log::error!("the settings could not be saved: {error}");
            format!("The settings could not be saved: {error}")
        })?;
        let view = settings::view(&policy, &person);
        self.apply_effects(&view);
        Ok(view)
    }

    fn apply_effects(&self, view: &SettingsView) {
        self.effects.set_log_level(view.log_level.value.into());
        if !self.autostart {
            log::info!("start at login is not applied in this run");
            return;
        }
        if let Err(error) = self.effects.set_autostart(view.start_at_login.value) {
            log::warn!("start at login could not be applied: {error}");
        }
    }
}

fn level_name(level: LogLevel) -> String {
    LevelFilter::from(level).to_string().to_lowercase()
}

/// One line per setting with its effective value and the layer it comes from.
fn start_lines(policy: &Layer, person: &Layer) -> [String; 3] {
    let view = settings::view(policy, person);
    let [
        (login, login_source),
        (level, level_source),
        (ilm, ilm_source),
    ] = settings::sources(policy, person);
    [
        format!(
            "{login} is {} from {login_source}",
            view.start_at_login.value
        ),
        format!(
            "{level} is {} from {level_source}",
            level_name(view.log_level.value)
        ),
        format!(
            "{ilm} is {} from {ilm_source}",
            view.ilm_url.value.as_deref().unwrap_or("not set")
        ),
    ]
}

impl ConnectionSettings for Settings {
    fn connection(&self) -> Connection {
        let (policy, person) = self.layers();
        Connection {
            locked: policy.ilm_url.is_some(),
            address: policy.ilm_url.or(person.ilm_url),
            provider: policy.sign_in_provider,
        }
    }

    fn save_address(&self, address: &IlmUrl) -> Result<(), String> {
        self.change(Change::IlmUrl(address.clone())).map(|_| ())
    }
}

#[tauri::command]
pub fn settings(state: State<'_, Arc<Settings>>) -> SettingsView {
    state.view()
}

#[tauri::command]
pub fn set_setting(
    state: State<'_, Arc<Settings>>,
    change: Change,
) -> Result<SettingsView, String> {
    state.change(change)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        autostart: Mutex<Vec<bool>>,
        levels: Mutex<Vec<LevelFilter>>,
    }

    struct Stand(Arc<Recorder>);

    impl Effects for Stand {
        fn set_autostart(&self, on: bool) -> Result<(), String> {
            self.0.autostart.lock().unwrap().push(on);
            Ok(())
        }
        fn set_log_level(&self, level: LevelFilter) {
            self.0.levels.lock().unwrap().push(level);
        }
    }

    struct Failing;

    impl Effects for Failing {
        fn set_autostart(&self, _: bool) -> Result<(), String> {
            Err("refused".into())
        }
        fn set_log_level(&self, _: LevelFilter) {}
    }

    fn fixture(policy: Layer, autostart: bool) -> (tempfile::TempDir, Settings, Arc<Recorder>) {
        let folder = tempfile::tempdir().unwrap();
        let recorder = Arc::new(Recorder::default());
        let settings = Settings::new(
            folder.path().join("settings.json"),
            move || policy.clone(),
            Stand(recorder.clone()),
            autostart,
        );
        (folder, settings, recorder)
    }

    fn no_policy() -> Layer {
        Layer::default()
    }

    #[test]
    fn the_view_merges_the_persons_file_with_the_policy() {
        let (folder, settings, _) = fixture(
            Layer {
                log_level: Some(LogLevel::Error),
                ..Layer::default()
            },
            true,
        );
        std::fs::write(
            folder.path().join("settings.json"),
            r#"{"startAtLogin": false, "logLevel": "debug"}"#,
        )
        .unwrap();

        let view = settings.view();

        assert!(!view.start_at_login.value && !view.start_at_login.locked);
        assert_eq!(view.log_level.value, LogLevel::Error);
        assert!(view.log_level.locked);
    }

    #[test]
    fn policy_is_read_on_every_call() {
        let folder = tempfile::tempdir().unwrap();
        let on = Arc::new(Mutex::new(false));
        let reader = on.clone();
        let settings = Settings::new(
            folder.path().join("settings.json"),
            move || Layer {
                start_at_login: reader.lock().unwrap().then_some(false),
                ..Layer::default()
            },
            Stand(Arc::default()),
            true,
        );
        assert!(!settings.view().start_at_login.locked);
        *on.lock().unwrap() = true;
        assert!(settings.view().start_at_login.locked);
    }

    #[test]
    fn a_policy_that_arrives_while_running_reaches_the_effects_not_the_file() {
        let folder = tempfile::tempdir().unwrap();
        let policy = Arc::new(Mutex::new(Layer::default()));
        let reader = policy.clone();
        let recorder = Arc::new(Recorder::default());
        let settings = Settings::new(
            folder.path().join("settings.json"),
            move || reader.lock().unwrap().clone(),
            Stand(recorder.clone()),
            true,
        );
        settings.view();
        *policy.lock().unwrap() = Layer {
            start_at_login: Some(false),
            log_level: Some(LogLevel::Error),
            ..Layer::default()
        };

        settings.view();

        assert_eq!(*recorder.autostart.lock().unwrap(), [true, false]);
        assert_eq!(
            *recorder.levels.lock().unwrap(),
            [LevelFilter::Info, LevelFilter::Error]
        );
        assert!(!folder.path().join("settings.json").exists());
    }

    #[test]
    fn a_change_is_saved_and_applied() {
        let (folder, settings, recorder) = fixture(no_policy(), true);

        let view = settings
            .change(Change::LogLevel(LogLevel::Debug))
            .expect("the change is accepted");

        assert_eq!(view.log_level.value, LogLevel::Debug);
        let saved = store::load(&folder.path().join("settings.json"));
        assert_eq!(saved.log_level, Some(LogLevel::Debug));
        assert_eq!(*recorder.levels.lock().unwrap(), [LevelFilter::Debug]);
        assert_eq!(*recorder.autostart.lock().unwrap(), [true]);
    }

    #[test]
    fn an_address_change_is_saved() {
        let (folder, settings, _) = fixture(no_policy(), true);

        let view = settings
            .change(Change::IlmUrl(IlmUrl::parse("ilm.example.com").unwrap()))
            .expect("the change is accepted");

        assert_eq!(
            view.ilm_url.value.as_deref(),
            Some("https://ilm.example.com")
        );
        let saved = store::load(&folder.path().join("settings.json"));
        assert_eq!(saved.ilm_url, IlmUrl::parse("ilm.example.com").ok());
    }

    #[test]
    fn a_locked_change_is_refused_and_nothing_is_saved() {
        let (folder, settings, recorder) = fixture(
            Layer {
                start_at_login: Some(false),
                ..Layer::default()
            },
            true,
        );

        let error = settings
            .change(Change::StartAtLogin(true))
            .expect_err("policy fixes the setting");

        assert_eq!(error, "Start at login is managed by your organization.");
        assert!(!folder.path().join("settings.json").exists());
        assert!(recorder.autostart.lock().unwrap().is_empty());
    }

    #[test]
    fn a_save_failure_is_returned_and_nothing_is_applied() {
        let folder = tempfile::tempdir().unwrap();
        let blocker = folder.path().join("blocker");
        std::fs::write(&blocker, "").unwrap();
        let recorder = Arc::new(Recorder::default());
        let settings = Settings::new(
            blocker.join("settings.json"),
            Layer::default,
            Stand(recorder.clone()),
            true,
        );

        let error = settings
            .change(Change::StartAtLogin(false))
            .expect_err("the folder cannot be created");

        assert!(error.starts_with("The settings could not be saved"));
        assert!(recorder.levels.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failing_autostart_does_not_fail_the_change() {
        let folder = tempfile::tempdir().unwrap();
        let settings = Settings::new(
            folder.path().join("settings.json"),
            Layer::default,
            Failing,
            true,
        );
        assert!(settings.change(Change::StartAtLogin(false)).is_ok());
    }

    #[test]
    fn start_applies_the_effective_values_once() {
        let (_folder, settings, recorder) = fixture(no_policy(), true);

        settings.start();

        assert_eq!(*recorder.autostart.lock().unwrap(), [true]);
        assert_eq!(*recorder.levels.lock().unwrap(), [LevelFilter::Info]);
    }

    #[test]
    fn autostart_is_skipped_but_the_log_level_applies() {
        let (_folder, settings, recorder) = fixture(no_policy(), false);

        settings.start();
        settings.change(Change::LogLevel(LogLevel::Warn)).unwrap();

        assert!(recorder.autostart.lock().unwrap().is_empty());
        assert_eq!(
            *recorder.levels.lock().unwrap(),
            [LevelFilter::Info, LevelFilter::Warn]
        );
    }

    #[test]
    fn the_connection_follows_policy_then_the_person() {
        use im_core::session::{Connection, ConnectionSettings};
        let policy = Layer {
            sign_in_provider: Some("Corporate".into()),
            ..Layer::default()
        };
        let (_folder, settings, _) = fixture(policy, true);
        assert_eq!(
            settings.connection(),
            Connection {
                address: None,
                locked: false,
                provider: Some("Corporate".into())
            }
        );

        let address = IlmUrl::parse("ilm.example.com").unwrap();
        settings.save_address(&address).unwrap();
        assert_eq!(settings.connection().address, Some(address));

        let (_folder, locked, _) = fixture(
            Layer {
                ilm_url: IlmUrl::parse("policy.example.com").ok(),
                ..Layer::default()
            },
            true,
        );
        let connection = locked.connection();
        assert!(connection.locked);
        assert_eq!(connection.address, IlmUrl::parse("policy.example.com").ok());
        assert!(
            locked
                .save_address(&IlmUrl::parse("ilm.example.com").unwrap())
                .is_err()
        );
    }

    #[test]
    fn autostart_applies_only_outside_self_check_and_debug_builds() {
        assert!(autostart_applies(false, false));
        assert!(!autostart_applies(true, false));
        assert!(!autostart_applies(false, true));
        assert!(!autostart_applies(true, true));
    }

    #[test]
    fn the_start_lines_name_each_value_and_layer() {
        let policy = Layer {
            log_level: Some(LogLevel::Warn),
            ..Layer::default()
        };
        let person = Layer {
            start_at_login: Some(false),
            ilm_url: IlmUrl::parse("ilm.example.com").ok(),
            ..Layer::default()
        };

        assert_eq!(
            start_lines(&policy, &person),
            [
                "StartAtLogin is false from person".to_string(),
                "LogLevel is warn from policy".to_string(),
                "IlmUrl is https://ilm.example.com from person".to_string()
            ]
        );
        assert_eq!(
            start_lines(&Layer::default(), &Layer::default())[0],
            "StartAtLogin is true from default"
        );
    }
}
