//! The settings model: built-in defaults, the person's choices and the organization's policy.

pub mod store;

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::identity::Fingerprint;
use crate::ilm::IlmUrl;
use crate::keys::{Offer, Storage};

/// How much the application writes to its log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "lowercase")
)]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
        }
    }
}

/// Which way of signing in the organization allows; no value allows both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignInMethod {
    Oauth,
    Certificate,
}

impl SignInMethod {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "oauth" => Some(Self::Oauth),
            "certificate" => Some(Self::Certificate),
            _ => None,
        }
    }
}

/// The key storage a policy name stands for.
pub fn parse_storage(text: &str) -> Option<Storage> {
    match text.trim() {
        "keychain" => Some(Storage::Keychain),
        "software" => Some(Storage::Software),
        "tpm" => Some(Storage::Tpm),
        _ => None,
    }
}

/// Minutes without input after which the application locks: a whole number from 1 to 1440.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "i64")]
pub struct IdleMinutes(u16);

impl IdleMinutes {
    pub fn new(minutes: i64) -> Option<Self> {
        match u16::try_from(minutes) {
            Ok(minutes @ 1..=1440) => Some(Self(minutes)),
            _ => None,
        }
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<i64> for IdleMinutes {
    type Error = String;

    fn try_from(minutes: i64) -> Result<Self, Self::Error> {
        Self::new(minutes).ok_or_else(|| format!("{minutes} is not from 1 to 1440 minutes"))
    }
}

/// Minutes between two checks with ILM: a whole number from 5 to 1440. The person chooses among
/// [`CheckMinutes::OPTIONS`]; policy may set any value in the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckMinutes(u16);

impl CheckMinutes {
    pub const OPTIONS: [u16; 4] = [5, 15, 30, 60];

    /// Any whole number of minutes from 5 to 1440.
    pub fn new(minutes: i64) -> Option<Self> {
        match u16::try_from(minutes) {
            Ok(minutes @ 5..=1440) => Some(Self(minutes)),
            _ => None,
        }
    }

    /// One of the minutes the person can choose.
    pub fn option(minutes: i64) -> Option<Self> {
        Self::new(minutes).filter(|minutes| Self::OPTIONS.contains(&minutes.0))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for CheckMinutes {
    fn default() -> Self {
        Self(DEFAULT_CHECK_EVERY)
    }
}

impl<'de> Deserialize<'de> for CheckMinutes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let minutes = i64::deserialize(deserializer)?;
        Self::option(minutes).ok_or_else(|| {
            serde::de::Error::custom(format!("{minutes} is not one of 5, 15, 30 or 60 minutes"))
        })
    }
}

/// Days before expiry from which a certificate counts as expiring: a whole number from 1 to 365. The person chooses
/// among [`WarnDays::OPTIONS`]; policy may set any value in the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WarnDays(u16);

impl WarnDays {
    pub const OPTIONS: [u16; 5] = [7, 14, 30, 60, 90];

    /// Any whole number of days from 1 to 365.
    pub fn new(days: i64) -> Option<Self> {
        match u16::try_from(days) {
            Ok(days @ 1..=365) => Some(Self(days)),
            _ => None,
        }
    }

    /// One of the days the person can choose.
    pub fn option(days: i64) -> Option<Self> {
        Self::new(days).filter(|days| Self::OPTIONS.contains(&days.0))
    }

    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for WarnDays {
    fn default() -> Self {
        Self(DEFAULT_WARN_DAYS)
    }
}

impl<'de> Deserialize<'de> for WarnDays {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let days = i64::deserialize(deserializer)?;
        Self::option(days).ok_or_else(|| {
            serde::de::Error::custom(format!("{days} is not one of 7, 14, 30, 60 or 90 days"))
        })
    }
}

/// Whether certificates renew themselves, and with which key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum AutomaticRenewal {
    Off,
    /// A new key for each renewal.
    #[default]
    NewKey,
    /// The key the certificate already has.
    SameKey,
}

impl AutomaticRenewal {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "off" => Some(Self::Off),
            "newKey" => Some(Self::NewKey),
            "sameKey" => Some(Self::SameKey),
            _ => None,
        }
    }
}

/// The certificate last used to sign in, with the ILM address it signed in to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberedCertificate {
    pub ilm: IlmUrl,
    pub fingerprint: Fingerprint,
}

/// The settings one source sets; a missing value leaves the setting to the next layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub start_at_login: Option<bool>,
    pub automatic_updates: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub ilm_url: Option<IlmUrl>,
    pub require_unlock: Option<bool>,
    pub lock_after_idle: Option<IdleMinutes>,
    pub check_every: Option<CheckMinutes>,
    pub warn_days: Option<WarnDays>,
    pub automatic_renewal: Option<AutomaticRenewal>,
    /// Which sign-in provider to use; only policy sets it.
    pub sign_in_provider: Option<String>,
    /// Which way of signing in is allowed; only policy sets it.
    pub sign_in_method: Option<SignInMethod>,
    /// The key storages the organization offers for new keys; only policy sets it.
    pub key_storages: Option<Vec<Storage>>,
    /// The key storage preselected for new keys; only policy sets it.
    pub default_key_storage: Option<Storage>,
    /// Whether a certificate that ILM prepared is completed without asking; only policy sets it.
    pub complete_prepared: Option<bool>,
    /// The RA Profiles people may request certificates from; only policy sets it.
    pub request_profiles: Option<Vec<String>>,
    /// The RA Profile the sign-in certificate is requested from; only policy sets it.
    pub sign_in_certificate_profile: Option<String>,
    /// The certificate last used to sign in; only the person's layer holds it.
    pub sign_in_certificate: Option<RememberedCertificate>,
}

/// Where an effective value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Default,
    Person,
    Policy,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Source::Default => "default",
            Source::Person => "person",
            Source::Policy => "policy",
        })
    }
}

/// An effective value and whether policy fixes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct Entry<T> {
    pub value: T,
    pub locked: bool,
}

/// Whether the system can ask the person to unlock the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum Unlock {
    Available,
    /// The system could ask, but the person has not set up a password, Touch ID or Windows Hello.
    NotSetUp,
    Unsupported,
}

/// Every setting as the interface shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub struct SettingsView {
    pub start_at_login: Entry<bool>,
    pub automatic_updates: Entry<bool>,
    pub log_level: Entry<LogLevel>,
    pub ilm_url: Entry<Option<String>>,
    pub require_unlock: Entry<bool>,
    pub lock_after_idle: Entry<Option<u16>>,
    /// Minutes between two checks with ILM.
    pub check_every: Entry<u16>,
    /// Days before expiry from which a certificate counts as expiring.
    pub warn_days: Entry<u16>,
    pub automatic_renewal: Entry<AutomaticRenewal>,
    /// What the system can do; the settings do not know it, so `view` says unsupported until the application
    /// reads the system.
    pub unlock: Unlock,
}

/// One setting changed by the person.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "key", content = "value", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, tag = "key", content = "value", rename_all = "camelCase")
)]
pub enum Change {
    StartAtLogin(bool),
    AutomaticUpdates(bool),
    LogLevel(LogLevel),
    IlmUrl(#[cfg_attr(any(test, feature = "ts"), ts(as = "String"))] IlmUrl),
    RequireUnlock(bool),
    LockAfterIdle(
        #[cfg_attr(any(test, feature = "ts"), ts(as = "Option<u16>"))] Option<IdleMinutes>,
    ),
    CheckEvery(#[cfg_attr(any(test, feature = "ts"), ts(as = "u16"))] CheckMinutes),
    WarnDays(#[cfg_attr(any(test, feature = "ts"), ts(as = "u16"))] WarnDays),
    AutomaticRenewal(AutomaticRenewal),
}

/// A change to a setting that policy fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Locked(&'static str);

impl fmt::Display for Locked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is managed by your organization.", self.0)
    }
}

impl std::error::Error for Locked {}

const DEFAULT_START_AT_LOGIN: bool = true;
const DEFAULT_AUTOMATIC_UPDATES: bool = true;
const DEFAULT_REQUIRE_UNLOCK: bool = true;
const DEFAULT_CHECK_EVERY: u16 = 15;
const DEFAULT_WARN_DAYS: u16 = 30;

fn resolve<T: Copy>(policy: Option<T>, person: Option<T>, default: T) -> (T, Source) {
    match (policy, person) {
        (Some(value), _) => (value, Source::Policy),
        (None, Some(value)) => (value, Source::Person),
        (None, None) => (default, Source::Default),
    }
}

fn entry<T>((value, source): (T, Source)) -> Entry<T> {
    Entry {
        value,
        locked: source == Source::Policy,
    }
}

fn start_at_login(policy: &Layer, person: &Layer) -> (bool, Source) {
    resolve(
        policy.start_at_login,
        person.start_at_login,
        DEFAULT_START_AT_LOGIN,
    )
}

fn automatic_updates(policy: &Layer, person: &Layer) -> (bool, Source) {
    resolve(
        policy.automatic_updates,
        person.automatic_updates,
        DEFAULT_AUTOMATIC_UPDATES,
    )
}

fn log_level(policy: &Layer, person: &Layer) -> (LogLevel, Source) {
    resolve(policy.log_level, person.log_level, LogLevel::default())
}

fn ilm_url<'a>(policy: &'a Layer, person: &'a Layer) -> (Option<&'a IlmUrl>, Source) {
    match (&policy.ilm_url, &person.ilm_url) {
        (Some(url), _) => (Some(url), Source::Policy),
        (None, Some(url)) => (Some(url), Source::Person),
        (None, None) => (None, Source::Default),
    }
}

fn require_unlock(policy: &Layer, person: &Layer) -> (bool, Source) {
    resolve(
        policy.require_unlock,
        person.require_unlock,
        DEFAULT_REQUIRE_UNLOCK,
    )
}

fn lock_after_idle(policy: &Layer, person: &Layer) -> (Option<IdleMinutes>, Source) {
    match (policy.lock_after_idle, person.lock_after_idle) {
        (Some(minutes), _) => (Some(minutes), Source::Policy),
        (None, Some(minutes)) => (Some(minutes), Source::Person),
        (None, None) => (None, Source::Default),
    }
}

fn check_every(policy: &Layer, person: &Layer) -> (CheckMinutes, Source) {
    resolve(
        policy.check_every,
        person.check_every,
        CheckMinutes::default(),
    )
}

/// How often the application checks ILM, policy over the person's choice over the default.
pub fn check_interval(policy: &Layer, person: &Layer) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(check_every(policy, person).0.get()) * 60)
}

fn warn_days_of(policy: &Layer, person: &Layer) -> (WarnDays, Source) {
    resolve(policy.warn_days, person.warn_days, WarnDays::default())
}

/// How many days before expiry a certificate counts as expiring, policy over the person's choice over the default.
pub fn warn_days(policy: &Layer, person: &Layer) -> WarnDays {
    warn_days_of(policy, person).0
}

fn automatic_renewal_of(policy: &Layer, person: &Layer) -> (AutomaticRenewal, Source) {
    resolve(
        policy.automatic_renewal,
        person.automatic_renewal,
        AutomaticRenewal::default(),
    )
}

/// Whether and how certificates renew themselves, policy over the person's choice over the default.
pub fn automatic_renewal(policy: &Layer, person: &Layer) -> AutomaticRenewal {
    automatic_renewal_of(policy, person).0
}

/// Whether policy completes a certificate that ILM prepared without asking.
pub fn complete_prepared(policy: &Layer) -> bool {
    policy.complete_prepared.unwrap_or(false)
}

/// The names of the RA Profiles policy lets people request from; none when policy names none.
pub fn request_profiles(policy: &Layer) -> &[String] {
    policy.request_profiles.as_deref().unwrap_or_default()
}

/// The name of the RA Profile policy sets for the sign-in certificate, if any.
pub fn sign_in_certificate_profile(policy: &Layer) -> Option<&str> {
    policy.sign_in_certificate_profile.as_deref()
}

/// The offers policy allows, in their order, and the storage to preselect: the policy default when
/// it is allowed, else the first allowed one.
pub fn allowed_offers(offers: Vec<Offer>, policy: &Layer) -> (Vec<Offer>, Option<Storage>) {
    let allowed: Vec<Offer> = offers
        .into_iter()
        .filter(|offer| {
            policy
                .key_storages
                .as_ref()
                .is_none_or(|storages| storages.contains(&offer.storage))
        })
        .collect();
    let preselected = policy
        .default_key_storage
        .filter(|wanted| allowed.iter().any(|offer| offer.storage == *wanted))
        .or_else(|| allowed.first().map(|offer| offer.storage));
    (allowed, preselected)
}

/// Merges the layers: policy over the person's choice over the default.
pub fn view(policy: &Layer, person: &Layer) -> SettingsView {
    SettingsView {
        start_at_login: entry(start_at_login(policy, person)),
        automatic_updates: entry(automatic_updates(policy, person)),
        log_level: entry(log_level(policy, person)),
        ilm_url: entry({
            let (url, source) = ilm_url(policy, person);
            (url.map(ToString::to_string), source)
        }),
        require_unlock: entry(require_unlock(policy, person)),
        lock_after_idle: entry({
            let (minutes, source) = lock_after_idle(policy, person);
            (minutes.map(IdleMinutes::get), source)
        }),
        check_every: entry({
            let (minutes, source) = check_every(policy, person);
            (minutes.get(), source)
        }),
        warn_days: entry({
            let (days, source) = warn_days_of(policy, person);
            (days.get(), source)
        }),
        automatic_renewal: entry(automatic_renewal_of(policy, person)),
        unlock: Unlock::Unsupported,
    }
}

/// The layer each effective value comes from, by setting name.
pub fn sources(policy: &Layer, person: &Layer) -> [(&'static str, Source); 4] {
    [
        ("StartAtLogin", start_at_login(policy, person).1),
        ("LogLevel", log_level(policy, person).1),
        ("IlmUrl", ilm_url(policy, person).1),
        ("AutomaticUpdates", automatic_updates(policy, person).1),
    ]
}

/// Stores a change in the person's layer unless policy fixes that setting.
pub fn apply(change: Change, policy: &Layer, person: &mut Layer) -> Result<(), Locked> {
    match change {
        Change::StartAtLogin(value) => {
            if policy.start_at_login.is_some() {
                return Err(Locked("Start at login"));
            }
            person.start_at_login = Some(value);
        }
        Change::AutomaticUpdates(value) => {
            if policy.automatic_updates.is_some() {
                return Err(Locked("Automatic updates"));
            }
            person.automatic_updates = Some(value);
        }
        Change::LogLevel(value) => {
            if policy.log_level.is_some() {
                return Err(Locked("Log level"));
            }
            person.log_level = Some(value);
        }
        Change::IlmUrl(value) => {
            if policy.ilm_url.is_some() {
                return Err(Locked("ILM address"));
            }
            person.ilm_url = Some(value);
        }
        Change::RequireUnlock(value) => {
            if policy.require_unlock.is_some() {
                return Err(Locked("Require unlock"));
            }
            person.require_unlock = Some(value);
        }
        Change::LockAfterIdle(value) => {
            if policy.lock_after_idle.is_some() {
                return Err(Locked("Lock after idle"));
            }
            person.lock_after_idle = value;
        }
        Change::CheckEvery(value) => {
            if policy.check_every.is_some() {
                return Err(Locked("Check ILM every"));
            }
            log::info!("the ILM check interval is now {} minutes", value.get());
            person.check_every = Some(value);
        }
        Change::WarnDays(value) => {
            if policy.warn_days.is_some() {
                return Err(Locked("Expiry warning"));
            }
            log::info!("the expiry warning is now {} days", value.get());
            person.warn_days = Some(value);
        }
        Change::AutomaticRenewal(value) => {
            if policy.automatic_renewal.is_some() {
                return Err(Locked("Automatic renewal"));
            }
            log::info!("automatic renewal is now {value:?}");
            person.automatic_renewal = Some(value);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy_with(start_at_login: bool, log_level: LogLevel) -> Layer {
        Layer {
            start_at_login: Some(start_at_login),
            log_level: Some(log_level),
            ..Layer::default()
        }
    }

    fn ilm(address: &str) -> Option<IlmUrl> {
        Some(IlmUrl::parse(address).unwrap())
    }

    #[test]
    fn the_view_leaves_what_the_system_can_do_to_the_application() {
        let view = view(&Layer::default(), &Layer::default());

        assert_eq!(view.unlock, Unlock::Unsupported);
    }

    #[test]
    fn empty_layers_give_the_defaults() {
        let view = view(&Layer::default(), &Layer::default());
        assert_eq!(
            view.start_at_login,
            Entry {
                value: true,
                locked: false
            }
        );
        assert_eq!(
            view.log_level,
            Entry {
                value: LogLevel::Info,
                locked: false
            }
        );
    }

    #[test]
    fn person_beats_default_without_locking() {
        let person = Layer {
            start_at_login: Some(false),
            log_level: Some(LogLevel::Debug),
            ..Layer::default()
        };
        let view = view(&Layer::default(), &person);
        assert_eq!(
            view.start_at_login,
            Entry {
                value: false,
                locked: false
            }
        );
        assert_eq!(
            view.log_level,
            Entry {
                value: LogLevel::Debug,
                locked: false
            }
        );
    }

    #[test]
    fn policy_beats_person_and_locks() {
        let person = Layer {
            start_at_login: Some(true),
            log_level: Some(LogLevel::Debug),
            ..Layer::default()
        };
        let view = view(&policy_with(false, LogLevel::Error), &person);
        assert_eq!(
            view.start_at_login,
            Entry {
                value: false,
                locked: true
            }
        );
        assert_eq!(
            view.log_level,
            Entry {
                value: LogLevel::Error,
                locked: true
            }
        );
    }

    #[test]
    fn policy_locks_only_the_keys_it_sets() {
        let policy = Layer {
            log_level: Some(LogLevel::Warn),
            ..Layer::default()
        };
        let view = view(&policy, &Layer::default());
        assert!(!view.start_at_login.locked);
        assert!(view.log_level.locked);
    }

    #[test]
    fn sources_name_the_layer_of_each_value() {
        let policy = Layer {
            log_level: Some(LogLevel::Warn),
            ..Layer::default()
        };
        let person = Layer {
            start_at_login: Some(false),
            ..Layer::default()
        };
        assert_eq!(
            sources(&policy, &person),
            [
                ("StartAtLogin", Source::Person),
                ("LogLevel", Source::Policy),
                ("IlmUrl", Source::Default),
                ("AutomaticUpdates", Source::Default)
            ]
        );
        assert_eq!(
            sources(&Layer::default(), &Layer::default()),
            [
                ("StartAtLogin", Source::Default),
                ("LogLevel", Source::Default),
                ("IlmUrl", Source::Default),
                ("AutomaticUpdates", Source::Default)
            ]
        );
        assert_eq!(Source::Policy.to_string(), "policy");
        assert_eq!(Source::Person.to_string(), "person");
        assert_eq!(Source::Default.to_string(), "default");
    }

    fn minutes(value: i64) -> Option<IdleMinutes> {
        Some(IdleMinutes::new(value).unwrap())
    }

    #[test]
    fn unlock_defaults_to_required_and_idle_lock_to_off() {
        let view = view(&Layer::default(), &Layer::default());
        assert_eq!(
            view.require_unlock,
            Entry {
                value: true,
                locked: false
            }
        );
        assert_eq!(
            view.lock_after_idle,
            Entry {
                value: None,
                locked: false
            }
        );
    }

    #[test]
    fn unlock_settings_follow_person_then_policy() {
        let person = Layer {
            require_unlock: Some(false),
            lock_after_idle: minutes(15),
            ..Layer::default()
        };
        let by_person = view(&Layer::default(), &person);
        assert_eq!(
            by_person.require_unlock,
            Entry {
                value: false,
                locked: false
            }
        );
        assert_eq!(
            by_person.lock_after_idle,
            Entry {
                value: Some(15),
                locked: false
            }
        );

        let policy = Layer {
            require_unlock: Some(true),
            lock_after_idle: minutes(60),
            ..Layer::default()
        };
        let by_policy = view(&policy, &person);
        assert_eq!(
            by_policy.require_unlock,
            Entry {
                value: true,
                locked: true
            }
        );
        assert_eq!(
            by_policy.lock_after_idle,
            Entry {
                value: Some(60),
                locked: true
            }
        );
    }

    #[test]
    fn idle_minutes_accept_one_to_1440_only() {
        for (value, accepted) in [
            (-1, false),
            (0, false),
            (1, true),
            (1440, true),
            (1441, false),
            (i64::MAX, false),
        ] {
            assert_eq!(IdleMinutes::new(value).is_some(), accepted, "{value}");
        }
        assert_eq!(IdleMinutes::new(90).unwrap().get(), 90);
    }

    #[test]
    fn locked_unlock_changes_are_refused_and_unlocked_ones_stored() {
        let policy = Layer {
            require_unlock: Some(true),
            lock_after_idle: minutes(5),
            ..Layer::default()
        };
        let mut person = Layer::default();
        let refused = apply(Change::RequireUnlock(false), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Require unlock is managed by your organization."
        );
        let refused = apply(Change::LockAfterIdle(None), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Lock after idle is managed by your organization."
        );
        assert_eq!(person, Layer::default());

        let open = Layer::default();
        apply(Change::RequireUnlock(false), &open, &mut person).unwrap();
        apply(Change::LockAfterIdle(minutes(30)), &open, &mut person).unwrap();
        assert_eq!(person.require_unlock, Some(false));
        assert_eq!(person.lock_after_idle, minutes(30));
        apply(Change::LockAfterIdle(None), &open, &mut person).unwrap();
        assert_eq!(person.lock_after_idle, None);
    }

    #[test]
    fn locked_change_is_refused_and_leaves_the_person_unchanged() {
        let policy = policy_with(false, LogLevel::Error);
        let mut person = Layer::default();
        let refused = apply(Change::StartAtLogin(true), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Start at login is managed by your organization."
        );
        let refused = apply(Change::LogLevel(LogLevel::Debug), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Log level is managed by your organization."
        );
        assert_eq!(person, Layer::default());
    }

    #[test]
    fn the_ilm_address_defaults_to_none_and_follows_person_then_policy() {
        let empty = view(&Layer::default(), &Layer::default());
        assert_eq!(
            empty.ilm_url,
            Entry {
                value: None,
                locked: false
            }
        );

        let person = Layer {
            ilm_url: ilm("person.example.com"),
            ..Layer::default()
        };
        let by_person = view(&Layer::default(), &person);
        assert_eq!(
            by_person.ilm_url,
            Entry {
                value: Some("https://person.example.com".into()),
                locked: false
            }
        );

        let policy = Layer {
            ilm_url: ilm("policy.example.com"),
            ..Layer::default()
        };
        let by_policy = view(&policy, &person);
        assert_eq!(
            by_policy.ilm_url,
            Entry {
                value: Some("https://policy.example.com".into()),
                locked: true
            }
        );
        assert_eq!(sources(&policy, &person)[2], ("IlmUrl", Source::Policy));
    }

    #[test]
    fn policy_locks_the_ilm_address_and_the_provider_has_no_change() {
        let policy = Layer {
            ilm_url: ilm("policy.example.com"),
            sign_in_provider: Some("Corporate".into()),
            ..Layer::default()
        };
        let mut person = Layer::default();
        let change = Change::IlmUrl(IlmUrl::parse("mine.example.com").unwrap());
        let refused = apply(change, &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "ILM address is managed by your organization."
        );
        assert_eq!(person, Layer::default());
        assert!(!view(&policy, &person).start_at_login.locked);
    }

    #[test]
    fn the_sign_in_method_is_parsed_by_name() {
        assert_eq!(SignInMethod::parse("oauth"), Some(SignInMethod::Oauth));
        assert_eq!(
            SignInMethod::parse(" certificate "),
            Some(SignInMethod::Certificate)
        );
        assert_eq!(SignInMethod::parse("OAuth"), None);
        assert_eq!(SignInMethod::parse(""), None);
    }

    #[test]
    fn storages_are_parsed_by_name() {
        assert_eq!(parse_storage("keychain"), Some(Storage::Keychain));
        assert_eq!(parse_storage(" software "), Some(Storage::Software));
        assert_eq!(parse_storage("tpm"), Some(Storage::Tpm));
        assert_eq!(parse_storage("TPM"), None);
        assert_eq!(parse_storage(""), None);
    }

    fn offer(storage: Storage) -> Offer {
        Offer {
            storage,
            types: Vec::new(),
        }
    }

    fn offers() -> Vec<Offer> {
        vec![
            offer(Storage::Software),
            offer(Storage::Keychain),
            offer(Storage::Tpm),
        ]
    }

    fn storages_of(offers: &[Offer]) -> Vec<Storage> {
        offers.iter().map(|offer| offer.storage).collect()
    }

    #[test]
    fn without_policy_every_offer_is_allowed_and_the_first_preselected() {
        let (allowed, preselected) = allowed_offers(offers(), &Layer::default());
        assert_eq!(allowed, offers());
        assert_eq!(preselected, Some(Storage::Software));
    }

    #[test]
    fn policy_limits_the_offers_and_keeps_their_order() {
        let policy = Layer {
            key_storages: Some(vec![Storage::Tpm, Storage::Software]),
            ..Layer::default()
        };
        let (allowed, preselected) = allowed_offers(offers(), &policy);
        assert_eq!(storages_of(&allowed), [Storage::Software, Storage::Tpm]);
        assert_eq!(preselected, Some(Storage::Software));
    }

    #[test]
    fn the_policy_default_is_preselected_only_when_allowed() {
        let mut policy = Layer {
            key_storages: Some(vec![Storage::Software, Storage::Tpm]),
            default_key_storage: Some(Storage::Tpm),
            ..Layer::default()
        };
        assert_eq!(allowed_offers(offers(), &policy).1, Some(Storage::Tpm));
        policy.default_key_storage = Some(Storage::Keychain);
        assert_eq!(allowed_offers(offers(), &policy).1, Some(Storage::Software));
        let none_offered = allowed_offers(vec![offer(Storage::Keychain)], &policy);
        assert_eq!(none_offered, (Vec::new(), None));
    }

    #[test]
    fn a_default_that_is_not_offered_gives_the_first_allowed() {
        let policy = Layer {
            default_key_storage: Some(Storage::Tpm),
            ..Layer::default()
        };
        let (allowed, preselected) = allowed_offers(vec![offer(Storage::Keychain)], &policy);
        assert_eq!(storages_of(&allowed), [Storage::Keychain]);
        assert_eq!(preselected, Some(Storage::Keychain));
    }

    #[test]
    fn a_new_ilm_address_keeps_the_remembered_certificate_for_the_old_one() {
        let remembered = RememberedCertificate {
            ilm: IlmUrl::parse("mine.example.com").unwrap(),
            fingerprint: Fingerprint::of(b"certificate"),
        };
        let mut person = Layer {
            ilm_url: ilm("mine.example.com"),
            sign_in_certificate: Some(remembered.clone()),
            ..Layer::default()
        };
        let other = Change::IlmUrl(IlmUrl::parse("other.example.com").unwrap());
        apply(other, &Layer::default(), &mut person).unwrap();
        assert_eq!(person.sign_in_certificate, Some(remembered));
    }

    #[test]
    fn an_unlocked_ilm_address_is_stored() {
        let mut person = Layer::default();
        let change = Change::IlmUrl(IlmUrl::parse("mine.example.com").unwrap());
        apply(change, &Layer::default(), &mut person).unwrap();
        assert_eq!(person.ilm_url, ilm("mine.example.com"));
    }

    #[test]
    fn unlocked_change_is_stored() {
        let mut person = Layer::default();
        apply(Change::StartAtLogin(false), &Layer::default(), &mut person).unwrap();
        apply(
            Change::LogLevel(LogLevel::Warn),
            &Layer::default(),
            &mut person,
        )
        .unwrap();
        assert_eq!(
            person,
            Layer {
                start_at_login: Some(false),
                log_level: Some(LogLevel::Warn),
                ..Layer::default()
            }
        );
    }

    #[test]
    fn log_level_maps_to_level_filter() {
        let filters: Vec<log::LevelFilter> = [
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(
            filters,
            [
                log::LevelFilter::Error,
                log::LevelFilter::Warn,
                log::LevelFilter::Info,
                log::LevelFilter::Debug
            ]
        );
    }

    #[test]
    fn check_minutes_accept_five_to_1440_and_the_person_four_of_them() {
        for (value, accepted) in [
            (4, false),
            (5, true),
            (90, true),
            (1440, true),
            (1441, false),
        ] {
            assert_eq!(CheckMinutes::new(value).is_some(), accepted, "{value}");
        }
        for (value, accepted) in [(5, true), (15, true), (30, true), (60, true), (45, false)] {
            assert_eq!(CheckMinutes::option(value).is_some(), accepted, "{value}");
        }
        assert_eq!(CheckMinutes::default().get(), 15);
    }

    #[test]
    fn check_every_defaults_to_fifteen_and_policy_wins() {
        let view_of = |policy: &Layer, person: &Layer| view(policy, person).check_every;
        assert_eq!(
            view_of(&Layer::default(), &Layer::default()),
            Entry {
                value: 15,
                locked: false
            }
        );
        let person = Layer {
            check_every: CheckMinutes::option(5),
            ..Layer::default()
        };
        assert_eq!(
            view_of(&Layer::default(), &person),
            Entry {
                value: 5,
                locked: false
            }
        );
        let policy = Layer {
            check_every: CheckMinutes::new(90),
            ..Layer::default()
        };
        assert_eq!(
            view_of(&policy, &person),
            Entry {
                value: 90,
                locked: true
            }
        );
        assert_eq!(
            check_interval(&policy, &person),
            std::time::Duration::from_secs(90 * 60)
        );
        assert_eq!(
            check_interval(&Layer::default(), &Layer::default()),
            std::time::Duration::from_secs(15 * 60)
        );
    }

    #[test]
    fn check_every_is_changed_unless_policy_fixes_it() {
        let mut person = Layer::default();
        let thirty = CheckMinutes::option(30).unwrap();
        apply(Change::CheckEvery(thirty), &Layer::default(), &mut person).unwrap();
        assert_eq!(person.check_every, Some(thirty));
        let policy = Layer {
            check_every: CheckMinutes::new(45),
            ..Layer::default()
        };
        let refused = apply(Change::CheckEvery(thirty), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Check ILM every is managed by your organization."
        );
    }

    #[test]
    fn warn_days_accept_one_to_365_and_the_person_five_of_them() {
        for (value, accepted) in [(0, false), (1, true), (45, true), (365, true), (366, false)] {
            assert_eq!(WarnDays::new(value).is_some(), accepted, "{value}");
        }
        for (value, accepted) in [
            (7, true),
            (14, true),
            (30, true),
            (60, true),
            (90, true),
            (45, false),
        ] {
            assert_eq!(WarnDays::option(value).is_some(), accepted, "{value}");
        }
        assert_eq!(WarnDays::default().get(), 30);
    }

    #[test]
    fn warn_days_default_to_thirty_and_policy_wins() {
        let view_of = |policy: &Layer, person: &Layer| view(policy, person).warn_days;
        assert_eq!(
            view_of(&Layer::default(), &Layer::default()),
            Entry {
                value: 30,
                locked: false
            }
        );
        let person = Layer {
            warn_days: WarnDays::option(7),
            ..Layer::default()
        };
        assert_eq!(
            view_of(&Layer::default(), &person),
            Entry {
                value: 7,
                locked: false
            }
        );
        let policy = Layer {
            warn_days: WarnDays::new(45),
            ..Layer::default()
        };
        assert_eq!(
            view_of(&policy, &person),
            Entry {
                value: 45,
                locked: true
            }
        );
        assert_eq!(warn_days(&policy, &person).get(), 45);
        assert_eq!(warn_days(&Layer::default(), &person).get(), 7);
        assert_eq!(warn_days(&Layer::default(), &Layer::default()).get(), 30);
    }

    #[test]
    fn automatic_updates_are_on_by_default() {
        let view = view(&Layer::default(), &Layer::default());
        assert_eq!(
            view.automatic_updates,
            Entry {
                value: true,
                locked: false
            }
        );
    }

    #[test]
    fn managed_automatic_updates_lock_the_entry() {
        let policy = Layer {
            automatic_updates: Some(false),
            ..Layer::default()
        };
        let person = Layer {
            automatic_updates: Some(true),
            ..Layer::default()
        };
        assert_eq!(
            view(&policy, &person).automatic_updates,
            Entry {
                value: false,
                locked: true
            }
        );
        assert_eq!(
            sources(&policy, &person)[3],
            ("AutomaticUpdates", Source::Policy)
        );
    }

    #[test]
    fn automatic_updates_are_changed_unless_policy_fixes_them() {
        let mut person = Layer::default();
        apply(
            Change::AutomaticUpdates(false),
            &Layer::default(),
            &mut person,
        )
        .unwrap();
        assert_eq!(person.automatic_updates, Some(false));
        let policy = Layer {
            automatic_updates: Some(false),
            ..Layer::default()
        };
        let refused = apply(Change::AutomaticUpdates(true), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Automatic updates is managed by your organization."
        );
        assert_eq!(person.automatic_updates, Some(false));
    }

    #[test]
    fn warn_days_are_changed_unless_policy_fixes_them() {
        let mut person = Layer::default();
        let sixty = WarnDays::option(60).unwrap();
        apply(Change::WarnDays(sixty), &Layer::default(), &mut person).unwrap();
        assert_eq!(person.warn_days, Some(sixty));
        let policy = Layer {
            warn_days: WarnDays::new(45),
            ..Layer::default()
        };
        let refused = apply(Change::WarnDays(sixty), &policy, &mut person).unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Expiry warning is managed by your organization."
        );
    }

    #[test]
    fn view_serialises_in_camel_case() {
        let json = serde_json::to_value(view(
            &policy_with(false, LogLevel::Debug),
            &Layer::default(),
        ))
        .unwrap();
        assert_eq!(
            json,
            json!({
                "startAtLogin": { "value": false, "locked": true },
                "automaticUpdates": { "value": true, "locked": false },
                "logLevel": { "value": "debug", "locked": true },
                "ilmUrl": { "value": null, "locked": false },
                "requireUnlock": { "value": true, "locked": false },
                "lockAfterIdle": { "value": null, "locked": false },
                "checkEvery": { "value": 15, "locked": false },
                "warnDays": { "value": 30, "locked": false },
                "automaticRenewal": { "value": "newKey", "locked": false },
                "unlock": "unsupported",
            })
        );
    }

    #[test]
    fn change_deserialises_as_a_tagged_union() {
        let login: Change =
            serde_json::from_value(json!({ "key": "startAtLogin", "value": false })).unwrap();
        let level: Change =
            serde_json::from_value(json!({ "key": "logLevel", "value": "warn" })).unwrap();
        assert_eq!(login, Change::StartAtLogin(false));
        let updates: Change =
            serde_json::from_value(json!({ "key": "automaticUpdates", "value": false })).unwrap();
        assert_eq!(updates, Change::AutomaticUpdates(false));
        assert_eq!(level, Change::LogLevel(LogLevel::Warn));
        let address: Change =
            serde_json::from_value(json!({ "key": "ilmUrl", "value": "ilm.example.com" })).unwrap();
        assert_eq!(
            address,
            Change::IlmUrl(IlmUrl::parse("https://ilm.example.com").unwrap())
        );
        let unlock: Change =
            serde_json::from_value(json!({ "key": "requireUnlock", "value": false })).unwrap();
        assert_eq!(unlock, Change::RequireUnlock(false));
        let idle: Change =
            serde_json::from_value(json!({ "key": "lockAfterIdle", "value": 20 })).unwrap();
        assert_eq!(idle, Change::LockAfterIdle(minutes(20)));
        let off: Change =
            serde_json::from_value(json!({ "key": "lockAfterIdle", "value": null })).unwrap();
        assert_eq!(off, Change::LockAfterIdle(None));
        let every: Change =
            serde_json::from_value(json!({ "key": "checkEvery", "value": 30 })).unwrap();
        assert_eq!(every, Change::CheckEvery(CheckMinutes::option(30).unwrap()));
        for bad in [json!(0), json!(10), json!(1440), json!("15"), json!(null)] {
            assert!(
                serde_json::from_value::<Change>(json!({ "key": "checkEvery", "value": bad }))
                    .is_err()
            );
        }
        let days: Change =
            serde_json::from_value(json!({ "key": "warnDays", "value": 60 })).unwrap();
        assert_eq!(days, Change::WarnDays(WarnDays::option(60).unwrap()));
        for bad in [
            json!(0),
            json!(1),
            json!(45),
            json!(365),
            json!("30"),
            json!(null),
        ] {
            assert!(
                serde_json::from_value::<Change>(json!({ "key": "warnDays", "value": bad }))
                    .is_err()
            );
        }
        for bad in [json!(0), json!(1441), json!(-5), json!("20")] {
            assert!(
                serde_json::from_value::<Change>(json!({ "key": "lockAfterIdle", "value": bad }))
                    .is_err()
            );
        }
        assert!(
            serde_json::from_value::<Change>(json!({ "key": "ilmUrl", "value": "http://x" }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<Change>(json!({ "key": "logLevel", "value": "loud" }))
                .is_err()
        );
    }

    #[test]
    fn the_enrolment_policy_reads_as_off_and_empty_without_policy() {
        let none = Layer::default();
        assert!(!complete_prepared(&none));
        assert!(request_profiles(&none).is_empty());
        assert_eq!(sign_in_certificate_profile(&none), None);
        let policy = Layer {
            complete_prepared: Some(true),
            request_profiles: Some(vec!["Web".into(), "Mail".into()]),
            sign_in_certificate_profile: Some("Sign-in".into()),
            ..Layer::default()
        };
        assert!(complete_prepared(&policy));
        assert_eq!(request_profiles(&policy), ["Web", "Mail"]);
        assert_eq!(sign_in_certificate_profile(&policy), Some("Sign-in"));
    }

    #[test]
    fn automatic_renewal_defaults_to_a_new_key_and_follows_person_then_policy() {
        let none = Layer::default();
        assert_eq!(automatic_renewal(&none, &none), AutomaticRenewal::NewKey);
        let person = Layer {
            automatic_renewal: Some(AutomaticRenewal::SameKey),
            ..Layer::default()
        };
        let by_person = view(&none, &person);
        assert_eq!(
            by_person.automatic_renewal,
            Entry {
                value: AutomaticRenewal::SameKey,
                locked: false
            }
        );
        let policy = Layer {
            automatic_renewal: Some(AutomaticRenewal::Off),
            ..Layer::default()
        };
        let by_policy = view(&policy, &person);
        assert_eq!(
            by_policy.automatic_renewal,
            Entry {
                value: AutomaticRenewal::Off,
                locked: true
            }
        );
    }

    #[test]
    fn a_locked_automatic_renewal_is_refused_and_an_unlocked_one_stored() {
        let mut person = Layer::default();
        apply(
            Change::AutomaticRenewal(AutomaticRenewal::SameKey),
            &Layer::default(),
            &mut person,
        )
        .unwrap();
        assert_eq!(person.automatic_renewal, Some(AutomaticRenewal::SameKey));
        let policy = Layer {
            automatic_renewal: Some(AutomaticRenewal::Off),
            ..Layer::default()
        };
        let refused = apply(
            Change::AutomaticRenewal(AutomaticRenewal::NewKey),
            &policy,
            &mut person,
        )
        .unwrap_err();
        assert_eq!(
            refused.to_string(),
            "Automatic renewal is managed by your organization."
        );
    }

    #[test]
    fn automatic_renewal_reads_its_three_names_only() {
        for (text, expected) in [
            ("off", Some(AutomaticRenewal::Off)),
            ("newKey", Some(AutomaticRenewal::NewKey)),
            (" sameKey ", Some(AutomaticRenewal::SameKey)),
            ("newkey", None),
            ("on", None),
            ("", None),
        ] {
            assert_eq!(AutomaticRenewal::parse(text), expected, "{text:?}");
        }
        let change: Change =
            serde_json::from_value(json!({ "key": "automaticRenewal", "value": "sameKey" }))
                .unwrap();
        assert_eq!(change, Change::AutomaticRenewal(AutomaticRenewal::SameKey));
        assert!(
            serde_json::from_value::<Change>(
                json!({ "key": "automaticRenewal", "value": "always" })
            )
            .is_err()
        );
    }
}
