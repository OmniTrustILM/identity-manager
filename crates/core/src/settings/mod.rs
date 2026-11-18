//! The settings model: built-in defaults, the person's choices and the organization's policy.

pub mod store;

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ilm::IlmUrl;

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

/// The settings one source sets; a missing value leaves the setting to the next layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    pub start_at_login: Option<bool>,
    pub log_level: Option<LogLevel>,
    pub ilm_url: Option<IlmUrl>,
    /// Which sign-in provider to use; only policy sets it.
    pub sign_in_provider: Option<String>,
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
    pub log_level: Entry<LogLevel>,
    pub ilm_url: Entry<Option<String>>,
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
    LogLevel(LogLevel),
    IlmUrl(#[cfg_attr(any(test, feature = "ts"), ts(as = "String"))] IlmUrl),
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

/// Merges the layers: policy over the person's choice over the default.
pub fn view(policy: &Layer, person: &Layer) -> SettingsView {
    SettingsView {
        start_at_login: entry(start_at_login(policy, person)),
        log_level: entry(log_level(policy, person)),
        ilm_url: entry({
            let (url, source) = ilm_url(policy, person);
            (url.map(ToString::to_string), source)
        }),
    }
}

/// The layer each effective value comes from, by setting name.
pub fn sources(policy: &Layer, person: &Layer) -> [(&'static str, Source); 3] {
    [
        ("StartAtLogin", start_at_login(policy, person).1),
        ("LogLevel", log_level(policy, person).1),
        ("IlmUrl", ilm_url(policy, person).1),
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
                ("IlmUrl", Source::Default)
            ]
        );
        assert_eq!(
            sources(&Layer::default(), &Layer::default()),
            [
                ("StartAtLogin", Source::Default),
                ("LogLevel", Source::Default),
                ("IlmUrl", Source::Default)
            ]
        );
        assert_eq!(Source::Policy.to_string(), "policy");
        assert_eq!(Source::Person.to_string(), "person");
        assert_eq!(Source::Default.to_string(), "default");
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
                "logLevel": { "value": "debug", "locked": true },
                "ilmUrl": { "value": null, "locked": false },
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
        assert_eq!(level, Change::LogLevel(LogLevel::Warn));
        let address: Change =
            serde_json::from_value(json!({ "key": "ilmUrl", "value": "ilm.example.com" })).unwrap();
        assert_eq!(
            address,
            Change::IlmUrl(IlmUrl::parse("https://ilm.example.com").unwrap())
        );
        assert!(
            serde_json::from_value::<Change>(json!({ "key": "ilmUrl", "value": "http://x" }))
                .is_err()
        );
        assert!(
            serde_json::from_value::<Change>(json!({ "key": "logLevel", "value": "loud" }))
                .is_err()
        );
    }
}
