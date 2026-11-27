//! The organization's policy: raw values read from a system source, mapped to a settings layer.

pub mod linux;
pub mod macos;
pub mod windows;

use std::collections::BTreeMap;
use std::fmt;
#[cfg(unix)]
use std::path::Path;

use crate::ilm::IlmUrl;
use crate::keys::Storage;
use crate::settings::{
    AutomaticRenewal, CheckMinutes, IdleMinutes, Layer, LogLevel, SignInMethod, WarnDays,
    parse_storage,
};

/// A value as a policy source stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValue {
    Bool(bool),
    Int(i64),
    Text(String),
    /// A value of a type policy does not use.
    Other,
}

/// The values of one source by name.
pub type RawMap = BTreeMap<String, PolicyValue>;

pub(crate) const START_AT_LOGIN: &str = "StartAtLogin";
pub(crate) const AUTOMATIC_UPDATES: &str = "AutomaticUpdates";
pub(crate) const LOG_LEVEL: &str = "LogLevel";
pub(crate) const ILM_URL: &str = "IlmUrl";
pub(crate) const REQUIRE_UNLOCK: &str = "RequireUnlock";
pub(crate) const LOCK_AFTER_IDLE: &str = "LockAfterIdle";
pub(crate) const CHECK_INTERVAL: &str = "CheckInterval";
pub(crate) const EXPIRY_WARNING_DAYS: &str = "ExpiryWarningDays";
pub(crate) const SIGN_IN_PROVIDER: &str = "SignInProvider";
pub(crate) const SIGN_IN_METHOD: &str = "SignInMethod";
pub(crate) const KEY_STORAGES: &str = "KeyStorages";
pub(crate) const DEFAULT_KEY_STORAGE: &str = "DefaultKeyStorage";
pub(crate) const AUTOMATIC_RENEWAL: &str = "AutomaticRenewal";
pub(crate) const COMPLETE_PREPARED: &str = "CompletePrepared";
pub(crate) const REQUEST_PROFILES: &str = "RequestProfiles";
pub(crate) const SIGN_IN_CERTIFICATE_PROFILE: &str = "SignInCertificateProfile";

/// What a policy value holds, as far as a policy template has to declare it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    /// A whole number from `min` to `max`.
    Int {
        min: i64,
        max: i64,
    },
    Text,
    /// One of these strings.
    Choice(&'static [&'static str]),
}

/// Every policy the reader knows, with its kind.
pub const POLICIES: [(&str, Kind); 16] = [
    (START_AT_LOGIN, Kind::Bool),
    (AUTOMATIC_UPDATES, Kind::Bool),
    (LOG_LEVEL, Kind::Choice(&["error", "warn", "info", "debug"])),
    (ILM_URL, Kind::Text),
    (REQUIRE_UNLOCK, Kind::Bool),
    (LOCK_AFTER_IDLE, Kind::Int { min: 1, max: 1440 }),
    (CHECK_INTERVAL, Kind::Int { min: 5, max: 1440 }),
    (EXPIRY_WARNING_DAYS, Kind::Int { min: 1, max: 365 }),
    (SIGN_IN_PROVIDER, Kind::Text),
    (SIGN_IN_METHOD, Kind::Choice(&["oauth", "certificate"])),
    (KEY_STORAGES, Kind::Text),
    (
        DEFAULT_KEY_STORAGE,
        Kind::Choice(&["keychain", "software", "tpm"]),
    ),
    (
        AUTOMATIC_RENEWAL,
        Kind::Choice(&["off", "newKey", "sameKey"]),
    ),
    (COMPLETE_PREPARED, Kind::Bool),
    (REQUEST_PROFILES, Kind::Text),
    (SIGN_IN_CERTIFICATE_PROFILE, Kind::Text),
];

/// Maps the known names with the expected types to a layer; anything else is ignored with a warning.
pub fn to_layer(raw: &RawMap, source: &str) -> Layer {
    let mut layer = Layer::default();
    for (name, value) in raw {
        match (name.as_str(), value) {
            (START_AT_LOGIN, PolicyValue::Bool(on)) => layer.start_at_login = Some(*on),
            (AUTOMATIC_UPDATES, PolicyValue::Bool(on)) => layer.automatic_updates = Some(*on),
            (LOG_LEVEL, PolicyValue::Text(text)) => match parse_level(text) {
                Some(level) => layer.log_level = Some(level),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (ILM_URL, PolicyValue::Text(text)) => match IlmUrl::parse(text) {
                Ok(url) => layer.ilm_url = Some(url),
                Err(error) => {
                    log::warn!("policy {name} in {source} has an invalid value ({error}); ignored");
                }
            },
            (REQUIRE_UNLOCK, PolicyValue::Bool(on)) => layer.require_unlock = Some(*on),
            (LOCK_AFTER_IDLE, PolicyValue::Int(minutes)) => match IdleMinutes::new(*minutes) {
                Some(minutes) => layer.lock_after_idle = Some(minutes),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (CHECK_INTERVAL, PolicyValue::Int(minutes)) => match CheckMinutes::new(*minutes) {
                Some(minutes) => layer.check_every = Some(minutes),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (EXPIRY_WARNING_DAYS, PolicyValue::Int(days)) => match WarnDays::new(*days) {
                Some(days) => layer.warn_days = Some(days),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (SIGN_IN_PROVIDER, PolicyValue::Text(text)) if !text.trim().is_empty() => {
                layer.sign_in_provider = Some(text.trim().to_string());
            }
            (SIGN_IN_PROVIDER, PolicyValue::Text(_)) => {
                log::warn!("policy {name} in {source} has an invalid value; ignored");
            }
            (SIGN_IN_METHOD, PolicyValue::Text(text)) => match SignInMethod::parse(text) {
                Some(method) => layer.sign_in_method = Some(method),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (KEY_STORAGES, PolicyValue::Text(text)) => {
                let storages = parse_storages(text, name, source);
                if storages.is_empty() {
                    log::warn!("policy {name} in {source} names no storage; none is allowed");
                }
                layer.key_storages = Some(storages);
            }
            (DEFAULT_KEY_STORAGE, PolicyValue::Text(text)) => match parse_storage(text) {
                Some(storage) => layer.default_key_storage = Some(storage),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (AUTOMATIC_RENEWAL, PolicyValue::Text(text)) => match AutomaticRenewal::parse(text) {
                Some(renewal) => layer.automatic_renewal = Some(renewal),
                None => log::warn!("policy {name} in {source} has an invalid value; ignored"),
            },
            (COMPLETE_PREPARED, PolicyValue::Bool(on)) => layer.complete_prepared = Some(*on),
            (REQUEST_PROFILES, PolicyValue::Text(text)) => {
                layer.request_profiles = Some(
                    text.split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
            }
            (SIGN_IN_CERTIFICATE_PROFILE, PolicyValue::Text(text)) => {
                layer.sign_in_certificate_profile =
                    Some(text.trim().to_string()).filter(|name| !name.is_empty());
            }
            (
                START_AT_LOGIN
                | AUTOMATIC_UPDATES
                | LOG_LEVEL
                | ILM_URL
                | REQUIRE_UNLOCK
                | LOCK_AFTER_IDLE
                | CHECK_INTERVAL
                | EXPIRY_WARNING_DAYS
                | SIGN_IN_PROVIDER
                | SIGN_IN_METHOD
                | KEY_STORAGES
                | DEFAULT_KEY_STORAGE
                | AUTOMATIC_RENEWAL
                | COMPLETE_PREPARED
                | REQUEST_PROFILES
                | SIGN_IN_CERTIFICATE_PROFILE,
                _,
            ) => {
                log::warn!("policy {name} in {source} has the wrong type; ignored");
            }
            _ => log::warn!("policy {name} in {source} is unknown; ignored"),
        }
    }
    layer
}

/// The storages a comma-separated list names; unknown names are skipped with a warning.
fn parse_storages(text: &str, name: &str, source: &str) -> Vec<Storage> {
    let mut storages = Vec::new();
    for part in text
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        match parse_storage(part) {
            Some(storage) if !storages.contains(&storage) => storages.push(storage),
            Some(_) => {}
            None => log::warn!("policy {name} in {source} names an unknown storage; skipped"),
        }
    }
    storages
}

fn parse_level(text: &str) -> Option<LogLevel> {
    match text {
        "error" => Some(LogLevel::Error),
        "warn" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        _ => None,
    }
}

/// Combines the machine and the user scope; the machine wins per key.
pub fn merge(machine: Layer, user: Layer) -> Layer {
    Layer {
        start_at_login: machine.start_at_login.or(user.start_at_login),
        automatic_updates: machine.automatic_updates.or(user.automatic_updates),
        log_level: machine.log_level.or(user.log_level),
        ilm_url: machine.ilm_url.or(user.ilm_url),
        require_unlock: machine.require_unlock.or(user.require_unlock),
        lock_after_idle: machine.lock_after_idle.or(user.lock_after_idle),
        check_every: machine.check_every.or(user.check_every),
        warn_days: machine.warn_days.or(user.warn_days),
        automatic_renewal: machine.automatic_renewal.or(user.automatic_renewal),
        sign_in_provider: machine.sign_in_provider.or(user.sign_in_provider),
        sign_in_method: machine.sign_in_method.or(user.sign_in_method),
        key_storages: machine.key_storages.or(user.key_storages),
        default_key_storage: machine.default_key_storage.or(user.default_key_storage),
        complete_prepared: machine.complete_prepared.or(user.complete_prepared),
        request_profiles: machine.request_profiles.or(user.request_profiles),
        sign_in_certificate_profile: machine
            .sign_in_certificate_profile
            .or(user.sign_in_certificate_profile),
        sign_in_certificate: None,
    }
}

/// The policy of the running system: the machine scope wins over the user scope per key.
/// Missing sources are normal; systems without a source give an empty layer.
pub fn read() -> Layer {
    #[cfg(target_os = "macos")]
    return macos::read();
    #[cfg(target_os = "linux")]
    return linux::read();
    #[cfg(windows)]
    return windows::read();
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    Layer::default()
}

/// What the file system says about one element on the path of a policy file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileMeta {
    pub is_symlink: bool,
    pub is_file: bool,
    pub uid: u32,
    pub mode: u32,
}

/// Why a policy file is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untrusted {
    EmptyChain,
    Symlink,
    NotAFile,
    NotOwnedByRoot,
    WritableByOthers,
}

impl fmt::Display for Untrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Untrusted::EmptyChain => "no path to check",
            Untrusted::Symlink => "a symbolic link on the path",
            Untrusted::NotAFile => "not a regular file",
            Untrusted::NotOwnedByRoot => "not owned by root",
            Untrusted::WritableByOthers => "writable by group or others",
        })
    }
}

const GROUP_OTHER_WRITE: u32 = 0o022;

/// Checks the file (first) and every folder above it up to `/`.
pub fn trusted(chain: &[FileMeta]) -> Result<(), Untrusted> {
    let (leaf, _) = chain.split_first().ok_or(Untrusted::EmptyChain)?;
    if !leaf.is_file && !leaf.is_symlink {
        return Err(Untrusted::NotAFile);
    }
    chain.iter().try_for_each(|meta| {
        if meta.is_symlink {
            Err(Untrusted::Symlink)
        } else if meta.uid != 0 {
            Err(Untrusted::NotOwnedByRoot)
        } else if meta.mode & GROUP_OTHER_WRITE != 0 {
            Err(Untrusted::WritableByOthers)
        } else {
            Ok(())
        }
    })
}

/// Reads the metadata of an absolute path and of each of its parents without following links.
#[cfg(unix)]
pub fn file_chain(path: &std::path::Path) -> std::io::Result<Vec<FileMeta>> {
    use std::os::unix::fs::MetadataExt;

    path.ancestors()
        .map(|part| {
            let meta = std::fs::symlink_metadata(part)?;
            Ok(FileMeta {
                is_symlink: meta.file_type().is_symlink(),
                is_file: meta.is_file(),
                uid: meta.uid(),
                mode: meta.mode(),
            })
        })
        .collect()
}

/// Reads one policy file. A missing file is normal; an untrusted or unreadable one is ignored with
/// a warning. Either way the layer is empty.
#[cfg(unix)]
pub fn read_file(path: &Path, parse: fn(&[u8], &str) -> RawMap) -> Layer {
    let source = path.display().to_string();
    let chain = match file_chain(path) {
        Ok(chain) => chain,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::debug!("no policy at {source}");
            return Layer::default();
        }
        Err(error) => {
            log::warn!("policy {source} cannot be inspected ({error}); ignored");
            return Layer::default();
        }
    };
    if let Err(reason) = trusted(&chain) {
        log::warn!("policy {source} is not trusted ({reason}); ignored");
        return Layer::default();
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            let raw = parse(&bytes, &source);
            log::debug!("policy found at {source} with {} value(s)", raw.len());
            to_layer(&raw, &source)
        }
        Err(error) => {
            log::warn!("policy {source} cannot be read ({error}); ignored");
            Layer::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(items: &[(&str, PolicyValue)]) -> RawMap {
        items
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()))
            .collect()
    }

    fn text(value: &str) -> PolicyValue {
        PolicyValue::Text(value.into())
    }

    #[test]
    fn known_names_with_expected_types_set_the_layer() {
        let layer = to_layer(
            &raw(&[
                ("StartAtLogin", PolicyValue::Bool(false)),
                ("AutomaticUpdates", PolicyValue::Bool(false)),
                ("LogLevel", text("debug")),
            ]),
            "test",
        );
        assert_eq!(layer.start_at_login, Some(false));
        assert_eq!(layer.automatic_updates, Some(false));
        assert_eq!(layer.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn the_address_and_the_provider_set_the_layer() {
        let layer = to_layer(
            &raw(&[
                ("IlmUrl", text("ilm.example.com/ilm")),
                ("SignInProvider", text("Corporate")),
            ]),
            "test",
        );
        assert_eq!(
            layer.ilm_url,
            IlmUrl::parse("https://ilm.example.com/ilm").ok()
        );
        assert_eq!(layer.sign_in_provider.as_deref(), Some("Corporate"));
    }

    #[test]
    fn an_invalid_address_or_an_empty_provider_is_ignored() {
        let layer = to_layer(
            &raw(&[
                ("IlmUrl", text("http://ilm.example.com")),
                ("SignInProvider", text(" ")),
            ]),
            "test",
        );
        assert_eq!(layer, Layer::default());
        let layer = to_layer(
            &raw(&[
                ("IlmUrl", PolicyValue::Bool(true)),
                ("SignInProvider", PolicyValue::Int(1)),
            ]),
            "test",
        );
        assert_eq!(layer, Layer::default());
    }

    #[test]
    fn the_sign_in_method_sets_the_layer_and_a_bad_one_is_ignored() {
        for (name, method) in [
            ("oauth", SignInMethod::Oauth),
            ("certificate", SignInMethod::Certificate),
        ] {
            let layer = to_layer(&raw(&[("SignInMethod", text(name))]), "test");
            assert_eq!(layer.sign_in_method, Some(method));
        }
        for value in [text("password"), text(""), PolicyValue::Int(1)] {
            let layer = to_layer(&raw(&[("SignInMethod", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn the_key_storages_set_the_layer_and_no_known_name_allows_none() {
        for (value, expected) in [
            ("keychain", Some(vec![Storage::Keychain])),
            (
                " tpm , software",
                Some(vec![Storage::Tpm, Storage::Software]),
            ),
            ("tpm,fido,tpm,", Some(vec![Storage::Tpm])),
            ("fido", Some(vec![])),
            ("", Some(vec![])),
        ] {
            let layer = to_layer(&raw(&[("KeyStorages", text(value))]), "test");
            assert_eq!(layer.key_storages, expected, "{value:?}");
        }
        for value in [PolicyValue::Bool(true), PolicyValue::Int(1)] {
            let layer = to_layer(&raw(&[("KeyStorages", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn the_default_key_storage_sets_the_layer_and_a_bad_one_is_ignored() {
        for (name, storage) in [
            ("keychain", Storage::Keychain),
            ("software", Storage::Software),
            ("tpm", Storage::Tpm),
        ] {
            let layer = to_layer(&raw(&[("DefaultKeyStorage", text(name))]), "test");
            assert_eq!(layer.default_key_storage, Some(storage));
        }
        for value in [text("fido"), text(""), PolicyValue::Int(1)] {
            let layer = to_layer(&raw(&[("DefaultKeyStorage", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn the_enrolment_keys_set_the_layer_and_a_wrong_type_is_ignored() {
        let layer = to_layer(
            &raw(&[("CompletePrepared", PolicyValue::Bool(true))]),
            "test",
        );
        assert_eq!(layer.complete_prepared, Some(true));
        for (value, expected) in [
            ("Web, Mail ,,Web2", vec!["Web", "Mail", "Web2"]),
            (" , ", vec![]),
            ("", vec![]),
        ] {
            let layer = to_layer(&raw(&[("RequestProfiles", text(value))]), "test");
            assert_eq!(
                layer.request_profiles,
                Some(expected.iter().map(|s| s.to_string()).collect()),
                "{value:?}"
            );
        }
        for (value, expected) in [(" Sign-in ", Some("Sign-in")), ("  ", None)] {
            let layer = to_layer(&raw(&[("SignInCertificateProfile", text(value))]), "test");
            assert_eq!(
                layer.sign_in_certificate_profile.as_deref(),
                expected,
                "{value:?}"
            );
        }
        for name in [
            "CompletePrepared",
            "RequestProfiles",
            "SignInCertificateProfile",
        ] {
            let wrong = if name == "CompletePrepared" {
                text("yes")
            } else {
                PolicyValue::Int(1)
            };
            assert_eq!(
                to_layer(&raw(&[(name, wrong)]), "test"),
                Layer::default(),
                "{name}"
            );
        }
    }

    #[test]
    fn the_automatic_renewal_sets_the_layer_and_a_bad_one_is_ignored() {
        for (name, renewal) in [
            ("off", AutomaticRenewal::Off),
            ("newKey", AutomaticRenewal::NewKey),
            ("sameKey", AutomaticRenewal::SameKey),
        ] {
            let layer = to_layer(&raw(&[("AutomaticRenewal", text(name))]), "test");
            assert_eq!(layer.automatic_renewal, Some(renewal));
        }
        for value in [text("always"), text(""), PolicyValue::Bool(true)] {
            let layer = to_layer(&raw(&[("AutomaticRenewal", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn the_unlock_names_set_the_layer() {
        let layer = to_layer(
            &raw(&[
                ("RequireUnlock", PolicyValue::Bool(false)),
                ("LockAfterIdle", PolicyValue::Int(20)),
            ]),
            "test",
        );
        assert_eq!(layer.require_unlock, Some(false));
        assert_eq!(layer.lock_after_idle, IdleMinutes::new(20));
    }

    #[test]
    fn lock_after_idle_outside_one_to_1440_is_ignored() {
        for (minutes, accepted) in [
            (-1, false),
            (0, false),
            (1, true),
            (1440, true),
            (1441, false),
        ] {
            let layer = to_layer(
                &raw(&[("LockAfterIdle", PolicyValue::Int(minutes))]),
                "test",
            );
            assert_eq!(layer.lock_after_idle.is_some(), accepted, "{minutes}");
        }
    }

    #[test]
    fn check_interval_outside_five_to_1440_is_ignored() {
        for (minutes, accepted) in [
            (-5, false),
            (0, false),
            (4, false),
            (5, true),
            (45, true),
            (1440, true),
            (1441, false),
        ] {
            let layer = to_layer(
                &raw(&[("CheckInterval", PolicyValue::Int(minutes))]),
                "test",
            );
            assert_eq!(layer.check_every.is_some(), accepted, "{minutes}");
        }
        for value in [text("15"), PolicyValue::Bool(true), PolicyValue::Other] {
            let layer = to_layer(&raw(&[("CheckInterval", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn expiry_warning_days_outside_one_to_365_are_ignored() {
        for (days, accepted) in [
            (-7, false),
            (0, false),
            (1, true),
            (45, true),
            (365, true),
            (366, false),
        ] {
            let layer = to_layer(
                &raw(&[("ExpiryWarningDays", PolicyValue::Int(days))]),
                "test",
            );
            assert_eq!(layer.warn_days.is_some(), accepted, "{days}");
        }
        for value in [text("30"), PolicyValue::Bool(true), PolicyValue::Other] {
            let layer = to_layer(&raw(&[("ExpiryWarningDays", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn wrong_types_for_the_unlock_names_are_ignored() {
        for value in [text("true"), PolicyValue::Int(1), PolicyValue::Other] {
            let layer = to_layer(&raw(&[("RequireUnlock", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
        for value in [text("20"), PolicyValue::Bool(true), PolicyValue::Other] {
            let layer = to_layer(&raw(&[("LockAfterIdle", value)]), "test");
            assert_eq!(layer, Layer::default());
        }
    }

    #[test]
    fn all_levels_are_recognised() {
        for (name, level) in [
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
        ] {
            let layer = to_layer(&raw(&[("LogLevel", text(name))]), "test");
            assert_eq!(layer.log_level, Some(level));
        }
    }

    #[test]
    fn wrong_types_unknown_names_and_bad_levels_are_ignored() {
        let layer = to_layer(
            &raw(&[
                ("StartAtLogin", PolicyValue::Int(2)),
                ("AutomaticUpdates", PolicyValue::Int(0)),
                ("LogLevel", text("loud")),
                ("Other", PolicyValue::Bool(true)),
            ]),
            "test",
        );
        assert_eq!(layer, Layer::default());
        let layer = to_layer(
            &raw(&[
                ("StartAtLogin", text("true")),
                ("AutomaticUpdates", text("false")),
                ("LogLevel", PolicyValue::Bool(true)),
            ]),
            "test",
        );
        assert_eq!(layer, Layer::default());
    }

    #[test]
    fn machine_wins_per_key() {
        let machine = Layer {
            start_at_login: Some(false),
            automatic_updates: Some(false),
            ilm_url: IlmUrl::parse("machine.example.com").ok(),
            ..Layer::default()
        };
        let user = Layer {
            start_at_login: Some(true),
            automatic_updates: Some(true),
            log_level: Some(LogLevel::Warn),
            ilm_url: IlmUrl::parse("user.example.com").ok(),
            sign_in_provider: Some("Corporate".into()),
            sign_in_method: Some(SignInMethod::Certificate),
            require_unlock: Some(false),
            lock_after_idle: IdleMinutes::new(10),
            check_every: CheckMinutes::new(10),
            warn_days: WarnDays::new(45),
            key_storages: Some(vec![Storage::Tpm]),
            default_key_storage: Some(Storage::Tpm),
            automatic_renewal: Some(AutomaticRenewal::SameKey),
            complete_prepared: Some(true),
            request_profiles: Some(vec!["Web".into()]),
            sign_in_certificate_profile: Some("Sign-in".into()),
            ..Layer::default()
        };
        let merged = merge(machine, user);
        assert_eq!(merged.complete_prepared, Some(true));
        assert_eq!(merged.request_profiles, Some(vec!["Web".to_string()]));
        assert_eq!(
            merged.sign_in_certificate_profile.as_deref(),
            Some("Sign-in")
        );
        assert_eq!(merged.automatic_renewal, Some(AutomaticRenewal::SameKey));
        assert_eq!(merged.key_storages, Some(vec![Storage::Tpm]));
        assert_eq!(merged.default_key_storage, Some(Storage::Tpm));
        assert_eq!(merged.check_every, CheckMinutes::new(10));
        assert_eq!(merged.warn_days, WarnDays::new(45));
        assert_eq!(merged.require_unlock, Some(false));
        assert_eq!(merged.lock_after_idle, IdleMinutes::new(10));
        assert_eq!(merged.sign_in_method, Some(SignInMethod::Certificate));
        assert_eq!(merged.start_at_login, Some(false));
        assert_eq!(merged.automatic_updates, Some(false));
        assert_eq!(merged.log_level, Some(LogLevel::Warn));
        assert_eq!(merged.ilm_url, IlmUrl::parse("machine.example.com").ok());
        assert_eq!(merged.sign_in_provider.as_deref(), Some("Corporate"));
    }

    fn folder(uid: u32, mode: u32) -> FileMeta {
        FileMeta {
            is_symlink: false,
            is_file: false,
            uid,
            mode,
        }
    }

    fn file(uid: u32, mode: u32) -> FileMeta {
        FileMeta {
            is_file: true,
            ..folder(uid, mode)
        }
    }

    #[test]
    fn root_owned_file_under_root_owned_folders_is_trusted() {
        let chain = [file(0, 0o100644), folder(0, 0o40755), folder(0, 0o40755)];
        assert_eq!(trusted(&chain), Ok(()));
    }

    #[test]
    fn untrusted_chains_are_refused_with_a_reason() {
        let symlink = FileMeta {
            is_symlink: true,
            ..file(0, 0o120777)
        };
        let linked_folder = FileMeta {
            is_symlink: true,
            ..folder(0, 0o120755)
        };
        let cases = [
            (vec![], Untrusted::EmptyChain),
            (vec![symlink], Untrusted::Symlink),
            (vec![file(0, 0o644), linked_folder], Untrusted::Symlink),
            (vec![folder(0, 0o755)], Untrusted::NotAFile),
            (vec![file(501, 0o644)], Untrusted::NotOwnedByRoot),
            (
                vec![file(0, 0o644), folder(501, 0o755)],
                Untrusted::NotOwnedByRoot,
            ),
            (vec![file(0, 0o664)], Untrusted::WritableByOthers),
            (vec![file(0, 0o646)], Untrusted::WritableByOthers),
            (
                vec![file(0, 0o644), folder(0, 0o775)],
                Untrusted::WritableByOthers,
            ),
            (
                vec![file(0, 0o644), folder(0, 0o757)],
                Untrusted::WritableByOthers,
            ),
        ];
        for (chain, reason) in cases {
            assert_eq!(trusted(&chain), Err(reason), "{chain:?}");
            assert!(!reason.to_string().is_empty());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_temporary_file_is_not_trusted_unless_root_owns_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy");
        std::fs::write(&path, b"x").unwrap();
        let chain = file_chain(&path).unwrap();
        assert!(chain[0].is_file);
        assert!(chain.len() > 2);
        assert!(trusted(&chain).is_err());
        assert!(file_chain(&dir.path().join("missing")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn read_file_ignores_untrusted_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.json");
        std::fs::write(&path, br#"{"StartAtLogin": false}"#).unwrap();
        // The temporary folder is not root's, so the source is refused.
        assert_eq!(read_file(&path, linux::parse_json), Layer::default());
        assert_eq!(
            read_file(&dir.path().join("missing"), linux::parse_json),
            Layer::default()
        );
    }

    #[test]
    fn read_gives_a_layer_on_any_system() {
        // No policy is installed on a developer machine or in the unit test run.
        let _ = read();
    }
}
