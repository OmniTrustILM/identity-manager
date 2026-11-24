//! The person's settings file: tolerant to read, atomic to write.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::{CheckMinutes, IdleMinutes, Layer, LogLevel, RememberedCertificate, WarnDays};
use crate::ilm::IlmUrl;

const START_AT_LOGIN: &str = "startAtLogin";
const LOG_LEVEL: &str = "logLevel";
const ILM_URL: &str = "ilmUrl";
const REQUIRE_UNLOCK: &str = "requireUnlock";
const LOCK_AFTER_IDLE: &str = "lockAfterIdle";
const CHECK_EVERY: &str = "checkEvery";
const WARN_DAYS: &str = "warnDays";
const SIGN_IN_CERTIFICATE: &str = "signInCertificate";

/// Reads the person's layer; a missing, unreadable or malformed file gives an empty layer
/// and an invalid or unknown key is dropped.
pub fn load(path: &Path) -> Layer {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            log::debug!("no settings file at {}", path.display());
            return Layer::default();
        }
        Err(error) => {
            log::warn!("settings file {} is unreadable: {error}", path.display());
            return Layer::default();
        }
    };
    let Ok(Value::Object(entries)) = serde_json::from_str::<Value>(&text) else {
        log::warn!(
            "settings file {} is not a JSON object; ignoring it",
            path.display()
        );
        return Layer::default();
    };
    parse(entries)
}

fn remembered_certificate(value: &Value) -> Option<RememberedCertificate> {
    let ilm = serde_json::from_value(value.get("ilm")?.clone()).ok()?;
    let fingerprint = value.get("fingerprint")?.as_str()?.parse().ok()?;
    Some(RememberedCertificate { ilm, fingerprint })
}

fn parse(entries: Map<String, Value>) -> Layer {
    let mut layer = Layer::default();
    for (key, value) in entries {
        match key.as_str() {
            START_AT_LOGIN => layer.start_at_login = value.as_bool(),
            LOG_LEVEL => layer.log_level = serde_json::from_value::<LogLevel>(value).ok(),
            ILM_URL => layer.ilm_url = serde_json::from_value::<IlmUrl>(value).ok(),
            REQUIRE_UNLOCK => layer.require_unlock = value.as_bool(),
            LOCK_AFTER_IDLE => {
                layer.lock_after_idle = value.as_i64().and_then(IdleMinutes::new);
            }
            CHECK_EVERY => layer.check_every = value.as_i64().and_then(CheckMinutes::option),
            WARN_DAYS => layer.warn_days = value.as_i64().and_then(WarnDays::option),
            SIGN_IN_CERTIFICATE => {
                layer.sign_in_certificate = remembered_certificate(&value);
            }
            _ => log::warn!("ignoring unknown setting {key}"),
        }
        let kept = match key.as_str() {
            START_AT_LOGIN => layer.start_at_login.is_some(),
            LOG_LEVEL => layer.log_level.is_some(),
            ILM_URL => layer.ilm_url.is_some(),
            REQUIRE_UNLOCK => layer.require_unlock.is_some(),
            LOCK_AFTER_IDLE => layer.lock_after_idle.is_some(),
            CHECK_EVERY => layer.check_every.is_some(),
            WARN_DAYS => layer.warn_days.is_some(),
            SIGN_IN_CERTIFICATE => layer.sign_in_certificate.is_some(),
            _ => continue,
        };
        if !kept {
            log::warn!("ignoring invalid value for setting {key}");
        }
    }
    layer
}

/// Writes the person's own values to `path`, creating the folder if needed; the file is
/// replaced atomically.
pub fn save(path: &Path, layer: &Layer) -> io::Result<()> {
    let mut entries = Map::new();
    if let Some(value) = layer.start_at_login {
        entries.insert(START_AT_LOGIN.into(), Value::Bool(value));
    }
    if let Some(value) = layer.log_level {
        entries.insert(LOG_LEVEL.into(), serde_json::to_value(value)?);
    }
    if let Some(value) = &layer.ilm_url {
        entries.insert(ILM_URL.into(), serde_json::to_value(value)?);
    }
    if let Some(value) = layer.require_unlock {
        entries.insert(REQUIRE_UNLOCK.into(), Value::Bool(value));
    }
    if let Some(value) = layer.lock_after_idle {
        entries.insert(LOCK_AFTER_IDLE.into(), Value::from(value.get()));
    }
    if let Some(value) = layer.check_every {
        entries.insert(CHECK_EVERY.into(), Value::from(value.get()));
    }
    if let Some(value) = layer.warn_days {
        entries.insert(WARN_DAYS.into(), Value::from(value.get()));
    }
    if let Some(value) = &layer.sign_in_certificate {
        entries.insert(
            SIGN_IN_CERTIFICATE.into(),
            serde_json::json!({
                "ilm": serde_json::to_value(&value.ilm)?,
                "fingerprint": value.fingerprint.to_string(),
            }),
        );
    }
    write_atomically(path, &serde_json::to_string_pretty(&entries)?)
}

/// The file `write_atomically` writes before it replaces `path`.
pub fn temporary_path(path: &Path) -> PathBuf {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    PathBuf::from(temporary)
}

/// Writes `text` to `path`, creating the folder if needed; the file is replaced atomically and, on Unix, readable
/// by its owner only.
pub fn write_atomically(path: &Path, text: &str) -> io::Result<()> {
    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)?;
    }
    let temporary = temporary_path(path);
    let _ = fs::remove_file(&temporary);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&temporary)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .and_then(|()| fs::rename(&temporary, path))
        .inspect_err(|_| {
            let _ = fs::remove_file(&temporary);
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Fingerprint;
    use tempfile::tempdir;

    fn person() -> Layer {
        Layer {
            start_at_login: Some(false),
            log_level: Some(LogLevel::Debug),
            ilm_url: Some(IlmUrl::parse("ilm.example.com").unwrap()),
            require_unlock: Some(false),
            lock_after_idle: IdleMinutes::new(15),
            check_every: CheckMinutes::option(30),
            warn_days: WarnDays::option(60),
            sign_in_provider: None,
            sign_in_method: None,
            key_storages: None,
            default_key_storage: None,
            sign_in_certificate: Some(remembered()),
        }
    }

    fn remembered() -> RememberedCertificate {
        RememberedCertificate {
            ilm: IlmUrl::parse("ilm.example.com").unwrap(),
            fingerprint: Fingerprint::of(b"certificate"),
        }
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempdir().unwrap();
        assert_eq!(load(&dir.path().join("settings.json")), Layer::default());
    }

    #[test]
    fn unreadable_file_is_empty() {
        let dir = tempdir().unwrap();
        assert_eq!(load(dir.path()), Layer::default());
    }

    #[test]
    fn round_trip_keeps_the_values() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        save(&path, &person()).unwrap();
        assert_eq!(load(&path), person());
    }

    #[test]
    fn file_uses_camel_case_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        save(&path, &person()).unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written,
            serde_json::json!({
                "startAtLogin": false,
                "logLevel": "debug",
                "ilmUrl": "https://ilm.example.com",
                "requireUnlock": false,
                "lockAfterIdle": 15,
                "checkEvery": 30,
                "warnDays": 60,
                "signInCertificate": {
                    "ilm": "https://ilm.example.com",
                    "fingerprint": Fingerprint::of(b"certificate").to_string()
                }
            })
        );
    }

    #[test]
    fn unknown_key_and_invalid_values_are_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{"theme":"dark","startAtLogin":"yes","logLevel":"debug"}"#,
        )
        .unwrap();
        assert_eq!(
            load(&path),
            Layer {
                start_at_login: None,
                log_level: Some(LogLevel::Debug),
                ..Layer::default()
            }
        );
        fs::write(&path, r#"{"startAtLogin":true,"logLevel":"loud"}"#).unwrap();
        assert_eq!(
            load(&path),
            Layer {
                start_at_login: Some(true),
                ..Layer::default()
            }
        );
        fs::write(&path, r#"{"ilmUrl":"http://ilm.example.com"}"#).unwrap();
        assert_eq!(load(&path), Layer::default());
        fs::write(&path, r#"{"ilmUrl":"ilm.example.com"}"#).unwrap();
        assert_eq!(
            load(&path).ilm_url,
            Some(IlmUrl::parse("https://ilm.example.com").unwrap())
        );
    }

    #[test]
    fn the_unlock_keys_are_read_and_invalid_values_are_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{"requireUnlock":false,"lockAfterIdle":1440}"#).unwrap();
        let layer = load(&path);
        assert_eq!(layer.require_unlock, Some(false));
        assert_eq!(layer.lock_after_idle, IdleMinutes::new(1440));
        for invalid in ["0", "1441", "-1", "1.5", r#""15""#, "true", "null"] {
            fs::write(&path, format!(r#"{{"lockAfterIdle":{invalid}}}"#)).unwrap();
            assert_eq!(load(&path), Layer::default(), "{invalid}");
        }
        fs::write(&path, r#"{"requireUnlock":"yes"}"#).unwrap();
        assert_eq!(load(&path), Layer::default());
    }

    #[test]
    fn check_every_is_read_only_for_the_offered_minutes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for minutes in [5, 15, 30, 60] {
            fs::write(&path, format!(r#"{{"checkEvery":{minutes}}}"#)).unwrap();
            assert_eq!(load(&path).check_every, CheckMinutes::option(minutes));
        }
        for invalid in [
            "0", "4", "10", "90", "1440", "-5", "15.5", r#""15""#, "null",
        ] {
            fs::write(&path, format!(r#"{{"checkEvery":{invalid}}}"#)).unwrap();
            assert_eq!(load(&path), Layer::default(), "{invalid}");
        }
    }

    #[test]
    fn warn_days_are_read_only_for_the_offered_days() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for days in [7, 14, 30, 60, 90] {
            fs::write(&path, format!(r#"{{"warnDays":{days}}}"#)).unwrap();
            assert_eq!(load(&path).warn_days, WarnDays::option(days));
        }
        for invalid in ["0", "1", "45", "365", "-7", "30.5", r#""30""#, "null"] {
            fs::write(&path, format!(r#"{{"warnDays":{invalid}}}"#)).unwrap();
            assert_eq!(load(&path), Layer::default(), "{invalid}");
        }
        fs::write(&path, "{}").unwrap();
        assert_eq!(load(&path).warn_days, None);
    }

    #[test]
    fn the_sign_in_certificate_is_read_and_an_invalid_one_is_dropped() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let fingerprint = Fingerprint::of(b"certificate");
        fs::write(
            &path,
            format!(
                r#"{{"signInCertificate":{{"ilm":"https://ilm.example.com","fingerprint":"{fingerprint}"}}}}"#
            ),
        )
        .unwrap();
        assert_eq!(load(&path).sign_in_certificate, Some(remembered()));
        for invalid in [
            r#"{"ilm":"https://ilm.example.com","fingerprint":"not a fingerprint"}"#,
            r#"{"fingerprint":"abc"}"#,
            r#""not an object""#,
            "7",
        ] {
            fs::write(&path, format!(r#"{{"signInCertificate":{invalid}}}"#)).unwrap();
            assert_eq!(load(&path), Layer::default());
        }
    }

    #[test]
    fn malformed_or_non_object_json_is_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for content in ["{ not json", "[true]", "", "null"] {
            fs::write(&path, content).unwrap();
            assert_eq!(load(&path), Layer::default(), "content: {content:?}");
        }
    }

    #[test]
    fn save_creates_the_folder_and_leaves_no_temporary_file() {
        let dir = tempdir().unwrap();
        let folder = dir.path().join("nested").join("config");
        let path = folder.join("settings.json");
        save(&path, &person()).unwrap();
        let names: Vec<_> = fs::read_dir(&folder)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["settings.json"]);
    }

    #[test]
    fn save_replaces_an_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, "{ not json").unwrap();
        save(&path, &person()).unwrap();
        assert_eq!(load(&path), person());
    }

    #[test]
    fn save_writes_only_the_set_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        save(&path, &Layer::default()).unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({}));

        let only_level = Layer {
            log_level: Some(LogLevel::Warn),
            ..Layer::default()
        };
        save(&path, &only_level).unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, serde_json::json!({ "logLevel": "warn" }));
    }

    #[test]
    fn failed_save_reports_the_error_and_leaves_no_temporary_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        fs::create_dir(&path).unwrap();
        assert!(save(&path, &person()).is_err());
        assert!(!dir.path().join("settings.json.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");

        write_atomically(&path, "{}").unwrap();
        write_atomically(&path, "{}").unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
