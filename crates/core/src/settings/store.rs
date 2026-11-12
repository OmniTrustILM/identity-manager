//! The person's settings file: tolerant to read, atomic to write.

use std::fs;
use std::io;
use std::path::Path;

use serde_json::{Map, Value};

use super::{Layer, LogLevel};

const START_AT_LOGIN: &str = "startAtLogin";
const LOG_LEVEL: &str = "logLevel";

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

fn parse(entries: Map<String, Value>) -> Layer {
    let mut layer = Layer::default();
    for (key, value) in entries {
        match key.as_str() {
            START_AT_LOGIN => layer.start_at_login = value.as_bool(),
            LOG_LEVEL => layer.log_level = serde_json::from_value::<LogLevel>(value).ok(),
            _ => log::warn!("ignoring unknown setting {key}"),
        }
        let kept = match key.as_str() {
            START_AT_LOGIN => layer.start_at_login.is_some(),
            LOG_LEVEL => layer.log_level.is_some(),
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
    let text = serde_json::to_string_pretty(&entries)?;

    if let Some(folder) = path.parent() {
        fs::create_dir_all(folder)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = Path::new(&temporary);
    fs::write(temporary, text)?;
    fs::rename(temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(temporary);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn person() -> Layer {
        Layer {
            start_at_login: Some(false),
            log_level: Some(LogLevel::Debug),
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
            serde_json::json!({ "startAtLogin": false, "logLevel": "debug" })
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
            }
        );
        fs::write(&path, r#"{"startAtLogin":true,"logLevel":"loud"}"#).unwrap();
        assert_eq!(
            load(&path),
            Layer {
                start_at_login: Some(true),
                log_level: None,
            }
        );
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
}
