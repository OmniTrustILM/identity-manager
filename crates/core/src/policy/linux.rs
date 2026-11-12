//! The Linux source: a JSON file.

use super::{PolicyValue, RawMap};
#[cfg(target_os = "linux")]
use crate::settings::Layer;
use serde_json::Value;

/// The one machine file.
#[cfg(target_os = "linux")]
pub fn read() -> Layer {
    super::read_file(
        std::path::Path::new("/etc/identity-manager/policy.json"),
        parse_json,
    )
}

/// Reads booleans, integers and strings of the top-level object; other values are kept as `Other`.
pub fn parse_json(bytes: &[u8], source: &str) -> RawMap {
    let object = match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(object)) => object,
        Ok(_) => {
            log::warn!("policy {source} is not an object; ignored");
            return RawMap::new();
        }
        Err(_) => {
            log::warn!("policy {source} is not valid JSON; ignored");
            return RawMap::new();
        }
    };
    object
        .into_iter()
        .map(|(name, value)| {
            let value = match value {
                Value::Bool(on) => PolicyValue::Bool(on),
                Value::Number(number) => {
                    number.as_i64().map_or(PolicyValue::Other, PolicyValue::Int)
                }
                Value::String(text) => PolicyValue::Text(text),
                _ => PolicyValue::Other,
            };
            (name, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::to_layer;

    #[test]
    fn json_yields_booleans_integers_strings_and_others() {
        let raw = parse_json(
            br#"{"StartAtLogin": true, "LogLevel": "error", "N": 3, "F": 1.5, "L": [1]}"#,
            "test",
        );
        assert_eq!(
            raw,
            RawMap::from([
                ("StartAtLogin".into(), PolicyValue::Bool(true)),
                ("LogLevel".into(), PolicyValue::Text("error".into())),
                ("N".into(), PolicyValue::Int(3)),
                ("F".into(), PolicyValue::Other),
                ("L".into(), PolicyValue::Other),
            ])
        );
    }

    #[test]
    fn a_json_null_or_huge_number_is_other() {
        let raw = parse_json(
            br#"{"StartAtLogin": null, "N": 18446744073709551615}"#,
            "test",
        );
        assert_eq!(raw["StartAtLogin"], PolicyValue::Other);
        assert_eq!(raw["N"], PolicyValue::Other);
        assert_eq!(to_layer(&raw, "test").start_at_login, None);
    }

    #[test]
    fn malformed_or_non_object_json_is_empty() {
        assert!(parse_json(b"{", "test").is_empty());
        assert!(parse_json(b"[true]", "test").is_empty());
    }

    #[test]
    fn a_json_string_is_not_a_bool_for_the_layer() {
        let raw = parse_json(br#"{"StartAtLogin": "true"}"#, "test");
        assert_eq!(to_layer(&raw, "test").start_at_login, None);
    }

    #[test]
    fn the_example_policy_file_parses_to_its_documented_values() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/policy/policy.json"
        ));
        let layer = to_layer(&parse_json(bytes, "example"), "example");
        assert_eq!(layer.start_at_login, Some(false));
        assert_eq!(layer.log_level, Some(crate::settings::LogLevel::Debug));
    }
}
