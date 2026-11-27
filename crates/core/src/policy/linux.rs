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
    fn check_interval_numbers_reach_the_layer() {
        for (value, expected) in [
            ("30", Some(30)),
            ("1440", Some(1440)),
            ("1", None),
            (r#""30""#, None),
        ] {
            let json = format!(r#"{{"CheckInterval": {value}}}"#);
            let layer = to_layer(&parse_json(json.as_bytes(), "test"), "test");
            assert_eq!(layer.check_every.map(|m| m.get()), expected, "{value}");
        }
    }

    #[test]
    fn expiry_warning_days_numbers_reach_the_layer() {
        for (value, expected) in [
            ("1", Some(1)),
            ("45", Some(45)),
            ("365", Some(365)),
            ("0", None),
            ("366", None),
            (r#""30""#, None),
        ] {
            let json = format!(r#"{{"ExpiryWarningDays": {value}}}"#);
            let layer = to_layer(&parse_json(json.as_bytes(), "test"), "test");
            assert_eq!(layer.warn_days.map(|d| d.get()), expected, "{value}");
        }
    }

    #[test]
    fn automatic_updates_reaches_the_layer() {
        let layer = to_layer(
            &parse_json(br#"{"AutomaticUpdates": false}"#, "test"),
            "test",
        );
        assert_eq!(layer.automatic_updates, Some(false));
        let layer = to_layer(
            &parse_json(br#"{"AutomaticUpdates": "false"}"#, "test"),
            "test",
        );
        assert_eq!(layer.automatic_updates, None);
    }

    #[test]
    fn key_storage_strings_reach_the_layer() {
        use crate::keys::Storage;
        let json = br#"{"KeyStorages": "software, tpm", "DefaultKeyStorage": "tpm"}"#;
        let layer = to_layer(&parse_json(json, "test"), "test");
        assert_eq!(
            layer.key_storages,
            Some(vec![Storage::Software, Storage::Tpm])
        );
        assert_eq!(layer.default_key_storage, Some(Storage::Tpm));
        let layer = to_layer(&parse_json(br#"{"KeyStorages": ["tpm"]}"#, "test"), "test");
        assert_eq!(layer.key_storages, None);
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
        assert_eq!(
            layer.ilm_url,
            crate::ilm::IlmUrl::parse("https://ilm.example.com").ok()
        );
        assert_eq!(layer.sign_in_provider.as_deref(), Some("Corporate"));
        assert_eq!(
            layer.sign_in_method,
            Some(crate::settings::SignInMethod::Oauth)
        );
        assert_eq!(layer.require_unlock, Some(true));
        assert_eq!(layer.lock_after_idle, crate::settings::IdleMinutes::new(15));
        assert_eq!(layer.check_every.map(|m| m.get()), Some(30));
        assert_eq!(layer.warn_days.map(|d| d.get()), Some(30));
        assert_eq!(
            layer.key_storages,
            Some(vec![
                crate::keys::Storage::Software,
                crate::keys::Storage::Tpm
            ])
        );
        assert_eq!(
            layer.default_key_storage,
            Some(crate::keys::Storage::Software)
        );
    }

    #[test]
    fn the_enrolment_values_reach_the_layer() {
        let json = br#"{"CompletePrepared": true, "RequestProfiles": "Web, Mail,",
            "SignInCertificateProfile": " Sign-in "}"#;
        let layer = to_layer(&parse_json(json, "test"), "test");
        assert_eq!(layer.complete_prepared, Some(true));
        assert_eq!(
            layer.request_profiles,
            Some(vec!["Web".to_string(), "Mail".to_string()])
        );
        assert_eq!(
            layer.sign_in_certificate_profile.as_deref(),
            Some("Sign-in")
        );
        let json = br#"{"CompletePrepared": "yes", "RequestProfiles": ["Web"]}"#;
        let layer = to_layer(&parse_json(json, "test"), "test");
        assert_eq!(layer.complete_prepared, None);
        assert_eq!(layer.request_profiles, None);
    }

    #[test]
    fn the_automatic_renewal_string_reaches_the_layer() {
        let layer = to_layer(
            &parse_json(br#"{"AutomaticRenewal": "newKey"}"#, "test"),
            "test",
        );
        assert_eq!(
            layer.automatic_renewal,
            Some(crate::settings::AutomaticRenewal::NewKey)
        );
        let layer = to_layer(
            &parse_json(br#"{"AutomaticRenewal": true}"#, "test"),
            "test",
        );
        assert_eq!(layer.automatic_renewal, None);
    }
}
