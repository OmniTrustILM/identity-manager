//! The Windows source: the values of a registry key.

use super::{
    CHECK_INTERVAL, ILM_URL, LOCK_AFTER_IDLE, LOG_LEVEL, PolicyValue, REQUIRE_UNLOCK, RawMap,
    SIGN_IN_METHOD, SIGN_IN_PROVIDER, START_AT_LOGIN,
};
#[cfg(windows)]
use crate::settings::Layer;

#[cfg(windows)]
const KEY: &str = r"SOFTWARE\Policies\OmniTrustILM\IdentityManager";

/// The machine key, then the user key; the machine wins per key.
#[cfg(windows)]
pub fn read() -> Layer {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    super::merge(
        read_key(HKEY_LOCAL_MACHINE, "HKLM"),
        read_key(HKEY_CURRENT_USER, "HKCU"),
    )
}

#[cfg(windows)]
fn read_key(hive: winreg::HKEY, scope: &str) -> Layer {
    use winreg::{RegKey, enums::RegType, types::FromRegValue};
    let source = format!(r"{scope}\{KEY}");
    let key = match RegKey::predef(hive).open_subkey(KEY) {
        Ok(key) => key,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            log::debug!("no policy at {source}");
            return Layer::default();
        }
        Err(error) => {
            log::warn!("policy {source} cannot be opened ({error}); ignored");
            return Layer::default();
        }
    };
    let values = key
        .enum_values()
        .filter_map(Result::ok)
        .map(|(name, value)| {
            let mapped = match value.vtype {
                RegType::REG_DWORD => {
                    u32::from_reg_value(&value).map_or(RegValue::Other, RegValue::Dword)
                }
                RegType::REG_SZ => {
                    String::from_reg_value(&value).map_or(RegValue::Other, RegValue::Sz)
                }
                _ => RegValue::Other,
            };
            (name, mapped)
        });
    let raw = parse_registry(values);
    log::info!("policy found at {source} with {} value(s)", raw.len());
    super::to_layer(&raw, &source)
}

/// A registry value as far as policy cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Dword(u32),
    Sz(String),
    Other,
}

/// `REG_DWORD` 0 and 1 are booleans, other numbers stay integers (`LockAfterIdle` and `CheckInterval` are always numbers), `REG_SZ` is text. Value names ignore case, as
/// they do in the registry.
pub fn parse_registry(values: impl IntoIterator<Item = (String, RegValue)>) -> RawMap {
    values
        .into_iter()
        .map(|(name, value)| {
            let name = known_name(name);
            let value = match value {
                RegValue::Dword(number) if name == LOCK_AFTER_IDLE || name == CHECK_INTERVAL => {
                    PolicyValue::Int(i64::from(number))
                }
                RegValue::Dword(0) => PolicyValue::Bool(false),
                RegValue::Dword(1) => PolicyValue::Bool(true),
                RegValue::Dword(number) => PolicyValue::Int(i64::from(number)),
                RegValue::Sz(text) => PolicyValue::Text(text),
                RegValue::Other => PolicyValue::Other,
            };
            (name, value)
        })
        .collect()
}

fn known_name(name: String) -> String {
    [
        START_AT_LOGIN,
        LOG_LEVEL,
        ILM_URL,
        REQUIRE_UNLOCK,
        LOCK_AFTER_IDLE,
        CHECK_INTERVAL,
        SIGN_IN_PROVIDER,
        SIGN_IN_METHOD,
    ]
    .into_iter()
    .find(|known| known.eq_ignore_ascii_case(&name))
    .map_or(name, str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::to_layer;

    fn parse(items: Vec<(&str, RegValue)>) -> RawMap {
        parse_registry(items.into_iter().map(|(name, v)| (name.to_string(), v)))
    }

    #[test]
    fn dwords_and_strings_map_to_values() {
        let raw = parse(vec![
            ("StartAtLogin", RegValue::Dword(0)),
            ("On", RegValue::Dword(1)),
            ("Big", RegValue::Dword(2)),
            ("LogLevel", RegValue::Sz("warn".into())),
            ("Binary", RegValue::Other),
        ]);
        assert_eq!(
            raw,
            RawMap::from([
                ("StartAtLogin".into(), PolicyValue::Bool(false)),
                ("On".into(), PolicyValue::Bool(true)),
                ("Big".into(), PolicyValue::Int(2)),
                ("LogLevel".into(), PolicyValue::Text("warn".into())),
                ("Binary".into(), PolicyValue::Other),
            ])
        );
    }

    #[test]
    fn value_names_match_in_any_case() {
        let layer = to_layer(
            &parse(vec![
                ("startatlogin", RegValue::Dword(0)),
                ("LOGLEVEL", RegValue::Sz("debug".into())),
                ("ilmurl", RegValue::Sz("ilm.example.com".into())),
                ("SIGNINPROVIDER", RegValue::Sz("Corporate".into())),
                ("signinmethod", RegValue::Sz("certificate".into())),
            ]),
            "test",
        );
        assert_eq!(layer.start_at_login, Some(false));
        assert_eq!(layer.log_level, Some(crate::settings::LogLevel::Debug));
        assert_eq!(
            layer.ilm_url,
            crate::ilm::IlmUrl::parse("ilm.example.com").ok()
        );
        assert_eq!(layer.sign_in_provider.as_deref(), Some("Corporate"));
        assert_eq!(
            layer.sign_in_method,
            Some(crate::settings::SignInMethod::Certificate)
        );
    }

    #[test]
    fn the_unlock_values_reach_the_layer() {
        for (minutes, expected) in [(1, 1), (90, 90)] {
            let layer = to_layer(
                &parse(vec![
                    ("requireunlock", RegValue::Dword(0)),
                    ("LockAfterIdle", RegValue::Dword(minutes)),
                ]),
                "test",
            );
            assert_eq!(layer.require_unlock, Some(false));
            assert_eq!(layer.lock_after_idle.map(|m| m.get()), Some(expected));
        }
        let layer = to_layer(&parse(vec![("LockAfterIdle", RegValue::Dword(0))]), "test");
        assert_eq!(layer.lock_after_idle, None);
    }

    #[test]
    fn check_interval_is_always_a_number() {
        for (minutes, expected) in [(5, Some(5)), (45, Some(45)), (1440, Some(1440)), (1, None)] {
            let layer = to_layer(
                &parse(vec![("checkinterval", RegValue::Dword(minutes))]),
                "test",
            );
            assert_eq!(layer.check_every.map(|m| m.get()), expected, "{minutes}");
        }
    }

    #[test]
    fn a_binary_value_is_not_a_bool_for_the_layer() {
        let layer = to_layer(&parse(vec![("StartAtLogin", RegValue::Other)]), "test");
        assert_eq!(layer.start_at_login, None);
    }

    #[test]
    fn dword_two_is_not_a_bool_for_the_layer() {
        let layer = to_layer(&parse(vec![("StartAtLogin", RegValue::Dword(2))]), "test");
        assert_eq!(layer.start_at_login, None);
    }
}
