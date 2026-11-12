//! The Windows source: the values of a registry key.

use super::{LOG_LEVEL, PolicyValue, RawMap, START_AT_LOGIN};
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

/// `REG_DWORD` 0 and 1 are booleans, other numbers stay integers, `REG_SZ` is text. Value names ignore case, as
/// they do in the registry.
pub fn parse_registry(values: impl IntoIterator<Item = (String, RegValue)>) -> RawMap {
    values
        .into_iter()
        .map(|(name, value)| {
            let value = match value {
                RegValue::Dword(0) => PolicyValue::Bool(false),
                RegValue::Dword(1) => PolicyValue::Bool(true),
                RegValue::Dword(number) => PolicyValue::Int(i64::from(number)),
                RegValue::Sz(text) => PolicyValue::Text(text),
                RegValue::Other => PolicyValue::Other,
            };
            (known_name(name), value)
        })
        .collect()
}

fn known_name(name: String) -> String {
    [START_AT_LOGIN, LOG_LEVEL]
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
            ]),
            "test",
        );
        assert_eq!(layer.start_at_login, Some(false));
        assert_eq!(layer.log_level, Some(crate::settings::LogLevel::Debug));
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
