//! The macOS source: a property list, XML or binary.

use super::{PolicyValue, RawMap};
#[cfg(target_os = "macos")]
use crate::settings::Layer;
use plist::Value;
#[cfg(target_os = "macos")]
use std::path::Path;

#[cfg(target_os = "macos")]
const FILE: &str = "com.omnitrust.identity-manager.plist";
#[cfg(target_os = "macos")]
const FOLDER: &str = "/Library/Managed Preferences";

/// The device file, then the file of the user the process runs as. The name comes from the user
/// database by process uid, not from the environment, which the person controls.
#[cfg(target_os = "macos")]
pub fn read() -> Layer {
    let machine = super::read_file(&Path::new(FOLDER).join(FILE), parse_plist);
    let user = match nix::unistd::User::from_uid(nix::unistd::getuid()) {
        Ok(Some(user)) if usable_name(&user.name) => {
            super::read_file(&Path::new(FOLDER).join(user.name).join(FILE), parse_plist)
        }
        _ => Layer::default(),
    };
    super::merge(machine, user)
}

/// A name that is one folder element.
#[cfg(target_os = "macos")]
fn usable_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\']) && name != ".."
}

/// Reads booleans, integers and strings of the top-level dictionary; other values are kept as `Other`.
/// Keys that macOS adds when it installs a profile (`PayloadUUID`, `_manualProfile`) are skipped.
pub fn parse_plist(bytes: &[u8], source: &str) -> RawMap {
    let dict = match Value::from_reader(std::io::Cursor::new(bytes)) {
        Ok(Value::Dictionary(dict)) => dict,
        Ok(_) => {
            log::warn!("policy {source} is not a dictionary; ignored");
            return RawMap::new();
        }
        Err(_) => {
            log::warn!("policy {source} is not a valid property list; ignored");
            return RawMap::new();
        }
    };
    dict.into_iter()
        .filter(|(name, _)| !name.starts_with("Payload") && !name.starts_with('_'))
        .map(|(name, value)| {
            let value = match value {
                Value::Boolean(on) => PolicyValue::Bool(on),
                Value::Integer(number) => number
                    .as_signed()
                    .map_or(PolicyValue::Other, PolicyValue::Int),
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

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>StartAtLogin</key><false/>
<key>LogLevel</key><string>debug</string>
<key>Count</key><integer>7</integer>
<key>Ratio</key><real>1.5</real>
</dict></plist>"#;

    fn expected() -> RawMap {
        RawMap::from([
            ("StartAtLogin".into(), PolicyValue::Bool(false)),
            ("LogLevel".into(), PolicyValue::Text("debug".into())),
            ("Count".into(), PolicyValue::Int(7)),
            ("Ratio".into(), PolicyValue::Other),
        ])
    }

    #[test]
    fn xml_plist_yields_booleans_integers_and_strings() {
        assert_eq!(parse_plist(XML.as_bytes(), "test"), expected());
    }

    #[test]
    fn binary_plist_yields_the_same_values() {
        let value = Value::from_reader_xml(XML.as_bytes()).unwrap();
        let mut bytes = Vec::new();
        value.to_writer_binary(&mut bytes).unwrap();
        assert_eq!(parse_plist(&bytes, "test"), expected());
    }

    #[test]
    fn malformed_or_non_dictionary_plist_is_empty() {
        assert!(parse_plist(b"not a plist", "test").is_empty());
        let array = br#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#;
        assert!(parse_plist(array, "test").is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_plain_names_are_usable_as_a_folder() {
        assert!(usable_name("alice"));
        for name in ["", "..", "a/b", "a\\b"] {
            assert!(!usable_name(name), "{name:?}");
        }
    }

    #[test]
    fn keys_added_by_a_profile_install_are_skipped() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>_manualProfile</key><true/>
<key>PayloadUUID</key><string>257F57EC-2F51-452A-ABFE-1648B83206B1</string>
<key>LogLevel</key><string>debug</string>
</dict></plist>"#;
        let raw = parse_plist(xml.as_bytes(), "test");
        assert_eq!(raw.keys().collect::<Vec<_>>(), ["LogLevel"]);
    }

    #[test]
    fn a_huge_plist_integer_is_other() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>StartAtLogin</key><integer>18446744073709551615</integer></dict></plist>"#;
        let raw = parse_plist(xml, "test");
        assert_eq!(raw["StartAtLogin"], PolicyValue::Other);
    }

    #[test]
    fn a_plist_integer_is_not_a_bool_for_the_layer() {
        let xml = br#"<?xml version="1.0"?><plist version="1.0"><dict>
<key>StartAtLogin</key><integer>1</integer></dict></plist>"#;
        let layer = crate::policy::to_layer(&parse_plist(xml, "test"), "test");
        assert_eq!(layer.start_at_login, None);
    }
}
