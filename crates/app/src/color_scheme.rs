use std::sync::{Mutex, PoisonError};

use serde::Serialize;
use tauri::State;

#[cfg(any(target_os = "linux", test))]
/// The event the interface listens to; its payload is a `Scheme` or null.
pub const EVENT: &str = "color-scheme";

// Only Linux asks the desktop, so elsewhere nothing builds a scheme.
/// A colour scheme the desktop asks for.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "lowercase"))]
pub enum Scheme {
    Dark,
    Light,
}

#[cfg(any(target_os = "linux", test))]
/// Maps the portal's `color-scheme` value: 1 prefers dark, 2 prefers light, anything else states no preference.
pub fn from_portal(value: u32) -> Option<Scheme> {
    match value {
        1 => Some(Scheme::Dark),
        2 => Some(Scheme::Light),
        _ => None,
    }
}

/// The latest scheme the desktop asked for, for windows that open after a change.
#[derive(Default)]
pub struct Current(Mutex<Option<Scheme>>);

#[tauri::command]
pub fn color_scheme(current: State<'_, Current>) -> Option<Scheme> {
    *current.0.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(any(target_os = "linux", test))]
fn publish<R: tauri::Runtime>(app: &tauri::AppHandle<R>, scheme: Option<Scheme>) {
    use tauri::{Emitter, Manager};

    let current = app.state::<Current>();
    *current.0.lock().unwrap_or_else(PoisonError::into_inner) = scheme;
    if let Err(error) = app.emit(EVENT, scheme) {
        log::warn!("the colour scheme could not be sent to the windows: {error}");
    }
}

/// Follows the desktop's colour scheme on a background thread; web views on Linux do not.
#[cfg(target_os = "linux")]
pub fn watch<R: tauri::Runtime>(app: tauri::AppHandle<R>) {
    std::thread::spawn(move || {
        if let Err(error) = portal::follow(&app) {
            log::info!("the desktop reports no colour scheme: {error}");
        }
    });
}

#[cfg(target_os = "linux")]
mod portal {
    use tauri::{AppHandle, Runtime};
    use zbus::blocking::{Connection, Proxy};
    use zbus::zvariant::{OwnedValue, Value};

    use super::{from_portal, publish};

    const NAMESPACE: &str = "org.freedesktop.appearance";
    const KEY: &str = "color-scheme";

    /// The scheme in a value read from the portal. `Read`, which portals older than version 2 offer in place of
    /// `ReadOne`, wraps the value in one more variant.
    pub(super) fn scheme(value: &Value<'_>) -> Option<super::Scheme> {
        let value = match value {
            Value::Value(inner) => inner,
            other => other,
        };
        u32::try_from(value).ok().and_then(from_portal)
    }

    fn read(settings: &Proxy<'_>) -> zbus::Result<OwnedValue> {
        settings
            .call("ReadOne", &(NAMESPACE, KEY))
            .or_else(|_| settings.call("Read", &(NAMESPACE, KEY)))
    }

    /// Publishes the current value, then every change, until the portal goes away.
    pub fn follow<R: Runtime>(app: &AppHandle<R>) -> zbus::Result<()> {
        let connection = Connection::session()?;
        let settings = Proxy::new(
            &connection,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Settings",
        )?;
        // Subscribe first so that a change between the read and the loop is not lost.
        let changes = settings.receive_signal("SettingChanged")?;
        // A failed read leaves the scheme unset; the changes still arrive.
        match read(&settings) {
            Ok(value) => publish(app, scheme(&value)),
            Err(error) => log::info!("the colour scheme could not be read: {error}"),
        }
        for message in changes {
            let Ok((namespace, key, value)) =
                message.body().deserialize::<(String, String, OwnedValue)>()
            else {
                continue;
            };
            if namespace == NAMESPACE && key == KEY {
                publish(app, scheme(&value));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tauri::test::{MockRuntime, mock_context, noop_assets};
    use tauri::{Listener, Manager};

    fn app() -> tauri::App<MockRuntime> {
        tauri::Builder::<MockRuntime>::new()
            .enable_macos_default_menu(false)
            .manage(Current::default())
            .build(mock_context(noop_assets()))
            .expect("the mock app builds")
    }

    #[test]
    fn maps_the_portal_values() {
        assert_eq!(from_portal(0), None);
        assert_eq!(from_portal(1), Some(Scheme::Dark));
        assert_eq!(from_portal(2), Some(Scheme::Light));
        assert_eq!(from_portal(3), None);
    }

    #[test]
    fn serialises_in_lower_case() {
        assert_eq!(serde_json::to_string(&Scheme::Dark).unwrap(), "\"dark\"");
        assert_eq!(serde_json::to_string(&Scheme::Light).unwrap(), "\"light\"");
    }

    #[test]
    fn nothing_is_reported_before_the_first_value() {
        let app = app();
        assert_eq!(color_scheme(app.state()), None);
    }

    #[test]
    fn publishing_stores_the_scheme_and_sends_it_to_the_windows() {
        let app = app();
        let (sent, received) = mpsc::channel();
        app.listen(EVENT, move |event| {
            sent.send(event.payload().to_string()).unwrap();
        });

        publish(app.handle(), Some(Scheme::Dark));
        assert_eq!(color_scheme(app.state()), Some(Scheme::Dark));
        assert_eq!(received.recv().unwrap(), "\"dark\"");

        publish(app.handle(), None);
        assert_eq!(color_scheme(app.state()), None);
        assert_eq!(received.recv().unwrap(), "null");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod portal_tests {
    use super::Scheme;
    use super::portal::scheme;
    use zbus::zvariant::Value;

    #[test]
    fn reads_a_plain_value_from_read_one_and_a_signal() {
        assert_eq!(scheme(&Value::U32(1)), Some(Scheme::Dark));
        assert_eq!(scheme(&Value::U32(2)), Some(Scheme::Light));
        assert_eq!(scheme(&Value::U32(0)), None);
    }

    #[test]
    fn unwraps_the_extra_variant_of_the_older_read() {
        let wrapped = Value::Value(Box::new(Value::U32(1)));
        assert_eq!(scheme(&wrapped), Some(Scheme::Dark));
    }

    #[test]
    fn a_value_that_is_not_a_number_states_no_preference() {
        assert_eq!(scheme(&Value::from("dark")), None);
    }
}
