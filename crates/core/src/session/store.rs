//! Where the refresh token lives between runs: the protected storage of the system.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use keyring_core::api::CredentialStore;
use serde::{Deserialize, Serialize};

use crate::ilm::IlmUrl;
use crate::oauth::token::RefreshToken;

const SERVICE: &str = "com.omnitrust.identity-manager";

/// What is kept for one ILM: the refresh token and what it belongs to.
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    pub ilm: IlmUrl,
    pub issuer: String,
    pub client_id: String,
    pub resource: Option<String>,
    pub refresh_token: RefreshToken,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("ilm", &self.ilm)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct Stored {
    ilm: IlmUrl,
    issuer: String,
    client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    refresh_token: String,
}

impl From<&Item> for Stored {
    fn from(item: &Item) -> Self {
        Self {
            ilm: item.ilm.clone(),
            issuer: item.issuer.clone(),
            client_id: item.client_id.clone(),
            resource: item.resource.clone(),
            refresh_token: item.refresh_token.as_str().to_owned(),
        }
    }
}

impl From<Stored> for Item {
    fn from(stored: Stored) -> Self {
        Self {
            ilm: stored.ilm,
            issuer: stored.issuer,
            client_id: stored.client_id,
            resource: stored.resource,
            refresh_token: RefreshToken::new(stored.refresh_token),
        }
    }
}

/// The storage could not be used. The text never holds the item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
impl StoreError {
    pub(crate) fn for_tests(text: &str) -> Self {
        Self(text.to_owned())
    }
}

impl From<keyring_core::Error> for StoreError {
    fn from(error: keyring_core::Error) -> Self {
        Self(error.to_string())
    }
}

/// One item per ILM address.
pub trait RefreshStore: Send + Sync {
    fn load(&self, ilm: &IlmUrl) -> Result<Option<Item>, StoreError>;
    fn save(&self, item: &Item) -> Result<(), StoreError>;
    /// Deleting what is not there is not an error.
    fn delete(&self, ilm: &IlmUrl) -> Result<(), StoreError>;
}

/// The protected storage of the system: the keychain, the Credential Manager or the Secret Service.
pub struct KeyringStore(Arc<CredentialStore>);

impl KeyringStore {
    pub fn system() -> Result<Self, StoreError> {
        Ok(Self::with(system_store()?))
    }

    fn with(store: Arc<CredentialStore>) -> Self {
        Self(store)
    }

    fn entry(&self, ilm: &IlmUrl) -> Result<keyring_core::Entry, StoreError> {
        Ok(self.0.build(SERVICE, ilm.as_str(), None)?)
    }
}

#[cfg(target_os = "macos")]
fn system_store() -> Result<Arc<CredentialStore>, StoreError> {
    Ok(apple_native_keyring_store::keychain::Store::new()?)
}

#[cfg(windows)]
fn system_store() -> Result<Arc<CredentialStore>, StoreError> {
    Ok(windows_native_keyring_store::Store::new()?)
}

#[cfg(target_os = "linux")]
fn system_store() -> Result<Arc<CredentialStore>, StoreError> {
    Ok(zbus_secret_service_keyring_store::Store::new()?)
}

impl RefreshStore for KeyringStore {
    fn load(&self, ilm: &IlmUrl) -> Result<Option<Item>, StoreError> {
        let text = match self.entry(ilm)?.get_password() {
            Ok(text) => text,
            Err(keyring_core::Error::NoEntry) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored = serde_json::from_str::<Stored>(&text)
            .map_err(|_| StoreError("The saved sign-in is not readable.".into()))?;
        Ok(Some(stored.into()).filter(|item: &Item| item.ilm == *ilm))
    }

    fn save(&self, item: &Item) -> Result<(), StoreError> {
        let text = serde_json::to_string(&Stored::from(item))
            .map_err(|_| StoreError("The sign-in could not be saved.".into()))?;
        Ok(self.entry(&item.ilm)?.set_password(&text)?)
    }

    fn delete(&self, ilm: &IlmUrl) -> Result<(), StoreError> {
        match self.entry(ilm)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Keeps items in memory, for tests.
#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Item>>);

impl MemoryStore {
    fn items(&self) -> std::sync::MutexGuard<'_, HashMap<String, Item>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl RefreshStore for MemoryStore {
    fn load(&self, ilm: &IlmUrl) -> Result<Option<Item>, StoreError> {
        Ok(self.items().get(ilm.as_str()).cloned())
    }

    fn save(&self, item: &Item) -> Result<(), StoreError> {
        self.items().insert(item.ilm.to_string(), item.clone());
        Ok(())
    }

    fn delete(&self, ilm: &IlmUrl) -> Result<(), StoreError> {
        self.items().remove(ilm.as_str());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyring_core::api::CredentialStoreApi;

    fn ilm(host: &str) -> IlmUrl {
        IlmUrl::parse(host).unwrap()
    }

    fn item(host: &str, refresh: &str) -> Item {
        Item {
            ilm: ilm(host),
            issuer: "https://idp.example.com".into(),
            client_id: "app".into(),
            resource: Some("https://ilm.example.com/api".into()),
            refresh_token: RefreshToken::new(refresh),
        }
    }

    fn keyring() -> KeyringStore {
        KeyringStore::with(keyring_core::mock::Store::new().unwrap())
    }

    fn stores() -> Vec<Box<dyn RefreshStore>> {
        vec![Box::new(MemoryStore::default()), Box::new(keyring())]
    }

    #[test]
    fn an_item_is_saved_loaded_replaced_and_deleted() {
        for store in stores() {
            let address = ilm("ilm.example.com");
            assert_eq!(store.load(&address), Ok(None));
            store.save(&item("ilm.example.com", "r1")).unwrap();
            assert!(store.load(&address).unwrap() == Some(item("ilm.example.com", "r1")));
            store.save(&item("ilm.example.com", "r2")).unwrap();
            let loaded = store.load(&address).unwrap().unwrap();
            assert_eq!(loaded.refresh_token.as_str(), "r2");
            store.delete(&address).unwrap();
            assert_eq!(store.load(&address), Ok(None));
            store.delete(&address).unwrap();
        }
    }

    #[test]
    fn items_are_kept_per_address() {
        for store in stores() {
            store.save(&item("a.example.com", "ra")).unwrap();
            assert_eq!(store.load(&ilm("b.example.com")), Ok(None));
            store.save(&item("b.example.com", "rb")).unwrap();
            store.delete(&ilm("a.example.com")).unwrap();
            assert!(store.load(&ilm("b.example.com")).unwrap().is_some());
        }
    }

    #[test]
    fn the_keyring_holds_one_json_item_under_the_service_and_the_address() {
        let credentials = keyring_core::mock::Store::new().unwrap();
        let store = KeyringStore::with(credentials.clone());
        store.save(&item("ilm.example.com", "r1")).unwrap();

        let text = credentials
            .build(SERVICE, "https://ilm.example.com", None)
            .unwrap()
            .get_password()
            .unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "ilm": "https://ilm.example.com",
                "issuer": "https://idp.example.com",
                "client_id": "app",
                "resource": "https://ilm.example.com/api",
                "refresh_token": "r1",
            })
        );
    }

    #[test]
    fn an_unreadable_item_is_an_error_and_a_foreign_one_is_ignored() {
        let credentials = keyring_core::mock::Store::new().unwrap();
        let store = KeyringStore::with(credentials.clone());
        let entry = credentials
            .build(SERVICE, "https://ilm.example.com", None)
            .unwrap();

        entry.set_password("not json").unwrap();
        let error = store.load(&ilm("ilm.example.com")).unwrap_err();
        assert!(!error.to_string().contains("not json"));

        let other = serde_json::to_string(&Stored::from(&item("other.example.com", "r"))).unwrap();
        entry.set_password(&other).unwrap();
        assert_eq!(store.load(&ilm("ilm.example.com")), Ok(None));
    }

    #[test]
    fn debug_output_hides_the_refresh_token() {
        let shown = format!("{:?}", item("ilm.example.com", "refresh-secret"));
        assert!(!shown.contains("refresh-secret"));
        assert!(shown.contains("ilm.example.com"));
    }
}
