//! The name of the smart card that holds the key of a certificate, which the keychain does not tell: the token
//! that the key names, looked up with CryptoTokenKit. Nothing here uses the key or asks for a PIN.

use core_foundation::base::{CFType, TCFType, ToVoid};
use core_foundation::string::CFString;
use im_core::identity::{KeyOrigin, KeyOrigins};
use objc2_crypto_token_kit::TKTokenWatcher;
use objc2_foundation::NSString;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework_sys::item::kSecAttrTokenID;

/// Reads the card of a token identity from the token the system keeps it on.
pub struct TokenKeyOrigins;

impl KeyOrigins for TokenKeyOrigins {
    fn origins(&self, ders: &[&[u8]]) -> Vec<KeyOrigin> {
        if ders.is_empty() {
            return Vec::new();
        }
        let tokens = token_identities();
        // SAFETY: creating a watcher without handlers has no preconditions.
        let watcher = unsafe { TKTokenWatcher::new() };
        ders.iter()
            .map(|der| KeyOrigin {
                provider: None,
                card: tokens
                    .iter()
                    .find(|(found, _)| found.as_slice() == *der)
                    .and_then(|(_, identity)| token_id(identity))
                    .and_then(|id| slot_name(&watcher, &id)),
            })
            .collect()
    }
}

/// The identities that live on tokens, with the DER of their certificate.
fn token_identities() -> Vec<(Vec<u8>, SecIdentity)> {
    let results = ItemSearchOptions::new()
        .access_group_token()
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All)
        .search();
    match results {
        Ok(results) => results
            .into_iter()
            .filter_map(|result| match result {
                SearchResult::Ref(Reference::Identity(identity)) => Some(identity),
                _ => None,
            })
            .filter_map(|identity| Some((identity.certificate().ok()?.to_der(), identity)))
            .collect(),
        Err(error) => {
            log::warn!("no card names: the tokens cannot be searched: {error}");
            Vec::new()
        }
    }
}

/// The identifier of the token that holds the private key of `identity`.
fn token_id(identity: &SecIdentity) -> Option<String> {
    let key = identity.private_key().ok()?;
    let attributes = key.attributes();
    // SAFETY: reading a constant the Security framework exports.
    let name = unsafe { kSecAttrTokenID };
    let value = attributes.find(name.to_void())?;
    // SAFETY: the dictionary owns the value, which `wrap_under_get_rule` retains for the wrapper.
    let value = unsafe { CFType::wrap_under_get_rule(*value) };
    value.downcast::<CFString>().map(|text| text.to_string())
}

/// The name of the card or reader of the token, as the system reports it.
fn slot_name(watcher: &TKTokenWatcher, token_id: &str) -> Option<String> {
    let id = NSString::from_str(token_id);
    // SAFETY: `id` is a live string, and the watcher answers from the token daemon without touching the token.
    let info = unsafe { watcher.tokenInfoForTokenID(&id) }?;
    // SAFETY: the info object is live and the call only reads a property.
    let name = unsafe { info.slotName() }?.to_string();
    Some(name).filter(|name| !name.trim().is_empty())
}
