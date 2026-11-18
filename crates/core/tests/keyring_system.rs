//! Uses the protected storage a CI runner provides (`scripts/verify.sh keyring-system` runs it).

use im_core::ilm::IlmUrl;
use im_core::oauth::token::RefreshToken;
use im_core::session::{Item, KeyringStore, RefreshStore};

#[test]
#[ignore = "writes to the protected storage of the system; scripts/verify.sh keyring-system runs it on CI"]
fn an_item_is_saved_loaded_and_deleted_in_the_system_storage() {
    let store = KeyringStore::system().expect("the system provides protected storage");
    let ilm = IlmUrl::parse("keyring-system-test.example.com").unwrap();
    let item = Item {
        ilm: ilm.clone(),
        issuer: "https://idp.example.com".into(),
        client_id: "keyring-system-test".into(),
        resource: None,
        refresh_token: RefreshToken::new("refresh-token-for-the-test"),
    };

    store.save(&item).expect("the item is saved");
    let loaded = store.load(&ilm).expect("the item is read");
    store.delete(&ilm).expect("the item is deleted");

    assert!(loaded == Some(item));
    assert_eq!(store.load(&ilm), Ok(None));
}
