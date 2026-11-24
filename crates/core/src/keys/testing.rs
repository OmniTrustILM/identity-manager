//! A key storage with keys in memory, made by aws-lc through rcgen, and the checks every storage must pass.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ECDSA_P521_SHA512_ASN1, ML_DSA_44, ML_DSA_65,
    ML_DSA_87, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey, VerificationAlgorithm,
};
use rcgen::{
    KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512,
    PKCS_ML_DSA_44, PKCS_ML_DSA_65, PKCS_ML_DSA_87, PKCS_RSA_SHA256, PublicKeyData, RsaKeySize,
    SigningKey,
};
use x509_parser::prelude::FromDer;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::{KeyError, KeyId, KeyStorage, KeyType, Offer, Storage, StoredKey};

const TYPES: [KeyType; 9] = [
    KeyType::Rsa { bits: 2048 },
    KeyType::Rsa { bits: 3072 },
    KeyType::Rsa { bits: 4096 },
    KeyType::EcP256,
    KeyType::EcP384,
    KeyType::EcP521,
    KeyType::MlDsa44,
    KeyType::MlDsa65,
    KeyType::MlDsa87,
];

/// A storage whose keys live in memory. It offers every key type in each storage it is made for.
pub struct InMemoryStorage {
    storages: Vec<Storage>,
    refuse_signing: bool,
    deleting_fails: AtomicBool,
    next: AtomicU64,
    keys: Mutex<HashMap<KeyId, (KeyType, Arc<KeyPair>)>>,
}

impl InMemoryStorage {
    pub fn new(storages: &[Storage]) -> Self {
        Self {
            storages: storages.to_vec(),
            refuse_signing: false,
            deleting_fails: AtomicBool::new(false),
            next: AtomicU64::new(1),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Every key of this storage answers a signing request with [`KeyError::Refused`].
    pub fn refusing_to_sign(mut self) -> Self {
        self.refuse_signing = true;
        self
    }

    /// While set, deleting a key fails with [`KeyError::Failed`] and the key stays.
    pub fn fail_deleting(&self, fail: bool) {
        self.deleting_fails.store(fail, Ordering::Relaxed);
    }

    /// How many keys this storage holds.
    pub fn count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }

    fn stored(&self, id: KeyId, key_type: KeyType, pair: Arc<KeyPair>) -> Box<dyn StoredKey> {
        Box::new(InMemoryKey {
            id,
            key_type,
            public_key: pair.subject_public_key_info(),
            pair,
            refuse_signing: self.refuse_signing,
        })
    }
}

fn generate(key_type: KeyType) -> Result<KeyPair, KeyError> {
    let made = match key_type {
        KeyType::Rsa { bits } => {
            let size = match bits {
                2048 => RsaKeySize::_2048,
                3072 => RsaKeySize::_3072,
                4096 => RsaKeySize::_4096,
                _ => return Err(KeyError::NotOffered),
            };
            KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, size)
        }
        KeyType::EcP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
        KeyType::EcP384 => KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384),
        KeyType::EcP521 => KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512),
        KeyType::MlDsa44 => KeyPair::generate_for(&PKCS_ML_DSA_44),
        KeyType::MlDsa65 => KeyPair::generate_for(&PKCS_ML_DSA_65),
        KeyType::MlDsa87 => KeyPair::generate_for(&PKCS_ML_DSA_87),
    };
    made.map_err(|error| KeyError::Failed(error.to_string()))
}

impl KeyStorage for InMemoryStorage {
    fn offered(&self) -> Vec<Offer> {
        self.storages
            .iter()
            .map(|storage| Offer {
                storage: *storage,
                types: TYPES.to_vec(),
            })
            .collect()
    }

    fn create(&self, storage: Storage, key_type: KeyType) -> Result<Box<dyn StoredKey>, KeyError> {
        if !self.storages.contains(&storage) || !TYPES.contains(&key_type) {
            return Err(KeyError::NotOffered);
        }
        let pair = Arc::new(generate(key_type)?);
        let id = KeyId {
            storage,
            name: format!("key-{}", self.next.fetch_add(1, Ordering::Relaxed)),
        };
        self.keys
            .lock()
            .unwrap()
            .insert(id.clone(), (key_type, pair.clone()));
        Ok(self.stored(id, key_type, pair))
    }

    fn open(&self, id: &KeyId) -> Result<Option<Box<dyn StoredKey>>, KeyError> {
        let found = self.keys.lock().unwrap().get(id).cloned();
        Ok(found.map(|(key_type, pair)| self.stored(id.clone(), key_type, pair)))
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeyError> {
        if self.deleting_fails.load(Ordering::Relaxed) {
            return Err(KeyError::Failed("the key cannot be deleted".into()));
        }
        self.keys.lock().unwrap().remove(id);
        Ok(())
    }
}

struct InMemoryKey {
    id: KeyId,
    key_type: KeyType,
    public_key: Vec<u8>,
    pair: Arc<KeyPair>,
    refuse_signing: bool,
}

impl StoredKey for InMemoryKey {
    fn id(&self) -> &KeyId {
        &self.id
    }

    fn key_type(&self) -> KeyType {
        self.key_type
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError> {
        if self.refuse_signing {
            return Err(KeyError::Refused);
        }
        self.pair
            .sign(message)
            .map_err(|error| KeyError::Failed(error.to_string()))
    }
}

/// Whether the signature is a valid signature of the message by the private key behind `key`.
pub fn verify(key: &dyn StoredKey, message: &[u8], signature: &[u8]) -> bool {
    let algorithm: &dyn VerificationAlgorithm = match key.key_type() {
        KeyType::Rsa { .. } => &RSA_PKCS1_2048_8192_SHA256,
        KeyType::EcP256 => &ECDSA_P256_SHA256_ASN1,
        KeyType::EcP384 => &ECDSA_P384_SHA384_ASN1,
        KeyType::EcP521 => &ECDSA_P521_SHA512_ASN1,
        KeyType::MlDsa44 => &ML_DSA_44,
        KeyType::MlDsa65 => &ML_DSA_65,
        KeyType::MlDsa87 => &ML_DSA_87,
    };
    let Ok((_, info)) = SubjectPublicKeyInfo::from_der(key.public_key()) else {
        return false;
    };
    UnparsedPublicKey::new(algorithm, info.subject_public_key.data.as_ref())
        .verify(message, signature)
        .is_ok()
}

/// What every [`KeyStorage`] must do: create, sign, open and delete a key of each offered type, and refuse
/// what it does not offer.
pub fn check_contract(storage: &dyn KeyStorage) {
    let offers = storage.offered();
    for offer in &offers {
        for key_type in &offer.types {
            check_key(storage, offer.storage, *key_type);
        }
        let unsupported = KeyType::Rsa { bits: 1024 };
        assert_eq!(
            storage.create(offer.storage, unsupported).err(),
            Some(KeyError::NotOffered),
            "{:?} must not offer {unsupported:?}",
            offer.storage
        );
    }
    for other in [Storage::Keychain, Storage::Software, Storage::Tpm] {
        if offers.iter().all(|offer| offer.storage != other) {
            assert_eq!(
                storage.create(other, KeyType::EcP256).err(),
                Some(KeyError::NotOffered),
                "{other:?} is not offered"
            );
        }
    }
}

fn check_key(storage: &dyn KeyStorage, kind: Storage, key_type: KeyType) {
    let what = format!("{kind:?} {key_type:?}");
    let key = storage.create(kind, key_type).expect(&what);
    assert_eq!(key.key_type(), key_type, "{what}");
    assert_eq!(key.id().storage, kind, "{what}");
    let signature = key.sign(b"message").expect(&what);
    assert!(verify(key.as_ref(), b"message", &signature), "{what}");
    let opened = storage.open(key.id()).expect(&what).expect(&what);
    assert_eq!(opened.public_key(), key.public_key(), "{what}");
    assert_eq!(opened.key_type(), key_type, "{what}");
    let signature = opened.sign(b"message").expect(&what);
    assert!(verify(key.as_ref(), b"message", &signature), "{what}");
    storage.delete(key.id()).expect(&what);
    assert!(storage.open(key.id()).expect(&what).is_none(), "{what}");
    storage.delete(key.id()).expect(&what);
}
