//! Private keys that stay in a key storage of the system: what a storage offers, and the traits to create,
//! find, sign with and delete a key.

pub mod encoding;
mod request;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use serde::{Deserialize, Serialize};

pub use request::{AlternativeName, NameType, RequestSubject, signing_request};

/// A place on this computer that keeps private keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Storage {
    Keychain,
    Software,
    Tpm,
}

/// A kind of key a request can be signed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa { bits: u32 },
    EcP256,
    EcP384,
    EcP521,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// Where a key is kept and the name that finds it again.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId {
    pub storage: Storage,
    pub name: String,
}

/// The key types a storage can create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub storage: Storage,
    pub types: Vec<KeyType>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The storage does not offer this key type.
    NotOffered,
    /// The person or the system said no.
    Refused,
    /// The reason, for the log only.
    Failed(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotOffered => f.write_str("the key storage does not offer this key type"),
            Self::Refused => f.write_str("the key storage refused"),
            Self::Failed(reason) => write!(f, "the key storage failed: {reason}"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The key storages of this computer.
pub trait KeyStorage: Send + Sync {
    /// The key types each storage can create.
    fn offered(&self) -> Vec<Offer>;
    fn create(&self, storage: Storage, key_type: KeyType) -> Result<Box<dyn StoredKey>, KeyError>;
    fn open(&self, id: &KeyId) -> Result<Option<Box<dyn StoredKey>>, KeyError>;
    /// Deleting a key that is gone is `Ok`.
    fn delete(&self, id: &KeyId) -> Result<(), KeyError>;
}

/// A private key in a storage. The key itself never leaves it.
pub trait StoredKey: Send + Sync {
    fn id(&self) -> &KeyId;
    fn key_type(&self) -> KeyType;
    /// The SubjectPublicKeyInfo, DER.
    fn public_key(&self) -> &[u8];
    /// The signature of the message in the form of the key type: PKCS#1 v1.5 with SHA-256 for RSA, DER for
    /// ECDSA, the plain signature for ML-DSA.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, KeyError>;
}

/// The computer has no key storage: nothing is offered.
pub struct NoKeyStorage;

impl KeyStorage for NoKeyStorage {
    fn offered(&self) -> Vec<Offer> {
        Vec::new()
    }

    fn create(&self, _: Storage, _: KeyType) -> Result<Box<dyn StoredKey>, KeyError> {
        Err(KeyError::NotOffered)
    }

    fn open(&self, _: &KeyId) -> Result<Option<Box<dyn StoredKey>>, KeyError> {
        Ok(None)
    }

    fn delete(&self, _: &KeyId) -> Result<(), KeyError> {
        Ok(())
    }
}

/// The RSA sizes a storage with this smallest and largest size offers: the common sizes inside the range,
/// never below 2048 bits.
pub fn rsa_types(min_bits: u32, max_bits: u32) -> Vec<KeyType> {
    [2048, 3072, 4096, 6144, 8192]
        .into_iter()
        .filter(|bits| (min_bits..=max_bits).contains(bits))
        .map(|bits| KeyType::Rsa { bits })
        .collect()
}

#[cfg(test)]
mod tests;
