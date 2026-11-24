//! Keys in the default (login) keychain, made and used through `SecKey`. The private key is created not
//! extractable: only signatures leave the keychain.

use std::sync::OnceLock;
use std::time::Instant;

use core_foundation::base::{TCFType, ToVoid};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use im_core::keys::encoding::{Curve, spki_from_ec_point, spki_from_rsa_pkcs1};
use im_core::keys::{KeyError, KeyId, KeyStorage, KeyType, Offer, Storage, StoredKey, rsa_types};
use security_framework::item::{ItemClass, ItemSearchOptions, KeyClass, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::item::{
    kSecAttrCanSign, kSecAttrIsPermanent, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeRSA, kSecAttrLabel, kSecPrivateKeyAttrs,
};

// SAFETY: the declaration matches the constant the Security framework exports.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrIsExtractable: CFStringRef;
}

const LABEL: &str = "Identity Manager key";
/// The largest RSA key the keychain makes.
const RSA_MAX_BITS: u32 = 4096;

const ERR_SEC_USER_CANCELED: i64 = -128;
const ERR_SEC_AUTH_FAILED: i64 = -25293;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i64 = -25308;
const ERR_SEC_ITEM_NOT_FOUND: i64 = -25300;

/// The default keychain of the current user.
pub struct Keychain;

impl KeyStorage for Keychain {
    fn offered(&self) -> Vec<Offer> {
        static OFFERED: OnceLock<Vec<Offer>> = OnceLock::new();
        OFFERED
            .get_or_init(|| {
                let mut types = rsa_types(2048, RSA_MAX_BITS);
                types.extend([KeyType::EcP256, KeyType::EcP384, KeyType::EcP521]);
                log::info!("key storage offered: Keychain with {types:?}");
                vec![Offer {
                    storage: Storage::Keychain,
                    types,
                }]
            })
            .clone()
    }

    fn create(&self, storage: Storage, key_type: KeyType) -> Result<Box<dyn StoredKey>, KeyError> {
        let offered = self.offered();
        if storage != Storage::Keychain || !offered[0].types.contains(&key_type) {
            return Err(KeyError::NotOffered);
        }
        let started = Instant::now();
        let key = generate(key_type)?;
        let stored = StoredSecKey::new(key.clone()).inspect_err(|_| {
            if let Err(error) = key.delete() {
                failure("delete", error.code().into(), error);
            }
        })?;
        log::info!(
            "key created: Keychain {key_type:?} in {} ms",
            started.elapsed().as_millis()
        );
        Ok(Box::new(stored))
    }

    fn open(&self, id: &KeyId) -> Result<Option<Box<dyn StoredKey>>, KeyError> {
        if id.storage != Storage::Keychain {
            return Ok(None);
        }
        match find(id)? {
            Some(key) => Ok(Some(Box::new(StoredSecKey::new(key)?))),
            None => Ok(None),
        }
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeyError> {
        if id.storage != Storage::Keychain {
            return Ok(());
        }
        if let Some(key) = find(id)? {
            key.delete()
                .map_err(|error| failure("delete", error.code().into(), error))?;
            log::info!("key deleted: Keychain");
        }
        Ok(())
    }
}

/// The Security framework's attribute names.
struct Names {
    key_type: CFStringRef,
    key_size: CFStringRef,
    label: CFStringRef,
    extractable: CFStringRef,
    permanent: CFStringRef,
    can_sign: CFStringRef,
    private_attributes: CFStringRef,
    rsa: CFStringRef,
    elliptic_curve: CFStringRef,
}

fn names() -> Names {
    // SAFETY: these are immutable CFString constants exported by the Security framework; they are valid for
    // the life of the process.
    unsafe {
        Names {
            key_type: kSecAttrKeyType,
            key_size: kSecAttrKeySizeInBits,
            label: kSecAttrLabel,
            extractable: kSecAttrIsExtractable,
            permanent: kSecAttrIsPermanent,
            can_sign: kSecAttrCanSign,
            private_attributes: kSecPrivateKeyAttrs,
            rsa: kSecAttrKeyTypeRSA,
            elliptic_curve: kSecAttrKeyTypeECSECPrimeRandom,
        }
    }
}

/// A private key in the keychain with the public key read from it.
struct StoredSecKey {
    id: KeyId,
    key_type: KeyType,
    public_key: Vec<u8>,
    key: SecKey,
}

impl StoredSecKey {
    fn new(key: SecKey) -> Result<Self, KeyError> {
        let key_type = key_type_of(&key)?;
        let public = key
            .public_key()
            .and_then(|public| public.external_representation())
            .ok_or_else(|| failed("read", "the public key is not available"))?;
        let application_label = key
            .application_label()
            .ok_or_else(|| failed("read", "the key has no application label"))?;
        Ok(Self {
            id: key_id(&application_label),
            key_type,
            public_key: spki(key_type, public.bytes()),
            key,
        })
    }
}

impl StoredKey for StoredSecKey {
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
        let algorithm = match self.key_type {
            KeyType::Rsa { .. } => Algorithm::RSASignatureMessagePKCS1v15SHA256,
            KeyType::EcP256 => Algorithm::ECDSASignatureMessageX962SHA256,
            KeyType::EcP384 => Algorithm::ECDSASignatureMessageX962SHA384,
            KeyType::EcP521 => Algorithm::ECDSASignatureMessageX962SHA512,
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                return Err(KeyError::NotOffered);
            }
        };
        self.key
            .create_signature(algorithm, message)
            .map_err(|error| failure("sign", error.code() as i64, error.description()))
    }
}

/// A permanent, not extractable signing key in the default keychain.
fn generate(key_type: KeyType) -> Result<SecKey, KeyError> {
    let names = names();
    let (kind, bits) = match key_type {
        KeyType::Rsa { bits } => (names.rsa, bits),
        KeyType::EcP256 => (names.elliptic_curve, 256),
        KeyType::EcP384 => (names.elliptic_curve, 384),
        KeyType::EcP521 => (names.elliptic_curve, 521),
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => return Err(KeyError::NotOffered),
    };
    let bits = CFNumber::from(bits as i32);
    let label = CFString::new(LABEL);
    let no = CFBoolean::false_value();
    let yes = CFBoolean::true_value();
    let mut private = CFMutableDictionary::new();
    private.add(&names.permanent.to_void(), &yes.to_void());
    private.add(&names.can_sign.to_void(), &yes.to_void());
    let mut attributes = CFMutableDictionary::new();
    attributes.add(&names.key_type.to_void(), &kind.to_void());
    attributes.add(&names.key_size.to_void(), &bits.to_void());
    attributes.add(&names.label.to_void(), &label.to_void());
    attributes.add(&names.extractable.to_void(), &no.to_void());
    attributes.add(&names.private_attributes.to_void(), &private.to_void());
    #[allow(deprecated)]
    SecKey::generate(attributes.to_immutable())
        .map_err(|error| failure("create", error.code() as i64, error.description()))
}

/// The private key with this id in the default keychain.
fn find(id: &KeyId) -> Result<Option<SecKey>, KeyError> {
    let Some(application_label) = application_label(id) else {
        return Ok(None);
    };
    let found = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
        .application_label(&application_label)
        .load_refs(true)
        .limit(1)
        .search();
    match found {
        Ok(results) => Ok(results.into_iter().find_map(|result| match result {
            SearchResult::Ref(Reference::Key(key)) => Some(key),
            _ => None,
        })),
        Err(error) if i64::from(error.code()) == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        Err(error) => Err(failure("open", error.code().into(), error)),
    }
}

/// The key type of a private key, from the attributes the keychain reports.
fn key_type_of(key: &SecKey) -> Result<KeyType, KeyError> {
    let names = names();
    let attributes = key.attributes();
    let kind = attributes
        .find(names.key_type.to_void())
        .map(|value| {
            // SAFETY: the key type attribute of a key is a CFString that the attributes dictionary owns.
            unsafe { CFString::wrap_under_get_rule(*value as CFStringRef) }
        })
        .ok_or_else(|| failed("read", "the key has no type"))?;
    let bits = attributes
        .find(names.key_size.to_void())
        .and_then(|value| {
            // SAFETY: the key size attribute of a key is a CFNumber that the attributes dictionary owns.
            unsafe { CFNumber::wrap_under_get_rule(*value as _) }.to_i32()
        })
        .ok_or_else(|| failed("read", "the key has no size"))?;
    // SAFETY: the key type constants are immutable CFStrings valid for the life of the process.
    let (rsa, curve) = unsafe {
        (
            CFString::wrap_under_get_rule(names.rsa),
            CFString::wrap_under_get_rule(names.elliptic_curve),
        )
    };
    match (bits, kind) {
        (bits, kind) if kind == rsa => Ok(KeyType::Rsa { bits: bits as u32 }),
        (256, kind) if kind == curve => Ok(KeyType::EcP256),
        (384, kind) if kind == curve => Ok(KeyType::EcP384),
        (521, kind) if kind == curve => Ok(KeyType::EcP521),
        _ => Err(failed("read", "the key is of a type that is not offered")),
    }
}

/// The SubjectPublicKeyInfo of a public key from the keychain's own form of it: PKCS#1 for RSA, the
/// uncompressed point for ECDSA.
fn spki(key_type: KeyType, public: &[u8]) -> Vec<u8> {
    match key_type {
        KeyType::Rsa { .. } => spki_from_rsa_pkcs1(public),
        KeyType::EcP256 => spki_from_ec_point(Curve::P256, public),
        KeyType::EcP384 => spki_from_ec_point(Curve::P384, public),
        KeyType::EcP521 => spki_from_ec_point(Curve::P521, public),
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => Vec::new(),
    }
}

/// The name of a key: its label and its application label (the hash of the public key) in hex.
fn key_id(application_label: &[u8]) -> KeyId {
    let hex: String = application_label
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    KeyId {
        storage: Storage::Keychain,
        name: format!("{LABEL}:{hex}"),
    }
}

/// The application label a key name holds, if it is one of ours.
pub(crate) fn application_label(id: &KeyId) -> Option<Vec<u8>> {
    let hex = id.name.strip_prefix(LABEL)?.strip_prefix(':')?;
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(hex.get(at..at + 2)?, 16).ok())
        .collect()
}

fn failed(operation: &str, reason: &str) -> KeyError {
    log::warn!("key storage {operation} failed: {reason}");
    KeyError::Failed(reason.to_string())
}

/// A refusal of the person or the system, or the failure with the `OSStatus` for the log.
fn failure(operation: &str, status: i64, reason: impl std::fmt::Display) -> KeyError {
    log::warn!("key storage {operation} failed: OSStatus {status}");
    match status {
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED | ERR_SEC_INTERACTION_NOT_ALLOWED => {
            KeyError::Refused
        }
        _ => KeyError::Failed(format!("OSStatus {status}: {reason}")),
    }
}

/// Whether the keychain reports the private key as extractable.
#[cfg(test)]
pub(super) fn extractable(id: &KeyId) -> Option<bool> {
    let key = find(id).ok()??;
    let attributes = key.attributes();
    let value = attributes.find(names().extractable.to_void())?;
    // SAFETY: the extractable attribute of a key is a CFBoolean that the attributes dictionary owns.
    Some(unsafe { CFBoolean::wrap_under_get_rule(*value as _) }.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_name_holds_the_application_label() {
        let id = key_id(&[0x00, 0xab, 0xff]);
        assert_eq!(id.name, "Identity Manager key:00abff");
        assert_eq!(application_label(&id), Some(vec![0x00, 0xab, 0xff]));
    }

    #[test]
    fn a_name_of_another_key_finds_nothing() {
        for name in [
            "",
            "other:00",
            "Identity Manager key:",
            "Identity Manager key:0",
            "Identity Manager key:zz",
        ] {
            let id = KeyId {
                storage: Storage::Keychain,
                name: name.into(),
            };
            assert_eq!(application_label(&id), None, "{name}");
        }
    }

    #[test]
    fn the_person_or_system_saying_no_is_a_refusal() {
        for status in [-128, -25293, -25308] {
            assert_eq!(failure("sign", status, "no"), KeyError::Refused);
        }
        assert_eq!(
            failure("sign", -50, "bad"),
            KeyError::Failed("OSStatus -50: bad".into())
        );
    }

    #[test]
    fn rsa_up_to_4096_and_three_curves_are_offered() {
        let offered = Keychain.offered();
        assert_eq!(
            offered[0].types,
            [
                KeyType::Rsa { bits: 2048 },
                KeyType::Rsa { bits: 3072 },
                KeyType::Rsa { bits: 4096 },
                KeyType::EcP256,
                KeyType::EcP384,
                KeyType::EcP521,
            ]
        );
    }

    #[test]
    fn a_type_that_is_not_offered_is_refused_before_the_keychain_is_touched() {
        for key_type in [
            KeyType::Rsa { bits: 1024 },
            KeyType::Rsa { bits: 8192 },
            KeyType::MlDsa44,
        ] {
            assert_eq!(
                Keychain.create(Storage::Keychain, key_type).err(),
                Some(KeyError::NotOffered)
            );
        }
        assert_eq!(
            Keychain.create(Storage::Tpm, KeyType::EcP256).err(),
            Some(KeyError::NotOffered)
        );
    }
}
