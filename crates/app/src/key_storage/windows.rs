//! Keys in the Microsoft Software Key Storage Provider and, where the computer has one, the Microsoft Platform
//! Crypto Provider (TPM), made and used through NCrypt. A key is created with export policy 0: only
//! signatures leave the provider.

use std::ffi::c_void;
use std::sync::OnceLock;
use std::time::Instant;

use im_core::keys::encoding::{
    digest, ecdsa_der_from_raw, key_types_from_cng, public_key_from_cng,
};
use im_core::keys::{KeyError, KeyId, KeyStorage, KeyType, Offer, Storage, StoredKey};
use windows::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_P384_ALGORITHM,
    BCRYPT_ECDSA_P521_ALGORITHM, BCRYPT_PKCS1_PADDING_INFO, BCRYPT_RSA_ALGORITHM,
    BCRYPT_RSAPUBLIC_BLOB, BCRYPT_SHA256_ALGORITHM, CERT_KEY_SPEC, MS_KEY_STORAGE_PROVIDER,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ALGORITHM_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_KEY_HANDLE,
    NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY, NCRYPT_LENGTHS_PROPERTY,
    NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PROV_HANDLE, NCRYPT_SIGNATURE_OPERATION, NCRYPT_SILENT_FLAG,
    NCRYPT_SUPPORTED_LENGTHS, NCryptAlgorithmName, NCryptCreatePersistedKey, NCryptDeleteKey,
    NCryptEnumAlgorithms, NCryptExportKey, NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject,
    NCryptGetProperty, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};
use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
use windows::core::{HRESULT, PCWSTR, w};

// The identifiers of ML-DSA, which the `windows` crate does not have yet, as `bcrypt.h` defines them.
const MLDSA_ALGORITHM: PCWSTR = w!("ML-DSA");
const PARAMETER_SET_NAME_PROPERTY: PCWSTR = w!("ParameterSetName");
const PQDSA_PUBLIC_BLOB: PCWSTR = w!("PQDSAPUBLICBLOB");
const PAD_PQDSA: u32 = 0x20;

const NTE_BAD_KEYSET: HRESULT = HRESULT(0x8009_0016_u32 as i32);
const NTE_NOT_FOUND: HRESULT = HRESULT(0x8009_0011_u32 as i32);
const NTE_USER_CANCELLED: HRESULT = HRESULT(0x8009_0036_u32 as i32);
const NTE_SILENT_CONTEXT: HRESULT = HRESULT(0x8009_0022_u32 as i32);
const SCARD_W_CANCELLED_BY_USER: HRESULT = HRESULT(0x8010_006E_u32 as i32);

/// `BCRYPT_PQDSA_PADDING_INFO`: the context string and the pre-hash algorithm of a PQDSA signature.
#[repr(C)]
struct PqdsaPaddingInfo {
    context: *const u8,
    context_length: u32,
    prehash_algorithm: PCWSTR,
}

type WinResult<T> = windows::core::Result<T>;

/// The Microsoft Software Key Storage Provider and the Microsoft Platform Crypto Provider.
pub struct Cng;

impl KeyStorage for Cng {
    fn offered(&self) -> Vec<Offer> {
        static OFFERED: OnceLock<Vec<Offer>> = OnceLock::new();
        OFFERED
            .get_or_init(|| {
                [Storage::Software, Storage::Tpm]
                    .into_iter()
                    .filter_map(|storage| {
                        let types = creatable_types(storage)?;
                        log::info!("key storage offered: {storage:?} with {types:?}");
                        Some(Offer { storage, types })
                    })
                    .collect()
            })
            .clone()
    }

    fn create(&self, storage: Storage, key_type: KeyType) -> Result<Box<dyn StoredKey>, KeyError> {
        let offered = self.offered();
        if !offered
            .iter()
            .any(|offer| offer.storage == storage && offer.types.contains(&key_type))
        {
            return Err(KeyError::NotOffered);
        }
        let started = Instant::now();
        let provider = open_provider(storage).map_err(|error| failure("create", &error))?;
        let (key, name) = create_key(&provider, key_type)?;
        let (read_type, public_key) = match read_public_key(&key) {
            Ok(public) => public,
            Err(error) => {
                discard(key);
                return Err(error);
            }
        };
        log::info!(
            "key created: {storage:?} {key_type:?} in {} ms",
            started.elapsed().as_millis()
        );
        Ok(Box::new(StoredCngKey {
            id: KeyId { storage, name },
            key_type: read_type,
            public_key,
            key,
            _provider: provider,
        }))
    }

    fn open(&self, id: &KeyId) -> Result<Option<Box<dyn StoredKey>>, KeyError> {
        let Some((provider, key)) = open_existing(id)? else {
            return Ok(None);
        };
        let (key_type, public_key) = read_public_key(&key)?;
        Ok(Some(Box::new(StoredCngKey {
            id: id.clone(),
            key_type,
            public_key,
            key,
            _provider: provider,
        })))
    }

    fn delete(&self, id: &KeyId) -> Result<(), KeyError> {
        if let Some((_provider, key)) = open_existing(id)? {
            key.delete().map_err(|error| failure("delete", &error))?;
            log::info!("key deleted: {:?}", id.storage);
        }
        Ok(())
    }
}

/// A private key in a provider, with the public key read from it.
struct StoredCngKey {
    id: KeyId,
    key_type: KeyType,
    public_key: Vec<u8>,
    // Dropped before the provider it came from.
    key: Key,
    _provider: Provider,
}

impl StoredKey for StoredCngKey {
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
        let signed = match digest(self.key_type, message) {
            Some(hash) => match self.key_type {
                KeyType::Rsa { .. } => {
                    let padding = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: BCRYPT_SHA256_ALGORITHM,
                    };
                    self.key.sign(
                        &hash,
                        Some(&padding as *const _ as _),
                        NCRYPT_PAD_PKCS1_FLAG.0,
                    )
                }
                _ => self.key.sign(&hash, None, 0),
            },
            None => {
                let padding = PqdsaPaddingInfo {
                    context: std::ptr::null(),
                    context_length: 0,
                    prehash_algorithm: PCWSTR::null(),
                };
                self.key
                    .sign(message, Some(&padding as *const _ as _), PAD_PQDSA)
            }
        }
        .map_err(|error| failure("sign", &error))?;
        match self.key_type {
            KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => ecdsa_der_from_raw(&signed),
            _ => Ok(signed),
        }
    }
}

/// An open storage provider, freed when dropped.
struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        free(self.0.into());
    }
}

/// An open key, freed when dropped.
struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        free(self.0.into());
    }
}

fn free(handle: NCRYPT_HANDLE) {
    // SAFETY: the handle belongs to the guard that calls this from its `drop`, which runs once.
    if let Err(error) = unsafe { NCryptFreeObject(handle) } {
        log::warn!(
            "key storage handle not freed: Windows error {:#010x}",
            error.code().0
        );
    }
}

impl Key {
    /// Deletes the key. The handle is gone with it; if the call fails, the handle is freed on drop.
    fn delete(self) -> WinResult<()> {
        // SAFETY: the handle is open and owned by `self`.
        unsafe { NCryptDeleteKey(self.0, NCRYPT_SILENT_FLAG.0) }?;
        std::mem::forget(self);
        Ok(())
    }

    fn set_property(&self, name: PCWSTR, value: &[u8]) -> WinResult<()> {
        // SAFETY: the handle is open; `name` is a NUL-terminated wide string and `value` a live slice that the
        // call copies.
        unsafe { NCryptSetProperty(self.0.into(), name, value, NCRYPT_FLAGS(0)) }
    }

    fn property(&self, name: PCWSTR) -> WinResult<Vec<u8>> {
        property(self.0.into(), name)
    }

    fn finalize(&self) -> WinResult<()> {
        // SAFETY: the handle is open and not yet finalised.
        unsafe { NCryptFinalizeKey(self.0, NCRYPT_SILENT_FLAG) }
    }

    /// The signature of `input`; `padding` is the padding structure that `flags` ask for.
    fn sign(&self, input: &[u8], padding: Option<*const c_void>, flags: u32) -> WinResult<Vec<u8>> {
        let flags = NCRYPT_FLAGS(flags | NCRYPT_SILENT_FLAG.0);
        let mut size = 0;
        // SAFETY: without an output buffer the call only reports the size; `padding` points at a structure
        // that outlives it.
        unsafe { NCryptSignHash(self.0, padding, input, None, &mut size, flags) }?;
        let mut signature = vec![0; size as usize];
        // SAFETY: the buffer is `size` bytes long, as the call asked.
        unsafe {
            NCryptSignHash(
                self.0,
                padding,
                input,
                Some(&mut signature),
                &mut size,
                flags,
            )
        }?;
        signature.truncate(size as usize);
        Ok(signature)
    }

    /// The public key blob in the format this key's algorithm exports.
    fn export_public_blob(&self) -> WinResult<Vec<u8>> {
        let algorithm = utf16_string(&self.property(NCRYPT_ALGORITHM_PROPERTY)?);
        let blob_type = match algorithm.as_str() {
            "RSA" => BCRYPT_RSAPUBLIC_BLOB,
            name if name.starts_with("ECDSA") => BCRYPT_ECCPUBLIC_BLOB,
            _ => PQDSA_PUBLIC_BLOB,
        };
        let mut size = 0;
        // SAFETY: without an output buffer the call only reports the size.
        unsafe {
            NCryptExportKey(
                self.0,
                None,
                blob_type,
                None,
                None,
                &mut size,
                NCRYPT_FLAGS(0),
            )
        }?;
        let mut blob = vec![0; size as usize];
        // SAFETY: the buffer is `size` bytes long, as the call asked.
        unsafe {
            NCryptExportKey(
                self.0,
                None,
                blob_type,
                None,
                Some(&mut blob),
                &mut size,
                NCRYPT_FLAGS(0),
            )
        }?;
        blob.truncate(size as usize);
        Ok(blob)
    }
}

fn property(handle: NCRYPT_HANDLE, name: PCWSTR) -> WinResult<Vec<u8>> {
    let mut size = 0;
    // SAFETY: without an output buffer the call only reports the size.
    unsafe {
        NCryptGetProperty(
            handle,
            name,
            None,
            &mut size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }?;
    let mut value = vec![0; size as usize];
    // SAFETY: the buffer is `size` bytes long, as the call asked.
    unsafe {
        NCryptGetProperty(
            handle,
            name,
            Some(&mut value),
            &mut size,
            OBJECT_SECURITY_INFORMATION(0),
        )
    }?;
    value.truncate(size as usize);
    Ok(value)
}

fn provider_name(storage: Storage) -> PCWSTR {
    match storage {
        Storage::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
        _ => MS_KEY_STORAGE_PROVIDER,
    }
}

fn open_provider(storage: Storage) -> WinResult<Provider> {
    let mut handle = NCRYPT_PROV_HANDLE::default();
    // SAFETY: the name is a constant NUL-terminated wide string; the handle is written on success.
    unsafe { NCryptOpenStorageProvider(&mut handle, provider_name(storage), 0) }?;
    Ok(Provider(handle))
}

/// The key types of a provider that a key was proven creatable for: those its signature algorithms list, and
/// of ML-DSA only the parameter sets of which a key was made and deleted.
fn creatable_types(storage: Storage) -> Option<Vec<KeyType>> {
    let provider = match open_provider(storage) {
        Ok(provider) => provider,
        Err(error) => {
            log::warn!(
                "key storage {storage:?} not available: Windows error {:#010x}",
                error.code().0
            );
            return None;
        }
    };
    let algorithms = match signature_algorithms(&provider) {
        Ok(algorithms) => algorithms,
        Err(error) => {
            log::warn!(
                "key storage {storage:?} not enumerated: Windows error {:#010x}",
                error.code().0
            );
            return None;
        }
    };
    let rsa_lengths = rsa_lengths(&provider)
        .inspect_err(|error| {
            log::warn!(
                "key storage {storage:?} RSA lengths not read: Windows error {:#010x}",
                error.code().0
            );
        })
        .ok();
    let types: Vec<KeyType> = key_types_from_cng(&algorithms, rsa_lengths)
        .into_iter()
        .filter(|key_type| match key_type {
            KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => {
                probe(&provider, storage, *key_type)
            }
            _ => true,
        })
        .collect();
    (!types.is_empty()).then_some(types)
}

/// Whether a key of this type can be made in the provider: one is made and deleted.
fn probe(provider: &Provider, storage: Storage, key_type: KeyType) -> bool {
    match create_key(provider, key_type) {
        Ok((key, _)) => {
            if let Err(error) = key.delete() {
                log::warn!(
                    "key storage {storage:?} probe key not deleted: Windows error {:#010x}",
                    error.code().0
                );
            }
            true
        }
        Err(_) => {
            log::warn!("key storage {storage:?} lists {key_type:?} but cannot create it");
            false
        }
    }
}

fn signature_algorithms(provider: &Provider) -> WinResult<Vec<String>> {
    let mut count = 0;
    let mut list: *mut NCryptAlgorithmName = std::ptr::null_mut();
    // SAFETY: the provider is open; on success the call allocates `count` entries at `list`.
    unsafe {
        NCryptEnumAlgorithms(
            provider.0,
            NCRYPT_SIGNATURE_OPERATION,
            &mut count,
            &mut list,
            0,
        )
    }?;
    if list.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: the call returned `count` entries at `list`, which stay valid until they are freed below.
    let entries = unsafe { std::slice::from_raw_parts(list, count as usize) };
    let names = entries
        .iter()
        // SAFETY: every name is a NUL-terminated wide string inside the allocation.
        .filter_map(|entry| unsafe { entry.pszName.to_string() }.ok())
        .collect();
    // SAFETY: `list` came from `NCryptEnumAlgorithms` and is not used after this.
    if let Err(error) = unsafe { NCryptFreeBuffer(list.cast()) } {
        log::warn!(
            "key storage buffer not freed: Windows error {:#010x}",
            error.code().0
        );
    }
    Ok(names)
}

/// The smallest and largest RSA key length of the provider, as a key of its own reports them.
fn rsa_lengths(provider: &Provider) -> WinResult<(u32, u32)> {
    let key = persisted_key(provider, BCRYPT_RSA_ALGORITHM, PCWSTR::null())?;
    let bytes = key.property(NCRYPT_LENGTHS_PROPERTY)?;
    let lengths = bytes
        .get(..std::mem::size_of::<NCRYPT_SUPPORTED_LENGTHS>())
        .ok_or_else(|| windows::core::Error::from(HRESULT(0x8009_000D_u32 as i32)))?;
    let field = |at: usize| u32::from_le_bytes(lengths[at..at + 4].try_into().expect("four bytes"));
    Ok((field(0), field(4)))
}

/// A new key of the algorithm in the provider; with a name it is persisted once finalised.
fn persisted_key(provider: &Provider, algorithm: PCWSTR, name: PCWSTR) -> WinResult<Key> {
    let mut handle = NCRYPT_KEY_HANDLE::default();
    // SAFETY: the provider is open; `algorithm` and `name` (or null for a key that is not kept) are
    // NUL-terminated wide strings that outlive the call.
    unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut handle,
            algorithm,
            name,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }?;
    Ok(Key(handle))
}

/// A signing key that is not exportable, with a new container name; a failure deletes what was made.
fn create_key(provider: &Provider, key_type: KeyType) -> Result<(Key, String), KeyError> {
    let name = container_name()?;
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let key = persisted_key(provider, algorithm(key_type), PCWSTR(wide.as_ptr()))
        .map_err(|error| failure("create", &error))?;
    match configure(&key, key_type) {
        Ok(()) => Ok((key, name)),
        Err(error) => {
            discard(key);
            Err(failure("create", &error))
        }
    }
}

fn configure(key: &Key, key_type: KeyType) -> WinResult<()> {
    match key_type {
        KeyType::Rsa { bits } => key.set_property(NCRYPT_LENGTH_PROPERTY, &bits.to_le_bytes())?,
        KeyType::MlDsa44 => set_parameter_set(key, "44")?,
        KeyType::MlDsa65 => set_parameter_set(key, "65")?,
        KeyType::MlDsa87 => set_parameter_set(key, "87")?,
        _ => {}
    }
    key.set_property(NCRYPT_EXPORT_POLICY_PROPERTY, &0u32.to_le_bytes())?;
    key.set_property(
        NCRYPT_KEY_USAGE_PROPERTY,
        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
    )?;
    key.finalize()
}

fn set_parameter_set(key: &Key, set: &str) -> WinResult<()> {
    let wide: Vec<u8> = set
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    key.set_property(PARAMETER_SET_NAME_PROPERTY, &wide)
}

fn algorithm(key_type: KeyType) -> PCWSTR {
    match key_type {
        KeyType::Rsa { .. } => BCRYPT_RSA_ALGORITHM,
        KeyType::EcP256 => BCRYPT_ECDSA_P256_ALGORITHM,
        KeyType::EcP384 => BCRYPT_ECDSA_P384_ALGORITHM,
        KeyType::EcP521 => BCRYPT_ECDSA_P521_ALGORITHM,
        KeyType::MlDsa44 | KeyType::MlDsa65 | KeyType::MlDsa87 => MLDSA_ALGORITHM,
    }
}

/// Deletes a key that was made but cannot be used; if that fails too, the handle is freed.
fn discard(key: Key) {
    if let Err(error) = key.delete() {
        log::warn!(
            "key storage half-made key not deleted: Windows error {:#010x}",
            error.code().0
        );
    }
}

fn container_name() -> Result<String, KeyError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| failed("create", &error.to_string()))?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("IdentityManager-{hex}"))
}

/// The key type and SubjectPublicKeyInfo of the key's public half.
fn read_public_key(key: &Key) -> Result<(KeyType, Vec<u8>), KeyError> {
    let blob = key
        .export_public_blob()
        .map_err(|error| failure("read", &error))?;
    public_key_from_cng(&blob)
}

/// The provider and the key of this id, or `None` when the provider has no such key.
fn open_existing(id: &KeyId) -> Result<Option<(Provider, Key)>, KeyError> {
    if id.storage == Storage::Keychain {
        return Ok(None);
    }
    let provider = match open_provider(id.storage) {
        Ok(provider) => provider,
        Err(error) if is_missing(&error) => return Ok(None),
        Err(error) => return Err(failure("open", &error)),
    };
    let wide: Vec<u16> = id.name.encode_utf16().chain([0]).collect();
    let mut handle = NCRYPT_KEY_HANDLE::default();
    // SAFETY: the provider is open; the name is a NUL-terminated wide string that outlives the call.
    let opened = unsafe {
        NCryptOpenKey(
            provider.0,
            &mut handle,
            PCWSTR(wide.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_SILENT_FLAG,
        )
    };
    match opened {
        Ok(()) => Ok(Some((provider, Key(handle)))),
        Err(error) if is_missing(&error) => Ok(None),
        Err(error) => Err(failure("open", &error)),
    }
}

fn is_missing(error: &windows::core::Error) -> bool {
    [NTE_BAD_KEYSET, NTE_NOT_FOUND].contains(&error.code())
}

/// A refusal of the person or the system, or the failure with the Windows error for the log.
fn failure(operation: &str, error: &windows::core::Error) -> KeyError {
    let code = error.code();
    log::warn!(
        "key storage {operation} failed: Windows error {:#010x}",
        code.0
    );
    if is_refusal(code) {
        KeyError::Refused
    } else {
        KeyError::Failed(format!("Windows error {:#010x}: {error}", code.0))
    }
}

fn is_refusal(code: HRESULT) -> bool {
    [
        NTE_USER_CANCELLED,
        NTE_SILENT_CONTEXT,
        SCARD_W_CANCELLED_BY_USER,
    ]
    .contains(&code)
}

fn failed(operation: &str, reason: &str) -> KeyError {
    log::warn!("key storage {operation} failed: {reason}");
    KeyError::Failed(reason.to_string())
}

/// The text of a UTF-16 property value, up to its terminator.
fn utf16_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The export policy of the key, as the provider reports it.
#[cfg(test)]
pub(super) fn export_policy(id: &KeyId) -> Option<u32> {
    let (_provider, key) = open_existing(id).ok()??;
    let value = key.property(NCRYPT_EXPORT_POLICY_PROPERTY).ok()?;
    Some(u32::from_le_bytes(value.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_person_or_system_saying_no_is_a_refusal() {
        for code in [
            NTE_USER_CANCELLED,
            NTE_SILENT_CONTEXT,
            SCARD_W_CANCELLED_BY_USER,
        ] {
            assert_eq!(
                failure("sign", &windows::core::Error::from(code)),
                KeyError::Refused
            );
        }
        assert!(matches!(
            failure("sign", &windows::core::Error::from(NTE_BAD_KEYSET)),
            KeyError::Failed(_)
        ));
    }

    #[test]
    fn a_property_text_ends_at_its_terminator() {
        let bytes: Vec<u8> = "RSA"
            .encode_utf16()
            .chain([0, 0x41])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(utf16_string(&bytes), "RSA");
    }
}
