//! Certificates in the default (login) keychain. The keychain pairs a certificate with the private key whose
//! application label is the hash of the certificate's public key, which makes the identity. No trust setting is
//! touched.

use im_core::identity::Fingerprint;
use im_core::install::{CertificateInstaller, InstallError};
use im_core::keys::KeyId;
use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::item::{
    AddRef, ItemAddOptions, ItemAddValue, ItemClass, ItemSearchOptions, Limit, Reference,
    SearchResult,
};
use security_framework::os::macos::keychain::SecKeychain;

use crate::key_storage::application_label;

const ERR_SEC_DUPLICATE_ITEM: i64 = -25299;
const ERR_SEC_ITEM_NOT_FOUND: i64 = -25300;

/// The default keychain of the current user.
pub struct Keychain;

impl CertificateInstaller for Keychain {
    fn install(
        &self,
        key: &KeyId,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        let label = application_label(key)
            .ok_or_else(|| failed("read", "the key is not one this application made"))?;
        add(leaf)?;
        for intermediate in intermediates {
            add(intermediate)?;
        }
        if has_identity(&label, leaf)? {
            log::info!("certificate installed: Keychain");
            Ok(())
        } else {
            Err(failed(
                "verify",
                "the keychain did not pair the certificate with the key",
            ))
        }
    }

    fn install_beside(
        &self,
        old: &Fingerprint,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        let label = identities("install beside")?
            .iter()
            .find(|identity| fingerprint_of(identity).as_ref() == Some(old))
            .and_then(key_label)
            .ok_or_else(|| failed("install beside", "the old certificate has no key here"))?;
        add(leaf)?;
        for intermediate in intermediates {
            add(intermediate)?;
        }
        if has_identity(&label, leaf)? {
            log::info!("certificate installed beside: Keychain");
            Ok(())
        } else {
            Err(failed(
                "verify",
                "the keychain did not pair the certificate with the key",
            ))
        }
    }

    fn remove(&self, fingerprint: &Fingerprint, delete_key: bool) -> Result<(), InstallError> {
        let Some(item) = certificate(fingerprint)? else {
            return Ok(());
        };
        let key_deleted = delete_key && delete_own_key(fingerprint)?;
        item.delete()
            .map_err(|error| status_failure("remove", error.code().into(), error))?;
        if certificate(fingerprint)?.is_some() {
            return Err(failed("verify", "the keychain still holds the certificate"));
        }
        log::info!(
            "certificate removed: Keychain, {}",
            if key_deleted {
                "key deleted"
            } else {
                "key kept"
            }
        );
        Ok(())
    }
}

/// Deletes the key of the certificate when no other certificate of the default keychain is for it; whether it was
/// deleted. A certificate whose key cannot be read keeps every key, as it may be for this one.
fn delete_own_key(fingerprint: &Fingerprint) -> Result<bool, InstallError> {
    let identities = identities("remove")?;
    let Some(key) = identities
        .iter()
        .find(|identity| fingerprint_of(identity).as_ref() == Some(fingerprint))
        .and_then(|identity| identity.private_key().ok())
    else {
        return Ok(false);
    };
    let Some(label) = key.application_label() else {
        log::warn!("certificate removal keeps the key: its label cannot be read");
        return Ok(false);
    };
    let shared = identities.iter().any(|identity| {
        fingerprint_of(identity).as_ref() != Some(fingerprint)
            && key_label(identity).is_none_or(|other| other == label)
    });
    if shared {
        log::info!("certificate removal keeps the key: another certificate may use it");
        return Ok(false);
    }
    key.delete()
        .map_err(|error| status_failure("delete key", error.code().into(), error))?;
    Ok(true)
}

/// The certificate item of the default keychain with this fingerprint.
fn certificate(fingerprint: &Fingerprint) -> Result<Option<SecCertificate>, InstallError> {
    Ok(search("remove", ItemClass::certificate())?
        .into_iter()
        .find_map(|result| match result {
            SearchResult::Ref(Reference::Certificate(certificate))
                if Fingerprint::of(&certificate.to_der()) == *fingerprint =>
            {
                Some(certificate)
            }
            _ => None,
        }))
}

/// The identities of the default keychain, the one the certificates are read from.
fn identities(operation: &str) -> Result<Vec<SecIdentity>, InstallError> {
    Ok(search(operation, ItemClass::identity())?
        .into_iter()
        .filter_map(|result| match result {
            SearchResult::Ref(Reference::Identity(identity)) => Some(identity),
            _ => None,
        })
        .collect())
}

/// The items of a class in the default keychain; none found is an empty list.
fn search(operation: &str, class: ItemClass) -> Result<Vec<SearchResult>, InstallError> {
    let default = SecKeychain::default()
        .map_err(|error| status_failure(operation, error.code().into(), error))?;
    let found = ItemSearchOptions::new()
        .keychains(&[default])
        .class(class)
        .load_refs(true)
        .limit(Limit::All)
        .search();
    match found {
        Ok(results) => Ok(results),
        Err(error) if i64::from(error.code()) == ERR_SEC_ITEM_NOT_FOUND => Ok(Vec::new()),
        Err(error) => Err(status_failure(operation, error.code().into(), error)),
    }
}

fn fingerprint_of(identity: &SecIdentity) -> Option<Fingerprint> {
    identity
        .certificate()
        .ok()
        .map(|certificate| Fingerprint::of(&certificate.to_der()))
}

fn key_label(identity: &SecIdentity) -> Option<Vec<u8>> {
    identity.private_key().ok()?.application_label()
}

/// Adds a certificate to the default keychain; one that is already there counts as added.
fn add(der: &[u8]) -> Result<(), InstallError> {
    let certificate = SecCertificate::from_der(der)
        .map_err(|error| status_failure("add", error.code().into(), error))?;
    match ItemAddOptions::new(ItemAddValue::Ref(AddRef::Certificate(certificate))).add() {
        Ok(()) => Ok(()),
        Err(error) if i64::from(error.code()) == ERR_SEC_DUPLICATE_ITEM => Ok(()),
        Err(error) => Err(status_failure("add", error.code().into(), error)),
    }
}

/// Whether the default keychain has an identity of this certificate with the key of this application label.
fn has_identity(label: &[u8], leaf: &[u8]) -> Result<bool, InstallError> {
    Ok(identities("verify")?.iter().any(|identity| {
        identity
            .certificate()
            .is_ok_and(|certificate| certificate.to_der() == leaf)
            && key_label(identity).as_deref() == Some(label)
    }))
}

fn failed(operation: &str, reason: &str) -> InstallError {
    log::warn!("certificate install {operation} failed: {reason}");
    InstallError::Failed(reason.to_string())
}

/// The failure with the `OSStatus` for the log and the report; the certificate is not part of either.
fn status_failure(operation: &str, status: i64, reason: impl std::fmt::Display) -> InstallError {
    log::warn!("certificate install {operation} failed: OSStatus {status}");
    InstallError::Failed(format!("OSStatus {status}: {reason}"))
}

/// Removes certificates from the keychain, for the test that installed them. A certificate made from DER is not the
/// keychain item, so the item is found by its DER and deleted.
#[cfg(test)]
pub(super) fn remove(der: &[u8]) {
    let found = ItemSearchOptions::new()
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .search()
        .unwrap_or_default();
    for result in found {
        if let SearchResult::Ref(Reference::Certificate(certificate)) = result
            && certificate.to_der() == der
        {
            let _ = certificate.delete();
        }
    }
}

/// Whether the default keychain holds this certificate, for the test that installed it.
#[cfg(test)]
pub(super) fn holds(der: &[u8]) -> bool {
    let Ok(default) = SecKeychain::default() else {
        return false;
    };
    ItemSearchOptions::new()
        .keychains(&[default])
        .class(ItemClass::certificate())
        .load_refs(true)
        .limit(Limit::All)
        .search()
        .unwrap_or_default()
        .into_iter()
        .any(|result| {
            matches!(result, SearchResult::Ref(Reference::Certificate(certificate))
                if certificate.to_der() == der)
        })
}
