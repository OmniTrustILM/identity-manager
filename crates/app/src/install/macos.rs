//! Certificates in the default (login) keychain. The keychain pairs a certificate with the private key whose
//! application label is the hash of the certificate's public key, which makes the identity. No trust setting is
//! touched.

use im_core::install::{CertificateInstaller, InstallError};
use im_core::keys::KeyId;
use security_framework::certificate::SecCertificate;
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

/// Whether the default keychain, the one the certificates are read from, has an identity of this certificate with
/// the key of this application label.
fn has_identity(label: &[u8], leaf: &[u8]) -> Result<bool, InstallError> {
    let default = SecKeychain::default()
        .map_err(|error| status_failure("verify", error.code().into(), error))?;
    let found = ItemSearchOptions::new()
        .keychains(&[default])
        .class(ItemClass::identity())
        .load_refs(true)
        .limit(Limit::All)
        .search();
    let results = match found {
        Ok(results) => results,
        Err(error) if i64::from(error.code()) == ERR_SEC_ITEM_NOT_FOUND => return Ok(false),
        Err(error) => return Err(status_failure("verify", error.code().into(), error)),
    };
    Ok(results.into_iter().any(|result| match result {
        SearchResult::Ref(Reference::Identity(identity)) => {
            identity
                .certificate()
                .is_ok_and(|certificate| certificate.to_der() == leaf)
                && identity
                    .private_key()
                    .is_ok_and(|key| key.application_label().as_deref() == Some(label))
        }
        _ => false,
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
