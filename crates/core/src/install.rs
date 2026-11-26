//! Putting an issued certificate where the system keeps it, next to the key it was asked for.

use std::fmt;

use x509_parser::error::X509Error;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::identity::Fingerprint;
use crate::keys::KeyId;

/// Why a certificate was not installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallError {
    /// This computer has nothing to install a certificate with.
    Unavailable,
    /// The installation failed; the reason is for the log.
    Failed(String),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("this computer cannot install certificates"),
            Self::Failed(reason) => write!(f, "the installation failed: {reason}"),
        }
    }
}

impl std::error::Error for InstallError {}

/// Installs the certificate ILM issued for the key a request was signed with.
pub trait CertificateInstaller: Send + Sync {
    /// `leaf` and `intermediates` are DER; the intermediates run from the issuer of the leaf upwards.
    /// Installing a certificate that is already installed for the key succeeds, as a follow may install it again
    /// after a crash.
    fn install(
        &self,
        key: &KeyId,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError>;

    /// Installs a certificate for the key that the installed certificate `old` already has; the key stays where
    /// it is. The caller has checked that the public keys are equal.
    fn install_beside(
        &self,
        old: &Fingerprint,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError>;

    /// Removes the installed certificate and, when `delete_key` is set, its private key. A certificate that is
    /// not installed is removed already.
    fn remove(&self, fingerprint: &Fingerprint, delete_key: bool) -> Result<(), InstallError>;
}

/// Whether `leaf` (DER) holds `public_key`; a certificate that cannot be read holds nothing.
pub fn is_for_key(leaf: &[u8], public_key: &[u8]) -> bool {
    X509Certificate::from_der(leaf).is_ok_and(|(_, parsed)| parsed.public_key().raw == public_key)
}

/// `chain` (DER) without the certificates that sign themselves, the roots, and those that cannot be read; the
/// order stays. A certificate signs itself when its own key verifies its signature, or, for a signature this
/// application cannot verify (an algorithm it does not have, or an RSA key below 2048 bits), when its subject reads
/// as its issuer and no other key is named as its authority.
pub fn intermediates(chain: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    chain
        .into_iter()
        .filter(|der| match X509Certificate::from_der(der) {
            Ok((_, parsed)) => !signs_itself(&parsed),
            Err(_) => {
                log::warn!("a certificate of the chain cannot be read and is left out");
                false
            }
        })
        .collect()
}

fn signs_itself(certificate: &X509Certificate<'_>) -> bool {
    match certificate.verify_signature(None) {
        Ok(()) => return true,
        Err(X509Error::SignatureUnsupportedAlgorithm) => {}
        Err(_) if has_small_rsa_key(certificate) => {}
        Err(_) => return false,
    }
    if certificate.subject().to_string() != certificate.issuer().to_string() {
        return false;
    }
    let mut authority = None;
    let mut subject = None;
    for extension in certificate.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(id) => {
                authority = id.key_identifier.as_ref().map(|id| id.0);
            }
            ParsedExtension::SubjectKeyIdentifier(id) => subject = Some(id.0),
            _ => {}
        }
    }
    authority.is_none_or(|authority| Some(authority) == subject)
}

/// Whether the key is an RSA key too small for the verifier, which accepts 2048 bits and more.
fn has_small_rsa_key(certificate: &X509Certificate<'_>) -> bool {
    matches!(certificate.public_key().parsed(), Ok(PublicKey::RSA(rsa)) if rsa.key_size() < 2048)
}

/// The computer cannot install certificates: every installation fails as unavailable.
pub struct NoInstaller;

impl CertificateInstaller for NoInstaller {
    fn install(&self, _: &KeyId, _: &[u8], _: &[Vec<u8>]) -> Result<(), InstallError> {
        Err(InstallError::Unavailable)
    }

    fn install_beside(&self, _: &Fingerprint, _: &[u8], _: &[Vec<u8>]) -> Result<(), InstallError> {
        Err(InstallError::Unavailable)
    }

    fn remove(&self, _: &Fingerprint, _: bool) -> Result<(), InstallError> {
        Err(InstallError::Unavailable)
    }
}

/// One installation a [`RecordingInstaller`] was asked for.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    pub key: KeyId,
    pub leaf: Vec<u8>,
    pub intermediates: usize,
}

/// One installation beside an installed certificate a [`RecordingInstaller`] was asked for.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationBeside {
    pub old: Fingerprint,
    pub leaf: Vec<u8>,
    pub intermediates: usize,
}

/// One removal a [`RecordingInstaller`] was asked for.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    pub fingerprint: Fingerprint,
    pub delete_key: bool,
}

/// An installer that only remembers what it was asked, and fails while it is told to.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct RecordingInstaller {
    calls: std::sync::Mutex<Vec<Installation>>,
    beside: std::sync::Mutex<Vec<InstallationBeside>>,
    removed: std::sync::Mutex<Vec<Removal>>,
    failing: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "testing"))]
impl RecordingInstaller {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every later installation fails, and is still recorded.
    pub fn fail(&self, failing: bool) {
        self.failing
            .store(failing, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn calls(&self) -> Vec<Installation> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn beside_calls(&self) -> Vec<InstallationBeside> {
        self.beside
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn removals(&self) -> Vec<Removal> {
        self.removed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn outcome(&self) -> Result<(), InstallError> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(InstallError::Failed("told to fail".to_owned()));
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
impl CertificateInstaller for RecordingInstaller {
    fn install(
        &self,
        key: &KeyId,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Installation {
                key: key.clone(),
                leaf: leaf.to_vec(),
                intermediates: intermediates.len(),
            });
        self.outcome()
    }

    fn install_beside(
        &self,
        old: &Fingerprint,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
    ) -> Result<(), InstallError> {
        self.beside
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(InstallationBeside {
                old: *old,
                leaf: leaf.to_vec(),
                intermediates: intermediates.len(),
            });
        self.outcome()
    }

    fn remove(&self, fingerprint: &Fingerprint, delete_key: bool) -> Result<(), InstallError> {
        self.removed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Removal {
                fingerprint: *fingerprint,
                delete_key,
            });
        self.outcome()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Storage;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P521_SHA512,
    };

    fn authority(name: &str) -> (CertificateParams, KeyPair) {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, name);
        (params, KeyPair::generate().unwrap())
    }

    /// A root, an intermediate it signed and a leaf the intermediate signed, as DER with the leaf's key.
    fn pki() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let (root_params, root_key) = authority("Root");
        let root = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);
        let (middle_params, middle_key) = authority("Middle");
        let middle = middle_params.signed_by(&middle_key, &root_issuer).unwrap();
        let middle_issuer = Issuer::new(middle_params, middle_key);
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::default()
            .signed_by(&leaf_key, &middle_issuer)
            .unwrap();
        let key = X509Certificate::from_der(leaf.der())
            .unwrap()
            .1
            .public_key()
            .raw
            .to_vec();
        (
            leaf.der().to_vec(),
            middle.der().to_vec(),
            root.der().to_vec(),
            key,
        )
    }

    #[test]
    fn a_leaf_is_for_the_key_it_holds_only() {
        let (leaf, _, _, public_key) = pki();
        assert!(is_for_key(&leaf, &public_key));
        assert!(!is_for_key(&leaf, &pki().3));
        assert!(!is_for_key(&[1, 2, 3], &public_key));
    }

    #[test]
    fn a_self_signed_root_is_dropped_and_the_intermediates_stay_in_order() {
        let (_, middle, root, _) = pki();
        let (upper_params, upper_key) = authority("Upper");
        let (root_params, root_key) = authority("Root");
        let other_root = Issuer::new(root_params, root_key);
        let upper = upper_params.signed_by(&upper_key, &other_root).unwrap();
        let upper = upper.der().to_vec();

        assert_eq!(
            intermediates(vec![middle.clone(), upper.clone(), root]),
            [middle, upper]
        );
    }

    #[test]
    fn a_root_whose_issuer_is_written_otherwise_than_its_subject_is_dropped() {
        let (_, middle, _, _) = pki();
        let (params, key) = authority("Root");
        let (issuer_params, _) = authority("ROOT");
        let same_key = KeyPair::from_pem(&key.serialize_pem()).unwrap();
        let root = params
            .signed_by(&key, &Issuer::new(issuer_params, same_key))
            .unwrap();
        let parsed = X509Certificate::from_der(root.der()).unwrap().1;
        assert_ne!(parsed.issuer().to_string(), parsed.subject().to_string());

        assert_eq!(
            intermediates(vec![middle.clone(), root.der().to_vec()]),
            [middle]
        );
    }

    /// A certificate named `Root` for `key`, issued by the same name with `issuer_key`, with an authority key
    /// identifier when `key_identifiers` is set.
    fn self_issued(key: &KeyPair, issuer_key: KeyPair, key_identifiers: bool) -> Vec<u8> {
        let (mut params, _) = authority("Root");
        params.use_authority_key_identifier_extension = key_identifiers;
        let (issuer_params, _) = authority("Root");
        params
            .signed_by(key, &Issuer::new(issuer_params, issuer_key))
            .unwrap()
            .der()
            .to_vec()
    }

    fn copy(key: &KeyPair) -> KeyPair {
        KeyPair::from_pem(&key.serialize_pem()).unwrap()
    }

    #[test]
    fn a_rollover_certificate_signed_by_the_previous_key_stays() {
        let (_, middle, _, _) = pki();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let previous = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let rollover = self_issued(&key, previous, false);

        assert_eq!(
            intermediates(vec![middle.clone(), rollover.clone()]),
            [middle, rollover]
        );
    }

    #[test]
    fn a_root_whose_signature_cannot_be_verified_is_dropped_by_its_names() {
        let (_, middle, _, _) = pki();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512).unwrap();
        let with_identifiers = self_issued(&key, copy(&key), true);
        let without = self_issued(&key, copy(&key), false);
        let parsed = X509Certificate::from_der(&without).unwrap().1;
        assert_eq!(
            parsed.verify_signature(None),
            Err(X509Error::SignatureUnsupportedAlgorithm)
        );

        assert_eq!(
            intermediates(vec![middle.clone(), with_identifiers, without]),
            [middle]
        );
    }

    #[test]
    fn a_rollover_certificate_whose_signature_cannot_be_verified_stays() {
        let (_, middle, _, _) = pki();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512).unwrap();
        let previous = KeyPair::generate_for(&PKCS_ECDSA_P521_SHA512).unwrap();
        let rollover = self_issued(&key, previous, true);

        assert_eq!(
            intermediates(vec![middle.clone(), rollover.clone()]),
            [middle, rollover]
        );
    }

    #[test]
    fn a_root_with_an_rsa_key_too_small_to_verify_is_dropped_by_its_names() {
        let (_, middle, _, _) = pki();
        let pem = include_str!("identity/testdata/rsa1024.pem");
        let (_, root) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();

        assert_eq!(intermediates(vec![middle.clone(), root.contents]), [middle]);
    }

    #[test]
    fn a_certificate_that_cannot_be_read_is_dropped() {
        let (_, middle, _, _) = pki();
        assert_eq!(intermediates(vec![vec![1, 2, 3], middle.clone()]), [middle]);
    }

    fn key() -> KeyId {
        KeyId {
            storage: Storage::Software,
            name: "k-1".into(),
        }
    }

    #[test]
    fn without_an_installer_nothing_is_installed() {
        assert_eq!(
            NoInstaller.install(&key(), &[1], &[]),
            Err(InstallError::Unavailable)
        );
    }

    #[test]
    fn the_recording_installer_remembers_each_call_and_fails_when_told() {
        let installer = RecordingInstaller::new();
        installer.install(&key(), &[1, 2], &[vec![3]]).unwrap();
        installer.fail(true);
        assert_eq!(
            installer.install(&key(), &[4], &[]),
            Err(InstallError::Failed("told to fail".into()))
        );
        assert_eq!(
            installer.calls(),
            [
                Installation {
                    key: key(),
                    leaf: vec![1, 2],
                    intermediates: 1
                },
                Installation {
                    key: key(),
                    leaf: vec![4],
                    intermediates: 0
                },
            ]
        );
    }

    #[test]
    fn without_an_installer_nothing_is_installed_beside_or_removed() {
        let old = Fingerprint::of(b"old");
        assert_eq!(
            NoInstaller.install_beside(&old, &[1], &[]),
            Err(InstallError::Unavailable)
        );
        assert_eq!(
            NoInstaller.remove(&old, true),
            Err(InstallError::Unavailable)
        );
    }

    #[test]
    fn the_recording_installer_remembers_installations_beside_and_removals() {
        let installer = RecordingInstaller::new();
        let old = Fingerprint::of(b"old");
        installer.install_beside(&old, &[1, 2], &[vec![3]]).unwrap();
        installer.remove(&old, false).unwrap();
        installer.fail(true);
        assert_eq!(
            installer.install_beside(&old, &[4], &[]),
            Err(InstallError::Failed("told to fail".into()))
        );
        assert_eq!(
            installer.remove(&old, true),
            Err(InstallError::Failed("told to fail".into()))
        );
        assert_eq!(
            installer.beside_calls(),
            [
                InstallationBeside {
                    old,
                    leaf: vec![1, 2],
                    intermediates: 1
                },
                InstallationBeside {
                    old,
                    leaf: vec![4],
                    intermediates: 0
                },
            ]
        );
        assert_eq!(
            installer.removals(),
            [
                Removal {
                    fingerprint: old,
                    delete_key: false
                },
                Removal {
                    fingerprint: old,
                    delete_key: true
                },
            ]
        );
        assert!(installer.calls().is_empty());
    }

    #[test]
    fn the_errors_speak_plainly() {
        assert_eq!(
            InstallError::Unavailable.to_string(),
            "this computer cannot install certificates"
        );
        assert_eq!(
            InstallError::Failed("denied".into()).to_string(),
            "the installation failed: denied"
        );
    }
}
