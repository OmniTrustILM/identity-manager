//! Putting an issued certificate where the system keeps it, next to the key it was asked for.

use std::fmt;

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
}

/// The computer cannot install certificates: every installation fails as unavailable.
pub struct NoInstaller;

impl CertificateInstaller for NoInstaller {
    fn install(&self, _: &KeyId, _: &[u8], _: &[Vec<u8>]) -> Result<(), InstallError> {
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

/// An installer that only remembers what it was asked, and fails while it is told to.
#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct RecordingInstaller {
    calls: std::sync::Mutex<Vec<Installation>>,
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
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(InstallError::Failed("told to fail".to_owned()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Storage;

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
