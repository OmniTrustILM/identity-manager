//! The requests that wait for ILM: a certificate asked for, or a key prepared, that is not yet a certificate
//! on this computer.

mod store;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::ilm::IlmUrl;
use crate::keys::KeyId;

/// A request waiting for ILM. Nothing secret is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Waiting {
    pub ilm: IlmUrl,
    pub username: String,
    /// The certificate ILM made for it; none until ILM answers the send.
    pub certificate: Option<String>,
    pub ra_profile: String,
    pub authority: String,
    pub key: KeyId,
    pub label: String,
    /// Milliseconds since 1970 UTC.
    pub since: i64,
    /// Whether the key was made for a certificate ILM registered in advance.
    pub prepared: bool,
}

/// The waiting requests, kept in `requests.json` in the settings folder. The file is read at first use and never written over while it cannot be read. Requests
/// of another ILM or person stay in the file and are left out of what is listed.
pub struct Requests {
    path: PathBuf,
    entries: Mutex<Option<Vec<Waiting>>>,
}

impl Requests {
    pub fn new(folder: &Path) -> Self {
        Self {
            path: folder.join(store::FILE),
            entries: Mutex::new(None),
        }
    }

    /// The requests, read at first use. A file that cannot be read is tried again at the next use.
    fn held(&self) -> io::Result<MutexGuard<'_, Option<Vec<Waiting>>>> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.is_none() {
            *entries = Some(store::read(&self.path)?);
        }
        Ok(entries)
    }

    /// Changes the requests and writes them; when the file cannot be read or the write fails nothing is kept.
    fn change(&self, change: impl FnOnce(&mut Vec<Waiting>)) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.as_mut().expect("the entries are loaded");
        let mut changed = entries.clone();
        change(&mut changed);
        store::write(&self.path, &changed)?;
        *entries = changed;
        Ok(())
    }

    /// Every request; none while the file cannot be read.
    pub fn all(&self) -> Vec<Waiting> {
        self.held()
            .ok()
            .and_then(|held| held.clone())
            .unwrap_or_default()
    }

    /// The requests of `username` at `ilm`.
    pub fn of(&self, ilm: &IlmUrl, username: &str) -> Vec<Waiting> {
        self.all()
            .into_iter()
            .filter(|entry| &entry.ilm == ilm && entry.username == username)
            .collect()
    }

    /// Keeps `entry`, replacing the one of the same key.
    pub fn add(&self, entry: Waiting) -> io::Result<()> {
        let described = describe(&entry);
        self.change(|entries| {
            entries.retain(|kept| kept.key != entry.key);
            entries.push(entry);
        })?;
        log::info!("a request is waiting for ILM ({described})");
        Ok(())
    }

    /// Records the certificate ILM made for the request of `key`. It is kept for as long as the application runs
    /// even when the file cannot be written, because ILM has the request by then.
    pub fn set_certificate(&self, key: &KeyId, certificate: &str) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.as_mut().expect("the entries are loaded");
        if let Some(entry) = entries.iter_mut().find(|entry| &entry.key == key) {
            entry.certificate = Some(certificate.to_owned());
        }
        store::write(&self.path, entries)
    }

    /// Drops the request of `key`; one that is not there is fine.
    pub fn remove(&self, key: &KeyId) -> io::Result<()> {
        let mut described = None;
        self.change(|entries| {
            if let Some(at) = entries.iter().position(|entry| &entry.key == key) {
                described = Some(describe(&entries.remove(at)));
            }
        })?;
        if let Some(described) = described {
            log::info!("a waiting request is removed ({described})");
        }
        Ok(())
    }
}

/// The certificate UUID, if known, and the RA Profile UUID: what the log may say of a request.
fn describe(entry: &Waiting) -> String {
    match &entry.certificate {
        Some(certificate) => format!("certificate {certificate}, RA Profile {}", entry.ra_profile),
        None => format!("RA Profile {}", entry.ra_profile),
    }
}
