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
    /// The UUID of the certificate ILM made for it; none until ILM answers the send.
    pub uuid: Option<String>,
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
    entries: Mutex<Cache>,
}

/// The requests as read, and whether the file lacks a change that was only kept in memory.
struct Cache {
    entries: Option<Vec<Waiting>>,
    unsaved: bool,
}

impl Requests {
    pub fn new(folder: &Path) -> Self {
        Self {
            path: folder.join(store::FILE),
            entries: Mutex::new(Cache {
                entries: None,
                unsaved: false,
            }),
        }
    }

    /// The requests, read at first use. A file that cannot be read is tried again at the next use.
    fn held(&self) -> io::Result<MutexGuard<'_, Cache>> {
        let mut cache = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.entries.is_none() {
            cache.entries = Some(store::read(&self.path)?);
        }
        Ok(cache)
    }

    /// Whether the file can be read, so a change can be written to it.
    pub fn readable(&self) -> io::Result<()> {
        self.held().map(drop)
    }

    /// Changes the requests and writes them; when the file cannot be read or the write fails nothing is kept.
    fn change(&self, change: impl FnOnce(&mut Vec<Waiting>)) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        let mut changed = entries.clone();
        change(&mut changed);
        store::write(&self.path, &changed)?;
        *entries = changed;
        held.unsaved = false;
        Ok(())
    }

    /// Every request; none while the file cannot be read.
    pub fn all(&self) -> Vec<Waiting> {
        self.held()
            .ok()
            .and_then(|held| held.entries.clone())
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

    /// Records the UUID of the certificate ILM made for the request of `key`. It is kept while the application runs
    /// even when the file cannot be written, because ILM has the request by then.
    pub fn set_uuid(&self, key: &KeyId, uuid: &str) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        if let Some(entry) = entries.iter_mut().find(|entry| &entry.key == key) {
            entry.uuid = Some(uuid.to_owned());
        }
        let written = store::write(&self.path, entries);
        held.unsaved = written.is_err();
        written
    }

    /// Writes the requests when a change was kept only in memory because the file could not be written.
    pub fn save_pending(&self) {
        let Ok(mut held) = self.held() else {
            return;
        };
        if !held.unsaved {
            return;
        }
        let entries = held.entries.as_deref().expect("the entries are loaded");
        match store::write(&self.path, entries) {
            Ok(()) => held.unsaved = false,
            Err(error) => log::warn!("the waiting requests cannot be written: {error}"),
        }
    }

    /// Drops the request of `key`; one that is not there is fine. When the file cannot be written the removal is kept
    /// in memory and written by `save_pending`, so the request is not followed again while the application runs.
    pub fn remove(&self, key: &KeyId) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        let Some(at) = entries.iter().position(|entry| &entry.key == key) else {
            return Ok(());
        };
        let described = describe(&entries.remove(at));
        let written = store::write(&self.path, entries);
        held.unsaved = written.is_err();
        if written.is_ok() {
            log::info!("a waiting request is removed ({described})");
        }
        written
    }
}

/// The certificate UUID, if known, and the RA Profile UUID: what the log may say of a request.
fn describe(entry: &Waiting) -> String {
    match &entry.uuid {
        Some(uuid) => format!("certificate {uuid}, RA Profile {}", entry.ra_profile),
        None => format!("RA Profile {}", entry.ra_profile),
    }
}
