//! The requests that wait for ILM: a certificate asked for, or a key prepared, that is not yet a certificate
//! on this computer.

mod store;
#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use crate::identity::Fingerprint;
use crate::ilm::IlmUrl;
use crate::keys::KeyId;

/// What a waiting request is for. Files written before renewals existed hold issue requests only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum Purpose {
    /// A new certificate, with the key in `key`.
    #[default]
    Issue,
    /// A certificate that replaces `replaces`, installed on this computer as `replaces_fingerprint`.
    Renew {
        replaces: String,
        replaces_fingerprint: Fingerprint,
        /// Whether the sign-in moves to the new certificate once it is installed.
        sign_in: bool,
        /// Whether the new certificate has the key of the old one, so no key was made.
        same_key: bool,
        /// Whether the application started it rather than the person.
        automatic: bool,
        /// Set once the new certificate is installed and the sign-in has not moved over to it yet.
        #[serde(default)]
        switch: Option<PendingSwitch>,
    },
    /// A revocation of `certificate`, installed on this computer as `fingerprint`.
    Revoke {
        certificate: String,
        fingerprint: Fingerprint,
        /// Whether the certificate is removed from this computer once it is revoked.
        remove: bool,
    },
}

/// A renewed certificate that is installed here while the sign-in has not moved over to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingSwitch {
    /// The installed certificate the sign-in moves to.
    pub fingerprint: Fingerprint,
    /// How many times moving over failed.
    pub failures: u8,
}

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
    /// The key made for the request; none for a renewal with the key the certificate has and for a revocation.
    #[serde(default)]
    pub key: Option<KeyId>,
    pub label: String,
    /// Milliseconds since 1970 UTC.
    pub since: i64,
    /// Whether the key was made for a certificate ILM registered in advance.
    pub prepared: bool,
    #[serde(default)]
    pub purpose: Purpose,
}

impl Waiting {
    /// Whether both are the same request: those with a key by the key, the others by the certificate they renew.
    fn is_same(&self, other: &Waiting) -> bool {
        match (&self.key, &other.key) {
            (Some(key), Some(other)) => key == other,
            (None, None) => {
                (self.renews().is_some() && self.renews() == other.renews())
                    || (self.revokes().is_some() && self.revokes() == other.revokes())
            }
            _ => false,
        }
    }

    /// The ILM uuid of the certificate a renewal replaces.
    pub fn renews(&self) -> Option<&str> {
        match &self.purpose {
            Purpose::Renew { replaces, .. } => Some(replaces),
            _ => None,
        }
    }

    /// The ILM uuid of the certificate a revocation is for.
    pub fn revokes(&self) -> Option<&str> {
        match &self.purpose {
            Purpose::Revoke { certificate, .. } => Some(certificate),
            _ => None,
        }
    }

    /// The renewed certificate the sign-in has still to move over to.
    pub fn pending_switch(&self) -> Option<PendingSwitch> {
        match &self.purpose {
            Purpose::Renew { switch, .. } => *switch,
            _ => None,
        }
    }

    /// The installed certificate a renewal replaces.
    pub fn replaces_fingerprint(&self) -> Option<Fingerprint> {
        match &self.purpose {
            Purpose::Renew {
                replaces_fingerprint,
                ..
            } => Some(*replaces_fingerprint),
            _ => None,
        }
    }
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
            entries.retain(|kept| !kept.is_same(&entry));
            entries.push(entry);
        })?;
        log::info!("a request is waiting for ILM ({described})");
        Ok(())
    }

    /// Records the UUID of the certificate ILM made for the request of `key`. It is kept while the application runs
    /// even when the file cannot be written, because ILM has the request by then.
    pub fn set_uuid(&self, key: &KeyId, uuid: &str) -> io::Result<()> {
        self.set_uuid_where(|entry| entry.key.as_ref() == Some(key), uuid)
    }

    /// Like [`Requests::set_uuid`], for the renewal without a key of the certificate `replaces`.
    pub fn set_renewal_uuid(&self, replaces: &str, uuid: &str) -> io::Result<()> {
        self.set_uuid_where(
            |entry| entry.key.is_none() && entry.renews() == Some(replaces),
            uuid,
        )
    }

    /// Records that the renewal of the certificate `replaces` is installed and its sign-in has not moved over.
    pub fn set_switch(&self, replaces: &str, pending: PendingSwitch) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        for entry in entries
            .iter_mut()
            .filter(|entry| entry.renews() == Some(replaces))
        {
            if let Purpose::Renew { switch, .. } = &mut entry.purpose {
                *switch = Some(pending);
            }
        }
        let written = store::write(&self.path, entries);
        held.unsaved = written.is_err();
        written
    }

    fn set_uuid_where(&self, is: impl Fn(&Waiting) -> bool, uuid: &str) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        if let Some(entry) = entries.iter_mut().find(|entry| is(entry)) {
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
        self.remove_where(|entry| entry.key.as_ref() == Some(key))
    }

    /// Like [`Requests::remove`], for the renewal without a key of the certificate `replaces`.
    pub fn remove_renewal(&self, replaces: &str) -> io::Result<()> {
        self.remove_where(|entry| entry.key.is_none() && entry.renews() == Some(replaces))
    }

    /// Like [`Requests::remove`], for the revocation of the certificate `certificate`.
    pub fn remove_revocation(&self, certificate: &str) -> io::Result<()> {
        self.remove_where(|entry| entry.revokes() == Some(certificate))
    }

    fn remove_where(&self, is: impl Fn(&Waiting) -> bool) -> io::Result<()> {
        let mut held = self.held()?;
        let entries = held.entries.as_mut().expect("the entries are loaded");
        let Some(at) = entries.iter().position(is) else {
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
