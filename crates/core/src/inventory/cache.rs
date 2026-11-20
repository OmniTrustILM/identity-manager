//! The file that keeps ILM's last answer, so the application can show it offline after a restart.
//!
//! It holds certificate metadata and fingerprints only: no token, no key and nothing else from this computer.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Snapshot;
use crate::ilm::IlmUrl;
use crate::settings::store::write_atomically;

pub(super) const FILE: &str = "ilm-cache.json";
const VERSION: u32 = 1;

#[derive(Serialize)]
struct Written<'a> {
    version: u32,
    ilm: &'a str,
    username: &'a str,
    #[serde(flatten)]
    snapshot: &'a Snapshot,
}

#[derive(Deserialize)]
struct Header {
    version: u32,
}

#[derive(Deserialize)]
struct Stored {
    ilm: String,
    username: String,
    #[serde(flatten)]
    snapshot: Snapshot,
}

/// Replaces the file with `snapshot`, which belongs to `username` at `ilm`.
pub(super) fn write(
    path: &Path,
    ilm: &IlmUrl,
    username: &str,
    snapshot: &Snapshot,
) -> io::Result<()> {
    let text = serde_json::to_string(&Written {
        version: VERSION,
        ilm: ilm.as_str(),
        username,
        snapshot,
    })?;
    write_atomically(path, &text)
}

/// The snapshot in the file, when it belongs to `username` at `ilm`. A file of someone else, of another
/// address, of an unknown version or one that cannot be read is deleted.
pub(super) fn read(path: &Path, ilm: &IlmUrl, username: &str) -> Option<Snapshot> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(error) => {
            log::warn!("the ILM cache cannot be read ({error}); it is deleted");
            delete(path);
            return None;
        }
    };
    match serde_json::from_slice::<Header>(&bytes) {
        Ok(Header { version: VERSION }) => {}
        Ok(Header { version }) => {
            log::warn!("the ILM cache has the unknown version {version}; it is deleted");
            delete(path);
            return None;
        }
        Err(_) => {
            log::warn!("the ILM cache is broken; it is deleted");
            delete(path);
            return None;
        }
    }
    let Ok(stored) = serde_json::from_slice::<Stored>(&bytes) else {
        log::warn!("the ILM cache is broken; it is deleted");
        delete(path);
        return None;
    };
    if stored.ilm != ilm.as_str() || stored.username != username {
        log::info!("the ILM cache belongs to another sign-in; it is deleted");
        delete(path);
        return None;
    }
    Some(stored.snapshot)
}

/// Removes the file; a missing file is fine.
pub(super) fn delete(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => log::info!("the ILM cache is deleted"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => log::warn!("the ILM cache could not be deleted: {error}"),
    }
}
