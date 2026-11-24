//! The file that keeps the requests waiting for ILM.
//!
//! It holds no secret: the key is named, never kept, and the challenge of a registration is not stored.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::Waiting;
use crate::settings::store::write_atomically;

pub(super) const FILE: &str = "requests.json";
const VERSION: u32 = 1;

#[derive(Serialize)]
struct Written<'a> {
    version: u32,
    waiting: &'a [Waiting],
}

#[derive(Deserialize)]
struct Header {
    version: u32,
}

#[derive(Deserialize)]
struct Stored {
    waiting: Vec<Waiting>,
}

/// Replaces the file with `waiting`.
pub(super) fn write(path: &Path, waiting: &[Waiting]) -> io::Result<()> {
    let text = serde_json::to_string_pretty(&Written {
        version: VERSION,
        waiting,
    })?;
    write_atomically(path, &text)
}

/// The requests in the file. A missing file holds none. One that cannot be read, is broken or has an unknown
/// version is an error, so it is never written over.
pub(super) fn read(path: &Path) -> io::Result<Vec<Waiting>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            log::warn!("the waiting requests cannot be read ({error})");
            return Err(error);
        }
    };
    match serde_json::from_slice::<Header>(&bytes) {
        Ok(Header { version: VERSION }) => {}
        Ok(Header { version }) => {
            log::warn!(
                "the waiting requests have the unknown version {version}; they are left alone"
            );
            return Err(invalid("the waiting requests have an unknown version"));
        }
        Err(_) => return Err(broken()),
    }
    serde_json::from_slice::<Stored>(&bytes)
        .map(|stored| stored.waiting)
        .map_err(|_| broken())
}

fn broken() -> io::Error {
    log::warn!("the waiting requests are broken; they are left alone");
    invalid("the waiting requests are broken")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
