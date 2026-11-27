//! What enrolment by policy did for each person, kept in `enrolment.json`.
//!
//! The file survives a sign-out, so a person who signs in again is not enrolled again. It holds no secret. A file
//! that cannot be read is never written over, and while it cannot be read nothing is known of any person.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::ilm::IlmUrl;
use crate::settings::store::write_atomically;

const FILE: &str = "enrolment.json";
const VERSION: u32 = 1;

/// How long a failed attempt holds the next one back, in milliseconds.
pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// The failure key of an RA Profile that policy names.
pub fn profile_key(ra_profile: &str) -> String {
    format!("profile:{ra_profile}")
}

/// The failure key of a certificate prepared in ILM.
pub fn prepared_key(certificate: &str) -> String {
    format!("prepared:{certificate}")
}

/// The failure key of a certificate that was to become the sign-in certificate.
pub fn sign_in_key(certificate: &str) -> String {
    format!("sign-in:{certificate}")
}

/// The last failed attempt at one thing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub key: String,
    /// Milliseconds since 1970 UTC.
    pub at: i64,
    /// How many attempts at the key have failed since the last success.
    #[serde(default)]
    pub count: u32,
}

/// What is kept for one person at one ILM.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Standing {
    /// The RA Profiles that were requested once.
    #[serde(default)]
    pub done: Vec<String>,
    /// The last failed attempt per key.
    #[serde(default)]
    pub failed: Vec<Failure>,
    /// The certificates enrolment installed, until it is settled whether they become the sign-in certificate.
    #[serde(default)]
    pub installed: Vec<String>,
}

impl Standing {
    pub fn is_done(&self, ra_profile: &str) -> bool {
        self.done.iter().any(|done| done == ra_profile)
    }

    /// Whether the attempt at `key` failed less than a day before `now`, milliseconds since 1970 UTC.
    pub fn failed_within_a_day(&self, key: &str, now: i64) -> bool {
        self.failed
            .iter()
            .any(|failure| failure.key == key && now.saturating_sub(failure.at) < DAY_MS)
    }

    /// How many attempts at `key` have failed since the last success.
    pub fn failures(&self, key: &str) -> u32 {
        self.failed
            .iter()
            .find(|failure| failure.key == key)
            .map_or(0, |failure| failure.count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    ilm: String,
    username: String,
    #[serde(flatten)]
    standing: Standing,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    version: u32,
    people: Vec<Person>,
}

#[derive(Deserialize)]
struct Header {
    version: u32,
}

/// The enrolment of the people of this computer.
pub struct Enrolments {
    path: PathBuf,
    /// Held while the file is read and written, so two changes do not interleave.
    changing: Mutex<()>,
}

impl Enrolments {
    pub fn new(folder: &Path) -> Self {
        Self {
            path: folder.join(FILE),
            changing: Mutex::new(()),
        }
    }

    /// What is kept for the person; nothing for one who is not in the file. An error while the file cannot be read,
    /// so nothing is enrolled on a guess.
    pub fn standing(&self, ilm: &IlmUrl, username: &str) -> io::Result<Standing> {
        Ok(self
            .read()?
            .into_iter()
            .find(|person| is_of(person, ilm, username))
            .map(|person| person.standing)
            .unwrap_or_default())
    }

    /// Notes that the RA Profile was requested for the person; whether it was not noted before.
    pub fn mark_done(&self, ilm: &IlmUrl, username: &str, ra_profile: &str) -> io::Result<bool> {
        let marked = self.change(ilm, username, |standing| {
            let new = !standing.is_done(ra_profile);
            if new {
                standing.done.push(ra_profile.to_owned());
            }
            new
        })?;
        if marked {
            log::info!("enrolment done for the RA Profile {ra_profile}");
        }
        Ok(marked)
    }

    /// Forgets that the RA Profile was requested for the person, as ILM surely never got the request.
    pub fn unmark_done(&self, ilm: &IlmUrl, username: &str, ra_profile: &str) -> io::Result<()> {
        self.change(ilm, username, |standing| {
            standing.done.retain(|done| done != ra_profile);
        })
    }

    /// Notes that the certificate `uuid` was installed by enrolment.
    pub fn mark_installed(&self, ilm: &IlmUrl, username: &str, uuid: &str) -> io::Result<()> {
        self.change(ilm, username, |standing| {
            if !standing.installed.iter().any(|installed| installed == uuid) {
                standing.installed.push(uuid.to_owned());
            }
        })
    }

    /// Forgets that the certificate `uuid` is waiting to be considered as the sign-in certificate.
    pub fn clear_installed(&self, ilm: &IlmUrl, username: &str, uuid: &str) -> io::Result<()> {
        self.change(ilm, username, |standing| {
            standing.installed.retain(|installed| installed != uuid);
        })
    }

    /// Notes that the attempt at `key` failed at `at`, replacing the earlier failure of the key and counting it.
    pub fn record_failure(
        &self,
        ilm: &IlmUrl,
        username: &str,
        key: &str,
        at: i64,
    ) -> io::Result<()> {
        self.change(ilm, username, |standing| {
            let count = standing.failures(key).saturating_add(1);
            standing.failed.retain(|failure| failure.key != key);
            standing.failed.push(Failure {
                key: key.to_owned(),
                at,
                count,
            });
        })
    }

    /// Forgets the failure of `key`, if there is one.
    pub fn clear_failure(&self, ilm: &IlmUrl, username: &str, key: &str) -> io::Result<()> {
        self.change(ilm, username, |standing| {
            standing.failed.retain(|failure| failure.key != key);
        })
    }

    fn read(&self) -> io::Result<Vec<Person>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                log::warn!("the enrolment record cannot be read ({error})");
                return Err(error);
            }
        };
        match serde_json::from_slice::<Header>(&bytes) {
            Ok(Header { version: VERSION }) => {}
            _ => return Err(unreadable()),
        }
        serde_json::from_slice::<Stored>(&bytes)
            .map(|stored| stored.people)
            .map_err(|_| unreadable())
    }

    fn change<T>(
        &self,
        ilm: &IlmUrl,
        username: &str,
        change: impl FnOnce(&mut Standing) -> T,
    ) -> io::Result<T> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut people = self.read()?;
        let at = people
            .iter()
            .position(|person| is_of(person, ilm, username))
            .unwrap_or_else(|| {
                people.push(Person {
                    ilm: ilm.as_str().to_owned(),
                    username: username.to_owned(),
                    ..Person::default()
                });
                people.len() - 1
            });
        let changed = change(&mut people[at].standing);
        let text = serde_json::to_string_pretty(&Stored {
            version: VERSION,
            people,
        })?;
        write_atomically(&self.path, &text)?;
        Ok(changed)
    }
}

fn is_of(person: &Person, ilm: &IlmUrl, username: &str) -> bool {
    person.ilm == ilm.as_str() && person.username == username
}

fn unreadable() -> io::Error {
    log::warn!("the enrolment record is broken or of an unknown version; it is left alone");
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the enrolment file cannot be read",
    )
}
