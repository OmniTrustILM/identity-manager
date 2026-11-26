//! The per-certificate switches of automatic renewal and the failed attempts, kept in `renewal.json`.
//!
//! Only the certificates that are switched off are listed. A file that cannot be read is never written over, and
//! while it exists but cannot be read every certificate counts as switched off.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::identity::Fingerprint;
use crate::ilm::IlmUrl;
use crate::settings::store::write_atomically;

const FILE: &str = "renewal.json";
const VERSION: u32 = 1;

/// What is kept for one person at one ILM.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    ilm: String,
    username: String,
    /// The certificates whose automatic renewal the person switched off.
    #[serde(default)]
    off: Vec<Fingerprint>,
    /// When the last automatic attempt on a certificate failed.
    #[serde(default)]
    failed: Vec<Failure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Failure {
    fingerprint: Fingerprint,
    /// Milliseconds since 1970 UTC.
    at: i64,
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

/// The switches and failures of the people of this computer.
pub struct Renewals {
    path: PathBuf,
    /// Held while the file is read and written, so two changes do not interleave.
    changing: Mutex<()>,
}

impl Renewals {
    pub fn new(folder: &Path) -> Self {
        Self {
            path: folder.join(FILE),
            changing: Mutex::new(()),
        }
    }

    /// Whether automatic renewal of the certificate is switched off. It is held back while the switches cannot be
    /// read.
    pub fn is_off(&self, ilm: &IlmUrl, username: &str, certificate: &Fingerprint) -> bool {
        self.read().map_or(true, |people| {
            find(&people, ilm, username).is_some_and(|person| person.off.contains(certificate))
        })
    }

    /// Switches automatic renewal of the certificate off or on.
    pub fn set_off(
        &self,
        ilm: &IlmUrl,
        username: &str,
        certificate: &Fingerprint,
        off: bool,
    ) -> io::Result<()> {
        self.change(ilm, username, |person| {
            person.off.retain(|kept| kept != certificate);
            if off {
                person.off.push(*certificate);
            }
        })
    }

    /// Moves the switch of a renewed certificate to its successor. A successor is left as it is when the renewed
    /// certificate was not switched off, so a replayed move keeps what the person set on the successor.
    pub fn carry(
        &self,
        ilm: &IlmUrl,
        username: &str,
        from: &Fingerprint,
        to: &Fingerprint,
    ) -> io::Result<()> {
        self.change(ilm, username, |person| {
            if person.off.contains(from) {
                person.off.retain(|kept| kept != from && kept != to);
                person.off.push(*to);
            }
            person.failed.retain(|failure| &failure.fingerprint != from);
        })
    }

    /// Forgets what is kept of the certificates that are not in `present`. The caller passes the certificates
    /// of this computer only when it has read them all.
    pub fn prune(&self, ilm: &IlmUrl, username: &str, present: &[Fingerprint]) -> io::Result<()> {
        self.change(ilm, username, |person| {
            person.off.retain(|kept| present.contains(kept));
            person
                .failed
                .retain(|failure| present.contains(&failure.fingerprint));
        })
    }

    /// When the last automatic attempt on the certificate failed.
    pub fn last_failure(
        &self,
        ilm: &IlmUrl,
        username: &str,
        certificate: &Fingerprint,
    ) -> Option<SystemTime> {
        let people = self.read().ok()?;
        find(&people, ilm, username)?
            .failed
            .iter()
            .find(|failure| &failure.fingerprint == certificate)
            .and_then(|failure| u64::try_from(failure.at).ok())
            .map(|at| UNIX_EPOCH + Duration::from_millis(at))
    }

    /// Notes that an automatic attempt on the certificate failed at `at`.
    pub fn record_failure(
        &self,
        ilm: &IlmUrl,
        username: &str,
        certificate: &Fingerprint,
        at: SystemTime,
    ) -> io::Result<()> {
        let at = at
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as i64);
        self.change(ilm, username, |person| {
            person
                .failed
                .retain(|failure| &failure.fingerprint != certificate);
            person.failed.push(Failure {
                fingerprint: *certificate,
                at,
            });
        })
    }

    fn read(&self) -> io::Result<Vec<Person>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                log::warn!("the renewal switches cannot be read ({error})");
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

    fn change(
        &self,
        ilm: &IlmUrl,
        username: &str,
        change: impl FnOnce(&mut Person),
    ) -> io::Result<()> {
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
        change(&mut people[at]);
        people.retain(|person| !person.off.is_empty() || !person.failed.is_empty());
        let text = serde_json::to_string_pretty(&Stored {
            version: VERSION,
            people,
        })?;
        write_atomically(&self.path, &text)
    }
}

fn find<'a>(people: &'a [Person], ilm: &IlmUrl, username: &str) -> Option<&'a Person> {
    people.iter().find(|person| is_of(person, ilm, username))
}

fn is_of(person: &Person, ilm: &IlmUrl, username: &str) -> bool {
    person.ilm == ilm.as_str() && person.username == username
}

fn unreadable() -> io::Error {
    log::warn!("the renewal switches are broken or of an unknown version; they are left alone");
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the renewal file cannot be read",
    )
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn ilm() -> IlmUrl {
        IlmUrl::parse("ilm.example.com").unwrap()
    }

    fn print(name: &str) -> Fingerprint {
        Fingerprint::of(name.as_bytes())
    }

    #[test]
    fn nothing_is_off_without_a_file() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        assert!(!renewals.is_off(&ilm(), "jdoe", &print("a")));
        assert_eq!(renewals.last_failure(&ilm(), "jdoe", &print("a")), None);
    }

    #[test]
    fn a_switch_survives_a_new_instance_and_belongs_to_one_person() {
        let dir = tempdir().unwrap();
        Renewals::new(dir.path())
            .set_off(&ilm(), "jdoe", &print("a"), true)
            .unwrap();

        let again = Renewals::new(dir.path());
        assert!(again.is_off(&ilm(), "jdoe", &print("a")));
        assert!(!again.is_off(&ilm(), "other", &print("a")));
        assert!(!again.is_off(&ilm(), "jdoe", &print("b")));
        assert!(!again.is_off(
            &IlmUrl::parse("other.example.com").unwrap(),
            "jdoe",
            &print("a")
        ));
    }

    #[test]
    fn the_file_is_versioned_and_lists_only_what_is_switched_off() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals.set_off(&ilm(), "jdoe", &print("a"), true).unwrap();
        renewals.set_off(&ilm(), "jdoe", &print("b"), true).unwrap();
        renewals
            .set_off(&ilm(), "jdoe", &print("b"), false)
            .unwrap();

        let text = std::fs::read_to_string(dir.path().join("renewal.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["version"], 1);
        assert_eq!(json["people"][0]["ilm"], "https://ilm.example.com");
        assert_eq!(json["people"][0]["username"], "jdoe");
        assert_eq!(json["people"][0]["off"], serde_json::json!([print("a")]));
    }

    #[test]
    fn switching_on_removes_the_certificate_and_the_last_one_empties_the_file() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals.set_off(&ilm(), "jdoe", &print("a"), true).unwrap();
        renewals.set_off(&ilm(), "jdoe", &print("a"), true).unwrap();
        renewals
            .set_off(&ilm(), "jdoe", &print("a"), false)
            .unwrap();

        assert!(!renewals.is_off(&ilm(), "jdoe", &print("a")));
        let text = std::fs::read_to_string(dir.path().join("renewal.json")).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["people"], serde_json::json!([]));
    }

    #[test]
    fn the_switch_moves_to_the_successor() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals
            .set_off(&ilm(), "jdoe", &print("old"), true)
            .unwrap();
        renewals
            .carry(&ilm(), "jdoe", &print("old"), &print("new"))
            .unwrap();

        assert!(!renewals.is_off(&ilm(), "jdoe", &print("old")));
        assert!(renewals.is_off(&ilm(), "jdoe", &print("new")));
    }

    #[test]
    fn carrying_twice_keeps_the_successor_off() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals
            .set_off(&ilm(), "jdoe", &print("old"), true)
            .unwrap();
        for _ in 0..2 {
            renewals
                .carry(&ilm(), "jdoe", &print("old"), &print("new"))
                .unwrap();
        }

        assert!(renewals.is_off(&ilm(), "jdoe", &print("new")));
        assert!(!renewals.is_off(&ilm(), "jdoe", &print("old")));
    }

    #[test]
    fn what_leaves_the_computer_is_pruned() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals.set_off(&ilm(), "jdoe", &print("a"), true).unwrap();
        renewals.set_off(&ilm(), "jdoe", &print("b"), true).unwrap();
        renewals
            .record_failure(
                &ilm(),
                "jdoe",
                &print("b"),
                UNIX_EPOCH + Duration::from_secs(5),
            )
            .unwrap();
        renewals.prune(&ilm(), "jdoe", &[print("a")]).unwrap();

        assert!(renewals.is_off(&ilm(), "jdoe", &print("a")));
        assert!(!renewals.is_off(&ilm(), "jdoe", &print("b")));
        assert_eq!(renewals.last_failure(&ilm(), "jdoe", &print("b")), None);
    }

    #[test]
    fn a_failure_is_kept_per_certificate_and_the_latest_wins() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        let first = UNIX_EPOCH + Duration::from_secs(1_000);
        let second = UNIX_EPOCH + Duration::from_secs(2_000);
        renewals
            .record_failure(&ilm(), "jdoe", &print("a"), first)
            .unwrap();
        renewals
            .record_failure(&ilm(), "jdoe", &print("a"), second)
            .unwrap();

        let again = Renewals::new(dir.path());
        assert_eq!(
            again.last_failure(&ilm(), "jdoe", &print("a")),
            Some(second)
        );
        assert_eq!(again.last_failure(&ilm(), "jdoe", &print("b")), None);
    }

    #[test]
    fn the_failure_of_the_old_certificate_is_forgotten_when_it_is_renewed() {
        let dir = tempdir().unwrap();
        let renewals = Renewals::new(dir.path());
        renewals
            .record_failure(
                &ilm(),
                "jdoe",
                &print("old"),
                UNIX_EPOCH + Duration::from_secs(9),
            )
            .unwrap();
        renewals
            .carry(&ilm(), "jdoe", &print("old"), &print("new"))
            .unwrap();

        assert_eq!(renewals.last_failure(&ilm(), "jdoe", &print("old")), None);
    }

    #[test]
    fn a_file_that_cannot_be_trusted_holds_renewal_back_and_is_never_written_over() {
        for text in [r#"{"version": 2, "people": []}"#, "{", r#"{"version": 1}"#] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("renewal.json");
            std::fs::write(&path, text).unwrap();
            let renewals = Renewals::new(dir.path());

            assert!(renewals.is_off(&ilm(), "jdoe", &print("a")));
            assert!(renewals.set_off(&ilm(), "jdoe", &print("a"), true).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
        }
    }
}
