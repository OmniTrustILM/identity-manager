use tempfile::tempdir;

use super::*;
use crate::keys::Storage;

fn ilm() -> IlmUrl {
    IlmUrl::parse("ilm.example.com").unwrap()
}

fn waiting(name: &str) -> Waiting {
    Waiting {
        ilm: ilm(),
        username: "jdoe".into(),
        certificate: None,
        ra_profile: "ra-1".into(),
        authority: "auth-1".into(),
        key: KeyId {
            storage: Storage::Software,
            name: name.into(),
        },
        label: format!("label of {name}"),
        since: 1_700_000_000_000,
        prepared: false,
    }
}

fn key(name: &str) -> KeyId {
    waiting(name).key
}

#[test]
fn a_request_survives_a_new_instance() {
    let dir = tempdir().unwrap();
    Requests::new(dir.path()).add(waiting("k-1")).unwrap();
    assert_eq!(Requests::new(dir.path()).all(), [waiting("k-1")]);
}

#[test]
fn nothing_waits_without_a_file() {
    let dir = tempdir().unwrap();
    assert!(Requests::new(dir.path()).all().is_empty());
}

#[test]
fn the_file_is_versioned() {
    let dir = tempdir().unwrap();
    Requests::new(dir.path()).add(waiting("k-1")).unwrap();
    let text = std::fs::read_to_string(dir.path().join("requests.json")).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["version"], 1);
    assert_eq!(json["waiting"][0]["raProfile"], "ra-1");
}

#[test]
fn a_file_that_cannot_be_trusted_is_never_written_over() {
    for text in [r#"{"version": 2, "waiting": []}"#, "{", r#"{"version": 1}"#] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requests.json");
        std::fs::write(&path, text).unwrap();
        let requests = Requests::new(dir.path());

        assert!(requests.all().is_empty());
        assert!(requests.add(waiting("k-1")).is_err());
        assert!(requests.set_certificate(&key("k-1"), "c-1").is_err());
        assert!(requests.remove(&key("k-1")).is_err());
        assert!(requests.of(&ilm(), "jdoe").is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
}

#[test]
fn a_certificate_is_kept_in_memory_when_the_file_cannot_be_written() {
    let dir = tempdir().unwrap();
    let requests = Requests::new(dir.path());
    requests.add(waiting("k-1")).unwrap();
    let path = dir.path().join("requests.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();

    assert!(requests.set_certificate(&key("k-1"), "c-1").is_err());

    assert_eq!(requests.all()[0].certificate.as_deref(), Some("c-1"));
}

#[test]
fn a_file_that_could_not_be_read_is_read_again_at_the_next_use() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("requests.json");
    std::fs::write(&path, "{").unwrap();
    let requests = Requests::new(dir.path());
    assert!(requests.add(waiting("k-1")).is_err());

    std::fs::remove_file(&path).unwrap();
    requests.add(waiting("k-2")).unwrap();

    assert_eq!(Requests::new(dir.path()).all(), [waiting("k-2")]);
}

#[test]
fn another_ilm_or_person_is_kept_and_not_listed() {
    let dir = tempdir().unwrap();
    let requests = Requests::new(dir.path());
    let mut elsewhere = waiting("k-2");
    elsewhere.ilm = IlmUrl::parse("other.example.com").unwrap();
    let mut someone = waiting("k-3");
    someone.username = "asmith".into();
    requests.add(elsewhere.clone()).unwrap();
    requests.add(someone.clone()).unwrap();
    requests.add(waiting("k-1")).unwrap();

    assert_eq!(requests.of(&ilm(), "jdoe"), [waiting("k-1")]);
    assert_eq!(
        Requests::new(dir.path()).all(),
        [elsewhere, someone, waiting("k-1")]
    );
}

#[test]
fn adding_a_key_again_replaces_its_request() {
    let dir = tempdir().unwrap();
    let requests = Requests::new(dir.path());
    requests.add(waiting("k-1")).unwrap();
    let mut again = waiting("k-1");
    again.label = "new".into();
    requests.add(again.clone()).unwrap();
    assert_eq!(requests.all(), [again]);
}

#[test]
fn the_certificate_is_set_for_its_key_only() {
    let dir = tempdir().unwrap();
    let requests = Requests::new(dir.path());
    requests.add(waiting("k-1")).unwrap();
    requests.add(waiting("k-2")).unwrap();
    requests.set_certificate(&key("k-2"), "c-2").unwrap();

    let mut second = waiting("k-2");
    second.certificate = Some("c-2".into());
    assert_eq!(Requests::new(dir.path()).all(), [waiting("k-1"), second]);
}

#[test]
fn a_request_is_removed_and_removing_an_absent_one_is_fine() {
    let dir = tempdir().unwrap();
    let requests = Requests::new(dir.path());
    requests.add(waiting("k-1")).unwrap();
    requests.remove(&key("k-1")).unwrap();
    requests.remove(&key("k-1")).unwrap();
    assert!(Requests::new(dir.path()).all().is_empty());
}

#[test]
fn a_failed_write_keeps_nothing_in_memory() {
    let dir = tempdir().unwrap();
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, "x").unwrap();
    let requests = Requests::new(&blocker);
    assert!(requests.add(waiting("k-1")).is_err());
    assert!(requests.all().is_empty());
}

#[cfg(unix)]
#[test]
fn the_file_is_for_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempdir().unwrap();
    Requests::new(dir.path()).add(waiting("k-1")).unwrap();
    let mode = std::fs::metadata(dir.path().join("requests.json"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}
