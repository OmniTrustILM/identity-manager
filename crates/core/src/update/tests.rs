use super::*;

fn at(text: &str) -> Timestamp {
    text.parse().unwrap()
}

#[test]
fn nothing_is_due_while_updates_are_off() {
    let now = at("2026-03-02T12:00:00Z");
    assert!(!due(now, None, false));
    assert!(!due(now, Some(at("2026-01-01T00:00:00Z")), false));
}

#[test]
fn a_check_is_due_when_none_was_made() {
    assert!(due(at("2026-03-02T12:00:00Z"), None, true));
}

#[test]
fn a_check_is_due_only_after_a_day() {
    let last = Some(at("2026-03-01T12:00:00Z"));
    assert!(!due(at("2026-03-02T11:59:59Z"), last, true));
    assert!(due(at("2026-03-02T12:00:00Z"), last, true));
    assert!(due(at("2026-03-02T12:00:01Z"), last, true));
}

#[test]
fn a_check_is_due_when_the_clock_moved_back() {
    assert!(due(
        at("2026-03-01T12:00:00Z"),
        Some(at("2026-03-02T12:00:00Z")),
        true
    ));
}

#[test]
fn only_a_later_version_is_newer() {
    assert!(!newer("0.1.0", "0.1.0"));
    assert!(!newer("0.2.0", "0.1.9"));
    assert!(newer("0.1.0", "0.1.1"));
    assert!(newer("0.9.0", "0.10.0"));
}

#[test]
fn pre_releases_follow_semver() {
    assert!(newer("0.1.0", "0.1.1-rc.1"));
    assert!(!newer("0.1.1", "0.1.1-rc.1"));
    assert!(newer("0.1.1-rc.1", "0.1.1"));
}

#[test]
fn build_metadata_does_not_make_a_version_newer() {
    assert!(!newer("0.1.0", "0.1.0+build.1"));
    assert!(!newer("0.1.0+build.2", "0.1.0+build.1"));
    assert!(newer("0.1.0+build.9", "0.1.1"));
}

#[test]
fn a_leading_v_on_the_offered_version_is_accepted() {
    assert!(newer("0.1.0", "v0.2.0"));
    assert!(!newer("0.2.0", "v0.2.0"));
}

#[test]
fn versions_that_do_not_parse_are_never_newer() {
    assert!(!newer("0.1.0", "latest"));
    assert!(!newer("0.1.0", ""));
    assert!(!newer("garbage", "0.2.0"));
    assert!(!newer("0.1.0", "vv0.2.0"));
}
