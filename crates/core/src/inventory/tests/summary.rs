use super::*;
use crate::inventory::summary::tests::local;

const DAY: i64 = 86_400_000;

fn in_days(count: i64) -> i64 {
    now() + count * DAY
}

fn days(days: i64) -> WarnDays {
    WarnDays::new(days).unwrap()
}

/// Two certificates ILM knows (one expiring in five days, one revoked) and one it does not.
fn here() -> Vec<LocalCertificate> {
    vec![
        local("soon", 1, in_days(5)),
        local("unknown", 2, in_days(300)),
        local("revoked", 3, in_days(300)),
    ]
}

async fn answering(setup: &Setup) {
    let soon = certificate("u-1", &print(1), true);
    let mut revoked = certificate("u-3", &print(3), true);
    revoked["state"] = json!("revoked");
    setup
        .ilm_answers(vec![soon.clone(), revoked.clone()], vec![soon, revoked])
        .await;
}

/// The items by name and kind; the real clock makes an expiry differ between runs, so it is shown as 0.
fn names(summary: &Summary) -> Vec<(&str, Kind)> {
    summary
        .attention
        .iter()
        .map(|item| match item.kind {
            Kind::Expiring { days, .. } => (item.name.as_str(), Kind::Expiring { days, on: 0 }),
            kind => (item.name.as_str(), kind),
        })
        .collect()
}

#[tokio::test]
async fn a_check_builds_the_summary_from_the_local_certificates_and_the_answer() {
    let setup = Setup::new().await;
    answering(&setup).await;
    assert!(
        setup.inventory.summary().is_none()
            || setup.inventory.summary().unwrap().checked_at.is_none()
    );

    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;

    let summary = setup.inventory.summary().unwrap();
    let checked_at = setup.inventory.snapshot().unwrap().checked_at;
    assert_eq!(summary.checked_at, Some(checked_at));
    assert!(summary.listed);
    assert_eq!(
        (
            summary.counts.valid,
            summary.counts.expiring,
            summary.counts.expired
        ),
        (1, 1, 0)
    );
    assert_eq!(summary.counts.not_in_ilm, Some(1));
    assert_eq!(
        names(&summary),
        [
            ("revoked", Kind::Revoked),
            ("soon", Kind::Expiring { days: 5, on: 0 }),
            ("", Kind::NotInIlm { count: 1 }),
        ]
    );
}

#[tokio::test]
async fn an_offline_check_builds_the_summary_again_from_the_cached_snapshot() {
    let mut setup = Setup::new().await;
    answering(&setup).await;
    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;
    let before = setup.inventory.summary().unwrap();

    setup.world.ilm = MockServer::start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut changed = here();
    changed.push(local("new", 4, in_days(2)));
    let status = setup
        .inventory
        .check_local(&setup.world.session, Trigger::Interval, &changed)
        .await;

    assert!(matches!(status, Status::Offline { .. }));
    let after = setup.inventory.summary().unwrap();
    assert_eq!(after.checked_at, before.checked_at);
    assert!(after.computed_at >= before.computed_at);
    assert_eq!(after.counts.expiring, 2);
    assert_eq!(after.counts.not_in_ilm, Some(1));
}

#[tokio::test]
async fn before_the_first_check_the_summary_is_from_the_store_and_the_cache() {
    let setup = Setup::new().await;
    answering(&setup).await;
    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;

    let restarted = Inventory::new(setup.folder.path());
    assert!(restarted.summary().is_none());
    restarted.adopt(&setup.world.session);
    restarted.set_local(&here());

    let summary = restarted.summary().unwrap();
    assert_eq!(
        summary.checked_at,
        setup.inventory.snapshot().map(|s| s.checked_at)
    );
    assert_eq!(summary.counts.not_in_ilm, Some(1));
    assert_eq!(names(&summary).len(), 3);
}

#[tokio::test]
async fn there_is_no_summary_until_the_certificates_on_this_computer_are_known() {
    let setup = Setup::new().await;
    let fresh = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(fresh.path());

    inventory.adopt(&setup.world.session);
    assert!(inventory.summary().is_none());

    inventory.set_local(&here());
    assert!(inventory.summary().is_some());
}

#[tokio::test]
async fn without_a_cache_nothing_is_said_about_ilm_before_the_first_check() {
    let setup = Setup::new().await;
    let fresh = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(fresh.path());

    inventory.adopt(&setup.world.session);
    inventory.set_local(&here());

    let summary = inventory.summary().unwrap();
    assert_eq!(summary.checked_at, None);
    assert_eq!(summary.counts.not_in_ilm, None);
    assert_eq!(
        names(&summary),
        [("soon", Kind::Expiring { days: 5, on: 0 })]
    );
}

#[tokio::test]
async fn a_change_of_the_warning_days_builds_the_summary_again_without_asking_ilm() {
    let setup = Setup::new().await;
    answering(&setup).await;
    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;
    let asked = setup.world.ilm.received_requests().await.unwrap().len();

    setup.inventory.configure(days(3));

    let summary = setup.inventory.summary().unwrap();
    assert_eq!(summary.counts.expiring, 0);
    assert_eq!(summary.counts.valid, 2);
    assert_eq!(names(&summary).len(), 2);
    setup.inventory.configure(days(90));
    assert_eq!(setup.inventory.summary().unwrap().counts.expiring, 1);
    assert_eq!(
        setup.world.ilm.received_requests().await.unwrap().len(),
        asked
    );
}

#[tokio::test]
async fn there_is_no_summary_while_nobody_is_signed_in_and_the_settings_stay() {
    let setup = Setup::new().await;
    answering(&setup).await;
    setup.inventory.configure(days(7));
    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;
    assert!(setup.inventory.summary().is_some());

    setup.world.session.sign_out().await;

    assert!(setup.inventory.summary().is_none());
    setup.inventory.set_local(&here());
    assert!(setup.inventory.summary().is_none());
    let kept = held(&setup.inventory.held);
    assert_eq!(kept.days, days(7));
}

#[tokio::test]
async fn the_log_of_a_summary_holds_counts_and_no_names() {
    capture_logs();
    let setup = Setup::new().await;
    answering(&setup).await;
    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;

    let log = LOG.lock().unwrap().join("\n");

    assert!(
        log.contains(
            "summary built: 1 valid, 1 expiring, 0 expired, 1 not in ILM, 2 need attention"
        )
    );
    for name in ["soon", "unknown", "revoked"] {
        assert!(!log.contains(&format!("{name}\"")), "{name} is logged");
    }
}

#[tokio::test]
async fn the_matched_fingerprints_are_the_local_certificates_ilm_knows_and_none_before_a_check() {
    let setup = Setup::new().await;
    answering(&setup).await;
    setup.inventory.set_local(&here());
    assert!(setup.inventory.matched_fingerprints().is_empty());

    setup
        .inventory
        .check_local(&setup.world.session, Trigger::Start, &here())
        .await;

    let mut matched = setup.inventory.matched_fingerprints();
    matched.sort();
    let mut expected = vec![print(1), print(3)];
    expected.sort();
    assert_eq!(matched, expected);
    assert_eq!(setup.inventory.local_fingerprints().len(), 3);
}
