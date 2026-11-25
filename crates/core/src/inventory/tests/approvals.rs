use super::*;
use crate::ilm::approvals::{ApprovalAction, Decision};
use crate::inventory::Approval;

const LIST: &str = "/api/v1/approvals/user";
const DETAIL: &str = "/api/v1/certificates/c-1";

fn waiting(uuid: &str, certificate: &str, creator: &str) -> Value {
    json!({
        "approvalUuid": uuid,
        "creatorUuid": "u-2",
        "creatorUsername": creator,
        "version": 1,
        "createdAt": "2026-11-25T10:00:00.000+00:00",
        "status": "PENDING",
        "resource": "certificates",
        "resourceAction": "issue",
        "objectUuid": certificate,
        "approvalProfileName": "Two eyes",
        "approvalProfileUuid": "p-1",
    })
}

impl Setup {
    async fn approvals(&self, items: Vec<Value>) {
        self.mock("GET", LIST)
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "approvals": items })))
            .mount(&self.world.ilm)
            .await;
    }

    async fn certificate(&self, name: &str) {
        self.detail(
            DETAIL,
            ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "c-1",
                "commonName": name,
                "raProfile": { "uuid": "ra-1", "name": "Servers" },
            })),
        )
        .await;
    }

    async fn decide(
        &self,
        uuid: &str,
        decision: Decision,
        comment: Option<&str>,
    ) -> Result<(), DecideError> {
        self.inventory
            .decide(&self.world.session, uuid, decision, comment, || true)
            .await
    }
}

/// The approval of the person who is signed in, as ILM lists it.
fn own(uuid: &str, certificate: &str) -> Value {
    let mut item = waiting(uuid, certificate, "jdoe");
    item["creatorUuid"] = json!("u-1");
    item
}

fn approvals_of(setup: &Setup) -> Vec<Approval> {
    setup.inventory.snapshot().unwrap().approvals
}

#[tokio::test]
async fn a_check_keeps_the_approvals_of_others_with_the_name_and_ra_profile_of_the_certificate() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .approvals(vec![waiting("a-1", "c-1", "ada"), own("a-2", "c-2")])
        .await;
    setup.certificate("demo220").await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert_eq!(
        approvals_of(&setup),
        [Approval {
            uuid: "a-1".to_owned(),
            action: ApprovalAction::Issue,
            requester: Some("ada".to_owned()),
            requested_at: 1_795_600_800_000,
            certificate_name: Some("demo220".to_owned()),
            ra_profile: Some("Servers".to_owned()),
        }]
    );
    assert_eq!(setup.inventory.approvals(), approvals_of(&setup));
}

#[tokio::test]
async fn an_approval_whose_certificate_the_person_may_not_read_is_kept_without_it() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .approvals(vec![
            waiting("a-1", "c-1", "ada"),
            waiting("a-2", "c-2", "ada"),
        ])
        .await;
    setup.detail(DETAIL, ResponseTemplate::new(403)).await;
    setup
        .detail("/api/v1/certificates/c-2", ResponseTemplate::new(404))
        .await;

    setup.check(&[]).await;

    let found = approvals_of(&setup);
    assert_eq!(found.len(), 2);
    assert!(
        found
            .iter()
            .all(|found| found.certificate_name.is_none() && found.ra_profile.is_none())
    );
}

#[tokio::test]
async fn approvals_are_read_also_when_the_person_may_not_list_certificates() {
    let setup = Setup::new().await;
    setup.profile(&[]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;

    setup.check(&[]).await;

    assert_eq!(approvals_of(&setup).len(), 1);
}

#[tokio::test]
async fn a_list_ilm_does_not_give_leaves_none_without_failing_the_check() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .mock("GET", LIST)
        .respond_with(ResponseTemplate::new(500))
        .mount(&setup.world.ilm)
        .await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert!(approvals_of(&setup).is_empty());
}

#[tokio::test]
async fn a_certificate_that_fails_to_read_does_not_fail_the_check() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.detail(DETAIL, ResponseTemplate::new(500)).await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    assert_eq!(approvals_of(&setup).len(), 1);
}

#[tokio::test]
async fn an_unauthorized_list_ends_the_check_as_a_sign_out() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .mock("GET", LIST)
        .respond_with(ResponseTemplate::new(401))
        .mount(&setup.world.ilm)
        .await;

    setup.check(&[]).await;

    assert!(setup.inventory.snapshot().is_none());
}

#[tokio::test]
async fn an_unauthorized_list_in_a_session_that_stays_signed_in_drops_the_approvals_and_goes_offline()
 {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    assert!(matches!(setup.check(&[]).await, Status::Fresh { .. }));
    assert_eq!(setup.inventory.approvals().len(), 1);
    setup
        .world
        .grant(
            "refresh_token",
            ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "renewed",
                "refresh_token": "refresh",
                "expires_in": 3600,
                "token_type": "Bearer",
            })),
            None,
        )
        .await;
    setup
        .mock("GET", LIST)
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&setup.world.ilm)
        .await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Offline { .. }));
    assert!(setup.world.session.signed_in_as().is_some());
    assert!(setup.inventory.approvals().is_empty());
}

#[tokio::test]
async fn the_cache_keeps_the_approvals_and_an_old_file_without_them_still_reads() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    let kept = setup.inventory.snapshot().unwrap();
    assert_eq!(kept.approvals.len(), 1);

    let restarted = Inventory::new(setup.folder.path());
    restarted.adopt(&setup.world.session);
    assert_eq!(restarted.snapshot().unwrap(), kept);
    assert!(restarted.approvals().is_empty());

    rewrite_cache(&setup, |written| {
        written.as_object_mut().unwrap().remove("approvals");
    })
    .await;
    let old = Inventory::new(setup.folder.path());
    old.adopt(&setup.world.session);
    assert_eq!(old.snapshot().unwrap().approvals, []);
}

#[tokio::test]
async fn a_decision_goes_to_ilm_and_the_approval_leaves_the_view_and_the_cache() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .approvals(vec![
            waiting("a-1", "c-1", "ada"),
            waiting("a-2", "c-1", "ada"),
        ])
        .await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/approveRecipient")
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&setup.world.ilm)
        .await;

    let done = setup.decide("a-1", Decision::Approve, Some("Fine.")).await;

    assert_eq!(done, Ok(()));
    let sent = setup
        .requests("PATCH", "/api/v1/approvals/a-1/approveRecipient")
        .await;
    assert_eq!(
        sent[0].body_json::<Value>().unwrap(),
        json!({ "comment": "Fine." })
    );
    let left: Vec<_> = approvals_of(&setup)
        .into_iter()
        .map(|found| found.uuid)
        .collect();
    assert_eq!(left, ["a-2"]);
    let restarted = Inventory::new(setup.folder.path());
    restarted.adopt(&setup.world.session);
    assert_eq!(restarted.snapshot().unwrap().approvals.len(), 1);
}

#[tokio::test]
async fn an_approval_that_no_longer_waits_leaves_too_and_says_so() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/rejectRecipient")
        .respond_with(ResponseTemplate::new(404))
        .mount(&setup.world.ilm)
        .await;

    let done = setup.decide("a-1", Decision::Reject, None).await;

    assert_eq!(done, Err(DecideError::NoLongerWaiting));
    assert!(approvals_of(&setup).is_empty());
}

#[tokio::test]
async fn a_refused_or_forbidden_decision_keeps_the_approval() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/approveRecipient")
        .respond_with(ResponseTemplate::new(422).set_body_json(json!(["Already decided."])))
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/rejectRecipient")
        .respond_with(ResponseTemplate::new(403))
        .mount(&setup.world.ilm)
        .await;

    assert_eq!(
        setup.decide("a-1", Decision::Approve, None).await,
        Err(DecideError::Refused(vec!["Already decided.".to_owned()]))
    );
    assert_eq!(
        setup.decide("a-1", Decision::Reject, None).await,
        Err(DecideError::NotAllowed)
    );
    assert_eq!(approvals_of(&setup).len(), 1);
}

#[tokio::test]
async fn the_summary_lists_the_approvals_of_a_fresh_check_without_attention() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    setup.inventory.set_local(&[]);

    setup.check(&[]).await;

    let summary = setup.inventory.summary().unwrap();
    assert_eq!(summary.needing_attention(), 0);
    assert!(summary.attention.iter().any(|item| {
        item.name == "demo220"
            && item.kind
                == Kind::Approval {
                    action: ApprovalAction::Issue,
                }
    }));
}

#[tokio::test]
async fn the_log_names_the_decision_and_holds_nothing_of_the_approval() {
    capture_logs();
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .approvals(vec![waiting("a-1", "c-1", "Unique-Creator-Q7")])
        .await;
    setup.certificate("Unique-Name-Q7").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/rejectRecipient")
        .respond_with(ResponseTemplate::new(204))
        .mount(&setup.world.ilm)
        .await;

    setup
        .decide("a-1", Decision::Reject, Some("Unique-Comment-Q7"))
        .await
        .unwrap();

    let log = LOG.lock().unwrap().join("\n");
    assert!(log.contains("approval decided: a-1 reject"), "{log}");
    assert!(log.contains("1 approvals"), "{log}");
    for private in ["Unique-Creator-Q7", "Unique-Name-Q7", "Unique-Comment-Q7"] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}

#[tokio::test]
async fn an_approval_of_the_person_is_left_out_by_uuid_when_ilm_names_no_creator() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    let mut item = own("a-1", "c-1");
    item["creatorUsername"] = json!(null);
    setup
        .approvals(vec![item, waiting("a-2", "c-1", "ada")])
        .await;
    setup.certificate("demo220").await;

    setup.check(&[]).await;

    let left: Vec<_> = approvals_of(&setup)
        .into_iter()
        .map(|found| found.uuid)
        .collect();
    assert_eq!(left, ["a-2"]);
}

#[tokio::test]
async fn a_decided_approval_does_not_come_back_from_a_later_check() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup
        .approvals(vec![
            waiting("a-1", "c-1", "ada"),
            waiting("a-2", "c-1", "ada"),
        ])
        .await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/approveRecipient")
        .respond_with(ResponseTemplate::new(204))
        .mount(&setup.world.ilm)
        .await;
    setup.decide("a-1", Decision::Approve, None).await.unwrap();

    setup.check(&[]).await;

    let left: Vec<_> = approvals_of(&setup)
        .into_iter()
        .map(|found| found.uuid)
        .collect();
    assert_eq!(left, ["a-2"]);
}

#[tokio::test]
async fn no_decision_is_sent_while_the_application_is_locked() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.approvals(vec![waiting("a-1", "c-1", "ada")]).await;
    setup.certificate("demo220").await;
    setup.check(&[]).await;
    setup
        .mock("PATCH", "/api/v1/approvals/a-1/approveRecipient")
        .respond_with(ResponseTemplate::new(204))
        .expect(0)
        .mount(&setup.world.ilm)
        .await;

    let done = setup
        .inventory
        .decide(&setup.world.session, "a-1", Decision::Approve, None, || {
            false
        })
        .await;

    assert_eq!(done, Err(DecideError::Failed(IlmError::Unreachable)));
    assert_eq!(approvals_of(&setup).len(), 1);
}
