use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use super::*;
use crate::ilm::certificates::search_text;
use crate::session::SessionView;
use crate::session::tests::{LOG, World, capture_logs};

const PROFILE: &str = "/api/v1/auth/profile";
const SEARCH: &str = "/api/v1/certificates";
const ALLOWED: &str = "/api/v1/resources/certificates/objects/allowed-actions";

fn print(number: u32) -> Fingerprint {
    Fingerprint::of(&number.to_be_bytes())
}

fn certificate(uuid: &str, fingerprint: &Fingerprint, managed: bool) -> Value {
    json!({
        "uuid": uuid,
        "commonName": format!("name of {uuid}"),
        "state": "issued",
        "validationStatus": "valid",
        "fingerprint": search_text(fingerprint),
        "raProfile": managed.then(|| json!({ "uuid": "ra-1", "name": "Servers" })),
    })
}

fn page(certificates: Vec<Value>, total: u64) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "certificates": certificates,
        "pageNumber": 1,
        "totalPages": 1,
        "totalItems": total,
    }))
}

fn profile(listings: &[&str]) -> Value {
    json!({
        "username": "jdoe",
        "firstName": "Jane",
        "lastName": "Doe",
        "email": "jane.doe@example.com",
        "certificate": { "uuid": "sign-in", "fingerprint": search_text(&print(99)) },
        "permissions": { "allowedListings": listings, "allowedActions": [] },
    })
}

/// Answers a question about allowed actions with `detail` for every certificate asked about.
fn everything_allowed(request: &Request) -> ResponseTemplate {
    let body: Value = request.body_json().unwrap();
    let items: Vec<Value> = body["uuids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|uuid| json!({ "uuid": uuid, "allowedActions": ["detail"] }))
        .collect();
    ResponseTemplate::new(200).set_body_json(json!({ "items": items }))
}

/// Answers a search for fingerprints with one managed certificate for each.
fn every_fingerprint_matches(request: &Request) -> ResponseTemplate {
    let body: Value = request.body_json().unwrap();
    let found: Vec<Value> = body["filters"][0]["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|print| {
            let print = print.as_str().unwrap();
            json!({
                "uuid": format!("u-{print}"),
                "commonName": "found",
                "state": "issued",
                "validationStatus": "valid",
                "fingerprint": print,
            })
        })
        .collect();
    let total = found.len() as u64;
    page(found, total)
}

struct Setup {
    world: World,
    inventory: Arc<Inventory>,
    folder: TempDir,
}

impl Setup {
    async fn new() -> Self {
        Self::with_refresh(Some("refresh")).await
    }

    async fn with_refresh(refresh: Option<&str>) -> Self {
        let world = World::new().await;
        world.code_grant("access", refresh, 3600).await;
        world.profile_for("access").await;
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        let folder = tempfile::tempdir().unwrap();
        let inventory = Arc::new(Inventory::new(folder.path()));
        inventory.attach(&world.session);
        Setup {
            world,
            inventory,
            folder,
        }
    }

    fn cache(&self) -> PathBuf {
        self.folder.path().join("ilm-cache.json")
    }

    async fn check(&self, local: &[Fingerprint]) -> Status {
        self.inventory
            .check(&self.world.session, Trigger::SyncNow, local)
            .await
    }

    fn mock(&self, verb: &str, tail: &str) -> wiremock::MockBuilder {
        Mock::given(method(verb)).and(path(tail))
    }

    async fn profile(&self, listings: &[&str]) {
        self.mock("GET", PROFILE)
            .respond_with(ResponseTemplate::new(200).set_body_json(profile(listings)))
            .with_priority(2)
            .mount(&self.world.ilm)
            .await;
    }

    /// The answers of an ILM that knows `found` as the match and lists `first` on its first page.
    async fn ilm_answers(&self, found: Vec<Value>, first: Vec<Value>) {
        self.profile(&["certificates"]).await;
        let matched = found.len() as u64;
        self.mock("POST", SEARCH)
            .and(body_string_contains("FINGERPRINT"))
            .respond_with(page(found, matched))
            .with_priority(2)
            .mount(&self.world.ilm)
            .await;
        let listed = first.len() as u64;
        self.mock("POST", SEARCH)
            .respond_with(page(first, listed))
            .mount(&self.world.ilm)
            .await;
        self.mock("POST", ALLOWED)
            .respond_with(everything_allowed)
            .mount(&self.world.ilm)
            .await;
    }

    async fn requests(&self, verb: &str, tail: &str) -> Vec<Request> {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|request| request.method.as_str() == verb && request.url.path() == tail)
            .collect()
    }
}

#[tokio::test]
async fn a_check_keeps_the_matches_the_first_page_and_the_allowed_actions() {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    let other = certificate("u-2", &print(7), false);
    setup
        .ilm_answers(vec![known.clone()], vec![known, other])
        .await;

    let status = setup.check(&[print(1), print(2)]).await;

    let snapshot = setup.inventory.snapshot().unwrap();
    assert_eq!(
        status,
        Status::Fresh {
            checked_at: snapshot.checked_at
        }
    );
    assert_eq!(status, setup.inventory.status());
    assert!(snapshot.listed);
    assert_eq!(snapshot.checked, [print(1), print(2)]);
    assert_eq!(snapshot.matches.len(), 1);
    assert_eq!(snapshot.matches[&print(1)].uuid, "u-1");
    assert!(snapshot.matches[&print(1)].ra_profile.is_some());
    assert_eq!(snapshot.sign_in.unwrap().uuid, "sign-in");
    let first = snapshot.first_page.unwrap();
    assert_eq!(first.total_items, 2);
    assert_eq!(first.certificates.len(), 2);
    let mut asked: Vec<_> = snapshot.allowed.keys().cloned().collect();
    asked.sort();
    assert_eq!(asked, ["u-1", "u-2"]);
    assert_eq!(snapshot.allowed["u-1"], ["detail"]);
    let search = setup.requests("POST", SEARCH).await;
    assert_eq!(search.len(), 2);
    let matching: Value = search[0].body_json().unwrap();
    assert_eq!(matching["filters"][0]["fieldIdentifier"], "FINGERPRINT");
    assert_eq!(matching["itemsPerPage"], 2);
    assert_eq!(setup.requests("POST", ALLOWED).await.len(), 1);
}

#[tokio::test]
async fn nothing_is_matched_without_local_certificates() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;

    setup.check(&[]).await;

    let snapshot = setup.inventory.snapshot().unwrap();
    assert!(snapshot.matches.is_empty());
    assert_eq!(snapshot.first_page.unwrap().total_items, 0);
    assert_eq!(setup.requests("POST", SEARCH).await.len(), 1);
    assert!(setup.requests("POST", ALLOWED).await.is_empty());
}

#[tokio::test]
async fn two_checks_at_once_ask_ilm_once() {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup
        .mock("GET", PROFILE)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(profile(&["certificates"]))
                .set_delay(Duration::from_millis(300)),
        )
        .with_priority(2)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(page(vec![known.clone()], 1))
        .with_priority(2)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", SEARCH)
        .respond_with(page(vec![known], 1))
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", ALLOWED)
        .respond_with(everything_allowed)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;

    let signed_in_reads = setup.requests("GET", PROFILE).await.len();
    let local = [print(1)];
    let (first, second) = tokio::join!(setup.check(&local), setup.check(&local));

    assert!(matches!(first, Status::Fresh { .. }));
    assert_eq!(first, second);
    assert_eq!(
        setup.requests("GET", PROFILE).await.len(),
        signed_in_reads + 1
    );
}

#[tokio::test]
async fn a_check_after_an_action_does_not_take_the_one_already_running() {
    let setup = Setup::new().await;
    setup
        .mock("GET", PROFILE)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(profile(&["certificates"]))
                .set_delay(Duration::from_millis(300)),
        )
        .with_priority(2)
        .mount(&setup.world.ilm)
        .await;
    setup.ilm_answers(vec![], vec![]).await;
    let reads = setup.requests("GET", PROFILE).await.len();

    let (first, second) = tokio::join!(setup.check(&[]), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        setup
            .inventory
            .check(&setup.world.session, Trigger::Action, &[])
            .await
    });

    assert!(matches!(first, Status::Fresh { .. }));
    assert!(matches!(second, Status::Fresh { .. }));
    assert_eq!(setup.requests("GET", PROFILE).await.len(), reads + 2);
}

#[tokio::test]
async fn checks_at_once_for_other_certificates_each_ask_ilm() {
    let setup = Setup::new().await;
    setup
        .mock("GET", PROFILE)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(profile(&["certificates"]))
                .set_delay(Duration::from_millis(300)),
        )
        .with_priority(2)
        .mount(&setup.world.ilm)
        .await;
    setup.ilm_answers(vec![], vec![]).await;
    let reads = setup.requests("GET", PROFILE).await.len();

    let (one, both) = ([print(1)], [print(1), print(2)]);
    let (_, second) = tokio::join!(setup.check(&one), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        setup.check(&both).await
    });

    assert!(matches!(second, Status::Fresh { .. }));
    assert_eq!(setup.requests("GET", PROFILE).await.len(), reads + 2);
    assert_eq!(
        setup.inventory.snapshot().unwrap().checked,
        [print(1), print(2)]
    );
}

#[tokio::test]
async fn what_ilm_returned_but_could_not_be_read_is_not_called_missing() {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup
        .ilm_answers(vec![known, json!({ "displayName": "no uuid" })], vec![])
        .await;

    setup.check(&[print(1), print(2)]).await;

    let snapshot = setup.inventory.snapshot().unwrap();
    assert_eq!(snapshot.checked, [print(1)]);
    assert_eq!(snapshot.matches.len(), 1);
}

#[tokio::test]
async fn every_page_of_the_fingerprint_search_is_read() {
    let setup = Setup::new().await;
    setup.profile(&["certificates"]).await;
    let archived = {
        let mut old = certificate("old", &print(1), false);
        old["archived"] = json!(true);
        old
    };
    let second_page = |found: Vec<Value>| {
        ResponseTemplate::new(200).set_body_json(json!({
            "certificates": found,
            "pageNumber": 2,
            "totalPages": 2,
            "totalItems": 2,
        }))
    };
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("\"pageNumber\":2"))
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(second_page(vec![certificate("live", &print(1), true)]))
        .with_priority(1)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "certificates": [archived],
            "pageNumber": 1,
            "totalPages": 2,
            "totalItems": 2,
        })))
        .with_priority(2)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", SEARCH)
        .respond_with(page(vec![], 0))
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", ALLOWED)
        .respond_with(everything_allowed)
        .mount(&setup.world.ilm)
        .await;

    setup.check(&[print(1)]).await;

    assert_eq!(
        setup.inventory.snapshot().unwrap().matches[&print(1)].uuid,
        "live"
    );
}

#[tokio::test]
async fn forgetting_also_deletes_a_half_written_cache() {
    let setup = Setup::new().await;
    let leftover = setup.folder.path().join("ilm-cache.json.tmp");
    std::fs::write(&leftover, "{").unwrap();

    setup.inventory.forget();

    assert!(!leftover.exists());
}

#[tokio::test]
async fn a_check_after_another_asks_again() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;

    setup.check(&[]).await;
    setup.check(&[]).await;

    assert_eq!(setup.requests("POST", SEARCH).await.len(), 2);
}

#[tokio::test]
async fn an_unreachable_ilm_keeps_the_snapshot_and_says_since_when() {
    let mut setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup.ilm_answers(vec![known.clone()], vec![known]).await;
    let Status::Fresh { checked_at } = setup.check(&[print(1)]).await else {
        panic!("the first check succeeds");
    };

    setup.world.ilm = MockServer::start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let status = setup.check(&[print(1)]).await;

    assert_eq!(
        status,
        Status::Offline {
            since: Some(checked_at),
            reason: UNREACHABLE.to_owned(),
            unreachable: true
        }
    );
    assert_eq!(setup.inventory.snapshot().unwrap().checked_at, checked_at);
    assert!(setup.cache().exists());
}

#[tokio::test]
async fn an_unreachable_ilm_without_a_snapshot_is_offline_since_never() {
    let mut setup = Setup::new().await;
    setup.world.ilm = MockServer::start().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let status = setup.check(&[print(1)]).await;

    assert_eq!(
        status,
        Status::Offline {
            since: None,
            reason: UNREACHABLE.to_owned(),
            unreachable: true
        }
    );
    assert!(setup.inventory.snapshot().is_none());
    assert!(!setup.cache().exists());
}

#[tokio::test]
async fn an_unexpected_answer_is_offline_with_its_reason_and_keeps_the_snapshot() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.check(&[]).await;
    let before = setup.inventory.snapshot().unwrap();
    setup
        .mock("POST", SEARCH)
        .respond_with(ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&setup.world.ilm)
        .await;

    let status = setup.check(&[print(1)]).await;

    assert_eq!(
        status,
        Status::Offline {
            since: Some(before.checked_at),
            reason: UNEXPECTED.to_owned(),
            unreachable: false
        }
    );
    assert_eq!(setup.inventory.snapshot().unwrap(), before);
}

#[tokio::test]
async fn signing_out_drops_the_snapshot_and_deletes_the_cache() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.check(&[]).await;
    assert!(setup.cache().exists());

    setup.world.session.sign_out().await;

    assert_eq!(setup.inventory.status(), Status::Never);
    assert!(setup.inventory.snapshot().is_none());
    assert!(!setup.cache().exists());
    assert_eq!(setup.check(&[]).await, Status::Never);
    assert!(!setup.cache().exists());
}

#[tokio::test]
async fn a_sign_in_that_ilm_ended_drops_the_snapshot_and_deletes_the_cache() {
    let setup = Setup::with_refresh(None).await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.check(&[]).await;
    assert!(setup.cache().exists());
    setup
        .mock("GET", PROFILE)
        .respond_with(ResponseTemplate::new(401))
        .with_priority(1)
        .mount(&setup.world.ilm)
        .await;

    let status = setup.check(&[]).await;

    assert_eq!(status, Status::Never);
    assert!(setup.inventory.snapshot().is_none());
    assert!(!setup.cache().exists());
    assert!(setup.world.session.signed_in_as().is_none());
}

#[tokio::test]
async fn a_sign_out_during_a_check_keeps_nothing() {
    let setup = Setup::new().await;
    setup
        .mock("GET", PROFILE)
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(profile(&["certificates"]))
                .set_delay(Duration::from_millis(300)),
        )
        .with_priority(2)
        .mount(&setup.world.ilm)
        .await;
    setup.ilm_answers(vec![], vec![]).await;

    let (_, signed_out) = tokio::join!(setup.check(&[]), async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        setup.world.session.sign_out().await
    });

    assert!(matches!(signed_out, SessionView::SignedOut { .. }));
    assert!(setup.inventory.snapshot().is_none());
    assert!(!setup.cache().exists());
}

#[tokio::test]
async fn without_the_listing_ilm_is_not_searched_but_the_profile_is_read() {
    let setup = Setup::new().await;
    setup.profile(&["keys"]).await;
    for tail in [SEARCH, ALLOWED] {
        setup
            .mock("POST", tail)
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&setup.world.ilm)
            .await;
    }

    let status = setup.check(&[print(1)]).await;

    assert!(matches!(status, Status::Fresh { .. }));
    let snapshot = setup.inventory.snapshot().unwrap();
    assert!(!snapshot.listed);
    assert!(snapshot.checked.is_empty());
    assert!(snapshot.matches.is_empty());
    assert!(snapshot.first_page.is_none());
    assert!(snapshot.allowed.is_empty());
    assert_eq!(snapshot.sign_in.unwrap().uuid, "sign-in");
}

#[tokio::test]
async fn a_live_page_needs_the_listing_and_is_not_kept() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    let session = &setup.world.session;
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("COMMON_NAME"))
        .and(body_string_contains("\"pageNumber\":3"))
        .respond_with(page(vec![certificate("u-9", &print(9), false)], 1))
        .with_priority(1)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;

    let found = setup.inventory.page(session, 3, Some("web")).await.unwrap();

    assert_eq!(found.certificates[0].uuid, "u-9");
    assert!(setup.inventory.snapshot().is_none());
    assert_eq!(setup.requests("POST", SEARCH).await.len(), 1);
}

#[tokio::test]
async fn a_page_follows_the_listing_of_the_latest_check_not_of_the_session() {
    let setup = Setup::new().await;
    setup.profile(&["keys"]).await;
    let session = &setup.world.session;
    session.check().await;
    let mut snapshot = empty_snapshot();
    snapshot.listed = true;
    setup.inventory.seed(snapshot);
    setup
        .mock("POST", SEARCH)
        .respond_with(page(vec![certificate("u-9", &print(9), false)], 1))
        .expect(1)
        .mount(&setup.world.ilm)
        .await;

    let found = setup.inventory.page(session, 1, None).await.unwrap();

    assert_eq!(found.certificates[0].uuid, "u-9");
}

#[tokio::test]
async fn a_page_is_refused_when_the_listing_is_missing() {
    let setup = Setup::new().await;
    // The profile of the sign-in lists certificates; a person without the listing gets none.
    let session = &setup.world.session;
    assert!(session.signed_in_as().unwrap().lists_certificates());
    setup.profile(&["keys"]).await;
    session.check().await;
    assert_eq!(
        setup.inventory.page(session, 1, None).await.unwrap_err(),
        Failure::NotAllowed
    );
}

async fn allowed_actions_answered_with(
    answer: ResponseTemplate,
) -> (Status, Option<Snapshot>, Setup) {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup.profile(&["certificates"]).await;
    setup
        .mock("POST", SEARCH)
        .respond_with(page(vec![known], 1))
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", ALLOWED)
        .respond_with(answer)
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    let status = setup.check(&[print(1)]).await;
    let snapshot = setup.inventory.snapshot();
    (status, snapshot, setup)
}

#[tokio::test]
async fn an_old_ilm_without_allowed_actions_does_not_fail_the_check() {
    for status in [404, 405] {
        let (status, snapshot, _setup) =
            allowed_actions_answered_with(ResponseTemplate::new(status)).await;
        let snapshot = snapshot.unwrap();
        assert!(matches!(status, Status::Fresh { .. }));
        assert!(snapshot.allowed.is_empty());
        assert_eq!(snapshot.matches.len(), 1);
    }
}

#[tokio::test]
async fn a_refused_allowed_actions_question_does_not_fail_the_check() {
    let (status, snapshot, _setup) =
        allowed_actions_answered_with(ResponseTemplate::new(422)).await;
    let snapshot = snapshot.unwrap();
    assert!(matches!(status, Status::Fresh { .. }));
    assert!(snapshot.allowed.is_empty());
    assert_eq!(snapshot.first_page.unwrap().certificates.len(), 1);
}

#[tokio::test]
async fn a_failing_or_unreadable_allowed_actions_answer_keeps_the_snapshot_without_actions() {
    let answers = [
        ResponseTemplate::new(403),
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string("not json"),
    ];
    for answer in answers {
        let (status, snapshot, _setup) = allowed_actions_answered_with(answer).await;
        let snapshot = snapshot.unwrap();
        assert!(matches!(status, Status::Fresh { .. }));
        assert!(snapshot.allowed.is_empty());
        assert_eq!(snapshot.matches.len(), 1);
        assert_eq!(snapshot.first_page.unwrap().certificates.len(), 1);
    }
}

#[tokio::test]
async fn more_than_a_thousand_fingerprints_are_asked_in_chunks() {
    let setup = Setup::new().await;
    setup.profile(&["certificates"]).await;
    setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(every_fingerprint_matches)
        .with_priority(2)
        .expect(2)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", SEARCH)
        .respond_with(page(vec![], 0))
        .expect(1)
        .mount(&setup.world.ilm)
        .await;
    setup
        .mock("POST", ALLOWED)
        .respond_with(everything_allowed)
        .expect(2)
        .mount(&setup.world.ilm)
        .await;
    let local: Vec<Fingerprint> = (0..1001).map(print).collect();

    setup.check(&local).await;

    let snapshot = setup.inventory.snapshot().unwrap();
    assert_eq!(snapshot.matches.len(), 1001);
    assert_eq!(snapshot.allowed.len(), 1001);
    let sizes: Vec<usize> = setup
        .requests("POST", ALLOWED)
        .await
        .iter()
        .map(|request| {
            request.body_json::<Value>().unwrap()["uuids"]
                .as_array()
                .unwrap()
                .len()
        })
        .collect();
    assert_eq!(sizes, [1000, 1]);
}

#[tokio::test]
async fn the_same_local_certificate_twice_is_asked_once() {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;

    setup.check(&[print(1), print(1)]).await;

    let search = setup.requests("POST", SEARCH).await;
    let matching: Value = search[0].body_json().unwrap();
    assert_eq!(matching["filters"][0]["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_archived_duplicate_does_not_replace_a_live_certificate() {
    let setup = Setup::new().await;
    let live = certificate("live", &print(1), true);
    let mut archived = certificate("old", &print(1), false);
    archived["archived"] = json!(true);
    setup
        .ilm_answers(vec![archived.clone(), live, archived], vec![])
        .await;

    setup.check(&[print(1)]).await;

    assert_eq!(
        setup.inventory.snapshot().unwrap().matches[&print(1)].uuid,
        "live"
    );
}

#[tokio::test]
async fn the_cache_is_written_after_a_check_and_holds_only_metadata() {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup.ilm_answers(vec![known.clone()], vec![known]).await;

    setup.check(&[print(1)]).await;

    let written: Value = serde_json::from_slice(&std::fs::read(setup.cache()).unwrap()).unwrap();
    let mut keys: Vec<_> = written.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "allowed",
            "checked",
            "checkedAt",
            "firstPage",
            "ilm",
            "listed",
            "matches",
            "signIn",
            "username",
            "version"
        ]
    );
    assert_eq!(written["version"], 1);
    assert_eq!(written["username"], "jdoe");
    assert_eq!(written["ilm"], setup.world.ilm.uri());
    assert!(written["matches"][print(1).to_string()].is_object());
    let text = written.to_string();
    assert!(!text.contains("access"));
    assert!(!text.contains("jane.doe@example.com"));
}

#[tokio::test]
async fn a_restart_takes_the_cache_and_shows_it_offline_until_a_check_succeeds() {
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup.ilm_answers(vec![known.clone()], vec![known]).await;
    setup.check(&[print(1)]).await;
    let kept = setup.inventory.snapshot().unwrap();

    let restarted = Arc::new(Inventory::new(setup.folder.path()));
    assert_eq!(restarted.status(), Status::Never);
    restarted.adopt(&setup.world.session);

    assert_eq!(restarted.snapshot().unwrap(), kept);
    assert_eq!(
        restarted.status(),
        Status::Offline {
            since: Some(kept.checked_at),
            reason: NOT_CHECKED_YET.to_owned(),
            unreachable: false
        }
    );
    let status = restarted
        .check(&setup.world.session, Trigger::Start, &[print(1)])
        .await;
    assert!(matches!(status, Status::Fresh { .. }));
}

type Edit = fn(&mut Value);

async fn rewrite_cache(setup: &Setup, change: impl FnOnce(&mut Value)) {
    let mut written: Value =
        serde_json::from_slice(&std::fs::read(setup.cache()).unwrap()).unwrap();
    change(&mut written);
    std::fs::write(setup.cache(), written.to_string()).unwrap();
}

async fn cached() -> Setup {
    let setup = Setup::new().await;
    setup.ilm_answers(vec![], vec![]).await;
    setup.check(&[]).await;
    setup
}

#[tokio::test]
async fn the_cache_of_another_user_or_address_is_deleted() {
    for (key, value) in [
        ("username", "someone-else"),
        ("ilm", "https://other.example.com"),
    ] {
        let setup = cached().await;
        rewrite_cache(&setup, |written| written[key] = json!(value)).await;

        let restarted = Inventory::new(setup.folder.path());
        restarted.adopt(&setup.world.session);

        assert!(restarted.snapshot().is_none(), "{key}");
        assert_eq!(restarted.status(), Status::Never);
        assert!(!setup.cache().exists(), "{key}");
    }
}

#[tokio::test]
async fn a_broken_or_unknown_cache_is_deleted() {
    let broken: [(&str, Edit); 3] = [
        ("version", |written| written["version"] = json!(2)),
        ("shape", |written| written["matches"] = json!("no")),
        ("missing", |written| {
            written.as_object_mut().unwrap().remove("checkedAt");
        }),
    ];
    for (name, change) in broken {
        let setup = cached().await;
        rewrite_cache(&setup, change).await;
        let restarted = Inventory::new(setup.folder.path());
        restarted.adopt(&setup.world.session);
        assert!(restarted.snapshot().is_none(), "{name}");
        assert!(!setup.cache().exists(), "{name}");
    }
    for content in ["{ not json", "", "[1]"] {
        let setup = cached().await;
        std::fs::write(setup.cache(), content).unwrap();
        let restarted = Inventory::new(setup.folder.path());
        restarted.adopt(&setup.world.session);
        assert!(restarted.snapshot().is_none(), "{content:?}");
        assert!(!setup.cache().exists(), "{content:?}");
    }
}

#[tokio::test]
async fn an_unreadable_cache_is_not_a_problem() {
    let setup = Setup::new().await;
    std::fs::create_dir(setup.cache()).unwrap();
    setup.ilm_answers(vec![], vec![]).await;

    let status = setup.check(&[]).await;

    assert!(matches!(status, Status::Fresh { .. }));
}

fn empty_snapshot() -> Snapshot {
    Snapshot {
        checked_at: 1_000,
        listed: true,
        checked: Vec::new(),
        matches: HashMap::new(),
        sign_in: None,
        first_page: None,
        allowed: HashMap::new(),
    }
}

/// A world whose saved sign-in cannot be renewed, with a cache of `username` at `address` in a folder.
async fn unreachable_with_cache(
    address: Option<&str>,
    username: &str,
) -> (World, TempDir, Inventory) {
    let world = World::at_address().await;
    world.put_item("r1");
    world
        .grant("refresh_token", ResponseTemplate::new(503), None)
        .await;
    let folder = tempfile::tempdir().unwrap();
    let ilm = address.map_or_else(|| world.address(), IlmUrl::for_tests);
    cache::write(
        &folder.path().join(cache::FILE),
        &ilm,
        username,
        &empty_snapshot(),
    )
    .unwrap();
    assert!(matches!(
        world.session.start().await,
        SessionView::Unreachable { .. }
    ));
    let inventory = Inventory::new(folder.path());
    (world, folder, inventory)
}

#[tokio::test]
async fn an_unreachable_start_takes_the_cache_of_its_address_and_shows_it_offline() {
    let (world, _folder, inventory) = unreachable_with_cache(None, "jdoe").await;

    inventory.adopt(&world.session);

    assert_eq!(inventory.snapshot().unwrap(), empty_snapshot());
    assert_eq!(
        inventory.status(),
        Status::Offline {
            since: Some(1_000),
            reason: UNREACHABLE.to_owned(),
            unreachable: true
        }
    );
}

#[tokio::test]
async fn a_live_page_while_unreachable_says_so() {
    let (world, _folder, inventory) = unreachable_with_cache(None, "jdoe").await;

    let result = inventory.page(&world.session, 1, None).await;

    assert_eq!(result.unwrap_err(), Failure::Unreachable);
}

#[tokio::test]
async fn an_unreachable_start_deletes_the_cache_of_another_address() {
    let (world, folder, inventory) =
        unreachable_with_cache(Some("https://other.example.com"), "jdoe").await;

    inventory.adopt(&world.session);

    assert!(inventory.snapshot().is_none());
    assert_eq!(inventory.status(), Status::Never);
    assert!(!folder.path().join(cache::FILE).exists());
}

#[tokio::test]
async fn a_sign_in_of_another_username_drops_the_cache_taken_while_unreachable() {
    let (world, _folder, inventory) = unreachable_with_cache(None, "someone-else").await;
    inventory.adopt(&world.session);
    assert!(inventory.snapshot().is_some());
    world.code_grant("access", None, 3600).await;
    world.profile_for("access").await;
    world.sign_in().await;

    inventory.adopt(&world.session);

    assert!(inventory.snapshot().is_none());
    assert_eq!(inventory.status(), Status::Never);
}

#[tokio::test]
async fn adopting_without_a_sign_in_or_a_cache_does_nothing() {
    let world = World::new().await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());

    inventory.adopt(&world.session);
    assert_eq!(inventory.status(), Status::Never);

    world.code_grant("access", None, 3600).await;
    world.profile_for("access").await;
    world.sign_in().await;
    inventory.adopt(&world.session);
    assert_eq!(inventory.status(), Status::Never);
}

#[tokio::test]
async fn a_check_while_signed_out_asks_nothing() {
    let world = World::new().await;
    let folder = tempfile::tempdir().unwrap();
    let inventory = Inventory::new(folder.path());

    let status = inventory
        .check(&world.session, Trigger::Interval, &[print(1)])
        .await;

    assert_eq!(status, Status::Never);
    assert!(world.ilm.received_requests().await.unwrap().is_empty());
}

#[test]
fn the_status_has_the_shape_the_interface_reads() {
    assert_eq!(
        serde_json::to_value(Status::Never).unwrap(),
        json!({ "state": "never" })
    );
    assert_eq!(
        serde_json::to_value(Status::Fresh { checked_at: 5 }).unwrap(),
        json!({ "state": "fresh", "checkedAt": 5 })
    );
    assert_eq!(
        serde_json::to_value(Status::Offline {
            since: None,
            reason: "x".into(),
            unreachable: false
        })
        .unwrap(),
        json!({ "state": "offline", "since": null, "reason": "x", "unreachable": false })
    );
}

#[test]
fn failures_and_triggers_say_what_happened() {
    assert_eq!(Failure::from(CallError::SignedOut), Failure::SignedOut);
    assert_eq!(Failure::from(CallError::Unreachable), Failure::Unreachable);
    assert_eq!(Failure::from(IlmError::Unreachable), Failure::Unreachable);
    for failure in [
        Failure::SignedOut,
        Failure::NotAllowed,
        Failure::Unreachable,
        Failure::Ilm(IlmError::Malformed),
    ] {
        assert!(!failure.to_string().is_empty());
    }
    for trigger in [
        Trigger::Start,
        Trigger::Interval,
        Trigger::SyncNow,
        Trigger::Action,
    ] {
        assert!(!trigger.to_string().is_empty());
    }
}

#[tokio::test]
async fn the_log_of_a_check_holds_no_name_email_or_search_text() {
    capture_logs();
    let setup = Setup::new().await;
    let known = certificate("u-1", &print(1), true);
    setup.ilm_answers(vec![known.clone()], vec![known]).await;
    setup.check(&[print(1)]).await;
    setup.world.session.sign_out().await;

    let log = LOG.lock().unwrap().join("\n");

    assert!(log.contains("checking ILM (sync now)"));
    assert!(log.contains("checked ILM: 1 on this computer, 1 matched"));
    assert!(log.contains("the ILM cache is written"));
    assert!(log.contains("the ILM cache is deleted"));
    for (index, secret) in [
        "jane.doe@example.com",
        "Jane",
        "name of u-1",
        &search_text(&print(1)),
    ]
    .iter()
    .enumerate()
    {
        assert!(!log.contains(secret), "forbidden value {index} is logged");
    }
}
