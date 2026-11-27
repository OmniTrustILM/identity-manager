//! Renewal at each check: what is renewed, what is told, and what the screens show.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, OtherNameValue, SanType};

use super::*;
use crate::app_info::Platform;
use crate::identity::certificate::{KeyLocation, describe};
use crate::install::RecordingInstaller;
use crate::keys::testing::InMemoryStorage;
use crate::keys::{KeyType, Offer, Storage};
use crate::renewal::store::Renewals;
use crate::requests::Requests;
use crate::settings::{AutomaticRenewal, Layer};

const DAY: Duration = Duration::from_secs(86_400);
const OPERATIONS: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/certificates";

struct Auto {
    setup: Setup,
    renewals: Arc<Renewals>,
    requests: Arc<Requests>,
    _renewals_folder: tempfile::TempDir,
    old: LocalCertificate,
    der: Vec<u8>,
    /// Counts down so that the latest detail served wins.
    priority: AtomicU8,
}

fn plan(renewals: &Arc<Renewals>, platform: Platform) -> Renewing {
    Renewing {
        platform,
        policy: Layer::default(),
        person: Layer::default(),
        offers: vec![Offer {
            storage: Storage::Software,
            types: vec![KeyType::EcP256],
        }],
        switches: renewals.clone(),
    }
}

impl Auto {
    /// A certificate of this computer that expires in `days`, which ILM lets the person do `actions` with.
    async fn expiring_in(days: u64, actions: &[&str]) -> Self {
        let mut world = World::new().await;
        let renewals_folder = tempfile::tempdir().unwrap();
        let renewals = Arc::new(Renewals::new(renewals_folder.path()));
        let requests = Arc::new(Requests::new(renewals_folder.path()));
        world.session = world
            .session
            .with_key_storage(Arc::new(InMemoryStorage::new(&[Storage::Software])))
            .with_installer(Arc::new(RecordingInstaller::new()))
            .with_requests(requests.clone())
            .with_renewals(renewals.clone());
        world.code_grant("access", Some("refresh"), 3600).await;
        world.profile_for("access").await;
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        let folder = tempfile::tempdir().unwrap();
        let inventory = Arc::new(Inventory::new(folder.path()));
        inventory.attach(&world.session);
        inventory.configure(WarnDays::new(30).unwrap());
        let setup = Setup {
            world,
            inventory,
            folder,
        };
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "web.example.com");
        let der = params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec();
        let mut old = describe(&der, KeyLocation::Software, SystemTime::now()).unwrap();
        old.not_after = SystemTime::now() + DAY * days as u32;
        let found = certificate("c-old", &old.fingerprint, true);
        setup.ilm_answers(vec![found.clone()], vec![found]).await;
        let allowed: Vec<String> = actions.iter().map(|action| (*action).to_owned()).collect();
        setup
            .mock("POST", ALLOWED)
            .respond_with(move |request: &Request| {
                let body: Value = request.body_json().unwrap();
                let items: Vec<Value> = body["uuids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|uuid| json!({ "uuid": uuid, "allowedActions": allowed }))
                    .collect();
                ResponseTemplate::new(200).set_body_json(json!({ "items": items }))
            })
            .with_priority(1)
            .mount(&setup.world.ilm)
            .await;
        let auto = Auto {
            setup,
            renewals,
            requests,
            _renewals_folder: renewals_folder,
            old,
            der,
            priority: AtomicU8::new(200),
        };
        auto.serve_detail(json!([]), Value::Null).await;
        auto
    }

    /// Serves the detail of the old certificate with `related` and `renewal_info`.
    async fn serve_detail(&self, related: Value, renewal_info: Value) {
        let mut detail = json!({
            "state": "issued",
            "certificateContent": STANDARD.encode(&self.der),
            "raProfile": { "uuid": "ra-1", "name": "Servers", "authorityInstanceUuid": "auth-1" },
            "relatedCertificates": related,
        });
        if !renewal_info.is_null() {
            detail["renewalInfo"] = renewal_info;
        }
        self.setup
            .mock("GET", "/api/v1/certificates/c-old")
            .respond_with(ResponseTemplate::new(200).set_body_json(detail))
            .with_priority(self.priority.fetch_sub(1, Ordering::SeqCst))
            .mount(&self.setup.world.ilm)
            .await;
    }

    async fn accepts(&self, verb: &str) {
        self.setup
            .mock("POST", &format!("{OPERATIONS}/c-old/{verb}"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-new" })))
            .mount(&self.setup.world.ilm)
            .await;
    }

    /// One check of ILM followed by the renewal of what is due.
    async fn check(&self, plan: &Renewing) {
        self.setup
            .inventory
            .check_local(
                &self.setup.world.session,
                Trigger::Interval,
                std::slice::from_ref(&self.old),
            )
            .await;
        self.setup
            .inventory
            .renew_due(&self.setup.world.session, plan, &|| true)
            .await;
    }

    async fn sent(&self, verb: &str) -> usize {
        self.setup
            .requests("POST", &format!("{OPERATIONS}/c-old/{verb}"))
            .await
            .len()
    }

    fn ilm(&self) -> IlmUrl {
        self.setup.world.address()
    }
}

#[tokio::test]
async fn a_certificate_that_is_due_is_renewed_once_with_a_new_key() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);

    auto.check(&plan).await;
    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 1);
    assert_eq!(auto.sent("renew").await, 0);
    let waiting = auto.setup.world.session.waiting_requests();
    assert_eq!(waiting.len(), 1);
    assert!(waiting[0].renews() == Some("c-old"));
}

#[tokio::test]
async fn a_renewal_sent_at_a_check_is_followed_at_once() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    auto.setup
        .mock("GET", "/api/v1/certificates/c-new")
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "state": "pending_approval" })),
        )
        .mount(&auto.setup.world.ilm)
        .await;

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    let followed = auto.setup.inventory.followed();
    assert_eq!(followed.len(), 1);
    assert_eq!(
        followed[0].outcome,
        crate::session::Outcome::Waiting(State::PendingApproval)
    );
}

#[tokio::test]
async fn nothing_is_renewed_when_the_batch_is_not_to_go_on() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);
    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;

    auto.setup
        .inventory
        .renew_due(&auto.setup.world.session, &plan, &|| false)
        .await;

    assert_eq!(auto.sent("rekey").await, 0);
}

#[tokio::test]
async fn nothing_is_renewed_when_the_sign_in_ended_after_the_check() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);
    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;
    let inventory = auto.setup.inventory.clone();

    auto.setup
        .inventory
        .renew_due(&auto.setup.world.session, &plan, &move || {
            inventory.forget();
            true
        })
        .await;

    assert_eq!(auto.sent("rekey").await, 0);
}

fn failed_renewal(uuid: &str, replaces: Fingerprint) -> Followed {
    Followed {
        uuid: Some(uuid.to_owned()),
        label: "web".to_owned(),
        outcome: crate::session::Outcome::Ended(crate::session::EndReason::Failed),
        replaces: Some(replaces),
    }
}

fn installed_renewal(uuid: &str, replaces: Fingerprint) -> Followed {
    installed_as(uuid, replaces, Fingerprint::of(b"successor"))
}

fn installed_as(uuid: &str, replaces: Fingerprint, installed: Fingerprint) -> Followed {
    Followed {
        uuid: Some(uuid.to_owned()),
        label: "web".to_owned(),
        outcome: crate::session::Outcome::Installed(crate::session::Installed {
            fingerprint: installed,
            storage: None,
            not_after: 0,
        }),
        replaces: Some(replaces),
    }
}

#[tokio::test]
async fn a_failed_renewal_is_not_kept_once_a_later_one_of_the_certificate_is_installed() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let other = Fingerprint::of(b"another certificate");
    held(&auto.setup.inventory.held).followed = vec![
        failed_renewal("c-a", auto.old.fingerprint),
        failed_renewal("c-x", other),
        installed_renewal("c-b", auto.old.fingerprint),
    ];

    let (_, changed) = auto.setup.inventory.follow(&auto.setup.world.session).await;

    assert!(changed);
    assert_eq!(
        auto.setup.inventory.followed(),
        vec![
            failed_renewal("c-x", other),
            installed_renewal("c-b", auto.old.fingerprint)
        ]
    );
}

#[tokio::test]
async fn a_failed_renewal_of_a_certificate_no_longer_here_is_not_given_out() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let removed = Fingerprint::of(b"removed certificate");
    held(&auto.setup.inventory.held).followed = vec![
        failed_renewal("c-a", auto.old.fingerprint),
        failed_renewal("c-x", removed),
        installed_renewal("c-b", removed),
    ];

    assert_eq!(auto.setup.inventory.followed().len(), 3);
    auto.setup
        .inventory
        .set_local(std::slice::from_ref(&auto.old));

    assert_eq!(
        auto.setup.inventory.followed(),
        vec![
            failed_renewal("c-a", auto.old.fingerprint),
            installed_renewal("c-b", removed)
        ]
    );
}

#[tokio::test]
async fn an_install_that_is_not_on_this_computer_yet_is_told() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let new_print = Fingerprint::of(b"successor");
    held(&auto.setup.inventory.held).followed =
        vec![installed_as("c-b", auto.old.fingerprint, new_print)];
    assert!(!auto.setup.inventory.installed_elsewhere());
    auto.setup
        .inventory
        .set_local(std::slice::from_ref(&auto.old));

    assert!(auto.setup.inventory.installed_elsewhere());

    let mut here = auto.old.clone();
    here.fingerprint = new_print;
    auto.setup.inventory.set_local(&[auto.old.clone(), here]);
    assert!(!auto.setup.inventory.installed_elsewhere());
}

#[tokio::test]
async fn a_renewal_whose_sign_in_has_not_moved_over_yet_counts_as_installed_elsewhere() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let mut pending = installed_as("c-b", auto.old.fingerprint, Fingerprint::of(b"successor"));
    pending.outcome = crate::session::Outcome::SwitchPending { failures: 1 };
    held(&auto.setup.inventory.held).followed = vec![pending];
    auto.setup
        .inventory
        .set_local(std::slice::from_ref(&auto.old));

    assert!(auto.setup.inventory.installed_elsewhere());
}

#[tokio::test]
async fn a_refusal_is_not_kept_once_a_renewal_of_the_certificate_is_installed() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let other = Fingerprint::of(b"another certificate");
    let refusal = |fingerprint| Refused {
        fingerprint,
        name: "web".to_owned(),
        message: "refused".to_owned(),
    };
    {
        let mut kept = held(&auto.setup.inventory.held);
        kept.followed = vec![installed_renewal("c-b", auto.old.fingerprint)];
        kept.refused = vec![refusal(auto.old.fingerprint), refusal(other)];
    }

    let (_, changed) = auto.setup.inventory.follow(&auto.setup.world.session).await;

    assert!(changed);
    let refused = auto.setup.inventory.renewal_refused();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].fingerprint, other);
}

#[tokio::test]
async fn the_setting_same_key_renews_with_the_stored_request() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("renew").await;
    let mut plan = plan(&auto.renewals, Platform::Macos);
    plan.person.automatic_renewal = Some(AutomaticRenewal::SameKey);

    auto.check(&plan).await;

    assert_eq!(auto.sent("renew").await, 1);
    assert_eq!(auto.sent("rekey").await, 0);
}

#[tokio::test]
async fn a_certificate_that_is_not_due_is_left_alone() {
    let auto = Auto::expiring_in(90, &["detail", "renew"]).await;
    auto.accepts("rekey").await;

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    assert_eq!(auto.sent("rekey").await, 0);
}

#[tokio::test]
async fn ilms_window_makes_a_certificate_due_before_the_warning_days() {
    let auto = Auto::expiring_in(90, &["detail", "renew"]).await;
    auto.serve_detail(json!([]), json!({ "windowStart": 1_000, "due": true }))
        .await;
    auto.accepts("rekey").await;

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    assert_eq!(auto.sent("rekey").await, 1);
}

#[tokio::test]
async fn a_certificate_switched_off_is_not_renewed() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    auto.renewals
        .set_off(&auto.ilm(), "jdoe", &auto.old.fingerprint, true)
        .unwrap();

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    assert_eq!(auto.sent("rekey").await, 0);
}

#[tokio::test]
async fn policy_turning_renewal_off_stops_every_renewal() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    let mut plan = plan(&auto.renewals, Platform::Macos);
    plan.policy.automatic_renewal = Some(AutomaticRenewal::Off);

    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 0);
    assert!(auto.setup.inventory.renewal_sign_in(&plan).is_empty());
}

#[tokio::test]
async fn a_certificate_ilm_does_not_let_the_person_renew_is_not_renewed_and_is_told_once() {
    let auto = Auto::expiring_in(10, &["detail"]).await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);

    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 0);
    let needs = auto.setup.inventory.renewal_needs(&plan, &[]);
    assert_eq!(needs.len(), 1);
    assert_eq!(needs[0].reason, Reason::NotAllowed);
    assert_eq!(
        needs[0].key(),
        format!("renewal:needs:{}", auto.old.fingerprint)
    );
    let view = &auto.setup.inventory.renewal_views(&plan, &[]);
    assert!(view.is_empty());
}

#[tokio::test]
async fn a_recent_failure_holds_the_next_attempt_back() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;
    auto.renewals
        .record_failure(
            &auto.ilm(),
            "jdoe",
            &auto.old.fingerprint,
            SystemTime::now() - Duration::from_secs(3600),
        )
        .unwrap();

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    assert_eq!(auto.sent("rekey").await, 0);
}

#[tokio::test]
async fn a_certificate_whose_revocation_waits_is_not_renewed_and_offers_no_renewal() {
    let auto = Auto::expiring_in(10, &["detail", "renew", "revoke"]).await;
    let mut revocation = auto.revocation();
    revocation.since = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    auto.requests.add(revocation.clone()).unwrap();
    auto.accepts("rekey").await;
    auto.accepts("renew").await;
    let plan = plan(&auto.renewals, Platform::Macos);

    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 0);
    assert_eq!(auto.sent("renew").await, 0);
    let view = &auto.setup.inventory.renewal_views(&plan, &[revocation])
        [&auto.old.fingerprint.to_string()];
    assert!(!view.renewable);
    assert_eq!(view.revoking, Some(RevokingStage::BeingRevoked));
}

#[tokio::test]
async fn a_certificate_with_a_successor_on_its_way_is_not_renewed_again() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.serve_detail(
        json!([{ "uuid": "c-next", "state": "pending_issue", "relationType": "renewal" }]),
        Value::Null,
    )
    .await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);

    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 0);
    assert!(
        auto.setup.inventory.renewal_views(&plan, &[])[&auto.old.fingerprint.to_string()].waiting
    );
}

#[tokio::test]
async fn a_replaced_certificate_is_not_renewed_and_shows_when_it_was_replaced() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let new_print = Fingerprint::of(b"successor");
    let mut successor = certificate("c-new", &new_print, true);
    successor["notBefore"] = json!(1_700_000_000_000i64);
    auto.setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(page(
            vec![certificate("c-old", &auto.old.fingerprint, true), successor],
            2,
        ))
        .with_priority(1)
        .mount(&auto.setup.world.ilm)
        .await;
    auto.serve_detail(
        json!([{ "uuid": "c-new", "state": "issued", "relationType": "renewal" }]),
        Value::Null,
    )
    .await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Macos);
    let mut successor_local = auto.old.clone();
    successor_local.fingerprint = new_print;
    successor_local.not_after = SystemTime::now() + DAY * 300;

    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            &[auto.old.clone(), successor_local],
        )
        .await;
    auto.setup
        .inventory
        .renew_due(&auto.setup.world.session, &plan, &|| true)
        .await;

    assert_eq!(auto.sent("rekey").await, 0);
    let views = auto.setup.inventory.renewal_views(&plan, &[]);
    let old = &views[&auto.old.fingerprint.to_string()];
    assert!(old.replaced && !old.renewable);
    assert_eq!(old.replaced_on, Some(1_700_000_000_000));
    assert_eq!(old.replaced_by, Some(new_print.to_string()));
    assert!(auto.setup.inventory.renewal_sign_in(&plan).is_empty());
}

#[tokio::test]
async fn a_certificate_installed_after_a_check_replaces_the_old_one_at_the_check_after_the_install()
{
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let new_print = Fingerprint::of(b"successor");
    auto.setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(page(
            vec![
                certificate("c-old", &auto.old.fingerprint, true),
                certificate("c-new", &new_print, true),
            ],
            2,
        ))
        .with_priority(1)
        .mount(&auto.setup.world.ilm)
        .await;
    auto.serve_detail(
        json!([{ "uuid": "c-new", "state": "issued", "relationType": "renewal" }]),
        Value::Null,
    )
    .await;
    let plan = plan(&auto.renewals, Platform::Macos);
    let key = auto.old.fingerprint.to_string();
    let session = &auto.setup.world.session;
    auto.setup
        .inventory
        .check_local(session, Trigger::Interval, std::slice::from_ref(&auto.old))
        .await;
    assert!(!auto.setup.inventory.renewal_views(&plan, &[])[&key].replaced);
    let mut successor = auto.old.clone();
    successor.fingerprint = new_print;
    successor.not_after = SystemTime::now() + DAY * 300;

    auto.setup
        .inventory
        .check_local(session, Trigger::Action, &[auto.old.clone(), successor])
        .await;

    assert!(auto.setup.inventory.renewal_views(&plan, &[])[&key].replaced);
}

#[tokio::test]
async fn nothing_is_renewed_or_shown_where_the_system_has_no_installer() {
    let auto = Auto::expiring_in(10, &["detail", "renew", "revoke"]).await;
    auto.accepts("rekey").await;
    let plan = plan(&auto.renewals, Platform::Linux);

    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 0);
    assert!(auto.setup.inventory.renewal_views(&plan, &[]).is_empty());
    assert!(auto.setup.inventory.renewal_needs(&plan, &[]).is_empty());
    assert!(auto.setup.inventory.renewal_sign_in(&plan).is_empty());
}

#[tokio::test]
async fn a_renewal_ilm_refuses_is_kept_for_the_person_and_not_tried_again_at_once() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.setup
        .mock("POST", &format!("{OPERATIONS}/c-old/rekey"))
        .respond_with(ResponseTemplate::new(422).set_body_json(json!(["Unique-Refusal-Z9"])))
        .mount(&auto.setup.world.ilm)
        .await;
    let plan = plan(&auto.renewals, Platform::Macos);

    auto.check(&plan).await;
    auto.check(&plan).await;

    assert_eq!(auto.sent("rekey").await, 1);
    let refused = auto.setup.inventory.renewal_refused();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].message, "Unique-Refusal-Z9");
    assert_eq!(
        refused[0].key(),
        format!("renewal:failed:{}", auto.old.fingerprint)
    );
}

#[tokio::test]
async fn the_screens_are_told_what_renewal_does_for_a_certificate() {
    let auto = Auto::expiring_in(10, &["detail", "renew", "revoke"]).await;
    auto.serve_detail(json!([]), json!({ "windowStart": 1_700_000_000_000i64 }))
        .await;
    let mut plan = plan(&auto.renewals, Platform::Macos);

    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;
    let key = auto.old.fingerprint.to_string();
    let view = auto.setup.inventory.renewal_views(&plan, &[])[&key].clone();

    assert!(view.renewable && view.automatic && !view.locked);
    assert!(view.new_key && view.can_revoke && !view.replaced && !view.waiting);
    assert_eq!(view.days_before, 30);
    assert_eq!(view.from, Some(1_700_000_000_000));
    assert_eq!(view.replaced_on, None);
    assert_eq!(view.replaced_by, None);

    auto.renewals
        .set_off(&auto.ilm(), "jdoe", &auto.old.fingerprint, true)
        .unwrap();
    plan.person.automatic_renewal = Some(AutomaticRenewal::SameKey);
    let view = auto.setup.inventory.renewal_views(&plan, &[])[&key].clone();
    assert!(!view.automatic && !view.new_key);

    plan.policy.automatic_renewal = Some(AutomaticRenewal::Off);
    let view = auto.setup.inventory.renewal_views(&plan, &[])[&key].clone();
    assert!(view.locked && !view.automatic);
}

#[tokio::test]
async fn a_certificate_whose_person_setting_is_off_is_not_shown_as_renewing_itself() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let mut plan = plan(&auto.renewals, Platform::Macos);
    plan.person.automatic_renewal = Some(AutomaticRenewal::Off);
    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;

    let view =
        auto.setup.inventory.renewal_views(&plan, &[])[&auto.old.fingerprint.to_string()].clone();

    assert!(!view.automatic && !view.locked && view.renewable);
}

#[tokio::test]
async fn a_certificate_whose_subject_a_request_cannot_carry_is_shown_as_keeping_its_key() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "web.example.com");
    params.subject_alt_names = vec![SanType::OtherName((
        vec![1, 2, 3, 4],
        OtherNameValue::Utf8String("v".to_owned()),
    ))];
    let der = params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap()
        .der()
        .to_vec();
    auto.setup
        .mock("GET", "/api/v1/certificates/c-old")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "issued",
            "certificateContent": STANDARD.encode(&der),
            "raProfile": { "uuid": "ra-1", "name": "Servers", "authorityInstanceUuid": "auth-1" },
            "relatedCertificates": [],
        })))
        .with_priority(1)
        .mount(&auto.setup.world.ilm)
        .await;
    let plan = plan(&auto.renewals, Platform::Macos);
    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;

    let view =
        auto.setup.inventory.renewal_views(&plan, &[])[&auto.old.fingerprint.to_string()].clone();

    assert!(view.renewable && !view.new_key);
}

#[tokio::test]
async fn an_expiring_certificate_that_renews_itself_asks_for_a_sign_in_while_nobody_is_signed_in() {
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    let plan = plan(&auto.renewals, Platform::Macos);
    auto.setup
        .inventory
        .check_local(
            &auto.setup.world.session,
            Trigger::Interval,
            std::slice::from_ref(&auto.old),
        )
        .await;

    let signs_in = auto.setup.inventory.renewal_sign_in(&plan);

    assert_eq!(signs_in.len(), 1);
    assert_eq!(
        signs_in[0].key(),
        format!("renewal:sign-in:{}", auto.old.fingerprint)
    );
    auto.renewals
        .set_off(&auto.ilm(), "jdoe", &auto.old.fingerprint, true)
        .unwrap();
    assert!(auto.setup.inventory.renewal_sign_in(&plan).is_empty());
}

#[tokio::test]
async fn the_log_of_an_automatic_renewal_holds_no_subject_or_key() {
    capture_logs();
    let auto = Auto::expiring_in(10, &["detail", "renew"]).await;
    auto.accepts("rekey").await;

    auto.check(&plan(&auto.renewals, Platform::Macos)).await;

    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains("renewal due: c-old (new key, automatic)"),
        "{log}"
    );
    assert!(log.contains("renewal sent: c-old"), "{log}");
    assert!(
        !log.contains("web.example.com") && !log.contains("jdoe"),
        "{log}"
    );
}

impl Auto {
    /// A revocation of the old certificate that waits for ILM.
    fn revocation(&self) -> Waiting {
        Waiting {
            ilm: self.ilm(),
            username: "jdoe".to_owned(),
            uuid: Some("c-old".to_owned()),
            ra_profile: "ra-1".to_owned(),
            authority: "auth-1".to_owned(),
            key: None,
            label: "web".to_owned(),
            since: 1,
            prepared: false,
            purpose: crate::requests::Purpose::Revoke {
                certificate: "c-old".to_owned(),
                fingerprint: self.old.fingerprint,
                remove: false,
            },
            enrolled: false,
        }
    }

    /// The view of the old certificate after a check, with `waiting` requests.
    async fn view_with(&self, waiting: &[Waiting]) -> Option<RenewalView> {
        let plan = plan(&self.renewals, Platform::Macos);
        self.setup
            .inventory
            .check_local(
                &self.setup.world.session,
                Trigger::Interval,
                std::slice::from_ref(&self.old),
            )
            .await;
        self.setup
            .inventory
            .renewal_views(&plan, waiting)
            .remove(&self.old.fingerprint.to_string())
    }
}

#[tokio::test]
async fn a_certificate_nobody_revokes_has_no_revoking_stage() {
    let auto = Auto::expiring_in(10, &["detail", "renew", "revoke"]).await;

    let view = auto.view_with(&[]).await.unwrap();

    assert_eq!(view.revoking, None);
}

#[tokio::test]
async fn a_revocation_that_waits_is_shown_as_being_revoked() {
    let auto = Auto::expiring_in(10, &["detail", "renew", "revoke"]).await;

    let view = auto.view_with(&[auto.revocation()]).await.unwrap();

    assert_eq!(view.revoking, Some(RevokingStage::BeingRevoked));
}

#[tokio::test]
async fn a_revocation_of_a_certificate_pending_approval_in_ilm_is_shown_as_waiting_for_approval() {
    let auto = Auto::expiring_in(10, &["detail", "revoke"]).await;
    let mut found = certificate("c-old", &auto.old.fingerprint, true);
    found["state"] = json!("pending_approval");
    auto.setup
        .mock("POST", SEARCH)
        .and(body_string_contains("FINGERPRINT"))
        .respond_with(page(vec![found], 1))
        .with_priority(1)
        .mount(&auto.setup.world.ilm)
        .await;

    let view = auto.view_with(&[auto.revocation()]).await.unwrap();

    assert_eq!(view.revoking, Some(RevokingStage::PendingApproval));
}

#[tokio::test]
async fn a_revocation_the_follow_found_waiting_for_approval_is_shown_so_before_the_next_check_reads_it()
 {
    let auto = Auto::expiring_in(10, &["detail", "revoke"]).await;
    auto.requests.add(auto.revocation()).unwrap();
    auto.setup
        .mock("GET", "/api/v1/certificates/c-old")
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "pending_approval",
            "certificateContent": STANDARD.encode(&auto.der),
            "raProfile": { "uuid": "ra-1", "name": "Servers", "authorityInstanceUuid": "auth-1" },
            "relatedCertificates": [],
        })))
        .with_priority(1)
        .mount(&auto.setup.world.ilm)
        .await;

    let view = auto.view_with(&[auto.revocation()]).await.unwrap();

    assert_eq!(view.revoking, Some(RevokingStage::PendingApproval));
}

#[tokio::test]
async fn a_certificate_with_a_waiting_revocation_keeps_its_view_when_ilm_no_longer_lets_the_person_revoke_it()
 {
    let auto = Auto::expiring_in(10, &["detail"]).await;

    let view = auto.view_with(&[auto.revocation()]).await.unwrap();

    assert!(!view.can_revoke && !view.renewable);
    assert_eq!(view.revoking, Some(RevokingStage::BeingRevoked));
}

#[tokio::test]
async fn a_revocation_of_another_certificate_is_not_shown() {
    let auto = Auto::expiring_in(10, &["detail", "revoke"]).await;
    let mut other = auto.revocation();
    other.uuid = Some("c-other".to_owned());
    other.purpose = crate::requests::Purpose::Revoke {
        certificate: "c-other".to_owned(),
        fingerprint: Fingerprint::of(b"other"),
        remove: false,
    };

    let view = auto.view_with(&[other]).await.unwrap();

    assert_eq!(view.revoking, None);
}
