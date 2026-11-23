//! The forms of the session: opening, callbacks as the signed-in person, the registry.

use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{body_json, method, path};
use wiremock::{Mock, ResponseTemplate};

use super::tests::{LOG, World, capture_logs};
use super::{FormError, SessionView};
use crate::attributes::{
    CallbackResult, CallbackView, FieldProblem, FieldView, FormCheck, FormContext, FormView,
    Problem, Value as AttrValue, option_key,
};

const PROFILE: &str = "/api/v1/auth/profile";
const CUSTOM: &str = "/api/v1/attributes/custom/resources/certificates";
const ISSUE: &str = "/api/v2/operations/authorities/auth-1/raProfiles/ra-1/attributes/issue";
const CALLBACK: &str = "/api/v1/certificates/ra-1/callback";

fn issue() -> FormContext {
    FormContext::Issue {
        authority: "auth-1".into(),
        ra_profile: "ra-1".into(),
    }
}

fn attribute(name: &str, content_type: &str, version: u8, properties: Value) -> Value {
    let mut properties = properties;
    properties["label"] = json!(format!("{name} label"));
    let mut raw = json!({
        "uuid": format!("uuid-{name}"),
        "name": name,
        "version": version,
        "type": "data",
        "contentType": content_type,
        "properties": properties,
    });
    if version == 3 {
        raw["schemaVersion"] = json!("v3");
    }
    raw
}

fn with(mut raw: Value, key: &str, value: Value) -> Value {
    raw[key] = value;
    raw
}

fn chooser(name: &str, options: Value, callback: Option<Value>) -> Value {
    let raw = with(
        attribute(name, "string", 3, json!({ "list": true })),
        "content",
        options,
    );
    match callback {
        Some(callback) => with(raw, "attributeCallback", callback),
        None => raw,
    }
}

fn legacy(mappings: Value) -> Value {
    json!({ "callbackContext": "core/getCredentials", "callbackMethod": "GET", "mappings": mappings })
}

fn issue_definitions() -> Vec<Value> {
    vec![
        chooser(
            "kind",
            json!([{ "data": "Basic", "contentType": "string" }, { "data": "Token", "contentType": "string" }]),
            None,
        ),
        with(
            attribute("credential", "credential", 2, json!({ "required": true })),
            "attributeCallback",
            legacy(
                json!([{ "from": "kind", "to": "credentialKind", "targets": ["pathVariable"] }]),
            ),
        ),
        chooser("region", json!([]), Some(json!({ "dependsOn": [] }))),
        chooser("zone", json!([]), Some(json!({ "dependsOn": ["region"] }))),
        chooser("site", json!([]), Some(json!({ "dependsOn": ["zone"] }))),
        with(
            attribute("fixed", "string", 3, json!({ "readOnly": true })),
            "content",
            json!([{ "data": "from ILM", "contentType": "string" }]),
        ),
        with(
            attribute("mirror", "string", 3, json!({})),
            "attributeCallback",
            legacy(json!([{ "from": "fixed", "to": "seen", "targets": ["body"] }])),
        ),
        json!({
            "uuid": "uuid-extension",
            "name": "extension",
            "version": 2,
            "type": "group",
            "content": [],
            "attributeCallback": legacy(json!([
                { "to": "credentialKind", "targets": ["pathVariable"], "value": "Basic" }
            ])),
        }),
    ]
}

/// The key of the option ILM gave as the string item `data`.
fn key(data: &str) -> String {
    option_key(&json!({ "data": data, "contentType": "string" }))
}

/// The choice of the option `data`, as the interface sends it.
fn option(data: &str) -> Value {
    json!({ "kind": "option", "value": key(data) })
}

fn text(text: &str) -> Value {
    json!({ "kind": "text", "value": text })
}

struct Open {
    world: World,
}

impl Open {
    async fn new() -> Self {
        let world = World::new().await;
        world.code_grant("access", Some("refresh"), 3600).await;
        Mock::given(method("GET"))
            .and(path(PROFILE))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "uuid": "u-person",
                "username": "jdoe",
                "permissions": { "allowedListings": [], "allowedActions": [] },
            })))
            .mount(&world.ilm)
            .await;
        assert!(matches!(
            world.sign_in().await,
            SessionView::SignedIn { .. }
        ));
        Self { world }
    }

    async fn serve(&self, verb: &str, route: &str, response: ResponseTemplate) {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(&self.world.ilm)
            .await;
    }

    async fn serve_definitions(&self, route: &str, definitions: Vec<Value>) {
        self.serve(
            "GET",
            route,
            ResponseTemplate::new(200).set_body_json(definitions),
        )
        .await;
    }

    /// An issue form over `issue_definitions`.
    async fn issue_form(&self) -> FormView {
        self.serve_definitions(ISSUE, issue_definitions()).await;
        self.world
            .session
            .open_form(issue())
            .await
            .unwrap()
            .unwrap()
    }

    async fn run(&self, form: &FormView, field: &str, values: Value, seq: u64) -> CallbackResult {
        self.world
            .session
            .run_callback(&form.id, field, &values, seq)
            .await
            .unwrap()
    }

    async fn callbacks_sent(&self) -> usize {
        self.world
            .ilm
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == CALLBACK)
            .count()
    }

    async fn answer(&self, items: Value) {
        self.serve(
            "POST",
            CALLBACK,
            ResponseTemplate::new(200).set_body_json(items),
        )
        .await;
    }
}

fn field<'a>(form: &'a FormView, name: &str) -> &'a FieldView {
    form.groups
        .iter()
        .flat_map(|group| group.fields.iter())
        .find(|field| field.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn names(form: &FormView) -> Vec<&str> {
    form.groups
        .iter()
        .flat_map(|group| group.fields.iter())
        .map(|field| field.name.as_str())
        .collect()
}

fn labels(field: &FieldView) -> Vec<&str> {
    field
        .options
        .iter()
        .map(|option| option.label.as_str())
        .collect()
}

fn problem_text(result: &CallbackResult) -> &str {
    result.problem.as_deref().expect("no problem")
}

fn check(open: &Open, form: &FormView, values: Value) -> FormCheck {
    open.world.session.check_form(&form.id, &values).unwrap()
}

#[tokio::test]
async fn a_custom_form_opens_from_the_custom_attributes_with_the_web_address() {
    let open = Open::new().await;
    open.serve_definitions(
        CUSTOM,
        vec![
            attribute("TestInt", "integer", 3, json!({})),
            attribute("odd", "quaternion", 3, json!({ "required": true })),
        ],
    )
    .await;

    let form = open
        .world
        .session
        .open_form(FormContext::Custom)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(form.groups[0].fields[0].name, "TestInt");
    assert_eq!(form.unsupported, ["odd label"]);
    assert_eq!(form.revision, 0);
    assert_eq!(form.id.len(), 32);
    assert!(form.web.unwrap().ends_with("/administrator/#/certificates"));
}

#[tokio::test]
async fn a_form_the_person_may_not_read_or_ilm_lacks_is_none() {
    for status in [403, 404] {
        let open = Open::new().await;
        open.serve("GET", CUSTOM, ResponseTemplate::new(status))
            .await;
        assert!(
            open.world
                .session
                .open_form(FormContext::Custom)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn a_form_that_cannot_be_read_says_why() {
    let open = Open::new().await;
    open.serve("GET", CUSTOM, ResponseTemplate::new(500)).await;
    assert_eq!(
        open.world.session.open_form(FormContext::Custom).await,
        Err(FormError::Unexpected(500))
    );
    let signed_out = World::new().await;
    assert_eq!(
        signed_out.session.open_form(FormContext::Custom).await,
        Err(FormError::SignedOut)
    );
}

#[tokio::test]
async fn at_most_eight_forms_stay_open_and_the_oldest_goes() {
    let open = Open::new().await;
    open.serve_definitions(CUSTOM, vec![attribute("TestInt", "integer", 3, json!({}))])
        .await;
    let mut ids = Vec::new();
    for _ in 0..9 {
        let form = open.world.session.open_form(FormContext::Custom).await;
        ids.push(form.unwrap().unwrap().id);
    }
    let session = &open.world.session;
    assert_eq!(
        session.check_form(&ids[0], &json!({})),
        Err(FormError::Gone)
    );
    for id in &ids[1..] {
        assert_eq!(
            session.check_form(id, &json!({})),
            Ok(FormCheck {
                revision: 0,
                problems: Vec::new()
            })
        );
    }
}

#[tokio::test]
async fn an_unknown_or_closed_form_is_a_plain_error() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    let session = &open.world.session;
    assert_eq!(session.check_form("nope", &json!({})), Err(FormError::Gone));
    assert_eq!(
        session.run_callback("nope", "kind", &json!({}), 1).await,
        Err(FormError::Gone)
    );
    session.close_form(&form.id);
    session.close_form(&form.id);
    assert_eq!(
        session.check_form(&form.id, &json!({})),
        Err(FormError::Gone)
    );
    assert!(FormError::Gone.to_string().contains("not open any more"));
}

#[tokio::test]
async fn forms_are_dropped_at_lock_and_at_sign_out() {
    let open = Open::new().await;
    let locked = open.issue_form().await;
    let other = open.issue_form().await;
    let session = &open.world.session;
    session.close_forms();
    for id in [&locked.id, &other.id] {
        assert_eq!(session.check_form(id, &json!({})), Err(FormError::Gone));
    }

    let signing_out = open.issue_form().await;
    session.sign_out().await;
    assert_eq!(
        session.check_form(&signing_out.id, &json!({})),
        Err(FormError::Gone)
    );
    assert_eq!(session.take_form(&signing_out.id), None);
}

#[tokio::test]
async fn an_opening_that_finishes_after_a_lock_registers_no_form() {
    let open = Open::new().await;
    open.serve(
        "GET",
        CUSTOM,
        ResponseTemplate::new(200)
            .set_body_json(json!([attribute("note", "string", 3, json!({}))]))
            .set_delay(Duration::from_millis(300)),
    )
    .await;
    let session = &open.world.session;

    let opening = session.open_form(FormContext::Custom);
    let locking = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        session.close_forms();
    };
    let (opened, ()) = tokio::join!(opening, locking);

    assert_eq!(opened, Err(FormError::Gone));
}

#[tokio::test]
async fn a_legacy_callback_runs_at_open_with_its_static_value_and_adds_the_fields_after_its_group()
{
    let open = Open::new().await;
    let form = open.issue_form().await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .and(body_json(json!({
            "uuid": "uuid-extension",
            "name": "extension",
            "pathVariable": { "credentialKind": "Basic" },
            "requestParameter": {},
            "body": {},
            "filter": {},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            attribute("email", "string", 2, json!({ "required": true })),
            attribute("phone", "string", 2, json!({})),
        ])))
        .expect(1)
        .mount(&open.world.ilm)
        .await;

    let result = open.run(&form, "extension", json!({}), 1).await;

    assert_eq!((result.seq, result.field.as_str()), (1, "extension"));
    assert_eq!(result.problem, None);
    let all = names(&result.form);
    let at = all.iter().position(|name| *name == "extension").unwrap();
    assert_eq!(all[at..], ["extension", "email", "phone"]);
    assert_eq!(result.form.revision, 1);
    assert_eq!(field(&result.form, "email").changed_at, 1);
    assert_eq!(field(&result.form, "email").value_set_at, 1);
    assert_eq!(
        open.world.session.check_form(&form.id, &json!({})),
        Ok(FormCheck {
            revision: 1,
            problems: vec![
                FieldProblem {
                    name: "credential".into(),
                    problem: Problem::Required
                },
                FieldProblem {
                    name: "email".into(),
                    problem: Problem::Required
                },
            ]
        })
    );
}

#[tokio::test]
async fn a_second_answer_of_a_group_replaces_the_fields_of_the_first() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    open.run(&form, "extension", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.answer(json!([attribute("phone", "string", 2, json!({}))]))
        .await;

    let second = open.run(&form, "extension", json!({}), 2).await;

    let all = names(&second.form);
    assert!(all.contains(&"phone") && !all.contains(&"email"));
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    assert!(definitions.fields.iter().all(|field| field.name != "email"));
}

#[tokio::test]
async fn a_mapping_reads_the_chosen_option_and_the_answer_becomes_the_options_of_the_field() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .and(body_json(json!({
            "uuid": "uuid-credential",
            "name": "credential",
            "pathVariable": { "credentialKind": "Token" },
            "requestParameter": {},
            "body": {},
            "filter": {},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "reference": "main", "data": { "uuid": "u-1", "name": "main" } },
            { "reference": "backup", "data": { "uuid": "u-2", "name": "backup" } },
        ])))
        .expect(1)
        .mount(&open.world.ilm)
        .await;

    let result = open
        .run(&form, "credential", json!({ "kind": option("Token") }), 3)
        .await;

    let credential = field(&result.form, "credential");
    assert_eq!(labels(credential), ["main", "backup"]);
    assert_eq!(credential.value, None);
    assert_eq!(credential.changed_at, 1);
    assert_eq!(credential.value_set_at, 0);
}

#[tokio::test]
async fn a_chosen_key_still_among_the_options_stays_valid_and_one_that_is_gone_is_not_an_option() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "eu", "contentType": "string" }, { "data": "us", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.answer(json!([{ "data": "us", "contentType": "string" }, { "data": "ap", "contentType": "string" }]))
        .await;

    let second = open
        .run(&form, "region", json!({ "region": option("us") }), 2)
        .await;

    let region = field(&second.form, "region");
    assert_eq!(region.options[0].key, key("us"));
    assert_eq!(region.value, None);
    assert_eq!(region.value_set_at, 0);
    let kept = check(&open, &form, json!({ "region": option("us") }));
    assert!(kept.problems.iter().all(|found| found.name != "region"));
    let gone = check(&open, &form, json!({ "region": option("eu") }));
    assert!(gone.problems.contains(&FieldProblem {
        name: "region".into(),
        problem: Problem::NotAnOption
    }));
}

#[tokio::test]
async fn a_chosen_option_keeps_its_meaning_when_the_options_are_reordered() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "Sales", "contentType": "string" }, { "data": "IT", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.answer(json!([{ "data": "IT", "contentType": "string" }, { "data": "Sales", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 2).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .and(body_json(json!({
            "uuid": "uuid-zone",
            "name": "zone",
            "pathVariable": {},
            "requestParameter": {},
            "body": {},
            "filter": {},
            "attributes": [{
                "uuid": "uuid-region",
                "name": "region",
                "contentType": "string",
                "version": "v3",
                "content": [{ "data": "Sales", "contentType": "string" }],
            }],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "data": "north", "contentType": "string" }
        ])))
        .expect(1)
        .mount(&open.world.ilm)
        .await;

    // The interface still shows its choice, made against the order of the first answer.
    let zone = open
        .run(&form, "zone", json!({ "region": option("Sales") }), 1)
        .await;

    assert_eq!(labels(field(&zone.form, "zone")), ["north"]);
}

#[tokio::test]
async fn a_key_that_is_not_among_the_options_counts_as_no_value_and_sends_no_item() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "eu", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.run(&form, "zone", json!({ "region": option("eu") }), 1)
        .await;
    let sent = open.callbacks_sent().await;

    let result = open
        .run(&form, "zone", json!({ "region": option("gone") }), 2)
        .await;

    assert_eq!(open.callbacks_sent().await, sent);
    assert!(field(&result.form, "zone").options.is_empty());
    assert!(
        check(&open, &form, json!({ "region": option("gone") }))
            .problems
            .iter()
            .any(|found| found.problem == Problem::NotAnOption)
    );
}

#[tokio::test]
async fn a_depends_on_callback_sends_the_attributes_it_depends_on_from_the_core_copy() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "eu", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .and(body_json(json!({
            "uuid": "uuid-zone",
            "name": "zone",
            "pathVariable": {},
            "requestParameter": {},
            "body": {},
            "filter": {},
            "attributes": [{
                "uuid": "uuid-region",
                "name": "region",
                "contentType": "string",
                "version": "v3",
                "content": [{ "data": "eu", "contentType": "string" }],
            }],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            { "data": "eu-1", "contentType": "string" }
        ])))
        .expect(1)
        .mount(&open.world.ilm)
        .await;

    let result = open
        .run(&form, "zone", json!({ "region": option("eu") }), 2)
        .await;

    assert_eq!(labels(field(&result.form, "zone")), ["eu-1"]);
}

#[tokio::test]
async fn a_dependency_without_a_value_clears_the_dependents_without_asking_ilm() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "eu", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.run(&form, "zone", json!({ "region": option("eu") }), 1)
        .await;
    let filled = open
        .run(&form, "site", json!({ "zone": option("eu") }), 1)
        .await;
    assert_eq!(labels(field(&filled.form, "site")), ["eu"]);
    let sent = open.callbacks_sent().await;

    let cleared = open.run(&form, "zone", json!({}), 2).await;

    assert_eq!(open.callbacks_sent().await, sent);
    for name in ["zone", "site"] {
        let cleared_field = field(&cleared.form, name);
        assert!(cleared_field.options.is_empty(), "{name} still has options");
        assert_eq!(cleared_field.changed_at, cleared.form.revision);
        assert_eq!(cleared_field.value_set_at, cleared.form.revision);
    }
    assert!(cleared.form.revision > filled.form.revision);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    for name in ["zone", "site"] {
        let found = definitions.fields.iter().find(|f| f.name == name).unwrap();
        assert!(found.content.is_empty(), "{name} still has options");
    }
}

#[tokio::test]
async fn a_callback_that_cannot_resolve_asks_nothing() {
    let open = Open::new().await;
    let form = open.issue_form().await;

    let unresolved = open.run(&form, "credential", json!({}), 1).await;
    let none = open.run(&form, "kind", json!({}), 1).await;
    let unknown = open.run(&form, "../../v1/users", json!({}), 1).await;

    for result in [unresolved, none, unknown] {
        assert_eq!(result.form, form);
        assert_eq!(result.problem, None);
    }
    assert_eq!(open.callbacks_sent().await, 0);
}

#[tokio::test]
async fn custom_attributes_have_no_callbacks_to_run() {
    let open = Open::new().await;
    open.serve_definitions(
        CUSTOM,
        vec![with(
            attribute("asks", "string", 3, json!({})),
            "attributeCallback",
            json!({ "dependsOn": [] }),
        )],
    )
    .await;
    let form = open
        .world
        .session
        .open_form(FormContext::Custom)
        .await
        .unwrap()
        .unwrap();

    let result = open.run(&form, "asks", json!({}), 1).await;

    assert_eq!(result.form, form);
    let requests = open.world.ilm.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() != "POST")
    );
}

#[tokio::test]
async fn the_interface_cannot_steer_the_call() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .and(body_json(json!({
            "uuid": "uuid-mirror",
            "name": "mirror",
            "pathVariable": {},
            "requestParameter": {},
            "body": { "seen": "from ILM" },
            "filter": {},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "data": "x" }])))
        .expect(1)
        .mount(&open.world.ilm)
        .await;

    // The interface also sends a value for the read-only field and keys that look like routing.
    let values = json!({
        "fixed": text("not from ILM"),
        "uuid": text("other"),
        "pathVariable": text("../x"),
        "nobody": text("x"),
    });
    let result = open.run(&form, "mirror", values, 1).await;

    assert_eq!(
        field(&result.form, "mirror").value,
        Some(AttrValue::Text("x".into()))
    );
}

#[tokio::test]
async fn values_of_the_wrong_kind_are_refused() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    let session = &open.world.session;
    assert_eq!(
        session
            .run_callback(
                &form.id,
                "mirror",
                &json!({ "mirror": { "kind": "bool", "value": true } }),
                1
            )
            .await,
        Err(FormError::BadValues)
    );
    assert_eq!(
        session.check_form(&form.id, &json!("not an object")),
        Err(FormError::BadValues)
    );
}

#[tokio::test]
async fn a_refusal_and_a_failure_say_so_on_the_field_and_the_form_stays_as_it_was() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.serve("POST", CALLBACK, ResponseTemplate::new(403))
        .await;
    let refused = open.run(&form, "mirror", json!({}), 1).await;
    assert_eq!(problem_text(&refused), "ILM does not allow this.");
    assert_eq!(refused.form, form);

    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.serve("POST", CALLBACK, ResponseTemplate::new(500))
        .await;
    let failed = open.run(&form, "mirror", json!({}), 2).await;
    assert_eq!(problem_text(&failed), "ILM did not answer.");

    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.serve(
        "POST",
        CALLBACK,
        ResponseTemplate::new(200).set_body_string("not json"),
    )
    .await;
    let unreadable = open.run(&form, "mirror", json!({}), 3).await;
    assert_eq!(problem_text(&unreadable), "ILM did not answer.");
    assert_eq!(unreadable.form, form);
}

#[tokio::test]
async fn an_answer_that_does_not_fit_the_attribute_is_a_problem_and_changes_nothing() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;

    let result = open.run(&form, "mirror", json!({}), 1).await;

    assert_eq!(problem_text(&result), "ILM did not answer.");
    assert_eq!(result.form, form);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    assert!(definitions.fields.iter().all(|field| field.name != "email"));
}

#[tokio::test]
async fn an_older_run_is_dropped_before_and_after_ilm_answers() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    // The first request is answered slowly with options a newer run replaced.
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "data": "slow" }]))
                .set_delay(Duration::from_millis(300)),
        )
        .up_to_n_times(1)
        .mount(&open.world.ilm)
        .await;
    open.answer(json!([{ "data": "fast" }])).await;

    let slow = open.run(&form, "mirror", json!({}), 5);
    let fast = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        open.run(&form, "mirror", json!({}), 6).await
    };
    let (slow, fast) = tokio::join!(slow, fast);

    assert_eq!(fast.form.revision, 1);
    assert_eq!(slow.form.revision, 1);
    assert_eq!(
        field(&slow.form, "mirror").value,
        Some(AttrValue::Text("fast".into()))
    );
    let late = open.run(&form, "mirror", json!({}), 4).await;
    assert_eq!(late.form.revision, 1);
    assert_eq!(open.callbacks_sent().await, 2);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    let mirror = definitions
        .fields
        .iter()
        .find(|f| f.name == "mirror")
        .unwrap();
    assert_eq!(mirror.content, [json!({ "data": "fast" })]);
}

#[tokio::test]
async fn a_callback_while_signed_out_is_refused() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.world.session.sign_out().await;
    assert_eq!(
        open.world
            .session
            .run_callback(&form.id, "mirror", &json!({}), 1)
            .await,
        Err(FormError::SignedOut)
    );
}

#[tokio::test]
async fn the_log_says_what_happened_without_values_options_or_messages() {
    capture_logs();
    let open = Open::new().await;
    open.serve_definitions(
        ISSUE,
        vec![
            with(
                attribute("Unique-Secret-Name", "secret", 2, json!({})),
                "attributeCallback",
                json!({ "dependsOn": [] }),
            ),
            attribute("odd", "quaternion", 3, json!({})),
        ],
    )
    .await;
    let form = open
        .world
        .session
        .open_form(issue())
        .await
        .unwrap()
        .unwrap();
    open.serve(
        "POST",
        CALLBACK,
        ResponseTemplate::new(200).set_body_json(json!([
            { "reference": "Unique-Option-Z9", "data": "Unique-Option-Z9" }
        ])),
    )
    .await;
    open.run(&form, "Unique-Secret-Name", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve(
        "POST",
        CALLBACK,
        ResponseTemplate::new(500).set_body_json(json!({ "message": "Unique-Message-Z9" })),
    )
    .await;
    open.run(&form, "Unique-Secret-Name", json!({}), 2).await;

    let log = LOG.lock().unwrap().join("\n");
    assert!(
        log.contains("a form of issue attributes was opened: 1 fields, 1 that cannot be shown")
    );
    assert!(log.contains("callback run for Unique-Secret-Name: answered (200)"));
    assert!(log.contains("callback run for Unique-Secret-Name: failed (500)"));
    assert!(log.contains("the attribute odd cannot be shown"));
    for private in ["Unique-Option-Z9", "Unique-Message-Z9", "u-person"] {
        assert!(!log.contains(private), "{private} is in the log");
    }
}

#[tokio::test]
async fn a_failed_newer_run_still_carries_what_an_older_run_committed() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "Sales", "contentType": "string" }, { "data": "IT", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.answer(json!([{ "data": "IT", "contentType": "string" }, { "data": "Sales", "contentType": "string" }]))
        .await;
    let reordered = open.run(&form, "region", json!({}), 2).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, issue_definitions()).await;
    open.serve("POST", CALLBACK, ResponseTemplate::new(500))
        .await;

    let failed = open.run(&form, "region", json!({}), 3).await;

    assert_eq!(problem_text(&failed), "ILM did not answer.");
    assert_eq!(failed.form, reordered.form);
    assert_eq!(field(&failed.form, "region").options[0].key, key("IT"));
}

#[tokio::test]
async fn clearing_a_field_drops_the_outstanding_answers_of_everything_it_clears() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([{ "data": "eu", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;
    open.run(&form, "zone", json!({ "region": option("eu") }), 1)
        .await;
    open.world.ilm.reset().await;
    Mock::given(method("POST"))
        .and(path(CALLBACK))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([{ "data": "late" }]))
                .set_delay(Duration::from_millis(300)),
        )
        .mount(&open.world.ilm)
        .await;

    let slow = open.run(&form, "site", json!({ "zone": option("eu") }), 1);
    let clearing = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        open.run(&form, "zone", json!({}), 2).await
    };
    let (slow, cleared) = tokio::join!(slow, clearing);

    for name in ["zone", "site"] {
        assert!(field(&cleared.form, name).options.is_empty());
        assert!(field(&slow.form, name).options.is_empty());
    }
    assert_eq!(slow.form, cleared.form);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    let site = definitions
        .fields
        .iter()
        .find(|f| f.name == "site")
        .unwrap();
    assert!(site.content.is_empty());
}

async fn extras_definitions(open: &Open, more: Vec<Value>) -> FormView {
    let mut definitions = vec![
        chooser(
            "region",
            json!([{ "data": "eu", "contentType": "string" }]),
            None,
        ),
        json!({
            "uuid": "uuid-extras",
            "name": "extras",
            "type": "group",
            "attributeCallback": { "dependsOn": ["region"] },
        }),
    ];
    definitions.extend(more);
    open.serve_definitions(ISSUE, definitions).await;
    open.world
        .session
        .open_form(issue())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn clearing_a_group_removes_the_fields_its_callback_added() {
    let open = Open::new().await;
    let form = extras_definitions(&open, Vec::new()).await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    let added = open
        .run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    assert!(names(&added.form).contains(&"email"));

    let cleared = open.run(&form, "extras", json!({}), 2).await;

    assert!(!names(&cleared.form).contains(&"email"));
    assert!(cleared.form.revision > added.form.revision);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    assert!(definitions.fields.iter().all(|f| f.name != "email"));
}

#[tokio::test]
async fn clearing_a_group_also_clears_what_depends_on_the_fields_it_added() {
    let open = Open::new().await;
    let form = extras_definitions(
        &open,
        vec![chooser(
            "pick",
            json!([]),
            Some(json!({ "dependsOn": ["email"] })),
        )],
    )
    .await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    open.run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([{ "data": "x", "contentType": "string" }]))
        .await;
    let picked = open
        .run(&form, "pick", json!({ "email": text("a@b.c") }), 1)
        .await;
    assert_eq!(labels(field(&picked.form, "pick")), ["x"]);

    let cleared = open.run(&form, "extras", json!({}), 2).await;

    assert!(field(&cleared.form, "pick").options.is_empty());
    assert_eq!(
        field(&cleared.form, "pick").value_set_at,
        cleared.form.revision
    );
    let late = open
        .run(&form, "pick", json!({ "email": text("a@b.c") }), 1)
        .await;
    assert_eq!(late.form, cleared.form);
}

#[tokio::test]
async fn the_required_fields_a_group_adds_that_cannot_be_shown_reach_the_interface() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    open.answer(json!([
        attribute("email", "string", 2, json!({})),
        attribute(
            "locked",
            "string",
            3,
            json!({ "required": true, "readOnly": true })
        ),
        attribute("spare", "string", 3, json!({ "readOnly": true })),
    ]))
    .await;

    let result = open.run(&form, "extension", json!({}), 1).await;

    assert!(!names(&result.form).contains(&"locked"));
    assert_eq!(result.form.unsupported, ["locked label"]);
}

fn pinned(callback: Value) -> Value {
    with(
        with(
            attribute(
                "pin",
                "string",
                3,
                json!({ "required": true, "visible": false }),
            ),
            "content",
            json!([{ "data": "1234", "contentType": "string" }]),
        ),
        "attributeCallback",
        callback,
    )
}

#[tokio::test]
async fn a_clear_that_empties_a_required_hidden_field_blocks_the_form_and_says_so() {
    let open = Open::new().await;
    let form = extras_definitions(&open, vec![pinned(json!({ "dependsOn": ["email"] }))]).await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    open.run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;

    let cleared = open.run(&form, "extras", json!({}), 2).await;

    assert_eq!(cleared.form.unsupported, ["pin label"]);
    assert!(
        open.world
            .session
            .form_definitions(&form.id)
            .unwrap()
            .blocked()
    );
}

#[tokio::test]
async fn an_empty_options_answer_that_empties_a_required_hidden_field_blocks_the_form() {
    let open = Open::new().await;
    let form = extras_definitions(&open, vec![pinned(json!({ "dependsOn": ["region"] }))]).await;
    open.answer(json!([])).await;

    let result = open
        .run(&form, "pin", json!({ "region": option("eu") }), 1)
        .await;

    assert_eq!(result.form.unsupported, ["pin label"]);
    assert!(
        open.world
            .session
            .form_definitions(&form.id)
            .unwrap()
            .blocked()
    );
}

#[tokio::test]
async fn a_hidden_fields_answer_shows_only_that_it_changed_never_its_options_or_value() {
    let open = Open::new().await;
    let form = extras_definitions(&open, vec![pinned(json!({ "dependsOn": ["region"] }))]).await;
    open.answer(json!([{ "data": "9876", "contentType": "string" }]))
        .await;

    let result = open
        .run(&form, "pin", json!({ "region": option("eu") }), 1)
        .await;

    let pin = field(&result.form, "pin");
    assert!(pin.options.is_empty());
    assert_eq!(pin.value, None);
    assert_eq!(pin.changed_at, result.form.revision);
    let (_, definitions) = open.world.session.take_form(&form.id).unwrap();
    let held = definitions.fields.iter().find(|f| f.name == "pin").unwrap();
    assert_eq!(
        held.content,
        [json!({ "data": "9876", "contentType": "string" })]
    );
}

#[tokio::test]
async fn an_empty_answer_to_a_group_removes_the_fields_and_blockers_it_added_before() {
    let open = Open::new().await;
    let form = extras_definitions(&open, Vec::new()).await;
    open.answer(json!([
        attribute("email", "string", 2, json!({})),
        attribute("odd", "mystery", 3, json!({ "required": true })),
    ]))
    .await;
    let first = open
        .run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    assert_eq!(first.form.unsupported, ["odd label"]);
    assert!(
        open.world
            .session
            .form_definitions(&form.id)
            .unwrap()
            .blocked()
    );
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([])).await;

    let second = open
        .run(&form, "extras", json!({ "region": option("eu") }), 2)
        .await;

    assert!(!names(&second.form).contains(&"email"));
    assert!(second.form.unsupported.is_empty());
    let definitions = open.world.session.form_definitions(&form.id).unwrap();
    assert!(!definitions.blocked());
}

#[tokio::test]
async fn a_group_answer_that_replaces_a_field_clears_what_depends_on_it_and_drops_its_answers() {
    let open = Open::new().await;
    let form = extras_definitions(
        &open,
        vec![chooser(
            "pick",
            json!([]),
            Some(json!({ "dependsOn": ["email"] })),
        )],
    )
    .await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    open.run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([{ "data": "x", "contentType": "string" }]))
        .await;
    open.run(&form, "pick", json!({ "email": text("a@b.c") }), 1)
        .await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([attribute("phone", "string", 2, json!({}))]))
        .await;

    let second = open
        .run(&form, "extras", json!({ "region": option("eu") }), 2)
        .await;

    assert!(field(&second.form, "pick").options.is_empty());
    assert_eq!(second.form.revision, 3);
    assert_eq!(field(&second.form, "pick").value_set_at, 3);
    assert_eq!(field(&second.form, "phone").value_set_at, 3);
    assert!(!names(&second.form).contains(&"email"));
    let late = open
        .run(&form, "pick", json!({ "email": text("a@b.c") }), 1)
        .await;
    assert_eq!(late.form, second.form);
}

#[tokio::test]
async fn a_group_answer_carries_the_callbacks_of_the_groups_it_adds_after_their_owner() {
    let open = Open::new().await;
    let form = extras_definitions(&open, Vec::new()).await;
    open.answer(json!([
        attribute("email", "string", 2, json!({})),
        json!({
            "uuid": "uuid-more",
            "name": "more",
            "type": "group",
            "attributeCallback": { "dependsOn": ["email"] },
        }),
    ]))
    .await;

    let result = open
        .run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;

    let more = field(&result.form, "more");
    assert!(more.hidden);
    assert_eq!(more.callback, CallbackView::OnChange(vec!["email".into()]));
    let all = names(&result.form);
    let at = all.iter().position(|name| *name == "extras").unwrap();
    assert_eq!(all[at..], ["extras", "email", "more"]);
}

#[tokio::test]
async fn a_group_added_by_a_group_adds_its_own_fields_after_it() {
    let open = Open::new().await;
    let form = extras_definitions(&open, Vec::new()).await;
    open.answer(json!([json!({
        "uuid": "uuid-more",
        "name": "more",
        "type": "group",
        "attributeCallback": { "dependsOn": [] },
    })]))
    .await;
    open.run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([attribute("deep", "string", 2, json!({}))]))
        .await;

    let result = open.run(&form, "more", json!({}), 1).await;

    let all = names(&result.form);
    let at = all.iter().position(|name| *name == "extras").unwrap();
    assert_eq!(all[at..], ["extras", "more", "deep"]);
}

#[tokio::test]
async fn a_replaced_field_drops_the_answers_still_on_their_way() {
    let open = Open::new().await;
    let form = extras_definitions(&open, Vec::new()).await;
    let child = |label: &str| {
        with(
            chooser("child", json!([]), Some(json!({ "dependsOn": [] }))),
            "description",
            json!(label),
        )
    };
    open.answer(json!([child("old")])).await;
    open.run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    open.run(&form, "child", json!({}), 1).await;
    open.world.ilm.reset().await;
    open.serve_definitions(ISSUE, Vec::new()).await;
    open.answer(json!([child("new")])).await;

    let second = open
        .run(&form, "extras", json!({ "region": option("eu") }), 2)
        .await;

    let late = open.run(&form, "child", json!({}), 1).await;
    assert_eq!(late.form, second.form);
    assert_eq!(
        field(&late.form, "child").description.as_deref(),
        Some("new")
    );
}

fn chooser_read_only(name: &str, multi: bool) -> Value {
    with(
        attribute(
            name,
            "string",
            3,
            json!({ "list": true, "readOnly": true, "multiSelect": multi }),
        ),
        "attributeCallback",
        json!({ "dependsOn": ["region"] }),
    )
}

#[tokio::test]
async fn the_answer_for_a_read_only_list_carries_what_the_form_shows_for_it() {
    let open = Open::new().await;
    let form = extras_definitions(
        &open,
        vec![
            chooser_read_only("locked", false),
            chooser_read_only("all", true),
        ],
    )
    .await;
    open.answer(json!([
        { "reference": "one", "data": "one" },
        { "reference": "two", "data": "two" }
    ]))
    .await;
    let one = option_key(&json!({ "reference": "one", "data": "one" }));
    let two = option_key(&json!({ "reference": "two", "data": "two" }));

    let single = open
        .run(&form, "locked", json!({ "region": option("eu") }), 1)
        .await;
    let multiple = open
        .run(&form, "all", json!({ "region": option("eu") }), 1)
        .await;

    let locked = field(&single.form, "locked");
    assert_eq!(locked.options.len(), 2);
    assert_eq!(locked.value, Some(AttrValue::Option(one.clone())));
    assert_eq!(locked.value_set_at, single.form.revision);
    let all = field(&multiple.form, "all");
    assert_eq!(
        all.value,
        Some(AttrValue::Options(vec![
            AttrValue::Option(one),
            AttrValue::Option(two)
        ]))
    );
    assert_eq!(all.changed_at, multiple.form.revision);
}

#[tokio::test]
async fn every_change_of_the_form_raises_the_revision_and_an_answer_that_sets_a_value_does_so_though_the_content_is_the_same()
 {
    let open = Open::new().await;
    let form = extras_definitions(&open, vec![pinned(json!({ "dependsOn": ["region"] }))]).await;
    open.answer(json!([{ "data": "1", "contentType": "string" }]))
        .await;

    let options = open
        .run(&form, "pin", json!({ "region": option("eu") }), 1)
        .await;
    let same = open
        .run(&form, "pin", json!({ "region": option("eu") }), 2)
        .await;
    open.world.ilm.reset().await;
    open.answer(json!([attribute("email", "string", 2, json!({}))]))
        .await;
    let fields = open
        .run(&form, "extras", json!({ "region": option("eu") }), 1)
        .await;
    let cleared = open.run(&form, "extras", json!({}), 2).await;

    assert_eq!(options.form.revision, 1);
    assert_eq!(same.form.revision, 2);
    assert_eq!(fields.form.revision, 3);
    assert_eq!(cleared.form.revision, 4);
}

#[tokio::test]
async fn a_check_names_the_revision_it_was_made_against() {
    let open = Open::new().await;
    let form = open.issue_form().await;
    assert_eq!(check(&open, &form, json!({})).revision, 0);
    open.answer(json!([{ "data": "eu", "contentType": "string" }]))
        .await;
    open.run(&form, "region", json!({}), 1).await;

    assert_eq!(check(&open, &form, json!({})).revision, 1);
}
