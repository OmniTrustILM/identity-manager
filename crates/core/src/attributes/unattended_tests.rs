use serde_json::{Value as Json, json};

use super::fixtures::{
    default_request_set, definition, demo_request_set, issue_attributes, read, upn_request_set,
    with,
};
use super::{Definitions, Needs, Value, Values, defaults, unattended};

fn needs(raw: Vec<Json>) -> Needs {
    unattended(&read(&raw)).unwrap_err()
}

fn one(raw: Json) -> Vec<Json> {
    vec![raw]
}

fn with_callback(raw: Json) -> Json {
    with(
        raw,
        "attributeCallback",
        json!({ "callbackContext": "core/getThings", "callbackMethod": "GET", "mappings": [] }),
    )
}

#[test]
fn definitions_that_all_have_defaults_give_those_values() {
    let definitions = read(&demo_request_set());

    let values = unattended(&definitions).unwrap();

    assert_eq!(values, defaults(&definitions.fields));
    assert_eq!(
        values.get("common-name"),
        Some(&Value::Text("demo220".into()))
    );
}

#[test]
fn nothing_to_fill_is_nothing_needed() {
    assert_eq!(unattended(&Definitions::default()).unwrap(), Values::new());
}

#[test]
fn optional_fields_without_a_default_need_nothing() {
    assert!(unattended(&read(&upn_request_set())).is_ok());
}

#[test]
fn a_required_attribute_this_application_cannot_show_blocks() {
    let raw = definition(3, "data", "odd", "bogus", json!({ "required": true }));

    assert_eq!(needs(one(raw)), Needs::Blocked);
}

#[test]
fn a_required_fixed_field_without_content_blocks() {
    let raw = definition(
        3,
        "data",
        "fixed",
        "string",
        json!({ "required": true, "readOnly": true }),
    );

    assert_eq!(needs(one(raw)), Needs::Blocked);
}

#[test]
fn a_callback_on_an_editable_field_needs_the_person() {
    let raw = with_callback(definition(3, "data", "field", "string", json!({})));

    assert_eq!(needs(one(raw)), Needs::Callback);
}

#[test]
fn a_callback_on_a_group_needs_the_person() {
    let group = json!({
        "uuid": "00000000-0000-4000-8000-0000000000e1",
        "name": "extension",
        "version": 2,
        "type": "group",
        "content": [],
        "attributeCallback": { "callbackContext": "core/getThings", "callbackMethod": "GET" }
    });

    assert_eq!(needs(one(group)), Needs::Callback);
}

#[test]
fn a_callback_on_a_field_the_person_cannot_edit_needs_nothing() {
    let raw = with(
        with_callback(definition(
            3,
            "data",
            "field",
            "string",
            json!({ "readOnly": true }),
        )),
        "content",
        json!([{ "data": "fixed", "contentType": "string" }]),
    );

    assert!(unattended(&read(&one(raw))).is_ok());
}

#[test]
fn a_required_secret_credential_or_resource_needs_the_person() {
    for (version, content_type) in [(3, "secret"), (2, "credential"), (3, "resource")] {
        let raw = definition(
            version,
            "data",
            "field",
            content_type,
            json!({ "required": true, "resource": "secrets" }),
        );

        assert_eq!(needs(one(raw)), Needs::Secret, "{content_type}");
    }
}

#[test]
fn an_optional_secret_needs_nothing() {
    let raw = definition(3, "data", "field", "secret", json!({}));

    assert!(unattended(&read(&one(raw))).is_ok());
}

#[test]
fn a_required_field_without_a_default_needs_the_person() {
    assert_eq!(needs(default_request_set()), Needs::Required);
}

#[test]
fn a_default_that_breaks_a_constraint_needs_the_person() {
    let raw = with(
        with(
            definition(3, "data", "field", "string", json!({})),
            "content",
            json!([{ "data": "abc", "contentType": "string" }]),
        ),
        "constraints",
        json!([{ "type": "regExp", "data": "[0-9]+" }]),
    );

    assert_eq!(needs(one(raw)), Needs::Invalid);
}

#[test]
fn issue_attributes_with_a_credential_and_callbacks_need_the_person() {
    assert_eq!(needs(issue_attributes()), Needs::Callback);
}

#[test]
fn a_required_yes_or_no_without_an_answer_needs_the_person() {
    let raw = definition(3, "data", "agree", "boolean", json!({ "required": true }));

    assert_eq!(needs(one(raw)), Needs::Required);
}

#[test]
fn a_required_yes_or_no_that_ilm_answers_needs_nothing() {
    let raw = with(
        definition(3, "data", "agree", "boolean", json!({ "required": true })),
        "content",
        json!([{ "data": false, "contentType": "boolean" }]),
    );

    assert_eq!(
        unattended(&read(&one(raw))).unwrap().get("agree"),
        Some(&Value::Bool(false))
    );
}
