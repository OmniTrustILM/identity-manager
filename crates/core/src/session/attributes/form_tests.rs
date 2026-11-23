//! The commit path of a form without a session: what moves the revision and the stamps of its fields, and the
//! registry rules a racing run cannot show through the session.

use serde_json::{Value as Json, json};

use super::Form;
use crate::attributes::{Definitions, FormContext, Stamp, Value, Values, option_key};
use crate::ilm::attributes::CallbackAnswer;

fn definition(name: &str, properties: Json, content: Json, callback: Option<Json>) -> Json {
    let mut properties = properties;
    properties["label"] = json!(name);
    let mut raw = json!({
        "uuid": format!("uuid-{name}"),
        "name": name,
        "version": 3,
        "schemaVersion": "v3",
        "type": "data",
        "contentType": "string",
        "properties": properties,
        "content": content,
    });
    if let Some(callback) = callback {
        raw["attributeCallback"] = callback;
    }
    raw
}

fn eu() -> Json {
    json!([{ "data": "eu", "contentType": "string" }])
}

fn eu_items() -> Vec<Json> {
    vec![json!({ "data": "eu", "contentType": "string" })]
}

fn group(name: &str) -> Json {
    json!({ "uuid": format!("uuid-{name}"), "name": name, "type": "group", "attributeCallback": { "dependsOn": [] } })
}

fn form() -> Form {
    let base = Definitions::read(&[
        definition("region", json!({ "list": true }), eu(), None),
        definition(
            "zone",
            json!({ "list": true }),
            eu(),
            Some(json!({ "dependsOn": ["region"] })),
        ),
        definition("note", json!({}), json!([]), None),
        group("extras"),
    ]);
    Form::new("form".into(), FormContext::Custom, None, base)
}

fn stamp(open: &Form, name: &str) -> Stamp {
    Stamp {
        value: None,
        ..open.stamps.get(name).cloned().unwrap_or_default()
    }
}

fn names(open: &Form) -> Vec<String> {
    open.view()
        .groups
        .iter()
        .flat_map(|group| group.fields.iter().map(|field| field.name.clone()))
        .collect()
}

#[test]
fn a_clear_of_a_superseded_run_changes_nothing() {
    let mut open = form();
    open.latest.insert("zone".into(), 3);

    assert!(!open.clear_current("zone", 2, vec!["zone".into()], &Values::new()));

    assert_eq!(open.revision, 0);
    assert!(!open.field_mut("zone").unwrap().content.is_empty());
}

#[test]
fn a_clear_of_a_fenced_run_changes_nothing() {
    let mut open = form();
    open.fenced.insert("zone".into(), 2);

    assert!(!open.clear_current("zone", 2, vec!["zone".into()], &Values::new()));
    assert!(!open.field_mut("zone").unwrap().content.is_empty());
}

#[test]
fn a_clear_of_the_current_run_empties_the_field_and_stamps_it() {
    let mut open = form();
    open.latest.insert("zone".into(), 2);

    assert!(open.clear_current("zone", 2, vec!["zone".into()], &Values::new()));

    assert!(open.field_mut("zone").unwrap().content.is_empty());
    assert_eq!(open.revision, 1);
    assert_eq!(
        stamp(&open, "zone"),
        Stamp {
            changed_at: 1,
            value_set_at: 1,
            ..Stamp::default()
        }
    );
}

#[test]
fn a_clear_of_a_field_nobody_can_have_filled_changes_nothing_but_one_the_person_typed_into_is_stamped()
 {
    let mut open = form();
    let mut hidden = Definitions::read(&[definition(
        "hidden",
        json!({ "visible": false }),
        json!([]),
        None,
    )]);
    open.base.fields.append(&mut hidden.fields);
    open.field_mut("zone").unwrap().content.clear();

    assert!(open.clear_current("hidden", 1, vec!["hidden".into()], &Values::new()));
    assert_eq!(open.revision, 0);

    assert!(open.clear_current("zone", 1, vec!["zone".into()], &Values::new()));
    assert_eq!(open.revision, 0);

    let typed = Values::from([("zone".to_owned(), Value::Text("eu".into()))]);
    assert!(open.clear_current("zone", 2, vec!["zone".into()], &typed));
    assert_eq!(
        stamp(&open, "zone"),
        Stamp {
            changed_at: 1,
            value_set_at: 1,
            ..Stamp::default()
        }
    );
}

#[test]
fn an_answer_with_new_options_leaves_the_choice_of_a_list_to_the_person() {
    let mut open = form();
    let items = vec![json!({ "data": "us", "contentType": "string" })];

    assert!(open.apply("zone", CallbackAnswer::Content(items)));

    assert_eq!(open.revision, 1);
    assert_eq!(
        stamp(&open, "zone"),
        Stamp {
            changed_at: 1,
            value_set_at: 0,
            ..Stamp::default()
        }
    );
}

#[test]
fn an_answer_that_leaves_a_required_list_one_option_sets_its_value() {
    let mut open = form();
    open.field_mut("zone").unwrap().required = true;
    let only = json!({ "data": "us", "contentType": "string" });

    assert!(open.apply("zone", CallbackAnswer::Content(vec![only.clone()])));

    assert_eq!(
        stamp(&open, "zone"),
        Stamp {
            changed_at: 1,
            value_set_at: 1,
            ..Stamp::default()
        }
    );
    let zone = open.view().groups[0].fields[1].clone();
    assert_eq!(
        zone.value,
        Some(crate::attributes::Value::Option(option_key(&only)))
    );
}

#[test]
fn an_answer_for_a_field_without_a_list_sets_its_value() {
    let mut open = form();

    assert!(open.apply("note", CallbackAnswer::Content(eu_items())));

    assert_eq!(
        stamp(&open, "note"),
        Stamp {
            changed_at: 1,
            value_set_at: 1,
            ..Stamp::default()
        }
    );
}

#[test]
fn an_answer_that_does_not_fit_changes_nothing() {
    let mut open = form();

    assert!(!open.apply("nobody", CallbackAnswer::Content(eu_items())));
    assert!(!open.apply("zone", CallbackAnswer::Definitions(Vec::new())));

    assert_eq!(open.revision, 0);
}

#[test]
fn a_group_answer_installs_its_fields_and_the_same_answer_again_changes_nothing() {
    let mut open = form();
    let fields = vec![definition("email", json!({}), json!([]), None)];

    assert!(open.apply("extras", CallbackAnswer::Definitions(fields.clone())));
    assert_eq!(names(&open), ["region", "zone", "note", "extras", "email"]);
    assert_eq!(
        stamp(&open, "email"),
        Stamp {
            changed_at: 1,
            value_set_at: 1,
            reset_at: 1,
            ..Stamp::default()
        }
    );

    assert!(open.apply("extras", CallbackAnswer::Definitions(fields)));
    assert_eq!(open.revision, 1);
}

#[test]
fn replacing_a_groups_fields_clears_what_depended_on_the_old_ones() {
    let mut open = form();
    open.apply(
        "extras",
        CallbackAnswer::Definitions(vec![definition("email", json!({}), json!([]), None)]),
    );
    let mut pick = Definitions::read(&[definition(
        "pick",
        json!({ "list": true }),
        eu(),
        Some(json!({ "dependsOn": ["email"] })),
    )]);
    open.base.fields.append(&mut pick.fields);

    open.apply(
        "extras",
        CallbackAnswer::Definitions(vec![definition("phone", json!({}), json!([]), None)]),
    );

    assert_eq!(
        names(&open),
        ["region", "zone", "note", "pick", "extras", "phone"]
    );
    assert!(open.field_mut("pick").unwrap().content.is_empty());
    assert_eq!(
        stamp(&open, "pick"),
        Stamp {
            changed_at: 2,
            value_set_at: 2,
            reset_at: 2,
            ..Stamp::default()
        }
    );
    assert_eq!(
        stamp(&open, "phone"),
        Stamp {
            changed_at: 2,
            value_set_at: 2,
            reset_at: 2,
            ..Stamp::default()
        }
    );
}

#[test]
fn an_empty_answer_removes_what_a_group_added() {
    let mut open = form();
    open.apply(
        "extras",
        CallbackAnswer::Definitions(vec![definition("email", json!({}), json!([]), None)]),
    );

    assert!(open.apply("extras", CallbackAnswer::Content(Vec::new())));

    assert_eq!(names(&open), ["region", "zone", "note", "extras"]);
    assert_eq!(open.revision, 2);
}

#[test]
fn every_blocker_is_in_the_snapshot() {
    let mut open = form();
    let locked = definition(
        "locked",
        json!({ "required": true, "readOnly": true }),
        json!([{ "data": "x", "contentType": "string" }]),
        Some(json!({ "dependsOn": ["region"] })),
    );
    open.apply("extras", CallbackAnswer::Definitions(vec![
        locked,
        json!({ "name": "odd", "type": "data", "contentType": "mystery", "properties": { "label": "Odd", "required": true } }),
    ]));
    assert_eq!(open.view().unsupported, ["Odd"]);

    open.apply("locked", CallbackAnswer::Content(Vec::new()));

    assert_eq!(open.view().unsupported, ["Odd", "locked"]);
}

fn pick() -> Form {
    let mut open = form();
    let mut pick = Definitions::read(&[definition(
        "pick",
        json!({ "list": true, "required": true }),
        json!([]),
        None,
    )]);
    open.base.fields.append(&mut pick.fields);
    open
}

fn view_of(open: &Form, name: &str) -> crate::attributes::FieldView {
    open.view()
        .groups
        .iter()
        .flat_map(|group| group.fields.iter())
        .find(|field| field.name == name)
        .cloned()
        .unwrap()
}

fn item(data: &str) -> Json {
    json!({ "data": data, "contentType": "string" })
}

#[test]
fn the_value_ilm_set_stays_when_the_options_grow_and_goes_when_its_key_is_no_longer_offered() {
    let mut open = pick();
    open.apply("pick", CallbackAnswer::Content(vec![item("sales")]));
    let sales = Some(crate::attributes::Value::Option(option_key(&item("sales"))));
    assert_eq!(view_of(&open, "pick").value, sales);

    open.apply(
        "pick",
        CallbackAnswer::Content(vec![item("it"), item("sales")]),
    );
    let grown = view_of(&open, "pick");
    assert_eq!(grown.value, sales);
    assert_eq!(grown.value_set_at, 1);
    assert_eq!(grown.changed_at, 2);

    open.apply(
        "pick",
        CallbackAnswer::Content(vec![item("ap"), item("it")]),
    );
    assert_eq!(view_of(&open, "pick").value, None);
}

#[test]
fn an_answer_that_sets_or_clears_a_value_is_stamped_though_the_content_is_the_same() {
    let mut open = form();

    open.apply("note", CallbackAnswer::Content(eu_items()));
    open.apply("note", CallbackAnswer::Content(eu_items()));
    assert_eq!(stamp(&open, "note").value_set_at, 2);
    assert_eq!(open.revision, 2);
    assert_eq!(stamp(&open, "note").changed_at, 1);

    open.apply("note", CallbackAnswer::Content(Vec::new()));
    open.apply("note", CallbackAnswer::Content(Vec::new()));
    assert_eq!(stamp(&open, "note").value_set_at, 4);
    assert_eq!(stamp(&open, "note").changed_at, 3);
    assert_eq!(view_of(&open, "note").value, None);
}

#[test]
fn an_answer_that_only_switches_a_string_to_a_callback_answer_commits() {
    let mut open = form();

    assert!(open.apply("zone", CallbackAnswer::Content(eu_items())));

    assert_eq!(open.revision, 1);
    assert_eq!(stamp(&open, "zone").changed_at, 1);
    assert_eq!(stamp(&open, "zone").value_set_at, 0);
}

#[test]
fn a_field_is_reset_when_a_clear_or_a_group_reaches_it_and_not_by_its_own_answer() {
    let mut open = form();
    open.latest.insert("region".into(), 1);

    open.clear_current("region", 1, vec!["region".into()], &Values::new());
    assert_eq!(stamp(&open, "region").reset_at, 0);
    assert_eq!(stamp(&open, "zone").reset_at, 1);

    open.apply(
        "extras",
        CallbackAnswer::Definitions(vec![definition("email", json!({}), json!([]), None)]),
    );
    assert_eq!(stamp(&open, "email").reset_at, 2);
    assert_eq!(stamp(&open, "extras").reset_at, 0);

    open.apply("note", CallbackAnswer::Content(eu_items()));
    assert_eq!(stamp(&open, "note").reset_at, 0);
}

#[test]
fn an_options_commit_that_retires_the_retained_value_leaves_it_out_without_a_stamp() {
    let mut open = pick();
    open.apply("pick", CallbackAnswer::Content(vec![item("sales")]));
    open.apply(
        "pick",
        CallbackAnswer::Content(vec![item("ap"), item("it")]),
    );
    let retired = view_of(&open, "pick");
    assert_eq!(retired.value, None);
    assert_eq!(retired.value_set_at, 1);
    assert_eq!(retired.changed_at, 2);
}

#[test]
fn a_dependency_clear_leaves_a_required_boolean_at_its_reset_value_as_no_edit() {
    let mut open = form();
    let boolean = |mut raw: Json| {
        raw["contentType"] = json!("boolean");
        raw
    };
    let mut pair = Definitions::read(&[
        boolean(definition(
            "a",
            json!({ "required": true }),
            json!([]),
            Some(json!({ "dependsOn": ["b"] })),
        )),
        boolean(definition(
            "b",
            json!({ "required": true }),
            json!([]),
            Some(json!({ "dependsOn": ["a"] })),
        )),
    ]);
    open.base.fields.append(&mut pair.fields);
    let both = || vec!["a".to_owned(), "b".to_owned()];
    let reset = Values::from([
        ("a".to_owned(), Value::Bool(false)),
        ("b".to_owned(), Value::Bool(false)),
    ]);

    open.clear_current("a", 1, both(), &reset);
    assert_eq!(open.revision, 0);

    let edited = Values::from([("b".to_owned(), Value::Bool(true))]);
    open.clear_current("a", 2, both(), &edited);
    assert_eq!(open.revision, 1);
}

#[test]
fn editable_fields_that_watch_each_other_stop_notifying_once_both_are_empty() {
    let mut open = form();
    let mut pair = Definitions::read(&[
        definition(
            "a",
            json!({}),
            json!([]),
            Some(json!({ "dependsOn": ["b"] })),
        ),
        definition(
            "b",
            json!({}),
            json!([]),
            Some(json!({ "dependsOn": ["a"] })),
        ),
    ]);
    open.base.fields.append(&mut pair.fields);
    let both = || vec!["a".to_owned(), "b".to_owned()];
    let typed = Values::from([("a".to_owned(), Value::Text("x".into()))]);

    assert!(open.clear_current("a", 1, both(), &typed));
    assert_eq!(open.revision, 1);

    assert!(open.clear_current("b", 1, both(), &Values::new()));
    assert!(open.clear_current("a", 2, both(), &Values::new()));
    assert_eq!(open.revision, 1);
}

#[test]
fn a_groups_answer_replaces_the_fields_its_static_content_defined() {
    let mut raw = group("extras");
    raw["content"] = json!([definition(
        "initial",
        json!({ "required": true }),
        json!([]),
        None
    )]);
    let mut open = Form::new(
        "form".into(),
        FormContext::Custom,
        None,
        Definitions::read(&[raw]),
    );
    assert_eq!(names(&open), ["extras", "initial"]);

    let answer = vec![definition("email", json!({}), json!([]), None)];
    assert!(open.apply("extras", CallbackAnswer::Definitions(answer)));

    assert_eq!(names(&open), ["extras", "email"]);
    let definitions = open.definitions();
    assert!(
        definitions
            .fields
            .iter()
            .all(|field| field.name != "initial")
    );
    assert_eq!(open.view().unsupported, Vec::<String>::new());
}
