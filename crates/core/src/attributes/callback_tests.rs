use serde_json::{Value as Json, json};

use super::fixtures::{definition, read, with};
use super::{
    Definitions, FormContext, Resolution, Value, Values, cleared_with, option_key, resolve,
};
use crate::ilm::attributes::{CallbackBody, CallbackRoute};

fn issue() -> FormContext {
    FormContext::Issue {
        authority: "auth-1".into(),
        ra_profile: "ra-1".into(),
    }
}

fn route() -> CallbackRoute {
    CallbackRoute::Resource {
        resource: "certificates".into(),
        parent: "ra-1".into(),
    }
}

fn legacy(mappings: Json) -> Json {
    json!({ "callbackContext": "core/getCredentials", "callbackMethod": "GET", "mappings": mappings })
}

fn next(depends_on: &[&str]) -> Json {
    json!({ "dependsOn": depends_on })
}

fn data(name: &str, content_type: &str, properties: Json, callback: Option<Json>) -> Json {
    let raw = definition(3, "data", name, content_type, properties);
    match callback {
        Some(callback) => with(raw, "attributeCallback", callback),
        None => raw,
    }
}

fn list(name: &str, items: Json, callback: Option<Json>) -> Json {
    with(
        data(name, "string", json!({ "list": true }), callback),
        "content",
        items,
    )
}

fn call(definitions: &Definitions, name: &str, values: &Values) -> Option<CallbackBody> {
    match resolve(&issue(), definitions, name, values) {
        Resolution::Call(found, body) => {
            assert_eq!(found, route());
            Some(*body)
        }
        _ => None,
    }
}

fn mapping(from: Option<&str>, value: Json) -> Json {
    let mut mapping = json!({ "to": "out", "targets": ["pathVariable", "body"] });
    if let Some(from) = from {
        mapping["from"] = json!(from);
    }
    if !value.is_null() {
        mapping["value"] = value;
    }
    mapping
}

fn values(pairs: &[(&str, Value)]) -> Values {
    pairs
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect()
}

#[test]
fn a_static_value_goes_to_every_target_with_the_attribute_named() {
    let found = read(&[data(
        "target",
        "string",
        json!({}),
        Some(legacy(json!([mapping(None, json!("Basic"))]))),
    )]);
    let body = call(&found, "target", &Values::new()).unwrap();
    assert_eq!(body.name, "target");
    assert_eq!(body.path_variable["out"], json!("Basic"));
    assert_eq!(body.body["out"], json!("Basic"));
    assert!(body.request_parameter.is_empty() && body.filter.is_empty());
    assert!(body.attributes.is_empty());
}

#[test]
fn a_falsy_static_value_falls_through_to_from_and_without_from_resolves_nothing() {
    let found = read(&[
        data("page", "integer", json!({}), None),
        data(
            "with-from",
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some("page"), json!(0))]))),
        ),
        data(
            "without-from",
            "string",
            json!({}),
            Some(legacy(json!([mapping(None, json!(false))]))),
        ),
    ]);
    let given = values(&[("page", Value::Integer("5".into()))]);
    let body = call(&found, "with-from", &given).unwrap();
    assert_eq!(body.path_variable["out"], json!(5));
    assert_eq!(
        resolve(&issue(), &found, "without-from", &given),
        Resolution::Skip
    );
}

#[test]
fn from_reads_the_value_by_path_then_data_then_uuid() {
    let credentials = with(
        data("cred", "credential", json!({}), None),
        "content",
        json!([{ "reference": "main", "data": { "uuid": "u-1", "name": "main" } }]),
    );
    let tags = list(
        "tags",
        json!([{ "data": "IT", "contentType": "string" }, { "data": "HR", "contentType": "string" }]),
        None,
    );
    let multi = with(
        with(
            data(
                "many",
                "string",
                json!({ "list": true, "multiSelect": true }),
                None,
            ),
            "content",
            json!([{ "data": "a" }, { "data": "b" }]),
        ),
        "version",
        json!(2),
    );
    let mut raw = vec![credentials, tags, multi];
    for (name, from) in [
        ("by-name", "cred.name"),
        ("by-uuid-path", "cred.uuid"),
        ("whole", "cred"),
        ("plain", "tags"),
        ("first", "many"),
    ] {
        raw.push(data(
            name,
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some(from), Json::Null)]))),
        ));
    }
    let found = read(&raw);
    let pick = |name: &str, index: usize| {
        let field = found
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap();
        Value::Option(option_key(&field.content[index]))
    };
    let given = values(&[
        ("cred", pick("cred", 0)),
        ("tags", pick("tags", 1)),
        (
            "many",
            Value::Options(vec![pick("many", 1), pick("many", 0)]),
        ),
    ]);
    let out = |name: &str| {
        call(&found, name, &given)
            .unwrap_or_else(|| panic!("{name}"))
            .path_variable["out"]
            .clone()
    };
    assert_eq!(out("by-name"), json!("main"));
    assert_eq!(out("by-uuid-path"), json!("u-1"));
    assert_eq!(out("whole"), json!("u-1"));
    assert_eq!(out("plain"), json!("HR"));
    assert_eq!(out("first"), json!("b"));
}

#[test]
fn any_mapping_that_does_not_resolve_means_no_call() {
    let found = read(&[
        data("known", "string", json!({}), None),
        data(
            "partial",
            "string",
            json!({}),
            Some(legacy(json!([
                mapping(None, json!("fixed")),
                mapping(Some("known"), Json::Null)
            ]))),
        ),
        data(
            "unknown",
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some("nobody.x"), Json::Null)]))),
        ),
        data(
            "path-missing",
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some("known.deeper"), Json::Null)]))),
        ),
    ]);
    let empty = values(&[("known", Value::Text("  ".into()))]);
    for name in ["partial", "unknown", "path-missing", "known", "absent"] {
        assert_eq!(resolve(&issue(), &found, name, &empty), Resolution::Skip);
    }
    let filled = values(&[("known", Value::Text("x".into()))]);
    assert!(call(&found, "partial", &filled).is_some());
}

#[test]
fn a_field_the_person_does_not_edit_gives_what_ilm_defined() {
    let fixed = with(
        data("fixed", "string", json!({ "readOnly": true }), None),
        "content",
        json!([{ "data": "from ILM" }]),
    );
    let found = read(&[
        fixed,
        data(
            "asks",
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some("fixed"), Json::Null)]))),
        ),
    ]);
    let body = call(&found, "asks", &Values::new()).unwrap();
    assert_eq!(body.path_variable["out"], json!("from ILM"));
}

#[test]
fn a_hidden_list_gives_what_ilm_defined_though_it_is_not_read_only() {
    let hidden = |name: &str, multi: bool| {
        with(
            with(
                data(
                    name,
                    "string",
                    json!({ "list": true, "visible": false, "multiSelect": multi }),
                    None,
                ),
                "content",
                json!([{ "data": "one" }, { "data": "two" }]),
            ),
            "name",
            json!(name),
        )
    };
    let asking = |name: &str, from: &str| {
        data(
            name,
            "string",
            json!({}),
            Some(legacy(json!([mapping(Some(from), Json::Null)]))),
        )
    };
    let found = read(&[
        hidden("single", false),
        hidden("many", true),
        asking("asks_one", "single"),
        asking("asks_many", "many"),
    ]);
    let one = call(&found, "asks_one", &Values::new()).unwrap();
    let many = call(&found, "asks_many", &Values::new()).unwrap();
    assert_eq!(one.path_variable["out"], json!("one"));
    assert_eq!(many.path_variable["out"], json!("one"));
}

#[test]
fn a_dependency_free_callback_asks_at_once_and_one_with_dependencies_sends_theirs() {
    let found = read(&[
        list(
            "region",
            json!([{ "data": "eu", "contentType": "string" }]),
            Some(next(&[])),
        ),
        list("zone", json!([]), Some(next(&["region"]))),
    ]);
    let body = call(&found, "region", &Values::new()).unwrap();
    assert!(body.attributes.is_empty());
    let eu = Value::Option(option_key(&found.fields[0].content[0]));
    let body = call(&found, "zone", &values(&[("region", eu)])).unwrap();
    assert_eq!(body.uuid, found.fields[1].uuid);
    assert_eq!(
        body.attributes,
        vec![json!({
            "uuid": found.fields[0].uuid,
            "name": "region",
            "contentType": "string",
            "version": "v3",
            "content": [{ "data": "eu", "contentType": "string" }],
        })]
    );
}

#[test]
fn a_dependency_without_a_value_clears_and_one_the_form_lacks_skips() {
    let found = read(&[
        list("region", json!([{ "data": "eu" }]), None),
        list("zone", json!([]), Some(next(&["region"]))),
        list("lost", json!([]), Some(next(&["nobody"]))),
    ]);
    assert_eq!(
        resolve(&issue(), &found, "zone", &Values::new()),
        Resolution::Cleared
    );
    assert_eq!(
        resolve(&issue(), &found, "lost", &Values::new()),
        Resolution::Skip
    );
}

#[test]
fn custom_attributes_and_attributes_without_a_callback_make_no_call() {
    let found = read(&[
        data("plain", "string", json!({}), None),
        data("asks", "string", json!({}), Some(next(&[]))),
    ]);
    assert_eq!(
        resolve(&FormContext::Custom, &found, "asks", &Values::new()),
        Resolution::Skip
    );
    assert_eq!(
        resolve(&issue(), &found, "plain", &Values::new()),
        Resolution::Skip
    );
}

#[test]
fn request_attributes_have_no_callback_route() {
    let found = read(&[data("asks", "string", json!({}), Some(next(&[])))]);
    let request = FormContext::Request {
        authority: "auth-1".into(),
        ra_profile: "ra-1".into(),
    };
    assert_eq!(request.kind(), "request attributes");
    assert_eq!(
        resolve(&request, &found, "asks", &Values::new()),
        Resolution::Skip
    );
}

#[test]
fn a_group_attribute_runs_its_callback_by_its_own_name_and_uuid() {
    let found = read(&[json!({
        "uuid": "g-1",
        "name": "extension",
        "version": 2,
        "type": "group",
        "content": [],
        "attributeCallback": legacy(json!([mapping(None, json!("Basic"))])),
    })]);
    let body = call(&found, "extension", &Values::new()).unwrap();
    assert_eq!(
        (body.uuid.as_str(), body.name.as_str()),
        ("g-1", "extension")
    );
}

#[test]
fn a_cleared_dependency_clears_the_fields_that_follow_it_again_and_again() {
    let found = read(&[
        list("a", json!([]), None),
        list("b", json!([]), Some(next(&["a"]))),
        list("c", json!([]), Some(next(&["b"]))),
        list("d", json!([]), Some(next(&["a", "c"]))),
        list(
            "legacy",
            json!([]),
            Some(legacy(json!([mapping(Some("a"), Json::Null)]))),
        ),
        list("other", json!([]), Some(next(&["elsewhere"]))),
    ]);
    assert_eq!(cleared_with(&found, "a"), ["a", "b", "d", "c"]);
    assert_eq!(cleared_with(&found, "c"), ["c", "d"]);
    assert_eq!(cleared_with(&found, "d"), ["d"]);
}
