use jiff::tz::{Offset, TimeZone};
use serde_json::{Value as Json, json};

use super::fixtures::{
    certificate_custom, definition, every_type, issue_attributes, odd_ones, read,
    request_attributes, with,
};
use super::*;

fn field<'a>(definitions: &'a Definitions, name: &str) -> &'a Definition {
    definitions
        .fields
        .iter()
        .find(|definition| definition.name == name)
        .unwrap_or_else(|| panic!("no field {name}"))
}

fn one(raw: Json) -> Definition {
    let found = read(&[raw]);
    assert!(found.unsupported.is_empty());
    found.fields.into_iter().next().unwrap()
}

fn data(content_type: &str, properties: Json) -> Definition {
    one(definition(3, "data", "field", content_type, properties))
}

fn with_content(raw: Json, content: Json) -> Definition {
    one(with(raw, "content", content))
}

fn with_constraints(content_type: &str, constraints: Json) -> Definition {
    one(with(
        definition(3, "data", "field", content_type, json!({})),
        "constraints",
        constraints,
    ))
}

fn values(name: &str, value: Value) -> Values {
    Values::from([(name.to_owned(), value)])
}

fn text(text: &str) -> Value {
    Value::Text(text.to_owned())
}

/// The choice of the option ILM gave as a string item `item`.
fn opt(item: &str) -> Value {
    Value::Option(option_key(
        &json!({ "data": item, "contentType": "string" }),
    ))
}

/// The choice of the option at `index` of the definition.
fn pick(definition: &Definition, index: usize) -> Value {
    Value::Option(option_key(&definition.content[index]))
}

/// The value as the interface sends it.
fn sent(value: &Value) -> Json {
    serde_json::to_value(value).unwrap()
}

mod definitions {
    use super::*;

    #[test]
    fn the_custom_attributes_of_certificates_are_read() {
        let found = read(&certificate_custom());
        assert_eq!(found.fields.len(), 8);
        assert!(found.unsupported.is_empty() && found.groups.is_empty());
        let department = field(&found, "department");
        assert_eq!(department.kind, Kind::Custom);
        assert_eq!(department.version, Version::V3);
        assert_eq!(department.content_type, ContentType::String);
        assert_eq!(department.group.as_deref(), Some("GroupMeNow"));
        assert!(department.list && department.multi_select && !department.extensible);
        assert!(department.visible && !department.required && !department.read_only);
        assert_eq!(department.description.as_deref(), Some("Owning department"));
        assert_eq!(department.content.len(), 2);
        assert!(field(&found, "Extensible List String").extensible);
        assert_eq!(field(&found, "TestInt").group, None);
    }

    #[test]
    fn a_missing_version_is_two_and_a_text_version_is_read() {
        let mut raw = definition(2, "data", "email", "string", json!({}));
        raw.as_object_mut().unwrap().remove("version");
        assert_eq!(one(raw.clone()).version, Version::V2);
        assert_eq!(
            one(with(raw.clone(), "version", json!("3"))).version,
            Version::V3
        );
        assert_eq!(one(with(raw, "version", Json::Null)).version, Version::V2);
    }

    #[test]
    fn every_content_type_is_read() {
        let found = read(&every_type());
        assert!(found.unsupported.is_empty());
        let types: Vec<&str> = found
            .fields
            .iter()
            .map(|definition| definition.content_type.code())
            .collect();
        assert_eq!(
            types,
            [
                "string",
                "text",
                "integer",
                "float",
                "boolean",
                "date",
                "time",
                "datetime",
                "secret",
                "file",
                "codeblock",
                "object",
                "credential",
                "resource"
            ]
        );
        assert!(field(&found, "a_secret").protected);
        assert!(field(&found, "a_credential").is_list());
        assert!(field(&found, "a_resource").is_list());
        assert!(!field(&found, "a_string").is_list());
    }

    #[test]
    fn a_version_three_secret_is_requested_as_version_two() {
        let secret = one(definition(3, "data", "pin", "secret", json!({})));
        assert_eq!(secret.request_version(), Version::V2);
        assert_eq!(data("string", json!({})).request_version(), Version::V3);
        assert_eq!(
            one(definition(2, "data", "x", "string", json!({}))).request_version(),
            Version::V2
        );
    }

    #[test]
    fn encrypted_protection_marks_an_attribute_protected() {
        let found = data("string", json!({ "protectionLevel": "encrypted" }));
        assert!(found.protected);
        assert!(!data("string", json!({ "protectionLevel": "none" })).protected);
    }

    #[test]
    fn a_required_fixed_attribute_without_content_but_with_a_callback_stays_a_field_that_blocks_the_form()
     {
        for properties in [json!({ "visible": false }), json!({ "readOnly": true })] {
            let mut properties = properties;
            properties["required"] = json!(true);
            let raw = with(
                definition(3, "data", "fixed", "string", properties),
                "attributeCallback",
                json!({ "dependsOn": [] }),
            );
            let found = read(&[raw]);
            assert!(found.unsupported.is_empty());
            assert_eq!(field(&found, "fixed").name, "fixed");
            assert_eq!(found.unshowable(), ["fixed label"]);
        }
    }

    #[test]
    fn a_required_hidden_or_read_only_attribute_without_content_blocks_the_form() {
        for properties in [json!({ "visible": false }), json!({ "readOnly": true })] {
            let mut properties = properties;
            properties["required"] = json!(true);
            let found = read(&[definition(3, "custom", "fixed", "string", properties)]);
            assert!(found.blocked());
            assert!(found.fields.is_empty());
            assert_eq!(found.unsupported[0].name, "fixed");
        }
        let filled = with(
            definition(
                3,
                "custom",
                "fixed",
                "string",
                json!({ "readOnly": true, "required": true }),
            ),
            "content",
            json!([{ "data": "x", "contentType": "string" }]),
        );
        assert!(!read(&[filled]).blocked());
        let optional = definition(3, "custom", "fixed", "string", json!({ "readOnly": true }));
        assert!(!read(&[optional]).blocked());
    }

    #[test]
    fn a_groups_static_content_is_read_as_its_fields() {
        let inner_group = json!({ "name": "inner", "type": "group", "content": [
            definition(3, "custom", "deep", "string", json!({}))
        ] });
        let outer = json!({ "name": "outer", "type": "group", "content": [
            definition(3, "custom", "child", "string", json!({ "required": true })),
            definition(3, "custom", "odd", "mystery", json!({ "required": true })),
            inner_group,
        ] });

        let found = read(&[outer]);

        let names: Vec<&str> = found.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["child", "deep"]);
        assert!(found.fields.iter().all(|f| f.group.is_some()));
        assert_eq!(field(&found, "child").group.as_deref(), Some("outer"));
        assert_eq!(field(&found, "deep").group.as_deref(), Some("inner"));
        assert_eq!(found.groups.len(), 2);
        assert!(found.blocked());
    }

    #[test]
    fn group_info_meta_and_what_cannot_be_shown_are_sorted_out() {
        let found = read(&odd_ones());
        assert_eq!(found.groups.len(), 1);
        assert_eq!(found.groups[0].name, "grouping");
        assert_eq!(found.groups[0].callback, None);
        assert_eq!(found.fields.len(), 1);
        assert_eq!(found.fields[0].kind, Kind::Info);
        assert_eq!(found.fields[0].content_type, ContentType::Text);
        let labels: Vec<(&str, bool)> = found
            .unsupported
            .iter()
            .map(|unsupported| (unsupported.label.as_str(), unsupported.required))
            .collect();
        assert_eq!(
            labels,
            [
                ("future-type label", true),
                ("future-optional label", false),
                ("future-version label", false),
                ("future-kind label", false),
                ("No name", false),
                ("no-label", false),
            ]
        );
        assert_eq!(found.unsupported[0].name, "future-type");
        assert!(found.blocked());
    }

    #[test]
    fn optional_unsupported_attributes_do_not_block() {
        let found = read(&[definition(3, "data", "future", "quaternion", json!({}))]);
        assert_eq!(found.unsupported.len(), 1);
        assert!(!found.blocked());
    }

    #[test]
    fn an_info_attribute_without_a_known_content_type_reads_as_text() {
        let found = read(&[definition(3, "info", "notice", "markdown", json!({}))]);
        assert_eq!(found.fields[0].content_type, ContentType::String);
    }

    #[test]
    fn callbacks_are_read_for_data_and_group_attributes() {
        let found = read(&issue_attributes());
        assert_eq!(found.fields.len(), 3);
        assert_eq!(field(&found, "email").callback, None);
        let callback = field(&found, "credential").callback.clone().unwrap();
        assert_eq!(callback.context.as_deref(), Some("core/getCredentials"));
        assert_eq!(callback.method.as_deref(), Some("GET"));
        assert_eq!(callback.depends_on, None);
        assert_eq!(
            callback.mappings,
            [
                Mapping {
                    from: Some("kind.data".into()),
                    to: "credentialKind".into(),
                    targets: vec![Target::PathVariable],
                    value: None,
                },
                Mapping {
                    from: None,
                    to: "page".into(),
                    targets: vec![Target::RequestParameter],
                    value: Some(json!(1)),
                },
            ]
        );
        let group = &found.groups[0];
        assert_eq!(group.name, "extension");
        assert_eq!(
            group.callback.as_ref().unwrap().mappings[0].value,
            Some(json!("Basic"))
        );
    }

    #[test]
    fn a_depends_on_list_marks_the_newer_callback_even_when_empty() {
        let callback = |raw: Json| {
            one(with(
                definition(3, "data", "field", "string", json!({})),
                "attributeCallback",
                raw,
            ))
            .callback
        };
        let empty = callback(json!({ "dependsOn": [] })).unwrap();
        assert_eq!(empty.depends_on, Some(Vec::new()));
        let named = callback(json!({ "dependsOn": ["a", "b", 3] })).unwrap();
        assert_eq!(named.depends_on, Some(vec!["a".into(), "b".into()]));
        assert_eq!(callback(json!({ "callbackMethod": "GET" })), None);
        assert_eq!(callback(json!("text")), None);
    }

    #[test]
    fn constraints_are_read_and_unknown_ones_ignored() {
        let found = with_constraints(
            "string",
            json!([
                { "data": "[a-z]+", "description": "letters", "errorMessage": "Letters only" },
                { "type": "regExp", "data": 5 },
                { "type": "range", "data": { "from": 1, "to": null } },
                { "type": "dateTime", "data": { "from": "2026-01-01T00:00:00" } },
                { "type": "jsonSchema", "data": "{}" },
                { "type": "regExp" },
                "text"
            ]),
        );
        assert_eq!(found.constraints.len(), 3);
        assert_eq!(found.constraints[0].rule, Rule::Pattern("[a-z]+".into()));
        assert_eq!(found.constraints[0].description.as_deref(), Some("letters"));
        assert_eq!(
            found.constraints[0].message.as_deref(),
            Some("Letters only")
        );
        assert_eq!(
            found.constraints[1].rule,
            Rule::Range {
                from: Some(1),
                to: None
            }
        );
        assert_eq!(
            found.constraints[2].rule,
            Rule::DateTime {
                from: Some("2026-01-01T00:00:00".into()),
                to: None
            }
        );
    }

    #[test]
    fn custom_attributes_have_no_constraints_and_no_callback() {
        let raw = with(
            with(
                definition(3, "custom", "c", "string", json!({})),
                "constraints",
                json!([{ "data": "x" }]),
            ),
            "attributeCallback",
            json!({ "dependsOn": [] }),
        );
        let found = one(raw);
        assert!(found.constraints.is_empty() && found.callback.is_none());
    }
}

mod values {
    use super::*;
    use crate::attributes::value::{parse_date, parse_datetime, parse_time};

    fn list(properties: Json) -> Definition {
        with_content(
            definition(3, "data", "field", "string", properties),
            json!([{ "data": "a", "contentType": "string" }, { "data": "b", "contentType": "string" }]),
        )
    }

    fn parsed(definition: Definition, sent: Json) -> Result<Values, ValueError> {
        parse_values(&[definition], &json!({ "field": sent }))
    }

    #[test]
    fn values_are_read_by_kind_against_the_definition() {
        let cases = [
            ("string", json!({ "kind": "text", "value": "x" }), text("x")),
            ("text", json!({ "kind": "text", "value": "x" }), text("x")),
            ("secret", json!({ "kind": "text", "value": "x" }), text("x")),
            (
                "integer",
                json!({ "kind": "integer", "value": "12" }),
                Value::Integer("12".into()),
            ),
            (
                "float",
                json!({ "kind": "float", "value": "1.5" }),
                Value::Float("1.5".into()),
            ),
            (
                "boolean",
                json!({ "kind": "bool", "value": true }),
                Value::Bool(true),
            ),
            (
                "date",
                json!({ "kind": "date", "value": "2026-01-02" }),
                Value::Date("2026-01-02".into()),
            ),
            (
                "time",
                json!({ "kind": "time", "value": "10:00" }),
                Value::Time("10:00".into()),
            ),
            (
                "datetime",
                json!({ "kind": "dateTime", "value": "2026-01-02T10:00" }),
                Value::DateTime("2026-01-02T10:00".into()),
            ),
            (
                "file",
                json!({ "kind": "file", "value": { "name": "a", "mime": "b", "content": "Yw==" } }),
                Value::File(FileValue {
                    name: "a".into(),
                    mime: "b".into(),
                    content: "Yw==".into(),
                }),
            ),
            (
                "codeblock",
                json!({ "kind": "code", "value": "x = 1" }),
                Value::Code("x = 1".into()),
            ),
            (
                "object",
                json!({ "kind": "object", "value": "{}" }),
                Value::Object("{}".into()),
            ),
        ];
        for (content_type, sent, expected) in cases {
            let found = parsed(data(content_type, json!({})), sent).unwrap();
            assert_eq!(found["field"], expected, "{content_type}");
        }
    }

    #[test]
    fn a_value_of_the_wrong_kind_is_refused() {
        let mismatch = Err(ValueError::Mismatch("field".into()));
        assert_eq!(
            parsed(
                data("integer", json!({})),
                json!({ "kind": "text", "value": "1" })
            ),
            mismatch
        );
        assert_eq!(parsed(data("string", json!({})), sent(&opt("a"))), mismatch);
        assert_eq!(
            parsed(data("string", json!({})), json!({ "kind": "nonsense" })),
            mismatch
        );
        assert_eq!(parsed(data("string", json!({})), json!(5)), mismatch);
        assert_eq!(
            parsed(
                list(json!({ "list": true })),
                json!({ "kind": "text", "value": "a" })
            ),
            mismatch
        );
    }

    #[test]
    fn values_that_are_not_an_object_are_malformed() {
        assert_eq!(parse_values(&[], &json!([1])), Err(ValueError::Malformed));
    }

    #[test]
    fn lists_take_options_and_extensible_lists_added_values() {
        let single = list(json!({ "list": true }));
        let found = parsed(single.clone(), sent(&opt("b"))).unwrap();
        assert_eq!(found["field"], opt("b"));
        let plain = json!({ "kind": "added", "value": { "kind": "text", "value": "c" } });
        assert!(parsed(single, plain.clone()).is_err());
        let extensible = list(json!({ "list": true, "extensibleList": true }));
        assert_eq!(
            parsed(extensible, plain.clone()).unwrap()["field"],
            Value::Added(Box::new(text("c")))
        );

        let many = json!({ "kind": "options", "value": [
            sent(&opt("a")),
            { "kind": "added", "value": { "kind": "text", "value": "c" } }
        ]});
        let multi = list(json!({ "list": true, "multiSelect": true }));
        assert!(parsed(multi, many.clone()).is_err());
        let multi = list(json!({ "list": true, "multiSelect": true, "extensibleList": true }));
        assert_eq!(
            parsed(multi.clone(), many).unwrap()["field"],
            Value::Options(vec![opt("a"), Value::Added(Box::new(text("c")))])
        );
        assert!(parsed(multi.clone(), sent(&opt("a"))).is_err());
        assert!(
            parsed(
                multi,
                json!({ "kind": "options", "value": [{ "kind": "text", "value": "x" }] })
            )
            .is_err()
        );
    }

    #[test]
    fn values_for_read_only_hidden_info_and_unknown_attributes_are_dropped() {
        let definitions = read(&[
            definition(3, "data", "locked", "string", json!({ "readOnly": true })),
            definition(3, "data", "unseen", "string", json!({ "visible": false })),
            definition(3, "info", "notice", "string", json!({})),
            definition(3, "data", "open", "string", json!({})),
        ])
        .fields;
        let wrong = json!({ "kind": "integer", "value": "1" });
        let sent = json!({
            "locked": wrong, "unseen": wrong, "notice": wrong, "stranger": wrong,
            "open": { "kind": "text", "value": "x" }
        });
        assert_eq!(
            parse_values(&definitions, &sent).unwrap(),
            values("open", text("x"))
        );
    }

    #[test]
    fn a_value_knows_when_nothing_was_entered() {
        assert!(text("").is_empty() && Value::Integer(" ".into()).is_empty());
        assert!(Value::Code(String::new()).is_empty() && Value::Options(Vec::new()).is_empty());
        assert!(Value::Added(Box::new(text(""))).is_empty());
        let file = FileValue {
            name: "a".into(),
            mime: "b".into(),
            content: String::new(),
        };
        assert!(Value::File(file).is_empty());
        assert!(!Value::Bool(false).is_empty() && !opt("a").is_empty() && !text("x").is_empty());
    }

    #[test]
    fn defaults_come_from_the_first_item() {
        let found = read(&every_type());
        let start = defaults(&found.fields);
        assert_eq!(start["a_string"], text("text"));
        assert_eq!(start["a_text"], text("lines"));
        assert_eq!(start["an_integer"], Value::Integer("7".into()));
        assert_eq!(start["a_float"], Value::Float("1.5".into()));
        assert_eq!(start["a_boolean"], Value::Bool(true));
        assert_eq!(start["a_date"], Value::Date("2026-02-28".into()));
        assert_eq!(start["a_time"], Value::Time("13:45:10".into()));
        assert_eq!(
            start["a_datetime"],
            Value::DateTime("2026-02-28T13:45:10.000+01:00".into())
        );
        assert_eq!(
            start["a_file"],
            Value::File(FileValue {
                name: "hello.txt".into(),
                mime: "text/plain".into(),
                content: "aGVsbG8=".into()
            })
        );
        assert_eq!(start["a_codeblock"], Value::Code("print(1)".into()));
        assert_eq!(start["an_object"], Value::Object(r#"{"key":[1,2]}"#.into()));
        for name in ["a_secret", "a_credential", "a_resource"] {
            assert!(!start.contains_key(name), "{name}");
        }
    }

    #[test]
    fn the_certificate_defaults_fill_only_what_ilm_defines() {
        let start = defaults(&read(&certificate_custom()).fields);
        assert_eq!(start.len(), 1);
        assert_eq!(start["qa_test_custom_attr"], text("qa was here"));
    }

    #[test]
    fn a_protected_attribute_is_never_filled_in() {
        let found = with_content(
            definition(
                3,
                "data",
                "pin",
                "string",
                json!({ "protectionLevel": "encrypted" }),
            ),
            json!([{ "data": "x", "contentType": "string" }]),
        );
        assert!(defaults(&[found]).is_empty());
    }

    #[test]
    fn a_required_boolean_without_content_starts_false() {
        let required = data("boolean", json!({ "required": true }));
        assert_eq!(defaults(&[required])["field"], Value::Bool(false));
        assert!(defaults(&[data("boolean", json!({}))]).is_empty());
    }

    #[test]
    fn a_list_starts_empty_unless_its_only_option_is_required() {
        assert!(defaults(&[list(json!({ "list": true }))]).is_empty());
        assert!(defaults(&[list(json!({ "list": true, "required": true }))]).is_empty());
        let single = with_content(
            definition(
                3,
                "data",
                "field",
                "string",
                json!({ "list": true, "required": true }),
            ),
            json!([{ "data": "a", "contentType": "string" }]),
        );
        assert_eq!(
            defaults(std::slice::from_ref(&single))["field"],
            pick(&single, 0)
        );
    }

    #[test]
    fn a_field_without_a_list_starts_with_its_first_items_data_and_an_answered_string_with_its_reference()
     {
        let field = |content: Json| {
            with_content(definition(3, "data", "field", "string", json!({})), content)
        };
        let items = json!([{ "data": "one" }, { "data": "two" }]);
        assert_eq!(defaults(&[field(items)])["field"], text("one"));
        assert!(defaults(&[field(json!([]))]).is_empty());
        let referenced = json!([{ "reference": "ref", "data": "other" }]);
        let mut answered = field(referenced);
        assert_eq!(defaults(&[answered.clone()])["field"], text("other"));
        answered.answered = true;
        assert_eq!(defaults(&[answered])["field"], text("ref"));
    }

    #[test]
    fn a_read_only_list_shows_what_it_defines() {
        let single = list(json!({ "list": true, "readOnly": true }));
        assert_eq!(defaults(&[single])["field"], opt("a"));
        let multi = list(json!({ "list": true, "multiSelect": true, "readOnly": true }));
        assert_eq!(
            defaults(&[multi])["field"],
            Value::Options(vec![opt("a"), opt("b")])
        );
    }

    #[test]
    fn dates_and_times_are_real() {
        assert_eq!(parse_date("2024-02-29").unwrap().to_string(), "2024-02-29");
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "2026-04-31",
            "26-01-01",
            "2026-1-1",
            "2026-01-01-01",
            "",
            "2100-02-29",
        ] {
            assert_eq!(parse_date(bad), None, "{bad}");
        }
        assert_eq!(parse_time("07:05").unwrap().to_string(), "07:05:00");
        assert_eq!(parse_time("23:59:59").unwrap().to_string(), "23:59:59");
        for bad in ["24:00", "10:60", "10:00:00:00", "1:00", "10:00.5", "ab:cd"] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_date_time_is_sent_in_utc_when_it_has_an_offset() {
        let cases = [
            ("2026-02-28T13:45:10.000+01:00", "2026-02-28T12:45:10.000Z"),
            ("2026-03-01T00:30+02:00", "2026-02-28T22:30:00.000Z"),
            ("2026-12-31T23:30:00-05:00", "2027-01-01T04:30:00.000Z"),
            ("2024-03-01T00:00:00+01:00", "2024-02-29T23:00:00.000Z"),
            ("2026-01-01T10:00:00.5Z", "2026-01-01T10:00:00.500Z"),
            ("2026-01-01T10:00:00.123456Z", "2026-01-01T10:00:00.123Z"),
        ];
        for (given, sent) in cases {
            assert_eq!(parse_datetime(given).unwrap().to_ilm(), sent, "{given}");
        }
    }

    #[test]
    fn a_date_time_without_an_offset_stays_local() {
        assert_eq!(
            parse_datetime("2026-01-01T10:00").unwrap().to_ilm(),
            "2026-01-01T10:00:00.000"
        );
    }

    #[test]
    fn a_malformed_date_time_is_not_read() {
        for bad in [
            "2026-01-01",
            "2026-01-01 10:00",
            "2026-01-01T25:00",
            "2026-01-01T10:00+25:00",
            "2026-01-01T10:00:00.Z",
            "2026-02-30T10:00",
            "T10:00",
        ] {
            assert!(parse_datetime(bad).is_none(), "{bad}");
        }
    }
}

mod validation {
    use super::*;

    fn problem(definition: &Definition, value: Option<Value>) -> Option<Problem> {
        let values = value
            .map(|value| values(&definition.name, value))
            .unwrap_or_default();
        check(std::slice::from_ref(definition), &values, &TimeZone::UTC)
            .into_iter()
            .next()
            .map(|found| found.problem)
    }

    #[test]
    fn a_required_field_needs_a_value() {
        let required = data("string", json!({ "required": true }));
        assert_eq!(problem(&required, None), Some(Problem::Required));
        assert_eq!(problem(&required, Some(text(""))), Some(Problem::Required));
        assert_eq!(problem(&required, Some(text("x"))), None);
        assert_eq!(problem(&data("string", json!({})), None), None);
        assert_eq!(problem(&data("string", json!({})), Some(text(""))), None);
    }

    #[test]
    fn a_required_boolean_is_filled_by_false() {
        let required = data("boolean", json!({ "required": true }));
        assert_eq!(problem(&required, Some(Value::Bool(false))), None);
        assert_eq!(problem(&required, None), Some(Problem::Required));
    }

    #[test]
    fn a_required_list_needs_a_choice() {
        let required = with_content(
            definition(
                3,
                "data",
                "field",
                "string",
                json!({ "list": true, "multiSelect": true, "required": true }),
            ),
            json!([{ "data": "a", "contentType": "string" }]),
        );
        assert_eq!(
            problem(&required, Some(Value::Options(Vec::new()))),
            Some(Problem::Required)
        );
        assert_eq!(
            problem(&required, Some(Value::Options(vec![opt("a")]))),
            None
        );
    }

    #[test]
    fn a_required_list_with_only_empty_added_values_counts_as_empty() {
        let required = with_content(
            definition(
                3,
                "data",
                "field",
                "string",
                json!({ "list": true, "multiSelect": true, "extensibleList": true, "required": true }),
            ),
            json!([{ "data": "a", "contentType": "string" }]),
        );
        let only_empty = Value::Options(vec![Value::Added(Box::new(text("")))]);
        assert_eq!(
            problem(&required, Some(only_empty)),
            Some(Problem::Required)
        );
        let mixed = Value::Options(vec![Value::Added(Box::new(text(""))), opt("a")]);
        assert_eq!(problem(&required, Some(mixed)), None);
    }

    #[test]
    fn an_integer_beyond_32_bits_is_not_an_integer() {
        let integer = data("integer", json!({}));
        for bad in ["2147483648", "-2147483649"] {
            assert_eq!(
                problem(&integer, Some(Value::Integer(bad.into()))),
                Some(Problem::NotInteger),
                "{bad}"
            );
        }
        for good in ["2147483647", "-2147483648"] {
            assert_eq!(problem(&integer, Some(Value::Integer(good.into()))), None);
        }
    }

    #[test]
    fn numbers_must_be_numbers() {
        let integer = data("integer", json!({}));
        for bad in ["abc", "1.5", "1e3", "9223372036854775808", "--1"] {
            assert_eq!(
                problem(&integer, Some(Value::Integer(bad.into()))),
                Some(Problem::NotInteger),
                "{bad}"
            );
        }
        assert_eq!(
            problem(&integer, Some(Value::Integer(" -42 ".into()))),
            None
        );
        let float = data("float", json!({}));
        for bad in ["abc", "NaN", "inf", "1,5"] {
            assert_eq!(
                problem(&float, Some(Value::Float(bad.into()))),
                Some(Problem::NotNumber),
                "{bad}"
            );
        }
        assert_eq!(problem(&float, Some(Value::Float("-1.5e2".into()))), None);
    }

    #[test]
    fn a_range_is_inclusive_and_may_be_open() {
        let range = |content_type| {
            with_constraints(
                content_type,
                json!([{ "type": "range", "data": { "from": 1, "to": 10 }, "errorMessage": "Between 1 and 10" }]),
            )
        };
        let integer = range("integer");
        let below = Some(Problem::Below {
            min: 1,
            message: Some("Between 1 and 10".into()),
        });
        let above = Some(Problem::Above {
            max: 10,
            message: Some("Between 1 and 10".into()),
        });
        assert_eq!(problem(&integer, Some(Value::Integer("0".into()))), below);
        assert_eq!(problem(&integer, Some(Value::Integer("11".into()))), above);
        for edge in ["1", "10", "5"] {
            assert_eq!(problem(&integer, Some(Value::Integer(edge.into()))), None);
        }
        let float = range("float");
        assert_eq!(problem(&float, Some(Value::Float("0.99".into()))), below);
        assert_eq!(problem(&float, Some(Value::Float("10.01".into()))), above);
        assert_eq!(problem(&float, Some(Value::Float("10".into()))), None);
        let open = with_constraints(
            "integer",
            json!([{ "type": "range", "data": { "from": null, "to": 3 } }]),
        );
        assert_eq!(problem(&open, Some(Value::Integer("-100".into()))), None);
        assert_eq!(
            problem(&open, Some(Value::Integer("4".into()))),
            Some(Problem::Above {
                max: 3,
                message: None
            })
        );
    }

    #[test]
    fn a_pattern_must_match_the_whole_string() {
        let pattern = with_constraints(
            "string",
            json!([{ "data": "[a-z]{2,3}", "errorMessage": "Two or three letters" }]),
        );
        let wrong = Some(Problem::Pattern {
            message: Some("Two or three letters".into()),
        });
        assert_eq!(problem(&pattern, Some(text("abcd"))), wrong);
        assert_eq!(problem(&pattern, Some(text("ab1"))), wrong);
        assert_eq!(problem(&pattern, Some(text("ab"))), None);
        let no_message = with_constraints("string", json!([{ "type": "regExp", "data": "a|b" }]));
        assert_eq!(
            problem(&no_message, Some(text("ab"))),
            Some(Problem::Pattern { message: None })
        );
        assert_eq!(problem(&no_message, Some(text("b"))), None);
    }

    #[test]
    fn a_pattern_rust_cannot_compile_is_left_to_ilm() {
        for pattern in ["(?=a)b", r"(a)\1", "(unclosed"] {
            let found = with_constraints("string", json!([{ "data": pattern }]));
            assert_eq!(problem(&found, Some(text("anything"))), None, "{pattern}");
        }
    }

    #[test]
    fn rules_apply_only_to_the_content_types_ilm_checks() {
        let text_field = with_constraints("text", json!([{ "data": "x" }]));
        assert_eq!(problem(&text_field, Some(text("y"))), None);
        let float_pattern = with_constraints("float", json!([{ "data": "x" }]));
        assert_eq!(
            problem(&float_pattern, Some(Value::Float("1".into()))),
            None
        );
        let string_range = with_constraints(
            "string",
            json!([{ "type": "range", "data": { "from": 5 } }]),
        );
        assert_eq!(problem(&string_range, Some(text("1"))), None);
    }

    #[test]
    fn dates_times_and_date_times_must_be_real() {
        assert_eq!(
            problem(
                &data("date", json!({})),
                Some(Value::Date("2026-02-30".into()))
            ),
            Some(Problem::BadDate)
        );
        assert_eq!(
            problem(
                &data("date", json!({})),
                Some(Value::Date("2026-02-28".into()))
            ),
            None
        );
        assert_eq!(
            problem(&data("time", json!({})), Some(Value::Time("25:00".into()))),
            Some(Problem::BadTime)
        );
        assert_eq!(
            problem(&data("time", json!({})), Some(Value::Time("07:30".into()))),
            None
        );
        let datetime = data("datetime", json!({}));
        assert_eq!(
            problem(&datetime, Some(Value::DateTime("tomorrow".into()))),
            Some(Problem::BadDateTime)
        );
        assert_eq!(
            problem(&datetime, Some(Value::DateTime("2026-02-28T07:30".into()))),
            None
        );
        assert_eq!(
            problem(
                &datetime,
                Some(Value::DateTime("2026-02-28T07:30:00Z".into()))
            ),
            None
        );
    }

    #[test]
    fn date_time_bounds_compare_wall_clock_time() {
        let bounded = with_constraints(
            "datetime",
            json!([{ "type": "dateTime", "data": { "from": "2026-01-01T00:00:00", "to": "2026-12-31T23:59:59" } }]),
        );
        let given = |text: &str| Some(Value::DateTime(text.into()));
        assert_eq!(
            problem(&bounded, given("2025-12-31T23:59")),
            Some(Problem::Before {
                from: "2026-01-01T00:00:00".into()
            })
        );
        assert_eq!(
            problem(&bounded, given("2027-01-01T01:00:00+01:00")),
            Some(Problem::After {
                to: "2026-12-31T23:59:59".into()
            })
        );
        for inside in [
            "2026-01-01T00:00",
            "2026-06-15T12:00:00Z",
            "2026-12-31T23:59:59",
        ] {
            assert_eq!(problem(&bounded, given(inside)), None, "{inside}");
        }
        let unreadable = with_constraints(
            "datetime",
            json!([{ "type": "dateTime", "data": { "from": "soon" } }]),
        );
        assert_eq!(problem(&unreadable, given("1999-01-01T00:00")), None);
    }

    #[test]
    fn an_offset_date_time_is_compared_in_the_computers_zone() {
        let bounded = with_constraints(
            "datetime",
            json!([{ "type": "dateTime", "data": { "from": "2026-11-23T18:00:00" } }]),
        );
        let given = || Some(Value::DateTime("2026-11-23T14:30:00Z".into()));
        let value = values(&bounded.name, given().unwrap());
        let in_zone = |zone: &TimeZone| {
            check(std::slice::from_ref(&bounded), &value, zone)
                .into_iter()
                .next()
                .map(|found| found.problem)
        };
        let india = TimeZone::fixed(Offset::from_seconds(5 * 3600 + 1800).unwrap());

        assert_eq!(
            in_zone(&TimeZone::UTC),
            Some(Problem::Before {
                from: "2026-11-23T18:00:00".into()
            })
        );
        assert_eq!(in_zone(&india), None);
        let zoneless = values(&bounded.name, Value::DateTime("2026-11-23T14:30".into()));
        assert_eq!(
            check(std::slice::from_ref(&bounded), &zoneless, &india)
                .first()
                .map(|found| found.problem.clone()),
            Some(Problem::Before {
                from: "2026-11-23T18:00:00".into()
            })
        );
    }

    #[test]
    fn an_object_must_be_json() {
        let object = data("object", json!({}));
        assert_eq!(
            problem(&object, Some(Value::Object("{".into()))),
            Some(Problem::BadJson)
        );
        assert_eq!(
            problem(&object, Some(Value::Object(r#"{"a":[1]}"#.into()))),
            None
        );
        assert_eq!(problem(&object, Some(Value::Object("42".into()))), None);
    }

    #[test]
    fn a_file_must_be_base64_and_small() {
        let file = data("file", json!({}));
        let given = |content: &str| {
            Some(Value::File(FileValue {
                name: "a".into(),
                mime: "b".into(),
                content: content.into(),
            }))
        };
        assert_eq!(problem(&file, given("aGVsbG8=")), None);
        assert_eq!(problem(&file, given("***")), Some(Problem::BadFile));
        let big = "A".repeat((MAX_FILE_BYTES / 3 + 1) * 4);
        assert_eq!(
            problem(&file, given(&big)),
            Some(Problem::FileTooLarge {
                max: MAX_FILE_BYTES as u64
            })
        );
        let limit = "A".repeat(MAX_FILE_BYTES / 3 * 4);
        assert_eq!(problem(&file, given(&limit)), None);
    }

    #[test]
    fn a_choice_must_be_an_option_of_the_definition() {
        let multi = with_content(
            definition(
                3,
                "data",
                "field",
                "string",
                json!({ "list": true, "multiSelect": true, "extensibleList": true }),
            ),
            json!([{ "data": "a", "contentType": "string" }]),
        );
        assert_eq!(
            problem(&multi, Some(Value::Options(vec![opt("a"), opt("zzz")]))),
            Some(Problem::NotAnOption)
        );
        assert_eq!(problem(&multi, Some(Value::Options(vec![opt("a")]))), None);
        let single = with_content(
            definition(3, "data", "field", "string", json!({ "list": true })),
            json!([{ "data": "a", "contentType": "string" }]),
        );
        assert_eq!(
            problem(&single, Some(opt("zzz"))),
            Some(Problem::NotAnOption)
        );
        assert_eq!(
            problem(&single, Some(Value::Added(Box::new(text("z"))))),
            Some(Problem::NotAnOption)
        );
        assert_eq!(
            problem(&single, Some(text("a"))),
            Some(Problem::NotAnOption)
        );
    }

    #[test]
    fn added_values_are_checked_like_typed_ones() {
        let found = one(with(
            with(
                definition(
                    3,
                    "data",
                    "field",
                    "integer",
                    json!({ "list": true, "extensibleList": true }),
                ),
                "content",
                json!([{ "data": 1, "contentType": "integer" }]),
            ),
            "constraints",
            json!([{ "type": "range", "data": { "from": 0, "to": 5 } }]),
        ));
        let added = |text: &str| Some(Value::Added(Box::new(Value::Integer(text.into()))));
        assert_eq!(problem(&found, added("x")), Some(Problem::NotInteger));
        assert_eq!(
            problem(&found, added("9")),
            Some(Problem::Above {
                max: 5,
                message: None
            })
        );
        assert_eq!(problem(&found, added("3")), None);
    }

    #[test]
    fn read_only_hidden_and_info_fields_are_not_checked() {
        let definitions = read(&[
            definition(
                3,
                "data",
                "locked",
                "string",
                json!({ "readOnly": true, "required": true }),
            ),
            definition(
                3,
                "data",
                "unseen",
                "string",
                json!({ "visible": false, "required": true }),
            ),
            definition(3, "info", "notice", "string", json!({ "required": true })),
        ])
        .fields;
        assert!(check(&definitions, &Values::new(), &TimeZone::UTC).is_empty());
    }

    #[test]
    fn problems_come_in_the_order_of_the_definitions_with_one_per_field() {
        let definitions = read(&certificate_custom()).fields;
        let required = read(&[
            definition(3, "data", "first", "string", json!({ "required": true })),
            definition(3, "data", "second", "integer", json!({})),
            definition(3, "data", "third", "string", json!({ "required": true })),
        ])
        .fields;
        let mut given = values("second", Value::Integer("x".into()));
        given.insert("third".into(), text("ok"));
        let found = check(&required, &given, &TimeZone::UTC);
        assert_eq!(
            found,
            [
                FieldProblem {
                    name: "first".into(),
                    problem: Problem::Required
                },
                FieldProblem {
                    name: "second".into(),
                    problem: Problem::NotInteger
                },
            ]
        );
        assert!(check(&definitions, &defaults(&definitions), &TimeZone::UTC).is_empty());
    }
}

mod requests {
    use super::*;

    fn built(definitions: &[Definition], values: &Values) -> Vec<Json> {
        request(definitions, values)
    }

    fn only(definition: Definition, value: Value) -> Json {
        let sent = built(
            std::slice::from_ref(&definition),
            &values(&definition.name, value),
        );
        assert_eq!(sent.len(), 1);
        sent.into_iter().next().unwrap()
    }

    #[test]
    fn a_request_attribute_names_the_definition() {
        let sent = only(data("string", json!({})), text("x"));
        assert_eq!(
            sent,
            json!({
                "uuid": "00000000-0000-4000-8000-000000000005",
                "name": "field",
                "contentType": "string",
                "version": "v3",
                "content": [{ "data": "x", "contentType": "string" }]
            })
        );
        let two = only(
            one(definition(2, "data", "field", "string", json!({}))),
            text("x"),
        );
        assert_eq!(two["version"], "v2");
        assert_eq!(two["content"], json!([{ "data": "x" }]));
    }

    #[test]
    fn a_definition_without_a_uuid_is_sent_without_one() {
        let mut raw = definition(3, "data", "field", "string", json!({}));
        raw.as_object_mut().unwrap().remove("uuid");
        assert!(only(one(raw), text("x")).get("uuid").is_none());
    }

    #[test]
    fn each_content_type_has_its_body() {
        let cases = [
            ("string", text("a"), json!("a")),
            ("text", text("a\nb"), json!("a\nb")),
            ("integer", Value::Integer(" 12 ".into()), json!(12)),
            ("float", Value::Float("1.25".into()), json!(1.25)),
            ("boolean", Value::Bool(false), json!(false)),
            (
                "date",
                Value::Date("2026-02-28".into()),
                json!("2026-02-28"),
            ),
            ("time", Value::Time("07:30".into()), json!("07:30:00")),
            ("time", Value::Time("07:30:15".into()), json!("07:30:15")),
            (
                "datetime",
                Value::DateTime("2026-02-28T13:45+01:00".into()),
                json!("2026-02-28T12:45:00.000Z"),
            ),
            (
                "file",
                Value::File(FileValue {
                    name: "a.txt".into(),
                    mime: "text/plain".into(),
                    content: "aGk=".into(),
                }),
                json!({ "content": "aGk=", "fileName": "a.txt", "mimeType": "text/plain" }),
            ),
            (
                "object",
                Value::Object(r#"{"a":1}"#.into()),
                json!(r#"{"a":1}"#),
            ),
        ];
        for (content_type, value, data_sent) in cases {
            let sent = only(data(content_type, json!({})), value);
            assert_eq!(sent["contentType"], content_type);
            assert_eq!(
                sent["content"],
                json!([{ "data": data_sent, "contentType": content_type }]),
                "{content_type}"
            );
        }
    }

    #[test]
    fn a_secret_is_a_version_two_item_without_content_type() {
        let secret = one(definition(2, "data", "pin", "secret", json!({})));
        let sent = only(secret, text("not-a-real-secret"));
        assert_eq!(sent["version"], "v2");
        assert_eq!(sent["contentType"], "secret");
        assert_eq!(
            sent["content"],
            json!([{ "data": { "secret": "not-a-real-secret" } }])
        );
        let newer = one(definition(3, "data", "pin", "secret", json!({})));
        let sent = only(newer, text("x"));
        assert_eq!(sent["version"], "v2");
        assert_eq!(sent["content"], json!([{ "data": { "secret": "x" } }]));
    }

    #[test]
    fn a_codeblock_is_base64_with_the_language_of_the_definition() {
        let python = with_content(
            definition(3, "data", "field", "codeblock", json!({})),
            json!([{ "data": { "code": "", "language": "python" }, "contentType": "codeblock" }]),
        );
        let sent = only(python, Value::Code("print(1)".into()));
        assert_eq!(
            sent["content"],
            json!([{ "data": { "code": "cHJpbnQoMSk=", "language": "python" }, "contentType": "codeblock" }])
        );
        let sent = only(data("codeblock", json!({})), Value::Code("x".into()));
        assert_eq!(sent["content"][0]["data"]["language"], "javascript");
    }

    #[test]
    fn a_chosen_option_goes_back_as_ilm_gave_it() {
        let found = read(&every_type());
        let credential = field(&found, "a_credential");
        let sent = only(credential.clone(), pick(credential, 0));
        assert_eq!(sent["version"], "v2");
        assert_eq!(sent["content"], json!(credential.content));
        let department = one(with(
            definition(
                3,
                "custom",
                "department",
                "string",
                json!({ "list": true, "multiSelect": true }),
            ),
            "content",
            json!([
                { "reference": "s", "data": "Sales", "contentType": "string" },
                { "data": "IT", "contentType": "string" }
            ]),
        ));
        let sent = only(
            department.clone(),
            Value::Options(vec![pick(&department, 1), pick(&department, 0)]),
        );
        assert_eq!(
            sent["content"],
            json!([department.content[1], department.content[0]])
        );
    }

    #[test]
    fn a_resource_is_cut_down_to_what_ilm_reads() {
        let found = read(&every_type());
        let resource = field(&found, "a_resource");
        let sent = only(resource.clone(), pick(resource, 0));
        assert_eq!(
            sent["content"],
            json!([{
                "reference": "Auth",
                "contentType": "resource",
                "data": { "resource": "authorities", "uuid": "u-2", "name": "Auth" }
            }])
        );
    }

    #[test]
    fn an_added_value_is_a_bare_item_without_reference() {
        let list = with_content(
            definition(
                3,
                "data",
                "field",
                "integer",
                json!({ "list": true, "multiSelect": true, "extensibleList": true }),
            ),
            json!([{ "reference": "one", "data": 1, "contentType": "integer" }]),
        );
        let first = pick(&list, 0);
        let sent = only(
            list,
            Value::Options(vec![
                first,
                Value::Added(Box::new(Value::Integer("7".into()))),
            ]),
        );
        assert_eq!(
            sent["content"],
            json!([
                { "reference": "one", "data": 1, "contentType": "integer" },
                { "data": 7, "contentType": "integer" }
            ])
        );
    }

    #[test]
    fn an_added_date_to_a_single_list_is_parsed_and_sent_as_a_new_item() {
        let list = with_content(
            definition(
                3,
                "data",
                "field",
                "date",
                json!({ "list": true, "extensibleList": true }),
            ),
            json!([{ "data": "2026-01-01", "contentType": "date" }]),
        );
        let sent = json!({ "field": { "kind": "added", "value": { "kind": "date", "value": "2026-02-03" } } });
        let parsed = parse_values(std::slice::from_ref(&list), &sent).unwrap();
        assert_eq!(
            parsed["field"],
            Value::Added(Box::new(Value::Date("2026-02-03".into())))
        );
        let body = built(std::slice::from_ref(&list), &parsed);
        assert_eq!(
            body[0]["content"],
            json!([{ "data": "2026-02-03", "contentType": "date" }])
        );
        assert_eq!(body[0]["contentType"], "date");
    }

    #[test]
    fn a_bad_added_integer_is_a_problem_of_its_field_not_a_refused_call() {
        let list = data("integer", json!({ "list": true, "extensibleList": true }));
        let sent =
            json!({ "field": { "kind": "added", "value": { "kind": "integer", "value": "4x" } } });
        let parsed = parse_values(std::slice::from_ref(&list), &sent).unwrap();
        assert_eq!(
            check(std::slice::from_ref(&list), &parsed, &TimeZone::UTC),
            vec![FieldProblem {
                name: "field".into(),
                problem: Problem::NotInteger
            }]
        );
    }

    #[test]
    fn empty_optional_values_are_left_out() {
        let definitions = read(&certificate_custom()).fields;
        let given: Values = [
            ("TestInt", Value::Integer(" ".into())),
            ("qa_test_custom_attr", text("")),
            ("department", Value::Options(Vec::new())),
            ("Local Certificate", Value::Bool(false)),
            ("datecustom", Value::Date("2026-01-02".into())),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let sent = built(&definitions, &given);
        let names: Vec<&str> = sent
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["datecustom", "Local Certificate"]);
        assert!(built(&definitions, &Values::new()).is_empty());
    }

    #[test]
    fn a_value_that_cannot_be_read_is_left_out() {
        let cases = [
            ("integer", Value::Integer("x".into())),
            ("float", Value::Float("NaN".into())),
            ("date", Value::Date("nope".into())),
            ("time", Value::Time("nope".into())),
            ("datetime", Value::DateTime("nope".into())),
            ("string", opt("a")),
        ];
        for (content_type, value) in cases {
            let definition = data(content_type, json!({}));
            assert!(built(std::slice::from_ref(&definition), &values("field", value)).is_empty());
        }
        let list = data("string", json!({ "list": true }));
        assert!(built(&[list], &values("field", opt("zzz"))).is_empty());
    }

    #[test]
    fn read_only_and_hidden_attributes_are_sent_exactly_as_defined() {
        let definitions = read(&request_attributes()).fields;
        let hidden = with_content(
            definition(3, "data", "unseen", "string", json!({ "visible": false })),
            json!([{ "reference": "r", "data": "kept", "contentType": "string" }]),
        );
        let mut all = definitions.clone();
        all.push(hidden.clone());
        let given: Values = [
            ("common-name", text("changed")),
            ("unseen", text("changed")),
            (
                "san",
                Value::Options(vec![Value::Added(Box::new(text("a.example.com")))]),
            ),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let sent = built(&all, &given);
        assert_eq!(sent.len(), 3);
        assert_eq!(sent[0]["name"], "common-name");
        assert_eq!(sent[0]["version"], "v3");
        assert_eq!(sent[0]["content"], json!(definitions[0].content));
        assert_eq!(sent[1]["name"], "san");
        assert_eq!(
            sent[1]["content"],
            json!([{ "data": "a.example.com", "contentType": "string" }])
        );
        assert_eq!(sent[2]["name"], "unseen");
        assert_eq!(sent[2]["content"], json!(hidden.content));
    }

    #[test]
    fn a_read_only_attribute_without_content_and_info_are_left_out() {
        let definitions = read(&[
            definition(3, "data", "locked", "string", json!({ "readOnly": true })),
            with(
                definition(3, "info", "notice", "string", json!({})),
                "content",
                json!([{ "data": "x" }]),
            ),
        ])
        .fields;
        assert!(built(&definitions, &Values::new()).is_empty());
    }

    #[test]
    fn a_form_filled_with_its_defaults_sends_what_ilm_defines() {
        let definitions = read(&every_type()).fields;
        let sent = built(&definitions, &defaults(&definitions));
        let names: Vec<&str> = sent
            .iter()
            .map(|item| item["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "a_string",
                "a_text",
                "an_integer",
                "a_float",
                "a_boolean",
                "a_date",
                "a_time",
                "a_datetime",
                "a_file",
                "a_codeblock",
                "an_object"
            ]
        );
        assert_eq!(sent[7]["content"][0]["data"], "2026-02-28T12:45:10.000Z");
    }
}

mod views {
    use super::*;

    fn view(raw: Vec<Json>) -> FormView {
        let definitions = read(&raw);
        FormView {
            id: "form-1".into(),
            revision: 0,
            groups: group_views(&definitions, &[], &Stamps::new()),
            unsupported: required_unsupported(&definitions),
            web: Some("https://ilm.example.com/administrator/#/certificates".into()),
        }
    }

    fn all_fields(view: &FormView) -> Vec<&FieldView> {
        view.groups
            .iter()
            .flat_map(|group| group.fields.iter())
            .collect()
    }

    fn named<'a>(view: &'a FormView, name: &str) -> &'a FieldView {
        all_fields(view)
            .into_iter()
            .find(|field| field.name == name)
            .unwrap()
    }

    #[test]
    fn ungrouped_fields_come_first_then_groups_in_order_of_appearance() {
        let found = view(certificate_custom());
        let titles: Vec<Option<&str>> = found
            .groups
            .iter()
            .map(|group| group.title.as_deref())
            .collect();
        assert_eq!(titles, [None, Some("GroupMeNow")]);
        let ungrouped: Vec<&str> = found.groups[0]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(
            ungrouped,
            [
                "TestInt",
                "qa_test_custom_attr",
                "datecustom",
                "repro-time",
                "datetimecustom",
                "Local Certificate"
            ]
        );
        let grouped: Vec<&str> = found.groups[1]
            .fields
            .iter()
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(grouped, ["department", "Extensible List String"]);
        assert_eq!(found.id, "form-1");
        assert_eq!(
            found.web.as_deref(),
            Some("https://ilm.example.com/administrator/#/certificates")
        );
    }

    #[test]
    fn a_form_without_ungrouped_fields_has_no_untitled_group() {
        let raw = vec![
            definition(3, "custom", "b", "string", json!({ "group": "Second" })),
            definition(3, "custom", "a", "string", json!({ "group": "First" })),
            definition(3, "custom", "c", "string", json!({ "group": "Second" })),
        ];
        let found = view(raw);
        let titles: Vec<Option<&str>> = found
            .groups
            .iter()
            .map(|group| group.title.as_deref())
            .collect();
        assert_eq!(titles, [Some("Second"), Some("First")]);
        assert_eq!(found.groups[0].fields.len(), 2);
        assert!(view(Vec::new()).groups.is_empty());
    }

    #[test]
    fn each_content_type_gets_its_control() {
        let found = view(every_type());
        let kinds: Vec<(&str, FieldKind)> = all_fields(&found)
            .into_iter()
            .map(|field| (field.name.as_str(), field.kind.unwrap()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("a_string", FieldKind::Textline),
                ("a_text", FieldKind::Textarea),
                ("an_integer", FieldKind::Integer),
                ("a_float", FieldKind::Float),
                ("a_boolean", FieldKind::Switch),
                ("a_date", FieldKind::Date),
                ("a_time", FieldKind::Time),
                ("a_datetime", FieldKind::Datetime),
                ("a_secret", FieldKind::Secret),
                ("a_file", FieldKind::File),
                ("a_codeblock", FieldKind::Code),
                ("an_object", FieldKind::Json),
                ("a_credential", FieldKind::Select),
                ("a_resource", FieldKind::Select),
            ]
        );
    }

    #[test]
    fn lists_protected_strings_and_info_get_theirs() {
        let found = view(certificate_custom());
        assert_eq!(
            named(&found, "department").kind,
            Some(FieldKind::Multiselect)
        );
        assert_eq!(
            named(&found, "Extensible List String").kind,
            Some(FieldKind::Select)
        );
        assert!(named(&found, "Extensible List String").extensible);
        let protected = view(vec![definition(
            3,
            "data",
            "pin",
            "string",
            json!({ "protectionLevel": "encrypted" }),
        )]);
        assert_eq!(named(&protected, "pin").kind, Some(FieldKind::Secret));
        let info = view(odd_ones());
        let notice = named(&info, "notice");
        assert_eq!(notice.kind, Some(FieldKind::Info));
        assert_eq!(notice.value, Some(text("First line\nSecond line")));
        assert_eq!(info.groups[0].title.as_deref(), Some("Notes"));
    }

    #[test]
    fn options_carry_their_key_and_label() {
        let items = json!([
            { "reference": "Ref", "data": "x", "contentType": "string" },
            { "data": "plain" },
            { "data": { "name": "Named", "uuid": "u" } },
            { "data": 5 }
        ]);
        let found = view(vec![with(
            definition(3, "data", "pick", "string", json!({ "list": true })),
            "content",
            items.clone(),
        )]);
        let options = &named(&found, "pick").options;
        let labels: Vec<&str> = options.iter().map(|option| option.label.as_str()).collect();
        assert_eq!(labels, ["Ref", "plain", "Named", "5"]);
        let keys: Vec<String> = items.as_array().unwrap().iter().map(option_key).collect();
        assert_eq!(
            options.iter().map(|o| &o.key).collect::<Vec<_>>(),
            keys.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_option_is_named_by_what_it_is_not_by_its_place() {
        let first = json!({ "reference": "A", "data": "a", "contentType": "string" });
        let second = json!({ "data": "b", "contentType": "string" });
        let key = option_key(&first);
        assert_eq!(key, option_key(&first.clone()));
        assert_ne!(key, option_key(&second));
        assert_ne!(
            key,
            option_key(&json!({ "data": "a", "contentType": "string" }))
        );
        let raw = with(
            definition(3, "data", "field", "string", json!({ "list": true })),
            "content",
            json!([second, first, first]),
        );
        let list = one(raw.clone());
        assert_eq!(list.option_keys(), [option_key(&second), key.clone()]);
        assert_eq!(list.option(&key), Some(&first));
        assert_eq!(list.option("nope"), None);
        let shown = view(vec![raw]);
        let keys: Vec<&String> = named(&shown, "field")
            .options
            .iter()
            .map(|o| &o.key)
            .collect();
        assert_eq!(keys, [&option_key(&second), &key]);
    }

    #[test]
    fn a_protected_field_has_no_options_and_no_value() {
        let found = view(vec![with(
            definition(
                3,
                "data",
                "pin",
                "string",
                json!({ "list": true, "protectionLevel": "encrypted", "readOnly": true }),
            ),
            "content",
            json!([{ "data": "a", "contentType": "string" }]),
        )]);
        let pin = named(&found, "pin");
        assert!(pin.options.is_empty());
        assert_eq!(pin.value, None);
    }

    #[test]
    fn the_fields_a_group_added_follow_it_however_deep_and_carry_their_stamps() {
        let raw = read(&[
            definition(3, "data", "first", "string", json!({})),
            json!({ "uuid": "g1", "name": "outer", "type": "group", "attributeCallback": { "dependsOn": [] } }),
            definition(3, "data", "last", "string", json!({})),
        ]);
        let inner = read(&[
            definition(3, "data", "mid", "string", json!({})),
            json!({ "uuid": "g2", "name": "inner", "type": "group", "attributeCallback": { "dependsOn": [] } }),
        ]);
        let deepest = read(&[definition(3, "data", "deep", "string", json!({}))]);
        let added = [("outer".to_owned(), inner), ("inner".to_owned(), deepest)];
        let stamps = Stamps::from([(
            "deep".to_owned(),
            Stamp {
                changed_at: 4,
                value_set_at: 3,
                ..Stamp::default()
            },
        )]);

        let groups = group_views(&raw, &added, &stamps);

        let names: Vec<&str> = groups[0].fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["first", "last", "outer", "mid", "inner", "deep"]);
        let deep = groups[0].fields.last().unwrap();
        assert_eq!((deep.changed_at, deep.value_set_at), (4, 3));
        assert_eq!(groups[0].fields[0].changed_at, 0);
    }

    #[test]
    fn a_group_that_adds_itself_is_shown_once() {
        let group = json!({ "uuid": "g", "name": "g", "type": "group", "attributeCallback": { "dependsOn": [] } });
        let raw = read(std::slice::from_ref(&group));
        let added = [("g".to_owned(), read(&[group]))];

        let groups = group_views(&raw, &added, &Stamps::new());

        let names: Vec<&str> = groups[0].fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["g"]);
    }

    #[test]
    fn the_view_carries_defaults_but_never_a_secret() {
        let found = view(every_type());
        assert_eq!(named(&found, "a_string").value, Some(text("text")));
        assert_eq!(
            named(&found, "a_codeblock").language.as_deref(),
            Some("python")
        );
        assert_eq!(named(&found, "a_string").language, None);
        assert_eq!(named(&found, "a_secret").value, None);
        assert_eq!(named(&view(certificate_custom()), "TestInt").value, None);
    }

    #[test]
    fn a_hidden_field_has_no_control_information() {
        let hidden = with(
            definition(
                3,
                "data",
                "unseen",
                "string",
                json!({ "visible": false, "list": true, "required": true }),
            ),
            "content",
            json!([{ "data": "a", "contentType": "string" }]),
        );
        let found = view(vec![hidden]);
        let field = named(&found, "unseen");
        assert!(field.hidden && field.required);
        assert_eq!(field.kind, None);
        assert!(field.options.is_empty() && field.constraints.is_empty() && !field.extensible);
        assert_eq!(field.value, None);
        assert_eq!(field.language, None);
    }

    #[test]
    fn an_extensible_list_says_what_an_added_value_is() {
        let list = |content_type: &str, properties: Json| {
            let mut found = view(vec![definition(
                3,
                "data",
                "field",
                content_type,
                properties,
            )]);
            found.groups.remove(0).fields.remove(0)
        };
        let extensible = json!({ "list": true, "extensibleList": true });
        let kinds: Vec<_> = [
            "string", "integer", "float", "date", "time", "datetime", "object",
        ]
        .into_iter()
        .map(|content_type| list(content_type, extensible.clone()).value_kind)
        .collect();
        assert_eq!(
            kinds,
            [
                Some(ValueKind::Text),
                Some(ValueKind::Integer),
                Some(ValueKind::Float),
                Some(ValueKind::Date),
                Some(ValueKind::Time),
                Some(ValueKind::DateTime),
                None
            ]
        );
        assert_eq!(list("integer", json!({ "list": true })).value_kind, None);
        assert_eq!(list("integer", json!({})).value_kind, None);
    }

    #[test]
    fn a_read_only_field_shows_what_it_defines() {
        let found = view(request_attributes());
        let field = named(&found, "common-name");
        assert!(field.read_only && field.required && !field.hidden);
        assert_eq!(field.value, Some(text("host.example.com")));
    }

    #[test]
    fn constraints_are_shown_as_hints() {
        let found = view(vec![with(
            definition(3, "data", "n", "integer", json!({})),
            "constraints",
            json!([
                { "type": "range", "data": { "from": 1, "to": 9 } },
                { "type": "dateTime", "data": { "from": "2026-01-01T00:00:00", "to": "2026-02-01T00:00:00" } },
                { "data": "\\d+", "description": "Digits" }
            ]),
        )]);
        assert_eq!(
            named(&found, "n").constraints,
            [
                ConstraintView::Range {
                    min: Some(1),
                    max: Some(9)
                },
                ConstraintView::DateTime {
                    from: Some("2026-01-01T00:00:00".into()),
                    to: Some("2026-02-01T00:00:00".into())
                },
                ConstraintView::Pattern {
                    description: Some("Digits".into())
                },
            ]
        );
    }

    #[test]
    fn a_callback_is_none_on_open_or_on_change() {
        let callback = |raw: Json| {
            let found = view(vec![with(
                definition(3, "data", "f", "string", json!({})),
                "attributeCallback",
                raw,
            )]);
            named(&found, "f").callback.clone()
        };
        assert_eq!(
            view(vec![definition(3, "data", "f", "string", json!({}))]).groups[0].fields[0]
                .callback,
            CallbackView::None
        );
        assert_eq!(callback(json!({ "dependsOn": [] })), CallbackView::OnOpen);
        assert_eq!(
            callback(json!({ "dependsOn": ["a", "b"] })),
            CallbackView::OnChange(vec!["a".into(), "b".into()])
        );
        assert_eq!(
            callback(json!({
                "callbackContext": "x",
                "mappings": [
                    { "from": "kind.data.name", "to": "k", "targets": ["body"] },
                    { "to": "p", "targets": ["body"], "value": 1 }
                ]
            })),
            CallbackView::OnChange(vec!["kind".into()])
        );
        assert_eq!(
            callback(
                json!({ "callbackContext": "core/getCredentials", "mappings": [{ "to": "p", "targets": ["body"], "value": 1 }] })
            ),
            CallbackView::OnOpen
        );
    }

    #[test]
    fn only_required_unsupported_attributes_are_listed() {
        let found = view(odd_ones());
        assert_eq!(found.unsupported, ["future-type label"]);
        assert!(view(certificate_custom()).unsupported.is_empty());
    }

    #[test]
    fn the_view_serialises_in_camel_case() {
        let found = view(certificate_custom());
        let text = serde_json::to_value(&found).unwrap();
        let department = &text["groups"][1]["fields"][0];
        assert_eq!(department["kind"], "multiselect");
        assert_eq!(department["readOnly"], false);
        assert_eq!(department["callback"], json!({ "kind": "none" }));
        assert_eq!(
            text["groups"][0]["fields"][1]["value"],
            json!({ "kind": "text", "value": "qa was here" })
        );
        let problem = serde_json::to_value(FieldProblem {
            name: "n".into(),
            problem: Problem::Below {
                min: 2,
                message: None,
            },
        })
        .unwrap();
        assert_eq!(
            problem,
            json!({ "name": "n", "problem": { "kind": "below", "min": 2, "message": null } })
        );
        let on_change = serde_json::to_value(CallbackView::OnChange(vec!["a".into()])).unwrap();
        assert_eq!(on_change, json!({ "kind": "onChange", "value": ["a"] }));
    }
}
