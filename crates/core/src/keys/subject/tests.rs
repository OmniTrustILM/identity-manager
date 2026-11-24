use std::net::IpAddr;

use serde_json::{Value as Json, json};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use super::*;
use crate::attributes::fixtures::{
    default_request_set, definition, demo_request_set, mapped, read, upn_request_set, with,
};
use crate::attributes::{Definitions, FileValue, Value};
use crate::keys::testing::InMemoryStorage;
use crate::keys::{KeyStorage, KeyType, Storage, signing_request};

fn definitions(raw: &[Json]) -> Vec<Definition> {
    let found: Definitions = read(raw);
    assert!(found.unsupported.is_empty());
    found.fields
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn values(pairs: &[(&str, Value)]) -> Values {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.clone()))
        .collect()
}

/// One optional string attribute named `name`, mapped onto `fields`.
fn one(name: &str, fields: Json) -> Json {
    mapped(definition(3, "data", name, "string", json!({})), fields)
}

fn rdn_of(code: &str, value: &str) -> Result<RequestSubject, Unmappable> {
    let raw = [one("field", json!([{ "fieldType": "rdn", "rdn": code }]))];
    subject(&definitions(&raw), &values(&[("field", text(value))]))
}

fn san_of(kind: &str, value: &str) -> Result<RequestSubject, Unmappable> {
    let raw = [one(
        "field",
        json!([{ "fieldType": "san", "generalNameType": kind }]),
    )];
    subject(&definitions(&raw), &values(&[("field", text(value))]))
}

fn names(items: &[(NameType, &str)]) -> Vec<(NameType, String)> {
    items
        .iter()
        .map(|(kind, value)| (kind.clone(), value.to_string()))
        .collect()
}

#[test]
fn every_name_code_gives_its_name_type() {
    let cases = [
        ("CN", NameType::CommonName),
        ("cn", NameType::CommonName),
        ("O", NameType::Organization),
        ("OU", NameType::OrganizationalUnit),
        ("C", NameType::Country),
        ("ST", NameType::State),
        ("S", NameType::State),
        ("L", NameType::Locality),
        ("EMAIL", NameType::Email),
        ("E", NameType::Email),
        ("emailAddress", NameType::Email),
        ("SERIALNUMBER", NameType::SerialNumber),
        ("serialNumber", NameType::SerialNumber),
        ("DC", NameType::DomainComponent),
        ("2.5.4.3", NameType::CommonName),
        ("2.5.4.10", NameType::Organization),
        ("2.5.4.11", NameType::OrganizationalUnit),
        ("2.5.4.6", NameType::Country),
        ("2.5.4.8", NameType::State),
        ("2.5.4.7", NameType::Locality),
        ("2.5.4.5", NameType::SerialNumber),
        ("1.2.840.113549.1.9.1", NameType::Email),
        ("0.9.2342.19200300.100.1.25", NameType::DomainComponent),
        ("2.5.4.9", NameType::Other(vec![2, 5, 4, 9])),
    ];
    for (code, expected) in cases {
        let built = rdn_of(code, "value").unwrap();
        assert_eq!(built.names, names(&[(expected, "value")]), "{code}");
    }
    assert_eq!(
        rdn_of("2.999", "value").unwrap().names,
        names(&[(NameType::Other(vec![2, 999]), "value")])
    );
    for code in ["3.1", "1.40"] {
        assert!(rdn_of(code, "value").is_err(), "{code}");
    }
}

#[test]
fn a_value_outside_the_string_type_of_its_name_is_invalid() {
    assert!(matches!(
        rdn_of("DC", "café"),
        Err(Unmappable::Invalid { .. })
    ));
    assert!(matches!(rdn_of("C", "ü"), Err(Unmappable::Invalid { .. })));
    assert!(matches!(
        san_of("dns", "münich.example"),
        Err(Unmappable::Invalid { .. })
    ));
}

#[test]
fn every_alternative_name_type_is_built() {
    let cases = [
        ("dns", AlternativeName::Dns("a.example".into()), "a.example"),
        (
            "email",
            AlternativeName::Email("a@b.example".into()),
            "a@b.example",
        ),
        (
            "ip",
            AlternativeName::Ip("192.0.2.7".parse::<IpAddr>().unwrap()),
            "192.0.2.7",
        ),
        (
            "ip",
            AlternativeName::Ip("2001:db8::1".parse::<IpAddr>().unwrap()),
            "2001:db8::1",
        ),
        (
            "uri",
            AlternativeName::Uri("https://a.example/x".into()),
            "https://a.example/x",
        ),
    ];
    for (kind, expected, value) in cases {
        let built = san_of(kind, value).unwrap();
        assert_eq!(built.alternative_names, vec![expected], "{kind}");
        assert!(built.names.is_empty());
    }
}

#[test]
fn a_bad_address_is_refused() {
    assert_eq!(
        san_of("ip", "not an address"),
        Err(Unmappable::Invalid {
            label: "field label".into()
        })
    );
}

#[test]
fn a_upn_is_built_from_its_other_name() {
    let set = definitions(&upn_request_set());
    let built = subject(&set, &values(&[("upn", text("a@corp.example"))])).unwrap();
    assert_eq!(
        built.alternative_names,
        vec![AlternativeName::Upn("a@corp.example".into())]
    );
}

#[test]
fn one_attribute_fills_the_name_and_the_alternative_name() {
    let set = definitions(&demo_request_set());
    let built = subject(&set, &Values::new()).unwrap();
    assert_eq!(built.names, names(&[(NameType::CommonName, "demo220")]));
    assert_eq!(
        built.alternative_names,
        vec![AlternativeName::Dns("demo220".into())]
    );
}

#[test]
fn a_read_only_default_is_used_whatever_the_values_say() {
    let set = definitions(&demo_request_set());
    let built = subject(&set, &values(&[("common-name", text("other"))])).unwrap();
    assert_eq!(built.names, names(&[(NameType::CommonName, "demo220")]));
}

#[test]
fn an_empty_optional_value_is_left_out() {
    let set = definitions(&default_request_set());
    let built = subject(
        &set,
        &values(&[
            ("commonName", text("host")),
            ("organization", text("")),
            ("country", text("CZ")),
        ]),
    )
    .unwrap();
    assert_eq!(
        built.names,
        names(&[(NameType::CommonName, "host"), (NameType::Country, "CZ")])
    );
}

#[test]
fn names_follow_the_order_of_the_mapping_then_of_the_definitions() {
    let raw = [
        one(
            "late",
            json!([{ "fieldType": "rdn", "rdn": "O", "order": 3 }]),
        ),
        one("unordered", json!([{ "fieldType": "rdn", "rdn": "L" }])),
        one(
            "first",
            json!([{ "fieldType": "rdn", "rdn": "CN", "order": 1 }]),
        ),
        one(
            "tied",
            json!([{ "fieldType": "rdn", "rdn": "OU", "order": 1 }]),
        ),
        one(
            "second",
            json!([{ "fieldType": "rdn", "rdn": "C", "order": 2 }]),
        ),
    ];
    let set = definitions(&raw);
    let given = values(&[
        ("late", text("3")),
        ("unordered", text("u")),
        ("first", text("1")),
        ("tied", text("1b")),
        ("second", text("2")),
    ]);
    let built = subject(&set, &given).unwrap();
    assert_eq!(
        built.names,
        names(&[
            (NameType::CommonName, "1"),
            (NameType::OrganizationalUnit, "1b"),
            (NameType::Country, "2"),
            (NameType::Organization, "3"),
            (NameType::Locality, "u"),
        ])
    );
}

#[test]
fn alternative_names_follow_the_same_order_and_may_repeat() {
    let raw = [
        one(
            "b",
            json!([{ "fieldType": "san", "generalNameType": "dns", "order": 2 }]),
        ),
        one(
            "a",
            json!([{ "fieldType": "san", "generalNameType": "dns", "order": 1 }]),
        ),
        one(
            "c",
            json!([{ "fieldType": "san", "generalNameType": "dns" }]),
        ),
    ];
    let built = subject(
        &definitions(&raw),
        &values(&[("a", text("a.x")), ("b", text("b.x")), ("c", text("a.x"))]),
    )
    .unwrap();
    let dns = |name: &str| AlternativeName::Dns(name.into());
    assert_eq!(
        built.alternative_names,
        vec![dns("a.x"), dns("b.x"), dns("a.x")]
    );
}

fn multi(name: &str, fields: Json) -> Json {
    mapped(
        definition(
            3,
            "data",
            name,
            "string",
            json!({ "list": true, "multiSelect": true, "extensibleList": true }),
        ),
        fields,
    )
}

fn added(items: &[&str]) -> Value {
    Value::Options(
        items
            .iter()
            .map(|item| Value::Added(Box::new(text(item))))
            .collect(),
    )
}

#[test]
fn a_multi_value_gives_one_alternative_name_per_item() {
    let raw = [multi(
        "san",
        json!([{ "fieldType": "san", "generalNameType": "dns" }]),
    )];
    let built = subject(
        &definitions(&raw),
        &values(&[("san", added(&["a.example", "b.example"]))]),
    )
    .unwrap();
    assert_eq!(
        built.alternative_names,
        vec![
            AlternativeName::Dns("a.example".into()),
            AlternativeName::Dns("b.example".into())
        ]
    );
}

#[test]
fn a_chosen_option_is_read_from_its_content() {
    let raw = [with(
        mapped(
            definition(3, "data", "unit", "string", json!({ "list": true })),
            json!([{ "fieldType": "rdn", "rdn": "OU" }]),
        ),
        "content",
        json!([{ "data": "Sales", "contentType": "string" }]),
    )];
    let set = definitions(&raw);
    let key = set[0].option_keys().remove(0);
    let built = subject(&set, &values(&[("unit", Value::Option(key))])).unwrap();
    assert_eq!(
        built.names,
        names(&[(NameType::OrganizationalUnit, "Sales")])
    );
}

#[test]
fn numbers_and_flags_are_taken_as_text() {
    let raw = [
        mapped(
            definition(3, "data", "serial", "integer", json!({})),
            json!([{ "fieldType": "rdn", "rdn": "SERIALNUMBER" }]),
        ),
        mapped(
            definition(3, "data", "flag", "boolean", json!({})),
            json!([{ "fieldType": "rdn", "rdn": "OU" }]),
        ),
    ];
    let built = subject(
        &definitions(&raw),
        &values(&[
            ("serial", Value::Integer("42".into())),
            ("flag", Value::Bool(true)),
        ]),
    )
    .unwrap();
    assert_eq!(
        built.names,
        names(&[
            (NameType::SerialNumber, "42"),
            (NameType::OrganizationalUnit, "true")
        ])
    );
}

#[test]
fn a_value_of_another_shape_is_invalid() {
    let raw = [mapped(
        definition(3, "data", "when", "file", json!({})),
        json!([{ "fieldType": "rdn", "rdn": "OU" }]),
    )];
    assert_eq!(
        subject(
            &definitions(&raw),
            &values(&[(
                "when",
                Value::File(FileValue {
                    name: "a.txt".into(),
                    mime: "text/plain".into(),
                    content: "aGk=".into()
                })
            )])
        ),
        Err(Unmappable::Invalid {
            label: "when label".into()
        })
    );
}

#[test]
fn a_value_given_to_an_attribute_without_a_mapping_is_refused() {
    let raw = [definition(3, "data", "plain", "string", json!({}))];
    assert_eq!(
        subject(&definitions(&raw), &values(&[("plain", text("x"))])),
        Err(Unmappable::Unsupported {
            label: "plain label".into()
        })
    );
}

#[test]
fn an_optional_attribute_without_a_mapping_and_a_value_is_fine() {
    let raw = [definition(3, "data", "plain", "string", json!({}))];
    let set = definitions(&raw);
    assert_eq!(
        subject(&set, &values(&[("plain", text(""))])).unwrap(),
        RequestSubject::default()
    );
    assert_eq!(
        subject(&set, &values(&[])).unwrap(),
        RequestSubject::default()
    );
    assert!(unbuildable(&set).is_empty());
}

#[test]
fn a_required_attribute_without_a_mapping_cannot_be_built() {
    let raw = [definition(
        3,
        "data",
        "plain",
        "string",
        json!({ "required": true }),
    )];
    let set = definitions(&raw);
    let blocked = unbuildable(&set);
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].name, "plain");
    assert_eq!(
        subject(&set, &values(&[("plain", text("x"))])),
        Err(Unmappable::Unsupported {
            label: "plain label".into()
        })
    );
}

#[test]
fn an_info_attribute_without_a_mapping_is_not_in_the_way() {
    let raw = [definition(
        3,
        "info",
        "note",
        "string",
        json!({ "required": true }),
    )];
    let set = definitions(&raw);
    assert!(unbuildable(&set).is_empty());
    assert_eq!(
        subject(&set, &values(&[])).unwrap(),
        RequestSubject::default()
    );
}

#[test]
fn a_value_given_to_a_field_that_cannot_be_written_is_refused_and_an_empty_one_is_fine() {
    let raw = [one(
        "both",
        json!([
            { "fieldType": "rdn", "rdn": "CN" },
            { "fieldType": "rdn", "rdn": "STREET" },
            { "fieldType": "extension", "extensionOid": "1.2.3.4" },
            { "fieldType": "san", "generalNameType": "directoryName" }
        ]),
    )];
    let set = definitions(&raw);
    assert_eq!(
        subject(&set, &values(&[("both", text("host"))])),
        Err(Unmappable::Unsupported {
            label: "both label".into()
        })
    );
    let built = subject(&set, &values(&[("both", text(""))])).unwrap();
    assert_eq!(built, RequestSubject::default());
    assert!(unbuildable(&set).is_empty());
}

#[test]
fn a_name_type_is_the_same_whichever_way_it_is_written() {
    let raw = [
        one("host", json!([{ "fieldType": "rdn", "rdn": "CN" }])),
        one("again", json!([{ "fieldType": "rdn", "rdn": "2.5.4.3" }])),
    ];
    assert_eq!(
        subject(
            &definitions(&raw),
            &values(&[("host", text("a")), ("again", text("b"))])
        ),
        Err(Unmappable::Repeated {
            label: "again label".into()
        })
    );
}

#[test]
fn an_other_name_is_a_upn_only_when_its_value_is_a_utf8_string() {
    let upn = |encoding: Option<&str>, required: bool| {
        let mut field = json!({
            "fieldType": "san",
            "generalNameType": "otherName",
            "otherNameOid": "1.3.6.1.4.1.311.20.2.3"
        });
        if let Some(encoding) = encoding {
            field["otherNameValueEncoding"] = json!(encoding);
        }
        let definition = mapped(
            definition(3, "data", "upn", "string", json!({ "required": required })),
            json!([field]),
        );
        definitions(&[definition])
    };
    let given = values(&[("upn", text("a@corp.example"))]);
    for encoding in [None, Some("UTF8String")] {
        let built = subject(&upn(encoding, true), &given).unwrap();
        assert_eq!(
            built.alternative_names,
            vec![AlternativeName::Upn("a@corp.example".into())]
        );
    }
    let set = upn(Some("DER"), true);
    assert_eq!(
        subject(&set, &given),
        Err(Unmappable::Unsupported {
            label: "upn label".into()
        })
    );
    assert_eq!(unbuildable(&set).len(), 1);
    assert_eq!(
        subject(&upn(Some("DER"), false), &given),
        Err(Unmappable::Unsupported {
            label: "upn label".into()
        })
    );
}

#[test]
fn an_unbuildable_required_attribute_is_unsupported_and_listed() {
    for field in [
        json!({ "fieldType": "rdn", "rdn": "STREET" }),
        json!({ "fieldType": "extension", "extensionOid": "1.2.3.4" }),
        json!({ "fieldType": "keyUsage" }),
        json!({ "fieldType": "san", "generalNameType": "registeredId" }),
        json!({ "fieldType": "san", "generalNameType": "directoryName" }),
        json!({ "fieldType": "san", "generalNameType": "otherName", "otherNameOid": "1.2.3" }),
    ] {
        let raw = [
            mapped(
                definition(3, "data", "needed", "string", json!({ "required": true })),
                json!([{ "fieldType": "rdn", "rdn": "CN" }, field]),
            ),
            one("fine", json!([{ "fieldType": "rdn", "rdn": "O" }])),
        ];
        let set = definitions(&raw);
        let wanted = Unmappable::Unsupported {
            label: "needed label".into(),
        };
        assert_eq!(
            subject(&set, &Values::new()),
            Err(wanted.clone()),
            "{field}"
        );
        assert_eq!(
            unbuildable(&set),
            vec![Unsupported {
                name: "needed".into(),
                label: "needed label".into(),
                required: true
            }]
        );
    }
}

#[test]
fn a_second_value_for_a_name_type_is_refused() {
    let raw = [
        multi("units", json!([{ "fieldType": "rdn", "rdn": "OU" }])),
        one("host", json!([{ "fieldType": "rdn", "rdn": "CN" }])),
        one("again", json!([{ "fieldType": "rdn", "rdn": "cn" }])),
    ];
    let set = definitions(&raw);
    assert_eq!(
        subject(&set, &values(&[("units", added(&["a", "b"]))])),
        Err(Unmappable::Repeated {
            label: "units label".into()
        })
    );
    assert_eq!(
        subject(&set, &values(&[("host", text("a")), ("again", text("b"))])),
        Err(Unmappable::Repeated {
            label: "again label".into()
        })
    );
}

#[test]
fn the_errors_say_it_in_plain_words() {
    let label = || "Host".to_owned();
    assert_eq!(
        Unmappable::Unsupported { label: label() }.to_string(),
        "Host cannot be put in the request by this application."
    );
    assert_eq!(
        Unmappable::Invalid { label: label() }.to_string(),
        "Host is not valid for the request."
    );
    assert_eq!(
        Unmappable::Repeated { label: label() }.to_string(),
        "Host has more than one value, which the request cannot hold."
    );
}

#[test]
fn a_signed_request_carries_the_subject_and_the_alternative_names() {
    let raw = [
        one(
            "country",
            json!([{ "fieldType": "rdn", "rdn": "C", "order": 3 }]),
        ),
        one(
            "host",
            json!([
                { "fieldType": "rdn", "rdn": "CN", "order": 1 },
                { "fieldType": "san", "generalNameType": "dns", "order": 1 }
            ]),
        ),
        one(
            "org",
            json!([{ "fieldType": "rdn", "rdn": "O", "order": 2 }]),
        ),
        one(
            "upn",
            json!([{
                "fieldType": "san",
                "generalNameType": "otherName",
                "otherNameOid": "1.3.6.1.4.1.311.20.2.3"
            }]),
        ),
        one(
            "ip",
            json!([{ "fieldType": "san", "generalNameType": "ip", "order": 2 }]),
        ),
    ];
    let given = values(&[
        ("country", text("CZ")),
        ("host", text("host.example")),
        ("org", text("Example")),
        ("upn", text("a@corp.example")),
        ("ip", text("192.0.2.7")),
    ]);
    let wanted = subject(&definitions(&raw), &given).unwrap();
    let key = InMemoryStorage::new(&[Storage::Software])
        .create(Storage::Software, KeyType::EcP256)
        .unwrap();
    let der = signing_request(key.as_ref(), &wanted).unwrap();
    let (_, request) = X509CertificationRequest::from_der(&der).unwrap();
    let info = &request.certification_request_info;
    let subject_names: Vec<String> = info
        .subject
        .iter_attributes()
        .map(|attribute| attribute.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(subject_names, ["host.example", "Example", "CZ"]);
    let found: Vec<String> = request
        .requested_extensions()
        .unwrap()
        .filter_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(san) => Some(san),
            _ => None,
        })
        .flat_map(|san| san.general_names.iter())
        .map(|name| match name {
            GeneralName::DNSName(name) => format!("dns {name}"),
            GeneralName::IPAddress(bytes) => format!("ip {bytes:?}"),
            GeneralName::OtherName(oid, value) => {
                format!("other {oid} {}", String::from_utf8_lossy(value))
            }
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0], "dns host.example");
    assert_eq!(found[1], "ip [192, 0, 2, 7]");
    assert!(found[2].starts_with("other 1.3.6.1.4.1.311.20.2.3"));
    assert!(found[2].contains("a@corp.example"));
}

#[test]
fn name_types_are_encoded_by_what_they_are() {
    let key = InMemoryStorage::new(&[Storage::Software])
        .create(Storage::Software, KeyType::EcP256)
        .unwrap();
    let wanted = RequestSubject {
        names: names(&[
            (NameType::DomainComponent, "example"),
            (NameType::Email, "a@b.example"),
            (NameType::Country, "CZ"),
        ]),
        alternative_names: Vec::new(),
    };
    let der = signing_request(key.as_ref(), &wanted).unwrap();
    let (_, request) = X509CertificationRequest::from_der(&der).unwrap();
    let tags: Vec<(String, u32)> = request
        .certification_request_info
        .subject
        .iter_attributes()
        .map(|attribute| {
            (
                attribute.attr_type().to_id_string(),
                attribute.attr_value().header.tag().0,
            )
        })
        .collect();
    // IA5String is 22 and PrintableString 19.
    assert_eq!(
        tags,
        [
            ("0.9.2342.19200300.100.1.25".to_owned(), 22),
            ("1.2.840.113549.1.9.1".to_owned(), 22),
            ("2.5.4.6".to_owned(), 19),
        ]
    );
}
