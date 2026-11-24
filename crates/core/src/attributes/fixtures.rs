//! Definitions shaped like the ones ILM sends, with no values of real systems.

use serde_json::{Value, json};

use super::Definitions;

/// A definition of `version` 3 or 2.
pub fn definition(
    version: u8,
    kind: &str,
    name: &str,
    content_type: &str,
    properties: Value,
) -> Value {
    let mut properties = properties;
    properties["label"] = json!(format!("{name} label"));
    let mut found = json!({
        "uuid": format!("00000000-0000-4000-8000-{:012}", name.len()),
        "name": name,
        "version": version,
        "type": kind,
        "contentType": content_type,
        "properties": properties,
    });
    if version == 3 {
        found["schemaVersion"] = json!("v3");
    }
    found
}

pub fn with(mut definition: Value, key: &str, value: Value) -> Value {
    definition[key] = value;
    definition
}

pub fn read(raw: &[Value]) -> Definitions {
    Definitions::read(raw)
}

/// The custom attributes of certificates.
pub fn certificate_custom() -> Vec<Value> {
    vec![
        with(
            with(
                definition(
                    3,
                    "custom",
                    "department",
                    "string",
                    json!({ "group": "GroupMeNow", "list": true, "multiSelect": true }),
                ),
                "content",
                json!([
                    { "data": "Sales", "contentType": "string" },
                    { "data": "IT", "contentType": "string" }
                ]),
            ),
            "description",
            json!("Owning department"),
        ),
        definition(3, "custom", "TestInt", "integer", json!({})),
        with(
            definition(3, "custom", "qa_test_custom_attr", "string", json!({})),
            "content",
            json!([{ "data": "qa was here", "contentType": "string" }]),
        ),
        with(
            definition(
                3,
                "custom",
                "Extensible List String",
                "string",
                json!({ "list": true, "extensibleList": true, "group": "GroupMeNow" }),
            ),
            "content",
            json!([
                { "data": "one", "contentType": "string" },
                { "data": "two", "contentType": "string" }
            ]),
        ),
        definition(3, "custom", "datecustom", "date", json!({})),
        definition(3, "custom", "repro-time", "time", json!({})),
        definition(3, "custom", "datetimecustom", "datetime", json!({})),
        definition(3, "custom", "Local Certificate", "boolean", json!({})),
    ]
}

/// The request attributes of an RA Profile.
pub fn request_attributes() -> Vec<Value> {
    vec![
        with(
            definition(
                3,
                "data",
                "common-name",
                "string",
                json!({ "required": true, "readOnly": true }),
            ),
            "content",
            json!([{ "reference": "host", "data": "host.example.com", "contentType": "string" }]),
        ),
        definition(
            3,
            "data",
            "san",
            "string",
            json!({ "list": true, "multiSelect": true, "extensibleList": true }),
        ),
        definition(3, "data", "service-entitlement", "text", json!({})),
    ]
}

/// A field mapping onto the certificate, with the fields as ILM sends them.
pub fn mapped(definition: Value, fields: Value) -> Value {
    with(
        definition,
        "fieldMapping",
        json!({ "objectType": "x509Certificate", "fields": fields }),
    )
}

/// The platform's default request set: six strings, each one name of the subject.
pub fn default_request_set() -> Vec<Value> {
    [
        ("commonName", "CN", true),
        ("organizationalUnit", "OU", false),
        ("organization", "O", false),
        ("locality", "L", false),
        ("state", "ST", false),
        ("country", "C", false),
    ]
    .into_iter()
    .map(|(name, rdn, required)| {
        mapped(
            definition(3, "data", name, "string", json!({ "required": required })),
            json!([{ "fieldType": "rdn", "rdn": rdn }]),
        )
    })
    .collect()
}

/// A request set with a read-only common name that is also a DNS name, a further DNS name and an extension.
pub fn demo_request_set() -> Vec<Value> {
    vec![
        with(
            mapped(
                definition(
                    3,
                    "data",
                    "common-name",
                    "string",
                    json!({ "required": true, "readOnly": true }),
                ),
                json!([
                    { "fieldType": "rdn", "rdn": "CN", "order": 1 },
                    { "fieldType": "san", "generalNameType": "dns", "order": 1 }
                ]),
            ),
            "content",
            json!([{ "data": "demo220", "contentType": "string" }]),
        ),
        mapped(
            definition(3, "data", "san", "string", json!({})),
            json!([{ "fieldType": "san", "generalNameType": "dns", "order": 2 }]),
        ),
        mapped(
            definition(3, "data", "service-entitlement", "string", json!({})),
            json!([{ "fieldType": "extension", "extensionOid": "1.3.6.1.5.5.7.1.24", "criticalOverridable": false }]),
        ),
    ]
}

/// One optional attribute that is a user principal name of Windows.
pub fn upn_request_set() -> Vec<Value> {
    vec![mapped(
        definition(3, "data", "upn", "string", json!({})),
        json!([{
            "fieldType": "san",
            "generalNameType": "otherName",
            "otherNameOid": "1.3.6.1.4.1.311.20.2.3",
            "otherNameValueEncoding": "UTF8String"
        }]),
    )]
}

/// The issue attributes of an RA Profile: version 2, one with a callback.
pub fn issue_attributes() -> Vec<Value> {
    vec![
        definition(2, "data", "email", "string", json!({ "required": false })),
        definition(
            2,
            "data",
            "san",
            "string",
            json!({ "list": true, "multiSelect": true }),
        ),
        json!({
            "uuid": "00000000-0000-4000-8000-0000000000e1",
            "name": "extension",
            "version": 2,
            "type": "group",
            "content": [],
            "attributeCallback": {
                "callbackContext": "core/getCredentials",
                "callbackMethod": "GET",
                "mappings": [{ "to": "credentialKind", "targets": ["pathVariable"], "value": "Basic" }]
            }
        }),
        with(
            definition(
                2,
                "data",
                "credential",
                "credential",
                json!({ "required": true }),
            ),
            "attributeCallback",
            json!({
                "callbackContext": "core/getCredentials",
                "callbackMethod": "GET",
                "mappings": [
                    { "from": "kind.data", "to": "credentialKind", "targets": ["pathVariable"] },
                    { "to": "page", "targets": ["requestParameter", "bad"], "value": 1 },
                    { "targets": ["body"], "value": "no target name" }
                ]
            }),
        ),
    ]
}

/// One data attribute of every content type, version 3 where ILM has one and version 2 where it has not.
pub fn every_type() -> Vec<Value> {
    let v3 = |name: &str, content_type: &str, content: Value| {
        with(
            definition(3, "data", name, content_type, json!({})),
            "content",
            content,
        )
    };
    let v2 = |name: &str, content_type: &str, content: Value| {
        with(
            definition(2, "data", name, content_type, json!({})),
            "content",
            content,
        )
    };
    vec![
        v3(
            "a_string",
            "string",
            json!([{ "data": "text", "contentType": "string" }]),
        ),
        v3(
            "a_text",
            "text",
            json!([{ "data": "lines", "contentType": "text" }]),
        ),
        v3(
            "an_integer",
            "integer",
            json!([{ "data": 7, "contentType": "integer" }]),
        ),
        v3(
            "a_float",
            "float",
            json!([{ "data": 1.5, "contentType": "float" }]),
        ),
        v3(
            "a_boolean",
            "boolean",
            json!([{ "data": true, "contentType": "boolean" }]),
        ),
        v3(
            "a_date",
            "date",
            json!([{ "data": "2026-02-28", "contentType": "date" }]),
        ),
        v3(
            "a_time",
            "time",
            json!([{ "data": "13:45:10", "contentType": "time" }]),
        ),
        v3(
            "a_datetime",
            "datetime",
            json!([{ "data": "2026-02-28T13:45:10.000+01:00", "contentType": "datetime" }]),
        ),
        v2(
            "a_secret",
            "secret",
            json!([{ "data": { "secret": "not-a-real-secret" } }]),
        ),
        v3(
            "a_file",
            "file",
            json!([{
                "data": { "content": "aGVsbG8=", "fileName": "hello.txt", "mimeType": "text/plain" },
                "contentType": "file"
            }]),
        ),
        v3(
            "a_codeblock",
            "codeblock",
            json!([{
                "data": { "code": "cHJpbnQoMSk=", "language": "python" },
                "contentType": "codeblock"
            }]),
        ),
        v3(
            "an_object",
            "object",
            json!([{ "data": { "key": [1, 2] }, "contentType": "object" }]),
        ),
        v2(
            "a_credential",
            "credential",
            json!([{ "reference": "main", "data": { "uuid": "u-1", "name": "main", "kind": "Basic", "attributes": [] } }]),
        ),
        v3(
            "a_resource",
            "resource",
            json!([{
                "reference": "Auth",
                "contentType": "resource",
                "data": { "resource": "authorities", "uuid": "u-2", "name": "Auth", "attributes": [] }
            }]),
        ),
    ]
}

/// A group, an info attribute, a meta attribute and attributes this application cannot show.
pub fn odd_ones() -> Vec<Value> {
    vec![
        json!({
            "uuid": "00000000-0000-4000-8000-0000000000a1",
            "name": "grouping",
            "version": 2,
            "type": "group",
            "content": []
        }),
        with(
            definition(3, "info", "notice", "text", json!({ "group": "Notes" })),
            "content",
            json!([
                { "data": "First line", "contentType": "text" },
                { "data": "Second line", "contentType": "text" }
            ]),
        ),
        definition(3, "meta", "source", "string", json!({ "global": true })),
        definition(
            3,
            "data",
            "future-type",
            "quaternion",
            json!({ "required": true }),
        ),
        definition(3, "data", "future-optional", "quaternion", json!({})),
        definition(7, "data", "future-version", "string", json!({})),
        definition(3, "future", "future-kind", "string", json!({})),
        json!({ "uuid": "x", "type": "data", "contentType": "string", "properties": { "label": "No name" } }),
        json!({ "name": "no-label", "type": "data", "contentType": "string", "properties": {} }),
        json!("not an object"),
    ]
}
