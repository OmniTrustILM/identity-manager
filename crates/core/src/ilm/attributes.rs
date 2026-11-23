//! The attribute definitions ILM gives out, the callbacks that fill them, and the address of ILM's web interface.
//! Definitions and callback answers stay raw JSON here; reading them is the job of the attribute model.

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use serde_json::{Map, Value};
use url::Url;

use super::IlmUrl;
use super::profile::IlmError;

/// The custom attributes of certificates.
pub fn custom_attributes_request(client: &Client, ilm: &IlmUrl) -> RequestBuilder {
    client.get(format!(
        "{}/v1/attributes/custom/resources/certificates",
        ilm.api()
    ))
}

/// The attributes an RA Profile asks for when a certificate is issued.
pub fn issue_attributes_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
) -> RequestBuilder {
    client.get(format!(
        "{}/v2/operations/authorities/{authority}/raProfiles/{ra_profile}/attributes/issue",
        ilm.api()
    ))
}

/// The attributes an RA Profile asks for when a certificate request is made.
pub fn csr_attributes_request(client: &Client, ilm: &IlmUrl, ra_profile: &str) -> RequestBuilder {
    let mut url = format!("{}/v1/certificates/csr/attributes", ilm.api());
    url.push_str("?raProfileUuid=");
    url.extend(url::form_urlencoded::byte_serialize(ra_profile.as_bytes()));
    client.get(url)
}

/// Reads a list of definitions as ILM sent it.
async fn read_definitions(response: Response, what: &str) -> Result<Vec<Value>, IlmError> {
    let status = response.status();
    match status {
        StatusCode::UNAUTHORIZED => Err(IlmError::Unauthorized),
        _ if status.is_success() => response.json::<Vec<Value>>().await.map_err(|_| {
            log::warn!("ILM sent {what} this application cannot read");
            IlmError::Malformed
        }),
        _ => {
            log::warn!("ILM answered the {what} request with {status}");
            Err(IlmError::Unexpected(status.as_u16()))
        }
    }
}

/// Reads the custom attributes; none when the person may not list them (403) or ILM does not have them (404).
pub async fn read_custom_attributes(response: Response) -> Result<Option<Vec<Value>>, IlmError> {
    let status = response.status();
    if matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND) {
        log::info!("ILM does not give the custom attributes ({status})");
        return Ok(None);
    }
    read_definitions(response, "custom attributes")
        .await
        .map(Some)
}

/// Reads the issue attributes of an RA Profile.
pub async fn read_issue_attributes(response: Response) -> Result<Vec<Value>, IlmError> {
    read_definitions(response, "issue attributes").await
}

/// Reads the CSR attributes of an RA Profile.
pub async fn read_csr_attributes(response: Response) -> Result<Vec<Value>, IlmError> {
    read_definitions(response, "CSR attributes").await
}

/// The endpoint a callback goes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackRoute {
    /// A connector's function group and kind, as the legacy forms ask for.
    Connector {
        connector: String,
        function_group: String,
        kind: String,
    },
    /// A connector, for the forms that name their interface in the body.
    ConnectorInterface { connector: String },
    /// A resource asked through its parent: an RA Profile through its authority, a certificate through its RA
    /// Profile.
    Resource { resource: String, parent: String },
}

/// What a callback sends: the values the mappings resolved, or the attributes the field depends on.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallbackBody {
    /// The attribute's UUID.
    pub uuid: String,
    /// The attribute's name; ILM finds the callback by it.
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_uuid: Option<String>,
    pub path_variable: Map<String, Value>,
    pub request_parameter: Map<String, Value>,
    pub body: Map<String, Value>,
    pub filter: Map<String, Value>,
    /// Request attributes of the fields a `dependsOn` callback names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<Value>,
}

/// The callback of one attribute.
pub fn callback_request(
    client: &Client,
    ilm: &IlmUrl,
    route: &CallbackRoute,
    body: &CallbackBody,
) -> RequestBuilder {
    let api = ilm.api();
    let url = match route {
        CallbackRoute::Connector {
            connector,
            function_group,
            kind,
        } => format!("{api}/v1/connectors/{connector}/{function_group}/{kind}/callback"),
        CallbackRoute::ConnectorInterface { connector } => {
            format!("{api}/v2/connectors/{connector}/callback")
        }
        CallbackRoute::Resource { resource, parent } => {
            format!("{api}/v1/{resource}/{parent}/callback")
        }
    };
    client.post(url).json(body)
}

/// What ILM answered to a callback.
#[derive(Debug, Clone, PartialEq)]
pub enum CallbackAnswer {
    /// Content items: the options or the value of the field.
    Content(Vec<Value>),
    /// Attribute definitions: the fields a group adds.
    Definitions(Vec<Value>),
}

/// Why a callback gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackError {
    /// The person may not do this.
    NotAllowed,
    /// ILM did not answer; the status says how.
    Failed(u16),
}

/// An answer is a list, or an object holding `content` or `attributes`. Items without `data` that name their
/// `type` are definitions.
fn answer_of(body: Value) -> Option<CallbackAnswer> {
    let (items, definitions) = match body {
        Value::Array(items) => {
            let definitions = !items.is_empty() && items.iter().all(is_definition);
            (items, definitions)
        }
        Value::Object(mut object) => {
            match (object.remove("content"), object.remove("attributes")) {
                (Some(Value::Array(items)), _) => (items, false),
                (_, Some(Value::Array(items))) => (items, true),
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(if definitions {
        CallbackAnswer::Definitions(items)
    } else {
        CallbackAnswer::Content(items)
    })
}

fn is_definition(item: &Value) -> bool {
    item.get("type").is_some_and(Value::is_string) && item.get("data").is_none()
}

/// Reads the answer to a callback.
pub async fn read_callback(response: Response) -> Result<CallbackAnswer, CallbackError> {
    let status = response.status();
    match status {
        StatusCode::FORBIDDEN => Err(CallbackError::NotAllowed),
        _ if status.is_success() => {
            let body = response.json::<Value>().await.ok();
            body.and_then(answer_of).ok_or_else(|| {
                log::warn!("ILM sent a callback answer this application cannot read");
                CallbackError::Failed(status.as_u16())
            })
        }
        _ => {
            log::warn!("ILM answered a callback with {status}");
            Err(CallbackError::Failed(status.as_u16()))
        }
    }
}

/// A page of ILM's web interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebTarget<'a> {
    /// The certificates, where ILM imports and uploads them.
    AddToIlm,
    RaProfile {
        authority: &'a str,
        ra_profile: &'a str,
    },
}

/// The address of a page of ILM's web interface: the origin of the ILM address, then the interface's own path.
pub fn web_url(ilm: &IlmUrl, target: &WebTarget) -> String {
    let origin = Url::parse(ilm.as_str())
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| ilm.as_str().to_string());
    let page = match target {
        WebTarget::AddToIlm => "certificates".to_string(),
        WebTarget::RaProfile {
            authority,
            ra_profile,
        } => format!("raprofiles/detail/{authority}/{ra_profile}"),
    };
    format!("{origin}/administrator/#/{page}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn certificate_attributes() -> Value {
        json!([
            {
                "uuid": "a1b2c3d4-0000-4000-8000-000000000001",
                "name": "department",
                "description": "Owning department",
                "version": 3,
                "schemaVersion": "v3",
                "type": "custom",
                "contentType": "string",
                "properties": {
                    "label": "Department",
                    "visible": true,
                    "group": "GroupMeNow",
                    "required": false,
                    "readOnly": false,
                    "list": true,
                    "multiSelect": true,
                    "extensibleList": false
                },
                "content": [
                    { "data": "Sales", "contentType": "string" },
                    { "data": "IT", "contentType": "string" }
                ]
            },
            {
                "uuid": "a1b2c3d4-0000-4000-8000-000000000002",
                "name": "TestInt",
                "version": 3,
                "schemaVersion": "v3",
                "type": "custom",
                "contentType": "integer",
                "properties": { "label": "Test integer", "visible": true, "group": null }
            },
            {
                "uuid": "a1b2c3d4-0000-4000-8000-000000000003",
                "name": "qa_test_custom_attr",
                "version": 3,
                "schemaVersion": "v3",
                "type": "custom",
                "contentType": "string",
                "properties": { "label": "QA attribute", "visible": true, "group": null },
                "content": [{ "data": "default text", "contentType": "string" }]
            }
        ])
    }

    fn request_attributes() -> Value {
        json!([
            {
                "uuid": "b1b2c3d4-0000-4000-8000-000000000001",
                "name": "common-name",
                "version": 3,
                "schemaVersion": "v3",
                "type": "data",
                "contentType": "string",
                "properties": { "label": "Common name", "required": true, "readOnly": true, "visible": true },
                "content": [{ "data": "host.example.com", "contentType": "string" }]
            },
            {
                "uuid": "b1b2c3d4-0000-4000-8000-000000000002",
                "name": "san",
                "version": 3,
                "schemaVersion": "v3",
                "type": "data",
                "contentType": "string",
                "properties": { "label": "SAN", "list": true, "multiSelect": true, "extensibleList": true }
            },
            {
                "uuid": "b1b2c3d4-0000-4000-8000-000000000003",
                "name": "service-entitlement",
                "version": 3,
                "schemaVersion": "v3",
                "type": "data",
                "contentType": "text",
                "properties": { "label": "Service entitlement" }
            }
        ])
    }

    fn issue_attributes() -> Value {
        json!([
            {
                "uuid": "c1b2c3d4-0000-4000-8000-000000000001",
                "name": "email",
                "version": 2,
                "type": "data",
                "contentType": "string",
                "properties": { "label": "Email", "required": false }
            },
            {
                "uuid": "c1b2c3d4-0000-4000-8000-000000000002",
                "name": "san",
                "version": 2,
                "type": "data",
                "contentType": "string",
                "properties": { "label": "SAN", "list": true, "multiSelect": true }
            },
            {
                "uuid": "c1b2c3d4-0000-4000-8000-000000000003",
                "name": "extension",
                "version": 2,
                "type": "group",
                "content": [],
                "attributeCallback": {
                    "callbackContext": "core/getCredentials",
                    "callbackMethod": "GET",
                    "mappings": [{ "to": "credentialKind", "targets": ["pathVariable"], "value": "Basic" }]
                }
            }
        ])
    }

    async fn serve_get(route: &str, response: ResponseTemplate) -> (MockServer, IlmUrl) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        (server, ilm)
    }

    async fn custom(response: ResponseTemplate) -> Result<Option<Vec<Value>>, IlmError> {
        let (_server, ilm) =
            serve_get("/api/v1/attributes/custom/resources/certificates", response).await;
        let sent = custom_attributes_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        read_custom_attributes(sent).await
    }

    async fn issue(response: ResponseTemplate) -> Result<Vec<Value>, IlmError> {
        let (_server, ilm) = serve_get(
            "/api/v2/operations/authorities/a-1/raProfiles/r-1/attributes/issue",
            response,
        )
        .await;
        let sent = issue_attributes_request(&client_for_tests(), &ilm, "a-1", "r-1")
            .send()
            .await
            .unwrap();
        read_issue_attributes(sent).await
    }

    async fn csr(response: ResponseTemplate) -> Result<Vec<Value>, IlmError> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/certificates/csr/attributes"))
            .and(query_param("raProfileUuid", "r-1"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = csr_attributes_request(&client_for_tests(), &ilm, "r-1")
            .send()
            .await
            .unwrap();
        read_csr_attributes(sent).await
    }

    #[tokio::test]
    async fn the_custom_attributes_come_back_raw() {
        let body = certificate_attributes();
        let found = custom(ResponseTemplate::new(200).set_body_json(&body))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Array(found), body);
    }

    #[tokio::test]
    async fn custom_attributes_the_person_may_not_see_or_ilm_lacks_are_none() {
        for status in [403, 404] {
            assert_eq!(custom(ResponseTemplate::new(status)).await, Ok(None));
        }
    }

    #[tokio::test]
    async fn other_custom_attribute_answers_are_errors() {
        assert_eq!(
            custom(ResponseTemplate::new(401)).await,
            Err(IlmError::Unauthorized)
        );
        assert_eq!(
            custom(ResponseTemplate::new(500)).await,
            Err(IlmError::Unexpected(500))
        );
        assert_eq!(
            custom(ResponseTemplate::new(200).set_body_string("{")).await,
            Err(IlmError::Malformed)
        );
        assert_eq!(
            custom(ResponseTemplate::new(200).set_body_json(json!({ "a": 1 }))).await,
            Err(IlmError::Malformed)
        );
    }

    #[tokio::test]
    async fn issue_attributes_come_back_raw_and_failures_are_errors() {
        let body = issue_attributes();
        let found = issue(ResponseTemplate::new(200).set_body_json(&body))
            .await
            .unwrap();
        assert_eq!(Value::Array(found), body);
        assert_eq!(
            issue(ResponseTemplate::new(403)).await,
            Err(IlmError::Unexpected(403))
        );
        assert_eq!(
            issue(ResponseTemplate::new(404)).await,
            Err(IlmError::Unexpected(404))
        );
        assert_eq!(
            issue(ResponseTemplate::new(500)).await,
            Err(IlmError::Unexpected(500))
        );
    }

    #[tokio::test]
    async fn csr_attributes_come_back_raw_and_failures_are_errors() {
        let body = request_attributes();
        let found = csr(ResponseTemplate::new(200).set_body_json(&body))
            .await
            .unwrap();
        assert_eq!(Value::Array(found), body);
        for status in [403, 404, 500] {
            assert_eq!(
                csr(ResponseTemplate::new(status)).await,
                Err(IlmError::Unexpected(status))
            );
        }
        assert_eq!(
            csr(ResponseTemplate::new(401)).await,
            Err(IlmError::Unauthorized)
        );
    }

    fn legacy_body() -> CallbackBody {
        let mut body = CallbackBody {
            uuid: "d1b2c3d4-0000-4000-8000-000000000001".into(),
            name: "credential".into(),
            ..CallbackBody::default()
        };
        body.path_variable
            .insert("credentialKind".into(), json!("Basic"));
        body.request_parameter.insert("page".into(), json!(1));
        body.body.insert("kind".into(), json!("x"));
        body.filter.insert("name.CONTAINS".into(), json!("ab"));
        body
    }

    async fn call(
        route: &CallbackRoute,
        body: &CallbackBody,
        route_path: &str,
        expected: Value,
        response: ResponseTemplate,
    ) -> Result<CallbackAnswer, CallbackError> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(route_path))
            .and(body_json(expected))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = callback_request(&client_for_tests(), &ilm, route, body)
            .send()
            .await
            .unwrap();
        read_callback(sent).await
    }

    fn items() -> Value {
        json!([{ "reference": "main", "data": { "uuid": "u-1", "name": "main" } }])
    }

    #[tokio::test]
    async fn a_legacy_connector_callback_goes_to_its_function_group_and_kind() {
        let route = CallbackRoute::Connector {
            connector: "k-1".into(),
            function_group: "authorityProvider".into(),
            kind: "EJBCA".into(),
        };
        let expected = json!({
            "uuid": "d1b2c3d4-0000-4000-8000-000000000001",
            "name": "credential",
            "pathVariable": { "credentialKind": "Basic" },
            "requestParameter": { "page": 1 },
            "body": { "kind": "x" },
            "filter": { "name.CONTAINS": "ab" }
        });
        let answer = call(
            &route,
            &legacy_body(),
            "/api/v1/connectors/k-1/authorityProvider/EJBCA/callback",
            expected,
            ResponseTemplate::new(200).set_body_json(items()),
        )
        .await;
        assert_eq!(
            answer,
            Ok(CallbackAnswer::Content(items().as_array().unwrap().clone()))
        );
    }

    #[tokio::test]
    async fn an_interface_callback_names_the_interface_and_carries_the_attributes() {
        let route = CallbackRoute::ConnectorInterface {
            connector: "k-1".into(),
        };
        let attribute = json!({
            "uuid": "b1b2c3d4-0000-4000-8000-000000000001",
            "name": "common-name",
            "contentType": "string",
            "version": "v3",
            "content": [{ "data": "host.example.com", "contentType": "string" }]
        });
        let body = CallbackBody {
            uuid: "d1b2c3d4-0000-4000-8000-000000000002".into(),
            name: "san".into(),
            interface_uuid: Some("e1b2c3d4-0000-4000-8000-000000000001".into()),
            attributes: vec![attribute.clone()],
            ..CallbackBody::default()
        };
        let expected = json!({
            "uuid": "d1b2c3d4-0000-4000-8000-000000000002",
            "name": "san",
            "interfaceUuid": "e1b2c3d4-0000-4000-8000-000000000001",
            "pathVariable": {},
            "requestParameter": {},
            "body": {},
            "filter": {},
            "attributes": [attribute]
        });
        let answer = call(
            &route,
            &body,
            "/api/v2/connectors/k-1/callback",
            expected,
            ResponseTemplate::new(200).set_body_json(json!({
                "content": [{ "data": "a.example.com", "contentType": "string" }]
            })),
        )
        .await;
        assert_eq!(
            answer,
            Ok(CallbackAnswer::Content(vec![
                json!({ "data": "a.example.com", "contentType": "string" })
            ]))
        );
    }

    #[tokio::test]
    async fn a_resource_callback_goes_through_its_parent() {
        let empty = json!({
            "uuid": "", "name": "", "pathVariable": {}, "requestParameter": {}, "body": {}, "filter": {}
        });
        for (resource, parent) in [("raProfiles", "a-1"), ("certificates", "r-1")] {
            let route = CallbackRoute::Resource {
                resource: resource.into(),
                parent: parent.into(),
            };
            let answer = call(
                &route,
                &CallbackBody::default(),
                &format!("/api/v1/{resource}/{parent}/callback"),
                empty.clone(),
                ResponseTemplate::new(200).set_body_json(json!([])),
            )
            .await;
            assert_eq!(answer, Ok(CallbackAnswer::Content(Vec::new())));
        }
    }

    #[tokio::test]
    async fn attribute_definitions_are_told_from_content() {
        let definitions = json!([{
            "uuid": "c1b2c3d4-0000-4000-8000-000000000001",
            "name": "email",
            "version": 2,
            "type": "data",
            "contentType": "string",
            "properties": { "label": "Email" }
        }]);
        let route = CallbackRoute::Resource {
            resource: "raProfiles".into(),
            parent: "a-1".into(),
        };
        for body in [
            definitions.clone(),
            json!({ "attributes": definitions.clone() }),
        ] {
            let answer = call(
                &route,
                &CallbackBody::default(),
                "/api/v1/raProfiles/a-1/callback",
                json!({
                    "uuid": "", "name": "", "pathVariable": {}, "requestParameter": {},
                    "body": {}, "filter": {}
                }),
                ResponseTemplate::new(200).set_body_json(body),
            )
            .await;
            assert_eq!(
                answer,
                Ok(CallbackAnswer::Definitions(
                    definitions.as_array().unwrap().clone()
                ))
            );
        }
    }

    #[tokio::test]
    async fn callback_failures_carry_the_status_only() {
        let route = CallbackRoute::ConnectorInterface {
            connector: "k-1".into(),
        };
        let body = CallbackBody::default();
        let expected = json!({
            "uuid": "", "name": "", "pathVariable": {}, "requestParameter": {}, "body": {}, "filter": {}
        });
        let cases = [
            (ResponseTemplate::new(403), CallbackError::NotAllowed),
            (ResponseTemplate::new(500), CallbackError::Failed(500)),
            (ResponseTemplate::new(422), CallbackError::Failed(422)),
            (
                ResponseTemplate::new(200).set_body_string("{"),
                CallbackError::Failed(200),
            ),
            (
                ResponseTemplate::new(200).set_body_json(json!(7)),
                CallbackError::Failed(200),
            ),
        ];
        for (response, error) in cases {
            let answer = call(
                &route,
                &body,
                "/api/v2/connectors/k-1/callback",
                expected.clone(),
                response,
            )
            .await;
            assert_eq!(answer, Err(error));
        }
    }

    #[test]
    fn the_web_address_is_the_origin_and_the_interface_path() {
        let cases = [
            ("https://ilm.example.com", "https://ilm.example.com"),
            (
                "https://ilm.example.com:8443",
                "https://ilm.example.com:8443",
            ),
            ("https://example.com/ilm", "https://example.com"),
        ];
        for (address, origin) in cases {
            let ilm = IlmUrl::parse(address).unwrap();
            assert_eq!(
                web_url(&ilm, &WebTarget::AddToIlm),
                format!("{origin}/administrator/#/certificates")
            );
            let target = WebTarget::RaProfile {
                authority: "a-1",
                ra_profile: "r-1",
            };
            assert_eq!(
                web_url(&ilm, &target),
                format!("{origin}/administrator/#/raprofiles/detail/a-1/r-1")
            );
        }
    }
}
