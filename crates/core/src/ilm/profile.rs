//! Who ILM says the signed-in person is, and what they may see.

use std::fmt;

use std::str::FromStr;

use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::IlmUrl;
use crate::identity::Fingerprint;
use crate::token::AccessToken;

/// Why ILM could not tell who the person is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlmError {
    Unauthorized,
    Unreachable,
    Unexpected(u16),
    Malformed,
}

impl fmt::Display for IlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IlmError::Unauthorized => f.write_str("ILM did not accept the sign-in."),
            IlmError::Unreachable => f.write_str("ILM cannot be reached."),
            IlmError::Unexpected(status) => write!(f, "ILM answered with an error ({status})."),
            IlmError::Malformed => {
                f.write_str("ILM answered in a way this application does not understand.")
            }
        }
    }
}

impl std::error::Error for IlmError {}

/// What a person may do on one kind of object.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ResourceActions {
    pub resource: String,
    pub actions: Vec<String>,
}

/// The certificate ILM knows the person by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInCertificate {
    pub uuid: String,
    pub fingerprint: Fingerprint,
}

/// The signed-in person and their permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub uuid: String,
    pub username: String,
    pub display_name: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub sign_in: Option<SignInCertificate>,
    pub allowed_listings: Vec<String>,
    pub allowed_actions: Vec<ResourceActions>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    uuid: String,
    username: String,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    description: Option<String>,
    certificate: Option<ProfileCertificate>,
    permissions: Permissions,
}

#[derive(Deserialize)]
struct ProfileCertificate {
    uuid: String,
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Permissions {
    allowed_listings: Vec<String>,
    #[serde(default)]
    allowed_actions: Vec<ResourceActions>,
}

impl From<Profile> for Person {
    fn from(profile: Profile) -> Self {
        let name = [profile.first_name.as_ref(), profile.last_name.as_ref()]
            .into_iter()
            .flatten()
            .map(|part| part.trim().to_string())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let display_name = if name.is_empty() {
            profile.username.clone()
        } else {
            name
        };
        Person {
            uuid: profile.uuid,
            username: profile.username,
            display_name,
            first_name: profile.first_name,
            last_name: profile.last_name,
            email: profile.email,
            description: profile.description,
            sign_in: profile.certificate.and_then(|certificate| {
                Some(SignInCertificate {
                    fingerprint: Fingerprint::from_str(&certificate.fingerprint).ok()?,
                    uuid: certificate.uuid,
                })
            }),
            allowed_listings: profile.permissions.allowed_listings,
            allowed_actions: profile.permissions.allowed_actions,
        }
    }
}

pub(super) fn profile_address(ilm: &IlmUrl) -> String {
    format!("{}/v1/auth/profile", ilm.api())
}

/// Asks ILM who the token belongs to.
pub async fn profile(
    client: &Client,
    ilm: &IlmUrl,
    token: &AccessToken,
) -> Result<Person, IlmError> {
    let response = client
        .get(profile_address(ilm))
        .bearer_auth(token.as_str())
        .send()
        .await
        .map_err(|_| {
            log::warn!("ILM at {ilm} could not be reached for the profile");
            IlmError::Unreachable
        })?;
    if response.status() == StatusCode::UNAUTHORIZED {
        log::warn!("ILM at {ilm} refused the access token");
        return Err(IlmError::Unauthorized);
    }
    read_profile(ilm, response).await
}

/// The profile request without a token, for a client that proves the person with a certificate.
pub(crate) fn profile_request(client: &Client, ilm: &IlmUrl) -> reqwest::RequestBuilder {
    client.get(profile_address(ilm))
}

/// Reads the answer to a profile request that was not a 401.
pub(crate) async fn read_profile(
    ilm: &IlmUrl,
    response: reqwest::Response,
) -> Result<Person, IlmError> {
    let status = response.status();
    if !status.is_success() {
        log::warn!("ILM at {ilm} answered the profile request with {status}");
        return Err(IlmError::Unexpected(status.as_u16()));
    }
    let profile = response.json::<Profile>().await.map_err(|_| {
        log::warn!("ILM at {ilm} sent a profile this application cannot read");
        IlmError::Malformed
    })?;
    Ok(Person::from(profile))
}

/// The request that makes the certificate `certificate_uuid` the person's sign-in certificate. ILM replaces the
/// names, email and description with what it is sent, so the person's own are sent back unchanged.
pub fn update_request(
    client: &Client,
    ilm: &IlmUrl,
    person: &Person,
    certificate_uuid: &str,
) -> RequestBuilder {
    client.put(profile_address(ilm)).json(&json!({
        "firstName": person.first_name,
        "lastName": person.last_name,
        "email": person.email,
        "description": person.description,
        "certificateUuid": certificate_uuid,
    }))
}

/// The messages ILM gives for a request it refused, in plain words; none when the answer holds no text. ILM
/// sends a message, a list of messages or an object holding either; the text is for the person, never the log.
pub(crate) async fn read_rejection(response: reqwest::Response) -> Vec<String> {
    let body = response.json::<serde_json::Value>().await;
    body.map(|body| messages(&body)).unwrap_or_default()
}

fn messages(body: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    match body {
        Value::String(text) => vec![text.clone()],
        Value::Array(items) => items.iter().flat_map(messages).collect(),
        Value::Object(fields) => ["message", "messages", "errors"]
            .into_iter()
            .filter_map(|key| fields.get(key))
            .flat_map(messages)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn fixture() -> serde_json::Value {
        json!({
            "uuid": "5d3a4c3e-0000-4000-8000-000000000001",
            "username": "jdoe",
            "firstName": "Jane",
            "lastName": "Doe",
            "email": "jane@example.com",
            "enabled": true,
            "systemUser": false,
            "groups": [],
            "roles": [],
            "customAttributes": [],
            "permissions": {
                "allowedListings": ["certificates", "keys"],
                "allowedActions": [
                    { "resource": "certificates", "actions": ["list", "detail"] },
                    { "resource": "keys", "actions": ["list"] }
                ]
            }
        })
    }

    async fn ask(response: ResponseTemplate) -> Result<Person, IlmError> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .and(header("authorization", "Bearer abc"))
            .respond_with(response)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        profile(&client_for_tests(), &ilm, &AccessToken::new("abc")).await
    }

    #[tokio::test]
    async fn the_person_and_permissions_are_read() {
        let person = ask(ResponseTemplate::new(200).set_body_json(fixture()))
            .await
            .unwrap();
        assert_eq!(person.uuid, "5d3a4c3e-0000-4000-8000-000000000001");
        assert_eq!(person.username, "jdoe");
        assert_eq!(person.display_name, "Jane Doe");
        assert_eq!(person.allowed_listings, ["certificates", "keys"]);
        assert_eq!(person.allowed_actions.len(), 2);
        assert_eq!(person.allowed_actions[0].resource, "certificates");
        assert_eq!(person.allowed_actions[0].actions, ["list", "detail"]);
    }

    const PRINT: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[tokio::test]
    async fn the_details_and_the_sign_in_certificate_are_read() {
        let mut body = fixture();
        body["description"] = json!("Works in finance");
        body["certificate"] = json!({ "uuid": "c-1", "fingerprint": PRINT });
        let person = ask(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        assert_eq!(person.first_name.as_deref(), Some("Jane"));
        assert_eq!(person.last_name.as_deref(), Some("Doe"));
        assert_eq!(person.email.as_deref(), Some("jane@example.com"));
        assert_eq!(person.description.as_deref(), Some("Works in finance"));
        let sign_in = person.sign_in.unwrap();
        assert_eq!(sign_in.uuid, "c-1");
        assert_eq!(sign_in.fingerprint, PRINT.parse().unwrap());
    }

    #[tokio::test]
    async fn without_a_usable_certificate_there_is_no_sign_in_certificate() {
        let person = ask(ResponseTemplate::new(200).set_body_json(fixture()))
            .await
            .unwrap();
        assert_eq!(person.sign_in, None);
        assert_eq!(person.description, None);
        let mut body = fixture();
        body["certificate"] = json!({ "uuid": "c-1", "fingerprint": "not hex" });
        let person = ask(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        assert_eq!(person.sign_in, None);
    }

    #[tokio::test]
    async fn the_update_sends_the_details_back_with_the_certificate() {
        let mut body = fixture();
        body["description"] = json!("Works in finance");
        let person = ask(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/auth/profile"))
            .and(wiremock::matchers::body_json(json!({
                "firstName": "Jane",
                "lastName": "Doe",
                "email": "jane@example.com",
                "description": "Works in finance",
                "certificateUuid": "c-9"
            })))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let response = update_request(&client_for_tests(), &ilm, &person, "c-9")
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
    }

    #[tokio::test]
    async fn without_a_name_the_user_name_is_shown() {
        let mut body = fixture();
        body["firstName"] = json!(null);
        body["lastName"] = json!("  ");
        body["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("allowedActions");
        let person = ask(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        assert_eq!(person.display_name, "jdoe");
        assert!(person.allowed_actions.is_empty());
    }

    #[tokio::test]
    async fn a_refused_token_is_unauthorized() {
        let error = ask(ResponseTemplate::new(401)).await.unwrap_err();
        assert_eq!(error, IlmError::Unauthorized);
    }

    #[tokio::test]
    async fn other_failures_and_garbage_are_told_apart() {
        assert_eq!(
            ask(ResponseTemplate::new(500)).await.unwrap_err(),
            IlmError::Unexpected(500)
        );
        assert_eq!(
            ask(ResponseTemplate::new(200).set_body_string("not json"))
                .await
                .unwrap_err(),
            IlmError::Malformed
        );
    }

    #[tokio::test]
    async fn a_server_that_is_gone_is_unreachable() {
        let ilm = IlmUrl::for_tests("http://127.0.0.1:1");
        let error = profile(&client_for_tests(), &ilm, &AccessToken::new("abc"))
            .await
            .unwrap_err();
        assert_eq!(error, IlmError::Unreachable);
    }

    #[test]
    fn every_error_has_a_plain_text() {
        for error in [
            IlmError::Unauthorized,
            IlmError::Unreachable,
            IlmError::Unexpected(502),
            IlmError::Malformed,
        ] {
            assert!(error.to_string().ends_with('.'));
        }
    }

    #[test]
    fn rejection_messages_are_read_from_each_shape_ilm_uses() {
        assert_eq!(messages(&json!("One.")), ["One."]);
        assert_eq!(messages(&json!(["One.", "Two."])), ["One.", "Two."]);
        assert_eq!(messages(&json!({ "message": ["One."] })), ["One."]);
        assert_eq!(
            messages(&json!({ "message": "One.", "errors": ["Two."], "status": 422 })),
            ["One.", "Two."]
        );
        assert!(messages(&json!({ "status": 422 })).is_empty());
    }
}
