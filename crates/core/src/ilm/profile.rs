//! Who ILM says the signed-in person is, and what they may see.

use std::fmt;

use reqwest::{Client, StatusCode};
use serde::Deserialize;

use super::IlmUrl;
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

/// The signed-in person and their permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub username: String,
    pub display_name: String,
    pub allowed_listings: Vec<String>,
    pub allowed_actions: Vec<ResourceActions>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    username: String,
    first_name: Option<String>,
    last_name: Option<String>,
    permissions: Permissions,
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
        let name = [profile.first_name, profile.last_name]
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
            username: profile.username,
            display_name,
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
        assert_eq!(person.username, "jdoe");
        assert_eq!(person.display_name, "Jane Doe");
        assert_eq!(person.allowed_listings, ["certificates", "keys"]);
        assert_eq!(person.allowed_actions.len(), 2);
        assert_eq!(person.allowed_actions[0].resource, "certificates");
        assert_eq!(person.allowed_actions[0].actions, ["list", "detail"]);
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
}
