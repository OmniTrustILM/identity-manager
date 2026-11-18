//! A provider's authorization server metadata (OIDC discovery, else RFC 8414).

use std::fmt;

use reqwest::Client;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub cimd_supported: bool,
    pub code_challenge_methods_supported: Vec<String>,
    /// Whether every answer from the provider names its issuer in `iss` (RFC 9207).
    pub iss_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataError {
    InvalidIssuer,
    Unreachable,
    IssuerMismatch,
    MissingEndpoint(&'static str),
    InsecureEndpoint(&'static str),
    NoS256,
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIssuer => f.write_str("the issuer is not a valid https address"),
            Self::Unreachable => f.write_str("no usable provider metadata was found"),
            Self::IssuerMismatch => {
                f.write_str("the issuer in the metadata differs from the published one")
            }
            Self::MissingEndpoint(name) => write!(f, "the metadata has no {name}"),
            Self::InsecureEndpoint(name) => write!(f, "the {name} is not an https address"),
            Self::NoS256 => f.write_str("the provider does not support PKCE with S256"),
        }
    }
}

impl std::error::Error for MetadataError {}

#[derive(Deserialize)]
struct Document {
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    client_id_metadata_document_supported: Option<bool>,
    code_challenge_methods_supported: Option<Vec<String>>,
    authorization_response_iss_parameter_supported: Option<bool>,
}

pub async fn provider_metadata(
    client: &Client,
    issuer: &str,
) -> Result<ProviderMetadata, MetadataError> {
    let issuer_url = Url::parse(issuer).map_err(|_| MetadataError::InvalidIssuer)?;
    if !is_secure(&issuer_url) {
        return Err(MetadataError::InvalidIssuer);
    }
    let result = match fetch(client, &oidc_address(&issuer_url)).await {
        Some(document) => accept(document, issuer),
        None => match fetch(client, &rfc8414_address(&issuer_url)).await {
            Some(document) => accept(document, issuer),
            None => Err(MetadataError::Unreachable),
        },
    };
    match &result {
        Ok(_) => log::info!("{issuer}: provider metadata found"),
        Err(error) => log::warn!("{issuer}: provider refused: {error}"),
    }
    result
}

fn oidc_address(issuer: &Url) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.as_str().trim_end_matches('/')
    )
}

fn rfc8414_address(issuer: &Url) -> String {
    let path = issuer.path().trim_end_matches('/');
    format!(
        "{}/.well-known/oauth-authorization-server{path}",
        issuer.origin().ascii_serialization()
    )
}

async fn fetch(client: &Client, address: &str) -> Option<Document> {
    let response = client.get(address).send().await.ok()?;
    if !response.status().is_success() {
        log::debug!("{address}: answered {}", response.status());
        return None;
    }
    response.json().await.ok()
}

fn accept(document: Document, issuer: &str) -> Result<ProviderMetadata, MetadataError> {
    if document.issuer.as_deref() != Some(issuer) {
        return Err(MetadataError::IssuerMismatch);
    }
    let authorization_endpoint =
        secure_endpoint(document.authorization_endpoint, "authorization_endpoint")?;
    let token_endpoint = secure_endpoint(document.token_endpoint, "token_endpoint")?;
    let revocation_endpoint = match document.revocation_endpoint {
        Some(_) => Some(secure_endpoint(
            document.revocation_endpoint,
            "revocation_endpoint",
        )?),
        None => None,
    };
    // Many providers do not publish their methods; a published list must hold S256.
    if document
        .code_challenge_methods_supported
        .as_ref()
        .is_some_and(|methods| !methods.iter().any(|method| method == "S256"))
    {
        return Err(MetadataError::NoS256);
    }
    let methods = document
        .code_challenge_methods_supported
        .unwrap_or_default();
    Ok(ProviderMetadata {
        issuer: issuer.to_owned(),
        authorization_endpoint,
        token_endpoint,
        revocation_endpoint,
        cimd_supported: document
            .client_id_metadata_document_supported
            .unwrap_or(false),
        code_challenge_methods_supported: methods,
        iss_required: document
            .authorization_response_iss_parameter_supported
            .unwrap_or(false),
    })
}

fn secure_endpoint(value: Option<String>, name: &'static str) -> Result<String, MetadataError> {
    let value = value.ok_or(MetadataError::MissingEndpoint(name))?;
    match Url::parse(&value) {
        Ok(url) if is_secure(&url) => Ok(value),
        _ => Err(MetadataError::InsecureEndpoint(name)),
    }
}

fn is_secure(url: &Url) -> bool {
    url.scheme() == "https"
        || (cfg!(test) && url.scheme() == "http" && url.host_str() == Some("127.0.0.1"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn document(issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
        })
    }

    async fn serve(server: &MockServer, at: &str, body: Value) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn reads_the_oidc_document_with_all_fields() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let mut body = document(&issuer);
        body["revocation_endpoint"] = json!(format!("{issuer}/revoke"));
        body["client_id_metadata_document_supported"] = json!(true);
        body["code_challenge_methods_supported"] = json!(["plain", "S256"]);
        body["authorization_response_iss_parameter_supported"] = json!(true);
        serve(&server, "/.well-known/openid-configuration", body).await;

        let metadata = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap();
        assert_eq!(metadata.issuer, issuer);
        assert_eq!(metadata.authorization_endpoint, format!("{issuer}/auth"));
        assert_eq!(metadata.token_endpoint, format!("{issuer}/token"));
        assert_eq!(
            metadata.revocation_endpoint,
            Some(format!("{issuer}/revoke"))
        );
        assert!(metadata.cimd_supported);
        assert_eq!(metadata.code_challenge_methods_supported, ["plain", "S256"]);
        assert!(metadata.iss_required);
    }

    #[tokio::test]
    async fn optional_fields_may_be_absent() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        serve(
            &server,
            "/.well-known/openid-configuration",
            document(&issuer),
        )
        .await;

        let metadata = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap();
        assert_eq!(metadata.revocation_endpoint, None);
        assert!(!metadata.cimd_supported);
        assert!(metadata.code_challenge_methods_supported.is_empty());
        assert!(!metadata.iss_required);
    }

    #[tokio::test]
    async fn keeps_the_issuer_path_for_oidc_and_ignores_a_trailing_slash() {
        let server = MockServer::start().await;
        let issuer = format!("{}/realms/x/", server.uri());
        serve(
            &server,
            "/realms/x/.well-known/openid-configuration",
            document(&issuer),
        )
        .await;

        assert!(
            provider_metadata(&client_for_tests(), &issuer)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn falls_back_to_rfc_8414_with_the_path_after_the_well_known_segment() {
        let server = MockServer::start().await;
        let issuer = format!("{}/realms/x", server.uri());
        serve(
            &server,
            "/.well-known/oauth-authorization-server/realms/x",
            document(&issuer),
        )
        .await;

        let metadata = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap();
        assert_eq!(metadata.issuer, issuer);
    }

    #[tokio::test]
    async fn falls_back_when_the_oidc_document_is_not_json() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        Mock::given(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
            .mount(&server)
            .await;
        serve(
            &server,
            "/.well-known/oauth-authorization-server",
            document(&issuer),
        )
        .await;

        assert!(
            provider_metadata(&client_for_tests(), &issuer)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn no_document_at_either_address_is_unreachable() {
        let server = MockServer::start().await;
        let error = provider_metadata(&client_for_tests(), &server.uri())
            .await
            .unwrap_err();
        assert_eq!(error, MetadataError::Unreachable);
    }

    #[tokio::test]
    async fn an_issuer_that_differs_is_refused() {
        let server = MockServer::start().await;
        serve(
            &server,
            "/.well-known/openid-configuration",
            document("https://other.example"),
        )
        .await;

        let error = provider_metadata(&client_for_tests(), &server.uri())
            .await
            .unwrap_err();
        assert_eq!(error, MetadataError::IssuerMismatch);
    }

    #[tokio::test]
    async fn a_missing_endpoint_is_refused() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let mut body = document(&issuer);
        body.as_object_mut().unwrap().remove("token_endpoint");
        serve(&server, "/.well-known/openid-configuration", body).await;

        let error = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap_err();
        assert_eq!(error, MetadataError::MissingEndpoint("token_endpoint"));
    }

    #[tokio::test]
    async fn an_endpoint_that_is_not_https_is_refused() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let mut body = document(&issuer);
        body["authorization_endpoint"] = json!("http://idp.example/auth");
        serve(&server, "/.well-known/openid-configuration", body).await;

        let error = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            MetadataError::InsecureEndpoint("authorization_endpoint")
        );
    }

    #[tokio::test]
    async fn a_revocation_endpoint_that_is_not_https_is_refused() {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let mut body = document(&issuer);
        body["revocation_endpoint"] = json!("ftp://idp.example/revoke");
        serve(&server, "/.well-known/openid-configuration", body).await;

        let error = provider_metadata(&client_for_tests(), &issuer)
            .await
            .unwrap_err();
        assert_eq!(
            error,
            MetadataError::InsecureEndpoint("revocation_endpoint")
        );
    }

    #[tokio::test]
    async fn a_method_list_without_s256_is_refused_even_when_empty() {
        for methods in [json!(["plain"]), json!([])] {
            let server = MockServer::start().await;
            let issuer = server.uri();
            let mut body = document(&issuer);
            body["code_challenge_methods_supported"] = methods;
            serve(&server, "/.well-known/openid-configuration", body).await;

            let error = provider_metadata(&client_for_tests(), &issuer)
                .await
                .unwrap_err();
            assert_eq!(error, MetadataError::NoS256);
        }
    }

    #[tokio::test]
    async fn an_issuer_that_is_not_a_secure_address_is_invalid() {
        for issuer in ["not a url", "http://idp.example"] {
            let error = provider_metadata(&client_for_tests(), issuer)
                .await
                .unwrap_err();
            assert_eq!(error, MetadataError::InvalidIssuer);
        }
    }

    #[test]
    fn errors_have_plain_messages() {
        assert!(MetadataError::NoS256.to_string().contains("S256"));
        assert!(MetadataError::Unreachable.to_string().contains("no usable"));
    }
}
