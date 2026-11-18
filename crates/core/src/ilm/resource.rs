//! What the ILM publishes about how to sign in (RFC 9728 protected resource metadata).

use std::fmt;

use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use url::Url;

use super::IlmUrl;
use super::profile::profile_address;

/// One identity provider the ILM accepts for applications.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PublishedProvider {
    pub issuer: String,
    pub name: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

/// The sign-in information of an ILM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceMetadata {
    pub resource: String,
    pub providers: Vec<PublishedProvider>,
}

/// Why the sign-in information could not be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    Unreachable,
    NotPublished { address: String },
    ForeignAddress { address: String },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::Unreachable => f.write_str("ILM cannot be reached."),
            DiscoveryError::NotPublished { address } => write!(
                f,
                "This ILM does not publish how to sign in. Address tried: {address}"
            ),
            DiscoveryError::ForeignAddress { address } => write!(
                f,
                "This ILM points to sign-in information on another server, which is not trusted: {address}"
            ),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[derive(Deserialize)]
struct Document {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
    #[serde(default)]
    otilm_authorization_servers: Vec<PublishedProvider>,
}

/// Finds and reads the sign-in information of the ILM, without a token.
pub async fn discover(client: &Client, ilm: &IlmUrl) -> Result<ResourceMetadata, DiscoveryError> {
    let address = metadata_address(client, ilm).await?;
    let response = client.get(&address).send().await.map_err(|_| {
        log::warn!("The sign-in information of {ilm} could not be fetched");
        DiscoveryError::Unreachable
    })?;
    let not_published = || DiscoveryError::NotPublished {
        address: address.clone(),
    };
    if !response.status().is_success() {
        log::warn!(
            "{ilm} answered {} at its sign-in information address",
            response.status()
        );
        return Err(not_published());
    }
    let document = response.json::<Document>().await.map_err(|_| {
        log::warn!("The sign-in information of {ilm} is not readable JSON");
        not_published()
    })?;
    if document.resource != ilm.api() {
        log::warn!(
            "The sign-in information of {ilm} is for another resource: {}",
            document.resource
        );
        return Err(not_published());
    }
    let metadata = accepted(ilm, document);
    for provider in &metadata.providers {
        log::info!(
            "{ilm} accepts sign-in with {} ({})",
            provider.name,
            provider.issuer
        );
    }
    Ok(metadata)
}

fn accepted(ilm: &IlmUrl, document: Document) -> ResourceMetadata {
    let providers = document
        .otilm_authorization_servers
        .into_iter()
        .filter(|provider| {
            let listed = document.authorization_servers.contains(&provider.issuer);
            if !listed {
                log::warn!(
                    "{ilm} lists {} without naming it as an authorization server; skipped",
                    provider.issuer
                );
            }
            listed
        })
        .collect();
    ResourceMetadata {
        resource: document.resource,
        providers,
    }
}

async fn metadata_address(client: &Client, ilm: &IlmUrl) -> Result<String, DiscoveryError> {
    let response = client.get(profile_address(ilm)).send().await.map_err(|_| {
        log::warn!("ILM at {ilm} could not be reached");
        DiscoveryError::Unreachable
    })?;
    if response.status() == StatusCode::UNAUTHORIZED
        && let Some(announced) = response
            .headers()
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(resource_metadata)
    {
        if !same_origin(ilm, announced) {
            log::warn!("{ilm} points to sign-in information on another origin; refused");
            return Err(DiscoveryError::ForeignAddress {
                address: announced.to_string(),
            });
        }
        log::info!("{ilm} announced where its sign-in information is");
        return Ok(announced.to_string());
    }
    log::info!("{ilm} announced nothing; using the standard address");
    Ok(standard_address(ilm))
}

fn resource_metadata(challenge: &str) -> Option<&str> {
    let (_, rest) = challenge.split_once("resource_metadata=\"")?;
    rest.split_once('"').map(|(value, _)| value)
}

fn same_origin(ilm: &IlmUrl, address: &str) -> bool {
    match (Url::parse(ilm.as_str()), Url::parse(address)) {
        (Ok(ilm), Ok(address)) => ilm.origin() == address.origin(),
        _ => false,
    }
}

/// RFC 9728 section 3.1: the well-known segment goes between the host and the path of the resource.
fn standard_address(ilm: &IlmUrl) -> String {
    let url = Url::parse(ilm.as_str()).expect("an ILM address is a valid URL");
    let origin = url.origin().ascii_serialization();
    format!(
        "{origin}/.well-known/oauth-protected-resource{}/api",
        url.path().trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource/api";

    fn document(base: &str) -> Value {
        json!({
            "resource": format!("{base}/api"),
            "authorization_servers": ["https://login.example.com"],
            "bearer_methods_supported": ["header"],
            "otilm_authorization_servers": [{
                "issuer": "https://login.example.com",
                "name": "Company sign-in",
                "client_id": "identity-manager",
                "scopes": ["openid", "offline_access"],
                "resource": format!("{base}/api"),
                "future_field": 1
            }],
            "future_top_level": true
        })
    }

    async fn serve_profile(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/api/v1/auth/profile"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn serve_document(server: &MockServer, at: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn run(server: &MockServer) -> Result<ResourceMetadata, DiscoveryError> {
        discover(&client_for_tests(), &IlmUrl::for_tests(&server.uri())).await
    }

    #[tokio::test]
    async fn the_address_in_the_401_header_is_used() {
        let server = MockServer::start().await;
        let announced = format!("{}/custom/metadata", server.uri());
        serve_profile(
            &server,
            ResponseTemplate::new(401).insert_header(
                "WWW-Authenticate",
                format!("Bearer error=\"invalid_token\", resource_metadata=\"{announced}\""),
            ),
        )
        .await;
        serve_document(
            &server,
            "/custom/metadata",
            ResponseTemplate::new(200).set_body_json(document(&server.uri())),
        )
        .await;
        let metadata = run(&server).await.unwrap();
        assert_eq!(metadata.resource, format!("{}/api", server.uri()));
        assert_eq!(
            metadata.providers,
            [PublishedProvider {
                issuer: "https://login.example.com".into(),
                name: "Company sign-in".into(),
                client_id: Some("identity-manager".into()),
                scopes: vec!["openid".into(), "offline_access".into()],
                resource: Some(format!("{}/api", server.uri())),
            }]
        );
    }

    #[tokio::test]
    async fn without_the_header_the_standard_address_is_used() {
        for status in [401, 200, 500] {
            let server = MockServer::start().await;
            serve_profile(&server, ResponseTemplate::new(status)).await;
            serve_document(
                &server,
                WELL_KNOWN,
                ResponseTemplate::new(200).set_body_json(document(&server.uri())),
            )
            .await;
            assert_eq!(run(&server).await.unwrap().providers.len(), 1, "{status}");
        }
    }

    #[tokio::test]
    async fn an_ilm_under_a_path_prefix_gets_the_well_known_segment_after_the_host() {
        let server = MockServer::start().await;
        let ilm = IlmUrl::for_tests(&format!("{}/p", server.uri()));
        serve_document(
            &server,
            "/.well-known/oauth-protected-resource/p/api",
            ResponseTemplate::new(200).set_body_json(document(&format!("{}/p", server.uri()))),
        )
        .await;
        let metadata = discover(&client_for_tests(), &ilm).await.unwrap();
        assert_eq!(metadata.resource, format!("{}/p/api", server.uri()));
    }

    #[tokio::test]
    async fn a_header_pointing_to_another_origin_is_refused() {
        let server = MockServer::start().await;
        for announced in ["http://127.0.0.1:1/meta", "https://evil.example.com/meta"] {
            server.reset().await;
            serve_profile(
                &server,
                ResponseTemplate::new(401).insert_header(
                    "WWW-Authenticate",
                    format!("Bearer resource_metadata=\"{announced}\""),
                ),
            )
            .await;
            let error = run(&server).await.unwrap_err();
            assert_eq!(
                error,
                DiscoveryError::ForeignAddress {
                    address: announced.into()
                }
            );
            assert!(error.to_string().contains(announced));
        }
    }

    #[tokio::test]
    async fn a_resource_that_is_not_the_ilms_api_is_refused() {
        let server = MockServer::start().await;
        serve_profile(&server, ResponseTemplate::new(401)).await;
        let mut body = document(&server.uri());
        body["resource"] = json!("https://other.example.com/api");
        serve_document(
            &server,
            WELL_KNOWN,
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
        let error = run(&server).await.unwrap_err();
        assert_eq!(
            error,
            DiscoveryError::NotPublished {
                address: format!("{}{WELL_KNOWN}", server.uri())
            }
        );
    }

    #[tokio::test]
    async fn a_provider_whose_issuer_is_not_an_authorization_server_is_dropped() {
        let server = MockServer::start().await;
        serve_profile(&server, ResponseTemplate::new(401)).await;
        let mut body = document(&server.uri());
        body["otilm_authorization_servers"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "issuer": "https://unlisted.example.com", "name": "Unlisted" }));
        serve_document(
            &server,
            WELL_KNOWN,
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
        let metadata = run(&server).await.unwrap();
        assert_eq!(metadata.providers.len(), 1);
        assert_eq!(metadata.providers[0].issuer, "https://login.example.com");
    }

    #[tokio::test]
    async fn a_document_without_providers_gives_an_empty_list() {
        let server = MockServer::start().await;
        serve_profile(&server, ResponseTemplate::new(401)).await;
        let body = json!({ "resource": format!("{}/api", server.uri()) });
        serve_document(
            &server,
            WELL_KNOWN,
            ResponseTemplate::new(200).set_body_json(body),
        )
        .await;
        assert!(run(&server).await.unwrap().providers.is_empty());
    }

    #[tokio::test]
    async fn a_missing_or_unreadable_document_means_nothing_is_published() {
        for response in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(200).set_body_string("<html>"),
            ResponseTemplate::new(200).set_body_json(json!({ "no": "resource" })),
        ] {
            let server = MockServer::start().await;
            serve_profile(&server, ResponseTemplate::new(401)).await;
            serve_document(&server, WELL_KNOWN, response).await;
            let error = run(&server).await.unwrap_err();
            assert!(matches!(error, DiscoveryError::NotPublished { .. }));
            assert!(error.to_string().contains(WELL_KNOWN));
        }
    }

    #[tokio::test]
    async fn a_server_that_is_gone_is_unreachable() {
        let ilm = IlmUrl::for_tests("http://127.0.0.1:1");
        let error = discover(&client_for_tests(), &ilm).await.unwrap_err();
        assert_eq!(error, DiscoveryError::Unreachable);
        assert!(error.to_string().ends_with('.'));
    }

    #[tokio::test]
    async fn a_document_that_cannot_be_fetched_is_unreachable() {
        let server = MockServer::start().await;
        serve_profile(
            &server,
            ResponseTemplate::new(401).insert_header(
                "WWW-Authenticate",
                format!("Bearer resource_metadata=\"{}/meta\"", server.uri()),
            ),
        )
        .await;
        serve_document(
            &server,
            "/meta",
            ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(60)),
        )
        .await;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(100))
            .build()
            .unwrap();
        let ilm = IlmUrl::for_tests(&server.uri());
        assert_eq!(
            discover(&client, &ilm).await.unwrap_err(),
            DiscoveryError::Unreachable
        );
    }

    #[test]
    fn the_standard_address_follows_rfc_9728() {
        let address = |url: &str| standard_address(&IlmUrl::parse(url).unwrap());
        assert_eq!(
            address("https://ilm.example.com"),
            "https://ilm.example.com/.well-known/oauth-protected-resource/api"
        );
        assert_eq!(
            address("https://h.example.com:8443/p"),
            "https://h.example.com:8443/.well-known/oauth-protected-resource/p/api"
        );
    }

    #[test]
    fn the_challenge_parameter_is_found_among_others() {
        assert_eq!(
            resource_metadata("Bearer realm=\"x\", resource_metadata=\"https://a/b\""),
            Some("https://a/b")
        );
        assert_eq!(resource_metadata("Bearer realm=\"x\""), None);
        assert_eq!(resource_metadata("Bearer resource_metadata=\"open"), None);
    }

    #[test]
    fn the_published_example_is_accepted() {
        let text = include_str!("../../../../docs/oauth/resource-metadata.example.json");
        let document: Document = serde_json::from_str(text).unwrap();
        let ilm = IlmUrl::parse("https://ilm.example.com").unwrap();
        assert_eq!(document.resource, ilm.api());
        let metadata = accepted(&ilm, document);
        assert_eq!(metadata.providers.len(), 1);
        assert_eq!(metadata.providers[0].name, "Company sign-in");
    }
}
