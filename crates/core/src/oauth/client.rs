//! Which client ID the app presents to a provider.

use std::fmt;

use super::metadata::ProviderMetadata;

/// Published at this address, the same for every installation.
pub const METADATA_DOCUMENT_URL: &str =
    "https://omnitrustilm.github.io/identity-manager/oauth/client-metadata.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientId(String);

impl ClientId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The provider has no client ID for the app and does not accept a metadata document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotUsable;

impl fmt::Display for NotUsable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the provider publishes no client ID and does not accept a client ID metadata document",
        )
    }
}

impl std::error::Error for NotUsable {}

/// The published client ID wins; otherwise the metadata document when the provider accepts one.
pub fn client_identity(
    published_client_id: Option<&str>,
    metadata: &ProviderMetadata,
) -> Result<ClientId, NotUsable> {
    if let Some(id) = published_client_id.filter(|id| !id.is_empty()) {
        log::info!(
            "{}: using the client ID the organization published",
            metadata.issuer
        );
        return Ok(ClientId(id.to_owned()));
    }
    if metadata.cimd_supported {
        log::info!(
            "{}: using the app's client ID metadata document",
            metadata.issuer
        );
        return Ok(ClientId(METADATA_DOCUMENT_URL.to_owned()));
    }
    log::warn!("{}: not usable: {NotUsable}", metadata.issuer);
    Err(NotUsable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn metadata(cimd_supported: bool) -> ProviderMetadata {
        ProviderMetadata {
            issuer: "https://idp.example".into(),
            authorization_endpoint: "https://idp.example/auth".into(),
            token_endpoint: "https://idp.example/token".into(),
            revocation_endpoint: None,
            scopes_supported: vec![],
            cimd_supported,
            code_challenge_methods_supported: vec![],
        }
    }

    #[test]
    fn the_published_client_id_wins() {
        let id = client_identity(Some("abc"), &metadata(true)).unwrap();
        assert_eq!(id.as_str(), "abc");
    }

    #[test]
    fn the_metadata_document_is_used_when_the_provider_accepts_one() {
        let id = client_identity(None, &metadata(true)).unwrap();
        assert_eq!(id.as_str(), METADATA_DOCUMENT_URL);
    }

    #[test]
    fn an_empty_published_client_id_counts_as_none() {
        let id = client_identity(Some(""), &metadata(true)).unwrap();
        assert_eq!(id.as_str(), METADATA_DOCUMENT_URL);
    }

    #[test]
    fn neither_is_not_usable_with_a_reason() {
        let error = client_identity(None, &metadata(false)).unwrap_err();
        assert!(error.to_string().contains("client ID"));
    }

    #[test]
    fn the_published_document_matches_the_constant() {
        let document: Value =
            serde_json::from_str(include_str!("../../../../docs/oauth/client-metadata.json"))
                .unwrap();
        assert_eq!(document["client_id"], METADATA_DOCUMENT_URL);
        assert_eq!(document["client_name"], "Identity Manager");
        assert_eq!(
            document["redirect_uris"],
            serde_json::json!(["http://127.0.0.1/callback"])
        );
        assert_eq!(
            document["grant_types"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(document["response_types"], serde_json::json!(["code"]));
        assert_eq!(document["token_endpoint_auth_method"], "none");
        assert_eq!(document["application_type"], "native");
    }
}
