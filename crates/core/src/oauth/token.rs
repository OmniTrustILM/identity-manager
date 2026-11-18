//! Tokens from the provider's token endpoint: code exchange, renewal and revocation.

use std::fmt;
use std::time::{Duration, Instant};

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;

use super::client::ClientId;
use super::metadata::ProviderMetadata;
use crate::token::AccessToken;

/// The authorization code from the redirect. `Debug` hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Code(String);

impl Code {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(..)")
    }
}

/// A refresh token. `Debug` hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshToken(..)")
    }
}

#[derive(Debug, Clone)]
pub struct Tokens {
    pub access: AccessToken,
    pub expires_at: Instant,
    pub refresh: Option<RefreshToken>,
}

/// The token endpoint turned the request down, or could not be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Refused,
    Unreachable,
}

pub type RenewError = TokenError;

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Refused => "the provider refused the request",
            Self::Unreachable => "the provider could not be reached",
        })
    }
}

impl std::error::Error for TokenError {}

/// Used when the provider names no lifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(300);
/// The longest lifetime taken from the provider, so that an absurd one cannot overflow the clock.
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

pub async fn exchange(
    client: &Client,
    metadata: &ProviderMetadata,
    client_id: &ClientId,
    code: &Code,
    verifier: &str,
    redirect_uri: &str,
    resource: Option<&str>,
) -> Result<Tokens, TokenError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", verifier),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id.as_str()),
    ];
    form.extend(resource.map(|resource| ("resource", resource)));
    let tokens = request_tokens(client, metadata, &form).await?;
    log::info!("{}: the code was exchanged for tokens", metadata.issuer);
    Ok(tokens)
}

/// A rotated refresh token comes back in `refresh`; without one the old token stays in use.
pub async fn refresh(
    client: &Client,
    metadata: &ProviderMetadata,
    client_id: &ClientId,
    refresh_token: &RefreshToken,
    resource: Option<&str>,
) -> Result<Tokens, RenewError> {
    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token.as_str()),
        ("client_id", client_id.as_str()),
    ];
    form.extend(resource.map(|resource| ("resource", resource)));
    let mut tokens = request_tokens(client, metadata, &form).await?;
    tokens.refresh.get_or_insert_with(|| refresh_token.clone());
    log::info!("{}: the access token was renewed", metadata.issuer);
    Ok(tokens)
}

/// RFC 7009. Does nothing when the provider publishes no revocation endpoint.
pub async fn revoke(
    client: &Client,
    metadata: &ProviderMetadata,
    client_id: &ClientId,
    refresh_token: &RefreshToken,
) -> Result<(), TokenError> {
    let Some(endpoint) = &metadata.revocation_endpoint else {
        log::info!("{}: no revocation endpoint to call", metadata.issuer);
        return Ok(());
    };
    let form = [
        ("token", refresh_token.as_str()),
        ("token_type_hint", "refresh_token"),
        ("client_id", client_id.as_str()),
    ];
    let response = post_form(client, endpoint, &form).await?;
    if response.status().is_success() {
        log::info!("{}: the refresh token was revoked", metadata.issuer);
        Ok(())
    } else {
        log::warn!(
            "{}: revocation answered {}",
            metadata.issuer,
            response.status()
        );
        Err(TokenError::Refused)
    }
}

async fn post_form(
    client: &Client,
    endpoint: &str,
    form: &[(&str, &str)],
) -> Result<Response, TokenError> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    client
        .post(endpoint)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(body)
        .send()
        .await
        .map_err(|error| {
            log::warn!("{endpoint}: not reachable: {}", error.without_url());
            TokenError::Unreachable
        })
}

async fn request_tokens(
    client: &Client,
    metadata: &ProviderMetadata,
    form: &[(&str, &str)],
) -> Result<Tokens, TokenError> {
    let response = post_form(client, &metadata.token_endpoint, form).await?;
    let status = response.status();
    if status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED {
        log::warn!("{}: the token endpoint answered {status}", metadata.issuer);
        return Err(TokenError::Refused);
    }
    if !status.is_success() {
        log::warn!("{}: the token endpoint answered {status}", metadata.issuer);
        return Err(TokenError::Unreachable);
    }
    let parsed = response.json::<TokenResponse>().await.map_err(|_| {
        log::warn!("{}: the token answer could not be read", metadata.issuer);
        TokenError::Unreachable
    })?;
    let lifetime = parsed
        .expires_in
        .map_or(DEFAULT_LIFETIME, Duration::from_secs)
        .min(MAX_LIFETIME);
    Ok(Tokens {
        access: AccessToken::new(parsed.access_token),
        expires_at: Instant::now() + lifetime,
        refresh: parsed.refresh_token.map(RefreshToken::new),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use crate::oauth::client::client_identity;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn metadata(server: &MockServer, revocation: bool) -> ProviderMetadata {
        ProviderMetadata {
            issuer: server.uri(),
            authorization_endpoint: format!("{}/auth", server.uri()),
            token_endpoint: format!("{}/token", server.uri()),
            revocation_endpoint: revocation.then(|| format!("{}/revoke", server.uri())),
            cimd_supported: false,
            code_challenge_methods_supported: vec![],
            iss_required: false,
        }
    }

    fn client_id(metadata: &ProviderMetadata) -> ClientId {
        client_identity(Some("app-id"), metadata).unwrap()
    }

    async fn token_endpoint(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn ok(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    async fn body_of_the_only_request(server: &MockServer) -> String {
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(
            request.headers.get("content-type").unwrap(),
            "application/x-www-form-urlencoded"
        );
        String::from_utf8(request.body.clone()).unwrap()
    }

    #[test]
    fn debug_output_hides_codes_and_refresh_tokens() {
        let tokens = Tokens {
            access: AccessToken::new("access-secret"),
            expires_at: Instant::now(),
            refresh: Some(RefreshToken::new("refresh-secret")),
        };
        let shown = format!("{:?} {:?}", Code::new("code-secret"), tokens);
        for secret in ["access-secret", "refresh-secret", "code-secret"] {
            assert!(!shown.contains(secret));
        }
        assert_eq!(Code::new("c").as_str(), "c");
        assert_eq!(RefreshToken::new("r").as_str(), "r");
    }

    #[test]
    fn errors_read_in_plain_words() {
        assert!(TokenError::Refused.to_string().contains("refused"));
        assert!(TokenError::Unreachable.to_string().contains("reached"));
    }

    #[tokio::test]
    async fn exchange_sends_the_code_the_verifier_and_the_client_id_but_no_secret() {
        let server = MockServer::start().await;
        token_endpoint(
            &server,
            ok(json!({"access_token": "a1", "expires_in": 120, "refresh_token": "r1", "token_type": "Bearer"})),
        )
        .await;
        let metadata = metadata(&server, false);
        let before = Instant::now();

        let tokens = exchange(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &Code::new("the-code"),
            "the-verifier",
            "http://127.0.0.1:5555/callback",
            Some("https://ilm.example/api"),
        )
        .await
        .unwrap();

        assert_eq!(tokens.access.as_str(), "a1");
        assert_eq!(tokens.refresh.unwrap().as_str(), "r1");
        assert!(tokens.expires_at >= before + Duration::from_secs(120));
        assert!(tokens.expires_at <= Instant::now() + Duration::from_secs(120));
        let body = body_of_the_only_request(&server).await;
        for part in [
            "grant_type=authorization_code",
            "code=the-code",
            "code_verifier=the-verifier",
            "client_id=app-id",
            "redirect_uri=http%3A%2F%2F127.0.0.1%3A5555%2Fcallback",
            "resource=https%3A%2F%2Film.example%2Fapi",
        ] {
            assert!(body.contains(part), "{part} missing");
        }
        assert!(!body.contains("secret"));
    }

    #[tokio::test]
    async fn exchange_without_a_refresh_token_or_resource() {
        let server = MockServer::start().await;
        token_endpoint(&server, ok(json!({"access_token": "a1", "expires_in": 60}))).await;
        let metadata = metadata(&server, false);

        let tokens = exchange(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &Code::new("c"),
            "v",
            "http://127.0.0.1:1/callback",
            None,
        )
        .await
        .unwrap();

        assert!(tokens.refresh.is_none());
        assert!(!body_of_the_only_request(&server).await.contains("resource"));
    }

    #[tokio::test]
    async fn a_missing_lifetime_gets_a_short_default() {
        let server = MockServer::start().await;
        token_endpoint(&server, ok(json!({"access_token": "a1"}))).await;
        let metadata = metadata(&server, false);

        let tokens = refresh(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r0"),
            None,
        )
        .await
        .unwrap();

        let left = tokens.expires_at.saturating_duration_since(Instant::now());
        assert!(left > Duration::from_secs(200) && left <= Duration::from_secs(300));
    }

    #[tokio::test]
    async fn a_huge_lifetime_is_capped_at_a_day() {
        let server = MockServer::start().await;
        token_endpoint(
            &server,
            ok(json!({"access_token": "a1", "expires_in": u64::MAX})),
        )
        .await;
        let metadata = metadata(&server, false);

        let tokens = refresh(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r0"),
            None,
        )
        .await
        .unwrap();

        let left = tokens.expires_at.saturating_duration_since(Instant::now());
        assert!(left > Duration::from_secs(23 * 60 * 60) && left <= MAX_LIFETIME);
    }

    #[tokio::test]
    async fn refresh_sends_the_refresh_token_and_takes_a_rotated_one() {
        let server = MockServer::start().await;
        token_endpoint(
            &server,
            ok(json!({"access_token": "a2", "expires_in": 60, "refresh_token": "r2"})),
        )
        .await;
        let metadata = metadata(&server, false);

        let tokens = refresh(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
            Some("https://ilm.example/api"),
        )
        .await
        .unwrap();

        assert_eq!(tokens.refresh.unwrap().as_str(), "r2");
        let body = body_of_the_only_request(&server).await;
        for part in [
            "grant_type=refresh_token",
            "refresh_token=r1",
            "client_id=app-id",
            "resource=",
        ] {
            assert!(body.contains(part), "{part} missing");
        }
        assert!(!body.contains("client_secret"));
    }

    #[tokio::test]
    async fn refresh_keeps_the_old_refresh_token_when_none_comes_back() {
        let server = MockServer::start().await;
        token_endpoint(&server, ok(json!({"access_token": "a2", "expires_in": 60}))).await;
        let metadata = metadata(&server, false);

        let tokens = refresh(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
            None,
        )
        .await
        .unwrap();

        assert_eq!(tokens.refresh.unwrap().as_str(), "r1");
    }

    #[tokio::test]
    async fn invalid_grant_and_other_client_errors_are_refusals() {
        for status in [400, 401] {
            let server = MockServer::start().await;
            token_endpoint(
                &server,
                ResponseTemplate::new(status).set_body_json(json!({"error": "invalid_grant"})),
            )
            .await;
            let metadata = metadata(&server, false);
            let result = refresh(
                &client_for_tests(),
                &metadata,
                &client_id(&metadata),
                &RefreshToken::new("r1"),
                None,
            )
            .await;
            assert_eq!(result.unwrap_err(), RenewError::Refused);
        }
    }

    #[tokio::test]
    async fn server_errors_and_unreadable_answers_keep_the_session() {
        for response in [
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_string("not json"),
            ok(json!({"expires_in": 60})),
        ] {
            let server = MockServer::start().await;
            token_endpoint(&server, response).await;
            let metadata = metadata(&server, false);
            let result = refresh(
                &client_for_tests(),
                &metadata,
                &client_id(&metadata),
                &RefreshToken::new("r1"),
                None,
            )
            .await;
            assert_eq!(result.unwrap_err(), RenewError::Unreachable);
        }
    }

    #[tokio::test]
    async fn a_connection_error_is_unreachable() {
        let server = MockServer::start().await;
        let mut metadata = metadata(&server, false);
        metadata.token_endpoint = "http://127.0.0.1:1/token".into();
        let result = refresh(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
            None,
        )
        .await;
        assert_eq!(result.unwrap_err(), RenewError::Unreachable);
    }

    #[tokio::test]
    async fn exchange_reports_a_refused_code() {
        let server = MockServer::start().await;
        token_endpoint(&server, ResponseTemplate::new(400)).await;
        let metadata = metadata(&server, false);
        let result = exchange(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &Code::new("c"),
            "v",
            "http://127.0.0.1:1/callback",
            None,
        )
        .await;
        assert_eq!(result.unwrap_err(), TokenError::Refused);
    }

    #[tokio::test]
    async fn revoke_posts_the_refresh_token_with_its_hint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .and(body_string_contains("token=r1"))
            .and(body_string_contains("token_type_hint=refresh_token"))
            .and(body_string_contains("client_id=app-id"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let metadata = metadata(&server, true);

        revoke(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn revoke_without_an_endpoint_does_nothing() {
        let server = MockServer::start().await;
        let metadata = metadata(&server, false);
        revoke(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
        )
        .await
        .unwrap();
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn revoke_reports_failures_for_the_caller_to_log() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let metadata = metadata(&server, true);
        let result = revoke(
            &client_for_tests(),
            &metadata,
            &client_id(&metadata),
            &RefreshToken::new("r1"),
        )
        .await;
        assert!(result.is_err());
    }
}
