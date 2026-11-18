//! The browser leg of the sign-in: the authorization request and the loopback listener that catches the answer.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use super::client::ClientId;
use super::metadata::ProviderMetadata;
use super::pkce::Pkce;
use super::token::Code;
use crate::ilm::resource::PublishedProvider;

/// How long the person has to finish in the browser.
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(300);

const CALLBACK_PATH: &str = "/callback";
const OFFLINE_ACCESS: &str = "offline_access";
const MAX_REQUEST_LINE: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(1);

const SUCCESS_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>Identity Manager</title>\
<p>You can close this tab and return to Identity Manager.</p>";
const FAILURE_PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>Identity Manager</title>\
<p>Sign-in did not complete. Return to Identity Manager and try again.</p>";

#[derive(Debug)]
pub enum FlowError {
    Listen,
    Endpoint,
    Timeout,
    Denied,
    Refused,
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Listen => "Could not open a local port to receive the sign-in answer.",
            Self::Endpoint => "The sign-in address of the provider is not valid.",
            Self::Timeout => "Sign-in took too long. Try again.",
            Self::Denied => "Sign-in was cancelled or denied.",
            Self::Refused => "The sign-in answer did not match the request and was refused.",
        })
    }
}

impl std::error::Error for FlowError {}

/// Dropping the request closes the listener, which cancels the sign-in.
pub struct AuthorizationRequest {
    pub url: Url,
    pub redirect_uri: String,
    pub state: String,
    pub verifier: String,
    pub listener: TcpListener,
}

impl AuthorizationRequest {
    pub async fn new(
        metadata: &ProviderMetadata,
        client_id: &ClientId,
        provider: &PublishedProvider,
    ) -> Result<Self, FlowError> {
        let mut url =
            Url::parse(&metadata.authorization_endpoint).map_err(|_| FlowError::Endpoint)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| {
                log::warn!("could not bind the loopback listener: {error}");
                FlowError::Listen
            })?;
        let port = listener.local_addr().map_err(|_| FlowError::Listen)?.port();
        let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");
        let pkce = Pkce::new();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id.as_str())
                .append_pair("redirect_uri", &redirect_uri);
            let scope = scope(metadata, provider);
            if !scope.is_empty() {
                query.append_pair("scope", &scope);
            }
            query
                .append_pair("state", &pkce.state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", "S256");
            if let Some(resource) = &provider.resource {
                query.append_pair("resource", resource);
            }
        }
        log::info!(
            "{}: waiting for the browser on port {port}",
            metadata.issuer
        );
        Ok(Self {
            url,
            redirect_uri,
            state: pkce.state,
            verifier: pkce.verifier,
            listener,
        })
    }
}

fn scope(metadata: &ProviderMetadata, provider: &PublishedProvider) -> String {
    let mut scopes = provider.scopes.clone();
    let wanted = OFFLINE_ACCESS.to_owned();
    if metadata.scopes_supported.contains(&wanted) && !scopes.contains(&wanted) {
        scopes.push(wanted);
    }
    scopes.join(" ")
}

/// Answers each connection and returns at the first answer to `/callback`, or when `timeout` ends.
/// Any other path is answered with 404 and the wait goes on; an answer to `/callback` that does not
/// match the request ends the flow. The listener is closed on return.
pub async fn wait_for_code(
    listener: TcpListener,
    state: &str,
    expected_issuer: &str,
    timeout: Duration,
) -> Result<Code, FlowError> {
    let wait = async {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let Some(target) = read_target(&mut stream).await else {
                respond(&mut stream, "400 Bad Request", FAILURE_PAGE).await;
                continue;
            };
            let Some(query) = target.strip_prefix(CALLBACK_PATH).and_then(callback_query) else {
                respond(&mut stream, "404 Not Found", FAILURE_PAGE).await;
                continue;
            };
            let outcome = judge(&query, state, expected_issuer);
            match &outcome {
                Ok(_) => respond(&mut stream, "200 OK", SUCCESS_PAGE).await,
                Err(_) => respond(&mut stream, "400 Bad Request", FAILURE_PAGE).await,
            }
            return outcome;
        }
    };
    tokio::time::timeout(timeout, wait)
        .await
        .unwrap_or_else(|_| {
            log::warn!("no sign-in answer arrived in time");
            Err(FlowError::Timeout)
        })
}

/// The query string after `/callback`; `None` when the path continues (`/callbackx`).
fn callback_query(rest: &str) -> Option<HashMap<String, String>> {
    let query = match rest {
        "" => "",
        _ => rest.strip_prefix('?')?,
    };
    Some(
        url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect(),
    )
}

fn judge(
    query: &HashMap<String, String>,
    state: &str,
    expected_issuer: &str,
) -> Result<Code, FlowError> {
    if query.get("state").map(String::as_str) != Some(state) {
        log::warn!("refused a sign-in answer with a missing or wrong state");
        return Err(FlowError::Refused);
    }
    if query.get("iss").is_some_and(|iss| iss != expected_issuer) {
        log::warn!("refused a sign-in answer from another issuer");
        return Err(FlowError::Refused);
    }
    if let Some(error) = query.get("error") {
        log::warn!("the provider answered with the error {error}");
        return Err(FlowError::Denied);
    }
    match query.get("code") {
        Some(code) if !code.is_empty() => Ok(Code::new(code.clone())),
        _ => {
            log::warn!("refused a sign-in answer without a code");
            Err(FlowError::Refused)
        }
    }
}

/// The request target of a well-formed `GET`; `None` for anything else, or when the line does not arrive.
async fn read_target(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(512);
    let read_line = async {
        let mut chunk = [0u8; 512];
        while buffer.len() < MAX_REQUEST_LINE && !buffer.windows(2).any(|pair| pair == b"\r\n") {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
    };
    tokio::time::timeout(READ_TIMEOUT, read_line).await.ok()?;
    let text = String::from_utf8_lossy(&buffer);
    let line = text.split("\r\n").next()?;
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(target), Some(version), None) if version.starts_with("HTTP/") => {
            Some(target.to_owned())
        }
        _ => None,
    }
}

async fn respond(stream: &mut TcpStream, status: &str, page: &str) {
    let answer = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{page}",
        page.len()
    );
    if stream.write_all(answer.as_bytes()).await.is_ok() {
        let _ = stream.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::client::client_identity;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const ISSUER: &str = "https://idp.example";

    fn metadata(scopes_supported: &[&str]) -> ProviderMetadata {
        ProviderMetadata {
            issuer: ISSUER.into(),
            authorization_endpoint: "https://idp.example/auth?tenant=t1".into(),
            token_endpoint: "https://idp.example/token".into(),
            revocation_endpoint: None,
            scopes_supported: scopes_supported.iter().map(|s| (*s).into()).collect(),
            cimd_supported: false,
            code_challenge_methods_supported: vec![],
        }
    }

    fn provider(scopes: &[&str], resource: Option<&str>) -> PublishedProvider {
        PublishedProvider {
            issuer: ISSUER.into(),
            name: "Example".into(),
            client_id: Some("app-id".into()),
            scopes: scopes.iter().map(|s| (*s).into()).collect(),
            resource: resource.map(Into::into),
        }
    }

    async fn request(
        supported: &[&str],
        scopes: &[&str],
        resource: Option<&str>,
    ) -> AuthorizationRequest {
        let metadata = metadata(supported);
        let client_id = client_identity(Some("app-id"), &metadata).unwrap();
        AuthorizationRequest::new(&metadata, &client_id, &provider(scopes, resource))
            .await
            .unwrap()
    }

    fn query(request: &AuthorizationRequest) -> HashMap<String, String> {
        request.url.query_pairs().into_owned().collect()
    }

    #[tokio::test]
    async fn the_url_carries_the_whole_request() {
        let request = request(&[], &["openid", "ilm"], Some("https://ilm.example/api")).await;
        let port = request.listener.local_addr().unwrap().port();
        let query = query(&request);

        assert_eq!(request.url.host_str(), Some("idp.example"));
        assert_eq!(request.url.path(), "/auth");
        assert_eq!(query["tenant"], "t1");
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "app-id");
        assert_eq!(
            query["redirect_uri"],
            format!("http://127.0.0.1:{port}/callback")
        );
        assert_eq!(request.redirect_uri, query["redirect_uri"]);
        assert_eq!(query["scope"], "openid ilm");
        assert_eq!(query["state"], request.state);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["code_challenge"].len(), 43);
        assert_ne!(query["code_challenge"], request.verifier);
        assert_eq!(query["resource"], "https://ilm.example/api");
        assert!(!request.url.as_str().contains(&request.verifier));
    }

    #[tokio::test]
    async fn no_resource_is_sent_unless_published() {
        let request = request(&[], &["openid"], None).await;
        assert!(!query(&request).contains_key("resource"));
    }

    #[tokio::test]
    async fn offline_access_is_added_only_when_the_provider_lists_it() {
        let listed = request(&["offline_access"], &["openid"], None).await;
        assert_eq!(query(&listed)["scope"], "openid offline_access");
        let unlisted = request(&["openid"], &["openid"], None).await;
        assert_eq!(query(&unlisted)["scope"], "openid");
        let present = request(&["offline_access"], &["openid", "offline_access"], None).await;
        assert_eq!(query(&present)["scope"], "openid offline_access");
    }

    #[tokio::test]
    async fn the_listener_is_bound_to_loopback_on_its_own_port() {
        let first = request(&[], &[], None).await;
        let second = request(&[], &[], None).await;
        let address = first.listener.local_addr().unwrap();
        assert!(address.ip().is_loopback() && address.is_ipv4());
        assert_ne!(address.port(), second.listener.local_addr().unwrap().port());
        assert!(!query(&first).contains_key("scope"));
    }

    #[tokio::test]
    async fn a_bad_authorization_endpoint_is_reported() {
        let mut metadata = metadata(&[]);
        metadata.authorization_endpoint = "not a url".into();
        let client_id = client_identity(Some("app-id"), &metadata).unwrap();
        let result = AuthorizationRequest::new(&metadata, &client_id, &provider(&[], None)).await;
        assert!(matches!(result, Err(FlowError::Endpoint)));
    }

    async fn get(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let line = format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        stream.write_all(line.as_bytes()).await.unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        answer
    }

    fn start(
        state: &'static str,
        timeout: Duration,
    ) -> (u16, tokio::task::JoinHandle<Result<Code, FlowError>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let listener = TcpListener::from_std(listener).unwrap();
        let task = tokio::spawn(wait_for_code(listener, state, ISSUER, timeout));
        (port, task)
    }

    const LONG: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn the_right_answer_gives_the_code_and_a_page() {
        let (port, task) = start("s1", LONG);
        let answer = get(
            port,
            "/callback?code=the-code&state=s1&iss=https%3A%2F%2Fidp.example",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 200"));
        assert!(answer.contains("You can close this tab"));
        assert!(!answer.contains("the-code"));
        assert_eq!(task.await.unwrap().unwrap().as_str(), "the-code");
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    #[tokio::test]
    async fn iss_is_optional() {
        let (port, task) = start("s1", LONG);
        get(port, "/callback?code=c&state=s1").await;
        assert_eq!(task.await.unwrap().unwrap().as_str(), "c");
    }

    #[tokio::test]
    async fn another_path_is_answered_and_the_wait_goes_on() {
        let (port, task) = start("s1", LONG);
        let answer = get(port, "/favicon.ico").await;
        assert!(answer.starts_with("HTTP/1.1 404"));
        get(port, "/callback?code=c&state=s1").await;
        assert_eq!(task.await.unwrap().unwrap().as_str(), "c");
    }

    #[tokio::test]
    async fn garbage_on_the_connection_is_answered_and_the_wait_goes_on() {
        let (port, task) = start("s1", LONG);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"\x16\x03\x01 nonsense\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 400"));
        get(port, "/callback?code=c&state=s1").await;
        assert_eq!(task.await.unwrap().unwrap().as_str(), "c");
    }

    #[tokio::test]
    async fn a_post_is_refused_and_the_wait_goes_on() {
        let (port, task) = start("s1", LONG);
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"POST /callback?code=c&state=s1 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 400"));
        get(port, "/callback?code=c&state=s1").await;
        assert_eq!(task.await.unwrap().unwrap().as_str(), "c");
    }

    #[tokio::test]
    async fn a_wrong_or_missing_state_fails_the_flow() {
        for target in ["/callback?code=c&state=other", "/callback?code=c"] {
            let (port, task) = start("s1", LONG);
            let answer = get(port, target).await;
            assert!(answer.starts_with("HTTP/1.1 400"));
            assert!(!answer.contains("You can close this tab"));
            assert!(matches!(task.await.unwrap(), Err(FlowError::Refused)));
        }
    }

    #[tokio::test]
    async fn a_mismatched_issuer_fails_the_flow() {
        let (port, task) = start("s1", LONG);
        let answer = get(
            port,
            "/callback?code=c&state=s1&iss=https%3A%2F%2Fevil.example",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 400"));
        assert!(matches!(task.await.unwrap(), Err(FlowError::Refused)));
    }

    #[tokio::test]
    async fn an_error_answer_is_a_plain_message() {
        let (port, task) = start("s1", LONG);
        let answer = get(
            port,
            "/callback?error=access_denied&error_description=%3Cb%3Ex&state=s1",
        )
        .await;
        assert!(answer.starts_with("HTTP/1.1 400"));
        assert!(!answer.contains("<b>"));
        let error = task.await.unwrap().unwrap_err();
        assert!(matches!(error, FlowError::Denied));
        assert!(error.to_string().contains("cancelled or denied"));
    }

    #[tokio::test]
    async fn an_answer_without_a_code_fails_the_flow() {
        let (port, task) = start("s1", LONG);
        get(port, "/callback?state=s1").await;
        assert!(matches!(task.await.unwrap(), Err(FlowError::Refused)));
    }

    #[tokio::test]
    async fn the_wait_ends_at_the_timeout_and_the_port_closes() {
        let (port, task) = start("s1", Duration::from_millis(100));
        assert!(matches!(task.await.unwrap(), Err(FlowError::Timeout)));
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    #[tokio::test]
    async fn a_silent_connection_does_not_hold_up_the_right_answer() {
        let (port, task) = start("s1", LONG);
        let _silent = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        get(port, "/callback?code=c&state=s1").await;
        assert_eq!(task.await.unwrap().unwrap().as_str(), "c");
    }

    #[tokio::test]
    async fn cancelling_closes_the_port() {
        let (port, task) = start("s1", LONG);
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    #[test]
    fn errors_read_in_plain_words() {
        for error in [
            FlowError::Listen,
            FlowError::Endpoint,
            FlowError::Timeout,
            FlowError::Denied,
            FlowError::Refused,
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
