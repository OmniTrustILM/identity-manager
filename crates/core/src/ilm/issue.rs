//! Asking ILM for a certificate: the request that issues one or completes one registered in advance, and the
//! reading of what ILM made of it. Issuing is asynchronous, so the state and the chain are read afterwards.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::IlmUrl;
use super::certificates::State;
use super::profile::{IlmError, read_rejection};

/// What goes to ILM with a request for a certificate: the signed request (DER) and the attributes as request
/// attributes.
pub struct IssueBody {
    pub request_der: Vec<u8>,
    pub attributes: Vec<Value>,
    pub custom_attributes: Vec<Value>,
}

/// The secret that ILM's registration of a certificate asks for. It lives in memory only and is never shown,
/// logged or written.
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Challenge(String);

impl Challenge {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    /// The text, for the body of the request only.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Challenge(..)")
    }
}

/// Why ILM did not take a request for a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueError {
    /// ILM refused the request and says why; the messages are for the person, never the log.
    Refused(Vec<String>),
    /// The person may not do this.
    NotAllowed,
    Failed(IlmError),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueError::Refused(messages) if messages.is_empty() => {
                f.write_str("ILM did not accept the request.")
            }
            IssueError::Refused(messages) => f.write_str(&messages.join(" ")),
            IssueError::NotAllowed => f.write_str("ILM does not allow this."),
            IssueError::Failed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for IssueError {}

/// Why the state of a certificate could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateError {
    /// ILM does not have the certificate.
    Gone,
    /// The person may not see it.
    NotAllowed,
    Failed(IlmError),
}

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::Gone => f.write_str("ILM does not know this certificate."),
            StateError::NotAllowed => f.write_str("ILM does not allow this."),
            StateError::Failed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StateError {}

/// Where a certificate stands in ILM and, once ILM has issued it, what it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedState {
    pub state: State,
    /// The DER of the certificate; none before it is issued.
    pub content: Option<Vec<u8>>,
    pub subject_dn: Option<String>,
    /// The alternative names by type, in the order of the types.
    pub alternative_names: Vec<(String, Vec<String>)>,
    /// Whether a certificate request is attached to the certificate.
    pub request_attached: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Issued {
    uuid: String,
    #[serde(default)]
    request_attribute_warnings: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawState {
    state: String,
    certificate_content: Option<String>,
    subject_dn: Option<String>,
    subject_alternative_names: Option<BTreeMap<String, Vec<String>>>,
    certificate_request: Option<Value>,
}

#[derive(Deserialize)]
struct RawChain {
    certificates: Vec<RawChainCertificate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawChainCertificate {
    certificate_content: Option<String>,
}

fn certificates_path(ilm: &IlmUrl, authority: &str, ra_profile: &str) -> String {
    format!(
        "{}/v2/operations/authorities/{authority}/raProfiles/{ra_profile}/certificates",
        ilm.api()
    )
}

fn body_of(body: &IssueBody) -> Value {
    json!({
        "request": STANDARD.encode(&body.request_der),
        "format": "pkcs10",
        "attributes": body.attributes,
        "customAttributes": body.custom_attributes,
    })
}

/// The request that asks an RA Profile for a new certificate.
pub fn issue_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    body: &IssueBody,
) -> RequestBuilder {
    client
        .post(certificates_path(ilm, authority, ra_profile))
        .json(&body_of(body))
}

/// The request that completes a certificate registered in advance. The challenge is sent only when there is one.
pub fn complete_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    uuid: &str,
    body: &IssueBody,
    challenge: Option<&Challenge>,
) -> RequestBuilder {
    let mut sent = body_of(body);
    if let (Some(challenge), Some(fields)) = (challenge, sent.as_object_mut()) {
        fields.insert("authorizationSecret".into(), json!(challenge.expose()));
    }
    client
        .post(format!(
            "{}/{uuid}/issue",
            certificates_path(ilm, authority, ra_profile)
        ))
        .json(&sent)
}

/// Reads the answer to either request: the UUID of the certificate ILM is making.
pub async fn read_issued(response: Response) -> Result<String, IssueError> {
    let status = response.status();
    match status {
        _ if status.is_success() => {
            let issued = response.json::<Issued>().await.map_err(|_| {
                log::warn!("ILM sent an issue answer this application cannot read");
                IssueError::Failed(IlmError::Malformed)
            })?;
            if !issued.request_attribute_warnings.is_empty() {
                log::info!(
                    "ILM had {} remarks on the attributes of the request",
                    issued.request_attribute_warnings.len()
                );
            }
            Ok(issued.uuid)
        }
        StatusCode::UNAUTHORIZED => Err(IssueError::Failed(IlmError::Unauthorized)),
        StatusCode::FORBIDDEN => Err(IssueError::NotAllowed),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => {
            Err(IssueError::Refused(read_rejection(response).await))
        }
        _ => {
            log::warn!("ILM answered the issue request with {status}");
            Err(IssueError::Failed(IlmError::Unexpected(status.as_u16())))
        }
    }
}

pub fn state_request(client: &Client, ilm: &IlmUrl, uuid: &str) -> RequestBuilder {
    client.get(format!("{}/v1/certificates/{uuid}", ilm.api()))
}

fn decode(content: &str) -> Result<Vec<u8>, IlmError> {
    STANDARD.decode(content).map_err(|_| {
        log::warn!("ILM sent certificate content that is not base64");
        IlmError::Malformed
    })
}

/// Reads the state of a certificate with, once it is issued, its content.
pub async fn read_state(response: Response) -> Result<IssuedState, StateError> {
    let status = response.status();
    match status {
        _ if status.is_success() => {}
        StatusCode::UNAUTHORIZED => return Err(StateError::Failed(IlmError::Unauthorized)),
        StatusCode::FORBIDDEN => return Err(StateError::NotAllowed),
        StatusCode::NOT_FOUND => return Err(StateError::Gone),
        _ => {
            log::warn!("ILM answered the state request with {status}");
            return Err(StateError::Failed(IlmError::Unexpected(status.as_u16())));
        }
    }
    let raw = response.json::<RawState>().await.map_err(|_| {
        log::warn!("ILM sent a certificate state this application cannot read");
        StateError::Failed(IlmError::Malformed)
    })?;
    let content = raw
        .certificate_content
        .filter(|content| !content.is_empty())
        .map(|content| decode(&content))
        .transpose()
        .map_err(StateError::Failed)?;
    Ok(IssuedState {
        state: State::from_code(&raw.state),
        content,
        subject_dn: raw.subject_dn,
        alternative_names: raw
            .subject_alternative_names
            .unwrap_or_default()
            .into_iter()
            .collect(),
        request_attached: raw
            .certificate_request
            .is_some_and(|request| !request.is_null()),
    })
}

/// The request for the chain above a certificate, without the certificate itself.
pub fn chain_request(client: &Client, ilm: &IlmUrl, uuid: &str) -> RequestBuilder {
    client.get(format!(
        "{}/v1/certificates/{uuid}/chain?withEndCertificate=false",
        ilm.api()
    ))
}

/// Reads the chain: the DER of each certificate, from the issuer of the given one upwards.
pub async fn read_chain(response: Response) -> Result<Vec<Vec<u8>>, IlmError> {
    let status = response.status();
    match status {
        _ if status.is_success() => {}
        StatusCode::UNAUTHORIZED => return Err(IlmError::Unauthorized),
        _ => {
            log::warn!("ILM answered the chain request with {status}");
            return Err(IlmError::Unexpected(status.as_u16()));
        }
    }
    let chain = response.json::<RawChain>().await.map_err(|_| {
        log::warn!("ILM sent a chain this application cannot read");
        IlmError::Malformed
    })?;
    chain
        .certificates
        .into_iter()
        .filter_map(|certificate| certificate.certificate_content)
        .filter(|content| !content.is_empty())
        .map(|content| decode(&content))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DER: [u8; 5] = [0x30, 0x82, 0x01, 0x0a, 0xff];
    const ISSUE: &str = "/api/v2/operations/authorities/a-1/raProfiles/r-1/certificates";

    fn body() -> IssueBody {
        IssueBody {
            request_der: DER.to_vec(),
            attributes: vec![json!({ "name": "validity", "content": [] })],
            custom_attributes: vec![json!({ "name": "department", "content": [] })],
        }
    }

    fn expected() -> Value {
        json!({
            "request": STANDARD.encode(DER),
            "format": "pkcs10",
            "attributes": [{ "name": "validity", "content": [] }],
            "customAttributes": [{ "name": "department", "content": [] }]
        })
    }

    async fn serve(verb: &str, route: &str, response: ResponseTemplate) -> (MockServer, IlmUrl) {
        let server = MockServer::start().await;
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(response)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        (server, ilm)
    }

    async fn issue(response: ResponseTemplate) -> Result<String, IssueError> {
        let (_server, ilm) = serve("POST", ISSUE, response).await;
        let sent = issue_request(&client_for_tests(), &ilm, "a-1", "r-1", &body())
            .send()
            .await
            .unwrap();
        read_issued(sent).await
    }

    async fn state(response: ResponseTemplate) -> Result<IssuedState, StateError> {
        let (_server, ilm) = serve("GET", "/api/v1/certificates/c-1", response).await;
        let sent = state_request(&client_for_tests(), &ilm, "c-1")
            .send()
            .await
            .unwrap();
        read_state(sent).await
    }

    async fn chain(response: ResponseTemplate) -> Result<Vec<Vec<u8>>, IlmError> {
        let (_server, ilm) = serve("GET", "/api/v1/certificates/c-1/chain", response).await;
        let sent = chain_request(&client_for_tests(), &ilm, "c-1")
            .send()
            .await
            .unwrap();
        read_chain(sent).await
    }

    #[tokio::test]
    async fn the_issue_request_has_the_exact_path_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(ISSUE))
            .and(body_json(expected()))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "uuid": "c-1", "certificateData": "", "requestAttributeWarnings": ["Careful."] }),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = issue_request(&client_for_tests(), &ilm, "a-1", "r-1", &body())
            .send()
            .await
            .unwrap();
        assert_eq!(read_issued(sent).await.unwrap(), "c-1");
    }

    #[tokio::test]
    async fn the_complete_request_sends_the_challenge_only_when_there_is_one() {
        let secret = json!({ "authorizationSecret": "S3CRET" });
        let mut with = expected();
        with.as_object_mut()
            .unwrap()
            .extend(secret.as_object().unwrap().clone());
        for (challenge, wanted) in [
            (Some(Challenge::new("S3CRET".into())), with),
            (None, expected()),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(format!("{ISSUE}/c-9/issue")))
                .and(body_json(wanted))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-9" })))
                .expect(1)
                .mount(&server)
                .await;
            let ilm = IlmUrl::for_tests(&server.uri());
            let sent = complete_request(
                &client_for_tests(),
                &ilm,
                "a-1",
                "r-1",
                "c-9",
                &body(),
                challenge.as_ref(),
            )
            .send()
            .await
            .unwrap();
            assert_eq!(read_issued(sent).await.unwrap(), "c-9");
        }
    }

    #[test]
    fn the_challenge_never_shows_itself() {
        let challenge = Challenge::new("S3CRET".into());
        assert_eq!(format!("{challenge:?}"), "Challenge(..)");
        let request = complete_request(
            &client_for_tests(),
            &IlmUrl::for_tests("http://127.0.0.1:1"),
            "a-1",
            "r-1",
            "c-9",
            &body(),
            Some(&challenge),
        );
        assert!(!format!("{request:?}").contains("S3CRET"));
        let read: Challenge = serde_json::from_value(json!("S3CRET")).unwrap();
        assert_eq!(read.expose(), "S3CRET");
    }

    #[tokio::test]
    async fn the_issue_answers_are_told_apart() {
        for status in [400, 404, 422] {
            assert_eq!(
                issue(
                    ResponseTemplate::new(status).set_body_json(json!(["Bad name.", "Bad key."]))
                )
                .await
                .unwrap_err(),
                IssueError::Refused(vec!["Bad name.".into(), "Bad key.".into()])
            );
        }
        assert_eq!(
            issue(ResponseTemplate::new(403)).await.unwrap_err(),
            IssueError::NotAllowed
        );
        assert_eq!(
            issue(ResponseTemplate::new(401)).await.unwrap_err(),
            IssueError::Failed(IlmError::Unauthorized)
        );
        assert_eq!(
            issue(ResponseTemplate::new(502)).await.unwrap_err(),
            IssueError::Failed(IlmError::Unexpected(502))
        );
        assert_eq!(
            issue(ResponseTemplate::new(200).set_body_string("{"))
                .await
                .unwrap_err(),
            IssueError::Failed(IlmError::Malformed)
        );
    }

    #[test]
    fn the_errors_speak_plainly() {
        assert_eq!(
            IssueError::NotAllowed.to_string(),
            "ILM does not allow this."
        );
        assert_eq!(
            IssueError::Refused(vec!["One.".into(), "Two.".into()]).to_string(),
            "One. Two."
        );
        assert_eq!(
            IssueError::Refused(Vec::new()).to_string(),
            "ILM did not accept the request."
        );
        assert_eq!(
            IssueError::Failed(IlmError::Unreachable).to_string(),
            IlmError::Unreachable.to_string()
        );
        assert_eq!(
            StateError::Gone.to_string(),
            "ILM does not know this certificate."
        );
        assert_eq!(
            StateError::NotAllowed.to_string(),
            "ILM does not allow this."
        );
    }

    #[tokio::test]
    async fn an_issued_certificate_is_read_with_its_names_in_order() {
        let found = state(ResponseTemplate::new(200).set_body_json(json!({
            "state": "issued",
            "certificateContent": STANDARD.encode(DER),
            "subjectDn": "CN=web",
            "subjectAlternativeNames": { "dNSName": ["a.example", "b.example"], "iPAddress": ["10.0.0.1"] }
        })))
        .await
        .unwrap();
        assert_eq!(found.state, State::Issued);
        assert_eq!(found.content, Some(DER.to_vec()));
        assert_eq!(found.subject_dn.as_deref(), Some("CN=web"));
        assert_eq!(
            found.alternative_names,
            [
                (
                    "dNSName".to_owned(),
                    vec!["a.example".to_owned(), "b.example".to_owned()]
                ),
                ("iPAddress".to_owned(), vec!["10.0.0.1".to_owned()]),
            ]
        );
    }

    #[tokio::test]
    async fn a_certificate_before_issue_has_no_content() {
        for body in [
            json!({ "state": "pending_issue" }),
            json!({ "state": "pending_issue", "certificateContent": null, "subjectAlternativeNames": null }),
            json!({ "state": "pending_issue", "certificateContent": "" }),
        ] {
            let found = state(ResponseTemplate::new(200).set_body_json(body))
                .await
                .unwrap();
            assert_eq!(found.state, State::PendingIssue);
            assert_eq!(found.content, None);
            assert_eq!(found.subject_dn, None);
            assert!(found.alternative_names.is_empty());
            assert!(!found.request_attached);
        }
    }

    #[tokio::test]
    async fn an_attached_request_is_told_from_none() {
        for (body, attached) in [
            (json!({ "state": "registered" }), false),
            (
                json!({ "state": "registered", "certificateRequest": null }),
                false,
            ),
            (
                json!({ "state": "registered", "certificateRequest": { "content": "AQID" } }),
                true,
            ),
        ] {
            let found = state(ResponseTemplate::new(200).set_body_json(body))
                .await
                .unwrap();
            assert_eq!(found.request_attached, attached);
        }
    }

    #[tokio::test]
    async fn the_state_answers_are_told_apart() {
        assert_eq!(
            state(ResponseTemplate::new(404)).await.unwrap_err(),
            StateError::Gone
        );
        assert_eq!(
            state(ResponseTemplate::new(403)).await.unwrap_err(),
            StateError::NotAllowed
        );
        assert_eq!(
            state(ResponseTemplate::new(401)).await.unwrap_err(),
            StateError::Failed(IlmError::Unauthorized)
        );
        assert_eq!(
            state(ResponseTemplate::new(500)).await.unwrap_err(),
            StateError::Failed(IlmError::Unexpected(500))
        );
        for body in [
            ResponseTemplate::new(200).set_body_string("{"),
            ResponseTemplate::new(200)
                .set_body_json(json!({ "state": "issued", "certificateContent": "***" })),
        ] {
            assert_eq!(
                state(body).await.unwrap_err(),
                StateError::Failed(IlmError::Malformed)
            );
        }
    }

    #[tokio::test]
    async fn the_chain_is_read_in_order_without_the_empty_elements() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/certificates/c-1/chain"))
            .and(query_param("withEndCertificate", "false"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "completeChain": true,
                "certificates": [
                    { "certificateContent": STANDARD.encode([1u8, 2]) },
                    { "uuid": "no content" },
                    { "certificateContent": STANDARD.encode([3u8]) }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = chain_request(&client_for_tests(), &ilm, "c-1")
            .send()
            .await
            .unwrap();
        assert_eq!(read_chain(sent).await.unwrap(), [vec![1, 2], vec![3]]);
    }

    #[tokio::test]
    async fn the_chain_answers_are_errors() {
        assert_eq!(
            chain(ResponseTemplate::new(401)).await,
            Err(IlmError::Unauthorized)
        );
        assert_eq!(
            chain(ResponseTemplate::new(503)).await,
            Err(IlmError::Unexpected(503))
        );
        assert_eq!(
            chain(ResponseTemplate::new(200).set_body_string("{")).await,
            Err(IlmError::Malformed)
        );
        assert_eq!(
            chain(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "certificates": [{ "certificateContent": "***" }] }))
            )
            .await,
            Err(IlmError::Malformed)
        );
    }
}
