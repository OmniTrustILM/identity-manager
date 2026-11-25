//! The approvals of certificate requests that wait for the person: the list ILM keeps for them, and the decision
//! the person takes as a recipient of an approval.

use std::fmt;

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::IlmUrl;
use super::certificates::millis;
use super::issue::state_request;
use super::profile::{IlmError, read_rejection};

/// The most approvals that one check reads.
const LIMIT: u32 = 1000;

/// What the request behind an approval asks ILM to do with a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename_all = "camelCase")
)]
pub enum ApprovalAction {
    Issue,
    Renew,
    Rekey,
    Revoke,
}

impl ApprovalAction {
    fn from_code(code: &str) -> Option<Self> {
        match code {
            "issue" => Some(Self::Issue),
            "renew" => Some(Self::Renew),
            "rekey" => Some(Self::Rekey),
            "revoke" => Some(Self::Revoke),
            _ => None,
        }
    }
}

/// An approval of a certificate that waits for the person's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Waiting {
    pub uuid: String,
    pub action: ApprovalAction,
    /// The ILM uuid of the person who asked.
    pub creator_uuid: String,
    /// For display only; None when ILM could not tell who asked.
    pub creator: Option<String>,
    /// Milliseconds since 1970 UTC.
    pub created_at: i64,
    /// The certificate the approval is about.
    pub certificate: String,
}

/// What the person decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
}

impl Decision {
    fn path(self) -> &'static str {
        match self {
            Self::Approve => "approveRecipient",
            Self::Reject => "rejectRecipient",
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        })
    }
}

/// Why a decision was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecideError {
    /// The approval is closed, expired, unknown or not addressed to the person.
    NoLongerWaiting,
    /// ILM refused the decision and says why; the messages are for the person, never the log.
    Refused(Vec<String>),
    /// The person may not do this.
    NotAllowed,
    Failed(IlmError),
}

impl fmt::Display for DecideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLongerWaiting => f.write_str("This request no longer waits for your decision."),
            Self::Refused(messages) if messages.is_empty() => {
                f.write_str("ILM did not accept the decision.")
            }
            Self::Refused(messages) => f.write_str(&messages.join(" ")),
            Self::NotAllowed => f.write_str("ILM does not allow this."),
            Self::Failed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DecideError {}

/// The request for the approvals that wait for the person.
pub fn list_request(client: &Client, ilm: &IlmUrl) -> RequestBuilder {
    client.get(format!(
        "{}/v1/approvals/user?history=false&itemsPerPage={LIMIT}&pageNumber=1",
        ilm.api()
    ))
}

#[derive(Deserialize)]
struct RawList {
    approvals: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawApproval {
    approval_uuid: String,
    creator_uuid: String,
    creator_username: Option<String>,
    created_at: Option<Value>,
    status: String,
    resource: String,
    resource_action: String,
    object_uuid: String,
}

/// Whether ILM names the resource of an approval as a certificate, in whichever form it writes the name.
fn is_certificate(resource: &str) -> bool {
    let resource = resource.to_ascii_lowercase();
    resource.strip_suffix('s').unwrap_or(&resource) == "certificate"
}

impl RawApproval {
    /// The approval, when it is a pending one about a certificate and one of the `ApprovalAction`s.
    fn waiting(self) -> Option<Waiting> {
        if !self.status.eq_ignore_ascii_case("pending") || !is_certificate(&self.resource) {
            return None;
        }
        Some(Waiting {
            uuid: self.approval_uuid,
            action: ApprovalAction::from_code(&self.resource_action)?,
            creator_uuid: self.creator_uuid,
            creator: self.creator_username.filter(|name| !name.is_empty()),
            created_at: self
                .created_at
                .as_ref()
                .and_then(millis)
                .unwrap_or_default(),
            certificate: self.object_uuid,
        })
    }
}

/// Reads the list: the pending approvals about certificates. An approval that cannot be read is left out.
pub async fn read_list(response: Response) -> Result<Vec<Waiting>, IlmError> {
    let status = response.status();
    if status == StatusCode::UNAUTHORIZED {
        return Err(IlmError::Unauthorized);
    }
    if !status.is_success() {
        log::warn!("ILM answered the approval list with {status}");
        return Err(IlmError::Unexpected(status.as_u16()));
    }
    let list = response.json::<RawList>().await.map_err(|_| {
        log::warn!("ILM sent an approval list this application cannot read");
        IlmError::Malformed
    })?;
    Ok(list
        .approvals
        .into_iter()
        .filter_map(|item| serde_json::from_value::<RawApproval>(item).ok())
        .filter_map(RawApproval::waiting)
        .collect())
}

/// The request that takes the person's `decision` on the approval `uuid`, with an optional `comment` ILM keeps with
/// it. It is the decision of a recipient, never ILM's override of the whole approval.
pub fn decide_request(
    client: &Client,
    ilm: &IlmUrl,
    uuid: &str,
    decision: Decision,
    comment: Option<&str>,
) -> RequestBuilder {
    client
        .patch(format!(
            "{}/v1/approvals/{uuid}/{}",
            ilm.api(),
            decision.path()
        ))
        .json(&json!({ "comment": comment }))
}

/// Reads ILM's answer to a decision.
pub async fn read_decision(response: Response) -> Result<(), DecideError> {
    let status = response.status();
    match status {
        _ if status.is_success() => Ok(()),
        StatusCode::UNAUTHORIZED => Err(DecideError::Failed(IlmError::Unauthorized)),
        StatusCode::FORBIDDEN => Err(DecideError::NotAllowed),
        StatusCode::NOT_FOUND => Err(DecideError::NoLongerWaiting),
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
            Err(DecideError::Refused(read_rejection(response).await))
        }
        _ => {
            log::warn!("ILM answered the decision with {status}");
            Err(DecideError::Failed(IlmError::Unexpected(status.as_u16())))
        }
    }
}

/// The request for the certificate an approval is about.
pub fn certificate_request(client: &Client, ilm: &IlmUrl, uuid: &str) -> RequestBuilder {
    state_request(client, ilm, uuid)
}

/// What ILM says of the certificate an approval is about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Described {
    pub name: Option<String>,
    pub ra_profile: Option<String>,
}

/// Why the certificate of an approval could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescribeError {
    /// The person may not see it, or ILM does not have it.
    Hidden,
    Failed(IlmError),
}

fn text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Reads the name and the RA Profile of a certificate.
pub async fn read_certificate(response: Response) -> Result<Described, DescribeError> {
    let status = response.status();
    match status {
        _ if status.is_success() => {}
        StatusCode::UNAUTHORIZED => return Err(DescribeError::Failed(IlmError::Unauthorized)),
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => return Err(DescribeError::Hidden),
        _ => {
            log::warn!("ILM answered the certificate of an approval with {status}");
            return Err(DescribeError::Failed(IlmError::Unexpected(status.as_u16())));
        }
    }
    let body = response.json::<Value>().await.map_err(|_| {
        log::warn!("ILM sent a certificate this application cannot read");
        DescribeError::Failed(IlmError::Malformed)
    })?;
    Ok(Described {
        name: ["displayName", "commonName", "subjectDn"]
            .into_iter()
            .find_map(|field| text(body.get(field))),
        ra_profile: text(
            body.get("raProfile")
                .and_then(|profile| profile.get("name")),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn approval(uuid: &str, resource: &str, action: &str, status: &str) -> Value {
        json!({
            "approvalUuid": uuid,
            "creatorUuid": "u-2",
            "creatorUsername": "ada",
            "version": 1,
            "createdAt": "2026-11-25T10:00:00.000+00:00",
            "expiryAt": null,
            "closedAt": null,
            "status": status,
            "resource": resource,
            "resourceAction": action,
            "objectUuid": "c-1",
            "approvalProfileName": "Two eyes",
            "approvalProfileUuid": "p-1",
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

    async fn list(response: ResponseTemplate) -> Result<Vec<Waiting>, IlmError> {
        let (_server, ilm) = serve("GET", "/api/v1/approvals/user", response).await;
        let sent = list_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        read_list(sent).await
    }

    async fn decide(decision: Decision, response: ResponseTemplate) -> Result<(), DecideError> {
        let route = format!("/api/v1/approvals/a-1/{}", decision.path());
        let (_server, ilm) = serve("PATCH", &route, response).await;
        let sent = decide_request(&client_for_tests(), &ilm, "a-1", decision, None)
            .send()
            .await
            .unwrap();
        read_decision(sent).await
    }

    async fn certificate(response: ResponseTemplate) -> Result<Described, DescribeError> {
        let (_server, ilm) = serve("GET", "/api/v1/certificates/c-1", response).await;
        let sent = certificate_request(&client_for_tests(), &ilm, "c-1")
            .send()
            .await
            .unwrap();
        read_certificate(sent).await
    }

    #[tokio::test]
    async fn the_list_asks_for_the_open_approvals_in_one_big_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/approvals/user"))
            .and(query_param("history", "false"))
            .and(query_param("itemsPerPage", "1000"))
            .and(query_param("pageNumber", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "approvals": [] })))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());

        let sent = list_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();

        assert_eq!(read_list(sent).await.unwrap(), []);
    }

    #[tokio::test]
    async fn only_pending_certificate_approvals_of_the_four_actions_are_kept() {
        let items = vec![
            approval("a-1", "certificates", "issue", "PENDING"),
            approval("a-2", "CERTIFICATE", "revoke", "PENDING"),
            approval("a-3", "certificates", "renew", "APPROVED"),
            approval("a-4", "keys", "issue", "PENDING"),
            approval("a-5", "certificates", "update", "PENDING"),
            approval("a-6", "certificates", "rekey", "PENDING"),
            json!({ "approvalUuid": "a-7" }),
        ];

        let kept = list(ResponseTemplate::new(200).set_body_json(json!({ "approvals": items })))
            .await
            .unwrap();

        let found: Vec<_> = kept
            .iter()
            .map(|found| (found.uuid.as_str(), found.action))
            .collect();
        assert_eq!(
            found,
            [
                ("a-1", ApprovalAction::Issue),
                ("a-2", ApprovalAction::Revoke),
                ("a-6", ApprovalAction::Rekey)
            ]
        );
        assert_eq!(kept[0].creator.as_deref(), Some("ada"));
        assert_eq!(kept[0].created_at, 1_795_600_800_000);
        assert_eq!(kept[0].certificate, "c-1");
    }

    #[tokio::test]
    async fn a_creator_ilm_could_not_name_is_none() {
        let mut item = approval("a-1", "certificates", "issue", "PENDING");
        item["creatorUsername"] = json!(null);

        let kept = list(ResponseTemplate::new(200).set_body_json(json!({ "approvals": [item] })))
            .await
            .unwrap();

        assert_eq!(kept[0].creator, None);
    }

    #[tokio::test]
    async fn the_list_answers_are_told_apart() {
        assert_eq!(
            list(ResponseTemplate::new(401)).await.unwrap_err(),
            IlmError::Unauthorized
        );
        assert_eq!(
            list(ResponseTemplate::new(403)).await.unwrap_err(),
            IlmError::Unexpected(403)
        );
        assert_eq!(
            list(ResponseTemplate::new(200).set_body_string("{"))
                .await
                .unwrap_err(),
            IlmError::Malformed
        );
    }

    #[tokio::test]
    async fn a_decision_goes_to_the_recipient_path_with_the_comment() {
        for (decision, tail) in [
            (Decision::Approve, "approveRecipient"),
            (Decision::Reject, "rejectRecipient"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("PATCH"))
                .and(path(format!("/api/v1/approvals/a-1/{tail}")))
                .and(body_json(json!({ "comment": "Fine." })))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&server)
                .await;
            let ilm = IlmUrl::for_tests(&server.uri());

            let sent = decide_request(&client_for_tests(), &ilm, "a-1", decision, Some("Fine."))
                .send()
                .await
                .unwrap();

            assert_eq!(read_decision(sent).await, Ok(()));
        }
    }

    #[tokio::test]
    async fn no_comment_is_sent_as_null() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(body_json(json!({ "comment": null })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());

        let sent = decide_request(&client_for_tests(), &ilm, "a-1", Decision::Reject, None)
            .send()
            .await
            .unwrap();

        assert_eq!(read_decision(sent).await, Ok(()));
    }

    #[tokio::test]
    async fn the_decision_answers_are_told_apart() {
        assert_eq!(
            decide(Decision::Approve, ResponseTemplate::new(404))
                .await
                .unwrap_err(),
            DecideError::NoLongerWaiting
        );
        assert_eq!(
            decide(
                Decision::Reject,
                ResponseTemplate::new(422).set_body_json(json!(["Already decided."]))
            )
            .await
            .unwrap_err(),
            DecideError::Refused(vec!["Already decided.".into()])
        );
        assert_eq!(
            decide(Decision::Approve, ResponseTemplate::new(403))
                .await
                .unwrap_err(),
            DecideError::NotAllowed
        );
        assert_eq!(
            decide(Decision::Approve, ResponseTemplate::new(401))
                .await
                .unwrap_err(),
            DecideError::Failed(IlmError::Unauthorized)
        );
        assert_eq!(
            decide(Decision::Approve, ResponseTemplate::new(502))
                .await
                .unwrap_err(),
            DecideError::Failed(IlmError::Unexpected(502))
        );
    }

    #[test]
    fn the_errors_speak_plainly() {
        assert_eq!(
            DecideError::NoLongerWaiting.to_string(),
            "This request no longer waits for your decision."
        );
        assert_eq!(
            DecideError::NotAllowed.to_string(),
            "ILM does not allow this."
        );
        assert_eq!(
            DecideError::Refused(vec!["One.".into(), "Two.".into()]).to_string(),
            "One. Two."
        );
        assert_eq!(
            DecideError::Refused(Vec::new()).to_string(),
            "ILM did not accept the decision."
        );
    }

    #[tokio::test]
    async fn the_certificate_gives_its_name_and_ra_profile() {
        let described = certificate(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": "c-1",
            "commonName": "demo220",
            "subjectDn": "CN=demo220",
            "raProfile": { "uuid": "ra-1", "name": "Servers" },
        })))
        .await
        .unwrap();

        assert_eq!(
            described,
            Described {
                name: Some("demo220".to_owned()),
                ra_profile: Some("Servers".to_owned())
            }
        );
        let bare = certificate(ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-1" })))
            .await
            .unwrap();
        assert_eq!(bare, Described::default());
    }

    #[tokio::test]
    async fn the_certificate_answers_are_told_apart() {
        for status in [403, 404] {
            assert_eq!(
                certificate(ResponseTemplate::new(status))
                    .await
                    .unwrap_err(),
                DescribeError::Hidden
            );
        }
        assert_eq!(
            certificate(ResponseTemplate::new(401)).await.unwrap_err(),
            DescribeError::Failed(IlmError::Unauthorized)
        );
        assert_eq!(
            certificate(ResponseTemplate::new(500)).await.unwrap_err(),
            DescribeError::Failed(IlmError::Unexpected(500))
        );
    }
}
