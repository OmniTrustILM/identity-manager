//! Renewing, rekeying and revoking a certificate through ILM. Renewing asks ILM to reuse the request it stored,
//! rekeying sends a new one; both make a new certificate and leave the old one as it is.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Client, RequestBuilder, Response};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use super::IlmUrl;
use super::issue::{IssueError, refusal};

/// Why the person revokes a certificate: the reasons a certificate holder can give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Reason {
    Unspecified,
    KeyCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    PrivilegeWithdrawn,
}

/// The address of an operation on a certificate. Each part is one path segment, whatever it holds.
fn operation_url(
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    certificate: &str,
    operation: &str,
) -> String {
    let mut url = Url::parse(&ilm.api()).expect("the ILM address is a valid address");
    url.path_segments_mut()
        .expect("the ILM address can have a path")
        .pop_if_empty()
        .extend([
            "v2",
            "operations",
            "authorities",
            authority,
            "raProfiles",
            ra_profile,
            "certificates",
            certificate,
            operation,
        ]);
    url.into()
}

fn send(client: &Client, url: String, body: Value) -> RequestBuilder {
    client.post(url).json(&body)
}

/// The request that renews a certificate with the request ILM stored for it.
pub fn renew_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    certificate: &str,
) -> RequestBuilder {
    send(
        client,
        operation_url(ilm, authority, ra_profile, certificate, "renew"),
        json!({ "replaceInLocations": false }),
    )
}

/// The request that renews a certificate with a new key, whose signed request (DER) it carries.
pub fn rekey_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    certificate: &str,
    request_der: &[u8],
) -> RequestBuilder {
    send(
        client,
        operation_url(ilm, authority, ra_profile, certificate, "rekey"),
        json!({
            "replaceInLocations": false,
            "request": STANDARD.encode(request_der),
            "format": "pkcs10",
        }),
    )
}

/// The request that revokes a certificate. ILM answers before the revocation is done.
pub fn revoke_request(
    client: &Client,
    ilm: &IlmUrl,
    authority: &str,
    ra_profile: &str,
    certificate: &str,
    reason: Reason,
) -> RequestBuilder {
    send(
        client,
        operation_url(ilm, authority, ra_profile, certificate, "revoke"),
        json!({ "reason": reason, "attributes": [], "destroyKey": false }),
    )
}

/// Reads ILM's answer to a revocation.
pub async fn read_revoked(response: Response) -> Result<(), IssueError> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(refusal(response).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use crate::ilm::issue::read_issued;
    use crate::ilm::profile::IlmError;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const BASE: &str = "/api/v2/operations/authorities/a-1/raProfiles/r-1/certificates/c-1";
    const DER: [u8; 4] = [0x30, 0x82, 0x01, 0xff];

    async fn mounted(
        operation: &str,
        body: Value,
        response: ResponseTemplate,
    ) -> (MockServer, IlmUrl) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("{BASE}/{operation}")))
            .and(body_json(body))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        (server, ilm)
    }

    fn made() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({ "uuid": "c-2", "certificateData": "" }))
    }

    #[tokio::test]
    async fn renewing_sends_no_request() {
        let (_server, ilm) = mounted("renew", json!({ "replaceInLocations": false }), made()).await;
        let sent = renew_request(&client_for_tests(), &ilm, "a-1", "r-1", "c-1")
            .send()
            .await
            .unwrap();
        assert_eq!(read_issued(sent).await.unwrap(), "c-2");
    }

    #[tokio::test]
    async fn rekeying_sends_the_new_request() {
        let body = json!({
            "replaceInLocations": false,
            "request": STANDARD.encode(DER),
            "format": "pkcs10",
        });
        let (_server, ilm) = mounted("rekey", body, made()).await;
        let sent = rekey_request(&client_for_tests(), &ilm, "a-1", "r-1", "c-1", &DER)
            .send()
            .await
            .unwrap();
        assert_eq!(read_issued(sent).await.unwrap(), "c-2");
    }

    #[test]
    fn the_reasons_are_written_as_ilm_knows_them() {
        let codes = [
            (Reason::Unspecified, "unspecified"),
            (Reason::KeyCompromise, "keyCompromise"),
            (Reason::AffiliationChanged, "affiliationChanged"),
            (Reason::Superseded, "superseded"),
            (Reason::CessationOfOperation, "cessationOfOperation"),
            (Reason::PrivilegeWithdrawn, "privilegeWithdrawn"),
        ];
        for (reason, code) in codes {
            assert_eq!(serde_json::to_value(reason).unwrap(), json!(code));
        }
    }

    #[tokio::test]
    async fn revoking_sends_the_reason_and_takes_no_content() {
        let body = json!({ "reason": "superseded", "attributes": [], "destroyKey": false });
        let (_server, ilm) = mounted("revoke", body, ResponseTemplate::new(204)).await;
        let sent = revoke_request(
            &client_for_tests(),
            &ilm,
            "a-1",
            "r-1",
            "c-1",
            Reason::Superseded,
        )
        .send()
        .await
        .unwrap();
        assert_eq!(read_revoked(sent).await, Ok(()));
    }

    async fn answered(status: u16, body: Option<Value>) -> [IssueError; 3] {
        let mut response = ResponseTemplate::new(status);
        if let Some(body) = body {
            response = response.set_body_json(body);
        }
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(response)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let client = client_for_tests();
        let renewed = renew_request(&client, &ilm, "a-1", "r-1", "c-1");
        let rekeyed = rekey_request(&client, &ilm, "a-1", "r-1", "c-1", &DER);
        let revoked = revoke_request(&client, &ilm, "a-1", "r-1", "c-1", Reason::Unspecified);
        [
            read_issued(renewed.send().await.unwrap())
                .await
                .unwrap_err(),
            read_issued(rekeyed.send().await.unwrap())
                .await
                .unwrap_err(),
            read_revoked(revoked.send().await.unwrap())
                .await
                .unwrap_err(),
        ]
    }

    #[tokio::test]
    async fn a_refusal_keeps_the_words_of_ilm() {
        let messages = json!(["Certificate is already revoked.", "Second."]);
        for status in [400, 404, 422] {
            for error in answered(status, Some(messages.clone())).await {
                assert_eq!(
                    error,
                    IssueError::Refused(vec![
                        "Certificate is already revoked.".into(),
                        "Second.".into()
                    ])
                );
            }
        }
    }

    #[tokio::test]
    async fn the_other_answers_are_told_apart() {
        for error in answered(403, None).await {
            assert_eq!(error, IssueError::NotAllowed);
        }
        for error in answered(401, None).await {
            assert_eq!(error, IssueError::Failed(IlmError::Unauthorized));
        }
        for status in [502, 503] {
            for error in answered(status, None).await {
                assert_eq!(error, IssueError::Failed(IlmError::Unexpected(status)));
            }
        }
    }

    #[test]
    fn each_part_of_the_address_is_one_segment() {
        let ilm = IlmUrl::for_tests("http://127.0.0.1:9/ilm");
        let url = operation_url(&ilm, "a/b", "r?x", "c#1", "renew");
        assert_eq!(
            url,
            "http://127.0.0.1:9/ilm/api/v2/operations/authorities/a%2Fb/raProfiles/r%3Fx/certificates/c%231/renew"
        );
    }
}
