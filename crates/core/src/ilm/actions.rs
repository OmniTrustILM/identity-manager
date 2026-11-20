//! What the person may do with each of a list of certificates, as ILM reports it.

use std::collections::HashMap;

use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Deserialize;
use serde_json::json;

use super::IlmUrl;
use super::profile::IlmError;

/// The most objects ILM is asked about in one request.
pub const MAX_UUIDS: usize = 1000;

/// How ILM answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Used,
    /// ILM is too old to know the question.
    Unsupported,
    /// ILM did not accept the question.
    Refused,
}

/// The allowed actions per certificate UUID. The map is empty unless the outcome is `Used`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedActions {
    pub actions: HashMap<String, Vec<String>>,
    pub outcome: Outcome,
}

#[derive(Deserialize)]
struct Answer {
    items: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    uuid: String,
    allowed_actions: Vec<String>,
}

/// Asks for the allowed actions on up to [`MAX_UUIDS`] certificates.
pub fn request(client: &Client, ilm: &IlmUrl, uuids: &[String]) -> RequestBuilder {
    client
        .post(format!(
            "{}/v1/resources/certificates/objects/allowed-actions",
            ilm.api()
        ))
        .json(&json!({ "uuids": uuids }))
}

fn without(outcome: Outcome) -> AllowedActions {
    AllowedActions {
        actions: HashMap::new(),
        outcome,
    }
}

/// Reads ILM's answer. A missing or refused question is not an error, so a check can go on without it.
pub async fn read(response: Response) -> Result<AllowedActions, IlmError> {
    let status = response.status();
    match status {
        StatusCode::UNAUTHORIZED => Err(IlmError::Unauthorized),
        StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
            log::info!("ILM does not report allowed actions ({status})");
            Ok(without(Outcome::Unsupported))
        }
        StatusCode::UNPROCESSABLE_ENTITY => {
            log::warn!("ILM refused the allowed actions request ({status})");
            Ok(without(Outcome::Refused))
        }
        status if status.is_success() => {
            let answer = response.json::<Answer>().await.map_err(|_| {
                log::warn!("ILM sent allowed actions this application cannot read");
                IlmError::Malformed
            })?;
            Ok(AllowedActions {
                actions: answer
                    .items
                    .into_iter()
                    .map(|item| (item.uuid, item.allowed_actions))
                    .collect(),
                outcome: Outcome::Used,
            })
        }
        status => {
            log::warn!("ILM answered the allowed actions request with {status}");
            Err(IlmError::Unexpected(status.as_u16()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn ask(response: ResponseTemplate) -> Result<AllowedActions, IlmError> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v1/resources/certificates/objects/allowed-actions",
            ))
            .and(body_json(json!({ "uuids": ["a", "b"] })))
            .respond_with(response)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let uuids = ["a".to_string(), "b".to_string()];
        let response = request(&client_for_tests(), &ilm, &uuids)
            .send()
            .await
            .unwrap();
        read(response).await
    }

    #[tokio::test]
    async fn the_answer_becomes_a_map() {
        let body = json!({ "items": [
            { "uuid": "a", "allowedActions": ["detail", "renew"] },
            { "uuid": "b", "allowedActions": [] }
        ]});
        let allowed = ask(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap();
        assert_eq!(allowed.outcome, Outcome::Used);
        assert_eq!(allowed.actions["a"], ["detail", "renew"]);
        assert!(allowed.actions["b"].is_empty());
    }

    #[tokio::test]
    async fn an_old_ilm_is_unsupported() {
        for status in [404, 405] {
            let allowed = ask(ResponseTemplate::new(status)).await.unwrap();
            assert_eq!(allowed.outcome, Outcome::Unsupported);
            assert!(allowed.actions.is_empty());
        }
    }

    #[tokio::test]
    async fn a_refused_question_gives_an_empty_map() {
        let allowed = ask(ResponseTemplate::new(422)).await.unwrap();
        assert_eq!(allowed.outcome, Outcome::Refused);
        assert!(allowed.actions.is_empty());
    }

    #[tokio::test]
    async fn other_answers_are_errors() {
        assert_eq!(
            ask(ResponseTemplate::new(401)).await.unwrap_err(),
            IlmError::Unauthorized
        );
        assert_eq!(
            ask(ResponseTemplate::new(500)).await.unwrap_err(),
            IlmError::Unexpected(500)
        );
        assert_eq!(
            ask(ResponseTemplate::new(200).set_body_string("{"))
                .await
                .unwrap_err(),
            IlmError::Malformed
        );
    }
}
