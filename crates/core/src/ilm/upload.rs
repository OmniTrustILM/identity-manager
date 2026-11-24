//! Adding a local certificate to ILM: the upload, the update that gives it an owner, group and RA Profile, and the
//! lists the person chooses a group and an RA Profile from.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::IlmUrl;
use super::profile::{IlmError, read_rejection};

/// Why ILM did not take a request of the add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddError {
    /// ILM holds the certificate already.
    AlreadyInIlm,
    /// The person may not do this.
    NotAllowed,
    /// ILM refused the request and says why; the messages are for the person, never the log.
    Rejected(Vec<String>),
    Failed(IlmError),
}

/// A group the person may put a certificate in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct GroupChoice {
    pub uuid: String,
    pub name: String,
}

/// An enabled RA Profile that may manage a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "ts"), derive(ts_rs::TS), ts(export))]
pub struct RaProfileChoice {
    pub uuid: String,
    pub name: String,
    /// The authority the profile issues from.
    pub authority: Option<String>,
    /// The UUID of that authority, which ILM's issuing paths name.
    pub authority_uuid: Option<String>,
}

#[derive(Deserialize)]
struct Uploaded {
    uuid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRaProfile {
    uuid: String,
    name: String,
    #[serde(default)]
    enabled: bool,
    authority_instance_name: Option<String>,
    authority_instance_uuid: Option<String>,
}

/// The upload of one certificate, given as its DER, with the custom attributes as request attributes.
pub fn upload_request(
    client: &Client,
    ilm: &IlmUrl,
    der: &[u8],
    custom_attributes: &[Value],
) -> RequestBuilder {
    client
        .post(format!("{}/v1/certificates/upload", ilm.api()))
        .json(
            &json!({ "certificate": STANDARD.encode(der), "customAttributes": custom_attributes }),
        )
}

/// The update of an uploaded certificate. Only what is given is sent, so ILM leaves the rest as it is.
pub fn update_request(
    client: &Client,
    ilm: &IlmUrl,
    uuid: &str,
    owner_uuid: Option<&str>,
    group_uuid: Option<&str>,
    ra_profile_uuid: Option<&str>,
) -> RequestBuilder {
    let mut body = Map::new();
    if let Some(owner) = owner_uuid {
        body.insert("ownerUuid".into(), json!(owner));
    }
    if let Some(group) = group_uuid {
        body.insert("groupUuids".into(), json!([group]));
    }
    if let Some(ra_profile) = ra_profile_uuid {
        body.insert("raProfileUuid".into(), json!(ra_profile));
    }
    client
        .patch(format!("{}/v1/certificates/{uuid}", ilm.api()))
        .json(&Value::Object(body))
}

pub fn groups_request(client: &Client, ilm: &IlmUrl) -> RequestBuilder {
    client.get(format!("{}/v1/groups", ilm.api()))
}

pub fn ra_profiles_request(client: &Client, ilm: &IlmUrl) -> RequestBuilder {
    client.get(format!("{}/v1/raProfiles?enabled=true", ilm.api()))
}

/// Sorts out the status of an answer to a change; a success passes through.
async fn check(response: Response, what: &str) -> Result<Response, AddError> {
    let status = response.status();
    match status {
        _ if status.is_success() => Ok(response),
        StatusCode::UNAUTHORIZED => Err(AddError::Failed(IlmError::Unauthorized)),
        StatusCode::FORBIDDEN => Err(AddError::NotAllowed),
        StatusCode::CONFLICT => Err(AddError::AlreadyInIlm),
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => {
            Err(AddError::Rejected(read_rejection(response).await))
        }
        _ => {
            log::warn!("ILM answered the {what} with {status}");
            Err(AddError::Failed(IlmError::Unexpected(status.as_u16())))
        }
    }
}

/// Reads the answer to the upload: the UUID ILM gave the certificate.
pub async fn read_upload(response: Response) -> Result<String, AddError> {
    let uploaded = check(response, "upload")
        .await?
        .json::<Uploaded>()
        .await
        .map_err(|_| {
            log::warn!("ILM sent an upload answer this application cannot read");
            AddError::Failed(IlmError::Malformed)
        })?;
    Ok(uploaded.uuid)
}

/// Reads the answer to the update.
pub async fn read_update(response: Response) -> Result<(), AddError> {
    check(response, "update").await.map(|_| ())
}

/// Reads a list the person may not see (403) or ILM does not have (404) as none.
async fn read_choices<T: serde::de::DeserializeOwned>(
    response: Response,
    what: &str,
) -> Result<Option<Vec<T>>, IlmError> {
    let status = response.status();
    match status {
        StatusCode::UNAUTHORIZED => Err(IlmError::Unauthorized),
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
            log::info!("ILM does not give the {what} ({status})");
            Ok(None)
        }
        _ if status.is_success() => response.json::<Vec<T>>().await.map(Some).map_err(|_| {
            log::warn!("ILM sent {what} this application cannot read");
            IlmError::Malformed
        }),
        _ => {
            log::warn!("ILM answered the {what} request with {status}");
            Err(IlmError::Unexpected(status.as_u16()))
        }
    }
}

/// Reads the groups; none when the person may not list them or ILM has none to give.
pub async fn read_groups(response: Response) -> Result<Option<Vec<GroupChoice>>, IlmError> {
    read_choices(response, "groups").await
}

/// Reads the RA Profiles, enabled ones only; none when the person may not list them or ILM has none to give.
pub async fn read_ra_profiles(
    response: Response,
) -> Result<Option<Vec<RaProfileChoice>>, IlmError> {
    Ok(read_choices::<RawRaProfile>(response, "RA Profiles")
        .await?
        .map(|profiles| {
            profiles
                .into_iter()
                .filter(|profile| profile.enabled)
                .map(|profile| RaProfileChoice {
                    uuid: profile.uuid,
                    name: profile.name,
                    authority: profile.authority_instance_name,
                    authority_uuid: profile.authority_instance_uuid,
                })
                .collect()
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::client_for_tests;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DER: [u8; 6] = [0x30, 0x82, 0x01, 0xff, 0x00, 0x7f];

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

    async fn upload(response: ResponseTemplate) -> Result<String, AddError> {
        let (_server, ilm) = serve("POST", "/api/v1/certificates/upload", response).await;
        let sent = upload_request(&client_for_tests(), &ilm, &DER, &[])
            .send()
            .await
            .unwrap();
        read_upload(sent).await
    }

    async fn update(response: ResponseTemplate) -> Result<(), AddError> {
        let (_server, ilm) = serve("PATCH", "/api/v1/certificates/c-1", response).await;
        let sent = update_request(&client_for_tests(), &ilm, "c-1", Some("u-1"), None, None)
            .send()
            .await
            .unwrap();
        read_update(sent).await
    }

    #[tokio::test]
    async fn the_upload_carries_the_exact_der_and_gives_the_uuid() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/certificates/upload"))
            .and(body_json(json!({
                "certificate": STANDARD.encode(DER),
                "customAttributes": []
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "uuid": "c-1" })))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = upload_request(&client_for_tests(), &ilm, &DER, &[])
            .send()
            .await
            .unwrap();
        assert_eq!(read_upload(sent).await.unwrap(), "c-1");
    }

    #[tokio::test]
    async fn the_upload_carries_the_custom_attributes() {
        let attributes = vec![json!({
            "uuid": "11111111-1111-4111-8111-111111111111",
            "name": "department",
            "contentType": "string",
            "version": "v3",
            "content": [{ "data": "Sales", "contentType": "string" }]
        })];
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/certificates/upload"))
            .and(body_json(json!({
                "certificate": STANDARD.encode(DER),
                "customAttributes": attributes
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "uuid": "c-1" })))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = upload_request(&client_for_tests(), &ilm, &DER, &attributes)
            .send()
            .await
            .unwrap();
        assert_eq!(read_upload(sent).await.unwrap(), "c-1");
    }

    #[tokio::test]
    async fn the_upload_answers_are_told_apart() {
        assert_eq!(
            upload(ResponseTemplate::new(409)).await.unwrap_err(),
            AddError::AlreadyInIlm
        );
        assert_eq!(
            upload(ResponseTemplate::new(403)).await.unwrap_err(),
            AddError::NotAllowed
        );
        assert_eq!(
            upload(ResponseTemplate::new(401)).await.unwrap_err(),
            AddError::Failed(IlmError::Unauthorized)
        );
        assert_eq!(
            upload(ResponseTemplate::new(500)).await.unwrap_err(),
            AddError::Failed(IlmError::Unexpected(500))
        );
        assert_eq!(
            upload(ResponseTemplate::new(201).set_body_string("{"))
                .await
                .unwrap_err(),
            AddError::Failed(IlmError::Malformed)
        );
    }

    #[tokio::test]
    async fn a_refused_request_gives_ilms_messages() {
        for status in [400, 404, 422] {
            let error = upload(
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "message": "Not a certificate." })),
            )
            .await
            .unwrap_err();
            assert_eq!(error, AddError::Rejected(vec!["Not a certificate.".into()]));
        }
        assert_eq!(
            update(ResponseTemplate::new(422).set_body_json(json!(["One.", "Two."])))
                .await
                .unwrap_err(),
            AddError::Rejected(vec!["One.".into(), "Two.".into()])
        );
        assert_eq!(
            update(ResponseTemplate::new(400)).await.unwrap_err(),
            AddError::Rejected(Vec::new())
        );
    }

    #[tokio::test]
    async fn the_update_sends_only_what_is_chosen() {
        let cases = [
            ((Some("u-1"), None, None), json!({ "ownerUuid": "u-1" })),
            (
                (Some("u-1"), Some("g-1"), Some("r-1")),
                json!({ "ownerUuid": "u-1", "groupUuids": ["g-1"], "raProfileUuid": "r-1" }),
            ),
            ((None, Some("g-1"), None), json!({ "groupUuids": ["g-1"] })),
            ((None, None, Some("r-1")), json!({ "raProfileUuid": "r-1" })),
        ];
        for ((owner, group, ra_profile), expected) in cases {
            let server = MockServer::start().await;
            Mock::given(method("PATCH"))
                .and(path("/api/v1/certificates/c-1"))
                .and(body_json(expected))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&server)
                .await;
            let ilm = IlmUrl::for_tests(&server.uri());
            let sent = update_request(&client_for_tests(), &ilm, "c-1", owner, group, ra_profile)
                .send()
                .await
                .unwrap();
            assert_eq!(read_update(sent).await, Ok(()));
        }
    }

    #[tokio::test]
    async fn the_update_answers_are_told_apart() {
        assert_eq!(update(ResponseTemplate::new(204)).await, Ok(()));
        assert_eq!(
            update(ResponseTemplate::new(403)).await.unwrap_err(),
            AddError::NotAllowed
        );
    }

    async fn groups(response: ResponseTemplate) -> Result<Option<Vec<GroupChoice>>, IlmError> {
        let (_server, ilm) = serve("GET", "/api/v1/groups", response).await;
        let sent = groups_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        read_groups(sent).await
    }

    async fn ra_profiles(
        response: ResponseTemplate,
    ) -> Result<Option<Vec<RaProfileChoice>>, IlmError> {
        let (_server, ilm) = serve("GET", "/api/v1/raProfiles", response).await;
        let sent = ra_profiles_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        read_ra_profiles(sent).await
    }

    #[tokio::test]
    async fn the_groups_are_read() {
        let body = json!([
            { "uuid": "g-1", "name": "Web", "description": "x", "customAttributes": [] },
            { "uuid": "g-2", "name": "Mail" }
        ]);
        let found = groups(ResponseTemplate::new(200).set_body_json(body))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            found,
            [
                GroupChoice {
                    uuid: "g-1".into(),
                    name: "Web".into()
                },
                GroupChoice {
                    uuid: "g-2".into(),
                    name: "Mail".into()
                },
            ]
        );
    }

    #[tokio::test]
    async fn only_enabled_ra_profiles_are_read_and_asked_for() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/raProfiles"))
            .and(query_param("enabled", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "uuid": "r-1", "name": "TLS", "enabled": true, "authorityInstanceName": "Corp CA", "authorityInstanceUuid": "a-1" },
                { "uuid": "r-2", "name": "Old", "enabled": false, "authorityInstanceName": "Corp CA" },
                { "uuid": "r-3", "name": "Bare", "enabled": true }
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let ilm = IlmUrl::for_tests(&server.uri());
        let sent = ra_profiles_request(&client_for_tests(), &ilm)
            .send()
            .await
            .unwrap();
        let found = read_ra_profiles(sent).await.unwrap().unwrap();
        assert_eq!(
            found,
            [
                RaProfileChoice {
                    uuid: "r-1".into(),
                    name: "TLS".into(),
                    authority: Some("Corp CA".into()),
                    authority_uuid: Some("a-1".into())
                },
                RaProfileChoice {
                    uuid: "r-3".into(),
                    name: "Bare".into(),
                    authority: None,
                    authority_uuid: None
                },
            ]
        );
    }

    #[tokio::test]
    async fn a_list_the_person_may_not_see_or_ilm_lacks_is_none() {
        for status in [403, 404] {
            assert_eq!(groups(ResponseTemplate::new(status)).await, Ok(None));
            assert_eq!(ra_profiles(ResponseTemplate::new(status)).await, Ok(None));
        }
    }

    #[tokio::test]
    async fn other_list_answers_are_errors() {
        assert_eq!(
            groups(ResponseTemplate::new(401)).await,
            Err(IlmError::Unauthorized)
        );
        assert_eq!(
            ra_profiles(ResponseTemplate::new(500)).await,
            Err(IlmError::Unexpected(500))
        );
        assert_eq!(
            ra_profiles(ResponseTemplate::new(200).set_body_string("{")).await,
            Err(IlmError::Malformed)
        );
    }
}
