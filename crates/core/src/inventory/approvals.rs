//! The approvals of certificate requests that wait for the person: what ILM says of each, kept with the snapshot,
//! and the decision the person takes.

use serde::{Deserialize, Serialize};

use super::{Failure, send};
use crate::ilm::approvals::{
    ApprovalAction, DescribeError, Described, Waiting, certificate_request, list_request,
    read_certificate, read_list,
};
use crate::ilm::profile::IlmError;
use crate::session::Session;

/// A request for a certificate that waits for the person's approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub uuid: String,
    pub action: ApprovalAction,
    /// None when ILM could not tell who asked.
    pub requester: Option<String>,
    /// Milliseconds since 1970 UTC.
    pub requested_at: i64,
    /// None when the person may not read the certificate.
    pub certificate_name: Option<String>,
    pub ra_profile: Option<String>,
}

impl Approval {
    fn new(waiting: Waiting, described: Described) -> Self {
        Self {
            uuid: waiting.uuid,
            action: waiting.action,
            requester: waiting.creator,
            requested_at: waiting.created_at,
            certificate_name: described.name,
            ra_profile: described.ra_profile,
        }
    }
}

/// Lets a failure that ends the check through; any other is logged and gives `T::default()`, so approvals ILM
/// cannot answer for do not fail the check.
fn lenient<T: Default>(result: Result<T, Failure>, what: &str) -> Result<T, Failure> {
    match result {
        Err(
            error @ (Failure::SignedOut
            | Failure::Unreachable
            | Failure::Ilm(IlmError::Unauthorized)),
        ) => Err(error),
        Err(error) => {
            log::warn!("{what}: {error}");
            Ok(T::default())
        }
        Ok(found) => Ok(found),
    }
}

async fn list(session: &Session) -> Result<Vec<Waiting>, Failure> {
    let response = send(session, list_request).await?;
    Ok(read_list(response).await?)
}

async fn describe(session: &Session, certificate: &str) -> Result<Described, Failure> {
    let response = send(session, |client, ilm| {
        certificate_request(client, ilm, certificate)
    })
    .await?;
    match read_certificate(response).await {
        Ok(described) => Ok(described),
        Err(DescribeError::Hidden) => Ok(Described::default()),
        Err(DescribeError::Failed(error)) => Err(error.into()),
    }
}

/// The approvals that wait for the person with the ILM uuid `person` and that someone else asked for, each with the name and RA Profile of its
/// certificate where the person may read it. A list ILM cannot give leaves none.
pub(super) async fn read(session: &Session, person: &str) -> Result<Vec<Approval>, Failure> {
    let listed = lenient(list(session).await, "the approvals are not available")?;
    let mut found = Vec::new();
    for waiting in listed
        .into_iter()
        .filter(|waiting| waiting.creator_uuid != person)
    {
        let described = lenient(
            describe(session, &waiting.certificate).await,
            "a certificate of an approval is not available",
        )?;
        found.push(Approval::new(waiting, described));
    }
    Ok(found)
}
