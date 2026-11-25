//! The command that decides a request for a certificate waiting for the person's approval. It refuses while the
//! application is locked and while nobody is signed in. The comment goes to ILM and nowhere else.

use im_core::ilm::approvals::{DecideError, Decision};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};

use crate::certificates::ilm;

/// What the person decides, as the interface names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS), ts(export, rename_all = "camelCase"))]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

impl From<ApprovalDecision> for Decision {
    fn from(decision: ApprovalDecision) -> Self {
        match decision {
            ApprovalDecision::Approve => Self::Approve,
            ApprovalDecision::Reject => Self::Reject,
        }
    }
}

/// Why a decision was not taken.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(
    test,
    derive(ts_rs::TS),
    ts(
        export,
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
pub enum ApprovalFailure {
    /// The words for the person.
    Message { message: String },
    /// The request is decided, expired or not for the person any more.
    NoLongerWaiting,
    /// ILM's messages, to show as they are.
    Refused { messages: Vec<String> },
}

impl From<String> for ApprovalFailure {
    fn from(message: String) -> Self {
        Self::Message { message }
    }
}

impl From<DecideError> for ApprovalFailure {
    fn from(error: DecideError) -> Self {
        match error {
            DecideError::NoLongerWaiting => Self::NoLongerWaiting,
            DecideError::Refused(messages) if !messages.is_empty() => Self::Refused { messages },
            other => other.to_string().into(),
        }
    }
}

/// The comment ILM keeps with the decision; none when the person wrote none.
fn comment_of(comment: Option<String>) -> Option<String> {
    comment.filter(|text| !text.trim().is_empty())
}

/// Approves or rejects the request `uuid` as a recipient of its approval.
#[tauri::command]
pub async fn decide_approval<R: Runtime>(
    app: AppHandle<R>,
    uuid: String,
    decision: ApprovalDecision,
    comment: Option<String>,
) -> Result<(), ApprovalFailure> {
    let ilm = ilm(&app);
    ilm.unlocked()?;
    crate::request::signed_in(ilm.session().signed_in_as())?;
    let comment = comment_of(comment);
    let decided = ilm
        .working(ilm.decide(&uuid, decision.into(), comment.as_deref()))
        .await;
    ilm.unlocked()?;
    Ok(decided?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use im_core::ilm::profile::IlmError;

    #[test]
    fn ilms_answers_become_what_the_interface_can_show() {
        assert_eq!(
            ApprovalFailure::from(DecideError::NoLongerWaiting),
            ApprovalFailure::NoLongerWaiting
        );
        assert_eq!(
            ApprovalFailure::from(DecideError::Refused(vec!["Already decided.".to_owned()])),
            ApprovalFailure::Refused {
                messages: vec!["Already decided.".to_owned()]
            }
        );
        assert_eq!(
            ApprovalFailure::from(DecideError::Refused(Vec::new())),
            ApprovalFailure::from("ILM did not accept the decision.".to_owned())
        );
        assert_eq!(
            ApprovalFailure::from(DecideError::NotAllowed),
            ApprovalFailure::from("ILM does not allow this.".to_owned())
        );
        assert_eq!(
            ApprovalFailure::from(DecideError::Failed(IlmError::Unreachable)),
            ApprovalFailure::from("ILM cannot be reached.".to_owned())
        );
    }

    #[test]
    fn the_failures_are_told_by_kind() {
        assert_eq!(
            serde_json::to_value(ApprovalFailure::NoLongerWaiting).unwrap(),
            serde_json::json!({ "kind": "noLongerWaiting" })
        );
        assert_eq!(
            serde_json::to_value(ApprovalFailure::Refused {
                messages: vec!["No.".to_owned()]
            })
            .unwrap(),
            serde_json::json!({ "kind": "refused", "messages": ["No."] })
        );
    }

    #[test]
    fn a_blank_comment_is_not_sent() {
        assert_eq!(comment_of(None), None);
        assert_eq!(comment_of(Some("  ".to_owned())), None);
        assert_eq!(
            comment_of(Some(" Fine. ".to_owned())),
            Some(" Fine. ".to_owned())
        );
    }

    #[test]
    fn the_decision_is_named_as_the_interface_writes_it() {
        let approve: ApprovalDecision = serde_json::from_str("\"approve\"").unwrap();
        assert_eq!(Decision::from(approve), Decision::Approve);
        let reject: ApprovalDecision = serde_json::from_str("\"reject\"").unwrap();
        assert_eq!(Decision::from(reject), Decision::Reject);
    }
}
