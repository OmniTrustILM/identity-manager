//! Whether a form can be sent with only the values ILM's definitions give, so nobody has to fill it in.

use jiff::tz::TimeZone;

use super::definition::{ContentType, Definitions};
use super::validate::check;
use super::value::{Values, defaults};
use super::view::Problem;

/// Why a form needs the person. For the log only; it names no value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// A required attribute cannot be shown here.
    Blocked,
    /// A field or group is filled by asking ILM.
    Callback,
    /// A secret, credential or resource is required, and only the person can choose it.
    Secret,
    /// A required value has no default.
    Required,
    /// A default breaks a constraint.
    Invalid,
    /// The request form gives no usable subject.
    Subject,
    /// The form is no longer open.
    Gone,
}

impl Needs {
    /// A short word for the log.
    pub fn code(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Callback => "callback",
            Self::Secret => "secret",
            Self::Required => "required",
            Self::Invalid => "invalid",
            Self::Subject => "subject",
            Self::Gone => "gone",
        }
    }
}

/// The values ILM's definitions give, when the form needs nothing more from the person.
pub fn unattended(definitions: &Definitions) -> Result<Values, Needs> {
    if definitions.blocked() {
        return Err(Needs::Blocked);
    }
    let editable = definitions
        .fields
        .iter()
        .filter(|field| field.is_editable());
    if definitions
        .groups
        .iter()
        .any(|group| group.callback.is_some())
        || editable.clone().any(|field| field.callback.is_some())
    {
        return Err(Needs::Callback);
    }
    let chosen = |content_type| {
        matches!(
            content_type,
            ContentType::Secret | ContentType::Credential | ContentType::Resource
        )
    };
    if editable
        .clone()
        .any(|field| field.required && chosen(field.content_type))
    {
        return Err(Needs::Secret);
    }
    if editable.clone().any(|field| {
        field.required
            && field.content_type == ContentType::Boolean
            && field
                .content
                .first()
                .and_then(|item| item.get("data"))
                .and_then(serde_json::Value::as_bool)
                .is_none()
    }) {
        return Err(Needs::Required);
    }
    let values = defaults(&definitions.fields);
    let problems = check(&definitions.fields, &values, &TimeZone::system());
    match problems.first() {
        None => Ok(values),
        Some(first) if first.problem == Problem::Required => Err(Needs::Required),
        Some(_) => Err(Needs::Invalid),
    }
}
