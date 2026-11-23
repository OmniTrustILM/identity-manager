//! ILM's attribute forms as pure functions: reading definitions, parsing and validating the values a person
//! typed, and building the request attributes ILM takes. Nothing here calls ILM or logs a value.

mod callback;
#[cfg(test)]
mod callback_tests;
mod definition;
#[cfg(test)]
mod fixtures;
mod request;
#[cfg(test)]
mod tests;
mod validate;
mod value;
mod view;

pub use callback::{FormContext, Resolution, cleared_with, resolve};
pub use definition::{
    Callback, Constraint, ContentType, Definition, Definitions, GroupAttribute, Kind, Mapping,
    Rule, Target, Unsupported, Version, option_key,
};
pub use request::request;
pub use validate::{MAX_FILE_BYTES, check};
pub use value::{FileValue, Value, ValueError, Values, default_of, defaults, fits, parse_values};
pub use view::{
    CallbackResult, CallbackView, ConstraintView, FieldKind, FieldProblem, FieldView, FormCheck,
    FormView, GroupView, OptionView, Problem, Stamp, Stamps, ValueKind, group_views,
    required_unsupported,
};
