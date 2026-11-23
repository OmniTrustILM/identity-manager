//! Checks the values of a form the way ILM's administrator interface does, plus the constraints ILM's server applies.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jiff::civil::DateTime;
use jiff::tz::TimeZone;
use regex::Regex;
use serde_json::Value as Json;

use super::definition::{ContentType, Definition, Rule};
use super::value::{Value, Values, fits, parse_date, parse_datetime, parse_time};
use super::view::{FieldProblem, Problem};

/// The largest file a form takes, in bytes.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;

/// The first problem of every field the person fills in, in the order of the definitions. Read-only, hidden and
/// info attributes are sent as defined and not checked. `zone` is the computer's, in which date-time bounds read.
pub fn check(definitions: &[Definition], values: &Values, zone: &TimeZone) -> Vec<FieldProblem> {
    definitions
        .iter()
        .filter(|definition| definition.is_editable())
        .filter_map(|definition| {
            let problem = problem_of(definition, values.get(&definition.name), zone)?;
            Some(FieldProblem {
                name: definition.name.clone(),
                problem,
            })
        })
        .collect()
}

fn problem_of(definition: &Definition, value: Option<&Value>, zone: &TimeZone) -> Option<Problem> {
    match value.filter(|value| !value.is_empty()) {
        None => definition.required.then_some(Problem::Required),
        Some(value) if !fits(definition, value) => Some(Problem::NotAnOption),
        Some(value) => problem_of_value(definition, value, zone),
    }
}

fn problem_of_value(definition: &Definition, value: &Value, zone: &TimeZone) -> Option<Problem> {
    match value {
        Value::Option(key) => definition
            .option(key)
            .is_none()
            .then_some(Problem::NotAnOption),
        Value::Options(items) => items
            .iter()
            .find_map(|item| problem_of_value(definition, item, zone)),
        Value::Added(inner) => scalar_problem(definition, inner, zone),
        scalar => scalar_problem(definition, scalar, zone),
    }
}

fn scalar_problem(definition: &Definition, value: &Value, zone: &TimeZone) -> Option<Problem> {
    match value {
        Value::Text(text) => pattern_problem(definition, text),
        Value::Integer(text) => match text.trim().parse::<i32>() {
            Ok(number) => range_problem(definition, f64::from(number)),
            Err(_) => Some(Problem::NotInteger),
        },
        Value::Float(text) => match text.trim().parse::<f64>() {
            Ok(number) if number.is_finite() => range_problem(definition, number),
            _ => Some(Problem::NotNumber),
        },
        Value::Date(text) => parse_date(text).is_none().then_some(Problem::BadDate),
        Value::Time(text) => parse_time(text).is_none().then_some(Problem::BadTime),
        Value::DateTime(text) => match parse_datetime(text) {
            Some(moment) => datetime_problem(definition, moment.local(zone)),
            None => Some(Problem::BadDateTime),
        },
        Value::Object(text) => serde_json::from_str::<Json>(text)
            .is_err()
            .then_some(Problem::BadJson),
        Value::File(file) => match STANDARD.decode(&file.content) {
            Ok(bytes) if bytes.len() > MAX_FILE_BYTES => Some(Problem::FileTooLarge {
                max: MAX_FILE_BYTES as u64,
            }),
            Ok(_) => None,
            Err(_) => Some(Problem::BadFile),
        },
        Value::Bool(_)
        | Value::Code(_)
        | Value::Option(_)
        | Value::Options(_)
        | Value::Added(_) => None,
    }
}

/// A pattern must match the whole value. One Rust cannot compile (look-around, back-references) is left to ILM.
fn pattern_problem(definition: &Definition, text: &str) -> Option<Problem> {
    if definition.content_type != ContentType::String {
        return None;
    }
    definition.constraints.iter().find_map(|constraint| {
        let Rule::Pattern(pattern) = &constraint.rule else {
            return None;
        };
        let compiled = Regex::new(&format!(r"\A(?:{pattern})\z")).ok()?;
        (!compiled.is_match(text)).then(|| Problem::Pattern {
            message: constraint.message.clone(),
        })
    })
}

fn range_problem(definition: &Definition, number: f64) -> Option<Problem> {
    if !matches!(
        definition.content_type,
        ContentType::Integer | ContentType::Float
    ) {
        return None;
    }
    definition.constraints.iter().find_map(|constraint| {
        let Rule::Range { from, to } = &constraint.rule else {
            return None;
        };
        let message = constraint.message.clone();
        match (from, to) {
            (Some(min), _) if number < *min as f64 => Some(Problem::Below { min: *min, message }),
            (_, Some(max)) if number > *max as f64 => Some(Problem::Above { max: *max, message }),
            _ => None,
        }
    })
}

fn bound(text: &Option<String>) -> Option<(&str, DateTime)> {
    let text = text.as_deref()?;
    Some((text, parse_datetime(text)?.wall_clock))
}

/// The bounds name no zone: they are the calendar fields the computer shows, so `key` is the value as the computer
/// shows it.
fn datetime_problem(definition: &Definition, key: DateTime) -> Option<Problem> {
    if definition.content_type != ContentType::DateTime {
        return None;
    }
    definition.constraints.iter().find_map(|constraint| {
        let Rule::DateTime { from, to } = &constraint.rule else {
            return None;
        };
        if let Some((from, limit)) = bound(from)
            && key < limit
        {
            return Some(Problem::Before {
                from: from.to_owned(),
            });
        }
        if let Some((to, limit)) = bound(to)
            && key > limit
        {
            return Some(Problem::After { to: to.to_owned() });
        }
        None
    })
}
