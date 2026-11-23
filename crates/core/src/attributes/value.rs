//! The values of a form: what the interface sends, how they are told apart from the definition, and the defaults.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jiff::civil::{Date, DateTime, Time};
use jiff::fmt::temporal::{Pieces, PiecesOffset};
use jiff::tz::{Offset, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use super::definition::{ContentType, Definition, Kind};

/// A file the person chose; the content is base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeFile", rename_all = "camelCase")
)]
pub struct FileValue {
    pub name: String,
    pub mime: String,
    pub content: String,
}

/// The value of one field as the person typed or chose it. Numbers, dates and objects stay as typed so a wrong
/// entry is a problem of its field, not a refusal of the whole form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeValue")
)]
pub enum Value {
    /// String, text and secret.
    Text(String),
    Integer(String),
    Float(String),
    Bool(bool),
    /// `yyyy-MM-dd`.
    Date(String),
    /// `HH:mm` or `HH:mm:ss`.
    Time(String),
    /// ISO date and time, with or without an offset.
    DateTime(String),
    File(FileValue),
    /// The code as text.
    Code(String),
    /// JSON as typed.
    Object(String),
    /// The option with this key among the definition's options.
    Option(String),
    /// Options and added values of a multi-select.
    Options(Vec<Value>),
    /// A value added to an extensible list.
    Added(Box<Value>),
}

/// The values of a form by attribute name.
pub type Values = HashMap<String, Value>;

/// Why values from the interface were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueError {
    /// Not an object of values.
    Malformed,
    /// The value of this attribute is not of the kind its definition asks for.
    Mismatch(String),
}

impl Value {
    /// Nothing was entered.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(text)
            | Self::Integer(text)
            | Self::Float(text)
            | Self::Date(text)
            | Self::Time(text)
            | Self::DateTime(text)
            | Self::Object(text) => text.trim().is_empty(),
            Self::Code(code) => code.is_empty(),
            Self::File(file) => file.content.is_empty(),
            Self::Options(items) => items.iter().all(Self::is_empty),
            Self::Added(inner) => inner.is_empty(),
            Self::Bool(_) | Self::Option(_) => false,
        }
    }
}

fn scalar_fits(content_type: ContentType, value: &Value) -> bool {
    use ContentType as C;
    matches!(
        (content_type, value),
        (C::String | C::Text | C::Secret, Value::Text(_))
            | (C::Integer, Value::Integer(_))
            | (C::Float, Value::Float(_))
            | (C::Boolean, Value::Bool(_))
            | (C::Date, Value::Date(_))
            | (C::Time, Value::Time(_))
            | (C::DateTime, Value::DateTime(_))
            | (C::File, Value::File(_))
            | (C::Codeblock, Value::Code(_))
            | (C::Object, Value::Object(_))
    )
}

fn added_fits(definition: &Definition, value: &Value) -> bool {
    definition.extensible && scalar_fits(definition.content_type, value)
}

/// Whether the value is of the kind the definition asks for.
pub fn fits(definition: &Definition, value: &Value) -> bool {
    if !definition.is_list() {
        return scalar_fits(definition.content_type, value);
    }
    match value {
        Value::Option(_) => !definition.multi_select,
        Value::Added(inner) => !definition.multi_select && added_fits(definition, inner),
        Value::Options(items) => {
            definition.multi_select
                && items.iter().all(|item| match item {
                    Value::Option(_) => true,
                    Value::Added(inner) => added_fits(definition, inner),
                    _ => false,
                })
        }
        _ => false,
    }
}

/// Reads the values the interface sent (an object of values tagged by kind) against the definitions, and refuses a
/// value of the wrong kind. Values for names without a definition, and for read-only, hidden and info attributes,
/// are dropped: those are sent as defined.
pub fn parse_values(definitions: &[Definition], sent: &Json) -> Result<Values, ValueError> {
    let object = sent.as_object().ok_or(ValueError::Malformed)?;
    let mut values = Values::new();
    for definition in definitions
        .iter()
        .filter(|definition| definition.is_editable())
    {
        let Some(raw) = object.get(&definition.name) else {
            continue;
        };
        let mismatch = || ValueError::Mismatch(definition.name.clone());
        let value: Value = serde_json::from_value(raw.clone()).map_err(|_| mismatch())?;
        if !fits(definition, &value) {
            return Err(mismatch());
        }
        values.insert(definition.name.clone(), value);
    }
    Ok(values)
}

fn text_of(data: &Json) -> Option<String> {
    match data {
        Json::String(text) => Some(text.clone()),
        Json::Number(number) => Some(number.to_string()),
        Json::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

pub(super) fn default_of_item(definition: &Definition, item: &Json) -> Option<Value> {
    let data = item.get("data")?;
    let reference = item.get("reference").and_then(Json::as_str);
    Some(match definition.content_type {
        ContentType::String | ContentType::Text => {
            Value::Text(text_of(data).or_else(|| reference.map(str::to_owned))?)
        }
        ContentType::Integer => Value::Integer(text_of(data)?),
        ContentType::Float => Value::Float(text_of(data)?),
        ContentType::Boolean => Value::Bool(data.as_bool()?),
        ContentType::Date => Value::Date(text_of(data)?),
        ContentType::Time => Value::Time(text_of(data)?),
        ContentType::DateTime => Value::DateTime(text_of(data)?),
        ContentType::File => Value::File(FileValue {
            content: data
                .get("content")
                .and_then(Json::as_str)
                .or(reference)?
                .to_owned(),
            name: data.get("fileName")?.as_str()?.to_owned(),
            mime: data.get("mimeType")?.as_str()?.to_owned(),
        }),
        ContentType::Codeblock => {
            let bytes = STANDARD.decode(data.get("code")?.as_str()?).ok()?;
            Value::Code(String::from_utf8(bytes).ok()?)
        }
        ContentType::Object => Value::Object(match data {
            Json::String(text) => text.clone(),
            other => other.to_string(),
        }),
        ContentType::Secret | ContentType::Credential | ContentType::Resource => return None,
    })
}

/// What ILM's content gives a field to start with: for a list, the choice ILM makes (the one option of a required
/// list, everything a read-only list shows); otherwise the first item's data. A string a callback answered takes the
/// item's reference first.
pub fn default_of(definition: &Definition) -> Option<Value> {
    if definition.protected {
        return None;
    }
    if definition.is_list() {
        let mut keys = definition.option_keys();
        return match keys.len() {
            0 => None,
            _ if definition.read_only && definition.multi_select => Some(Value::Options(
                keys.into_iter().map(Value::Option).collect(),
            )),
            count
                if definition.read_only
                    || (definition.required && count == 1 && !definition.multi_select) =>
            {
                Some(Value::Option(keys.swap_remove(0)))
            }
            _ => None,
        };
    }
    let first = definition.content.first();
    let reference = first
        .and_then(|item| item.get("reference"))
        .and_then(Json::as_str);
    let value = match (definition.content_type, reference) {
        (ContentType::String | ContentType::Text, Some(reference)) if definition.answered => {
            Some(Value::Text(reference.to_owned()))
        }
        _ => first.and_then(|item| default_of_item(definition, item)),
    };
    match (value, definition.content_type) {
        (None, ContentType::Boolean) if definition.required => Some(Value::Bool(false)),
        (value, _) => value,
    }
}

/// The values a form starts with. Secrets are never filled in; a list starts with nothing chosen unless its single
/// option is required, or the field is read-only and shows what ILM defines.
pub fn defaults(definitions: &[Definition]) -> Values {
    definitions
        .iter()
        .filter(|definition| definition.kind != Kind::Info)
        .filter_map(|definition| Some((definition.name.clone(), default_of(definition)?)))
        .collect()
}

/// A date and time of day as written, with the offset when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Moment {
    pub(super) wall_clock: DateTime,
    offset: Option<Offset>,
}

impl Moment {
    /// The calendar fields as `zone` shows them: a value with an offset is converted, one without is as written.
    pub(super) fn local(self, zone: &TimeZone) -> DateTime {
        match self
            .offset
            .map(|offset| offset.to_timestamp(self.wall_clock))
        {
            Some(Ok(timestamp)) => timestamp.to_zoned(zone.clone()).datetime(),
            Some(Err(_)) | None => self.wall_clock,
        }
    }

    /// ILM's text for it: UTC when the offset is known, else the local time as written.
    pub(super) fn to_ilm(self) -> String {
        const LOCAL: &str = "%Y-%m-%dT%H:%M:%S%.3f";
        match self
            .offset
            .map(|offset| offset.to_timestamp(self.wall_clock))
        {
            Some(Ok(timestamp)) => timestamp.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            Some(Err(_)) | None => self.wall_clock.strftime(LOCAL).to_string(),
        }
    }
}

/// `yyyy-MM-dd`, a real date.
pub(super) fn parse_date(text: &str) -> Option<Date> {
    text.parse().ok()
}

/// `HH:mm` or `HH:mm:ss`.
pub(super) fn parse_time(text: &str) -> Option<Time> {
    if text.contains('.') {
        return None;
    }
    text.parse().ok()
}

/// ISO date and time, optionally with `Z` or `±HH:mm`.
pub(super) fn parse_datetime(text: &str) -> Option<Moment> {
    if text.as_bytes().get(10) != Some(&b'T') {
        return None;
    }
    let pieces = Pieces::parse(text).ok()?;
    let offset = match pieces.offset() {
        None => None,
        Some(PiecesOffset::Zulu) => Some(Offset::UTC),
        Some(PiecesOffset::Numeric(numeric)) if numeric.offset().seconds().abs() < 86_400 => {
            Some(numeric.offset())
        }
        Some(_) => return None,
    };
    Some(Moment {
        wall_clock: DateTime::from_parts(pieces.date(), pieces.time()?),
        offset,
    })
}
