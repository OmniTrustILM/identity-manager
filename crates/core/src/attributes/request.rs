//! The request attributes ILM takes, built from definitions and the values a person gave.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Number, Value as Json, json};

use super::definition::{ContentType, Definition, Kind, Version};
use super::value::{Value, Values, parse_date, parse_datetime, parse_time};

/// The `RequestAttribute` of every attribute that has content. Read-only and hidden attributes are sent exactly as
/// defined, because ILM requires equality; the values given for them are not looked at. Empty optional values are
/// left out; a required one that is empty is for the check to refuse before this.
pub fn request(definitions: &[Definition], values: &Values) -> Vec<Json> {
    definitions
        .iter()
        .filter(|definition| definition.kind != Kind::Info)
        .filter_map(|definition| {
            let content = if definition.is_editable() {
                values
                    .get(&definition.name)
                    .map(|value| items(definition, value))
                    .unwrap_or_default()
            } else {
                definition.content.clone()
            };
            if content.is_empty() {
                return None;
            }
            let mut attribute = Map::new();
            if !definition.uuid.is_empty() {
                attribute.insert("uuid".into(), json!(definition.uuid));
            }
            attribute.insert("name".into(), json!(definition.name));
            attribute.insert("contentType".into(), json!(definition.content_type.code()));
            attribute.insert("version".into(), json!(definition.request_version().code()));
            attribute.insert("content".into(), Json::Array(content));
            Some(Json::Object(attribute))
        })
        .collect()
}

fn items(definition: &Definition, value: &Value) -> Vec<Json> {
    match value {
        Value::Option(key) => definition
            .option(key)
            .map(|item| chosen(definition, item))
            .into_iter()
            .collect(),
        Value::Options(list) => list
            .iter()
            .flat_map(|item| items(definition, item))
            .collect(),
        Value::Added(inner) => scalar_item(definition, inner).into_iter().collect(),
        scalar => scalar_item(definition, scalar).into_iter().collect(),
    }
}

/// A chosen option goes back as ILM gave it; a resource is cut down to what ILM reads of it.
fn chosen(definition: &Definition, item: &Json) -> Json {
    let mut item = item.clone();
    if definition.content_type == ContentType::Resource
        && let Some(object) = item.as_object_mut()
        && let Some(data) = object.get("data").and_then(Json::as_object)
    {
        let kept: Map<String, Json> = ["resource", "uuid", "name"]
            .iter()
            .filter_map(|key| Some((key.to_string(), data.get(*key)?.clone())))
            .collect();
        object.insert("data".into(), Json::Object(kept));
    }
    item
}

fn scalar_item(definition: &Definition, value: &Value) -> Option<Json> {
    if value.is_empty() {
        return None;
    }
    let data = match value {
        Value::Text(text) if definition.content_type == ContentType::Secret => {
            json!({ "secret": text })
        }
        Value::Text(text) => json!(text),
        Value::Integer(text) => json!(text.trim().parse::<i32>().ok()?),
        Value::Float(text) => Json::Number(Number::from_f64(text.trim().parse::<f64>().ok()?)?),
        Value::Bool(flag) => json!(flag),
        Value::Date(text) => json!(parse_date(text)?.to_string()),
        Value::Time(text) => json!(parse_time(text)?.strftime("%H:%M:%S").to_string()),
        Value::DateTime(text) => json!(parse_datetime(text)?.to_ilm()),
        Value::File(file) => json!({
            "content": file.content,
            "fileName": file.name,
            "mimeType": file.mime,
        }),
        Value::Code(code) => json!({
            "code": STANDARD.encode(code),
            "language": definition.language(),
        }),
        Value::Object(text) => json!(text),
        Value::Option(_) | Value::Options(_) | Value::Added(_) => return None,
    };
    let mut item = Map::new();
    item.insert("data".into(), data);
    if definition.request_version() == Version::V3 {
        item.insert("contentType".into(), json!(definition.content_type.code()));
    }
    Some(Json::Object(item))
}
