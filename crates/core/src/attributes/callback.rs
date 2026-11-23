//! Callbacks as ILM's administrator interface runs them: which request a field's callback makes, what is cleared
//! when a dependency goes, and how an answer changes the form. Nothing here calls ILM or logs.

use serde_json::{Map, Number, Value as Json};

use super::definition::{Callback, ContentType, Definition, Definitions, Mapping, Target};
use super::request::request;
use super::value::{Value, Values, defaults};
use crate::ilm::attributes::{CallbackBody, CallbackRoute};

/// Where a form came from, which decides the endpoint its callbacks go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormContext {
    /// The custom attributes of certificates. They have no callbacks.
    Custom,
    /// The attributes an RA Profile of an authority asks for when a certificate is issued.
    Issue {
        authority: String,
        ra_profile: String,
    },
}

impl FormContext {
    /// What the log calls it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Custom => "custom attributes",
            Self::Issue { .. } => "issue attributes",
        }
    }

    /// Issuance callbacks, legacy and newer, go through ILM Core by the RA Profile; ILM finds the authority and
    /// connector itself.
    fn route(&self) -> Option<CallbackRoute> {
        match self {
            Self::Custom => None,
            Self::Issue { ra_profile, .. } => Some(CallbackRoute::Resource {
                resource: "certificates".to_owned(),
                parent: ra_profile.clone(),
            }),
        }
    }
}

/// What a callback does for the values the form has now.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    Call(CallbackRoute, Box<CallbackBody>),
    /// A dependency has no value: the field loses its value and options.
    Cleared,
    /// Nothing to ask: no callback, a mapping that cannot be resolved, or a form without callbacks.
    Skip,
}

/// The callback of a field or a group attribute, with what its request carries.
struct Owner<'a> {
    uuid: &'a str,
    name: &'a str,
    callback: &'a Callback,
    content_type: Option<ContentType>,
}

fn owner<'a>(definitions: &'a Definitions, name: &str) -> Option<Owner<'a>> {
    let field = definitions
        .fields
        .iter()
        .find(|field| field.name == name)
        .and_then(|field| {
            Some(Owner {
                uuid: &field.uuid,
                name: &field.name,
                callback: field.callback.as_ref()?,
                content_type: Some(field.content_type),
            })
        });
    field.or_else(|| {
        let group = definitions.groups.iter().find(|group| group.name == name)?;
        Some(Owner {
            uuid: &group.uuid,
            name: &group.name,
            callback: group.callback.as_ref()?,
            content_type: None,
        })
    })
}

/// The fields a newer-kind callback depends on: it has no legacy context. Resource attributes are always answered
/// by ILM Core and take the legacy path.
fn depends_on(callback: &Callback, content_type: Option<ContentType>) -> Option<&[String]> {
    let names = callback.depends_on.as_deref()?;
    (callback.context.is_none() && content_type != Some(ContentType::Resource)).then_some(names)
}

/// What the callback of `name` does for `values`. A callback ILM could not make sense of, one in a context that
/// has no route, and one that cannot be fully resolved all skip: nothing is sent.
pub fn resolve(
    context: &FormContext,
    definitions: &Definitions,
    name: &str,
    values: &Values,
) -> Resolution {
    let (Some(owner), Some(route)) = (owner(definitions, name), context.route()) else {
        return Resolution::Skip;
    };
    let mut body = CallbackBody {
        uuid: owner.uuid.to_owned(),
        name: owner.name.to_owned(),
        ..CallbackBody::default()
    };
    match depends_on(owner.callback, owner.content_type) {
        Some(names) => {
            let Some(dependencies) = names
                .iter()
                .map(|name| definitions.fields.iter().find(|field| &field.name == name))
                .collect::<Option<Vec<_>>>()
            else {
                return Resolution::Skip;
            };
            let dependencies: Vec<Definition> = dependencies.into_iter().cloned().collect();
            let attributes = request(&dependencies, values);
            let given = |name: &String| {
                attributes
                    .iter()
                    .any(|attribute| attribute.get("name").and_then(Json::as_str) == Some(name))
            };
            if !names.iter().all(given) {
                return Resolution::Cleared;
            }
            body.attributes = attributes;
        }
        None => {
            if owner.callback.context.is_none() && owner.content_type != Some(ContentType::Resource)
            {
                return Resolution::Skip;
            }
            for mapping in &owner.callback.mappings {
                let Some(value) = mapped(definitions, values, mapping) else {
                    return Resolution::Skip;
                };
                for target in &mapping.targets {
                    place(&mut body, *target, &mapping.to, value.clone());
                }
            }
        }
    }
    Resolution::Call(route, Box::new(body))
}

fn place(body: &mut CallbackBody, target: Target, to: &str, value: Json) {
    let map = match target {
        Target::PathVariable => &mut body.path_variable,
        Target::RequestParameter => &mut body.request_parameter,
        Target::Body => &mut body.body,
        Target::Filter => &mut body.filter,
    };
    map.insert(to.to_owned(), value);
}

/// What a JavaScript `if` calls true.
fn truthy(value: &Json) -> bool {
    match value {
        Json::Null => false,
        Json::Bool(flag) => *flag,
        Json::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Json::String(text) => !text.is_empty(),
        Json::Array(_) | Json::Object(_) => true,
    }
}

/// A static value counts only when it is truthy; otherwise the field `from` names gives the value.
fn mapped(definitions: &Definitions, values: &Values, mapping: &Mapping) -> Option<Json> {
    if let Some(value) = mapping.value.as_ref().filter(|value| truthy(value)) {
        return Some(value.clone());
    }
    from_value(definitions, values, mapping.from.as_deref()?)
}

/// `from` is a field name, or a field name and a path into its value.
fn from_value(definitions: &Definitions, values: &Values, from: &str) -> Option<Json> {
    let mut segments = from.split('.');
    let head = segments.next().unwrap_or_default();
    let field = definitions.fields.iter().find(|field| field.name == head)?;
    let path: Vec<&str> = segments.collect();
    let raw = form_value(field, values)?;
    let raw = first(&raw);
    if !path.is_empty() {
        let under_data = raw.get("data");
        for start in [Some(raw), under_data] {
            if let Some(found) = start.and_then(|start| walk(start, &path))
                && is_primitive(found)
            {
                return Some(found.clone());
            }
        }
    }
    unwrap_object(raw)
}

fn first(value: &Json) -> &Json {
    match value {
        Json::Array(items) => items.first().unwrap_or(value),
        other => other,
    }
}

fn walk<'a>(start: &'a Json, path: &[&str]) -> Option<&'a Json> {
    path.iter()
        .try_fold(start, |current, key| first(current).get(key))
}

fn is_primitive(value: &Json) -> bool {
    matches!(value, Json::String(_) | Json::Number(_) | Json::Bool(_))
}

/// An object gives its `data`, and that object, if it names a `uuid`, the uuid.
fn unwrap_object(value: &Json) -> Option<Json> {
    let inner = match value {
        Json::Object(object) => object
            .get("data")
            .filter(|data| !data.is_null())
            .unwrap_or(value),
        Json::Null => return None,
        other => return Some(other.clone()),
    };
    match inner.get("uuid") {
        Some(Json::String(uuid)) => Some(Json::String(uuid.clone())),
        _ => Some(inner.clone()),
    }
}

/// The value a field has: what the person gave, or for a field they do not edit, what ILM defined.
fn form_value(field: &Definition, values: &Values) -> Option<Json> {
    let value = if field.is_editable() {
        values.get(&field.name).cloned()
    } else {
        defaults(std::slice::from_ref(field)).remove(&field.name)
    }?;
    json_of(field, &value)
}

fn json_of(field: &Definition, value: &Value) -> Option<Json> {
    if value.is_empty() {
        return None;
    }
    Some(match value {
        Value::Text(text)
        | Value::Date(text)
        | Value::Time(text)
        | Value::DateTime(text)
        | Value::Code(text) => Json::String(text.clone()),
        Value::Integer(text) => Json::from(text.trim().parse::<i32>().ok()?),
        Value::Float(text) => Json::Number(Number::from_f64(text.trim().parse().ok()?)?),
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Object(text) => serde_json::from_str(text).ok()?,
        Value::File(file) => {
            let mut object = Map::new();
            object.insert("fileName".into(), file.name.clone().into());
            object.insert("mimeType".into(), file.mime.clone().into());
            object.insert("content".into(), file.content.clone().into());
            Json::Object(object)
        }
        Value::Option(key) => field.option(key)?.clone(),
        Value::Options(items) => Json::Array(
            items
                .iter()
                .filter_map(|item| json_of(field, item))
                .collect(),
        ),
        Value::Added(inner) => json_of(field, inner)?,
    })
}

/// The fields `name` loses when it has no value any more: itself, and every field whose newer-kind callback
/// depends on a field that is lost, again and again.
pub fn cleared_with(definitions: &Definitions, name: &str) -> Vec<String> {
    let fields = definitions.fields.iter().filter_map(|field| {
        let names = depends_on(field.callback.as_ref()?, Some(field.content_type))?;
        Some((field.name.as_str(), names))
    });
    let groups = definitions.groups.iter().filter_map(|group| {
        let names = depends_on(group.callback.as_ref()?, None)?;
        Some((group.name.as_str(), names))
    });
    let watchers: Vec<(&str, &[String])> = fields.chain(groups).collect();
    let mut lost = vec![name.to_owned()];
    let mut index = 0;
    while let Some(current) = lost.get(index).cloned() {
        for (watcher, names) in &watchers {
            if names.contains(&current) && !lost.iter().any(|known| known == watcher) {
                lost.push((*watcher).to_owned());
            }
        }
        index += 1;
    }
    lost
}
