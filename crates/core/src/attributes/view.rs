//! The form as the interface sees it: camelCase, nothing the interface could use to steer a call to ILM.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use serde_json::Value as Json;

use super::definition::{
    Callback, Constraint, ContentType, Definition, Definitions, GroupAttribute, Kind, Rule,
    option_key,
};
use super::value::{Value, default_of};

/// What is wrong with a field's value. A `message` is ILM's own text for the failed rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeProblem", rename_all = "camelCase")
)]
pub enum Problem {
    Required,
    NotInteger,
    NotNumber,
    Pattern {
        message: Option<String>,
    },
    Below {
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        min: i64,
        message: Option<String>,
    },
    Above {
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        max: i64,
        message: Option<String>,
    },
    /// Earlier than the first date-time allowed.
    Before {
        from: String,
    },
    /// Later than the last date-time allowed.
    After {
        to: String,
    },
    BadDate,
    BadTime,
    BadDateTime,
    BadJson,
    /// The file is not valid base64.
    BadFile,
    FileTooLarge {
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
        max: u64,
    },
    NotAnOption,
}

/// A problem and the field it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeFieldProblem")
)]
pub struct FieldProblem {
    pub name: String,
    pub problem: Problem,
}

/// The control of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeFieldKind", rename_all = "lowercase")
)]
pub enum FieldKind {
    Textline,
    Textarea,
    Secret,
    Integer,
    Float,
    Switch,
    Date,
    Time,
    Datetime,
    File,
    Code,
    Json,
    Select,
    Multiselect,
    Info,
}

/// The kind of value a person may add to an extensible list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeValueKind", rename_all = "camelCase")
)]
pub enum ValueKind {
    Text,
    Integer,
    Float,
    Date,
    Time,
    DateTime,
}

/// An option of a list, named by its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeOptionView")
)]
pub struct OptionView {
    pub key: String,
    pub label: String,
}

/// When the form last changed a field, by revision, and the value ILM last set, which stays whatever the options
/// become.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stamp {
    pub changed_at: u64,
    pub value_set_at: u64,
    pub reset_at: u64,
    pub value: Option<Value>,
}

/// The stamps of the fields of a form, by name.
pub type Stamps = HashMap<String, Stamp>;

/// A rule of the definition worth telling the person about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeConstraintView", rename_all = "camelCase")
)]
pub enum ConstraintView {
    Pattern {
        description: Option<String>,
    },
    Range {
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
        min: Option<i64>,
        #[cfg_attr(any(test, feature = "ts"), ts(type = "number | null"))]
        max: Option<i64>,
    },
    DateTime {
        from: Option<String>,
        to: Option<String>,
    },
}

/// When the interface asks the core to run the field's callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeCallbackView", rename_all = "camelCase")
)]
pub enum CallbackView {
    None,
    /// Once, when the form opens.
    OnOpen,
    /// When one of these fields changes.
    OnChange(Vec<String>),
}

/// One field of a form. A hidden field has no control, options, value or constraints.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeFieldView", rename_all = "camelCase")
)]
pub struct FieldView {
    pub name: String,
    pub label: String,
    pub description: Option<String>,
    pub kind: Option<FieldKind>,
    pub required: bool,
    pub read_only: bool,
    pub hidden: bool,
    pub extensible: bool,
    /// What an added value of an extensible list is; none when the list takes no added values of a kind this
    /// application can type.
    pub value_kind: Option<ValueKind>,
    pub options: Vec<OptionView>,
    /// What the field starts with; for an info field, its text.
    pub value: Option<Value>,
    /// The language of a code field.
    pub language: Option<String>,
    pub constraints: Vec<ConstraintView>,
    pub callback: CallbackView,
    /// The revision of the form at which the field's options, content or value last changed.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub changed_at: u64,
    /// The revision at which ILM last set or cleared the field's value; 0 when it never did.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub value_set_at: u64,
    /// The revision at which the field was last reset (cleared by what it depends on, or replaced by its group) or
    /// installed; 0 when it never was. Its own callback starts again when this grows.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub reset_at: u64,
}

/// The answer to the interface's request to run the callback of a field: the form as it is now, and, when ILM gave no
/// answer, the words for the person.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeCallbackResult")
)]
pub struct CallbackResult {
    /// The sequence number the interface gave.
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub seq: u64,
    pub field: String,
    pub form: FormView,
    pub problem: Option<String>,
}

/// The problems of a form's values, and the revision of the form they were checked against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeCheck")
)]
pub struct FormCheck {
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub revision: u64,
    pub problems: Vec<FieldProblem>,
}

/// The fields of one group; the ungrouped ones come first, without a title.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeGroupView")
)]
pub struct GroupView {
    pub title: Option<String>,
    pub fields: Vec<FieldView>,
}

/// A form the interface can show: everything it needs to draw it, as of one revision. Of two snapshots of a form, the
/// one with the higher revision is the newer.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[cfg_attr(
    any(test, feature = "ts"),
    derive(ts_rs::TS),
    ts(export, rename = "AttributeFormView")
)]
pub struct FormView {
    pub id: String,
    #[cfg_attr(any(test, feature = "ts"), ts(type = "number"))]
    pub revision: u64,
    pub groups: Vec<GroupView>,
    /// The labels of what keeps the form from being sent: the required attributes this application cannot show, and
    /// the required ones the person cannot fill that are left without content.
    pub unsupported: Vec<String>,
    /// Where ILM's web interface fills the form in.
    pub web: Option<String>,
}

/// The labels of the required attributes that cannot be shown.
pub fn required_unsupported(definitions: &Definitions) -> Vec<String> {
    definitions
        .unsupported
        .iter()
        .filter(|unsupported| unsupported.required)
        .map(|unsupported| unsupported.label.clone())
        .collect()
}

/// The groups of the form: the fields of the definitions by group, the ungrouped ones first and without a title, and
/// after each group attribute the fields its callback added, however deep. Groups follow the order in which they
/// first appear in the definitions.
pub fn group_views(
    definitions: &Definitions,
    added: &[(String, Definitions)],
    stamps: &Stamps,
) -> Vec<GroupView> {
    let mut groups: Vec<GroupView> = Vec::new();
    let titles = std::iter::once(None).chain(definitions.fields.iter().map(|d| d.group.as_ref()));
    for title in titles {
        if groups.iter().any(|group| group.title.as_ref() == title) {
            continue;
        }
        let fields: Vec<FieldView> = definitions
            .fields
            .iter()
            .filter(|definition| definition.group.as_ref() == title)
            .map(|definition| field_view(definition, stamp_of(stamps, &definition.name)))
            .collect();
        if !fields.is_empty() {
            groups.push(GroupView {
                title: title.cloned(),
                fields,
            });
        }
    }
    add_group_callbacks(&mut groups, definitions, stamps);
    let mut shown = HashSet::new();
    for group in &mut groups {
        group.fields = with_added(std::mem::take(&mut group.fields), added, stamps, &mut shown);
    }
    groups
}

fn stamp_of(stamps: &Stamps, name: &str) -> Stamp {
    stamps.get(name).cloned().unwrap_or_default()
}

/// The fields, each followed by what its callback added, again and again; a name shows once.
fn with_added(
    fields: Vec<FieldView>,
    added: &[(String, Definitions)],
    stamps: &Stamps,
    shown: &mut HashSet<String>,
) -> Vec<FieldView> {
    let mut all = Vec::new();
    for field in fields {
        if !shown.insert(field.name.clone()) {
            continue;
        }
        let more = added.iter().find(|(group, _)| *group == field.name);
        let owned = more
            .map(|(_, more)| views(more, stamps))
            .unwrap_or_default();
        all.push(field);
        all.extend(with_added(owned, added, stamps, shown));
    }
    all
}

/// The fields of these definitions, and the group attributes with a callback as hidden fields.
fn views(definitions: &Definitions, stamps: &Stamps) -> Vec<FieldView> {
    let mut fields: Vec<FieldView> = definitions
        .fields
        .iter()
        .map(|definition| field_view(definition, stamp_of(stamps, &definition.name)))
        .collect();
    fields.extend(group_callback_views(definitions, stamps));
    fields
}

/// A group attribute holds no value but its callback adds fields, so it is listed among the ungrouped fields.
fn add_group_callbacks(groups: &mut Vec<GroupView>, definitions: &Definitions, stamps: &Stamps) {
    let watchers = group_callback_views(definitions, stamps);
    if watchers.is_empty() {
        return;
    }
    match groups.iter_mut().find(|group| group.title.is_none()) {
        Some(ungrouped) => ungrouped.fields.extend(watchers),
        None => groups.insert(
            0,
            GroupView {
                title: None,
                fields: watchers,
            },
        ),
    }
}

fn group_callback_views(definitions: &Definitions, stamps: &Stamps) -> Vec<FieldView> {
    definitions
        .groups
        .iter()
        .filter_map(|group| group_callback_view(group, stamp_of(stamps, &group.name)))
        .collect()
}

fn group_callback_view(group: &GroupAttribute, stamp: Stamp) -> Option<FieldView> {
    let callback = group.callback.as_ref()?;
    Some(FieldView {
        name: group.name.clone(),
        label: group.name.clone(),
        description: None,
        kind: None,
        required: false,
        read_only: false,
        hidden: true,
        extensible: false,
        value_kind: None,
        options: Vec::new(),
        value: None,
        language: None,
        constraints: Vec::new(),
        callback: callback_view(callback),
        changed_at: stamp.changed_at,
        value_set_at: stamp.value_set_at,
        reset_at: stamp.reset_at,
    })
}

/// The options of a list, each key once.
fn option_views(definition: &Definition) -> Vec<OptionView> {
    let mut seen = HashSet::new();
    definition
        .content
        .iter()
        .filter(|item| seen.insert(option_key(item)))
        .map(|item| OptionView {
            key: option_key(item),
            label: option_label(item),
        })
        .collect()
}

fn field_view(definition: &Definition, stamp: Stamp) -> FieldView {
    let shown = definition.visible;
    let is_info = definition.kind == Kind::Info;
    let listed = shown && definition.is_list() && !definition.protected;
    FieldView {
        name: definition.name.clone(),
        label: definition.label.clone(),
        description: definition.description.clone(),
        kind: shown.then(|| kind_of(definition)),
        required: definition.required,
        read_only: definition.read_only,
        hidden: !shown,
        extensible: shown && definition.extensible,
        value_kind: (shown && definition.extensible && definition.is_list())
            .then(|| value_kind_of(definition.content_type))
            .flatten(),
        options: if listed {
            option_views(definition)
        } else {
            Vec::new()
        },
        value: match (shown, is_info) {
            (false, _) => None,
            (true, true) => Some(Value::Text(info_text(&definition.content))),
            (true, false) => start_value(definition, &stamp),
        },
        language: (shown && definition.content_type == ContentType::Codeblock)
            .then(|| definition.language().to_owned()),
        constraints: if shown {
            definition.constraints.iter().map(constraint_view).collect()
        } else {
            Vec::new()
        },
        callback: definition
            .callback
            .as_ref()
            .map_or(CallbackView::None, callback_view),
        changed_at: stamp.changed_at,
        value_set_at: stamp.value_set_at,
        reset_at: stamp.reset_at,
    }
}

/// What the field starts with: the value ILM last set, or the choice it cleared; before ILM set any, what its
/// content gives. Keys the options no longer offer are left out.
fn start_value(definition: &Definition, stamp: &Stamp) -> Option<Value> {
    if stamp.value_set_at == 0 {
        return default_of(definition);
    }
    let offered = definition.option_keys();
    let gone = |value: &Value| matches!(value, Value::Option(key) if !offered.contains(key));
    match stamp.value.clone()? {
        Value::Options(values) => Some(Value::Options(
            values.into_iter().filter(|value| !gone(value)).collect(),
        )),
        value if gone(&value) => None,
        value => Some(value),
    }
}

fn value_kind_of(content_type: ContentType) -> Option<ValueKind> {
    match content_type {
        ContentType::String | ContentType::Text => Some(ValueKind::Text),
        ContentType::Integer => Some(ValueKind::Integer),
        ContentType::Float => Some(ValueKind::Float),
        ContentType::Date => Some(ValueKind::Date),
        ContentType::Time => Some(ValueKind::Time),
        ContentType::DateTime => Some(ValueKind::DateTime),
        _ => None,
    }
}

fn kind_of(definition: &Definition) -> FieldKind {
    if definition.kind == Kind::Info {
        return FieldKind::Info;
    }
    if definition.is_list() {
        return if definition.multi_select {
            FieldKind::Multiselect
        } else {
            FieldKind::Select
        };
    }
    match definition.content_type {
        ContentType::String | ContentType::Text if definition.protected => FieldKind::Secret,
        ContentType::String => FieldKind::Textline,
        ContentType::Text => FieldKind::Textarea,
        ContentType::Secret => FieldKind::Secret,
        ContentType::Integer => FieldKind::Integer,
        ContentType::Float => FieldKind::Float,
        ContentType::Boolean => FieldKind::Switch,
        ContentType::Date => FieldKind::Date,
        ContentType::Time => FieldKind::Time,
        ContentType::DateTime => FieldKind::Datetime,
        ContentType::File => FieldKind::File,
        ContentType::Codeblock => FieldKind::Code,
        ContentType::Object => FieldKind::Json,
        ContentType::Credential | ContentType::Resource => FieldKind::Select,
    }
}

fn plain(data: &Json) -> String {
    match data {
        Json::String(text) => text.clone(),
        Json::Null => String::new(),
        other => other.to_string(),
    }
}

/// An option shows its reference, else its data; an object shows its name.
fn option_label(item: &Json) -> String {
    if let Some(reference) = item.get("reference").and_then(Json::as_str) {
        return reference.to_owned();
    }
    let data = item.get("data").unwrap_or(&Json::Null);
    match data.get("name").and_then(Json::as_str) {
        Some(name) => name.to_owned(),
        None => plain(data),
    }
}

fn info_text(content: &[Json]) -> String {
    content
        .iter()
        .map(|item| plain(item.get("data").unwrap_or(&Json::Null)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn constraint_view(constraint: &Constraint) -> ConstraintView {
    match &constraint.rule {
        Rule::Pattern(_) => ConstraintView::Pattern {
            description: constraint.description.clone(),
        },
        Rule::Range { from, to } => ConstraintView::Range {
            min: *from,
            max: *to,
        },
        Rule::DateTime { from, to } => ConstraintView::DateTime {
            from: from.clone(),
            to: to.clone(),
        },
    }
}

/// A legacy callback watches the fields its mappings read, the newer kind the fields it depends on.
fn callback_view(callback: &Callback) -> CallbackView {
    let watched: Vec<String> = match &callback.depends_on {
        Some(names) => names.clone(),
        None => callback
            .mappings
            .iter()
            .filter_map(|mapping| mapping.from.as_deref())
            .map(|from| from.split('.').next().unwrap_or(from).to_owned())
            .collect(),
    };
    if watched.is_empty() {
        CallbackView::OnOpen
    } else {
        CallbackView::OnChange(watched)
    }
}
