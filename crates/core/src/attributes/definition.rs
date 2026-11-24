//! One model over ILM's version 2 and version 3 attribute definitions.

use serde_json::{Map, Value as Json, json};
use sha2::{Digest, Sha256};

/// What an attribute is, for the attributes a form can show. Group and meta attributes are not fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Data,
    Info,
    Custom,
}

/// The content types ILM's administrator interface renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    String,
    Text,
    Integer,
    Float,
    Boolean,
    Date,
    Time,
    DateTime,
    Secret,
    File,
    Codeblock,
    Object,
    Credential,
    Resource,
}

impl ContentType {
    pub fn code(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Text => "text",
            Self::Integer => "integer",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Date => "date",
            Self::Time => "time",
            Self::DateTime => "datetime",
            Self::Secret => "secret",
            Self::File => "file",
            Self::Codeblock => "codeblock",
            Self::Object => "object",
            Self::Credential => "credential",
            Self::Resource => "resource",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "string" => Self::String,
            "text" => Self::Text,
            "integer" => Self::Integer,
            "float" => Self::Float,
            "boolean" => Self::Boolean,
            "date" => Self::Date,
            "time" => Self::Time,
            "datetime" => Self::DateTime,
            "secret" => Self::Secret,
            "file" => Self::File,
            "codeblock" => Self::Codeblock,
            "object" => Self::Object,
            "credential" => Self::Credential,
            "resource" => Self::Resource,
            _ => return None,
        })
    }
}

/// The schema version of a definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V2,
    V3,
}

impl Version {
    /// The code a request attribute carries.
    pub fn code(self) -> &'static str {
        match self {
            Self::V2 => "v2",
            Self::V3 => "v3",
        }
    }
}

/// Where a callback puts a mapped value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    PathVariable,
    RequestParameter,
    Body,
    Filter,
}

/// One value a legacy callback sends: a static `value`, or the field `from` names, placed under `to`.
#[derive(Debug, Clone, PartialEq)]
pub struct Mapping {
    pub from: Option<String>,
    pub to: String,
    pub targets: Vec<Target>,
    pub value: Option<Json>,
}

/// The callback of an attribute. A `depends_on` list, even an empty one, marks the newer kind; the legacy kind names
/// a `context` and its mappings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Callback {
    pub context: Option<String>,
    pub method: Option<String>,
    pub mappings: Vec<Mapping>,
    pub depends_on: Option<Vec<String>>,
}

/// A check ILM applies to a value.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// The whole string matches.
    Pattern(String),
    /// Inclusive bounds; either may be open.
    Range { from: Option<i64>, to: Option<i64> },
    /// Bounds as local date-times (`yyyy-MM-ddTHH:mm:ss`); either may be open.
    DateTime {
        from: Option<String>,
        to: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Constraint {
    pub description: Option<String>,
    /// The text ILM's interface shows when the rule fails.
    pub message: Option<String>,
    pub rule: Rule,
}

/// A place in the certificate a request attribute's value goes to. The codes are ILM's, as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedField {
    /// A name of the subject: a short code such as `CN`, or a dotted OID.
    Rdn { rdn: String, order: Option<u32> },
    /// A name of the subject alternative name, with the OID of an `otherName`.
    San {
        general_name: String,
        other_name_oid: Option<String>,
        /// How the value of an `otherName` is encoded; none when ILM does not say.
        other_name_encoding: Option<String>,
        order: Option<u32>,
    },
    /// An extension, a key usage or anything this application does not know.
    Other,
}

/// An attribute a form can show.
#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    pub uuid: String,
    pub name: String,
    pub description: Option<String>,
    pub kind: Kind,
    pub version: Version,
    pub content_type: ContentType,
    pub label: String,
    pub visible: bool,
    pub group: Option<String>,
    pub required: bool,
    pub read_only: bool,
    pub list: bool,
    pub multi_select: bool,
    pub extensible: bool,
    /// Encrypted by ILM, or a secret.
    pub protected: bool,
    pub resource: Option<String>,
    /// Defaults, or the options of a list, as ILM sent the items.
    pub content: Vec<Json>,
    pub constraints: Vec<Constraint>,
    pub callback: Option<Callback>,
    /// A callback of ILM gave the content, which then names a field's value by its reference.
    pub answered: bool,
    /// What the value is put into in a certificate request, in ILM's order; empty when it is put nowhere.
    pub mapping: Vec<MappedField>,
}

impl Definition {
    /// The person picks from options: a list, and credentials and resources, which ILM fills by callback.
    pub fn is_list(&self) -> bool {
        self.list
            || matches!(
                self.content_type,
                ContentType::Credential | ContentType::Resource
            )
    }

    /// The person gives a value: not read-only, not hidden and not info.
    pub fn is_editable(&self) -> bool {
        self.kind != Kind::Info && !self.read_only && self.visible
    }

    /// ILM requires this value, the person cannot give it, and ILM's definition holds none: it cannot be sent.
    pub fn is_unshowable(&self) -> bool {
        self.kind != Kind::Info
            && self.required
            && (self.read_only || !self.visible)
            && self.content.is_empty()
    }

    /// The keys of the options, in order, each once: an option is named by what it is, not by its place.
    pub fn option_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = Vec::new();
        for key in self.content.iter().map(option_key) {
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        keys
    }

    /// The option the key names.
    pub fn option(&self, key: &str) -> Option<&Json> {
        self.content.iter().find(|item| option_key(item) == key)
    }

    /// The version a request attribute for this definition carries: ILM has no version 3 secret or credential.
    pub fn request_version(&self) -> Version {
        match (self.version, self.content_type) {
            (Version::V3, ContentType::Secret | ContentType::Credential) => Version::V2,
            (version, _) => version,
        }
    }

    /// The language of a codeblock, as the definition's first item fixes it.
    pub fn language(&self) -> &str {
        self.content
            .first()
            .and_then(|item| item.pointer("/data/language"))
            .and_then(Json::as_str)
            .unwrap_or("javascript")
    }
}

/// The key of an option: a short digest of the reference, data and content type ILM gave the item.
pub fn option_key(item: &Json) -> String {
    let identity = json!({
        "reference": item.get("reference"),
        "data": item.get("data"),
        "contentType": item.get("contentType"),
    });
    Sha256::digest(identity.to_string())[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A group attribute: it holds no value, its callback adds fields.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupAttribute {
    pub uuid: String,
    pub name: String,
    pub callback: Option<Callback>,
}

/// An attribute this application cannot show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub name: String,
    pub required: bool,
    pub label: String,
}

/// The definitions ILM sent, sorted by what the form does with them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Definitions {
    pub fields: Vec<Definition>,
    pub groups: Vec<GroupAttribute>,
    pub unsupported: Vec<Unsupported>,
    /// The names of the fields and groups each group attribute's static content defined, by group name.
    pub children: Vec<(String, Vec<String>)>,
}

enum Read {
    Field(Box<Definition>),
    Group(GroupAttribute),
    Unsupported(Unsupported),
    Dropped,
}

impl Definitions {
    /// Reads raw definitions. Meta attributes are dropped; an attribute with an unknown type, content type or
    /// version, or without a name or label, is listed as unsupported.
    pub fn read(raw: &[Json]) -> Self {
        Self::read_items(raw, None)
    }

    /// Reads the static content of the group attribute `group`: its definitions are fields of that group.
    fn read_in(raw: &[Json], group: &str) -> Self {
        Self::read_items(raw, Some(group))
    }

    fn read_items(raw: &[Json], group: Option<&str>) -> Self {
        let mut found = Self::default();
        for item in raw {
            match read_one(item) {
                Read::Field(mut field) => {
                    if field.group.is_none() {
                        field.group = group.map(str::to_owned);
                    }
                    found.fields.push(*field);
                }
                Read::Group(group) => {
                    let content = item.get("content").and_then(Json::as_array);
                    let inner = content.map(|raw| Self::read_in(raw, &group.name));
                    if let Some(inner) = &inner {
                        let fields = inner.fields.iter().map(|field| &field.name);
                        let groups = inner.groups.iter().map(|group| &group.name);
                        let names = fields.chain(groups).cloned().collect();
                        found.children.push((group.name.clone(), names));
                    }
                    found.groups.push(group);
                    if let Some(inner) = inner {
                        found.children.extend(inner.children);
                        found.fields.extend(inner.fields);
                        found.groups.extend(inner.groups);
                        found.unsupported.extend(inner.unsupported);
                    }
                }
                Read::Unsupported(unsupported) => found.unsupported.push(unsupported),
                Read::Dropped => {}
            }
        }
        found
    }

    /// No attribute at all.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.groups.is_empty() && self.unsupported.is_empty()
    }

    /// A required attribute cannot be shown, or a callback left a required one the person cannot fill without
    /// content, so the form cannot be sent.
    pub fn blocked(&self) -> bool {
        self.unsupported
            .iter()
            .any(|unsupported| unsupported.required)
            || self.fields.iter().any(Definition::is_unshowable)
    }

    /// The labels of the fields a callback left unshowable.
    pub fn unshowable(&self) -> Vec<String> {
        self.fields
            .iter()
            .filter(|field| field.is_unshowable())
            .map(|field| field.label.clone())
            .collect()
    }
}

fn text(object: &Map<String, Json>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn flag(properties: Option<&Map<String, Json>>, key: &str) -> Option<bool> {
    properties?.get(key)?.as_bool()
}

fn version_of(raw: Option<&Json>) -> Option<Version> {
    let number = match raw {
        None | Some(Json::Null) => return Some(Version::V2),
        Some(Json::Number(number)) => number.as_i64()?,
        Some(Json::String(text)) => text.parse().ok()?,
        Some(_) => return None,
    };
    match number {
        2 => Some(Version::V2),
        3 => Some(Version::V3),
        _ => None,
    }
}

fn read_one(raw: &Json) -> Read {
    let Some(object) = raw.as_object() else {
        return Read::Dropped;
    };
    let name = text(object, "name");
    let type_code = object.get("type").and_then(Json::as_str);
    match type_code {
        Some("meta") => return Read::Dropped,
        Some("group") => {
            return name.map_or(Read::Dropped, |name| {
                Read::Group(GroupAttribute {
                    uuid: text(object, "uuid").unwrap_or_default(),
                    name,
                    callback: object.get("attributeCallback").and_then(read_callback),
                })
            });
        }
        _ => {}
    }
    let properties = object.get("properties").and_then(Json::as_object);
    let label = properties.and_then(|properties| text(properties, "label"));
    let unsupported = || {
        Read::Unsupported(Unsupported {
            name: name.clone().unwrap_or_default(),
            required: flag(properties, "required").unwrap_or(false),
            label: label.clone().or_else(|| name.clone()).unwrap_or_default(),
        })
    };
    let kind = match type_code {
        Some("data") => Kind::Data,
        Some("info") => Kind::Info,
        Some("custom") => Kind::Custom,
        _ => return unsupported(),
    };
    let Some(version) = version_of(object.get("version")) else {
        return unsupported();
    };
    let (Some(name), Some(label)) = (name.clone(), label.clone()) else {
        return unsupported();
    };
    let content_type = object
        .get("contentType")
        .and_then(Json::as_str)
        .and_then(ContentType::from_code);
    let content_type = match (kind, content_type) {
        (_, Some(content_type)) => content_type,
        (Kind::Info, None) => ContentType::String,
        _ => return unsupported(),
    };
    let data = kind == Kind::Data;
    let content = object
        .get("content")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    let required = flag(properties, "required").unwrap_or(false);
    let read_only = flag(properties, "readOnly").unwrap_or(false);
    let visible = flag(properties, "visible").unwrap_or(true);
    let field = Definition {
        uuid: text(object, "uuid").unwrap_or_default(),
        name,
        description: text(object, "description"),
        kind,
        version,
        content_type,
        label,
        visible,
        group: properties.and_then(|properties| text(properties, "group")),
        required,
        read_only,
        list: flag(properties, "list").unwrap_or(false),
        multi_select: flag(properties, "multiSelect").unwrap_or(false),
        extensible: flag(properties, "extensibleList").unwrap_or(false),
        protected: content_type == ContentType::Secret
            || properties
                .and_then(|properties| properties.get("protectionLevel"))
                .and_then(Json::as_str)
                == Some("encrypted"),
        resource: properties.and_then(|properties| text(properties, "resource")),
        content,
        constraints: if data {
            read_constraints(object)
        } else {
            Vec::new()
        },
        callback: if data {
            object.get("attributeCallback").and_then(read_callback)
        } else {
            None
        },
        answered: false,
        mapping: read_mapping_fields(object),
    };
    if field.is_unshowable() && field.callback.is_none() {
        return unsupported();
    }
    Read::Field(Box::new(field))
}

/// The fields of a mapping onto a certificate; a mapping onto anything else is none.
fn read_mapping_fields(object: &Map<String, Json>) -> Vec<MappedField> {
    let Some(mapping) = object.get("fieldMapping") else {
        return Vec::new();
    };
    if mapping.get("objectType").and_then(Json::as_str) != Some("x509Certificate") {
        return Vec::new();
    }
    let fields = mapping.get("fields").and_then(Json::as_array);
    fields
        .map(|fields| fields.iter().map(read_mapped_field).collect())
        .unwrap_or_default()
}

fn read_mapped_field(raw: &Json) -> MappedField {
    let Some(object) = raw.as_object() else {
        return MappedField::Other;
    };
    let order = object
        .get("order")
        .and_then(Json::as_u64)
        .and_then(|order| u32::try_from(order).ok());
    match (object.get("fieldType").and_then(Json::as_str), object) {
        (Some("rdn"), object) => {
            text(object, "rdn").map_or(MappedField::Other, |rdn| MappedField::Rdn { rdn, order })
        }
        (Some("san"), object) => {
            text(object, "generalNameType").map_or(MappedField::Other, |general_name| {
                MappedField::San {
                    general_name,
                    other_name_oid: text(object, "otherNameOid"),
                    other_name_encoding: text(object, "otherNameValueEncoding"),
                    order,
                }
            })
        }
        _ => MappedField::Other,
    }
}

fn strings(raw: &Json) -> Vec<String> {
    raw.as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn read_target(code: &str) -> Option<Target> {
    Some(match code {
        "pathVariable" => Target::PathVariable,
        "requestParameter" => Target::RequestParameter,
        "body" => Target::Body,
        "filter" => Target::Filter,
        _ => return None,
    })
}

fn read_mapping(raw: &Json) -> Option<Mapping> {
    let object = raw.as_object()?;
    Some(Mapping {
        from: text(object, "from"),
        to: text(object, "to")?,
        targets: object
            .get("targets")
            .map(strings)
            .unwrap_or_default()
            .iter()
            .filter_map(|code| read_target(code))
            .collect(),
        value: object
            .get("value")
            .filter(|value| !value.is_null())
            .cloned(),
    })
}

/// A callback needs a legacy context or a `dependsOn` list; anything else is no callback.
fn read_callback(raw: &Json) -> Option<Callback> {
    let object = raw.as_object()?;
    let callback = Callback {
        context: text(object, "callbackContext"),
        method: text(object, "callbackMethod"),
        mappings: object
            .get("mappings")
            .and_then(Json::as_array)
            .map(|items| items.iter().filter_map(read_mapping).collect())
            .unwrap_or_default(),
        depends_on: object
            .get("dependsOn")
            .filter(|list| list.is_array())
            .map(strings),
    };
    (callback.context.is_some() || callback.depends_on.is_some()).then_some(callback)
}

fn bound(data: &Json, key: &str) -> Option<i64> {
    data.get(key).and_then(Json::as_i64)
}

fn read_constraint(raw: &Json) -> Option<Constraint> {
    let object = raw.as_object()?;
    let data = object.get("data")?;
    let rule = match object
        .get("type")
        .and_then(Json::as_str)
        .unwrap_or("regExp")
    {
        "regExp" => Rule::Pattern(data.as_str()?.to_owned()),
        "range" => Rule::Range {
            from: bound(data, "from"),
            to: bound(data, "to"),
        },
        "dateTime" => Rule::DateTime {
            from: data.get("from").and_then(Json::as_str).map(str::to_owned),
            to: data.get("to").and_then(Json::as_str).map(str::to_owned),
        },
        _ => return None,
    };
    Some(Constraint {
        description: text(object, "description"),
        message: text(object, "errorMessage"),
        rule,
    })
}

fn read_constraints(object: &Map<String, Json>) -> Vec<Constraint> {
    object
        .get("constraints")
        .and_then(Json::as_array)
        .map(|items| items.iter().filter_map(read_constraint).collect())
        .unwrap_or_default()
}
