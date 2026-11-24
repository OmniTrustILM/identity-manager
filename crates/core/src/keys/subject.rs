//! The subject of a certificate request, built from ILM's request attributes and the values a person gave.
//!
//! ILM accepts a request only when every name in it is one its request attributes map, so nothing else goes in.
//! No value is ever logged.

use std::net::IpAddr;

use rcgen::string::{Ia5String, PrintableString};
use serde_json::Value as Json;

use super::request::{DOMAIN_COMPONENT, EMAIL_ADDRESS, SERIAL_NUMBER};
use super::{AlternativeName, NameType, RequestSubject};
use crate::attributes::{Definition, Kind, MappedField, Unsupported, Values, request};

const USER_PRINCIPAL_NAME: &str = "1.3.6.1.4.1.311.20.2.3";

/// Why a request cannot be built from the attributes. The text is for the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unmappable {
    /// An attribute goes nowhere, or somewhere this application cannot write.
    Unsupported { label: String },
    /// The value is not one a request can hold.
    Invalid { label: String },
    /// A name type of the subject would get two values, and the request keeps one.
    Repeated { label: String },
}

impl std::fmt::Display for Unmappable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { label } => {
                write!(
                    f,
                    "{label} cannot be put in the request by this application."
                )
            }
            Self::Invalid { label } => write!(f, "{label} is not valid for the request."),
            Self::Repeated { label } => write!(
                f,
                "{label} has more than one value, which the request cannot hold."
            ),
        }
    }
}

impl std::error::Error for Unmappable {}

/// Where a mapped field goes, when this application can write it.
enum Target {
    Name(NameType),
    Alternative(fn(String) -> AlternativeName),
    Address,
}

fn target(field: &MappedField) -> Option<Target> {
    match field {
        MappedField::Rdn { rdn, .. } => name_type(rdn).map(Target::Name),
        MappedField::San {
            general_name,
            other_name_oid,
            other_name_encoding,
            ..
        } => match (
            general_name.as_str(),
            other_name_oid.as_deref(),
            other_name_encoding.as_deref(),
        ) {
            ("dns", ..) => Some(Target::Alternative(AlternativeName::Dns)),
            ("email", ..) => Some(Target::Alternative(AlternativeName::Email)),
            ("uri", ..) => Some(Target::Alternative(AlternativeName::Uri)),
            ("ip", ..) => Some(Target::Address),
            ("otherName", Some(USER_PRINCIPAL_NAME), None | Some("UTF8String")) => {
                Some(Target::Alternative(AlternativeName::Upn))
            }
            _ => None,
        },
        MappedField::Other => None,
    }
}

pub(super) fn name_type(code: &str) -> Option<NameType> {
    Some(match code.to_ascii_uppercase().as_str() {
        "CN" => NameType::CommonName,
        "O" => NameType::Organization,
        "OU" => NameType::OrganizationalUnit,
        "C" => NameType::Country,
        "ST" | "S" => NameType::State,
        "L" => NameType::Locality,
        "EMAIL" | "E" | "EMAILADDRESS" => NameType::Email,
        "SERIALNUMBER" => NameType::SerialNumber,
        "DC" => NameType::DomainComponent,
        _ => known(oid_arcs(code)?),
    })
}

/// The name type an OBJECT IDENTIFIER stands for, whichever way it is written.
fn known(arcs: Vec<u64>) -> NameType {
    match arcs.as_slice() {
        [2, 5, 4, 3] => NameType::CommonName,
        [2, 5, 4, 10] => NameType::Organization,
        [2, 5, 4, 11] => NameType::OrganizationalUnit,
        [2, 5, 4, 6] => NameType::Country,
        [2, 5, 4, 8] => NameType::State,
        [2, 5, 4, 7] => NameType::Locality,
        arcs if arcs == SERIAL_NUMBER => NameType::SerialNumber,
        arcs if arcs == EMAIL_ADDRESS => NameType::Email,
        arcs if arcs == DOMAIN_COMPONENT => NameType::DomainComponent,
        _ => NameType::Other(arcs),
    }
}

fn oid_arcs(code: &str) -> Option<Vec<u64>> {
    let arcs: Vec<u64> = code
        .split('.')
        .map(|arc| arc.parse().ok())
        .collect::<Option<_>>()?;
    let valid = match arcs.as_slice() {
        [0 | 1, second, ..] => *second < 40,
        [2, ..] => true,
        _ => false,
    };
    (arcs.len() >= 2 && valid).then_some(arcs)
}

/// Whether the value fits the string type its name is written in.
fn fits_name(kind: &NameType, text: &str) -> bool {
    match kind {
        NameType::Email | NameType::DomainComponent => Ia5String::try_from(text).is_ok(),
        NameType::Country | NameType::SerialNumber => PrintableString::try_from(text).is_ok(),
        _ => true,
    }
}

/// Whether the value fits the string type its alternative name is written in.
fn fits_alternative(name: &AlternativeName) -> bool {
    match name {
        AlternativeName::Dns(text) | AlternativeName::Email(text) | AlternativeName::Uri(text) => {
            Ia5String::try_from(text.as_str()).is_ok()
        }
        AlternativeName::Upn(_) | AlternativeName::Ip(_) => true,
    }
}

fn order_of(field: &MappedField) -> u32 {
    match field {
        MappedField::Rdn { order, .. } | MappedField::San { order, .. } => {
            order.unwrap_or(u32::MAX)
        }
        MappedField::Other => u32::MAX,
    }
}

/// The text of one content item: what ILM would read as its data.
fn text_of(item: &Json) -> Option<String> {
    match item.get("data")? {
        Json::String(text) => Some(text.clone()),
        Json::Number(number) => Some(number.to_string()),
        Json::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

/// A value the person gives that the attribute maps nowhere, so the request could not hold it.
fn is_unmapped(definition: &Definition) -> bool {
    definition.is_editable() && definition.mapping.is_empty()
}

/// The attribute has no mapping that takes a value, or has a field this application cannot write.
fn cannot_be_written(definition: &Definition) -> bool {
    is_unmapped(definition)
        || definition
            .mapping
            .iter()
            .any(|field| target(field).is_none())
}

/// A required attribute with no mapping, or with a field this application cannot write, blocks the request.
fn is_unbuildable(definition: &Definition) -> bool {
    definition.required && cannot_be_written(definition)
}

/// Removes the optional attributes that cannot be written into the request, so a form made of the rest cannot
/// carry a value that would refuse it.
pub fn without_unwritable(definitions: &mut Vec<Definition>) {
    definitions.retain(|definition| {
        definition.required || definition.kind == Kind::Info || !cannot_be_written(definition)
    });
}

/// The attributes that must be in the request and go somewhere this application cannot write.
pub fn unbuildable(definitions: &[Definition]) -> Vec<Unsupported> {
    definitions
        .iter()
        .filter(|definition| is_unbuildable(definition))
        .map(|definition| Unsupported {
            name: definition.name.clone(),
            label: definition.label.clone(),
            required: true,
        })
        .collect()
}

/// The subject of the request: each attribute's value as ILM would receive it, put where the attribute's mapping
/// says. A value that has nowhere to go is refused, and so is a name type that would get two values, because the
/// request keeps one of a type.
pub fn subject(definitions: &[Definition], values: &Values) -> Result<RequestSubject, Unmappable> {
    if let Some(definition) = definitions
        .iter()
        .find(|definition| is_unbuildable(definition))
    {
        return Err(Unmappable::Unsupported {
            label: definition.label.clone(),
        });
    }
    let mut names: Vec<(u32, NameType, String, &Definition)> = Vec::new();
    let mut alternatives: Vec<(u32, AlternativeName)> = Vec::new();
    for attribute in request(definitions, values) {
        let Some(definition) = definitions
            .iter()
            .find(|definition| attribute["name"] == definition.name.as_str())
        else {
            continue;
        };
        let invalid = || Unmappable::Invalid {
            label: definition.label.clone(),
        };
        let items = attribute["content"]
            .as_array()
            .map_or(&[][..], Vec::as_slice);
        let texts: Vec<String> = items
            .iter()
            .map(|item| text_of(item).ok_or_else(invalid))
            .collect::<Result<_, _>>()?;
        if is_unmapped(definition) && !texts.is_empty() {
            return Err(Unmappable::Unsupported {
                label: definition.label.clone(),
            });
        }
        for field in &definition.mapping {
            let order = order_of(field);
            let Some(target) = target(field) else {
                if texts.is_empty() {
                    continue;
                }
                return Err(Unmappable::Unsupported {
                    label: definition.label.clone(),
                });
            };
            for text in &texts {
                match &target {
                    Target::Name(kind) => {
                        if !fits_name(kind, text) {
                            return Err(invalid());
                        }
                        names.push((order, kind.clone(), text.clone(), definition));
                    }
                    Target::Alternative(build) => {
                        let name = build(text.clone());
                        if !fits_alternative(&name) {
                            return Err(invalid());
                        }
                        alternatives.push((order, name));
                    }
                    Target::Address => {
                        let address: IpAddr = text.trim().parse().map_err(|_| invalid())?;
                        alternatives.push((order, AlternativeName::Ip(address)));
                    }
                }
            }
        }
    }
    names.sort_by_key(|(order, ..)| *order);
    alternatives.sort_by_key(|(order, _)| *order);
    for (index, (_, kind, _, definition)) in names.iter().enumerate() {
        if names[..index].iter().any(|(_, other, ..)| other == kind) {
            return Err(Unmappable::Repeated {
                label: definition.label.clone(),
            });
        }
    }
    log::debug!(
        "request subject built: {} names, {} alternative names",
        names.len(),
        alternatives.len()
    );
    Ok(RequestSubject {
        names: names
            .into_iter()
            .map(|(_, kind, text, _)| (kind, text))
            .collect(),
        alternative_names: alternatives.into_iter().map(|(_, name)| name).collect(),
    })
}

#[cfg(test)]
mod tests;
