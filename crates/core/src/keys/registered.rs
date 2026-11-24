//! The identity of a certificate registered in advance, read from the subject and alternative names ILM shows,
//! so the request carries what ILM registered. No value is ever logged.

use std::net::IpAddr;

use super::subject::name_type;
use super::{AlternativeName, RequestSubject, Unmappable};

const USER_PRINCIPAL_NAME: &str = "1.3.6.1.4.1.311.20.2.3";

/// The subject of the request for a registered certificate: the names of `subject_dn` (RFC 4514 text, the most
/// specific name first) and the alternative names by the type ILM names them. A request writes the subject from
/// the most general name down, so the names come out in reverse. A name this application cannot write, or a type
/// of name that would get two values, refuses the request.
pub fn registered_subject(
    subject_dn: Option<&str>,
    alternative_names: &[(String, Vec<String>)],
) -> Result<RequestSubject, Unmappable> {
    let mut names = Vec::new();
    for (key, value) in subject_dn.map_or_else(|| Ok(Vec::new()), components)? {
        let kind = name_type(&alias(&key))
            .ok_or_else(|| Unmappable::Unsupported { label: key.clone() })?;
        if names.iter().any(|(other, _)| *other == kind) {
            return Err(Unmappable::Repeated { label: key });
        }
        names.push((kind, value));
    }
    names.reverse();
    let mut alternatives = Vec::new();
    for (kind, values) in alternative_names {
        for value in values {
            alternatives.push(alternative(kind, value)?);
        }
    }
    Ok(RequestSubject {
        names,
        alternative_names: alternatives,
    })
}

/// The code `name_type` knows for a key of a distinguished name.
fn alias(key: &str) -> String {
    let upper = key.to_ascii_uppercase();
    match upper.as_str() {
        "EMAILADDRESS" => "E".to_owned(),
        _ => upper.strip_prefix("OID.").unwrap_or(&upper).to_owned(),
    }
}

fn alternative(kind: &str, value: &str) -> Result<AlternativeName, Unmappable> {
    let unsupported = || Unmappable::Unsupported {
        label: kind.to_owned(),
    };
    Ok(match kind {
        "dNSName" => AlternativeName::Dns(value.to_owned()),
        "rfc822Name" => AlternativeName::Email(value.to_owned()),
        "uniformResourceIdentifier" => AlternativeName::Uri(value.to_owned()),
        "iPAddress" => AlternativeName::Ip(value.trim().parse::<IpAddr>().map_err(|_| {
            Unmappable::Invalid {
                label: kind.to_owned(),
            }
        })?),
        "otherName" => match value.split_once('=') {
            Some((USER_PRINCIPAL_NAME, name)) => AlternativeName::Upn(name.to_owned()),
            _ => return Err(unsupported()),
        },
        _ => return Err(unsupported()),
    })
}

/// The key and value of each name of an RFC 4514 text, in the order written.
fn components(text: &str) -> Result<Vec<(String, String)>, Unmappable> {
    let invalid = || Unmappable::Invalid {
        label: "The subject".to_owned(),
    };
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    split_names(text)
        .ok_or_else(invalid)?
        .into_iter()
        .map(|part| {
            let (key, raw) = part.split_once('=').ok_or_else(invalid)?;
            let value = unescape(raw).ok_or_else(invalid)?;
            if key.trim().is_empty() || value.is_empty() || raw.starts_with('#') {
                return Err(invalid());
            }
            Ok((key.trim().to_owned(), value))
        })
        .collect()
}

/// The text cut at each comma that is not escaped; none when a name has several values (an unescaped plus).
fn split_names(text: &str) -> Option<Vec<String>> {
    let mut parts = vec![String::new()];
    let mut escaped = false;
    for character in text.chars() {
        let part = parts.last_mut()?;
        match (escaped, character) {
            (true, _) => {
                part.push(character);
                escaped = false;
            }
            (false, '\\') => {
                part.push(character);
                escaped = true;
            }
            (false, '+') => return None,
            (false, ',') => parts.push(String::new()),
            (false, _) => part.push(character),
        }
    }
    Some(parts)
}

/// The value with its escapes read: a backslash before a character, or before two hexadecimal digits that are a
/// byte of the UTF-8 text.
fn unescape(raw: &str) -> Option<String> {
    let mut bytes = Vec::new();
    let mut characters = raw.chars().peekable();
    while let Some(character) = characters.next() {
        let literal = if character == '\\' {
            let escaped = characters.next()?;
            match (
                escaped.to_digit(16),
                characters.peek().and_then(|next| next.to_digit(16)),
            ) {
                (Some(high), Some(low)) => {
                    characters.next();
                    bytes.push((high * 16 + low) as u8);
                    continue;
                }
                _ => escaped,
            }
        } else {
            character
        };
        bytes.extend_from_slice(literal.encode_utf8(&mut [0; 4]).as_bytes());
    }
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests;
