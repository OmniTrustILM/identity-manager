//! The address of the ILM the application talks to.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

pub mod actions;
pub mod approvals;
pub mod attributes;
pub mod certificates;
pub mod issue;
pub mod profile;
pub mod renew;
pub mod resource;
pub mod upload;

/// Why an ILM address is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    NotHttps,
    Invalid,
    UserInfo,
    Query,
    Fragment,
    TrailingSlash,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AddressError::Empty => "Enter the address of your ILM.",
            AddressError::NotHttps => "The address must use https.",
            AddressError::Invalid => "This is not a valid address.",
            AddressError::UserInfo => "The address must not contain a user name or password.",
            AddressError::Query => "The address must not contain a query.",
            AddressError::Fragment => "The address must not contain a fragment.",
            AddressError::TrailingSlash => "The address must not end with a slash.",
        })
    }
}

impl std::error::Error for AddressError {}

/// A normalised ILM address: HTTPS, with the path of an ILM under a prefix and no trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IlmUrl(String);

impl IlmUrl {
    /// Reads what the person typed. A bare host becomes `https://host`.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(AddressError::Empty);
        }
        if input.ends_with('/') {
            return Err(AddressError::TrailingSlash);
        }
        let url = if input.contains("://") {
            Url::parse(input)
        } else {
            Url::parse(&format!("https://{input}"))
        }
        .map_err(|_| AddressError::Invalid)?;
        if url.scheme() != "https" {
            return Err(AddressError::NotHttps);
        }
        if url.host_str().is_none() {
            return Err(AddressError::Invalid);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(AddressError::UserInfo);
        }
        if url.query().is_some() {
            return Err(AddressError::Query);
        }
        if url.fragment().is_some() {
            return Err(AddressError::Fragment);
        }
        let text = url.as_str();
        Ok(IlmUrl(text.strip_suffix('/').unwrap_or(text).to_string()))
    }

    /// An address on a stand-in server (`http://127.0.0.1:port`), skipping the HTTPS rule.
    #[cfg(test)]
    pub fn for_tests(address: &str) -> Self {
        IlmUrl(address.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The base of ILM's API.
    pub fn api(&self) -> String {
        format!("{}/api", self.0)
    }
}

impl fmt::Display for IlmUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for IlmUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for IlmUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> String {
        IlmUrl::parse(input).unwrap().to_string()
    }

    #[test]
    fn a_host_becomes_an_https_address() {
        assert_eq!(parsed("ilm.example.com"), "https://ilm.example.com");
        assert_eq!(
            parsed("  ilm.example.com:8443 "),
            "https://ilm.example.com:8443"
        );
        assert_eq!(parsed("ILM.Example.com"), "https://ilm.example.com");
    }

    #[test]
    fn https_addresses_keep_their_path() {
        assert_eq!(parsed("https://ilm.example.com"), "https://ilm.example.com");
        assert_eq!(parsed("https://example.com/ilm"), "https://example.com/ilm");
        assert_eq!(parsed("example.com/a/b"), "https://example.com/a/b");
    }

    #[test]
    fn refused_forms_say_why() {
        let cases = [
            ("", AddressError::Empty),
            ("   ", AddressError::Empty),
            ("http://ilm.example.com", AddressError::NotHttps),
            ("ftp://ilm.example.com", AddressError::NotHttps),
            ("https://ilm.example.com/", AddressError::TrailingSlash),
            ("https://example.com/ilm/", AddressError::TrailingSlash),
            ("https://ilm.example.com?a=b", AddressError::Query),
            ("https://ilm.example.com/x#top", AddressError::Fragment),
            ("https://user@ilm.example.com", AddressError::UserInfo),
            ("https://user:pw@ilm.example.com", AddressError::UserInfo),
            ("https://:443", AddressError::Invalid),
            ("https://exa mple.com", AddressError::Invalid),
        ];
        for (input, error) in cases {
            assert_eq!(IlmUrl::parse(input), Err(error), "{input:?}");
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn the_api_base_is_under_the_address() {
        let url = IlmUrl::parse("https://example.com/ilm").unwrap();
        assert_eq!(url.api(), "https://example.com/ilm/api");
        assert_eq!(url.as_str(), "https://example.com/ilm");
    }

    #[test]
    fn it_serialises_as_text_and_reads_only_valid_addresses() {
        let url = IlmUrl::parse("ilm.example.com").unwrap();
        let json = serde_json::to_value(&url).unwrap();
        assert_eq!(json, serde_json::json!("https://ilm.example.com"));
        assert_eq!(serde_json::from_value::<IlmUrl>(json).unwrap(), url);
        assert!(serde_json::from_value::<IlmUrl>(serde_json::json!("http://x")).is_err());
    }
}
