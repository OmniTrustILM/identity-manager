//! A bearer token that never prints its value.

use std::fmt;

/// An access token for ILM. It is kept in memory only and its `Debug` output hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_hides_the_value() {
        let token = AccessToken::new("secret-value");
        assert!(!format!("{token:?}").contains("secret-value"));
        assert_eq!(token.as_str(), "secret-value");
    }
}
