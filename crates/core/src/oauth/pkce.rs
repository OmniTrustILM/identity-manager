//! The one-time secrets of an authorization code flow with PKCE (RFC 7636).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

const SECRET_BYTES: usize = 32;

/// The verifier stays with the app, the challenge goes to the provider, `state` ties the answer to the request.
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
}

impl Pkce {
    pub fn new() -> Self {
        let verifier = random_secret();
        Self {
            challenge: challenge_for(&verifier),
            verifier,
            state: random_secret(),
        }
    }
}

impl Default for Pkce {
    fn default() -> Self {
        Self::new()
    }
}

fn random_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).expect("the system provides random bytes");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_matches_the_rfc_7636_example() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn secrets_are_32_random_bytes_in_base64url() {
        let a = Pkce::new();
        let b = Pkce::new();
        for secret in [&a.verifier, &a.state] {
            assert_eq!(URL_SAFE_NO_PAD.decode(secret).unwrap().len(), SECRET_BYTES);
        }
        assert_ne!(a.verifier, a.state);
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.state, b.state);
        assert_eq!(a.challenge, challenge_for(&a.verifier));
    }
}
