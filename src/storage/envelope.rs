//! The versioned wrapper every stored entry body is written inside.
//!
//! Phase 1 writes `{"v":1,"alg":"none","body":"..."}`. Phase 2 will write
//! `{"v":2,"alg":"xchacha20poly1305","n":"...","ct":"..."}` and read both.
//! The version tag exists so that transition needs no migration and no
//! guessing: a reader always knows what it is holding.
//!
//! This sits *above* [`super::codec`], which handles the gloo-compatible
//! JSON-string encoding on the `localStorage` side. Two layers, two jobs:
//! the codec preserves compatibility with data the Dioxus build wrote, this
//! preserves forward compatibility with data phase 2 will write.

use serde::{Deserialize, Serialize};

const VERSION: u8 = 1;
const ALG_PLAINTEXT: &str = "none";

/// A stored envelope could not be interpreted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("stored value is not a valid envelope: {0}")]
    Malformed(String),
    #[error("stored value uses envelope version {0}, which this build cannot read")]
    UnsupportedVersion(u8),
    #[error("stored value uses algorithm `{0}`, which this build cannot read")]
    UnsupportedAlg(String),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    alg: String,
    #[serde(default)]
    body: String,
}

/// Wraps a plaintext body for storage.
pub fn wrap(body: &str) -> String {
    let env = Envelope {
        v: VERSION,
        alg: ALG_PLAINTEXT.to_string(),
        body: body.to_owned(),
    };
    // Every field is a plain String/u8; serialization cannot fail.
    serde_json::to_string(&env).expect("envelope must serialize")
}

/// Reads a body back out of a stored envelope.
pub fn unwrap(raw: &str) -> Result<String, EnvelopeError> {
    let env: Envelope =
        serde_json::from_str(raw).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
    if env.v != VERSION {
        return Err(EnvelopeError::UnsupportedVersion(env.v));
    }
    if env.alg != ALG_PLAINTEXT {
        return Err(EnvelopeError::UnsupportedAlg(env.alg));
    }
    Ok(env.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_body() {
        let body = "11:45-12:15 code1\n- did a thing";
        assert_eq!(unwrap(&wrap(body)).expect("round trip"), body);
    }

    /// Pins invariant I8. The version and algorithm tags are what let phase 2
    /// tell a plaintext row from a ciphertext row.
    #[test]
    fn wrapped_value_is_version_tagged() {
        let raw = wrap("x");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(v["v"], 1);
        assert_eq!(v["alg"], "none");
        assert_eq!(v["body"], "x");
    }

    /// A future `v: 2` envelope reaching a phase-1 client must be a loud
    /// error, never silently rendered as if it were the plaintext body.
    #[test]
    fn unknown_version_is_an_error() {
        let future = r#"{"v":2,"alg":"xchacha20poly1305","n":"AA","ct":"BB"}"#;
        assert!(matches!(
            unwrap(future),
            Err(EnvelopeError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn unknown_algorithm_is_an_error() {
        let odd = r#"{"v":1,"alg":"rot13","body":"x"}"#;
        assert!(matches!(unwrap(odd), Err(EnvelopeError::UnsupportedAlg(_))));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(unwrap("not json"), Err(EnvelopeError::Malformed(_))));
    }

    /// An empty body is a real, meaningful state (`Some("")` in the hook's
    /// tri-state) and must survive the round trip distinctly from absence.
    #[test]
    fn empty_body_round_trips() {
        assert_eq!(unwrap(&wrap("")).expect("round trip"), "");
    }
}
