//! The versioned wrapper every stored entry body is written inside.
//!
//! Phase 1 wrote `{"v":1,"alg":"none","body":"..."}`. Phase 2 writes
//! `{"v":2,"alg":"a256gcm","n":"...","ct":"..."}` (the wire shape lives in
//! [`crate::crypto::wire`]). Which of the two [`wrap`] produces is decided by
//! whether the session holds a key; which of the two a *reader* gets is never
//! asked here at all — [`plan_read`] dispatches on the row's own `v` (spec
//! E3). The version tag is what lets both shapes coexist in one account with
//! no migration and no guessing: a reader always knows what it is holding
//! from the row alone.
//!
//! This sits *above* [`super::codec`], which handles the gloo-compatible
//! JSON-string encoding on the `localStorage` side. Two layers, two jobs:
//! the codec preserves compatibility with data the Dioxus build wrote, this
//! preserves forward compatibility with data phase 2 will write.

use serde::{Deserialize, Serialize};

#[cfg(feature = "hydrate")]
use crate::crypto::SessionKey;
#[cfg(feature = "hydrate")]
use crate::crypto::subtle::CryptoError;
use crate::crypto::wire::{self, Sealed, WireError};

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
    #[error("stored value is a v2 envelope this build cannot read: {0}")]
    Wire(#[from] WireError),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u8,
    alg: String,
    #[serde(default)]
    body: String,
}

/// What a stored envelope turns out to be, before any key is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPlan {
    /// A v1 row. The body is right here.
    Plaintext(String),
    /// A v2 row. Needs the session key to open.
    Sealed(Sealed),
}

/// Decides what a stored string is, without needing a key.
///
/// Dispatch is on the row's own `v`, never on whether the account has
/// encryption enabled. That is what makes a half-finished migration safe to
/// read rather than corrupting (spec E3): a background re-encryption pass
/// can stop at any row, leaving an account with both shapes at once, and
/// every row still reads correctly because each one carries its own answer.
pub fn plan_read(raw: &str) -> Result<ReadPlan, EnvelopeError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
    let version = value["v"]
        .as_u64()
        .ok_or_else(|| EnvelopeError::Malformed("missing or non-numeric `v` field".to_string()))?;

    match version {
        1 => {
            let env: Envelope =
                serde_json::from_str(raw).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
            if env.alg != ALG_PLAINTEXT {
                return Err(EnvelopeError::UnsupportedAlg(env.alg));
            }
            Ok(ReadPlan::Plaintext(env.body))
        }
        2 => Ok(ReadPlan::Sealed(wire::decode_v2(raw)?)),
        // `EnvelopeError::UnsupportedVersion` is a `u8`, but `version` came
        // from JSON as a `u64` — a value above 255 must be reported as
        // malformed, never silently truncated into some other version's
        // number by an `as` cast.
        other => Err(u8::try_from(other)
            .map(EnvelopeError::UnsupportedVersion)
            .unwrap_or_else(|_| {
                EnvelopeError::Malformed(format!("envelope version {other} is out of range"))
            })),
    }
}

/// Wraps a plaintext body for storage, unsealed.
///
/// Still the whole story for a signed-out device, whose `localStorage` is
/// never encrypted, and for the legacy blob `local::resolve_load` normalizes
/// into an envelope so the read path stays uniform.
pub fn wrap_v1(body: &str) -> String {
    let env = Envelope {
        v: VERSION,
        alg: ALG_PLAINTEXT.to_string(),
        body: body.to_owned(),
    };
    // Every field is a plain String/u8; serialization cannot fail.
    serde_json::to_string(&env).expect("envelope must serialize")
}

/// Wraps a body for storage, sealing it first when the session holds a key.
///
/// The write half of the version dispatch, and the *only* place it is made:
/// `None` writes v1, `Some` writes v2. The read half never consults this
/// choice — it reads each row's own `v` (spec E3) — which is exactly what
/// lets a half-migrated account keep working: new writes land as v2 while
/// the rows the migration has not reached yet still read as v1.
///
/// Browser-only, because sealing is: the plaintext branch could run
/// anywhere, but a function that silently degrades to writing plaintext on a
/// target where `Some` cannot exist is the wrong shape for the one call that
/// decides whether a body is encrypted.
#[cfg(feature = "hydrate")]
pub async fn wrap(body: &str, session: Option<&SessionKey>) -> Result<String, CryptoError> {
    match session {
        None => Ok(wrap_v1(body)),
        Some(session) => Ok(wire::encode_v2(&session.seal(body).await?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A body with a newline in it: entries are multi-line by nature, and
    /// the JSON encoding is the only thing standing between that and a
    /// mangled round trip.
    #[test]
    fn round_trips_a_multiline_body() {
        let body = "11:45-12:15 code1\n- did a thing";
        assert!(matches!(plan_read(&wrap_v1(body)), Ok(ReadPlan::Plaintext(b)) if b == body));
    }

    /// Pins invariant I8. The version and algorithm tags are what let phase 2
    /// tell a plaintext row from a ciphertext row.
    #[test]
    fn wrapped_value_is_version_tagged() {
        let raw = wrap_v1("x");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(v["v"], 1);
        assert_eq!(v["alg"], "none");
        assert_eq!(v["body"], "x");
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(
            plan_read("not json"),
            Err(EnvelopeError::Malformed(_))
        ));
    }

    /// Spec E3. Dispatch is on the row's own version, never on account state.
    /// A partially migrated account holds both shapes at once and every row
    /// must read correctly — this is the whole reason the migration is
    /// resumable.
    #[test]
    fn a_v1_row_reads_as_plaintext_even_when_v2_rows_exist() {
        let v1 = wrap_v1("11:45-12:15 code1");
        assert!(
            matches!(plan_read(&v1), Ok(ReadPlan::Plaintext(body)) if body == "11:45-12:15 code1")
        );
    }

    #[test]
    fn a_v2_row_reads_as_ciphertext_needing_the_key() {
        let raw = wire::encode_v2(&Sealed {
            nonce: vec![0; wire::NONCE_LEN],
            ciphertext: vec![9, 9, 9],
        });
        let ReadPlan::Sealed(sealed) = plan_read(&raw).expect("plan") else {
            panic!("v2 must plan as Sealed");
        };
        assert_eq!(sealed.ciphertext, vec![9, 9, 9]);
    }

    /// `plan_read`'s v2 arm hands `raw` straight to `wire::decode_v2` with
    /// `?`, and only `decode_v2` itself is exercised directly elsewhere —
    /// this pins that a malformed v2 row surfaces through `plan_read` as
    /// `EnvelopeError::Wire`, not flattened into `Malformed` on the way.
    #[test]
    fn a_malformed_v2_envelope_surfaces_as_a_wire_error() {
        let raw = r#"{"v":2,"alg":"a256gcm","n":"!!!!","ct":"AAAA"}"#;
        assert!(matches!(plan_read(raw), Err(EnvelopeError::Wire(_))));
    }

    /// The forward-compatibility guarantee phase 1 shipped, still holding one
    /// version further out. `v: 2` used to be the unknown, must-error case;
    /// phase 2 made it readable (see `a_v2_row_reads_as_ciphertext_needing_the_key`
    /// above), so `v: 3` takes over the role this test pins: an envelope this
    /// build cannot read is a loud error, never rendered as if it were text.
    #[test]
    fn an_unknown_future_version_is_still_an_error() {
        let v3 = r#"{"v":3,"alg":"something-new","x":"AA"}"#;
        assert!(matches!(
            plan_read(v3),
            Err(EnvelopeError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn a_v1_row_with_a_foreign_algorithm_is_an_error() {
        let odd = r#"{"v":1,"alg":"rot13","body":"x"}"#;
        assert!(matches!(
            plan_read(odd),
            Err(EnvelopeError::UnsupportedAlg(_))
        ));
    }

    /// `Some("")` is a real state in the hydration tri-state — "loaded,
    /// nothing saved" — and must survive distinctly from absence.
    #[test]
    fn an_empty_v1_body_round_trips() {
        assert!(matches!(plan_read(&wrap_v1("")), Ok(ReadPlan::Plaintext(b)) if b.is_empty()));
    }
}
