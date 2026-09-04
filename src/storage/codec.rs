//! The on-disk representation of stored values.
//!
//! `gloo_storage` — used by the previous Dioxus build — wrote every value as
//! `serde_json::to_string(&value)`, so a stored `String` is a *JSON-encoded*
//! string (`"\"hello\""`, not `hello`). This module preserves that encoding so
//! data written by the old build still loads.

use serde::{Serialize, de::DeserializeOwned};

/// A stored value could not be read back.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("could not decode stored value: {0}")]
pub struct DecodeError(String);

/// Encodes a value for storage, matching `gloo_storage`'s representation.
pub fn encode<T: Serialize>(value: &T) -> String {
    // `String` and every type this app stores serialize infallibly; a failure
    // here is a programming error, not a runtime condition.
    serde_json::to_string(value).expect("stored types must serialize")
}

/// Decodes a value previously written by [`encode`] (or by `gloo_storage`).
pub fn decode<T: DeserializeOwned>(raw: &str) -> Result<T, DecodeError> {
    serde_json::from_str(raw).map_err(|e| DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_round_trip() {
        let original = "11:45-12:15 code1\n- did a thing".to_string();
        let encoded = encode(&original);
        let decoded: String = decode(&encoded).expect("round trip should decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn gloo_format_compat() {
        // Exactly what gloo_storage::LocalStorage::set wrote for this value.
        let as_gloo_wrote_it = "\"11:45-12:15 code1\"";
        let decoded: String = decode(as_gloo_wrote_it).expect("gloo-written value should decode");
        assert_eq!(decoded, "11:45-12:15 code1");

        // And we still write that same shape.
        assert_eq!(encode(&"11:45-12:15 code1".to_string()), as_gloo_wrote_it);
    }

    #[test]
    fn decode_rejects_unencoded_text() {
        // A bare, un-JSON-encoded value is not something either build wrote;
        // surfacing it as an error beats silently returning garbage.
        let result = decode::<String>("11:45-12:15 code1");
        assert!(result.is_err(), "bare text must not decode as a stored value");
    }
}
