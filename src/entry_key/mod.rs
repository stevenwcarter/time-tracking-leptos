//! The wrapped-data-key store.
//!
//! Each row is one *route* to the account's data key: a passkey whose PRF
//! output derives the unwrapping key, or the recovery code. The server holds
//! only the wrapped blobs — it has no code path that can produce the key
//! itself (spec section 5.3).

pub mod store;

/// How a wrap is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapKind {
    /// Unwrapped by a key derived from one credential's PRF output.
    Passkey,
    /// Unwrapped by a key derived from the account's recovery code.
    Recovery,
}

impl WrapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            WrapKind::Passkey => "passkey",
            WrapKind::Recovery => "recovery",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "passkey" => Some(WrapKind::Passkey),
            "recovery" => Some(WrapKind::Recovery),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_and_parse_round_trip() {
        for kind in [WrapKind::Passkey, WrapKind::Recovery] {
            assert_eq!(WrapKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(WrapKind::parse("bogus"), None);
    }
}
