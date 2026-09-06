//! The wrapped-data-key store.
//!
//! Each row is one *route* to the account's data key: a passkey whose PRF
//! output derives the unwrapping key, or the account's encryption key. The
//! server holds only the wrapped blobs — it has no code path that can produce
//! the key itself (spec section 5.3).
//!
//! Which route a row is, is [`crate::crypto::wire::WrapKind`]. That enum sits
//! in `crypto::wire` rather than here because the browser needs it too, to
//! pick the route it can open, and this module is `ssr`-only.

pub mod store;
