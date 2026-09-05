//! Client-side encryption of entry bodies.
//!
//! See `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`.

pub mod recovery;
/// The `SubtleCrypto` calls. Browser-only: WebCrypto has no host equivalent,
/// so this module exists solely in the wasm bundle.
#[cfg(feature = "hydrate")]
pub mod subtle;
pub mod wire;
