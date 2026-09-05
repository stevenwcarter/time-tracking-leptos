# Client-Side Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encrypt signed-in users' entry bodies in the browser under a key the server never sees, unwrapped by passkey PRF with a recovery code as backup.

**Architecture:** A random AES-256-GCM data key (DEK) per account, generated in the browser. It is wrapped with AES-KW under two independently-derived KEKs — one from the passkey's WebAuthn PRF output, one from a 160-bit recovery code — and the wrapped blobs are stored server-side. Unwrapped, the DEK lives as a **non-extractable** `CryptoKey` in IndexedDB, so unlocking is once per device. Encryption is applied at the existing storage seam (`src/storage/envelope.rs`), so no component that reads or writes entry text changes.

**Tech Stack:** Leptos 0.8 SSR + hydration, Axum, Diesel/SQLite, WebCrypto (`SubtleCrypto`) and IndexedDB via `js_sys::Reflect` / `web-sys`, `webauthn-rs` 0.6.

**Spec:** `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`

---

## Global Constraints

Every task's requirements implicitly include this section.

**Verification — all four must pass before any task is called done:**

```
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features --all-targets -- -D warnings
cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings
cargo fmt --all -- --check
```

Plain `cargo clippy --features ssr --no-default-features` does **not** lint modules gated `#[cfg(any(feature = "hydrate", test))]`. Both clippy lines above are required, not optional.

Never run plain `cargo build`/`cargo test` without `--features ssr --no-default-features`, and never `cargo leptos build` mid-task — they fight over the target dir.

**Code conventions:**

- Edition 2024. No `unsafe` — this crate deliberately has none. In particular, `std::env::set_var` is unsafe in edition 2024; if a test needs environment input, restructure so the value is a parameter (see `SmtpSettings` in `src/email/mod.rs` for the established pattern).
- Branch polymorphism uses `Either`/`EitherOf3`, never `.into_any()`.
- `gen` is a reserved word in edition 2024. Do not name anything `gen`.
- Tailwind v4 CSS-first. No `tailwind.config.js`, no npm step, no `@theme` block. Use default-palette utilities.
- Match the surrounding comment density: this codebase explains *why*, not *what*, and reviewers expect that.

**Crypto constants — never change these strings.** Changing one silently makes every existing wrapped key unopenable (spec E6):

- `APP_SALT` = SHA-256 of the ASCII bytes `time-tracking-leptos/entry-key/v1`
- passkey HKDF info = `tt/entry-kek/passkey/v1`
- recovery HKDF info = `tt/entry-kek/recovery/v1`
- envelope v2 `alg` = `a256gcm`
- AES-GCM nonce = 12 bytes, fresh per write
- wrapped key = 40 bytes (AES-KW of a 256-bit key)

**Base64** is `base64::engine::general_purpose::STANDARD` (padded), matching the rest of the codebase.

**The hydration contract (CLAUDE.md — read it):** the server renders `None` for entry state and `EncryptionState::Unknown` for encryption state, on every backend, for every user. `src/app.rs`'s `ssr_omits_loaded_state` and `ssr_omits_entry_content_even_when_signed_in` assert negatively. **Do not weaken either to make a change pass.**

**Storage keys are a compatibility surface.** `time_entry`, `time_entry:YYYY-MM-DD`, `time_entry_import_done`. Changing one orphans existing users' data.

**Two kinds of code in this plan, treated differently:**

1. **Pure logic** (`crypto/wire.rs`, `crypto/recovery.rs`, envelope dispatch, wrap selection, migration filtering, repositories, server functions). The plan gives exact code and exact tests. Write it as given; if it does not compile, fix it and say so in your report.
2. **Browser-API glue** (`crypto/subtle.rs`, `crypto/keystore.rs`, the PRF read in `webauthn_browser.rs`). The plan gives the *contract*, the equivalent JavaScript, and points at the existing Rust idiom to copy. **You write the binding code.** Do not treat the JavaScript as something to transliterate blindly — verify each call against the real signature and make it compile. Report anything where the plan's JS was wrong.

**Async effects take a `Generation` token.** Every async effect in this codebase — `hook::use_persistent`, the week range load, the calendar dot fetch — guards against out-of-order resolution with `storage::Generation`. Any new async effect does too. Sign-in and sign-out flip state mid-flight; this is not theoretical.

**No subagents.** Implementers do not dispatch subagents, helpers, or reviewers. Review arrives from the controller after your report.

---

## File Structure

**New:**

| File | Responsibility |
|---|---|
| `migrations/2026-09-05-000001_entry_key/{up,down}.sql` | `user.encrypted_at`, `entry_key_wrap` table |
| `src/entry_key/mod.rs` | Module root, `WrapKind` |
| `src/entry_key/store.rs` | Diesel repository for `entry_key_wrap` + `encrypted_at` |
| `src/crypto/mod.rs` | `SessionKey` handle, ceremony orchestration |
| `src/crypto/wire.rs` | Envelope v2 format, constants, base64 — **pure** |
| `src/crypto/recovery.rs` | Recovery-code generation, format, normalization — **pure** |
| `src/crypto/subtle.rs` | `SubtleCrypto` calls — browser only |
| `src/crypto/keystore.rs` | IndexedDB storage of the non-extractable key — browser only |
| `src/encryption_ctx.rs` | `EncryptionState`, `EncryptionCtx`, the post-hydration probe |
| `src/server_fns/encryption.rs` | Status, wraps, enable, add-wrap, replace-recovery |
| `src/components/unlock.rs` | The locked-state prompt (passkey / recovery code) |
| `src/components/encryption_panel.rs` | `/account`'s enable + manage UI |

**Modified:** `Cargo.toml`, `src/schema.rs`, `src/lib.rs`, `src/storage/envelope.rs`, `src/storage/mod.rs`, `src/webauthn_browser.rs`, `src/server_fns/{mod,entries,passkey}.rs`, `src/components/account_page.rs`, `src/app.rs`, `src/test_support.rs`, `README.md`, `CLAUDE.md`.

**Task dependency order.** Tasks 2 and 3 are pure and independent of everything; they can be batched. Task 4 needs 2. Tasks 5–7 need 2. Task 12 needs 4 and 7. Tasks 13–17 need 12.

---

## Task 1: Dependencies, migration, and the wrap repository

**Files:**
- Modify: `Cargo.toml`
- Create: `migrations/2026-09-05-000001_entry_key/up.sql`, `down.sql`
- Modify: `src/schema.rs`
- Create: `src/entry_key/mod.rs`, `src/entry_key/store.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `entry_key::WrapKind`, `entry_key::store::{WrapRow, set_encrypted, is_encrypted, insert_wrap, list_wraps, delete_wrap_for_credential, replace_recovery_wrap, passkey_wrap_count}`

- [ ] **Step 1: Add dependencies**

In `Cargo.toml`, add `"dep:base64"` to the **`hydrate`** feature list (it is currently only in `ssr`; the browser now needs it for envelope v2).

Add these `web-sys` features for IndexedDB:

```toml
  "IdbFactory",
  "IdbOpenDbRequest",
  "IdbDatabase",
  "IdbTransaction",
  "IdbTransactionMode",
  "IdbObjectStore",
  "IdbRequest",
  "IdbVersionChangeEvent",
  "Event",
  "EventTarget",
  "DomException",
```

Add to `[dev-dependencies]`, with this comment:

```toml
# Host-side second implementation of the wire format. WebCrypto exists only
# in a browser and this project has no wasm test runner, so these let an
# ordinary `cargo test` decrypt an envelope the browser would have written
# and produce one the browser must be able to read — pinning nonce
# placement, tag inclusion, base64 alphabet and HKDF inputs against a
# different implementation rather than against ourselves (spec section 10).
aes-gcm = "0.10"
aes-kw = "0.2"
hkdf = "0.12"
sha2 = "0.10"
```

Do **not** add these as normal dependencies. They must not reach the wasm bundle.

- [ ] **Step 2: Verify the dependency set stays OpenSSL-free**

```
cargo tree -i openssl-sys ; cargo tree -i native-tls
```

Expected: both report nothing. This project is rustls-only.

- [ ] **Step 3: Write the migration**

`migrations/2026-09-05-000001_entry_key/up.sql`:

```sql
ALTER TABLE user ADD COLUMN encrypted_at TIMESTAMP;

CREATE TABLE entry_key_wrap (
  id            INTEGER   PRIMARY KEY,
  user_id       INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  kind          TEXT      NOT NULL,
  credential_id BLOB,
  wrapped_key   BLOB      NOT NULL,
  kdf           TEXT      NOT NULL,
  wrap_alg      TEXT      NOT NULL,
  created_at    TIMESTAMP NOT NULL
);

CREATE INDEX idx_entry_key_wrap_user ON entry_key_wrap(user_id);
CREATE UNIQUE INDEX idx_entry_key_wrap_cred
  ON entry_key_wrap(user_id, credential_id) WHERE credential_id IS NOT NULL;
```

`down.sql`:

```sql
DROP TABLE entry_key_wrap;
-- SQLite before 3.35 cannot DROP COLUMN; this migration is not reversed in
-- practice, and the column is nullable so leaving it is harmless.
```

- [ ] **Step 4: Update `src/schema.rs`**

Add `encrypted_at -> Nullable<Timestamp>` to the `user` table block, and a new `entry_key_wrap` block matching the DDL. Follow the exact style of the existing `passkey_credential` block. Add `entry_key_wrap` to the `allow_tables_to_appear_in_same_query!` list if one exists.

- [ ] **Step 5: Write the failing repository tests**

`src/entry_key/store.rs`, tests module. Use the same in-memory-pool helper the existing repositories use — read `src/passkey/store.rs`'s test module and copy its setup exactly.

```rust
#[test]
fn account_starts_unencrypted() {
    let (mut conn, uid) = seed();
    assert!(!is_encrypted(&mut conn, uid).expect("query"));
}

#[test]
fn enabling_marks_the_account_and_stores_both_wraps() {
    let (mut conn, uid) = seed();
    set_encrypted(&mut conn, uid).expect("mark");
    insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("passkey");
    insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[9; 40]).expect("recovery");

    assert!(is_encrypted(&mut conn, uid).expect("query"));
    let wraps = list_wraps(&mut conn, uid).expect("list");
    assert_eq!(wraps.len(), 2);
    assert_eq!(passkey_wrap_count(&mut conn, uid).expect("count"), 1);
}

/// The wrap is what makes a credential able to unlock. Two rows for the same
/// credential would mean an ambiguous unwrap route.
#[test]
fn one_wrap_per_credential() {
    let (mut conn, uid) = seed();
    insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("first");
    assert!(insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[8; 40]).is_err());
}

/// Two accounts may hold the same credential id without colliding — the
/// unique index is per user, not global.
#[test]
fn the_credential_index_is_scoped_to_one_user() {
    let (mut conn, a) = seed();
    let b = seed_another_user(&mut conn);
    insert_wrap(&mut conn, a, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("a");
    insert_wrap(&mut conn, b, WrapKind::Passkey, Some(b"cred-1"), &[8; 40]).expect("b");
}

/// Several recovery rows would make "which one does the code open?"
/// ambiguous. Re-issuing replaces rather than accumulates.
#[test]
fn replacing_the_recovery_wrap_leaves_exactly_one() {
    let (mut conn, uid) = seed();
    insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("first");
    replace_recovery_wrap(&mut conn, uid, &[2; 40]).expect("replace");

    let recovery: Vec<_> = list_wraps(&mut conn, uid)
        .expect("list")
        .into_iter()
        .filter(|w| w.kind == WrapKind::Recovery)
        .collect();
    assert_eq!(recovery.len(), 1);
    assert_eq!(recovery[0].wrapped_key, vec![2; 40]);
}

#[test]
fn deleting_a_credential_wrap_removes_only_that_one() {
    let (mut conn, uid) = seed();
    insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("one");
    insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-2"), &[8; 40]).expect("two");
    delete_wrap_for_credential(&mut conn, uid, b"cred-1").expect("delete");

    let wraps = list_wraps(&mut conn, uid).expect("list");
    assert_eq!(wraps.len(), 1);
    assert_eq!(wraps[0].credential_id.as_deref(), Some(&b"cred-2"[..]));
}

/// The user row owns the flag, so deleting the user must not strand wraps.
#[test]
fn wraps_cascade_with_the_user() {
    let (mut conn, uid) = seed();
    insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("wrap");
    delete_user(&mut conn, uid).expect("delete user");
    assert!(list_wraps(&mut conn, uid).expect("list").is_empty());
}
```

`wraps_cascade_with_the_user` only passes if `PRAGMA foreign_keys=ON` is applied by the pool customizer. It is (see `src/db.rs`), and this test pins that it stays on.

- [ ] **Step 6: Run the tests, confirm they fail**

```
cargo test --features ssr --no-default-features --lib entry_key::
```

Expected: compilation failure — the module does not exist yet.

- [ ] **Step 7: Implement `src/entry_key/mod.rs`**

```rust
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
```

Add a round-trip test for `as_str`/`parse` covering both variants and one unknown string.

- [ ] **Step 8: Implement `src/entry_key/store.rs`**

Model it on `src/passkey/store.rs` — same `DbConn` alias, same `anyhow::Result`, same insertable/queryable struct split. Constants for the labels:

```rust
/// Recorded per row for the same reason the envelope carries `alg`: a future
/// change becomes a new value rather than a guess about old rows.
const KDF: &str = "hkdf-sha256";
const WRAP_ALG: &str = "aeskw256";
```

`WrapRow` is the public read shape: `{ kind: WrapKind, credential_id: Option<Vec<u8>>, wrapped_key: Vec<u8>, kdf: String, wrap_alg: String }`.

`replace_recovery_wrap` deletes then inserts **inside one transaction**. Diesel's transaction closure needs an explicit error type annotation or it fails with E0283 — write `conn.transaction::<_, diesel::result::Error, _>(|conn| { ... })`.

Remember `use diesel::prelude::*;` — a missing `RunQueryDsl` is the single most common compile error in this codebase's repositories.

- [ ] **Step 9: Register the module**

Add `pub mod entry_key;` to `src/lib.rs`, gated `#[cfg(feature = "ssr")]` if the neighbouring repository modules are (check `src/passkey`'s registration and match it).

- [ ] **Step 10: Run the tests**

```
cargo test --features ssr --no-default-features --lib entry_key::
```

Expected: PASS.

- [ ] **Step 11: Full verification**

Run all four Global Constraints commands. All clean.

- [ ] **Step 12: Commit**

```bash
git add Cargo.toml migrations src/schema.rs src/entry_key src/lib.rs
git commit -m "feat: entry_key_wrap schema and repository"
```

---

## Task 2: `crypto::wire` — the envelope v2 format

**Files:**
- Create: `src/crypto/mod.rs` (module declarations only for now), `src/crypto/wire.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `crypto::wire::{APP_SALT, INFO_PASSKEY, INFO_RECOVERY, ALG_V2, NONCE_LEN, WRAPPED_KEY_LEN, V2, Sealed, encode_v2, decode_v2, WireError}`

This module is **pure** — no `web_sys`, no `wasm_bindgen`. Gate it `#[cfg(any(feature = "hydrate", feature = "ssr", test))]`, i.e. do not gate it at all; it must compile everywhere so host tests can reach it.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Spec E6. These bytes are load-bearing: changing any of them makes
    /// every existing wrapped key unopenable, with no error that says so.
    /// This test exists to make that change impossible to do by accident.
    #[test]
    fn derivation_inputs_are_pinned() {
        assert_eq!(INFO_PASSKEY, b"tt/entry-kek/passkey/v1");
        assert_eq!(INFO_RECOVERY, b"tt/entry-kek/recovery/v1");
        assert_eq!(ALG_V2, "a256gcm");
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(WRAPPED_KEY_LEN, 40);

        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"time-tracking-leptos/entry-key/v1");
        assert_eq!(APP_SALT, expected.as_slice());
    }

    #[test]
    fn v2_round_trips() {
        let sealed = Sealed { nonce: vec![3; NONCE_LEN], ciphertext: b"abc".to_vec() };
        let decoded = decode_v2(&encode_v2(&sealed)).expect("round trip");
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn v2_shape_is_pinned() {
        let raw = encode_v2(&Sealed { nonce: vec![0; NONCE_LEN], ciphertext: vec![1, 2, 3] });
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(v["v"], 2);
        assert_eq!(v["alg"], "a256gcm");
        assert!(v["n"].is_string());
        assert!(v["ct"].is_string());
        assert!(v.get("body").is_none(), "v2 must not carry a plaintext body field");
    }

    #[test]
    fn a_wrong_nonce_length_is_rejected() {
        let raw = r#"{"v":2,"alg":"a256gcm","n":"AAAA","ct":"AAAA"}"#;
        assert!(matches!(decode_v2(raw), Err(WireError::NonceLength(3))));
    }

    #[test]
    fn a_foreign_algorithm_is_rejected() {
        let raw = format!(
            r#"{{"v":2,"alg":"rot13","n":"{}","ct":"AAAA"}}"#,
            base64_of(&[0u8; NONCE_LEN])
        );
        assert!(matches!(decode_v2(&raw), Err(WireError::UnsupportedAlg(_))));
    }

    #[test]
    fn non_base64_is_rejected() {
        let raw = r#"{"v":2,"alg":"a256gcm","n":"!!!!","ct":"AAAA"}"#;
        assert!(matches!(decode_v2(raw), Err(WireError::Base64(_))));
    }
}
```

- [ ] **Step 2: Write the cross-implementation tests**

This is the load-bearing part of the whole plan's test strategy. It proves the format the browser will produce is the format a *different* AES-GCM implementation reads, and vice versa. Put it in the same tests module:

```rust
    /// The browser's WebCrypto is not available here, so a second, independent
    /// AES-256-GCM implementation stands in for it. If our nonce placement,
    /// tag handling or base64 alphabet were wrong, these would fail — which is
    /// exactly the class of bug that would otherwise only appear in a browser
    /// against real user data (spec section 10).
    mod cross_implementation {
        use super::*;
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        fn cipher() -> Aes256Gcm {
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[42u8; 32]))
        }

        /// WebCrypto's `encrypt` returns `ciphertext ‖ tag` as one buffer, and
        /// `aes-gcm`'s `encrypt` produces the same layout. An envelope built
        /// from one must decrypt with the other.
        #[test]
        fn an_envelope_we_encode_decrypts_with_a_second_implementation() {
            let nonce = [7u8; NONCE_LEN];
            let ct = cipher()
                .encrypt(Nonce::from_slice(&nonce), b"11:45-12:15 code1".as_ref())
                .expect("encrypt");

            let raw = encode_v2(&Sealed { nonce: nonce.to_vec(), ciphertext: ct });
            let decoded = decode_v2(&raw).expect("decode");

            let plain = cipher()
                .decrypt(Nonce::from_slice(&decoded.nonce), decoded.ciphertext.as_ref())
                .expect("decrypt");
            assert_eq!(plain, b"11:45-12:15 code1");
        }

        /// A tampered ciphertext must fail authentication, not decrypt to
        /// something. This is what makes a corrupted or substituted row a loud
        /// error rather than silent garbage on screen.
        #[test]
        fn tampering_is_detected() {
            let nonce = [7u8; NONCE_LEN];
            let mut ct = cipher()
                .encrypt(Nonce::from_slice(&nonce), b"secret".as_ref())
                .expect("encrypt");
            ct[0] ^= 0x01;

            let decoded = decode_v2(&encode_v2(&Sealed { nonce: nonce.to_vec(), ciphertext: ct }))
                .expect("decode");
            assert!(
                cipher()
                    .decrypt(Nonce::from_slice(&decoded.nonce), decoded.ciphertext.as_ref())
                    .is_err()
            );
        }

        /// HKDF with our exact salt and info strings, against the RustCrypto
        /// implementation. If `APP_SALT` or an info string drifted, the derived
        /// KEK would change and every stored wrap would stop opening — this
        /// pins the derivation, not just the constants.
        #[test]
        fn passkey_and_recovery_derivations_differ_and_are_stable() {
            use hkdf::Hkdf;
            use sha2::Sha256;

            let ikm = [1u8; 32];
            let derive = |info: &[u8]| {
                let mut out = [0u8; 32];
                Hkdf::<Sha256>::new(Some(APP_SALT), &ikm)
                    .expand(info, &mut out)
                    .expect("expand");
                out
            };

            let passkey = derive(INFO_PASSKEY);
            let recovery = derive(INFO_RECOVERY);
            assert_ne!(passkey, recovery, "the two routes must not share a KEK");

            // Pinned so a change to APP_SALT or the info strings fails loudly
            // here rather than silently in a browser.
            assert_eq!(hex_of(&passkey).len(), 64);
        }
    }
```

Add small `base64_of` / `hex_of` test helpers.

The `assert_eq!(hex_of(&passkey).len(), 64)` line is a placeholder for a real golden value: **once the test runs, replace it with the actual derived hex string** so the derivation is pinned to an exact output. Paste the real value into your report.

- [ ] **Step 3: Run, confirm failure**

```
cargo test --features ssr --no-default-features --lib crypto::wire
```

Expected: compilation failure.

- [ ] **Step 4: Implement `src/crypto/wire.rs`**

```rust
//! The on-the-wire shapes and the constants that derive keys.
//!
//! Pure by design: no `web_sys`, no `wasm_bindgen`. WebCrypto exists only in
//! a browser and this project has no wasm test runner, so everything that can
//! be decided without a browser lives here where `cargo test` can reach it
//! (spec section 10).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Envelope version written by this build.
pub const V2: u8 = 2;
/// The only body algorithm this build understands.
pub const ALG_V2: &str = "a256gcm";
/// AES-GCM nonce length, in bytes. Fresh per write, never reused.
pub const NONCE_LEN: usize = 12;
/// AES-KW of a 256-bit key.
pub const WRAPPED_KEY_LEN: usize = 40;

/// HKDF `info` for the passkey-PRF route.
pub const INFO_PASSKEY: &[u8] = b"tt/entry-kek/passkey/v1";
/// HKDF `info` for the recovery-code route.
pub const INFO_RECOVERY: &[u8] = b"tt/entry-kek/recovery/v1";

/// HKDF salt: SHA-256 of `time-tracking-leptos/entry-key/v1`.
///
/// A constant rather than a per-account value, and that is deliberate. The
/// PRF secret is already per-credential, so the salt only separates this
/// application and this purpose from others. A per-account salt would have to
/// be fetched before the assertion, and at sign-in the account is not yet
/// known — the discoverable flow identifies the user *from* the assertion.
/// That would cost the one-gesture unlock to buy nothing (spec section 4.2).
pub const APP_SALT: &[u8; 32] = &[/* filled in at Step 5 */];
```

**Step 5 fills `APP_SALT`.** Write it as an explicit 32-byte array literal, not a runtime hash — it must be a `const`. Compute the value with:

```
printf 'time-tracking-leptos/entry-key/v1' | sha256sum
```

then transcribe the bytes. `derivation_inputs_are_pinned` re-derives it with `sha2` and will catch a transcription error.

The rest of the module:

```rust
/// A nonce and the AES-GCM output that goes with it. WebCrypto returns
/// `ciphertext ‖ tag` as a single buffer, so `ciphertext` includes the tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("envelope is not valid JSON: {0}")]
    Malformed(String),
    #[error("field `{0}` is not valid base64")]
    Base64(String),
    #[error("nonce is {0} bytes, expected 12")]
    NonceLength(usize),
    #[error("algorithm `{0}` is not supported by this build")]
    UnsupportedAlg(String),
}

pub fn encode_v2(sealed: &Sealed) -> String { /* serde_json of the v2 shape */ }

pub fn decode_v2(raw: &str) -> Result<Sealed, WireError> { /* validate alg, base64, nonce len */ }
```

`decode_v2` validates in this order: JSON parse, `alg` match, base64 of both fields, nonce length. Order matters for which error a caller sees.

- [ ] **Step 5: Register the module**

`src/crypto/mod.rs`:

```rust
//! Client-side encryption of entry bodies.
//!
//! See `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`.

pub mod wire;
```

Add `pub mod crypto;` to `src/lib.rs`, **ungated** — `wire` must compile on both targets and under plain `cargo test`.

- [ ] **Step 6: Run the tests, replace the golden value**

```
cargo test --features ssr --no-default-features --lib crypto::wire
```

Expected: PASS. Replace the placeholder assertion from Step 2 with the real derived hex and re-run.

- [ ] **Step 7: Full verification, then commit**

```bash
git add src/crypto src/lib.rs
git commit -m "feat: envelope v2 wire format and derivation constants"
```

---

## Task 3: `crypto::recovery` — the recovery code

**Files:**
- Create: `src/crypto/recovery.rs`
- Modify: `src/crypto/mod.rs`

**Interfaces:**
- Consumes: nothing
- Produces: `crypto::recovery::{CODE_BYTES, CODE_CHARS, format_code, normalize, RecoveryError}`

Pure, ungated, host-tested. The randomness is **injected**, not read from the environment, so generation is testable.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twenty_bytes_become_thirty_two_characters_in_eight_groups() {
        let code = format_code(&[0xAB; CODE_BYTES]);
        assert_eq!(code.len(), CODE_CHARS + 7, "32 chars plus 7 hyphens");
        assert_eq!(code.matches('-').count(), 7);
        for group in code.split('-') {
            assert_eq!(group.len(), 4);
        }
    }

    #[test]
    fn formatting_is_deterministic_and_reversible() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
        let code = format_code(&bytes);
        assert_eq!(normalize(&code).expect("normalize"), bytes.to_vec());
    }

    /// The user reads this off a screen and types it on another device.
    /// Every one of these is a realistic transcription, and all must work.
    #[test]
    fn normalization_accepts_realistic_transcriptions() {
        let bytes = [7u8; CODE_BYTES];
        let canonical = format_code(&bytes);
        let stripped = canonical.replace('-', "");

        for variant in [
            canonical.clone(),
            stripped.clone(),
            stripped.to_lowercase(),
            format!("  {canonical}  "),
            canonical.replace('-', " "),
        ] {
            assert_eq!(
                normalize(&variant).expect(&format!("{variant:?} should normalize")),
                bytes.to_vec()
            );
        }
    }

    /// Crockford base32 folds the characters people confuse. Someone reading
    /// `0` as `O` must still get in.
    #[test]
    fn crockford_aliases_are_folded() {
        let with_zero = "0000-0000-0000-0000-0000-0000-0000-0000";
        let with_oh = "OOOO-OOOO-OOOO-OOOO-OOOO-OOOO-OOOO-OOOO";
        assert_eq!(normalize(with_zero).expect("zero"), normalize(with_oh).expect("oh"));

        let with_one = "1111-1111-1111-1111-1111-1111-1111-1111";
        for alias in ["IIII", "LLLL", "iiii", "llll"] {
            let candidate = vec![alias; 8].join("-");
            assert_eq!(
                normalize(&candidate).expect("alias"),
                normalize(with_one).expect("one"),
            );
        }
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(matches!(normalize("ABCD"), Err(RecoveryError::Length(4))));
        let too_long = format!("{}A", "0".repeat(CODE_CHARS));
        assert!(matches!(normalize(&too_long), Err(RecoveryError::Length(33))));
    }

    #[test]
    fn characters_outside_the_alphabet_are_rejected() {
        let bad = format!("U{}", "0".repeat(CODE_CHARS - 1));
        assert!(matches!(normalize(&bad), Err(RecoveryError::Character('U'))));
    }

    /// 160 bits. Anything less and the "no rate limiting needed" argument in
    /// the spec stops holding.
    #[test]
    fn the_code_carries_one_hundred_and_sixty_bits() {
        assert_eq!(CODE_BYTES * 8, 160);
    }
}
```

Note `U` is deliberately excluded from Crockford base32 (it is excluded to avoid accidental obscenities); it is the right character to test rejection with.

- [ ] **Step 2: Run, confirm failure**

- [ ] **Step 3: Implement**

```rust
//! The recovery code: 160 random bits, Crockford base32, eight groups of four.
//!
//! No checksum. AES-KW's unwrap is authenticated, so a wrong code fails to
//! open the wrap and cannot produce a false positive — a checksum would be a
//! second thing to get wrong for no gain (spec section 9.2).
//!
//! Generation takes its randomness as an argument rather than reading it from
//! the browser, so the formatting is testable on the host. The caller passes
//! bytes from `crypto.getRandomValues`.

/// Bytes of entropy in a code. 20 bytes = 160 bits.
pub const CODE_BYTES: usize = 20;
/// Characters in a normalized code. 160 bits / 5 bits per symbol.
pub const CODE_CHARS: usize = 32;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
```

`format_code(bytes: &[u8; CODE_BYTES]) -> String` packs 160 bits into 32 five-bit symbols, most-significant bit first, and joins groups of four with `-`.

`normalize(input: &str) -> Result<Vec<u8>, RecoveryError>` strips whitespace and `-`, uppercases, maps `I`/`L`→`1` and `O`→`0`, checks the length is exactly `CODE_CHARS`, maps each character through `ALPHABET` (rejecting anything absent), and repacks to 20 bytes.

The bit packing is the one place this task can silently go wrong — `formatting_is_deterministic_and_reversible` is the test that catches it. Make sure it passes before moving on.

- [ ] **Step 4: Register in `src/crypto/mod.rs`, run tests, full verification, commit**

```bash
git commit -m "feat: recovery code format and normalization"
```

---

## Task 4: Envelope v2 dispatch

**Files:**
- Modify: `src/storage/envelope.rs`

**Interfaces:**
- Consumes: `crypto::wire::{Sealed, encode_v2, decode_v2, WireError}`
- Produces: `envelope::{Plan, plan_read, wrap_v1, ReadPlan}` — the pure dispatch layer. The async, key-taking `wrap`/`unwrap` arrive in Task 12, once `SessionKey` exists.

Keeping this task pure and synchronous is deliberate: version dispatch is the invariant partial migration rests on (spec E3), and it is fully testable here. Task 12 wires it to the key.

- [ ] **Step 1: Write the failing tests**

Replace `unknown_version_is_an_error` — its `v: 2` fixture is now *readable*. Version 3 takes over as the unknown case. **Do not delete the test; re-point it**, and add a comment saying v2 became readable in phase 2.

```rust
/// Spec E3. Dispatch is on the row's own version, never on account state.
/// A partially migrated account holds both shapes at once and every row must
/// read correctly — this is the whole reason the migration is resumable.
#[test]
fn a_v1_row_reads_as_plaintext_even_when_v2_rows_exist() {
    let v1 = wrap_v1("11:45-12:15 code1");
    assert!(matches!(plan_read(&v1), Ok(ReadPlan::Plaintext(body)) if body == "11:45-12:15 code1"));
}

#[test]
fn a_v2_row_reads_as_ciphertext_needing_the_key() {
    let raw = crate::crypto::wire::encode_v2(&Sealed {
        nonce: vec![0; NONCE_LEN],
        ciphertext: vec![9, 9, 9],
    });
    let ReadPlan::Sealed(sealed) = plan_read(&raw).expect("plan") else {
        panic!("v2 must plan as Sealed");
    };
    assert_eq!(sealed.ciphertext, vec![9, 9, 9]);
}

/// The forward-compatibility guarantee phase 1 shipped, still holding one
/// version further out: an envelope this build cannot read is a loud error,
/// never rendered as if it were text.
#[test]
fn an_unknown_future_version_is_still_an_error() {
    let v3 = r#"{"v":3,"alg":"something-new","x":"AA"}"#;
    assert!(matches!(plan_read(v3), Err(EnvelopeError::UnsupportedVersion(3))));
}

#[test]
fn a_v1_row_with_a_foreign_algorithm_is_an_error() {
    let odd = r#"{"v":1,"alg":"rot13","body":"x"}"#;
    assert!(matches!(plan_read(odd), Err(EnvelopeError::UnsupportedAlg(_))));
}

#[test]
fn malformed_json_is_an_error() {
    assert!(matches!(plan_read("not json"), Err(EnvelopeError::Malformed(_))));
}

/// `Some("")` is a real state in the hydration tri-state — "loaded, nothing
/// saved" — and must survive distinctly from absence.
#[test]
fn an_empty_v1_body_round_trips() {
    assert!(matches!(plan_read(&wrap_v1("")), Ok(ReadPlan::Plaintext(b)) if b.is_empty()));
}
```

- [ ] **Step 2: Run, confirm failure**

- [ ] **Step 3: Implement the dispatch**

```rust
/// What a stored envelope turns out to be, before any key is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPlan {
    /// A v1 row. The body is right here.
    Plaintext(String),
    /// A v2 row. Needs the session key to open.
    Sealed(crate::crypto::wire::Sealed),
}

/// Decides what a stored string is, without needing a key.
///
/// Dispatch is on the row's own `v`, never on whether the account has
/// encryption enabled. That is what makes a half-finished migration safe to
/// read rather than corrupting (spec E3).
pub fn plan_read(raw: &str) -> Result<ReadPlan, EnvelopeError> { ... }
```

Parse the JSON once into a `serde_json::Value`, read `v`, then branch: `1` deserializes the existing `Envelope` struct and checks `alg == "none"`; `2` delegates to `wire::decode_v2` (mapping `WireError` into a new `EnvelopeError::Wire` variant); anything else is `UnsupportedVersion`.

Rename the existing `wrap` to `wrap_v1` and keep it unchanged. Keep `unwrap` for now as a thin wrapper over `plan_read` that errors on `Sealed` — Task 12 removes it. Add a `#[deprecated]`-style comment rather than an attribute (an attribute would fail `-D warnings` at its existing call sites).

- [ ] **Step 4: Run tests, full verification, commit**

```bash
git commit -m "feat: envelope v2 dispatch, v3 becomes the unknown version"
```

---

## Task 5: `crypto::subtle` — the WebCrypto shell

**Files:**
- Create: `src/crypto/subtle.rs`
- Modify: `src/crypto/mod.rs`

**Interfaces:**
- Consumes: `crypto::wire::{APP_SALT, INFO_PASSKEY, INFO_RECOVERY, NONCE_LEN, Sealed}`
- Produces: the functions in the contract table below.

**This is browser-API glue.** The plan gives the contract and the equivalent JavaScript. You write and compile the Rust. Gate the whole module `#[cfg(feature = "hydrate")]`.

**Copy the idiom from `src/webauthn_browser.rs`'s `browser` module** — it already does exactly this shape of work against `navigator.credentials`: `js_sys::Reflect::get` to reach a method, `dyn_into::<Function>()`, `call1`, `dyn_into::<js_sys::Promise>()`, `JsFuture::from(promise).await`. Read it first and match it. Do **not** invent a different style.

- [ ] **Step 1: Read the reference implementation**

Read `src/webauthn_browser.rs` lines 95–215 in full before writing anything. Note `method()`, `classify()`, and how errors become a typed enum rather than a `JsValue`.

- [ ] **Step 2: Define the error type and the handle**

```rust
/// A WebCrypto operation failed. The `String` is for the log, never for the
/// user — callers map this to a human sentence themselves.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

/// A live, non-extractable AES-256-GCM key. Cloneable because `CryptoKey` is
/// a JS handle; cloning duplicates the handle, not the key material.
#[derive(Clone)]
pub struct DataKey(pub(crate) js_sys::Object);
```

- [ ] **Step 3: Implement against this contract**

| Rust | Equivalent JavaScript |
|---|---|
| `random_bytes(n: usize) -> Result<Vec<u8>, CryptoError>` | `crypto.getRandomValues(new Uint8Array(n))` |
| `generate_dek_extractable() -> Result<Object, CryptoError>` | `crypto.subtle.generateKey({name:"AES-GCM",length:256}, true, ["encrypt","decrypt"])` |
| `import_dek_non_extractable(raw: &[u8]) -> Result<DataKey, CryptoError>` | `crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"])` |
| `derive_kek(ikm: &[u8], info: &[u8]) -> Result<Kek, CryptoError>` | `const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);`<br>`await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt:APP_SALT,info}, k, {name:"AES-KW",length:256}, false, ["wrapKey","unwrapKey"])` |
| `wrap_dek(dek: &RawDataKey, kek: &Kek) -> Result<Vec<u8>, CryptoError>` | `crypto.subtle.wrapKey("raw", dek, kek, "AES-KW")` → 40 bytes. Throws `InvalidAccessError` unless the wrapped key is extractable — which is why it takes `RawDataKey`. |
| `unwrap_dek_sealed(wrapped: &[u8], kek: &Kek) -> Result<DataKey, CryptoError>` and `unwrap_dek_raw(..) -> Result<RawDataKey, CryptoError>` | `crypto.subtle.unwrapKey("raw", wrapped, kek, "AES-KW", {name:"AES-GCM",length:256}, extractable, ["encrypt","decrypt"])` |
| `export_raw(key: &RawDataKey) -> Result<Vec<u8>, CryptoError>` | `crypto.subtle.exportKey("raw", key)`. Needed by §6.1 step 6 as well as §6.5 — an earlier draft of this plan said 6.5 only, and that was wrong. |
| `seal(dek: &DataKey, plaintext: &str) -> Result<Sealed, CryptoError>` | fresh 12-byte nonce, then `crypto.subtle.encrypt({name:"AES-GCM",iv:nonce}, dek, utf8)` |
| `open(dek: &DataKey, sealed: &Sealed) -> Result<String, CryptoError>` | `crypto.subtle.decrypt({name:"AES-GCM",iv:sealed.nonce}, dek, sealed.ciphertext)` then UTF-8 |

**Constraints that are easy to get wrong — check each:**

- **Superseded by the implementation, which is better than this plan was.** The original design guarded extractability with a `bool`, then an `Extractable` enum. Review replaced both with newtypes: `DataKey` (sealed), `RawDataKey` (extractable), `Kek`. Choosing wrongly is now a compile error rather than something a reader must notice, and `DataKey::from_object` additionally reads the key's own `extractable` property back and refuses anything but `false` — the only mechanical guard on spec E5 available without a wasm test runner.
- `derive_kek`'s `salt` is `APP_SALT` — pass the constant, never a fresh random value.
- `seal` generates a **new** nonce per call. Never accept one as a parameter; that is how nonce reuse happens.
- `open` must map a decryption failure to `CryptoError`, not panic. A failed GCM authentication is an expected outcome (wrong key, tampered row), not a bug.
- Byte arrays cross into JS as `js_sys::Uint8Array::from(slice)`. Reading back: `js_sys::Uint8Array::new(&array_buffer).to_vec()`.

- [ ] **Step 4: Verify it compiles for wasm**

```
cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings
```

This is the only compile check that reaches this module. It must be clean.

- [ ] **Step 5: Add a module doc comment naming what is untested**

```rust
//! The `SubtleCrypto` calls.
//!
//! **Not covered by any automated test.** WebCrypto exists only in a browser
//! and this project has no wasm test runner. Everything decidable without a
//! browser was pushed into `crypto::wire` and `crypto::recovery`, which are
//! host-tested; what is left here is the calls themselves. The wire format
//! they produce *is* pinned, by `wire`'s cross-implementation tests against
//! the `aes-gcm` crate — so a format error fails on the host. What only a
//! browser can catch is a wrong argument to `deriveKey` or a wrong
//! `extractable` flag. Review this file by reading it (spec section 10).
```

- [ ] **Step 6: Full verification, commit**

```bash
git commit -m "feat: WebCrypto shell for key derivation, wrapping and sealing"
```

---

## Task 6: `crypto::keystore` — per-device key storage

**Files:**
- Create: `src/crypto/keystore.rs`
- Modify: `src/crypto/mod.rs`

**Interfaces:**
- Consumes: `crypto::subtle::{DataKey, CryptoError}`
- Produces: `keystore::{put, get, clear}`

Browser-API glue again — contract here, code from you. Gate `#[cfg(feature = "hydrate")]`.

- [ ] **Step 1: Implement against this contract**

```rust
/// Stores the unlocked key for this device.
pub async fn put(user: &str, key: &DataKey) -> Result<(), CryptoError>;

/// Reads it back, if one is stored **for this user**.
pub async fn get(user: &str) -> Result<Option<DataKey>, CryptoError>;

/// Forgets it. Called on sign-out and on "Lock now".
pub async fn clear() -> Result<(), CryptoError>;
```

Database `tt-keys`, version 1, object store `keys`, one record under key `"dek"` holding `{ user: <string>, key: <CryptoKey> }`.

Equivalent JavaScript:

```js
const db = await new Promise((res, rej) => {
  const r = indexedDB.open("tt-keys", 1);
  r.onupgradeneeded = () => r.result.createObjectStore("keys");
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const tx = db.transaction("keys", "readwrite");
tx.objectStore("keys").put({ user, key }, "dek");
```

**Constraints:**

- A `CryptoKey` is structured-cloneable, so a **non-extractable** key survives the round trip and stays non-extractable. This is the whole reason IndexedDB is used rather than `localStorage`, which can only hold strings and would therefore require extractable key bytes. Say so in the module doc.
- `get` compares the stored `user` against the argument and returns `Ok(None)` on mismatch, **discarding the record**. A second account signing in on the same browser must not inherit the first account's key — that would surface as decryption failures that look like data corruption.
- IndexedDB is event-based, not promise-based. Bridge with `wasm_bindgen::closure::Closure` and a `js_sys::Promise`; `web_sys::IdbOpenDbRequest` has `set_onsuccess` / `set_onerror` / `set_onupgradeneeded`. Keep each closure alive until it fires (`Closure::once_into_js`, or hold it in the promise's scope).
- Every failure path returns `Ok(None)` or `Err`, never panics. A private window, cleared site data, or a browser with IndexedDB disabled must degrade to `Locked`, not a blank page.

- [ ] **Step 2: Module doc naming what is untested**

Same shape as Task 5 Step 5: this is inspection-only, and say which decision above it *is* tested (none — but the user-mismatch rule is worth stating as the thing a reviewer must check by eye).

- [ ] **Step 3: Wasm clippy clean, full verification, commit**

```bash
git commit -m "feat: per-device keystore for the non-extractable data key"
```

---

## Task 7: `crypto::mod` — `SessionKey` and the ceremonies

**Files:**
- Modify: `src/crypto/mod.rs`

**Interfaces:**
- Consumes: everything from Tasks 2, 3, 5, 6
- Produces: `crypto::{SessionKey, WrapRoute, choose_route, enable, unlock_with_prf, unlock_with_recovery, add_passkey_route, reissue_recovery}`

The orchestration layer. The **route-selection decision is pure and must be host-tested**; the rest is browser-bound.

- [ ] **Step 1: Write the failing test for the pure part**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(kind: WrapKind, cred: Option<&[u8]>) -> WrapRow { ... }

    /// The credential that just asserted is the one whose wrap must be used.
    /// Picking any other passkey's wrap would derive the wrong KEK and fail
    /// to unwrap — with an error indistinguishable from a corrupt row.
    #[test]
    fn the_asserting_credential_selects_its_own_wrap() {
        let rows = vec![
            wrap(WrapKind::Passkey, Some(b"cred-a")),
            wrap(WrapKind::Passkey, Some(b"cred-b")),
            wrap(WrapKind::Recovery, None),
        ];
        let chosen = choose_route(&rows, Some(b"cred-b")).expect("route");
        assert_eq!(chosen.credential_id.as_deref(), Some(&b"cred-b"[..]));
    }

    /// A passkey enrolled before encryption was enabled, or one whose
    /// authenticator has no PRF, has no wrap. That is a clean "this passkey
    /// cannot unlock", not a fallback to someone else's wrap.
    #[test]
    fn a_credential_with_no_wrap_has_no_route() {
        let rows = vec![wrap(WrapKind::Passkey, Some(b"cred-a")), wrap(WrapKind::Recovery, None)];
        assert!(choose_route(&rows, Some(b"unknown")).is_none());
    }

    #[test]
    fn no_credential_selects_the_recovery_route() {
        let rows = vec![wrap(WrapKind::Passkey, Some(b"cred-a")), wrap(WrapKind::Recovery, None)];
        assert_eq!(choose_route(&rows, None).expect("route").kind, WrapKind::Recovery);
    }

    #[test]
    fn an_account_with_no_recovery_wrap_has_no_recovery_route() {
        let rows = vec![wrap(WrapKind::Passkey, Some(b"cred-a"))];
        assert!(choose_route(&rows, None).is_none());
    }
}
```

- [ ] **Step 2: Implement `choose_route`** — pure, no `web_sys`, gated `#[cfg(any(feature = "hydrate", test))]` so host tests reach it. Run the tests; they must pass.

- [ ] **Step 3: Implement `SessionKey`**

```rust
/// The unlocked data key for this session, plus who it belongs to.
#[derive(Clone)]
pub struct SessionKey {
    key: subtle::DataKey,
    user: String,
}

impl SessionKey {
    pub async fn seal(&self, plaintext: &str) -> Result<wire::Sealed, CryptoError>;
    pub async fn open(&self, sealed: &wire::Sealed) -> Result<String, CryptoError>;
}
```

- [ ] **Step 4: Implement the ceremonies** — each is a sequence over Tasks 5 and 6, matching spec §6:

- `enable(prf_output, user) -> Result<(SessionKey, String /* recovery code */, Vec<u8> /* passkey wrap */, Vec<u8> /* recovery wrap */)>`: generate DEK extractable; `random_bytes(CODE_BYTES)` → `format_code`; derive both KEKs; wrap twice; export raw; re-import non-extractable; `keystore::put`. **The extractable handle must not outlive this function.**
- `unlock_with_prf(prf_output, wrap, user) -> Result<SessionKey>`
- `unlock_with_recovery(code, wrap, user) -> Result<SessionKey>`: `normalize` first; a `RecoveryError` maps to a distinct error variant so the UI can say "that doesn't look like a recovery code" rather than "that code didn't work".
- `add_passkey_route(existing_route_material, new_prf_output, wraps) -> Result<Vec<u8>>`: unwrap **extractable** from an existing route, derive the new KEK, wrap, drop the extractable handle.
- `reissue_recovery(session_key_material) -> Result<(String, Vec<u8>)>`

- [ ] **Step 5: Wasm clippy clean, host tests pass, full verification, commit**

```bash
git commit -m "feat: session key and the enable/unlock/recover ceremonies"
```

---

## Task 8: PRF output from an assertion

**Files:**
- Modify: `src/webauthn_browser.rs`

**Interfaces:**
- Produces: `webauthn_browser::authenticate_with_prf(challenge_json: &str, prf_salt: &[u8]) -> Result<(String, Option<Vec<u8>>), WebauthnUserError>`

- [ ] **Step 1: Understand the two constraints before writing code**

Both are recorded in spec §7.1 and both were learned the hard way in phase 1:

1. **Set the extension on the parsed options object, in the browser** — after `parseRequestOptionsFromJSON`, not by editing the server's challenge JSON. Browser support for `prf.eval` inside the JSON parser is inconsistent. This also means `passkey_login_start` needs no server change at all.
2. **The PRF result cannot go through `JSON.stringify`.** `getClientExtensionResults().prf.results.first` is an `ArrayBuffer`, and `JSON.stringify` renders it `{}`. Read it with `Reflect::get` and copy via `js_sys::Uint8Array::new(&buf).to_vec()`. This is why the existing host-tested `prf_enabled_from_json` trick does not extend here.

- [ ] **Step 2: Refactor `invoke` to allow a post-parse hook**

`invoke` currently parses options and immediately calls. Extract the options-building so a caller can mutate the parsed `options` object before `navigator.credentials.get`. Keep `register` and `authenticate` behaviourally identical — they are covered by `tests/passkey_access.rs` and must stay passing.

- [ ] **Step 3: Implement `authenticate_with_prf`**

Equivalent JavaScript for the mutation:

```js
options.extensions = { prf: { eval: { first: new Uint8Array(prfSalt) } } };
```

and for the read:

```js
const first = cred.getClientExtensionResults()?.prf?.results?.first;  // ArrayBuffer | undefined
```

Return `Ok((credential_json, None))` when any step of the read is absent — an authenticator without PRF, or a browser that ignored the extension. **Never fail the assertion because PRF was unavailable**: this same call performs sign-in, and a user whose authenticator lacks PRF must still be able to sign in. They land in `Locked` and use their recovery code.

- [ ] **Step 4: Confirm the existing passkey tests still pass**

```
cargo test --features ssr --no-default-features --test passkey_access
```

- [ ] **Step 5: Wasm clippy clean, full verification, commit**

```bash
git commit -m "feat: read PRF output from a sign-in assertion"
```

---

## Task 9: Encryption server functions

**Files:**
- Create: `src/server_fns/encryption.rs`
- Modify: `src/server_fns/mod.rs`

**Interfaces:**
- Consumes: `entry_key::store::*` (Task 1)
- Produces: the five functions in spec §7.6

- [ ] **Step 1: Write the failing integration tests**

New file `tests/encryption_access.rs`. Model it on `tests/entry_access.rs` — same `TestApp` harness, same session-cookie helper. Read that file first.

```rust
/// Wraps are per-account key material. One user reading another's would not
/// leak the key — the wraps are opaque — but it would leak the credential
/// ids and the account's encryption state, and there is no reason to allow it.
#[tokio::test]
async fn wraps_are_scoped_to_the_signed_in_user() { ... }

#[tokio::test]
async fn enabling_twice_is_refused() { ... }

#[tokio::test]
async fn status_reports_disabled_before_enabling_and_enabled_after() { ... }

/// Spec section 6.6. A user with one passkey and a lost recovery code could
/// otherwise destroy their own data with a single click.
#[tokio::test]
async fn deleting_the_last_passkey_wrap_is_refused_while_encrypted() { ... }

#[tokio::test]
async fn deleting_a_non_last_passkey_is_allowed_and_removes_its_wrap() { ... }

/// An unauthenticated caller must reach none of this.
#[tokio::test]
async fn every_encryption_endpoint_requires_a_session() { ... }
```

For `every_encryption_endpoint_requires_a_session`: **post the correct content type.** Phase 1 shipped a uniformity test that posted `application/json` at form-urlencoded server functions, so all four probes failed deserialization before reaching the handler and the test asserted nothing for four tasks. Include a positive control — one authenticated request that succeeds — so a vacuous pass is impossible.

- [ ] **Step 2: Run, confirm failure. Step 3: Implement.**

Use `super::require_user()`, `super::log_and_fail(...)`, `super::server_err(...)` exactly as the existing server functions do. Every write is one Diesel transaction with the explicit error-type annotation.

`encryption_enable` errors if `encrypted_at` is already set — this is what makes a double-submit safe.

`encryption_add_passkey_wrap` verifies the credential belongs to the caller before inserting; a wrap for someone else's credential id would be nonsense.

- [ ] **Step 4: Tests pass, full verification, commit**

```bash
git commit -m "feat: encryption status, wrap, and enable server functions"
```

---

## Task 10: Bulk entry endpoints

**Files:**
- Modify: `src/server_fns/entries.rs`, `src/entries/repo.rs`

**Interfaces:**
- Produces: `entries_all() -> Result<Vec<(String, String)>>`, `entry_save_many(Vec<(String, String)>) -> Result<()>`

- [ ] **Step 1: Write the failing tests** in `tests/entry_access.rs`:

```rust
#[tokio::test]
async fn entries_all_returns_every_row_for_the_caller_only() { ... }

#[tokio::test]
async fn save_many_writes_every_entry_in_one_call() { ... }

/// Partial application would leave the migration in a state neither the
/// client nor the server can describe. All or nothing.
#[tokio::test]
async fn save_many_is_atomic_when_one_entry_is_rejected() { ... }

/// The same cap `entry_save` applies, applied per body. A bulk endpoint that
/// skipped it would be a way around the limit.
#[tokio::test]
async fn save_many_enforces_the_per_body_length_cap() { ... }
```

- [ ] **Step 2: Implement.** Read `entry_save`'s existing cap and reuse the identical constant — do not re-declare the number. One transaction for the whole batch.

`entries_all` has no date bounds by design (spec §8): the migration needs every row, and the alternative is a server that inspects envelope versions, which §9.1 of the phase-1 spec forbids.

- [ ] **Step 3: Tests pass, full verification, commit**

```bash
git commit -m "feat: entries_all and entry_save_many for the migration pass"
```

---

## Task 11: Storage seam threading

**Files:**
- Modify: `src/storage/mod.rs`, `src/storage/envelope.rs`, `src/storage/remote.rs`

**Interfaces:**
- Consumes: `crypto::SessionKey`, `envelope::{plan_read, ReadPlan}`
- Produces: `storage::{load, store, bodies_in_range}` taking `Option<&SessionKey>`

- [ ] **Step 1: Preserve the `'static` property of `store`**

`store` is a plain `fn` returning `impl Future`, not an `async fn`, and its doc comment says why: `value` is copied into an owned `String` **before** the `async move`, because `Persistent::set` hands the future to `spawn_local`, which requires `'static`. Spec E4.

The `envelope::wrap` call moves **inside** the async block (sealing is now async). The `let value = value.to_owned()` stays **outside** it. Keep the existing doc comment and extend it — do not delete the warning.

- [ ] **Step 2: Write the failing tests**

`unwrap_bodies` becomes async and takes the key. Its existing tests move with it. Add:

```rust
/// A row that fails to open is skipped, not fatal to the range. One corrupt
/// or foreign-key row must not blank out the whole week — the same blast
/// radius rule the phase-1 version already followed.
#[tokio::test]
async fn a_row_that_cannot_be_opened_is_skipped_not_fatal() { ... }

/// A partially migrated account. Both shapes in one range, both readable.
#[tokio::test]
async fn a_mixed_v1_and_v2_range_reads_every_row() { ... }
```

These need a `SessionKey`, which needs a browser. **Test the pure part instead:** extract the per-row decision — given a `ReadPlan` and whether a key is present, does this row yield a body, skip, or error — into a pure function and test that exhaustively. Name it and say in its doc comment that it exists to be testable.

- [ ] **Step 3: Implement.** `load` and `bodies_in_range` gain `key: Option<&SessionKey>`; `store` gains it too. `None` means the account is not encrypted: write v1, read either. `Some` means write v2, read either.

Reading a v2 row with `key == None` is `StorageError::Locked` — a new variant, distinct from `Envelope`, because the UI treats it as "unlock", not "corrupt".

- [ ] **Step 4: Update all call sites** — `hook::use_persistent`, `week_view`, `calendar`, `import_banner`. They read the key from `EncryptionCtx` (Task 12). Until Task 12 lands, pass `None` and leave a `// Task 12 threads the real key` comment.

- [ ] **Step 5: Full verification, commit**

```bash
git commit -m "feat: thread the session key through the storage seam"
```

---

## Task 12: `EncryptionCtx` and the post-hydration probe

**Files:**
- Create: `src/encryption_ctx.rs`
- Modify: `src/app.rs`, `src/lib.rs`

- [ ] **Step 1: Write the failing SSR test** in `src/app.rs`, beside the two existing negative SSR tests:

```rust
/// Spec E2. The server could read `encrypted_at` cheaply, but rendering
/// `Locked` would put user-derived state in the SSR body — and the client
/// cannot distinguish locked from unlocked without an async IndexedDB read
/// anyway, so the first client render would differ regardless. `Unknown` on
/// both sides is the only value that hydrates.
///
/// Asserts negatively, like its two neighbours. Do not weaken it to make a
/// change pass.
#[test]
fn ssr_renders_unknown_encryption_state() {
    let html = render_at_signed_in("2026-09-05", "alice@example.com");
    assert!(!html.contains("Unlock"), "SSR must not render the locked prompt");
    assert!(!html.contains("recovery code"), "SSR must not render unlock UI");
}
```

Read the existing `render_app`/`render_at` helpers first and follow their shape.

- [ ] **Step 2: Implement `EncryptionState` and `EncryptionCtx`** per spec §7.4.

- [ ] **Step 3: Implement the probe `Effect`.** It reruns on `AuthCtx::user`. Signed out → `Disabled`, no server call. Signed in → `encryption_status()`, then `keystore::get`.

**It takes a `Generation` token.** Sign-in and sign-out flip the user mid-flight and only the newest probe may publish. Every other async effect in this codebase does this; read `hook::use_persistent`'s `Effect` and copy the token-across-await pattern exactly.

- [ ] **Step 4: Provide it in `app.rs`** beside `AuthCtx`, and thread the key into the Task 11 call sites, replacing the `None` placeholders.

- [ ] **Step 5: Full verification, commit**

```bash
git commit -m "feat: EncryptionCtx and its post-hydration probe"
```

---

## Task 13: The unlock prompt

**Files:**
- Create: `src/components/unlock.rs`
- Modify: `src/components/mod.rs`, `src/app.rs`

- [ ] **Step 1:** `DayView` and `WeekView` mount the entry area only when `Disabled` or `Unlocked`. `Locked` renders `<UnlockPrompt/>`. `Unknown` renders blank — matching SSR.

Use `EitherOf3`, never `.into_any()`.

- [ ] **Step 2:** `UnlockPrompt` offers "Use a passkey" (assertion with PRF eval, via Task 8) and "Enter your recovery code". A `RecoveryError` from normalization says *"That doesn't look like a recovery code"*; a failed unwrap says *"That recovery code didn't work."* Two different sentences, because they are two different user situations.

- [ ] **Step 3:** After a successful recovery unlock, offer a freshly generated code (spec §6.4). Declining is allowed.

- [ ] **Step 4:** Full verification, commit.

```bash
git commit -m "feat: unlock prompt for locked sessions"
```

---

## Task 14: The `/account` encryption panel

**Files:**
- Create: `src/components/encryption_panel.rs`
- Modify: `src/components/account_page.rs`, `src/components/mod.rs`

- [ ] **Step 1: The enable flow** per spec §6.1. The dialog must say, in plain words, that losing every passkey *and* the recovery code means the entries are unreadable permanently — by the user and by the operator. Do not soften this.

The recovery code screen has a copy control and requires an explicit confirmation before closing. The code is never shown again.

**Warn that enabling triggers a second WebAuthn prompt** (creation does not return PRF output — only whether PRF is available), so the user is not surprised by a second biometric request.

- [ ] **Step 2: The manage view** when already encrypted: which passkeys can unlock and which cannot (`prf_capable = false` rows are labelled, not hidden), "Lock now", "Generate a new recovery code", and — when the migration is unfinished — "N days still unencrypted" with a resume control.

- [ ] **Step 3: Adding a passkey to an encrypted account** per spec §6.5. If the session is `Locked`, ask the user to unlock first rather than failing.

- [ ] **Step 4: Full verification, commit**

```bash
git commit -m "feat: encryption panel on the account page"
```

---

## Task 15: The migration pass

**Files:**
- Modify: `src/components/encryption_panel.rs`, `src/crypto/mod.rs`

- [ ] **Step 1: Write the failing test for the pure decision**

```rust
/// Resumability rests on this: the pass re-runs and simply finds fewer v1
/// rows. A row that is already v2 must never be re-encrypted — doing so
/// would decrypt-and-reseal needlessly, and a bug there would destroy data.
#[test]
fn only_v1_rows_are_selected_for_migration() { ... }

#[test]
fn an_unreadable_row_is_reported_not_silently_skipped() { ... }

#[test]
fn an_account_with_no_v1_rows_needs_no_work() { ... }
```

`rows_needing_migration(rows: &[(NaiveDate, String)]) -> MigrationPlan` is pure over `plan_read`'s output. Test it exhaustively.

- [ ] **Step 2: Implement the runner:** `entries_all()` → `rows_needing_migration` → seal each → `entry_save_many`. Show progress; report a count on completion.

- [ ] **Step 3:** A row that fails to *read* is reported to the user with its date, not skipped silently — unlike the week view's range read, this is a one-time operation where a silent skip means a row stays plaintext forever with nobody told.

- [ ] **Step 4: Full verification, commit**

```bash
git commit -m "feat: resumable migration of existing rows to v2"
```

---

## Task 16: Sign-out, lock, and the sign-in unlock

**Files:**
- Modify: `src/components/account_menu.rs`, `src/server_fns/session.rs` call sites, `src/components/encryption_panel.rs`

- [ ] **Step 1:** Sign-out clears the keystore. This must happen even if the server call fails — a session that is locally signed out must not leave a usable key behind.

- [ ] **Step 2:** "Sign out everywhere" clears it too.

- [ ] **Step 3:** Passkey sign-in rides the PRF output straight into an unlock (spec §6.2) — one gesture, no second prompt. If the account is not encrypted, discard the PRF output silently.

- [ ] **Step 4:** Full verification, commit.

```bash
git commit -m "feat: clear the keystore on sign-out, unlock on passkey sign-in"
```

---

## Task 17: Documentation and final verification

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`

- [ ] **Step 1: Correct the phase-1 spec.** Its §9.2 and §9.3 predict XChaCha20 and an Argon2id passphrase. Add a pointer at the top of §9 to the phase-2 spec and mark those two subsections superseded. **Do not delete them** — the record of what was predicted, and why it changed, is the useful part.

- [ ] **Step 2: `CLAUDE.md`.** The header currently says signed-in entries are stored "as **plaintext**" and that client-side encryption is "a planned phase 2", and that "An operator with database access can read every signed-in user's entries today." All three statements become false for encrypted accounts and remain true for accounts that never enabled it. Rewrite precisely — do not overclaim in either direction.

Add `src/crypto/` and `src/entry_key/` to the Layout section. Add the crypto constants to the Conventions section as a compatibility surface, beside the storage-key note, with the same warning shape.

- [ ] **Step 3: `README.md`.** The Architecture section says "Signed-in users' entries are stored server-side, and today that storage is plaintext". Update it. Add a user-facing section on enabling encryption, the recovery code, and what happens if it is lost.

No new environment variables are introduced by this feature — confirm that is still true before claiming it.

- [ ] **Step 4: Run the full verification matrix and report the actual numbers**

```
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features --all-targets -- -D warnings
cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings
cargo fmt --all -- --check
cargo tree -i openssl-sys ; cargo tree -i native-tls
cargo leptos build --release
```

- [ ] **Step 5: Commit**

```bash
git commit -m "docs: record phase 2 encryption in README, CLAUDE.md and the phase-1 spec"
```

---

## Self-review notes

Checked while writing, recorded so the executor knows what was already considered:

- **Spec coverage.** Every numbered spec section maps to a task: §4 → 2/5, §5 → 1/4, §6.1 → 14, §6.2 → 16, §6.3 → 13, §6.4 → 13, §6.5 → 14, §6.6 → 9, §6.7 → 16, §7.1 → 8, §7.2 → 2/3/5/6/7, §7.3 → 6, §7.4 → 12, §7.5 → 11, §7.6 → 9/10, §8 → 15, §9 → 3, §10 → throughout, §11 → 2 (E6), 11 (E3/E4), 12 (E2).
- **The `store` `'static` property (E4)** is called out in Task 11 Step 1 because it is exactly the kind of thing a well-meaning refactor to `async fn` would break, and nothing but a compile error would say so.
- **`extractable`** is flagged at both Task 5 (the parameter) and Task 7 (the single `true` call site), because getting it backwards silently defeats decision 3 and no test can catch it.
- **The vacuous-test failure mode** from phase 1 is called out explicitly in Task 9 Step 1, with a required positive control.
- **Known gap:** Tasks 5, 6, and the PRF read in 8 have no automated coverage and cannot have any without a wasm test runner. Task 2's cross-implementation tests narrow this to "did we call the API correctly" rather than "is the format right". The final review should read those three files rather than trust a green suite.
