# Accounts, Passkeys, and Dated Entries — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional email-magic-link + passkey accounts to the time tracker, and move entries from a single `localStorage` blob to one row per user per calendar day, with the date in the URL.

**Architecture:** A Diesel/SQLite data layer and an axum session middleware sit behind Leptos server functions. The existing `src/storage/` seam — built async precisely for this — gains a date-keyed `StorageKey`, a `Backend` selector (`Local` for signed-out, `Remote` for signed-in), and a versioned envelope, so no view component changes shape. The server never parses or renders entry bodies, because phase 2 encrypts them client-side.

**Tech Stack:** Leptos 0.8 (SSR + hydrate), axum 0.8, Diesel 2.2 + SQLite (bundled) + r2d2, `diesel_migrations` (embedded), `webauthn-rs` 0.6.1-dev, `lettre` (rustls), `ring`, `chrono`, `uuid` v7.

**Spec:** `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`

## Global Constraints

Every task's requirements implicitly include this section.

- **Edition 2024**, nightly toolchain pinned by `rust-toolchain.toml`.
- **Test:** `cargo test --features ssr --no-default-features`
- **Lint:** `cargo clippy --features ssr --no-default-features` — must be clean.
- **Wasm check:** `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate`
- **Never run plain `cargo build` / `cargo test`.** They fight `cargo leptos` over the same target dir and mutually invalidate the cache. `cargo clippy` / `cargo check` are safe.
- **OpenSSL-free, rustls only.** Verify with `cargo tree -i openssl-sys` and `cargo tree -i native-tls` — both must report nothing.
- **Commit `Cargo.lock`** in the same commit as any dependency change. CI uses `--locked`.
- **Branch polymorphism uses `Either`/`EitherOf3`, never `.into_any()`.**
- **Tailwind v4 CSS-first.** No `tailwind.config.js`, no npm step. Custom utilities go in `style/tailwind.css` under `@layer components`.
- **Storage key strings are a compatibility surface.** Changing one orphans existing users' saved data.
- **The server must never parse, aggregate, search, validate, or render an entry body** (spec §9.1). It stores and returns opaque strings. This is load-bearing for phase-2 encryption, not a style preference.
- **Feature partitioning:** `ssr` = server binary, `hydrate` = wasm bundle. Anything touching `web_sys` is `hydrate`-only; anything touching Diesel/axum is `ssr`-only. Server-fn *bodies* are `ssr`-gated; their *signatures* compile on both.
- **Secrets are per-purpose.** `SESSION_KEY` signs sessions; a separate `PASSKEY_STATE_KEY` signs ceremony state. Never reuse one key for two purposes.

---

## File Structure

**New — server-side (`ssr`):**

| File | Responsibility |
|---|---|
| `src/db.rs` | r2d2 pool, PRAGMA customizer, embedded migrations runner |
| `src/schema.rs` | Hand-written Diesel table macros (no diesel CLI needed) |
| `src/context.rs` | `AppCtx`: pool + mailer + webauthn + session claims |
| `src/auth/mod.rs` | Module root |
| `src/auth/user.rs` | The `user` table: normalization, lookup, epoch bump |
| `src/auth/magic_link.rs` | Mint / consume magic-link tokens |
| `src/auth/middleware.rs` | axum layer: verify cookie, insert `AppCtx` |
| `src/auth/handler.rs` | `GET /magic/{token}` axum handler |
| `src/entries/mod.rs` | Module root |
| `src/entries/repo.rs` | Diesel CRUD + range queries for `time_entry` |
| `src/email/mod.rs` | `Mailer` enum: `Smtp` / `Capture` / `Disabled` |
| `src/passkey/mod.rs` | Module root |
| `src/passkey/webauthn.rs` | `Webauthn` singleton from env |
| `src/passkey/state.rs` | HMAC-signed `__pk_state` ceremony cookie |
| `src/passkey/store.rs` | Diesel CRUD for `passkey_credential` |
| `src/server/cookie.rs` | Shared `Set-Cookie` construction |

**New — shared (both targets):**

| File | Responsibility |
|---|---|
| `src/session.rs` | Session token format, issue + stateless verify |
| `src/auth_ctx.rs` | `AuthCtx` view-layer identity + backend selection |
| `src/test_support.rs` | Router builder and session helpers shared by `tests/` |
| `src/dto.rs` | Types crossing the server-fn boundary |
| `src/date.rs` | Date parsing/formatting, ISO-week arithmetic |
| `src/rate_limit.rs` | In-memory token buckets (IP and email) |
| `src/storage/envelope.rs` | Versioned `{v, alg, body}` envelope |
| `src/storage/remote.rs` | Server-fn-backed storage backend |
| `src/server_fns/mod.rs` | Shared helpers: `require_user`, `server_err` |
| `src/server_fns/session.rs` | `current_session`, `request_magic_link`, `logout`, `sign_out_everywhere` |
| `src/server_fns/entries.rs` | `entry_load`, `entry_save`, range fns |
| `src/server_fns/passkey.rs` | Seven passkey ceremony + management fns |

**New — client-side (`hydrate`):**

| File | Responsibility |
|---|---|
| `src/webauthn_browser.rs` | `navigator.credentials` bridge (+ PRF extension results) |

**New — components:**

| File | Responsibility |
|---|---|
| `src/components/header.rs` | Slim app header: title / date / account slot |
| `src/components/account_menu.rs` | Corner popover: sign-in form and signed-in menu |
| `src/components/calendar.rs` | Date popover with entry dots and ‹ › steppers |
| `src/components/import_banner.rs` | One-time "import N days from this device" |
| `src/components/account_page.rs` | `/account`: passkey list, add, rename, delete |
| `src/components/week_view.rs` | `/week/:date`: client-side weekly aggregation |

**Modified:**

| File | Change |
|---|---|
| `Cargo.toml` | New deps, feature partitioning |
| `src/lib.rs` | Register new modules with correct `cfg` gates |
| `src/main.rs` | Pool, migrations, middleware, `/magic`, static-before-Leptos route order |
| `src/app.rs` | Routes `/`, `/:date`, `/week/:date`, `/account`; header; SSR tests |
| `src/storage/mod.rs` | `StorageKey(NaiveDate)`, `Backend`, envelope wiring |
| `src/storage/local.rs` | Dated keys + legacy alias |
| `src/storage/hook.rs` | Reactive `Signal` args, reset-on-key-change |
| `src/components/time_entry_area.rs` | Accept the reactive `Persistent` |
| `src/components/time_display.rs` | Accept the reactive `Persistent` |
| `migrations/` | Four new migration directories |
| `tests/routes.rs` | Route priority (I4) |
| `tests/magic_link.rs` | Magic-link flow and request uniformity (I5) |
| `tests/entry_access.rs` | Cross-user scoping and revocation (I7) |
| `tests/passkey_access.rs` | Passkey enumeration resistance (I6) |

---

## Phase 1 — Foundations

### Task 1: Dependencies, migrations, and the database pool

**Files:**
- Modify: `Cargo.toml`
- Create: `migrations/2026-09-04-000001_user/{up,down}.sql`
- Create: `migrations/2026-09-04-000002_time_entry/{up,down}.sql`
- Create: `migrations/2026-09-04-000003_magic_link_token/{up,down}.sql`
- Create: `migrations/2026-09-04-000004_passkey_credential/{up,down}.sql`
- Create: `src/schema.rs`
- Create: `src/db.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `db::DbPool`, `db::DbConn`, `db::build_pool() -> anyhow::Result<DbPool>`, `db::run_migrations(&DbPool) -> anyhow::Result<()>`, and the `schema::{user, time_entry, magic_link_token, passkey_credential}` table modules.

- [ ] **Step 1: Add dependencies to `Cargo.toml`**

Add to the always-on block (both targets need dates):

```toml
chrono = { version = "0.4", default-features = false, features = [
  "clock", "std", "serde", "wasmbind",
] }
```

`wasmbind` is gated inside chrono to `cfg(target_arch = "wasm32")`, so it pulls nothing extra into the server build. It is what makes `Local::now()` work in the browser.

Add to the hydrate-only block:

```toml
js-sys = { version = "0.3", optional = true }
```

Extend the existing `web-sys` feature list with:

```toml
  "Document",
  "Element",
  "HtmlElement",
  "History",
  "Location",
  "AuthenticationExtensionsClientInputs",
  "AuthenticatorAssertionResponse",
  "AuthenticatorAttestationResponse",
  "AuthenticatorResponse",
  "CredentialCreationOptions",
  "CredentialRequestOptions",
  "CredentialsContainer",
  "PublicKeyCredential",
  "PublicKeyCredentialCreationOptions",
  "PublicKeyCredentialDescriptor",
  "PublicKeyCredentialRequestOptions",
```

Add to the SSR-only block:

```toml
axum-extra = { version = "0.12", features = ["cookie"], optional = true }
cookie = { version = "0.18", optional = true }
diesel = { version = "2.2", default-features = false, features = [
  "sqlite", "r2d2", "chrono", "returning_clauses_for_sqlite_3_35",
], optional = true }
diesel_migrations = { version = "2.2", features = ["sqlite"], optional = true }
# -sys crate pinned so the static SQLite is bundled (no system libsqlite3) and
# stays under diesel's `<0.38.0` ceiling. Consumed only through diesel, never
# named in our source — which is why cargo-machete cannot see it.
libsqlite3-sys = { version = "0.37", features = ["bundled"], optional = true }
lettre = { version = "0.11", default-features = false, features = [
  "smtp-transport", "tokio1-rustls-tls", "builder",
], optional = true }
ring = { version = "0.17", optional = true }
base64 = { version = "0.22", optional = true }
hex = { version = "0.4", optional = true }
uuid = { version = "1", features = ["v7"], optional = true }
anyhow = { version = "1", optional = true }
tracing = { version = "0.1", optional = true }
tracing-subscriber = { version = "0.3", features = ["env-filter"], optional = true }
dotenvy = { version = "0.15", optional = true }
webauthn-rs = { version = "0.6.1-dev", features = [
  "danger-allow-state-serialisation", "conditional-ui",
], optional = true }
webauthn-rs-proto = { version = "0.6.1-dev", optional = true }
```

Add a dev-dependencies section:

```toml
[dev-dependencies]
webauthn-authenticator-rs = { version = "0.6.1-dev", default-features = false, features = [
  "softpasskey",
] }
```

Add a machete allowlist next to `[package]`:

```toml
[package.metadata.cargo-machete]
ignored = ["libsqlite3-sys"]
```

Extend the feature lists:

```toml
hydrate = [
  "leptos/hydrate",
  "dep:console_error_panic_hook",
  "dep:wasm-bindgen",
  "dep:wasm-bindgen-futures",
  "dep:js-sys",
  "dep:web-sys",
]
ssr = [
  "leptos/ssr",
  "leptos_meta/ssr",
  "leptos_router/ssr",
  "dep:leptos_axum",
  "dep:axum",
  "dep:axum-extra",
  "dep:cookie",
  "dep:tokio",
  "dep:diesel",
  "dep:diesel_migrations",
  "dep:libsqlite3-sys",
  "dep:lettre",
  "dep:ring",
  "dep:base64",
  "dep:hex",
  "dep:uuid",
  "dep:anyhow",
  "dep:tracing",
  "dep:tracing-subscriber",
  "dep:dotenvy",
  "dep:webauthn-rs",
  "dep:webauthn-rs-proto",
]
```

- [ ] **Step 2: Verify the dependency graph is OpenSSL-free**

Run:
```bash
cargo tree -i openssl-sys --features ssr --no-default-features 2>&1 | tail -3
cargo tree -i native-tls --features ssr --no-default-features 2>&1 | tail -3
```
Expected: both report `error: package ID specification ... did not match any packages` — i.e. nothing depends on them. If either resolves, a dependency defaulted to native-tls; find it with `cargo tree -e features` and add `default-features = false`.

- [ ] **Step 3: Write the four migrations**

`migrations/2026-09-04-000001_user/up.sql`:

```sql
CREATE TABLE user (
  id            INTEGER PRIMARY KEY,
  email         TEXT      NOT NULL,
  session_epoch INTEGER   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_user_email ON user(email);
```

`migrations/2026-09-04-000001_user/down.sql`:

```sql
DROP TABLE user;
```

`migrations/2026-09-04-000002_time_entry/up.sql`:

```sql
CREATE TABLE time_entry (
  user_id    INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  entry_date TEXT      NOT NULL,
  body       TEXT      NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY (user_id, entry_date)
);
CREATE INDEX idx_time_entry_user_date ON time_entry(user_id, entry_date);
```

`migrations/2026-09-04-000002_time_entry/down.sql`:

```sql
DROP TABLE time_entry;
```

`migrations/2026-09-04-000003_magic_link_token/up.sql`:

```sql
CREATE TABLE magic_link_token (
  id         INTEGER   PRIMARY KEY,
  token_hash BLOB      NOT NULL,
  email      TEXT      NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_magic_token_hash ON magic_link_token(token_hash);
```

`migrations/2026-09-04-000003_magic_link_token/down.sql`:

```sql
DROP TABLE magic_link_token;
```

`migrations/2026-09-04-000004_passkey_credential/up.sql`:

```sql
CREATE TABLE passkey_credential (
  id            INTEGER   PRIMARY KEY,
  user_id       INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  credential_id BLOB      NOT NULL,
  passkey       BLOB      NOT NULL,
  name          TEXT,
  prf_capable   BOOLEAN   NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL,
  last_used_at  TIMESTAMP
);
CREATE UNIQUE INDEX idx_passkey_credential_id ON passkey_credential(credential_id);
CREATE INDEX idx_passkey_user ON passkey_credential(user_id);
```

`migrations/2026-09-04-000004_passkey_credential/down.sql`:

```sql
DROP TABLE passkey_credential;
```

- [ ] **Step 4: Write `src/schema.rs` by hand**

Hand-written rather than generated: `diesel print-schema` needs the diesel CLI and a live database file, and these four tables are small and stable. If you later add tables, keep this file hand-maintained to match.

```rust
//! Diesel table definitions.
//!
//! Hand-written rather than produced by `diesel print-schema`, so the build
//! needs neither the diesel CLI nor a database file present. Keep in sync
//! with `migrations/` by hand.

diesel::table! {
    user (id) {
        id -> Integer,
        email -> Text,
        session_epoch -> BigInt,
        created_at -> Timestamp,
    }
}

diesel::table! {
    time_entry (user_id, entry_date) {
        user_id -> Integer,
        entry_date -> Text,
        body -> Text,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    magic_link_token (id) {
        id -> Integer,
        token_hash -> Binary,
        email -> Text,
        expires_at -> Timestamp,
        used_at -> Nullable<Timestamp>,
        created_at -> Timestamp,
    }
}

diesel::table! {
    passkey_credential (id) {
        id -> Integer,
        user_id -> Integer,
        credential_id -> Binary,
        passkey -> Binary,
        name -> Nullable<Text>,
        prf_capable -> Bool,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(time_entry -> user (user_id));
diesel::joinable!(passkey_credential -> user (user_id));
diesel::allow_tables_to_appear_in_same_query!(
    user,
    time_entry,
    magic_link_token,
    passkey_credential,
);
```

- [ ] **Step 5: Write the failing test for the pool**

Create `src/db.rs` containing only the test module first, so the test names exist before the implementation:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory pool must apply migrations and be usable afterwards.
    #[test]
    fn memory_pool_applies_migrations() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let n: i64 = diesel::sql_query("SELECT COUNT(*) AS c FROM user")
            .get_result::<Count>(&mut conn)
            .expect("user table exists")
            .c;
        assert_eq!(n, 0);
    }

    /// `foreign_keys` is per-connection and MUST be set by the customizer;
    /// without it the ON DELETE CASCADE in the schema silently does nothing.
    #[test]
    fn foreign_keys_pragma_is_on() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let on: i64 = diesel::sql_query("PRAGMA foreign_keys")
            .get_result::<Count>(&mut conn)
            .expect("pragma readable")
            .c;
        assert_eq!(on, 1, "foreign_keys must be ON for cascade deletes to work");
    }

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        c: i64,
    }
}
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cargo test --features ssr --no-default-features db::`
Expected: FAIL to compile — `cannot find function 'test_pool' in this scope`.

- [ ] **Step 7: Implement `src/db.rs`**

```rust
//! Diesel r2d2 pool, connection PRAGMAs, and embedded migrations.
//!
//! Migrations are compiled in via `diesel_migrations` and run on every
//! startup. They are idempotent, so there is no separate migrate step and
//! the image ships no `migrations/` directory.

use std::env;
use std::fs;
use std::path::Path;

use diesel::connection::SimpleConnection;
use diesel::r2d2::{
    ConnectionManager, CustomizeConnection, Error as R2d2Error, Pool, PooledConnection,
};
use diesel::sqlite::SqliteConnection;
use diesel_migrations::{EmbeddedMigrations, MigrationHarness, embed_migrations};

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<SqliteConnection>>;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("./migrations");

/// Applies SQLite PRAGMAs to every pooled connection.
///
/// `busy_timeout` MUST come first: `journal_mode = WAL` takes an exclusive
/// lock on the DB header, and r2d2 opens its initial connections in parallel.
/// Without a busy timeout already in effect the racing connections see
/// SQLITE_BUSY immediately and pool construction fails.
///
/// `foreign_keys` is per-connection, not per-database — set here or the
/// schema's ON DELETE CASCADE clauses silently do nothing.
#[derive(Debug)]
struct ConnectionInit;

impl CustomizeConnection<SqliteConnection, R2d2Error> for ConnectionInit {
    fn on_acquire(&self, conn: &mut SqliteConnection) -> Result<(), R2d2Error> {
        conn.batch_execute(
            "PRAGMA busy_timeout = 5000; \
             PRAGMA journal_mode = WAL; \
             PRAGMA foreign_keys = ON;",
        )
        .map_err(R2d2Error::QueryError)
    }
}

/// Builds a pool from `DATABASE_URL` (default `./data/time-tracking.db`),
/// creating the parent directory if needed.
///
/// `:memory:` is capped at one connection on purpose. A bare `:memory:` URL
/// gives each connection its *own* empty database, so a multi-connection pool
/// would hand some callers an unmigrated schema.
pub fn build_pool() -> anyhow::Result<DbPool> {
    let url = env::var("DATABASE_URL").unwrap_or_else(|_| "./data/time-tracking.db".to_string());

    let max_size = if url == ":memory:" {
        1
    } else {
        if let Some(parent) = Path::new(&url).parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        8
    };

    let manager = ConnectionManager::<SqliteConnection>::new(&url);
    Ok(Pool::builder()
        .max_size(max_size)
        .connection_customizer(Box::new(ConnectionInit))
        .build(manager)?)
}

/// Runs all pending migrations. Idempotent; call once at startup.
pub fn run_migrations(pool: &DbPool) -> anyhow::Result<()> {
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| anyhow::anyhow!("migrations failed: {e}"))?;
    Ok(())
}

/// A migrated, single-connection in-memory pool for tests.
///
/// Not `#[cfg(test)]`: integration tests and other modules' test suites use
/// it too, and `#[cfg(test)]` items are invisible across crate-internal test
/// binaries. Gated on `ssr` so it never reaches the wasm bundle.
#[cfg(feature = "ssr")]
pub fn test_pool() -> DbPool {
    let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
    let pool = Pool::builder()
        .max_size(1)
        .connection_customizer(Box::new(ConnectionInit))
        .build(manager)
        .expect("in-memory pool");
    run_migrations(&pool).expect("migrations apply");
    pool
}
```

- [ ] **Step 8: Register the modules in `src/lib.rs`**

```rust
#![recursion_limit = "512"]

pub mod app;
pub mod clipboard;
pub mod components;
pub mod storage;

#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod schema;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::app::App);
}
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features db::`
Expected: PASS — `memory_pool_applies_migrations` and `foreign_keys_pragma_is_on`.

- [ ] **Step 10: Verify the wasm target still builds**

Run: `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate`
Expected: success. If Diesel or ring appear in the wasm build, an `ssr` gate is missing.

- [ ] **Step 11: Commit**

```bash
git add Cargo.toml Cargo.lock migrations/ src/schema.rs src/db.rs src/lib.rs
git commit -m "feat(db): add SQLite pool, embedded migrations, and schema

Four tables: user, time_entry, magic_link_token, passkey_credential.
PRAGMAs are applied per-connection with busy_timeout first, because
journal_mode=WAL locks the header and r2d2 opens connections in
parallel at pool build.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 2: The storage envelope

**Files:**
- Create: `src/storage/envelope.rs`
- Modify: `src/storage/mod.rs` (add `pub mod envelope;`)

**Interfaces:**
- Consumes: nothing.
- Produces: `envelope::wrap(body: &str) -> String`, `envelope::unwrap(raw: &str) -> Result<String, EnvelopeError>`, `envelope::EnvelopeError`.

**Why this exists:** phase 2 stores ciphertext in the same column. Without a version tag written from day one, phase 2 must guess whether each stored value is plaintext or ciphertext — a guess that is wrong exactly when a body happens to look like base64. See spec §9.2.

- [ ] **Step 1: Write the failing tests**

Create `src/storage/envelope.rs` with only the tests:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features storage::envelope`
Expected: FAIL to compile — `cannot find function 'wrap'`.

- [ ] **Step 3: Implement the envelope**

Prepend to `src/storage/envelope.rs`:

```rust
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
```

Add `pub mod envelope;` to `src/storage/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features storage::envelope`
Expected: PASS — six tests.

- [ ] **Step 5: Commit**

```bash
git add src/storage/envelope.rs src/storage/mod.rs
git commit -m "feat(storage): add versioned envelope for stored bodies

Pins spec invariant I8. Phase 2 writes ciphertext into the same column;
the version tag is what lets a reader tell the two apart instead of
guessing from the shape of the data.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 3: Date helpers

**Files:**
- Create: `src/date.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `date::parse_iso(&str) -> Option<NaiveDate>`, `date::to_iso(NaiveDate) -> String`, `date::week_bounds(NaiveDate) -> (NaiveDate, NaiveDate)`, `date::month_bounds(NaiveDate) -> (NaiveDate, NaiveDate)`, `date::format_long(NaiveDate) -> String`, `date::today_local() -> NaiveDate` (hydrate) / `date::today_utc() -> NaiveDate` (ssr).

- [ ] **Step 1: Write the failing tests**

Create `src/date.rs` with only the tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    #[test]
    fn parses_and_formats_iso() {
        assert_eq!(parse_iso("2026-09-04"), Some(d(2026, 9, 4)));
        assert_eq!(to_iso(d(2026, 9, 4)), "2026-09-04");
    }

    /// The date segment comes straight off the URL, so every junk shape a
    /// user or crawler can put there must be rejected rather than panic.
    #[test]
    fn rejects_non_dates() {
        for junk in [
            "", "account", "favicon.ico", "2026-13-01", "2026-02-30",
            "2026-9-4", "20260904", "2026-09-04T00:00:00",
        ] {
            assert_eq!(parse_iso(junk), None, "{junk:?} must not parse");
        }
    }

    #[test]
    fn week_runs_monday_to_sunday() {
        // 2026-09-04 is a Friday.
        let (start, end) = week_bounds(d(2026, 9, 4));
        assert_eq!(start, d(2026, 8, 31), "week starts Monday");
        assert_eq!(end, d(2026, 9, 6), "week ends Sunday");
    }

    #[test]
    fn week_bounds_are_stable_at_the_edges() {
        // A Monday is its own week start; a Sunday is its own week end.
        let (mon_start, _) = week_bounds(d(2026, 8, 31));
        assert_eq!(mon_start, d(2026, 8, 31));
        let (_, sun_end) = week_bounds(d(2026, 9, 6));
        assert_eq!(sun_end, d(2026, 9, 6));
    }

    /// A week spanning a year boundary is the case an off-by-one hides in.
    #[test]
    fn week_spans_a_year_boundary() {
        // 2027-01-01 is a Friday.
        let (start, end) = week_bounds(d(2027, 1, 1));
        assert_eq!(start, d(2026, 12, 28));
        assert_eq!(end, d(2027, 1, 3));
    }

    #[test]
    fn month_bounds_cover_the_whole_month() {
        assert_eq!(month_bounds(d(2026, 9, 4)), (d(2026, 9, 1), d(2026, 9, 30)));
        assert_eq!(month_bounds(d(2026, 12, 9)), (d(2026, 12, 1), d(2026, 12, 31)));
        // February in a leap year — the case a naive "day 28" gets wrong.
        assert_eq!(month_bounds(d(2028, 2, 5)), (d(2028, 2, 1), d(2028, 2, 29)));
    }

    #[test]
    fn formats_a_human_label() {
        assert_eq!(format_long(d(2026, 9, 4)), "Friday, Sep 4");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features date::`
Expected: FAIL to compile — `cannot find function 'parse_iso'`.

- [ ] **Step 3: Implement `src/date.rs`**

Prepend to `src/date.rs`:

```rust
//! Calendar arithmetic shared by both targets.
//!
//! Weeks run Monday to Sunday (ISO 8601). The URL carries dates as
//! `YYYY-MM-DD`, which sorts lexically — that is why `time_entry.entry_date`
//! is TEXT and why range queries can use a plain `BETWEEN`.

use chrono::{Datelike, Days, NaiveDate};

/// Parses a `YYYY-MM-DD` URL segment. Strict: anything else is `None`.
pub fn parse_iso(raw: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok()
}

/// Renders a date the way the URL and the database both store it.
pub fn to_iso(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

/// The Monday and Sunday bracketing `date`, inclusive.
pub fn week_bounds(date: NaiveDate) -> (NaiveDate, NaiveDate) {
    let from_monday = date.weekday().num_days_from_monday() as u64;
    let start = date - Days::new(from_monday);
    let end = start + Days::new(6);
    (start, end)
}

/// The first and last day of `date`'s month, inclusive.
pub fn month_bounds(date: NaiveDate) -> (NaiveDate, NaiveDate) {
    let start = date.with_day(1).expect("day 1 exists in every month");
    // Walk to the first of the next month, then step back one day. Avoids a
    // per-month length table and gets February right in leap years.
    let next_month = if start.month() == 12 {
        NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)
    }
    .expect("first of next month is a valid date");
    (start, next_month - Days::new(1))
}

/// The label shown in the header, e.g. "Friday, Sep 4".
pub fn format_long(date: NaiveDate) -> String {
    date.format("%A, %b %-d").to_string()
}

/// The browser's local calendar date.
///
/// Only the browser can answer this: the server does not know the visitor's
/// timezone, which is why `/` renders its date slot blank and the client
/// replaces the URL after hydration (spec §8.1).
#[cfg(feature = "hydrate")]
pub fn today_local() -> NaiveDate {
    chrono::Local::now().date_naive()
}

/// The server's UTC date. Used only where a date is needed for logging or a
/// token expiry — never to decide which day a user is looking at.
#[cfg(feature = "ssr")]
pub fn today_utc() -> NaiveDate {
    chrono::Utc::now().date_naive()
}
```

Add `pub mod date;` to `src/lib.rs` (ungated — both targets need it).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features date::`
Expected: PASS — seven tests.

- [ ] **Step 5: Commit**

```bash
git add src/date.rs src/lib.rs
git commit -m "feat(date): add ISO date parsing and week/month bounds

Weeks run Monday-Sunday. parse_iso is strict because the date segment
comes straight off the URL, where crawlers put arbitrary junk.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 4: Session tokens

**Files:**
- Create: `src/session.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `session::SessionClaims { email: String, epoch: i64 }`, `session::issue(email: &str, epoch: i64) -> String`, `session::verify(raw: &str) -> Result<SessionClaims, SessionError>`, `session::SessionError`, `session::COOKIE_NAME`, `session::MAX_AGE_SECONDS`.

**Why not photo365's `X-Login`:** that token is a 48-bit truncated keyed hash over the email with no expiry and no revocation path. This one uses a full-width HMAC, carries an expiry, and carries the issuing epoch so a `session_epoch` bump invalidates it (spec §5.1).

- [ ] **Step 1: Write the failing tests**

Create `src/session.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    const KEY: &str = "test-session-key-not-a-real-secret";

    fn issued_at(email: &str, epoch: i64, now: i64) -> String {
        issue_at(email, epoch, now, KEY.as_bytes())
    }

    #[test]
    fn round_trips_claims() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 3, now);
        let claims = verify_at(&tok, now + 60, KEY.as_bytes()).expect("valid");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.epoch, 3);
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let mut parts: Vec<&str> = tok.split('.').collect();
        let mut sig = parts[5].to_string();
        let last = sig.pop().expect("non-empty signature");
        sig.push(if last == '0' { '1' } else { '0' });
        parts[5] = &sig;
        assert_eq!(
            verify_at(&parts.join("."), now + 60, KEY.as_bytes()),
            Err(SessionError::BadSignature)
        );
    }

    /// Swapping the email while keeping a valid signature from another token
    /// is the attack the MAC exists to stop.
    #[test]
    fn rejects_a_swapped_email() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let parts: Vec<&str> = tok.split('.').collect();
        let forged = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0],
            b64(b"mallory@example.com"),
            parts[2],
            parts[3],
            parts[4],
            parts[5],
        );
        assert_eq!(
            verify_at(&forged, now + 60, KEY.as_bytes()),
            Err(SessionError::BadSignature)
        );
    }

    #[test]
    fn rejects_an_expired_token() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let after = now + MAX_AGE_SECONDS + 1;
        assert_eq!(
            verify_at(&tok, after, KEY.as_bytes()),
            Err(SessionError::Expired)
        );
    }

    #[test]
    fn tolerates_small_clock_skew_but_not_large() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        // Verifier's clock 3s behind the issuer: fine.
        assert!(verify_at(&tok, now - 3, KEY.as_bytes()).is_ok());
        // An hour behind: not fine.
        assert_eq!(
            verify_at(&tok, now - 3600, KEY.as_bytes()),
            Err(SessionError::InFuture)
        );
    }

    #[test]
    fn rejects_a_token_signed_with_another_key() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        assert_eq!(
            verify_at(&tok, now + 60, b"a-completely-different-key"),
            Err(SessionError::BadSignature)
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        let now = 1_788_000_000;
        for junk in ["", "garbage", "v1.a.b.c", "v9.a.b.c.d.e"] {
            assert_eq!(
                verify_at(junk, now, KEY.as_bytes()),
                Err(SessionError::Malformed),
                "{junk:?} must be rejected as malformed"
            );
        }
    }

    /// The epoch must survive verification intact — it is what
    /// `require_user` compares against the database to honour a revocation.
    #[test]
    fn carries_the_issuing_epoch() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 41, now);
        assert_eq!(
            verify_at(&tok, now + 60, KEY.as_bytes()).expect("valid").epoch,
            41
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features session::`
Expected: FAIL to compile — `cannot find function 'issue_at'`.

- [ ] **Step 3: Implement `src/session.rs`**

Prepend to `src/session.rs`:

```rust
//! The session cookie's token format.
//!
//! `v1.<b64url(email)>.<issued>.<expires>.<epoch>.<hmac_hex>`, with the MAC
//! taken over the five preceding dot-joined fields.
//!
//! Verification here is deliberately **stateless** — signature and clock
//! only, no database. That is all the page shell needs to decide whether to
//! render a signed-in corner. Revocation lives one layer up:
//! `server_fns::require_user` compares the `epoch` carried here against the
//! user row's `session_epoch`, so bumping that column signs every device out
//! on its next data access. See spec §5.1.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::hmac;

pub const COOKIE_NAME: &str = "tt_session";
/// 30 days.
pub const MAX_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;
const VERSION: &str = "v1";
const SKEW_TOLERANCE_SECS: i64 = 5;

/// What a valid session token asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    pub email: String,
    pub epoch: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("session token is malformed")]
    Malformed,
    #[error("session token signature does not verify")]
    BadSignature,
    #[error("session token has expired")]
    Expired,
    #[error("session token was issued in the future")]
    InFuture,
}

fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

fn sign(payload: &str, key: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hex::encode(hmac::sign(&key, payload.as_bytes()).as_ref())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Issues a token valid for [`MAX_AGE_SECONDS`] from `now`.
fn issue_at(email: &str, epoch: i64, now: i64, key: &[u8]) -> String {
    let payload = format!(
        "{VERSION}.{}.{now}.{}.{epoch}",
        b64(email.as_bytes()),
        now + MAX_AGE_SECONDS,
    );
    let mac = sign(&payload, key);
    format!("{payload}.{mac}")
}

/// Verifies signature and clock. Performs no database access.
fn verify_at(raw: &str, now: i64, key: &[u8]) -> Result<SessionClaims, SessionError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 6 || parts[0] != VERSION {
        return Err(SessionError::Malformed);
    }
    let issued: i64 = parts[2].parse().map_err(|_| SessionError::Malformed)?;
    let expires: i64 = parts[3].parse().map_err(|_| SessionError::Malformed)?;
    let epoch: i64 = parts[4].parse().map_err(|_| SessionError::Malformed)?;

    // Signature is checked before any claim is trusted, including the clock
    // fields parsed above — those are only used after this point.
    let payload = parts[..5].join(".");
    if !constant_time_eq(sign(&payload, key).as_bytes(), parts[5].as_bytes()) {
        return Err(SessionError::BadSignature);
    }

    if issued > now + SKEW_TOLERANCE_SECS {
        return Err(SessionError::InFuture);
    }
    if now >= expires {
        return Err(SessionError::Expired);
    }

    let email = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(SessionError::Malformed)?;

    Ok(SessionClaims { email, epoch })
}

/// The signing key, read once per call from `SESSION_KEY`.
///
/// In release builds an unset or empty key is fatal — refusing to boot beats
/// silently signing every session with a guessable constant. In debug builds
/// a random ephemeral key is generated with a warning, so `cargo leptos
/// watch` works out of the box; sessions then do not survive a restart.
#[cfg(feature = "ssr")]
fn session_key() -> Vec<u8> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        match std::env::var("SESSION_KEY") {
            Ok(k) if !k.is_empty() => k.into_bytes(),
            _ if cfg!(debug_assertions) => {
                use ring::rand::{SecureRandom, SystemRandom};
                let mut buf = [0u8; 32];
                SystemRandom::new()
                    .fill(&mut buf)
                    .expect("system randomness");
                tracing::warn!(
                    "SESSION_KEY is unset; generated an ephemeral key. \
                     Sessions will not survive a restart. Set SESSION_KEY \
                     for anything but local development."
                );
                buf.to_vec()
            }
            _ => panic!("SESSION_KEY must be set to a non-empty value in release builds"),
        }
        .clone()
    })
    .clone()
}

#[cfg(feature = "ssr")]
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Issues a session token for `email` at the user's current `epoch`.
#[cfg(feature = "ssr")]
pub fn issue(email: &str, epoch: i64) -> String {
    issue_at(email, epoch, now_secs(), &session_key())
}

/// Verifies a session token's signature and clock.
#[cfg(feature = "ssr")]
pub fn verify(raw: &str) -> Result<SessionClaims, SessionError> {
    verify_at(raw, now_secs(), &session_key())
}
```

Add `pub mod session;` to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features session::`
Expected: PASS — eight tests.

- [ ] **Step 5: Commit**

```bash
git add src/session.rs src/lib.rs
git commit -m "feat(session): add HMAC session token with expiry and epoch

Full-width HMAC-SHA256 rather than photo365's 48-bit truncated hash,
plus an expiry and the issuing session_epoch so revocation is possible.
Verification is stateless by design; the epoch is compared against the
database only by callers that touch user data.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 5: Rate limiting

**Files:**
- Create: `src/rate_limit.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `rate_limit::Limiter::new(capacity: u32, refill_per_sec: f64) -> Limiter`, `Limiter::check_at(&self, key: &str, now: f64) -> bool`, `rate_limit::check_ip(&str) -> bool`, `rate_limit::check_email(&str) -> bool`.

**Why both keys:** limiting by IP alone lets an attacker rotating addresses mail-bomb one victim; limiting by email alone lets one host enumerate many addresses. Spec §5.4.

- [ ] **Step 1: Write the failing tests**

Create `src/rate_limit.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let lim = Limiter::new(3, 0.1);
        for i in 0..3 {
            assert!(lim.check_at("a", 0.0), "request {i} should be allowed");
        }
        assert!(!lim.check_at("a", 0.0), "the 4th request must be denied");
    }

    #[test]
    fn refills_over_time() {
        let lim = Limiter::new(2, 1.0); // one token per second
        assert!(lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 0.0));
        assert!(!lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 1.0), "one second refills one token");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let lim = Limiter::new(2, 1.0);
        assert!(lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 0.0));
        // A long idle period must not bank unlimited tokens.
        assert!(lim.check_at("a", 10_000.0));
        assert!(lim.check_at("a", 10_000.0));
        assert!(!lim.check_at("a", 10_000.0), "capacity is still 2");
    }

    /// Buckets must not bleed between keys, or one busy user locks out all.
    #[test]
    fn keys_are_independent() {
        let lim = Limiter::new(1, 0.1);
        assert!(lim.check_at("a", 0.0));
        assert!(!lim.check_at("a", 0.0));
        assert!(lim.check_at("b", 0.0), "a different key has its own bucket");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features rate_limit::`
Expected: FAIL to compile — `cannot find type 'Limiter'`.

- [ ] **Step 3: Implement `src/rate_limit.rs`**

Prepend to `src/rate_limit.rs`:

```rust
//! In-memory token buckets guarding the magic-link and passkey entry points.
//!
//! Two independent limiters, both applied. By IP, so one host cannot spray
//! many addresses; by email, so an attacker rotating IPs cannot mail-bomb one
//! victim. Either limit alone leaves the other attack open.
//!
//! In-memory is sufficient: this is a single process, and a restart clearing
//! the buckets is not a useful window against a 15-minute token.

use std::collections::HashMap;
use std::sync::Mutex;

/// Magic-link requests: 5 immediately, then one back every 30s.
const MAGIC_CAPACITY: u32 = 5;
const MAGIC_REFILL_PER_SEC: f64 = 1.0 / 30.0;

struct Bucket {
    tokens: f64,
    last_seen: f64,
}

/// A keyed token-bucket limiter.
pub struct Limiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Limiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consumes one token for `key` at time `now` (unix seconds, fractional).
    /// Returns `false` when the bucket is empty.
    ///
    /// `now` is a parameter rather than read from the clock so the refill
    /// behaviour is testable without sleeping.
    pub fn check_at(&self, key: &str, now: f64) -> bool {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.capacity,
            last_seen: now,
        });

        let elapsed = (now - bucket.last_seen).max(0.0);
        // Capped at capacity: idling must not bank tokens without limit.
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(feature = "ssr")]
fn now_secs_f64() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}

#[cfg(feature = "ssr")]
fn magic_ip() -> &'static Limiter {
    use std::sync::OnceLock;
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(MAGIC_CAPACITY, MAGIC_REFILL_PER_SEC))
}

#[cfg(feature = "ssr")]
fn magic_email() -> &'static Limiter {
    use std::sync::OnceLock;
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(MAGIC_CAPACITY, MAGIC_REFILL_PER_SEC))
}

/// `true` when this client IP is within quota.
#[cfg(feature = "ssr")]
pub fn check_ip(ip: &str) -> bool {
    magic_ip().check_at(ip, now_secs_f64())
}

/// `true` when this recipient address is within quota.
#[cfg(feature = "ssr")]
pub fn check_email(email: &str) -> bool {
    magic_email().check_at(email, now_secs_f64())
}
```

Add `pub mod rate_limit;` to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features rate_limit::`
Expected: PASS — four tests.

- [ ] **Step 5: Run clippy and commit**

```bash
cargo clippy --features ssr --no-default-features
git add src/rate_limit.rs src/lib.rs
git commit -m "feat(rate-limit): add token buckets keyed by IP and by email

Both limits are applied to magic-link requests. IP alone lets an
attacker rotating addresses mail-bomb one victim; email alone lets one
host enumerate many addresses.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Phase 2 — Server data layer

### Task 6: User and entry repositories

**Files:**
- Create: `src/auth/mod.rs`
- Create: `src/auth/user.rs`
- Create: `src/entries/mod.rs`
- Create: `src/entries/repo.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `db::{DbConn, test_pool}`, `schema::{user, time_entry}`, `date::to_iso`, `storage::envelope`.
- Produces:
  - `auth::user::User { id: i32, email: String, session_epoch: i64 }`
  - `auth::user::normalize_email(&str) -> Option<String>`
  - `auth::user::find_by_email(&mut DbConn, &str) -> anyhow::Result<Option<User>>`
  - `auth::user::find_or_create(&mut DbConn, &str) -> anyhow::Result<User>`
  - `auth::user::bump_epoch(&mut DbConn, i32) -> anyhow::Result<()>`
  - `entries::repo::load(&mut DbConn, i32, NaiveDate) -> anyhow::Result<Option<String>>`
  - `entries::repo::save(&mut DbConn, i32, NaiveDate, &str) -> anyhow::Result<()>`
  - `entries::repo::dates_in_range(&mut DbConn, i32, NaiveDate, NaiveDate) -> anyhow::Result<Vec<NaiveDate>>`
  - `entries::repo::entries_in_range(&mut DbConn, i32, NaiveDate, NaiveDate) -> anyhow::Result<Vec<(NaiveDate, String)>>`

- [ ] **Step 1: Write the failing tests for the user repository**

Create `src/auth/user.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[test]
    fn normalizes_case_and_whitespace() {
        assert_eq!(
            normalize_email("  Alice@Example.COM \n"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn rejects_impossible_addresses() {
        for junk in ["", "   ", "no-at-sign", "@nolocal.com", "trailing@", "a b@c.com"] {
            assert_eq!(normalize_email(junk), None, "{junk:?} must be rejected");
        }
    }

    /// Two spellings that differ only in case are one account; anything else
    /// is deliberately two accounts (spec section 4.2 — no provider-specific
    /// canonicalization).
    #[test]
    fn find_or_create_is_idempotent_across_case() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = find_or_create(&mut conn, "alice@example.com").expect("create");
        let b = find_or_create(&mut conn, "ALICE@example.com").expect("find");
        assert_eq!(a.id, b.id);
        assert_eq!(b.email, "alice@example.com");
    }

    #[test]
    fn dots_in_the_local_part_are_distinct_accounts() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = find_or_create(&mut conn, "a.b@example.com").expect("create");
        let b = find_or_create(&mut conn, "ab@example.com").expect("create");
        assert_ne!(a.id, b.id, "no gmail-style dot canonicalization");
    }

    #[test]
    fn new_users_start_at_epoch_zero() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert_eq!(
            find_or_create(&mut conn, "alice@example.com").expect("create").session_epoch,
            0
        );
    }

    #[test]
    fn find_by_email_misses_cleanly() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert!(find_by_email(&mut conn, "nobody@example.com").expect("query").is_none());
    }

    /// Bumping the epoch is how "sign out everywhere" works: every issued
    /// token carries the epoch it was minted under, and require_user rejects
    /// a mismatch.
    #[test]
    fn bump_epoch_increments() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let u = find_or_create(&mut conn, "alice@example.com").expect("create");
        bump_epoch(&mut conn, u.id).expect("bump");
        bump_epoch(&mut conn, u.id).expect("bump");
        let after = find_by_email(&mut conn, "alice@example.com").expect("query").expect("exists");
        assert_eq!(after.session_epoch, 2);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features auth::user`
Expected: FAIL to compile — `cannot find function 'normalize_email'`.

- [ ] **Step 3: Implement `src/auth/user.rs`**

Prepend to `src/auth/user.rs`:

```rust
//! The `user` table: the single identity anchor.
//!
//! Rows are created lazily, on a successful magic-link consume — never by
//! *requesting* a link. That is what keeps `request_magic_link` free of an
//! account-enumeration signal (spec section 5.2).

use anyhow::{Context, Result};
use chrono::Utc;
use diesel::prelude::*;

use crate::db::DbConn;
use crate::schema::user;

/// An account.
#[derive(Queryable, Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub session_epoch: i64,
    #[diesel(column_name = created_at)]
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = user)]
struct NewUser<'a> {
    email: &'a str,
    session_epoch: i64,
    created_at: chrono::NaiveDateTime,
}

/// Trims and lowercases, and rejects addresses that cannot be real.
///
/// Deliberately *not* provider-aware: no gmail dot-stripping, no plus-tag
/// removal. photo365 needs that to deduplicate customers across checkout
/// flows; here two spellings are simply two accounts, which surprises nobody
/// and costs no dependency.
pub fn normalize_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return None;
    }
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') || domain.contains('@') {
        return None;
    }
    Some(trimmed)
}

pub fn find_by_email(conn: &mut DbConn, email: &str) -> Result<Option<User>> {
    let Some(normalized) = normalize_email(email) else {
        return Ok(None);
    };
    Ok(user::table
        .filter(user::email.eq(&normalized))
        .first::<User>(conn)
        .optional()
        .context("select user by email")?)
}

/// Returns the existing account for `email`, creating one if absent.
pub fn find_or_create(conn: &mut DbConn, email: &str) -> Result<User> {
    let normalized =
        normalize_email(email).ok_or_else(|| anyhow::anyhow!("not a usable email address"))?;

    conn.transaction(|conn| {
        if let Some(found) = user::table
            .filter(user::email.eq(&normalized))
            .first::<User>(conn)
            .optional()?
        {
            return Ok(found);
        }
        diesel::insert_into(user::table)
            .values(NewUser {
                email: &normalized,
                session_epoch: 0,
                created_at: Utc::now().naive_utc(),
            })
            .execute(conn)?;
        user::table
            .filter(user::email.eq(&normalized))
            .first::<User>(conn)
    })
    .context("find or create user")
}

/// Invalidates every session token already issued to this user.
pub fn bump_epoch(conn: &mut DbConn, user_id: i32) -> Result<()> {
    diesel::update(user::table.find(user_id))
        .set(user::session_epoch.eq(user::session_epoch + 1))
        .execute(conn)
        .context("bump session_epoch")?;
    Ok(())
}
```

Create `src/auth/mod.rs`:

```rust
//! Authentication: identity, magic links, session middleware.

pub mod user;
```

Add to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`: `pub mod auth;`

- [ ] **Step 4: Run the user tests to verify they pass**

Run: `cargo test --features ssr --no-default-features auth::user`
Expected: PASS — seven tests.

- [ ] **Step 5: Write the failing tests for the entry repository**

Create `src/entries/repo.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::auth::user;
    use crate::db::{DbConn, test_pool};

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    fn user_id(conn: &mut DbConn, email: &str) -> i32 {
        user::find_or_create(conn, email).expect("create user").id
    }

    #[test]
    fn save_then_load_round_trips() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "body-text").expect("save");
        assert_eq!(
            load(&mut conn, uid, d(2026, 9, 4)).expect("load"),
            Some("body-text".to_string())
        );
    }

    #[test]
    fn load_misses_cleanly() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        assert_eq!(load(&mut conn, uid, d(2026, 9, 4)).expect("load"), None);
    }

    /// Saving the same day twice must update, not accumulate rows or fail on
    /// the composite primary key.
    #[test]
    fn save_is_an_upsert() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "first").expect("save");
        save(&mut conn, uid, d(2026, 9, 4), "second").expect("save");
        assert_eq!(
            load(&mut conn, uid, d(2026, 9, 4)).expect("load"),
            Some("second".to_string())
        );
        assert_eq!(dates_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 30)).expect("range").len(), 1);
    }

    /// Range bounds are inclusive on both ends. An exclusive upper bound
    /// silently drops the last day of every week and month view.
    #[test]
    fn range_bounds_are_inclusive() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        for day in [31, 1, 2, 6, 7] {
            let date = if day == 31 { d(2026, 8, 31) } else { d(2026, 9, day) };
            save(&mut conn, uid, date, "x").expect("save");
        }
        let got = dates_in_range(&mut conn, uid, d(2026, 8, 31), d(2026, 9, 6)).expect("range");
        assert_eq!(got, vec![d(2026, 8, 31), d(2026, 9, 1), d(2026, 9, 2), d(2026, 9, 6)]);
    }

    #[test]
    fn range_results_are_date_ordered() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        for date in [d(2026, 9, 9), d(2026, 9, 2), d(2026, 9, 30), d(2026, 9, 10)] {
            save(&mut conn, uid, date, "x").expect("save");
        }
        let got = dates_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 30)).expect("range");
        assert_eq!(got, vec![d(2026, 9, 2), d(2026, 9, 9), d(2026, 9, 10), d(2026, 9, 30)],
            "TEXT dates must sort chronologically, not 10 before 2");
    }

    #[test]
    fn entries_in_range_returns_bodies() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 1), "one").expect("save");
        save(&mut conn, uid, d(2026, 9, 3), "three").expect("save");
        assert_eq!(
            entries_in_range(&mut conn, uid, d(2026, 9, 1), d(2026, 9, 7)).expect("range"),
            vec![(d(2026, 9, 1), "one".to_string()), (d(2026, 9, 3), "three".to_string())]
        );
    }

    /// Pins invariant I7 for reads. Every query is scoped by user_id; a user
    /// must never observe another user's rows through any range or point read.
    #[test]
    fn reads_are_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        save(&mut conn, alice, d(2026, 9, 4), "alice-secret").expect("save");

        assert_eq!(load(&mut conn, mallory, d(2026, 9, 4)).expect("load"), None);
        assert!(dates_in_range(&mut conn, mallory, d(2026, 1, 1), d(2026, 12, 31)).expect("range").is_empty());
        assert!(entries_in_range(&mut conn, mallory, d(2026, 1, 1), d(2026, 12, 31)).expect("range").is_empty());
    }

    /// A write by one user must not overwrite another's row for the same day.
    #[test]
    fn writes_are_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        save(&mut conn, alice, d(2026, 9, 4), "alice-body").expect("save");
        save(&mut conn, mallory, d(2026, 9, 4), "mallory-body").expect("save");
        assert_eq!(load(&mut conn, alice, d(2026, 9, 4)).expect("load"), Some("alice-body".to_string()));
    }

    /// Deleting a user must take their entries with them, which only works
    /// if the foreign_keys PRAGMA is actually on.
    #[test]
    fn deleting_a_user_cascades_to_entries() {
        use crate::schema::user as user_table;
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        save(&mut conn, uid, d(2026, 9, 4), "x").expect("save");
        diesel::delete(user_table::table.find(uid)).execute(&mut conn).expect("delete user");
        assert!(entries_in_range(&mut conn, uid, d(2026, 1, 1), d(2026, 12, 31)).expect("range").is_empty());
    }
}
```

- [ ] **Step 6: Run the entry tests to verify they fail**

Run: `cargo test --features ssr --no-default-features entries::repo`
Expected: FAIL to compile — `cannot find function 'save'`.

- [ ] **Step 7: Implement `src/entries/repo.rs`**

Prepend to `src/entries/repo.rs`:

```rust
//! The `time_entry` table: one row per user per calendar day.
//!
//! `body` is an **opaque string** to this module and to every caller above
//! it. Nothing here parses, validates, or inspects it — phase 2 stores
//! ciphertext in this column and the server will not hold the key
//! (spec section 9.1).
//!
//! `entry_date` is TEXT holding `YYYY-MM-DD`, which sorts lexically in the
//! same order it sorts chronologically. That is what lets range queries use
//! a plain inclusive `BETWEEN` and still come back date-ordered.

use anyhow::{Context, Result};
use chrono::{NaiveDate, Utc};
use diesel::prelude::*;

use crate::date::{parse_iso, to_iso};
use crate::db::DbConn;
use crate::schema::time_entry;

#[derive(Insertable)]
#[diesel(table_name = time_entry)]
struct NewEntry<'a> {
    user_id: i32,
    entry_date: &'a str,
    body: &'a str,
    updated_at: chrono::NaiveDateTime,
}

/// Reads one day's stored body.
pub fn load(conn: &mut DbConn, user_id: i32, date: NaiveDate) -> Result<Option<String>> {
    Ok(time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.eq(to_iso(date)))
        .select(time_entry::body)
        .first::<String>(conn)
        .optional()
        .context("select time_entry")?)
}

/// Writes one day's body, replacing any previous value for that day.
pub fn save(conn: &mut DbConn, user_id: i32, date: NaiveDate, body: &str) -> Result<()> {
    let iso = to_iso(date);
    let now = Utc::now().naive_utc();
    diesel::insert_into(time_entry::table)
        .values(NewEntry {
            user_id,
            entry_date: &iso,
            body,
            updated_at: now,
        })
        .on_conflict((time_entry::user_id, time_entry::entry_date))
        .do_update()
        .set((time_entry::body.eq(body), time_entry::updated_at.eq(now)))
        .execute(conn)
        .context("upsert time_entry")?;
    Ok(())
}

/// The days in `[from, to]` that have an entry. **Dates only** — the calendar
/// needs to place dots, and shipping every body in the month to answer that
/// would leak far more than the question asks.
pub fn dates_in_range(
    conn: &mut DbConn,
    user_id: i32,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>> {
    let rows: Vec<String> = time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.between(to_iso(from), to_iso(to)))
        .order(time_entry::entry_date.asc())
        .select(time_entry::entry_date)
        .load(conn)
        .context("select entry dates in range")?;
    // A row whose date fails to parse would mean a corrupt write; skipping it
    // beats failing the whole range and blanking the calendar.
    Ok(rows.iter().filter_map(|s| parse_iso(s)).collect())
}

/// Every entry in `[from, to]`, bodies included and opaque.
pub fn entries_in_range(
    conn: &mut DbConn,
    user_id: i32,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(NaiveDate, String)>> {
    let rows: Vec<(String, String)> = time_entry::table
        .filter(time_entry::user_id.eq(user_id))
        .filter(time_entry::entry_date.between(to_iso(from), to_iso(to)))
        .order(time_entry::entry_date.asc())
        .select((time_entry::entry_date, time_entry::body))
        .load(conn)
        .context("select entries in range")?;
    Ok(rows
        .into_iter()
        .filter_map(|(d, b)| parse_iso(&d).map(|d| (d, b)))
        .collect())
}
```

Create `src/entries/mod.rs`:

```rust
//! Per-day time entries.

pub mod repo;
```

Add to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`: `pub mod entries;`

- [ ] **Step 8: Run the entry tests to verify they pass**

Run: `cargo test --features ssr --no-default-features entries::repo`
Expected: PASS — nine tests.

- [ ] **Step 9: Run the whole suite and clippy, then commit**

```bash
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features
git add src/auth/ src/entries/ src/lib.rs
git commit -m "feat(data): add user and per-day entry repositories

Pins invariant I7: every entry query is scoped by user_id inside the
WHERE clause, with cross-user read and write tests. Entry bodies are
opaque here — nothing parses them, because phase 2 stores ciphertext
in the same column.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 7: Magic-link tokens

**Files:**
- Create: `src/auth/magic_link.rs`
- Modify: `src/auth/mod.rs`

**Interfaces:**
- Consumes: `db::DbConn`, `auth::user`, `schema::magic_link_token`.
- Produces:
  - `auth::magic_link::mint(&mut DbConn, &str, Duration) -> anyhow::Result<String>` (returns the raw token)
  - `auth::magic_link::consume(&mut DbConn, &str) -> anyhow::Result<ConsumeResult>`
  - `auth::magic_link::ConsumeResult { Consumed { email }, Stale { email }, NotFound }`
  - `auth::magic_link::ttl() -> chrono::Duration`

- [ ] **Step 1: Write the failing tests**

Create `src/auth/magic_link.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[test]
    fn mint_then_consume_signs_in() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Consumed { email: "alice@example.com".to_string() }
        );
    }

    /// Single use. The second click is the common support case, and it must
    /// report Stale (so the caller can reissue) rather than NotFound.
    #[test]
    fn a_second_consume_is_stale() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        consume(&mut conn, &token).expect("first consume");
        assert_eq!(
            consume(&mut conn, &token).expect("second consume"),
            ConsumeResult::Stale { email: "alice@example.com".to_string() }
        );
    }

    #[test]
    fn an_expired_token_is_stale() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::seconds(-1)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Stale { email: "alice@example.com".to_string() }
        );
    }

    #[test]
    fn an_unknown_token_is_not_found() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert_eq!(
            consume(&mut conn, "no-such-token").expect("consume"),
            ConsumeResult::NotFound
        );
    }

    /// A database leak must not hand an attacker live sign-in links, so the
    /// raw token is never stored — only its SHA-256.
    #[test]
    fn the_raw_token_is_never_stored() {
        use crate::schema::magic_link_token;
        use diesel::prelude::*;

        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");

        let stored: Vec<u8> = magic_link_token::table
            .select(magic_link_token::token_hash)
            .first(&mut conn)
            .expect("row exists");
        assert_ne!(stored, token.as_bytes(), "token must be hashed, not stored raw");
        assert_eq!(stored.len(), 32, "SHA-256 is 32 bytes");
    }

    /// Two tokens minted back to back must differ, or one user's link would
    /// sign in another.
    #[test]
    fn tokens_are_unique() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        let b = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        assert_ne!(a, b);
    }

    /// The consuming UPDATE carries `used_at IS NULL` in its WHERE clause, so
    /// two racing clicks cannot both win. Simulated here by consuming twice
    /// against the same row and asserting exactly one Consumed.
    #[test]
    fn concurrent_consume_has_exactly_one_winner() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        let results = [
            consume(&mut conn, &token).expect("consume"),
            consume(&mut conn, &token).expect("consume"),
        ];
        let winners = results
            .iter()
            .filter(|r| matches!(r, ConsumeResult::Consumed { .. }))
            .count();
        assert_eq!(winners, 1, "exactly one consumer may win");
    }

    #[test]
    fn consume_normalizes_the_stored_email() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "  Alice@Example.COM ", Duration::minutes(15)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Consumed { email: "alice@example.com".to_string() }
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features auth::magic_link`
Expected: FAIL to compile — `cannot find function 'mint'`.

- [ ] **Step 3: Implement `src/auth/magic_link.rs`**

Prepend to `src/auth/magic_link.rs`:

```rust
//! One-time sign-in tokens delivered by email.
//!
//! The raw token exists only in the URL that is mailed out; the database
//! holds its SHA-256. A leaked database snapshot therefore yields no usable
//! sign-in links, only evidence that some link once existed.

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use ring::digest::{SHA256, digest};

use crate::auth::user::normalize_email;
use crate::db::DbConn;
use crate::schema::magic_link_token;

/// Outcome of presenting a token at `/magic/{token}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Valid and now spent. Sign the user in.
    Consumed { email: String },
    /// Known token, but already used or past its expiry. The caller should
    /// mint and mail a fresh link — this is the "clicked yesterday's email"
    /// case, and by far the most common support question.
    Stale { email: String },
    /// No such token.
    NotFound,
}

#[derive(Insertable)]
#[diesel(table_name = magic_link_token)]
struct NewToken<'a> {
    token_hash: &'a [u8],
    email: &'a str,
    expires_at: chrono::NaiveDateTime,
    created_at: chrono::NaiveDateTime,
}

/// The configured link lifetime, default 15 minutes.
pub fn ttl() -> Duration {
    let secs = std::env::var("MAGIC_LINK_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900);
    Duration::seconds(secs)
}

fn hash(token: &str) -> Vec<u8> {
    digest(&SHA256, token.as_bytes()).as_ref().to_vec()
}

/// Creates a token row and returns the raw token to embed in a URL.
///
/// The returned string is the only copy; it is not recoverable from the
/// database afterwards.
pub fn mint(conn: &mut DbConn, email: &str, ttl: Duration) -> Result<String> {
    let normalized = normalize_email(email)
        .ok_or_else(|| anyhow::anyhow!("not a usable email address"))?;
    let token = uuid::Uuid::now_v7().to_string();
    let now = Utc::now().naive_utc();

    diesel::insert_into(magic_link_token::table)
        .values(NewToken {
            token_hash: &hash(&token),
            email: &normalized,
            expires_at: now + ttl,
            created_at: now,
        })
        .execute(conn)
        .context("insert magic_link_token")?;

    Ok(token)
}

/// Atomically spends a token.
///
/// The SELECT and UPDATE run in one transaction and the UPDATE carries
/// `used_at IS NULL` in its own WHERE clause, so two concurrent consumers
/// race correctly: the loser's UPDATE matches zero rows and it reports
/// `Stale` rather than also signing in.
pub fn consume(conn: &mut DbConn, token: &str) -> Result<ConsumeResult> {
    let token_hash = hash(token);
    let now = Utc::now().naive_utc();

    conn.transaction(|conn| {
        let row: Option<(i32, String, Option<chrono::NaiveDateTime>, chrono::NaiveDateTime)> =
            magic_link_token::table
                .filter(magic_link_token::token_hash.eq(&token_hash))
                .select((
                    magic_link_token::id,
                    magic_link_token::email,
                    magic_link_token::used_at,
                    magic_link_token::expires_at,
                ))
                .first(conn)
                .optional()?;

        let Some((id, email, used_at, expires_at)) = row else {
            return Ok(ConsumeResult::NotFound);
        };

        if used_at.is_some() || expires_at <= now {
            return Ok(ConsumeResult::Stale { email });
        }

        let updated = diesel::update(
            magic_link_token::table
                .find(id)
                .filter(magic_link_token::used_at.is_null()),
        )
        .set(magic_link_token::used_at.eq(now))
        .execute(conn)?;

        if updated == 1 {
            Ok(ConsumeResult::Consumed { email })
        } else {
            // Lost the race: another request spent it between our SELECT and
            // our UPDATE.
            Ok(ConsumeResult::Stale { email })
        }
    })
    .context("consume magic link token")
}
```

Add `pub mod magic_link;` to `src/auth/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features auth::magic_link`
Expected: PASS — eight tests.

- [ ] **Step 5: Commit**

```bash
git add src/auth/magic_link.rs src/auth/mod.rs
git commit -m "feat(auth): add one-time magic-link tokens

Stores SHA-256 of the token, never the token, so a database leak yields
no live sign-in links. Consume runs SELECT and UPDATE in one
transaction with used_at IS NULL in the UPDATE's WHERE clause, so
concurrent clicks have exactly one winner.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 8: Passkey storage and ceremony state

**Files:**
- Create: `src/passkey/mod.rs`
- Create: `src/passkey/webauthn.rs`
- Create: `src/passkey/state.rs`
- Create: `src/passkey/store.rs`
- Create: `src/server/mod.rs`
- Create: `src/server/cookie.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `db::DbConn`, `schema::passkey_credential`.
- Produces:
  - `server::cookie::http_only(name: &str, value: &str, max_age: i64) -> String`
  - `passkey::webauthn::build_from_env() -> Arc<Webauthn>`
  - `passkey::state::{PasskeyState, encode, decode, set_cookie_header, clear_cookie_header, COOKIE_NAME}`
  - `passkey::store::{PasskeyRow, insert, list_by_user, find_by_credential_id, user_has_passkey, delete_for_user, rename_for_user, update_after_use, default_name, MAX_NAME_LEN}`

- [ ] **Step 1: Write and implement the cookie helper**

Create `src/server/cookie.rs`:

```rust
//! Shared `Set-Cookie` construction.
//!
//! One shape for both cookies this app sets: `Path=/`, `HttpOnly`,
//! `SameSite=Lax`, and `Secure` outside debug builds. Pass an empty value
//! with `max_age = 0` to clear.

/// Builds an `HttpOnly; SameSite=Lax` cookie header scoped to `Path=/`.
pub fn http_only(name: &str, value: &str, max_age: i64) -> String {
    let secure = if cfg!(debug_assertions) { "" } else { "; Secure" };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age={max_age}")
}

#[cfg(test)]
mod tests {
    use super::http_only;

    /// `Secure` is build-mode dependent, so assert it against the same cfg
    /// the helper uses rather than hardcoding one build's answer.
    fn secure_suffix() -> &'static str {
        if cfg!(debug_assertions) { "" } else { "; Secure" }
    }

    #[test]
    fn sets_a_session_cookie() {
        assert_eq!(
            http_only("tt_session", "abc", 2_592_000),
            format!("tt_session=abc; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=2592000", secure_suffix())
        );
    }

    #[test]
    fn clears_with_an_empty_value_and_zero_age() {
        assert_eq!(
            http_only("tt_session", "", 0),
            format!("tt_session=; Path=/; HttpOnly; SameSite=Lax{}; Max-Age=0", secure_suffix())
        );
    }
}
```

Create `src/server/mod.rs`:

```rust
//! Server-only HTTP plumbing.

pub mod cookie;
```

Add to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`: `pub mod server;`

- [ ] **Step 2: Implement the Webauthn singleton**

Create `src/passkey/webauthn.rs`:

```rust
//! The `Webauthn` instance, built once from env at startup.

use std::sync::Arc;
use webauthn_rs::prelude::*;

/// Builds the relying-party configuration.
///
/// Defaults suit local development against `cargo leptos watch`. In
/// production `WEBAUTHN_RP_ORIGIN` must match the browser's origin exactly,
/// scheme included, or every ceremony fails with an origin mismatch.
pub fn build_from_env() -> Arc<Webauthn> {
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin_str = std::env::var("WEBAUTHN_RP_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_string());
    let rp_origin = Url::parse(&rp_origin_str)
        .unwrap_or_else(|e| panic!("invalid WEBAUTHN_RP_ORIGIN={rp_origin_str:?}: {e}"));
    let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Time Tracker".to_string());

    Arc::new(
        WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("WebauthnBuilder::new")
            .rp_name(&rp_name)
            .build()
            .expect("Webauthn::build"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_defaults() {
        let _wa: Arc<Webauthn> = build_from_env();
    }
}
```

- [ ] **Step 3: Write the failing tests for ceremony state**

Create `src/passkey/state.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::passkey::webauthn::build_from_env;

    fn a_registration() -> (String, PasskeyRegistration) {
        // SAFETY of intent: the key only needs to be non-empty and stable
        // within the test process.
        unsafe { std::env::set_var("PASSKEY_STATE_KEY", "test-passkey-state-key") };
        let wa = build_from_env();
        let (_ccr, reg) = wa
            .start_passkey_registration(
                Uuid::new_v4(),
                "alice@example.com",
                "alice@example.com",
                None,
            )
            .expect("start registration");
        ("alice@example.com".to_string(), reg)
    }

    #[test]
    fn encode_decode_round_trips() {
        let (subject, reg) = a_registration();
        let encoded = encode(&PasskeyState::reg(subject.clone(), reg)).expect("encode");
        match decode(&encoded).expect("decode") {
            PasskeyState::Reg { subject: got, .. } => assert_eq!(got, subject),
            other => panic!("expected Reg, got {other:?}"),
        }
    }

    /// The ceremony state rides in a cookie the user can edit. A tampered
    /// payload must be rejected, not deserialized.
    #[test]
    fn rejects_a_tampered_payload() {
        let (subject, reg) = a_registration();
        let encoded = encode(&PasskeyState::reg(subject, reg)).expect("encode");
        let mut bytes = BASE64_URL_SAFE_NO_PAD.decode(encoded.as_bytes()).expect("decode b64");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        assert!(decode(&BASE64_URL_SAFE_NO_PAD.encode(&bytes)).is_err());
    }

    #[test]
    fn rejects_an_expired_state() {
        let (subject, reg) = a_registration();
        let mut state = PasskeyState::reg(subject, reg);
        match &mut state {
            PasskeyState::Reg { expires_at, .. } => *expires_at = now_secs() - 1,
            _ => unreachable!(),
        }
        let encoded = encode(&state).expect("encode");
        assert!(decode(&encoded).is_err(), "expired state must not decode");
    }

    #[test]
    fn clear_header_expires_the_cookie() {
        assert!(clear_cookie_header().contains("Max-Age=0"));
        assert!(clear_cookie_header().starts_with(COOKIE_NAME));
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features passkey::state`
Expected: FAIL to compile — `cannot find type 'PasskeyState'`.

- [ ] **Step 5: Implement `src/passkey/state.rs`**

Prepend to `src/passkey/state.rs`:

```rust
//! In-flight WebAuthn ceremony state, HMAC-signed into a short-lived cookie.
//!
//! Never persisted to the database: a ceremony lasts seconds, and a table
//! would need sweeping. The signature is what makes it safe to hand the
//! state to the client — a user can read their own ceremony state, but
//! cannot forge one naming another subject.
//!
//! Signed with `PASSKEY_STATE_KEY`, deliberately *not* the session key.
//! photo365 reuses one `HASH_KEY` for every purpose; separate keys mean
//! compromising one does not forge the others.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::BASE64_URL_SAFE_NO_PAD;
use chrono::Utc;
use ring::hmac;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::server::cookie;

pub const COOKIE_NAME: &str = "__pk_state";
const MAX_AGE_SECONDS: i64 = 300;
/// Domain separation, so a signature minted here can never be replayed as a
/// session token even if the two keys were ever misconfigured to match.
const DOMAIN_TAG: &[u8] = b"passkey-ceremony-v1\0";
const SIG_LEN: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PasskeyState {
    Reg {
        subject: String,
        reg: PasskeyRegistration,
        expires_at: i64,
    },
    Auth {
        subject: String,
        auth: PasskeyAuthentication,
        expires_at: i64,
    },
    DiscoverableAuth {
        auth: DiscoverableAuthentication,
        expires_at: i64,
    },
}

impl PasskeyState {
    pub fn reg(subject: String, reg: PasskeyRegistration) -> Self {
        Self::Reg { subject, reg, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    pub fn auth(subject: String, auth: PasskeyAuthentication) -> Self {
        Self::Auth { subject, auth, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    pub fn discoverable(auth: DiscoverableAuthentication) -> Self {
        Self::DiscoverableAuth { auth, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    fn expires_at(&self) -> i64 {
        match self {
            Self::Reg { expires_at, .. }
            | Self::Auth { expires_at, .. }
            | Self::DiscoverableAuth { expires_at, .. } => *expires_at,
        }
    }
}

fn now_secs() -> i64 {
    Utc::now().timestamp()
}

fn key() -> hmac::Key {
    let configured = std::env::var("PASSKEY_STATE_KEY").unwrap_or_default();
    let configured = if configured.is_empty() {
        // Fall back to the session key rather than a constant: still a real
        // secret, still domain-separated by DOMAIN_TAG below.
        std::env::var("SESSION_KEY").unwrap_or_default()
    } else {
        configured
    };
    assert!(
        !configured.is_empty(),
        "PASSKEY_STATE_KEY (or SESSION_KEY) must be set to a non-empty value"
    );
    let mut material = DOMAIN_TAG.to_vec();
    material.extend_from_slice(configured.as_bytes());
    hmac::Key::new(hmac::HMAC_SHA256, &material)
}

pub fn encode(state: &PasskeyState) -> Result<String> {
    let body = serde_json::to_vec(state).context("serialize ceremony state")?;
    let sig = hmac::sign(&key(), &body);
    let mut out = body;
    out.extend_from_slice(sig.as_ref());
    Ok(BASE64_URL_SAFE_NO_PAD.encode(&out))
}

pub fn decode(raw: &str) -> Result<PasskeyState> {
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .context("base64 decode ceremony state")?;
    if bytes.len() < SIG_LEN {
        bail!("ceremony state payload too short");
    }
    let (body, sig) = bytes.split_at(bytes.len() - SIG_LEN);
    hmac::verify(&key(), body, sig).map_err(|_| anyhow!("ceremony state signature invalid"))?;
    let state: PasskeyState =
        serde_json::from_slice(body).context("deserialize ceremony state")?;
    if state.expires_at() < now_secs() {
        bail!("ceremony state expired");
    }
    Ok(state)
}

pub fn set_cookie_header(encoded: &str) -> String {
    cookie::http_only(COOKIE_NAME, encoded, MAX_AGE_SECONDS)
}

pub fn clear_cookie_header() -> String {
    cookie::http_only(COOKIE_NAME, "", 0)
}
```

Create `src/passkey/mod.rs`:

```rust
//! Server-side WebAuthn / passkey support.

pub mod state;
pub mod store;
pub mod webauthn;
```

Add to `src/lib.rs`, gated `#[cfg(feature = "ssr")]`: `pub mod passkey;`

- [ ] **Step 6: Run the state tests to verify they pass**

Run: `cargo test --features ssr --no-default-features passkey::`
Expected: PASS — five tests (four state, one webauthn).

- [ ] **Step 7: Write the failing tests for the passkey store**

Create `src/passkey/store.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::auth::user;
    use crate::db::{DbConn, test_pool};
    use crate::passkey::webauthn::build_from_env;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    /// Enrols a credential through a real software authenticator, so the
    /// stored blob is the same shape a browser produces.
    fn enrol(subject: &str) -> Passkey {
        let wa = build_from_env();
        let (ccr, reg_state) = wa
            .start_passkey_registration(Uuid::new_v4(), subject, subject, None)
            .expect("start registration");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let rsp = authenticator
            .do_registration(wa.get_allowed_origins()[0].clone(), ccr)
            .expect("authenticator registration");
        wa.finish_passkey_registration(&rsp, &reg_state)
            .expect("finish registration")
    }

    fn user_id(conn: &mut DbConn, email: &str) -> i32 {
        user::find_or_create(conn, email).expect("create user").id
    }

    #[test]
    fn insert_then_list_round_trips() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");

        let rows = list_by_user(&mut conn, uid).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].credential_id, key.cred_id().to_vec());
    }

    /// The blob must deserialize back into a usable Passkey. This is the
    /// test that catches a bincode/serde_json mix-up: bincode cannot handle
    /// Passkey's flattened extension map and fails only at read time.
    #[test]
    fn stored_blob_deserializes_back_to_a_passkey() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");

        let rows = list_by_user(&mut conn, uid).expect("list");
        let restored = rows[0].deserialize_passkey().expect("blob decodes");
        assert_eq!(restored.cred_id(), key.cred_id());
    }

    #[test]
    fn find_by_credential_id_locates_the_row() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");
        let found = find_by_credential_id(&mut conn, key.cred_id().as_ref())
            .expect("query")
            .expect("row found");
        assert_eq!(found.user_id, uid);
    }

    #[test]
    fn user_has_passkey_reflects_enrolment() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        assert!(!user_has_passkey(&mut conn, uid).expect("query"));
        insert(&mut conn, uid, &enrol("alice@example.com"), false).expect("insert");
        assert!(user_has_passkey(&mut conn, uid).expect("query"));
    }

    #[test]
    fn prf_capability_is_persisted() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        insert(&mut conn, uid, &enrol("alice@example.com"), true).expect("insert");
        assert!(list_by_user(&mut conn, uid).expect("list")[0].prf_capable);
    }

    /// Pins invariant I7 for passkeys. The owning user is part of the
    /// DELETE's WHERE clause, so another user's delete matches no row.
    #[test]
    fn delete_is_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        insert(&mut conn, alice, &enrol("alice@example.com"), false).expect("insert");
        let row_id = list_by_user(&mut conn, alice).expect("list")[0].id;

        assert!(!delete_for_user(&mut conn, row_id, mallory).expect("delete"));
        assert_eq!(list_by_user(&mut conn, alice).expect("list").len(), 1);
        assert!(delete_for_user(&mut conn, row_id, alice).expect("delete"));
        assert!(list_by_user(&mut conn, alice).expect("list").is_empty());
    }

    #[test]
    fn rename_is_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        insert(&mut conn, alice, &enrol("alice@example.com"), false).expect("insert");
        let row_id = list_by_user(&mut conn, alice).expect("list")[0].id;

        assert!(!rename_for_user(&mut conn, row_id, mallory, Some("pwned")).expect("rename"));
        assert!(rename_for_user(&mut conn, row_id, alice, Some("Laptop")).expect("rename"));
        assert_eq!(
            list_by_user(&mut conn, alice).expect("list")[0].name.as_deref(),
            Some("Laptop")
        );
    }

    #[test]
    fn default_name_is_date_derived() {
        let when = chrono::NaiveDate::from_ymd_opt(2026, 9, 4)
            .expect("valid date")
            .and_hms_opt(12, 0, 0)
            .expect("valid time");
        assert_eq!(default_name(when), "Passkey · Sep 4, 2026");
    }
}
```

- [ ] **Step 8: Run the store tests to verify they fail**

Run: `cargo test --features ssr --no-default-features passkey::store`
Expected: FAIL to compile — `cannot find function 'insert'`.

- [ ] **Step 9: Implement `src/passkey/store.rs`**

Prepend to `src/passkey/store.rs`:

```rust
//! Diesel CRUD for `passkey_credential`.
//!
//! Credentials hang off `user_id`, not a free-text email column as in
//! photo365: a foreign key makes the user row the single identity anchor,
//! which matters once phase 2 attaches wrapped encryption keys to it.

use anyhow::{Context, Result};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use webauthn_rs::prelude::*;

use crate::db::DbConn;
use crate::schema::passkey_credential;

/// Longest customer-supplied passkey label we store.
pub const MAX_NAME_LEN: usize = 64;

#[derive(Queryable, Debug, Clone)]
pub struct PasskeyRow {
    pub id: i32,
    pub user_id: i32,
    pub credential_id: Vec<u8>,
    passkey: Vec<u8>,
    pub name: Option<String>,
    pub prf_capable: bool,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

impl PasskeyRow {
    /// Decodes the stored credential.
    ///
    /// `serde_json`, **not** bincode. `Passkey` flattens a
    /// `BTreeMap<String, serde_cbor_2::Value>` of unknown extension keys,
    /// which needs a self-describing format; bincode calls
    /// `deserialize_any` on the flattened map and fails — and only once a
    /// real authenticator returns an extension, so it survives naive tests.
    pub fn deserialize_passkey(&self) -> Result<Passkey> {
        serde_json::from_slice(&self.passkey).context("decode Passkey blob")
    }

    /// The label to show, falling back to a date-derived default.
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| default_name(self.created_at))
    }
}

/// The label used when the user has not named a credential.
pub fn default_name(created_at: NaiveDateTime) -> String {
    format!("Passkey · {}", created_at.format("%b %-d, %Y"))
}

#[derive(Insertable)]
#[diesel(table_name = passkey_credential)]
struct NewPasskey<'a> {
    user_id: i32,
    credential_id: &'a [u8],
    passkey: &'a [u8],
    name: Option<String>,
    prf_capable: bool,
    created_at: NaiveDateTime,
}

/// Stores a freshly registered credential.
///
/// `prf_capable` records whether the authenticator reported PRF support at
/// creation time. Nothing reads it in phase 1; it exists so phase 2 can tell
/// which credentials can derive an encryption key without making every user
/// delete and re-enrol (spec section 9.3).
pub fn insert(conn: &mut DbConn, user_id: i32, key: &Passkey, prf_capable: bool) -> Result<i32> {
    let blob = serde_json::to_vec(key).context("encode Passkey blob")?;
    let cred_id = key.cred_id().to_vec();
    let now = Utc::now().naive_utc();

    conn.transaction(|conn| {
        diesel::insert_into(passkey_credential::table)
            .values(NewPasskey {
                user_id,
                credential_id: &cred_id,
                passkey: &blob,
                name: None,
                prf_capable,
                created_at: now,
            })
            .execute(conn)?;
        passkey_credential::table
            .filter(passkey_credential::credential_id.eq(&cred_id))
            .select(passkey_credential::id)
            .first::<i32>(conn)
    })
    .context("insert passkey_credential")
}

pub fn list_by_user(conn: &mut DbConn, user_id: i32) -> Result<Vec<PasskeyRow>> {
    Ok(passkey_credential::table
        .filter(passkey_credential::user_id.eq(user_id))
        .order(passkey_credential::created_at.desc())
        .load::<PasskeyRow>(conn)
        .context("list passkeys")?)
}

pub fn find_by_credential_id(conn: &mut DbConn, cred_id: &[u8]) -> Result<Option<PasskeyRow>> {
    Ok(passkey_credential::table
        .filter(passkey_credential::credential_id.eq(cred_id))
        .first::<PasskeyRow>(conn)
        .optional()
        .context("find passkey by credential id")?)
}

pub fn user_has_passkey(conn: &mut DbConn, user_id: i32) -> Result<bool> {
    let n: i64 = passkey_credential::table
        .filter(passkey_credential::user_id.eq(user_id))
        .count()
        .get_result(conn)
        .context("count passkeys")?;
    Ok(n > 0)
}

/// Deletes a credential. The owning `user_id` is part of the WHERE clause,
/// so another user's request matches no row rather than being rejected after
/// a separate ownership check — no TOCTOU window.
pub fn delete_for_user(conn: &mut DbConn, id: i32, user_id: i32) -> Result<bool> {
    let n = diesel::delete(
        passkey_credential::table
            .filter(passkey_credential::id.eq(id))
            .filter(passkey_credential::user_id.eq(user_id)),
    )
    .execute(conn)
    .context("delete passkey")?;
    Ok(n > 0)
}

/// Renames a credential, scoped the same way as [`delete_for_user`].
pub fn rename_for_user(
    conn: &mut DbConn,
    id: i32,
    user_id: i32,
    name: Option<&str>,
) -> Result<bool> {
    let trimmed = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_NAME_LEN).collect::<String>());
    let n = diesel::update(
        passkey_credential::table
            .filter(passkey_credential::id.eq(id))
            .filter(passkey_credential::user_id.eq(user_id)),
    )
    .set(passkey_credential::name.eq(trimmed))
    .execute(conn)
    .context("rename passkey")?;
    Ok(n > 0)
}

/// Persists the advanced credential counter after a successful assertion.
pub fn update_after_use(conn: &mut DbConn, row_id: i32, key: &Passkey) -> Result<()> {
    let blob = serde_json::to_vec(key).context("encode Passkey blob")?;
    diesel::update(passkey_credential::table.find(row_id))
        .set((
            passkey_credential::passkey.eq(blob),
            passkey_credential::last_used_at.eq(Utc::now().naive_utc()),
        ))
        .execute(conn)
        .context("update passkey after use")?;
    Ok(())
}
```

- [ ] **Step 10: Run the store tests to verify they pass**

Run: `cargo test --features ssr --no-default-features passkey::`
Expected: PASS — thirteen tests.

- [ ] **Step 11: Run the whole suite, clippy, and the wasm build; then commit**

```bash
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/passkey/ src/server/ src/lib.rs
git commit -m "feat(passkey): add credential store and signed ceremony state

Credentials key off user_id rather than photo365's free-text subject.
Ceremony state is signed with PASSKEY_STATE_KEY, separate from the
session key and domain-separated, so neither signature can be replayed
as the other. Blobs are serde_json because Passkey's flattened
extension map cannot round-trip through bincode.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Phase 3 — Server wiring

### Task 9: Application context, session middleware, and route order

**Files:**
- Create: `src/context.rs`
- Create: `src/auth/middleware.rs`
- Modify: `src/main.rs`, `src/auth/mod.rs`, `src/lib.rs`
- Create: `tests/routes.rs`

**Interfaces:**
- Consumes: `db::{DbPool, build_pool, run_migrations}`, `session::{verify, COOKIE_NAME}`, `passkey::webauthn::build_from_env`, `email::Mailer` (Task 10 — until then the field is added but constructed as `Mailer::Disabled`).
- Produces:
  - `context::AppCtx { pool: DbPool, mailer: Mailer, webauthn: Arc<Webauthn>, claims: Option<SessionClaims>, client_ip: Option<String> }`
  - `AppCtx::conn(&self) -> anyhow::Result<DbConn>`
  - `AppCtx::with_session(&self, Option<SessionClaims>, Option<String>) -> AppCtx`
  - `auth::middleware::attach` — an axum `from_fn` middleware

**Ordering note:** Task 10 creates `email::Mailer`. Implement `Mailer` as an empty enum stub here only if you are executing tasks out of order; the normal order is 9 → 10, and Task 9's `AppCtx` references `Mailer` by name. If `email` does not exist yet, create `src/email/mod.rs` containing just `pub enum Mailer { Disabled }` and let Task 10 fill it in.

- [ ] **Step 1: Implement `src/context.rs`**

```rust
//! The per-request application context.
//!
//! A base `AppCtx` (pool, mailer, webauthn) is built once at startup and
//! layered onto the router. The session middleware clones it per request,
//! attaching that request's verified claims, and stashes the clone in the
//! request's extensions. Both the page-render handler and the server-fn
//! handler pull it back out and `provide_context` it, so a server fn reaches
//! everything it needs through `use_context::<AppCtx>()`.

use std::sync::Arc;

use anyhow::Context;
use webauthn_rs::prelude::Webauthn;

use crate::db::{DbConn, DbPool};
use crate::email::Mailer;
use crate::session::SessionClaims;

#[derive(Clone)]
pub struct AppCtx {
    pub pool: DbPool,
    pub mailer: Mailer,
    pub webauthn: Arc<Webauthn>,
    /// The verified session claims for this request, if any.
    ///
    /// Verified means signature and clock only — it does **not** mean the
    /// user still exists or has not signed out everywhere. Callers that
    /// touch user data must go through `server_fns::require_user`.
    pub claims: Option<SessionClaims>,
    pub client_ip: Option<String>,
}

impl AppCtx {
    /// Builds the base context. Call once at startup.
    pub fn new(pool: DbPool, mailer: Mailer) -> Self {
        Self {
            pool,
            mailer,
            webauthn: crate::passkey::webauthn::build_from_env(),
            claims: None,
            client_ip: None,
        }
    }

    pub fn conn(&self) -> anyhow::Result<DbConn> {
        self.pool.get().context("checkout database connection")
    }

    /// Clones the base context with this request's session attached.
    pub fn with_session(&self, claims: Option<SessionClaims>, client_ip: Option<String>) -> Self {
        Self {
            claims,
            client_ip,
            ..self.clone()
        }
    }
}
```

- [ ] **Step 2: Implement `src/auth/middleware.rs`**

```rust
//! Axum middleware that turns a cookie into session claims.

use axum::extract::{ConnectInfo, Extension, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;

use crate::context::AppCtx;
use crate::session::{self, COOKIE_NAME};

/// Verifies the session cookie and attaches the result to the request.
///
/// An absent, malformed, expired, or badly-signed cookie all produce the
/// same outcome — `claims: None` — because none of them is distinguishable
/// to a legitimate visitor and treating them differently only leaks detail.
pub async fn attach(
    Extension(base): Extension<AppCtx>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let claims = jar
        .get(COOKIE_NAME)
        .and_then(|c| session::verify(c.value()).ok());

    let client_ip = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());

    req.extensions_mut().insert(base.with_session(claims, client_ip));
    next.run(req).await
}
```

Add `pub mod middleware;` to `src/auth/mod.rs`. Add `pub mod context;` (gated `ssr`) to `src/lib.rs`.

- [ ] **Step 3: Rewrite `src/main.rs`**

```rust
#![recursion_limit = "512"]

#[cfg(feature = "ssr")]
mod server_main {
    use axum::body::Body;
    use axum::extract::{Extension, State};
    use axum::http::Request;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Router, middleware};
    use leptos::prelude::*;
    use leptos_axum::{
        LeptosRoutes, generate_route_list, handle_server_fns_with_context,
        render_app_to_stream_with_context,
    };
    use time_tracking_leptos::app::{App, shell};
    use time_tracking_leptos::context::AppCtx;
    use time_tracking_leptos::{auth, db, email};

    /// Root-level static files that must be routed explicitly.
    ///
    /// The app's `/{date}` route matches **any** single path segment, so it
    /// shadows the static-file fallback for anything at the root. Adding a
    /// file to `public/` at the top level means adding it here too, or it
    /// silently starts serving the app's HTML instead. Nested paths
    /// (`/pkg/...`) are unaffected — they have more than one segment.
    const ROOT_ASSETS: &[&str] = &["/favicon.ico"];

    /// Renders a page with the per-request context in scope.
    async fn leptos_routes_handler(
        State(options): State<LeptosOptions>,
        Extension(ctx): Extension<AppCtx>,
        req: Request<Body>,
    ) -> Response {
        let handler = render_app_to_stream_with_context(
            {
                let ctx = ctx.clone();
                move || provide_context(ctx.clone())
            },
            move || shell(options.clone()),
        );
        handler(req).await.into_response()
    }

    /// Dispatches a server fn with the per-request context in scope.
    async fn server_fn_handler(
        Extension(ctx): Extension<AppCtx>,
        req: Request<Body>,
    ) -> impl IntoResponse {
        handle_server_fns_with_context(move || provide_context(ctx.clone()), req).await
    }

    pub async fn run() {
        dotenvy::dotenv().ok();
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::fmt().with_env_filter(filter).init();

        let conf = get_configuration(None).expect("failed to read Leptos configuration");
        let leptos_options = conf.leptos_options;
        let addr = leptos_options.site_addr;
        let routes = generate_route_list(App);

        let pool = db::build_pool().expect("build database pool");
        db::run_migrations(&pool).expect("run migrations");
        let base_ctx = AppCtx::new(pool, email::Mailer::from_env());

        let static_handler = leptos_axum::file_and_error_handler::<LeptosOptions, _>(shell);
        let mut app = Router::<LeptosOptions>::new()
            // Before the Leptos routes: `/magic/{token}` and the root assets
            // must win over `/{date}`.
            .route("/magic/{token}", get(auth::handler::consume));
        for path in ROOT_ASSETS {
            app = app.route(path, get(static_handler.clone()));
        }

        let app = app
            .route(
                "/api/{*fn_name}",
                post(server_fn_handler).get(server_fn_handler),
            )
            .leptos_routes_with_handler(routes, get(leptos_routes_handler))
            .fallback(static_handler)
            .layer(middleware::from_fn(auth::middleware::attach))
            .layer(Extension(base_ctx))
            .with_state(leptos_options);

        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .expect("failed to bind listen address");
        tracing::info!("listening on http://{addr}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .expect("server error");
    }
}

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    server_main::run().await;
}

#[cfg(not(feature = "ssr"))]
fn main() {
    // The wasm bundle's entrypoint is `lib::hydrate`, not this.
}
```

- [ ] **Step 4: Write the failing route-priority test**

Create `tests/routes.rs`:

```rust
//! Pins spec invariant I4: adding `/{date}` as a top-level route means any
//! single-segment path now matches the app. Static root assets and the
//! `/account` route must still win.

#![cfg(feature = "ssr")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Builds the router exactly as `main` does. Kept in sync by construction:
/// `time_tracking_leptos::test_support::router()` is the same function main
/// calls.
async fn get(path: &str) -> (StatusCode, String) {
    let app = time_tracking_leptos::test_support::router().await;
    let res = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn favicon_is_not_shadowed_by_the_date_route() {
    let (status, body) = get("/favicon.ico").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<!DOCTYPE html>"),
        "/favicon.ico served the app shell — the /{{date}} route is shadowing \
         the static handler (see ROOT_ASSETS in main.rs)"
    );
}

#[tokio::test]
async fn account_route_beats_the_date_route() {
    let (status, body) = get("/account").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Passkeys"),
        "/account rendered the day view instead of the account page"
    );
}

#[tokio::test]
async fn a_real_date_renders_the_day_view() {
    let (status, body) = get("/2026-09-04").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Time Entry"), "date route did not render the day view");
}

#[tokio::test]
async fn a_non_date_segment_is_not_found() {
    let (_, body) = get("/definitely-not-a-date").await;
    assert!(body.contains("Page not found"), "junk segment must render NotFound");
}
```

- [ ] **Step 5: Add the shared router builder**

The test and `main` must build the *same* router, or the test pins nothing. Extract it. In `src/lib.rs`, add:

```rust
/// Router construction shared by `main` and the integration tests.
///
/// Not `#[cfg(test)]`: `tests/` is a separate crate and cannot see
/// `#[cfg(test)]` items. Gated on `ssr` so it never reaches wasm.
#[cfg(feature = "ssr")]
pub mod test_support;
```

Create `src/test_support.rs` exposing `pub async fn router() -> axum::Router`, and move the router-building body of `server_main::run` into it so both call the same code. `run` becomes: build the router via `test_support::router()`, bind, serve. Set `DATABASE_URL=:memory:` and `SESSION_KEY` inside `router()` when they are unset, so the test binary needs no environment.

- [ ] **Step 6: Run the route tests**

Run: `cargo test --features ssr --no-default-features --test routes`
Expected: PASS — four tests. `account_route_beats_the_date_route` will fail until Task 21 adds `/account`; mark it `#[ignore]` with the reason `"enabled by Task 21"` and remove the attribute there.

- [ ] **Step 7: Commit**

```bash
git add src/context.rs src/auth/middleware.rs src/main.rs src/test_support.rs src/lib.rs tests/routes.rs
git commit -m "feat(server): add per-request context, session middleware, routing

Pins invariant I4. The new /{date} route matches any single path
segment, which shadows the static-file fallback for root assets; the
ROOT_ASSETS list and its test are what keep /favicon.ico working.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 10: The mailer

**Files:**
- Create: `src/email/mod.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `email::Mailer { Smtp(SmtpMailer), Capture(CaptureMailer), Disabled }`, `Mailer::from_env() -> Mailer`, `Mailer::capture() -> Mailer`, `Mailer::send(&self, OutboundEmail)`, `Mailer::captured(&self) -> Vec<OutboundEmail>`, `email::OutboundEmail { to, subject, text, html }`, `email::site_base_url() -> String`, `email::magic_link_email(&str, i64) -> (String, String)`, `email::mask(&str) -> String`.

- [ ] **Step 1: Write the failing tests**

Create `src/email/mod.rs` with only the tests:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capture_records_what_was_sent() {
        let mailer = Mailer::capture();
        mailer
            .send(OutboundEmail {
                to: "alice@example.com".into(),
                subject: "hi".into(),
                text: "body".into(),
                html: None,
            })
            .await
            .expect("capture send");
        let got = mailer.captured();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].to, "alice@example.com");
    }

    /// An unconfigured mailer must be a loud no-op, not an error that fails
    /// the sign-in request. Development runs this way by design.
    #[tokio::test]
    async fn disabled_send_succeeds_and_records_nothing() {
        let mailer = Mailer::Disabled;
        assert!(mailer.send(OutboundEmail {
            to: "alice@example.com".into(),
            subject: "hi".into(),
            text: "body".into(),
            html: None,
        }).await.is_ok());
        assert!(mailer.captured().is_empty());
    }

    #[test]
    fn magic_link_email_contains_the_url_in_both_parts() {
        let (text, html) = magic_link_email("https://example.test/magic/abc", 900);
        assert!(text.contains("https://example.test/magic/abc"));
        assert!(html.contains("https://example.test/magic/abc"));
        assert!(text.contains("15 minutes"), "TTL must be stated in minutes");
    }

    /// The "check your email" screen echoes the address back. Masking keeps
    /// a shoulder-surfer from reading a full address off the screen while
    /// still letting the user confirm they typed the right one.
    #[test]
    fn masks_an_address_for_display() {
        assert_eq!(mask("alice@example.com"), "ali•••@example.com");
        assert_eq!(mask("ab@example.com"), "•••@example.com");
        assert_eq!(mask("not-an-address"), "•••");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --features ssr --no-default-features email::`
Expected: FAIL to compile — `cannot find type 'Mailer'`.

- [ ] **Step 3: Implement `src/email/mod.rs`**

Prepend to `src/email/mod.rs`:

```rust
//! Outbound email.
//!
//! Three transports: `Smtp` for production, `Capture` so tests can assert on
//! a message without a relay, and `Disabled` for a development run with no
//! SMTP configured — which logs the link instead of sending it.
//!
//! There is deliberately **no durable outbox**. photo365 has one (a table, a
//! worker, exponential backoff) because it sends order notifications that
//! must not be lost. This app sends exactly one kind of message, a sign-in
//! link that expires in fifteen minutes and that the user can re-request by
//! clicking a button. Retry machinery would cost more than it buys.
//! Sends are `tokio::spawn`ed by the caller so a slow relay never parks a
//! request.

use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundEmail {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

#[derive(Clone, Default)]
pub struct CaptureMailer {
    sent: Arc<Mutex<Vec<OutboundEmail>>>,
}

#[derive(Clone)]
pub struct SmtpMailer {
    from: String,
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
}

#[derive(Clone)]
pub enum Mailer {
    Smtp(SmtpMailer),
    Capture(CaptureMailer),
    /// No SMTP configured. Sends log the message and succeed.
    Disabled,
}

impl Mailer {
    /// Builds the production transport, or `Disabled` when `SMTP_HOST` is
    /// unset. Unset is a supported development mode, not an error.
    pub fn from_env() -> Self {
        match SmtpMailer::from_env() {
            Some(m) => Mailer::Smtp(m),
            None => {
                tracing::warn!(
                    "SMTP_HOST is unset; magic links will be logged, not emailed"
                );
                Mailer::Disabled
            }
        }
    }

    pub fn capture() -> Self {
        Mailer::Capture(CaptureMailer::default())
    }

    pub async fn send(&self, email: OutboundEmail) -> anyhow::Result<()> {
        match self {
            Mailer::Smtp(m) => m.send(email).await,
            Mailer::Capture(m) => {
                m.sent
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(email);
                Ok(())
            }
            Mailer::Disabled => {
                tracing::info!(to = %email.to, "email not sent (no SMTP configured):\n{}", email.text);
                Ok(())
            }
        }
    }

    /// Test support: read back what `Capture` recorded.
    pub fn captured(&self) -> Vec<OutboundEmail> {
        match self {
            Mailer::Capture(m) => m.sent.lock().unwrap_or_else(|p| p.into_inner()).clone(),
            _ => Vec::new(),
        }
    }
}

impl SmtpMailer {
    fn from_env() -> Option<Self> {
        use lettre::transport::smtp::authentication::Credentials;

        let host = std::env::var("SMTP_HOST").ok().filter(|s| !s.is_empty())?;
        let port = std::env::var("SMTP_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(587);
        let user = std::env::var("SMTP_USER").ok().filter(|s| !s.is_empty())?;
        let pass = std::env::var("SMTP_PASS").ok().filter(|s| !s.is_empty())?;
        let from = std::env::var("SMTP_FROM").ok().filter(|s| !s.is_empty())?;

        let transport =
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&host)
                .ok()?
                .port(port)
                .credentials(Credentials::new(user, pass))
                .build();
        Some(Self { from, transport })
    }

    async fn send(&self, email: OutboundEmail) -> anyhow::Result<()> {
        use lettre::AsyncTransport;
        use lettre::message::{MultiPart, SinglePart, header};

        let builder = lettre::Message::builder()
            .from(self.from.parse()?)
            .to(email.to.parse()?)
            .subject(&email.subject);

        let message = match email.html {
            Some(html) => builder.multipart(MultiPart::alternative_plain_html(email.text, html))?,
            None => builder
                .singlepart(SinglePart::builder().header(header::ContentType::TEXT_PLAIN).body(email.text))?,
        };
        self.transport.send(message).await?;
        Ok(())
    }
}

/// The absolute base the magic-link URL is built from.
pub fn site_base_url() -> String {
    std::env::var("SITE_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

/// The sign-in email's plain-text and HTML bodies.
pub fn magic_link_email(url: &str, ttl_seconds: i64) -> (String, String) {
    let minutes = ttl_seconds / 60;
    let text = format!(
        "Here's your sign-in link for Time Tracker:\n\n  {url}\n\n\
         It expires in {minutes} minutes and can only be used once.\n\n\
         If you didn't request this, you can ignore this email.\n"
    );
    let html = format!(
        "<p>Here's your sign-in link for Time Tracker:</p>\
         <p><a href=\"{url}\">{url}</a></p>\
         <p>It expires in {minutes} minutes and can only be used once.</p>\
         <p>If you didn't request this, you can ignore this email.</p>"
    );
    (text, html)
}

/// Partially hides an address for display on the "check your email" screen.
pub fn mask(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "•••".to_string();
    };
    if local.chars().count() <= 2 {
        return format!("•••@{domain}");
    }
    let head: String = local.chars().take(3).collect();
    format!("{head}•••@{domain}")
}
```

Add `pub mod email;` (gated `ssr`) to `src/lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features email::`
Expected: PASS — four tests.

- [ ] **Step 5: Verify no OpenSSL crept in with lettre, then commit**

```bash
cargo tree -i openssl-sys --features ssr --no-default-features 2>&1 | tail -2
cargo clippy --features ssr --no-default-features
git add src/email/ src/lib.rs Cargo.lock
git commit -m "feat(email): add SMTP/capture/disabled mailer

No durable outbox: this app sends one kind of message, a 15-minute
sign-in link the user can re-request with a button. Unset SMTP is a
supported dev mode that logs the link.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 11: The `/magic/{token}` handler

**Files:**
- Create: `src/auth/handler.rs`
- Modify: `src/auth/mod.rs`
- Create: `tests/magic_link.rs`

**Interfaces:**
- Consumes: `AppCtx`, `auth::magic_link`, `auth::user`, `session::issue`, `server::cookie`, `email`.
- Produces: `auth::handler::consume` — an axum handler for `GET /magic/{token}`.

- [ ] **Step 1: Implement `src/auth/handler.rs`**

```rust
//! `GET /magic/{token}` — spend a sign-in link and set the session cookie.
//!
//! A plain axum handler rather than a Leptos route: it sets a header and
//! redirects, and never renders the app.

use axum::extract::{Extension, Path};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::magic_link::{self, ConsumeResult};
use crate::auth::user;
use crate::context::AppCtx;
use crate::email::{self, OutboundEmail};
use crate::server::cookie;
use crate::session::{self, COOKIE_NAME, MAX_AGE_SECONDS};

pub async fn consume(Extension(ctx): Extension<AppCtx>, Path(token): Path<String>) -> Response {
    let mut conn = match ctx.conn() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("magic link: no database connection: {e:?}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response();
        }
    };

    match magic_link::consume(&mut conn, &token) {
        Ok(ConsumeResult::Consumed { email }) => match user::find_or_create(&mut conn, &email) {
            Ok(u) => {
                tracing::info!(user = %u.email, "signed in via magic link");
                sign_in_response(&u.email, u.session_epoch)
            }
            Err(e) => {
                tracing::error!("magic link: could not create user: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response()
            }
        },
        Ok(ConsumeResult::Stale { email }) => reissue(&ctx, &mut conn, &email),
        Ok(ConsumeResult::NotFound) => {
            (StatusCode::NOT_FOUND, "This link is no longer valid.").into_response()
        }
        Err(e) => {
            tracing::error!("magic link consume failed: {e:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response()
        }
    }
}

fn sign_in_response(email: &str, epoch: i64) -> Response {
    let token = session::issue(email, epoch);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        cookie::http_only(COOKIE_NAME, &token, MAX_AGE_SECONDS)
            .parse()
            .expect("cookie header is ASCII"),
    );
    headers.insert(header::LOCATION, "/".parse().expect("static location"));
    (StatusCode::SEE_OTHER, headers).into_response()
}

/// A used or expired link. Mint a fresh one, mail it, and say so.
///
/// This is the single most common support case — a user clicking yesterday's
/// email — and turning it into "here's a new link" rather than a dead end is
/// most of the value of having the branch at all.
fn reissue(ctx: &AppCtx, conn: &mut crate::db::DbConn, email: &str) -> Response {
    let ttl = magic_link::ttl();
    let minted = magic_link::mint(conn, email, ttl);

    let body = match minted {
        Ok(token) => {
            let url = format!("{}/magic/{token}", email::site_base_url());
            let (text, html) = email::magic_link_email(&url, ttl.num_seconds());
            let mailer = ctx.mailer.clone();
            let to = email.to_string();
            tokio::spawn(async move {
                if let Err(e) = mailer
                    .send(OutboundEmail {
                        to,
                        subject: "Your Time Tracker sign-in link".to_string(),
                        text,
                        html: Some(html),
                    })
                    .await
                {
                    tracing::error!("reissued magic-link email failed: {e:?}");
                }
            });
            page(
                "Check your email",
                &format!(
                    "That link had already been used or had expired, so we've sent a \
                     fresh one to <strong>{}</strong>.",
                    email::mask(email)
                ),
            )
        }
        Err(e) => {
            tracing::error!("could not reissue magic link: {e:?}");
            page(
                "Please try again",
                "We couldn't send a new link. Go back and request one.",
            )
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().expect("static content type"),
    );
    (StatusCode::OK, headers, body).into_response()
}

/// A standalone page. This route runs outside the Leptos app, so it carries
/// its own minimal markup rather than reaching for a component.
fn page(heading: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{heading} — Time Tracker</title></head>\
         <body style=\"font-family:system-ui,sans-serif;background:#f9fafb;color:#1f2937;\
         max-width:32rem;margin:4rem auto;padding:1rem;\">\
         <h1 style=\"font-size:1.25rem;\">{heading}</h1><p>{body}</p>\
         <p><a href=\"/\" style=\"color:#2563eb;\">Back to Time Tracker</a></p>\
         </body></html>"
    )
}
```

Add `pub mod handler;` to `src/auth/mod.rs`.

- [ ] **Step 2: Write the integration tests**

Create `tests/magic_link.rs`:

```rust
//! End-to-end coverage of the `/magic/{token}` route.

#![cfg(feature = "ssr")]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn a_valid_link_sets_a_session_cookie_and_redirects() {
    let (app, token) = time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let res = app
        .oneshot(Request::builder().uri(format!("/magic/{token}")).body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get(header::LOCATION).expect("location"), "/");

    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("ascii");
    assert!(cookie.starts_with("tt_session="));
    assert!(cookie.contains("HttpOnly"), "session cookie must be HttpOnly");
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn replaying_a_link_does_not_sign_in() {
    let (app, token) = time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let first = app
        .clone()
        .oneshot(Request::builder().uri(format!("/magic/{token}")).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = app
        .oneshot(Request::builder().uri(format!("/magic/{token}")).body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(second.status(), StatusCode::OK, "replay renders the reissue page");
    assert!(
        second.headers().get(header::SET_COOKIE).is_none(),
        "a replayed link must not set a session cookie"
    );
}

#[tokio::test]
async fn an_unknown_token_is_a_404_with_no_cookie() {
    let (app, _) = time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let res = app
        .oneshot(Request::builder().uri("/magic/nope").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::SET_COOKIE).is_none());
}
```

Add `app_with_magic_link(email) -> (Router, String)` to `src/test_support.rs`: build the router with a `Mailer::capture()`, mint a token against its pool, and return both.

- [ ] **Step 3: Run the tests**

Run: `cargo test --features ssr --no-default-features --test magic_link`
Expected: PASS — three tests.

- [ ] **Step 4: Commit**

```bash
git add src/auth/handler.rs src/auth/mod.rs src/test_support.rs tests/magic_link.rs
git commit -m "feat(auth): add the /magic/{token} sign-in handler

A used or expired link mints and mails a fresh one rather than dead-
ending, because clicking yesterday's email is the common case.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 12: Session server functions

**Files:**
- Create: `src/server_fns/mod.rs`
- Create: `src/server_fns/session.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `AppCtx`, `auth::{user, magic_link}`, `session`, `email`, `rate_limit`.
- Produces:
  - `server_fns::require_ctx() -> Result<AppCtx, ServerFnError>` (ssr)
  - `server_fns::require_user() -> Result<(AppCtx, User), ServerFnError>` (ssr)
  - `server_fns::server_err(&str) -> ServerFnError` (ssr)
  - `server_fns::session::{current_session, request_magic_link, logout, sign_out_everywhere}`

- [ ] **Step 1: Implement `src/server_fns/mod.rs`**

```rust
//! Leptos server functions and their shared helpers.

pub mod entries;
pub mod passkey;
pub mod session;

#[cfg(feature = "ssr")]
mod ssr_helpers {
    use leptos::prelude::*;

    use crate::auth::user::{self, User};
    use crate::context::AppCtx;

    /// A user-facing error. Never carries internal detail.
    pub fn server_err(msg: &str) -> ServerFnError {
        ServerFnError::ServerError(msg.to_string())
    }

    /// Logs `err` with `what` for context and returns an opaque message.
    ///
    /// Curried so it drops straight into `.map_err(...)` without a closure
    /// at every call site.
    pub fn log_and_fail<E: std::fmt::Debug>(
        what: &'static str,
        user_msg: &'static str,
    ) -> impl FnOnce(E) -> ServerFnError {
        move |err| {
            tracing::error!("{what} failed: {err:?}");
            ServerFnError::ServerError(user_msg.to_string())
        }
    }

    pub fn require_ctx() -> Result<AppCtx, ServerFnError> {
        use_context::<AppCtx>().ok_or_else(|| server_err("Internal server error"))
    }

    /// Resolves the session to a live user, enforcing revocation.
    ///
    /// This is the **only** place `session_epoch` is checked. Stateless
    /// token verification (in `session::verify`) says the token is
    /// well-formed and unexpired; it cannot know the user signed out
    /// everywhere afterwards. Every function touching user data must come
    /// through here rather than trusting `ctx.claims` directly.
    pub fn require_user() -> Result<(AppCtx, User), ServerFnError> {
        let ctx = require_ctx()?;
        let claims = ctx.claims.clone().ok_or_else(|| server_err("Not signed in"))?;
        let mut conn = ctx.conn().map_err(log_and_fail("conn", "Internal server error"))?;
        let found = user::find_by_email(&mut conn, &claims.email)
            .map_err(log_and_fail("find_by_email", "Internal server error"))?
            .ok_or_else(|| server_err("Not signed in"))?;
        if found.session_epoch != claims.epoch {
            return Err(server_err("Not signed in"));
        }
        drop(conn);
        Ok((ctx, found))
    }
}

#[cfg(feature = "ssr")]
pub use ssr_helpers::*;
```

- [ ] **Step 2: Implement `src/server_fns/session.rs`**

```rust
//! Sign-in, sign-out, and "who am I".

use leptos::prelude::*;

#[cfg(feature = "ssr")]
fn set_cookie(value: String) {
    use axum::http::{HeaderValue, header};
    use leptos_axum::ResponseOptions;
    if let Some(response) = use_context::<ResponseOptions>() {
        if let Ok(hv) = HeaderValue::from_str(&value) {
            response.insert_header(header::SET_COOKIE, hv);
        }
    }
}

/// The signed-in address, or `None`.
///
/// Cheap by design: the stateless claim is enough to render the account
/// corner, so this does not touch the database.
#[server(endpoint = "session/current")]
pub async fn current_session() -> Result<Option<String>, ServerFnError> {
    let ctx = super::require_ctx()?;
    Ok(ctx.claims.map(|c| c.email))
}

/// Mails a sign-in link.
///
/// Returns `Ok(())` for **every** outcome a caller could use to probe: an
/// unknown address, a known one, a rate-limited request, and a failed SMTP
/// handshake all look identical. That uniformity is the entire
/// account-enumeration defence — a variant returning "no such account"
/// undoes it (spec section 5.2, invariant I5).
#[server(endpoint = "session/request_link")]
pub async fn request_magic_link(email: String) -> Result<(), ServerFnError> {
    use crate::auth::{magic_link, user};
    use crate::email::{self, OutboundEmail};
    use crate::rate_limit;

    let ctx = super::require_ctx()?;

    let Some(normalized) = user::normalize_email(&email) else {
        return Ok(());
    };

    let ip = ctx.client_ip.clone().unwrap_or_else(|| "unknown".to_string());
    if !rate_limit::check_ip(&ip) || !rate_limit::check_email(&normalized) {
        tracing::debug!("magic-link request over quota");
        return Ok(());
    }

    let ttl = magic_link::ttl();
    let token = {
        let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
        match magic_link::mint(&mut conn, &normalized, ttl) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("could not mint magic link: {e:?}");
                return Ok(());
            }
        }
    };

    let url = format!("{}/magic/{token}", email::site_base_url());
    let (text, html) = email::magic_link_email(&url, ttl.num_seconds());
    let mailer = ctx.mailer.clone();

    // Spawned, not awaited: a slow relay must not park the request. The user
    // is told "check your email" either way and can ask again.
    tokio::spawn(async move {
        if let Err(e) = mailer
            .send(OutboundEmail {
                to: normalized,
                subject: "Your Time Tracker sign-in link".to_string(),
                text,
                html: Some(html),
            })
            .await
        {
            tracing::error!("magic-link email failed: {e:?}");
        }
    });

    Ok(())
}

/// Clears the session cookie on this device only.
#[server(endpoint = "session/logout")]
pub async fn logout() -> Result<(), ServerFnError> {
    use crate::server::cookie;
    use crate::session::COOKIE_NAME;
    set_cookie(cookie::http_only(COOKIE_NAME, "", 0));
    Ok(())
}

/// Invalidates every session token issued to this user, on every device.
#[server(endpoint = "session/logout_all")]
pub async fn sign_out_everywhere() -> Result<(), ServerFnError> {
    use crate::auth::user;
    use crate::server::cookie;
    use crate::session::COOKIE_NAME;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    user::bump_epoch(&mut conn, me.id)
        .map_err(super::log_and_fail("bump_epoch", "Internal server error"))?;
    set_cookie(cookie::http_only(COOKIE_NAME, "", 0));
    Ok(())
}
```

Add `pub mod server_fns;` (ungated — server-fn *signatures* must compile on both targets) to `src/lib.rs`.

- [ ] **Step 3: Write the uniformity test (invariant I5)**

Add to `tests/magic_link.rs`:

```rust
/// Pins invariant I5. An attacker must not be able to tell a registered
/// address from an unregistered one, or a rate-limited request from an
/// accepted one, by anything in the response.
#[tokio::test]
async fn request_magic_link_responds_identically_for_every_outcome() {
    let app = time_tracking_leptos::test_support::router().await;

    async fn post(app: axum::Router, email: &str) -> (StatusCode, String) {
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/request_link")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"email":"{email}"}}"#)))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.expect("body");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    // Register one address so the two cases genuinely differ server-side.
    time_tracking_leptos::test_support::seed_user(&app, "known@example.com").await;

    let known = post(app.clone(), "known@example.com").await;
    let unknown = post(app.clone(), "nobody@example.com").await;
    let malformed = post(app.clone(), "not-an-address").await;
    assert_eq!(known, unknown, "known and unknown addresses must be indistinguishable");
    assert_eq!(known, malformed, "a malformed address must look the same too");

    // Exhaust the bucket; the over-quota response must still match.
    for _ in 0..10 {
        let _ = post(app.clone(), "known@example.com").await;
    }
    assert_eq!(post(app, "known@example.com").await, known, "rate-limited must look the same");
}
```

Add `seed_user(&Router, &str)` to `src/test_support.rs`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --features ssr --no-default-features --test magic_link`
Expected: PASS — four tests.

- [ ] **Step 5: Commit**

```bash
git add src/server_fns/ src/lib.rs tests/magic_link.rs src/test_support.rs
git commit -m "feat(server-fns): add session functions

Pins invariant I5: request_magic_link returns Ok(()) for unknown,
known, malformed, and rate-limited alike. require_user is the single
place session_epoch is checked, which is what makes sign-out-everywhere
real.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 13: Entry server functions

**Files:**
- Create: `src/server_fns/entries.rs`
- Create: `tests/entry_access.rs`

**Interfaces:**
- Consumes: `server_fns::require_user`, `entries::repo`, `date`.
- Produces: `entry_load(String) -> Option<String>`, `entry_save(String, String) -> ()`, `entry_dates_in_range(String, String) -> Vec<String>`, `entries_in_range(String, String) -> Vec<(String, String)>`.

Dates cross the wire as ISO strings, not `NaiveDate`: the wire format is then explicit and stable, and a malformed date is a server-side rejection rather than a deserialization failure with a worse message.

- [ ] **Step 1: Implement `src/server_fns/entries.rs`**

```rust
//! Reading and writing one day's entry, and range queries.
//!
//! Bodies are **opaque** on this boundary in both directions. Nothing here
//! parses, validates, or inspects an entry beyond a length cap — phase 2
//! sends ciphertext through these same functions and the server will not
//! hold the key (spec section 9.1).

use leptos::prelude::*;

/// Refuses absurd inputs without inspecting them. Generous: a long day of
/// notes is a few kilobytes, and phase-2 ciphertext is larger than its
/// plaintext.
#[cfg(feature = "ssr")]
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Widest span a single range query may cover, so one request cannot ask for
/// a decade.
#[cfg(feature = "ssr")]
const MAX_RANGE_DAYS: i64 = 366;

#[cfg(feature = "ssr")]
fn parse_date(raw: &str) -> Result<chrono::NaiveDate, ServerFnError> {
    crate::date::parse_iso(raw).ok_or_else(|| super::server_err("Invalid date"))
}

#[cfg(feature = "ssr")]
fn parse_range(from: &str, to: &str) -> Result<(chrono::NaiveDate, chrono::NaiveDate), ServerFnError> {
    let from = parse_date(from)?;
    let to = parse_date(to)?;
    if to < from {
        return Err(super::server_err("Invalid date range"));
    }
    if (to - from).num_days() > MAX_RANGE_DAYS {
        return Err(super::server_err("Date range is too wide"));
    }
    Ok((from, to))
}

/// One day's stored body, or `None` if that day has nothing saved.
#[server(endpoint = "entries/load")]
pub async fn entry_load(date: String) -> Result<Option<String>, ServerFnError> {
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let date = parse_date(&date)?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    repo::load(&mut conn, me.id, date).map_err(super::log_and_fail("entry load", "Internal server error"))
}

/// Writes one day's body, replacing whatever was there.
#[server(endpoint = "entries/save")]
pub async fn entry_save(date: String, body: String) -> Result<(), ServerFnError> {
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let date = parse_date(&date)?;
    if body.len() > MAX_BODY_BYTES {
        return Err(super::server_err("That entry is too large to save"));
    }
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    repo::save(&mut conn, me.id, date, &body)
        .map_err(super::log_and_fail("entry save", "Internal server error"))
}

/// Which days in the range have an entry. Dates only — see the note on
/// `repo::dates_in_range` for why this is not the same call as
/// [`entries_in_range`].
#[server(endpoint = "entries/dates")]
pub async fn entry_dates_in_range(from: String, to: String) -> Result<Vec<String>, ServerFnError> {
    use crate::date::to_iso;
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let (from, to) = parse_range(&from, &to)?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(repo::dates_in_range(&mut conn, me.id, from, to)
        .map_err(super::log_and_fail("dates in range", "Internal server error"))?
        .into_iter()
        .map(to_iso)
        .collect())
}

/// Every entry in the range, bodies included and uninterpreted.
///
/// The week view aggregates these **in the browser**. Doing it here would be
/// impossible once bodies are encrypted, so it is not done here now.
#[server(endpoint = "entries/range")]
pub async fn entries_in_range(
    from: String,
    to: String,
) -> Result<Vec<(String, String)>, ServerFnError> {
    use crate::date::to_iso;
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let (from, to) = parse_range(&from, &to)?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(repo::entries_in_range(&mut conn, me.id, from, to)
        .map_err(super::log_and_fail("entries in range", "Internal server error"))?
        .into_iter()
        .map(|(d, b)| (to_iso(d), b))
        .collect())
}
```

- [ ] **Step 2: Write the access-control tests (invariant I7 at the API boundary)**

Create `tests/entry_access.rs`:

```rust
//! Pins invariant I7 where it matters most: at the HTTP boundary, with a
//! real session cookie, not just at the repository.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{TestApp, signed_in_as};

#[tokio::test]
async fn a_user_cannot_read_another_users_entry() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;

    alice.save_entry("2026-09-04", "alice-secret").await.expect("save");

    assert_eq!(mallory.load_entry("2026-09-04").await.expect("load"), None);
    assert!(mallory.entries_in_range("2026-09-01", "2026-09-30").await.expect("range").is_empty());
    assert!(mallory.entry_dates_in_range("2026-09-01", "2026-09-30").await.expect("range").is_empty());
}

#[tokio::test]
async fn a_signed_out_caller_is_refused() {
    let app = TestApp::new().await;
    let anon = app.anonymous();
    assert!(anon.load_entry("2026-09-04").await.is_err());
    assert!(anon.save_entry("2026-09-04", "x").await.is_err());
    assert!(anon.entries_in_range("2026-09-01", "2026-09-30").await.is_err());
}

/// Bumping the epoch must invalidate a cookie that is otherwise still valid.
#[tokio::test]
async fn sign_out_everywhere_invalidates_an_existing_cookie() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    alice.save_entry("2026-09-04", "x").await.expect("save");

    let other_device = alice.clone_session();
    alice.sign_out_everywhere().await.expect("sign out everywhere");

    assert!(
        other_device.load_entry("2026-09-04").await.is_err(),
        "a token minted under the old epoch must stop working"
    );
}

#[tokio::test]
async fn malformed_dates_and_wide_ranges_are_rejected() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    assert!(alice.load_entry("not-a-date").await.is_err());
    assert!(alice.entries_in_range("2026-09-30", "2026-09-01").await.is_err(), "reversed range");
    assert!(alice.entries_in_range("2020-01-01", "2026-12-31").await.is_err(), "range too wide");
}
```

Add `TestApp`, `signed_in_as`, and the session helper methods to `src/test_support.rs`. `TestApp` owns a router plus its pool; a session helper holds a cookie string and posts to `/api/entries/*` with it.

- [ ] **Step 3: Run the tests**

Run: `cargo test --features ssr --no-default-features --test entry_access`
Expected: PASS — four tests.

- [ ] **Step 4: Commit**

```bash
git add src/server_fns/entries.rs tests/entry_access.rs src/test_support.rs
git commit -m "feat(server-fns): add entry load, save, and range functions

Pins invariant I7 at the HTTP boundary with real session cookies, and
covers epoch revocation. Bodies are opaque in both directions; the week
view aggregates client-side because the server cannot do it once phase 2
encrypts.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 14: Passkey server functions

**Files:**
- Create: `src/server_fns/passkey.rs`
- Create: `src/dto.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `require_ctx`, `require_user`, `passkey::{state, store}`, `auth::user`, `session::issue`.
- Produces: `PasskeyListItem` DTO plus `passkey_register_start()`, `passkey_register_finish(String, bool)`, `passkey_login_start(Option<String>)`, `passkey_login_finish(String)`, `passkey_list()`, `passkey_rename(i32, String)`, `passkey_delete(i32)`.

- [ ] **Step 1: Create the DTO**

`src/dto.rs`:

```rust
//! Types crossing the server-fn boundary. Shared by both targets.

use serde::{Deserialize, Serialize};

/// One row of the `/account` passkey list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyListItem {
    pub id: i32,
    /// Already resolved to the date-derived default when unnamed, so the
    /// view never has to know the fallback rule.
    pub name: String,
    pub added: String,
    pub last_used: Option<String>,
}
```

Add `pub mod dto;` (ungated) to `src/lib.rs`.

- [ ] **Step 2: Implement `src/server_fns/passkey.rs`**

```rust
//! WebAuthn ceremonies and passkey management.
//!
//! Ported from photo365 with one identity change: credentials key off
//! `user_id` rather than a free-text email subject.

use leptos::prelude::*;

use crate::dto::PasskeyListItem;

#[cfg(feature = "ssr")]
fn set_cookie(value: String) {
    use axum::http::{HeaderValue, header};
    use leptos_axum::ResponseOptions;
    if let Some(response) = use_context::<ResponseOptions>() {
        if let Ok(hv) = HeaderValue::from_str(&value) {
            response.insert_header(header::SET_COOKIE, hv);
        }
    }
}

/// Adds the options webauthn-rs does not emit, by editing the serialized
/// challenge before it reaches the browser.
///
/// Two edits, both load-bearing:
///
/// 1. `residentKey: required`. webauthn-rs ships `requireResidentKey: false`,
///    which lets some providers store a **non-discoverable** credential.
///    That silently breaks the username-less "Use a passkey" flow, because
///    the credential never surfaces without an `allowCredentials` list. The
///    stored registration state is unaffected; verification works either way.
/// 2. `extensions.prf`. Requesting PRF is only possible at *creation* time,
///    and webauthn-rs 0.6 has no typed API for it. Phase 1 ignores the
///    result; phase 2 derives an encryption key from it. Without this, every
///    passkey enrolled now would have to be deleted and re-added later
///    (spec section 9.3).
#[cfg(feature = "ssr")]
fn augment_creation_options(ccr: &mut serde_json::Value) {
    let Some(public_key) = ccr.get_mut("publicKey").and_then(|v| v.as_object_mut()) else {
        tracing::error!("creation options had no publicKey object");
        return;
    };

    let selection = public_key
        .entry("authenticatorSelection")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(sel) = selection.as_object_mut() {
        sel.insert("residentKey".into(), serde_json::json!("required"));
        sel.insert("requireResidentKey".into(), serde_json::json!(true));
    }

    let extensions = public_key
        .entry("extensions")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(ext) = extensions.as_object_mut() {
        ext.insert("prf".into(), serde_json::json!({}));
    }
}

/// Begins enrolling a passkey for the signed-in user.
#[server(endpoint = "passkey/register_start")]
pub async fn passkey_register_start() -> Result<String, ServerFnError> {
    use crate::passkey::state::{PasskeyState, encode, set_cookie_header};
    use crate::passkey::store;
    use webauthn_rs::prelude::*;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;

    // Excluding the user's existing credentials stops a double-enrolment of
    // the same authenticator, which would otherwise show up as a duplicate
    // row the user cannot tell apart.
    let exclude: Vec<CredentialID> = store::list_by_user(&mut conn, me.id)
        .map_err(super::log_and_fail("list passkeys", "Internal server error"))?
        .into_iter()
        .map(|row| row.credential_id.into())
        .collect();

    // A stable per-user UUID, so re-registering does not create a second
    // WebAuthn "user" in the authenticator's UI.
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, me.email.as_bytes());

    let (ccr, reg) = ctx
        .webauthn
        .start_passkey_registration(uuid, &me.email, &me.email, Some(exclude))
        .map_err(super::log_and_fail("start registration", "Could not start passkey registration"))?;

    let mut ccr_json = serde_json::to_value(&ccr)
        .map_err(super::log_and_fail("serialize ccr", "Internal server error"))?;
    augment_creation_options(&mut ccr_json);

    let encoded = encode(&PasskeyState::reg(me.email.clone(), reg))
        .map_err(super::log_and_fail("encode state", "Internal server error"))?;
    set_cookie(set_cookie_header(&encoded));

    serde_json::to_string(&ccr_json)
        .map_err(super::log_and_fail("serialize ccr json", "Internal server error"))
}

/// Completes enrolment. `prf_capable` is what the browser reported from
/// `getClientExtensionResults()`; see `webauthn_browser::register`.
#[server(endpoint = "passkey/register_finish")]
pub async fn passkey_register_finish(
    response_json: String,
    prf_capable: bool,
) -> Result<(), ServerFnError> {
    use crate::passkey::state::{COOKIE_NAME, PasskeyState, clear_cookie_header, decode};
    use crate::passkey::store;
    use webauthn_rs::prelude::*;

    let (ctx, me) = super::require_user()?;

    let jar = leptos_axum::extract::<axum_extra::extract::CookieJar>()
        .await
        .map_err(|_| super::server_err("Could not read cookies"))?;
    let raw = jar
        .get(COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or_else(|| super::server_err("Your passkey session expired. Please retry."))?;
    let state = decode(&raw)
        .map_err(|_| super::server_err("Your passkey session is invalid. Please retry."))?;
    set_cookie(clear_cookie_header());

    let PasskeyState::Reg { subject, reg, .. } = state else {
        return Err(super::server_err("Wrong ceremony type."));
    };
    // The ceremony state is signed, but it is still client-held: bind it to
    // the session that is finishing it.
    if subject != me.email {
        return Err(super::server_err("Wrong ceremony type."));
    }

    let rpc: RegisterPublicKeyCredential = serde_json::from_str(&response_json)
        .map_err(|_| super::server_err("Malformed credential response."))?;
    let key = ctx
        .webauthn
        .finish_passkey_registration(&rpc, &reg)
        .map_err(|e| {
            tracing::warn!("finish_passkey_registration: {e:?}");
            super::server_err("Could not verify your passkey.")
        })?;

    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    store::insert(&mut conn, me.id, &key, prf_capable)
        .map_err(super::log_and_fail("insert passkey", "Internal server error"))?;
    Ok(())
}

/// Begins a sign-in ceremony.
///
/// `Some(email)` builds a ceremony over that address's credentials; `None`
/// starts the discoverable flow behind the "Use a passkey" button.
///
/// SECURITY: an unregistered address and a registered one with no enrolled
/// passkeys both fall through to the same generic error below. That equality
/// — not any earlier check — is what stops account enumeration (invariant I6).
#[server(endpoint = "passkey/login_start")]
pub async fn passkey_login_start(email: Option<String>) -> Result<String, ServerFnError> {
    use crate::auth::user;
    use crate::passkey::state::{PasskeyState, encode, set_cookie_header};
    use crate::passkey::store;
    use crate::rate_limit;
    use webauthn_rs::prelude::*;

    let ctx = super::require_ctx()?;
    let ip = ctx.client_ip.clone().unwrap_or_else(|| "unknown".to_string());
    if !rate_limit::check_ip(&ip) {
        return Err(super::server_err("Too many attempts. Please wait a minute."));
    }

    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;

    let (rcr, state) = match email {
        Some(raw) => {
            let generic = || super::server_err("We couldn't verify your passkey.");
            let normalized = user::normalize_email(&raw).ok_or_else(generic)?;
            let found = user::find_by_email(&mut conn, &normalized)
                .map_err(super::log_and_fail("find user", "Internal server error"))?
                .ok_or_else(generic)?;
            let rows = store::list_by_user(&mut conn, found.id)
                .map_err(super::log_and_fail("list passkeys", "Internal server error"))?;
            if rows.is_empty() {
                return Err(generic());
            }
            let keys: Vec<Passkey> = rows
                .iter()
                .map(|r| r.deserialize_passkey())
                .collect::<Result<_, _>>()
                .map_err(super::log_and_fail("decode passkey", "Internal server error"))?;
            let (rcr, auth) = ctx
                .webauthn
                .start_passkey_authentication(&keys)
                .map_err(|e| {
                    tracing::warn!("start_passkey_authentication: {e:?}");
                    generic()
                })?;
            (rcr, PasskeyState::auth(normalized, auth))
        }
        None => {
            let (rcr, auth) = ctx
                .webauthn
                .start_discoverable_authentication()
                .map_err(|e| {
                    tracing::warn!("start_discoverable_authentication: {e:?}");
                    super::server_err("We couldn't verify your passkey.")
                })?;
            (rcr, PasskeyState::discoverable(auth))
        }
    };

    let encoded = encode(&state).map_err(super::log_and_fail("encode state", "Internal server error"))?;
    set_cookie(set_cookie_header(&encoded));
    serde_json::to_string(&rcr).map_err(super::log_and_fail("serialize rcr", "Internal server error"))
}

/// Completes a sign-in ceremony and sets the session cookie.
#[server(endpoint = "passkey/login_finish")]
pub async fn passkey_login_finish(response_json: String) -> Result<(), ServerFnError> {
    use crate::auth::user;
    use crate::passkey::state::{COOKIE_NAME, PasskeyState, clear_cookie_header, decode};
    use crate::passkey::store;
    use crate::server::cookie;
    use crate::session::{self, COOKIE_NAME as SESSION_COOKIE, MAX_AGE_SECONDS};
    use webauthn_rs::prelude::*;

    let ctx = super::require_ctx()?;
    let generic = || super::server_err("We couldn't verify your passkey.");

    let jar = leptos_axum::extract::<axum_extra::extract::CookieJar>()
        .await
        .map_err(|_| super::server_err("Could not read cookies"))?;
    let raw = jar
        .get(COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or_else(|| super::server_err("Your sign-in session expired. Please retry."))?;
    let state = decode(&raw)
        .map_err(|_| super::server_err("Your sign-in session is invalid. Please retry."))?;
    set_cookie(clear_cookie_header());

    let pkc: PublicKeyCredential = serde_json::from_str(&response_json)
        .map_err(|_| super::server_err("Malformed credential response."))?;

    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;

    let (row, updated) = match state {
        PasskeyState::Auth { subject, auth, .. } => {
            let result = ctx
                .webauthn
                .finish_passkey_authentication(&pkc, &auth)
                .map_err(|e| {
                    tracing::warn!("finish_passkey_authentication: {e:?}");
                    generic()
                })?;
            let row = store::find_by_credential_id(&mut conn, result.cred_id().as_ref())
                .map_err(super::log_and_fail("find credential", "Internal server error"))?
                .ok_or_else(generic)?;
            let owner = user::find_by_email(&mut conn, &subject)
                .map_err(super::log_and_fail("find user", "Internal server error"))?
                .ok_or_else(generic)?;
            // The ceremony named a subject; the credential must belong to it.
            if row.user_id != owner.id {
                tracing::warn!("passkey subject mismatch");
                return Err(generic());
            }
            let mut key = row.deserialize_passkey()
                .map_err(super::log_and_fail("decode passkey", "Internal server error"))?;
            key.update_credential(&result);
            (row, key)
        }
        PasskeyState::DiscoverableAuth { auth, .. } => {
            let (_uuid, cred_id) = ctx
                .webauthn
                .identify_discoverable_authentication(&pkc)
                .map_err(|e| {
                    tracing::warn!("identify_discoverable_authentication: {e:?}");
                    generic()
                })?;
            let row = store::find_by_credential_id(&mut conn, cred_id)
                .map_err(super::log_and_fail("find credential", "Internal server error"))?
                .ok_or_else(generic)?;
            let key = row.deserialize_passkey()
                .map_err(super::log_and_fail("decode passkey", "Internal server error"))?;
            let result = ctx
                .webauthn
                .finish_discoverable_authentication(&pkc, auth, &[key.clone().into()])
                .map_err(|e| {
                    tracing::warn!("finish_discoverable_authentication: {e:?}");
                    generic()
                })?;
            let mut key = key;
            key.update_credential(&result);
            (row, key)
        }
        PasskeyState::Reg { .. } => return Err(super::server_err("Wrong ceremony type.")),
    };

    store::update_after_use(&mut conn, row.id, &updated)
        .map_err(super::log_and_fail("update passkey", "Internal server error"))?;

    let owner: crate::auth::user::User = {
        use crate::schema::user as user_table;
        use diesel::prelude::*;
        user_table::table
            .find(row.user_id)
            .first(&mut conn)
            .map_err(super::log_and_fail("load user", "Internal server error"))?
    };

    let token = session::issue(&owner.email, owner.session_epoch);
    set_cookie(cookie::http_only(SESSION_COOKIE, &token, MAX_AGE_SECONDS));
    tracing::info!(user = %owner.email, "signed in via passkey");
    Ok(())
}

/// The signed-in user's passkeys, newest first.
#[server(endpoint = "passkey/list")]
pub async fn passkey_list() -> Result<Vec<PasskeyListItem>, ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(store::list_by_user(&mut conn, me.id)
        .map_err(super::log_and_fail("list passkeys", "Internal server error"))?
        .into_iter()
        .map(|row| PasskeyListItem {
            id: row.id,
            name: row.display_name(),
            added: row.created_at.format("%b %-d, %Y").to_string(),
            last_used: row.last_used_at.map(|t| t.format("%b %-d, %Y").to_string()),
        })
        .collect())
}

#[server(endpoint = "passkey/rename")]
pub async fn passkey_rename(id: i32, name: String) -> Result<(), ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    let renamed = store::rename_for_user(&mut conn, id, me.id, Some(&name))
        .map_err(super::log_and_fail("rename passkey", "Internal server error"))?;
    if renamed { Ok(()) } else { Err(super::server_err("That passkey no longer exists.")) }
}

#[server(endpoint = "passkey/delete")]
pub async fn passkey_delete(id: i32) -> Result<(), ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    let deleted = store::delete_for_user(&mut conn, id, me.id)
        .map_err(super::log_and_fail("delete passkey", "Internal server error"))?;
    if deleted { Ok(()) } else { Err(super::server_err("That passkey no longer exists.")) }
}
```

- [ ] **Step 3: Write the enumeration-resistance test (invariant I6)**

Create `tests/passkey_access.rs`:

```rust
//! Pins invariant I6 and passkey ownership scoping.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{TestApp, signed_in_as};

/// An unregistered address and a registered address with no enrolled
/// passkeys must be indistinguishable. If they ever differ, `passkey_login_start`
/// becomes an account-existence oracle.
#[tokio::test]
async fn login_start_cannot_distinguish_unknown_from_passkey_less() {
    let app = TestApp::new().await;
    // Registered, but has enrolled no passkeys.
    let _ = signed_in_as(&app, "known@example.com").await;

    let known = app.anonymous().passkey_login_start(Some("known@example.com")).await;
    let unknown = app.anonymous().passkey_login_start(Some("nobody@example.com")).await;

    let (Err(a), Err(b)) = (known, unknown) else {
        panic!("both must fail: neither address has an enrolled passkey");
    };
    assert_eq!(a.to_string(), b.to_string(), "error text must be identical");
}

#[tokio::test]
async fn passkey_management_requires_a_session() {
    let app = TestApp::new().await;
    let anon = app.anonymous();
    assert!(anon.passkey_list().await.is_err());
    assert!(anon.passkey_delete(1).await.is_err());
    assert!(anon.passkey_rename(1, "x").await.is_err());
}

#[tokio::test]
async fn a_user_cannot_delete_another_users_passkey() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;
    let id = alice.enrol_passkey().await.expect("enrol");

    assert!(mallory.passkey_delete(id).await.is_err());
    assert_eq!(alice.passkey_list().await.expect("list").len(), 1);
}
```

Add `enrol_passkey()` to the test session helper, driving `SoftPasskey` through the two server fns.

- [ ] **Step 4: Run the tests, clippy, and the wasm build**

```bash
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
```
Expected: all pass. The wasm build compiles the server-fn *signatures* only; if a `#[cfg(feature = "ssr")]` is missing on a body, this is where it surfaces.

- [ ] **Step 5: Commit**

```bash
git add src/server_fns/passkey.rs src/dto.rs src/lib.rs tests/passkey_access.rs src/test_support.rs
git commit -m "feat(server-fns): add passkey ceremonies and management

Pins invariant I6. The creation challenge is post-processed to force
residentKey=required (webauthn-rs ships false, which silently breaks
username-less sign-in) and to request the PRF extension, which can only
be asked for at creation time and which phase 2 needs.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Phase 4 — The client storage seam

### Task 15: Dated keys, backends, and envelope wiring

**Files:**
- Modify: `src/storage/mod.rs`

**Interfaces:**
- Consumes: `storage::envelope`, `date::to_iso`.
- Produces:
  - `storage::StorageKey::TimeEntry(NaiveDate)`, `StorageKey::as_key(self) -> String`, `StorageKey::date(self) -> NaiveDate`
  - `storage::Backend { Local, Remote }`
  - `storage::LEGACY_KEY: &str`
  - `load(Backend, StorageKey) -> Result<Option<String>, StorageError>`
  - `store(Backend, StorageKey, &str) -> impl Future<Output = Result<(), StorageError>>`
  - `clear(Backend, StorageKey) -> Result<(), StorageError>`
  - `dates_with_entries(Backend, NaiveDate, NaiveDate) -> Result<Vec<NaiveDate>, StorageError>`

**Design note — where the envelope lives.** Backends hand `mod.rs` an
*envelope string* and receive one back; `mod.rs` alone wraps and unwraps. That
keeps both backends storing the identical shape, and it is what lets the
legacy `localStorage` value (which predates envelopes entirely) be normalized
inside `local.rs` and then flow through the same path as everything else.

- [ ] **Step 1: Write the failing tests**

Replace the test module in `src/storage/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// The legacy key is every existing user's data. Changing this string
    /// orphans all of it (CLAUDE.md: storage keys are a compatibility
    /// surface).
    #[test]
    fn legacy_key_matches_the_dioxus_key() {
        assert_eq!(LEGACY_KEY, "time_entry");
    }

    /// The dated key format is equally a compatibility surface from the
    /// moment it ships.
    #[test]
    fn dated_key_format_is_pinned() {
        assert_eq!(StorageKey::TimeEntry(d(2026, 9, 4)).as_key(), "time_entry:2026-09-04");
        assert_eq!(StorageKey::TimeEntry(d(2026, 1, 5)).as_key(), "time_entry:2026-01-05");
    }

    /// Dated keys must sort chronologically as strings, so a key scan can
    /// range over them without parsing every one.
    #[test]
    fn dated_keys_sort_chronologically() {
        let mut keys = [
            StorageKey::TimeEntry(d(2026, 9, 10)).as_key(),
            StorageKey::TimeEntry(d(2026, 9, 2)).as_key(),
            StorageKey::TimeEntry(d(2026, 10, 1)).as_key(),
        ];
        keys.sort();
        assert_eq!(
            keys,
            ["time_entry:2026-09-02", "time_entry:2026-09-10", "time_entry:2026-10-01"]
        );
    }

    /// Pins spec invariant I1 at the seam. Under `ssr` there is no browser
    /// storage and no permission to resolve a remote read during render, so
    /// every backend must report "nothing loaded". If this ever returns
    /// `Some`, the server renders content the hydrating client cannot
    /// reproduce.
    #[test]
    fn ssr_backends_return_none() {
        for backend in [Backend::Local, Backend::Remote] {
            assert_eq!(
                block_on(load(backend, StorageKey::TimeEntry(d(2026, 9, 4)))),
                Ok(None),
                "{backend:?} must not load during SSR"
            );
        }
    }

    #[test]
    fn ssr_writes_are_noops() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(block_on(store(Backend::Local, key, "x")), Ok(()));
        assert_eq!(block_on(clear(Backend::Local, key)), Ok(()));
    }

    /// Minimal executor — these futures never yield under `ssr`.
    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("ssr storage futures must complete immediately"),
        }
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --features ssr --no-default-features storage::tests`
Expected: FAIL to compile — `StorageKey::TimeEntry` takes no arguments.

- [ ] **Step 3: Rewrite `src/storage/mod.rs`**

```rust
//! Persistent storage seam.
//!
//! Components never touch this module directly — they use
//! [`hook::use_persistent`]. Two things vary behind it:
//!
//! - **Which day** is being read or written ([`StorageKey`]).
//! - **Where** it lives ([`Backend`]): `localStorage` when signed out, the
//!   server when signed in.
//!
//! Values cross this boundary as [`envelope`]-wrapped strings. Wrapping and
//! unwrapping happen *here*, not in the backends, so both store the same
//! shape and the pre-envelope legacy value can be normalized in one place.

pub mod codec;
pub mod envelope;
pub mod hook;
#[cfg(feature = "hydrate")]
pub mod local;
#[cfg(feature = "hydrate")]
pub mod remote;

use std::future::Future;

use chrono::NaiveDate;

use crate::date::to_iso;

/// The key every pre-dated entry was stored under.
///
/// Load-bearing: this is where all existing users' data lives. `local.rs`
/// reads it as an alias for today until the first rewrite. Changing this
/// string orphans that data.
pub const LEGACY_KEY: &str = "time_entry";

/// Identifies one stored document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKey {
    TimeEntry(NaiveDate),
}

impl StorageKey {
    /// The key as written to the underlying store.
    ///
    /// `time_entry:YYYY-MM-DD`, which sorts chronologically as a string —
    /// that is what lets a `localStorage` key scan answer a date-range
    /// question without parsing every key.
    pub fn as_key(self) -> String {
        match self {
            StorageKey::TimeEntry(date) => format!("{LEGACY_KEY}:{}", to_iso(date)),
        }
    }

    pub fn date(self) -> NaiveDate {
        match self {
            StorageKey::TimeEntry(date) => date,
        }
    }
}

/// Where a value lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The browser's `localStorage`. Used when signed out.
    Local,
    /// The server, via server functions. Used when signed in.
    Remote,
}

/// Something went wrong reaching or interpreting the backing store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("browser storage is unavailable")]
    Unavailable,
    #[error("stored value for `{key}` could not be read: {source}")]
    Decode { key: String, source: codec::DecodeError },
    #[error("stored value for `{key}` could not be unwrapped: {source}")]
    Envelope { key: String, source: envelope::EnvelopeError },
    #[error("failed to write `{key}` to storage")]
    Write { key: String },
    #[error("the server rejected the request: {0}")]
    Server(String),
}

/// Reads a stored value. `Ok(None)` means "nothing stored for this day".
///
/// Under `ssr` this is always `Ok(None)` for **every** backend — including
/// `Remote`, whose rows the server could technically read. That refusal is
/// deliberate: it keeps the server's render independent of user data, which
/// is both the existing hydration contract and a hard requirement once
/// phase 2 encrypts bodies the server cannot decrypt (spec sections 9.1, I1).
pub async fn load(backend: Backend, key: StorageKey) -> Result<Option<String>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::load(key).await?,
            Backend::Remote => remote::load(key).await?,
        };
        match raw {
            None => Ok(None),
            Some(raw) => envelope::unwrap(&raw)
                .map(Some)
                .map_err(|source| StorageError::Envelope { key: key.as_key(), source }),
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, key);
        Ok(None)
    }
}

/// Writes a value, replacing any previous one for that day.
///
/// A plain fn building the future by hand, not an `async fn`: `value` is
/// copied into an owned `String` *before* the `async move`. That is
/// load-bearing — `Persistent::set` hands this future to `spawn_local`,
/// which requires `'static`, and an `async fn` taking `&str` would capture
/// the caller's borrow instead. Do not "simplify" it.
pub fn store(
    backend: Backend,
    key: StorageKey,
    value: &str,
) -> impl Future<Output = Result<(), StorageError>> {
    let wrapped = envelope::wrap(value);
    async move {
        #[cfg(feature = "hydrate")]
        {
            match backend {
                Backend::Local => local::store(key, &wrapped).await,
                Backend::Remote => remote::store(key, &wrapped).await,
            }
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (backend, key, wrapped);
            Ok(())
        }
    }
}

/// Removes a stored value. A no-op under `ssr`.
pub async fn clear(backend: Backend, key: StorageKey) -> Result<(), StorageError> {
    #[cfg(feature = "hydrate")]
    {
        match backend {
            Backend::Local => local::clear(key).await,
            Backend::Remote => remote::clear(key).await,
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, key);
        Ok(())
    }
}

/// Which days in `[from, to]` have an entry. Feeds the calendar's dots.
pub async fn dates_with_entries(
    backend: Backend,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        match backend {
            Backend::Local => local::dates_with_entries(from, to).await,
            Backend::Remote => remote::dates_with_entries(from, to).await,
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to);
        Ok(Vec::new())
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features storage::`
Expected: PASS — envelope tests plus five new seam tests.

- [ ] **Step 5: Commit**

```bash
git add src/storage/mod.rs
git commit -m "feat(storage): key entries by date and select a backend

StorageKey carries a NaiveDate; Backend picks localStorage or the
server. Envelope wrapping lives here rather than in the backends, so
both store the same shape and the pre-envelope legacy value can be
normalized in one place.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 16: The `localStorage` backend and the legacy alias

**Files:**
- Modify: `src/storage/local.rs`

**Interfaces:**
- Consumes: `StorageKey`, `StorageError`, `codec`, `envelope`, `date`.
- Produces: `local::{load, store, clear, dates_with_entries}`, plus the host-testable helpers `local::resolve_load` and `local::should_clear_legacy`.

**Testing approach.** `web_sys` cannot run in this project's host test suite (there is no wasm test runner, matching the existing project's position). So the *decision* logic is extracted into pure functions that take the storage reads as arguments and are tested directly; the `web_sys` calls around them stay thin enough to verify by inspection. This is what makes invariant I3 testable at all.

- [ ] **Step 1: Write the failing tests**

Add to `src/storage/local.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }
    const TODAY: fn() -> chrono::NaiveDate = || {
        chrono::NaiveDate::from_ymd_opt(2026, 9, 4).expect("valid date")
    };

    /// A dated value always wins, and comes back as-is.
    #[test]
    fn dated_value_is_used_when_present() {
        let dated = Some(envelope::wrap("dated-body"));
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), dated.clone(), legacy).expect("resolve");
        assert_eq!(got, dated);
    }

    /// Invariant I3: the legacy blob surfaces for today when nothing dated
    /// exists — this is what makes an existing user's data appear where they
    /// left it rather than vanishing.
    #[test]
    fn legacy_value_surfaces_for_today() {
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), None, legacy).expect("resolve");
        assert_eq!(got, Some(envelope::wrap("legacy-body")),
            "the legacy value must be normalized into an envelope");
    }

    /// Invariant I3: and only for today. Attributing it to every empty day
    /// would show the same text on every date in the calendar.
    #[test]
    fn legacy_value_does_not_surface_for_another_day() {
        let legacy = Some("\"legacy-body\"".to_string());
        assert_eq!(resolve_load(d(2026, 9, 3), TODAY(), None, legacy).expect("resolve"), None);
    }

    /// Invariant I3: once today has its own value the alias is finished,
    /// even if the legacy key has not been cleaned up yet.
    #[test]
    fn legacy_value_is_ignored_once_a_dated_value_exists() {
        let dated = Some(envelope::wrap(""));
        let legacy = Some("\"legacy-body\"".to_string());
        let got = resolve_load(d(2026, 9, 4), TODAY(), dated.clone(), legacy).expect("resolve");
        assert_eq!(got, dated, "an empty-but-present dated value still wins");
    }

    #[test]
    fn absent_everywhere_is_none() {
        assert_eq!(resolve_load(d(2026, 9, 4), TODAY(), None, None).expect("resolve"), None);
    }

    /// A corrupt legacy value must be an error the caller can log, not a
    /// silent "you have no data".
    #[test]
    fn undecodable_legacy_value_is_an_error() {
        let legacy = Some("this is not codec-encoded".to_string());
        assert!(resolve_load(d(2026, 9, 4), TODAY(), None, legacy).is_err());
    }

    /// Invariant I3: the alias is self-erasing, but only when the write that
    /// supersedes it is today's. Writing to yesterday must leave the legacy
    /// value intact, because it still aliases today.
    #[test]
    fn legacy_is_cleared_only_by_writing_today() {
        assert!(should_clear_legacy(d(2026, 9, 4), TODAY()));
        assert!(!should_clear_legacy(d(2026, 9, 3), TODAY()));
        assert!(!should_clear_legacy(d(2026, 9, 5), TODAY()));
    }

    #[test]
    fn key_scan_selects_dates_in_range_only() {
        let keys = vec![
            "time_entry:2026-08-31".to_string(),
            "time_entry:2026-09-04".to_string(),
            "time_entry:2026-09-30".to_string(),
            "time_entry".to_string(),          // legacy, undated
            "some_other_key".to_string(),
            "time_entry:not-a-date".to_string(),
        ];
        let got = dates_from_keys(&keys, d(2026, 9, 1), d(2026, 9, 10));
        assert_eq!(got, vec![d(2026, 9, 4)]);
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --features ssr --no-default-features storage::local`
Expected: FAIL — the module is `hydrate`-gated, so it does not compile under `ssr` yet.

Change the module gate in `src/storage/mod.rs` so the pure helpers are host-testable:

```rust
#[cfg(any(feature = "hydrate", test))]
pub mod local;
```

and gate only the `web_sys` functions inside `local.rs` with `#[cfg(feature = "hydrate")]`. Re-run: FAIL to compile — `cannot find function 'resolve_load'`.

- [ ] **Step 3: Rewrite `src/storage/local.rs`**

```rust
//! `localStorage` backend.
//!
//! The `web_sys` calls are deliberately thin wrappers around the pure
//! decision functions below, which are host-testable. There is no wasm test
//! runner in this project, so anything with real logic has to live on this
//! side of that line.

use chrono::NaiveDate;

use super::{LEGACY_KEY, StorageError, StorageKey, codec, envelope};
use crate::date::parse_iso;

/// Decides what a read returns, given both stored values.
///
/// The legacy blob (`time_entry`, written before entries were dated) is
/// treated as **today's** entry, and only when today has nothing of its own.
/// Filing it under today is a guess — the text was typed on some earlier
/// day — but it is a *visible* guess: the user opens the app and sees their
/// work where they left it, and can move it. Silently migrating it at boot
/// makes the same guess on whatever day they next happen to visit, which may
/// be weeks later, with nothing on screen to explain it.
///
/// Returns an envelope string, so the caller's unwrap path is uniform.
pub fn resolve_load(
    requested: NaiveDate,
    today: NaiveDate,
    dated_raw: Option<String>,
    legacy_raw: Option<String>,
) -> Result<Option<String>, StorageError> {
    if let Some(raw) = dated_raw {
        return decode_stored(&raw, &StorageKey::TimeEntry(requested).as_key()).map(Some);
    }
    if requested != today {
        return Ok(None);
    }
    let Some(raw) = legacy_raw else {
        return Ok(None);
    };
    // The legacy value predates envelopes: it is a bare codec-encoded string.
    let body: String = codec::decode(&raw).map_err(|source| StorageError::Decode {
        key: LEGACY_KEY.to_string(),
        source,
    })?;
    Ok(Some(envelope::wrap(&body)))
}

/// A dated value is codec-encoded *around* an envelope, so decode one layer
/// here and let the seam unwrap the other.
fn decode_stored(raw: &str, key: &str) -> Result<String, StorageError> {
    codec::decode(raw).map_err(|source| StorageError::Decode {
        key: key.to_string(),
        source,
    })
}

/// Whether writing `written` supersedes the legacy alias.
///
/// Only a write to *today* does. Writing to another day leaves the legacy
/// value alone, because it is still aliasing today and deleting it there
/// would destroy data the user has not seen yet.
pub fn should_clear_legacy(written: NaiveDate, today: NaiveDate) -> bool {
    written == today
}

/// Picks the dated keys falling inside `[from, to]`.
///
/// Ignores the undated legacy key and anything that is not ours: a browser
/// profile holds keys from every app on the origin.
pub fn dates_from_keys(keys: &[String], from: NaiveDate, to: NaiveDate) -> Vec<NaiveDate> {
    let prefix = format!("{LEGACY_KEY}:");
    let mut out: Vec<NaiveDate> = keys
        .iter()
        .filter_map(|k| k.strip_prefix(&prefix))
        .filter_map(parse_iso)
        .filter(|d| *d >= from && *d <= to)
        .collect();
    out.sort_unstable();
    out
}

#[cfg(feature = "hydrate")]
mod browser {
    use super::*;

    fn storage() -> Result<web_sys::Storage, StorageError> {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .ok_or(StorageError::Unavailable)
    }

    fn read(store: &web_sys::Storage, key: &str) -> Result<Option<String>, StorageError> {
        store.get_item(key).map_err(|_| StorageError::Unavailable)
    }

    pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
        let store = storage()?;
        let dated = read(&store, &key.as_key())?;
        let legacy = read(&store, LEGACY_KEY)?;
        resolve_load(key.date(), crate::date::today_local(), dated, legacy)
    }

    pub async fn store_value(key: StorageKey, envelope: &str) -> Result<(), StorageError> {
        let store = storage()?;
        store
            .set_item(&key.as_key(), &codec::encode(&envelope))
            .map_err(|_| StorageError::Write { key: key.as_key() })?;

        // The alias has now been superseded for today. Removing it is what
        // makes it self-erasing after exactly one edit.
        if should_clear_legacy(key.date(), crate::date::today_local()) {
            let _ = store.remove_item(LEGACY_KEY);
        }
        Ok(())
    }

    pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
        let store = storage()?;
        store
            .remove_item(&key.as_key())
            .map_err(|_| StorageError::Write { key: key.as_key() })
    }

    pub async fn dates_with_entries(
        from: NaiveDate,
        to: NaiveDate,
    ) -> Result<Vec<NaiveDate>, StorageError> {
        let store = storage()?;
        let len = store.length().map_err(|_| StorageError::Unavailable)?;
        let mut keys = Vec::with_capacity(len as usize);
        for i in 0..len {
            if let Ok(Some(k)) = store.key(i) {
                keys.push(k);
            }
        }
        Ok(dates_from_keys(&keys, from, to))
    }
}

#[cfg(feature = "hydrate")]
pub use browser::{clear, dates_with_entries, load, store_value as store};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features storage::local`
Expected: PASS — eight tests.

- [ ] **Step 5: Verify the wasm build, then commit**

```bash
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/storage/local.rs src/storage/mod.rs
git commit -m "feat(storage): date localStorage keys with a legacy alias

Pins invariant I3. The pre-dated 'time_entry' key is read as today's
entry until the first write to today supersedes it, then deleted.
Writing another day leaves it alone, because it still aliases today.
Decision logic is pure and host-tested; the web_sys layer is a thin
wrapper, since there is no wasm test runner here.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 17: The remote backend and the reactive hook

**Files:**
- Create: `src/storage/remote.rs`
- Modify: `src/storage/hook.rs`

**Interfaces:**
- Consumes: `server_fns::entries`, `StorageKey`, `StorageError`.
- Produces: `remote::{load, store, clear, dates_with_entries}`; `hook::use_persistent(Signal<StorageKey>, Signal<Backend>) -> Persistent` with `Persistent::{get, set, clear}` unchanged.

- [ ] **Step 1: Implement `src/storage/remote.rs`**

```rust
//! Server-backed storage, used when signed in.
//!
//! A thin adapter over the entry server functions. It moves envelope strings
//! and never inspects them — the server does not either (spec section 9.1).

use chrono::NaiveDate;

use super::{StorageError, StorageKey};
use crate::date::{parse_iso, to_iso};
use crate::server_fns::entries;

fn server_error(e: leptos::prelude::ServerFnError) -> StorageError {
    StorageError::Server(e.to_string())
}

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    entries::entry_load(to_iso(key.date()))
        .await
        .map_err(server_error)
}

pub async fn store(key: StorageKey, envelope: &str) -> Result<(), StorageError> {
    entries::entry_save(to_iso(key.date()), envelope.to_string())
        .await
        .map_err(server_error)
}

/// Clearing a day writes an empty envelope rather than deleting the row.
///
/// "Cleared" and "never written" are the same thing to the reader, and an
/// empty row keeps the day's `updated_at` meaningful. It also means clear
/// and save take the same path, so there is one less server fn to authorize.
pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    store(key, &super::envelope::wrap("")).await
}

pub async fn dates_with_entries(
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    Ok(entries::entry_dates_in_range(to_iso(from), to_iso(to))
        .await
        .map_err(server_error)?
        .iter()
        .filter_map(|s| parse_iso(s))
        .collect())
}
```

- [ ] **Step 2: Write the failing test for the reactive hook**

Add to `src/storage/hook.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_value_is_loaded_as_is() {
        assert_eq!(loaded_value(Ok(Some("saved".to_string()))), "saved");
    }

    #[test]
    fn nothing_stored_becomes_loaded_and_empty() {
        assert_eq!(loaded_value(Ok(None)), "");
    }

    #[test]
    fn read_failure_becomes_loaded_and_empty() {
        assert_eq!(loaded_value(Err(StorageError::Unavailable)), "");
    }

    /// Pins invariant I2. Two loads are in flight; the *older* one resolves
    /// last. Without a generation guard it would overwrite the newer day's
    /// value, showing the wrong date's text with no indication anything is
    /// wrong.
    #[test]
    fn a_stale_load_does_not_overwrite_a_newer_one() {
        let mut gen = Generation::default();
        let first = gen.next();
        let second = gen.next();
        assert!(gen.is_current(second), "the newest load may write");
        assert!(!gen.is_current(first), "an older load must be discarded");
    }

    #[test]
    fn a_single_load_is_always_current() {
        let mut gen = Generation::default();
        let only = gen.next();
        assert!(gen.is_current(only));
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test --features ssr --no-default-features storage::hook`
Expected: FAIL to compile — `cannot find type 'Generation'`.

- [ ] **Step 4: Rewrite `src/storage/hook.rs`**

```rust
//! The Leptos-facing half of the storage seam.
//!
//! # The hydration contract (spec section 5 of the migration design)
//!
//! The server and the client's *first* render must produce identical DOM.
//! Neither `localStorage` nor a server round trip is available during that
//! render, so the value starts as `None` on **both** targets and is filled
//! in by an `Effect`, which runs only after hydration has matched.
//!
//! | Value          | Meaning                     | Renders as            |
//! |----------------|-----------------------------|-----------------------|
//! | `None`         | Not yet read from storage   | Blank                 |
//! | `Some("")`     | Loaded; nothing saved       | The empty-state text  |
//! | `Some(text)`   | Loaded with data            | The parsed summary    |
//!
//! Collapsing the first two makes the server assert an empty state it cannot
//! know, and returning users see "No projects found" flash before their data
//! appears.
//!
//! # Why the arguments are signals
//!
//! Both the day being viewed and the backend change *during* a session — the
//! day when the user picks a date, the backend when they sign in. Re-running
//! the load is therefore normal operation, not a corner case, which brings
//! two obligations the single-shot version did not have: reset to `None`
//! first (so the previous day's text never appears under the new day's
//! heading), and discard stale in-flight loads (below).

use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;

use super::{Backend, StorageError, StorageKey, load, store};

/// Monotonic counter identifying the newest in-flight load.
///
/// Loads are async and can overlap: changing the date twice quickly starts
/// two, and nothing guarantees they resolve in order. Only the newest may
/// publish its result.
#[derive(Debug, Default, Clone, Copy)]
pub struct Generation(u64);

impl Generation {
    /// Starts a new load, invalidating any earlier one.
    pub fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// Whether `token` identifies the newest load.
    pub fn is_current(&self, token: u64) -> bool {
        self.0 == token
    }
}

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
    }

    /// The day this is currently bound to.
    pub fn key(self) -> StorageKey {
        self.key.get_untracked()
    }

    /// Updates the value and writes it through to storage.
    pub fn set(self, value: String) {
        self.set_value.set(Some(value.clone()));
        let key = self.key.get_untracked();
        let backend = self.backend.get_untracked();
        spawn_local(async move {
            // A failed write must not break the UI — the in-memory value
            // stands — but it must not be silent either: Safari private
            // browsing and a quota-exceeded `setItem` both throw, and the
            // user would otherwise lose data with nothing to explain why.
            if let Err(err) = store(backend, key, &value).await {
                error!("failed to persist value for {key:?}: {err}");
            }
        });
    }

    /// Resets to the empty (but loaded) state.
    pub fn clear(self) {
        self.set(String::new());
    }
}

/// Collapses a storage read into the loaded state.
///
/// Both "nothing stored" and "the read failed" become loaded-and-empty:
/// leaving the value unloaded on error would strand the UI blank forever.
/// A read failure is still logged first, so a corrupt value does not
/// silently masquerade as "nothing saved".
fn loaded_value(read: Result<Option<String>, StorageError>) -> String {
    match read {
        Ok(value) => value.unwrap_or_default(),
        Err(err) => {
            error!("failed to load persisted value, treating as empty: {err}");
            String::new()
        }
    }
}

/// Reads `key` from `backend`, re-reading whenever either changes.
pub fn use_persistent(key: Signal<StorageKey>, backend: Signal<Backend>) -> Persistent {
    // Identical on server and client, which is what makes hydration match.
    let (value, set_value) = signal::<Option<String>>(None);
    let generation = StoredValue::new(Generation::default());

    // `Effect::new` never runs during SSR, and on the client it runs after
    // the first render — so the DOM has already been matched by the time
    // this can change anything.
    Effect::new(move |_| {
        let key = key.get();
        let backend = backend.get();
        let token = generation.update_value(Generation::next);

        // Back to "not loaded" before the new read starts. Without this the
        // previous day's text stays on screen under the new day's heading
        // until the load resolves (invariant I2).
        set_value.set(None);

        spawn_local(async move {
            let loaded = loaded_value(load(backend, key).await);
            // Discard if a newer load started while this one was in flight.
            if generation.with_value(|g| g.is_current(token)) {
                set_value.set(Some(loaded));
            }
        });
    });

    Persistent {
        value,
        set_value,
        key,
        backend,
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features storage::hook`
Expected: PASS — five tests.

- [ ] **Step 6: Verify the wasm build, then commit**

```bash
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
cargo clippy --features ssr --no-default-features
git add src/storage/remote.rs src/storage/hook.rs
git commit -m "feat(storage): add remote backend and make the hook reactive

Pins invariant I2. The key and backend are now signals, so loads re-run
mid-session; that brings a reset-to-None before each read and a
generation guard so an older in-flight load cannot overwrite a newer
day's value.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 18: The browser WebAuthn bridge

**Files:**
- Create: `src/webauthn_browser.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `js_sys`, `web_sys`, `wasm_bindgen`.
- Produces: `webauthn_browser::register(&str) -> Result<(String, bool), WebauthnUserError>` (credential JSON plus PRF capability), `webauthn_browser::authenticate(&str) -> Result<String, WebauthnUserError>`, `webauthn_browser::WebauthnUserError`, `webauthn_browser::friendly_error(String) -> String`.

**Ported deliberately.** The base of this file is photo365's `webauthn_browser.rs`. It routes through the browser's own `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` / `toJSON` rather than hand-rolling base64url. The obvious alternative — `JSON.parse` the server payload and hand it straight to `navigator.credentials` — fails every ceremony, because WebAuthn requires `challenge`, `user.id`, and `excludeCredentials[].id` to be `ArrayBuffer`s rather than the base64url strings webauthn-rs emits. Worse, the browser reports that as `NotAllowedError`, which naive error mapping renders as "user cancelled".

- [ ] **Step 1: Write the failing test for the error mapper**

Create `src/webauthn_browser.rs` with only:

```rust
#[cfg(test)]
mod tests {
    use super::friendly_error;

    #[test]
    fn cancellation_is_named_plainly() {
        assert_eq!(friendly_error("cancelled".into()), "Sign-in was cancelled.");
        assert_eq!(friendly_error("NotAllowedError: ...".into()), "Sign-in was cancelled.");
    }

    #[test]
    fn unsupported_browsers_get_a_specific_message() {
        for raw in ["not supported", "no window", "credentials.create/get returned non-Promise"] {
            assert_eq!(
                friendly_error(raw.into()),
                "Your browser doesn't support passkeys for this site."
            );
        }
    }

    /// Server-fn errors are already user-facing and pass through, so the
    /// account page can show "That passkey no longer exists." verbatim.
    #[test]
    fn server_messages_pass_through() {
        for raw in [
            "We couldn't verify your passkey.",
            "Your sign-in session expired. Please retry.",
            "Too many attempts. Please wait a minute.",
            "That passkey no longer exists.",
            "Not signed in",
        ] {
            assert_eq!(friendly_error(raw.into()), raw);
        }
    }

    /// Anything else collapses. Raw JS internals must never reach the user.
    #[test]
    fn unknown_errors_collapse_to_something_generic() {
        assert_eq!(
            friendly_error("TypeError: Cannot read properties of undefined".into()),
            "Couldn't complete that passkey step. Please try again."
        );
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --features ssr --no-default-features webauthn_browser`
Expected: FAIL to compile — `cannot find function 'friendly_error'`.

Register the module in `src/lib.rs` as `#[cfg(any(feature = "hydrate", test))] pub mod webauthn_browser;` and gate the `web_sys` half inside it, so the mapper is host-testable.

- [ ] **Step 3: Implement `src/webauthn_browser.rs`**

```rust
//! Hydrate-only wrapper around `navigator.credentials.create/get`.
//!
//! Both entry points take the server's WebAuthn JSON challenge and return
//! the browser's response as JSON, leaning on the browser's own
//! `PublicKeyCredential.parseCreationOptionsFromJSON()`,
//! `parseRequestOptionsFromJSON()`, and `toJSON()` rather than doing
//! base64url plumbing by hand. Passing the parsed server payload straight to
//! `navigator.credentials` does not work: the API needs `ArrayBuffer`s where
//! webauthn-rs emits base64url strings, and the browser reports the mismatch
//! as `NotAllowedError` — indistinguishable from the user hitting cancel.

/// Maps a raw WebAuthn or server error to something a person can act on.
///
/// Deliberately narrow: server-fn messages are already user-facing and pass
/// through by prefix; everything else collapses, so raw JS internals never
/// reach the UI.
pub fn friendly_error(raw: String) -> String {
    let lower = raw.to_lowercase();
    if lower.contains("cancel") || lower.contains("notallowederror") {
        "Sign-in was cancelled.".to_string()
    } else if lower.contains("not supported")
        || lower.contains("unavailable")
        || lower.contains("no window")
        || lower.contains("non-promise")
    {
        "Your browser doesn't support passkeys for this site.".to_string()
    } else if raw.starts_with("We couldn't")
        || raw.starts_with("Your sign-in")
        || raw.starts_with("Your passkey")
        || raw.starts_with("Too many")
        || raw.starts_with("That passkey")
        || raw.starts_with("Not signed in")
        || raw.starts_with("Wrong ceremony")
        || raw.starts_with("Malformed credential")
    {
        raw
    } else {
        "Couldn't complete that passkey step. Please try again.".to_string()
    }
}

#[cfg(feature = "hydrate")]
mod browser {
    use std::fmt;

    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::js_sys::{self, Function, Object, Reflect};

    #[derive(Debug)]
    pub enum WebauthnUserError {
        Cancelled,
        NotSupported,
        Other(String),
    }

    impl fmt::Display for WebauthnUserError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Cancelled => f.write_str("cancelled"),
                Self::NotSupported => f.write_str("not supported"),
                Self::Other(s) => f.write_str(s),
            }
        }
    }

    fn pk_constructor() -> Result<Object, WebauthnUserError> {
        let win = web_sys::window().ok_or_else(|| WebauthnUserError::Other("no window".into()))?;
        Reflect::get(&win, &"PublicKeyCredential".into())
            .map_err(|_| WebauthnUserError::NotSupported)?
            .dyn_into::<Object>()
            .map_err(|_| WebauthnUserError::NotSupported)
    }

    fn stringify(v: &JsValue) -> String {
        js_sys::JSON::stringify(v)
            .ok()
            .and_then(|s| s.as_string())
            .unwrap_or_default()
    }

    fn classify(e: JsValue) -> WebauthnUserError {
        let name = Reflect::get(&e, &"name".into())
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        if name == "NotAllowedError" {
            WebauthnUserError::Cancelled
        } else {
            WebauthnUserError::Other(format!("{name}: {}", stringify(&e)))
        }
    }

    fn method(on: &JsValue, name: &str) -> Result<Function, WebauthnUserError> {
        Reflect::get(on, &name.into())
            .map_err(|_| WebauthnUserError::NotSupported)?
            .dyn_into::<Function>()
            .map_err(|_| WebauthnUserError::NotSupported)
    }

    /// Runs one ceremony, returning the raw credential object.
    async fn invoke(
        challenge_json: &str,
        parse_method: &str,
        creds_method: &str,
    ) -> Result<JsValue, WebauthnUserError> {
        let pk = pk_constructor()?;
        let parse = method(&pk, parse_method)?;

        let challenge = js_sys::JSON::parse(challenge_json)
            .map_err(|_| WebauthnUserError::Other("bad challenge JSON".into()))?;
        let public_key = Reflect::get(&challenge, &"publicKey".into())
            .map_err(|_| WebauthnUserError::Other("missing publicKey".into()))?;
        let options = parse.call1(&pk, &public_key).map_err(classify)?;

        let win = web_sys::window().ok_or_else(|| WebauthnUserError::Other("no window".into()))?;
        let creds = win.navigator().credentials();
        let arg = Object::new();
        Reflect::set(&arg, &"publicKey".into(), &options).ok();

        let promise = method(&creds, creds_method)?
            .call1(&creds, &arg)
            .map_err(classify)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| {
                WebauthnUserError::Other("credentials.create/get returned non-Promise".into())
            })?;

        JsFuture::from(promise).await.map_err(classify)
    }

    fn to_json(cred: &JsValue) -> Result<String, WebauthnUserError> {
        Ok(stringify(&method(cred, "toJSON")?.call0(cred).map_err(classify)?))
    }

    /// Whether the authenticator enabled the PRF extension.
    ///
    /// `toJSON()` omits extension results, so this has to come from
    /// `getClientExtensionResults()` separately. Phase 1 only records the
    /// answer; phase 2 derives an encryption key from PRF output on
    /// credentials where this was true (spec section 9.3).
    fn prf_enabled(cred: &JsValue) -> bool {
        let Ok(results) = method(cred, "getClientExtensionResults").and_then(|f| {
            f.call0(cred).map_err(classify)
        }) else {
            return false;
        };
        Reflect::get(&results, &"prf".into())
            .ok()
            .and_then(|prf| Reflect::get(&prf, &"enabled".into()).ok())
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// Enrols a credential. Returns its JSON and whether PRF is available.
    pub async fn register(challenge_json: &str) -> Result<(String, bool), WebauthnUserError> {
        let cred = invoke(challenge_json, "parseCreationOptionsFromJSON", "create").await?;
        Ok((to_json(&cred)?, prf_enabled(&cred)))
    }

    /// Runs a sign-in assertion.
    pub async fn authenticate(challenge_json: &str) -> Result<String, WebauthnUserError> {
        let cred = invoke(challenge_json, "parseRequestOptionsFromJSON", "get").await?;
        to_json(&cred)
    }
}

#[cfg(feature = "hydrate")]
pub use browser::{WebauthnUserError, authenticate, register};
```

- [ ] **Step 4: Run the tests, then the wasm build**

```bash
cargo test --features ssr --no-default-features webauthn_browser
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
```
Expected: four tests pass; the wasm build succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/webauthn_browser.rs src/lib.rs
git commit -m "feat(passkey): add the browser credentials bridge

Ported from photo365: routes through the browser's own
parseCreationOptionsFromJSON/toJSON rather than hand-rolling base64url,
because WebAuthn wants ArrayBuffers where webauthn-rs emits strings and
reports the mismatch as NotAllowedError — i.e. as a cancellation.

register() additionally reads getClientExtensionResults() for PRF
support, which toJSON omits and which phase 2 needs.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Phase 5 — User interface

### Task 19: Auth context, routes, and the day view

**Files:**
- Modify: `src/app.rs`
- Create: `src/auth_ctx.rs`
- Modify: `src/lib.rs`, `src/components/mod.rs`

**Interfaces:**
- Consumes: `storage::{Backend, StorageKey}`, `storage::hook::use_persistent`, `date`, `context::AppCtx` (ssr).
- Produces: `auth_ctx::AuthCtx { user: RwSignal<Option<String>> }`, `AuthCtx::backend(self) -> Signal<Backend>`, `auth_ctx::initial_user() -> Option<String>`; routes `/`, `/{date}`, `/week/{date}`, `/account`.

**How the server renders auth state without breaking hydration.** The server
knows who is signed in — the cookie is on the request — and rendering "Sign
in" for a signed-in user would flash wrong content on every reload. But the
client's *first* render must produce identical DOM, and the browser has no
cookie access (`HttpOnly`) and no context.

So `shell()` writes the answer into the document as a `<meta name="tt-user">`
tag, and `initial_user()` reads it from `AppCtx` under `ssr` and from that
same meta tag under `hydrate`. Both sides compute the same initial value from
the same source, synchronously, with no `Resource` and no `Suspense` — which
matters because `render_app()` in the SSR tests renders synchronously and
CLAUDE.md documents that adding async rendering would make it stop tracking
production.

This is the *only* thing the server is allowed to know about the user. Entry
bodies stay unrendered (invariant I1).

- [ ] **Step 1: Implement `src/auth_ctx.rs`**

```rust
//! Who is signed in, as far as the view layer is concerned.

use leptos::prelude::*;

use crate::storage::Backend;

/// The signed-in identity, shared across the component tree.
#[derive(Clone, Copy)]
pub struct AuthCtx {
    /// The signed-in email address, or `None` when signed out.
    pub user: RwSignal<Option<String>>,
}

impl AuthCtx {
    /// Where this session's entries live.
    ///
    /// Signing in or out flips this, and `use_persistent` re-reads because
    /// it is a signal.
    pub fn backend(self) -> Signal<Backend> {
        let user = self.user;
        Signal::derive(move || {
            if user.get().is_some() {
                Backend::Remote
            } else {
                Backend::Local
            }
        })
    }

    pub fn is_signed_in(self) -> bool {
        self.user.get().is_some()
    }
}

/// The name of the meta tag carrying the signed-in address through hydration.
pub const USER_META: &str = "tt-user";

/// The signed-in address as of the first render, on either target.
///
/// Server: from the request context. Browser: from the meta tag the server
/// wrote. Both produce the same value, so the first client render matches
/// the server's DOM exactly.
pub fn initial_user() -> Option<String> {
    #[cfg(feature = "ssr")]
    {
        use_context::<crate::context::AppCtx>().and_then(|ctx| ctx.claims.map(|c| c.email))
    }
    #[cfg(feature = "hydrate")]
    {
        use wasm_bindgen::JsCast;
        web_sys::window()?
            .document()?
            .query_selector(&format!("meta[name=\"{USER_META}\"]"))
            .ok()
            .flatten()?
            .dyn_into::<web_sys::HtmlMetaElement>()
            .ok()
            .map(|m| m.content())
            .filter(|c| !c.is_empty())
    }
    #[cfg(not(any(feature = "ssr", feature = "hydrate")))]
    {
        None
    }
}
```

Add `pub mod auth_ctx;` (ungated) to `src/lib.rs`.

- [ ] **Step 2: Rewrite `src/app.rs`**

```rust
use leptos::either::Either;
use leptos::prelude::*;
use leptos_meta::{MetaTags, Stylesheet, Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::hooks::use_params_map;
use leptos_router::path;

use crate::auth_ctx::{AuthCtx, USER_META, initial_user};
use crate::components::account_page::AccountPage;
use crate::components::header::AppHeader;
use crate::components::import_banner::ImportBanner;
use crate::components::time_display::TimeDisplay;
use crate::components::time_entry_area::TimeEntryArea;
use crate::components::week_view::WeekView;
use crate::date::{parse_iso, to_iso};
use crate::storage::StorageKey;
use crate::storage::hook::use_persistent;

/// The SSR document shell. `HydrationScripts` injects the wasm loader.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    // Carried into the browser so the client's first render can reach the
    // same conclusion the server did, without a cookie or a round trip.
    // See `auth_ctx::initial_user`.
    let user = initial_user();

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                {user.map(|email| view! { <meta name=USER_META content=email/> })}
                <link rel="icon" href="/favicon.ico"/>
                <AutoReload options=options.clone()/>
                <HydrationScripts options/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();
    provide_context(AuthCtx {
        user: RwSignal::new(initial_user()),
    });

    view! {
        <Stylesheet id="leptos" href="/pkg/time-tracking-leptos.css"/>
        <Title text="Time Tracker"/>
        <Router>
            <Routes fallback=NotFound>
                <Route path=path!("/") view=TodayRedirect/>
                <Route path=path!("/account") view=AccountPage/>
                <Route path=path!("/week/:date") view=WeekView/>
                <Route path=path!("/:date") view=DayPage/>
            </Routes>
        </Router>
    }
}

/// `/` — the canonical entry point, which does not name a date.
///
/// The server cannot resolve "today": it does not know the visitor's
/// timezone, and guessing is wrong for somebody near midnight every single
/// day. So it renders the chrome with an empty date slot, and the browser
/// replaces the URL with its own local date once hydrated. A deep link to
/// `/2026-09-04` skips all of this, because there the date is knowable
/// server-side (spec section 8.1).
#[component]
fn TodayRedirect() -> impl IntoView {
    #[cfg(feature = "hydrate")]
    {
        use leptos_router::NavigateOptions;
        use leptos_router::hooks::use_navigate;
        let navigate = use_navigate();
        Effect::new(move |_| {
            navigate(
                &format!("/{}", to_iso(crate::date::today_local())),
                NavigateOptions { replace: true, ..Default::default() },
            );
        });
    }

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=None/>
        </div>
    }
}

/// `/{date}` — the day view.
#[component]
fn DayPage() -> impl IntoView {
    let params = use_params_map();
    let parsed = Signal::derive(move || {
        params.with(|p| p.get("date").and_then(|raw| parse_iso(&raw)))
    });

    view! {
        {move || match parsed.get() {
            // A single path segment that is not a date. The route pattern
            // cannot express "date-shaped", so the check lives here.
            None => Either::Left(view! { <NotFound/> }),
            Some(date) => Either::Right(view! { <DayView date=date/> }),
        }}
    }
}

#[component]
fn DayView(date: chrono::NaiveDate) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let key = Signal::derive(move || StorageKey::TimeEntry(date));
    let entry = use_persistent(key, auth.backend());

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=Some(date)/>
            <div class="w-full max-w-7xl mx-auto px-4 py-8">
                <ImportBanner/>
                <div class="flex flex-col md:flex-row gap-6 w-full">
                    <TimeEntryArea entry=entry/>
                    <TimeDisplay entry=entry/>
                </div>
            </div>
        </div>
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <main class="min-h-screen flex items-center justify-center bg-gray-50">
            <p class="text-gray-600">"Page not found."</p>
        </main>
    }
}
```

Note `DayView` takes `date` by value and builds a constant signal: the route
remounts on a date change, so the key does not need to track the params
signal. If a future change makes the route reuse the component across dates,
`key` must derive from `parsed` instead — `use_persistent` is already reactive
and will handle it.

- [ ] **Step 3: Extend the SSR tests (invariant I1)**

Replace the test module in `src/app.rs`:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    /// Renders `App` exactly as the server would.
    ///
    /// `leptos_axum`'s handler provides the requested path as a `RequestUrl`
    /// before rendering and `<Router>` panics without it, so we do the same.
    /// When `signed_in_as` is `Some`, an `AppCtx` carrying verified claims is
    /// provided too — which is what production does for a request arriving
    /// with a valid session cookie.
    ///
    /// Still synchronous (`.to_html()`), still providing neither
    /// `ServerMetaContext` nor `ResponseOptions`. Both remain harmless while
    /// the app has no `Resource`s or `<Suspense>` boundaries; see CLAUDE.md.
    fn render_at(path: &str, signed_in_as: Option<&str>) -> String {
        use leptos_router::location::RequestUrl;

        let runtime = Owner::new();
        let path = path.to_string();
        let claims = signed_in_as.map(|email| crate::session::SessionClaims {
            email: email.to_string(),
            epoch: 0,
        });
        let html = runtime.with(move || {
            provide_context(RequestUrl::new(&path));
            if let Some(claims) = claims {
                provide_context(crate::test_support::app_ctx_with_claims(Some(claims)));
            }
            view! { <App/> }.to_html()
        });
        runtime.cleanup();
        html
    }

    fn render_app() -> String {
        render_at("/2026-09-04", None)
    }

    #[test]
    fn ssr_renders_chrome() {
        let html = render_app();
        assert!(html.contains("Time Entry"), "entry pane heading missing");
        assert!(html.contains("Time Summary"), "summary pane heading missing");
        assert!(html.contains("How to use this tool"), "help toggle missing");
        assert!(
            html.contains("whitespace-pre-wrap"),
            "help sample block missing — it must be in the SSR'd HTML, not \
             mounted client-side, or hydration sees a different node count"
        );
    }

    /// Pins spec invariant I2 of the migration design. The server cannot know
    /// whether the user has saved data, so it must not render any conclusion
    /// that depends on it.
    #[test]
    fn ssr_omits_loaded_state() {
        let html = render_app();
        assert!(
            !html.contains("No projects found"),
            "server rendered the empty state it cannot know; returning users \
             would see it flash before their data loads"
        );
        assert!(!html.contains("hours)"), "server rendered a computed total");
        assert!(!html.contains("No dead time"), "server rendered a dead-time conclusion");
    }

    /// Pins invariant I1, and this is the case that would otherwise regress
    /// silently. For a signed-in visitor the server *could* read the entry
    /// row — it has the user and the date. It must not. Phase 2 encrypts
    /// bodies client-side, so a server render of entry content is not a
    /// performance win to be added later; it is a design the encryption
    /// cannot coexist with.
    #[test]
    fn ssr_omits_entry_content_even_when_signed_in() {
        let html = render_at("/2026-09-04", Some("alice@example.com"));
        assert!(
            !html.contains("No projects found"),
            "server rendered loaded state for a signed-in user"
        );
        assert!(!html.contains("hours)"), "server rendered a computed total for a signed-in user");
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "the SSR'd textarea must still be empty for a signed-in user"
        );
    }

    /// The other half of the same decision: auth state *is* server-rendered,
    /// because the cookie is right there and a flash of "Sign in" on every
    /// reload is worse than the alternative.
    #[test]
    fn ssr_renders_the_signed_in_identity() {
        let html = render_at("/2026-09-04", Some("alice@example.com"));
        assert!(
            html.contains("alice"),
            "the signed-in identity must be server-rendered, or a returning \
             user sees 'Sign in' flash before their account appears"
        );
    }

    #[test]
    fn ssr_renders_sign_in_when_signed_out() {
        let html = render_at("/2026-09-04", None);
        assert!(html.contains("Sign in"), "signed-out header must offer sign-in");
    }

    /// `/` cannot name a date, so it must render none rather than guess.
    #[test]
    fn root_route_renders_no_date() {
        let html = render_at("/", None);
        assert!(
            !html.contains("2026"),
            "`/` must not render a specific date — the server does not know \
             the visitor's timezone (spec section 8.1)"
        );
    }

    #[test]
    fn a_non_date_segment_renders_not_found() {
        let html = render_at("/not-a-date", None);
        assert!(html.contains("Page not found"));
    }

    /// Pins invariant I4 for the one element whose SSR shape is subtle.
    #[test]
    fn ssr_textarea_is_empty() {
        let html = render_app();
        assert!(
            html.contains("<textarea") && html.contains("></textarea>"),
            "the SSR'd textarea must have no text content, so the hydrate-side \
             prop:value binding attaches to a matching node"
        );
    }
}
```

Add `app_ctx_with_claims(Option<SessionClaims>) -> AppCtx` to `src/test_support.rs`, building a context over an in-memory pool and a capture mailer.

- [ ] **Step 4: Run the tests**

Run: `cargo test --features ssr --no-default-features app::`
Expected: PASS — nine tests. (Tasks 20–24 supply `AppHeader`, `ImportBanner`, `AccountPage`, and `WeekView`; implement them as minimal stubs now if executing strictly in order, and this task's tests will still hold once they are filled in.)

- [ ] **Step 5: Commit**

```bash
git add src/app.rs src/auth_ctx.rs src/lib.rs src/components/mod.rs src/test_support.rs
git commit -m "feat(app): add dated routes and server-rendered auth state

Pins invariant I1 with the case that matters: a signed-in SSR render
must still emit no entry content, even though the server could read the
row. Auth state IS server-rendered, carried into hydration through a
meta tag so both sides compute the same first render without a Resource.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 20: The app header and account menu

**Files:**
- Create: `src/components/header.rs`
- Create: `src/components/account_menu.rs`
- Modify: `src/components/mod.rs`, `style/tailwind.css`

**Interfaces:**
- Consumes: `AuthCtx`, `server_fns::session`, `webauthn_browser`, `date::format_long`.
- Produces: `header::AppHeader { date: Option<NaiveDate> }`, `account_menu::AccountMenu`.

**Layout (chosen in brainstorming, option B):** one slim row — title left, date
centre, account right.

- [ ] **Step 1: Implement `src/components/header.rs`**

```rust
//! The slim application header: title, date control, account slot.

use leptos::prelude::*;
use leptos_router::components::A;

use crate::components::account_menu::AccountMenu;
use crate::components::calendar::DatePicker;

#[component]
pub fn AppHeader(
    /// `None` on `/`, where the server cannot know the date yet.
    date: Option<chrono::NaiveDate>,
) -> impl IntoView {
    view! {
        <header class="bg-white border-b border-gray-200">
            <div class="w-full max-w-7xl mx-auto px-4 h-14 flex items-center gap-4">
                <A href="/" attr:class="text-sm font-bold text-gray-900 tracking-wide no-underline shrink-0">
                    "Time Tracker"
                </A>
                <div class="flex-1 flex justify-center min-w-0">
                    // Absent rather than empty on `/`: the slot renders no
                    // date because none is known, and the client fills the
                    // URL in after hydration.
                    {date.map(|date| view! { <DatePicker date=date/> })}
                </div>
                <div class="shrink-0">
                    <AccountMenu/>
                </div>
            </div>
        </header>
    }
}
```

- [ ] **Step 2: Implement `src/components/account_menu.rs`**

```rust
//! The upper-right account control: sign-in popover when signed out, a small
//! menu when signed in.

use leptos::either::Either;
use leptos::prelude::*;
use leptos_router::components::A;

use crate::auth_ctx::AuthCtx;
use crate::server_fns::session::{logout, request_magic_link};

/// The local part of an address, capped, for the corner label.
pub fn short_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    if local.chars().count() <= 18 {
        local.to_string()
    } else {
        local.chars().take(18).chain(std::iter::once('…')).collect()
    }
}

#[component]
pub fn AccountMenu() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let open = RwSignal::new(false);

    view! {
        <div class="relative">
            {move || match auth.user.get() {
                None => Either::Left(view! {
                    <button
                        type="button"
                        class="text-sm text-gray-600 hover:text-gray-900 px-2 py-1 rounded"
                        on:click=move |_| open.update(|o| *o = !*o)
                    >
                        "Sign in"
                    </button>
                }),
                Some(email) => Either::Right(view! {
                    <button
                        type="button"
                        class="flex items-center gap-2 text-sm text-gray-700 hover:text-gray-900 px-2 py-1 rounded"
                        on:click=move |_| open.update(|o| *o = !*o)
                    >
                        <span class="w-6 h-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold flex items-center justify-center">
                            {email.chars().next().unwrap_or('?').to_uppercase().to_string()}
                        </span>
                        <span>{short_name(&email)}</span>
                        <span class="text-gray-400 text-xs">"▾"</span>
                    </button>
                }),
            }}

            <div
                class="absolute right-0 top-9 w-64 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-20"
                class:hidden=move || !open.get()
            >
                {move || match auth.user.get() {
                    None => Either::Left(view! { <SignInPanel/> }),
                    Some(email) => Either::Right(view! { <SignedInPanel email=email/> }),
                }}
            </div>
        </div>
    }
}

#[component]
fn SignedInPanel(email: String) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");

    let sign_out = move |_| {
        leptos::task::spawn_local(async move {
            if logout().await.is_ok() {
                // Clearing the signal flips `AuthCtx::backend()` to Local,
                // which makes `use_persistent` re-read from localStorage —
                // no reload needed.
                auth.user.set(None);
            }
        });
    };

    view! {
        <p class="text-xs text-gray-500 truncate pb-2 mb-2 border-b border-gray-100">{email}</p>
        <A href="/account" attr:class="block text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5 no-underline">
            "Passkeys"
        </A>
        <button
            type="button"
            class="w-full text-left text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5"
            on:click=sign_out
        >
            "Sign out"
        </button>
    }
}

/// Email entry, plus the passkey shortcut.
///
/// Both paths end in the same "check your email" style confirmation and
/// neither reveals whether the address is registered — see invariant I5.
#[component]
fn SignInPanel() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let sent = RwSignal::new(false);
    let status = RwSignal::new(String::new());

    let send = move |_| {
        let address = email.get_untracked();
        leptos::task::spawn_local(async move {
            // The result is deliberately not branched on: success and every
            // failure mode look the same to the user, which is what stops
            // this form being an account-existence oracle.
            let _ = request_magic_link(address).await;
            sent.set(true);
        });
    };

    let use_passkey = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let typed = email.get_untracked();
            leptos::task::spawn_local(async move {
                match run_passkey_login(typed).await {
                    Ok(()) => {
                        if let Some(w) = web_sys::window() {
                            let _ = w.location().reload();
                        }
                    }
                    Err(e) => status.set(crate::webauthn_browser::friendly_error(e)),
                }
            });
        }
    };

    view! {
        {move || if sent.get() {
            Either::Left(view! {
                <div>
                    <p class="text-sm font-semibold text-gray-900 mb-1">"Check your email"</p>
                    <p class="text-xs text-gray-600">
                        "If that address has an account or can have one, a sign-in link is on its way. It works once and expires in 15 minutes."
                    </p>
                    <button
                        type="button"
                        class="mt-3 w-full text-sm border border-gray-300 rounded py-1.5 hover:bg-gray-50"
                        on:click=move |_| sent.set(false)
                    >
                        "Use a different address"
                    </button>
                </div>
            })
        } else {
            Either::Right(view! {
                <div>
                    <p class="text-sm font-semibold text-gray-900 mb-2">"Sign in"</p>
                    <label class="block text-xs text-gray-500 mb-1" for="signin-email">"Email"</label>
                    <input
                        id="signin-email"
                        type="email"
                        autocomplete="username webauthn"
                        class="w-full border border-gray-300 rounded px-2 py-1.5 text-sm mb-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        prop:value=move || email.get()
                        on:input=move |ev| email.set(event_target_value(&ev))
                    />
                    <button
                        type="button"
                        class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-1.5 hover:bg-blue-700"
                        on:click=send
                    >
                        "Email me a link"
                    </button>
                    <p class="text-center text-xs text-gray-400 my-2">"or"</p>
                    <button
                        type="button"
                        class="w-full border border-gray-300 text-sm rounded py-1.5 hover:bg-gray-50"
                        on:click=use_passkey
                    >
                        "Use a passkey"
                    </button>
                    <p class="text-xs text-gray-600 mt-2">
                        "An account syncs your entries across devices. Without one, everything stays in this browser."
                    </p>
                    {move || {
                        let s = status.get();
                        (!s.is_empty()).then(|| view! { <p class="text-xs text-red-600 mt-2">{s}</p> })
                    }}
                </div>
            })
        }}
    }
}

/// Runs the sign-in ceremony. An empty address uses the discoverable flow,
/// which is what makes the button work with nothing typed.
#[cfg(feature = "hydrate")]
async fn run_passkey_login(typed_email: String) -> Result<(), String> {
    use crate::server_fns::passkey::{passkey_login_finish, passkey_login_start};
    use crate::webauthn_browser;

    let email = (!typed_email.trim().is_empty()).then_some(typed_email);
    let challenge = passkey_login_start(email).await.map_err(|e| e.to_string())?;
    let credential = webauthn_browser::authenticate(&challenge)
        .await
        .map_err(|e| e.to_string())?;
    passkey_login_finish(credential).await.map_err(|e| e.to_string())
}
```

- [ ] **Step 3: Write the tests for the label helper**

Add to `src/components/account_menu.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::short_name;

    #[test]
    fn shows_the_local_part() {
        assert_eq!(short_name("steve@javapl.us"), "steve");
    }

    #[test]
    fn truncates_a_long_local_part() {
        let out = short_name("averyverylonglocalpartindeed@example.com");
        assert_eq!(out.chars().count(), 19, "18 chars plus an ellipsis");
        assert!(out.ends_with('…'));
    }

    #[test]
    fn an_address_without_an_at_is_used_directly() {
        assert_eq!(short_name("bob"), "bob");
    }
}
```

- [ ] **Step 4: Run the tests and commit**

```bash
cargo test --features ssr --no-default-features components::account_menu
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/components/header.rs src/components/account_menu.rs src/components/mod.rs
git commit -m "feat(ui): add the app header and account menu

Slim header: title left, date centre, account right. The sign-in form
does not branch on the result of request_magic_link — success and every
failure look identical, which is what keeps it from being an
account-existence oracle.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 21: The `/account` page

**Files:**
- Create: `src/components/account_page.rs`
- Modify: `src/components/mod.rs`, `tests/routes.rs`

**Interfaces:**
- Consumes: `dto::PasskeyListItem`, `server_fns::passkey`, `webauthn_browser`, `AuthCtx`.
- Produces: `account_page::AccountPage`.

- [ ] **Step 1: Implement `src/components/account_page.rs`**

```rust
//! `/account` — passkey management.
//!
//! A route rather than a popover: it is the natural home for phase 2's
//! encryption settings, and a link somebody can be sent when a passkey
//! misbehaves.

use leptos::either::Either;
use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::components::A;

use crate::auth_ctx::AuthCtx;
use crate::components::header::AppHeader;
use crate::dto::PasskeyListItem;
use crate::server_fns::passkey::{passkey_delete, passkey_list, passkey_rename};

#[component]
pub fn AccountPage() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");

    view! {
        <Title text="Account — Time Tracker"/>
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=None/>
            <div class="w-full max-w-2xl mx-auto px-4 py-8">
                {move || match auth.user.get() {
                    None => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <h1 class="text-xl font-semibold text-gray-800 mb-2">"Passkeys"</h1>
                            <p class="text-sm text-gray-600">
                                "Sign in to manage passkeys for your account."
                            </p>
                            <A href="/" attr:class="inline-block mt-4 text-sm text-blue-600 no-underline">
                                "Back to today"
                            </A>
                        </div>
                    }),
                    Some(email) => Either::Right(view! { <PasskeySection email=email/> }),
                }}
            </div>
        </div>
    }
}

#[component]
fn PasskeySection(email: String) -> impl IntoView {
    // `Resource` here is safe: this route is client-navigated and never part
    // of the day view's SSR path, so it does not affect the synchronous
    // render the SSR tests rely on.
    let rows = Resource::new(|| (), |_| async { passkey_list().await.unwrap_or_default() });
    let status = RwSignal::new(String::new());

    let add = move |_| {
        #[cfg(feature = "hydrate")]
        leptos::task::spawn_local(async move {
            match run_registration().await {
                Ok(()) => {
                    status.set("Passkey added.".to_string());
                    rows.refetch();
                }
                Err(e) => status.set(crate::webauthn_browser::friendly_error(e)),
            }
        });
    };

    let remove = move |id: i32| {
        leptos::task::spawn_local(async move {
            match passkey_delete(id).await {
                Ok(()) => {
                    status.set("Passkey removed.".to_string());
                    rows.refetch();
                }
                Err(e) => status.set(crate::webauthn_browser::friendly_error(e.to_string())),
            }
        });
    };

    let rename = move |id: i32, name: String| {
        leptos::task::spawn_local(async move {
            match passkey_rename(id, name).await {
                Ok(()) => rows.refetch(),
                Err(e) => status.set(crate::webauthn_browser::friendly_error(e.to_string())),
            }
        });
    };

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <A href="/" attr:class="text-sm text-blue-600 no-underline">"‹ Back to today"</A>
            <h1 class="text-xl font-semibold text-gray-800 mt-3 mb-1">"Passkeys"</h1>
            <p class="text-sm text-gray-500 mb-5">{email}</p>

            <Suspense fallback=|| view! { <p class="text-sm text-gray-500">"Loading…"</p> }>
                {move || Suspend::new(async move {
                    let list = rows.await;
                    if list.is_empty() {
                        Either::Left(view! {
                            <p class="text-sm text-gray-600">
                                "No passkeys yet. Add one to sign in with Touch ID, Windows Hello, or your phone — no email round trip."
                            </p>
                        })
                    } else {
                        Either::Right(view! {
                            <ul class="divide-y divide-gray-100">
                                {list.into_iter()
                                    .map(|row| view! { <PasskeyRow row=row on_remove=remove on_rename=rename/> })
                                    .collect_view()}
                            </ul>
                        })
                    }
                })}
            </Suspense>

            <button
                type="button"
                class="mt-6 bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700"
                on:click=add
            >
                "Add a passkey"
            </button>
            {move || {
                let s = status.get();
                (!s.is_empty()).then(|| view! { <p class="mt-3 text-sm text-gray-600">{s}</p> })
            }}
        </div>
    }
}

#[component]
fn PasskeyRow(
    row: PasskeyListItem,
    on_remove: impl Fn(i32) + Copy + 'static,
    on_rename: impl Fn(i32, String) + Copy + 'static,
) -> impl IntoView {
    let id = row.id;
    let editing = RwSignal::new(false);
    let draft = RwSignal::new(row.name.clone());
    let last_used = row.last_used.clone().unwrap_or_else(|| "Never".to_string());

    let commit = move |_| {
        editing.set(false);
        on_rename(id, draft.get_untracked());
    };

    view! {
        <li class="flex items-start justify-between gap-3 py-3">
            <div class="min-w-0">
                {move || if editing.get() {
                    Either::Left(view! {
                        <input
                            class="border border-gray-300 rounded px-2 py-1 text-sm w-48"
                            prop:value=move || draft.get()
                            on:input=move |ev| draft.set(event_target_value(&ev))
                            on:blur=commit
                        />
                    })
                } else {
                    Either::Right(view! {
                        <button
                            type="button"
                            class="text-sm font-medium text-gray-900 hover:text-blue-600"
                            on:click=move |_| editing.set(true)
                        >
                            {move || draft.get()}
                            <span class="text-gray-400 ml-1 text-xs">"✎"</span>
                        </button>
                    })
                }}
                <p class="text-xs text-gray-500">"Added "{row.added.clone()}</p>
                <p class="text-xs text-gray-500">"Last used: "{last_used}</p>
            </div>
            <button
                type="button"
                class="text-sm text-red-600 hover:text-red-800 shrink-0"
                on:click=move |_| on_remove(id)
            >
                "Remove"
            </button>
        </li>
    }
}

#[cfg(feature = "hydrate")]
async fn run_registration() -> Result<(), String> {
    use crate::server_fns::passkey::{passkey_register_finish, passkey_register_start};
    use crate::webauthn_browser;

    let challenge = passkey_register_start().await.map_err(|e| e.to_string())?;
    // `prf_capable` comes from getClientExtensionResults(), which toJSON()
    // does not include. Phase 1 only records it (spec section 9.3).
    let (credential, prf_capable) = webauthn_browser::register(&challenge)
        .await
        .map_err(|e| e.to_string())?;
    passkey_register_finish(credential, prf_capable)
        .await
        .map_err(|e| e.to_string())
}
```

- [ ] **Step 2: Enable the route-priority test**

Remove the `#[ignore]` from `account_route_beats_the_date_route` in `tests/routes.rs`.

- [ ] **Step 3: Run and commit**

```bash
cargo test --features ssr --no-default-features
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/components/account_page.rs src/components/mod.rs tests/routes.rs
git commit -m "feat(ui): add the /account passkey management page

A route rather than a popover, so it is linkable and so phase 2's
encryption settings have a home. Registration records the PRF
capability the browser reports.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 22: The calendar picker

**Files:**
- Create: `src/components/calendar.rs`
- Modify: `src/components/mod.rs`

**Interfaces:**
- Consumes: `date::{month_bounds, format_long, to_iso}`, `storage::dates_with_entries`, `AuthCtx`.
- Produces: `calendar::DatePicker { date: NaiveDate }`, `calendar::month_grid(NaiveDate) -> Vec<Option<NaiveDate>>`.

- [ ] **Step 1: Write the failing tests for the grid**

Add to `src/components/calendar.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// September 2026 starts on a Tuesday, so one leading blank for Monday.
    #[test]
    fn grid_pads_to_the_first_weekday() {
        let grid = month_grid(d(2026, 9, 4));
        assert_eq!(grid[0], None, "Monday cell is empty");
        assert_eq!(grid[1], Some(d(2026, 9, 1)), "the 1st falls on Tuesday");
    }

    #[test]
    fn grid_covers_every_day_of_the_month() {
        let grid = month_grid(d(2026, 9, 4));
        let days: Vec<_> = grid.iter().flatten().collect();
        assert_eq!(days.len(), 30, "September has 30 days");
        assert_eq!(days.first(), Some(&&d(2026, 9, 1)));
        assert_eq!(days.last(), Some(&&d(2026, 9, 30)));
    }

    /// A month starting on Monday needs no padding at all — the case an
    /// unconditional "add N blanks" gets wrong by a whole week.
    #[test]
    fn a_month_starting_on_monday_has_no_padding() {
        // 2026-06-01 is a Monday.
        let grid = month_grid(d(2026, 6, 15));
        assert_eq!(grid[0], Some(d(2026, 6, 1)));
    }

    #[test]
    fn grid_length_is_a_whole_number_of_weeks() {
        for (y, m) in [(2026, 2), (2026, 9), (2028, 2), (2026, 11)] {
            let grid = month_grid(d(y, m, 1));
            assert_eq!(grid.len() % 7, 0, "{y}-{m} grid must fill whole weeks");
        }
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Run: `cargo test --features ssr --no-default-features components::calendar`
Expected: FAIL to compile — `cannot find function 'month_grid'`.

Prepend to `src/components/calendar.rs`:

```rust
//! The header's date control: a label, day steppers, and a month popover
//! marking the days that have entries.

use chrono::{Datelike, Days, NaiveDate};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::auth_ctx::AuthCtx;
use crate::date::{format_long, month_bounds, to_iso};
use crate::storage::dates_with_entries;

/// The month's days laid out Monday-first, padded with `None` so each row of
/// seven is a calendar week.
pub fn month_grid(any_day: NaiveDate) -> Vec<Option<NaiveDate>> {
    let (first, last) = month_bounds(any_day);
    let lead = first.weekday().num_days_from_monday() as usize;

    let mut cells: Vec<Option<NaiveDate>> = vec![None; lead];
    let mut day = first;
    while day <= last {
        cells.push(Some(day));
        day += Days::new(1);
    }
    // Pad the final row so the grid is always whole weeks; a ragged last row
    // makes the CSS grid reflow the columns.
    while cells.len() % 7 != 0 {
        cells.push(None);
    }
    cells
}

#[component]
pub fn DatePicker(date: NaiveDate) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let open = RwSignal::new(false);
    let navigate = use_navigate();

    let go = {
        let navigate = navigate.clone();
        move |target: NaiveDate| {
            open.set(false);
            navigate(&format!("/{}", to_iso(target)), Default::default());
        }
    };

    // Which days in the visible month have entries. Refetched when the month
    // or the backend changes — signing in must repopulate the dots.
    let marked = RwSignal::new(Vec::<NaiveDate>::new());
    let backend = auth.backend();
    Effect::new(move |_| {
        let backend = backend.get();
        let (from, to) = month_bounds(date);
        leptos::task::spawn_local(async move {
            // A failed lookup means no dots, never a broken calendar: the
            // picker's job is navigation, and the marks are a convenience.
            marked.set(dates_with_entries(backend, from, to).await.unwrap_or_default());
        });
    });

    view! {
        <div class="relative flex items-center gap-1">
            <button
                type="button"
                class="px-1.5 py-1 text-gray-400 hover:text-gray-700 text-sm"
                aria-label="Previous day"
                on:click={let go = go.clone(); move |_| go(date - Days::new(1))}
            >
                "‹"
            </button>
            <button
                type="button"
                class="text-sm font-semibold text-gray-900 border border-gray-300 rounded px-3 py-1 hover:bg-gray-50 whitespace-nowrap"
                on:click=move |_| open.update(|o| *o = !*o)
            >
                {format_long(date)}
            </button>
            <button
                type="button"
                class="px-1.5 py-1 text-gray-400 hover:text-gray-700 text-sm"
                aria-label="Next day"
                on:click={let go = go.clone(); move |_| go(date + Days::new(1))}
            >
                "›"
            </button>

            <div
                class="absolute left-1/2 -translate-x-1/2 top-10 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-20 w-64"
                class:hidden=move || !open.get()
            >
                <p class="text-xs font-semibold text-gray-700 text-center mb-2">
                    {date.format("%B %Y").to_string()}
                </p>
                <div class="grid grid-cols-7 gap-0.5 text-center">
                    {["M", "T", "W", "T", "F", "S", "S"]
                        .into_iter()
                        .enumerate()
                        .map(|(i, label)| view! {
                            <span class="text-[10px] text-gray-400" id=format!("dow-{i}")>{label}</span>
                        })
                        .collect_view()}
                    {move || month_grid(date)
                        .into_iter()
                        .map(|cell| match cell {
                            None => leptos::either::Either::Left(view! { <span></span> }),
                            Some(day) => {
                                let is_selected = day == date;
                                let has_entry = marked.get().contains(&day);
                                let go = go.clone();
                                leptos::either::Either::Right(view! {
                                    <button
                                        type="button"
                                        class="text-xs rounded py-1 hover:bg-blue-50 relative"
                                        class:bg-blue-600=is_selected
                                        class:text-white=is_selected
                                        class:font-semibold=has_entry
                                        on:click=move |_| go(day)
                                    >
                                        {day.day().to_string()}
                                        {has_entry.then(|| view! {
                                            <span class="absolute bottom-0.5 left-1/2 -translate-x-1/2 w-1 h-1 rounded-full bg-blue-500"></span>
                                        })}
                                    </button>
                                })
                            }
                        })
                        .collect_view()}
                </div>
            </div>
        </div>
    }
}
```

- [ ] **Step 3: Run the tests and commit**

```bash
cargo test --features ssr --no-default-features components::calendar
git add src/components/calendar.rs src/components/mod.rs
git commit -m "feat(ui): add the calendar date picker with entry dots

The grid is Monday-first and always a whole number of weeks. Dots come
from dates_with_entries, which returns dates only — the calendar needs
to know which days have something, not what.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 23: The week view

**Files:**
- Create: `src/components/week_view.rs`
- Modify: `src/components/mod.rs`, `src/components/account_menu.rs`

**Interfaces:**
- Consumes: `date::week_bounds`, `storage::entries_in_range` (via a new `storage::bodies_in_range`), `time_tracking_parser`.
- Produces: `week_view::WeekView`, `week_view::aggregate(&[(NaiveDate, String)]) -> WeekTotals`.

**Why the aggregation is here and not on the server.** Phase 2 encrypts entry
bodies client-side; the server will not hold the key and therefore cannot
total anything. Writing the aggregation server-side now would have to be
deleted later, so it is written where it will keep working (spec section 9.1).

- [ ] **Step 1: Write the failing tests for the aggregation**

Add to `src/components/week_view.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    #[test]
    fn totals_a_single_day() {
        let rows = vec![(d(2026, 9, 1), "9-10 code1\n- did a thing".to_string())];
        let totals = aggregate(&rows);
        assert_eq!(totals.total_minutes, 60);
        assert_eq!(totals.per_day.len(), 1);
        assert_eq!(totals.per_project.len(), 1);
        assert_eq!(totals.per_project[0].0, "code1");
        assert_eq!(totals.per_project[0].1, 60);
    }

    /// The point of the view: one project worked across several days is one
    /// row with the combined total.
    #[test]
    fn sums_a_project_across_days() {
        let rows = vec![
            (d(2026, 9, 1), "9-10 code1".to_string()),
            (d(2026, 9, 2), "9-11 code1".to_string()),
            (d(2026, 9, 3), "9-10 code2".to_string()),
        ];
        let totals = aggregate(&rows);
        assert_eq!(totals.total_minutes, 240);
        let code1 = totals.per_project.iter().find(|(n, _)| n == "code1").expect("code1 present");
        assert_eq!(code1.1, 180);
    }

    /// Biggest first, so a weekly timesheet reads top-down.
    #[test]
    fn projects_are_ordered_by_time_descending() {
        let rows = vec![
            (d(2026, 9, 1), "9-10 small".to_string()),
            (d(2026, 9, 2), "9-13 large".to_string()),
        ];
        let totals = aggregate(&rows);
        assert_eq!(totals.per_project[0].0, "large");
    }

    #[test]
    fn an_empty_week_totals_zero() {
        let totals = aggregate(&[]);
        assert_eq!(totals.total_minutes, 0);
        assert!(totals.per_project.is_empty());
        assert!(totals.per_day.is_empty());
    }

    /// A day saved and then emptied is a real state; it must not become a
    /// zero-minute row cluttering the view.
    #[test]
    fn empty_bodies_contribute_no_rows() {
        let rows = vec![(d(2026, 9, 1), String::new()), (d(2026, 9, 2), "9-10 code1".into())];
        let totals = aggregate(&rows);
        assert_eq!(totals.per_day.len(), 1, "only the non-empty day counts");
        assert_eq!(totals.total_minutes, 60);
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Run: `cargo test --features ssr --no-default-features components::week_view`
Expected: FAIL to compile — `cannot find function 'aggregate'`.

Prepend to `src/components/week_view.rs`:

```rust
//! `/week/{date}` — a read-only weekly summary.
//!
//! Every total on this page is computed **in the browser**, from bodies the
//! server hands over uninterpreted. That is not an optimization: phase 2
//! encrypts bodies client-side, so a server-side weekly total could not
//! survive it (spec section 9.1).

use chrono::{Days, NaiveDate};
use leptos::either::Either;
use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::components::A;
use leptos_router::hooks::use_params_map;
use time_tracking_parser::{Time, parse_time_tracking_data};

use crate::auth_ctx::AuthCtx;
use crate::components::header::AppHeader;
use crate::date::{parse_iso, to_iso, week_bounds};
use crate::storage::bodies_in_range;

/// A week's totals, ready to render.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WeekTotals {
    pub total_minutes: u32,
    /// `(date, minutes)`, chronological. Days with no work are absent.
    pub per_day: Vec<(NaiveDate, u32)>,
    /// `(project, minutes)`, largest first.
    pub per_project: Vec<(String, u32)>,
}

/// Parses each day and combines the results.
pub fn aggregate(rows: &[(NaiveDate, String)]) -> WeekTotals {
    use std::collections::HashMap;

    let mut per_project: HashMap<String, u32> = HashMap::new();
    let mut per_day = Vec::new();
    let mut total_minutes = 0;

    for (date, body) in rows {
        let parsed = parse_time_tracking_data(body);
        if parsed.total_minutes == 0 && parsed.projects.is_empty() {
            // A day that was saved and then emptied. Skipping it keeps
            // zero-minute rows out of the table.
            continue;
        }
        total_minutes += parsed.total_minutes;
        per_day.push((*date, parsed.total_minutes));
        for project in parsed.projects {
            *per_project.entry(project.name).or_default() += project.total_minutes;
        }
    }

    let mut per_project: Vec<(String, u32)> = per_project.into_iter().collect();
    // Largest first, then by name so equal totals are stably ordered rather
    // than reshuffling between renders.
    per_project.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    per_day.sort_by_key(|(d, _)| *d);

    WeekTotals { total_minutes, per_day, per_project }
}

#[component]
pub fn WeekView() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let params = use_params_map();
    let anchor = Signal::derive(move || {
        params.with(|p| p.get("date").and_then(|raw| parse_iso(&raw)))
    });

    view! {
        <Title text="Week — Time Tracker"/>
        {move || match anchor.get() {
            None => Either::Left(view! {
                <div class="min-h-screen bg-gray-50">
                    <AppHeader date=None/>
                    <main class="max-w-2xl mx-auto px-4 py-8">
                        <p class="text-gray-600">"That isn't a date."</p>
                    </main>
                </div>
            }),
            Some(day) => Either::Right(view! { <WeekBody anchor=day backend=auth.backend()/> }),
        }}
    }
}

#[component]
fn WeekBody(anchor: NaiveDate, backend: Signal<crate::storage::Backend>) -> impl IntoView {
    let (start, end) = week_bounds(anchor);
    // `None` until loaded, exactly like the day view's entry: the totals are
    // a conclusion about stored data, and the shell must not assert one
    // before it has any.
    let totals = RwSignal::new(Option::<WeekTotals>::None);

    Effect::new(move |_| {
        let backend = backend.get();
        totals.set(None);
        leptos::task::spawn_local(async move {
            let rows = bodies_in_range(backend, start, end).await.unwrap_or_default();
            totals.set(Some(aggregate(&rows)));
        });
    });

    view! {
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=Some(anchor)/>
            <main class="w-full max-w-3xl mx-auto px-4 py-8">
                <div class="flex items-center justify-between mb-5">
                    <h1 class="text-xl font-semibold text-gray-800">
                        {format!("Week of {}", start.format("%b %-d, %Y"))}
                    </h1>
                    <div class="flex gap-3 text-sm">
                        <A href=format!("/week/{}", to_iso(start - Days::new(7))) attr:class="text-blue-600 no-underline">"‹ Previous"</A>
                        <A href=format!("/week/{}", to_iso(start + Days::new(7))) attr:class="text-blue-600 no-underline">"Next ›"</A>
                    </div>
                </div>

                {move || match totals.get() {
                    None => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="value-slot"></p>
                        </div>
                    }),
                    Some(t) if t.per_day.is_empty() => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <p class="text-sm text-gray-500">"Nothing logged this week."</p>
                        </div>
                    }),
                    Some(t) => Either::Right(view! { <WeekTables totals=t/> }),
                }}
            </main>
        </div>
    }
}

#[component]
fn WeekTables(totals: WeekTotals) -> impl IntoView {
    let grand = format!(
        "{} ({} hrs)",
        Time::format_duration_minutes(totals.total_minutes),
        Time::format_duration_decimal(totals.total_minutes),
    );

    view! {
        <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-6 rounded">
            <h2 class="text-sm font-medium text-green-800 mb-1">"Total for the week"</h2>
            <p class="text-lg font-semibold text-green-700 value-slot">{grand}</p>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6 mb-6">
            <h2 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">"By project"</h2>
            <div class="space-y-2">
                {totals.per_project.into_iter().map(|(name, minutes)| view! {
                    <div class="flex items-center justify-between">
                        <span class="text-sm text-gray-800">{name}</span>
                        <span class="text-sm font-medium text-blue-600 bg-blue-100 px-2 py-0.5 rounded-full">
                            {format!("{} ({} hrs)",
                                Time::format_duration_minutes(minutes),
                                Time::format_duration_decimal(minutes))}
                        </span>
                    </div>
                }).collect_view()}
            </div>
        </div>

        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">"By day"</h2>
            <div class="space-y-2">
                {totals.per_day.into_iter().map(|(date, minutes)| view! {
                    <div class="flex items-center justify-between">
                        <A href=format!("/{}", to_iso(date)) attr:class="text-sm text-blue-600 no-underline">
                            {date.format("%A, %b %-d").to_string()}
                        </A>
                        <span class="text-sm text-gray-700">
                            {format!("{} ({} hrs)",
                                Time::format_duration_minutes(minutes),
                                Time::format_duration_decimal(minutes))}
                        </span>
                    </div>
                }).collect_view()}
            </div>
        </div>
    }
}
```

- [ ] **Step 3: Add `bodies_in_range` to the storage seam**

In `src/storage/mod.rs`:

```rust
/// Every stored body in `[from, to]`, unwrapped. Feeds the week view.
///
/// Separate from [`dates_with_entries`] because the two answer different
/// questions and should move different amounts of data: the calendar wants
/// to know *which* days, this wants *what*.
pub async fn bodies_in_range(
    backend: Backend,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(NaiveDate, String)>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::bodies_in_range(from, to).await?,
            Backend::Remote => remote::bodies_in_range(from, to).await?,
        };
        raw.into_iter()
            .map(|(date, env)| {
                envelope::unwrap(&env)
                    .map(|body| (date, body))
                    .map_err(|source| StorageError::Envelope {
                        key: StorageKey::TimeEntry(date).as_key(),
                        source,
                    })
            })
            .collect()
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to);
        Ok(Vec::new())
    }
}
```

Add the matching `bodies_in_range` to `local.rs` (key scan, then read each) and `remote.rs` (one `entries::entries_in_range` call).

- [ ] **Step 4: Link the week view from the account menu**

Add above "Passkeys" in `SignedInPanel`, and in the signed-out panel omit it:

```rust
<A
    href=move || format!("/week/{}", crate::date::to_iso(crate::date::today_local()))
    attr:class="block text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5 no-underline"
>
    "This week"
</A>
```

Under `ssr` `today_local` does not exist; use `crate::date::today_utc()` behind a `cfg` or route to `/week/` of the currently viewed date instead. Prefer the latter — pass the header's date down — so the link is correct on both targets without a `cfg`.

- [ ] **Step 5: Run and commit**

```bash
cargo test --features ssr --no-default-features
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/components/week_view.rs src/components/mod.rs src/components/account_menu.rs src/storage/
git commit -m "feat(ui): add the read-only week summary

Aggregation runs in the browser over bodies the server never parses,
because phase 2 encrypts them and a server-side total could not survive
that.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

### Task 24: The import banner

**Files:**
- Create: `src/components/import_banner.rs`
- Modify: `src/components/mod.rs`

**Interfaces:**
- Consumes: `storage::{Backend, StorageKey, dates_with_entries, bodies_in_range, store}`, `AuthCtx`.
- Produces: `import_banner::ImportBanner`, `import_banner::importable(&[NaiveDate], &[NaiveDate]) -> Vec<NaiveDate>`, `import_banner::DONE_FLAG_KEY`.

- [ ] **Step 1: Write the failing tests**

Add to `src/components/import_banner.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// Pins invariant I9. A day that already exists server-side is never
    /// offered, so importing can never overwrite work done on another
    /// device — which is what makes the one-click offer safe.
    #[test]
    fn days_already_on_the_server_are_excluded() {
        let local = vec![d(2026, 9, 1), d(2026, 9, 2), d(2026, 9, 3)];
        let remote = vec![d(2026, 9, 2)];
        assert_eq!(importable(&local, &remote), vec![d(2026, 9, 1), d(2026, 9, 3)]);
    }

    #[test]
    fn nothing_local_means_nothing_to_import() {
        assert!(importable(&[], &[d(2026, 9, 1)]).is_empty());
    }

    #[test]
    fn every_local_day_is_offered_when_the_server_is_empty() {
        let local = vec![d(2026, 9, 1), d(2026, 9, 2)];
        assert_eq!(importable(&local, &[]), local);
    }

    #[test]
    fn a_fully_covered_device_offers_nothing() {
        let days = vec![d(2026, 9, 1), d(2026, 9, 2)];
        assert!(importable(&days, &days).is_empty());
    }

    /// The flag is per-device, and its key is a compatibility surface like
    /// every other storage key.
    #[test]
    fn done_flag_key_is_pinned() {
        assert_eq!(DONE_FLAG_KEY, "time_entry_import_done");
    }
}
```

- [ ] **Step 2: Run to verify failure, then implement**

Run: `cargo test --features ssr --no-default-features components::import_banner`
Expected: FAIL to compile — `cannot find function 'importable'`.

Prepend to `src/components/import_banner.rs`:

```rust
//! "Import N days from this device?" — shown once, after a first sign-in on
//! a browser that has local entries the account does not.
//!
//! Signing in switches the storage backend from `Local` to `Remote`, which
//! would otherwise make a user's on-device work appear to vanish.

use chrono::NaiveDate;
use leptos::prelude::*;

use crate::auth_ctx::AuthCtx;
use crate::storage::{Backend, StorageKey, bodies_in_range, dates_with_entries, store};

/// Per-device marker so the banner appears at most once.
///
/// Device-scoped rather than account-scoped because it describes *this
/// browser's* leftovers, not a fact about the account.
pub const DONE_FLAG_KEY: &str = "time_entry_import_done";

/// How far back a first sign-in looks for local entries.
const LOOKBACK_DAYS: i64 = 365;

/// The local days worth offering: those the server does not already have.
///
/// Excluding days the server already holds is what makes the import safe to
/// run from a single button with no confirmation — a second device signing
/// in cannot clobber the first device's work with a stale local copy
/// (invariant I9).
pub fn importable(local: &[NaiveDate], remote: &[NaiveDate]) -> Vec<NaiveDate> {
    local.iter().filter(|d| !remote.contains(d)).copied().collect()
}

#[component]
pub fn ImportBanner() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let candidates = RwSignal::new(Vec::<NaiveDate>::new());
    let status = RwSignal::new(Option::<String>::None);

    #[cfg(feature = "hydrate")]
    Effect::new(move |_| {
        if !auth.is_signed_in() || already_done() {
            candidates.set(Vec::new());
            return;
        }
        leptos::task::spawn_local(async move {
            let today = crate::date::today_local();
            let from = today - chrono::Days::new(LOOKBACK_DAYS as u64);
            let local = dates_with_entries(Backend::Local, from, today).await.unwrap_or_default();
            if local.is_empty() {
                mark_done();
                return;
            }
            let remote = dates_with_entries(Backend::Remote, from, today).await.unwrap_or_default();
            let offer = importable(&local, &remote);
            if offer.is_empty() {
                mark_done();
            }
            candidates.set(offer);
        });
    });

    let dismiss = move |_| {
        #[cfg(feature = "hydrate")]
        mark_done();
        candidates.set(Vec::new());
    };

    let import = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let days = candidates.get_untracked();
            leptos::task::spawn_local(async move {
                let Some(&first) = days.first() else { return };
                let Some(&last) = days.last() else { return };
                let bodies = bodies_in_range(Backend::Local, first, last)
                    .await
                    .unwrap_or_default();

                let mut copied = 0;
                for (date, body) in bodies {
                    if !days.contains(&date) {
                        continue;
                    }
                    // Local copies are deliberately left in place: a failed
                    // import then loses nothing, and signing out still
                    // leaves the user their data.
                    if store(Backend::Remote, StorageKey::TimeEntry(date), &body).await.is_ok() {
                        copied += 1;
                    }
                }
                mark_done();
                candidates.set(Vec::new());
                status.set(Some(format!(
                    "Imported {copied} {}.",
                    if copied == 1 { "day" } else { "days" }
                )));
            });
        }
    };

    view! {
        {move || {
            let pending = candidates.get();
            (!pending.is_empty()).then(|| view! {
                <div class="mb-6 flex flex-wrap items-center gap-3 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3">
                    <p class="text-sm text-blue-900 flex-1">
                        {format!(
                            "This device has {} {} saved locally that your account doesn't. Import them?",
                            pending.len(),
                            if pending.len() == 1 { "day" } else { "days" },
                        )}
                    </p>
                    <button
                        type="button"
                        class="text-sm bg-blue-600 text-white rounded px-3 py-1.5 font-medium hover:bg-blue-700"
                        on:click=import
                    >
                        "Import"
                    </button>
                    <button
                        type="button"
                        class="text-sm text-blue-700 px-2 py-1.5 hover:underline"
                        on:click=dismiss
                    >
                        "No thanks"
                    </button>
                </div>
            })
        }}
        {move || status.get().map(|s| view! {
            <p class="mb-6 text-sm text-gray-600">{s}</p>
        })}
    }
}

#[cfg(feature = "hydrate")]
fn flag_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

#[cfg(feature = "hydrate")]
fn already_done() -> bool {
    flag_storage()
        .and_then(|s| s.get_item(DONE_FLAG_KEY).ok().flatten())
        .is_some()
}

#[cfg(feature = "hydrate")]
fn mark_done() {
    if let Some(s) = flag_storage() {
        let _ = s.set_item(DONE_FLAG_KEY, "1");
    }
}
```

- [ ] **Step 3: Run everything and commit**

```bash
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
git add src/components/import_banner.rs src/components/mod.rs
git commit -m "feat(ui): offer to import on-device entries after first sign-in

Pins invariant I9: days the server already has are never offered, so
the one-click import cannot clobber work from another device. Local
copies are left in place, so a failed import loses nothing.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Phase 6 — Documentation and finish

### Task 25: Documentation, configuration, and full verification

**Files:**
- Modify: `CLAUDE.md`, `README.md`, `Dockerfile`, `.gitignore`
- Create: `.env.example`

- [ ] **Step 1: Add `.env.example`**

```bash
# Copy to .env for local development. `cargo leptos watch` reads it via dotenvy.

# SQLite file. Created along with its parent directory on first run.
DATABASE_URL=./data/time-tracking.db

# Signs session cookies. REQUIRED in release builds — the binary refuses to
# start without it. Unset in a debug build, an ephemeral key is generated and
# sessions do not survive a restart. Generate with:
#   openssl rand -hex 32
SESSION_KEY=

# Signs in-flight WebAuthn ceremony state. Falls back to SESSION_KEY when
# unset; set it separately so one leaked secret cannot forge the other.
PASSKEY_STATE_KEY=

# Absolute base URL used to build magic-link URLs. Must match how users
# actually reach the app, or the emailed links point somewhere wrong.
SITE_BASE_URL=http://localhost:3000

# Unset SMTP_HOST logs sign-in links instead of emailing them — the normal
# development mode.
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
SMTP_FROM=

# Must match the browser's origin exactly, scheme included.
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_ORIGIN=http://localhost:3000
WEBAUTHN_RP_NAME=Time Tracker

MAGIC_LINK_TTL_SECONDS=900
```

Add `/data` and `.env` to `.gitignore`.

- [ ] **Step 2: Update `CLAUDE.md`**

Amend the existing sections rather than appending. Specifically:

1. The opening paragraph currently says "All user data lives in the browser's `localStorage`; nothing is stored server-side." Replace with a description of the two backends and the phase-2 encryption goal.
2. Extend the hydration-contract section: the tri-state now also resets on a key change, and the server renders auth state but never entry content.
3. Add a **Storage keys** note covering `time_entry:YYYY-MM-DD`, the legacy alias, and `time_entry_import_done`.
4. Add a **Routing** note: `/{date}` shadows single-segment static paths; root assets must be listed in `ROOT_ASSETS` in `main.rs`.
5. Add an **Encryption trajectory** note: the server must never parse an entry body, and the week view aggregates client-side for that reason.
6. Add the new env vars to a **Configuration** table.
7. Update **Commands** with `cargo test --features ssr --no-default-features --test routes` and note that integration tests live in `tests/`.
8. Link the new spec under **Design docs**.

- [ ] **Step 3: Update `README.md`**

Add a "Configuration" section pointing at `.env.example`, an "Accounts" section explaining that sign-in is optional and what it changes, and correct the existing **Architecture** paragraph, which currently states "No time-tracking data is sent to or stored on the server." That is now false for signed-in users and must say so, along with the phase-2 encryption plan.

- [ ] **Step 4: Update the `Dockerfile`**

The runtime stage needs a writable location for the SQLite file. Add:

```dockerfile
ENV DATABASE_URL=/data/time-tracking.db
VOLUME ["/data"]
```

Note in a comment that `SESSION_KEY` must be supplied at run time or the container exits immediately, which is the intended behavior.

- [ ] **Step 5: Full verification**

```bash
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features -- -D warnings
cargo fmt --all --check
cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate
cargo tree -i openssl-sys --features ssr --no-default-features 2>&1 | tail -2
cargo tree -i native-tls --features ssr --no-default-features 2>&1 | tail -2
cargo leptos build --release
```

Expected: tests pass, clippy clean with warnings denied, formatting clean, wasm builds, neither TLS crate resolves, release build succeeds.

- [ ] **Step 6: Manual smoke test**

`cargo leptos watch`, then confirm in a browser:

1. Signed out, `/` replaces itself with today's dated URL and the existing entry (under the legacy key) appears.
2. Editing writes `time_entry:<today>` and removes `time_entry` — check devtools.
3. `‹`/`›` and the calendar change the date; the entry follows; no flash of the previous day's text.
4. Request a link; it appears in the server log. Visiting it signs you in.
5. The import banner offers the local days; importing files them correctly; it does not reappear on reload.
6. `/account` adds, renames, and removes a passkey; signing out and using "Use a passkey" signs back in.
7. `/favicon.ico` still returns the icon.

- [ ] **Step 7: Commit**

```bash
git add CLAUDE.md README.md Dockerfile .env.example .gitignore
git commit -m "docs: document accounts, dated storage, and routing traps

Corrects two now-false statements: CLAUDE.md's 'nothing is stored
server-side' and README's 'no time-tracking data is sent to the
server'. Adds the routing note about /{date} shadowing root assets.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu"
```

---

## Plan Self-Review

**Spec coverage.** Every numbered spec section maps to at least one task:
§4 → 1, 6, 7, 8; §5.1 → 4, 9; §5.2 → 7, 11, 12; §5.3 → 8, 14, 18, 21;
§5.4 → 5, 12; §6 → 9, 12, 13, 14; §7 → 15, 16, 17; §7.5 → 24;
§8 → 19, 22; §8.5 → 23; §9.2 → 2; §9.3 → 14, 18; §10 (I1–I9) → 19, 17, 16,
9, 12, 14, 6+13, 2, 24; §11 → throughout; §12 → 25; §13 → 25 step 6.

**Invariant-to-test map.** I1 → `app::tests::ssr_omits_entry_content_even_when_signed_in`;
I2 → `storage::hook::tests::a_stale_load_does_not_overwrite_a_newer_one`;
I3 → four tests in `storage::local::tests`; I4 → `tests/routes.rs`;
I5 → `request_magic_link_responds_identically_for_every_outcome`;
I6 → `login_start_cannot_distinguish_unknown_from_passkey_less`;
I7 → `entries::repo::tests` plus `tests/entry_access.rs`;
I8 → `storage::envelope::tests::wrapped_value_is_version_tagged`;
I9 → `import_banner::tests::days_already_on_the_server_are_excluded`.

**Known forward references.** Task 9 names `email::Mailer` before Task 10
creates it (stub noted in the task). Task 19 names `AppHeader`,
`ImportBanner`, `AccountPage`, and `WeekView` before Tasks 20–24 create them
(stub noted). Task 9's `account_route_beats_the_date_route` is `#[ignore]`d
until Task 21. These are the only ones; no other task references a symbol no
task defines.
