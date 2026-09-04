# Dioxus → Leptos SSR Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the client-only Dioxus wasm app with a Leptos 0.8 SSR + hydration app on Axum, preserving every user-visible behavior and all `localStorage` data.

**Architecture:** One crate, two artifacts (`ssr` server binary + `hydrate` wasm bundle), built by cargo-leptos. Persistent state is `Option<String>` — `None` until read from `localStorage` *after* hydration — so the server and the client's first render agree by construction. Storage sits behind an async seam so the future passkey/encrypted-store work is contained.

**Tech Stack:** Leptos 0.8 (nightly features), leptos_router, leptos_meta, leptos_axum, Axum 0.8, tokio, cargo-leptos 0.3.7, Tailwind v4 (CSS-first), `time-tracking-parser` (pinned git rev, unchanged).

**Spec:** `docs/superpowers/specs/2026-09-03-leptos-migration-design.md`

## Global Constraints

- Rust **edition 2024** for the crate; `rustfmt.toml` pins `edition = "2024"` to match.
- Crate name is **`time-tracking-leptos`** everywhere (package name, `default-run`, `output-name`, CI image tag).
- Toolchain is **nightly**, pinned via `rust-toolchain.toml`, with the `wasm32-unknown-unknown` target.
- Leptos crates enable the **`nightly`** feature (gives the `signal()` call shorthand).
- `#![recursion_limit = "512"]` on **both** `src/lib.rs` and `src/main.rs` — the bin is a separate crate root.
- Container listens on **port 80**; runtime image is `gcr.io/distroless/cc-debian12` (**not** `:nonroot`, which cannot bind a privileged port). `site-addr` in `Cargo.toml` stays `127.0.0.1:3000` for local `cargo leptos watch`; the Dockerfile overrides with `LEPTOS_SITE_ADDR=0.0.0.0:80`.
- **No `tailwind.config.js`.** Tailwind v4 is CSS-first; `@source` lives in `style/tailwind.css`.
- **No `<Suspense>` or `<Transition>` anywhere.** There are no Resources in this migration.
- Branch polymorphism uses `Either` / `EitherOf3`, never `.into_any()`.
- Stored values keep `gloo_storage`'s on-disk encoding (a JSON-encoded string) so existing user data survives.
- Every commit message ends with:
  `Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu`

## Divergence log

While executing, append any place this repo contradicts the `migrate-to-leptos` skill to `docs/superpowers/skill-divergences.md`. Phase 8 consumes that file. Do not skip entries because they seem small.

---

## Phase 1 — Toolchain and build scaffolding

### Task 1: Pin the toolchain and formatter

**Files:**
- Create: `rust-toolchain.toml`
- Create: `rustfmt.toml`
- Delete: `rust-analyzer.toml`
- Modify: `clippy.toml`

**Interfaces:**
- Produces: a nightly toolchain with `wasm32-unknown-unknown` available to all later tasks.

- [ ] **Step 1: Write `rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly"
targets = ["wasm32-unknown-unknown"]
components = ["rustfmt", "clippy", "rust-src"]
```

- [ ] **Step 2: Write `rustfmt.toml`**

```toml
edition = "2024"
```

- [ ] **Step 3: Delete the Dioxus rustfmt override**

`rust-analyzer.toml` currently forces `dx fmt` as the format command. `dx` will not exist after this migration.

```bash
git rm -f rust-analyzer.toml
```

- [ ] **Step 4: Rewrite `clippy.toml` for Leptos**

The `dioxus_signals::Write` entry is gone, but Leptos's reactive graph uses the same `generational_box` guards, so those entries stay and remain valuable.

```toml
await-holding-invalid-types = [
  { path = "generational_box::GenerationalRef", reason = "Reads should not be held over an await point. This will cause any writes to fail while the await is pending since the read borrow is still active." },
  { path = "generational_box::GenerationalRefMut", reason = "Writes should not be held over an await point. This will cause any reads or writes to fail while the await is pending since the write borrow is still active." },
]
```

- [ ] **Step 5: Verify the toolchain resolves**

Run: `rustup show active-toolchain && rustc --version`
Expected: a `nightly-*` toolchain, sourced from `rust-toolchain.toml`.

- [ ] **Step 6: Commit**

```bash
git add rust-toolchain.toml rustfmt.toml clippy.toml
git commit -m "$(cat <<'EOF'
build: pin nightly toolchain and edition 2024 formatting

Drops the Dioxus-specific rust-analyzer rustfmt override and the
dioxus_signals clippy entry; keeps the generational_box await guards,
which Leptos's reactive graph shares.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 2: Move the Tailwind pipeline to cargo-leptos

**Files:**
- Create: `style/tailwind.css`
- Create: `public/favicon.ico` (via `git mv`)
- Delete: `tailwind.css`, `assets/tailwind.css`, `assets/favicon.ico`, `package.json`, `package-lock.json`, `Dioxus.toml`, `nginx/default.conf`

**Interfaces:**
- Produces: `style/tailwind.css` as cargo-leptos's `tailwind-input-file`; `public/` as its `assets-dir`.

- [ ] **Step 1: Create the Tailwind v4 source**

The existing root `tailwind.css` is already v4 CSS-first. It moves to `style/` with the `@source` glob repointed relative to the new location, plus explicit page-chrome theming so the `<textarea>` does not fall back to user-agent styling.

```bash
mkdir -p style public
```

Write `style/tailwind.css`:

```css
@import "tailwindcss";

@source "../src/**/*.rs";

/* The summary panel's value slots are blank until storage is read
   (see spec §5). Reserve their height so the fill-in does not shift
   layout. */
@layer components {
    .value-slot {
        min-height: 1.75rem;
    }
}
```

- [ ] **Step 2: Move the favicon into the assets dir**

```bash
git mv assets/favicon.ico public/favicon.ico
```

- [ ] **Step 3: Delete the npm Tailwind pipeline and Dioxus/nginx config**

```bash
git rm -f tailwind.css assets/tailwind.css package.json package-lock.json Dioxus.toml
git rm -r nginx
```

- [ ] **Step 4: Update `.dockerignore`**

The npm files no longer exist; `style/` and `public/` must NOT be ignored (cargo-leptos needs them in the build context).

```
node_modules
target
.git
```

- [ ] **Step 5: Verify the tree**

Run: `git status --short && ls style public`
Expected: `style/tailwind.css` and `public/favicon.ico` present; deletions staged; no `assets/` directory remains.

- [ ] **Step 6: Commit**

```bash
git add -A style public .dockerignore
git commit -m "$(cat <<'EOF'
build: move Tailwind v4 to cargo-leptos, drop npm and nginx

Tailwind v4 is CSS-first, so @source moves into style/tailwind.css and
no tailwind.config.js is created. The static nginx runtime goes away
because the Leptos binary now serves the app directly.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

## Phase 2 — Cargo.toml and the Leptos skeleton

> The repo does **not** compile between Task 3 and Task 5. That is expected; do not attempt to fix intermediate build errors by reverting.

### Task 3: Rewrite `Cargo.toml`

**Files:**
- Modify: `Cargo.toml` (full replacement)

**Interfaces:**
- Produces: `ssr` / `hydrate` features; `[lib] crate-type`; `[package.metadata.leptos]` consumed by cargo-leptos from Task 5 onward.

- [ ] **Step 1: Replace `Cargo.toml` entirely**

```toml
[package]
name = "time-tracking-leptos"
version = "0.1.3"
authors = ["Steven Carter <steve@javapl.us>"]
edition = "2024"
publish = false
default-run = "time-tracking-leptos"

[lib]
crate-type = ["cdylib", "rlib"]

[[bin]]
name = "time-tracking-leptos"
path = "src/main.rs"

[dependencies]
# Always-on — compiled into both the server binary and the wasm bundle.
leptos = { version = "0.8", features = ["nightly"] }
leptos_router = { version = "0.8", features = ["nightly"] }
leptos_meta = "0.8"
serde = { version = "1.0.219", features = ["derive"] }
serde_json = "1.0"
thiserror = "2.0"
time-tracking-parser = { git = "https://github.com/stevenwcarter/time-tracking-parser" }

# Hydrate-only (wasm).
console_error_panic_hook = { version = "0.1", optional = true }
wasm-bindgen = { version = "0.2.100", optional = true }
wasm-bindgen-futures = { version = "0.4.50", optional = true }
web-sys = { version = "0.3.77", optional = true, features = [
  "Clipboard",
  "Navigator",
  "Storage",
  "Window",
] }

# SSR-only (server binary).
axum = { version = "0.8", optional = true }
leptos_axum = { version = "0.8", optional = true }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net"], optional = true }
tower = { version = "0.5", features = ["util"], optional = true }
tower-http = { version = "0.6", features = ["fs", "compression-gzip"], optional = true }

[features]
default = []
hydrate = [
  "leptos/hydrate",
  "dep:console_error_panic_hook",
  "dep:wasm-bindgen",
  "dep:wasm-bindgen-futures",
  "dep:web-sys",
]
ssr = [
  "leptos/ssr",
  "leptos_meta/ssr",
  "leptos_router/ssr",
  "dep:leptos_axum",
  "dep:axum",
  "dep:tokio",
  "dep:tower",
  "dep:tower-http",
]

[profile.release]
codegen-units = 1
opt-level = 'z'
lto = true

[profile.wasm-release]
inherits = "release"
opt-level = 'z'
lto = true
codegen-units = 1
panic = "abort"

[package.metadata.leptos]
output-name          = "time-tracking-leptos"
site-root            = "target/site"
site-pkg-dir         = "pkg"
# Local dev only. The Docker image overrides this with LEPTOS_SITE_ADDR=0.0.0.0:80,
# because binding port 80 locally would need privileges.
site-addr            = "127.0.0.1:3000"
reload-port          = 3001
assets-dir           = "public"
tailwind-input-file  = "style/tailwind.css"
browserquery         = "defaults"
env                  = "DEV"
bin-features         = ["ssr"]
bin-default-features = false
lib-features         = ["hydrate"]
lib-default-features = false
lib-profile-release  = "wasm-release"
```

- [ ] **Step 2: Verify the manifest parses**

Run: `cargo metadata --no-deps --format-version 1 > /dev/null && echo OK`
Expected: `OK`. (A full build will still fail — `src/` has not been rewritten yet.)

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "$(cat <<'EOF'
build: restructure Cargo.toml for Leptos ssr/hydrate split

Renames the crate to time-tracking-leptos, moves to edition 2024, and
partitions dependencies across the ssr and hydrate features. Drops
dioxus, dioxus-clipboard and gloo-storage.

The crate does not compile until the src/ rewrite lands.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 4: Crate roots and the app shell

**Files:**
- Modify: `src/lib.rs` (full replacement)
- Modify: `src/main.rs` (full replacement)
- Create: `src/app.rs`
- Delete: `src/hooks_composed.rs`

**Interfaces:**
- Consumes: the `ssr`/`hydrate` features from Task 3.
- Produces:
  - `time_tracking_leptos::app::App` — the root `#[component]`.
  - `time_tracking_leptos::app::shell(LeptosOptions) -> impl IntoView`.
  - `time_tracking_leptos::hydrate()` — the `#[wasm_bindgen]` wasm entrypoint.

- [ ] **Step 1: Write `src/lib.rs`**

```rust
#![recursion_limit = "512"]

pub mod app;
pub mod clipboard;
pub mod components;
pub mod storage;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::app::App);
}
```

- [ ] **Step 2: Write `src/app.rs` with a placeholder home page**

The real page arrives in Task 11; this establishes the shell and route so the server can be smoke-tested first.

```rust
use leptos::prelude::*;
use leptos_meta::{provide_meta_context, MetaTags, Stylesheet, Title};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

/// The SSR document shell. `HydrationScripts` injects the wasm loader.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
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

    view! {
        <Stylesheet id="leptos" href="/pkg/time-tracking-leptos.css"/>
        <Title text="Time Tracker"/>
        <Router>
            <Routes fallback=NotFound>
                <Route path=path!("/") view=HomePage/>
            </Routes>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    view! { <p>"Leptos is running."</p> }
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

- [ ] **Step 3: Write `src/main.rs`**

`get_configuration(None)` reads `LEPTOS_*` env vars, which is how the Docker image overrides `site-addr` to `0.0.0.0:80`.

```rust
#![recursion_limit = "512"]

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use leptos::logging::log;
    use leptos::prelude::*;
    use leptos_axum::{generate_route_list, LeptosRoutes};
    use time_tracking_leptos::app::{shell, App};

    let conf = get_configuration(None).expect("failed to read Leptos configuration");
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        // Serves everything under `site-root`, including /pkg/*.css and the
        // wasm bundle. Safe as a fallback because the app mounts no wildcard
        // route that could shadow it.
        .fallback(leptos_axum::file_and_error_handler(shell))
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind listen address");
    log!("listening on http://{addr}");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("server error");
}

#[cfg(not(feature = "ssr"))]
fn main() {
    // The wasm bundle's entrypoint is `lib::hydrate`, not this.
}
```

- [ ] **Step 4: Delete the Dioxus persistence hook**

Its replacement is the `storage` module built in Phase 3.

```bash
git rm -f src/hooks_composed.rs
```

- [ ] **Step 5: Stub the modules `lib.rs` declares**

Tasks 5–10 fill these in; they must exist for the crate root to resolve.

```bash
mkdir -p src/storage src/components
printf '//! Clipboard access. Real implementation lands in Task 9.\n' > src/clipboard.rs
printf '//! Persistent storage seam. Real implementation lands in Tasks 5-8.\n' > src/storage/mod.rs
printf '//! View components. Real implementations land in Tasks 10-13.\n' > src/components/mod.rs
```

- [ ] **Step 6: Verify both targets build**

Run: `cargo build --bin time-tracking-leptos --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished` — no errors.

Run: `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate 2>&1 | tail -5`
Expected: `Finished` — no errors.

- [ ] **Step 7: Commit**

```bash
git add -A src
git commit -m "$(cat <<'EOF'
feat: add Leptos crate roots, document shell and Axum server

Replaces the Dioxus entrypoint with the standard Leptos SSR shape: a
lib root exposing the wasm hydrate() entrypoint, an Axum binary serving
generated routes, and a document shell wiring HydrationScripts.

HomePage is a placeholder; the ported UI lands in Task 11.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 5: Smoke-test the skeleton

**Files:** none (verification only)

- [ ] **Step 1: Build with cargo-leptos**

Run: `cargo leptos build 2>&1 | tail -20`
Expected: builds the binary, the wasm bundle, and the Tailwind CSS; no errors.

- [ ] **Step 2: Start the server and curl it**

```bash
./target/debug/time-tracking-leptos &
sleep 3
curl -s -o /dev/null -w "root:%{http_code}\n" http://127.0.0.1:3000/
curl -s -o /dev/null -w "css:%{http_code}\n" http://127.0.0.1:3000/pkg/time-tracking-leptos.css
curl -s -I http://127.0.0.1:3000/pkg/time-tracking-leptos.css | grep -i content-type
curl -s -o /dev/null -w "favicon:%{http_code}\n" http://127.0.0.1:3000/favicon.ico
curl -s http://127.0.0.1:3000/ | grep -o "Leptos is running"
kill %1
```

Expected: `root:200`, `css:200`, `Content-Type: text/css`, `favicon:200`, and `Leptos is running`.

**If `css` is not 200 or the content type is `text/html`:** the fallback is not reaching `site-root`. Confirm `assets-dir = "public"` and `site-root = "target/site"` in `Cargo.toml`, and that `target/site/pkg/time-tracking-leptos.css` exists on disk. Record the resolution in the divergence log.

- [ ] **Step 3: No commit** — verification only.

---

## Phase 3 — The storage seam (TDD)

### Task 6: Storage codec

**Files:**
- Create: `src/storage/codec.rs`
- Modify: `src/storage/mod.rs`

**Interfaces:**
- Produces:
  - `codec::encode<T: Serialize>(&T) -> String`
  - `codec::decode<T: DeserializeOwned>(&str) -> Result<T, DecodeError>`
  - `codec::DecodeError` (Clone + PartialEq + Eq + Error)

This is the only host-testable part of storage: the `localStorage` calls themselves are `hydrate`-only and cannot run under `cargo test`. Isolating the wire format here is what makes the gloo-compatibility guarantee testable.

- [ ] **Step 1: Write the failing tests**

Create `src/storage/codec.rs` containing only the tests:

```rust
//! The on-disk representation of stored values.
//!
//! `gloo_storage` — used by the previous Dioxus build — wrote every value as
//! `serde_json::to_string(&value)`, so a stored `String` is a *JSON-encoded*
//! string (`"\"hello\""`, not `hello`). This module preserves that encoding so
//! data written by the old build still loads.

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
```

- [ ] **Step 2: Run the tests to verify they fail**

First declare the module. In `src/storage/mod.rs`:

```rust
//! Persistent storage seam.

pub mod codec;
```

Run: `cargo test --features ssr --no-default-features codec 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'encode' in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `src/storage/codec.rs`, above the `mod tests` block:

```rust
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --features ssr --no-default-features codec 2>&1 | tail -20`
Expected: `test result: ok. 3 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/storage
git commit -m "$(cat <<'EOF'
feat: add storage codec preserving gloo_storage's wire format

gloo_storage wrote values as JSON-encoded strings. Keeping that encoding
means time entries saved by the Dioxus build still load after the
migration, which the gloo_format_compat test pins.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 7: Storage keys, errors, and the async API

**Files:**
- Modify: `src/storage/mod.rs`

**Interfaces:**
- Consumes: `codec::{encode, decode, DecodeError}` from Task 6.
- Produces:
  - `StorageKey` (Copy enum, `as_str() -> &'static str`)
  - `StorageError` (Clone + PartialEq + Eq + Error)
  - `async load(StorageKey) -> Result<Option<String>, StorageError>`
  - `async store(StorageKey, &str) -> Result<(), StorageError>`
  - `async clear(StorageKey) -> Result<(), StorageError>`

- [ ] **Step 1: Write the failing test**

Append to `src/storage/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_matches_dioxus_key() {
        // The Dioxus build called use_persistent("time_entry", ...). Changing
        // this string orphans every existing user's saved data.
        assert_eq!(StorageKey::TimeEntry.as_str(), "time_entry");
    }

    /// Pins invariant I1 from the spec: under `ssr` there is no browser
    /// storage, so `load` yields `None` and the server render starts unloaded.
    /// If this ever returns `Some`, the server would render content the
    /// client's first (hydrating) render cannot reproduce.
    #[test]
    fn ssr_backend_returns_none() {
        let loaded = futures_lite_block_on(load(StorageKey::TimeEntry));
        assert_eq!(loaded, Ok(None));
    }

    #[test]
    fn ssr_writes_are_noops() {
        assert_eq!(futures_lite_block_on(store(StorageKey::TimeEntry, "x")), Ok(()));
        assert_eq!(futures_lite_block_on(clear(StorageKey::TimeEntry)), Ok(()));
    }

    /// Minimal executor — these futures never yield under `ssr`, so polling
    /// once is sufficient and avoids pulling in a runtime just for tests.
    fn futures_lite_block_on<T>(fut: impl Future<Output = T>) -> T {
        use std::pin::pin;
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        match pin!(fut).poll(&mut Context::from_waker(&waker)) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("ssr storage futures must complete immediately"),
        }
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --features ssr --no-default-features storage 2>&1 | tail -20`
Expected: FAIL — `cannot find type 'StorageKey' in this scope`.

- [ ] **Step 3: Write the implementation**

Replace the head of `src/storage/mod.rs` (keeping the `mod tests` block at the bottom):

```rust
//! Persistent storage seam.
//!
//! Components never touch this module directly — they use [`hook::use_persistent`].
//! The API is async even though today's only backend (`localStorage`) is
//! synchronous, so that swapping in server-backed encrypted storage later
//! changes nothing outside this directory. See spec §6.

pub mod codec;
pub mod hook;
#[cfg(feature = "hydrate")]
pub mod local;

use std::future::Future;

/// Identifies one stored document.
///
/// An enum rather than a free string so the planned multi-day-store work
/// extends this type instead of leaking stringly-typed keys through the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKey {
    TimeEntry,
}

impl StorageKey {
    /// The key as written to the underlying store. These strings are a
    /// compatibility surface: changing one orphans existing user data.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageKey::TimeEntry => "time_entry",
        }
    }
}

/// Something went wrong reaching or interpreting the backing store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("browser storage is unavailable")]
    Unavailable,
    #[error("stored value for `{key}` could not be read: {source}")]
    Decode {
        key: &'static str,
        source: codec::DecodeError,
    },
    #[error("failed to write `{key}` to storage")]
    Write { key: &'static str },
}

/// Reads a stored value. `Ok(None)` means "nothing stored under this key".
///
/// Under `ssr` there is no browser storage, so this is always `Ok(None)`.
pub fn load(key: StorageKey) -> impl Future<Output = Result<Option<String>, StorageError>> {
    async move {
        #[cfg(feature = "hydrate")]
        {
            local::load(key).await
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = key;
            Ok(None)
        }
    }
}

/// Writes a value, replacing any previous one. A no-op under `ssr`.
pub fn store(key: StorageKey, value: &str) -> impl Future<Output = Result<(), StorageError>> {
    let value = value.to_owned();
    async move {
        #[cfg(feature = "hydrate")]
        {
            local::store(key, &value).await
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (key, value);
            Ok(())
        }
    }
}

/// Removes a stored value. A no-op under `ssr`.
pub fn clear(key: StorageKey) -> impl Future<Output = Result<(), StorageError>> {
    async move {
        #[cfg(feature = "hydrate")]
        {
            local::clear(key).await
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = key;
            Ok(())
        }
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --features ssr --no-default-features storage 2>&1 | tail -20`
Expected: `test result: ok. 3 passed`.

The `hook` and `local` modules do not exist yet, so this will first fail with `file not found for module`. Create empty placeholders to get the test green:

```bash
printf '//! Leptos hook. Real implementation lands in Task 9.\n' > src/storage/hook.rs
printf '//! localStorage backend. Real implementation lands in Task 8.\n' > src/storage/local.rs
```

Then re-run and confirm `ok. 3 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/storage
git commit -m "$(cat <<'EOF'
feat: add storage keys, errors and the async load/store API

The API is async ahead of need so that server-backed encrypted storage
later changes nothing outside src/storage. Under ssr every operation is
a no-op, which pins spec invariant I1: the server render always starts
in the unloaded state.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 8: The `localStorage` backend

**Files:**
- Modify: `src/storage/local.rs`

**Interfaces:**
- Consumes: `codec`, `StorageKey`, `StorageError` from Tasks 6–7.
- Produces: `local::{load, store, clear}`, mirroring the `mod.rs` signatures.

This module is `hydrate`-only, so it is verified by the wasm build compiling, not by a host test. Its logic is deliberately thin — all the testable behavior lives in `codec` (Task 6).

- [ ] **Step 1: Write the implementation**

```rust
//! `localStorage` backend, compiled only into the wasm bundle.
//!
//! Deliberately thin: the wire format lives in [`super::codec`], which is
//! host-testable, while this file is only the `web_sys` plumbing.

use super::{StorageError, StorageKey, codec};

fn storage() -> Result<web_sys::Storage, StorageError> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or(StorageError::Unavailable)
}

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    let raw = storage()?
        .get_item(key.as_str())
        .map_err(|_| StorageError::Unavailable)?;

    match raw {
        None => Ok(None),
        Some(raw) => codec::decode(&raw)
            .map(Some)
            .map_err(|source| StorageError::Decode {
                key: key.as_str(),
                source,
            }),
    }
}

pub async fn store(key: StorageKey, value: &str) -> Result<(), StorageError> {
    storage()?
        .set_item(key.as_str(), &codec::encode(&value))
        .map_err(|_| StorageError::Write { key: key.as_str() })
}

pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    storage()?
        .remove_item(key.as_str())
        .map_err(|_| StorageError::Write { key: key.as_str() })
}
```

- [ ] **Step 2: Verify the wasm target compiles**

Run: `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate 2>&1 | tail -5`
Expected: `Finished`.

- [ ] **Step 3: Verify the server target still compiles (the module must be excluded)**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished` — `web_sys` must not appear in the server build.

- [ ] **Step 4: Commit**

```bash
git add src/storage/local.rs
git commit -m "$(cat <<'EOF'
feat: add the localStorage backend for the hydrate target

Replaces gloo-storage with a direct web_sys call. Kept thin on purpose:
the testable wire format lives in storage::codec, this is only plumbing.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 9: The `use_persistent` hook

**Files:**
- Modify: `src/storage/hook.rs`

**Interfaces:**
- Consumes: `storage::{load, store, StorageKey}`.
- Produces:
  - `Persistent` (Copy): `get(self) -> Option<String>`, `set(self, String)`, `clear(self)`
  - `use_persistent(StorageKey) -> Persistent`

This is where the spec's hydration contract (§5) is implemented. The `Option` is load-bearing — read the doc comments before changing anything here.

- [ ] **Step 1: Write the implementation**

```rust
//! The Leptos-facing half of the storage seam.
//!
//! # The hydration contract (spec §5)
//!
//! The server and the client's *first* render must produce identical DOM.
//! `localStorage` does not exist on the server, so the value starts as `None`
//! on **both** targets and is only filled in by an `Effect`, which runs after
//! hydration has already matched the server's output.
//!
//! `None` and `Some(String::new())` are meaningfully different:
//!
//! | Value          | Meaning                     | Renders as            |
//! |----------------|-----------------------------|-----------------------|
//! | `None`         | Not yet read from storage   | Blank                 |
//! | `Some("")`     | Loaded; nothing saved       | The empty-state text  |
//! | `Some(text)`   | Loaded with data            | The parsed summary    |
//!
//! Collapsing those two cases makes the server assert an empty state it cannot
//! know, and returning users see a flash of "No projects found" before their
//! data appears.

use leptos::prelude::*;
use leptos::task::spawn_local;

use super::{StorageKey, load, store};

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: StorageKey,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
    }

    /// Updates the value and writes it through to storage.
    pub fn set(self, value: String) {
        self.set_value.set(Some(value.clone()));
        let key = self.key;
        spawn_local(async move {
            // A failed write must not break the UI; the in-memory value stands.
            let _ = store(key, &value).await;
        });
    }

    /// Resets to the empty (but loaded) state.
    pub fn clear(self) {
        self.set(String::new());
    }
}

/// Reads `key` from storage after hydration, exposing the tri-state above.
pub fn use_persistent(key: StorageKey) -> Persistent {
    // Identical on server and client, which is what makes hydration match.
    let (value, set_value) = signal::<Option<String>>(None);

    // `Effect::new` never runs during SSR, and on the client it runs *after*
    // the first render — so the DOM has already been matched by the time this
    // can change anything.
    Effect::new(move |_| {
        spawn_local(async move {
            // A read failure is indistinguishable from "nothing stored" as far
            // as the UI is concerned: either way we are now loaded and empty.
            let stored = load(key).await.ok().flatten().unwrap_or_default();
            set_value.set(Some(stored));
        });
    });

    Persistent {
        value,
        set_value,
        key,
    }
}
```

- [ ] **Step 2: Verify both targets compile**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished`.

Run: `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate 2>&1 | tail -5`
Expected: `Finished`.

- [ ] **Step 3: Commit**

```bash
git add src/storage/hook.rs
git commit -m "$(cat <<'EOF'
feat: add use_persistent implementing the hydration contract

Value is Option<String>: None until localStorage is read after
hydration, so server and first client render agree by construction and
the server never asserts an empty state it cannot know.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

## Phase 4 — Components

All ported views must reproduce the Dioxus DOM and Tailwind classes exactly. The original markup is at `src/main.rs` in commit `6d02ba8` — read it with `git show 6d02ba8:src/main.rs` when in doubt.

### Task 10: Clipboard

**Files:**
- Modify: `src/clipboard.rs`

**Interfaces:**
- Produces: `clipboard::copy_to_clipboard(String)` — same signature on both targets, so call sites need no `cfg`.

- [ ] **Step 1: Write the implementation**

```rust
//! Clipboard access.
//!
//! Both targets expose the same signature so call sites stay `cfg`-free —
//! only the side effect differs, never the rendered output (spec invariant I4).

/// Copies `text` to the system clipboard. Fire-and-forget.
#[cfg(feature = "hydrate")]
pub fn copy_to_clipboard(text: String) {
    use wasm_bindgen_futures::JsFuture;

    leptos::task::spawn_local(async move {
        let Some(window) = web_sys::window() else {
            return;
        };
        // Rejects when the document lacks focus or permission is denied;
        // there is no useful recovery, so the copy is simply dropped.
        let _ = JsFuture::from(window.navigator().clipboard().write_text(&text)).await;
    });
}

/// No-op on the server: there is no clipboard to write to.
#[cfg(not(feature = "hydrate"))]
pub fn copy_to_clipboard(_text: String) {}
```

- [ ] **Step 2: Verify both targets compile**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -3 && cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate 2>&1 | tail -3`
Expected: two `Finished` lines.

- [ ] **Step 3: Commit**

```bash
git add src/clipboard.rs
git commit -m "$(cat <<'EOF'
feat: port clipboard access off dioxus-clipboard

Same signature on both targets so call sites need no cfg; only the side
effect is gated, never the rendered output.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 11: Summary components

**Files:**
- Create: `src/components/summary.rs`
- Modify: `src/components/mod.rs`

**Interfaces:**
- Produces: `TimeOverview`, `WorkingTimeDisplay`, `DeadTimeDisplay`, `WarningsDisplay`, `SummarySkeleton`.

- [ ] **Step 1: Write `src/components/summary.rs`**

```rust
//! The right-hand summary panel's pieces.

use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;

#[component]
pub fn TimeOverview(start_time: String, end_time: String) -> impl IntoView {
    view! {
        <div class="bg-blue-50 rounded-lg p-4 mb-6">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"Start Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot">{start_time}</p>
                </div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"End Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot">{end_time}</p>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn WorkingTimeDisplay(total: String, total_decimal: String) -> impl IntoView {
    view! {
        <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-4">
            <h3 class="text-sm font-medium text-green-800 mb-1">"Total Working Time"</h3>
            <p class="text-lg font-semibold text-green-700 value-slot">
                {format!("{total} ({total_decimal} hours)")}
            </p>
        </div>
    }
}

#[component]
pub fn DeadTimeDisplay(dead_minutes: u32, dead: String, dead_decimal: String) -> impl IntoView {
    // Thresholds match the Dioxus original: none / under 90 min / 90+ min.
    if dead_minutes == 0 {
        EitherOf3::A(view! {
            <div class="border-l-4 border-green-400 bg-green-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-green-800 mb-1">"Dead Time"</h3>
                <p class="text-lg font-semibold text-green-700 value-slot">
                    "No dead time (gaps) found"
                </p>
            </div>
        })
    } else if dead_minutes < 90 {
        EitherOf3::B(view! {
            <div class="border-l-4 border-yellow-400 bg-yellow-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-yellow-800 mb-1">"Total Dead Time"</h3>
                <p class="text-lg font-semibold text-yellow-700 value-slot">
                    {format!("{dead} ({dead_decimal} hours)")}
                </p>
            </div>
        })
    } else {
        EitherOf3::C(view! {
            <div class="border-l-4 border-red-400 bg-red-50 p-4 mb-6">
                <h3 class="text-sm font-medium text-red-800 mb-1">"Total Dead Time"</h3>
                <p class="text-lg font-semibold text-red-700 value-slot">
                    {format!("{dead} ({dead_decimal} hours)")}
                </p>
            </div>
        })
    }
}

#[component]
pub fn WarningsDisplay(warnings: Vec<String>) -> impl IntoView {
    if warnings.is_empty() {
        return Either::Left(view! { <div></div> });
    }

    let rows = warnings
        .into_iter()
        .map(|warning| {
            view! {
                <p class="text-sm text-yellow-700 flex items-start">
                    <span class="text-yellow-500 mr-2 mt-0.5 text-xs">"⚠"</span>
                    <span>{warning}</span>
                </p>
            }
        })
        .collect_view();

    Either::Right(view! {
        <div class="border-l-4 border-yellow-400 bg-yellow-50 p-4 mb-6">
            <h3 class="text-sm font-medium text-yellow-800 mb-2">"Warnings"</h3>
            <div class="space-y-1">{rows}</div>
        </div>
    })
}

/// Rendered while the stored value is still `None` (spec §5).
///
/// Shows the panel's chrome with empty value slots and, critically, **no**
/// empty-state message — the server does not yet know whether the user has
/// data, and claiming otherwise causes a flash of wrong content on reload.
#[component]
pub fn SummarySkeleton() -> impl IntoView {
    view! {
        <div class="bg-blue-50 rounded-lg p-4 mb-6">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"Start Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot"></p>
                </div>
                <div class="text-center">
                    <p class="text-sm text-gray-600 font-medium">"End Time"</p>
                    <p class="text-lg font-semibold text-blue-700 value-slot"></p>
                </div>
            </div>
        </div>
        <div class="border-l-4 border-gray-200 bg-gray-50 p-4 mb-4">
            <h3 class="text-sm font-medium text-gray-500 mb-1">"Total Working Time"</h3>
            <p class="value-slot"></p>
        </div>
        <div class="border-l-4 border-gray-200 bg-gray-50 p-4 mb-6">
            <h3 class="text-sm font-medium text-gray-500 mb-1">"Dead Time"</h3>
            <p class="value-slot"></p>
        </div>
    }
}
```

- [ ] **Step 2: Declare the module**

`src/components/mod.rs`:

```rust
//! View components.

pub mod summary;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished`.

- [ ] **Step 4: Commit**

```bash
git add src/components
git commit -m "$(cat <<'EOF'
feat: port the summary panel components to Leptos

Adds SummarySkeleton for the pre-load branch: panel chrome with empty
value slots and deliberately no empty-state message, so reloads never
flash "No projects found" before the user's data arrives.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 12: Project list components

**Files:**
- Create: `src/components/projects.rs`
- Modify: `src/components/mod.rs`

**Interfaces:**
- Consumes: `clipboard::copy_to_clipboard`.
- Produces: `ProjectItem`, `ProjectsDisplay`.

- [ ] **Step 1: Write `src/components/projects.rs`**

```rust
//! The per-project breakdown, including click-to-copy notes.

use leptos::either::Either;
use leptos::prelude::*;
use time_tracking_parser::{ProjectSummary, Time};

use crate::clipboard::copy_to_clipboard;

#[component]
pub fn ProjectItem(project: ProjectSummary) -> impl IntoView {
    let duration = format!(
        "{} ({} hrs)",
        Time::format_duration_minutes(project.total_minutes),
        Time::format_duration_decimal(project.total_minutes),
    );

    // Pre-rendered here rather than in the handler so the click path stays
    // allocation-free and the closure only needs to clone a finished string.
    let notes_for_clipboard = project
        .notes
        .iter()
        .map(|note| format!("- {note}"))
        .collect::<Vec<_>>()
        .join("\n");

    let name = project.name;
    let notes = project.notes;

    let note_rows = notes
        .iter()
        .map(|note| {
            view! {
                <p class="text-sm text-gray-600 flex items-start">
                    <span class="text-gray-400 mr-2 mt-0.5 text-xs">"-"</span>
                    <span>{note.clone()}</span>
                </p>
            }
        })
        .collect_view();

    let has_notes = !notes.is_empty();

    view! {
        <div
            class="bg-gray-50 rounded-lg p-4 border border-gray-200 cursor-pointer hover:bg-gray-100 transition-colors"
            on:click=move |_| copy_to_clipboard(notes_for_clipboard.clone())
        >
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-3">
                <h4 class="text-base font-semibold text-gray-800">{name}</h4>
                <span class="text-sm font-medium text-blue-600 bg-blue-100 px-2 py-1 rounded-full mt-1 sm:mt-0">
                    {duration}
                </span>
            </div>
            <div class="space-y-1" class:hidden=move || !has_notes>
                {note_rows}
            </div>
        </div>
    }
}

#[component]
pub fn ProjectsDisplay(projects: Vec<ProjectSummary>) -> impl IntoView {
    if projects.is_empty() {
        return Either::Left(view! {
            <div class="text-center py-8 text-gray-500">
                <p class="text-sm">
                    "No projects found. Enter your time tracking data to see the breakdown."
                </p>
            </div>
        });
    }

    let items = projects
        .into_iter()
        .map(|project| view! { <ProjectItem project=project/> })
        .collect_view();

    Either::Right(view! {
        <div>
            <h3 class="text-lg font-semibold text-gray-800 mb-4 border-b border-gray-200 pb-2">
                "Projects"
            </h3>
            <div class="space-y-4">{items}</div>
        </div>
    })
}
```

- [ ] **Step 2: Declare the module**

Append to `src/components/mod.rs`:

```rust
pub mod projects;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished`.

- [ ] **Step 4: Commit**

```bash
git add src/components
git commit -m "$(cat <<'EOF'
feat: port the project breakdown components to Leptos

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 13: Time display and entry area

**Files:**
- Create: `src/components/time_display.rs`
- Create: `src/components/time_entry_area.rs`
- Modify: `src/components/mod.rs`

**Interfaces:**
- Consumes: `Persistent`, the summary components, `ProjectsDisplay`.
- Produces: `TimeDisplay`, `TimeEntryArea`.

- [ ] **Step 1: Write the failing test for the parser's empty-input behavior**

Create `src/components/time_display.rs` with only the test:

```rust
#[cfg(test)]
mod tests {
    use time_tracking_parser::parse_time_tracking_data;

    /// Pins spec invariant I3. The `Some("")` branch renders the output of
    /// this call, so the parser must be total over empty input and must report
    /// genuinely-empty results rather than, say, a spurious warning.
    #[test]
    fn empty_parse_is_total() {
        let data = parse_time_tracking_data("");
        assert_eq!(data.total_minutes, 0);
        assert_eq!(data.dead_time_minutes, 0);
        assert!(data.projects.is_empty(), "empty input yields no projects");
        assert!(data.warnings.is_empty(), "empty input yields no warnings");
    }
}
```

- [ ] **Step 2: Run the test to verify it compiles and passes**

Run: `cargo test --features ssr --no-default-features empty_parse 2>&1 | tail -20`
Expected: `ok. 1 passed`. (This test characterizes existing parser behavior. If it fails, the parser's empty-input contract differs from the spec's assumption — stop and report rather than editing the assertion to match.)

- [ ] **Step 3: Write `TimeDisplay` above the test module**

```rust
//! The right-hand summary panel.

use leptos::either::Either;
use leptos::prelude::*;
use time_tracking_parser::parse_time_tracking_data;

use crate::components::projects::ProjectsDisplay;
use crate::components::summary::{
    DeadTimeDisplay, SummarySkeleton, TimeOverview, WarningsDisplay, WorkingTimeDisplay,
};
use crate::storage::hook::Persistent;

#[component]
pub fn TimeDisplay(entry: Persistent) -> impl IntoView {
    view! {
        <div class="w-full md:w-1/2 bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="p-6">
                <h2 class="text-xl font-semibold text-gray-800 mb-6">"Time Summary"</h2>
                {move || match entry.get() {
                    // Storage not read yet — blank slots, no claims. See spec §5.
                    None => Either::Left(view! { <SummarySkeleton/> }),
                    Some(text) => Either::Right(view! { <SummaryBody text=text/> }),
                }}
            </div>
        </div>
    }
}

/// Parses `text` and renders the full breakdown.
///
/// Reparsing on every keystroke replaces the Dioxus build's per-field memos.
/// The input is a single textarea's worth of text and the parser is pure, so
/// the simpler shape costs nothing measurable.
#[component]
fn SummaryBody(text: String) -> impl IntoView {
    let data = parse_time_tracking_data(&text);

    // Formatting borrows `data`, so all of it happens before the field moves.
    let start_time = data.formatted_start_time();
    let end_time = data.formatted_end_time();
    let total = data.formatted_total_minutes();
    let total_decimal = data.formatted_total_decimal();
    let dead = data.formatted_dead_time_minutes();
    let dead_decimal = data.formatted_dead_decimal();
    let dead_minutes = data.dead_time_minutes;
    let warnings = data.warnings;
    let projects = data.projects;

    view! {
        <TimeOverview start_time=start_time end_time=end_time/>
        <WorkingTimeDisplay total=total total_decimal=total_decimal/>
        <DeadTimeDisplay dead_minutes=dead_minutes dead=dead dead_decimal=dead_decimal/>
        <WarningsDisplay warnings=warnings/>
        <ProjectsDisplay projects=projects/>
    }
}
```

- [ ] **Step 4: Write `src/components/time_entry_area.rs`**

```rust
//! The left-hand entry pane: the textarea and the collapsible help.

use leptos::prelude::*;

use crate::storage::hook::Persistent;

const PLACEHOLDER: &str = "Enter your time tracking data here...\n\nExample:\n11:45-12:15 code1\n- Comment explaining what you did\n12:15-1:30 code2\n- Comment about what you were doing\n1:30-2 code1\n2-4 code3";

const SAMPLE: &str = "11:45-12:15 code1\n- Comment explaining what you did\n12:15-1:30 code2\n- Comment about what you were doing\n1:30-2 code1\n2-4 code3";

#[component]
pub fn TimeEntryArea(entry: Persistent) -> impl IntoView {
    view! {
        <div class="w-full md:w-1/2 bg-white rounded-lg shadow-sm border border-gray-200">
            <div class="p-6">
                <div class="flex justify-between items-center mb-4">
                    <h2 class="text-xl font-semibold text-gray-800">"Time Entry"</h2>
                    <button
                        class="px-3 py-1 text-sm bg-red-500 text-white rounded hover:bg-red-600 transition-colors"
                        on:click=move |_| entry.clear()
                    >
                        "Clear"
                    </button>
                </div>
                <textarea
                    id="time-entry-input"
                    class="w-full h-64 p-3 border border-gray-300 rounded-md resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors placeholder-gray-500 text-sm font-mono"
                    placeholder=PLACEHOLDER
                    // `prop:` rather than an attribute: a textarea's value is
                    // not reflected as an attribute after first render. Leptos
                    // does not serialize props into SSR output, so the server
                    // emits an empty textarea and hydration matches it.
                    prop:value=move || entry.get().unwrap_or_default()
                    on:input=move |ev| entry.set(event_target_value(&ev))
                ></textarea>
                <HelpSection/>
            </div>
        </div>
    }
}

#[component]
fn HelpSection() -> impl IntoView {
    let (show_help, set_show_help) = signal(false);

    view! {
        <div class="mt-4">
            <button
                class="flex items-center text-sm text-blue-600 hover:text-blue-800 transition-colors"
                on:click=move |_| set_show_help.update(|shown| *shown = !*shown)
            >
                <span class="mr-1">{move || if show_help.get() { "▼" } else { "▶" }}</span>
                "How to use this tool"
            </button>
            // Toggled by class rather than <Show> so the node count stays
            // constant and the help text is present in the SSR'd HTML.
            <div
                class="mt-3 p-4 bg-blue-50 rounded-lg border border-blue-200"
                class:hidden=move || !show_help.get()
            >
                <p class="text-sm text-gray-700 mb-3">
                    "You should enter your time in the format shown below. \"code1\" and \"code2\" can be anything you'd like, and the time will be aggregated together, even if you work on other time codes in the interim. You can try copying the data below into the text area to see a sample report. From the report, you can then note the time and copy the comments into the notes field in your time tracker."
                </p>
                <pre class="text-sm font-mono bg-gray-100 p-3 rounded border text-gray-800 whitespace-pre-wrap">
                    {SAMPLE}
                </pre>
            </div>
        </div>
    }
}
```

- [ ] **Step 5: Declare the modules**

Append to `src/components/mod.rs`:

```rust
pub mod time_display;
pub mod time_entry_area;
```

- [ ] **Step 6: Verify compilation and tests**

Run: `cargo build --lib --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished`.

Run: `cargo test --features ssr --no-default-features 2>&1 | tail -10`
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add src/components
git commit -m "$(cat <<'EOF'
feat: port the entry area and summary display to Leptos

TimeDisplay branches on the storage tri-state via Either, rendering the
skeleton until localStorage has been read. The textarea binds prop:value
rather than an attribute, which also keeps the SSR'd element empty and
hydration consistent.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

## Phase 5 — Wire up the app and pin the SSR output

### Task 14: Replace the placeholder home page

**Files:**
- Modify: `src/app.rs`

**Interfaces:**
- Consumes: `TimeEntryArea`, `TimeDisplay`, `use_persistent`, `StorageKey`.

- [ ] **Step 1: Replace `HomePage` in `src/app.rs`**

Replace the placeholder `HomePage` with the real layout, and add the imports:

```rust
use crate::components::time_display::TimeDisplay;
use crate::components::time_entry_area::TimeEntryArea;
use crate::storage::StorageKey;
use crate::storage::hook::use_persistent;

#[component]
fn HomePage() -> impl IntoView {
    let entry = use_persistent(StorageKey::TimeEntry);

    view! {
        <div class="min-h-screen bg-gray-50">
            <div class="w-full max-w-7xl mx-auto px-4 py-8">
                <div class="flex flex-col md:flex-row gap-6 w-full">
                    <TimeEntryArea entry=entry/>
                    <TimeDisplay entry=entry/>
                </div>
            </div>
        </div>
    }
}
```

- [ ] **Step 2: Verify both targets build**

Run: `cargo build --bin time-tracking-leptos --features ssr --no-default-features 2>&1 | tail -5`
Expected: `Finished`.

Run: `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate 2>&1 | tail -5`
Expected: `Finished`.

- [ ] **Step 3: Commit**

```bash
git add src/app.rs
git commit -m "$(cat <<'EOF'
feat: wire the ported components into the home page

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 15: Pin the SSR output

**Files:**
- Modify: `src/app.rs` (append a test module)

These tests are the migration's regression guard. `ssr_omits_loaded_state` is deliberately a *negative* assertion: it fails both if the server starts rendering user data and if someone collapses the `None`/`Some("")` branches, which is the exact change that reintroduces the wrong-content flash.

- [ ] **Step 1: Write the failing tests**

Append to `src/app.rs`:

```rust
#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    /// Renders `App` exactly as the server would.
    fn render_app() -> String {
        use leptos::prelude::*;
        let runtime = Owner::new();
        let html = runtime.with(|| view! { <App/> }.to_html());
        runtime.cleanup();
        html
    }

    #[test]
    fn ssr_renders_chrome() {
        let html = render_app();
        assert!(html.contains("Time Entry"), "entry pane heading missing");
        assert!(html.contains("Time Summary"), "summary pane heading missing");
        assert!(
            html.contains("How to use this tool"),
            "help toggle missing"
        );
        assert!(
            html.contains("11:45-12:15 code1"),
            "help sample block missing — it must be in the SSR'd HTML, not \
             mounted client-side, or hydration sees a different node count"
        );
    }

    /// Pins spec invariant I2. The server cannot know whether the user has
    /// saved data, so it must not render any conclusion that depends on it.
    #[test]
    fn ssr_omits_loaded_state() {
        let html = render_app();
        assert!(
            !html.contains("No projects found"),
            "server rendered the empty state it cannot know; returning users \
             would see it flash before their data loads (spec §5)"
        );
        assert!(
            !html.contains("hours)"),
            "server rendered a computed total; the summary must be blank \
             until localStorage is read (spec §5)"
        );
        assert!(
            !html.contains("No dead time"),
            "server rendered a dead-time conclusion (spec §5)"
        );
    }

    /// Pins spec invariant I4 for the one element whose SSR shape is subtle.
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

- [ ] **Step 2: Run the tests**

Run: `cargo test --features ssr --no-default-features 2>&1 | tail -20`
Expected: all three pass.

**If `render_app` fails to compile,** the Leptos 0.8 SSR render helper differs from the shape above. Check `leptos::prelude` for the available `to_html` / `render_to_string` entrypoint and adjust — the *assertions* are the contract, not the helper. Record the working shape in the divergence log.

**If `ssr_omits_loaded_state` fails,** do not weaken the assertion. It means `TimeDisplay` is rendering `SummaryBody` on the server, which breaks the hydration contract. Fix `TimeDisplay`.

- [ ] **Step 3: Commit**

```bash
git add src/app.rs
git commit -m "$(cat <<'EOF'
test: pin the SSR output against the hydration contract

ssr_omits_loaded_state asserts negatively on purpose: it fails both if
the server starts rendering user data and if the None/Some("") branches
are collapsed, which is the change that reintroduces the flash of
"No projects found" on reload for users with saved data.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 16: Full-stack verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full acceptance battery**

```bash
cargo test --features ssr --no-default-features 2>&1 | tail -5
cargo clippy --features ssr --no-default-features 2>&1 | grep -E "^(warning|error)" | head
cargo build --release --no-default-features --features hydrate --target wasm32-unknown-unknown 2>&1 | tail -3
cargo tree --target wasm32-unknown-unknown --no-default-features --features hydrate -e features 2>&1 | grep -E "^(axum|tokio|tower)\b" | head
cargo leptos build --release 2>&1 | tail -10
```

Expected: tests pass; no project clippy warnings; wasm release builds; the `cargo tree` grep is **empty**; cargo-leptos completes.

- [ ] **Step 2: HTTP smoke test**

```bash
LEPTOS_SITE_ADDR=127.0.0.1:3000 ./target/release/time-tracking-leptos &
sleep 3
curl -s -o /dev/null -w "root:%{http_code}\n" http://127.0.0.1:3000/
curl -s -o /dev/null -w "css:%{http_code}\n" http://127.0.0.1:3000/pkg/time-tracking-leptos.css
curl -s -I http://127.0.0.1:3000/pkg/time-tracking-leptos.css | grep -i content-type
curl -s http://127.0.0.1:3000/ > /tmp/ssr.html
grep -c "Time Summary" /tmp/ssr.html
grep -c "No projects found" /tmp/ssr.html || echo "absent (correct)"
kill %1
```

Expected: `root:200`, `css:200`, `Content-Type: text/css`, `Time Summary` present, `No projects found` **absent**.

- [ ] **Step 3: No commit** — verification only. Report any failure rather than working around it.

---

## Phase 6 — Deployment

### Task 17: Rewrite the Dockerfile

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Replace `Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1.7
FROM rust:1-slim AS builder

# curl + ca-certificates: fetching the cargo-leptos release tarball.
# The pre-built binary is used instead of `cargo install cargo-leptos`, which
# drags in git2 -> libgit2-sys -> openssl-sys and needs a full C/Perl toolchain.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --component rust-src \
 && rustup default nightly \
 && rustup target add wasm32-unknown-unknown

# Pinned: an unpinned install silently changes the build on every cargo-leptos
# release.
ARG CARGO_LEPTOS_VERSION=0.3.7
RUN curl -L \
    "https://github.com/leptos-rs/cargo-leptos/releases/download/v${CARGO_LEPTOS_VERSION}/cargo-leptos-x86_64-unknown-linux-gnu.tar.gz" \
    | tar xz --strip-components=1 -C /usr/local/cargo/bin/ \
 && chmod +x /usr/local/cargo/bin/cargo-leptos \
 && cargo leptos --version

WORKDIR /build
COPY . .

RUN cargo leptos build --release

# Not the :nonroot variant — the app binds port 80, which needs privileges.
FROM gcr.io/distroless/cc-debian12 AS runtime
WORKDIR /app

COPY --from=builder /build/target/release/time-tracking-leptos /app/time-tracking-leptos
COPY --from=builder /build/target/site /app/site

ENV LEPTOS_OUTPUT_NAME=time-tracking-leptos \
    LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    LEPTOS_SITE_ADDR=0.0.0.0:80

EXPOSE 80
CMD ["/app/time-tracking-leptos"]
```

- [ ] **Step 2: Build and run the image**

```bash
docker build -t time-tracking-leptos:test .
docker run --rm -d -p 8099:80 --name tt-test time-tracking-leptos:test
sleep 3
curl -s -o /dev/null -w "root:%{http_code}\n" http://127.0.0.1:8099/
curl -s -I http://127.0.0.1:8099/pkg/time-tracking-leptos.css | grep -i content-type
curl -s http://127.0.0.1:8099/ | grep -c "Time Summary"
docker stop tt-test
```

Expected: `root:200`, `Content-Type: text/css`, `Time Summary` found.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "$(cat <<'EOF'
build: rewrite the Dockerfile for cargo-leptos and distroless

Replaces the dx-bundle + nginx:alpine static runtime with a cargo-leptos
build and a distroless runtime serving the app directly. Keeps port 80
so the image stays a drop-in replacement; that requires the root-capable
distroless/cc variant rather than :nonroot.

cargo-leptos is installed from a pinned release tarball rather than
cargo install, which would pull in the openssl build chain.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 18: Update CI and project metadata

**Files:**
- Rename: `.github/workflows/dioxus.yml` → `.github/workflows/build.yml`
- Modify: the renamed workflow
- Modify: `.versionrc.json`
- Modify: `README.md`

> **Confirm with the user before committing** — this changes the pushed Docker image tag, which is outward-facing.

- [ ] **Step 1: Rename the workflow**

```bash
git mv .github/workflows/dioxus.yml .github/workflows/build.yml
```

- [ ] **Step 2: Update the workflow contents**

In `.github/workflows/build.yml`, change the workflow name and every image reference:

- `name: Dioxus build` → `name: Build`
- `${{ secrets.docker_registry }}/time-tracking-dioxus` → `${{ secrets.docker_registry }}/time-tracking-leptos`
- both `cache-from` / `cache-to` refs: `…/time-tracking-dioxus:buildcache` → `…/time-tracking-leptos:buildcache`

Add `leptos-migration` to the `pull_request.branches` list so the branch builds before merge:

```yaml
  pull_request:
    branches:
      - "main"
      - "develop"
      - "leptos-migration"
```

- [ ] **Step 3: Update `.versionrc.json` URLs**

Replace both occurrences of `time-tracking-dioxus` with `time-tracking-leptos` in `commitUrlFormat` and `compareUrlFormat`.

- [ ] **Step 4: Rewrite the README development section**

Replace the whole `## Development` section (Tailwind + `dx serve` instructions) with:

```markdown
## Development

Requires the pinned nightly toolchain (installed automatically from
`rust-toolchain.toml`) and [cargo-leptos](https://github.com/leptos-rs/cargo-leptos):

```bash
cargo install --locked cargo-leptos
```

Then:

```bash
cargo leptos watch
```

The app serves at <http://127.0.0.1:3000>. Tailwind is compiled by cargo-leptos
from `style/tailwind.css` — there is no npm step.

### Tests

```bash
cargo test --features ssr --no-default-features
```

### Architecture

The app is Leptos SSR + hydration: the server renders the page shell and the
app's *unloaded* state, and the browser fills in the user's saved time entry
from `localStorage` after hydration. No time-tracking data is sent to or stored
on the server.

See `docs/superpowers/specs/2026-09-03-leptos-migration-design.md` for the
design, particularly §5 on the hydration contract — the reason stored state is
`Option<String>` rather than `String`.
```

Also update the intro line: "built with [Dioxus]" → "built with [Leptos](https://leptos.dev/)".

- [ ] **Step 5: Ask the user to confirm the image-tag rename, then commit**

```bash
git add .github .versionrc.json README.md
git commit -m "$(cat <<'EOF'
ci: rename the built image to time-tracking-leptos

The pushed Docker image tag changes; anything pulling
<registry>/time-tracking-dioxus must be repointed.

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

### Task 19: Update `CLAUDE.md`

**Files:**
- Create: `CLAUDE.md`

The repo has no `CLAUDE.md`. The hydration contract is exactly the kind of non-obvious constraint a future session would otherwise violate.

- [ ] **Step 1: Write `CLAUDE.md`**

```markdown
# time-tracking-leptos

Leptos 0.8 SSR + hydration app on Axum, built with cargo-leptos. Parses
free-form time-tracking text into a per-project summary. All user data lives in
the browser's `localStorage`; nothing is stored server-side.

## Commands

| Task | Command |
|---|---|
| Dev server | `cargo leptos watch` (serves at :3000) |
| Tests | `cargo test --features ssr --no-default-features` |
| Lint | `cargo clippy --features ssr --no-default-features` |
| Wasm build | `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate` |
| Release | `cargo leptos build --release` |

Plain `cargo build`/`test` and `cargo leptos build` fight over the same target
dir and mutually invalidate the cache. `cargo clippy`/`check` are safe.

## The hydration contract — read before touching state

Persistent state is `Option<String>`, **not** `String`:

| Value | Meaning | Renders as |
|---|---|---|
| `None` | Not yet read from storage | Blank |
| `Some("")` | Loaded; nothing saved | "No projects found…" |
| `Some(text)` | Loaded with data | The parsed summary |

The server has no `localStorage`, so it must render the `None` branch. If the
server rendered an empty state instead, returning users would see a flash of
"No projects found" before their data appeared, and any server-rendered *data*
would fail hydration outright.

`src/app.rs`'s `ssr_omits_loaded_state` test pins this. It asserts negatively —
do not weaken it to make a change pass.

## Layout

- `src/app.rs` — document shell, router, root component, SSR output tests
- `src/storage/` — the storage seam. Components use `hook::use_persistent`;
  everything else is an implementation detail. The API is async so that
  server-backed encrypted storage (see `TODO.md`) can drop in without touching
  any component.
- `src/components/` — one file per group of related views
- `src/clipboard.rs` — same signature on both targets, side effect gated

## Conventions

- Edition 2024; nightly toolchain pinned by `rust-toolchain.toml`.
- Branch polymorphism uses `Either`/`EitherOf3`, never `.into_any()`.
- Tailwind v4 CSS-first: tokens and `@source` live in `style/tailwind.css`.
  There is no `tailwind.config.js` and no npm step.
- Storage key strings are a compatibility surface — changing one orphans
  existing users' saved data.

## Design docs

`docs/superpowers/specs/2026-09-03-leptos-migration-design.md`
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "$(cat <<'EOF'
docs: add CLAUDE.md covering the hydration contract

Claude-Session: https://claude.ai/code/session_01G292LgCacPziDHpETURXEu
EOF
)"
```

---

## Phase 7 — Generalize the `migrate-to-leptos` skill

> Scope per the user's decision: fully generalize across **Rust** web stacks; add a short "if your source isn't Rust" section naming the fork without a full playbook.

### Task 20: Generalize `SKILL.md`

**Files:**
- Modify: `/home/steve/.claude/skills/migrate-to-leptos/SKILL.md`
- Read: `docs/superpowers/skill-divergences.md` (accumulated during Phases 1–6)

- [ ] **Step 1: Rewrite the framing sections**

Change these, keeping the overall structure:

1. **Description + "When to use"** — currently assumes Axum + Askama + Juniper. Generalize to: any Rust web project moving to Leptos SSR, whether the source renders server-side (Askama/Maud/Tera/Minijinja on Axum/Actix/Rocket) or client-side (Dioxus/Yew/Sycamore wasm SPA).

2. **Replace "The locked-in decisions (skip brainstorming on these)"** with **"The decisions this migration involves"** — each entry becomes a *question* with a default answer and an explicit **applies when** condition. The twelve current entries map to:
   - Universal: hydration model, crate structure, CSS pipeline, toolchain, sequencing, testing strategy, Docker runtime.
   - Conditional on the source having a server: keep-the-existing-API endpoint, per-request context/session plumbing.
   - Conditional on the source being SSR already: URL-shape preservation, hashed-CSS layer.
   - Conditional on the source being a client-side SPA: **new** — "the server is the new artifact", and "where does client-only state live at SSR time" (the hydration contract).

3. **Add a Step 0 to the Process: classify the source.** Three branches:
   - *Rust, server-rendered templates* → the original playbook applies nearly whole.
   - *Rust, client-side wasm SPA* → no service layer, no DTOs, no server fns; the work is adding a server and solving the client-only-state hydration problem.
   - *Not Rust* → see the new section from Task 21.

4. **Soften the photo365 references.** Every "the user chose X" becomes "X is the default; photo365 chose it because Y". Point at `references/examples/` for the two worked migrations.

- [ ] **Step 2: Verify the skill still reads coherently**

Run: `wc -l /home/steve/.claude/skills/migrate-to-leptos/SKILL.md`
Expected: under 250 lines. If longer, push detail into `references/`.

- [ ] **Step 3: Commit (in the skill repo)**

```bash
cd /home/steve/.claude/skills/migrate-to-leptos
git add -A . 2>/dev/null || true
```

If `~/.claude` is not a git repo, skip the commit — report that to the user instead.

---

### Task 21: Generalize the reference files

**Files:**
- Modify: `references/decisions.md`, `references/phase-plan.md`, `references/cargo-toml-template.md`, `references/verification.md`, `references/dispatch-chunking.md`
- Create: `references/examples/photo365.md`, `references/examples/time-tracking.md`, `references/non-rust-sources.md`

- [ ] **Step 1: Split the worked examples out of `decisions.md`**

Move photo365's *specific answers* (keep `/graphql`, `FolderSvc`, `PHOTO_DIR`, the `?auth=` token flow) into `references/examples/photo365.md`. Write `references/examples/time-tracking.md` from this repo's spec: a CSR wasm SPA with no server, where SSR was chosen for a future auth story, and the hydration contract was the central design problem.

`decisions.md` keeps only the decision *questions*, their defaults, and their applies-when conditions.

- [ ] **Step 2: Restructure `phase-plan.md` into a conditional skeleton**

The current seven phases hard-code photo365's task list. Replace with phases whose *contents* depend on the Step 0 classification:

| Phase | Always | Only if source has a server | Only if source is a wasm SPA |
|---|---|---|---|
| 1 Scaffolding | toolchain, CSS pipeline, assets | — | — |
| 2 Cargo restructure | features, lib/bin roots, shell | — | — |
| 3 Server | router, static serving | port existing endpoints, per-request context | **build the server from scratch** |
| 4 Data layer | — | DTOs + server fns over the service layer | **often empty — no server state** |
| 5 Components | port the view layer | — | **plus: solve client-only-state hydration** |
| 6 Interactivity | port client behavior | — | — |
| 7 Deploy | Dockerfile, CI, smoke test | — | runtime changes from static host to binary |

State explicitly that the task count scales with the source: photo365 was ~32 tasks, this repo was ~22.

- [ ] **Step 3: Reduce `cargo-toml-template.md` to a core plus add-ons**

The current template lists photo365's entire dependency set. Cut to the always-needed core (leptos, leptos_router, leptos_meta, serde, the hydrate trio, axum/tokio/tower/leptos_axum) and add a table of optional blocks to paste in per source stack (GraphQL, image processing, crypto, caches, DB).

**Fix the Tailwind bug found in this migration:** `tailwind-config-file` and the `tailwind.config.js` snippet are a Tailwind **v3** shape. For v4, `@source` belongs in the input CSS and no config file is needed. Correct the template and note when a config file is still wanted.

- [ ] **Step 4: Genericize `verification.md`**

Its 11-step smoke test is photo365's endpoint list verbatim (`/Pets`, `/thumbnail/…`, `?auth=`). Rewrite as a *checklist template*: build verification (which is genuinely universal — keep as-is), then a table of endpoint classes to instantiate per project (root, a data page, static assets, any preserved API). Keep the wasm-dep-tree audit and the acceptance-criteria section unchanged; both generalize.

- [ ] **Step 5: Write `references/non-rust-sources.md`**

Short — one page. Content:

- The skill's playbook assumes the *backend* survives the migration. If the source is React/Next.js, Vue, Django, or Rails, that assumption fails and the first decision is a fork:
  - **Rewrite the backend in Rust** — Leptos server fns replace the existing API. Largest effort; cleanest end state; the rest of this skill then applies.
  - **Keep the existing backend** — Leptos SSR talks to it over HTTP. The Rust side owns rendering only. Server fns become thin proxies, or are skipped in favor of `Resource` + a plain HTTP client.
- Questions to settle before either path: where does session/auth live; is there an existing API contract worth preserving; does the existing backend need to keep serving other clients; is the data layer reachable from Rust at all.
- Explicitly: this skill does **not** carry a verified playbook for these; brainstorm the fork with the user rather than assuming.

- [ ] **Step 6: Update `dispatch-chunking.md`**

Replace the fixed 9-dispatch pattern with the *principle* (batch by phase; split only where a chunk leaves the repo in a known state; review at phase boundaries where the repo actually builds), then give both worked chunkings — photo365's 9 dispatches and this repo's — as examples.

- [ ] **Step 7: Verify**

Run: `ls /home/steve/.claude/skills/migrate-to-leptos/references/ && wc -l /home/steve/.claude/skills/migrate-to-leptos/references/*.md`
Expected: the new files exist; no single reference file is unreasonably long.

Re-read `SKILL.md` and confirm every `references/` link it makes still resolves.

- [ ] **Step 8: Report the skill changes to the user**

Summarize what changed and what the second worked example taught, since the skill lives outside this repo and will not appear in the branch diff.

---

## Self-review notes

- **Spec coverage:** §4 architecture → Tasks 3–5, 14. §5 hydration contract → Tasks 9, 13, 15. §6 storage seam → Tasks 6–9. §7 cross-cutting → Tasks 1, 2, 3, 17, 18. §8 testing → Tasks 6, 7, 13, 15. §10 acceptance → Task 16 (1–7, 9), Task 17 (8), user (10). §11 skill work → Tasks 20–21.
- **Known risk:** the `render_app` helper in Task 15 Step 1 is the one API shape not verified against the installed Leptos version. Task 15 Step 2 carries explicit instructions for adapting it without weakening the assertions.
- **Deliberate omission:** no `/api/{*fn_name}` server-fn route is mounted. The spec proposed it, but `.leptos_routes()` already registers the server-fn handler, so adding it manually would be duplication. Adding the first `#[server]` fn requires no router change.
