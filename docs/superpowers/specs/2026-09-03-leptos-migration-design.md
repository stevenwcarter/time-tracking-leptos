# Dioxus → Leptos SSR Migration — Design Spec

**Date:** 2026-09-03
**Repo:** `time-tracking-leptos` (crate currently `time-tracking-dioxus`)
**Status:** Approved for planning

---

## 1. Summary

Migrate the time-tracking app from a **client-side-only Dioxus wasm SPA** to a
**Leptos 0.8 SSR + hydration** application built with cargo-leptos on Axum.

All user-visible behavior is preserved: paste time-tracking text into a
textarea, see a live-parsed summary beside it, click a project to copy its notes
to the clipboard, and have the textarea contents survive a page reload.

No state is sent to or stored on the server. The server renders the page shell
and the app's *empty* state; everything the user types stays in the browser's
`localStorage`, exactly as today.

## 2. Why this migration, and why SSR specifically

The app has no server today — nginx serves a static wasm bundle. Introducing a
Rust server binary is real work that buys nothing for the *current* feature set.
It is justified entirely by `TODO.md`:

> Explore whether we can create a passkey from javascript and use that to
> encrypt/decrypt their notes somehow… enable client-side encryption easily,
> with minimal friction to a user

Plus the stated follow-on of **multiple day-stores per user with passkey
sign-in**. Both need a server:

- WebAuthn/passkeys require a **relying party** to generate challenges and
  verify signatures. There is no purely client-side passkey flow.
- Per-user, multi-device day-stores require somewhere to put the (encrypted)
  blobs.

Choosing CSR now would mean doing an SSR migration a second time. Choosing SSR
now makes that future work **additive** — `#[server]` functions and a session
layer drop into a server that already exists.

**Non-goal:** this migration does *not* implement passkeys, encryption, or
per-user stores. It only ensures those are additive rather than another
migration. See §9.

## 3. Current-state inventory

| File | Lines | Role | Disposition |
|---|---|---|---|
| `src/main.rs` | 275 | `dioxus::launch` + all 9 components | Rewritten: server bootstrap; components move to `src/components/` |
| `src/lib.rs` | 2 | Two `pub mod` lines | Rewritten: feature-partitioned module tree + `hydrate()` |
| `src/hooks_composed.rs` | 65 | `use_persistent` — signal + `gloo_storage::LocalStorage` | Replaced by `src/storage/` (§6) |
| `src/clipboard.rs` | 20 | `web_sys` clipboard write | Kept, cfg-gated to `hydrate` |
| `assets/tailwind.css` | 19 KB | npm-compiled Tailwind output | Deleted — cargo-leptos generates `/pkg/*.css` |
| `tailwind.css` | 2 | v4 CSS-first source | Moves to `style/tailwind.css` |
| `package.json` / `package-lock.json` | — | `@tailwindcss/cli` devDep | Deleted — cargo-leptos drives Tailwind |
| `Dioxus.toml` | — | Dioxus web config | Deleted |
| `nginx/default.conf` | — | Static file server | Deleted — Axum serves directly |
| `Dockerfile` | — | `dx bundle` → `nginx:alpine` | Rewritten: cargo-leptos → distroless |
| `rust-analyzer.toml` | 2 | Overrides rustfmt with `dx fmt` | Deleted |
| `clippy.toml` | 8 | `await-holding-invalid-types` for Dioxus signal types | Rewritten for Leptos equivalents |
| `.github/workflows/dioxus.yml` | — | Docker build/push | Renamed + image name updated |

**Dependencies removed:** `dioxus`, `dioxus-clipboard`, `gloo-storage`.
**Dependency kept:** `time-tracking-parser` (pure Rust + serde; compiles for
both `wasm32-unknown-unknown` and the host — the pinned rev `cf34921` stays).

### Components to port (9)

`App`, `TimeEntryArea`, `HelpSection`, `TimeOverview`, `WorkingTimeDisplay`,
`DeadTimeDisplay`, `WarningsDisplay`, `ProjectItem`, `ProjectsDisplay`,
`TimeDisplay`. Every one is a pure presentational function of its props except
`App` (owns the persistent signal), `HelpSection` (owns a local `show_help`
toggle), `TimeDisplay` (owns the derived memos), and `ProjectItem` (clipboard
side effect).

One component is **added**: `SummarySkeleton`, the pre-load branch required by
the hydration contract in §5. It renders the summary panel's chrome with blank
value slots and no empty-state message.

## 4. Target architecture

Single crate, two artifacts, per the standard Leptos SSR partition.

```
time-tracking-leptos/
├── rust-toolchain.toml         nightly + wasm32-unknown-unknown
├── rustfmt.toml                edition = "2024"
├── Cargo.toml                  [lib] cdylib+rlib; ssr / hydrate features
├── style/tailwind.css          @import "tailwindcss"; @source "../src";
├── public/favicon.ico          assets-dir, copied to target/site/
├── src/
│   ├── lib.rs                  module tree + #[wasm_bindgen] hydrate()
│   ├── main.rs                 #[cfg(ssr)] Axum bootstrap / #[cfg(not)] stub
│   ├── app.rs                  shell() + App() + Router
│   ├── clipboard.rs            hydrate-only clipboard write, no-op under ssr
│   ├── storage/
│   │   ├── mod.rs              StorageKey, StorageError, async load/store/clear
│   │   ├── codec.rs            pure encode/decode (gloo-compatible JSON string)
│   │   ├── local.rs            #[cfg(hydrate)] localStorage backend
│   │   └── hook.rs             use_persistent() Leptos hook
│   └── components/
│       ├── mod.rs
│       ├── time_entry_area.rs  TimeEntryArea + HelpSection
│       ├── time_display.rs     TimeDisplay (owns the memos)
│       ├── summary.rs          TimeOverview, WorkingTimeDisplay,
│       │                       DeadTimeDisplay, WarningsDisplay,
│       │                       SummarySkeleton (new — the §5 None branch)
│       └── projects.rs         ProjectItem, ProjectsDisplay
└── Dockerfile                  rust slim builder → distroless/cc-debian12
```

**Build artifacts:** `target/release/time-tracking-leptos` (server binary) and
`target/site/pkg/time-tracking-leptos.{js,wasm,css}` (hydrate bundle).

### Routing

One route. `path!("/")` → `HomePage`. No wildcard route, so none of the
`/{*path}` traps apply — but `/pkg` is still mounted via `nest_service` **before**
the Leptos routes, because `file_and_error_handler` as fallback can still shadow
it.

This migration defines zero `#[server]` functions. No explicit server-fn route
is needed either: `.leptos_routes()` already registers the server-fn handler, so
adding the first `#[server]` fn later requires no router change.

### Render mode

`render_app_async_with_context` is unnecessary here — there are no Resources, so
there is nothing to await. Use the default
`leptos_axum::render_app_to_stream` shape. No `<Suspense>`/`<Transition>`
anywhere in this migration, which sidesteps that entire class of hydration bug.

## 5. The hydration contract (the load-bearing design decision)

This is the only genuinely tricky part of the migration, and every other choice
follows from it.

**The problem.** The user's saved text lives in `localStorage`, which does not
exist on the server. If the client rendered that text during its first
(hydration) pass, the client DOM would diverge from the server DOM and hydration
would fail.

**The contract.**

> The server and the client's *first* render both produce the app in its
> **unloaded** state — the stored value is `None`, and every region derived from
> it renders blank. `localStorage` is read only **after** hydration completes,
> inside an `Effect`, which flips the value to `Some(_)` and populates those
> regions reactively.

The state is `Option<String>`, not `String`, because the app must distinguish
three cases that a bare `String` conflates:

| Value | Meaning | Renders as |
|---|---|---|
| `None` | Not yet read from storage | Blank — no numbers, no message |
| `Some("")` | Loaded; genuinely nothing saved | "No projects found…", 00:00 totals |
| `Some(text)` | Loaded with data | The parsed summary |

Rendering "No projects found" server-side would be asserting the middle case
when we are actually in the first. A returning user would see a flash of
actively-wrong content ("the app lost my data") rather than a neutral blank.
An `Option` also makes the loaded-but-valueless state unrepresentable, versus
carrying a separate `loaded: bool` alongside a `String`.

Concretely:

```rust
// src/storage/hook.rs
pub fn use_persistent(key: StorageKey) -> Persistent {
    // Identical on server and client: None means "not read yet".
    let (value, set_value) = signal::<Option<String>>(None);

    // Effect::new never runs during SSR. On the client it runs AFTER the
    // first (hydrating) render, so the initial DOM already matched.
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            let stored = storage::load(key).await.unwrap_or_default();
            set_value.set(Some(stored.unwrap_or_default()));
        });
    });

    Persistent { value, set_value, key }
}
```

Consumers branch with `Either`, not `.into_any()`:

```rust
match persistent.get() {
    None       => Either::Left(view! { <SummarySkeleton/> }),
    Some(text) => Either::Right(view! { <SummaryBody data=parse(&text)/> }),
}
```

Both branches are inside a plain reactive closure, **not** a `<Suspense>`. The
closure hydrates via `RenderEffect`, whose first-run cursor walk matches SSR
output cleanly, so none of the Suspense marker-alignment hazards apply.

**Consequences accepted:**

1. **Blank regions on first paint**, filling in immediately after hydration.
   For a `localStorage` read this is sub-frame in practice.
2. **Layout shift is bounded by reserving space.** The summary panel's chrome —
   the "Time Summary" heading, the overview/working-time/dead-time boxes — is
   static and renders server-side; only the *values* inside them are blank while
   `None`. The projects list renders as an empty region of the same minimum
   height. The whole panel is never blanked.
3. `<textarea>` is bound with `prop:value`, not an attribute. Leptos does not
   serialize `prop:` bindings into SSR output, so the server emits
   `<textarea></textarea>` and the client attaches the binding to the same empty
   element. This is consistent by construction, in both the `None` and
   `Some("")` cases.

**Why this is also the right end state.** Once notes are encrypted with a
passkey-derived key (`TODO.md`), the server *cannot* render the summary at any
point in the future — the decryption key exists only in the browser. Blank-then-
populate is therefore permanent architecture for that path, not a workaround for
`localStorage`. If instead a future feature stores data server-side
*unencrypted*, the `None` branch is replaced by a `Resource` + `<Transition>`,
which is the same shape with framework machinery doing the flag-keeping.

**Invariants this design depends on** (per the repo's spec discipline — each
gets a pinning test in §8, *not* a prose assurance):

- **I1.** `use_persistent` initializes to `None` on both targets. If a future
  change makes the server seed this from a cookie or a server function without
  also changing the client's first render, hydration breaks.
- **I2.** The `None` branch renders no data-derived content — in particular it
  must not emit the `Some("")` empty-state text. A future edit that "simplifies"
  the two branches into one reintroduces the wrong-content flash.
- **I3.** `parse_time_tracking_data("")` is total and yields zeroed totals with
  no projects, so the `Some("")` branch is well-defined.
- **I4.** No component's *rendered output* differs between `ssr` and `hydrate`
  cfg. Only side effects (clipboard, storage) are cfg-gated.

## 6. The storage seam

Chosen shape: **async-facing API now**, so that swapping localStorage for
server-side encrypted storage later touches only `src/storage/`, not any
component.

```rust
// src/storage/mod.rs

/// Identifies one stored document. An enum rather than a string so the
/// future multi-day-store work extends this type instead of leaking
/// stringly-typed keys through the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKey {
    TimeEntry,
    // Future: Day(NaiveDate), etc.
}

impl StorageKey {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageKey::TimeEntry => "time_entry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError { .. }

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError>;
pub async fn store(key: StorageKey, value: &str) -> Result<(), StorageError>;
pub async fn clear(key: StorageKey) -> Result<(), StorageError>;
```

Two layers of insulation:

- **Components** only ever touch `use_persistent` / `Persistent` (§5). They
  never see `StorageKey` plumbing or async.
- **`use_persistent`** only ever touches the three async free functions above.

`Persistent` exposes the tri-state from §5 and hides the write-through:

```rust
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: StorageKey,
}

impl Persistent {
    /// `None` until storage has been read. See §5.
    pub fn get(self) -> Option<String>;
    /// Updates the signal and writes through to storage.
    pub fn set(self, value: String);
}
```

Note that `load`'s `Ok(None)` (nothing stored) and `Persistent::get`'s `None`
(not yet read) are **different**: `use_persistent` collapses the former into
`Some(String::new())`, so `get() == None` means exclusively "unloaded".

Under `hydrate`, the implementation is `web_sys` `localStorage` (dropping the
`gloo-storage` dependency — it is one `window().local_storage()` call and we
already need `web-sys`). Under `ssr`, `load` returns `Ok(None)` and
`store`/`clear` are `Ok(())` no-ops. The `ssr` no-op is belt-and-braces only:
`Effect::new` never runs during SSR, so `load` is not called there in the first
place. Both facts independently keep I1 true.

The `time_entry` value keeps its **existing on-disk representation** — a
JSON-encoded string, as `gloo_storage` wrote it — so users' saved text survives
the migration. This is a compatibility requirement, tested in §8.

**Why async today, when localStorage is synchronous:** the point of the seam is
that the *call sites* never change. A server-backed `load` will be a network
round-trip; making that shape visible now costs one `spawn_local` in
`use_persistent` and zero changes anywhere else later.

## 7. Cross-cutting changes

### Crate rename
`time-tracking-dioxus` → `time-tracking-leptos`, propagated to
`[package].name`, `default-run`, `[package.metadata.leptos].output-name`,
`.versionrc.json` URLs, and the CI Docker image tag.

**Deployment coordination required (outside this repo):** renaming the GitHub
repository `stevenwcarter/time-tracking-dioxus` → `…-leptos`, and repointing
anything that pulls `<registry>/time-tracking-dioxus` to
`<registry>/time-tracking-leptos`.

### Edition 2024
The crate moves `edition = "2021"` → `"2024"`, and a new `rustfmt.toml` pins
`edition = "2024"` to match — per the global rule that all crates' editions equal
`rustfmt.toml`'s, so `cargo fmt --all` and a bare `rustfmt` agree.

### Tailwind v4, CSS-first
The existing root `tailwind.css` already uses v4 syntax
(`@import "tailwindcss"; @source …`). It moves to `style/tailwind.css` with the
`@source` glob repointed at `../src`, and cargo-leptos's
`tailwind-input-file` drives it.

**No `tailwind.config.js` is created.** Tailwind v4 is CSS-first; a v3-style
config file is not needed when `@source` is declared in CSS. (The
`migrate-to-leptos` skill's template says to create one — that is a v3
assumption and is one of the skill bugs Phase 7 fixes.)

### Port
The container **keeps port 80** (`LEPTOS_SITE_ADDR=0.0.0.0:80`, `EXPOSE 80`),
so the new image is a drop-in replacement for the nginx one — no compose file,
k8s manifest, or reverse proxy in front of it needs repointing.

This constrains the runtime image: binding port 80 requires either root or
`CAP_NET_BIND_SERVICE`. Use `gcr.io/distroless/cc-debian12`, whose default user
is root — **not** the `:nonroot` variant, which cannot bind a privileged port.

Local development is the one place this differs: `cargo leptos watch` reads
`site-addr` from `[package.metadata.leptos]`, and binding 80 locally needs
privileges. `site-addr` is therefore set to `127.0.0.1:3000` for dev, and the
Dockerfile overrides it via the `LEPTOS_SITE_ADDR` env var at runtime. The env
var wins over the manifest value, so the two never conflict.

### `recursion_limit`
`#![recursion_limit = "512"]` on **both** `lib.rs` and `main.rs` — the bin is a
separate crate root and does not inherit the lib's attribute.

## 8. Testing strategy

The current repo has **zero tests**. This migration adds a small suite targeted
at the invariants the design actually leans on, rather than broad coverage of
presentational components.

| Test | Pins | Location |
|---|---|---|
| `codec_round_trip` | encode → decode returns the same value | `src/storage/codec.rs` |
| `gloo_format_compat` | a value written in `gloo_storage`'s JSON-string encoding still decodes | `src/storage/codec.rs` |
| `ssr_backend_returns_none` | **I1** — under `ssr`, `load` yields `Ok(None)` | `src/storage/mod.rs` |
| `empty_parse_is_total` | **I3** — `parse_time_tracking_data("")` yields zeroed totals and no projects | `src/components/time_display.rs` |
| `ssr_renders_chrome` | **I1 + I4** — `render_to_string(App)` contains the static chrome: "Time Summary", "Time Entry", the help text, the sample-format block | `src/app.rs` |
| `ssr_omits_loaded_state` | **I2** — the SSR'd HTML does **not** contain "No projects found", any `hrs` total, or any persisted text | `src/app.rs` |
| `ssr_textarea_is_empty` | **I4** — the SSR'd `<textarea>` has no text content, so hydrate's `prop:value` binding attaches to a matching node | `src/app.rs` |

`ssr_omits_loaded_state` is the load-bearing one, and it is deliberately a
*negative* assertion. It fails if anyone later makes the server render user data
without addressing the hydration contract, **and** it fails if anyone collapses
the `None`/`Some("")` branches back into a single empty-state render — the exact
regression that reintroduces the wrong-content flash. A positive-only test would
catch neither.

**Not tested:** individual presentational components (no runtime to render them
against without an integration harness, and their content is asserted
transitively by the SSR render test). No E2E browser tests. Hydration itself is
verified by the manual smoke test in §10.

## 9. Explicitly out of scope

Deferred to their own specs, but unblocked by this one:

- Passkey/WebAuthn registration and sign-in.
- Client-side encryption of notes (incl. the WebAuthn PRF-extension key
  derivation the TODO speculates about).
- Server-side encrypted blob storage; multiple day-stores per user.
- Any `#[server]` function. The router mounts `/api/{*fn_name}` so adding the
  first one is a one-file change.

## 10. Acceptance criteria

A complete migration satisfies all of:

1. `cargo leptos build --release` succeeds.
2. `cargo test --features ssr --no-default-features` passes.
3. `cargo build --release --no-default-features --features hydrate --target wasm32-unknown-unknown` succeeds.
4. `cargo tree --target wasm32-unknown-unknown --no-default-features --features hydrate -e features` shows no `axum`/`tokio`/`tower` lines.
5. `cargo clippy --features ssr --no-default-features` is clean of project warnings.
6. `curl /` returns 200, contains "Time Summary" and "Time Entry", and does
   **not** contain "No projects found" (§5 — the server does not assert a
   loaded state it cannot know).
7. `curl -I /pkg/time-tracking-leptos.css` returns 200 with `Content-Type: text/css`.
8. `docker build .` succeeds; the container serves criteria 6–7 on port 80.
9. `git ls-files` shows no `Dioxus.toml`, `nginx/`, `package.json`, `assets/tailwind.css`, `src/hooks_composed.rs`.
10. **Browser smoke test** (user-run):
    - a. Load `/` — page is styled, no console errors, **no hydration errors**.
    - b. Type into the textarea — summary updates live.
    - c. Reload with data saved — typed text is restored, and the summary goes
         blank → populated. It must **never** flash "No projects found".
    - d. Reload with storage cleared — summary settles on "No projects found".
    - e. A value saved by the *old Dioxus build* still loads (§6 compatibility).
    - f. Click a project row — its notes land on the clipboard.
    - g. Toggle "How to use this tool" — help panel expands and collapses.
    - h. Click "Clear" — textarea empties and stays empty across a reload.

## 11. Skill generalization (Phase 7 of the plan)

This migration is the second worked example for the `migrate-to-leptos` skill,
and it broke most of the skill's assumptions. The skill is written as though
photo365's shape (Axum + Askama + Juniper + cookie auth) were the general case.

Phase 7 rewrites it into a general guideline covering **any Rust web stack**,
with a shorter "if your source isn't Rust" section that names the fork without a
full playbook (per the user's chosen breadth). Divergences found during this
migration are logged as they occur in `docs/superpowers/skill-divergences.md`
and folded in at Phase 7. Known already:

- `tailwind.config.js` is a Tailwind v3 assumption; v4 is CSS-first (§7).
- Decisions 1 (keep `/graphql`) and 9 (per-request `GraphQLContext`) do not
  apply to a source with no server; the skill presents them as universal.
- The 7-phase plan assumes a service layer, DTOs, and server functions —
  a CSR→SSR migration of a stateless app has none of these.
- Phases assume SSR→SSR; the source may be a wasm SPA already, making the
  *server* the new artifact rather than the client.
- `verification.md`'s smoke test is photo365's endpoint list verbatim.
