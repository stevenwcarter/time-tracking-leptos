# time-tracking-leptos

Leptos 0.8 SSR + hydration app on Axum, built with cargo-leptos. Parses
free-form time-tracking text into a per-project summary. Signed-out users'
data lives only in the browser's `localStorage`. Signed-in users' entries are
stored server-side in SQLite — currently as **plaintext**; client-side
encryption is a planned phase 2 (see Encryption trajectory, below). An
operator with database access can read every signed-in user's entries today.

## Commands

| Task | Command |
|---|---|
| Dev server | `cargo leptos watch` (serves at :3000) |
| Tests | `cargo test --features ssr --no-default-features` |
| One integration test file | `cargo test --features ssr --no-default-features --test routes` |
| Lint | `cargo clippy --features ssr --no-default-features` |
| Lint, full coverage | `cargo clippy --features ssr --no-default-features --all-targets -- -D warnings` |
| Wasm build | `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate` |
| Release | `cargo leptos build --release` |

Plain `cargo build`/`test` and `cargo leptos build` fight over the same target
dir and mutually invalidate the cache. `cargo clippy`/`check` are safe.

Integration tests live in `tests/` (`routes.rs`, `magic_link.rs`,
`entry_access.rs`, `passkey_access.rs`); the plain `Tests` command above
already runs all of them, and `--test routes` above just narrows a run to one
file while iterating.

**Plain `cargo clippy --features ssr --no-default-features` does not lint
everything.** Modules gated `#[cfg(any(feature = "hydrate", test))]` —
`src/storage/local.rs`, `src/webauthn_browser.rs`, and part of
`src/storage/mod.rs` — are compiled by neither `ssr` nor a bare `clippy`
invocation (`hydrate` is off, and `clippy` alone doesn't turn on `cfg(test)`
the way `--all-targets` or `cargo test` does). Their pure, host-tested
functions only get linted by:

```
cargo clippy --features ssr --no-default-features --all-targets -- -D warnings
cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings
```

Treat both as required before calling the lint clean, not optional extras.

## The hydration contract — read before touching state

Persistent state is `Option<String>`, **not** `String`:

| Value | Meaning | Renders as |
|---|---|---|
| `None` | Not yet read from storage | Blank |
| `Some("")` | Loaded; nothing saved | "No projects found…" |
| `Some(text)` | Loaded with data | The parsed summary |

The server has no `localStorage`, and no permission to resolve a remote read
during render either, so it must render the `None` branch — for every
backend, and even for a signed-in visitor whose row it could otherwise read
trivially. If the server rendered an empty state instead, returning users
would see a flash of "No projects found" before their data appeared, and any
server-rendered *data* would fail hydration outright.

The tri-state also resets to `None` whenever the *key* changes — a new date,
or a backend switch on sign-in/sign-out — before that key's load starts.
Skipping that reset leaves the previous key's text on screen under the new
heading until the load resolves (`storage::hook::use_persistent`'s `Effect`).

The server *does* render auth state — the header's signed-in identity — just
never entry content. The cookie is available synchronously and cheap to
render, but returning a body is exactly what the server must never do; see
Encryption trajectory, below.

`src/app.rs`'s `ssr_omits_loaded_state` and
`ssr_omits_entry_content_even_when_signed_in` tests pin this. Both assert
negatively — do not weaken either to make a change pass.

`render_app()` (via `render_at()`), the helper behind these SSR tests, only
provides a `RequestUrl` context and, for the signed-in case, an `AppCtx` —
not `ServerMetaContext`, request `Parts`, or `ResponseOptions`. That's
harmless today: `leptos_meta` writes nothing to the body buffer either way,
so the rendered HTML still matches production. But the gap emits a
swallowed warning, and a future feature that depends on those contexts will
need the helper extended.

`render_app()` also renders synchronously via `.to_html()`, while production
streams through `leptos_axum`'s route handler. There are no `Resource`s or
`<Suspense>` boundaries in the app today, so the two agree — but adding async
rendering would make this helper stop tracking production, and the SSR tests
would need revisiting.

## Storage keys — a compatibility surface

- `time_entry:YYYY-MM-DD` — the dated key every entry is stored under going
  forward. The format keeps lexical and chronological order in agreement, so
  a key scan can answer a date-range question without parsing every key.
- `time_entry` (`LEGACY_KEY`) — the pre-dated key every existing user's data
  sits under. Read-only and self-erasing: it surfaces only for today's date
  and only until the first write to a dated key, which removes it.
- `time_entry_import_done` — set once a device has been offered the one-time
  import of its local entries into a newly signed-in account (whether the
  user accepted or dismissed it), so the import banner never appears twice on
  the same device.

Changing any of these strings orphans existing users' saved data.

## Routing

`/{date}` matches **any** single path segment, so it shadows the static-file
fallback for anything at the root — a request for `/favicon.ico` would
otherwise render the app instead of the icon. Root-level static assets are
therefore routed explicitly, ahead of the Leptos routes, via the
`ROOT_ASSETS` list in `src/test_support.rs` (the router-construction module
shared by `main` and the integration tests, not `main.rs` itself). Adding a
file to `public/`'s top level means adding it to `ROOT_ASSETS` too, or it
silently starts serving the app's HTML instead. Pinned by `tests/routes.rs`.

## Encryption trajectory

Phase 1 (current) stores entry bodies as plaintext, wrapped in a versioned
envelope (`{"v":1,"alg":"none",...}`) so phase 2 can start writing
`{"v":2,"alg":"xchacha20poly1305",...}` rows without a migration. Regardless
of phase, one rule holds: **the server must never parse, aggregate, search,
or render an entry body** — it only stores and returns opaque strings. That
is why the week view aggregates per-project totals in the browser rather than
in a server query: a server-side aggregation is exactly what phase 2's
encryption would break, and would have to be rewritten rather than simply
gaining a decrypt step.

## Layout

- `src/app.rs` — document shell, router, root component, SSR output tests
- `src/storage/` — the storage seam. Components use `hook::use_persistent`;
  everything else is an implementation detail. The API is async so both
  backends (`Local`, `Remote`) share it, and so phase-2 client-side
  encryption (see Encryption trajectory, above) can drop in without touching
  any component.
- `src/components/` — one file per group of related views: `summary`,
  `projects`, `time_display`, `time_entry_area`, `header`, `account_menu`,
  `account_page`, `calendar`, `week_view`, `import_banner`, `unlock`,
  `encryption_panel`, `status` (the shared note/problem line `/account`'s
  two halves both talk back through)
- `src/clipboard.rs` — same signature on both targets, side effect gated

## Configuration

Copy `.env.example` to `.env` for local development; see README.md's
Configuration section for what each variable does. Summarized here:

| Variable | Required | Default |
|---|---|---|
| `DATABASE_URL` | no | `./data/time-tracking.db` |
| `SESSION_KEY` | release builds only | ephemeral, debug builds only |
| `PASSKEY_STATE_KEY` | no | falls back to `SESSION_KEY` |
| `MAGIC_LINK_TTL_SECONDS` | no | `900` |
| `SITE_BASE_URL` | no (must be correct for emailed links) | `http://localhost:3000` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | no | unset `SMTP_HOST` logs links instead of sending |
| `SMTP_INSECURE` | no | unset — STARTTLS required; `1`/`true` drops TLS for a local catcher |
| `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` / `WEBAUTHN_RP_NAME` | no | suit `localhost:3000` |
| `RUST_LOG` | no | `info` |

## Conventions

- Edition 2024; nightly toolchain pinned by `rust-toolchain.toml`.
- Branch polymorphism uses `Either`/`EitherOf3`, never `.into_any()`.
- Tailwind v4 CSS-first: `@source` lives in `style/tailwind.css`, which pulls
  in Tailwind's default palette/scale — there is no `@theme` block, so no
  custom design tokens are defined, just one custom utility (`.value-slot`)
  in `@layer components`. There is no `tailwind.config.js` and no npm step.
- Storage key strings are a compatibility surface — changing one orphans
  existing users' saved data.

## Design docs

- `docs/superpowers/specs/2026-09-03-leptos-migration-design.md`
- `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
