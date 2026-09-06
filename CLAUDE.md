# time-tracking-leptos

Leptos 0.8 SSR + hydration app on Axum, built with cargo-leptos. Parses
free-form time-tracking text into a per-project summary. Signed-out users'
data lives only in the browser's `localStorage` and never reaches the server.
Signed-in users' entries are stored server-side in SQLite, and **whether an
operator can read them depends on the account**:

- **Encryption off** — every account by default. Bodies are stored as
  plaintext in a `{"v":1,"alg":"none",…}` envelope. An operator with database
  access can read them.
- **Encryption on** — opt-in, offered to every account. Bodies are stored as
  `{"v":2,"alg":"a256gcm",…}` ciphertext under an AES-256-GCM key the server
  never holds and cannot derive. An operator with database access reads
  nothing but wrapped blobs.

Neither statement generalizes to the other kind of account, and a single
account can be **mid-migration** — enabling re-writes existing rows one pass
at a time, and dispatch is per row on that row's own `v`, so a half-migrated
account is a normal, readable state rather than a broken one. See Encryption,
below.

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
`entry_access.rs`, `passkey_access.rs`, `encryption_access.rs`,
`passkey_quota.rs`); the plain `Tests` command above already runs all of
them, and `--test routes` above just narrows a run to one file while
iterating. `passkey_quota.rs` is deliberately alone in its binary: the rate
limiters are process-wide statics keyed by client IP, no test request
carries one, and that file exhausts a bucket — see its header before adding
a second test to it.

**Plain `cargo clippy --features ssr --no-default-features` does not lint
everything.** Modules gated `#[cfg(any(feature = "hydrate", test))]` —
`src/storage/local.rs`, `src/webauthn_browser.rs`, `src/crypto/flow.rs`, and
part of `src/storage/mod.rs` and `src/crypto/mod.rs` — are compiled by neither
`ssr` nor a bare `clippy` invocation (`hydrate` is off, and `clippy` alone
doesn't turn on `cfg(test)` the way `--all-targets` or `cargo test` does).
Their pure, host-tested functions only get linted by:

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
Encryption, below.

### The second tri-state: `EncryptionState` and `WriteKey`

`src/encryption_ctx.rs` carries the same shape one level out, and `Unknown`
is load-bearing for SSR in exactly the way `None` is:

| State | Meaning | Server renders it? |
|---|---|---|
| `Unknown` | Probe has not resolved | **Yes**, for a signed-in visitor |
| `Unreachable` | Probe ran, the status call failed | No — the server never probes |
| `Disabled` | Account has no encryption | **Yes**, for a signed-out visitor |
| `Locked` | Encrypted, no key on this device | No |
| `Unlocked(SessionKey)` | Encrypted, key in hand | No — the variant is uninhabited under `ssr` |

The seed is **not** always `Unknown`. It is computed from
`auth_ctx::initial_user`, which both targets derive identically from the
session cookie: a signed-out visitor seeds `Disabled` (they use
`Backend::Local`, which is never encrypted — a fact, not a conclusion), and a
signed-in visitor seeds `Unknown`. Seeding `Disabled` for a signed-in visitor
would be a *conclusion* asserted before anything was read, and its write key
is `Plaintext` — which is how plaintext rows get written into an encrypted
account.

That is the other half. Writes take a `WriteKey`, not an
`Option<&SessionKey>`, because on a write "no key" is ambiguous and one of
its meanings is unrecoverable:

- `Plaintext` — no encryption, write v1.
- `Sealed(&SessionKey)` — seal and write v2.
- `Locked` — refuse with `StorageError::Locked`. `Unknown`, `Unreachable`
  and `Locked` all map here. Refusing costs a retry; guessing costs a silent
  plaintext row that no later migration pass would ever flag, because a v1
  row is exactly what an un-migrated account legitimately holds.

`EncryptionState::write_key` is the single conversion, and `clear` takes a
`WriteKey` too — on `Remote`, clearing a day stores an empty body rather than
deleting the row, so it is a write wearing a different name. Reads keep
`Option<&SessionKey>`: a row says which version it is, so there is no
ambiguity to resolve.

`src/app.rs`'s `ssr_omits_loaded_state`,
`ssr_omits_entry_content_even_when_signed_in`,
`ssr_renders_unknown_encryption_state`,
`ssr_offers_an_editable_entry_area_when_signed_out` and
`ssr_still_withholds_an_editable_entry_area_when_signed_in` pin all of this.
All but the last assert negatively, and the last two are a matched pair
asserting the signed-out and signed-in halves against each other. Do not
weaken any of them to make a change pass.

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

## Encryption

Both phases have shipped. Phase 1 put every body in a versioned envelope
(`{"v":1,"alg":"none",…}`); phase 2 spends that by writing
`{"v":2,"alg":"a256gcm",…}` for accounts that opt in, with **no data
migration** — the version tag was the whole point.

One rule holds regardless, and it is the load-bearing one: **the server must
never parse, aggregate, search, or render an entry body.** It stores and
returns opaque strings, capped by length and nothing else. That is why the
week view aggregates per-project totals in the browser rather than in a
server query, and why the enable-time migration filters `v: 1` rows
client-side after fetching all of them — a server-side aggregation or a
server-side version scan is exactly what encryption breaks.

**The key hierarchy.** A per-account AES-256-GCM data key (DEK) is generated
in the browser and wrapped (AES-KW) under independently derived KEKs: one
from a passkey's WebAuthn PRF output, one from a 160-bit recovery code. Both
derivations are HKDF-SHA256 over a fixed `APP_SALT` with a per-route `info`
string. The server stores only the 40-byte wrapped blobs. Unwrapped, the DEK
is held as a **non-extractable** `CryptoKey` in IndexedDB (database
`tt-keys`, store `keys`, id `dek`), so unlock is once per device rather than
once per page.

**Enabling has two routes** (spec §6.1), and the account's own capability
picks one — it is not a user preference:

| | Passkey + recovery | Recovery only |
|---|---|---|
| Offered when | some enrolled credential reported `prf_capable` | none did |
| Wraps written | `passkey` + `recovery` | `recovery` only |
| Unlock | passkey, in the sign-in gesture; code as backup | the code, typed once per device |
| Losing the code | survivable while a keyed passkey remains | **total** |

The second route exists because PRF support is a property of the browser and
the authenticator, not a setting: a password-manager extension that never
implemented the extension makes the first route permanently impossible, and
what the old dead end ("add a passkey that can hold a key") actually produced
was a plaintext account. **No migration was needed** —
`entry_key_wrap.credential_id` is nullable and both unique indexes are
partial. A recovery-only account stops being one as soon as a PRF-capable
passkey is given a key from the code, through `/account`'s existing
give-a-key flow. §6.6's "don't delete the last passkey wrap" refusal is
vacuous while there are zero of them and starts applying at the first.

**Consequences worth knowing before touching any of it:**

- The recovery code is shown **once**, at enable. Losing every passkey *and*
  the code makes that account's entries unreadable permanently, by everyone
  — or losing the code alone, on the recovery-only route. There is no
  operator recourse; that is the feature working. **The panel's two warnings
  are deliberately different sentences and must stay that way**: a user shown
  the two-wrap wording over a one-wrap account has been told they have a
  fallback they do not have. The words hang off `EnableRoute`, not off the
  section rendering them, and the code screen carries the route for the same
  reason.
- Adding a passkey to an encrypted account costs **three** authenticator
  interactions (create the new credential; open an *existing* route to
  re-derive the raw DEK — a passkey assertion, or the recovery code; assert
  against the new credential for its PRF output). Non-extractability is why:
  a sealed key cannot yield its bytes even to this session's own code, so
  being unlocked buys no shortcut (spec §6.5).
- Sign-out clears the device key. A magic-link sign-in lands `Locked` and
  needs an explicit unlock; a passkey sign-in unlocks in the same gesture,
  which is why `APP_SALT` is a constant and not per account.
- **Not defended:** which days have entries, approximate body length, script
  running on the app's own origin, and a malicious server build (the server
  ships the JS). Spec §2 states each as a decision.

Full design: `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`,
whose §11 lists the invariants (E1–E7) a change here has to keep.

## Layout

- `src/app.rs` — document shell, router, root component, SSR output tests
- `src/storage/` — the storage seam. Components use `hook::use_persistent`;
  everything else is an implementation detail. The API is async so both
  backends (`Local`, `Remote`) share it, and so client-side encryption drops
  in *here* — no component that reads or writes a day's text knows it exists.
- `src/crypto/` — everything the browser does with keys. `wire.rs` (the v2
  envelope, `APP_SALT`, the HKDF `info` strings — pure and host-tested) and
  `recovery.rs` (code generation, formatting, normalization — pure, RNG
  injected) carry the logic; `subtle.rs` (WebCrypto) and `keystore.rs`
  (IndexedDB) are the thinnest possible browser-only shells, reviewed by
  reading rather than by test. `mod.rs` holds `SessionKey` and `choose_route`;
  `flow.rs` holds the ceremony steps that need the authenticator *and* the
  server, so their wording and their retries cannot drift between the unlock
  prompt, the encryption panel and the account page.
- `src/entry_key/` — the **server** side of the same feature, and it never
  touches a key: a Diesel repository over `entry_key_wrap` and
  `user.encrypted_at`, moving wrapped blobs it cannot open.
- `src/encryption_ctx.rs` — `EncryptionState`, the post-hydration probe, and
  the only place that asks *whose* key a session holds.
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
- **The crypto constants are a compatibility surface too, and a quieter one.**
  In `src/crypto/wire.rs`:

  | Constant | Value |
  |---|---|
  | `APP_SALT` | SHA-256 of the ASCII bytes `time-tracking-leptos/entry-key/v1` |
  | passkey HKDF `info` | `tt/entry-kek/passkey/v1` |
  | recovery HKDF `info` | `tt/entry-kek/recovery/v1` |
  | envelope v2 `alg` | `a256gcm` |

  Changing any one of them silently makes every existing wrapped key
  unopenable, and **nothing reports it as an error** — a KEK derived from
  different inputs is a perfectly valid key that simply unwraps nothing, so
  the symptom is every account failing to unlock at once, looking like
  corruption. Swapping the two `info` strings between routes is the same
  failure with an even better disguise: both wraps are well-formed and
  neither opens. `wire.rs`'s `derivation_inputs_are_pinned` and
  `each_kind_keeps_its_own_info_string` exist to make that change impossible
  to do by accident; do not update them to match a new value (invariant E6).

## Design docs

- `docs/superpowers/specs/2026-09-03-leptos-migration-design.md`
- `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
  (its §9.2 and §9.3 are superseded by the one below and marked so in place)
- `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`
