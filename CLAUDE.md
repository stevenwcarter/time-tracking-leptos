# time-tracking-leptos

Leptos 0.8 SSR + hydration app on Axum, built with cargo-leptos. Parses
free-form time-tracking text into a per-project summary. Where an entry is
stored decides how it is stored, and the two answers are opposite on purpose:

- **Signed out — `localStorage`, always plaintext.** A
  `{"v":1,"alg":"none",…}` envelope in the browser. It never reaches the
  server, so there is nothing for server-side encryption to defend and no
  key material to defend it with. This is a decision, not a gap (phase-2
  spec §1.2), and it is the mode the setup gate's escape hatch falls back
  to.
- **Signed in — SQLite on the server, always ciphertext.** A
  `{"v":2,"alg":"a256gcm",…}` envelope sealed under an AES-256-GCM key the
  server never holds and cannot derive. An operator with database access
  reads nothing but wrapped blobs.

**There is no third case.** Encryption is not an account setting and cannot
be declined: `entry_save` refuses every write from an account whose
`user.encrypted_at` is null (invariant E9), and a signed-in account without
it is routed to setup instead of the day and week views. No server-side
plaintext row can be written by this build, and none is migrated — see
Encryption, below, which also carries the one deployment assumption whose
failure is unrecoverable.

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

- `Plaintext` — no encryption, write v1. **Only `Backend::Local` may take
  it.** Paired with `Remote` it is refused with
  `StorageError::EncryptionRequired`, since the server would refuse the same
  write anyway (invariant E9) and refusing here saves the round trip.
- `Sealed(&SessionKey)` — seal and write v2.
- `Locked` — refuse with `StorageError::Locked`. `Unknown`, `Unreachable`
  and `Locked` all map here. Refusing costs a retry; guessing costs a
  plaintext row in an account that must not hold one, and nothing on the
  read side would ever flag it — dispatch is per row, so a v1 row is read as
  plaintext without complaint wherever it turns up.

`storage::write_target` is the single place both refusals are made, shared by
`store` and `clear` — on `Remote`, clearing a day stores an empty body rather
than deleting the row, so it is a write wearing a different name.
`EncryptionState::write_key` is the single conversion from state to key, and
`EncryptionState::writes(backend)` reads that decision back out so the entry
area cannot offer a box the seam then refuses. Reads keep
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

The gate has its own matched set in the same module —
`a_signed_in_account_without_encryption_gets_no_entry_area`,
`the_gate_offers_a_way_back_to_local_mode`,
`the_setup_view_hides_the_link_that_would_only_bounce_back`,
`a_signed_out_visitor_is_not_gated` and
`the_entry_area_is_read_only_until_a_save_would_be_stored`. They are pairs
for the same reason: an assertion that a gated account sees the escape means
little without its complement asserting a set-up account does not.

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

Three phases have shipped. Phase 1 put every body in a versioned envelope
(`{"v":1,"alg":"none",…}`); phase 2 spent that by writing
`{"v":2,"alg":"a256gcm",…}` for accounts that opted in; **phase 3 removed the
opting.** Server-side storage is now encrypted or it does not happen.

> ### Deploying this build requires an empty database
>
> **The production database must be deleted before this build is deployed.**
> This is the one assumption in the branch whose failure is silent and
> unrecoverable — everything else here fails loudly and is fixed by re-running
> something.
>
> The rename changed the stored `entry_key_wrap.kind` value from `'recovery'`
> to `'encryption_key'`, and it did so by **editing a shipped migration in
> place** rather than adding a new one. A database that survives has already
> run `2026-09-05-000001_entry_key`, so Diesel will not re-run it: the rows
> keep saying `'recovery'`, `idx_entry_key_wrap_one_encryption_key`'s
> predicate never matches them, and `WrapKind::parse` returns `None` for
> every one. The wrap holding that account's data key becomes unfindable.
> Nothing errors at deploy time and nothing errors at startup; the symptom is
> every encrypted account failing to unlock, looking exactly like corruption.
> There is no recovery, because the key that would decrypt the entries is the
> one that can no longer be located.
>
> If a database ever *does* have to survive this change, the fix is a real
> forward migration (`UPDATE entry_key_wrap SET kind = 'encryption_key' WHERE
> kind = 'recovery'`, and the index rebuilt) — never a second in-place edit.

One rule holds through all three phases, and it is the load-bearing one:
**the server must never parse, aggregate, search, or render an entry body.**
It stores and returns opaque strings, capped by length and nothing else.
That is why the week view aggregates per-project totals in the browser rather
than in a server query, and it is why enforcement in §3 of the phase-3 spec
is a check on `user.encrypted_at` — an account column — rather than the
obvious "reject a body that is not a v2 envelope", which would be the server
parsing an entry (invariants E1 and E10).

**Enforcement, and where it lives.** `entry_save` is the only endpoint that
writes an entry, and it refuses unless `encrypted_at` is set, reading it in
the same transaction as the write so a save racing `encryption_enable` sees
one consistent account state. The client half is
`storage::write_target`, which refuses the `(Backend::Remote,
WriteKey::Plaintext)` pair with `StorageError::EncryptionRequired` — the
single place both write refusals are made, shared by `store` and `clear`.
What this does **not** buy is protection against a modified client that
enables encryption and then posts plaintext anyway; that is the same trust
boundary phase 2 recorded, and closing it would require reading bodies.
Do not "fix" it.

**The gate.** A signed-in account with no encryption gets
`components::setup_gate::SetupGate` in place of the day and week views, and
is navigated to `/account`. Both hang off `Writes::SetupRequired`, which
needs the post-hydration probe, so neither is ever server-rendered. Setup is
two steps: a passkey (step 1 of 2, explicitly **optional**, framed as
skipping the email link rather than as an encryption prerequisite) and then
encryption itself (step 2 of 2). **The escape hatch is load-bearing** —
"Sign out and use this device only" returns the browser to `Backend::Local`,
which is fully functional and stores nothing server-side. Without it the gate
reads as a lock-out. `src/app.rs` asserts both that a gated account sees it
and that a set-up account does not.

**Nothing migrates, and no code exists to.** `entries_all`, `entry_save_many`
and `MigrationPlan` are gone with the pass they served. The v1 *read* path
stays regardless: `envelope::plan_read` is shared by both backends and
`Backend::Local` still writes v1, so removing it would break signed-out
storage. What went is narrower than "v1 support" — it is the write route by
which a `Remote` save could produce a v1 row.

**The key hierarchy.** A per-account AES-256-GCM data key (DEK) is generated
in the browser and wrapped (AES-KW) under independently derived KEKs: one
from a passkey's WebAuthn PRF output, one from a 160-bit **encryption key**
— a printable string the user saves. It is not a recovery code and is not
single-use: nothing consumes or invalidates it, so it opens every entry on
any device until the owner generates a replacement. Both
derivations are HKDF-SHA256 over a fixed `APP_SALT` with a per-route `info`
string. The server stores only the 40-byte wrapped blobs. Unwrapped, the DEK
is held as a **non-extractable** `CryptoKey` in IndexedDB (database
`tt-keys`, store `keys`, id `dek`), so unlock is once per device rather than
once per page.

**Enabling has two routes** (phase-2 spec §6.1), and the account's own
capability picks one — it is not a user preference. *Which* route, not
*whether*:

| | Passkey + encryption key | Encryption key only |
|---|---|---|
| Offered when | some enrolled credential reported `prf_capable` | none did |
| Wraps written | `passkey` + `encryption_key` | `encryption_key` only |
| Unlock | passkey, in the sign-in gesture; the encryption key as the second way in | the encryption key, typed once per device |
| Losing the encryption key | survivable while a keyed passkey remains | **total** |

The second route exists because PRF support is a property of the browser and
the authenticator, not a setting: a password-manager extension that never
implemented the extension makes the first route permanently impossible, and
what the old dead end ("add a passkey that can hold a key") actually produced
was a plaintext account. Now that a plaintext account cannot store anything,
that dead end would be a lock-out rather than a downgrade — which is why the
key-only route has to stay reachable, and why step 1 is optional.
**No migration was needed** — `entry_key_wrap.credential_id` is nullable and
both unique indexes are partial. An encryption-key-only account stops being
one as soon as a PRF-capable passkey is given a key from it, through
`/account`'s existing give-a-key flow. §6.6's "don't delete the last passkey
wrap" refusal is vacuous while there are zero of them and starts applying at
the first.

**Consequences worth knowing before touching any of it:**

- The encryption key is shown **once**, at enable. Losing every passkey *and*
  the encryption key makes that account's entries unreadable permanently, by
  everyone — or losing the key alone, on the encryption-key-only route. There is no
  operator recourse; that is the feature working. **The panel's two warnings
  are deliberately different sentences and must stay that way**: a user shown
  the two-wrap wording over a one-wrap account has been told they have a
  fallback they do not have. The words hang off `EnableRoute`, not off the
  section rendering them, and the key screen carries the route for the same
  reason.
- Adding a passkey to an encrypted account costs **three** authenticator
  interactions (create the new credential; open an *existing* route to
  re-derive the raw DEK — a passkey assertion, or the encryption key; assert
  against the new credential for its PRF output). Non-extractability is why:
  a sealed key cannot yield its bytes even to this session's own code, so
  being unlocked buys no shortcut (spec §6.5).
- Sign-out clears the device key. A magic-link sign-in lands `Locked` and
  needs an explicit unlock; a passkey sign-in unlocks in the same gesture,
  which is why `APP_SALT` is a constant and not per account.
- **Not defended:** which days have entries, approximate body length, script
  running on the app's own origin, and a malicious server build (the server
  ships the JS). Phase-2 spec §2 states each as a decision. Note that none of
  these became *less* true by making encryption mandatory — the gate changes
  who is encrypted, not what encryption defends.

Full design: `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`
for the key hierarchy, ceremonies and threat model — its §11 lists invariants
E1–E8 — and
`docs/superpowers/specs/2026-09-06-encryption-required-design.md` for the
enforcement, the gate and the rename, whose §6 adds E9 and E10. Parts of the
phase-2 spec are superseded by the phase-3 one and are marked so in place,
not deleted.

## Layout

- `src/app.rs` — document shell, router, root component, SSR output tests
- `src/storage/` — the storage seam. Components use `hook::use_persistent`;
  everything else is an implementation detail. The API is async so both
  backends (`Local`, `Remote`) share it, and so client-side encryption drops
  in *here* — no component that reads or writes a day's text knows it exists.
- `src/crypto/` — everything the browser does with keys. `wire.rs` (the v2
  envelope, `APP_SALT`, the HKDF `info` strings — pure and host-tested) and
  `encryption_key.rs` (generation, formatting, normalization of the
  printable encryption key — pure, RNG injected) carry the logic; `subtle.rs` (WebCrypto) and `keystore.rs`
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
  two halves both talk back through), `setup_gate` (what a signed-in
  account with no encryption gets instead of its entries, and the sign-out
  escape from it)
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
- **So is `entry_key_wrap.kind`, and it was changed anyway.** `'recovery'`
  became `'encryption_key'` by editing a shipped migration in place, which
  is safe only against an empty database. See the Encryption section's
  deployment box; do not take it as a precedent for editing another shipped
  migration.
- **The crypto constants are a compatibility surface too, and a quieter one.**
  In `src/crypto/wire.rs`:

  | Constant | Value |
  |---|---|
  | `APP_SALT` | SHA-256 of the ASCII bytes `time-tracking-leptos/entry-key/v1` |
  | passkey HKDF `info` | `tt/entry-kek/passkey/v1` |
  | encryption-key HKDF `info` | `tt/entry-kek/recovery/v1` (the stale `recovery` is deliberate — see below) |
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

  **The `recovery` inside the second `info` string is deliberately stale.**
  "Recovery code" was renamed to "encryption key" everywhere else, including
  the stored `entry_key_wrap.kind` value — but not here, because that string
  is an opaque domain separator no user ever sees, and rewriting it to match
  the new vocabulary would be exactly the silent break described above.

## Design docs

- `docs/superpowers/specs/2026-09-03-leptos-migration-design.md`
- `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
  (its §9.2 and §9.3 are superseded by the one below and marked so in place)
- `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`
  (its §8 migration, its opt-in framing, and the `entries_all` /
  `entry_save_many` rows of §7.6 are superseded by the one below and marked
  so in place — the predictions and why they changed are the useful part)
- `docs/superpowers/specs/2026-09-06-encryption-required-design.md`
