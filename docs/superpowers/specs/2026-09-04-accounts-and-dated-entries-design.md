# Accounts, Passkeys, and Dated Entries — Design Spec

**Date:** 2026-09-04
**Status:** Approved, ready for implementation
**Supersedes nothing.** Extends `2026-09-03-leptos-migration-design.md`, whose
§5 (the hydration contract) and §6 (the storage seam) this design builds on
directly rather than replacing.

## 1. Summary

Adds optional accounts to the time tracker: sign in by email magic link,
manage passkeys, and keep one entry per calendar day on the server instead of
a single blob in `localStorage`. The date being viewed lives in the URL; a
calendar picker changes it; a read-only week view aggregates a range.

Three things stay true that shape everything else:

1. **The app still works signed out.** `localStorage` remains a first-class
   backend, not a degraded mode. No account is required to use the tool.
2. **The server never renders entry content.** It is structurally blind to
   what a user typed, today by convention and next phase by cryptography.
3. **Phase 2 is end-to-end encryption the server cannot undo.** Every choice
   here is checked against "does this still work when the server cannot read
   the body?" — §9 lists what that forbids.

Storing bodies as plaintext is a deliberate, temporary phase-1 position. §9
defines the envelope that makes phase 2 an additive change rather than a
migration.

## 2. Goals and non-goals

**In scope**

- Email magic-link sign-in, and sign-out.
- Passkey enrolment, listing, rename, delete, and passkey sign-in.
- An `/account` page hosting passkey management.
- One server-side entry per `(user, date)`; date carried in the URL.
- A calendar picker that marks which days have entries.
- A read-only `/week/:date` summary aggregating a week.
- A range API returning opaque rows.
- One-time import of on-device entries when a user first signs in.

**Explicitly out of scope (phase 2 or later)**

- Any encryption of stored bodies. Phase 1 writes plaintext.
- Passphrase entry, key derivation, key wrapping, or key rotation.
- Account deletion, email change, data export.
- Sharing, multi-user projects, or any read path across users.
- Offline editing and conflict resolution. Last write wins, silently.
- A month *view*. The calendar queries a month-wide range to place its dots
  (§8.4), but there is no month summary page; only week aggregation is
  specified.

## 3. Decisions taken during brainstorming

Recorded so a later reader knows these were chosen, not defaulted into.

| # | Decision | Rejected alternative |
|---|---|---|
| D1 | `localStorage` stays the signed-out store; on first sign-in, offer to import on-device entries | Requiring sign-in; silent backend switch |
| D2 | `/` means today, resolved **client-side**, then router-replaced to `/YYYY-MM-DD` | Server-side "today" from a `TZ` env var |
| D3 | Direct `lettre` SMTP send, spawned off the request path | Porting photo365's 1250-line durable outbox |
| D4 | Range API feeds **both** calendar dots and a read-only week view | Shipping the API with no consumer |
| D5 | Slim app header: title left, date centre, account right | Floating avatar with no header |
| D6 | Sign-in in a corner popover; passkeys on an `/account` route | Everything in the popover; a modal |
| D7 | Legacy `time_entry` key is read as an alias for today until first rewrite | One-time migration; orphaning it |
| D8 | Session token: full HMAC-SHA256, expiry, revocable epoch | Porting photo365's 48-bit `X-Login` verbatim |
| D9 | Request the WebAuthn PRF extension now; plan a passphrase fallback | Deciding key derivation in phase 2 |

### 3.1 A stale note in the crate-decisions file

`~/.claude/rust-crate-decisions.md` says to prefer `webauthn-rp` over
`webauthn-rs` because the latter forces OpenSSL into the graph. That is no
longer true as of `webauthn-rs` 0.6: it uses `crypto-glue` (RustCrypto), and
photo365's `Cargo.lock` contains no `openssl` or `openssl-sys` — only
`openssl-probe`, pulled by `rustls-native-certs` and unrelated.

This project therefore uses **`webauthn-rs` 0.6.1-dev**, matching photo365,
which makes the ceremony code a near-verbatim port rather than a rewrite.
The crate-decisions file should be updated separately; that is not this
change's job.

## 4. Data model

SQLite via Diesel, `r2d2` pool, PRAGMAs (`busy_timeout` **first**, then
`journal_mode=WAL`, `foreign_keys=ON`) applied by a `CustomizeConnection`
customizer, and `diesel_migrations::embed_migrations!` run at boot. This
mirrors `photo365/src/db.rs`, including the `:memory:` single-connection
special case that makes in-memory test pools share one schema.

### 4.1 Tables

```sql
-- 0001_user
CREATE TABLE user (
  id            INTEGER PRIMARY KEY,
  email         TEXT    NOT NULL,   -- normalized: trimmed, lowercased
  session_epoch INTEGER NOT NULL DEFAULT 0,
  created_at    TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_user_email ON user(email);

-- 0002_time_entry
CREATE TABLE time_entry (
  user_id    INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  entry_date TEXT    NOT NULL,      -- 'YYYY-MM-DD', lexically sortable
  body       TEXT    NOT NULL,      -- opaque envelope; see §9.2
  updated_at TIMESTAMP NOT NULL,
  PRIMARY KEY (user_id, entry_date)
);
CREATE INDEX idx_time_entry_user_date ON time_entry(user_id, entry_date);

-- 0003_magic_link_token
CREATE TABLE magic_link_token (
  id         INTEGER PRIMARY KEY,
  token_hash BLOB    NOT NULL,      -- SHA-256 of the token; never the token
  email      TEXT    NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at    TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX idx_magic_token_hash ON magic_link_token(token_hash);

-- 0004_passkey_credential
CREATE TABLE passkey_credential (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  credential_id BLOB    NOT NULL,
  passkey       BLOB    NOT NULL,   -- serde_json, not bincode; see §6.3
  name          TEXT,
  prf_capable   BOOLEAN NOT NULL DEFAULT 0,   -- see §9.3
  created_at    TIMESTAMP NOT NULL,
  last_used_at  TIMESTAMP
);
CREATE UNIQUE INDEX idx_passkey_credential_id ON passkey_credential(credential_id);
CREATE INDEX idx_passkey_user ON passkey_credential(user_id);
```

`entry_date` is `TEXT` rather than `DATE`: SQLite has no date type, ISO-8601
strings sort correctly under `BETWEEN`, and it keeps the Diesel mapping
`String`-simple with `NaiveDate` conversion at the repository boundary.

Two divergences from photo365, both deliberate:

- Passkeys hang off `user_id`, not a free-text `subject` column. photo365
  keys passkeys by email string; a real foreign key means a user row is the
  single identity anchor, which matters once phase 2 attaches wrapped keys.
- `magic_link_token` stores a **SHA-256 of the token**, never the token. A
  database leak then does not hand an attacker fifteen minutes of live
  sign-in links. Lookup hashes the presented token and matches on that.

### 4.2 Identity

`email` is normalized by trimming and ASCII-lowercasing, nothing more. No
provider-specific canonicalization (gmail dot-stripping and the like) —
photo365 needed that to deduplicate customers across checkout flows; here two
spellings of an address are simply two accounts, which is surprising to nobody
and avoids a dependency.

User rows are created **lazily on first successful magic-link consume**, never
by requesting a link. This is what keeps `request_magic_link` free of an
account-enumeration signal (§5.2).

## 5. Authentication

### 5.1 Session token

Cookie `tt_session`, `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` outside
debug builds, `Max-Age` 30 days.

```
v1.<base64url(email)>.<issued_unix>.<expires_unix>.<epoch>.<hmac_hex>
```

HMAC-SHA256 over the preceding dot-joined fields, full width (not truncated),
keyed by `SESSION_KEY`, compared in constant time.

Verification is deliberately **two-tier**:

- `SessionClaims::verify(raw) -> Option<SessionClaims>` is stateless: signature,
  `issued <= now + 5s` skew, `now < expires`. No database access. This is all
  the page shell needs to render the account corner.
- `require_user(ctx, &claims) -> Result<User>` loads the user row and rejects
  when `claims.epoch != user.session_epoch`. Every server fn that touches
  entry data calls this.

The split is the point: rendering a page costs no query, while revocation is
still real. "Sign out everywhere" is `UPDATE user SET session_epoch = session_epoch + 1`,
which invalidates every outstanding token for that user on its next data
access.

`SESSION_KEY` handling: required and non-empty in release builds — the binary
refuses to start without it. In debug builds an unset key generates a random
ephemeral key and logs a prominent warning; sessions then do not survive a
restart, which is correct for `cargo leptos watch` and unacceptable in
production.

`SESSION_KEY` is a **distinct secret** from any WebAuthn or ceremony key.
photo365 reuses one `HASH_KEY` across login tokens, magic links, and passkey
ceremony state; separate keys per purpose means compromising one does not
forge the others.

### 5.2 Magic link

`request_magic_link(email)` — a server fn:

1. Normalize; reject syntactically impossible addresses.
2. Rate-limit (§5.4). Over quota returns the same `Ok(())` as success.
3. Mint a `uuid::Uuid::now_v7()` token; insert `(sha256(token), email, expires_at = now + 15m)`.
4. `tokio::spawn` the SMTP send. Return immediately.
5. Return `Ok(())` **always** — for an unknown address, a known one, a
   rate-limited caller, and a failed SMTP handshake alike.

The UI therefore always shows "check your email". A uniform response is the
whole enumeration defence; a variant that returns "no such account" undoes it.

`GET /magic/{token}` is a **plain axum handler**, not a Leptos route — it sets
a cookie and redirects, never renders. It consumes the token inside a
transaction whose `UPDATE` carries `used_at IS NULL` in its `WHERE` clause, so
two concurrent clicks race correctly and exactly one wins. On success it
upserts the user row, mints a session, and `303`s to `/`.

Outcomes:

| Case | Response |
|---|---|
| Valid, unused, unexpired | Set cookie, `303` to `/` |
| Exists but used or expired | Mint and send a fresh link, render a plain "we sent you a new link" page |
| No such token | `404` with a neutral message |

The stale-reissue path is ported from photo365 because it removes the single
most common support question — a user clicking yesterday's link. It sends to
the address on the *stored* row, so it leaks nothing to whoever holds the URL
beyond the fact that some link once existed.

### 5.3 Passkeys

Ported from photo365 with the identity change from §4.1. The parts that are
copied deliberately, because each encodes a fix that is expensive to
rediscover:

- **`residentKey: Required` forced onto the challenge.** webauthn-rs emits
  `requireResidentKey: false`, which lets some providers store a
  non-discoverable credential — silently breaking username-less sign-in,
  because the credential never surfaces without an `allowCredentials` list.
- **`src/webauthn_browser.rs` verbatim.** It routes through the browser's
  `parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` / `toJSON`
  rather than hand-rolling base64url. The naive version passes base64url
  strings where the API demands `ArrayBuffer`s; every ceremony fails, and the
  failure surfaces as a misleading "user cancelled".
- **The `__pk_state` ceremony cookie**: HMAC-signed, five-minute expiry, never
  persisted to the database.
- **Uniform failure text.** An unregistered address and a registered address
  with no enrolled passkeys must return the identical error. That equality is
  the enumeration defence, not an aesthetic choice.

Sign-in supports both the discoverable flow ("Use a passkey", no email typed)
and the typed-email flow. Registration requires an existing session.

Deviations from photo365: no conditional-UI autofill, no `login_activity`
table, no observability events, no magic-link-with-passkey-hint landing route.
Those serve photo365's scale and admin surface; here they are cost without
benefit.

### 5.4 Rate limiting

An in-memory token bucket keyed by client IP **and** separately by normalized
email, both applied to `request_magic_link` and passkey ceremony starts.
Without the per-email limit, an attacker rotating IPs can still use the
service to mail-bomb one address.

In-memory is sufficient: this is a single-process app, and a restart clearing
the buckets is not a meaningful attack window for a 15-minute token.

## 6. Server structure

### 6.1 Per-request context

An axum middleware reads the cookie, runs the stateless verify, and inserts an
`AppCtx { pool, mailer, webauthn, claims: Option<SessionClaims> }` into request
extensions. `leptos_axum::handle_server_fns_with_context` and the route handler
both pull it back out and `provide_context` it, so server fns reach it with
`use_context::<AppCtx>()`.

This is also what lets the SSR render know whether the visitor is signed in —
see §8.1, where that turns out to be load-bearing.

### 6.2 Server functions

| Function | Auth | Returns |
|---|---|---|
| `current_session()` | none | `Option<String>` (email) |
| `request_magic_link(email)` | none | `Ok(())` always |
| `logout()` | none | `Ok(())`, clears cookie |
| `sign_out_everywhere()` | required | bumps `session_epoch` |
| `entry_load(date)` | required | `Option<String>` envelope |
| `entry_save(date, body)` | required | `Ok(())`, upsert |
| `entry_dates_in_range(from, to)` | required | `Vec<NaiveDate>` — **dates only** |
| `entries_in_range(from, to)` | required | `Vec<(NaiveDate, String)>` opaque |
| `passkey_register_start/finish` | required | challenge / `Ok(())` |
| `passkey_login_start/finish` | none | challenge / `Ok(())` |
| `passkey_list / rename / delete` | required | rows / `Ok(())` |

`entry_dates_in_range` is separate from `entries_in_range` on purpose. The
calendar needs only "which days have something"; giving it a function that
returns bodies would ship every body in the visible month to satisfy a dot.
Two functions, least data each.

Every data function calls `require_user` and scopes its query by `user_id`.
Deletes and renames carry `user_id` **inside the `WHERE` clause** rather than
checking ownership first — no row matches, no change, no TOCTOU window.

### 6.3 Diesel and `Passkey` serialization

The `passkey` blob is `serde_json`, **not** bincode. `Passkey` flattens a
`BTreeMap<String, serde_cbor_2::Value>` of unknown extension keys, which needs
a self-describing format; bincode calls `deserialize_any` on the flattened map
and fails at runtime. photo365 has this comment in its store; it is repeated
here because the failure appears only when a real authenticator returns an
extension.

## 7. The storage seam

§6 of the migration spec built this API async specifically so a server backend
could drop in "without touching any component". This is that moment, and the
prediction mostly holds — components keep their signatures and the tri-state.
Two things do change.

### 7.1 Keys gain a date

```rust
pub enum StorageKey {
    TimeEntry(NaiveDate),
}

impl StorageKey {
    pub fn as_key(self) -> String {
        match self {
            StorageKey::TimeEntry(d) => format!("time_entry:{}", d.format("%Y-%m-%d")),
        }
    }
}
```

`as_key` returns `String`, not `&'static str`. The existing
`storage_key_matches_dioxus_key` test is rewritten, not deleted: it now pins
both the dated format and the legacy constant.

### 7.2 The legacy alias (D7)

`LEGACY_KEY = "time_entry"` — the key every current user's data sits under.
`local::load` applies it under three conditions, all required:

1. The dated key holds nothing, **and**
2. the requested date is the browser's today, **and**
3. `time_entry` holds a decodable value.

Then it returns the legacy value. The next `store` writes the dated key and
removes `time_entry`, so the alias is self-erasing after one edit.

Filing the legacy blob under "today" is a guess — the text was typed on some
earlier day. It is the right guess because it is *visible*: the user opens the
app, sees their text where they left it, and can move it. A one-time migration
at boot (the rejected D7 alternative) makes the same guess silently, on
whatever day they happen to next open the app, which may be weeks later.

### 7.3 Backends

```rust
pub enum Backend { Local, Remote }
```

`load`/`store`/`clear` take a `Backend`. `Remote` calls server fns; `Local`
keeps today's `web_sys` path. Under `ssr` both remain no-ops returning
`Ok(None)` — the server has neither `localStorage` nor, by §9.1, permission to
resolve a remote read during render.

### 7.4 The hook becomes reactive

```rust
pub fn use_persistent(
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
) -> Persistent
```

Both arguments are signals because both change during a session: the key when
the user picks a date, the backend when they sign in or out. The existing
`Effect` already re-runs on signal change; what is new is that it must
**reset the value to `None` before loading**. Skipping that reset shows the
previous day's text under the new day's heading until the load resolves —
the exact wrong-content flash the tri-state exists to prevent.

`Persistent`'s public surface (`get`, `set`, `clear`) and the `Option<String>`
tri-state are unchanged. No component signature changes.

### 7.5 Importing on-device entries (D1)

Signing in switches the backend from `Local` to `Remote`, which would
otherwise make a user's on-device work appear to vanish. After a session is
established, the client:

1. Scans `localStorage` for `time_entry:*` keys, plus the legacy key (which is
   attributed to the day it is aliased to, per §7.2).
2. Calls `entry_dates_in_range` over the span those keys cover.
3. Offers to import only the days **absent** from that result.

The offer is a single inline banner under the header — "Import N days from
this device?" with import and dismiss — not a per-day prompt. Import calls
`entry_save` per day and leaves the local copies in place; nothing is deleted,
so a failed import loses nothing and a user who signs out still has their
data.

Both outcomes write a `time_entry_import_done` flag to `localStorage`, so the
banner appears at most once per device. It is scoped per device rather than
per account because it describes *this browser's* leftovers.

Days that already exist server-side are never overwritten. That rule is what
makes the operation safe to offer without a confirmation dialog: a second
device signing in cannot clobber the first device's work with a stale local
copy.

## 8. Dates, routing, and the "today" problem

### 8.1 Resolving today (D2)

The server cannot know the browser's timezone, so `/` cannot be rendered as a
specific date without being wrong for somebody near midnight. `/` therefore
renders the date slot **blank**, exactly as the summary panel already renders
blank before storage is read; after hydration the browser resolves its local
today and issues a router replace to `/YYYY-MM-DD`.

This extends an existing pattern rather than introducing one. It costs a brief
blank date on a cold load of `/`; a deep link to `/2026-09-04` renders its
date server-side immediately, because there the date is knowable.

### 8.2 Routes

| Route | Handler |
|---|---|
| `/` | Today, client-resolved, replaces to the dated URL |
| `/:date` | The day view. Non-parsing segments render `NotFound` |
| `/week/:date` | Read-only week summary; any day in the week |
| `/account` | Passkey management |
| `/magic/{token}` | axum handler, not a Leptos route |

### 8.3 A trap this introduces

The migration spec notes the static-file fallback is "safe as a fallback
because the app mounts no wildcard route that could shadow it." **`/:date`
shadows it.** A request for `/favicon.ico` matches the date param route and
renders the app instead of the icon.

Mitigation: register `/favicon.ico` and the asset paths explicitly *before*
`leptos_routes`, so axum's more-specific static segments win, and keep the
fallback for everything else. This gets an integration test asserting
`/favicon.ico` returns image bytes — the failure is silent and cosmetic enough
to survive a casual review.

Route priority between `/account` and `/:date` gets its own test for the same
reason.

### 8.4 The calendar

A popover anchored to the date control. It fetches the visible month
(`entry_dates_in_range` when signed in, a `localStorage` key scan when not)
and marks days that have entries. `‹` and `›` step one day. Changing the date
is a router navigation; nothing else drives it, so the URL is always the
single source of truth for which day is on screen.

### 8.5 The week view

`/week/:date` resolves to the ISO week (Monday start) containing `date`. It
fetches raw rows via `entries_in_range`, parses **each day's body in the
browser** with `time_tracking_parser`, and renders per-project totals across
the week plus a per-day total. Read-only; editing happens on the day view.

That the parsing happens client-side is not an implementation detail — see
§9.1.

## 9. The encryption trajectory

Phase 2 encrypts entry bodies so that the operator cannot read them. Phase 1
does not encrypt anything, but it must not foreclose that. This section is the
contract phase 2 depends on.

### 9.1 What the server may never do

**The server must never parse, aggregate, search, validate, or render an entry
body.** It stores and returns opaque strings.

Three consequences, all already reflected above:

- Week aggregation is client-side (§8.5). A server-side weekly total would be
  impossible to keep in phase 2 and would have to be rewritten.
- The server does not render entry content during SSR, even for a signed-in
  user whose rows it could trivially read (§10.1).
- `entry_save` performs no validation of `body` beyond a length cap.

### 9.2 The envelope

Bodies are stored as a versioned JSON envelope from day one:

```json
{ "v": 1, "alg": "none", "body": "11:45-12:15 code1\n- ..." }
```

Phase 2 writes `{"v":2,"alg":"xchacha20poly1305","n":"<base64>","ct":"<base64>"}`
and reads both. Without the version tag, phase 2 must guess whether each row
is plaintext or ciphertext — a guess that is wrong exactly when a body happens
to look like base64.

The envelope is applied at the storage seam, so both backends store the same
shape and a future export moves between them unchanged. Note this is a
*second* encoding layer above `storage/codec.rs`'s gloo-compatible JSON
string encoding on the `localStorage` side; the codec's compatibility
contract is untouched.

### 9.3 Passkey PRF (D9)

Phase 2 generates a random data key and wraps it twice: once under a key
derived from the WebAuthn PRF extension, once under an Argon2id passphrase
key. Either unwraps the data; the server sees only wrapped blobs.

The PRF extension must be requested when a credential is **created** — it
cannot be added to an existing one. Phase 1 therefore:

- Injects `extensions: { prf: {} }` into the serialized creation challenge,
  the same post-processing step that already forces `residentKey: Required`.
  webauthn-rs 0.6 does not expose PRF in its typed API.
- Extends `webauthn_browser::register` to also return
  `getClientExtensionResults()`. `toJSON()` omits extension results, so
  without this the PRF-enabled flag is invisible.
- Persists `prf_capable` on the credential row.

Nothing reads `prf_capable` in phase 1. It exists so phase 2 can tell which
credentials can unlock data without forcing every user to delete and re-enrol
every passkey.

### 9.4 What phase 1 knowingly leaks

Stated so it is a decision rather than a discovery:

- **Which days a user logged time**, via `entry_dates_in_range` and the row
  existence it reports. Phase 2 does not fix this; hiding it would mean
  fetching every day of the month to render dots.
- **Body length**, approximately, via ciphertext length in phase 2.
- **Email addresses and sign-in times**, unavoidably.
- **Every body, to the operator, for the whole of phase 1.**

## 10. Invariants this feature depends on

Each is stated with the test that pins it. A test skipped because "invariant X
makes it safe" is an unguarded dependency on X; these are the ones this feature
would otherwise acquire.

**I1 — The server renders no entry body, signed in or not.**
The existing `ssr_omits_loaded_state` covers the signed-out case only. It is
extended with a case that renders the app **with a valid session in context**
and asserts no body text and no computed total appears. Without this, a later
"why not SSR the data, we have it" change passes every existing test and
silently makes phase 2 impossible.

**I2 — The tri-state survives a key change.**
Not covered the way an earlier draft of this entry claimed. This project has
no wasm/reactive test runner, so there is no cheap way to mount
`use_persistent`'s `Effect` and assert on the signal it drives — a test that
"changes the key signal and asserts the value returns to `None` before the
next load resolves" does not exist and cannot be written cheaply here. What
*is* tested, in `src/storage/mod.rs`'s `tests` module, is the `Generation`
counter in isolation (`a_stale_load_does_not_overwrite_a_newer_one`,
`a_single_load_is_always_current`): given two tokens, the newer one is
current and the older one is not. Those tests exercise `Generation` alone —
not `use_persistent`'s `Effect`, which is what actually calls
`Generation::next` and `set_value.set(None)` on every key/backend change
(`src/storage/hook.rs`). A wrong-order token capture, a dropped
`set_value.set(None)` reset, or a dropped `is_current` gate in that `Effect`
would compile and leave every existing test green. The `Effect` is guarded by
inspection, not by a test. Guards the stale-content flash from §7.4.

**I3 — The legacy alias is read-only and self-erasing.**
Tests: legacy value surfaces for today; does *not* surface for another date;
does not surface once a dated value exists; is removed after the first write.

**I4 — Static assets outrank the date route.**
An integration test that `/favicon.ico` returns image bytes and `/account`
renders the account page (§8.3).

**I5 — `request_magic_link` is uniform.**
A test asserting byte-identical responses for an unknown address, a known
address, and a rate-limited caller.

**I6 — Passkey failures are indistinguishable.**
A test asserting the identical error for an unregistered email and a
registered email with no enrolled passkeys.

**I7 — Data access is scoped by `user_id` in the query.**
Tests attempting cross-user read, rename, and delete, asserting no rows change.

**I8 — Envelope round-trips and is version-tagged.**
A test that a stored body decodes to `{"v":1,"alg":"none"}` and that an
unknown `v` is an error rather than a silent misread.

**I9 — Import never overwrites a server-side day.**
A test that importing a device holding a local entry for a date that already
exists server-side leaves the server row untouched (§7.5). This is what makes
the import safe without a confirmation step; a regression here destroys real
work on a second device and would otherwise be caught only by a user.

## 11. Testing strategy

Following the existing suite's shape: host-testable logic in unit tests,
`--features ssr` for anything touching the server, no wasm test runner.

- **Pure/host:** envelope codec, session token issue/verify (expiry, skew,
  tampering, epoch mismatch), key formatting, ISO-week arithmetic, email
  normalization, rate-limit buckets.
- **Database:** `:memory:` pool per test with migrations applied. Entry upsert,
  range queries at boundaries (first and last day inclusive), magic-link
  consume including the concurrent-consume race, passkey CRUD, cross-user
  scoping (I7).
- **SSR render:** extends `render_app()`. The helper currently provides only
  `RequestUrl`; it gains an optional session context so I1's signed-in case
  can render. CLAUDE.md's note that it omits `ResponseOptions` and
  `ServerMetaContext` still applies and is still benign.
- **Integration (axum):** `/magic/{token}` happy path, replay, expiry;
  cookie attributes; route priority (I4).
- **Passkey ceremonies:** `webauthn-authenticator-rs`'s `SoftPasskey`, as
  photo365 does, so registration and authentication are exercised end to end
  without a browser.

The wasm-only paths — `webauthn_browser`, the `localStorage` backend — stay
verified by their host-testable seams plus manual check, matching the existing
project's position.

**Lint coverage gap.** Those host-testable seams live in modules gated
`#[cfg(any(feature = "hydrate", test))]` — `src/storage/local.rs`,
`src/webauthn_browser.rs`, and part of `src/storage/mod.rs`. The project's
documented lint command, `cargo clippy --features ssr --no-default-features`,
compiles neither `hydrate` (off, by the flags) nor `cfg(test)` (off, because a
bare `clippy` invocation isn't `--all-targets` or `cargo test`), so it never
lints them. The actual minimum is `cargo clippy --features ssr
--no-default-features --all-targets -- -D warnings` (which turns `cfg(test)`
on) plus a `--target wasm32-unknown-unknown --features hydrate` pass (which
turns `hydrate` on instead) — together they cover both halves of the `any(...)`
gate. CLAUDE.md's Commands table documents both as required, not optional.

## 12. Configuration

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` | no | SQLite path; default `./data/time-tracking.db` |
| `SESSION_KEY` | **release only** | Session HMAC key; ephemeral in debug |
| `SITE_BASE_URL` | yes for email | Absolute base for magic-link URLs |
| `SMTP_HOST/PORT/USER/PASS/FROM` | no | Unset disables sending, logs a warning |
| `WEBAUTHN_RP_ID/ORIGIN/NAME` | no | Defaults suit `localhost:3000` |
| `MAGIC_LINK_TTL_SECONDS` | no | Default 900 |

Unset SMTP is a supported development mode: links are logged rather than sent.
It must not be reachable in release without a warning on every send.

## 13. Acceptance criteria

1. Signed out, the app behaves as it does today, including for a user whose
   data is under the legacy key.
2. A user can request a link, click it, and be signed in; the link fails on a
   second click.
3. A signed-in user can enrol a passkey, rename it, delete it, and sign in
   with it on a fresh session.
4. Entries save per day; navigating between dates loads the right entry with
   no flash of the previous day's text.
5. The calendar marks days with entries, signed in and signed out.
6. `/week/:date` totals the week, computed in the browser.
7. On first sign-in with on-device entries, the import prompt appears once,
   imports days whose server rows are empty, and does not reappear.
8. `cargo clippy --features ssr --no-default-features` is clean; the wasm
   target builds; the full suite passes.
9. Every invariant in §10 has a failing-first test.

## 14. Risks

- **Scope.** This is materially larger than the migration. The plan orders
  tasks so auth, dates, and the week view land in sequence, each usable alone.
- **Route shadowing (§8.3).** Silent when wrong. Pinned by I4.
- **PRF availability.** The extension may be refused; `prf_capable` is then
  `false` and phase 2 falls back to the passphrase. Phase 1 behavior is
  unaffected either way.
- **SMTP in production.** A spawned send that fails is only logged. Acceptable
  for a 15-minute re-requestable link; revisit if support load says otherwise.
