# Client-side encryption (phase 2)

**Status:** design, approved 2026-09-05
**Supersedes:** §9.2 and §9.3 of
`2026-09-04-accounts-and-dated-entries-design.md` (see §1.3 below)

## 1. Goal

Entry bodies stored on the server become ciphertext the server cannot read.
The key exists only in the user's browser, derived from their passkey.

Phase 1 shipped the groundwork deliberately: a version-tagged envelope, a
server that never parses a body, client-side week aggregation, and
`extensions.prf` requested on every credential at creation time. This phase
spends that groundwork.

### 1.1 The three decisions that shape everything

Taken with the project owner on 2026-09-05:

1. **Unlock is passkey PRF; the backup is a one-time recovery code.** No
   passphrase. The recovery code is shown once, at enable, and is the only
   way back in if every passkey is lost.
2. **Encryption is offered when the first PRF-capable passkey is enrolled**,
   not mandatory and not a separate setting. Accounts with no passkey stay
   plaintext and keep working. Accepting re-encrypts all existing rows.
3. **Unlock is once per device.** The data key is kept as a
   **non-extractable** `CryptoKey` in IndexedDB, so reloads and restarts do
   not re-prompt.

### 1.2 Non-goals

- Encrypting signed-out `localStorage` data. There is no key material there
  and the threat this addresses — the operator reading the database — does
  not exist for data that never leaves the browser. `Backend::Local` keeps
  writing `v:1`.
- Hiding *which days* have entries. §9.4 of the phase-1 spec already
  recorded this as accepted: the calendar's dots need it, and hiding it
  would mean fetching every day of the month.
- Multi-user or shared entries. There is one DEK per account.
- Key rotation of the DEK itself. Rotating the *wraps* (add/remove a
  passkey, reissue the recovery code) is supported; re-keying every row is
  not.

### 1.3 Where this departs from the phase-1 spec

Phase 1 §9.2 predicted `alg: "xchacha20poly1305"` and §9.3 assumed an
Argon2id passphrase as the second wrapper. Both change:

| Phase-1 prediction | Actual | Why |
|---|---|---|
| XChaCha20-Poly1305 in wasm | **AES-256-GCM via WebCrypto** | Decision 3 requires a non-extractable key, which is a WebCrypto-only capability, and WebCrypto has no ChaCha. Also costs zero wasm bundle weight and is hardware-accelerated. |
| Argon2id passphrase wrapper | **160-bit recovery code, HKDF** | Decision 1. At 160 bits of entropy a memory-hard KDF buys nothing — Argon2id exists to make *low*-entropy secrets expensive to guess. |
| Per-account PRF salt | **Fixed application salt** | §4.2. A per-account salt would have to be fetched before the assertion, which defeats the one-gesture unlock in §6.2. |

The `alg` field in the envelope exists precisely so this is a recordable
choice rather than a migration. The phase-1 spec is amended in place by this
document; its §9.2/§9.3 text is superseded, not deleted.

## 2. Threat model

**Defended:** an operator, a backup, a stolen database file, or a subpoena
served on the host. None of them yield entry text.

**Not defended, stated so it is a decision rather than a discovery:**

- **Which days a user logged time**, and roughly **how long** each entry is
  (ciphertext length). Carried forward from phase-1 §9.4.
- **Email addresses and sign-in times.** Unavoidable; the server
  authenticates.
- **Script running on the app's own origin.** On a device that has unlocked,
  an XSS can *use* the key to decrypt. It cannot read the key bytes out or
  exfiltrate the key — that is what non-extractable buys — but this is a
  limit on the blast radius, not immunity.
- **A malicious server build.** The server ships the JavaScript. An operator
  who changes the build can capture keys as they are derived. Client-side
  encryption defends against an operator reading data at rest, not against
  one who rewrites the client. Saying otherwise would be dishonest.
- **Rows written before the user enabled encryption**, in the window before
  the migration pass completes. §8.

## 3. What changes

Small blast radius, by design. Phase 1 put the seam in the right place.

**Changed:** `src/storage/envelope.rs` (v2 support, becomes async),
`src/storage/mod.rs` (thread the key handle through `load`/`store`/
`bodies_in_range`), `src/webauthn_browser.rs` (PRF eval on assertion),
`src/server_fns/{passkey,entries}.rs`, `src/components/account_page.rs`,
`src/app.rs` (provide `EncryptionCtx`), `Cargo.toml`.

**New:** `src/crypto/mod.rs`, `src/crypto/wire.rs`, `src/crypto/recovery.rs`,
`src/crypto/subtle.rs`, `src/crypto/keystore.rs`, `src/encryption_ctx.rs`,
`src/entry_key/{mod,store}.rs`, `src/server_fns/encryption.rs`,
`src/components/unlock.rs`, one migration.

**Unchanged, and this is the point:** every component that reads or writes a
day's text. `summary`, `projects`, `time_display`, `time_entry_area`,
`calendar`, `week_view`, `import_banner` and `hook::use_persistent` do not
learn that encryption exists. They hand strings to the storage seam exactly
as before.

## 4. Key hierarchy

```
passkey PRF output (32 bytes, per credential, deterministic)
        │  HKDF-SHA256(salt = APP_SALT, info = "tt/entry-kek/passkey/v1")
        ▼
    KEK (AES-KW 256)  ──unwraps──┐
                                 │
recovery code (160 bits)         ├──►  DEK (AES-256-GCM, non-extractable)
        │  HKDF-SHA256(salt = APP_SALT, info = "tt/entry-kek/recovery/v1")
        ▼                        │            │
    KEK (AES-KW 256)  ──unwraps──┘            │ AES-GCM, fresh 96-bit nonce
                                              ▼
                                        entry body ciphertext
```

### 4.1 Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Body encryption | AES-256-GCM, 96-bit random nonce per write | Nonce is per *write*, never reused. GCM output is `ciphertext ‖ 16-byte tag`, exactly as WebCrypto returns it. |
| Key wrapping | AES-KW (RFC 3394) | Wrapping a 256-bit key yields 40 bytes. AES-KW is authenticated, so a wrong KEK fails to unwrap rather than yielding garbage — see §6.4. |
| Key derivation | HKDF-SHA256 | Both inputs are already high-entropy. |

### 4.2 The salt is a constant

`APP_SALT` is the 32-byte SHA-256 of the ASCII string
`time-tracking-leptos/entry-key/v1`, compiled in.

A per-account random salt was considered and rejected. The PRF secret is
already per-credential, so the salt contributes only domain separation
between applications and between purposes — which a constant provides. A
per-account salt would have to be fetched from the server *before* the
assertion, and at sign-in time the account is not yet known (the discoverable
flow identifies the user *from* the assertion). That would forfeit the
one-gesture unlock in §6.2 to buy nothing.

The two `info` strings provide separation between the passkey and recovery
paths.

### 4.3 Extractability

The DEK is generated **extractable** so it can be wrapped, wrapped once per
route, and then immediately re-imported **non-extractable** for use. The
extractable handle is dropped and never stored. Every subsequent unwrap
(`unwrapKey` with `extractable = false`) produces a non-extractable key.

The one exception: adding a passkey to an already-encrypted account needs the
raw DEK to wrap it under the new KEK. §6.5 handles this by re-deriving an
extractable copy from an existing route at that moment, using it, and
discarding it.

## 5. Data model

### 5.1 Envelope v2

```json
{ "v": 2, "alg": "a256gcm", "n": "<base64 12 bytes>", "ct": "<base64>" }
```

Base64 is standard, with padding (`base64::engine::general_purpose::STANDARD`),
matching the rest of the codebase.

Dispatch is on the row's own `v`, never on account state. A v1 row in an
encrypted account still reads as plaintext. This is what makes a partial
migration safe rather than corrupting.

`envelope::unwrap` already errors on `v: 2` today, and
`unknown_version_is_an_error` pins it. That test is *replaced*, not weakened:
v2 becomes readable, and a new `v: 3` takes over as the unknown-version
case.

### 5.2 Schema

```sql
-- migrations/2026-09-05-000001_entry_key/up.sql
ALTER TABLE user ADD COLUMN encrypted_at TIMESTAMP;

CREATE TABLE entry_key_wrap (
  id            INTEGER   PRIMARY KEY,
  user_id       INTEGER   NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  kind          TEXT      NOT NULL,          -- 'passkey' | 'recovery'
  credential_id BLOB,                        -- set iff kind = 'passkey'
  wrapped_key   BLOB      NOT NULL,          -- 40 bytes, AES-KW
  kdf           TEXT      NOT NULL,          -- 'hkdf-sha256'
  wrap_alg      TEXT      NOT NULL,          -- 'aeskw256'
  created_at    TIMESTAMP NOT NULL
);
CREATE INDEX idx_entry_key_wrap_user ON entry_key_wrap(user_id);
CREATE UNIQUE INDEX idx_entry_key_wrap_cred
  ON entry_key_wrap(user_id, credential_id) WHERE credential_id IS NOT NULL;
```

`user.encrypted_at` is the authoritative "encryption is on" flag. It is set
when the wraps are first written, *before* the migration pass runs, so an
interrupted migration leaves the account correctly marked as encrypted.

`kdf` and `wrap_alg` are recorded per row for the same reason the envelope
carries `alg`: so a future change is a new value rather than a guess.

Deleting a passkey deletes its wrap (§6.6). The recovery wrap has no
`credential_id` and is never deleted, only replaced.

### 5.3 What the server holds

Wrapped key blobs, an algorithm label, and ciphertext. There is no code path
on the server that can produce a DEK, and no server function returns anything
from which one could be derived. The server does not see the recovery code —
only the 40-byte blob wrapped under a key derived from it.

## 6. Ceremonies

### 6.1 Enable

Triggered from `/account` immediately after a passkey is enrolled with
`prf_capable = true`. The panel states plainly what is about to happen and
that the recovery code is the only backup.

1. Client asserts with PRF eval (§7.1) to obtain the PRF output for the new
   credential. **This is a second WebAuthn prompt** — creation does not
   return PRF output, only whether PRF is available.
2. Generate the DEK (extractable) and a 160-bit recovery code.
3. Derive both KEKs; wrap the DEK twice.
4. `encryption_enable(passkey_wrap, credential_id, recovery_wrap)` — one
   server call, one transaction: sets `user.encrypted_at` and inserts both
   wrap rows. Fails if `encrypted_at` is already set.
5. Show the recovery code. The user must actively confirm they have saved it
   before the dialog closes; there is a "copy" control, and the code is never
   shown again.
6. Re-import the DEK non-extractable, store it in the keystore (§7.3), and
   run the migration (§8).

If step 4 fails, nothing has changed server-side and the ceremony is simply
retried. If the browser is closed between 4 and 6, the account is encrypted
with zero rows migrated, which §8 resumes.

### 6.2 Unlock, riding on sign-in

Passkey sign-in already performs an assertion. Injecting `prf.eval` into
*that* assertion means signing in with a passkey unlocks the data in the same
gesture, with no second prompt. This is the reason for the fixed salt (§4.2).

The PRF output is read from `getClientExtensionResults()` in the browser and
never leaves it — `passkey_login_finish` receives only the credential JSON, as
today. The client then fetches its wraps, unwraps the DEK, and stores it.

If the account is not encrypted, the PRF output is discarded and nothing else
happens.

### 6.3 Unlock, explicitly

A magic-link sign-in, or a device whose keystore was cleared, lands
`EncryptionCtx` in `Locked`. `DayView` and `WeekView` render an unlock prompt
in place of the entry area, with two routes: "Use a passkey" (assertion with
PRF eval) and "Use a recovery code".

WebAuthn requires a user gesture, so this cannot happen automatically on page
load. The prompt is the gesture.

### 6.4 Recovery

The user pastes the code. It is normalized (§9.2), HKDF'd to a KEK, and used
to unwrap the recovery wrap. AES-KW is authenticated, so a wrong code fails
the unwrap cleanly — there is no checksum in the code format because the
unwrap *is* the check, and it cannot produce a false positive.

After a successful recovery unlock the DEK is stored in that device's
keystore, so it is a one-time cost per device. Recovery works on a browser
with no PRF support at all.

The user is then offered a freshly generated recovery code, since the old one
has now been typed and possibly copied somewhere careless. Declining is
allowed; the old code keeps working.

### 6.5 Adding a passkey to an encrypted account

Enrolment proceeds as today, then: assert with PRF eval against the *new*
credential to get its PRF output, derive its KEK, wrap the DEK under it,
insert the wrap row.

This needs the raw DEK, which the non-extractable keystore copy cannot
provide. The DEK is therefore re-unwrapped **extractable** from an existing
route in that moment, used, and dropped. If the session is `Locked`, the user
is asked to unlock first.

A passkey enrolled with `prf_capable = false` gets no wrap and cannot unlock.
`/account` says so on that row rather than letting the user believe otherwise.

### 6.6 Removing a passkey

Deletes its wrap row in the same transaction as the credential. The server
**refuses** to delete the last `kind = 'passkey'` wrap while `encrypted_at`
is set, with a message pointing at the recovery code — otherwise a user with
one passkey and a lost code could destroy their own data with a single click.
Removing a non-last passkey is unrestricted.

### 6.7 Lock and sign-out

Both clear the keystore entry. Sign-out already exists and gains one call.
"Lock now" is a control on `/account`.

## 7. Client components

### 7.1 PRF on the assertion — `webauthn_browser`

`authenticate` gains a sibling that takes the PRF salt and returns the PRF
output alongside the credential JSON:

```rust
pub async fn authenticate_with_prf(
    challenge_json: &str,
    prf_salt: &[u8],
) -> Result<(String, Option<Vec<u8>>), WebauthnUserError>
```

Two implementation constraints, both learned from phase 1:

- **The extension is set on the parsed options object, in the browser**, not
  serialized into the challenge JSON on the server. Browser support for
  `prf.eval` inside `parseRequestOptionsFromJSON` is inconsistent; setting
  `options.extensions = { prf: { eval: { first: <Uint8Array> } } }` after
  parsing sidesteps the question entirely. The server's challenge JSON is
  unchanged, which also means `passkey_login_start` needs no edit.
- **The result cannot go through `JSON.stringify`.** `prf.results.first` is
  an `ArrayBuffer`, which stringifies to `{}`. It is read by direct `Reflect`
  access and copied into a `Vec<u8>`. This is why the existing
  `prf_enabled_from_json` host-test trick does not extend to the output;
  see §10.

### 7.2 `src/crypto/` — the crypto layer

Split so that as much as possible is host-testable:

| File | Contents | Testable on host? |
|---|---|---|
| `wire.rs` | Envelope v2 serialization, base64, nonce length constants, `APP_SALT`, HKDF `info` strings | **Yes** — pure |
| `recovery.rs` | Recovery-code generation from 20 random bytes, formatting, normalization, parsing | **Yes** — pure, RNG injected |
| `subtle.rs` | The `SubtleCrypto` calls: `generateKey`, `deriveKey`, `wrapKey`, `unwrapKey`, `encrypt`, `decrypt` | No — browser only |
| `keystore.rs` | IndexedDB put/get/delete of the non-extractable `CryptoKey` | No — browser only |
| `mod.rs` | `SessionKey` handle, orchestration | Partly |

`subtle.rs` follows the idiom `webauthn_browser.rs` already established:
`js_sys::Reflect` against `window.crypto.subtle`, algorithm parameters built
as `js_sys::Object`. This keeps `web-sys` feature growth to the IndexedDB
types only.

### 7.3 `keystore.rs`

IndexedDB database `tt-keys`, object store `keys`, one record under id
`"dek"`:

```
{ user: "<signed-in email>", key: <non-extractable CryptoKey> }
```

`CryptoKey` is structured-cloneable, so a non-extractable key can be stored
and read back while remaining unreadable to script. The stored `user` is
checked on read: a different account signing in on the same browser finds a
mismatch and the record is discarded rather than producing decryption
failures that look like corruption.

### 7.4 `EncryptionCtx`

```rust
pub enum EncryptionState {
    Unknown,     // before the post-hydration probe resolves
    Disabled,    // account has no encryption
    Locked,      // encrypted, no key on this device
    Unlocked,    // key available
}
```

Provided at the app root beside `AuthCtx`. `DayView` and `WeekView` mount the
entry area only in `Disabled` and `Unlocked`; `Locked` renders the unlock
prompt; `Unknown` renders blank.

It resolves after hydration, in one `Effect` that reruns whenever
`AuthCtx::user` changes. Signed out → `Disabled` without a server call.
Signed in → `encryption_status()`; if that reports the account is not
encrypted, `Disabled`; otherwise read the keystore, and land on `Unlocked`
or `Locked` according to whether a key for this user was found. That
`Effect` takes a `Generation` token like every other async effect in this
codebase — sign-in and sign-out can flip the backend mid-flight, and only the
newest probe may publish.

**The server always renders `Unknown`.** It could read `encrypted_at`
cheaply, but rendering `Locked` would put user-derived state in the SSR body,
and the client cannot know locked-from-unlocked without an async IndexedDB
read anyway — so the first client render would differ regardless. `Unknown`
on both sides is the only value that hydrates. This is the same reasoning as
the existing entry tri-state, and the same reasoning that keeps
`ssr_omits_loaded_state` passing.

### 7.5 The storage seam

`envelope::wrap`/`unwrap` become async and take `Option<&SessionKey>`:
`None` writes v1, `Some` writes v2. `load`, `clear`, `dates_with_entries` and
`bodies_in_range` are already `async`.

`store` is **not** an `async fn` — it is a plain fn returning
`impl Future`, and its doc comment says why: `value` is copied into an owned
`String` *before* the `async move`, because `Persistent::set` hands the future
to `spawn_local`, which requires `'static`. That property must survive. The
`envelope::wrap` call moves inside the async block; the `let value =
value.to_owned()` stays outside it.

### 7.6 Server-function inventory

Every one of these moves opaque blobs. None can derive a DEK.

| Function | Signature | Notes |
|---|---|---|
| `encryption_status` | `() -> Result<EncryptionStatus>` | `{ enabled: bool, unmigrated_hint: bool }`. Cheap; called on every post-hydration probe. |
| `encryption_wraps` | `() -> Result<Vec<WrapRow>>` | The signed-in user's wraps: `kind`, `credential_id`, `wrapped_key`, `kdf`, `wrap_alg`. |
| `encryption_enable` | `(passkey_wrap: Vec<u8>, credential_id: Vec<u8>, recovery_wrap: Vec<u8>) -> Result<()>` | One transaction: sets `encrypted_at`, inserts both rows. Errors if already enabled. |
| `encryption_add_passkey_wrap` | `(credential_id: Vec<u8>, wrapped_key: Vec<u8>) -> Result<()>` | §6.5. Rejects a credential that is not the caller's. |
| `encryption_replace_recovery_wrap` | `(wrapped_key: Vec<u8>) -> Result<()>` | §6.4's re-issue. Replaces the single recovery row. |
| `entries_all` | `() -> Result<Vec<(String, String)>>` | §8. Opaque strings. |
| `entry_save_many` | `(entries: Vec<(String, String)>) -> Result<()>` | §8. One transaction. Same per-body length cap as `entry_save`. |

`passkey_delete` (existing) gains the §6.6 refusal and deletes the matching
wrap in the same transaction.

## 8. Migrating existing rows

Two round trips, resumable, no schema change:

1. `entries_all()` — every `(date, stored_string)` for the user, one call.
2. Client filters for rows whose envelope is `v: 1`, decrypts nothing,
   encrypts each body, and calls `entry_save_many(Vec<(date, body)>)` — one
   call, one transaction.

Resumability falls out of §5.1: dispatch is per-row, so re-running the pass
simply finds fewer v1 rows. If the migration is interrupted, `/account` shows
"N days still unencrypted" and offers to finish.

`entries_all` returns the whole account in one response. For this
application's data volume that is the right trade against the alternative
(a per-row round trip, or a server that inspects envelope versions and thus
parses bodies — forbidden by §9.1 of the phase-1 spec).

The import banner needs no change: imported local entries pass through
`storage::store`, which encrypts them because the seam does.

## 9. Formats

### 9.1 Recovery code

160 bits from `crypto.getRandomValues`, Crockford base32, 32 characters,
displayed in eight groups of four:

```
K7M2-9XQR-4TVB-8HJN-3PWD-6ZFG-2SCY-5NKA
```

### 9.2 Normalization

Applied before use, host-tested as a table:

- Strip whitespace and hyphens
- Uppercase
- Crockford aliases: `I`, `L` → `1`; `O` → `0`
- Reject anything not in the Crockford alphabet, and any length but 32

No checksum: AES-KW's authenticated unwrap is the check (§6.4), and a
checksum would be a second thing to get wrong for no gain.

## 10. Testing strategy

WebCrypto exists only in a browser and this project has no wasm test runner.
That limit is stated here rather than argued away, per the project's rule
that "no test needed because of invariant X" is a red flag.

**Host-tested (ordinary `cargo test`):**

- Envelope v2 round-trip, field shape, base64, and version dispatch.
- **Cross-implementation wire-format tests.** AES-256-GCM, AES-KW and
  HKDF-SHA256 are standard, so dev-dependencies on `aes-gcm`, `aes-kw`,
  `hkdf` and `sha2` let the host decrypt an envelope the browser would have
  produced, and produce one the browser must be able to read. This pins the
  *format* — nonce placement, tag inclusion, base64 alphabet, HKDF `info`
  strings, `APP_SALT` — against a second implementation rather than against
  itself.
- Recovery-code generation (RNG injected), formatting, normalization table,
  and every rejection case.
- Wrap-route selection: which wrap to try given a credential id and the
  available rows.
- The migration's "which rows still need encrypting" decision, as a pure
  function over `(date, stored_string)` pairs.
- Every server function, repository, and the last-passkey-wrap refusal
  (§6.6), via the existing `TestApp` harness.
- `EncryptionState` transitions and the SSR-renders-`Unknown` assertion,
  extending `app.rs`'s existing negative SSR tests.

**Inspection-only, listed so it is visible:**

- The `subtle.rs` calls themselves — did we pass the right algorithm object
  to `deriveKey`, is `extractable` false on the right call.
- `keystore.rs`'s IndexedDB event plumbing.
- Reading `prf.results.first` out of `getClientExtensionResults()` (§7.1).

Each of these is kept to the thinnest shell that can hold the call, with the
decision above it extracted and tested. This is the same technique phase 1
used for `prf_enabled_from_json` and `local::resolve_load`.

**Manual smoke test**, required before release, because none of the above
covers the click-through: enable on a real authenticator, confirm the
recovery code screen, watch the migration complete, reload and confirm no
re-prompt, sign out and back in via magic link, unlock with the recovery
code, add a second passkey, remove the first, and confirm the last-passkey
refusal fires.

## 11. Invariants this feature depends on

Written down so a later change touching one of these can find who relies on
it — the phase-1 spec's §10 convention.

- **E1. The server never parses an entry body.** Inherited from phase-1
  §9.1 and now load-bearing rather than aspirational: `entries_all` returns
  opaque strings and the migration's version filtering happens in the
  browser. *Guarded by:* the absence of any body-inspecting server code, plus
  the existing week-aggregation-is-client-side tests.
- **E2. SSR renders no entry content and no encryption state.** *Guarded by:*
  `ssr_omits_loaded_state`, `ssr_omits_entry_content_even_when_signed_in`,
  and a new `ssr_renders_unknown_encryption_state`.
- **E3. Envelope dispatch is per-row, on the row's own `v`.** Partial
  migration correctness rests entirely on this. *Guarded by:* mixed-version
  round-trip tests.
- **E4. `store` copies its value before the `async move`.** Pre-existing;
  `spawn_local` needs `'static`. *Guarded by:* compilation, and the doc
  comment saying so.
- **E5. The DEK is never stored extractable and never sent to the server.**
  *Guarded by:* inspection of `subtle.rs` and `keystore.rs`, plus the
  absence of any server function accepting key material. This is the
  weakest-guarded invariant in the list and the one most worth re-reading in
  review.
- **E6. `APP_SALT` and the two HKDF `info` strings never change.** Changing
  one silently makes every existing wrap unopenable. *Guarded by:*
  constant-pinning tests that assert their exact bytes, in the same spirit as
  `legacy_key_matches_the_dioxus_key`.

## 12. Failure modes

| Situation | Behaviour |
|---|---|
| Enable interrupted after wraps written | Account encrypted, 0 rows migrated. `/account` offers to finish. All rows still readable. |
| Migration interrupted | Mixed v1/v2. All rows readable. Resumes on demand. |
| Wrong recovery code | AES-KW unwrap fails; "That recovery code didn't work." No lockout counter — the code is 160 bits. |
| Passkey lost, code lost | Data is unreadable, permanently, by everyone. Stated in the enable dialog in those words. |
| Keystore cleared (private window, site data cleared) | `Locked`. Unlock re-populates it. |
| Authenticator without PRF | Cannot unlock by passkey; recovery code works. `/account` labels the row. |
| v2 row reaching a pre-phase-2 client | `UnsupportedVersion(2)` — a loud error, never rendered as text. Already tested. |
