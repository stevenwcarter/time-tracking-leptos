# Encryption Required Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server accepts only encrypted entries. An account either has encryption enabled or it cannot write, and signing in without it lands on setup rather than a day view that would refuse to save.

**Architecture:** Enforcement is a check on `user.encrypted_at`, never on a body — the server must not learn what an entry contains (invariant E1). The migration and every server-side plaintext write route are deleted rather than gated. "Recovery code" is renamed to "encryption key" throughout, because it was never single-use.

**Tech Stack:** Leptos 0.8 SSR + hydration, Axum, Diesel/SQLite, WebCrypto and IndexedDB via `js_sys`/`web-sys`.

**Spec:** `docs/superpowers/specs/2026-09-06-encryption-required-design.md`

---

## Global Constraints

**Verification — all five must pass before any task is done:**

```
cargo fmt --all                       # imperative, not --check; there is no pre-commit hook
cargo check --no-default-features
cargo test --features ssr --no-default-features
cargo clippy --features ssr --no-default-features --all-targets -- -D warnings
cargo clippy --lib --target wasm32-unknown-unknown --no-default-features --features hydrate -- -D warnings
cargo fmt --all -- --check
```

**Run the test suite in the FOREGROUND and read its output.** Do not background it and wait on a monitor — three agents in the previous run stalled that way and had to be recovered by hand. Report the per-binary count from your own run; the baseline is **319 passing**.

**The four SSR guards must pass unweakened** — `ssr_omits_loaded_state`, `ssr_omits_entry_content_even_when_signed_in`, `ssr_renders_unknown_encryption_state`, and the encryption panel's own. They assert negatively and guard the hydration contract. Do not adjust one to make a change compile.

**Invariant E1 is absolute.** The server never parses, aggregates, searches, or renders an entry body. Every enforcement decision in this plan reads `user.encrypted_at`; none reads an envelope. If you find yourself wanting to check a body's version server-side, stop and report it.

**Code conventions:**
- Edition 2024. No `unsafe` — this crate deliberately has none.
- `gen` is a reserved word.
- `Either`/`EitherOf3` for branch polymorphism, never `.into_any()`.
- Tailwind v4 CSS-first: no config file, no npm step, no `@theme` block.
- Diesel transaction closures need an explicit error type or you get E0283: `conn.transaction::<_, diesel::result::Error, _>(|conn| { … })`.
- Match the surrounding comment density — this codebase explains *why*, not *what*.

**`TODO.md` has an uncommitted edit belonging to the human owner.** Do not commit, revert, or touch it, in any task.

**Do not dispatch subagents.** Review arrives from the controller after your report.

---

## File Structure

| File | What happens to it |
|---|---|
| `src/components/encryption_panel.rs` | Loses the migration UI (19 sites); gains the two-step setup |
| `src/entries/repo.rs`, `src/server_fns/entries.rs` | Lose the migration queries; gain the `encrypted_at` refusal |
| `src/crypto/recovery.rs` | Renamed to `src/crypto/encryption_key.rs` |
| `src/crypto/{mod,wire,flow}.rs` | Identifier rename; `WrapKind::Recovery` → `WrapKind::EncryptionKey` |
| `src/storage/mod.rs` | `WriteKey` loses the route by which `Remote` could write v1 |
| `src/app.rs` | The sign-in gate and its routing |
| `src/components/unlock.rs`, `account_page.rs`, `account_menu.rs` | Copy and identifier rename |
| `migrations/2026-09-05-000001_entry_key/up.sql` | `kind` value `'recovery'` → `'encryption_key'` — edited in place, not a new migration |

**Task order is deliberate:** the migration is removed *before* the rename, so ~500 rename sites are not applied to code about to be deleted.

---

## Task 1: Remove the migration

**Files:** `src/components/encryption_panel.rs`, `src/entries/repo.rs`, `src/server_fns/entries.rs`, `src/dto.rs`, `src/test_support.rs`, `tests/entry_access.rs`

**Produces:** an `/account` panel with no migration surface.

Nothing starts plaintext any more and the database is wiped before deploy, so there is nothing left for this code to do.

- [ ] **Step 1: Find the full surface**

```
git grep -n 'MigrationPlan\|migration_scan\|rows_needing_migration\|fn migrate\|entries_all\|PendingRow\|unmigrated'
```

Read every hit before deleting anything. The panel has ~19 sites; `repo.rs` has ~5.

- [ ] **Step 2: Delete the migration pass and its UI**

`MigrationPlan`, `PendingRow`, the scan, the runner, the per-row progress, the resume control, and the "N days still unencrypted" reporting.

- [ ] **Step 3: Decide `entries_all`'s fate, and say which**

Its only caller was the migration. Check with `git grep -n 'entries_all'`. If nothing else calls it, delete it and its repository query and its tests. **If something does, keep it and report what.** Do not leave a server function whose only caller you just removed.

- [ ] **Step 4: Check what the panel now renders with nothing to migrate**

The manage view had a section reporting migration state. Removing it must not leave an empty container, a dangling heading, or a `Status` line with nothing to say. Render the panel in a test and look at the output.

- [ ] **Step 5: Run the tests**

Expect failures in `tests/entry_access.rs` for the deleted endpoints. Delete those tests — they cover code that no longer exists. **Do not delete a test that covers something still shipping**; if one looks borderline, report it rather than guessing.

- [ ] **Step 6: Full verification, then commit**

```bash
git commit -m "refactor: remove the plaintext migration"
```

---

## Task 2: Refuse writes from accounts without encryption

**Files:** `src/server_fns/entries.rs`, `src/storage/mod.rs`, `tests/entry_access.rs`

**Produces:** invariant E9. This is the entire enforcement mechanism for the feature.

- [ ] **Step 1: Write the failing tests first**

In `tests/entry_access.rs`, using the existing `TestApp` harness:

```rust
/// Invariant E9, and the whole point of the feature. If this regresses,
/// plaintext storage becomes possible again with nothing else to catch it.
#[tokio::test]
async fn entry_save_is_refused_when_the_account_has_no_encryption() { … }

#[tokio::test]
async fn entry_save_many_is_refused_when_the_account_has_no_encryption() { … }

/// The refusal must lift the moment encryption is enabled — a check that
/// never passes is indistinguishable from a broken endpoint.
#[tokio::test]
async fn both_endpoints_accept_once_encryption_is_enabled() { … }
```

That third test is not ceremony: it is the positive control. Without it, an
endpoint that refuses *everything* passes the first two.

- [ ] **Step 2: Run them, confirm they fail**

- [ ] **Step 3: Implement the check**

Read `user.encrypted_at` in the same transaction as the write. **Do not inspect the body** — E1, and it is the reason week totals are computed in the browser. The refusal message names what to do ("set up encryption first"), not what went wrong internally.

- [ ] **Step 4: Remove the route by which `Remote` could write v1**

`WriteKey::Plaintext` is still correct for `Backend::Local`, which is plaintext by design. What must go is the path where a `Remote` write can carry it. Make that unrepresentable if you can; if the type will not express it cleanly, enforce it at the seam and say in a comment why the type could not.

- [ ] **Step 5: Confirm the sensitivity**

Delete the check, watch the first two tests fail, restore. Report that you did — a guard whose test you have not seen fail is not evidence.

- [ ] **Step 6: Full verification, then commit**

---

## Task 3: Rename "recovery code" to "encryption key"

**Files:** ~23 under `src/` and `tests/`, plus the migration SQL

**Produces:** one vocabulary. Mechanical but wide — about 500 sites before Task 1's deletions, fewer after.

It was never single-use: nothing consumes or invalidates the wrap, so the same string works forever on any device. "Recovery code" means the opposite everywhere else, and the panel's own copy already says *"Not a backup — the key itself"* twice, which is prose working around its own label.

- [ ] **Step 1: Rename the module and identifiers**

`src/crypto/recovery.rs` → `src/crypto/encryption_key.rs`. Then `WrapKind::Recovery`, `Opener::Recovery`, `unlock_with_recovery`, `recovery_wrap`, `reissue_recovery`, `enable_recovery_only`, `RecoveryOnly`, `REISSUE_UNCONFIRMED` and their neighbours. Let the compiler find them; `git grep -n 'recovery\|Recovery'` for anything it cannot.

- [ ] **Step 2: Change the stored `kind` value**

In `migrations/2026-09-05-000001_entry_key/up.sql`, the partial index predicate `WHERE kind = 'recovery'` becomes `'encryption_key'`, and `WrapKind::as_str`/`parse` change with it. **Edit the migration in place — do not add a second one.** It has not shipped anywhere, and the database is wiped before deploy.

- [ ] **Step 3: Do NOT rename the HKDF `info` strings**

`tt/entry-kek/recovery/v1` stays exactly as it is. Invariant E6 says they never change; a wiped database makes changing them *safe* rather than *necessary*, and establishing that they are changeable is worse than a stale-looking constant.

**Add a comment at their definition** explaining why they disagree with the vocabulary around them, so the next reader does not "fix" the inconsistency. The pinning test that asserts their exact bytes stays unchanged.

- [ ] **Step 4: Rewrite the user-facing copy**

Every string a user reads. The point is not search-and-replace — the copy must now say what the thing is: permanent, reusable, grants full access until replaced, and on the fallback route the only key there is. The existing warnings are strong and should stay strong; they just stop calling it a recovery code.

- [ ] **Step 5: Full verification, then commit**

The suite must be green with no test weakened. A rename that needed an assertion loosened is not a rename.

---

## Task 4: Gate sign-in on setup

**Files:** `src/app.rs`, `src/encryption_ctx.rs`, `src/components/account_page.rs`

**Produces:** the routing gate and its escape hatch.

- [ ] **Step 1: Write the failing SSR tests**

In `src/app.rs`, in the same negative style as its neighbours:

```rust
/// A signed-in account with no encryption must not be shown a writing
/// surface. The previous branch spent a fix round establishing that an
/// editable box which silently refuses to save is worse than no box.
#[test]
fn a_signed_in_account_without_encryption_gets_no_entry_area() { … }

/// The escape must be visible, not merely reachable. Without it the gate
/// reads as a lock-out to anyone who signed in on a borrowed machine.
#[test]
fn the_gate_offers_a_way_back_to_local_mode() { … }

/// Signed out is untouched — local mode is fully functional and stores
/// nothing on the server.
#[test]
fn a_signed_out_visitor_is_not_gated() { … }
```

- [ ] **Step 2: Implement the gate**

An account is set up when `encrypted_at` is non-null. `EncryptionCtx` already probes this; extend rather than duplicate. Signed in and not set up routes to `/account`'s setup view; the day and week views are unreachable.

**Hydration:** the server renders `Unknown` for a signed-in user (it cannot know the device's key state), so the gate must not depend on anything the server cannot compute. Read `CLAUDE.md`'s hydration contract before writing this. The seed already distinguishes signed-out from signed-in — reuse that.

- [ ] **Step 3: The escape hatch**

"Sign out and use this device only", visibly, on the setup view. It signs out and returns to local mode.

- [ ] **Step 4: Full verification, then commit**

---

## Task 5: The two-step setup flow

**Files:** `src/components/encryption_panel.rs`, `src/components/account_page.rs`

**Produces:** the setup view the gate routes to.

- [ ] **Step 1: Step one — a passkey, for signing in**

Framed as what it does for the user: no email link every time. **Not** framed as an encryption prerequisite — it works with any authenticator, including ones that cannot hold a key, and it is worth having on its own.

- [ ] **Step 2: Step two — encryption, routed by capability**

The `prf_capable` answer falls out of step 1's enrolment, so no authenticator prompt is spent discovering it:

- capable → wrapped under the passkey *and* an encryption key
- not capable → the encryption key alone, with the stronger warning **and an explanation of why the passkey route was not offered**, naming the authenticator where it identified itself

A user who declines step 1 entirely still reaches step 2 on the encryption-key route.

- [ ] **Step 3: Test what each path renders**

That a capable account is offered the two-wrap route; that a non-capable one is offered the single-key route *with the reason stated*; and that the two warnings share no sentence. A user shown the two-wrap wording on a single-key account has been misled about how much slack they have.

- [ ] **Step 4: Full verification, then commit**

---

## Task 6: Documentation and final verification

**Files:** `CLAUDE.md`, `README.md`, both specs

- [ ] **Step 1: Correct every statement that encryption is optional**

`CLAUDE.md` and `README.md` both describe encryption as something an account may or may not have. That is no longer true for server-side storage. Signed-out local mode is still plaintext and must stay described as such — the distinction is now the *only* thing that makes those documents accurate.

- [ ] **Step 2: Update the phase-2 spec**

`2026-09-05-client-side-encryption-design.md` describes an opt-in feature with a migration. Mark what this branch superseded, pointing at the new spec. **Do not delete the superseded text** — what was predicted, and why it changed, is the useful part.

- [ ] **Step 3: Record E9 and E10** in the new spec's invariant list if the implementation ended up differing from §6.

- [ ] **Step 4: Confirm no new environment variables**

Grep `env::var` and compare against `README.md`'s table. Report the answer rather than assuming it.

- [ ] **Step 5: Run the full matrix and report actual numbers**

Including `cargo leptos build --release`, which is the only check exercising the real wasm bundle and the Tailwind pass together. Report its duration and result.

- [ ] **Step 6: Commit**

---

## Self-review notes

- **Spec coverage:** §2 → T1, T2; §3 → T2; §4 → T4, T5; §5 → T3; §6 → T2, T6.
- **Ordering:** T1 before T3 so the rename is not applied to deleted code. T2 before T4 so the gate has something to gate on. T5 after T4 so the setup view exists before it is routed to.
- **The riskiest task is T3**, not because it is hard but because it is wide: ~500 sites, and a rename that quietly weakens a test to stay green is worse than no rename. Its step 5 says so explicitly.
- **Known gap carried forward:** the ceremonies still reach WebCrypto and WebAuthn and cannot be host-tested. The manual smoke test in the phase-2 spec §10 gains the two-step setup flow and the gate.
