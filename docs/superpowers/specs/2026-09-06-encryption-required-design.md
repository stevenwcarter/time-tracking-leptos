# Encryption required for server-side storage

**Status:** design, approved 2026-09-06
**Builds on:** `2026-09-05-client-side-encryption-design.md`, which made
encryption possible. This makes it the only way to store anything on the
server. Parts of that document are superseded by this one and are marked so
in place — §1.1 decision 2, §2's last bullet, §5.2's `kind` comment, §6.1's
trigger and step 6, §7.6's last two rows, §8 entirely, §9's vocabulary, and
four rows of §12.

> **Before deploying: the database must be empty. See §1.4.** It is the one
> assumption here whose failure is silent, unrecoverable, and not fixed by
> re-running anything.

## 1. Goal

The server stops accepting unencrypted entries. An account either has
encryption enabled or it cannot write, and signing in without it lands the
user on setup rather than on a day view they cannot save to.

### 1.1 Why now

Phase 2 shipped encryption as opt-in, which left three things sitting
awkwardly together: a migration pass that exists only to fix accounts that
started plaintext, a `WriteKey::Plaintext` route that is correct only for
accounts nobody has upgraded, and documentation that has to keep saying
"signed-in entries are encrypted *for accounts that turned it on*". Making
encryption a precondition removes all three.

The owner is wiping the database before deploying this, so there is no
existing plaintext to preserve. That is what makes the removal clean rather
than a migration problem.

### 1.2 The decisions

Taken with the project owner on 2026-09-06:

1. **No existing plaintext rows survive.** The database is wiped before
   deploy. Nothing migrates, and no code exists to migrate it.
2. **The gate is hard, with a way out.** Signed in without encryption means
   the setup page and nothing else — plus a visible "sign out and use this
   device only" escape back to local mode.
3. **A passkey is pushed for *login*, independently of encryption.** A passkey
   spares the user the magic-link round trip every time, and that is worth
   having whether or not the same credential can hold a key.
4. **The encryption route is chosen by what that passkey turns out to be.**
   PRF-capable wraps the data key under it, with an encryption key as a
   second route. Not capable falls back to the encryption key alone.
5. **"Recovery code" is renamed to "encryption key".** It was never
   single-use; see §5.

### 1.3 Non-goals

- Changing signed-out `localStorage`. It stays plaintext v1 — client-side
  data the server never sees, and the threat this addresses does not apply
  (phase-2 §1.2).
- Verifying that a stored body is *actually* ciphertext. The server cannot,
  and §3 explains why that is deliberate rather than a shortfall.
- Migrating anything. There is nothing to migrate.

### 1.4 The deployment requirement, and why it is the dangerous one

**The production database must be deleted before this build is deployed.**

Decision 1 above says the database is wiped, and treats that as a
convenience: it is what makes removing the migration clean. It is also a
**hard precondition**, and the two should not be confused, because one of the
changes in this branch is only correct against an empty database and fails
in a way nothing reports.

§5.2's rename changes the stored `entry_key_wrap.kind` value from
`'recovery'` to `'encryption_key'`, and it does so **by editing
`migrations/2026-09-05-000001_entry_key/up.sql` in place** rather than adding
a forward migration. Against an empty database that is exactly right — the
migration has never run, so it runs once with the new value and nothing has
to be rewritten. Against a database that has already run it, Diesel will not
run it again, and three things then go wrong together:

1. Existing rows keep saying `'recovery'`.
2. `idx_entry_key_wrap_one_encryption_key`'s predicate, `WHERE kind =
   'encryption_key'`, matches none of them — so the "one key wrap per
   account" guarantee stops holding for exactly the accounts that have one.
3. `WrapKind::parse("recovery")` returns `None`, and every caller treats an
   unparseable kind as a row this build does not understand.

The account's data key is wrapped under that row. Once it cannot be found,
**the account's entries cannot be decrypted by anyone, including their
owner** — the ciphertext is intact and the key that opens it is unreachable.

**What makes this worth its own section is not the severity, it is the
silence.** Every other assumption in this branch fails loudly and is fixed by
re-running something: a stale client posting an entry gets a refusal it can
show the user, an interrupted enable retries, a failed probe offers a retry.
This one throws nothing at deploy time, nothing at startup, and nothing on
the first request. The symptom is every encrypted account failing to unlock
at once, which looks like corruption rather than like a migration that did
not happen.

**If a database ever does have to survive this change**, the answer is a
real forward migration — `UPDATE entry_key_wrap SET kind = 'encryption_key'
WHERE kind = 'recovery'`, with the partial index dropped and recreated —
never a second in-place edit of a shipped migration. The in-place edit is
justified here by the wipe and by nothing else, and it should not be read as
a precedent.

## 2. What is removed

| Removed | Why it can go |
|---|---|
| The migration pass, its `MigrationPlan`, and the per-row progress UI | Nothing starts plaintext any more |
| The unmigrated-day counting and the resume control on `/account` | Same |
| `entries_all` | Its only caller was the migration. Check before deleting — if the panel still needs it for something else, keep it and say what for. **Checked: it did not. Deleted.** |
| `entry_save_many` | Same: the bulk write existed to seal a backlog in one pass. `entry_save` becomes the only entry write, and so the only place §3's rule needs enforcing |
| `WriteKey::Plaintext` reaching `Backend::Remote` | An account that could use it cannot write at all |

**The v1 *read* path stays, and an earlier draft of this section was wrong to
say otherwise.** `envelope::plan_read` is shared by both backends, and
`Backend::Local` still writes v1 — signed-out data is plaintext by design
(phase-2 §1.2). Removing the v1 arm would break local storage, which is the
no-account mode the escape hatch in §4.1 depends on.

So what goes is narrower than "v1 support": the *write* route by which a
`Remote` save could produce a v1 row. Reading one remains possible and costs
nothing, because per-row dispatch already handles it and the same code serves
`Local` regardless.

## 3. Enforcement is account-level, and that is a design choice

The obvious implementation of "no unencrypted storage" is to have
`entry_save` reject a body that is not a v2 envelope. **It must not.**

Invariant E1 — inherited from phase 1 and load-bearing for the whole
design — says the server never parses, aggregates, searches, or renders an
entry body. It is why week totals are computed in the browser rather than in
SQL. A server that inspects an envelope to check its version is parsing the
body, and once that is acceptable the next feature that wants to peek has a
precedent.

So enforcement is: **`entry_save` refuses when the account's `encrypted_at`
is null.** That is a property of the account row, checkable without looking
at anything the user wrote. It is the only endpoint that needs the rule
because it is the only one that writes an entry: `entry_save_many` existed
for the migration pass §2 removes, and goes with it.

What this buys: a client that is correctly implemented cannot store
plaintext. What it does not buy: protection against a *modified* client that
enables encryption and then posts plaintext bodies anyway. That is the same
trust boundary phase-2 §2 already records — a user can always lie to a server
about their own data, and the server has no way to tell without reading it,
which is the thing being prevented. Recording it here so nobody later
mistakes the gap for an oversight and "fixes" it by parsing.

## 4. The sign-in flow

### 4.1 The gate

After sign-in, an account is *set up* when `encrypted_at` is non-null.
Anything else routes to `/account`'s setup view, and the day and week views
are unreachable until it is.

The gate exists because of what the previous branch learned the hard way: an
editable box that silently refuses to save is worse than no box. An account
that cannot write should not be shown a writing surface.

**The escape must be visible, not merely present.** A user who signed in on a
borrowed machine, or who wants to look before committing, needs an obvious
route out — "sign out and use this device only" returns them to local mode,
which works fully and stores nothing on the server. Without it the gate reads
as a lock-out.

### 4.2 Setup, in two steps

**Step 1 — add a passkey, for signing in.** Framed as what it is: so you do
not need an email link every time. This works with any authenticator,
including ones that cannot hold a key.

**Step 2 — turn on encryption.** The route is decided by what step 1
reported, not by asking the user to understand PRF:

- **`prf_capable` true** → the data key is wrapped under the passkey *and*
  under an encryption key. Two routes; losing one is survivable.
- **`prf_capable` false** → wrapped under the encryption key alone, with the
  stronger warning, and an explanation of why the passkey route was not
  offered — naming the authenticator if it identified itself.

The capability answer falls out of an enrolment the user wanted anyway. No
authenticator prompt is spent discovering it, and nobody is offered a route
their hardware cannot complete.

A user who declines step 1 entirely can still reach step 2 — an account with
no passkey at all gets the encryption-key-only route. The passkey is pressed
for login convenience, not required for encryption.

### 4.3 What the user sees afterwards

Once `encrypted_at` is set, everything behaves as phase 2 already describes:
the day view mounts, writes seal, a new device shows the unlock prompt, and
the keystore holds the key non-extractably per device.

## 5. "Recovery code" becomes "encryption key"

### 5.1 Why the old name was wrong

It was never single-use. `unlock_with_recovery` unwraps the data key and does
nothing else — nothing consumes, deletes, rotates or invalidates the wrap.
The same string works indefinitely, on any device, as many times as the user
likes. Only explicitly generating a new one retires it.

"Recovery code" means the opposite everywhere else. GitHub and Google issue
sheets of single-use codes that are crossed off as they are spent. A user
mapping our string onto that model could reasonably treat it as spent after
one use and handle it carelessly — while it still grants full read access to
every entry in the account, forever, from anywhere.

The accurate analogue is 1Password's Secret Key: high-entropy, permanent,
needed on each new device, never consumed.

This matters more under §1.2's decision 4, not less. On the fallback route
that string is not a backup; it is the entire key.

### 5.2 What changes, and what does not

**Renamed:** every user-facing string; `crypto::recovery` (the file, to
`src/crypto/encryption_key.rs`) →
`crypto::encryption_key`; `unlock_with_recovery`, `recovery_wrap`,
`WrapKind::Recovery`, `Opener::Recovery`, `reissue_recovery` and their
neighbours; and the stored `kind` column value, which becomes
`'encryption_key'`. The column value is a database compatibility surface and
would normally be frozen — it changes only because the database is being
wiped, and leaving it as `'recovery'` while everything else reads
"encryption key" is the kind of half-rename that misleads a year later.

**The column value is changed by editing the shipped migration in place, and
that is the branch's one unrecoverable assumption — see §1.4.** It is correct
against an empty database and silently destroys every encrypted account's
access against a surviving one. §1.4 states the failure, why nothing reports
it, and what a real forward migration would have to do instead.

**Not renamed: the HKDF `info` strings.** `tt/entry-kek/recovery/v1` stays
exactly as it is. They are opaque domain-separation constants that never
reach a user, invariant E6 says they never change, and a wiped database makes
changing them *safe* rather than *necessary*. Establishing that they are
changeable is worse than a stale-looking constant. A comment at their
definition records why they disagree with the vocabulary around them.

### 5.3 The copy has to carry the correction

Renaming the identifier does not fix the mental model on its own. Wherever
the key is shown, the text says plainly that it is permanent, reusable, and
grants full access until replaced — and on the fallback route, that it is the
only key there is.

## 6. Invariants

Carried forward from phase 2, with two added.

- **E1–E8** hold unchanged. E7's plaintext-downgrade rule becomes easier to
  satisfy, not harder: with no server-side plaintext route, `WriteKey` loses
  its `Plaintext` arm for `Remote` entirely.
- **E9. The server refuses entry writes from an account with no
  `encrypted_at`.** *Guarded by:* integration tests posting `entry_save` —
  now the only endpoint that writes an entry — as an un-enabled account and
  asserting refusal. This is the whole enforcement mechanism; if it
  regresses, plaintext storage becomes possible again with nothing else to
  catch it.
- **E10. The server still never inspects a body.** §3. Enforcement reads
  `encrypted_at`, never an envelope. *Guarded by:* the absence of any
  body-parsing server code, and by E1's existing tests.

**Both checked against the shipped implementation on 2026-09-06**, since a
spec that outran its code is how an invariant quietly stops being one. E9:
`entry_save` is the only `#[server]` function in `src/server_fns/entries.rs`
that writes, it refuses on `store::is_encrypted` inside the same transaction
as the write, and `tests/entry_access.rs` asserts both halves
(`entry_save_is_refused_when_the_account_has_no_encryption` and
`entry_save_is_accepted_once_encryption_is_enabled`). E10: the refusal reads
an account column and the module's own header records that bodies are opaque
in both directions; the only thing done to a body anywhere on the server is
a length comparison. `entry_save_many` and `entries_all` are gone, so neither
invariant has a second endpoint to hold at. An earlier draft of §3 and of E9
named `entry_save_many` as also guarded — that was corrected before this
spec was final, and is noted here so a reader of the branch history does not
reintroduce it.

## 7. Failure modes

| Situation | Behaviour |
|---|---|
| Signed in, no encryption, tries to reach the day view | Routed to setup. No editable surface is rendered. |
| Signed in, no encryption, a stale client posts an entry anyway | Server refuses on `encrypted_at`. The client surfaces it as "set up encryption first", not a generic error. |
| Enrols a passkey that turns out not to be PRF-capable | Encryption offered on the encryption-key route, with the reason stated and the authenticator named where known. The passkey still works for signing in — which is why it was worth enrolling. |
| Declines the passkey entirely | Encryption-key route, same as above. Sign-in continues to use magic links. |
| Wants out | "Sign out and use this device only" returns to local mode, which is fully functional and stores nothing server-side. |
| Existing plaintext rows | None — the database is wiped before deploy. Were any to survive, the client would still read them: `plan_read`'s v1 arm stays for `Backend::Local`'s sake (§2), so a stray v1 row renders rather than erroring. Nothing can create one server-side. |
