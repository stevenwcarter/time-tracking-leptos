# Time Tracker

A simple time tracking app built with [Leptos](https://leptos.dev/) and [Tailwind CSS](https://tailwindcss.com/).

## Development

Requires the pinned nightly toolchain (installed automatically from
`rust-toolchain.toml`) and [cargo-leptos](https://github.com/leptos-rs/cargo-leptos),
pinned to the same version the `Dockerfile` builds with:

```bash
cargo install --locked cargo-leptos --version 0.3.7
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

## Configuration

Copy `.env.example` to `.env` and fill in what you need — `cargo leptos watch`
loads it automatically via `dotenvy`. Nothing is required to run the app
signed-out; `SESSION_KEY` becomes required the moment you build in release
mode, because sign-in depends on it.

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | no | `./data/time-tracking.db` | SQLite file path. Its parent directory is created on first run. |
| `SESSION_KEY` | **yes, in release builds** | none — the binary logs an error naming the variable and exits if it is unset or empty | Signs session cookies. In a debug build an ephemeral key is generated instead, with a warning; sessions from it do not survive a restart. That debug fallback does not extend to passkey ceremonies — see `PASSKEY_STATE_KEY`. |
| `PASSKEY_STATE_KEY` | no | falls back to `SESSION_KEY` | Signs in-flight WebAuthn ceremony state. Set it separately from `SESSION_KEY` so one leaked secret cannot forge the other — a domain tag keeps the two signatures apart even when they share a value. Unlike `SESSION_KEY`, there is no ephemeral-key fallback in debug builds: if both this and `SESSION_KEY` are unset or empty, the first passkey ceremony panics, even in development. |
| `MAGIC_LINK_TTL_SECONDS` | no | `900` | How long a magic-link sign-in token stays valid, in seconds. |
| `SITE_BASE_URL` | no, but must be correct | `http://localhost:3000` | Absolute base URL used to build the links emailed for sign-in. Must match how users actually reach the app, or the emailed links point somewhere wrong. |
| `SMTP_HOST` | no | unset | SMTP relay host. Unset is a supported development mode: sign-in links are logged to the server's output instead of emailed. |
| `SMTP_PORT` | no | `587` | SMTP relay port. |
| `SMTP_USER` | no | unset | SMTP auth username. |
| `SMTP_PASS` | no | unset | SMTP auth password. |
| `SMTP_FROM` | no | unset | The `From:` address on sign-in emails. |
| `SMTP_INSECURE` | no | unset (STARTTLS required) | Set to `1` or `true` to connect with **no TLS at all**, for a local mail catcher that speaks none. Any other value, including `yes` and `on`, leaves STARTTLS required, so a typo cannot silently downgrade a relay. AUTH credentials cross the network in cleartext when this is on; the server logs a warning at startup naming the host. Never set it against a relay you do not own the wire to. |
| `WEBAUTHN_RP_ID` | no | `localhost` | WebAuthn relying-party ID. |
| `WEBAUTHN_RP_ORIGIN` | no | `http://localhost:3000` | WebAuthn relying-party origin. Must match the browser's origin exactly, scheme included, or every passkey ceremony fails with an origin mismatch. |
| `WEBAUTHN_RP_NAME` | no | `Time Tracker` | Relying-party name shown in the browser's own passkey UI. |
| `RUST_LOG` | no | `info` | Log level/filter, via `tracing_subscriber`'s `EnvFilter`. |

Two more are read implicitly rather than via a table entry above: `.env`
itself is optional (`dotenvy::dotenv()` loads it if present and is a silent
no-op otherwise — every variable above can instead be set directly in the
environment), and `RUST_LOG` above is consumed by `EnvFilter`, not read
directly by name in the code.

**Set by the Docker image / cargo-leptos, not meant to be set by hand:**
`LEPTOS_OUTPUT_NAME`, `LEPTOS_SITE_ROOT`, `LEPTOS_SITE_PKG_DIR`,
`LEPTOS_SITE_ADDR`.

**Build-time only:** `CARGO_LEPTOS_VERSION`, the `Dockerfile`'s pinned
cargo-leptos release.

## Deploying

**Delete the existing production database before deploying this build.**

This release changed a value stored in the `entry_key_wrap` table by editing
an already-shipped migration in place instead of adding a new one, which is
safe only if no database has run the old version. A database that survives
will still hold the old value; the migration will not re-run, and the key
that would decrypt each affected account's entries can no longer be located.
There is no repair and no support recourse for that, so **the server refuses
to start rather than serve it.**

After migrations and before it binds a port, the process counts
`entry_key_wrap` rows carrying a `kind` this build cannot parse. If it finds
any it logs one `ERROR` line — naming the count and this rename — and exits
with status 1.

**In production that shows up as a crash-looping deploy, not as a running app
with broken accounts.** A container platform restarts the process, watches it
exit at once, and reports a failing health check or a restart back-off; the
only explanation is that one log line, in the logs of a container that keeps
dying. Read it before concluding the build is bad. It is the check doing its
job, and the fix is the wipe this release requires — never hand-editing the
rows it names, each of which is the only route to an account's data key.

The check finds nothing on a wiped database, and costs one query. If a
database ever has to survive the change, it needs a real forward migration
that rewrites the stored value — not a second in-place edit.

## Accounts

Signing in is optional — the app works fully without it, exactly as it did
before accounts existed. Signing in with an emailed magic link or a passkey
changes where entries are stored, and what that costs you is one setup step:

- Entries move from `localStorage` to a per-day row in SQLite, scoped to your
  account, instead of one blob held only in this browser.
- **Before your account can store anything, you set up encryption.** The
  server will not hold an entry it could read, so a newly signed-in account
  is taken to `/account` and the day and week views wait until that is done.
  It is two steps and you only do it once — see Encrypting your entries,
  below.
- The first time you sign in on a device that already has local entries, a
  banner offers to import them; days that already exist on the server are
  left untouched either way, so importing twice is safe.
- `/account` manages passkeys: add one, rename it, or remove it — and is
  where encryption is set up and managed.
- Signing out returns you to the `localStorage` backend, which needs no setup
  and stores nothing on the server. That is also the way out if you signed in
  somewhere you would rather not set up a key: the setup screen offers "sign
  out and use this device only". Nothing already saved on the server is
  deleted.

See the Configuration section above for the SMTP settings that control
magic-link email and the `WEBAUTHN_RP_*` settings that control passkeys.

### Seeing sign-in emails locally

With `SMTP_HOST` unset, sign-in links are written to the server's log — enough
to click through, and the lowest-setup option. To exercise the real send path
instead, `docker-compose.yml` runs [Mailpit](https://mailpit.axllent.org/), a
catcher that accepts any credentials and speaks no TLS:

```bash
docker compose up -d mailpit   # SMTP on :2025, web UI on http://localhost:9025
```

```dotenv
SMTP_HOST=localhost
SMTP_PORT=2025
SMTP_USER=dev
SMTP_PASS=dev
SMTP_FROM=Time Tracker Dev <dev@example.com>
SMTP_INSECURE=true
```

`SMTP_INSECURE` is what makes this work: without it the transport requires
STARTTLS, which Mailpit does not offer, and every send fails with "STARTTLS is
not supported on this server". Sign-in emails then appear in the web UI.

## Encrypting your entries

Signing in moves your entries onto the server, and **everything the server
stores for you is encrypted.** This is not a setting and there is no
plaintext option: an account that has not set up encryption cannot save an
entry at all, which is why signing in for the first time takes you to
`/account` rather than to your day.

Signed-*out* entries are the opposite, deliberately: they are plain text in
your browser's `localStorage`. There is nothing to encrypt them with and no
one to hide them from — they never leave the browser and the server never
sees them. If you would rather not set up a key at all, that mode is fully
functional and the setup screen offers it as "sign out and use this device
only".

**What encryption does.** Your browser generates a key, encrypts every entry
with it, and sends the server only ciphertext. The key never leaves your
browser — the server stores *wrapped* copies of it that it has no way to
open. The server holds the encrypted text, which day each entry belongs to,
and roughly how long it is; it cannot read a word of any entry, and neither
can anyone with a copy of the database, a backup, or a court order served on
whoever hosts it.

**Setting it up takes two steps**, both on `/account`:

1. **Add a passkey — optional.** This is about signing in, not about
   encryption: a passkey replaces the emailed link with one prompt from
   whatever your device already unlocks with. Any authenticator will do,
   including one that cannot hold a key. You can skip it.
2. **Turn on encryption.** This is the step that matters, and it works
   whether or not you did step 1.

Step 2 runs by one of two routes, and which one you get depends on your
passkeys rather than on a choice you make:

- **A passkey and an encryption key**, if you have enrolled a passkey whose
  authenticator supports the WebAuthn PRF extension — most modern platform
  authenticators and security keys do. The passkey unlocks your entries in
  the same gesture as signing in, and the encryption key is the second way
  in behind it.
- **An encryption key alone**, if none of them do. Some password-manager
  browser extensions have not implemented the extension the unlock key is
  derived from, and that is not something a setting can turn on. This route
  still encrypts your entries; you unlock by typing the encryption key once
  per browser, after which that browser remembers it like any other. The
  difference is what that key is worth: there is no passkey behind it, so
  **losing it loses your entries outright.** The panel says so in those words
  before you start.

Either way, there is nothing to convert afterwards. Your account had no
server-side entries before this, because it could not save any — so the
moment encryption is on, the day view opens and everything you write from
then on is sealed. There is no conversion pass to watch, wait for, or resume.

The second route is not a dead end. If you later enrol a passkey that *can*
hold a key, `/account` will give it one using your encryption key, and from
then on that passkey unlocks your entries too.

**Your encryption key is shown once.** Enabling generates a 32-character key
and shows it to you on a screen you have to confirm before it closes. It is
never shown again. Write it down or put it in a password manager *before*
clicking through — it is what gets you back in on a browser your passkey
cannot reach, or after your passkey is gone.

It is a key, not a recovery code, and the difference matters when you decide
where to keep it. Nothing uses it up: it does not expire, it is not spent by
being typed, and the same string opens every entry in your account, on any
browser, as many times as you like — until you replace it. Treat it the way
you would treat the entries themselves.

> **If you lose every passkey and the encryption key — or just the key, if
> that is the only one your account has — your entries are gone,
> permanently.** Not locked, not recoverable by support, not restorable from
> a backup — the ciphertext is still there and no key on earth opens it. That
> is exactly what "the server cannot read your entries" costs, and it is not
> a limitation anyone can lift for you afterwards.

You can ask `/account` for a fresh encryption key at any time, which replaces
the old one. You are offered one automatically after unlocking with the key
you have, since typing it in may have left it somewhere careless.

**Unlocking.** Each browser unlocks once and then remembers — the key is
stored in that browser in a form scripts cannot read out, so reloads and
restarts do not re-prompt. Signing in *with a passkey* unlocks in the same
gesture, with no extra prompt. Signing in with a magic link does not, so the
day view asks you to unlock, either with a passkey or with your encryption
key. "Lock now" on `/account` forgets the key for that browser, and so does
signing out. Clearing site data or using a private window means unlocking
again.

**Adding a passkey to an encrypted account takes three prompts.** Your
authenticator asks three times in a row: once to create the new passkey, once
against a passkey you already have — to recover the key so it can be wrapped
for the new one — and once against the new passkey. You can substitute your
encryption key for that middle prompt, but there is no way to do it in fewer
than three steps: the key is deliberately held in a form nothing can copy
out, the app included, so it has to be re-derived at that moment. `/account`
says so before you start rather than springing three prompts on you one at a
time.

**Removing a passkey** deletes its ability to unlock. The app refuses to
remove the *last* passkey that can unlock your entries, and points you at
your encryption key instead, so a single click cannot destroy your data. (On
the encryption-key-only route there are none to protect, and the refusal
starts applying the moment you give a passkey a key.)

**What it does not protect against.** Encryption defends your entries at
rest — an operator reading the database, a stolen backup, a subpoena. It does
not hide which days you logged time or roughly how much you wrote; it does
not hide your email address or when you signed in; and it cannot defend
against a server that ships modified JavaScript to your browser, because the
server is what serves the app in the first place.

## Architecture

The app is Leptos SSR + hydration: the server renders the page shell, the
header's signed-in/signed-out state, and the app's *unloaded* entry state; the
browser fills in the actual saved time entry after hydration, from
`localStorage` when signed out or from the server when signed in.

Where an entry is stored decides how it is stored, and there are exactly two
answers:

- **Signed out — plaintext in `localStorage`**, never sent to the server.
- **Signed in — ciphertext in SQLite**, sealed in the browser under a key the
  server never holds.

There is no third case. The server refuses to write an entry for an account
that has not set up encryption, so no plaintext row can be created
server-side by this build, and none is converted from one — an account gains
its first server-side entry only after it has a key. Each stored row still
carries its own version tag and is read according to that tag, which is what
lets one code path serve both backends.

The server is structured so that it never needs to parse an entry's contents:
the week view's totals are computed in the browser, not in a server query,
and the write refusal above reads a column on the *account* row
(`user.encrypted_at`) rather than looking at the body to see which kind it
is. That structure predates the encryption and is what let it drop in at the
storage seam without touching a single component that reads or writes entry
text.

See `docs/superpowers/specs/2026-09-03-leptos-migration-design.md` for the
hydration contract — the reason stored state is `Option<String>` rather than
`String` — `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
for accounts and per-day storage,
`docs/superpowers/specs/2026-09-05-client-side-encryption-design.md` for the
key hierarchy, the ceremonies, the threat model, and the invariants a change
in this area has to keep, and
`docs/superpowers/specs/2026-09-06-encryption-required-design.md` for why
encryption is a precondition rather than a feature. The last supersedes parts
of the one before it, which are marked as superseded in place rather than
removed.
