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

## Accounts

Signing in is optional — the app works fully without it, exactly as it did
before accounts existed. Signing in with an emailed magic link or a passkey
changes where entries are stored, and nothing else about how the app is used:

- Entries move from `localStorage` to a per-day row in SQLite, scoped to your
  account, instead of one blob held only in this browser.
- The first time you sign in on a device that already has local entries, a
  banner offers to import them; days that already exist on the server are
  left untouched either way, so importing twice is safe.
- `/account` manages passkeys: add one, rename it, or remove it — and, once
  you have a passkey that supports it, turns on encryption (below).
- Signing out returns you to the `localStorage` backend. Nothing already
  saved on the server is deleted.

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

Signing in moves your entries onto the server. By default they are stored
there in the clear, which means whoever runs the server can read them. You
can turn that off.

**What enabling encryption does.** Your browser generates a key, encrypts
every entry with it, and sends the server only ciphertext. The key never
leaves your browser — the server stores two *wrapped* copies of it that it
has no way to open. From then on the server holds the encrypted text, which
day each entry belongs to, and roughly how long it is; it cannot read a word
of any entry, and neither can anyone with a copy of the database, a backup,
or a court order served on whoever hosts it.

**How to turn it on.** `/account` offers it once you have enrolled a passkey
whose authenticator supports the WebAuthn PRF extension — most modern
platform authenticators and security keys do. Accounts without one keep
working exactly as before, unencrypted. Enabling re-encrypts the entries you
already have, in one pass you can watch; if it is interrupted, `/account`
tells you how many days are left and offers to finish. Nothing becomes
unreadable in the meantime.

**Your recovery code is shown once, and it is the only backup.** Enabling
generates a 32-character code and shows it to you on a screen you have to
confirm before it closes. It is never shown again. Write it down or put it in
a password manager *before* clicking through — the code is what gets you back
in on a browser your passkey cannot reach, or after your passkey is gone.

> **If you lose every passkey and the recovery code, your entries are gone,
> permanently.** Not locked, not recoverable by support, not restorable from
> a backup — the ciphertext is still there and no key on earth opens it. That
> is exactly what "the server cannot read your entries" costs, and it is not
> a limitation anyone can lift for you afterwards.

You can ask `/account` for a fresh recovery code at any time, which replaces
the old one. You are offered one automatically after unlocking with a code,
since typing it in may have left it somewhere careless.

**Unlocking.** Each browser unlocks once and then remembers — the key is
stored in that browser in a form scripts cannot read out, so reloads and
restarts do not re-prompt. Signing in *with a passkey* unlocks in the same
gesture, with no extra prompt. Signing in with a magic link does not, so the
day view asks you to unlock, either with a passkey or with your recovery
code. "Lock now" on `/account` forgets the key for that browser, and so does
signing out. Clearing site data or using a private window means unlocking
again.

**Adding a passkey to an encrypted account takes three prompts.** Your
authenticator asks three times in a row: once to create the new passkey, once
against a passkey you already have — to recover the key so it can be wrapped
for the new one — and once against the new passkey. You can substitute your
recovery code for that middle prompt, but there is no way to do it in fewer
than three steps: the key is deliberately held in a form nothing can copy
out, the app included, so it has to be re-derived at that moment. `/account`
says so before you start rather than springing three prompts on you one at a
time.

**Removing a passkey** deletes its ability to unlock. The app refuses to
remove your *last* unlocking passkey while encryption is on, and points you
at your recovery code instead, so a single click cannot destroy your data.

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

Signed-out users' time-tracking data is never sent to the server: it lives
only in `localStorage`. **Signed-in users' entries are stored server-side, and
whether that storage is readable by the operator depends on the account.** An
account that has enabled encryption (above) stores ciphertext under a key the
server never holds; an account that has not — the default, and the only
option for an account with no PRF-capable passkey — stores plaintext that
anyone with database access can read. Both shapes coexist, and so do both
within a single account while its migration pass runs: each stored row
carries its own version tag and is read according to that tag, which is what
makes a half-migrated account a normal state rather than a broken one.

The server is structured so that it never needs to parse an entry's contents
— the week view's totals are computed in the browser, not in a server query,
and the enable-time migration asks the browser, not the database, which rows
still need encrypting. That structure predates the encryption and is what
let it drop in at the storage seam without touching a single component that
reads or writes entry text.

See `docs/superpowers/specs/2026-09-03-leptos-migration-design.md` for the
hydration contract — the reason stored state is `Option<String>` rather than
`String` — `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
for accounts and per-day storage, and
`docs/superpowers/specs/2026-09-05-client-side-encryption-design.md` for the
key hierarchy, the ceremonies, the threat model, and the invariants a change
in this area has to keep.

