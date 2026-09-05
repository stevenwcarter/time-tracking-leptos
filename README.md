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
- `/account` manages passkeys: add one, rename it, or remove it.
- Signing out returns you to the `localStorage` backend. Nothing already
  saved on the server is deleted.

See the Configuration section above for the SMTP settings that control
magic-link email and the `WEBAUTHN_RP_*` settings that control passkeys.

## Architecture

The app is Leptos SSR + hydration: the server renders the page shell, the
header's signed-in/signed-out state, and the app's *unloaded* entry state; the
browser fills in the actual saved time entry after hydration, from
`localStorage` when signed out or from the server when signed in.

Signed-out users' time-tracking data is never sent to the server: it lives
only in `localStorage`. **Signed-in users' entries are stored server-side, and
today that storage is plaintext** — anyone with access to the database can
read them. The server is structured so that it never needs to parse an
entry's contents (the week view's totals, for instance, are computed in the
browser, not in a server query) specifically so that a planned phase 2 can
replace plaintext storage with client-side encryption the server cannot undo,
without changing that structure. Until phase 2 ships, treat every signed-in
entry as readable by whoever operates the server.

See `docs/superpowers/specs/2026-09-03-leptos-migration-design.md` for the
hydration contract — the reason stored state is `Option<String>` rather than
`String` — and `docs/superpowers/specs/2026-09-04-accounts-and-dated-entries-design.md`
for accounts, per-day storage, and the encryption trajectory (§9).

