# Time Tracker

A simple time tracking app built with [Leptos](https://leptos.dev/) and [Tailwind CSS](https://tailwindcss.com/).

## Development

Requires the pinned nightly toolchain (installed automatically from
`rust-toolchain.toml`) and [cargo-leptos](https://github.com/leptos-rs/cargo-leptos):

```bash
cargo install --locked cargo-leptos
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

### Architecture

The app is Leptos SSR + hydration: the server renders the page shell and the
app's *unloaded* state, and the browser fills in the user's saved time entry
from `localStorage` after hydration. No time-tracking data is sent to or stored
on the server.

See `docs/superpowers/specs/2026-09-03-leptos-migration-design.md` for the
design, particularly §5 on the hydration contract — the reason stored state is
`Option<String>` rather than `String`.

