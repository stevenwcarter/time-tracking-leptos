# time-tracking-leptos

Leptos 0.8 SSR + hydration app on Axum, built with cargo-leptos. Parses
free-form time-tracking text into a per-project summary. All user data lives in
the browser's `localStorage`; nothing is stored server-side.

## Commands

| Task | Command |
|---|---|
| Dev server | `cargo leptos watch` (serves at :3000) |
| Tests | `cargo test --features ssr --no-default-features` |
| Lint | `cargo clippy --features ssr --no-default-features` |
| Wasm build | `cargo build --lib --target wasm32-unknown-unknown --no-default-features --features hydrate` |
| Release | `cargo leptos build --release` |

Plain `cargo build`/`test` and `cargo leptos build` fight over the same target
dir and mutually invalidate the cache. `cargo clippy`/`check` are safe.

## The hydration contract — read before touching state

Persistent state is `Option<String>`, **not** `String`:

| Value | Meaning | Renders as |
|---|---|---|
| `None` | Not yet read from storage | Blank |
| `Some("")` | Loaded; nothing saved | "No projects found…" |
| `Some(text)` | Loaded with data | The parsed summary |

The server has no `localStorage`, so it must render the `None` branch. If the
server rendered an empty state instead, returning users would see a flash of
"No projects found" before their data appeared, and any server-rendered *data*
would fail hydration outright.

`src/app.rs`'s `ssr_omits_loaded_state` test pins this. It asserts negatively —
do not weaken it to make a change pass.

`render_app()`, the helper behind these SSR tests, only provides a
`RequestUrl` context — not `ServerMetaContext`, request `Parts`, or
`ResponseOptions`. That's harmless today: `leptos_meta` writes nothing to the
body buffer either way, so the rendered HTML still matches production. But the
gap emits a swallowed warning, and a future feature that depends on those
contexts will need the helper extended.

`render_app()` also renders synchronously via `.to_html()`, while production
streams through `leptos_axum`'s route handler. There are no `Resource`s or
`<Suspense>` boundaries in the app today, so the two agree — but adding async
rendering would make this helper stop tracking production, and the SSR tests
would need revisiting.

## Layout

- `src/app.rs` — document shell, router, root component, SSR output tests
- `src/storage/` — the storage seam. Components use `hook::use_persistent`;
  everything else is an implementation detail. The API is async so that
  server-backed encrypted storage (see `TODO.md`) can drop in without touching
  any component.
- `src/components/` — one file per group of related views: `summary`,
  `projects`, `time_display`, `time_entry_area`
- `src/clipboard.rs` — same signature on both targets, side effect gated

## Conventions

- Edition 2024; nightly toolchain pinned by `rust-toolchain.toml`.
- Branch polymorphism uses `Either`/`EitherOf3`, never `.into_any()`.
- Tailwind v4 CSS-first: `@source` lives in `style/tailwind.css`, which pulls
  in Tailwind's default palette/scale — there is no `@theme` block, so no
  custom design tokens are defined, just one custom utility (`.value-slot`)
  in `@layer components`. There is no `tailwind.config.js` and no npm step.
- Storage key strings are a compatibility surface — changing one orphans
  existing users' saved data.

## Design docs

`docs/superpowers/specs/2026-09-03-leptos-migration-design.md`
