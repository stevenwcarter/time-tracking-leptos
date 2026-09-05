#![recursion_limit = "512"]

pub mod app;
pub mod auth_ctx;
pub mod clipboard;
pub mod components;
// Ungated on purpose, and `base64` is a non-optional dependency to keep it
// that way. This module holds the envelope format and the key-derivation
// constants — a compatibility surface whose corruption would silently make
// every wrapped key unopenable — so it should compile and its tests should
// run in every configuration, not only the two the app ships. `base64` is
// pure Rust with no dependencies of its own, so unconditional costs nothing.
pub mod crypto;
pub mod date;
pub mod dto;
pub mod encryption_ctx;
pub mod server_fns;
pub mod storage;
#[cfg(test)]
pub(crate) mod test_util;
// `test` as well as `hydrate`, same split as `storage::local`: `friendly_error`
// is pure and host-tested since there is no wasm test runner in this project.
// Only the `web_sys` ceremony wrapper inside stays gated to `hydrate` alone.
#[cfg(any(feature = "hydrate", test))]
pub mod webauthn_browser;

#[cfg(feature = "ssr")]
pub mod auth;
#[cfg(feature = "ssr")]
pub mod context;
#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod email;
#[cfg(feature = "ssr")]
pub mod entries;
#[cfg(feature = "ssr")]
pub mod entry_key;
#[cfg(feature = "ssr")]
pub mod passkey;
#[cfg(feature = "ssr")]
pub mod rate_limit;
#[cfg(feature = "ssr")]
pub mod schema;
#[cfg(feature = "ssr")]
pub mod server;
#[cfg(feature = "ssr")]
pub mod session;
/// Router construction shared by `main` and the integration tests.
///
/// Not `#[cfg(test)]`: `tests/` is a separate crate and cannot see
/// `#[cfg(test)]` items. Gated on `ssr` so it never reaches wasm.
#[cfg(feature = "ssr")]
pub mod test_support;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::app::App);
}
