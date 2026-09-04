#![recursion_limit = "512"]

pub mod app;
pub mod auth_ctx;
pub mod clipboard;
pub mod components;
pub mod date;
pub mod dto;
pub mod server_fns;
pub mod storage;
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
