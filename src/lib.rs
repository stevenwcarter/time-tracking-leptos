#![recursion_limit = "512"]

pub mod app;
pub mod clipboard;
pub mod components;
pub mod storage;

#[cfg(feature = "ssr")]
pub mod db;
#[cfg(feature = "ssr")]
pub mod schema;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(crate::app::App);
}
