//! Clipboard access.
//!
//! Both targets expose the same signature so call sites stay `cfg`-free —
//! only the side effect differs, never the rendered output (spec invariant I4).

/// Copies `text` to the system clipboard. Fire-and-forget.
#[cfg(feature = "hydrate")]
pub fn copy_to_clipboard(text: String) {
    use wasm_bindgen_futures::JsFuture;

    leptos::task::spawn_local(async move {
        let Some(window) = web_sys::window() else {
            return;
        };
        // Rejects when the document lacks focus or permission is denied;
        // there is no useful recovery, so the copy is simply dropped.
        let _ = JsFuture::from(window.navigator().clipboard().write_text(&text)).await;
    });
}

/// No-op on the server: there is no clipboard to write to.
#[cfg(not(feature = "hydrate"))]
pub fn copy_to_clipboard(_text: String) {}
