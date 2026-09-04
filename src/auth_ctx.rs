//! Who is signed in, as far as the view layer is concerned.

use leptos::prelude::*;

#[cfg(feature = "ssr")]
use crate::context::AppCtx;
use crate::storage::Backend;
#[cfg(feature = "hydrate")]
use wasm_bindgen::JsCast;

/// The name of the meta tag carrying the signed-in address through
/// hydration. See [`initial_user`].
pub const USER_META: &str = "tt-user";

/// The signed-in identity, shared across the component tree.
#[derive(Clone, Copy)]
pub struct AuthCtx {
    /// The signed-in email address, or `None` when signed out.
    pub user: RwSignal<Option<String>>,
}

impl AuthCtx {
    /// Where this session's entries live.
    ///
    /// Signing in or out flips this, and `use_persistent` re-reads because
    /// it is a signal.
    pub fn backend(self) -> Signal<Backend> {
        let user = self.user;
        Signal::derive(move || {
            if user.get().is_some() {
                Backend::Remote
            } else {
                Backend::Local
            }
        })
    }

    /// Whether a user is currently signed in.
    pub fn is_signed_in(self) -> bool {
        self.user.get().is_some()
    }
}

/// The signed-in address as of the first render, on either target.
///
/// Server: read from the request's [`AppCtx`] — the already-verified
/// session claims the session middleware attached. Browser: read from the
/// `<meta name="tt-user">` tag `shell()` wrote into the document. Both
/// compute the same value from the same underlying fact (the session
/// cookie), so the first client render matches the server's DOM exactly,
/// with no `Resource` and no `<Suspense>` — see CLAUDE.md's hydration
/// contract.
///
/// This is the *only* thing the server is allowed to know about the user
/// for rendering purposes; entry bodies stay unrendered (invariant I1).
pub fn initial_user() -> Option<String> {
    #[cfg(feature = "ssr")]
    {
        use_context::<AppCtx>().and_then(|ctx| ctx.claims.map(|claims| claims.email))
    }
    #[cfg(feature = "hydrate")]
    {
        web_sys::window()?
            .document()?
            .query_selector(&format!("meta[name=\"{USER_META}\"]"))
            .ok()
            .flatten()?
            .dyn_into::<web_sys::HtmlMetaElement>()
            .ok()
            .map(|meta| meta.content())
            .filter(|content| !content.is_empty())
    }
    #[cfg(not(any(feature = "ssr", feature = "hydrate")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `backend()` is the one thing standing between a signed-in user's
    /// entries and the server versus a signed-out user's `localStorage`. It
    /// is called exactly once (`app.rs`'s `DayView`), and nothing else in
    /// the suite exercises its output: the SSR tests only ever see
    /// `Persistent`'s synchronous `None` regardless of backend, so an
    /// inverted condition here would not fail a single existing test — it
    /// would just silently send the wrong users' data to the wrong place.
    #[test]
    fn signed_out_backend_is_local() {
        let runtime = Owner::new();
        runtime.with(|| {
            let auth = AuthCtx {
                user: RwSignal::new(None),
            };
            assert_eq!(auth.backend().get_untracked(), Backend::Local);
        });
        runtime.cleanup();
    }

    #[test]
    fn signed_in_backend_is_remote() {
        let runtime = Owner::new();
        runtime.with(|| {
            let auth = AuthCtx {
                user: RwSignal::new(Some("alice@example.com".to_string())),
            };
            assert_eq!(auth.backend().get_untracked(), Backend::Remote);
        });
        runtime.cleanup();
    }
}
