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
