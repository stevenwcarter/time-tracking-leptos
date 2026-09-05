//! Who is signed in, as far as the view layer is concerned — and what
//! leaving takes with it.

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

/// Forgets the data key this device has stored, whatever it holds.
///
/// The one call spec section 6.7 says sign-out gains. Deleting a record
/// that is not there succeeds, so this is safe on a device that never
/// unlocked and on an account that was never encrypted.
///
/// A failure is logged rather than returned, and that is the whole reason
/// this returns `()`: signing out must not become refusable because
/// IndexedDB would not cooperate, and there is nowhere to put the message
/// anyway — the panel that would show it is torn down by the very sign-out
/// that produced it. "Lock now" is the path that *can* report a failed
/// clear, and does; see [`EncryptionCtx::lock`](crate::encryption_ctx::EncryptionCtx::lock).
pub async fn forget_device_key() {
    #[cfg(feature = "hydrate")]
    if let Err(e) = crate::crypto::keystore::clear().await {
        leptos::logging::error!("sign-out could not forget this device's data key: {e}");
    }
}

/// Signs out on this device: forget the key, then end the session.
///
/// Both controls run through here — the account menu's "Sign out" and
/// `/account`'s "Sign out everywhere" — because the *order* is the security
/// property and two copies of it would drift. `forget` is awaited to
/// completion before `end_session` is so much as started, and its outcome
/// is never consulted in either direction: a browser that is locally signed
/// out must not still hold a usable data key for whoever opens it next, and
/// that has to hold whether or not the server agreed the sign-out happened
/// (spec section 6.7).
///
/// The server's answer is passed straight back, so a caller still learns
/// that its half failed and can say so. What it cannot do is make the key
/// clearing wait on that answer.
///
/// Both halves are parameters rather than calls in the body so the order is
/// pinned by a host test: the real ones reach IndexedDB and the network,
/// neither of which exists off the browser, so nothing about the sequence
/// would otherwise be checkable by anything but reading it.
pub async fn sign_out(
    forget: impl Future<Output = ()>,
    end_session: impl Future<Output = Result<(), ServerFnError>>,
) -> Result<(), ServerFnError> {
    forget.await;
    end_session.await
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
    use std::cell::RefCell;

    use super::*;
    use crate::test_util::block_on;

    /// Records which half of [`sign_out`] ran, and in what order.
    fn trace() -> RefCell<Vec<&'static str>> {
        RefCell::new(Vec::new())
    }

    /// Spec section 6.7's ordering: the device key is gone before the
    /// server is asked for anything.
    ///
    /// The `hydrate` half of this — the IndexedDB delete itself — has no
    /// host equivalent and is reviewed by reading `crypto::keystore`. What
    /// is checkable here, and is the part a later edit could quietly
    /// change, is the sequence.
    #[test]
    fn signing_out_forgets_the_device_key_before_it_ends_the_session() {
        let steps = trace();
        let done = block_on(sign_out(
            async { steps.borrow_mut().push("forget") },
            async {
                steps.borrow_mut().push("end session");
                Ok(())
            },
        ));
        assert!(done.is_ok());
        assert_eq!(*steps.borrow(), ["forget", "end session"]);
    }

    /// The case the control exists for. A sign-out the server refused still
    /// signs the user out of *this browser's* stored key — otherwise
    /// somebody who was told "couldn't sign out", shrugged, and walked away
    /// from a shared machine has left a working data key behind them.
    ///
    /// The failure is still reported: the assertion on `done` is what stops
    /// this being satisfied by swallowing the error instead.
    #[test]
    fn a_sign_out_the_server_refused_still_forgets_the_device_key() {
        let steps = trace();
        let done = block_on(sign_out(
            async { steps.borrow_mut().push("forget") },
            async {
                steps.borrow_mut().push("end session");
                Err(ServerFnError::ServerError("offline".to_string()))
            },
        ));
        assert!(
            done.is_err(),
            "the caller must still learn the server failed"
        );
        assert_eq!(
            *steps.borrow(),
            ["forget", "end session"],
            "the key clearing must not be conditional on the server call"
        );
    }

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
