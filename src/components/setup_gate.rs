//! What a signed-in account with no encryption gets instead of its entries,
//! and the way back out of it.
//!
//! Spec section 4.1. The server stores entries only for accounts that have
//! encryption (invariant E9), so such an account cannot save anything — and
//! an editable box that silently refuses to save is worse than no box: the
//! user types, nothing persists, and nothing says so. The day and week views
//! therefore mount [`SetupGate`] in place of their content and send the user
//! to `/account`, where [`SetupBanner`] says why they arrived there.
//!
//! **The escape is what stops the gate being a lock-out.** Signing out
//! returns this browser to `Backend::Local`, which is fully functional and
//! stores nothing on the server (spec section 1.2's non-goal) — the honest
//! offer to somebody who signed in on a borrowed machine, or who wants to
//! look before committing. Without it the only route past the gate is a
//! ceremony they may not want to perform on this device.
//!
//! Neither component is ever server-rendered. Both hang off
//! [`Writes::SetupRequired`](crate::encryption_ctx::Writes::SetupRequired),
//! which needs the probe's answer, and the server seeds a signed-in visitor
//! at `EncryptionState::Unknown` (invariant E2) and a signed-out one at
//! `Backend::Local`, where the same state is not gated at all.

use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

use crate::auth_ctx::{AuthCtx, forget_device_key, sign_out};
use crate::encryption_ctx::EncryptionCtx;
use crate::server_fns::session::logout;

/// Shown in place of the day and week views for an account that cannot
/// store anything yet.
///
/// It both navigates to `/account` and renders a way there. The navigation
/// is what makes the views "unreachable" in the spec's sense; the markup is
/// what a browser that has not run the effect yet — or a user who arrived
/// back here — still has something to act on.
#[component]
pub fn SetupGate() -> impl IntoView {
    // Browser-only, and an `Effect` rather than a redirect the server could
    // have issued: the state that mounts this component exists only once the
    // post-hydration probe has answered, so there is no server render in
    // which the decision could have been made.
    //
    // `replace`, for `TodayRedirect`'s reason. A pushed entry would leave
    // the back button pointing at a page that immediately bounces forward
    // again, which reads as a broken button rather than as a gate.
    #[cfg(feature = "hydrate")]
    {
        use leptos_router::NavigateOptions;
        use leptos_router::hooks::use_navigate;

        let navigate = use_navigate();
        Effect::new(move |_| {
            navigate(
                "/account",
                NavigateOptions {
                    replace: true,
                    ..Default::default()
                },
            );
        });
    }

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h2 class="text-lg font-semibold text-gray-800 mb-1">"Set up encryption to save entries"</h2>
            // States the constraint rather than apologising for it: nothing
            // is broken and nothing is lost, there is simply nowhere for a
            // save to go until the account has a key.
            <p class="text-sm text-gray-600 mb-4">
                "Your entries are encrypted in this browser before they leave it, and your \
                 account can't store anything until that's set up."
            </p>
            <A
                href="/account"
                attr:class="inline-block bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 no-underline hover:bg-blue-700"
            >
                "Set up encryption"
            </A>
        </div>
    }
}

/// The gate's explanation at the top of `/account`, and the way out of it.
///
/// Above the passkey and encryption sections rather than beside them,
/// because a user who was moved here did not ask to be: the first thing on
/// the page has to be why.
#[component]
pub fn SetupBanner() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let status = RwSignal::new(String::new());

    let use_this_device_only = move |_| {
        // Through `sign_out` like every other control, and built in the
        // handler rather than inside the `spawn_local`: its first step is
        // synchronous precisely so that a probe still in flight is
        // invalidated at the click rather than a microtask later (spec
        // section 6.7).
        let signing_out = sign_out(encryption, forget_device_key(), logout());
        spawn_local(async move {
            match signing_out.await {
                // Clearing the signal *is* "use this device only":
                // `AuthCtx::backend()` flips to `Local`, which turns this
                // session's `Writes::SetupRequired` into `Accepted`, and
                // `use_persistent` re-reads `localStorage` in place. No
                // reload, and nothing to confirm — the page changing under
                // them is the confirmation.
                Ok(()) => auth.user.set(None),
                Err(e) => status.set(format!("Couldn't sign out: {e}")),
            }
        });
    };

    view! {
        <div class="mb-6 rounded-lg border border-amber-200 bg-amber-50 p-4">
            <h2 class="text-base font-semibold text-amber-900 mb-1">
                "Turn on encryption to store entries"
            </h2>
            <p class="text-sm text-amber-900 mb-4">
                "Nothing you type is saved to your account yet. The server only ever holds \
                 entries it can't read, so it won't store any until this account has a key."
            </p>
            <button
                type="button"
                class="text-sm font-semibold border border-amber-300 bg-white text-amber-900 rounded px-3 py-2 hover:bg-amber-100"
                on:click=use_this_device_only
            >
                "Sign out and use this device only"
            </button>
            // The offer is only honest if it says what is given up, and what
            // is not: local mode is the whole app, minus the account.
            <p class="text-xs text-amber-800 mt-2">
                "Your entries stay in this browser and never reach the server. Everything else \
                 works the same, and you can sign in again whenever you like."
            </p>
            {move || {
                let line = status.get();
                (!line.is_empty()).then(|| view! { <p class="text-xs text-red-700 mt-2">{line}</p> })
            }}
        </div>
    }
}
