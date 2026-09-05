//! The upper-right account control: sign-in popover when signed out, a small
//! menu when signed in.

use chrono::NaiveDate;
use leptos::either::Either;
use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

use crate::auth_ctx::{AuthCtx, forget_device_key, sign_out};
use crate::date::to_iso;
use crate::encryption_ctx::EncryptionCtx;
use crate::server_fns::session::{logout, request_magic_link};

/// The local part of an address, capped, for the corner label.
///
/// `split_once`, not `split(…).next()`: the latter's `unwrap_or` fallback is
/// unreachable — `split` always yields at least one item — so an address with
/// no `@` took the same branch as one with, and the test for it tested
/// nothing. `split_once` returns `None` exactly when there is no `@`, which
/// is the case the fallback is for.
pub fn short_name(email: &str) -> String {
    let local = email.split_once('@').map_or(email, |(local, _)| local);
    if local.chars().count() <= 18 {
        local.to_string()
    } else {
        local.chars().take(18).chain(std::iter::once('…')).collect()
    }
}

#[component]
pub fn AccountMenu(
    /// The day currently in view, so the signed-in menu can link to its
    /// week. `None` on routes that don't name one (`/`, `/account`) — there
    /// the "This week" link is omitted rather than guessed.
    date: Option<NaiveDate>,
) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let open = RwSignal::new(false);

    view! {
        <div class="relative">
            {move || match auth.user.get() {
                None => Either::Left(view! {
                    <button
                        type="button"
                        class="text-sm text-gray-600 hover:text-gray-900 px-2 py-1 rounded"
                        on:click=move |_| open.update(|o| *o = !*o)
                    >
                        "Sign in"
                    </button>
                }),
                Some(email) => Either::Right(view! {
                    <button
                        type="button"
                        class="flex items-center gap-2 text-sm text-gray-700 hover:text-gray-900 px-2 py-1 rounded"
                        on:click=move |_| open.update(|o| *o = !*o)
                    >
                        <span class="w-6 h-6 rounded-full bg-blue-100 text-blue-700 text-xs font-bold flex items-center justify-center">
                            {email.chars().next().unwrap_or('?').to_uppercase().to_string()}
                        </span>
                        <span>{short_name(&email)}</span>
                        <span class="text-gray-400 text-xs">"▾"</span>
                    </button>
                }),
            }}

            <div
                class="absolute right-0 top-9 w-64 bg-white border border-gray-200 rounded-lg shadow-lg p-3 z-20"
                class:hidden=move || !open.get()
            >
                {move || match auth.user.get() {
                    None => Either::Left(view! { <SignInPanel/> }),
                    Some(email) => Either::Right(
                        view! { <SignedInPanel email=email date=date open=open/> },
                    ),
                }}
            </div>
        </div>
    }
}

#[component]
fn SignedInPanel(
    email: String,
    date: Option<NaiveDate>,
    /// This panel's own popover, so signing out can close it.
    open: RwSignal<bool>,
) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let status = RwSignal::new(String::new());

    let on_sign_out = move |_| {
        spawn_local(async move {
            // `sign_out` invalidates anything in flight and forgets this
            // device's data key first, regardless of what the server then
            // says, which is why the whole call goes through it rather than
            // adding a line to either arm below (spec section 6.7). Clearing
            // `auth.user` on success re-runs `EncryptionCtx`'s probe, and a
            // probe for a signed-out visitor publishes `Disabled`, which
            // holds no key — but that happens a round trip later, which is
            // what `signing_out` covers.
            match sign_out(
                move || encryption.signing_out(),
                forget_device_key(),
                logout(),
            )
            .await
            {
                Ok(()) => {
                    // Closed first, deliberately: the popover is describing
                    // an account that is about to stop existing, and clearing
                    // `auth.user` disposes this very panel. Setting `open`
                    // beforehand keeps that write clear of the teardown it
                    // triggers.
                    open.set(false);
                    // Clearing the signal flips `AuthCtx::backend()` to Local,
                    // which makes `use_persistent` re-read from localStorage —
                    // no reload needed.
                    auth.user.set(None);
                }
                Err(e) => {
                    // A failed sign-out leaves the session cookie in place.
                    // Silence here is the difference between a user knowing
                    // to try again and one walking away from a shared
                    // machine believing they are signed out.
                    //
                    // The device key is gone by now either way, so a session
                    // that survives this reads as unlocked until the page is
                    // reloaded and locked from then on. One unlock prompt is
                    // the right side of that trade.
                    error!("sign-out failed: {e}");
                    status.set("Couldn't sign out. Check your connection and try again.".into());
                }
            }
        });
    };

    view! {
        <p class="text-xs text-gray-500 truncate pb-2 mb-2 border-b border-gray-100">{email}</p>
        // Only on routes that already name a day: there is no client-only
        // "today" to fall back on here (`date::today_local` doesn't exist
        // under `ssr`), so a dateless route just omits the link rather than
        // guessing — the same tradeoff `AppHeader` makes for `DatePicker`.
        {date.map(|date| view! {
            <A
                href=format!("/week/{}", to_iso(date))
                attr:class="block text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5 no-underline"
            >
                "This week"
            </A>
        })}
        <A
            href="/account"
            attr:class="block text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5 no-underline"
        >
            "Passkeys"
        </A>
        <button
            type="button"
            class="w-full text-left text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5"
            on:click=on_sign_out
        >
            "Sign out"
        </button>
        {move || {
            let s = status.get();
            (!s.is_empty()).then(|| view! { <p class="text-xs text-red-600 mt-2">{s}</p> })
        }}
    }
}

/// Email entry, plus the passkey shortcut.
///
/// Both paths end in the same "check your email" style confirmation and
/// neither reveals whether the address is registered — see invariant I5.
#[component]
fn SignInPanel() -> impl IntoView {
    let email = RwSignal::new(String::new());
    let sent = RwSignal::new(false);
    let status = RwSignal::new(String::new());

    let send = move |_| {
        let address = email.get_untracked();
        spawn_local(async move {
            // The result is deliberately not branched on: success and every
            // failure mode look the same to the user, which is what stops
            // this form being an account-existence oracle.
            let _ = request_magic_link(address).await;
            sent.set(true);
        });
    };

    let use_passkey = move |_| {
        #[cfg(feature = "hydrate")]
        {
            let typed = email.get_untracked();
            spawn_local(async move {
                match run_passkey_login(typed).await {
                    Ok(()) => {
                        if let Some(w) = web_sys::window() {
                            let _ = w.location().reload();
                        }
                    }
                    Err(e) => status.set(crate::webauthn_browser::friendly_error(e)),
                }
            });
        }
    };

    view! {
        {move || if sent.get() {
            Either::Left(view! {
                <div>
                    <p class="text-sm font-semibold text-gray-900 mb-1">"Check your email"</p>
                    // No specific lifetime: `MAGIC_LINK_TTL_SECONDS` is
                    // operator-tunable and read only under `ssr`
                    // (`magic_link::ttl`), so this panel — which renders on
                    // both targets and must hydrate byte-identically —
                    // cannot know it. The mailed link states its own real
                    // TTL (`email::magic_link_email`), which is where the
                    // number belongs anyway.
                    <p class="text-xs text-gray-600">
                        "If that address has an account or can have one, a sign-in link is on its way. It works once, and the email says how long it lasts."
                    </p>
                    <button
                        type="button"
                        class="mt-3 w-full text-sm border border-gray-300 rounded py-1.5 hover:bg-gray-50"
                        on:click=move |_| sent.set(false)
                    >
                        "Use a different address"
                    </button>
                </div>
            })
        } else {
            Either::Right(view! {
                <div>
                    <p class="text-sm font-semibold text-gray-900 mb-2">"Sign in"</p>
                    <label class="block text-xs text-gray-500 mb-1" for="signin-email">"Email"</label>
                    <input
                        id="signin-email"
                        type="email"
                        autocomplete="username webauthn"
                        class="w-full border border-gray-300 rounded px-2 py-1.5 text-sm mb-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        prop:value=move || email.get()
                        on:input=move |ev| email.set(event_target_value(&ev))
                    />
                    <button
                        type="button"
                        class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-1.5 hover:bg-blue-700"
                        on:click=send
                    >
                        "Email me a link"
                    </button>
                    <p class="text-center text-xs text-gray-400 my-2">"or"</p>
                    <button
                        type="button"
                        class="w-full border border-gray-300 text-sm rounded py-1.5 hover:bg-gray-50"
                        on:click=use_passkey
                    >
                        "Use a passkey"
                    </button>
                    <p class="text-xs text-gray-600 mt-2">
                        "An account syncs your entries across devices. Without one, everything stays in this browser."
                    </p>
                    {move || {
                        let s = status.get();
                        (!s.is_empty()).then(|| view! { <p class="text-xs text-red-600 mt-2">{s}</p> })
                    }}
                </div>
            })
        }}
    }
}

/// Runs the sign-in ceremony, and rides its PRF output straight into an
/// unlock (spec section 6.2). An empty address uses the discoverable flow,
/// which is what makes the button work with nothing typed.
///
/// Signing in already costs one authenticator interaction. Evaluating the
/// PRF on *that* assertion — which is what the fixed application salt in
/// spec section 4.2 buys — means an encrypted account is signed in and
/// unlocked from a single Touch ID prompt, with no second ceremony and no
/// trip through the unlock screen.
#[cfg(feature = "hydrate")]
async fn run_passkey_login(typed_email: String) -> Result<(), String> {
    use crate::crypto::wire::APP_SALT;
    use crate::server_fns::passkey::{passkey_login_finish, passkey_login_start};
    use crate::webauthn_browser;

    let email = (!typed_email.trim().is_empty()).then_some(typed_email);
    let challenge = passkey_login_start(email)
        .await
        .map_err(|e| e.to_string())?;
    let (credential, prf_output) = webauthn_browser::authenticate_with_prf(&challenge, APP_SALT)
        .await
        .map_err(|e| e.to_string())?;
    passkey_login_finish(credential.clone())
        .await
        .map_err(|e| e.to_string())?;

    // Past this line the user is signed in, and nothing below may take that
    // back. An authenticator with no PRF, a browser that ignored the
    // extension, or a result in a shape this build did not expect all arrive
    // here as `None` — see `authenticate_with_prf` — and all of them are an
    // ordinary sign-in that lands in a `Locked` session the recovery code
    // opens. Turning any of them into an error would lock the user out of
    // the application itself, which is a far worse failure than the one this
    // feature exists to prevent.
    if let Some(prf_output) = prf_output {
        unlock_after_sign_in(&credential, &prf_output).await;
    }
    Ok(())
}

/// Turns the sign-in assertion's PRF output into this device's data key, or
/// gives up quietly.
///
/// **Returns `()`, and that is the guarantee rather than a convention:** a
/// function with no error type cannot contribute one to the sign-in that
/// called it, whatever is added to its body later.
///
/// It publishes nothing into [`EncryptionCtx`](crate::encryption_ctx::EncryptionCtx)
/// either, because there is nothing to publish into: signing in reloads the
/// page (see the caller), so the key's only job here is to reach the
/// keystore, where the next load's probe picks it up as `Unlocked`. That
/// also settles the identity question `EncryptionCtx::unlock` answers for an
/// in-page unlock — a key must never be used for an account other than the
/// one it was derived for. Here the address comes from `current_session`,
/// the server's own view of the cookie it has just issued, and
/// `SessionKey::remember` files the keystore record under it; `keystore::get`
/// then hands that record back only to a matching address. Guessing the
/// address instead — from what was typed, which the discoverable flow leaves
/// empty and which the server normalizes anyway — would file the record
/// under a name the next load does not ask for, and the reward for one Touch
/// ID prompt would be an unlock screen.
///
/// The comparison `EncryptionCtx::unlock` makes is not available here and
/// cannot be: the page has not reloaded, so `AuthCtx::user` still says
/// whatever it said before this sign-in. The guard this path *can* honour is
/// the one inside `SessionKey::remember` — a sign-out or a "Lock now" issued
/// since the ceremony started outranks the write.
#[cfg(feature = "hydrate")]
async fn unlock_after_sign_in(credential_json: &str, prf_output: &[u8]) {
    use crate::crypto::flow::credential_id_from_response;
    use crate::crypto::{choose_route, unlock_with_prf};
    use crate::server_fns::encryption::{encryption_status, encryption_wraps};
    use crate::server_fns::session::current_session;

    let Ok(Some(user)) = current_session().await else {
        error!("signed in, but could not read back which account to unlock");
        return;
    };
    let Ok(status) = encryption_status()
        .await
        .inspect_err(|e| error!("could not read the account's encryption status: {e}"))
    else {
        return;
    };
    // Not an error and not worth a log line: an account with no encryption
    // has no key to unlock, so the PRF output is simply discarded (spec
    // section 6.2).
    if !status.enabled {
        return;
    }

    let Ok(wraps) = encryption_wraps()
        .await
        .inspect_err(|e| error!("could not read the account's key wraps: {e}"))
    else {
        return;
    };
    let Some(credential_id) = credential_id_from_response(credential_json) else {
        error!("the passkey that signed in did not identify itself to this browser");
        return;
    };
    let Some(route) = choose_route(&wraps, Some(&credential_id)) else {
        // The credential signs in but has no wrap of its own: enrolled
        // before encryption was turned on, or its keying step never
        // finished. `/account` labels it, and the unlock prompt offers the
        // recovery code — neither is this function's business.
        return;
    };
    // The key is never published anywhere — signing in reloads the page —
    // so all that matters is that it reaches the keystore, which is what the
    // reload's probe reads back. The write is a step of its own rather than
    // a side effect of the unlock, so that the guard on it is visible here:
    // `SessionKey::remember` refuses if this device has been asked to forget
    // its key since the ceremony began, which is the only check this path
    // can make (there is no live `AuthCtx` to compare against yet).
    match unlock_with_prf(prf_output, &route.wrapped_key, &user).await {
        Ok(key) => {
            if let Err(e) = key.remember().await {
                error!("the key the sign-in opened could not be stored on this device: {e}");
            }
        }
        Err(e) => error!("the passkey that signed in could not open this account's key: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::short_name;

    #[test]
    fn shows_the_local_part() {
        assert_eq!(short_name("steve@javapl.us"), "steve");
    }

    #[test]
    fn truncates_a_long_local_part() {
        let out = short_name("averyverylonglocalpartindeed@example.com");
        assert_eq!(out.chars().count(), 19, "18 chars plus an ellipsis");
        assert!(out.ends_with('…'));
    }

    #[test]
    fn an_address_without_an_at_is_used_directly() {
        assert_eq!(short_name("bob"), "bob");
    }
}
