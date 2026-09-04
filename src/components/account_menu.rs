//! The upper-right account control: sign-in popover when signed out, a small
//! menu when signed in.

use leptos::either::Either;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;

use crate::auth_ctx::AuthCtx;
use crate::server_fns::session::{logout, request_magic_link};

/// The local part of an address, capped, for the corner label.
pub fn short_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or(email);
    if local.chars().count() <= 18 {
        local.to_string()
    } else {
        local.chars().take(18).chain(std::iter::once('…')).collect()
    }
}

#[component]
pub fn AccountMenu() -> impl IntoView {
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
                    Some(email) => Either::Right(view! { <SignedInPanel email=email/> }),
                }}
            </div>
        </div>
    }
}

#[component]
fn SignedInPanel(email: String) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");

    let sign_out = move |_| {
        spawn_local(async move {
            if logout().await.is_ok() {
                // Clearing the signal flips `AuthCtx::backend()` to Local,
                // which makes `use_persistent` re-read from localStorage —
                // no reload needed.
                auth.user.set(None);
            }
        });
    };

    view! {
        <p class="text-xs text-gray-500 truncate pb-2 mb-2 border-b border-gray-100">{email}</p>
        <A
            href="/account"
            attr:class="block text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5 no-underline"
        >
            "Passkeys"
        </A>
        <button
            type="button"
            class="w-full text-left text-sm text-gray-700 hover:bg-gray-50 rounded px-2 py-1.5"
            on:click=sign_out
        >
            "Sign out"
        </button>
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
                    <p class="text-xs text-gray-600">
                        "If that address has an account or can have one, a sign-in link is on its way. It works once and expires in 15 minutes."
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

/// Runs the sign-in ceremony. An empty address uses the discoverable flow,
/// which is what makes the button work with nothing typed.
#[cfg(feature = "hydrate")]
async fn run_passkey_login(typed_email: String) -> Result<(), String> {
    use crate::server_fns::passkey::{passkey_login_finish, passkey_login_start};
    use crate::webauthn_browser;

    let email = (!typed_email.trim().is_empty()).then_some(typed_email);
    let challenge = passkey_login_start(email)
        .await
        .map_err(|e| e.to_string())?;
    let credential = webauthn_browser::authenticate(&challenge)
        .await
        .map_err(|e| e.to_string())?;
    passkey_login_finish(credential)
        .await
        .map_err(|e| e.to_string())
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
