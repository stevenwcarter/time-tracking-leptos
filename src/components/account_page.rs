//! `/account` — passkey management.
//!
//! A route rather than a popover: it is the natural home for phase 2's
//! encryption settings, and a link somebody can be sent when a passkey
//! misbehaves.

use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::components::A;

use crate::auth_ctx::AuthCtx;
use crate::components::header::AppHeader;
use crate::dto::PasskeyListItem;
use crate::server_fns::passkey::{passkey_delete, passkey_list, passkey_rename};

/// Formats a passkey-management error for display.
///
/// `friendly_error` lives in `webauthn_browser`, which is compiled only for
/// `hydrate` (or `test`) — see `lib.rs`'s module gate. The `not(hydrate)`
/// branch below is dead in practice: `remove`'s and `rename`'s `on:click`
/// handlers only ever run in the browser. It exists purely so this call
/// site type-checks under a plain `ssr` build too, the same cfg-swap
/// `auth_ctx::initial_user` uses for the same reason.
fn passkey_error(e: ServerFnError) -> String {
    #[cfg(feature = "hydrate")]
    {
        crate::webauthn_browser::friendly_error(e.to_string())
    }
    #[cfg(not(feature = "hydrate"))]
    {
        e.to_string()
    }
}

#[component]
pub fn AccountPage() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");

    view! {
        <Title text="Account — Time Tracker"/>
        <div class="min-h-screen bg-gray-50">
            <AppHeader date=None/>
            <div class="w-full max-w-2xl mx-auto px-4 py-8">
                {move || match auth.user.get() {
                    None => Either::Left(view! {
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <h1 class="text-xl font-semibold text-gray-800 mb-2">"Passkeys"</h1>
                            <p class="text-sm text-gray-600">
                                "Sign in to manage passkeys for your account."
                            </p>
                            <A href="/" attr:class="inline-block mt-4 text-sm text-blue-600 no-underline">
                                "Back to today"
                            </A>
                        </div>
                    }),
                    Some(email) => Either::Right(view! { <PasskeySection email=email/> }),
                }}
            </div>
        </div>
    }
}

#[component]
fn PasskeySection(email: String) -> impl IntoView {
    // `Resource` here is safe: this route is client-navigated and never part
    // of the day view's SSR path, so it does not affect the synchronous
    // render the SSR tests rely on. Created at the top of the component,
    // never inside a closure, so SSR's render walk cannot construct it twice.
    let rows = Resource::new(|| (), |_| async { passkey_list().await });
    let status = RwSignal::new(String::new());

    let add = move |_| {
        #[cfg(feature = "hydrate")]
        leptos::task::spawn_local(async move {
            match run_registration().await {
                Ok(()) => {
                    status.set("Passkey added.".to_string());
                    rows.refetch();
                }
                Err(e) => status.set(crate::webauthn_browser::friendly_error(e)),
            }
        });
    };

    let remove = move |id: i32| {
        leptos::task::spawn_local(async move {
            match passkey_delete(id).await {
                Ok(()) => {
                    status.set("Passkey removed.".to_string());
                    rows.refetch();
                }
                Err(e) => status.set(passkey_error(e)),
            }
        });
    };

    let rename = move |id: i32, name: String| {
        leptos::task::spawn_local(async move {
            match passkey_rename(id, name).await {
                Ok(()) => {
                    status.set("Passkey renamed.".to_string());
                    rows.refetch();
                }
                Err(e) => status.set(passkey_error(e)),
            }
        });
    };

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <A href="/" attr:class="text-sm text-blue-600 no-underline">"‹ Back to today"</A>
            <h1 class="text-xl font-semibold text-gray-800 mt-3 mb-1">"Passkeys"</h1>
            <p class="text-sm text-gray-500 mb-5">{email}</p>

            // Bare `Suspend::new(...)`, not wrapped in an outer `move ||`:
            // `<Suspense>`'s `children` prop is already a re-callable
            // closure, so it re-invokes this block itself whenever `rows`
            // re-suspends (e.g. after `refetch()`). An extra `move ||` here
            // inserts a second reactive-marker pair at the Suspense
            // boundary that SSR and hydrate don't agree on, producing
            // "expected marker, found <element>" hydration errors.
            <Suspense fallback=|| view! { <p class="text-sm text-gray-500">"Loading…"</p> }>
                {Suspend::new(async move {
                    match rows.await {
                        Ok(list) if list.is_empty() => EitherOf3::A(view! {
                            <p class="text-sm text-gray-600">
                                "No passkeys yet. Add one to sign in with Touch ID, Windows Hello, or your phone — no email round trip."
                            </p>
                        }),
                        Ok(list) => EitherOf3::B(view! {
                            <ul class="divide-y divide-gray-100">
                                {list.into_iter()
                                    .map(|row| view! { <PasskeyRow row=row on_remove=remove on_rename=rename/> })
                                    .collect_view()}
                            </ul>
                        }),
                        Err(e) => EitherOf3::C(view! {
                            <p class="text-sm text-red-600">
                                {passkey_error(e)}
                            </p>
                        }),
                    }
                })}
            </Suspense>

            <button
                type="button"
                class="mt-6 bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700"
                on:click=add
            >
                "Add a passkey"
            </button>
            {move || {
                let s = status.get();
                (!s.is_empty()).then(|| view! { <p class="mt-3 text-sm text-gray-600">{s}</p> })
            }}
        </div>
    }
}

#[component]
fn PasskeyRow(
    row: PasskeyListItem,
    on_remove: impl Fn(i32) + Copy + Send + 'static,
    on_rename: impl Fn(i32, String) + Copy + Send + 'static,
) -> impl IntoView {
    let id = row.id;
    let editing = RwSignal::new(false);
    let draft = RwSignal::new(row.name);
    let last_used = row.last_used.unwrap_or_else(|| "Never".to_string());
    let added = row.added;

    let commit = move |_| {
        editing.set(false);
        on_rename(id, draft.get_untracked());
    };

    view! {
        <li class="flex items-start justify-between gap-3 py-3">
            <div class="min-w-0">
                {move || if editing.get() {
                    Either::Left(view! {
                        <input
                            class="border border-gray-300 rounded px-2 py-1 text-sm w-48"
                            prop:value=move || draft.get()
                            on:input=move |ev| draft.set(event_target_value(&ev))
                            on:blur=commit
                        />
                    })
                } else {
                    Either::Right(view! {
                        <button
                            type="button"
                            class="text-sm font-medium text-gray-900 hover:text-blue-600"
                            on:click=move |_| editing.set(true)
                        >
                            {move || draft.get()}
                            <span class="text-gray-400 ml-1 text-xs">"✎"</span>
                        </button>
                    })
                }}
                <p class="text-xs text-gray-500">"Added "{added}</p>
                <p class="text-xs text-gray-500">"Last used: "{last_used}</p>
            </div>
            <button
                type="button"
                class="text-sm text-red-600 hover:text-red-800 shrink-0"
                on:click=move |_| on_remove(id)
            >
                "Remove"
            </button>
        </li>
    }
}

/// Runs the registration ceremony, including the round trip to
/// `passkey_register_finish`.
///
/// `webauthn_browser::register` returns `(credential_json, prf_capable)` —
/// both values are threaded straight into `passkey_register_finish`
/// unmodified. `prf_capable` cannot be recovered from the credential JSON
/// alone (`toJSON()` omits extension results), so dropping or defaulting it
/// here would silently record every passkey enrolled through this page as
/// not-PRF-capable, forcing phase 2 to conclude none of them can derive an
/// encryption key.
#[cfg(feature = "hydrate")]
async fn run_registration() -> Result<(), String> {
    use crate::server_fns::passkey::{passkey_register_finish, passkey_register_start};
    use crate::webauthn_browser;

    let challenge = passkey_register_start().await.map_err(|e| e.to_string())?;
    // `prf_capable` comes from getClientExtensionResults(), which toJSON()
    // does not include. Phase 1 only records it (spec section 9.3).
    let (credential, prf_capable) = webauthn_browser::register(&challenge)
        .await
        .map_err(|e| e.to_string())?;
    passkey_register_finish(credential, prf_capable)
        .await
        .map_err(|e| e.to_string())
}
