//! `/account` — passkey management, and the encryption panel beside it.
//!
//! A route rather than a popover: it is the natural home for the encryption
//! settings, and a link somebody can be sent when a passkey misbehaves.
//!
//! The two halves are coupled in one direction that matters. On an encrypted
//! account a passkey is not just a way in — it is a route to the data key —
//! so adding or removing one changes what
//! [`EncryptionPanel`](crate::components::encryption_panel::EncryptionPanel)
//! has to say. They share a `reload` counter rather than each fetching on
//! their own schedule, so the page cannot show a passkey in one list and not
//! the other.

use leptos::either::{Either, EitherOf3};
use leptos::prelude::*;
use leptos_meta::Title;
use leptos_router::components::A;

use crate::auth_ctx::{AuthCtx, forget_device_key, sign_out};
use crate::components::encryption_panel::EncryptionPanel;
use crate::components::header::AppHeader;
use crate::components::setup_gate::SetupBanner;
use crate::components::status::Status;
use crate::dto::PasskeyListItem;
use crate::encryption_ctx::{EncryptionCtx, EncryptionState, Writes};
use crate::server_fns::passkey::{passkey_delete, passkey_list, passkey_rename};
use crate::server_fns::session::sign_out_everywhere;

/// Formats a passkey-management error for display.
///
/// `friendly_error` lives in `webauthn_browser`, which is compiled only for
/// `hydrate` (or `test`) — see `lib.rs`'s module gate. The `not(hydrate)`
/// branch below is dead in practice: `remove`'s and `rename`'s `on:click`
/// handlers only ever run in the browser. It exists purely so this call
/// site type-checks under a plain `ssr` build too, the same cfg-swap
/// `auth_ctx::initial_user` uses for the same reason.
fn passkey_error(e: ServerFnError) -> Status {
    #[cfg(feature = "hydrate")]
    {
        Status::Problem(crate::webauthn_browser::friendly_error(e.to_string()))
    }
    #[cfg(not(feature = "hydrate"))]
    {
        Status::Problem(e.to_string())
    }
}

#[component]
pub fn AccountPage() -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let backend = auth.backend();
    // Lifted here rather than owned by either section, because both write it
    // and both read it: the passkey list bumps it after an add or a remove,
    // and the encryption panel bumps it after keying a credential.
    let reload = RwSignal::new(0u32);

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
                    Some(email) => Either::Right(view! {
                        // This page is where spec section 4.1's gate sends
                        // an account that cannot store anything, so it has
                        // to open by saying why — a user who was moved here
                        // did not ask to be. Asked of `EncryptionCtx` with
                        // the same call the day and week views gate on, so
                        // the banner cannot appear on a page they let
                        // through, or stay away from one they do not.
                        {move || (encryption.writes(backend.get()) == Writes::SetupRequired)
                            .then(|| view! { <SetupBanner/> })}
                        <PasskeySection email=email reload=reload/>
                        <EncryptionPanel reload=reload/>
                    }),
                }}
            </div>
        </div>
    }
}

#[component]
fn PasskeySection(email: String, reload: RwSignal<u32>) -> impl IntoView {
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    // `Resource` here is safe: this route is client-navigated and never part
    // of the day view's SSR path, so it does not affect the synchronous
    // render the SSR tests rely on. Created at the top of the component,
    // never inside a closure, so SSR's render walk cannot construct it twice.
    //
    // Sourced from `reload` rather than refetched by hand, so the encryption
    // panel's writes refresh this list too — one trigger, both halves.
    let rows = Resource::new(move || reload.get(), |_| async { passkey_list().await });
    // `Status`, not a bare `String`, so spec section 6.6's refusal to remove
    // the last passkey that can unlock an encrypted account does not render
    // in the same muted grey as "Passkey renamed." It is the one message on
    // this page that stops the user doing something, and it has to look like
    // it.
    let status = RwSignal::new(Option::<Status>::None);
    // Whether the account is encrypted, which changes what adding a passkey
    // costs and therefore what has to be said before it starts.
    let encrypted = Memo::new(move |_| {
        matches!(
            encryption.state(),
            EncryptionState::Locked | EncryptionState::Unlocked(_)
        )
    });
    let confirm_add = RwSignal::new(false);

    let refresh = move || reload.update(|n| *n += 1);

    let add = move |_| {
        confirm_add.set(false);
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            let encrypted = encrypted.get_untracked();
            leptos::task::spawn_local(async move {
                match run_registration().await {
                    Ok(new_credential) => {
                        if encrypted {
                            // Shown *during* the two assertions, not after:
                            // the browser is about to ask twice and the
                            // prompts themselves cannot say which passkey
                            // to choose.
                            status.set(Some(Status::Note(
                                "Passkey added. Two more prompts: first a passkey that can \
                                 already open your entries, then the new one."
                                    .to_string(),
                            )));
                        }
                        status.set(Some(
                            finish_added_passkey(&user, encrypted, new_credential).await,
                        ));
                        refresh();
                    }
                    Err(e) => status.set(Some(Status::Problem(
                        crate::webauthn_browser::friendly_error(e),
                    ))),
                }
            });
        }
    };

    let remove = move |id: i32| {
        leptos::task::spawn_local(async move {
            match passkey_delete(id).await {
                Ok(()) => {
                    status.set(Some(Status::Note("Passkey removed.".to_string())));
                    refresh();
                }
                // Includes spec section 6.6's refusal to remove the last
                // passkey that can unlock an encrypted account. That message
                // names the encryption key and the alternative, so it is
                // shown as it stands rather than collapsed into a generic
                // failure — `webauthn_browser::friendly_error` passes it
                // through by prefix — and as a `Problem`, because a refusal
                // in the same grey as "Passkey renamed." is a refusal the
                // user scrolls past.
                Err(e) => status.set(Some(passkey_error(e))),
            }
        });
    };

    // The only caller of `sign_out_everywhere` outside the test suite. The
    // endpoint bumps `session_epoch`, which is what invalidates every token
    // already issued — the revocation path spec §5.1 makes load-bearing.
    // Without a control, a user who loses a device has no way to reach it,
    // and session cookies live 30 days.
    let sign_out_all = move |_| {
        // Through `sign_out` for the same reason the header's control is:
        // this device's data key goes first, and goes whether or not the
        // server manages to revoke anything (spec section 6.7). Revoking
        // every session and leaving a working key on the device in front of
        // you would be the wrong half of the job. Built in the handler, not
        // in the spawned block, so the invalidation lands at the click —
        // see `sign_out`.
        let signing_out = sign_out(encryption, forget_device_key(), sign_out_everywhere());
        leptos::task::spawn_local(async move {
            match signing_out.await {
                // Same local teardown as the header's sign-out: clear the
                // signal rather than reload, so `use_persistent` re-reads
                // from localStorage in place. This flips the page to its
                // signed-out branch, which is the confirmation — a status
                // line set here would be destroyed by that same flip.
                Ok(()) => auth.user.set(None),
                Err(e) => status.set(Some(passkey_error(e))),
            }
        });
    };

    let rename = move |id: i32, name: String| {
        leptos::task::spawn_local(async move {
            match passkey_rename(id, name).await {
                Ok(()) => {
                    status.set(Some(Status::Note("Passkey renamed.".to_string())));
                    refresh();
                }
                Err(e) => status.set(Some(passkey_error(e))),
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
                            <p class="text-sm text-red-700">
                                {passkey_error(e).message().to_string()}
                            </p>
                        }),
                    }
                })}
            </Suspense>

            // On an encrypted account, adding a passkey is not one gesture:
            // the new credential has to be created, then keyed, and keying
            // it needs an assertion against a credential that can already
            // unlock plus one against the new one (spec section 6.5). Three
            // prompts, always — said here rather than sprung one at a time.
            {move || match (encrypted.get(), confirm_add.get()) {
                (true, false) => EitherOf3::A(view! {
                    <button
                        type="button"
                        class="mt-6 bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700"
                        on:click=move |_| confirm_add.set(true)
                    >
                        "Add a passkey"
                    </button>
                }),
                (true, true) => EitherOf3::B(view! {
                    <div class="mt-6 rounded border border-gray-200 bg-gray-50 p-3">
                        <p class="text-sm text-gray-700 mb-1">
                            "Your entries are encrypted, so this takes three passkey prompts: \
                             one to create the new passkey, one against a passkey that can \
                             already open your entries, and one against the new one."
                        </p>
                        <p class="text-xs text-gray-500 mb-3">
                            "If it stops partway, the new passkey still signs you in — the \
                             encryption panel below will offer to give it an unlock key."
                        </p>
                        <button
                            type="button"
                            class="bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700 mr-2"
                            on:click=add
                        >
                            "Continue"
                        </button>
                        <button
                            type="button"
                            class="text-sm text-gray-600 hover:text-gray-900 px-2 py-2"
                            on:click=move |_| confirm_add.set(false)
                        >
                            "Cancel"
                        </button>
                    </div>
                }),
                (false, _) => EitherOf3::C(view! {
                    <button
                        type="button"
                        class="mt-6 bg-blue-600 text-white text-sm font-semibold rounded px-4 py-2 hover:bg-blue-700"
                        on:click=add
                    >
                        "Add a passkey"
                    </button>
                }),
            }}
            {move || status.get().map(|line| view! {
                <p class=format!("mt-3 {}", line.tone())>{line.message().to_string()}</p>
            })}

            // Deliberately secondary to the passkey actions above: a
            // control for a lost device, not something to reach for by
            // habit.
            <div class="mt-8 pt-4 border-t border-gray-100">
                <button
                    type="button"
                    class="text-sm text-gray-600 hover:text-gray-900 underline"
                    on:click=sign_out_all
                >
                    "Sign out everywhere"
                </button>
                <p class="text-xs text-gray-500 mt-1">
                    "Ends every signed-in session for this account, on every device, including this one. Use this if you've lost a device."
                </p>
            </div>
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
/// `passkey_register_finish`, and reports which credential was created.
///
/// `webauthn_browser::register` returns `(credential_json, prf_capable)` —
/// both values are threaded straight into `passkey_register_finish`
/// unmodified. `prf_capable` cannot be recovered from the credential JSON
/// alone (`toJSON()` omits extension results), so dropping or defaulting it
/// here would silently record every passkey enrolled through this page as
/// not-PRF-capable, and the encryption panel would conclude none of them can
/// derive a key.
///
// Known wart, left rather than moved: the paragraphs above were written for
// `run_registration`, below, and this module sits between the two halves of
// its doc comment.
#[cfg(test)]
mod tests {
    use super::*;

    /// Spec section 6.6's refusal arrives through here — the server declines
    /// to remove the last passkey that can unlock an encrypted account, and
    /// the message names the encryption key and the alternative. It has to
    /// land as a problem: this is the one message on the page that stops the
    /// user doing something, and in the same grey as "Passkey renamed." it
    /// is one they scroll past and then retry.
    #[test]
    fn a_refused_passkey_change_is_reported_as_a_problem() {
        let refused = passkey_error(ServerFnError::ServerError(
            "That's the last passkey that can unlock your entries.".to_string(),
        ));
        assert!(
            matches!(refused, Status::Problem(_)),
            "a refusal must not render as a note"
        );
        assert!(
            refused.message().contains("last passkey"),
            "the server's own words must survive: {}",
            refused.message()
        );
    }
}

/// The credential id is `Ok(None)`, never `Err`, when the response cannot be
/// parsed: the passkey exists by then, and reporting a failure would tell
/// the user to add another one. What is lost is only the ability to key it
/// in the same gesture, which the encryption panel's per-passkey control
/// recovers.
#[cfg(feature = "hydrate")]
async fn run_registration() -> Result<Option<Vec<u8>>, String> {
    use crate::crypto::flow::credential_id_from_response;
    use crate::server_fns::passkey::{passkey_register_finish, passkey_register_start};
    use crate::webauthn_browser;

    let challenge = passkey_register_start().await.map_err(|e| e.to_string())?;
    // `prf_capable` comes from getClientExtensionResults(), which toJSON()
    // does not include. It is recorded now and read by the encryption panel
    // (spec section 9.3 of the phase-1 design, section 6.5 here).
    let (credential, prf_capable) = webauthn_browser::register(&challenge)
        .await
        .map_err(|e| e.to_string())?;
    passkey_register_finish(credential.clone(), prf_capable)
        .await
        .map_err(|e| e.to_string())?;
    Ok(credential_id_from_response(&credential))
}

/// Continues an enrolment into spec section 6.5's wrap step when the account
/// is encrypted, and reports what the user is left holding.
///
/// Every outcome says whether the passkey signs the user in (it always
/// does), and separately whether it opens their entries (it may not). Those
/// are two different capabilities on an encrypted account, and a message
/// that says only "Passkey added" would let somebody believe they had gained
/// a second way back in when they had not. The severity carries the same
/// distinction: only the outcome where both hold is a [`Status::Note`].
#[cfg(feature = "hydrate")]
async fn finish_added_passkey(user: &str, encrypted: bool, credential: Option<Vec<u8>>) -> Status {
    use crate::crypto::KeySource;

    if !encrypted {
        return Status::Note("Passkey added.".to_string());
    }
    let Some(credential) = credential else {
        return Status::Problem(
            "Passkey added, but this browser couldn't tell which credential it is, so it has \
             no unlock key yet. Use “Give it an unlock key” below."
                .to_string(),
        );
    };
    // A passkey opener, because this path has just been through one
    // authenticator prompt and can reasonably ask for another. When there is
    // no passkey that can unlock — an account reopened with its encryption
    // key — this fails and says so, and the panel below offers the
    // encryption-key route that does work (see `flow::add_passkey_key`).
    match crate::crypto::flow::add_passkey_key(user, &credential, KeySource::Passkey).await {
        Ok(()) => Status::Note("Passkey added, and it can open your entries.".to_string()),
        // A problem, not a note: the passkey signs the user in but does not
        // open their entries, and somebody who reads this as "added" thinks
        // they have gained a second way back in when they have not.
        Err(message) => Status::Problem(format!(
            "Passkey added, but it has no unlock key yet, so it won't open your entries: \
             {message} Use “Give it an unlock key” below to try again."
        )),
    }
}
