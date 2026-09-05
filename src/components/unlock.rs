//! The unlock prompt for a session the user has to act on (spec section 6.3).
//!
//! `DayView` and `WeekView` mount this in place of the entry area whenever
//! `EncryptionCtx` reads `Locked` — or `Unreachable`, the state a failed
//! probe leaves behind, which needs a different panel and offers a retry
//! rather than an unlock. Which of the two arrives as [`UnlockReason`],
//! decided by the gate that mounted this; see there for why it is a prop.
//! Neither state ever happens on the server, which always reads `Unknown`
//! (invariant E2), so the WebAuthn/WebCrypto ceremonies below are dead code
//! there, not merely unreachable UI.
//!
//! Two routes open the account's data key: a passkey assertion with the PRF
//! extension evaluated, and a typed recovery code. A recovery unlock has one
//! more step than a passkey one — spec section 6.4's offer of a fresh code —
//! which is why the flow below has more than two states.

use leptos::either::{Either, EitherOf4};
use leptos::prelude::*;
#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::auth_ctx::AuthCtx;
#[cfg(feature = "hydrate")]
use crate::crypto::SessionKey;
#[cfg(feature = "hydrate")]
use crate::encryption_ctx::EncryptionCtx;

/// Why this prompt is on screen, decided by whoever mounted it.
///
/// A prop rather than a second read of `EncryptionCtx`. The two states that
/// mount this component are exactly the two the gates in `DayView` and
/// `WeekBody` have already matched on, so re-deriving the answer here would
/// buy three match arms that cannot happen and a subscription to a signal
/// whose very next change unmounts this component.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnlockReason {
    /// The account is encrypted and this device holds no key for it.
    Locked,
    /// The probe could not say whether the account is encrypted at all.
    Unreachable,
}

/// Where the prompt is in its flow.
///
/// Plain data only, so this type — and the signal that holds it — is the
/// same on every target. The key a successful unlock produces is real only
/// in the browser and never sits in here: it is bridged separately (see
/// `UnlockPrompt`'s `pending_key`), because a `SessionKey` under `hydrate`
/// wraps a JS `CryptoKey`, which is neither `Send` nor `Sync`, and this enum
/// has to be nameable — and orderable into an ordinary `RwSignal` — on every
/// target.
///
/// `OfferReissue` and `ShowNewCode` are only ever built by `ceremony`, below,
/// which is `#[cfg(feature = "hydrate")]`-only — so a build with `hydrate`
/// off (the server binary; also a bare `cargo check`/`clippy` with neither
/// feature) never constructs either, and `dead_code` reads that as "never
/// constructed" rather than "constructed on the one target that matters
/// here." The wasm build does construct both, and stays linted for real
/// dead code on this type.
#[derive(Clone, Default)]
#[cfg_attr(not(feature = "hydrate"), allow(dead_code))]
enum Mode {
    /// The two routes, plus whatever `status` holds from the last attempt.
    #[default]
    Choosing,
    /// The recovery code input is open.
    EnteringCode,
    /// A recovery unlock just succeeded. `code`/`wrap` are the *old*
    /// route's own bytes — kept only long enough to build the `Opener`
    /// `reissue_recovery` needs if the user accepts the offer.
    OfferReissue { code: String, wrap: Vec<u8> },
    /// The freshly generated code, shown once.
    ShowNewCode(String),
}

#[component]
pub fn UnlockPrompt(reason: UnlockReason) -> impl IntoView {
    // Neither context is read anywhere below except inside a
    // `#[cfg(feature = "hydrate")]` block: everything either does — an
    // unlock ceremony, a re-probe — reaches WebAuthn, WebCrypto or the
    // network, and this component structurally never renders on the server
    // (both states that mount it are post-probe, and the server always reads
    // `Unknown`). Fetching them anyway would leave both unused there, which
    // is exactly what `#[cfg]`-ing the fetch alongside every use avoids.
    #[cfg(feature = "hydrate")]
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    #[cfg(feature = "hydrate")]
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let mode = RwSignal::new(Mode::default());
    let status = RwSignal::new(String::new());
    let code_input = RwSignal::new(String::new());
    // Whether a ceremony is in flight. Every button that starts one — and
    // every button that would tear this component down while one is running
    // — is disabled on it, so a double-click cannot open two assertions, and
    // "keep my current code" cannot unmount the panel out from under a
    // re-issue that is still awaiting the server.
    let busy = RwSignal::new(false);

    // Bridges a recovery unlock's two clicks: the code submit, which
    // produces the key, and the reissue answer, which is what actually
    // hands it to `EncryptionCtx`. Publishing the key the moment the unwrap
    // succeeds — instead of holding it here — would flip `EncryptionCtx` to
    // `Unlocked` immediately, which is what the parent's gate watches: this
    // very component would be unmounted before the offer in spec section
    // 6.4 could be shown, let alone answered.
    //
    // `LocalStorage`, the same fork `EncryptionCtx`'s own signal makes and
    // for the same reason: a `SessionKey` wraps a JS `CryptoKey` under
    // `hydrate`, which is neither `Send` nor `Sync`.
    #[cfg(feature = "hydrate")]
    let pending_key = StoredValue::<Option<SessionKey>, LocalStorage>::new_local(None);

    let use_passkey = move |_| {
        status.set(String::new());
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                // Unreachable in practice: `UnlockPrompt` only mounts for a
                // signed-in, encrypted account. Doing nothing rather than
                // panicking costs nothing if that ever stops holding.
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = ceremony::unlock_with_passkey(&user).await;
                // Cleared before the branch, not inside each arm: the
                // success arm unmounts this component, so anything after it
                // would be writing to a disposed signal.
                busy.set(false);
                match outcome {
                    // Awaited rather than fired and forgotten: `unlock`
                    // writes this device's keystore behind its own identity
                    // check, and nothing after it here depends on the
                    // answer.
                    Ok(key) => encryption.unlock(key).await,
                    Err(msg) => status.set(msg),
                }
            });
        }
    };

    let open_code_entry = move |_| {
        status.set(String::new());
        mode.set(Mode::EnteringCode);
    };

    let back_to_choosing = move |_| {
        status.set(String::new());
        mode.set(Mode::Choosing);
    };

    let submit_code = move |_| {
        status.set(String::new());
        #[cfg(feature = "hydrate")]
        {
            let Some(user) = auth.user.get_untracked() else {
                return;
            };
            let typed = code_input.get_untracked();
            busy.set(true);
            spawn_local(async move {
                let outcome = ceremony::unlock_with_recovery_code(&typed, &user).await;
                busy.set(false);
                match outcome {
                    Ok((key, code, wrap)) => {
                        pending_key.set_value(Some(key));
                        mode.set(Mode::OfferReissue { code, wrap });
                    }
                    Err(msg) => status.set(msg),
                }
            });
        }
    };

    let skip_reissue = move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(Some(key)) = pending_key.try_update_value(Option::take) {
            spawn_local(async move { encryption.unlock(key).await });
        }
    };

    let generate_new_code = move |_| {
        status.set(String::new());
        #[cfg(feature = "hydrate")]
        {
            let Mode::OfferReissue { code, wrap } = mode.get_untracked() else {
                return;
            };
            busy.set(true);
            spawn_local(async move {
                let outcome = ceremony::reissue_recovery_code(&code, &wrap).await;
                busy.set(false);
                match outcome {
                    Ok(new_code) => mode.set(Mode::ShowNewCode(new_code)),
                    Err(msg) => {
                        status.set(msg);
                        mode.set(Mode::OfferReissue { code, wrap });
                    }
                }
            });
        }
    };

    let finish_after_new_code = move |_| {
        #[cfg(feature = "hydrate")]
        if let Some(Some(key)) = pending_key.try_update_value(Option::take) {
            spawn_local(async move { encryption.unlock(key).await });
        }
    };

    let retry_probe = move |_| {
        status.set(String::new());
        // The context owns the `Generation` this re-uses, so a retry started
        // while the first probe is still in flight invalidates it rather
        // than racing it.
        #[cfg(feature = "hydrate")]
        encryption.retry();
    };

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            {move || {
                let s = status.get();
                (!s.is_empty()).then(|| view! { <p class="text-xs text-red-600 mb-3">{s}</p> })
            }}
            {match reason {
                // Nothing here mentions a key, deliberately: the account may
                // not even be encrypted, and "unlock" would tell the user
                // they are shut out of something that might not exist. What
                // is true is narrower — the app could not find out, and
                // until it does it will not write.
                UnlockReason::Unreachable => Either::Left(view! {
                    <div>
                        <h2 class="text-lg font-semibold text-gray-800 mb-1">"Couldn't check this account"</h2>
                        <p class="text-sm text-gray-600 mb-4">
                            "We couldn't tell whether this account's entries are encrypted, so \
                             nothing is being saved — guessing wrong would store your entries \
                             unencrypted. This is usually a connection problem."
                        </p>
                        <button
                            type="button"
                            class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700"
                            on:click=retry_probe
                        >
                            "Try again"
                        </button>
                    </div>
                }),
                // The flow this component was written for.
                UnlockReason::Locked => Either::Right(view! {
                    {move || match mode.get() {
                        Mode::Choosing => EitherOf4::A(view! {
                            <div>
                                <h2 class="text-lg font-semibold text-gray-800 mb-1">"Unlock your entries"</h2>
                                <p class="text-sm text-gray-600 mb-4">
                                    "This account's entries are encrypted, and this device doesn't hold the key yet."
                                </p>
                                <button
                                    type="button"
                                    class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=use_passkey
                                >
                                    "Use a passkey"
                                </button>
                                <button
                                    type="button"
                                    class="w-full border border-gray-300 text-sm rounded py-2 hover:bg-gray-50 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=open_code_entry
                                >
                                    "Enter your recovery code"
                                </button>
                            </div>
                        }),
                        Mode::EnteringCode => EitherOf4::B(view! {
                            <div>
                                <h2 class="text-lg font-semibold text-gray-800 mb-1">"Enter your recovery code"</h2>
                                <p class="text-sm text-gray-600 mb-3">"Thirty-two characters, in groups of four."</p>
                                <input
                                    type="text"
                                    autocomplete="off"
                                    spellcheck="false"
                                    class="w-full border border-gray-300 rounded px-2 py-1.5 text-sm mb-3 font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                    placeholder="0000-0000-0000-0000-0000-0000-0000-0000"
                                    prop:value=move || code_input.get()
                                    on:input=move |ev| code_input.set(event_target_value(&ev))
                                />
                                <button
                                    type="button"
                                    class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=submit_code
                                >
                                    "Unlock"
                                </button>
                                <button
                                    type="button"
                                    class="w-full text-sm text-gray-600 hover:text-gray-900 py-1 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=back_to_choosing
                                >
                                    "Back"
                                </button>
                            </div>
                        }),
                        Mode::OfferReissue { .. } => EitherOf4::C(view! {
                            <div>
                                <h2 class="text-lg font-semibold text-gray-800 mb-1">"Get a new recovery code?"</h2>
                                <p class="text-sm text-gray-600 mb-4">
                                    "You just typed the code you have, so treat it as less private than it was. \
                                     A new one replaces it — the old code stops working once this finishes — or \
                                     you can keep the one you have."
                                </p>
                                <button
                                    type="button"
                                    class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=generate_new_code
                                >
                                    "Generate a new code"
                                </button>
                                <button
                                    type="button"
                                    class="w-full border border-gray-300 text-sm rounded py-2 hover:bg-gray-50 disabled:opacity-60"
                                    disabled=move || busy.get()
                                    on:click=skip_reissue
                                >
                                    "Keep my current code"
                                </button>
                            </div>
                        }),
                        Mode::ShowNewCode(code) => EitherOf4::D(view! {
                            <div>
                                <h2 class="text-lg font-semibold text-gray-800 mb-1">"Your new recovery code"</h2>
                                <p class="text-sm text-gray-600 mb-3">
                                    "Write this down or save it somewhere safe. It won't be shown again, and the \
                                     code you just used no longer works."
                                </p>
                                <p class="font-mono text-sm bg-gray-50 border border-gray-200 rounded px-3 py-2 mb-4 break-all">
                                    {code}
                                </p>
                                <button
                                    type="button"
                                    class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700"
                                    on:click=finish_after_new_code
                                >
                                    "I've saved it"
                                </button>
                            </div>
                        }),
                    }}
                }),
            }}
        </div>
    }
}

/// This prompt's two routes to the data key, and spec section 6.4's offer
/// of a fresh code after the second one.
///
/// Thin over [`crate::crypto::flow`], which owns the steps the `/account`
/// encryption panel runs too — the assertion and the recovery re-issue. What
/// stays here is the wording: every failure below is phrased for somebody
/// who is shut out and looking for a way back in, which is not what the same
/// failure means on `/account`.
///
/// Browser-only, like the rest of spec section 6: every function here
/// reaches WebAuthn, WebCrypto, or both.
#[cfg(feature = "hydrate")]
mod ceremony {
    use crate::crypto::flow::{self, AssertionError};
    use crate::crypto::{
        Opener, SessionKey, UnlockError, choose_route, unlock_with_prf, unlock_with_recovery,
    };
    use crate::server_fns::encryption::encryption_wraps;

    /// The passkey route (spec section 6.3): an assertion verified the same
    /// way passkey sign-in verifies one, with the PRF extension evaluated
    /// alongside it.
    ///
    /// Every failure that is not the unwrap itself points at the recovery
    /// code, because that route works when this one does not — including on
    /// a browser with no PRF support at all.
    pub async fn unlock_with_passkey(user: &str) -> Result<SessionKey, String> {
        // The wraps come first, before the authenticator is touched at all.
        // Both orders work, and this is the one every other ceremony uses
        // (`flow::add_passkey_key`, the panel's re-issue): a server that
        // cannot answer is going to sink this attempt whatever the
        // authenticator says, so asking the user for a passkey — or a
        // fingerprint, or a phone — before finding that out spends a real
        // gesture on a failure that was already decided.
        let wraps = encryption_wraps().await.map_err(flow::server_unreachable)?;

        // The credential id is kept apart from `choose_route`'s `None`,
        // rather than folded into it: `None` there means "the user chose the
        // recovery route", and a `rawId` that could not be parsed is not
        // that. Sharing one representation would send the passkey path off
        // to open the *recovery* wrap with a PRF output — the unwrap would
        // fail, so the user is never told a wrong thing succeeded, but they
        // would be told the wrong reason it failed.
        let assertion = flow::assert_with_prf(user).await.map_err(|err| match err {
            AssertionError::Ceremony(message) => message,
            AssertionError::NoPrf => "That passkey didn't provide an unlock key on this \
                                      browser. Try your recovery code instead."
                .to_string(),
            AssertionError::Unidentified => "That passkey didn't identify itself to this \
                                             browser. Try your recovery code instead."
                .to_string(),
        })?;

        let route = choose_route(&wraps, Some(&assertion.credential_id)).ok_or_else(|| {
            "That passkey can't unlock this account. Try your recovery code instead.".to_string()
        })?;

        unlock_with_prf(&assertion.prf_output, &route.wrapped_key, user)
            .await
            .map_err(|_| "That passkey couldn't unlock this account.".to_string())
    }

    /// The recovery route (spec section 6.4). Returns the unlocked key
    /// together with the code and wrap that opened it — `reissue_recovery`
    /// needs both to reopen the same route if the user accepts a fresh one.
    ///
    /// The two errors `unlock_with_recovery` can return say two different
    /// things and must stay two different sentences: a malformed code never
    /// reached the unwrap at all, while a well-formed one that failed could
    /// be wrong, or could be a corrupt row — AES-KW's unwrap cannot tell
    /// those apart, so this must not claim either specifically.
    pub async fn unlock_with_recovery_code(
        typed: &str,
        user: &str,
    ) -> Result<(SessionKey, String, Vec<u8>), String> {
        let wraps = encryption_wraps().await.map_err(flow::server_unreachable)?;
        let route = choose_route(&wraps, None)
            .ok_or_else(|| "This account has no recovery code set up.".to_string())?;

        let key = unlock_with_recovery(typed, &route.wrapped_key, user)
            .await
            .map_err(|err| match err {
                UnlockError::Malformed(_) => "That doesn't look like a recovery code.".to_string(),
                UnlockError::Crypto(_) => "That recovery code didn't work.".to_string(),
            })?;

        Ok((key, typed.to_string(), route.wrapped_key))
    }

    /// Spec section 6.4's offer, reopening the route that just succeeded.
    ///
    /// `old_code`/`old_wrap` are the only way to get the raw key back out,
    /// since the `SessionKey` the caller is already holding cannot yield it
    /// (invariant E5).
    pub async fn reissue_recovery_code(old_code: &str, old_wrap: &[u8]) -> Result<String, String> {
        flow::reissue(&Opener::Recovery {
            code: old_code,
            wrap: old_wrap,
        })
        .await
    }
}
