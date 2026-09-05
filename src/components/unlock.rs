//! The unlock prompt for a `Locked` session (spec section 6.3).
//!
//! `DayView` and `WeekView` mount this in place of the entry area whenever
//! `EncryptionCtx` reads `Locked` — never on the server, which always reads
//! `Unknown` (invariant E2), so the WebAuthn/WebCrypto ceremonies below are
//! dead code there, not merely unreachable UI.
//!
//! Two routes open the account's data key: a passkey assertion with the PRF
//! extension evaluated, and a typed recovery code. A recovery unlock has one
//! more step than a passkey one — spec section 6.4's offer of a fresh code —
//! which is why the flow below has more than two states.

use leptos::either::EitherOf4;
use leptos::prelude::*;
#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

#[cfg(feature = "hydrate")]
use crate::auth_ctx::AuthCtx;
#[cfg(feature = "hydrate")]
use crate::crypto::SessionKey;
#[cfg(feature = "hydrate")]
use crate::encryption_ctx::EncryptionCtx;

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
pub fn UnlockPrompt() -> impl IntoView {
    // Neither context is read anywhere below except inside a
    // `#[cfg(feature = "hydrate")]` block: this component structurally never
    // renders under `ssr` (`EncryptionCtx` there is always `Unknown`, never
    // `Locked`), so there is nothing for either to do on that target — and
    // fetching them anyway would leave both unused there, which is exactly
    // what `#[cfg]`-ing the fetch alongside every use avoids.
    #[cfg(feature = "hydrate")]
    let auth = use_context::<AuthCtx>().expect("AuthCtx provided by App");
    #[cfg(feature = "hydrate")]
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let mode = RwSignal::new(Mode::default());
    let status = RwSignal::new(String::new());
    let code_input = RwSignal::new(String::new());

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
            spawn_local(async move {
                match ceremony::unlock_with_passkey(&user).await {
                    Ok(key) => encryption.unlock(key),
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
            spawn_local(async move {
                match ceremony::unlock_with_recovery_code(&typed, &user).await {
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
            encryption.unlock(key);
        }
    };

    let generate_new_code = move |_| {
        status.set(String::new());
        #[cfg(feature = "hydrate")]
        {
            let Mode::OfferReissue { code, wrap } = mode.get_untracked() else {
                return;
            };
            spawn_local(async move {
                match ceremony::reissue_recovery_code(&code, &wrap).await {
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
            encryption.unlock(key);
        }
    };

    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            {move || {
                let s = status.get();
                (!s.is_empty()).then(|| view! { <p class="text-xs text-red-600 mb-3">{s}</p> })
            }}
            {move || match mode.get() {
                Mode::Choosing => EitherOf4::A(view! {
                    <div>
                        <h2 class="text-lg font-semibold text-gray-800 mb-1">"Unlock your entries"</h2>
                        <p class="text-sm text-gray-600 mb-4">
                            "This account's entries are encrypted, and this device doesn't hold the key yet."
                        </p>
                        <button
                            type="button"
                            class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2"
                            on:click=use_passkey
                        >
                            "Use a passkey"
                        </button>
                        <button
                            type="button"
                            class="w-full border border-gray-300 text-sm rounded py-2 hover:bg-gray-50"
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
                            class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2"
                            on:click=submit_code
                        >
                            "Unlock"
                        </button>
                        <button
                            type="button"
                            class="w-full text-sm text-gray-600 hover:text-gray-900 py-1"
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
                            class="w-full bg-blue-600 text-white text-sm font-semibold rounded py-2 hover:bg-blue-700 mb-2"
                            on:click=generate_new_code
                        >
                            "Generate a new code"
                        </button>
                        <button
                            type="button"
                            class="w-full border border-gray-300 text-sm rounded py-2 hover:bg-gray-50"
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
        </div>
    }
}

/// The WebAuthn/WebCrypto ceremonies, and the one piece of wire-parsing they
/// need that neither `webauthn_browser` nor `crypto` already does.
///
/// Browser-only, like the rest of spec section 6: every function here
/// reaches WebAuthn, WebCrypto, or both.
#[cfg(feature = "hydrate")]
mod ceremony {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use leptos::prelude::ServerFnError;

    use crate::crypto::wire::APP_SALT;
    use crate::crypto::{
        Opener, SessionKey, UnlockError, choose_route, reissue_recovery, unlock_with_prf,
        unlock_with_recovery,
    };
    use crate::server_fns::encryption::{encryption_replace_recovery_wrap, encryption_wraps};
    use crate::server_fns::passkey::{passkey_login_finish, passkey_login_start};
    use crate::webauthn_browser;

    /// A network or server failure unrelated to WebAuthn itself — reaching
    /// `encryption_wraps`/`encryption_replace_recovery_wrap`, whose own
    /// errors are already the generic "Internal server error" `log_and_fail`
    /// produces (the specific cause is logged server-side, not sent here).
    fn server_unreachable(_: ServerFnError) -> String {
        "Couldn't reach the server. Check your connection and try again.".to_string()
    }

    /// Pulls the credential id back out of an assertion response, so
    /// `choose_route` can tell which passkey's wrap to open.
    ///
    /// `toJSON()`'s `rawId` is the browser's base64url encoding of the same
    /// bytes webauthn-rs stores as `entry_key_wrap.credential_id` — reading
    /// it back out here is the only way this component learns which
    /// credential just asserted, since `passkey_login_finish` reports only
    /// success or failure, not which row it verified.
    fn credential_id_from_response(response_json: &str) -> Option<Vec<u8>> {
        let value: serde_json::Value = serde_json::from_str(response_json).ok()?;
        let raw_id = value.get("rawId")?.as_str()?;
        URL_SAFE_NO_PAD.decode(raw_id).ok()
    }

    /// The passkey route (spec section 6.3): an assertion verified the same
    /// way passkey sign-in verifies one, with the PRF extension evaluated
    /// alongside it.
    ///
    /// Reuses `passkey_login_start`/`passkey_login_finish` rather than a
    /// dedicated pair — the ceremony is identical, and the only side effect
    /// finishing it has that an already-signed-in session didn't already
    /// have is a refreshed session token, which is harmless.
    pub async fn unlock_with_passkey(user: &str) -> Result<SessionKey, String> {
        let challenge = passkey_login_start(Some(user.to_string()))
            .await
            .map_err(|e| webauthn_browser::friendly_error(e.to_string()))?;

        let (response, prf_output) = webauthn_browser::authenticate_with_prf(&challenge, APP_SALT)
            .await
            .map_err(|e| webauthn_browser::friendly_error(e.to_string()))?;

        passkey_login_finish(response.clone())
            .await
            .map_err(|e| webauthn_browser::friendly_error(e.to_string()))?;

        let Some(prf_output) = prf_output else {
            return Err(
                "That passkey didn't provide an unlock key on this browser. Try your \
                 recovery code instead."
                    .to_string(),
            );
        };

        let wraps = encryption_wraps().await.map_err(server_unreachable)?;
        let credential_id = credential_id_from_response(&response);
        let route = choose_route(&wraps, credential_id.as_deref()).ok_or_else(|| {
            "That passkey can't unlock this account. Try your recovery code instead.".to_string()
        })?;

        unlock_with_prf(&prf_output, &route.wrapped_key, user)
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
        let wraps = encryption_wraps().await.map_err(server_unreachable)?;
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

    /// Spec section 6.4's offer: wraps the data key under a fresh code and
    /// replaces the stored recovery wrap.
    ///
    /// `old_code`/`old_wrap` reopen the route that just succeeded — the only
    /// way to get the raw key back out, since the `SessionKey` the caller is
    /// already holding cannot yield it (invariant E5).
    pub async fn reissue_recovery_code(old_code: &str, old_wrap: &[u8]) -> Result<String, String> {
        let opener = Opener::Recovery {
            code: old_code,
            wrap: old_wrap,
        };
        let (new_code, new_wrap) = reissue_recovery(&opener).await.map_err(|_| {
            "Couldn't generate a new recovery code. Your current one still works.".to_string()
        })?;

        encryption_replace_recovery_wrap(new_wrap)
            .await
            .map_err(server_unreachable)?;

        Ok(new_code)
    }
}
