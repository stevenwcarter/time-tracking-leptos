//! Whether this account is encrypted, and whether this device can read it.
//!
//! The view layer's half of spec section 7.4. Components never touch
//! `crypto` directly: they read this context, and the storage seam takes the
//! answer out of it.
//!
//! # Why the server always renders `Unknown`
//!
//! The same reasoning as the entry tri-state in [`crate::storage::hook`],
//! one step further out. The server *could* read `encrypted_at` cheaply —
//! it has the session — but rendering `Locked` would put user-derived state
//! in the SSR body, and the browser cannot tell locked from unlocked without
//! an async IndexedDB read anyway, so the first client render would differ
//! regardless. [`EncryptionState::Unknown`] on both sides is the only value
//! that hydrates (invariant E2, pinned by `app`'s
//! `ssr_renders_unknown_encryption_state`).
//!
//! `Disabled` would hydrate just as cleanly, which is exactly why the
//! starting value is worth being deliberate about: it is a *conclusion* —
//! "this account has no encryption" — and asserting it about a signed-in
//! visitor before anything has been read is what starts writing plaintext
//! rows into an encrypted account.

use leptos::prelude::*;

#[cfg(feature = "hydrate")]
use leptos::logging::error;
#[cfg(feature = "hydrate")]
use leptos::task::spawn_local;

use crate::auth_ctx::AuthCtx;
use crate::crypto::SessionKey;
use crate::storage::WriteKey;

#[cfg(feature = "hydrate")]
use crate::server_fns::encryption::encryption_status;
#[cfg(feature = "hydrate")]
use crate::storage::Generation;

/// How the state is stored, which is the one thing in this module that has
/// to fork on target.
///
/// Under `hydrate` the `Unlocked` arm holds a JS `CryptoKey` handle, which
/// is neither `Send` nor `Sync`, so the signal has to be `LocalStorage` —
/// harmless there, because wasm is single-threaded. Under `ssr`
/// [`SessionKey`] is uninhabited, so [`EncryptionState`] *is* `Send + Sync`
/// and the ordinary storage applies.
///
/// Not a stylistic choice in either direction. A `LocalStorage` signal wraps
/// its value in a `SendWrapper`, which panics when dropped on a thread other
/// than the one that created it — and an owner created while rendering one
/// request can be disposed on any tokio worker, so using it server-side
/// would buy an intermittent panic. Keeping the server on the ordinary
/// storage also means the `Send + Sync` bound, rather than a comment, is
/// what stops key material ever reaching a server render.
#[cfg(feature = "hydrate")]
type StateSignal = RwSignal<EncryptionState, LocalStorage>;
#[cfg(not(feature = "hydrate"))]
type StateSignal = RwSignal<EncryptionState>;

/// A signal holding the value both targets start from.
fn unknown_state() -> StateSignal {
    #[cfg(feature = "hydrate")]
    {
        RwSignal::new_local(EncryptionState::Unknown)
    }
    #[cfg(not(feature = "hydrate"))]
    {
        RwSignal::new(EncryptionState::Unknown)
    }
}

/// What the view layer knows about this account's encryption.
///
/// Four states rather than the three an account can be in, because "not yet
/// known" is a state the UI has to render — see this module's header.
#[derive(Clone)]
pub enum EncryptionState {
    /// Before the probe resolves, and everything the server ever renders.
    Unknown,
    /// The account has no encryption; bodies are stored in the clear.
    Disabled,
    /// Encrypted, and this device holds no key for it.
    Locked,
    /// Encrypted, and this device holds the key.
    ///
    /// The key rides in the variant rather than sitting in a signal beside
    /// it, so "unlocked with no key" and "locked while holding one" are not
    /// states this type can express. On any non-browser target
    /// [`SessionKey`] is uninhabited, which makes this variant
    /// unconstructible there — the compiler's way of saying that a server
    /// render never holds key material (spec sections 7.4 and 9.1).
    Unlocked(SessionKey),
}

impl EncryptionState {
    /// The key to open stored bodies with, or `None` when there is none.
    ///
    /// `Unknown` and `Locked` both read as "no key", and that is safe: a v2
    /// row then surfaces as [`crate::storage::StorageError::Locked`], which
    /// is the honest answer for a reader who has not unlocked yet, and a v1
    /// row reads identically either way (spec E3).
    pub fn key(&self) -> Option<&SessionKey> {
        match self {
            EncryptionState::Unlocked(key) => Some(key),
            EncryptionState::Unknown | EncryptionState::Disabled | EncryptionState::Locked => None,
        }
    }

    /// What a write should do, which is deliberately *not* the mirror of
    /// [`key`](Self::key).
    ///
    /// A read can collapse "not encrypted" and "no key here" into one
    /// answer, because the row itself says which it is. A write cannot: the
    /// body is on its way out and nothing downstream would ever notice that
    /// an encrypted account had just taken a plaintext row. So `Locked`
    /// refuses — and so does `Unknown`, because a write that cannot yet say
    /// whether the account is encrypted must not guess, and the wrong guess
    /// is unrecoverable in exactly the same way (see [`WriteKey`]).
    pub fn write_key(&self) -> WriteKey<'_> {
        match self {
            EncryptionState::Disabled => WriteKey::Plaintext,
            EncryptionState::Unlocked(key) => WriteKey::Sealed(key),
            EncryptionState::Unknown | EncryptionState::Locked => WriteKey::Locked,
        }
    }
}

/// This account's encryption state, shared across the component tree.
#[derive(Clone, Copy)]
pub struct EncryptionCtx {
    state: StateSignal,
}

impl EncryptionCtx {
    /// Creates the context and starts the probe that resolves it.
    ///
    /// The context is usable immediately and reads [`EncryptionState::Unknown`]
    /// until the probe lands; on the server it stays that way forever,
    /// which is the whole point (see this module's header).
    pub fn probing(auth: AuthCtx) -> Self {
        let state = unknown_state();

        // Browser-only in full, not merely dormant under `ssr`: the probe
        // reaches a server function and this device's IndexedDB, and a
        // render may touch neither. `Effect::new` never runs during SSR
        // anyway (see `storage::hook`), so gating the whole block just keeps
        // a keystore read out of the server binary.
        #[cfg(feature = "hydrate")]
        {
            let generation = StoredValue::new(Generation::default());

            Effect::new(move |_| {
                // Tracked: signing in and out are live, no-reload toggles
                // (`AccountMenu` flips `AuthCtx::user` in place), and each
                // one changes the answer.
                let user = auth.user.get();

                // Captured synchronously, before the `spawn_local` below,
                // for the reason `week_view`'s range load spells out: this
                // effect can re-run — and start a second probe — while an
                // earlier one is still awaiting the server, and reading the
                // token back out after the await would race that second run
                // for the increment.
                let token = generation
                    .try_update_value(Generation::next)
                    .unwrap_or_default();

                let Some(user) = user else {
                    // Signed out means `localStorage`, which is never
                    // encrypted (spec section 1.2). So this needs no server
                    // call — and must not make one, since there is no
                    // session to make it with.
                    state.set(EncryptionState::Disabled);
                    return;
                };

                // Back to "not known yet" before the probe starts, so an
                // `Unlocked` reached for the previous account never survives
                // into the next one's render — the same reset
                // `use_persistent` does when its key changes.
                state.set(EncryptionState::Unknown);

                spawn_local(async move {
                    let probed = probe(&user).await;
                    // Only the newest probe may publish; an older one
                    // landing after a sign-in or sign-out must be discarded
                    // rather than overwrite it. `try_with_value` rather than
                    // the panicking form, since this owner can be disposed
                    // while a probe is still in flight.
                    let is_current = generation
                        .try_with_value(|g| g.is_current(token))
                        .unwrap_or(false);
                    if is_current {
                        state.set(probed);
                    }
                });
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = auth;

        Self { state }
    }

    /// Builds a context already parked at `state`, bypassing the probe
    /// entirely.
    ///
    /// Test-only, and the only way to reach `Locked` — or to pin
    /// `Disabled`/`Unlocked` explicitly — on the host: `probing` always
    /// starts at `Unknown`, and the `Effect` that could move it anywhere
    /// else is `hydrate`-only. `DayView`'s and `WeekView`'s mount-gate tests
    /// need exactly this to prove those components actually branch on
    /// `EncryptionState`, not merely that the states exist.
    ///
    /// `ssr` as well as `test`: both call sites render with `.to_html()`,
    /// which needs `leptos`'s `ssr` feature, so this has no caller — and
    /// would be dead code — under a bare `cargo test --no-default-features`.
    #[cfg(all(test, feature = "ssr"))]
    pub(crate) fn for_state(state: EncryptionState) -> Self {
        #[cfg(feature = "hydrate")]
        let state = RwSignal::new_local(state);
        #[cfg(not(feature = "hydrate"))]
        let state = RwSignal::new(state);
        Self { state }
    }

    /// The current state, tracked.
    ///
    /// Tracked is what makes an unlock visible without a reload: the day and
    /// week loads read through here, so resolving the probe — or unlocking
    /// later — re-runs them and the text appears.
    pub fn state(self) -> EncryptionState {
        self.state.get()
    }

    /// The current state, without subscribing.
    ///
    /// The write path's read. A save must use the session as it is right
    /// now, not turn itself into a reactive dependency of the effect it was
    /// spawned from — the same reason `Persistent::set` reads its key and
    /// backend untracked.
    pub fn state_untracked(self) -> EncryptionState {
        self.state.get_untracked()
    }

    /// Publishes a session an unlock ceremony just opened (spec section 6.3).
    ///
    /// The only way anything outside this module reaches `Unlocked` other
    /// than the probe finding a key already in the keystore.
    /// `crypto::unlock_with_prf`/`unlock_with_recovery` have already called
    /// `SessionKey::adopt`, which writes the keystore record — this call
    /// only tells the rest of the tree the session changed, which is what
    /// makes the day and week loads (tracked through [`state`](Self::state))
    /// re-run and show the now-readable entries without a reload.
    ///
    /// `hydrate`-only, like the type it takes: nothing off the browser ever
    /// holds a `SessionKey` to pass here.
    #[cfg(feature = "hydrate")]
    pub fn unlock(self, key: SessionKey) {
        self.state.set(EncryptionState::Unlocked(key));
    }
}

/// The two reads behind the probe, in the order that avoids the second one
/// whenever the first already settles the answer.
#[cfg(feature = "hydrate")]
async fn probe(user: &str) -> EncryptionState {
    let status = match encryption_status().await {
        Ok(status) => status,
        Err(err) => {
            // Not `Disabled`. That is a conclusion about the account, and
            // reaching it from a failed request would mount the entry area
            // and start writing v1 rows into an account that may well be
            // encrypted. Staying `Unknown` says only what is true — nothing
            // was learned — and refuses writes until something is
            // (`EncryptionState::write_key`).
            error!("could not read the account's encryption status: {err}");
            return EncryptionState::Unknown;
        }
    };
    if !status.enabled {
        return EncryptionState::Disabled;
    }
    match SessionKey::restore(user).await {
        Ok(Some(key)) => EncryptionState::Unlocked(key),
        Ok(None) => EncryptionState::Locked,
        Err(err) => {
            // A keystore that could not be opened is `Locked`, exactly like
            // an empty one: the user still has their passkey and their
            // recovery code, and an unlock prompt is what gets them back in
            // (`crypto::keystore`'s point 2).
            error!("could not read this device's key store: {err}");
            EncryptionState::Locked
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec E2 at the unit level, and the half the SSR test cannot reach:
    /// `Unknown` and `Disabled` both hydrate cleanly, so a render is blind
    /// to the difference between them. The difference is what a signed-in
    /// visitor's *writes* then do — see `write_key` below.
    #[test]
    fn a_context_that_has_not_probed_yet_is_unknown() {
        let owner = Owner::new();
        owner.with(|| {
            let auth = AuthCtx {
                user: RwSignal::new(None),
            };
            let ctx = EncryptionCtx::probing(auth);
            assert!(matches!(ctx.state(), EncryptionState::Unknown));
            assert!(matches!(
                ctx.state_untracked().write_key(),
                WriteKey::Locked
            ));
        });
        owner.cleanup();
    }

    /// The regression this guards against, and the reason the write side
    /// has its own three-state type: a session that cannot seal must refuse
    /// the write rather than fall back to plaintext. `Unknown` is included
    /// deliberately — it is the state every signed-in page load starts in,
    /// so treating it as "no encryption" would downgrade the first save
    /// after every reload.
    #[test]
    fn a_session_that_cannot_seal_refuses_to_write() {
        assert!(matches!(
            EncryptionState::Unknown.write_key(),
            WriteKey::Locked
        ));
        assert!(matches!(
            EncryptionState::Locked.write_key(),
            WriteKey::Locked
        ));
    }

    #[test]
    fn an_account_with_encryption_off_writes_plaintext() {
        assert!(matches!(
            EncryptionState::Disabled.write_key(),
            WriteKey::Plaintext
        ));
    }

    /// The read side's complement: only `Unlocked` offers a key, and it is
    /// the one arm no host test can build — `SessionKey` is uninhabited off
    /// the browser. What is testable is that nothing *else* offers one, so a
    /// state that cannot decrypt never claims it can.
    #[test]
    fn only_an_unlocked_session_offers_a_read_key() {
        for state in [
            EncryptionState::Unknown,
            EncryptionState::Disabled,
            EncryptionState::Locked,
        ] {
            assert!(state.key().is_none());
        }
    }
}
