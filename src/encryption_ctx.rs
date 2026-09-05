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
//!
//! # Identity lives here
//!
//! This module is the only place that asks *whose* key a session holds. The
//! storage seam takes the key it is handed and tries it (see
//! [`crate::storage`]'s header), so the guarantees that keep a key and an
//! account together are all below: the probe resets to `Unknown` whenever
//! `AuthCtx::user` changes, `SessionKey::restore` reads the keystore under
//! the signed-in address, and `EncryptionCtx::unlock` refuses a key whose
//! `SessionKey::user` is not the one signed in now — *before* that key is
//! written to this device's keystore, which is the ordering that makes
//! signing out actually take.

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
/// Five states rather than the three an account can be in, because "not yet
/// known" is a state the UI has to render — see this module's header — and
/// because a probe that *failed* has to be told apart from one that has not
/// finished (see [`Unreachable`](Self::Unreachable)).
#[derive(Clone)]
pub enum EncryptionState {
    /// Before the probe resolves, and everything the server ever renders.
    Unknown,
    /// The probe ran and could not answer: the status call failed.
    ///
    /// Every decision this feeds is `Unknown`'s — no key, no write — and it
    /// differs in exactly one respect, which is why it is a state rather
    /// than a comment on `Unknown`: nothing more will happen on its own.
    /// The probe's effect re-runs only when `AuthCtx::user` changes, so
    /// without `EncryptionCtx::retry` one dropped request would refuse
    /// every write for the rest of the session, with a console line as the
    /// only trace. The server never probes and so never reaches this,
    /// which is what keeps invariant E2 intact.
    Unreachable,
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
    /// `Unknown`, `Unreachable` and `Locked` all read as "no key", and that
    /// is safe: a v2 row then surfaces as
    /// [`crate::storage::StorageError::Locked`], which is the honest answer
    /// for a reader who has not unlocked yet, and a v1 row reads identically
    /// either way (spec E3).
    pub fn key(&self) -> Option<&SessionKey> {
        match self {
            EncryptionState::Unlocked(key) => Some(key),
            EncryptionState::Unknown
            | EncryptionState::Unreachable
            | EncryptionState::Disabled
            | EncryptionState::Locked => None,
        }
    }

    /// What a write should do, which is deliberately *not* the mirror of
    /// [`key`](Self::key).
    ///
    /// A read can collapse "not encrypted" and "no key here" into one
    /// answer, because the row itself says which it is. A write cannot: the
    /// body is on its way out and nothing downstream would ever notice that
    /// an encrypted account had just taken a plaintext row. So `Locked`
    /// refuses — and so do `Unknown` and `Unreachable`, because a write that
    /// cannot yet say whether the account is encrypted must not guess, and
    /// the wrong guess is unrecoverable in exactly the same way (see
    /// [`WriteKey`]).
    pub fn write_key(&self) -> WriteKey<'_> {
        match self {
            EncryptionState::Disabled => WriteKey::Plaintext,
            EncryptionState::Unlocked(key) => WriteKey::Sealed(key),
            EncryptionState::Unknown | EncryptionState::Unreachable | EncryptionState::Locked => {
                WriteKey::Locked
            }
        }
    }
}

/// Which key a read would use, reduced to something a `Memo` can compare.
///
/// The load in [`crate::storage::hook::use_persistent`] has to re-run when
/// the key changes — an unlock is what turns a sealed row into readable
/// text — and must *not* re-run when anything else about the state does. A
/// re-run resets the value to `None` and republishes whatever storage holds,
/// so a probe resolving in the window between a keystroke and its save would
/// wipe what the user had just typed off the screen. Every keyless state
/// therefore collapses to one value: a load run under any of them reads
/// exactly the same rows with exactly no key.
///
/// Keys are told apart by a counter rather than by their contents, because
/// [`SessionKey`] is neither comparable nor even inhabited off the browser:
/// this is the `n`th key the page load published. Two publishes of the same
/// key material read as two keys, which costs one redundant load — the safe
/// direction, since the alternative is a load that should have happened and
/// did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdentity {
    /// No key at all: `Unknown`, `Unreachable`, `Disabled` or `Locked`.
    NoKey,
    /// The `n`th key published in this page load.
    Key(u64),
}

/// This account's encryption state, shared across the component tree.
#[derive(Clone, Copy)]
pub struct EncryptionCtx {
    state: StateSignal,
    /// How many keys this page load has published, which is what gives
    /// [`KeyIdentity`] something to compare. See
    /// [`publish`](Self::publish).
    keys: StoredValue<u64>,
    /// Who the state is about.
    ///
    /// `hydrate`-only because the browser is the only target that can hold
    /// a key to check against it — a `cfg` rather than an `allow`, so the
    /// field's absence says so rather than a comment.
    #[cfg(feature = "hydrate")]
    auth: AuthCtx,
    /// Shared by the first probe, every [`retry`](Self::retry) and
    /// [`signing_out`](Self::signing_out), so all three can invalidate each
    /// other.
    ///
    /// Ungated, unlike the probe it guards: `signing_out` is called from a
    /// click handler that is not itself `cfg`-forked, and a counter the
    /// server never bumps costs eight bytes.
    generation: StoredValue<Generation>,
}

impl EncryptionCtx {
    /// Creates the context and starts the probe that resolves it.
    ///
    /// The context is usable immediately and reads [`EncryptionState::Unknown`]
    /// until the probe lands; on the server it stays that way forever,
    /// which is the whole point (see this module's header).
    pub fn probing(auth: AuthCtx) -> Self {
        let ctx = Self {
            state: unknown_state(),
            keys: StoredValue::new(0),
            #[cfg(feature = "hydrate")]
            auth,
            generation: StoredValue::new(Generation::default()),
        };

        // Browser-only in full, not merely dormant under `ssr`: the probe
        // reaches a server function and this device's IndexedDB, and a
        // render may touch neither. `Effect::new` never runs during SSR
        // anyway (see `storage::hook`), so gating the whole block just keeps
        // a keystore read out of the server binary.
        #[cfg(feature = "hydrate")]
        {
            Effect::new(move |_| {
                // Tracked: signing *out* is a live, no-reload toggle
                // (`AccountMenu` clears `AuthCtx::user` in place) and it
                // changes the answer. Signing in reloads the page instead,
                // so this effect meets that one as a fresh page load rather
                // than as a change.
                ctx.start_probe(auth.user.get());
            });
        }
        #[cfg(not(feature = "hydrate"))]
        let _ = auth;

        ctx
    }

    /// Invalidates every probe in flight and returns the token of the one
    /// starting now.
    ///
    /// Every path that changes what a probe should answer goes through here
    /// — [`start_probe`](Self::start_probe), [`retry`](Self::retry) and
    /// [`signing_out`](Self::signing_out) — so there is one counter and one
    /// rule about who may publish.
    fn begin_probe(self) -> u64 {
        self.generation
            .try_update_value(Generation::next)
            .unwrap_or_default()
    }

    /// Whether `token` still identifies the newest probe, and so may
    /// publish.
    ///
    /// `try_with_value` rather than the panicking form, since this owner can
    /// be disposed while a probe is still in flight. A fallback of `false`
    /// degrades to "discard the answer", which is the safe direction.
    #[cfg(any(feature = "hydrate", test))]
    fn may_publish(self, token: u64) -> bool {
        self.generation
            .try_with_value(|g| g.is_current(token))
            .unwrap_or(false)
    }

    /// Invalidates every probe in flight, because the user has asked to sign
    /// out.
    ///
    /// Called at the *start* of sign-out, before the server is asked for
    /// anything, and that timing is the whole of the point. `AuthCtx::user`
    /// is not cleared until `logout()` answers — a full network round trip
    /// later — and until it is, the probe's effect does not re-run and
    /// nothing else bumps the counter. A probe already in flight when the
    /// button was pressed therefore stays current for that entire window and
    /// can land and publish `Unlocked` for an account the user has just
    /// asked the device to forget, driving a keystore write behind
    /// `crypto::forget_device_key`'s back.
    ///
    /// It publishes nothing itself, deliberately: a sign-out the server
    /// refuses leaves the user signed in, and moving the state here would
    /// strand that session on a value nothing re-runs to correct.
    pub fn signing_out(self) {
        let _ = self.begin_probe();
    }

    /// Starts a probe for `user`, discarding any probe still in flight.
    ///
    /// The token is captured synchronously, before the `spawn_local` below,
    /// for the reason `week_view`'s range load spells out: this can be
    /// called again — from the effect, or from [`retry`](Self::retry) —
    /// while an earlier probe is still awaiting the server, and reading the
    /// token back out after the await would race that later run for the
    /// increment.
    #[cfg(feature = "hydrate")]
    fn start_probe(self, user: Option<String>) {
        let token = self.begin_probe();

        let Some(user) = user else {
            // Signed out means `localStorage`, which is never encrypted
            // (spec section 1.2). So this needs no server call — and must
            // not make one, since there is no session to make it with.
            self.publish(EncryptionState::Disabled);
            return;
        };

        // Back to "not known yet" before the probe starts, so an `Unlocked`
        // reached for the previous account never survives into the next
        // one's render — the same reset `use_persistent` does when its key
        // changes.
        self.publish(EncryptionState::Unknown);

        spawn_local(async move {
            let probed = probe(&user).await;
            // Only the newest probe may publish; an older one landing after
            // a sign-out, or after a retry overtook it, must be discarded
            // rather than overwrite it.
            if self.may_publish(token) {
                self.publish(probed);
            }
        });
    }

    /// Runs the probe again, which is the only thing that can move
    /// [`EncryptionState::Unreachable`].
    ///
    /// Without it a single dropped request refuses every write for the rest
    /// of the session: the probe's effect re-runs only when `AuthCtx::user`
    /// changes, and a failed probe changes nothing that would trigger it.
    /// `UnlockPrompt`'s retry button is the way out.
    ///
    /// Shares the probe's `Generation` rather than taking one of its own. A
    /// retry and the probe it retries are two runs of the same thing and
    /// only the newest may publish; two counters would each read itself as
    /// current, and whichever answer arrived last would win regardless of
    /// which was asked for last.
    #[cfg(feature = "hydrate")]
    pub fn retry(self) {
        // Untracked: this runs from a click handler rather than an effect,
        // so there is no dependency worth registering — and registering one
        // would make the handler's owner a subscriber of `AuthCtx`.
        self.start_probe(self.auth.user.get_untracked());
    }

    /// Publishes `state`, giving a newly unlocked key an identity of its
    /// own.
    ///
    /// Every write to the signal goes through here, and the counter is
    /// bumped *before* the set, so a `Memo` over
    /// [`key_identity`](Self::key_identity) recomputing in response to that
    /// set already sees the new number.
    #[cfg(any(feature = "hydrate", test))]
    fn publish(self, state: EncryptionState) {
        if matches!(state, EncryptionState::Unlocked(_)) {
            let _ = self.keys.try_update_value(|n| *n += 1);
        }
        self.state.set(state);
    }

    /// Builds a context already parked at `state`, bypassing the probe
    /// entirely.
    ///
    /// Test-only, and the only way to reach `Locked` or `Unreachable` — or
    /// to pin `Disabled` explicitly — on the host: `probing` always starts
    /// at `Unknown`, and the `Effect` that could move it anywhere else is
    /// `hydrate`-only. `DayView`'s and `WeekView`'s mount-gate tests need
    /// exactly this to prove those components actually branch on
    /// `EncryptionState`, not merely that the states exist, and
    /// `storage::hook`'s reload test needs it to drive a transition.
    ///
    /// `ssr` as well as `test`: the mount-gate call sites render with
    /// `.to_html()`, which needs `leptos`'s `ssr` feature, so this has no
    /// caller — and would be dead code — under a bare
    /// `cargo test --no-default-features`.
    #[cfg(all(test, feature = "ssr"))]
    pub(crate) fn for_state(state: EncryptionState) -> Self {
        let ctx = Self {
            state: unknown_state(),
            keys: StoredValue::new(0),
            #[cfg(feature = "hydrate")]
            auth: AuthCtx {
                user: RwSignal::new(None),
            },
            generation: StoredValue::new(Generation::default()),
        };
        ctx.publish(state);
        ctx
    }

    /// Moves a [`for_state`](Self::for_state) context to another state, so a
    /// test can drive a transition rather than only observe one. Goes
    /// through [`publish`](Self::publish), so key identities behave here
    /// exactly as they do in the browser.
    #[cfg(all(test, feature = "ssr"))]
    pub(crate) fn set_for_test(self, state: EncryptionState) {
        self.publish(state);
    }

    /// The current state, tracked.
    ///
    /// Tracked is what makes an unlock visible without a reload: the day and
    /// week views render through here, so resolving the probe — or
    /// unlocking later — swaps the unlock prompt for the entry area.
    ///
    /// Reads that only want to know *which key* should not use this; see
    /// [`key_identity`](Self::key_identity).
    pub fn state(self) -> EncryptionState {
        self.state.get()
    }

    /// The current state, without subscribing.
    ///
    /// The write path's read, and the load path's read of the key itself. A
    /// save must use the session as it is right now, not turn itself into a
    /// reactive dependency of the effect it was spawned from — the same
    /// reason `Persistent::set` reads its key and backend untracked.
    pub fn state_untracked(self) -> EncryptionState {
        self.state.get_untracked()
    }

    /// Which key a read would use, tracked — the narrow dependency the
    /// storage load subscribes to instead of [`state`](Self::state).
    ///
    /// See [`KeyIdentity`] for why the load must not track the state's
    /// shape.
    pub fn key_identity(self) -> KeyIdentity {
        match self.state.get() {
            EncryptionState::Unlocked(_) => {
                KeyIdentity::Key(self.keys.try_get_value().unwrap_or_default())
            }
            EncryptionState::Unknown
            | EncryptionState::Unreachable
            | EncryptionState::Disabled
            | EncryptionState::Locked => KeyIdentity::NoKey,
        }
    }

    /// Whether `key` belongs to the account signed in *right now*.
    #[cfg(feature = "hydrate")]
    fn is_current_account(self, key: &SessionKey) -> bool {
        self.auth.user.get_untracked().as_deref() == Some(key.user())
    }

    /// Publishes a session an unlock ceremony just opened, and remembers it
    /// on this device (spec sections 6.3 and 7.3).
    ///
    /// The only way anything outside this module reaches `Unlocked` other
    /// than the probe finding a key already in the keystore.
    ///
    /// The keystore write happens *here*, behind the identity check below,
    /// and not inside the ceremony that produced the key. It used to happen
    /// there, on the way to building the `SessionKey` — before anyone had
    /// asked whose account this was — so an unlock resolving after a
    /// sign-out left the previous account's record on the device. Another
    /// account could not read it (`keystore::get` checks the stored user),
    /// but "your key is gone from this device" is exactly the promise
    /// sign-out makes, and that broke it.
    ///
    /// Async for the same reason: the write has to be sequenced against the
    /// check rather than fired past it.
    ///
    /// `hydrate`-only, like the type it takes: nothing off the browser ever
    /// holds a `SessionKey` to pass here.
    #[cfg(feature = "hydrate")]
    pub async fn unlock(self, key: SessionKey) {
        // The ceremony that produced this key is async and the account menu
        // stays mounted throughout it, so the account can change underneath
        // it — signing out is a live toggle. A key opened for the account
        // that has just left must not become this session's: on the
        // signed-out page it would seal `localStorage` rows under a key
        // nothing can restore afterwards. This is the check the storage
        // seam relies on and never repeats (see `storage`'s header).
        if !self.is_current_account(&key) {
            error!("discarding an unlock for an account that is no longer signed in");
            return;
        }
        if let Err(e) = key.remember().await {
            error!("could not remember the data key on this device: {e}");
        }
        // Checked again on the far side of the write, because the write is
        // itself an await and signing out is a live toggle for the whole of
        // it. `crypto::forget_device_key`'s delete and this put are two
        // IndexedDB transactions with nothing ordering them against each
        // other, so a sign-out landing inside this window can be undone only
        // by looking afterwards.
        if !self.is_current_account(&key) {
            error!("an unlock landed for an account that has since signed out; forgetting it");
            if let Err(e) = crate::crypto::forget_device_key().await {
                error!("could not forget the key written for a signed-out account: {e}");
            }
            return;
        }
        self.publish(EncryptionState::Unlocked(key));
    }

    /// Forgets this device's key, on purpose (spec section 6.7).
    ///
    /// Publishes `Locked` *before* awaiting the keystore, so the in-memory
    /// key is dropped the moment the user asks rather than whenever
    /// IndexedDB gets round to it. The two halves matter separately: the
    /// publish is what stops this page reading and writing entries, and the
    /// clear is what stops the next page load picking the key straight back
    /// up. A failed clear is therefore worth telling the user about — this
    /// returns the error rather than logging it, because "locked until you
    /// reload" is not what they asked for.
    ///
    /// Only meaningful for an encrypted account, which is the only state
    /// `/account`'s panel offers it from; publishing `Locked` for an
    /// unencrypted one would claim an encryption that does not exist.
    ///
    /// Goes through [`crate::crypto::forget_device_key`] rather than the
    /// keystore directly, so an unlock ceremony still running when the user
    /// pressed this cannot write its key back afterwards.
    #[cfg(feature = "hydrate")]
    pub async fn lock(self) -> Result<(), crate::crypto::subtle::CryptoError> {
        self.publish(EncryptionState::Locked);
        crate::crypto::forget_device_key().await
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
            // encrypted. `Unreachable` says only what is true — nothing was
            // learned — refuses writes until something is
            // (`EncryptionState::write_key`), and unlike `Unknown` says so
            // to the user, who can then ask for another try.
            error!("could not read the account's encryption status: {err}");
            return EncryptionState::Unreachable;
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
    /// visitor's *writes* then do.
    ///
    /// What this can pin is only the starting value, not that a probe ran
    /// and found nothing: the probe is an `Effect`, `hydrate`-only, and
    /// absent from this build entirely. The `AuthCtx` is decorative for the
    /// same reason — a signed-in one would produce this same result here.
    #[test]
    fn a_context_starts_unknown_and_refuses_writes() {
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
    /// after every reload — and so is `Unreachable`, which is the state a
    /// failed probe leaves behind and would otherwise downgrade every save
    /// for the rest of the session.
    #[test]
    fn a_session_that_cannot_seal_refuses_to_write() {
        for state in [
            EncryptionState::Unknown,
            EncryptionState::Unreachable,
            EncryptionState::Locked,
        ] {
            assert!(matches!(state.write_key(), WriteKey::Locked));
        }
    }

    #[test]
    fn an_account_with_encryption_off_writes_plaintext() {
        assert!(matches!(
            EncryptionState::Disabled.write_key(),
            WriteKey::Plaintext
        ));
    }

    // `EncryptionState::key` has no host test of its own, deliberately. The
    // only arm that can answer `Some` is `Unlocked`, which needs a
    // `SessionKey` — uninhabited off the browser — so the three arms a host
    // test can build could not return one whatever the body of the function
    // said. An assertion over them passes against every possible
    // implementation, which reads as coverage of the read path while
    // guarding nothing. `write_key`, above, is where the same decision is
    // genuinely discriminable, and it is tested there.

    /// Extension 2 of the sign-out story, at the level the host can reach.
    ///
    /// Signing out clears `AuthCtx::user` only once `logout()` has answered,
    /// so a probe already in flight when the button was pressed stays
    /// current for a whole network round trip — long enough to land and
    /// publish `Unlocked`, which is a key republished onto a device that has
    /// just been told to forget one. Bumping the counter the moment the user
    /// asks is what closes that window.
    ///
    /// The probe itself is `hydrate`-only, so what this drives is the
    /// generation bookkeeping underneath it: the same `begin_probe` /
    /// `may_publish` pair `start_probe` uses, which is the whole of the
    /// decision about who is allowed to publish.
    #[cfg(feature = "ssr")]
    #[test]
    fn signing_out_invalidates_a_probe_already_in_flight() {
        let owner = Owner::new();
        owner.with(|| {
            let ctx = EncryptionCtx::for_state(EncryptionState::Unknown);
            let in_flight = ctx.begin_probe();
            assert!(
                ctx.may_publish(in_flight),
                "the probe is the newest until something else starts"
            );

            ctx.signing_out();

            assert!(
                !ctx.may_publish(in_flight),
                "a probe in flight when the user signed out must not publish afterwards"
            );
        });
        owner.cleanup();
    }

    /// The narrowing A1 turns on, at the unit level: every state without a
    /// key reduces to one identity, so a `Memo` over it stays silent across
    /// a transition between them. The reload that a notification would
    /// trigger is what erased a keystroke made while the probe was still
    /// running — `storage::hook` pins that end of it.
    #[cfg(feature = "ssr")]
    #[test]
    fn every_keyless_state_shares_one_key_identity() {
        let owner = Owner::new();
        owner.with(|| {
            let ctx = EncryptionCtx::for_state(EncryptionState::Unknown);
            assert_eq!(ctx.key_identity(), KeyIdentity::NoKey);
            for state in [
                EncryptionState::Unreachable,
                EncryptionState::Disabled,
                EncryptionState::Locked,
            ] {
                ctx.set_for_test(state);
                assert_eq!(
                    ctx.key_identity(),
                    KeyIdentity::NoKey,
                    "a state with no key must not read as a new key"
                );
            }
        });
        owner.cleanup();
    }
}
