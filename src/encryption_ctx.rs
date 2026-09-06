//! Whether this account is encrypted, and whether this device can read it.
//!
//! The view layer's half of spec section 7.4. Components never touch
//! `crypto` directly: they read this context, and the storage seam takes the
//! answer out of it.
//!
//! # Why the seed depends on who is signed in
//!
//! [`EncryptionCtx::probing`] does not start every page load at `Unknown`.
//! It starts at [`EncryptionState::Disabled`] for a signed-out visitor and
//! at `Unknown` for a signed-in one, and the two halves have different
//! reasons.
//!
//! A signed-out visitor uses `Backend::Local` (`AuthCtx::backend`), which is
//! never encrypted (spec section 1.2). That is not a conclusion read from a
//! row nobody has fetched yet — it is a fact about which backend
//! `localStorage` is, true before any probe could run. Starting that
//! visitor at `Unknown` anyway bought nothing but a read-only textarea and
//! a "Getting ready" banner on the app's main page, for as long as wasm
//! took to load, for a visitor who was never at risk.
//!
//! A signed-in visitor is the case the rest of this section is about — the
//! same reasoning as the entry tri-state in [`crate::storage::hook`], one
//! step further out. The server *could* read `encrypted_at` cheaply — it
//! has the session — but rendering `Locked` would put user-derived state in
//! the SSR body, and the browser cannot tell locked from unlocked without
//! an async IndexedDB read anyway, so the first client render would differ
//! regardless. [`EncryptionState::Unknown`] on both sides is the only value
//! that hydrates for that visitor (invariant E2, pinned by `app`'s
//! `ssr_renders_unknown_encryption_state`).
//!
//! `Disabled` would hydrate just as cleanly for a signed-in visitor too,
//! which is exactly why seeding it there would be wrong rather than merely
//! unnecessary: it is a *conclusion* — "this account has no encryption" —
//! and asserting it before anything has been read is what starts writing
//! plaintext rows into an account that may be encrypted.
//!
//! Both halves are computed from [`crate::auth_ctx::initial_user`], which
//! server and browser already derive identically from the same underlying
//! fact — the session cookie — so seeding from it costs nothing hydration
//! was not already paying for; see that function's doc comment.
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
#[cfg(any(feature = "hydrate", test))]
use crate::dto::EncryptionStatus;
use crate::storage::{Backend, WriteKey};

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
fn state_signal(initial: EncryptionState) -> StateSignal {
    #[cfg(feature = "hydrate")]
    {
        RwSignal::new_local(initial)
    }
    #[cfg(not(feature = "hydrate"))]
    {
        RwSignal::new(initial)
    }
}

/// What a page load should seed [`EncryptionCtx`] to, from the same
/// signed-in identity both targets already compute identically — see this
/// module's header for why a signed-out visitor gets a conclusion instead
/// of the probe's usual starting point.
fn initial_state(user: Option<&str>) -> EncryptionState {
    if user.is_some() {
        EncryptionState::Unknown
    } else {
        EncryptionState::Disabled
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
    /// Before the probe resolves. What the server renders for a signed-in
    /// visitor — the only visitor it ever probes for; see this module's
    /// header for the signed-out seed.
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
    ///
    /// Also what a signed-out visitor's context seeds to, on both targets,
    /// before anything has run — see this module's header. `Backend::Local`
    /// is never encrypted, so nothing about that visitor needs a probe to
    /// answer.
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

    /// Whether a save made right now would be stored, and if not, whether
    /// the user can do anything about it.
    ///
    /// Reads the decision back out of [`write_key`](Self::write_key) rather
    /// than repeating the match, so the entry area cannot invite a keystroke
    /// the seam then refuses. See [`Writes`].
    ///
    /// # Why this takes the backend
    ///
    /// [`Disabled`](Self::Disabled) answers two opposite questions depending
    /// on where the write is going, and only one of them is a refusal.
    /// `localStorage` is never encrypted (spec section 1.2), so a signed-out
    /// visitor's plaintext write is exactly right — that is the fully
    /// working mode the gate's escape hatch falls back to. The server stores
    /// entries only for accounts that have encryption (invariant E9), so the
    /// same state on [`Backend::Remote`] is a write that cannot land, and
    /// the day and week views must not offer a surface for it (spec section
    /// 4.1).
    ///
    /// The backend is a parameter rather than a second pair of
    /// [`EncryptionState`] variants because `storage::write_target` — the
    /// seam this mirrors — decides on exactly the pair
    /// `(Backend, WriteKey)`, and a mirror taking fewer inputs than the
    /// decision it reflects is reflecting something narrower than it claims.
    /// Every caller already holds the backend — as a field on
    /// [`crate::storage::hook::Persistent`], and as `AuthCtx::backend()` at
    /// the three gates — so nothing is saved by hiding it. Splitting the
    /// state instead would mean deriving that same fact a second time, out
    /// of the probe, and two derivations of one fact can lag each other
    /// where one cannot.
    pub fn writes(&self, backend: Backend) -> Writes {
        match (backend, self.write_key()) {
            // Checked before the backend, exactly as `write_target` does:
            // a session that cannot seal refuses wherever it is writing.
            (_, WriteKey::Locked) => Writes::Refused,
            (Backend::Local, _) => Writes::Accepted,
            (Backend::Remote, WriteKey::Sealed(_)) => Writes::Accepted,
            (Backend::Remote, WriteKey::Plaintext) => Writes::SetupRequired,
        }
    }
}

/// Whether a save made right now would be stored, and if not, whose problem
/// that is.
///
/// The write side's counterpart to [`KeyIdentity`], and the answer the entry
/// area renders itself from. It is derived from
/// [`write_key`](EncryptionState::write_key) and the backend rather than
/// matched on the state again, so the box the user can type into and the
/// call that refuses the keystroke cannot come to disagree.
///
/// It exists because the disagreement is silent. For a signed-in visitor the
/// server renders `Unknown` (invariant E2) and so does the client's first
/// render, and `Unknown` is `WriteKey::Locked` — a window a full network
/// round trip wide, with the textarea mounted and editable throughout.
/// Anything typed into it was refused with nothing on screen to say so. A
/// signed-out visitor never sees that window at all; their seed is
/// `Disabled`, which is why the seed depends on who is signed in (see this
/// module's header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writes {
    /// This device can seal, or the write is going somewhere that needs no
    /// sealing. A save lands.
    Accepted,
    /// Nothing is known about the account's encryption yet, or this device
    /// holds no key for it. A save would be refused, and only a probe
    /// answering or an unlock changes that.
    Refused,
    /// The account has no encryption, and the server stores entries only
    /// for accounts that do (invariant E9).
    ///
    /// A refusal like [`Refused`](Self::Refused), and told apart from it
    /// because it is the one the *user* can clear and the only one with
    /// somewhere to send them. This is spec section 4.1's gate: the day and
    /// week views mount `SetupGate` instead of their content, rather than a
    /// writing surface every save would be dropped from.
    SetupRequired,
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

/// Which identity a state reduces to, given how many keys this page load
/// has published.
///
/// Lifted out of [`EncryptionCtx::key_identity`] because that method cannot
/// be driven both ways on the host: its only key-bearing state needs a
/// [`SessionKey`], which is uninhabited off the browser, so a test over the
/// states a host *can* build passes just as well against
/// `fn key_identity(self) -> KeyIdentity { KeyIdentity::NoKey }`.
///
/// That implementation is not a hypothetical — it is the failure the whole
/// `Memo` narrowing risks, and it fails quietly. `use_persistent`'s load
/// subscribes to this, so if unlocking never produced a *new* identity the
/// load would not re-run and a user who had just unlocked would go on seeing
/// an empty day until they navigated somewhere else.
fn identity_of(has_key: bool, keys: u64) -> KeyIdentity {
    if has_key {
        KeyIdentity::Key(keys)
    } else {
        KeyIdentity::NoKey
    }
}

/// How a row failed to read, seen as evidence about the session that read
/// it rather than about the row.
///
/// The distinction is invariant E8's: the state is computed once per page
/// load and re-probed only when `AuthCtx::user` changes, so a stored row is
/// the only thing that can contradict it. These are the two shapes that
/// contradiction arrives in.
#[cfg(any(feature = "hydrate", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnreadableRow {
    /// Sealed against a session holding no key at all. Only an encrypted
    /// account can hold such a row and only a keyless session can fail to
    /// open one, so it is proof rather than a hint.
    Sealed,
    /// Opened with the key this session holds, and it did not open.
    ///
    /// Ambiguous, unlike `Sealed`: usually the row really is damaged. But a
    /// tab whose cookie has been replaced — a second tab signing in as
    /// somebody else — fails exactly this way, on every row of the account
    /// it has now been handed, while still reporting `Unlocked` and
    /// accepting writes. That is why acting on it is latched rather than
    /// trusted (see [`EncryptionCtx::claim_reprobe`]).
    Unopenable,
}

#[cfg(any(feature = "hydrate", test))]
impl UnreadableRow {
    /// Whether acting on this row is limited to once per page load.
    ///
    /// Only [`Unopenable`](Self::Unopenable) is, and only because its
    /// evidence is ambiguous. A sealed row proves what it says, so a state
    /// it contradicts can be re-probed every time one turns up.
    fn latched(self) -> bool {
        matches!(self, UnreadableRow::Unopenable)
    }

    /// What to log when this row contradicts the session that read it.
    #[cfg(feature = "hydrate")]
    fn contradiction(self) -> &'static str {
        match self {
            UnreadableRow::Sealed => {
                "a sealed row reached a session that believes this account is unencrypted"
            }
            UnreadableRow::Unopenable => {
                "a row would not open under this session's key; re-probing once, in case this \
                 tab's account has been replaced"
            }
        }
    }
}

/// Which state a row that would not read contradicts, and what a probe
/// confirming it should park at meanwhile — or `None` when the row tells
/// this state nothing it does not already say.
///
/// Lifted out of the methods below for the reason [`identity_of`] was: the
/// decision is the half an edit can quietly get wrong, and it is the only
/// half of either path a host test can drive, since the probe it feeds is
/// `hydrate`-only.
///
/// The two rows contradict opposite states, which is why one function
/// answers for both. A sealed row can only reach a session with *no* key,
/// so it says nothing to a state that already knows it has none; what it
/// contradicts is [`EncryptionState::Disabled`], the one state that is
/// simultaneously a conclusion and [`WriteKey::Plaintext`]. A row that would
/// not *open* is the mirror image: it can only reach a session that *has* a
/// key, so [`EncryptionState::Unlocked`] is the only state it contradicts.
///
/// The parking states differ for the same reason. A sealed row has already
/// proved the account is encrypted, so its probe parks at
/// [`EncryptionState::Locked`] and the unlock prompt goes up at once. A row
/// that would not open has proved nothing — it may simply be damaged — so
/// its probe parks at [`EncryptionState::Unknown`], which refuses writes
/// without asserting anything about the account.
///
/// The `Sealed` half is a decision nothing currently asks for: see
/// [`EncryptionCtx::sealed_row_seen`] for why the gate leaves it dormant.
#[cfg(any(feature = "hydrate", test))]
fn contradicted_by(row: UnreadableRow, state: &EncryptionState) -> Option<EncryptionState> {
    match row {
        UnreadableRow::Sealed => {
            matches!(state, EncryptionState::Disabled).then_some(EncryptionState::Locked)
        }
        UnreadableRow::Unopenable => state.key().is_some().then_some(EncryptionState::Unknown),
    }
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
    /// Whether this page load has already spent its one re-probe on an
    /// ambiguous row. See [`claim_reprobe`](Self::claim_reprobe).
    #[cfg(any(feature = "hydrate", test))]
    reprobed: StoredValue<bool>,
}

impl EncryptionCtx {
    /// Creates the context, seeded from `auth`, and starts the probe that
    /// resolves it.
    ///
    /// The seed is not always [`EncryptionState::Unknown`] — see this
    /// module's header. It is read once, untracked, at the same moment
    /// [`crate::auth_ctx::initial_user`] decided `auth` itself: this is the
    /// value both targets' *first* render must agree on, not a second
    /// reactive dependency alongside the `Effect` below, which already
    /// re-runs the probe whenever `auth.user` changes afterward. On the
    /// server a signed-in seed stays `Unknown` forever, since the probe
    /// never runs there — which is the half of the whole point this
    /// module's header was already making.
    pub fn probing(auth: AuthCtx) -> Self {
        let ctx = Self {
            state: state_signal(initial_state(auth.user.get_untracked().as_deref())),
            keys: StoredValue::new(0),
            #[cfg(feature = "hydrate")]
            auth,
            generation: StoredValue::new(Generation::default()),
            #[cfg(any(feature = "hydrate", test))]
            reprobed: StoredValue::new(false),
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
                ctx.start_probe(auth.user.get(), EncryptionState::Unknown);
            });
        }

        ctx
    }

    /// Invalidates every probe in flight and returns the token of the one
    /// starting now.
    ///
    /// Every path that changes what a probe should answer goes through here
    /// — [`start_probe`](Self::start_probe), [`retry`](Self::retry),
    /// [`signing_out`](Self::signing_out), [`unlock`](Self::unlock) and
    /// [`lock`](Self::lock) — so there is one counter and one rule about who
    /// may publish.
    ///
    /// `pub(crate)` for the last of those reasons only: [`crate::auth_ctx`]'s
    /// host test drives sign-out's ordering, and the invalidation is the
    /// step it has to be able to see happen.
    pub(crate) fn begin_probe(self) -> u64 {
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
    ///
    /// `pub(crate)` alongside [`begin_probe`](Self::begin_probe), and for the
    /// same test.
    #[cfg(any(feature = "hydrate", test))]
    pub(crate) fn may_publish(self, token: u64) -> bool {
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

    /// Starts a probe for `user`, discarding any probe still in flight, and
    /// parks the state at `meanwhile` until it answers.
    ///
    /// The token is captured synchronously, before the `spawn_local` below,
    /// for the reason `week_view`'s range load spells out: this can be
    /// called again — from the effect, from [`retry`](Self::retry), or from
    /// [`sealed_row_seen`](Self::sealed_row_seen) — while an earlier probe
    /// is still awaiting the server, and reading the token back out after
    /// the await would race that later run for the increment.
    ///
    /// `meanwhile` is a parameter because the two reasons to probe start
    /// from different amounts of knowledge. An ordinary probe knows nothing
    /// and parks at [`EncryptionState::Unknown`]; a probe started because a
    /// sealed row turned up has already been shown that the account is
    /// encrypted, and parking that one at `Unknown` would throw the
    /// evidence away for the width of a round trip.
    #[cfg(feature = "hydrate")]
    fn start_probe(self, user: Option<String>, meanwhile: EncryptionState) {
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
        self.publish(meanwhile);

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
        self.start_probe(self.auth.user.get_untracked(), EncryptionState::Unknown);
    }

    /// Takes the single re-probe a page load allows an ambiguous row to
    /// start, returning whether this call got it.
    ///
    /// The latch is what makes [`UnreadableRow::Unopenable`] safe to act on
    /// at all. That row usually *is* damaged, and a probe answering for the
    /// same account republishes `Unlocked` — a new [`KeyIdentity`], which
    /// re-runs the load, which fails the same way, which probes again.
    /// Spending the probe once breaks that cycle by construction rather than
    /// by timing, and costs nothing that matters: staleness is a property of
    /// the page load, so one look is all it ever takes to find it.
    #[cfg(any(feature = "hydrate", test))]
    fn claim_reprobe(self) -> bool {
        self.reprobed
            .try_update_value(|spent| {
                let first = !*spent;
                *spent = true;
                first
            })
            .unwrap_or(false)
    }

    /// Re-probes because `row` contradicts what this session says about
    /// itself, or does nothing when it does not. Returns whether a probe
    /// started.
    ///
    /// The probe runs even where the row has already settled the account's
    /// encryption, because the row cannot say whether this *device* has a
    /// key waiting in its keystore, and finding one is what turns the unlock
    /// prompt back into the day.
    #[cfg(feature = "hydrate")]
    fn reprobe(self, row: UnreadableRow) -> bool {
        let Some(meanwhile) = contradicted_by(row, &self.state_untracked()) else {
            return false;
        };
        // Checked after the contradiction, never before it: a row that says
        // nothing to this state must not spend the one probe a page load
        // gets.
        if row.latched() && !self.claim_reprobe() {
            return false;
        }
        error!("{}", row.contradiction());
        self.start_probe(self.auth.user.get_untracked(), meanwhile);
        true
    }

    /// Records that the storage seam met a row this session holds no key
    /// for, and re-probes if that contradicts what the state says.
    ///
    /// This was built for the long-lived tab. The state is computed once per
    /// page load and re-probed only when `AuthCtx::user` changes, so a tab
    /// left open while encryption is switched on elsewhere — a second tab,
    /// another device — goes on reporting [`EncryptionState::Disabled`]
    /// indefinitely, and every day sealed since then reads back as
    /// [`crate::storage::StorageError::Locked`].
    ///
    /// **Spec section 4.1's gate took that case over, and no live path
    /// reaches this any more.** [`contradicted_by`] says a sealed row
    /// contradicts exactly one state, `Disabled`, and `Disabled` on
    /// [`crate::storage::Backend::Remote`] is now [`Writes::SetupRequired`]:
    /// `week_view`'s range effect returns before its read, and the day view's
    /// read still starts but `SetupGate` navigates away and disposes the
    /// `Generation` it holds, so the result is discarded before this arm.
    /// `Backend::Local` cannot produce a sealed row at all —
    /// `storage::write_target` has no arm that seals to it. What corrects a
    /// stale tab instead is `SetupGate`'s own `retry`, which re-probes on
    /// arrival rather than trusting the state that sent it there.
    ///
    /// Kept rather than removed, and honestly: the report costs one call at
    /// the seam, the decision behind it is host-tested, and it is the net
    /// already in place if the gate's shape changes — a new backend, or a
    /// state that stops being `SetupRequired`. It is a dormant guard, not a
    /// working mechanism, and should not be cited as one.
    ///
    /// Which states that contradicts, and what the probe parks at meanwhile,
    /// is [`contradicted_by`]'s decision; every other state is left alone,
    /// each for its own reason: `Unknown` already has a probe on the way to
    /// the same answer; `Locked` is the answer; `Unreachable` refuses writes
    /// and offers the user a retry, and re-probing behind their back would
    /// trade a truthful "we could not tell" for a spinner; and `Unlocked`
    /// cannot produce a sealed read at all — the row it cannot read fails
    /// the other way, which is [`unopenable_row_seen`](Self::unopenable_row_seen).
    ///
    /// Ungated so the storage seam can report the row from code that
    /// compiles on every target. Off the browser there is no probe to start
    /// and no keystore to read, and the seam's load never runs there
    /// (`storage::hook`'s effect is browser-only), so an `ssr` build gets a
    /// no-op it never calls.
    pub fn sealed_row_seen(self) {
        #[cfg(feature = "hydrate")]
        let _ = self.reprobe(UnreadableRow::Sealed);
    }

    /// Records that the storage seam met a row this session's own key would
    /// not open, and re-probes **once per page load** if that contradicts
    /// the state. Returns whether it started that probe.
    ///
    /// [`sealed_row_seen`](Self::sealed_row_seen)'s sibling, for the tab
    /// that goes stale across a *sign-in* rather than an enable. A second
    /// tab signing in as somebody else replaces this tab's cookie, and
    /// nothing re-runs the probe to notice: `Backend::Remote` then returns
    /// the *other* account's rows, which this tab's key does not open. That
    /// failure is [`crate::storage::StorageError::Crypto`], not `Locked`, so
    /// none of the sealed-row machinery sees it — and the tab goes on
    /// reporting `Unlocked`, rendering an empty *editable* box over somebody
    /// else's day, whose next keystroke seals it under a key that account
    /// will never have.
    ///
    /// The re-probe is what closes it, and the account check in [`probe`] is
    /// what makes the answer safe: a tab whose cookie has been replaced
    /// lands on `Unreachable`, which refuses writes and says plainly that
    /// nothing could be established, rather than on a conclusion about an
    /// account it is not showing.
    ///
    /// The return value is for the caller's *display*, not its safety: a
    /// caller that started a probe should leave the day unloaded rather than
    /// render it empty, since the state this publishes re-runs the load
    /// anyway. Refusing the write is entirely
    /// [`EncryptionState::write_key`]'s job.
    pub fn unopenable_row_seen(self) -> bool {
        #[cfg(feature = "hydrate")]
        {
            self.reprobe(UnreadableRow::Unopenable)
        }
        // Same reasoning as `sealed_row_seen`: reportable from every
        // target, actionable only where a probe exists to start.
        #[cfg(not(feature = "hydrate"))]
        false
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
    /// Test-only, and still the only way to reach `Locked` or `Unreachable`
    /// on the host — the `Effect` that could move `probing` there is
    /// `hydrate`-only. It is also how a test pins `Disabled` for a
    /// *signed-in* identity, which `probing` itself never does (a signed-in
    /// seed always starts at `Unknown`; see this module's header) — a
    /// signed-out `probing` reaches `Disabled` too, but only by way of
    /// constructing an `AuthCtx` a test may not otherwise need. `DayView`'s
    /// and `WeekView`'s mount-gate tests need exactly this to prove those
    /// components actually branch on `EncryptionState`, not merely that the
    /// states exist, and `storage::hook`'s reload test needs it to drive a
    /// transition.
    ///
    /// `ssr` as well as `test`: the mount-gate call sites render with
    /// `.to_html()`, which needs `leptos`'s `ssr` feature, so this has no
    /// caller — and would be dead code — under a bare
    /// `cargo test --no-default-features`.
    #[cfg(all(test, feature = "ssr"))]
    pub(crate) fn for_state(state: EncryptionState) -> Self {
        let ctx = Self {
            state: state_signal(EncryptionState::Unknown),
            keys: StoredValue::new(0),
            #[cfg(feature = "hydrate")]
            auth: AuthCtx {
                user: RwSignal::new(None),
            },
            generation: StoredValue::new(Generation::default()),
            reprobed: StoredValue::new(false),
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

    /// Whether a save made right now would be stored, tracked.
    ///
    /// Tracked because the answer changes under the user: the probe
    /// resolving is what turns a page that cannot save into one that can —
    /// or into one that has to be set up first — with no other event to
    /// redraw on. The backend is taken rather than read back out of
    /// `AuthCtx`, both because this context does not hold one off the
    /// browser and for the reason [`EncryptionState::writes`] gives.
    pub fn writes(self, backend: Backend) -> Writes {
        self.state.get().writes(backend)
    }

    /// Which key a read would use, tracked — the narrow dependency the
    /// storage load subscribes to instead of [`state`](Self::state).
    ///
    /// See [`KeyIdentity`] for why the load must not track the state's
    /// shape, and [`identity_of`] for why the decision itself lives outside
    /// this method.
    pub fn key_identity(self) -> KeyIdentity {
        identity_of(
            self.state.get().key().is_some(),
            self.keys.try_get_value().unwrap_or_default(),
        )
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
        // An unlock is a newer answer than any probe already in flight, and
        // it is also something `lock` and `signing_out` must be able to
        // outrank — so it takes a token like everything else that publishes.
        let token = self.begin_probe();
        // Published *before* the keystore write, and this is invariant E7's
        // second half rather than a nicety. The enable ceremony reaches here
        // with the account already encrypted server-side while this context
        // still says `Disabled`, whose write key is `Plaintext`; the await
        // below yields to the event loop, and the event loop is where clicks
        // come from. `Locked` is the strictly safe answer for that window —
        // it refuses writes rather than downgrading one — and it is a no-op
        // on every other unlock path, which is already `Locked`.
        //
        // It goes *after* the identity check above, not before, so a key for
        // an account that has already signed out still publishes nothing at
        // all.
        self.publish(EncryptionState::Locked);
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
        // "Lock now" and sign-out both bump the counter, and `Forgets`
        // already stopped `remember` writing anything durable. Without this
        // the in-memory half would go through anyway: the user would press
        // "Lock now" mid-ceremony, watch it take, and find the session
        // unlocked again a moment later with nothing on the device to
        // explain it.
        if !self.may_publish(token) {
            error!("this device was asked to forget its key while an unlock was in flight");
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
    /// pressed this cannot write its key back afterwards. The counter is
    /// bumped for the same reason one step further out: a probe that read
    /// the keystore *before* the clear is still holding a key, and without
    /// this it would land afterwards and publish `Unlocked` straight over
    /// the `Locked` the user just asked for.
    #[cfg(feature = "hydrate")]
    pub async fn lock(self) -> Result<(), crate::crypto::subtle::CryptoError> {
        let _ = self.begin_probe();
        self.publish(EncryptionState::Locked);
        crate::crypto::forget_device_key().await
    }
}

/// What a status answer means for the tab that asked, before this device's
/// keystore is consulted.
#[cfg(any(feature = "hydrate", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeAnswer {
    /// The answer is about somebody else's account, so it settles nothing
    /// about this one.
    WrongAccount,
    /// The account this tab is showing has no encryption.
    NotEncrypted,
    /// Encrypted, and this tab's. Whether it reads as locked or unlocked is
    /// then up to the keystore.
    NeedsKey,
}

/// Whether a status answer is about the account the tab asked for, and what
/// it says if it is.
///
/// The probe's two reads ask two different sources about `user`, and the
/// first answers for whoever the *session cookie* names rather than for
/// `user` itself. Those are the same account right up until a second tab
/// signs in as somebody else, at which point this tab's cookie changes
/// underneath it and nothing re-runs the probe to notice. Publishing a
/// conclusion drawn from one account's row while the keystore is read under
/// another's is how one account's key comes to seal the other's entries.
///
/// The account is checked **first**, before `enabled` is even looked at, and
/// that ordering is the point: the dangerous answer is a `WrongAccount` read
/// as [`ProbeAnswer::NotEncrypted`], because that one writes plaintext into
/// an account nobody here has established anything about.
///
/// A free function rather than three lines inside [`probe`] because `probe`
/// is `hydrate`-only and reaches a server function: this is the whole of the
/// decision, and the only part of it a host test can drive. The two failure
/// directions are not alike — an always-mismatch bug is loud, since every
/// signed-in visitor goes permanently `Unreachable`, while a never-mismatch
/// bug is silent and restores the defect this exists to prevent.
#[cfg(any(feature = "hydrate", test))]
fn probe_answer(status: &EncryptionStatus, user: &str) -> ProbeAnswer {
    if status.account != user {
        ProbeAnswer::WrongAccount
    } else if status.enabled {
        ProbeAnswer::NeedsKey
    } else {
        ProbeAnswer::NotEncrypted
    }
}

/// The two reads behind the probe, in the order that avoids the second one
/// whenever the first already settles the answer. See [`probe_answer`] for
/// why the first is checked against the account it was asked about.
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
    match probe_answer(&status, user) {
        ProbeAnswer::WrongAccount => {
            // Not `Disabled` and not `Locked`: neither is a fact about the
            // account this tab is showing, and one of them writes plaintext.
            // `Unreachable` says what is true — nothing was learned about
            // *this* account — and refuses every write until something is.
            // The retry it offers will keep landing here for as long as the
            // cookie disagrees, which is the honest outcome: a tab whose
            // session has been replaced needs a reload, not a spinner.
            error!("this tab's session now belongs to another account; refusing to answer for it");
            EncryptionState::Unreachable
        }
        ProbeAnswer::NotEncrypted => EncryptionState::Disabled,
        ProbeAnswer::NeedsKey => match SessionKey::restore(user).await {
            Ok(Some(key)) => EncryptionState::Unlocked(key),
            Ok(None) => EncryptionState::Locked,
            Err(err) => {
                // A keystore that could not be opened is `Locked`, exactly
                // like an empty one: the user still has their passkey and
                // their encryption key, and an unlock prompt is what gets
                // them back in (`crypto::keystore`'s point 2).
                error!("could not read this device's key store: {err}");
                EncryptionState::Locked
            }
        },
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
    /// absent from this build entirely.
    #[test]
    fn a_signed_in_context_starts_unknown_and_refuses_writes() {
        let owner = Owner::new();
        owner.with(|| {
            let auth = AuthCtx {
                user: RwSignal::new(Some("alice@example.com".to_string())),
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

    /// The seed this round adds, at the unit level below `app`'s SSR tests:
    /// a signed-out visitor uses `Backend::Local`, which is never encrypted
    /// (spec 1.2), so nothing about their session needs the probe to
    /// answer. Starting them at `Unknown` instead bought a read-only
    /// textarea for as long as wasm took to load, on the app's main page,
    /// for a visitor who was never at risk — see this module's header.
    #[test]
    fn a_signed_out_context_starts_disabled_and_accepts_writes() {
        let owner = Owner::new();
        owner.with(|| {
            let auth = AuthCtx {
                user: RwSignal::new(None),
            };
            let ctx = EncryptionCtx::probing(auth);
            assert!(matches!(ctx.state(), EncryptionState::Disabled));
            assert!(matches!(
                ctx.state_untracked().write_key(),
                WriteKey::Plaintext
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

    /// A session that cannot seal is refused on *either* backend, which is
    /// the ordering `crate::storage::write_target` also uses: it returns
    /// `Locked` before it so much as looks at where the write was going.
    ///
    /// This asserts about `writes` alone and claims no more than that. The
    /// agreement between what the view offers and what the seam accepts is
    /// pinned by `storage`'s
    /// `the_gate_and_the_seam_agree_on_every_state_a_host_can_build`, which
    /// is the only test that calls both.
    ///
    /// `Unlocked` is absent because it needs a `SessionKey`, uninhabited on
    /// the host; its arm is the one `write_key` and `writes` share by
    /// construction, since the second reads the first.
    #[test]
    fn a_session_that_cannot_seal_is_refused_on_either_backend() {
        for backend in [Backend::Local, Backend::Remote] {
            for state in [
                EncryptionState::Unknown,
                EncryptionState::Unreachable,
                EncryptionState::Locked,
            ] {
                assert_eq!(state.writes(backend), Writes::Refused);
            }
        }
    }

    /// The half spec section 4.1 turns on, and the reason `writes` takes a
    /// backend at all: `Disabled` is the ordinary working state of a
    /// signed-out visitor and a hard stop for a signed-in one, and nothing
    /// about the state alone tells the two apart.
    ///
    /// Both directions are asserted because both failures are silent and
    /// opposite. Answering `Accepted` on `Remote` restores the defect the
    /// gate exists to prevent — a box that takes keystrokes the server then
    /// drops, since the account cannot legally hold a row (invariant E9).
    /// Answering `SetupRequired` on `Local` locks every signed-out visitor
    /// out of the app's main page, and out of the very mode the gate's
    /// escape hatch falls back to.
    #[test]
    fn the_same_state_saves_locally_and_needs_setup_on_the_server() {
        assert_eq!(
            EncryptionState::Disabled.writes(Backend::Local),
            Writes::Accepted,
            "`localStorage` is never encrypted, so there is nothing to set up"
        );
        assert_eq!(
            EncryptionState::Disabled.writes(Backend::Remote),
            Writes::SetupRequired,
            "the server stores nothing for an account without encryption, so \
             the user has to be sent somewhere rather than merely refused"
        );
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

    /// The branch that keeps a long-lived tab honest, at the level the host
    /// can reach — which is the decision itself, driven through the same
    /// function the browser consults.
    ///
    /// `Disabled` is the state a tab holds when encryption was switched on
    /// somewhere else after it loaded, and it is the dangerous one: it
    /// writes plaintext and mounts an editable box. A sealed row proves it
    /// wrong — only an encrypted account can hold one — and the state has to
    /// move on that evidence, because nothing else will: the probe re-runs
    /// on an `AuthCtx::user` change and there is no such change here.
    ///
    /// Parking at `Locked` rather than `Unknown` is asserted too, and it is
    /// half the fix: `Unknown` would throw the row's proof away for the
    /// width of a round trip, which is exactly long enough to leave the
    /// editable box on screen.
    ///
    /// **What this does not cover:** that anything *acts* on the answer.
    /// [`EncryptionCtx::reprobe`] and the `start_probe` it calls are
    /// `hydrate`-only and no host test reaches either, so a change that kept
    /// this decision and stopped consulting it would pass here. There is no
    /// wasm test runner in this project; the smoke list (spec §10, items 8
    /// and 9) is that half's only guard.
    #[test]
    fn a_sealed_row_contradicts_only_the_state_that_writes_plaintext() {
        assert!(
            matches!(
                contradicted_by(UnreadableRow::Sealed, &EncryptionState::Disabled),
                Some(EncryptionState::Locked)
            ),
            "a sealed row must not leave a session writing plaintext, and the row has \
             already proved the account is encrypted"
        );

        // `Unknown` already has a probe on the way to the same answer,
        // `Locked` is the answer, and `Unreachable` is a conclusion the user
        // was told about and offered a retry for — re-probing behind their
        // back would trade a truthful state for a spinner.
        for state in [
            EncryptionState::Unknown,
            EncryptionState::Unreachable,
            EncryptionState::Locked,
        ] {
            assert!(
                contradicted_by(UnreadableRow::Sealed, &state).is_none(),
                "a state that already refuses writes must not be re-probed"
            );
        }
    }

    /// The sibling row, and the arm that closes the *sign-in* half of the
    /// same staleness: a row that would not open contradicts a session
    /// holding a key, and nothing else.
    ///
    /// Only the keyless half is assertable here. `Unlocked` needs a
    /// `SessionKey`, uninhabited off the browser, so this cannot drive
    /// `contradicted_by`'s positive answer and would pass against an
    /// implementation that returned `None` for every state — the same limit
    /// [`identity_of`] exists to work around, and it has no equivalent here
    /// because the states themselves are what differ. What it does pin is
    /// the half that could spend the page load's one re-probe for nothing,
    /// and the parking state: `Unknown`, not `Locked`, because this row has
    /// proved nothing about the account and may simply be damaged.
    #[test]
    fn a_row_that_will_not_open_contradicts_only_a_session_holding_a_key() {
        for state in [
            EncryptionState::Unknown,
            EncryptionState::Unreachable,
            EncryptionState::Disabled,
            EncryptionState::Locked,
        ] {
            assert!(
                contradicted_by(UnreadableRow::Unopenable, &state).is_none(),
                "a session with no key cannot have failed to open a row with one"
            );
        }
        assert!(
            UnreadableRow::Unopenable.latched(),
            "the ambiguous row is the latched one; the sealed row proves what it says"
        );
        assert!(!UnreadableRow::Sealed.latched());
    }

    /// The latch, which is the whole reason acting on an ambiguous row is
    /// safe rather than a loop.
    ///
    /// A row that will not open is usually just damaged, and a probe
    /// answering for the same account republishes `Unlocked` — a new
    /// `KeyIdentity`, which re-runs the load, which fails the same way. One
    /// probe per page load ends that by construction, not by timing, and one
    /// is enough: staleness is a property of the page load.
    #[cfg(feature = "ssr")]
    #[test]
    fn the_re_probe_an_ambiguous_row_asks_for_is_spent_once() {
        let owner = Owner::new();
        owner.with(|| {
            let ctx = EncryptionCtx::for_state(EncryptionState::Unknown);
            assert!(
                ctx.claim_reprobe(),
                "the first ambiguous row gets the probe"
            );
            for _ in 0..3 {
                assert!(
                    !ctx.claim_reprobe(),
                    "a second probe is what turns a corrupt row into a loop"
                );
            }
        });
        owner.cleanup();
    }

    /// The check that makes the re-probe above *safe* rather than merely
    /// bounded: a tab whose cookie has been replaced must not believe the
    /// answer it gets back.
    ///
    /// The account is compared before `enabled` is read, and that ordering
    /// is the assertion below with `enabled: false`. Reading it the other
    /// way round would let another account's unencrypted status publish
    /// `Disabled` here — `WriteKey::Plaintext` — which is precisely how one
    /// account's session comes to write into another's day.
    #[test]
    fn only_the_account_this_tab_is_showing_may_answer_for_it() {
        let status = |account: &str, enabled| EncryptionStatus {
            account: account.to_string(),
            enabled,
        };

        assert_eq!(
            probe_answer(&status("bob@example.com", true), "alice@example.com"),
            ProbeAnswer::WrongAccount
        );
        assert_eq!(
            probe_answer(&status("bob@example.com", false), "alice@example.com"),
            ProbeAnswer::WrongAccount,
            "another account's 'no encryption' must never become this account's"
        );

        assert_eq!(
            probe_answer(&status("alice@example.com", true), "alice@example.com"),
            ProbeAnswer::NeedsKey
        );
        assert_eq!(
            probe_answer(&status("alice@example.com", false), "alice@example.com"),
            ProbeAnswer::NotEncrypted
        );
    }

    /// The narrowing A1 turns on, driven both ways — which is the whole
    /// reason [`identity_of`] exists as a function rather than as three
    /// match arms inside `key_identity`. Walking only the keyless states
    /// would pass against an implementation that returned `NoKey` for
    /// everything, and that implementation is the failure this guards.
    ///
    /// Each assertion is one half of the `Memo`'s job. Collapsing the
    /// keyless states is what stops the probe resolving from restarting the
    /// load — the restart that blanked a keystroke made while the probe was
    /// still running (`storage::hook` pins that end of it). Telling two keys
    /// apart is what makes an unlock re-run the load at all; without it a
    /// user who had just unlocked would keep seeing an empty day.
    #[test]
    fn a_key_reads_as_a_new_identity_and_a_keyless_state_never_does() {
        assert_eq!(identity_of(false, 0), KeyIdentity::NoKey);
        assert_eq!(
            identity_of(false, 7),
            KeyIdentity::NoKey,
            "the counter must not leak into a state that holds no key"
        );
        assert_eq!(identity_of(true, 1), KeyIdentity::Key(1));
        assert_ne!(
            identity_of(true, 1),
            identity_of(true, 2),
            "two unlocks must read as two keys, or the load that would reveal the second \
             never re-runs"
        );
    }

    /// The half of the same decision that `key_identity` itself owns: that
    /// `has_key` is read out of [`EncryptionState::key`] and not out of some
    /// other predicate. An implementation that asked
    /// `!matches!(state, Disabled)` instead would fail this.
    ///
    /// **It cannot observe the arm its name is about.** `Unlocked` needs a
    /// `SessionKey`, uninhabited off the browser, so the four states walked
    /// below are four that `key()` has no way to tell apart: this passes
    /// against any implementation that answers `NoKey` for a keyless state,
    /// which is every implementation that reads the key at all. The arm that
    /// tells two keys apart — the one the `Memo` narrowing actually risks —
    /// is driven through `identity_of` above, and the counter's own
    /// increment in `publish` has no host test either and is guarded by
    /// reading.
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
