//! The Leptos-facing half of the storage seam.
//!
//! # The hydration contract (spec section 5 of the migration design)
//!
//! The server and the client's *first* render must produce identical DOM.
//! Neither `localStorage` nor a server round trip is available during that
//! render, so the value starts as `None` on **both** targets and is filled
//! in by an `Effect`, which runs only after hydration has matched.
//!
//! | Value          | Meaning                     | Renders as            |
//! |----------------|-----------------------------|-----------------------|
//! | `None`         | Not yet read from storage   | Blank                 |
//! | `Some("")`     | Loaded; nothing saved       | The empty-state text  |
//! | `Some(text)`   | Loaded with data            | The parsed summary    |
//!
//! Collapsing the first two makes the server assert an empty state it cannot
//! know, and returning users see "No projects found" flash before their data
//! appears.
//!
//! # Why the arguments are signals
//!
//! Both the day being viewed and the backend change *during* a session — the
//! day when the user picks a date, the backend when they sign in. Re-running
//! the load is therefore normal operation, not a corner case, which brings
//! two obligations the single-shot version did not have: reset to `None`
//! first (so the previous day's text never appears under the new day's
//! heading), and discard stale in-flight loads (below).

use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;

use super::{Backend, Generation, StorageError, StorageKey, load, store};
use crate::encryption_ctx::{EncryptionCtx, EncryptionState, KeyIdentity, Writes};

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
    /// Whether this account's bodies are sealed, and with what.
    encryption: EncryptionCtx,
    /// Shared with the loading effect, so a write can invalidate a read.
    /// See [`begin_operation`].
    generation: StoredValue<Generation>,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
    }

    /// Whether a [`set`](Self::set) made right now would be stored.
    ///
    /// Asked of the same object the save goes through, deliberately: an
    /// editor that reads the session from anywhere else can come to invite a
    /// keystroke this `Persistent` then refuses, and the refusal is silent
    /// (see [`Writes`]).
    pub fn writes(self) -> Writes {
        self.encryption.writes()
    }

    /// Updates the value and writes it through to storage.
    pub fn set(self, value: String) {
        // Load-bearing, and easy to mistake for read-path bookkeeping: the
        // effect below blanks the value and starts a load, and the textarea
        // stays editable for the whole of that window — a microtask on
        // `Local`, a network round trip on `Remote`, reopened on every date
        // change and on sign-in and sign-out. A keystroke landing in that
        // window is a *newer* truth than the load, so the load must be
        // invalidated here. Without this bump the load resolves, still
        // passes its `is_current` check, and silently replaces what the user
        // typed — with the save already on disk, leaving screen and store
        // disagreeing.
        begin_operation(self.generation);
        self.set_value.set(Some(value.clone()));
        // A write must use the day, backend and session current *right
        // now*, not subscribe to their future changes — reading them
        // untracked keeps this call from becoming a reactive dependency of
        // its own effect.
        let key = self.key.get_untracked();
        let backend = self.backend.get_untracked();
        let session = self.encryption.state_untracked();
        spawn_local(async move {
            // A failed write must not break the UI — the in-memory value
            // stands — but it must not be silent either: Safari private
            // browsing and a quota-exceeded `setItem` both throw, a session
            // that cannot seal refuses outright rather than storing the body
            // in the clear, and the user would otherwise lose data with
            // nothing to explain why.
            if let Err(err) = store(backend, key, &value, session.write_key()).await {
                error!("failed to persist value for {key:?}: {err}");
            }
        });
    }

    /// Resets to the empty (but loaded) state.
    pub fn clear(self) {
        self.set(String::new());
    }
}

/// What a finished read leaves the day showing.
///
/// Two outcomes rather than a `String`, because one read failure must not
/// be shown as "nothing saved": see [`loaded_value`].
#[derive(Debug, PartialEq, Eq)]
enum Loaded {
    /// The text to publish — found, genuinely empty, or a failure it is safe
    /// to render as empty.
    Value(String),
    /// The row is sealed and this session holds no key for it. There is
    /// content here and the user cannot be shown it.
    Sealed,
}

/// Collapses a storage read into the loaded state.
///
/// Both "nothing stored" and "the read failed" become loaded-and-empty:
/// leaving the value unloaded on error would strand the UI blank forever.
/// A read failure is still logged first, so a corrupt value does not
/// silently masquerade as "nothing saved".
///
/// [`StorageError::Locked`] is the one failure that must not take that
/// route, and the reason is what happens *next*. It means the row holds real
/// ciphertext, so rendering it as "nothing saved" hands the user an empty
/// box over a day that has content in it — and if the session believes the
/// account is unencrypted, that box is editable and the next keystroke
/// replaces the ciphertext with a plaintext row. The content is then gone,
/// with the user having been shown nothing to suggest there was any. Every
/// other error leaves the stored row exactly where it is.
///
/// The mount gate in `DayView` normally makes this unreachable, but it keys
/// off the session state while the evidence is in the row: when the state is
/// stale the gate does not fire, which is precisely when this matters (see
/// [`EncryptionCtx::sealed_row_seen`]).
fn loaded_value(read: Result<Option<String>, StorageError>) -> Loaded {
    match read {
        Ok(value) => Loaded::Value(value.unwrap_or_default()),
        Err(StorageError::Locked { key }) => {
            error!("`{key}` is sealed and this session holds no key for it");
            Loaded::Sealed
        }
        Err(err) => {
            error!("failed to load persisted value, treating as empty: {err}");
            Loaded::Value(String::new())
        }
    }
}

/// Starts a new storage operation, invalidating any load still in flight,
/// and returns its token.
///
/// Every path that changes what the stored value *should* be goes through
/// here — the read path in [`use_persistent`]'s effect, and the write path in
/// [`Persistent::set`]. Only a token still current when its load resolves may
/// publish.
///
/// `try_update_value` rather than the panicking default: this `StoredValue`
/// belongs to the same owner as the effect, but a spawned load can still be
/// resolving after that owner (and therefore this value) is disposed, e.g. on
/// navigation away. A fallback of 0 is never issued by [`Generation::next`],
/// so it can never read as current — the disposed case degrades to "discard
/// the load" rather than panicking.
fn begin_operation(generation: StoredValue<Generation>) -> u64 {
    generation
        .try_update_value(Generation::next)
        .unwrap_or_default()
}

/// Which key the load would use, as a `Memo` so that a change in the
/// session's *shape* which leaves the key alone notifies nobody.
///
/// The load has to re-run when the key changes — an unlock is what turns a
/// sealed row into readable text — and must not re-run when anything else
/// about the session does. Tracking the whole state made the probe resolving
/// (`Unknown` to `Disabled`, say) restart the load, and a restart blanks the
/// value and republishes whatever storage holds: a keystroke made during the
/// probe window, which the same window refused to save, was reverted on
/// screen in front of the user. `Memo` is what turns "the state changed" into
/// "the key changed" — see [`KeyIdentity`].
///
/// `pub(crate)` because `week_view`'s range load wants the same narrowing
/// for the same reason, one signal wider: nothing about one keyless state
/// becoming another changes what either read would return.
pub(crate) fn session_identity(encryption: EncryptionCtx) -> Memo<KeyIdentity> {
    Memo::new(move |_| encryption.key_identity())
}

/// Reads the load's three inputs with exactly the reactive dependencies the
/// load should have.
///
/// The session itself is read *untracked*: `identity` is the only
/// session-shaped thing this subscribes to, and it has already decided
/// whether this load should happen at all. Reading [`EncryptionCtx::state`]
/// here instead is the bug [`session_identity`] describes, so the two reads
/// live together where the difference is visible.
fn load_inputs(
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
    encryption: EncryptionCtx,
    identity: Memo<KeyIdentity>,
) -> (StorageKey, Backend, EncryptionState) {
    identity.track();
    (key.get(), backend.get(), encryption.state_untracked())
}

/// Reads `key` from `backend`, re-reading whenever either changes.
///
/// The session comes from context rather than an argument, because unlike
/// the day and the backend it is one fact about the whole page: every reader
/// and writer in the tree wants the same answer, and threading it would just
/// push this `use_context` into each of them.
pub fn use_persistent(key: Signal<StorageKey>, backend: Signal<Backend>) -> Persistent {
    // Identical on server and client, which is what makes hydration match.
    let (value, set_value) = signal::<Option<String>>(None);
    let encryption = use_context::<EncryptionCtx>().expect("EncryptionCtx provided by App");
    let generation = StoredValue::new(Generation::default());

    let identity = session_identity(encryption);

    // `Effect::new` never runs during SSR, and on the client it runs after
    // the first render — so the DOM has already been matched by the time
    // this can change anything.
    Effect::new(move |_| {
        let (key, backend, session) = load_inputs(key, backend, encryption, identity);
        let token = begin_operation(generation);

        // Back to "not loaded" before the new read starts. Without this the
        // previous day's text stays on screen under the new day's heading
        // until the load resolves (invariant I2).
        set_value.set(None);

        spawn_local(async move {
            let loaded = loaded_value(load(backend, key, session.key()).await);
            // Discard if a newer load started while this one was in flight,
            // or if this component has since been unmounted.
            let is_current = generation
                .try_with_value(|g| g.is_current(token))
                .unwrap_or(false);
            if !is_current {
                return;
            }
            match loaded {
                Loaded::Value(value) => set_value.set(Some(value)),
                // Left unloaded — blank, not "nothing saved" — and reported
                // to the context, which is the only thing that can correct
                // a session state the row has just contradicted. Once it
                // does, the gate above swaps this day for the unlock
                // prompt, and an unlock re-runs this load with a key.
                Loaded::Sealed => encryption.sealed_row_seen(),
            }
        });
    });

    Persistent {
        value,
        set_value,
        key,
        backend,
        encryption,
        generation,
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::*;

    fn date(day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, day).expect("valid date")
    }

    /// A `Persistent` wired the way [`use_persistent`] wires one, minus the
    /// `Effect` — which never runs under `ssr` anyway (see this module's
    /// header), so there is nothing to drive it with here. Everything the
    /// write path touches is real.
    ///
    /// Its `EncryptionCtx` is pinned at `Unknown` via `for_state` rather
    /// than built through `probing`, so it stays a refusal regardless of how
    /// `probing` seeds a signed-out identity (`encryption_ctx`'s header) —
    /// what these tests exercise is the bookkeeping `set` does *before*
    /// spawning, and nothing polls the spawned future.
    fn persistent(generation: StoredValue<Generation>) -> Persistent {
        let (value, set_value) = signal::<Option<String>>(None);
        let date = date(4);
        Persistent {
            value,
            set_value,
            key: Signal::stored(StorageKey::TimeEntry(date)),
            backend: Signal::stored(Backend::Local),
            encryption: EncryptionCtx::for_state(EncryptionState::Unknown),
            generation,
        }
    }

    /// `Persistent::set` is spawned into the same thread-local pool
    /// `spawn_local` uses in the browser. Nothing polls it here, and nothing
    /// needs to — the write's *store* is a no-op under `ssr`; what this
    /// module tests is the bookkeeping `set` does before spawning. Without an
    /// executor installed, `spawn_local` panics in a debug build.
    fn with_executor() {
        let _ = any_spawner::Executor::init_futures_executor();
    }

    /// The regression this guards against: a keystroke landing while a load
    /// is in flight must invalidate that load. Both are async, the textarea
    /// is editable throughout, and on `Remote` the window is a whole network
    /// round trip — so a load that stays current outlives the newer truth
    /// the user just typed and silently overwrites it on screen, while the
    /// save it raced has already reached the store.
    #[test]
    fn a_write_invalidates_a_load_already_in_flight() {
        with_executor();
        let owner = Owner::new();
        owner.with(|| {
            let generation = StoredValue::new(Generation::default());
            // The effect starts a load and holds its token across the await.
            let in_flight = begin_operation(generation);
            assert!(
                generation
                    .try_with_value(|g| g.is_current(in_flight))
                    .unwrap_or(false),
                "the load is the newest operation until something else starts"
            );

            persistent(generation).set("typed while loading".to_string());

            assert!(
                !generation
                    .try_with_value(|g| g.is_current(in_flight))
                    .unwrap_or(true),
                "the load must be discarded rather than overwrite the keystroke"
            );
        });
        owner.cleanup();
    }

    /// The regression this guards against: the probe resolving must not
    /// restart the load. A restart blanks the value and republishes what
    /// storage holds, so anything typed since the load began — while the
    /// textarea was editable and the probe still in flight — is wiped off
    /// the screen, and the write that raced it was refused for being made
    /// before the account's encryption was known. Nothing about one keyless
    /// state becoming another changes what the load would read.
    ///
    /// A `Memo` stands in for the effect: `Effect::new` never runs under
    /// `ssr` (this module's header), while a memo recomputes on exactly the
    /// dependency changes an effect would re-run on.
    #[test]
    fn a_session_change_that_keeps_the_key_does_not_reload() {
        let owner = Owner::new();
        owner.with(|| {
            let encryption = EncryptionCtx::for_state(EncryptionState::Unknown);
            let identity = session_identity(encryption);
            let day = RwSignal::new(StorageKey::TimeEntry(date(4)));
            let key: Signal<StorageKey> = day.into();
            let backend = Signal::stored(Backend::Local);
            let loads = StoredValue::new(0usize);
            let load = Memo::new(move |_| {
                load_inputs(key, backend, encryption, identity);
                loads.update_value(|n| *n += 1);
            });

            load.get();
            assert_eq!(loads.get_value(), 1, "the first render loads");

            encryption.set_for_test(EncryptionState::Disabled);
            load.get();
            assert_eq!(
                loads.get_value(),
                1,
                "the probe resolving must not restart the load"
            );

            // The complement, and the reason this is a narrowing rather than
            // a removal: the load must still re-run for the reasons it
            // always did.
            day.set(StorageKey::TimeEntry(date(5)));
            load.get();
            assert_eq!(loads.get_value(), 2, "a new day must still reload");
        });
        owner.cleanup();
    }

    #[test]
    fn found_value_is_loaded_as_is() {
        assert_eq!(
            loaded_value(Ok(Some("saved".to_string()))),
            Loaded::Value("saved".to_string())
        );
    }

    #[test]
    fn nothing_stored_becomes_loaded_and_empty() {
        assert_eq!(loaded_value(Ok(None)), Loaded::Value(String::new()));
    }

    #[test]
    fn read_failure_becomes_loaded_and_empty() {
        assert_eq!(
            loaded_value(Err(StorageError::Unavailable)),
            Loaded::Value(String::new())
        );
    }

    /// The one read failure that must not be shown as "nothing saved", and
    /// the only data-destroying path either half of this seam has.
    ///
    /// A sealed row means the day *has* content. Collapsing it to an empty
    /// string renders "No projects found" over real ciphertext, and — on a
    /// session that still believes the account is unencrypted, which is what
    /// a tab left open across an enable elsewhere believes — hands the user
    /// an editable box whose first keystroke replaces that ciphertext with a
    /// plaintext row. Nothing downstream would flag it: a v1 row is exactly
    /// what an un-migrated account legitimately holds.
    ///
    /// Asserted against the empty value specifically, not merely "not the
    /// text", because empty is the answer that does the damage.
    #[test]
    fn a_sealed_row_is_never_shown_as_nothing_saved() {
        let sealed = loaded_value(Err(StorageError::Locked {
            key: StorageKey::TimeEntry(date(4)).as_key(),
        }));
        assert_eq!(
            sealed,
            Loaded::Sealed,
            "a row this session cannot open must not read as an empty day"
        );
    }

    // `Generation`'s own behaviour (a stale load is discarded, a single
    // load is always current) is pinned once in `storage::tests`, where the
    // type now lives — it is shared with `week_view`'s range load. A local
    // `an_unraced_load_still_publishes` used to restate the second of those
    // here; it called `begin_operation` and asserted the token was current,
    // touching neither the read path nor `Persistent`, so it was a verbatim
    // duplicate of `storage::a_single_load_is_always_current` wearing this
    // module's name.
}
