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

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
    /// Shared with the loading effect, so a write can invalidate a read.
    /// See [`begin_operation`].
    generation: StoredValue<Generation>,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
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
        // A write must use the day and backend current *right now*, not
        // subscribe to their future changes — reading them untracked keeps
        // this call from becoming a reactive dependency of its own effect.
        let key = self.key.get_untracked();
        let backend = self.backend.get_untracked();
        spawn_local(async move {
            // A failed write must not break the UI — the in-memory value
            // stands — but it must not be silent either: Safari private
            // browsing and a quota-exceeded `setItem` both throw, and the
            // user would otherwise lose data with nothing to explain why.
            if let Err(err) = store(backend, key, &value).await {
                error!("failed to persist value for {key:?}: {err}");
            }
        });
    }

    /// Resets to the empty (but loaded) state.
    pub fn clear(self) {
        self.set(String::new());
    }
}

/// Collapses a storage read into the loaded state.
///
/// Both "nothing stored" and "the read failed" become loaded-and-empty:
/// leaving the value unloaded on error would strand the UI blank forever.
/// A read failure is still logged first, so a corrupt value does not
/// silently masquerade as "nothing saved".
fn loaded_value(read: Result<Option<String>, StorageError>) -> String {
    match read {
        Ok(value) => value.unwrap_or_default(),
        Err(err) => {
            error!("failed to load persisted value, treating as empty: {err}");
            String::new()
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

/// Reads `key` from `backend`, re-reading whenever either changes.
pub fn use_persistent(key: Signal<StorageKey>, backend: Signal<Backend>) -> Persistent {
    // Identical on server and client, which is what makes hydration match.
    let (value, set_value) = signal::<Option<String>>(None);
    let generation = StoredValue::new(Generation::default());

    // `Effect::new` never runs during SSR, and on the client it runs after
    // the first render — so the DOM has already been matched by the time
    // this can change anything.
    Effect::new(move |_| {
        let key = key.get();
        let backend = backend.get();
        let token = begin_operation(generation);

        // Back to "not loaded" before the new read starts. Without this the
        // previous day's text stays on screen under the new day's heading
        // until the load resolves (invariant I2).
        set_value.set(None);

        spawn_local(async move {
            let loaded = loaded_value(load(backend, key).await);
            // Discard if a newer load started while this one was in flight,
            // or if this component has since been unmounted.
            let is_current = generation
                .try_with_value(|g| g.is_current(token))
                .unwrap_or(false);
            if is_current {
                set_value.set(Some(loaded));
            }
        });
    });

    Persistent {
        value,
        set_value,
        key,
        backend,
        generation,
    }
}

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::*;

    /// A `Persistent` wired the way [`use_persistent`] wires one, minus the
    /// `Effect` — which never runs under `ssr` anyway (see this module's
    /// header), so there is nothing to drive it with here. Everything the
    /// write path touches is real.
    fn persistent(generation: StoredValue<Generation>) -> Persistent {
        let (value, set_value) = signal::<Option<String>>(None);
        let date = NaiveDate::from_ymd_opt(2026, 9, 4).expect("valid date");
        Persistent {
            value,
            set_value,
            key: Signal::stored(StorageKey::TimeEntry(date)),
            backend: Signal::stored(Backend::Local),
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

    /// The complement: with no write racing it, a load still publishes.
    /// Bumping the generation unconditionally somewhere on the read path
    /// would discard every load and leave the UI blank forever.
    #[test]
    fn an_unraced_load_still_publishes() {
        let owner = Owner::new();
        owner.with(|| {
            let generation = StoredValue::new(Generation::default());
            let in_flight = begin_operation(generation);
            assert!(
                generation
                    .try_with_value(|g| g.is_current(in_flight))
                    .unwrap_or(false)
            );
        });
        owner.cleanup();
    }

    #[test]
    fn found_value_is_loaded_as_is() {
        assert_eq!(loaded_value(Ok(Some("saved".to_string()))), "saved");
    }

    #[test]
    fn nothing_stored_becomes_loaded_and_empty() {
        assert_eq!(loaded_value(Ok(None)), "");
    }

    #[test]
    fn read_failure_becomes_loaded_and_empty() {
        assert_eq!(loaded_value(Err(StorageError::Unavailable)), "");
    }

    // `Generation`'s own behaviour (a stale load is discarded, a single
    // load is always current) is pinned once in `storage::tests`, where the
    // type now lives — it is shared with `week_view`'s range load.
}
