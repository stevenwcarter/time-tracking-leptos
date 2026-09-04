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

use super::{Backend, StorageError, StorageKey, load, store};

/// Monotonic counter identifying the newest in-flight load.
///
/// Loads are async and can overlap: changing the date twice quickly starts
/// two, and nothing guarantees they resolve in order. Only the newest may
/// publish its result. Purely internal to [`use_persistent`], so it stays
/// unexported.
#[derive(Debug, Default, Clone, Copy)]
struct Generation(u64);

impl Generation {
    /// Starts a new load, invalidating any earlier one, and returns its
    /// token. Tokens start at 1, so 0 is a safe "never current" sentinel.
    fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// Whether `token` identifies the newest load.
    fn is_current(&self, token: u64) -> bool {
        self.0 == token
    }
}

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: Signal<StorageKey>,
    backend: Signal<Backend>,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
    }

    /// Updates the value and writes it through to storage.
    pub fn set(self, value: String) {
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
        // `try_update_value` rather than the panicking default: this
        // `StoredValue` belongs to the same owner as the effect, but the
        // spawned load below can still be resolving after that owner (and
        // therefore this value) is disposed, e.g. on navigation away. A
        // fallback of 0 is never issued by `next`, so it can never read as
        // current — the disposed case degrades to "discard the load".
        let token = generation
            .try_update_value(Generation::next)
            .unwrap_or_default();

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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Pins invariant I2. Two loads are in flight; the *older* one resolves
    /// last. Without a generation guard it would overwrite the newer day's
    /// value, showing the wrong date's text with no indication anything is
    /// wrong.
    #[test]
    fn a_stale_load_does_not_overwrite_a_newer_one() {
        let mut generation = Generation::default();
        let first = generation.next();
        let second = generation.next();
        assert!(generation.is_current(second), "the newest load may write");
        assert!(
            !generation.is_current(first),
            "an older load must be discarded"
        );
    }

    #[test]
    fn a_single_load_is_always_current() {
        let mut generation = Generation::default();
        let only = generation.next();
        assert!(generation.is_current(only));
    }
}
