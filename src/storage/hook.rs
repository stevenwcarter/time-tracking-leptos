//! The Leptos-facing half of the storage seam.
//!
//! # The hydration contract (spec §5)
//!
//! The server and the client's *first* render must produce identical DOM.
//! `localStorage` does not exist on the server, so the value starts as `None`
//! on **both** targets and is only filled in by an `Effect`, which runs after
//! hydration has already matched the server's output.
//!
//! `None` and `Some(String::new())` are meaningfully different:
//!
//! | Value          | Meaning                     | Renders as            |
//! |----------------|-----------------------------|-----------------------|
//! | `None`         | Not yet read from storage   | Blank                 |
//! | `Some("")`     | Loaded; nothing saved       | The empty-state text  |
//! | `Some(text)`   | Loaded with data            | The parsed summary    |
//!
//! Collapsing those two cases makes the server assert an empty state it cannot
//! know, and returning users see a flash of "No projects found" before their
//! data appears.

use leptos::logging::error;
use leptos::prelude::*;
use leptos::task::spawn_local;

use super::{StorageError, StorageKey, load, store};

/// A value persisted across reloads, with the load state made explicit.
#[derive(Clone, Copy)]
pub struct Persistent {
    value: ReadSignal<Option<String>>,
    set_value: WriteSignal<Option<String>>,
    key: StorageKey,
}

impl Persistent {
    /// The current value, or `None` if storage has not been read yet.
    pub fn get(self) -> Option<String> {
        self.value.get()
    }

    /// Updates the value and writes it through to storage.
    pub fn set(self, value: String) {
        self.set_value.set(Some(value.clone()));
        let key = self.key;
        spawn_local(async move {
            // A failed write must not break the UI; the in-memory value stands.
            // But it must not be silent either — Safari private browsing and a
            // quota-exceeded `setItem` both throw, and the user would otherwise
            // lose data with nothing in the console to explain why.
            if let Err(err) = store(key, &value).await {
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
/// A read failure is still logged before being collapsed, so a corrupt
/// stored value doesn't silently masquerade as "nothing saved".
fn loaded_value(read: Result<Option<String>, StorageError>) -> String {
    match read {
        Ok(value) => value.unwrap_or_default(),
        Err(err) => {
            error!("failed to load persisted value, treating as empty: {err}");
            String::new()
        }
    }
}

/// Reads `key` from storage after hydration, exposing the tri-state above.
pub fn use_persistent(key: StorageKey) -> Persistent {
    // Identical on server and client, which is what makes hydration match.
    let (value, set_value) = signal::<Option<String>>(None);

    // `Effect::new` never runs during SSR, and on the client it runs *after*
    // the first render — so the DOM has already been matched by the time this
    // can change anything.
    Effect::new(move |_| {
        spawn_local(async move {
            set_value.set(Some(loaded_value(load(key).await)));
        });
    });

    Persistent {
        value,
        set_value,
        key,
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
}
