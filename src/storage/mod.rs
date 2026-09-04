//! Persistent storage seam.
//!
//! Components never touch this module directly — they use [`hook::use_persistent`].
//! The API is async even though today's only backend (`localStorage`) is
//! synchronous, so that swapping in server-backed encrypted storage later
//! changes nothing outside this directory. See spec §6.

pub mod codec;
pub mod hook;
#[cfg(feature = "hydrate")]
pub mod local;

use std::future::Future;

/// Identifies one stored document.
///
/// An enum rather than a free string so the planned multi-day-store work
/// extends this type instead of leaking stringly-typed keys through the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKey {
    TimeEntry,
}

impl StorageKey {
    /// The key as written to the underlying store. These strings are a
    /// compatibility surface: changing one orphans existing user data.
    pub fn as_str(self) -> &'static str {
        match self {
            StorageKey::TimeEntry => "time_entry",
        }
    }
}

/// Something went wrong reaching or interpreting the backing store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("browser storage is unavailable")]
    Unavailable,
    #[error("stored value for `{key}` could not be read: {source}")]
    Decode {
        key: &'static str,
        source: codec::DecodeError,
    },
    #[error("failed to write `{key}` to storage")]
    Write { key: &'static str },
}

/// Reads a stored value. `Ok(None)` means "nothing stored under this key".
///
/// Under `ssr` there is no browser storage, so this is always `Ok(None)`.
pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        local::load(key).await
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = key;
        Ok(None)
    }
}

/// Writes a value, replacing any previous one. A no-op under `ssr`.
///
/// Unlike `load`/`clear`, this is a plain fn that builds the future by hand:
/// `value` is copied into an owned `String` *before* the `async move` block.
/// That is load-bearing, not style — `Persistent::set` in `hook.rs` hands this
/// future to `spawn_local`, which requires `'static`. A plain
/// `async fn store(_, value: &str)` would instead capture the caller's
/// borrow, so the future could only live as long as `value`, failing that
/// bound. Do not "simplify" this to match its siblings.
pub fn store(key: StorageKey, value: &str) -> impl Future<Output = Result<(), StorageError>> {
    let value = value.to_owned();
    async move {
        #[cfg(feature = "hydrate")]
        {
            local::store(key, &value).await
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (key, value);
            Ok(())
        }
    }
}

/// Removes a stored value. A no-op under `ssr`.
pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    #[cfg(feature = "hydrate")]
    {
        local::clear(key).await
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = key;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_matches_dioxus_key() {
        // The Dioxus build called use_persistent("time_entry", ...). Changing
        // this string orphans every existing user's saved data.
        assert_eq!(StorageKey::TimeEntry.as_str(), "time_entry");
    }

    /// Pins invariant I1 from the spec: under `ssr` there is no browser
    /// storage, so `load` yields `None` and the server render starts unloaded.
    /// If this ever returns `Some`, the server would render content the
    /// client's first (hydrating) render cannot reproduce.
    #[test]
    fn ssr_backend_returns_none() {
        let loaded = futures_lite_block_on(load(StorageKey::TimeEntry));
        assert_eq!(loaded, Ok(None));
    }

    #[test]
    fn ssr_writes_are_noops() {
        assert_eq!(
            futures_lite_block_on(store(StorageKey::TimeEntry, "x")),
            Ok(())
        );
        assert_eq!(futures_lite_block_on(clear(StorageKey::TimeEntry)), Ok(()));
    }

    /// Minimal executor — these futures never yield under `ssr`, so polling
    /// once is sufficient and avoids pulling in a runtime just for tests.
    fn futures_lite_block_on<T>(fut: impl Future<Output = T>) -> T {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        match pin!(fut).poll(&mut Context::from_waker(waker)) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("ssr storage futures must complete immediately"),
        }
    }
}
