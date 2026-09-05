//! Persistent storage seam.
//!
//! A single day's value is read or written through [`hook::use_persistent`];
//! components should not call [`load`] or [`store`] directly. A *range* of
//! days ([`dates_with_entries`], [`bodies_in_range`]) has no per-day signal
//! to hang off of, so those are called directly (`week_view` is the only
//! caller today). Two things vary behind either path:
//!
//! - **Which day** is being read or written ([`StorageKey`]).
//! - **Where** it lives ([`Backend`]): `localStorage` when signed out, the
//!   server when signed in.
//!
//! Values cross this boundary as [`envelope`]-wrapped strings. Wrapping and
//! unwrapping happen *here*, not in the backends, so both store the same
//! shape and the pre-envelope legacy value can be normalized in one place.

pub mod codec;
pub mod envelope;
pub mod hook;
// `test` as well as `hydrate`: `local`'s decision logic (`resolve_load`,
// `should_clear_legacy`, `dates_from_keys`) is pure and host-tested, since
// there is no wasm test runner in this project. Only the `web_sys` calls
// inside `local` stay gated to `hydrate` alone.
#[cfg(any(feature = "hydrate", test))]
pub mod local;
#[cfg(feature = "hydrate")]
pub mod remote;

use std::future::Future;

use chrono::NaiveDate;

use crate::date::to_iso;

/// The key every pre-dated entry was stored under.
///
/// Load-bearing: this is where all existing users' data lives. `local.rs`
/// reads it as an alias for today until the first rewrite. Changing this
/// string orphans that data.
pub const LEGACY_KEY: &str = "time_entry";

/// Identifies one stored document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKey {
    TimeEntry(NaiveDate),
}

impl StorageKey {
    /// The key as written to the underlying store.
    ///
    /// `time_entry:YYYY-MM-DD`, which sorts chronologically as a string —
    /// that is what lets a `localStorage` key scan answer a date-range
    /// question without parsing every key.
    pub fn as_key(self) -> String {
        match self {
            StorageKey::TimeEntry(date) => format!("{LEGACY_KEY}:{}", to_iso(date)),
        }
    }

    /// The day this key addresses.
    pub fn date(self) -> NaiveDate {
        match self {
            StorageKey::TimeEntry(date) => date,
        }
    }
}

/// Where a value lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// The browser's `localStorage`. Used when signed out.
    Local,
    /// The server, via server functions. Used when signed in.
    Remote,
}

/// Monotonic counter identifying the newest in-flight load.
///
/// Loads are async and can overlap — re-running one while an earlier call is
/// still in flight is normal (a changed date, a changed backend, a
/// fast-clicked "next week"), and nothing guarantees the two resolve in the
/// order they started. Only the newest may publish its result; an older one
/// arriving after must be discarded rather than overwrite it.
///
/// Shared by [`hook::use_persistent`] and `week_view`'s range load, which
/// both need the same guard. Only the type is `pub(crate)`: the shape of the
/// guard is settled, but the actual holding-a-token-across-an-await dance
/// stays with each caller, so it can be paired with that caller's specific
/// signal writes.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Generation(u64);

impl Generation {
    /// Starts a new load, invalidating any earlier one, and returns its
    /// token. Tokens start at 1, so 0 is a safe "never current" sentinel.
    pub(crate) fn next(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// Whether `token` identifies the newest load.
    pub(crate) fn is_current(&self, token: u64) -> bool {
        self.0 == token
    }
}

/// Something went wrong reaching or interpreting the backing store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    #[error("browser storage is unavailable")]
    Unavailable,
    #[error("stored value for `{key}` could not be read: {source}")]
    Decode {
        key: String,
        source: codec::DecodeError,
    },
    #[error("stored value for `{key}` could not be unwrapped: {source}")]
    Envelope {
        key: String,
        source: envelope::EnvelopeError,
    },
    #[error("failed to write `{key}` to storage")]
    Write { key: String },
    #[error("the server rejected the request: {0}")]
    Server(String),
}

/// Reads a stored value. `Ok(None)` means "nothing stored for this day".
///
/// Under `ssr` this is always `Ok(None)` for **every** backend — including
/// `Remote`, whose rows the server could technically read. That refusal is
/// deliberate: it keeps the server's render independent of user data, which
/// is both the existing hydration contract and a hard requirement once
/// phase 2 encrypts bodies the server cannot decrypt (spec sections 9.1, I1).
pub async fn load(backend: Backend, key: StorageKey) -> Result<Option<String>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::load(key).await?,
            Backend::Remote => remote::load(key).await?,
        };
        match raw {
            None => Ok(None),
            Some(raw) => {
                envelope::unwrap(&raw)
                    .map(Some)
                    .map_err(|source| StorageError::Envelope {
                        key: key.as_key(),
                        source,
                    })
            }
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, key);
        Ok(None)
    }
}

/// Writes a value, replacing any previous one for that day.
///
/// A plain fn building the future by hand, not an `async fn`: `value` is
/// copied into an owned `String` *before* the `async move`. That is
/// load-bearing — `Persistent::set` hands this future to `spawn_local`,
/// which requires `'static`, and an `async fn` taking `&str` would capture
/// the caller's borrow instead. Do not "simplify" it.
pub fn store(
    backend: Backend,
    key: StorageKey,
    value: &str,
) -> impl Future<Output = Result<(), StorageError>> {
    let wrapped = envelope::wrap(value);
    async move {
        #[cfg(feature = "hydrate")]
        {
            match backend {
                Backend::Local => local::store(key, &wrapped).await,
                Backend::Remote => remote::store(key, &wrapped).await,
            }
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (backend, key, wrapped);
            Ok(())
        }
    }
}

/// Removes a stored value. A no-op under `ssr`.
pub async fn clear(backend: Backend, key: StorageKey) -> Result<(), StorageError> {
    #[cfg(feature = "hydrate")]
    {
        match backend {
            Backend::Local => local::clear(key).await,
            Backend::Remote => remote::clear(key).await,
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, key);
        Ok(())
    }
}

/// Which days in `[from, to]` have an entry. Feeds the calendar's dots.
pub async fn dates_with_entries(
    backend: Backend,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        match backend {
            Backend::Local => local::dates_with_entries(from, to).await,
            Backend::Remote => remote::dates_with_entries(from, to).await,
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to);
        Ok(Vec::new())
    }
}

/// Every stored body in `[from, to]`, unwrapped. Feeds the week view.
///
/// Separate from [`dates_with_entries`] because the two answer different
/// questions and should move different amounts of data: the calendar wants
/// to know *which* days, this wants *what*.
pub async fn bodies_in_range(
    backend: Backend,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(NaiveDate, String)>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::bodies_in_range(from, to).await?,
            Backend::Remote => remote::bodies_in_range(from, to).await?,
        };
        raw.into_iter()
            .map(|(date, env)| {
                envelope::unwrap(&env)
                    .map(|body| (date, body))
                    .map_err(|source| StorageError::Envelope {
                        key: StorageKey::TimeEntry(date).as_key(),
                        source,
                    })
            })
            .collect()
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// The legacy key is every existing user's data. Changing this string
    /// orphans all of it (CLAUDE.md: storage keys are a compatibility
    /// surface).
    #[test]
    fn legacy_key_matches_the_dioxus_key() {
        assert_eq!(LEGACY_KEY, "time_entry");
    }

    /// The dated key format is equally a compatibility surface from the
    /// moment it ships.
    #[test]
    fn dated_key_format_is_pinned() {
        assert_eq!(
            StorageKey::TimeEntry(d(2026, 9, 4)).as_key(),
            "time_entry:2026-09-04"
        );
        assert_eq!(
            StorageKey::TimeEntry(d(2026, 1, 5)).as_key(),
            "time_entry:2026-01-05"
        );
    }

    /// Dated keys must sort chronologically as strings, so a key scan can
    /// range over them without parsing every one.
    #[test]
    fn dated_keys_sort_chronologically() {
        let mut keys = [
            StorageKey::TimeEntry(d(2026, 9, 10)).as_key(),
            StorageKey::TimeEntry(d(2026, 9, 2)).as_key(),
            StorageKey::TimeEntry(d(2026, 10, 1)).as_key(),
        ];
        keys.sort();
        assert_eq!(
            keys,
            [
                "time_entry:2026-09-02",
                "time_entry:2026-09-10",
                "time_entry:2026-10-01"
            ]
        );
    }

    /// Pins spec invariant I1 at the seam. Under `ssr` there is no browser
    /// storage and no permission to resolve a remote read during render, so
    /// every backend must report "nothing loaded". If this ever returns
    /// `Some`, the server renders content the hydrating client cannot
    /// reproduce.
    #[test]
    fn ssr_backends_return_none() {
        for backend in [Backend::Local, Backend::Remote] {
            assert_eq!(
                block_on(load(backend, StorageKey::TimeEntry(d(2026, 9, 4)))),
                Ok(None),
                "{backend:?} must not load during SSR"
            );
        }
    }

    #[test]
    fn ssr_writes_are_noops() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(block_on(store(Backend::Local, key, "x")), Ok(()));
        assert_eq!(block_on(clear(Backend::Local, key)), Ok(()));
    }

    /// Same invariant as `ssr_backends_return_none`, for the range read the
    /// week view uses: no backend may return content during SSR.
    #[test]
    fn ssr_bodies_in_range_is_empty() {
        for backend in [Backend::Local, Backend::Remote] {
            assert_eq!(
                block_on(bodies_in_range(backend, d(2026, 8, 31), d(2026, 9, 6))),
                Ok(Vec::new()),
                "{backend:?} must not return entries during SSR"
            );
        }
    }

    /// Pins invariant I2 for a range load: the *older* of two overlapping
    /// loads resolves last. Without a generation guard it would overwrite
    /// the newer result with stale data.
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

    /// Minimal executor — these futures never yield under `ssr`.
    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};
        match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("ssr storage futures must complete immediately"),
        }
    }
}
