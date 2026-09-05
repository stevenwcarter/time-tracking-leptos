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
//!
//! Encryption is the third thing that varies, and it varies here for the
//! same reason. [`load`], [`store`] and [`bodies_in_range`] take an
//! `Option<&SessionKey>` and seal or open around the backend call, so no
//! component ever learns that an entry body is anything but a string. `None`
//! is an account with encryption off: write v1, read whatever each row says
//! it is. `Some` writes v2 and still reads either — which is what lets a
//! half-migrated account work at all (spec E3).

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
#[cfg(any(feature = "hydrate", test))]
use leptos::logging::error;

use crate::crypto::SessionKey;
#[cfg(any(feature = "hydrate", test))]
use crate::crypto::wire::Sealed;
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
    /// The row is sealed and this session holds no key to open it.
    ///
    /// Deliberately *not* [`StorageError::Envelope`]. The two send the user
    /// to opposite places — "unlock and try again" against "this row is
    /// damaged" — and only the first is true here, of a reader who has
    /// simply not unlocked yet.
    #[error("`{key}` is encrypted and this session holds no key for it")]
    Locked { key: String },
    /// The key was there and the operation still failed: a tampered or
    /// truncated row on a read, a WebCrypto failure on a write.
    ///
    /// One variant for both directions, because no caller treats them
    /// differently — either way this body did not survive the trip — and
    /// because the underlying `CryptoError` is browser-only, flattened to
    /// its message (`detail`, not `source`, which `thiserror` reserves for a
    /// real nested error) so that `StorageError` stays one type on every
    /// target.
    #[error("could not encrypt or decrypt `{key}`: {detail}")]
    Crypto { key: String, detail: String },
    #[error("failed to write `{key}` to storage")]
    Write { key: String },
    #[error("the server rejected the request: {0}")]
    Server(String),
}

/// What reading one stored row comes down to, once its version has been
/// dispatched on.
///
/// The sealed arm carries the key beside the ciphertext rather than leaving
/// the opener to go looking for one again: "sealed, and nobody has the key"
/// is a state this type cannot hold, because that case is
/// [`StorageError::Locked`] and never gets this far.
///
/// Generic over the key so [`decide_row`] can be host-tested — see there.
#[cfg(any(feature = "hydrate", test))]
#[derive(Debug)]
enum RowRead<'a, K> {
    /// A v1 row: the body was stored in the clear and is right here.
    Plaintext(String),
    /// A v2 row, and the key that opens it.
    Sealed(&'a K, Sealed),
}

/// Decides what reading one stored row requires, before any key is used.
///
/// Split out of [`load`] and [`decide_rows`] **because it is the only part
/// of the encrypted read path a host test can reach**: opening a v2 row goes
/// through `SessionKey`, which wraps a WebCrypto handle that cannot exist
/// outside a browser, and this project has no wasm test runner. So
/// everything up to that one `open` call — version dispatch, the
/// malformed-row error, and the locked case — is decided here, where
/// `cargo test` can cover it exhaustively. `K` is generic for the same
/// reason: the decision never looks *inside* the key, only at whether there
/// is one, so a test can stand a unit in for it.
///
/// Dispatch is on the row's own `v` and on nothing else — not on whether the
/// account has encryption enabled, not on whether a key happens to be in
/// hand (spec E3). A half-migrated account holds both shapes at once and can
/// be interrupted again at any point, so each row has to carry its own
/// answer.
#[cfg(any(feature = "hydrate", test))]
fn decide_row<'a, K>(
    raw: &str,
    session: Option<&'a K>,
    key: StorageKey,
) -> Result<RowRead<'a, K>, StorageError> {
    let plan = envelope::plan_read(raw).map_err(|source| StorageError::Envelope {
        key: key.as_key(),
        source,
    })?;
    match (plan, session) {
        (envelope::ReadPlan::Plaintext(body), _) => Ok(RowRead::Plaintext(body)),
        (envelope::ReadPlan::Sealed(sealed), Some(session)) => Ok(RowRead::Sealed(session, sealed)),
        (envelope::ReadPlan::Sealed(_), None) => Err(StorageError::Locked { key: key.as_key() }),
    }
}

/// Carries out what [`decide_row`] decided, which for a sealed row is the
/// one step of the read path no host test can run.
#[cfg(feature = "hydrate")]
async fn open_row(read: RowRead<'_, SessionKey>, key: StorageKey) -> Result<String, StorageError> {
    match read {
        RowRead::Plaintext(body) => Ok(body),
        RowRead::Sealed(session, sealed) => {
            session
                .open(&sealed)
                .await
                .map_err(|err| StorageError::Crypto {
                    key: key.as_key(),
                    detail: err.to_string(),
                })
        }
    }
}

/// Reads a stored value. `Ok(None)` means "nothing stored for this day".
///
/// `session` is the account's unlocked data key, or `None` when the account
/// has no encryption. It is consulted only by a row that says it needs one:
/// a v1 row reads identically either way (spec E3).
///
/// Under `ssr` this is always `Ok(None)` for **every** backend — including
/// `Remote`, whose rows the server could technically read. That refusal is
/// deliberate: it keeps the server's render independent of user data, which
/// is both the existing hydration contract and a hard requirement now that
/// phase 2 encrypts bodies the server cannot decrypt (spec sections 9.1, I1).
pub async fn load(
    backend: Backend,
    key: StorageKey,
    session: Option<&SessionKey>,
) -> Result<Option<String>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::load(key).await?,
            Backend::Remote => remote::load(key).await?,
        };
        match raw {
            None => Ok(None),
            Some(raw) => open_row(decide_row(&raw, session, key)?, key)
                .await
                .map(Some),
        }
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, key, session);
        Ok(None)
    }
}

/// Writes a value, replacing any previous one for that day.
///
/// `session` picks the envelope version: `None` writes v1, `Some` seals and
/// writes v2 (see [`envelope::wrap`]). Readers never consult that choice.
///
/// A plain fn building the future by hand, not an `async fn`: `value` is
/// copied into an owned `String` — and `session` into an owned key — *before*
/// the `async move`. That is load-bearing — `Persistent::set` hands this
/// future to `spawn_local`, which requires `'static`, and an `async fn`
/// taking `&str` would capture the caller's borrow instead. Do not
/// "simplify" it.
///
/// Sealing is async, so the [`envelope::wrap`] call itself has to happen
/// *inside* the async block; only the two copies above it may not move
/// there. `use<>` is what makes that a compile error rather than a subtle
/// one: it declares that the returned future captures no lifetime at all,
/// so moving either copy inside the block fails here instead of at some
/// distant `spawn_local` (spec E4).
pub fn store(
    backend: Backend,
    key: StorageKey,
    value: &str,
    session: Option<&SessionKey>,
) -> impl Future<Output = Result<(), StorageError>> + use<> {
    let value = value.to_owned();
    let session = session.cloned();
    async move {
        #[cfg(feature = "hydrate")]
        {
            let wrapped = envelope::wrap(&value, session.as_ref())
                .await
                .map_err(|err| StorageError::Crypto {
                    key: key.as_key(),
                    detail: err.to_string(),
                })?;
            match backend {
                Backend::Local => local::store(key, &wrapped).await,
                Backend::Remote => remote::store(key, &wrapped).await,
            }
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (backend, key, value, session);
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

/// The range read's blast-radius rule, in one place: a row that cannot be
/// read costs its own day and nothing more.
///
/// Collecting into a `Result` instead would scope a single unreadable row to
/// the entire week — `WeekBody` would fall back to an empty `Vec` and render
/// "Nothing logged this week." even when six of seven days are fine. That is
/// a worse blast radius than the per-day path: `hook::loaded_value` scopes a
/// failure to the one key it belongs to, so this does too, just at range
/// width instead of single-key width.
///
/// Shared by both passes of the range read below. They fail for unrelated
/// reasons — an envelope that will not parse, a body that will not decrypt —
/// and owe the reader the same six good days either way.
#[cfg(any(feature = "hydrate", test))]
fn keep_row<T>(date: NaiveDate, read: Result<T, StorageError>) -> Option<(NaiveDate, T)> {
    match read {
        Ok(value) => Some((date, value)),
        Err(err) => {
            error!("skipping {date}: {err}");
            None
        }
    }
}

/// Decides every row of a range read, dropping (and logging) the ones that
/// cannot be read at all.
///
/// The half of the range read that needs no key, and therefore the half a
/// host test can drive: pure, free of `web_sys`, and where the blast-radius
/// rule above is exercised.
///
/// `test` as well as `hydrate`, same reason as `local`'s decision logic: its
/// only non-test call site is inside [`bodies_in_range`]'s `hydrate` branch,
/// so an `ssr`-only build has no caller for it at all.
#[cfg(any(feature = "hydrate", test))]
fn decide_rows<'a, K>(
    rows: Vec<(NaiveDate, String)>,
    session: Option<&'a K>,
) -> Vec<(NaiveDate, RowRead<'a, K>)> {
    rows.into_iter()
        .filter_map(|(date, raw)| {
            keep_row(date, decide_row(&raw, session, StorageKey::TimeEntry(date)))
        })
        .collect()
}

/// Every stored body in `[from, to]`, unwrapped and opened. Feeds the week
/// view.
///
/// Separate from [`dates_with_entries`] because the two answer different
/// questions and should move different amounts of data: the calendar wants
/// to know *which* days, this wants *what*.
///
/// Two passes rather than one because only the first can be tested here: the
/// decisions come out of [`decide_rows`] on the host, and the sealed rows
/// among them are opened afterwards, in the browser. A row lost in either
/// pass costs only its own day ([`keep_row`]).
pub async fn bodies_in_range(
    backend: Backend,
    from: NaiveDate,
    to: NaiveDate,
    session: Option<&SessionKey>,
) -> Result<Vec<(NaiveDate, String)>, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::bodies_in_range(from, to).await?,
            Backend::Remote => remote::bodies_in_range(from, to).await?,
        };
        let mut bodies = Vec::new();
        for (date, read) in decide_rows(raw, session) {
            let opened = open_row(read, StorageKey::TimeEntry(date)).await;
            bodies.extend(keep_row(date, opened));
        }
        Ok(bodies)
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to, session);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wire;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// Stands in for the session key. `decide_row` is generic over the key
    /// and never looks inside one, so a byte does the job here — a
    /// distinctive byte, so a test can check that a decision hands back *the*
    /// key it was given rather than merely that some key came out.
    const SESSION: u8 = 42;

    /// A v2 row. `tag` distinguishes one row's ciphertext from another's, so
    /// a test can tell *which* row a decision came from and not merely that
    /// some sealed row did.
    fn sealed(tag: u8) -> String {
        wire::encode_v2(&Sealed {
            nonce: vec![0; wire::NONCE_LEN],
            ciphertext: vec![tag],
        })
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
                block_on(load(backend, StorageKey::TimeEntry(d(2026, 9, 4)), None)),
                Ok(None),
                "{backend:?} must not load during SSR"
            );
        }
    }

    #[test]
    fn ssr_writes_are_noops() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(block_on(store(Backend::Local, key, "x", None)), Ok(()));
        assert_eq!(block_on(clear(Backend::Local, key)), Ok(()));
    }

    /// Same invariant as `ssr_backends_return_none`, for the range read the
    /// week view uses: no backend may return content during SSR.
    #[test]
    fn ssr_bodies_in_range_is_empty() {
        for backend in [Backend::Local, Backend::Remote] {
            assert_eq!(
                block_on(bodies_in_range(
                    backend,
                    d(2026, 8, 31),
                    d(2026, 9, 6),
                    None
                )),
                Ok(Vec::new()),
                "{backend:?} must not return entries during SSR"
            );
        }
    }

    /// The decision this whole task turns on, and the one an obvious
    /// implementation gets wrong: a sealed row that nobody can open is
    /// `Locked`, not `Envelope`. The two send the reader to opposite
    /// places — "unlock and try again" against "this row is damaged" — and
    /// only the first is true of someone who has not unlocked yet.
    #[test]
    fn a_sealed_row_with_no_key_is_locked_not_corrupt() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(
            decide_row(&sealed(7), None::<&u8>, key).unwrap_err(),
            StorageError::Locked { key: key.as_key() }
        );
    }

    /// The sealed decision has to carry the key *and* the ciphertext, since
    /// pairing them is what makes "sealed but unopenable" unrepresentable
    /// past this point. Both halves are asserted: a decision that returned
    /// the right ciphertext beside some other key would open to garbage.
    #[test]
    fn a_sealed_row_with_a_key_carries_both_that_key_and_the_ciphertext() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        let read = decide_row(&sealed(7), Some(&SESSION), key).expect("a key opens it");
        assert!(matches!(read, RowRead::Sealed(k, s) if *k == SESSION && s.ciphertext == vec![7]));
    }

    #[test]
    fn a_plaintext_row_reads_with_no_key_at_all() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        let read = decide_row(&envelope::wrap_v1("9-10 code1"), None::<&u8>, key).expect("v1");
        assert!(matches!(read, RowRead::Plaintext(body) if body == "9-10 code1"));
    }

    /// Spec E3, in the direction a migration makes real: an account that is
    /// encrypted — and so holds a key — still has rows the migration has not
    /// reached. Dispatching on the key rather than on the row's own `v`
    /// would try to decrypt every one of them.
    #[test]
    fn a_plaintext_row_still_reads_as_plaintext_when_a_key_is_present() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        let read = decide_row(&envelope::wrap_v1("9-10 code1"), Some(&SESSION), key).expect("v1");
        assert!(matches!(read, RowRead::Plaintext(body) if body == "9-10 code1"));
    }

    /// A row that is not an envelope at all is corrupt whether or not a key
    /// is in hand — `Locked` is specifically "v2 and no key", not a catch-all
    /// for anything unreadable.
    #[test]
    fn a_malformed_row_is_an_envelope_error_with_or_without_a_key() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert!(matches!(
            decide_row("not an envelope", None::<&u8>, key),
            Err(StorageError::Envelope { .. })
        ));
        assert!(matches!(
            decide_row("not an envelope", Some(&SESSION), key),
            Err(StorageError::Envelope { .. })
        ));
    }

    /// The regression this guards against: one corrupt envelope must cost
    /// only its own day, not the whole range.
    #[test]
    fn a_bad_envelope_is_skipped_but_the_rest_of_the_range_survives() {
        let good = envelope::wrap_v1("9-10 code1");
        let rows = vec![
            (d(2026, 9, 1), good.clone()),
            (d(2026, 9, 2), "not an envelope".to_string()),
            (d(2026, 9, 3), good),
        ];
        let kept = decide_rows(rows, None::<&u8>);
        assert_eq!(
            kept.iter().map(|(date, _)| *date).collect::<Vec<_>>(),
            vec![d(2026, 9, 1), d(2026, 9, 3)],
            "the corrupt day must be dropped, not the whole week"
        );
    }

    #[test]
    fn every_valid_envelope_is_kept() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), envelope::wrap_v1("b")),
        ];
        assert_eq!(decide_rows(rows, None::<&u8>).len(), 2);
    }

    /// The same blast-radius rule for the failure this task introduces. A
    /// locked row in the middle of a week is the *expected* state of a
    /// signed-in visitor who has not unlocked on this device yet, so it had
    /// better not take the signed-out days around it down with it.
    #[test]
    fn a_locked_row_costs_only_its_own_day() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), sealed(7)),
            (d(2026, 9, 3), envelope::wrap_v1("b")),
        ];
        assert_eq!(
            decide_rows(rows, None::<&u8>)
                .iter()
                .map(|(date, _)| *date)
                .collect::<Vec<_>>(),
            vec![d(2026, 9, 1), d(2026, 9, 3)]
        );
    }

    /// A partially migrated account, at range width: both shapes in one
    /// week, each decided on its own `v` (spec E3). The migration can stop
    /// anywhere, so this is not a corner case — it is what every account
    /// looks like between "enable" and "finished".
    #[test]
    fn a_mixed_v1_and_v2_range_decides_every_row_on_its_own_version() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), sealed(7)),
            (d(2026, 9, 3), envelope::wrap_v1("b")),
        ];
        let decided = decide_rows(rows, Some(&SESSION));
        assert_eq!(decided.len(), 3, "a half-migrated range must lose no rows");
        assert!(matches!(&decided[0].1, RowRead::Plaintext(b) if b == "a"));
        assert!(
            matches!(&decided[1].1, RowRead::Sealed(k, s) if **k == SESSION && s.ciphertext == vec![7])
        );
        assert!(matches!(&decided[2].1, RowRead::Plaintext(b) if b == "b"));
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
