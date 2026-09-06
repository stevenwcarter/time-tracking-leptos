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
//! same reason. [`load`] and [`bodies_in_range`] take an
//! `Option<&SessionKey>`, [`store`] takes a [`WriteKey`], and both seal or
//! open around the backend call, so no component ever learns that an entry
//! body is anything but a string. With no key: read whatever each row says
//! it is, and write v1. With one: write v2 and still read either — which is
//! what lets a half-migrated account work at all (spec E3).
//!
//! The two directions take different types because "no key" means different
//! things in each; [`WriteKey`] says why.
//!
//! # Whose key it is, is not checked here
//!
//! [`load`] and [`bodies_in_range`] try whatever key they are handed against
//! whatever rows come back; neither asks whether that key belongs to the
//! account those rows came from. A key for the wrong account opens nothing,
//! so every row would surface as [`StorageError::Crypto`] — "this row is
//! damaged" — rather than as the wrong-account condition it actually is.
//!
//! That is layering, not an oversight: identity belongs to
//! [`crate::encryption_ctx`], which resets to `Unknown` on every
//! `AuthCtx::user` change, restores from the keystore under the signed-in
//! address, and refuses an unlock for anyone else. This seam depends on all
//! three. If a future change ever lets one account's key reach another
//! account's rows, the symptom will be a whole range of "damaged" rows, and
//! this note is where to start looking.

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
#[cfg(feature = "hydrate")]
use std::mem;

use chrono::NaiveDate;
#[cfg(any(feature = "hydrate", test))]
use leptos::logging::error;

use crate::crypto::SessionKey;
#[cfg(any(feature = "hydrate", test))]
use crate::crypto::wire::Sealed;
use crate::date::{parse_iso, to_iso};

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

    /// The inverse of [`as_key`](Self::as_key), or `None` for a string that
    /// does not name a stored day.
    ///
    /// Needed because [`StorageError`] carries the key as the string the
    /// backend saw, so a report built from one can only name the day it
    /// belongs to by parsing it back. The migration pass is the caller that
    /// cares: a body it cannot seal blocks that account's pass for good, and
    /// "this browser couldn't encrypt your entries" points the user at their
    /// browser instead of at the entry they could go and edit.
    pub fn parse(raw: &str) -> Option<Self> {
        let date = raw.strip_prefix(LEGACY_KEY)?.strip_prefix(':')?;
        parse_iso(date).map(StorageKey::TimeEntry)
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

/// What the seam should do with a body on the way out.
///
/// Distinct from the read side's `Option<&SessionKey>` for one reason: on a
/// write, "no key" is ambiguous and one of its two meanings is dangerous. An
/// account with encryption off should write v1. An encrypted account whose
/// device holds no key must write *nothing* — a v1 row there is a silent
/// plaintext downgrade, and nothing downstream would ever flag it: the
/// migration pass reads it as an ordinary un-migrated row and re-seals it,
/// so the only trace is the window in which the body sat on the server in
/// the clear. Reads have no such ambiguity — a row says which it is — which
/// is why only this direction needs the extra state.
///
/// [`crate::encryption_ctx::EncryptionState::write_key`] is the one place
/// that decides which of these an account is in.
pub enum WriteKey<'a> {
    /// The account has no encryption. Write v1.
    Plaintext,
    /// The account is encrypted and this session can seal. Write v2.
    Sealed(&'a SessionKey),
    /// The account is encrypted and this session cannot seal — locked, or
    /// not yet known to be either. Refuse.
    Locked,
}

/// Which row a bulk write is on, for whatever is reporting it.
///
/// A pair rather than two `usize` arguments, which a caller could swap
/// without the compiler minding and which would then count backwards. `day`
/// is the row being worked on, not the row finished — it is reported before
/// the seal, so the first one is visible too.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub day: usize,
    pub total: usize,
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
    /// The account is encrypted and this session holds no key for it.
    ///
    /// On a read, the row is sealed and cannot be opened. On a write, the
    /// body was not stored at all — writing it unsealed would silently
    /// downgrade an encrypted account's row to plaintext, which is what
    /// [`WriteKey`] exists to make impossible.
    ///
    /// Deliberately *not* [`StorageError::Envelope`]. The two send the user
    /// to opposite places — "unlock and try again" against "this row is
    /// damaged" — and only the first is true here, of a session that has
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
/// `session` picks the envelope version: [`WriteKey::Plaintext`] writes v1,
/// [`WriteKey::Sealed`] seals and writes v2 (see [`envelope::wrap`]), and
/// [`WriteKey::Locked`] writes nothing and fails with
/// [`StorageError::Locked`]. Readers never consult that choice.
///
/// The refusal is decided here rather than in either `cfg` branch below, so
/// it holds on every target and costs no backend call — a locked write is
/// not a write that failed partway, it is one that never started.
///
/// A plain fn building the future by hand, not an `async fn`: `value` is
/// copied into an owned `String` — and `session` resolved into an owned
/// decision — *before* the `async move`. That is load-bearing —
/// `Persistent::set` hands this future to `spawn_local`, which requires
/// `'static`, and an `async fn` taking `&str` would capture the caller's
/// borrow instead. Do not "simplify" it.
///
/// Sealing is async, so the [`envelope::wrap`] call itself has to happen
/// *inside* the async block; only the two values above it may not move
/// there. `use<>` is what makes that a compile error rather than a subtle
/// one: it declares that the returned future captures no lifetime at all,
/// so moving either inside the block fails here instead of at some distant
/// `spawn_local` (spec E4).
/// Turns a [`WriteKey`] into "seal with this, or don't", refusing the one
/// state that must never reach a backend.
///
/// **The single place the plaintext-downgrade refusal is made**, shared by
/// [`store`] and [`store_many`]. A second write path that decided this for
/// itself is exactly how the refusal gets lost: nothing downstream would
/// notice an encrypted account taking v1 rows (invariant E7).
///
/// Owned rather than borrowed because [`store`] hands its future to
/// `spawn_local`, which needs `'static`.
fn sealing_key(key: StorageKey, session: WriteKey<'_>) -> Result<Option<SessionKey>, StorageError> {
    match session {
        WriteKey::Plaintext => Ok(None),
        // `Option::cloned`, not a direct `session.clone()`: on a target
        // where `SessionKey` is uninhabited this arm cannot be reached, and
        // cloning the key itself would say so as an `unreachable_code`
        // warning. Going through the `Option` keeps the expression's type
        // inhabited and the arm silent.
        WriteKey::Sealed(session) => Ok(Some(session).cloned()),
        WriteKey::Locked => Err(StorageError::Locked { key: key.as_key() }),
    }
}

pub fn store(
    backend: Backend,
    key: StorageKey,
    value: &str,
    session: WriteKey<'_>,
) -> impl Future<Output = Result<(), StorageError>> + use<> {
    let value = value.to_owned();
    let sealing = sealing_key(key, session);
    async move {
        let session = sealing?;
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

/// How much one bulk write carries: at most this many rows, and at most this
/// many bytes of sealed body across them.
///
/// The pass is chunked rather than posted whole because the whole is
/// unbounded — an account's entire history in one request holds one SQLite
/// write transaction open for as long as it takes to apply, and the same
/// reasoning that gives `entry_save` a per-body cap applies to the count.
/// Per-row dispatch (spec E3) is what makes chunking cost nothing: each
/// chunk is correct on its own, and a pass that stops between chunks leaves
/// fewer v1 rows for the next one to find, which is exactly the
/// resumability spec section 8 already relies on.
///
/// Both bounds sit under `entry_save_many`'s own caps — and a chunk can
/// exceed [`BATCH_BYTES`] only by the one oversized row it flushes for, so
/// the widest chunk this can send is still well under them.
#[cfg(feature = "hydrate")]
const BATCH_ROWS: usize = 100;

#[cfg(feature = "hydrate")]
const BATCH_BYTES: usize = 512 * 1024;

/// Seals a whole account's worth of days and writes them — the encryption
/// migration pass of spec section 8.
///
/// Here rather than in the panel that runs it, because of what [`WriteKey`]
/// guards. A pass that sealed its own bodies and posted them itself would be
/// a second write path, and the first thing a second write path loses is the
/// refusal: a locked session would rewrite a whole account as v1 with
/// nothing downstream to notice (invariant E7). Going through
/// [`sealing_key`] means that decision is made once, for the batch, before
/// any row is touched.
///
/// Sent in chunks rather than as one request; see [`BATCH_ROWS`] for why,
/// and for why that costs the pass nothing. What it *does* cost is the claim
/// that a failed pass changed nothing: rows in chunks that already landed
/// stay sealed, and a caller reporting the failure has to say so.
///
/// No `Backend`, deliberately. A signed-out device stores in `localStorage`,
/// which is never encrypted (spec section 1.2), so there is no migration for
/// it to run and no local bulk write to reach.
///
/// `progress` is called before each row is sealed, on the await that yields
/// to the event loop, so a caller reporting it actually sees the count move.
pub async fn store_many(
    rows: Vec<(NaiveDate, String)>,
    session: WriteKey<'_>,
    progress: impl Fn(Progress),
) -> Result<(), StorageError> {
    let total = rows.len();
    // An empty batch is a real outcome — a pass that found nothing left to
    // do — and writing nothing needs no key at all.
    let Some(&(first, _)) = rows.first() else {
        return Ok(());
    };
    let sealing = sealing_key(StorageKey::TimeEntry(first), session)?;

    #[cfg(feature = "hydrate")]
    {
        let mut batch: Vec<(NaiveDate, String)> = Vec::new();
        let mut bytes = 0;
        for (index, (date, body)) in rows.into_iter().enumerate() {
            progress(Progress {
                day: index + 1,
                total,
            });
            let key = StorageKey::TimeEntry(date);
            let wrapped = envelope::wrap(&body, sealing.as_ref())
                .await
                .map_err(|err| StorageError::Crypto {
                    key: key.as_key(),
                    detail: err.to_string(),
                })?;
            // Flushed before this row joins, not after, so a single body
            // larger than the byte bound still travels — alone, in its own
            // chunk — rather than being refused by a rule about batches.
            if !batch.is_empty()
                && (batch.len() >= BATCH_ROWS || bytes + wrapped.len() > BATCH_BYTES)
            {
                remote::store_many(mem::take(&mut batch)).await?;
                bytes = 0;
            }
            bytes += wrapped.len();
            batch.push((date, wrapped));
        }
        remote::store_many(batch).await
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (rows, sealing, progress, total);
        Ok(())
    }
}

/// Removes a stored value.
///
/// Takes a [`WriteKey`] because on `Remote` this *is* a write: clearing a day
/// stores an empty body rather than deleting the row, so that "cleared" and
/// "never written" read alike, the day's `updated_at` stays meaningful, and
/// there is one less server fn to authorize. Letting a locked session
/// through would therefore put a v1 row into an encrypted account — the
/// plaintext downgrade invariant E7 exists to prevent — so `Remote` goes
/// through [`store`], which already refuses and already picks the envelope
/// version.
///
/// `Local` removes the key rather than rewriting it, so it has no envelope
/// to pick, but it refuses a locked session too: "can this session write?"
/// should have one answer per session and not one per backend.
pub async fn clear(
    backend: Backend,
    key: StorageKey,
    session: WriteKey<'_>,
) -> Result<(), StorageError> {
    match backend {
        Backend::Remote => store(backend, key, "", session).await,
        Backend::Local => {
            if matches!(session, WriteKey::Locked) {
                return Err(StorageError::Locked { key: key.as_key() });
            }
            clear_local(key).await
        }
    }
}

/// `localStorage`'s half of [`clear`]. A no-op under `ssr`.
async fn clear_local(key: StorageKey) -> Result<(), StorageError> {
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

/// What one pass of [`decide_rows`] made of a range.
///
/// The flag travels with the rows because dropping a sealed row is not the
/// same kind of loss as dropping a corrupt one. A corrupt row is a fact
/// about that row; a sealed row is a fact about the *session* — it can only
/// exist in an encrypted account, and only a session with no key can fail to
/// open it — so it is the evidence that settles whether this page load's
/// idea of the account is still true (see
/// [`crate::encryption_ctx::EncryptionCtx::sealed_row_seen`]).
#[cfg(any(feature = "hydrate", test))]
struct DecidedRows<'a, K> {
    rows: Vec<(NaiveDate, RowRead<'a, K>)>,
    /// Whether at least one row was sealed against a session holding no key.
    sealed: bool,
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
) -> DecidedRows<'a, K> {
    let mut sealed = false;
    let rows = rows
        .into_iter()
        .filter_map(|(date, raw)| {
            let read = decide_row(&raw, session, StorageKey::TimeEntry(date));
            sealed |= matches!(read, Err(StorageError::Locked { .. }));
            keep_row(date, read)
        })
        .collect();
    DecidedRows { rows, sealed }
}

/// What one pass of [`open_rows`] made of the rows [`decide_rows`] handed
/// it.
///
/// [`DecidedRows`] one layer down, and the flag travels for a weaker version
/// of the same reason. A row that will not open is usually a fact about that
/// row — but a session whose key belongs to another account fails this way
/// on *every* row it reads, while still believing it is unlocked, so it is
/// evidence worth carrying rather than only logging (see
/// [`crate::encryption_ctx::EncryptionCtx::unopenable_row_seen`], which is
/// what decides whether it means anything).
#[cfg(any(feature = "hydrate", test))]
struct OpenedRows {
    rows: Vec<(NaiveDate, String)>,
    /// Whether at least one row refused to open under the key it was given.
    unopenable: bool,
}

/// Opens every decided row, dropping (and logging) the ones that will not
/// open.
///
/// Generic over the opener for the same reason [`decide_row`] is generic over
/// the key. The real opener is [`open_row`], which needs a browser, but the
/// control flow around it is ordinary code — and it is the half that decides
/// whether one unreadable row costs a day or a week ([`keep_row`]). A
/// stand-in opener puts that within reach of `cargo test`; only the one
/// `SubtleCrypto` call stays out of it.
#[cfg(any(feature = "hydrate", test))]
async fn open_rows<'a, K, F, Fut>(rows: Vec<(NaiveDate, RowRead<'a, K>)>, open: F) -> OpenedRows
where
    F: Fn(RowRead<'a, K>, StorageKey) -> Fut,
    Fut: Future<Output = Result<String, StorageError>>,
{
    let mut bodies = Vec::new();
    let mut unopenable = false;
    for (date, read) in rows {
        let opened = open(read, StorageKey::TimeEntry(date)).await;
        unopenable |= matches!(opened, Err(StorageError::Crypto { .. }));
        bodies.extend(keep_row(date, opened));
    }
    OpenedRows {
        rows: bodies,
        unopenable,
    }
}

/// Every stored body a range read could open, and whether it had to leave
/// any sealed.
///
/// The rows alone would be a lie by omission on a session whose state is out
/// of date: a week of sealed days comes back empty and renders as "Nothing
/// logged this week." The flag is what lets the caller tell that apart from
/// a genuinely empty week and say so.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RangeRead {
    pub rows: Vec<(NaiveDate, String)>,
    /// Whether at least one row in the range was sealed against this
    /// session. See [`DecidedRows`].
    pub sealed: bool,
    /// Whether at least one row refused to open under the key this session
    /// *does* hold. See [`OpenedRows`].
    pub unopenable: bool,
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
) -> Result<RangeRead, StorageError> {
    #[cfg(feature = "hydrate")]
    {
        let raw = match backend {
            Backend::Local => local::bodies_in_range(from, to).await?,
            Backend::Remote => remote::bodies_in_range(from, to).await?,
        };
        let decided = decide_rows(raw, session);
        let opened = open_rows(decided.rows, open_row).await;
        Ok(RangeRead {
            rows: opened.rows,
            sealed: decided.sealed,
            unopenable: opened.unopenable,
        })
    }
    #[cfg(not(feature = "hydrate"))]
    {
        let _ = (backend, from, to, session);
        Ok(RangeRead::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::wire;
    use crate::test_util::block_on;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// Stands in for the session key. `decide_row` is generic over the key
    /// and never looks inside one, so a byte does the job here.
    ///
    /// It is a readable placeholder, not a discriminator: only one key is
    /// ever in scope, and a function generic over `K` with a single `&K` to
    /// hand has nothing else it could return, so `*k == SESSION` cannot fail
    /// against a type-correct implementation. What the sealed-row assertions
    /// below actually pin is the *ciphertext* travelling with the decision.
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

    /// The round trip the migration's failure report depends on: a
    /// `StorageError` carries the key as a string, and naming the day it
    /// belongs to means reading it back.
    #[test]
    fn a_dated_key_parses_back_to_its_day() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(StorageKey::parse(&key.as_key()), Some(key));
    }

    /// Anything that is not a dated key reads as no day at all, rather than
    /// as some day the caller would then name in a message.
    #[test]
    fn a_string_that_is_not_a_dated_key_names_no_day() {
        for raw in [
            "",
            LEGACY_KEY,
            "time_entry:",
            "time_entry:not-a-date",
            "time_entry:2026-02-30",
            "other:2026-09-04",
            "2026-09-04",
        ] {
            assert_eq!(
                StorageKey::parse(raw),
                None,
                "{raw:?} must not parse as a stored day"
            );
        }
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
        assert_eq!(
            block_on(store(Backend::Local, key, "x", WriteKey::Plaintext)),
            Ok(())
        );
        assert_eq!(
            block_on(clear(Backend::Local, key, WriteKey::Plaintext)),
            Ok(())
        );
    }

    /// The regression this guards against: a session that cannot seal must
    /// refuse the write, not fall back to writing the body in the clear.
    /// A plaintext row in an encrypted account is invisible afterwards —
    /// the migration pass would re-seal it as if it had always been an
    /// un-migrated row, leaving nothing to say the body had been exposed.
    ///
    /// Asserted on a target that cannot encrypt anything at all, which is
    /// the point: the refusal is decided before any backend or any
    /// `cfg` branch, so it cannot be lost to one.
    #[test]
    fn a_locked_session_refuses_the_write_rather_than_downgrading_it() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(
            block_on(store(Backend::Local, key, "9-10 code1", WriteKey::Locked)),
            Err(StorageError::Locked { key: key.as_key() })
        );
    }

    /// The regression this guards against: clearing a day on `Remote` stores
    /// an empty *body* rather than deleting the row, so a locked session let
    /// through here would write a v1 row into an encrypted account — the
    /// same plaintext downgrade `store` refuses, arriving through the one
    /// door that used to have no lock on it (invariant E7).
    #[test]
    fn a_locked_session_refuses_to_clear_on_either_backend() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        for backend in [Backend::Local, Backend::Remote] {
            assert_eq!(
                block_on(clear(backend, key, WriteKey::Locked)),
                Err(StorageError::Locked { key: key.as_key() }),
                "{backend:?} must refuse to clear a day it cannot seal"
            );
        }
    }

    /// The same refusal as `store`, at the one other door into the write
    /// path. The migration pass rewrites a whole account in one call, so a
    /// locked session let through here would downgrade every row at once —
    /// the widest possible version of invariant E7's failure, and the reason
    /// the pass goes through this seam rather than sealing and posting on
    /// its own.
    #[test]
    fn a_locked_session_refuses_the_whole_migration_batch() {
        let day = d(2026, 9, 1);
        assert_eq!(
            block_on(store_many(
                vec![(day, "9-10 code1".to_string())],
                WriteKey::Locked,
                |_| {},
            )),
            Err(StorageError::Locked {
                key: StorageKey::TimeEntry(day).as_key()
            })
        );
    }

    /// An empty batch is a real outcome — a pass that found nothing left to
    /// do — and writing nothing needs no key. Reporting it as a refusal
    /// would turn "already finished" into an error on every re-run.
    #[test]
    fn an_empty_migration_batch_is_not_a_refusal() {
        assert_eq!(
            block_on(store_many(Vec::new(), WriteKey::Locked, |_| {})),
            Ok(())
        );
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
                Ok(RangeRead::default()),
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
    /// past this point.
    ///
    /// Only the ciphertext half discriminates; the key half is there for
    /// readability, for the reason [`SESSION`] gives.
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
            kept.rows.iter().map(|(date, _)| *date).collect::<Vec<_>>(),
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
        assert_eq!(decide_rows(rows, None::<&u8>).rows.len(), 2);
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
        let decided = decide_rows(rows, None::<&u8>);
        assert_eq!(
            decided
                .rows
                .iter()
                .map(|(date, _)| *date)
                .collect::<Vec<_>>(),
            vec![d(2026, 9, 1), d(2026, 9, 3)]
        );
        assert!(
            decided.sealed,
            "a row this session could not open must be reported, not only dropped: a week \
             that came back short reads as an empty week"
        );
    }

    /// Stands in for [`open_row`], which needs a browser. A plaintext row
    /// passes through; a sealed one fails the way a tampered or truncated
    /// row does, which is the only failure the second pass can see.
    async fn open_or_fail(read: RowRead<'_, u8>, key: StorageKey) -> Result<String, StorageError> {
        match read {
            RowRead::Plaintext(body) => Ok(body),
            RowRead::Sealed(..) => Err(StorageError::Crypto {
                key: key.as_key(),
                detail: "stand-in opener".to_string(),
            }),
        }
    }

    /// The blast-radius rule again, for the pass that carries it second: a
    /// row that decoded fine and then would not *open* must cost its own day
    /// and nothing more. The `decide_rows` assertion first is what places the
    /// loss in the second pass — all three rows survive the first.
    ///
    /// The flag is asserted alongside, and it is not the same claim as the
    /// rows: dropping a day is the right blast radius, but a *silently*
    /// dropped day is what makes a wrong-account week read as a light one.
    /// Only the flag can tell the caller the difference.
    #[test]
    fn a_row_that_will_not_open_costs_only_its_own_day() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), sealed(7)),
            (d(2026, 9, 3), envelope::wrap_v1("b")),
        ];
        let decided = decide_rows(rows, Some(&SESSION));
        assert_eq!(
            decided.rows.len(),
            3,
            "every row must survive the first pass"
        );
        assert!(
            !decided.sealed,
            "a session holding a key met no sealed row, whatever the opener then did"
        );

        let opened = block_on(open_rows(decided.rows, open_or_fail));
        assert_eq!(
            opened.rows,
            vec![
                (d(2026, 9, 1), "a".to_string()),
                (d(2026, 9, 3), "b".to_string())
            ],
            "the unopenable day must be dropped, not the whole week"
        );
        assert!(
            opened.unopenable,
            "a row that would not open under this session's own key must be reported, not \
             only dropped: every row of another account's week fails exactly this way"
        );
    }

    /// The complement, and the reason the rule is "skip", not "swallow":
    /// with nothing failing, every row still has to come out — and nothing
    /// is reported unopenable, or an ordinary week would spend the page
    /// load's one re-probe.
    #[test]
    fn every_row_that_opens_is_kept() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), envelope::wrap_v1("b")),
        ];
        let opened = block_on(open_rows(decide_rows(rows, None::<&u8>).rows, open_or_fail));
        assert_eq!(
            opened.rows,
            vec![
                (d(2026, 9, 1), "a".to_string()),
                (d(2026, 9, 2), "b".to_string())
            ]
        );
        assert!(!opened.unopenable);
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
        let decided = decide_rows(rows, Some(&SESSION)).rows;
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
}
