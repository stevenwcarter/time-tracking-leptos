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
//! it is, and write v1 — a write [`Backend::Local`] alone still has a route
//! to, since the server refuses an entry from an account with no encryption
//! (invariant E9). With one: write v2 and still read either, because
//! dispatch is per row, on the row's own version (spec E3).
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
    /// backend saw, so anything reporting one can only name the day it
    /// belongs to by parsing it back. `local`'s key scan is the caller
    /// today: it reads every `localStorage` key and keeps the ones that
    /// name a stored day.
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
/// write, "no key" is ambiguous and one of its two meanings is dangerous. A
/// device with no account writes v1 into `localStorage`. An encrypted
/// account whose device holds no key must write *nothing* — a v1 row there
/// is a silent plaintext downgrade, and the row itself carries no trace of
/// one, since v1 is exactly what a device with no account legitimately
/// writes. Reads have no such ambiguity — a row says which it is — which is
/// why only this direction needs the extra state.
///
/// [`crate::encryption_ctx::EncryptionState::write_key`] is the one place
/// that decides which of these a session is in; [`write_target`] is the one
/// place that decides what each means for the backend in hand.
///
/// Generic over the key, defaulted to [`SessionKey`], so [`write_target`]'s
/// sealed arms have a host representative: `SessionKey` is uninhabited off
/// the browser, so `Sealed` is otherwise unconstructible anywhere a test
/// runs. Every caller writes `WriteKey<'_>` and gets the default.
pub enum WriteKey<'a, K = SessionKey> {
    /// No encryption in play. Write v1 — which, since the server stopped
    /// accepting unencrypted entries, only [`Backend::Local`] can take.
    Plaintext,
    /// The account is encrypted and this session can seal. Write v2.
    Sealed(&'a K),
    /// The account is encrypted and this session cannot seal — locked, or
    /// not yet known to be either. Refuse.
    Locked,
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
    /// A server-backed write with nothing to seal it with: the account has
    /// no encryption, and the server only stores entries for accounts that
    /// do (invariant E9).
    ///
    /// Distinct from [`StorageError::Locked`], which is a *device* that
    /// holds no key for an account that has one — retrying after an unlock
    /// fixes that, and nothing fixes this but setting encryption up. The
    /// server refuses the same write on the same grounds; refusing here as
    /// well only means a save that could never land does not travel.
    #[error("`{key}` cannot be stored: this account has no encryption set up")]
    EncryptionRequired { key: String },
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
/// hand (spec E3). One reader serves both shapes: `localStorage` is v1 by
/// design and an account's rows are v2, and the same device moves between
/// the two on every sign-in, so each row has to carry its own answer.
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
/// The backend and `session` together pick the envelope version and decide
/// whether there is a write at all — see [`write_target`], which is where
/// both refusals live, and `WriteTarget::sealing`, which is where the
/// version itself is chosen. [`WriteKey::Sealed`] seals and writes v2 (see
/// [`envelope::wrap`]); [`WriteKey::Plaintext`] writes v1, which only
/// [`Backend::Local`] may take. Readers never consult that choice.
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
pub fn store(
    backend: Backend,
    key: StorageKey,
    value: &str,
    session: WriteKey<'_>,
) -> impl Future<Output = Result<(), StorageError>> + use<> {
    let value = value.to_owned();
    let target = write_target(backend, key, session);
    async move {
        let target = target?;
        #[cfg(feature = "hydrate")]
        {
            let wrapped = envelope::wrap(&value, target.sealing())
                .await
                .map_err(|err| StorageError::Crypto {
                    key: key.as_key(),
                    detail: err.to_string(),
                })?;
            match target {
                WriteTarget::Local => local::store(key, &wrapped).await,
                WriteTarget::Remote(_) => remote::store(key, &wrapped).await,
            }
        }
        #[cfg(not(feature = "hydrate"))]
        {
            let _ = (key, value, target);
            Ok(())
        }
    }
}

/// Where a write is going, and what it does to the body on the way.
///
/// One value rather than the `(Backend, WriteKey)` pair the caller holds,
/// because one of those pairs must not exist: an unsealed write to
/// [`Backend::Remote`] is the plaintext row the server now refuses outright
/// (invariant E9), and invariant E7 already says nothing downstream would
/// notice one. With the two resolved into a single value, `Remote` cannot
/// be *reached* except through an arm that is carrying a key — a later edit
/// to [`store`]'s dispatch cannot write a plaintext row to the server
/// without inventing a variant to say so.
///
/// **Why the pair is resolved rather than refused by a signature.** Both
/// halves are runtime values — the backend follows `AuthCtx::user`, the
/// write key follows a probe of the account — so no call site holds them at
/// compile time and no signature could reject the combination there. The
/// type earns its keep on the other side of the check instead: everything
/// after [`write_target`] is unable to express the pair at all.
///
/// Owned rather than borrowed because [`store`] hands its future to
/// `spawn_local`, which needs `'static`. Generic over the key, defaulted to
/// [`SessionKey`], for the reason `decide_row` is generic over its own: the
/// sealed arm has no host representative otherwise, and the decision it
/// carries would then be asserted nowhere.
enum WriteTarget<K = SessionKey> {
    /// `localStorage`, always v1. Plaintext by design: the store belongs to
    /// the device rather than to an account, and this is the mode the
    /// signed-out visitor — and anyone who takes the "use this device only"
    /// way out — lives in (spec section 1.2's non-goal).
    Local,
    /// The server, sealed under this session's key. There is deliberately
    /// no unsealed arm.
    Remote(K),
}

impl<K> WriteTarget<K> {
    /// The key [`envelope::wrap`] should seal under, if any — the whole of
    /// what makes a remote write v2 rather than v1.
    ///
    /// Compiled and asserted on the host rather than left to the browser
    /// build, because this is the one write decision whose failure has no
    /// downstream witness. The server refuses an unencrypted *account*
    /// (invariant E9) but can never refuse a plaintext *body*, since
    /// invariant E1 forbids it from looking at one — so a `Remote` arm
    /// returning `None` here would post plaintext into an encrypted account
    /// with every other guard in the system still passing.
    #[cfg(any(feature = "hydrate", test))]
    fn sealing(&self) -> Option<&K> {
        match self {
            WriteTarget::Local => None,
            WriteTarget::Remote(session) => Some(session),
        }
    }
}

/// Pairs the backend with what the session can do, refusing the two
/// combinations that must never reach a backend.
///
/// **The single place either write refusal is made**, shared by [`store`]
/// and — through it — by [`clear`]. A second write path that decided this
/// for itself is exactly how a refusal gets lost: nothing downstream would
/// notice an encrypted account taking a v1 row (invariant E7), and nothing
/// on this side would notice a plaintext body being posted to an account
/// that cannot legally hold one (invariant E9).
///
/// The refusals are decided here rather than inside [`store`]'s `cfg`
/// branches, so they hold on every target and cost no backend call — a
/// refused write is not a write that failed partway, it is one that never
/// started.
fn write_target<K: Clone>(
    backend: Backend,
    key: StorageKey,
    session: WriteKey<'_, K>,
) -> Result<WriteTarget<K>, StorageError> {
    let sealing = match session {
        WriteKey::Plaintext => None,
        // `Option::cloned`, not a direct `session.clone()`: with the default
        // `SessionKey`, on a target where it is uninhabited this arm cannot
        // be reached, and cloning the key itself would say so as an
        // `unreachable_code` warning. Going through the `Option` keeps the
        // expression's type inhabited and the arm silent.
        WriteKey::Sealed(session) => Some(session).cloned(),
        WriteKey::Locked => return Err(StorageError::Locked { key: key.as_key() }),
    };

    match (backend, sealing) {
        // `Local` writes v1 whatever the session holds. `localStorage` is
        // never encrypted (spec section 1.2), and a row sealed there under a
        // key the signed-out reader will not have is a row nothing can open
        // again. The pairing barely arises — the backend follows
        // `AuthCtx::user`, so a session holding a key is normally on
        // `Remote` — but it needs an answer, and this is the safe one.
        (Backend::Local, _) => Ok(WriteTarget::Local),
        (Backend::Remote, Some(session)) => Ok(WriteTarget::Remote(session)),
        (Backend::Remote, None) => Err(StorageError::EncryptionRequired { key: key.as_key() }),
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
/// version. That inheritance carries invariant E9 too: a clear is a write,
/// so an account with no encryption cannot make one either.
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
    use crate::encryption_ctx::{EncryptionState, Writes};
    use crate::test_util::block_on;

    fn d(y: i32, m: u32, day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(y, m, day).expect("valid date")
    }

    /// Stands in for the session key. `decide_row` and `write_target` are
    /// generic over the key and never look inside one, so a byte does the
    /// job here.
    ///
    /// It is a readable placeholder, not a discriminator: only one key is
    /// ever in scope, and a function generic over `K` with a single `&K` to
    /// hand has nothing else it could return, so `*k == SESSION` cannot fail
    /// against a type-correct implementation. What the sealed-row assertions
    /// below actually pin is the *ciphertext* travelling with the decision;
    /// what the write assertions pin is `Some` against `None`.
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

    /// The round trip any report of a failed day depends on: a
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
    /// A plaintext row in an encrypted account is invisible afterwards — a
    /// v1 row is exactly what a device with no account legitimately writes,
    /// so nothing about the row itself says the body had been exposed.
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

    /// Invariant E9's half of the seam: a body with nothing to seal it may
    /// still go to `localStorage`, which is plaintext by design, and must
    /// not go to the server, which no longer accepts one.
    ///
    /// The server refuses the same write on the same grounds — that is the
    /// half that holds against a client which skips this one, and
    /// `tests/entry_access.rs` is where it is pinned. This is what stops a
    /// save that could never land from travelling at all, and it is asserted
    /// on a target with no browser storage and no network precisely because
    /// the decision is made before either could be reached.
    #[test]
    fn a_remote_write_with_no_key_is_refused_rather_than_sent_in_the_clear() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        assert_eq!(
            block_on(store(
                Backend::Remote,
                key,
                "9-10 code1",
                WriteKey::Plaintext
            )),
            Err(StorageError::EncryptionRequired { key: key.as_key() })
        );
        assert_eq!(
            block_on(clear(Backend::Remote, key, WriteKey::Plaintext)),
            Err(StorageError::EncryptionRequired { key: key.as_key() }),
            "clearing a day on `Remote` is a write of an empty body, not a delete"
        );
        assert_eq!(
            block_on(store(
                Backend::Local,
                key,
                "9-10 code1",
                WriteKey::Plaintext
            )),
            Ok(()),
            "`localStorage` keeps the plaintext route it is built on"
        );
    }

    /// The other half of that seam, and the half nothing used to assert: a
    /// remote write does not merely *reach* the server, it reaches it
    /// sealed. `store` picks the envelope from `sealing()`, so this pins
    /// the choice that makes an account's rows v2.
    ///
    /// The `Some`/`None` distinction is the whole of what it discriminates,
    /// and that is the distinction that matters: the server cannot catch a
    /// plaintext body, because invariant E1 forbids it from looking at one,
    /// so a `Remote` arm quietly answering `None` would be caught nowhere
    /// else in the system.
    ///
    /// Reachable at all only because `WriteTarget` is generic over the key:
    /// `SessionKey` is uninhabited here, so `(Remote, Sealed)` has no host
    /// representative of its own.
    #[test]
    fn a_remote_write_is_sealed_under_the_key_it_was_given() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        let target = write_target(Backend::Remote, key, WriteKey::Sealed(&SESSION))
            .expect("a session that can seal may write to the server");
        assert!(matches!(target, WriteTarget::Remote(k) if k == SESSION));
        assert_eq!(
            target.sealing(),
            Some(&SESSION),
            "a body bound for the server must be sealed, not merely addressed there"
        );
    }

    /// The same decision in the direction that would cost data the other
    /// way: `localStorage` is read by signed-out sessions holding no key,
    /// so a row sealed there is a row nothing can open again.
    #[test]
    fn a_local_write_stays_unsealed_even_with_a_key_in_hand() {
        let key = StorageKey::TimeEntry(d(2026, 9, 4));
        let target = write_target(Backend::Local, key, WriteKey::Sealed(&SESSION))
            .expect("`localStorage` takes a write from any session that is not locked");
        assert_eq!(target.sealing(), None);
    }

    /// The property this whole feature turns on, driven from *both* sides
    /// rather than asserted about one of them.
    ///
    /// [`crate::encryption_ctx::EncryptionState::writes`] is what the day and
    /// week views render themselves from; [`write_target`] is what a save
    /// actually meets. If those two ever disagreed, the entry area would
    /// invite a keystroke the save then refused — the exact silence `Writes`
    /// exists to end — and nothing downstream would notice, because a refused
    /// write is not one that failed partway, it is one that never started.
    ///
    /// Until this test the agreement was held by two hand-written `match`es
    /// in two modules and by prose: the sibling assertion in `encryption_ctx`
    /// names the property but calls only `writes`, so `write_target` could be
    /// given an arm accepting what the gate refuses and every test in the
    /// crate would still pass. This is the cross-check, and it fails on drift
    /// in either direction.
    ///
    /// `EncryptionState::Unlocked` is absent because it carries a
    /// `SessionKey`, uninhabited off the browser — and it is the one arm the
    /// two share by construction anyway, since `writes` reads `write_key` and
    /// `write_target` consumes what `write_key` returns.
    #[test]
    fn the_gate_and_the_seam_agree_on_every_state_a_host_can_build() {
        // Carried as names because `EncryptionState` is deliberately not
        // `Debug`: on the browser it holds key material.
        let states = [
            ("Unknown", EncryptionState::Unknown),
            ("Unreachable", EncryptionState::Unreachable),
            ("Locked", EncryptionState::Locked),
            ("Disabled", EncryptionState::Disabled),
        ];
        let key = StorageKey::TimeEntry(d(2026, 9, 4));

        for backend in [Backend::Local, Backend::Remote] {
            for (name, state) in &states {
                // The one question both sides can be asked: does a save
                // made right now land?
                let seam = write_target(backend, key, state.write_key()).is_ok();
                let gate = state.writes(backend) == Writes::Accepted;
                assert_eq!(
                    seam,
                    gate,
                    "{name} on {backend:?}: the view says a save {}, the seam {}",
                    if gate { "lands" } else { "does not land" },
                    if seam { "takes it" } else { "refuses it" },
                );
            }
        }
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

    /// Spec E3, in the direction that costs data if it is lost: holding a
    /// key must not make the reader assume every row was sealed under it.
    ///
    /// Not a before-and-after that will age out, either. One reader serves
    /// `localStorage`, which is v1 by design, and the account's rows, which
    /// are v2; and whether a key is in hand follows the encryption state
    /// rather than the backend, so a sign-in moving the device between the
    /// two can pair either shape with either answer.
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

    /// Both shapes in one week, each decided on its own `v` (spec E3), at
    /// range width rather than one row at a time: the week view reads a
    /// whole range in one call, so a single row of the older shape must cost
    /// that row's content at worst, never the week's.
    #[test]
    fn a_mixed_v1_and_v2_range_decides_every_row_on_its_own_version() {
        let rows = vec![
            (d(2026, 9, 1), envelope::wrap_v1("a")),
            (d(2026, 9, 2), sealed(7)),
            (d(2026, 9, 3), envelope::wrap_v1("b")),
        ];
        let decided = decide_rows(rows, Some(&SESSION)).rows;
        assert_eq!(decided.len(), 3, "a mixed-version range must lose no rows");
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
