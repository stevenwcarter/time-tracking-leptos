//! Reading and writing one day's entry, and range queries.
//!
//! Bodies are **opaque** on this boundary in both directions. Nothing here
//! parses, validates, or inspects an entry beyond a length cap — phase 2
//! sends ciphertext through these same functions and the server will not
//! hold the key (spec section 9.1).

use leptos::prelude::*;

/// Refuses absurd inputs without inspecting them. Generous: a long day of
/// notes is a few kilobytes, and phase-2 ciphertext is larger than its
/// plaintext.
#[cfg(feature = "ssr")]
const MAX_BODY_BYTES: usize = 256 * 1024;

/// Widest span a single range query may cover, so one request cannot ask for
/// a decade.
#[cfg(feature = "ssr")]
const MAX_RANGE_DAYS: i64 = 366;

/// The most rows one bulk write may carry, and the most bytes across all of
/// them.
///
/// The per-body cap alone does not bound a batch: 256 KiB times "however
/// many rows the client sent" is not a limit, and every row is written
/// inside one SQLite transaction on a single-process WAL database with a
/// 5 s `busy_timeout`. The row count is the half nothing else bounds —
/// tens of thousands of small rows fit inside any byte limit.
///
/// The byte cap is deliberately *below* the request-size limit the
/// server-fn layer already imposes (a couple of MiB, at which a batch is
/// rejected as `Deserialization: length limit exceeded`). That limit is
/// somebody else's implementation detail and its message tells a user
/// nothing, so this endpoint states its own bound and refuses in its own
/// words before reaching it.
///
/// Both sit above what `storage::store_many` sends (100 rows, 512 KiB), so
/// a migration that chunks the way this crate's own client does never meets
/// either. What they refuse is a caller that does not.
#[cfg(feature = "ssr")]
const MAX_BATCH_ROWS: usize = 200;

#[cfg(feature = "ssr")]
const MAX_BATCH_BYTES: usize = 1024 * 1024;

#[cfg(feature = "ssr")]
fn parse_date(raw: &str) -> Result<chrono::NaiveDate, ServerFnError> {
    crate::date::parse_iso(raw).ok_or_else(|| super::server_err("Invalid date"))
}

#[cfg(feature = "ssr")]
fn parse_range(
    from: &str,
    to: &str,
) -> Result<(chrono::NaiveDate, chrono::NaiveDate), ServerFnError> {
    let from = parse_date(from)?;
    let to = parse_date(to)?;
    if to < from {
        return Err(super::server_err("Invalid date range"));
    }
    if (to - from).num_days() > MAX_RANGE_DAYS {
        return Err(super::server_err("Date range is too wide"));
    }
    Ok((from, to))
}

/// One day's stored body, or `None` if that day has nothing saved.
#[server(endpoint = "entries/load")]
pub async fn entry_load(date: String) -> Result<Option<String>, ServerFnError> {
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let date = parse_date(&date)?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    repo::load(&mut conn, me.id, date)
        .map_err(super::log_and_fail("entry load", "Internal server error"))
}

/// Writes one day's body, replacing whatever was there.
#[server(endpoint = "entries/save")]
pub async fn entry_save(date: String, body: String) -> Result<(), ServerFnError> {
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let date = parse_date(&date)?;
    if body.len() > MAX_BODY_BYTES {
        return Err(super::server_err("That entry is too large to save"));
    }
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    repo::save(&mut conn, me.id, date, &body)
        .map_err(super::log_and_fail("entry save", "Internal server error"))
}

/// Which days in the range have an entry. Dates only — see the note on
/// `repo::dates_in_range` for why this is not the same call as
/// [`entries_in_range`].
#[server(endpoint = "entries/dates")]
pub async fn entry_dates_in_range(from: String, to: String) -> Result<Vec<String>, ServerFnError> {
    use crate::date::to_iso;
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let (from, to) = parse_range(&from, &to)?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(repo::dates_in_range(&mut conn, me.id, from, to)
        .map_err(super::log_and_fail(
            "dates in range",
            "Internal server error",
        ))?
        .into_iter()
        .map(to_iso)
        .collect())
}

/// Every entry in the range, bodies included and uninterpreted.
///
/// The week view aggregates these **in the browser**. Doing it here would be
/// impossible once bodies are encrypted, so it is not done here now.
#[server(endpoint = "entries/range")]
pub async fn entries_in_range(
    from: String,
    to: String,
) -> Result<Vec<(String, String)>, ServerFnError> {
    use crate::date::to_iso;
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let (from, to) = parse_range(&from, &to)?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(repo::entries_in_range(&mut conn, me.id, from, to)
        .map_err(super::log_and_fail(
            "entries in range",
            "Internal server error",
        ))?
        .into_iter()
        .map(|(d, b)| (to_iso(d), b))
        .collect())
}

/// Every entry the caller has ever saved, bodies included and uninterpreted,
/// with no date bounds.
///
/// This exists to feed the encryption migration pass (spec section 8): the
/// client needs every row to find which still carry a `v: 1` envelope, and
/// answering that server-side would mean inspecting envelope versions —
/// parsing bodies, which invariant E1 forbids outright.
#[server(endpoint = "entries/all")]
pub async fn entries_all() -> Result<Vec<(String, String)>, ServerFnError> {
    use crate::date::to_iso;
    use crate::entries::repo;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(repo::entries_all(&mut conn, me.id)
        .map_err(super::log_and_fail("entries all", "Internal server error"))?
        .into_iter()
        .map(|(d, b)| (to_iso(d), b))
        .collect())
}

/// The two ways the batch transaction in [`entry_save_many`] can fail: an
/// expected, user-facing refusal (bad date, oversized body) versus an
/// unexpected database error.
///
/// Diesel's `transaction` needs one error type for the whole closure, and
/// the two must stay distinguishable: reporting a refusal as `Ok(Err(..))`
/// (the way `encryption_enable` reports its "already enabled" refusal)
/// would have `transaction` **commit** the entries already written earlier
/// in the same loop, since Diesel only rolls back on an `Err` return —
/// `encryption_enable` gets away with `Ok(Err(..))` only because that check
/// runs before any write. Reporting a refusal's message as a plain
/// `anyhow::Error` string would go the other way and work, but a genuine
/// `Db` error's message would then flow straight to the caller too,
/// breaking `server_err`'s rule that a user-facing message never carries
/// internal detail.
#[cfg(feature = "ssr")]
enum SaveManyError {
    Refused(&'static str),
    Db(anyhow::Error),
}

#[cfg(feature = "ssr")]
impl From<diesel::result::Error> for SaveManyError {
    fn from(err: diesel::result::Error) -> Self {
        SaveManyError::Db(err.into())
    }
}

/// Writes every `(date, body)` pair in one call, one transaction — the write
/// half of the encryption migration pass (spec section 8). Applies
/// `entry_save`'s own length cap to each body; a bulk endpoint that skipped
/// it would be a way around the limit.
///
/// The batch as a whole is capped too, on both row count and total bytes,
/// and *before* the transaction opens rather than inside it: refusing an
/// oversized request should not first take the database's write lock. See
/// [`MAX_BATCH_ROWS`].
///
/// Each entry is validated and written in the same pass through the loop,
/// rather than validated up front and written in a second pass: only that
/// ordering lets an entry rejected partway through undo the entries already
/// written ahead of it in the same call, via the transaction's rollback.
/// That rollback scopes one *call*; a migration pass is several of them, and
/// spec section 8's per-row dispatch is what makes a pass that stops
/// between calls resumable rather than half-broken.
#[server(endpoint = "entries/save_many")]
pub async fn entry_save_many(entries: Vec<(String, String)>) -> Result<(), ServerFnError> {
    use diesel::prelude::*;

    use crate::date::parse_iso;
    use crate::entries::repo;

    let (ctx, me) = super::require_user()?;

    if entries.len() > MAX_BATCH_ROWS {
        return Err(super::server_err("That's too many entries in one request"));
    }
    if entries.iter().map(|(_, body)| body.len()).sum::<usize>() > MAX_BATCH_BYTES {
        return Err(super::server_err(
            "That batch of entries is too large to save",
        ));
    }

    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    let result = conn.transaction::<(), SaveManyError, _>(|conn| {
        for (date, body) in &entries {
            let date = parse_iso(date).ok_or(SaveManyError::Refused("Invalid date"))?;
            if body.len() > MAX_BODY_BYTES {
                return Err(SaveManyError::Refused("That entry is too large to save"));
            }
            repo::save(conn, me.id, date, body).map_err(SaveManyError::Db)?;
        }
        Ok(())
    });

    result.map_err(|err| match err {
        SaveManyError::Refused(msg) => super::server_err(msg),
        SaveManyError::Db(err) => {
            super::log_and_fail("entry save many", "Internal server error")(err)
        }
    })
}
