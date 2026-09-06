//! Reading and writing one day's entry, and range queries.
//!
//! Bodies are **opaque** on this boundary in both directions. Nothing here
//! parses, validates, or inspects an entry beyond a length cap — what these
//! functions carry is ciphertext and the server holds no key for it (spec
//! section 9.1, invariant E1).
//!
//! The one precondition a write has to meet is therefore a property of the
//! *account* rather than of the body: [`entry_save`] refuses unless
//! `user.encrypted_at` is set (invariant E9).

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
///
/// Refused unless the account has encryption enabled — invariant E9, and
/// the whole enforcement mechanism for it. The check reads
/// `user.encrypted_at`, a property of the account *row*, and never the
/// body: a server that opened the envelope to see which version it carried
/// would be parsing an entry, which is precisely what invariant E1 forbids
/// and the reason week totals are aggregated in the browser. Once that were
/// acceptable, the next feature wanting to peek would have a precedent.
///
/// What the check buys: a correctly implemented client cannot store
/// plaintext here. What it does not: a *modified* client can enable
/// encryption and then post plaintext bodies anyway, and nothing on this
/// side could tell without reading them — the very thing being prevented.
/// That is the trust boundary the encryption design already records, noted
/// here so nobody later mistakes the gap for an oversight and closes it by
/// parsing.
///
/// Read in the same transaction as the write, so a save racing
/// `encryption_enable` sees one consistent account state rather than a
/// check and a write straddling two.
#[server(endpoint = "entries/save")]
pub async fn entry_save(date: String, body: String) -> Result<(), ServerFnError> {
    use diesel::prelude::*;

    use crate::entries::repo;
    use crate::entry_key::store;

    let (ctx, me) = super::require_user()?;
    let date = parse_date(&date)?;
    if body.len() > MAX_BODY_BYTES {
        return Err(super::server_err("That entry is too large to save"));
    }
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    // The inner `Result<(), &str>` is the outcome the caller sees: `Err` is
    // an expected, user-facing refusal, never a bug worth logging. Diesel
    // *commits* an `Ok(Err(..))` rather than rolling it back, which is safe
    // here for the same reason it is in `encryption_enable`: the refusal is
    // decided before this transaction has written anything.
    let outcome = conn
        .transaction::<Result<(), &'static str>, anyhow::Error, _>(|conn| {
            if !store::is_encrypted(conn, me.id)? {
                return Ok(Err(
                    "Set up encryption on this account before saving entries.",
                ));
            }
            repo::save(conn, me.id, date, &body)?;
            Ok(Ok(()))
        })
        .map_err(super::log_and_fail("entry save", "Internal server error"))?;

    outcome.map_err(super::server_err)
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
