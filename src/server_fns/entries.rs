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
