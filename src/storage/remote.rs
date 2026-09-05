//! Server-backed storage, used when signed in.
//!
//! A thin adapter over the entry server functions. It moves envelope strings
//! and never inspects them — the server does not either (spec section 9.1).

use chrono::NaiveDate;
use leptos::prelude::ServerFnError;

use super::{StorageError, StorageKey};
use crate::date::{parse_iso, to_iso};
use crate::server_fns::entries;

fn server_error(e: ServerFnError) -> StorageError {
    StorageError::Server(e.to_string())
}

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    entries::entry_load(to_iso(key.date()))
        .await
        .map_err(server_error)
}

pub async fn store(key: StorageKey, envelope: &str) -> Result<(), StorageError> {
    entries::entry_save(to_iso(key.date()), envelope.to_string())
        .await
        .map_err(server_error)
}

/// Writes many days in one transaction, still envelope-wrapped.
///
/// The bulk half of the seam's [`store_many`](super::store_many): the
/// endpoint applies `entry_save`'s own length cap to each body and rolls the
/// whole batch back if any row is refused, which is what makes the migration
/// pass resumable rather than half-applied.
pub async fn store_many(rows: Vec<(NaiveDate, String)>) -> Result<(), StorageError> {
    entries::entry_save_many(
        rows.into_iter()
            .map(|(date, envelope)| (to_iso(date), envelope))
            .collect(),
    )
    .await
    .map_err(server_error)
}

pub async fn dates_with_entries(
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    Ok(entries::entry_dates_in_range(to_iso(from), to_iso(to))
        .await
        .map_err(server_error)?
        .iter()
        .filter_map(|s| parse_iso(s))
        .collect())
}

/// Every stored body in `[from, to]`, still envelope-wrapped — unwrapping
/// happens back in `mod.rs`, never here (see the module doc there).
pub async fn bodies_in_range(
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<(NaiveDate, String)>, StorageError> {
    Ok(entries::entries_in_range(to_iso(from), to_iso(to))
        .await
        .map_err(server_error)?
        .into_iter()
        .filter_map(|(date, body)| parse_iso(&date).map(|date| (date, body)))
        .collect())
}
