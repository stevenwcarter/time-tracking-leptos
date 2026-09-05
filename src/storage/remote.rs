//! Server-backed storage, used when signed in.
//!
//! A thin adapter over the entry server functions. It moves envelope strings
//! and never inspects them — the server does not either (spec section 9.1).

use chrono::NaiveDate;
use leptos::prelude::ServerFnError;

use super::{StorageError, StorageKey, envelope};
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

/// Clearing a day writes an empty envelope rather than deleting the row.
///
/// "Cleared" and "never written" are the same thing to the reader, and an
/// empty row keeps the day's `updated_at` meaningful. It also means clear
/// and save take the same path, so there is one less server fn to authorize.
pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    store(key, &envelope::wrap("")).await
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
