//! `localStorage` backend, compiled only into the wasm bundle.
//!
//! Deliberately thin: the wire format lives in [`super::codec`], which is
//! host-testable, while this file is only the `web_sys` plumbing.

use chrono::NaiveDate;

use super::{StorageError, StorageKey, codec};

fn storage() -> Result<web_sys::Storage, StorageError> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or(StorageError::Unavailable)
}

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    let key_str = key.as_key();
    let raw = storage()?
        .get_item(&key_str)
        .map_err(|_| StorageError::Unavailable)?;

    match raw {
        None => Ok(None),
        Some(raw) => codec::decode(&raw)
            .map(Some)
            .map_err(|source| StorageError::Decode {
                key: key_str,
                source,
            }),
    }
}

pub async fn store(key: StorageKey, value: &str) -> Result<(), StorageError> {
    let key_str = key.as_key();
    storage()?
        .set_item(&key_str, &codec::encode(&value))
        .map_err(|_| StorageError::Write { key: key_str })
}

pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    let key_str = key.as_key();
    storage()?
        .remove_item(&key_str)
        .map_err(|_| StorageError::Write { key: key_str })
}

/// Stub — Task 16 owns the real key scan over `localStorage` (and the
/// normalization of [`super::LEGACY_KEY`] into the dated format). Returning
/// an empty range keeps `storage::mod` compiling until then.
pub async fn dates_with_entries(
    _from: NaiveDate,
    _to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    Ok(Vec::new())
}
