//! `localStorage` backend, compiled only into the wasm bundle.
//!
//! Deliberately thin: the wire format lives in [`super::codec`], which is
//! host-testable, while this file is only the `web_sys` plumbing.

use super::{StorageError, StorageKey, codec};

fn storage() -> Result<web_sys::Storage, StorageError> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .ok_or(StorageError::Unavailable)
}

pub async fn load(key: StorageKey) -> Result<Option<String>, StorageError> {
    let raw = storage()?
        .get_item(key.as_str())
        .map_err(|_| StorageError::Unavailable)?;

    match raw {
        None => Ok(None),
        Some(raw) => codec::decode(&raw)
            .map(Some)
            .map_err(|source| StorageError::Decode {
                key: key.as_str(),
                source,
            }),
    }
}

pub async fn store(key: StorageKey, value: &str) -> Result<(), StorageError> {
    storage()?
        .set_item(key.as_str(), &codec::encode(&value))
        .map_err(|_| StorageError::Write { key: key.as_str() })
}

pub async fn clear(key: StorageKey) -> Result<(), StorageError> {
    storage()?
        .remove_item(key.as_str())
        .map_err(|_| StorageError::Write { key: key.as_str() })
}
