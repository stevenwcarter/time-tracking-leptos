//! Server-backed storage, reached from the browser via server functions.
//!
//! Stub — Task 17 owns this file and replaces every function below with a
//! real call into the entry server functions. Kept minimal here only so
//! `storage::mod` compiles and its `Backend::Remote` path exists to test
//! against.

use chrono::NaiveDate;

use super::{StorageError, StorageKey};

/// Stub. Task 17 replaces this with a server-function call.
pub async fn load(_key: StorageKey) -> Result<Option<String>, StorageError> {
    Ok(None)
}

/// Stub. Task 17 replaces this with a server-function call.
pub async fn store(_key: StorageKey, _value: &str) -> Result<(), StorageError> {
    Ok(())
}

/// Stub. Task 17 replaces this with a server-function call.
pub async fn clear(_key: StorageKey) -> Result<(), StorageError> {
    Ok(())
}

/// Stub. Task 17 replaces this with a server-function call.
pub async fn dates_with_entries(
    _from: NaiveDate,
    _to: NaiveDate,
) -> Result<Vec<NaiveDate>, StorageError> {
    Ok(Vec::new())
}
