//! The unlocked data key, remembered per device.
//!
//! One record — `{ user, key }` stored under the id `"dek"`, in object store
//! `keys` of database `tt-keys` — holds the [`DataKey`] a successful unlock
//! produced, so a reload does not prompt for the passkey again (spec section
//! 7.3).
//!
//! **Why IndexedDB rather than `localStorage`.** A `CryptoKey` is
//! structured-cloneable, so IndexedDB can store a *non-extractable* key and
//! hand it back still non-extractable: script on the page can decrypt with
//! it but cannot read its bytes out or send them anywhere. `localStorage`
//! holds strings and nothing else, so persisting a key there would mean
//! writing raw key bytes into a store any script can read — strictly worse,
//! for exactly the same convenience. That is the whole reason this file is
//! shaped around an event-based API instead of a two-line `set_item` call
//! (invariant E5).
//!
//! **Not covered by any automated test, and cannot be.** IndexedDB exists
//! only in a browser and this project has no wasm test runner, so — like
//! [`super::subtle`] — this file is reviewed by reading it. The thing a
//! reviewer must check by eye, because nothing else will:
//!
//! 1. [`get`] compares the stored `user` against its argument and returns
//!    `Ok(None)` on a mismatch, discarding the record. Two accounts sharing
//!    one browser is ordinary — a work login and a personal one — and
//!    handing account B the key stored for account A produces decryption
//!    failures indistinguishable from data corruption.
//! 2. Every failure path returns `Err` or `Ok(None)`; nothing here panics.
//!    A private window, cleared site data, IndexedDB switched off, an open
//!    blocked by another connection — all of these are ordinary, and all of
//!    them must land the session on `Locked` with an unlock prompt. The user
//!    still has their passkey and their recovery code; a panic would take
//!    both away from them.
//!
//! No error raised here carries key material: failures name the IndexedDB
//! operation and the `DOMException` that ended it, nothing else.

use js_sys::{Function, Object, Promise, Reflect};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::JsFuture;
use web_sys::{IdbDatabase, IdbObjectStore, IdbRequest, IdbTransactionMode};

use super::subtle::{CryptoError, DataKey, failed, js_object};

/// The database this feature owns; nothing else in the app uses IndexedDB.
const DB_NAME: &str = "tt-keys";
/// Raising this reruns `onupgradeneeded` on every device. There is nothing
/// to migrate yet, and a bump is also the only way `onblocked` below can
/// fire, so it is not a free change.
const DB_VERSION: u32 = 1;
/// The one object store.
const STORE: &str = "keys";
/// The one record's key: a device holds at most one unlocked data key.
const RECORD: &str = "dek";
/// Record field: the account the stored key belongs to.
const USER_FIELD: &str = "user";
/// Record field: the `CryptoKey` itself.
const KEY_FIELD: &str = "key";

/// A rejection value shaped the way [`failed`] expects.
///
/// It reads `name` off whatever it is handed — which a `DOMException`
/// carries — so a reason synthesized here has to carry one too.
fn reason(name: &str) -> JsValue {
    js_object(&[("name", name.into())]).into()
}

/// Bridges one request's `success` and `error` events onto a promise's
/// `resolve` and `reject`. IndexedDB is event-based; everything below is
/// `await`ed through this.
///
/// **Closure lifetime.** Each handler is a [`Closure::once_into_js`], which
/// hands the boxed Rust closure to JS: assigning the returned value to
/// `onsuccess` gives the request its own reference, so dropping our
/// `JsValue` when this function returns does not free it. A borrowed
/// `Closure` would be dropped here instead, detaching the handler — and the
/// promise would then never settle, which surfaces as a hang rather than as
/// an error. The handler that never fires (the `error` one on a request that
/// succeeds) leaks its box: tens of bytes per keystore call, which is the
/// trade this API is designed around.
fn set_handlers(request: &IdbRequest, resolve: &Function, reject: &Function) {
    let succeeded = request.clone();
    let resolve = resolve.clone();
    let on_success = Closure::once_into_js(move || {
        // `result` throws only while the request is still pending, which is
        // not the case inside its own success event.
        let value = succeeded.result().unwrap_or(JsValue::UNDEFINED);
        resolve.call1(&JsValue::UNDEFINED, &value).ok();
    });
    request.set_onsuccess(Some(on_success.unchecked_ref()));

    let errored = request.clone();
    let reject = reject.clone();
    let on_error = Closure::once_into_js(move || {
        let thrown = match errored.error() {
            Ok(Some(exception)) => exception.into(),
            _ => reason("the request reported no error"),
        };
        reject.call1(&JsValue::UNDEFINED, &thrown).ok();
    });
    request.set_onerror(Some(on_error.unchecked_ref()));
}

/// Awaits one ordinary `IDBRequest`.
fn settle(request: &IdbRequest) -> Promise {
    let request = request.clone();
    Promise::new(&mut |resolve, reject| set_handlers(&request, &resolve, &reject))
}

/// Opens `tt-keys`, creating the object store on a device's first use.
///
/// `onupgradeneeded` fires *before* `onsuccess` on a first open and is the
/// only place the store can be created; without it every later transaction
/// fails with `NotFoundError`.
///
/// `onblocked` fires instead of either when another connection is holding an
/// older version open. It is unreachable while [`DB_VERSION`] stays at 1 and
/// every call closes its connection, but it is wired to `reject` anyway,
/// because unhandled it is the one path that would hang instead of failing.
async fn open_db() -> Result<IdbDatabase, CryptoError> {
    let window = web_sys::window().ok_or_else(|| CryptoError("no window".to_string()))?;
    let factory = window
        .indexed_db()
        .map_err(|e| failed("indexedDB", &e))?
        .ok_or_else(|| CryptoError("IndexedDB is unavailable in this browser".to_string()))?;
    let request = factory
        .open_with_u32(DB_NAME, DB_VERSION)
        .map_err(|e| failed("indexedDB.open", &e))?;

    let promise = Promise::new(&mut |resolve, reject| {
        set_handlers(&request, &resolve, &reject);

        let upgrading = request.clone();
        let on_upgrade = Closure::once_into_js(move || {
            let Ok(opened) = upgrading.result() else {
                return;
            };
            let Ok(db) = opened.dyn_into::<IdbDatabase>() else {
                return;
            };
            // Reached only when this version of the store does not exist
            // yet, so it cannot meaningfully fail; if it somehow did, the
            // transaction that follows reports it and nothing panics.
            db.create_object_store(STORE).ok();
        });
        request.set_onupgradeneeded(Some(on_upgrade.unchecked_ref()));

        let on_blocked = Closure::once_into_js(move || {
            reject
                .call1(
                    &JsValue::UNDEFINED,
                    &reason("blocked by another connection"),
                )
                .ok();
        });
        request.set_onblocked(Some(on_blocked.unchecked_ref()));
    });

    JsFuture::from(promise)
        .await
        .map_err(|e| failed("indexedDB.open", &e))?
        .dyn_into::<IdbDatabase>()
        .map_err(|_| CryptoError("indexedDB.open resolved to something else".to_string()))
}

/// Opens a transaction over the one object store.
///
/// The caller has to issue its request before the next `await`: a
/// transaction goes inactive as soon as the event loop turns with nothing
/// pending on it, and using it after that throws `TransactionInactiveError`.
fn store(db: &IdbDatabase, mode: IdbTransactionMode) -> Result<IdbObjectStore, CryptoError> {
    db.transaction_with_str_and_mode(STORE, mode)
        .map_err(|e| failed("transaction", &e))?
        .object_store(STORE)
        .map_err(|e| failed("objectStore", &e))
}

/// Writes the record, replacing whatever was under `"dek"`.
///
/// What is awaited is the request, not the transaction's commit. A commit
/// that then fails — a full disk, an eviction — leaves the device with no
/// stored key, which is exactly the state it was in before: the next load
/// lands on `Locked` and asks for an unlock.
async fn put_in(db: &IdbDatabase, user: &str, key: &DataKey) -> Result<(), CryptoError> {
    let record = js_object(&[
        (USER_FIELD, JsValue::from_str(user)),
        (KEY_FIELD, key.0.clone().into()),
    ]);
    let request = store(db, IdbTransactionMode::Readwrite)?
        .put_with_key(&record, &RECORD.into())
        .map_err(|e| failed("put", &e))?;

    JsFuture::from(settle(&request))
        .await
        .map_err(|e| failed("put", &e))?;
    Ok(())
}

/// Reads the record and decides whether it belongs to `user`.
async fn get_from(db: &IdbDatabase, user: &str) -> Result<Option<DataKey>, CryptoError> {
    let request = store(db, IdbTransactionMode::Readonly)?
        .get(&RECORD.into())
        .map_err(|e| failed("get", &e))?;
    let record = JsFuture::from(settle(&request))
        .await
        .map_err(|e| failed("get", &e))?;

    // Nothing stored on this device — a first visit, a private window, or
    // site data the user cleared. The ordinary answer, not a failure.
    if record.is_undefined() || record.is_null() {
        return Ok(None);
    }

    // The rule this whole module turns on: the key stored for one account is
    // never handed to another. A stored `user` that is absent, unreadable,
    // or simply someone else's all mean the same thing here.
    let stored_user = Reflect::get(&record, &USER_FIELD.into())
        .ok()
        .and_then(|value| value.as_string());
    if stored_user.as_deref() != Some(user) {
        discard(db).await;
        return Ok(None);
    }

    let key = Reflect::get(&record, &KEY_FIELD.into())
        .ok()
        .and_then(|value| value.dyn_into::<Object>().ok());
    let Some(key) = key else {
        // A record with no usable key in it is worse than no record: it
        // would be re-read on every load and never work. Drop it.
        discard(db).await;
        return Ok(None);
    };
    Ok(Some(DataKey(key)))
}

/// Removes the record.
async fn delete_from(db: &IdbDatabase) -> Result<(), CryptoError> {
    let request = store(db, IdbTransactionMode::Readwrite)?
        .delete(&RECORD.into())
        .map_err(|e| failed("delete", &e))?;

    JsFuture::from(settle(&request))
        .await
        .map_err(|e| failed("delete", &e))?;
    Ok(())
}

/// Removes the record on a read path that refuses to hand its key back,
/// ignoring failures.
///
/// The answer to the caller is `None` whether or not the delete lands — the
/// key was not returned either way — so a failure here must not turn that
/// answer into an error.
async fn discard(db: &IdbDatabase) {
    let _ = delete_from(db).await;
}

/// Stores the unlocked key for this device, replacing any earlier one.
///
/// Called at the end of the enable ceremony and of every unlock, so the next
/// load of this browser finds a key and never prompts.
pub async fn put(user: &str, key: &DataKey) -> Result<(), CryptoError> {
    let db = open_db().await?;
    let stored = put_in(&db, user, key).await;
    // Closed explicitly rather than left to garbage collection: a lingering
    // connection is what would make a future `DB_VERSION` bump block.
    db.close();
    stored
}

/// Reads the key back, if this device holds one **for `user`**.
///
/// `Ok(None)` covers every ordinary "no key here": a device that has never
/// unlocked, a private window, cleared site data, and a record belonging to
/// a different account. `Err` means IndexedDB itself was unusable. Callers
/// treat both as `Locked` and prompt for an unlock — the difference is only
/// worth logging.
pub async fn get(user: &str) -> Result<Option<DataKey>, CryptoError> {
    let db = open_db().await?;
    let found = get_from(&db, user).await;
    db.close();
    found
}

/// Forgets this device's key. Sign-out and "Lock now" both call it.
///
/// Deleting a record that is not there succeeds, so this is safe to call
/// unconditionally — including on a device that never stored one.
pub async fn clear() -> Result<(), CryptoError> {
    let db = open_db().await?;
    let cleared = delete_from(&db).await;
    db.close();
    cleared
}
