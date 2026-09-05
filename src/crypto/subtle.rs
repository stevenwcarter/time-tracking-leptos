//! The `SubtleCrypto` calls.
//!
//! **Not covered by any automated test.** WebCrypto exists only in a browser
//! and this project has no wasm test runner. Everything decidable without a
//! browser was pushed into [`super::wire`] and [`super::recovery`], which are
//! host-tested; what is left here is the calls themselves. The wire format
//! they produce *is* pinned, by `wire`'s cross-implementation tests against
//! the `aes-gcm` crate — so a format error fails on the host. What only a
//! browser can catch is a wrong argument to `deriveKey` or a wrong
//! `extractable` flag. Review this file by reading it (spec section 10).
//!
//! The three things a reviewer should check by eye, because nothing else
//! will:
//!
//! 1. [`unwrap_dek`] is called with [`Extractable::Sealed`] everywhere except
//!    the single add-a-passkey path of spec section 6.5 (invariant E5).
//! 2. [`seal`] draws a fresh nonce per call and takes none from its caller.
//! 3. [`derive_kek`] passes [`APP_SALT`], never a fresh random salt
//!    (invariant E6).
//!
//! Everything reaches `window.crypto` through [`Reflect`] rather than
//! `web_sys::Crypto`, the same way [`crate::webauthn_browser`] reaches
//! `navigator.credentials`. That keeps this feature's `web-sys` growth to the
//! IndexedDB types the keystore needs (spec section 7.2).
//!
//! No error here carries key material, PRF output, a recovery code, or
//! plaintext: failures name the operation, never its inputs.

use js_sys::{Array, ArrayBuffer, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::wire::{self, APP_SALT, NONCE_LEN};

/// A WebCrypto operation failed. The `String` is for the log, never for the
/// user — callers map this to a human sentence themselves.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

/// A live, non-extractable AES-256-GCM key. Cloneable because `CryptoKey` is
/// a JS handle; cloning duplicates the handle, not the key material.
///
/// Deliberately not `Debug`: the point of the type is that its bytes cannot
/// be read, and a derived formatter is an invitation to log it anyway.
#[derive(Clone)]
pub struct DataKey(pub(crate) Object);

/// Whether an unwrapped key may have its bytes read back out.
///
/// [`Extractable::Sealed`] is correct everywhere except one path — adding a
/// passkey to an already-encrypted account (spec section 6.5), which must
/// re-wrap the raw data key under the new credential's KEK, uses the raw
/// handle immediately, and drops it.
///
/// This is an enum rather than a `bool` so that no call site can read
/// `unwrap_dek(w, k, true)` without saying what the `true` means. Getting it
/// backwards silently defeats the whole non-extractable design (invariant
/// E5) and no test in this project can catch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extractable {
    /// The key can be used but its bytes cannot be exported.
    Sealed,
    /// The key's bytes can be exported with [`export_raw`].
    Raw,
}

impl Extractable {
    /// The `extractable` argument WebCrypto expects.
    fn as_js(self) -> JsValue {
        match self {
            Self::Sealed => JsValue::FALSE,
            Self::Raw => JsValue::TRUE,
        }
    }
}

/// WebCrypto's name for the body cipher.
const AES_GCM: &str = "AES-GCM";
/// WebCrypto's name for the key-wrapping algorithm (AES-KW, RFC 3394).
const AES_KW: &str = "AES-KW";
/// The KDF every KEK is derived with.
const HKDF: &str = "HKDF";
/// HKDF's hash.
const SHA_256: &str = "SHA-256";
/// The only key format used here: unstructured bytes.
const RAW: &str = "raw";
/// Bit length of the data key and of every key-encryption key.
const KEY_BITS: u32 = 256;

/// `["encrypt", "decrypt"]` — everything a data key may do.
fn dek_usages() -> Array {
    Array::of2(&"encrypt".into(), &"decrypt".into())
}

/// `["wrapKey", "unwrapKey"]` — everything a key-encryption key may do.
/// Deliberately *not* `encrypt`/`decrypt`: a KEK's only job is the data key.
fn kek_usages() -> Array {
    Array::of2(&"wrapKey".into(), &"unwrapKey".into())
}

/// `["deriveKey"]` — everything imported HKDF input keying material may do.
fn ikm_usages() -> Array {
    Array::of1(&"deriveKey".into())
}

/// Builds a JS object literal.
///
/// `Reflect::set` on a freshly created, extensible `Object` with plain string
/// keys cannot fail, so its result is discarded — the same call shape, and
/// the same `.ok()`, that `webauthn_browser` uses to build its `publicKey`
/// argument.
///
/// Shared with [`super::keystore`], which builds its stored record the same
/// way.
pub(super) fn js_object(fields: &[(&str, JsValue)]) -> Object {
    let object = Object::new();
    for (name, value) in fields {
        Reflect::set(&object, &(*name).into(), value).ok();
    }
    object
}

/// Builds an argument array.
///
/// `SubtleCrypto::unwrapKey` takes seven arguments, past both
/// `Function::call3` and `Array::of5`, so every call in this module goes
/// through `Function::apply` with an array built here rather than switching
/// styles at the one long signature.
fn js_array(items: &[&JsValue]) -> Array {
    let array = Array::new();
    for item in items {
        array.push(item);
    }
    array
}

/// Reads the JS-side `name` of a thrown value and names the operation it came
/// from.
///
/// The exception's `message` is deliberately dropped. `name` is a closed set
/// of `DOMException` identifiers — `OperationError` for a failed
/// authentication, `InvalidAccessError` for a key used against the wrong
/// algorithm — which is enough to tell an expected failure from a bug, while
/// `message` is the one field an implementation could echo an argument into.
/// Every argument in this module is key material or plaintext.
///
/// Shared with [`super::keystore`], whose failures arrive as IndexedDB
/// `DOMException`s and carry a `name` in the same way.
pub(super) fn failed(operation: &str, thrown: &JsValue) -> CryptoError {
    let name = Reflect::get(thrown, &"name".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_else(|| "unknown error".to_string());
    CryptoError(format!("{operation} failed: {name}"))
}

/// A method is missing, or is not callable, on the object it was read from.
fn unavailable(name: &str) -> CryptoError {
    CryptoError(format!("{name} is unavailable in this browser"))
}

/// Reaches a callable property, as `webauthn_browser::browser::method` does.
fn method(on: &JsValue, name: &str) -> Result<Function, CryptoError> {
    Reflect::get(on, &name.into())
        .map_err(|_| unavailable(name))?
        .dyn_into::<Function>()
        .map_err(|_| unavailable(name))
}

/// `window.crypto`.
fn crypto() -> Result<Object, CryptoError> {
    let window = web_sys::window().ok_or_else(|| CryptoError("no window".to_string()))?;
    Reflect::get(&window, &"crypto".into())
        .map_err(|_| unavailable("window.crypto"))?
        .dyn_into::<Object>()
        .map_err(|_| unavailable("window.crypto"))
}

/// `window.crypto.subtle`.
///
/// Absent outside a secure context, which is why the error says so: served
/// over plain HTTP from anything but `localhost`, every function in this
/// module fails here and nowhere else.
fn subtle() -> Result<Object, CryptoError> {
    let crypto = crypto()?;
    Reflect::get(&crypto, &"subtle".into())
        .map_err(|_| unavailable("crypto.subtle"))?
        .dyn_into::<Object>()
        .map_err(|_| {
            CryptoError("crypto.subtle is unavailable; this page is not a secure context".into())
        })
}

/// Calls `crypto.subtle.<name>(...args)` and awaits the promise it returns.
///
/// Every `SubtleCrypto` method used here is promise-returning, so this is the
/// single place a WebCrypto call is made and the single place one is
/// classified.
async fn subtle_call(name: &str, args: &Array) -> Result<JsValue, CryptoError> {
    let subtle = subtle()?;
    let promise = method(&subtle, name)?
        .apply(&subtle, args)
        .map_err(|e| failed(name, &e))?
        .dyn_into::<Promise>()
        .map_err(|_| CryptoError(format!("crypto.subtle.{name} returned a non-Promise")))?;

    JsFuture::from(promise).await.map_err(|e| failed(name, &e))
}

/// Narrows a resolved `CryptoKey` to the handle callers pass back in.
fn as_key(operation: &str, resolved: JsValue) -> Result<Object, CryptoError> {
    resolved.dyn_into::<Object>().map_err(|_| {
        CryptoError(format!(
            "{operation} resolved to something other than a key"
        ))
    })
}

/// Copies a resolved `ArrayBuffer` out into owned bytes.
fn as_bytes(operation: &str, resolved: JsValue) -> Result<Vec<u8>, CryptoError> {
    let buffer = resolved.dyn_into::<ArrayBuffer>().map_err(|_| {
        CryptoError(format!(
            "{operation} resolved to something other than an ArrayBuffer"
        ))
    })?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

/// `crypto.getRandomValues(new Uint8Array(n))`.
///
/// The only source of randomness in this crate's browser half: the AES-GCM
/// nonce in [`seal`] and the recovery code's entropy both come from here.
pub fn random_bytes(n: usize) -> Result<Vec<u8>, CryptoError> {
    let length =
        u32::try_from(n).map_err(|_| CryptoError("requested too many random bytes".to_string()))?;
    let crypto = crypto()?;
    let buffer = Uint8Array::new_with_length(length);
    // `getRandomValues` fills the array it is handed and returns that same
    // array, so the filled bytes are read back off `buffer` rather than off
    // the return value.
    method(&crypto, "getRandomValues")?
        .call1(&crypto, &buffer)
        .map_err(|e| failed("getRandomValues", &e))?;
    Ok(buffer.to_vec())
}

/// `crypto.subtle.generateKey({name:"AES-GCM",length:256}, true, ["encrypt","decrypt"])`
///
/// Extractable, and the only function here that generates a key that way: the
/// enable ceremony has to wrap the fresh data key under two KEKs before it
/// can re-import it sealed. The handle this returns must not outlive that
/// ceremony (spec section 6.1).
pub async fn generate_dek_extractable() -> Result<Object, CryptoError> {
    let algorithm = js_object(&[("name", AES_GCM.into()), ("length", KEY_BITS.into())]);
    let usages = dek_usages();
    let args = js_array(&[&algorithm, &JsValue::TRUE, &usages]);

    as_key("generateKey", subtle_call("generateKey", &args).await?)
}

/// `crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"])`
///
/// The one way a [`DataKey`] is built from bytes. `extractable` is `false`
/// here unconditionally — there is no variant of this call that yields a
/// readable data key, because nothing but the enable ceremony's own
/// short-lived handle is ever allowed to be one (invariant E5).
pub async fn import_dek_non_extractable(raw: &[u8]) -> Result<DataKey, CryptoError> {
    let algorithm = js_object(&[("name", AES_GCM.into())]);
    let material = Uint8Array::from(raw);
    let usages = dek_usages();
    let args = js_array(&[&RAW.into(), &material, &algorithm, &JsValue::FALSE, &usages]);

    Ok(DataKey(as_key(
        "importKey",
        subtle_call("importKey", &args).await?,
    )?))
}

/// Derives a key-encryption key from input keying material — a passkey's PRF
/// output, or a recovery code — with HKDF-SHA256.
///
/// ```js
/// const k = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
/// await crypto.subtle.deriveKey(
///   {name:"HKDF", hash:"SHA-256", salt: APP_SALT, info},
///   k,
///   {name:"AES-KW", length:256},
///   false,
///   ["wrapKey","unwrapKey"],
/// );
/// ```
///
/// `salt` is [`APP_SALT`], a constant, and must stay one. It is what makes
/// the same passkey derive the same KEK on every device and forever; a fresh
/// random salt here would produce a key that works once and never again, and
/// the failure would look like data corruption rather than like a bug
/// (invariant E6, spec section 4.2).
///
/// `info` separates the two routes — `wire::INFO_PASSKEY` from
/// `wire::INFO_RECOVERY` — so one route's KEK can never open the other's
/// wrap. The derived key is non-extractable and may only wrap and unwrap.
pub async fn derive_kek(ikm: &[u8], info: &[u8]) -> Result<Object, CryptoError> {
    let material = Uint8Array::from(ikm);
    let base_usages = ikm_usages();
    let import_args = js_array(&[
        &RAW.into(),
        &material,
        &HKDF.into(),
        &JsValue::FALSE,
        &base_usages,
    ]);
    let base_key = subtle_call("importKey", &import_args).await?;

    let hkdf_params = js_object(&[
        ("name", HKDF.into()),
        ("hash", SHA_256.into()),
        ("salt", Uint8Array::from(&APP_SALT[..]).into()),
        ("info", Uint8Array::from(info).into()),
    ]);
    let derived_algorithm = js_object(&[("name", AES_KW.into()), ("length", KEY_BITS.into())]);
    let derived_usages = kek_usages();
    let derive_args = js_array(&[
        &hkdf_params,
        &base_key,
        &derived_algorithm,
        &JsValue::FALSE,
        &derived_usages,
    ]);

    as_key("deriveKey", subtle_call("deriveKey", &derive_args).await?)
}

/// `crypto.subtle.wrapKey("raw", dek, kek, "AES-KW")`
///
/// Returns exactly [`wire::WRAPPED_KEY_LEN`] bytes for a 256-bit data key —
/// the width the `entry_key_wrap.wrapped_key` column is sized to.
pub async fn wrap_dek(dek: &Object, kek: &Object) -> Result<Vec<u8>, CryptoError> {
    let args = js_array(&[&RAW.into(), dek, kek, &AES_KW.into()]);

    as_bytes("wrapKey", subtle_call("wrapKey", &args).await?)
}

/// `crypto.subtle.unwrapKey("raw", wrapped, kek, "AES-KW", {name:"AES-GCM",length:256}, extractable, ["encrypt","decrypt"])`
///
/// Pass [`Extractable::Sealed`] unless you are the add-a-passkey path of spec
/// section 6.5; see [`Extractable`].
///
/// AES-KW is authenticated, so the wrong KEK — a wrong recovery code, the
/// wrong credential's wrap — fails here cleanly instead of yielding a key
/// that decrypts to garbage. That is why the recovery code carries no
/// checksum (spec section 6.4).
pub async fn unwrap_dek(
    wrapped: &[u8],
    kek: &Object,
    extractable: Extractable,
) -> Result<Object, CryptoError> {
    let material = Uint8Array::from(wrapped);
    let unwrapped_algorithm = js_object(&[("name", AES_GCM.into()), ("length", KEY_BITS.into())]);
    let usages = dek_usages();
    let args = js_array(&[
        &RAW.into(),
        &material,
        kek,
        &AES_KW.into(),
        &unwrapped_algorithm,
        &extractable.as_js(),
        &usages,
    ]);

    as_key("unwrapKey", subtle_call("unwrapKey", &args).await?)
}

/// `crypto.subtle.exportKey("raw", key)`
///
/// Only ever called on a handle that was created extractable: the enable
/// ceremony's generated key, or an [`Extractable::Raw`] unwrap in spec
/// section 6.5. On any other handle WebCrypto refuses, which is the whole
/// protection — so a call added here against a [`DataKey`] would fail at
/// runtime rather than leak, but it should not be written in the first place.
pub async fn export_raw(key: &Object) -> Result<Vec<u8>, CryptoError> {
    let args = js_array(&[&RAW.into(), key]);

    as_bytes("exportKey", subtle_call("exportKey", &args).await?)
}

/// Encrypts one entry body under the data key.
///
/// ```js
/// crypto.subtle.encrypt({name:"AES-GCM", iv: nonce}, dek, utf8)
/// ```
///
/// The nonce is drawn fresh from [`random_bytes`] on every call and there is
/// deliberately no way for a caller to supply one. Reusing a nonce under the
/// same AES-GCM key leaks the XOR of the two plaintexts and makes tag forgery
/// possible; no caller has a legitimate reason to choose one, so none can.
///
/// WebCrypto returns `ciphertext ‖ tag` as a single buffer, which is what
/// [`wire::Sealed::ciphertext`] holds.
pub async fn seal(dek: &DataKey, plaintext: &str) -> Result<wire::Sealed, CryptoError> {
    let nonce = random_bytes(NONCE_LEN)?;
    let algorithm = js_object(&[
        ("name", AES_GCM.into()),
        ("iv", Uint8Array::from(nonce.as_slice()).into()),
    ]);
    let body = Uint8Array::from(plaintext.as_bytes());
    let args = js_array(&[&algorithm, &dek.0, &body]);

    let ciphertext = as_bytes("encrypt", subtle_call("encrypt", &args).await?)?;
    Ok(wire::Sealed { nonce, ciphertext })
}

/// Decrypts one entry body under the data key.
///
/// ```js
/// crypto.subtle.decrypt({name:"AES-GCM", iv: sealed.nonce}, dek, sealed.ciphertext)
/// ```
///
/// A failed authentication is an expected outcome — the wrong key, a tampered
/// or substituted row — and becomes a [`CryptoError`] like any other failure,
/// never a panic. So does a body that is not valid UTF-8, which authenticated
/// ciphertext should make impossible but which must not be a panic if it ever
/// happens.
pub async fn open(dek: &DataKey, sealed: &wire::Sealed) -> Result<String, CryptoError> {
    let algorithm = js_object(&[
        ("name", AES_GCM.into()),
        ("iv", Uint8Array::from(sealed.nonce.as_slice()).into()),
    ]);
    let body = Uint8Array::from(sealed.ciphertext.as_slice());
    let args = js_array(&[&algorithm, &dek.0, &body]);

    let plaintext = as_bytes("decrypt", subtle_call("decrypt", &args).await?)?;
    String::from_utf8(plaintext)
        .map_err(|_| CryptoError("decrypted entry body is not valid UTF-8".to_string()))
}
