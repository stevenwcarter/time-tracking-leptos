//! The `SubtleCrypto` calls.
//!
//! **Not covered by any automated test.** WebCrypto exists only in a browser
//! and this project has no wasm test runner. Everything decidable without a
//! browser was pushed into [`super::wire`] and [`super::encryption_key`], which are
//! host-tested; what is left here is the calls themselves. The wire format
//! they produce *is* pinned, by `wire`'s cross-implementation tests against
//! the `aes-gcm` crate — so a format error fails on the host. What only a
//! browser can catch is a wrong argument to `deriveKey` or a wrong
//! `extractable` flag. Review this file by reading it (spec section 10).
//!
//! The three things a reviewer should check by eye, because nothing else
//! will:
//!
//! 1. The extractable handle — a [`RawDataKey`], from
//!    [`generate_dek_extractable`] or [`unwrap_dek_raw`] — appears only in
//!    the enable ceremony of spec section 6.1 and the single add-a-passkey
//!    path of spec section 6.5, and is dropped as soon as it has been
//!    wrapped. Every other holder of the data key has a [`DataKey`], which
//!    cannot be exported and cannot be turned into a [`RawDataKey`]
//!    (invariant E5).
//! 2. [`seal`] draws a fresh nonce per call and takes none from its caller.
//! 3. [`derive_kek`] passes [`APP_SALT`], never a fresh random salt
//!    (invariant E6).
//!
//! Everything reaches `window.crypto` through [`Reflect`] rather than
//! `web_sys::Crypto`, the same way [`crate::webauthn_browser`] reaches
//! `navigator.credentials`. That keeps this feature's `web-sys` growth to the
//! IndexedDB types the keystore needs (spec section 7.2).
//!
//! No error here carries key material, PRF output, an encryption key, or
//! plaintext. A failure names the operation and repeats what the browser
//! said about it; it never repeats the operation's inputs. See [`failed`] for
//! why the browser's own words are safe to keep and what would change that.

use js_sys::{Array, ArrayBuffer, Function, Object, Promise, Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use super::wire::{self, APP_SALT, NONCE_LEN, WrapKind};

/// A WebCrypto operation failed. The `String` is for the log, never for the
/// user — callers map this to a human sentence themselves.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(pub String);

/// A live AES-256-GCM key that reported itself non-extractable when this
/// handle was built — see [`DataKey::from_object`], which is the only way to
/// build one and refuses a key that says otherwise. Cloneable because
/// `CryptoKey` is a JS handle; cloning duplicates the handle, not the key
/// material.
///
/// Deliberately not `Debug`: the point of the type is that its bytes cannot
/// be read, and a derived formatter is an invitation to log it anyway.
#[derive(Clone)]
pub struct DataKey(Object);

impl DataKey {
    /// Wraps a `CryptoKey` handle after confirming it really is
    /// non-extractable.
    ///
    /// [`as_key`] proves only that the value is *an object*, which every JS
    /// object is. The `extractable: false` argument we passed leaves no
    /// trace in the result's Rust type, so a key that came back extractable
    /// anyway would be a working, silently exportable data key and nothing
    /// would fail. Reading `CryptoKey.extractable` back off the key itself
    /// is the one mechanical check available on invariant E5 in a project
    /// with no wasm test runner: WebCrypto cannot be exercised on the host
    /// at all, so no test can stand in for this. A missing or non-boolean
    /// property fails the same way a `true` does — this is not the place to
    /// give a surprising object the benefit of the doubt.
    ///
    /// `operation` names where the key came from and reaches the log only;
    /// like every error in this module it carries no key material.
    ///
    /// `pub(super)` rather than public: the handle inside a [`DataKey`] is
    /// this module's business, and [`super::keystore`] is the only outside
    /// caller — it rebuilds one from the `CryptoKey` IndexedDB gave back.
    pub(super) fn from_object(operation: &str, key: Object) -> Result<Self, CryptoError> {
        let extractable = Reflect::get(&key, &"extractable".into())
            .ok()
            .and_then(|value| value.as_bool());
        if extractable != Some(false) {
            return Err(CryptoError(format!(
                "{operation} returned a data key that is not sealed"
            )));
        }
        Ok(Self(key))
    }

    /// The underlying handle, for [`super::keystore`] to store.
    pub(super) fn as_object(&self) -> &Object {
        &self.0
    }
}

/// A data key handle whose bytes *can* be read back out.
///
/// It exists because `wrapKey` will not accept a non-extractable key: the
/// enable ceremony's first wrap (spec section 6.1) and the re-wrap when a
/// second passkey is added (spec section 6.5) both need a handle that was
/// created extractable. [`export_raw`] then takes the same handle.
///
/// Every value of this type is short-lived by construction — it exists
/// between generating or unwrapping the data key and wrapping it, and is
/// dropped there. There is no conversion from a [`DataKey`], so the sealed
/// key that the rest of the app holds can never become one (invariant E5).
///
/// Not `Debug`, and not `Clone`, for the reasons [`DataKey`] is not.
pub struct RawDataKey(Object);

/// A key-encryption key: the AES-KW key [`derive_kek`] produces, whose only
/// job is to wrap and unwrap the data key.
///
/// A distinct type from the two data-key handles so that [`wrap_dek`]'s
/// arguments cannot be swapped. In JS both are `CryptoKey`s, so the mistake
/// would be a runtime `InvalidAccessError` at best; here it does not compile.
pub struct Kek(Object);

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

/// Reads the JS-side `name` and `message` of a thrown value and names the
/// operation it came from.
///
/// **The `message` is kept — unconditionally, not only in a debug build.**
/// It is the field an implementation could in principle echo an argument
/// into, so the reasoning is worth stating:
///
/// - Every secret this module handles crosses into JS as a `Uint8Array`
///   BufferSource: key material, PRF output, encryption-key bytes, entry
///   plaintext. The strings passed to WebCrypto are all compile-time
///   constants — `"raw"`, `"AES-GCM"`, `"AES-KW"`, `"HKDF"`, `"SHA-256"`,
///   the usage names. IndexedDB, via [`super::keystore`], additionally
///   passes the fixed database, store and record names, plus one dynamic
///   string: `put_in` stores the account's `user` identifier alongside the
///   key. None of that is key material, which is the property this
///   argument actually needs — `user` is an email the client already holds,
///   not a secret — so for key material specifically to reach a `message`,
///   a browser would have to format typed-array contents into an exception
///   string, which none does.
/// - Against that, `name` alone is often useless. Every argument-shape
///   mistake — a malformed algorithm object, a missing field, the wrong sort
///   of value — arrives as the same `"TypeError"`, and all of what
///   distinguishes them lives in `message`. Those are exactly the failures
///   this module's header says only a browser can catch, and this is the
///   only channel it has for reporting one.
/// - [`crate::webauthn_browser`]'s `classify` already puts the whole
///   stringified exception into its error, so keeping `message` here follows
///   the house rule rather than inventing a stricter one.
///
/// **What would invalidate this.** A change that passes secret material to
/// WebCrypto or IndexedDB *as a string* — a JWK import instead of `"raw"`, a
/// base64 or passphrase argument, an entry body used as a record key — makes
/// a `message` able to quote a secret, and this decision has to be revisited
/// at that point.
///
/// Shared with [`super::keystore`], whose failures arrive as IndexedDB
/// `DOMException`s and carry both fields in the same way.
pub(super) fn failed(operation: &str, thrown: &JsValue) -> CryptoError {
    let text = |property: &str| {
        Reflect::get(thrown, &property.into())
            .ok()
            .and_then(|value| value.as_string())
            .filter(|value| !value.is_empty())
    };
    let name = text("name").unwrap_or_else(|| "unknown error".to_string());
    CryptoError(match text("message") {
        Some(message) => format!("{operation} failed: {name}: {message}"),
        None => format!("{operation} failed: {name}"),
    })
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
/// over plain HTTP from anything but `localhost`, every function that reaches
/// WebCrypto fails here and nowhere else. [`random_bytes`] is the one
/// exception — it calls `getRandomValues` on `window.crypto` itself, which an
/// insecure context still has, so randomness keeps working on a page where
/// nothing else in this module does.
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
/// nonce in [`seal`] and an encryption key's entropy both come from here.
/// Unlike everything else here it does not go through [`subtle`], so it works
/// in an insecure context too.
///
/// Only sane lengths are `Err`-safe. `Uint8Array::new_with_length` is not a
/// `catch` import, so a length the JS engine refuses to allocate throws
/// across the wasm boundary instead of returning `Err`. The two call sites
/// ask for [`NONCE_LEN`] and [`super::encryption_key::KEY_BYTES`] — 12 and 20
/// bytes — so nothing here comes near that bound.
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
/// can re-import it sealed, and `wrapKey` refuses a non-extractable key. The
/// [`RawDataKey`] this returns must not outlive that ceremony (spec section
/// 6.1).
pub async fn generate_dek_extractable() -> Result<RawDataKey, CryptoError> {
    let algorithm = js_object(&[("name", AES_GCM.into()), ("length", KEY_BITS.into())]);
    let usages = dek_usages();
    let args = js_array(&[&algorithm, &JsValue::TRUE, &usages]);

    Ok(RawDataKey(as_key(
        "generateKey",
        subtle_call("generateKey", &args).await?,
    )?))
}

/// `crypto.subtle.importKey("raw", raw, {name:"AES-GCM"}, false, ["encrypt","decrypt"])`
///
/// The one way a [`DataKey`] is built from bytes. `extractable` is `false`
/// here unconditionally — there is no variant of this call that yields a
/// readable data key, because nothing but the enable ceremony's own
/// short-lived handle is ever allowed to be one (invariant E5) — and
/// [`DataKey::from_object`] checks that the browser agreed.
pub async fn import_dek_non_extractable(raw: &[u8]) -> Result<DataKey, CryptoError> {
    let algorithm = js_object(&[("name", AES_GCM.into())]);
    let material = Uint8Array::from(raw);
    let usages = dek_usages();
    let args = js_array(&[&RAW.into(), &material, &algorithm, &JsValue::FALSE, &usages]);

    let key = as_key("importKey", subtle_call("importKey", &args).await?)?;
    DataKey::from_object("importKey", key)
}

/// Derives a key-encryption key from input keying material — a passkey's PRF
/// output, or an encryption key — with HKDF-SHA256.
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
/// `kind` selects `info` via [`WrapKind::info`] rather than taking one as a
/// raw byte string: the two routes must never share an `info`, and a
/// `WrapKind` is the only way to name one of them, so a wrap made under the
/// wrong route's `info` — which would be a well-formed wrap no device ever
/// opens — is not an argument a caller can pass by mistake (invariant E6).
/// The derived key is non-extractable and may only wrap and unwrap.
pub async fn derive_kek(ikm: &[u8], kind: WrapKind) -> Result<Kek, CryptoError> {
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
        ("info", Uint8Array::from(kind.info()).into()),
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

    Ok(Kek(as_key(
        "deriveKey",
        subtle_call("deriveKey", &derive_args).await?,
    )?))
}

/// `crypto.subtle.wrapKey("raw", dek, kek, "AES-KW")`
///
/// Returns exactly [`wire::WRAPPED_KEY_LEN`] bytes for a 256-bit data key —
/// the width the `entry_key_wrap.wrapped_key` column is sized to.
///
/// **`wrapKey` throws `InvalidAccessError` unless the key being wrapped is
/// extractable.** That precondition is why the data key arrives here as a
/// [`RawDataKey`] and not as a [`DataKey`]: the sealed handle would fail this
/// call at runtime, in the browser, where no test in this project can see it.
///
/// The two handles are separate types for the same reason. In JS they are
/// both `CryptoKey`s, so `wrapKey(dek, kek)` with the arguments the wrong way
/// round is a well-formed call that fails only at runtime.
pub async fn wrap_dek(dek: &RawDataKey, kek: &Kek) -> Result<Vec<u8>, CryptoError> {
    let args = js_array(&[&RAW.into(), &dek.0, &kek.0, &AES_KW.into()]);

    as_bytes("wrapKey", subtle_call("wrapKey", &args).await?)
}

/// `crypto.subtle.unwrapKey("raw", wrapped, kek, "AES-KW", {name:"AES-GCM",length:256}, extractable, ["encrypt","decrypt"])`
///
/// The `extractable` argument is not a parameter: the two public wrappers
/// below each pass their own, and their return types say which they passed.
///
/// AES-KW is authenticated, so the wrong KEK — a wrong encryption key, the
/// wrong credential's wrap — fails here cleanly instead of yielding a key
/// that decrypts to garbage. That is why the encryption key carries no
/// checksum (spec section 6.4).
async fn unwrap_key(
    wrapped: &[u8],
    kek: &Kek,
    extractable: &JsValue,
) -> Result<Object, CryptoError> {
    let material = Uint8Array::from(wrapped);
    let unwrapped_algorithm = js_object(&[("name", AES_GCM.into()), ("length", KEY_BITS.into())]);
    let usages = dek_usages();
    let args = js_array(&[
        &RAW.into(),
        &material,
        &kek.0,
        &AES_KW.into(),
        &unwrapped_algorithm,
        extractable,
        &usages,
    ]);

    as_key("unwrapKey", subtle_call("unwrapKey", &args).await?)
}

/// Unwraps the stored data key into a sealed [`DataKey`].
///
/// This is the unlock path — every sign-in, on every device — and the only
/// one anything outside the two ceremonies should need. See [`unwrap_key`]
/// for what a wrong KEK does, and [`DataKey::from_object`] for why the
/// result is inspected rather than trusted.
pub async fn unwrap_dek_sealed(wrapped: &[u8], kek: &Kek) -> Result<DataKey, CryptoError> {
    let key = unwrap_key(wrapped, kek, &JsValue::FALSE).await?;
    DataKey::from_object("unwrapKey", key)
}

/// Unwraps the stored data key into an exportable [`RawDataKey`].
///
/// Only the add-a-passkey path of spec section 6.5 may call this: it opens
/// the existing wrap, re-wraps the same data key under the new credential's
/// KEK, and drops the handle. A new call site is a change to invariant E5 and
/// should be reviewed as one.
pub async fn unwrap_dek_raw(wrapped: &[u8], kek: &Kek) -> Result<RawDataKey, CryptoError> {
    Ok(RawDataKey(unwrap_key(wrapped, kek, &JsValue::TRUE).await?))
}

/// `crypto.subtle.exportKey("raw", key)`
///
/// Takes only a [`RawDataKey`] — the enable ceremony's generated key or an
/// [`unwrap_dek_raw`] handle from spec section 6.5. WebCrypto would refuse a
/// sealed key at runtime, but the point of the parameter type is that the
/// call cannot be written: handing this a [`DataKey`] does not compile, so
/// the protection is not left to a browser to enforce.
pub async fn export_raw(key: &RawDataKey) -> Result<Vec<u8>, CryptoError> {
    let args = js_array(&[&RAW.into(), &key.0]);

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
