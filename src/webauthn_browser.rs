//! Hydrate-only wrapper around `navigator.credentials.create/get`.
//!
//! Every entry point takes the server's WebAuthn JSON challenge and returns
//! the browser's response as JSON, leaning on the browser's own
//! `PublicKeyCredential.parseCreationOptionsFromJSON()`,
//! `parseRequestOptionsFromJSON()`, and `toJSON()` rather than doing
//! base64url plumbing by hand. Passing the parsed server payload straight to
//! `navigator.credentials` does not work: the API needs `ArrayBuffer`s where
//! webauthn-rs emits base64url strings, and the browser reports the mismatch
//! as `NotAllowedError` — indistinguishable from the user hitting cancel.
//!
//! (The typed `web_sys` bindings for those same three methods exist but sit
//! behind `--cfg=web_sys_unstable_apis`, which this project does not set, so
//! they are invoked here through `js_sys::Reflect` instead.)

/// The fixed wrapper `ServerFnError`'s own `Display` puts in front of every
/// `ServerFnError::ServerError` message — the only variant this crate's
/// server fns ever return (see `server_fns::server_err` and
/// `server_fns::log_and_fail`). Every caller below hands [`friendly_error`]
/// `err.to_string()`, never the message itself, so it always arrives wearing
/// this prefix.
const SERVER_FN_ERROR_PREFIX: &str = "error running server function: ";

/// Maps a raw WebAuthn or server error to something a person can act on.
///
/// Deliberately narrow: server-fn messages are already user-facing and pass
/// through by prefix; everything else collapses, so raw JS internals never
/// reach the UI.
///
/// [`SERVER_FN_ERROR_PREFIX`] is stripped first, before any of the matching
/// below runs. Without that, every `starts_with` check below is matching
/// against text that no longer starts with what it names — `raw` starts
/// with "error running server function: ", never with "This is your last
/// passkey" — so none of them could ever fire, and every server-fn refusal
/// this function exists to preserve would silently collapse to the generic
/// fallback instead.
///
/// The pass-through prefixes are a coupling to server-fn message text (see
/// the `server_err` calls in `server_fns::passkey` and `server_fns::mod`) —
/// if a server fn's wording changes, its message silently stops matching and
/// collapses to the generic text below instead of failing loudly. Known
/// trade-off, not something to solve here.
pub fn friendly_error(raw: String) -> String {
    let raw = raw
        .strip_prefix(SERVER_FN_ERROR_PREFIX)
        .map(str::to_string)
        .unwrap_or(raw);
    let lower = raw.to_lowercase();
    if lower.contains("cancel") || lower.contains("notallowederror") {
        "Sign-in was cancelled.".to_string()
    } else if lower.contains("not supported")
        || lower.contains("unavailable")
        || lower.contains("no window")
        || lower.contains("non-promise")
    {
        "Your browser doesn't support passkeys for this site.".to_string()
    } else if raw.starts_with("We couldn't")
        || raw.starts_with("Your sign-in")
        || raw.starts_with("Your passkey")
        || raw.starts_with("Too many")
        || raw.starts_with("That passkey")
        || raw.starts_with("This is your last passkey")
        || raw.starts_with("Encryption is already")
        || raw.starts_with("Not signed in")
        || raw.starts_with("Wrong ceremony")
        || raw.starts_with("Malformed credential")
    {
        raw
    } else {
        "Couldn't complete that passkey step. Please try again.".to_string()
    }
}

/// The decision behind [`browser::prf_enabled`], pulled out so it is
/// host-testable: takes the JSON-stringified result of
/// `getClientExtensionResults()` rather than a live `JsValue`.
///
/// Every step is fallible-safe: malformed JSON, a missing `prf` key, a
/// missing `enabled` field, or a non-boolean value must all read as "no PRF
/// support", never panic — misreading this as `false` just means a fallback
/// path; misreading it as `true` (or panicking) would break the ceremony.
///
/// Note the mechanism differs from the live `Reflect`-based check this
/// replaced, even though the outcome does not: `Reflect::get` on a JS value
/// that lacks a `prf` key returns `undefined`, and a *further* `Reflect::get`
/// on `undefined` throws — so the old code's `false` for "no `prf` key" came
/// from an error path. Here, `serde_json`'s `Value::get` returns `None` for
/// a missing key directly. Both collapse to `false`, but they are not the
/// same mechanism; don't read this as a line-for-line port of the old chain.
pub(crate) fn prf_enabled_from_json(extension_results_json: &str) -> bool {
    let Ok(results) = serde_json::from_str::<serde_json::Value>(extension_results_json) else {
        return false;
    };
    results
        .get("prf")
        .and_then(|prf| prf.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

#[cfg(feature = "hydrate")]
mod browser {
    use std::fmt;

    use js_sys::{ArrayBuffer, Function, Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;

    /// A WebAuthn ceremony failure, already sorted into the buckets
    /// [`super::friendly_error`] knows how to explain.
    #[derive(Debug)]
    pub enum WebauthnUserError {
        Cancelled,
        NotSupported,
        Other(String),
    }

    impl fmt::Display for WebauthnUserError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Cancelled => f.write_str("cancelled"),
                Self::NotSupported => f.write_str("not supported"),
                Self::Other(s) => f.write_str(s),
            }
        }
    }

    fn pk_constructor() -> Result<Object, WebauthnUserError> {
        let win = web_sys::window().ok_or_else(|| WebauthnUserError::Other("no window".into()))?;
        Reflect::get(&win, &"PublicKeyCredential".into())
            .map_err(|_| WebauthnUserError::NotSupported)?
            .dyn_into::<Object>()
            .map_err(|_| WebauthnUserError::NotSupported)
    }

    fn stringify(v: &JsValue) -> String {
        js_sys::JSON::stringify(v)
            .ok()
            .and_then(|s| s.as_string())
            .unwrap_or_default()
    }

    fn classify(e: JsValue) -> WebauthnUserError {
        let name = Reflect::get(&e, &"name".into())
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        if name == "NotAllowedError" {
            WebauthnUserError::Cancelled
        } else {
            WebauthnUserError::Other(format!("{name}: {}", stringify(&e)))
        }
    }

    fn method(on: &JsValue, name: &str) -> Result<Function, WebauthnUserError> {
        Reflect::get(on, &name.into())
            .map_err(|_| WebauthnUserError::NotSupported)?
            .dyn_into::<Function>()
            .map_err(|_| WebauthnUserError::NotSupported)
    }

    /// Turns the server's challenge JSON into the browser's own options
    /// object.
    ///
    /// Split out from [`invoke`] so a caller can mutate the parsed options
    /// before the ceremony runs — which is the only place the PRF extension
    /// may be added; see [`authenticate_with_prf`].
    fn parse_options(
        challenge_json: &str,
        parse_method: &str,
    ) -> Result<JsValue, WebauthnUserError> {
        let pk = pk_constructor()?;
        let parse = method(&pk, parse_method)?;

        let challenge = js_sys::JSON::parse(challenge_json)
            .map_err(|_| WebauthnUserError::Other("bad challenge JSON".into()))?;
        let public_key = Reflect::get(&challenge, &"publicKey".into())
            .map_err(|_| WebauthnUserError::Other("missing publicKey".into()))?;
        parse.call1(&pk, &public_key).map_err(classify)
    }

    /// Runs `navigator.credentials.<creds_method>({ publicKey: options })`.
    async fn call_credentials(
        options: &JsValue,
        creds_method: &str,
    ) -> Result<JsValue, WebauthnUserError> {
        let win = web_sys::window().ok_or_else(|| WebauthnUserError::Other("no window".into()))?;
        let creds = win.navigator().credentials();
        let arg = Object::new();
        Reflect::set(&arg, &"publicKey".into(), options).ok();

        let promise = method(&creds, creds_method)?
            .call1(&creds, &arg)
            .map_err(classify)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| {
                WebauthnUserError::Other("credentials.create/get returned non-Promise".into())
            })?;

        JsFuture::from(promise).await.map_err(classify)
    }

    /// Runs one ceremony, returning the raw credential object.
    async fn invoke(
        challenge_json: &str,
        parse_method: &str,
        creds_method: &str,
    ) -> Result<JsValue, WebauthnUserError> {
        let options = parse_options(challenge_json, parse_method)?;
        call_credentials(&options, creds_method).await
    }

    fn to_json(cred: &JsValue) -> Result<String, WebauthnUserError> {
        Ok(stringify(
            &method(cred, "toJSON")?.call0(cred).map_err(classify)?,
        ))
    }

    /// Whether the authenticator enabled the PRF extension.
    ///
    /// `toJSON()` omits extension results, so this has to come from
    /// `getClientExtensionResults()` separately. Phase 1 only records the
    /// answer; phase 2 derives an encryption key from PRF output on
    /// credentials where this was true (spec section 9.3).
    ///
    /// Only "can we reach the results at all" lives here — a missing
    /// `getClientExtensionResults` method or a throwing call both read as
    /// "no PRF support" and never panic. The actual `prf.enabled` decision
    /// is [`super::prf_enabled_from_json`], which is host-tested.
    fn prf_enabled(cred: &JsValue) -> bool {
        let Ok(get_results) = method(cred, "getClientExtensionResults") else {
            return false;
        };
        let Ok(results) = get_results.call0(cred) else {
            return false;
        };
        super::prf_enabled_from_json(&stringify(&results))
    }

    /// Builds `{ prf: { eval: { first: <salt> } } }`.
    ///
    /// `Reflect::set` on a fresh, extensible object under a string key cannot
    /// fail, so its result is discarded — the same shape [`call_credentials`]
    /// uses to build its `publicKey` argument.
    fn prf_eval_extension(prf_salt: &[u8]) -> Object {
        let nest = |name: &str, value: &JsValue| {
            let object = Object::new();
            Reflect::set(&object, &name.into(), value).ok();
            object
        };
        let eval = nest("first", &Uint8Array::from(prf_salt).into());
        let prf = nest("eval", &eval.into());
        nest("prf", &prf.into())
    }

    /// The PRF output from a completed assertion, or `None` if there wasn't
    /// one.
    ///
    /// **Nothing automated covers this function** (spec section 10 lists it
    /// as inspection-only), and the trick that made [`prf_enabled`]'s
    /// decision host-testable cannot be reused: `prf.results.first` is an
    /// `ArrayBuffer`, and `JSON.stringify` renders an `ArrayBuffer` as `{}`.
    /// There is no `prf_output_from_json` to write, so don't go looking for
    /// one — the live JS values have to be walked.
    ///
    /// Every step reads as "no PRF output" rather than panicking, with one
    /// narrow exception: `Uint8Array::new(&buffer)` below is a non-`catch`
    /// wasm-bindgen binding, so a detached `ArrayBuffer` would throw straight
    /// past this function's `Option` contract rather than read as `None`.
    /// Unreachable in practice — `buffer` is freshly minted by the browser
    /// for this assertion, never a value this code could itself have
    /// detached — but it means the claim above is "reads as no output",
    /// not "provably cannot panic." Note the hops are checked in order
    /// because `Reflect::get` on a value that turned out to be `undefined`
    /// throws: a missing `prf` key surfaces as the `Err` of the *following*
    /// get, not of its own.
    fn prf_output(cred: &JsValue) -> Option<Vec<u8>> {
        let results = method(cred, "getClientExtensionResults")
            .ok()?
            .call0(cred)
            .ok()?;
        let prf = Reflect::get(&results, &"prf".into()).ok()?;
        let prf_results = Reflect::get(&prf, &"results".into()).ok()?;
        let first = Reflect::get(&prf_results, &"first".into()).ok()?;
        let buffer = first.dyn_into::<ArrayBuffer>().ok()?;
        let bytes = Uint8Array::new(&buffer).to_vec();

        // An empty buffer is not a PRF output. Handing one on would derive a
        // key-encryption key from no entropy at all, and it would round-trip
        // happily — the worst way for this to fail.
        //
        // Anything else — including a result that is not the 32 bytes this
        // build's own derivation expects — is forwarded uninspected, and
        // that is a deliberate choice, not an oversight: HKDF accepts input
        // keying material of any length, and a given authenticator returns
        // the same length on every assertion, so an odd length is
        // self-consistent rather than a sign of corruption. Rejecting it
        // would trade a working unlock for a lockout on a spec-violating
        // browser or authenticator — availability is the right bias here.
        (!bytes.is_empty()).then_some(bytes)
    }

    /// Enrols a credential. Returns its JSON and whether PRF is available.
    pub async fn register(challenge_json: &str) -> Result<(String, bool), WebauthnUserError> {
        let cred = invoke(challenge_json, "parseCreationOptionsFromJSON", "create").await?;
        Ok((to_json(&cred)?, prf_enabled(&cred)))
    }

    /// Runs a sign-in assertion that also evaluates the PRF at `prf_salt`,
    /// returning the credential JSON and, when the authenticator produced
    /// one, the PRF output.
    ///
    /// Signing in already costs one assertion, so riding PRF on it unlocks
    /// the user's data in the same gesture instead of prompting twice (spec
    /// section 6.2). The PRF output is the caller's to turn into a key; it
    /// never leaves the browser.
    ///
    /// **The only assertion in the crate**, sign-in included. There is no
    /// plain `authenticate` sibling to reach for: asking for the PRF costs
    /// an authenticator that cannot provide it nothing — no extra prompt,
    /// no failure, just a `None` — so a second entry point would only be a
    /// way to forget the unlock.
    ///
    /// **`None` is not a failure.** An authenticator without PRF, a browser
    /// that ignored the extension, or a result in an unexpected shape all
    /// yield `Ok((json, None))` and let sign-in complete. This same call
    /// performs the sign-in: failing it because PRF was unavailable would
    /// lock the user out of the application, where `None` only lands them in
    /// a locked session they can open with their recovery code.
    ///
    /// **The extension is set here, on the parsed options object, and not in
    /// the server's challenge JSON.** Browser support for `prf.eval` inside
    /// `parseRequestOptionsFromJSON` is inconsistent, so a salt that went
    /// through the JSON parser would silently do nothing on some browsers
    /// (spec section 7.1). One welcome consequence: `passkey_login_start`
    /// needs no change at all. Assignment rather than a merge is safe today
    /// because `start_passkey_authentication` always passes `extensions:
    /// None` for the login challenge — not because the type is small:
    /// `RequestAuthenticationExtensions` actually carries three fields
    /// (`appid`, `uvm`, `hmac_get_secret`). **If the login challenge ever
    /// gains a server-side extension, this line will silently drop it** —
    /// that is the point at which assignment here must become a merge. A
    /// failed set is ignored for the same reason a missing result is: it
    /// costs the unlock, not the sign-in.
    ///
    /// Coverage: [`prf_output`], which reads the result, has none — see its
    /// own note. `register`'s neighbouring capability check runs through
    /// [`super::prf_enabled_from_json`], which *is* host-tested; the two are
    /// not in the same category and a reviewer should not read them as such.
    pub async fn authenticate_with_prf(
        challenge_json: &str,
        prf_salt: &[u8],
    ) -> Result<(String, Option<Vec<u8>>), WebauthnUserError> {
        let options = parse_options(challenge_json, "parseRequestOptionsFromJSON")?;
        Reflect::set(
            &options,
            &"extensions".into(),
            &prf_eval_extension(prf_salt).into(),
        )
        .ok();

        let cred = call_credentials(&options, "get").await?;
        Ok((to_json(&cred)?, prf_output(&cred)))
    }
}

#[cfg(feature = "hydrate")]
pub use browser::{WebauthnUserError, authenticate_with_prf, register};

#[cfg(test)]
mod tests {
    use leptos::prelude::ServerFnError;

    use super::{friendly_error, prf_enabled_from_json};

    /// What every real call site actually hands `friendly_error`: a
    /// `ServerFnError`'s own `Display`, wrapper prefix included — not the
    /// message a server fn built.
    ///
    /// Every server fn in this crate returns `ServerFnError::ServerError`
    /// (`server_fns::server_err`, `server_fns::log_and_fail`), so that is the
    /// one variant worth reproducing here. A test that instead fed
    /// `friendly_error` the bare message — as this file's tests used to —
    /// exercises a shape production never produces: `err.to_string()` always
    /// carries `SERVER_FN_ERROR_PREFIX`, and a `starts_with` match against
    /// the un-prefixed message proves nothing about whether the same match
    /// survives it.
    fn server_fn_message(msg: &str) -> String {
        let err: ServerFnError = ServerFnError::ServerError(msg.to_string());
        err.to_string()
    }

    #[test]
    fn cancellation_is_named_plainly() {
        assert_eq!(friendly_error("cancelled".into()), "Sign-in was cancelled.");
        assert_eq!(
            friendly_error("NotAllowedError: ...".into()),
            "Sign-in was cancelled."
        );
    }

    #[test]
    fn unsupported_browsers_get_a_specific_message() {
        for raw in [
            "not supported",
            "no window",
            "credentials.create/get returned non-Promise",
        ] {
            assert_eq!(
                friendly_error(raw.into()),
                "Your browser doesn't support passkeys for this site."
            );
        }
    }

    /// Server-fn errors are already user-facing and pass through, so the
    /// account page can show "That passkey no longer exists." verbatim.
    ///
    /// Goes through [`server_fn_message`], not a bare literal: this is the
    /// prefixed shape `account_page::passkey_error` actually hands
    /// `friendly_error`, and the un-prefixed shape would pass this assertion
    /// whether or not the prefix was ever stripped.
    #[test]
    fn server_messages_pass_through() {
        for raw in [
            "We couldn't verify your passkey.",
            "Your sign-in session expired. Please retry.",
            "Too many attempts. Please wait a minute.",
            "That passkey no longer exists.",
            "Not signed in",
        ] {
            assert_eq!(friendly_error(server_fn_message(raw)), raw);
        }
    }

    /// The two refusals whose whole value is the explanation they carry.
    ///
    /// Both are raised by `server_fns::passkey`/`server_fns::encryption` and
    /// reach the user through `account_page::passkey_error`, which runs them
    /// through here. Collapsing the first would replace "removing this would
    /// lock you out — use your recovery code" with "please try again", and
    /// the user would try again until the passkey was gone. Kept in its own
    /// test, rather than folded into `server_messages_pass_through` above,
    /// because these two are the ones where the generic fallback is
    /// actively harmful rather than merely unhelpful.
    ///
    /// Goes through [`server_fn_message`] for the same reason
    /// `server_messages_pass_through` does — and this is the test that once
    /// did not: it fed `friendly_error` the bare message, which matched the
    /// `starts_with` allowlist by construction and would keep passing
    /// however the prefix was handled, proving nothing about the shape that
    /// actually ships.
    #[test]
    fn encryption_refusals_keep_their_explanation() {
        for raw in [
            // `server_fns::passkey::passkey_delete`, spec section 6.6.
            "This is your last passkey that can unlock your encrypted entries. \
             Removing it would lock you out for good — use your recovery code, \
             or add another passkey first.",
            // `server_fns::encryption::encryption_enable`.
            "Encryption is already enabled for this account.",
        ] {
            assert_eq!(friendly_error(server_fn_message(raw)), raw);
        }
    }

    /// Anything else collapses. Raw JS internals must never reach the user.
    #[test]
    fn unknown_errors_collapse_to_something_generic() {
        assert_eq!(
            friendly_error("TypeError: Cannot read properties of undefined".into()),
            "Couldn't complete that passkey step. Please try again."
        );
    }

    /// The one shape that must read as PRF-capable.
    #[test]
    fn prf_enabled_true_is_read_through() {
        assert!(prf_enabled_from_json(r#"{"prf":{"enabled":true}}"#));
    }

    /// No `prf` key at all — an authenticator that never got asked, or
    /// doesn't support the extension.
    #[test]
    fn prf_absent_is_not_capable() {
        assert!(!prf_enabled_from_json("{}"));
    }

    /// `prf` present but empty — the authenticator answered without an
    /// `enabled` field.
    #[test]
    fn prf_enabled_field_absent_is_not_capable() {
        assert!(!prf_enabled_from_json(r#"{"prf":{}}"#));
    }

    /// `enabled` present but not a boolean must not be read as truthy.
    #[test]
    fn prf_enabled_non_boolean_is_not_capable() {
        assert!(!prf_enabled_from_json(r#"{"prf":{"enabled":"true"}}"#));
    }

    /// Not valid JSON at all — must not panic.
    #[test]
    fn malformed_json_is_not_capable() {
        assert!(!prf_enabled_from_json("not json"));
    }
}
