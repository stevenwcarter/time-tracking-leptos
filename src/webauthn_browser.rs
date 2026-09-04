//! Hydrate-only wrapper around `navigator.credentials.create/get`.
//!
//! Both entry points take the server's WebAuthn JSON challenge and return
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

/// Maps a raw WebAuthn or server error to something a person can act on.
///
/// Deliberately narrow: server-fn messages are already user-facing and pass
/// through by prefix; everything else collapses, so raw JS internals never
/// reach the UI.
///
/// The pass-through prefixes are a coupling to server-fn message text (see
/// the `server_err` calls in `server_fns::passkey` and `server_fns::mod`) —
/// if a server fn's wording changes, its message silently stops matching and
/// collapses to the generic text below instead of failing loudly. Known
/// trade-off, not something to solve here.
pub fn friendly_error(raw: String) -> String {
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

    use js_sys::{Function, Object, Reflect};
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

    /// Runs one ceremony, returning the raw credential object.
    async fn invoke(
        challenge_json: &str,
        parse_method: &str,
        creds_method: &str,
    ) -> Result<JsValue, WebauthnUserError> {
        let pk = pk_constructor()?;
        let parse = method(&pk, parse_method)?;

        let challenge = js_sys::JSON::parse(challenge_json)
            .map_err(|_| WebauthnUserError::Other("bad challenge JSON".into()))?;
        let public_key = Reflect::get(&challenge, &"publicKey".into())
            .map_err(|_| WebauthnUserError::Other("missing publicKey".into()))?;
        let options = parse.call1(&pk, &public_key).map_err(classify)?;

        let win = web_sys::window().ok_or_else(|| WebauthnUserError::Other("no window".into()))?;
        let creds = win.navigator().credentials();
        let arg = Object::new();
        Reflect::set(&arg, &"publicKey".into(), &options).ok();

        let promise = method(&creds, creds_method)?
            .call1(&creds, &arg)
            .map_err(classify)?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| {
                WebauthnUserError::Other("credentials.create/get returned non-Promise".into())
            })?;

        JsFuture::from(promise).await.map_err(classify)
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

    /// Enrols a credential. Returns its JSON and whether PRF is available.
    pub async fn register(challenge_json: &str) -> Result<(String, bool), WebauthnUserError> {
        let cred = invoke(challenge_json, "parseCreationOptionsFromJSON", "create").await?;
        Ok((to_json(&cred)?, prf_enabled(&cred)))
    }

    /// Runs a sign-in assertion.
    pub async fn authenticate(challenge_json: &str) -> Result<String, WebauthnUserError> {
        let cred = invoke(challenge_json, "parseRequestOptionsFromJSON", "get").await?;
        to_json(&cred)
    }
}

#[cfg(feature = "hydrate")]
pub use browser::{WebauthnUserError, authenticate, register};

#[cfg(test)]
mod tests {
    use super::{friendly_error, prf_enabled_from_json};

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
    #[test]
    fn server_messages_pass_through() {
        for raw in [
            "We couldn't verify your passkey.",
            "Your sign-in session expired. Please retry.",
            "Too many attempts. Please wait a minute.",
            "That passkey no longer exists.",
            "Not signed in",
        ] {
            assert_eq!(friendly_error(raw.into()), raw);
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
