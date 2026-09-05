//! The ceremony steps that need the authenticator *and* the server.
//!
//! [`subtle`](super::subtle) and [`keystore`](super::keystore) reach
//! WebCrypto and IndexedDB; `server_fns` reaches the network. The steps
//! below need both at once, and each is run from more than one place: the
//! unlock prompt and the `/account` encryption panel share the same
//! PRF-evaluated assertion and the same recovery re-issue, and the panel
//! shares [`add_passkey_key`] with the account page's enrolment button.
//!
//! They live here rather than in whichever component happened to want one
//! first, so the wording of a failure — and the retry that protects the
//! recovery wrap — cannot drift between callers. Ceremonies with a single
//! caller stay with that caller.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[cfg(feature = "hydrate")]
use leptos::logging::error;
#[cfg(feature = "hydrate")]
use leptos::prelude::ServerFnError;

#[cfg(feature = "hydrate")]
use super::{Opener, reissue_recovery};

/// Pulls the credential id back out of a WebAuthn response.
///
/// `toJSON()`'s `rawId` is the browser's base64url encoding of the same
/// bytes webauthn-rs stores as `passkey_credential.credential_id` and
/// `entry_key_wrap.credential_id` — reading it back out here is the only way
/// the client learns *which* credential just answered, since
/// `passkey_login_finish` reports only success or failure, not which row it
/// verified.
///
/// Every step is fallible-safe: a response that is not JSON, carries no
/// `rawId`, or carries one that is not base64url yields `None` rather than
/// panicking. Callers treat `None` as "that credential did not identify
/// itself", which is a different outcome from "the user chose the recovery
/// route" — see [`super::choose_route`].
pub fn credential_id_from_response(response_json: &str) -> Option<Vec<u8>> {
    let value: serde_json::Value = serde_json::from_str(response_json).ok()?;
    let raw_id = value.get("rawId")?.as_str()?;
    URL_SAFE_NO_PAD.decode(raw_id).ok()
}

/// One PRF-evaluated assertion: which credential answered, and the key
/// material it produced.
///
/// The two travel together because every caller needs both — the PRF output
/// derives a key-encryption key, and the credential id says which stored
/// wrap that key opens (or, when adding a route, which credential the new
/// wrap is filed under).
#[cfg(feature = "hydrate")]
pub struct PrfAssertion {
    /// The credential the user chose, as stored on the server.
    pub credential_id: Vec<u8>,
    /// That credential's PRF output for [`super::wire::APP_SALT`]. Never
    /// leaves the browser.
    pub prf_output: Vec<u8>,
}

/// Why an assertion did not yield usable key material.
///
/// Three variants rather than one string, because the three send the user to
/// three different places and only the caller knows where those are: an
/// unlock offers the recovery code, while enabling encryption cannot.
#[cfg(feature = "hydrate")]
pub enum AssertionError {
    /// The ceremony itself failed — cancelled, unsupported, or refused by
    /// the server. Already a user-facing sentence, via
    /// [`crate::webauthn_browser::friendly_error`].
    Ceremony(String),
    /// The assertion succeeded and the authenticator returned no PRF output.
    /// Not an error in the ceremony: this authenticator or browser simply
    /// cannot derive an encryption key.
    NoPrf,
    /// The response did not say which credential answered, so there is no
    /// way to know which wrap it corresponds to.
    Unidentified,
}

/// Runs a passkey assertion with the PRF extension evaluated (spec 7.1).
///
/// Reuses `passkey_login_start`/`passkey_login_finish` rather than a
/// dedicated pair — the ceremony is identical, and the only side effect
/// finishing it has that an already-signed-in session did not already have
/// is a refreshed session token, which is harmless. Finishing also consumes
/// the ceremony cookie `passkey_login_start` set, rather than leaving it to
/// expire.
///
/// The challenge is built from `user`'s own credentials, so whichever one
/// answers belongs to the account that asked.
#[cfg(feature = "hydrate")]
pub async fn assert_with_prf(user: &str) -> Result<PrfAssertion, AssertionError> {
    use crate::server_fns::passkey::{passkey_login_finish, passkey_login_start};
    use crate::webauthn_browser;

    use super::wire::APP_SALT;

    let ceremony = |raw: String| AssertionError::Ceremony(webauthn_browser::friendly_error(raw));

    let challenge = passkey_login_start(Some(user.to_string()))
        .await
        .map_err(|e| ceremony(e.to_string()))?;

    let (response, prf_output) = webauthn_browser::authenticate_with_prf(&challenge, APP_SALT)
        .await
        .map_err(|e| ceremony(e.to_string()))?;

    passkey_login_finish(response.clone())
        .await
        .map_err(|e| ceremony(e.to_string()))?;

    let prf_output = prf_output.ok_or(AssertionError::NoPrf)?;
    let credential_id =
        credential_id_from_response(&response).ok_or(AssertionError::Unidentified)?;

    Ok(PrfAssertion {
        credential_id,
        prf_output,
    })
}

/// Turns an assertion failure into a sentence, for a caller with no
/// recovery-code fallback to point at.
///
/// `UnlockPrompt` deliberately does *not* use this: every failure there ends
/// with "try your recovery code instead", which is the right advice for
/// somebody shut out and the wrong advice on `/account`, where the recovery
/// code is either not issued yet or not the thing that was asked for.
#[cfg(feature = "hydrate")]
pub fn assertion_message(err: AssertionError) -> String {
    match err {
        AssertionError::Ceremony(message) => message,
        AssertionError::NoPrf => "That passkey's authenticator didn't produce an encryption \
                                  key on this browser. Try another passkey."
            .to_string(),
        AssertionError::Unidentified => {
            "That passkey didn't identify itself to this browser, so there's no way to tell \
             which key it holds."
                .to_string()
        }
    }
}

/// Gives `target` its own route to the account's data key (spec 6.5).
///
/// **Two authenticator interactions, and there is no version with fewer.**
/// `wrapKey` needs the raw data key, and neither this device's keystore copy
/// nor an unlocked [`super::SessionKey`] can produce it (invariant E5) — so
/// an existing route has to be reopened in the moment. Counting the creation
/// of the credential itself, enrolling a passkey on an encrypted account
/// costs three, always. The panel says so before it starts.
///
/// The second assertion must answer with `target`. Filing the wrap under
/// whichever credential happened to reply would leave `target` still
/// keyless while quietly keying something else, and the user would be told
/// it worked.
#[cfg(feature = "hydrate")]
pub async fn add_passkey_key(user: &str, target: &[u8]) -> Result<(), String> {
    use crate::server_fns::encryption::{encryption_add_passkey_wrap, encryption_wraps};

    use super::{add_passkey_route, choose_route};

    let wraps = encryption_wraps().await.map_err(server_unreachable)?;
    if choose_route(&wraps, Some(target)).is_some() {
        return Err("That passkey can already open your entries.".to_string());
    }

    let existing = assert_with_prf(user).await.map_err(assertion_message)?;
    let route = choose_route(&wraps, Some(&existing.credential_id)).ok_or_else(|| {
        "That passkey can't open your entries either, so it has no key to pass on. Choose one \
         that already can."
            .to_string()
    })?;

    let fresh = assert_with_prf(user).await.map_err(assertion_message)?;
    if fresh.credential_id != target {
        return Err(
            "That wasn't the passkey this step is for. Start again and choose it when \
                    your browser asks the second time."
                .to_string(),
        );
    }

    let wrapped = add_passkey_route(
        &Opener::Passkey {
            prf_output: &existing.prf_output,
            wrap: &route.wrapped_key,
        },
        &fresh.prf_output,
    )
    .await
    .map_err(|_| "Couldn't derive an unlock key for that passkey.".to_string())?;

    encryption_add_passkey_wrap(target.to_vec(), wrapped)
        .await
        .map_err(server_unreachable)
}

/// A network or server failure unrelated to WebAuthn itself.
///
/// The server functions this covers already report their own errors as the
/// generic "Internal server error" `log_and_fail` produces — the specific
/// cause is logged server-side, not sent here — so there is nothing to
/// forward and a connection hint is the more useful thing to say.
#[cfg(feature = "hydrate")]
pub fn server_unreachable(_: ServerFnError) -> String {
    "Couldn't reach the server. Check your connection and try again.".to_string()
}

/// Stores a re-issued recovery wrap, retrying once with the identical bytes.
///
/// The failure this exists for is a *lost response*, not a lost request. If
/// the replace commits and the reply never arrives, the client reports
/// "couldn't reach the server" and leaves the user believing their old code
/// still works — while the server now holds a wrap derived from a code they
/// were never shown. They find out when they have lost every passkey and
/// reach for the recovery code, at which point the entries are unreadable
/// for good. Low probability, total consequence, and it defeats the one
/// safety net the design rests on.
///
/// `encryption_replace_recovery_wrap` is idempotent for a given wrap (see
/// its own doc), which is what makes a retry safe: the second call either
/// finds the work already done or finishes it, and either way the account
/// ends up holding the code the user is about to be shown.
#[cfg(feature = "hydrate")]
async fn store_recovery_wrap(wrapped_key: Vec<u8>) -> Result<(), String> {
    use crate::server_fns::encryption::encryption_replace_recovery_wrap;

    match encryption_replace_recovery_wrap(wrapped_key.clone()).await {
        Ok(()) => Ok(()),
        Err(first) => {
            error!("storing the re-issued recovery wrap failed, retrying once: {first}");
            encryption_replace_recovery_wrap(wrapped_key)
                .await
                .map_err(server_unreachable)
        }
    }
}

/// Spec section 6.4's offer: wraps the data key under a fresh code and
/// replaces the stored recovery wrap, returning the code to show once.
///
/// `existing` is any route the caller can open right now — the only way to
/// get the raw key back out, since a [`super::SessionKey`] cannot yield it
/// (invariant E5). The old code keeps working until the server has replaced
/// the row, so a failure here costs the user nothing.
#[cfg(feature = "hydrate")]
pub async fn reissue(existing: &Opener<'_>) -> Result<String, String> {
    let (new_code, new_wrap) = reissue_recovery(existing).await.map_err(|_| {
        "Couldn't generate a new recovery code. Your current one still works.".to_string()
    })?;
    store_recovery_wrap(new_wrap).await?;
    Ok(new_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The happy path, against the encoding a browser actually emits:
    /// base64url, unpadded. Padded or standard-alphabet base64 would decode
    /// to the wrong bytes — or not at all — and the symptom would be an
    /// unlock that fails as if the wrap were corrupt.
    #[test]
    fn reads_the_raw_id_a_browser_emits() {
        // 0xFF 0xFE 0xFD encodes as `//79` in standard base64 and `__79` in
        // base64url, and `_` is not in the standard alphabet at all — so
        // this fixture fails outright against the wrong engine rather than
        // decoding to some other bytes.
        let json = r#"{"id":"__79","rawId":"__79","type":"public-key"}"#;
        assert_eq!(
            credential_id_from_response(json),
            Some(vec![0xff, 0xfe, 0xfd])
        );
    }

    /// Every malformed shape reads as "that credential did not identify
    /// itself" rather than panicking. `None` is a route the caller reports;
    /// a panic in a `spawn_local` would leave the ceremony hung with no
    /// message at all.
    #[test]
    fn a_response_without_a_usable_raw_id_yields_nothing() {
        for json in [
            "not json",
            "{}",
            r#"{"rawId":null}"#,
            r#"{"rawId":42}"#,
            r#"{"rawId":"not base64url!!"}"#,
        ] {
            assert_eq!(
                credential_id_from_response(json),
                None,
                "{json} must not decode to a credential id"
            );
        }
    }
}
