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
use super::{KeySource, Opener, UnlockError, reissue_recovery};
#[cfg(feature = "hydrate")]
use crate::dto::WrapDto;

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

/// A route to the account's data key with the secret that opens it already
/// in hand.
///
/// Owns both halves because [`Opener`] borrows both, and the passkey arm's
/// PRF output exists only as a local of the assertion that produced it. The
/// pairing is the one `Opener` documents: a KEK derived from the wrong
/// secret fails exactly like a corrupt row, so the two must not be brought
/// together at a call site.
#[cfg(feature = "hydrate")]
enum OpenedRoute {
    Passkey { prf_output: Vec<u8>, wrap: Vec<u8> },
    Recovery { code: String, wrap: Vec<u8> },
}

#[cfg(feature = "hydrate")]
impl OpenedRoute {
    fn opener(&self) -> Opener<'_> {
        match self {
            OpenedRoute::Passkey { prf_output, wrap } => Opener::Passkey { prf_output, wrap },
            OpenedRoute::Recovery { code, wrap } => Opener::Recovery { code, wrap },
        }
    }

    /// What a failed re-wrap means, which depends on which secret was meant
    /// to open the key.
    ///
    /// A passkey's PRF output either derives the KEK or the authenticator
    /// cannot do it at all, and there is nothing for the user to correct. A
    /// recovery code is something they typed: telling them "couldn't derive
    /// an unlock key" for a mistyped code would send them looking for a
    /// fault in the passkey instead of in the twenty characters they just
    /// entered.
    fn rewrap_failed(&self, err: UnlockError) -> String {
        match (self, err) {
            (OpenedRoute::Recovery { .. }, UnlockError::Malformed(_)) => {
                "That doesn't look like a recovery code, so nothing was changed.".to_string()
            }
            (OpenedRoute::Recovery { .. }, UnlockError::Crypto(_)) => {
                "That recovery code didn't open your entries, so that passkey was left as it \
                 was. Check the code and try again."
                    .to_string()
            }
            (OpenedRoute::Passkey { .. }, _) => {
                "Couldn't derive an unlock key for that passkey.".to_string()
            }
        }
    }
}

/// Opens the route `source` names, ready to be re-wrapped under a new one.
#[cfg(feature = "hydrate")]
async fn open_existing_route(
    user: &str,
    source: KeySource,
    wraps: &[WrapDto],
) -> Result<OpenedRoute, String> {
    use super::choose_route;

    match source {
        KeySource::Passkey => {
            let existing = assert_with_prf(user).await.map_err(assertion_message)?;
            let route = choose_route(wraps, Some(&existing.credential_id)).ok_or_else(|| {
                "That passkey can't open your entries either, so it has no key to pass on. \
                 Choose one that already can."
                    .to_string()
            })?;
            Ok(OpenedRoute::Passkey {
                prf_output: existing.prf_output,
                wrap: route.wrapped_key,
            })
        }
        KeySource::Recovery(code) => {
            let route = choose_route(wraps, None).ok_or_else(|| {
                "This account has no recovery code on file, so there's nothing left to open \
                 your entries with."
                    .to_string()
            })?;
            Ok(OpenedRoute::Recovery {
                code,
                wrap: route.wrapped_key,
            })
        }
    }
}

/// Refuses an assertion that did not come from the credential this step is
/// for.
///
/// A named step with its own test rather than an inline `!=` inside
/// [`add_passkey_key`], which is browser-only and so unreachable from
/// `cargo test` in a project with no wasm runner. It is the only thing
/// standing between "the wrap was filed under whichever credential happened
/// to answer" and a success message: `target` would stay keyless while
/// something else quietly gained a route, and the user would be told it
/// worked.
///
/// A byte-for-byte comparison, length included. A prefix match would accept
/// a shorter credential id as the longer one it starts with — the plausible
/// way to get this wrong — so the test drives that case specifically.
#[cfg(any(feature = "hydrate", test))]
fn must_be_target(answered: &[u8], target: &[u8]) -> Result<(), String> {
    if answered == target {
        return Ok(());
    }
    Err("That wasn't the passkey this step is for. Start again and choose it when your \
         browser asks for it."
        .to_string())
}

/// Gives `target` its own route to the account's data key (spec 6.5).
///
/// `wrapKey` needs the raw data key, and neither this device's keystore copy
/// nor an unlocked [`super::SessionKey`] can produce it (invariant E5) — so
/// an existing route has to be reopened in the moment. `source` says which
/// one, and the recovery route is not a convenience: a user who lost every
/// passkey and got back in with their code has no passkey opener to offer,
/// so a passkey-only ceremony would leave that account unable to key the
/// replacement passkey they just enrolled — recovery-code-only, on every
/// device, for good. Recovering is meant to get somebody back in, not cost
/// them the way back.
///
/// The cost differs by route, which is why the panel names it before it
/// starts. A passkey opener means two authenticator interactions here, three
/// counting the credential's own creation, and there is no version with
/// fewer. A recovery opener means one: the assertion against `target`.
///
/// That assertion must answer with `target`. Filing the wrap under whichever
/// credential happened to reply would leave `target` still keyless while
/// quietly keying something else, and the user would be told it worked.
#[cfg(feature = "hydrate")]
pub async fn add_passkey_key(user: &str, target: &[u8], source: KeySource) -> Result<(), String> {
    use crate::server_fns::encryption::{encryption_add_passkey_wrap, encryption_wraps};

    use super::{add_passkey_route, choose_route};

    let wraps = encryption_wraps().await.map_err(server_unreachable)?;
    if choose_route(&wraps, Some(target)).is_some() {
        return Err("That passkey can already open your entries.".to_string());
    }

    let existing = open_existing_route(user, source, &wraps).await?;

    let fresh = assert_with_prf(user).await.map_err(assertion_message)?;
    must_be_target(&fresh.credential_id, target)?;

    let wrapped = add_passkey_route(&existing.opener(), &fresh.prf_output)
        .await
        .map_err(|err| existing.rewrap_failed(err))?;

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
pub const SERVER_UNREACHABLE: &str =
    "Couldn't reach the server. Check your connection and try again.";

#[cfg(feature = "hydrate")]
pub fn server_unreachable(_: ServerFnError) -> String {
    SERVER_UNREACHABLE.to_string()
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

    /// The guard that keeps a wrap and its credential together. Adding a
    /// passkey asks for two assertions and the user picks from a browser
    /// list, so answering with the wrong one is an ordinary mistake rather
    /// than an attack — and the outcome without this check is the bad kind
    /// of silent: the new passkey stays keyless, some other credential gains
    /// a second route it did not need, and the panel reports success.
    ///
    /// The prefix case is the one worth spelling out. A comparison that
    /// stopped at the shorter length would accept `[1, 2]` as `[1, 2, 3]`,
    /// and credential ids are opaque byte strings with no fixed length.
    #[test]
    fn only_the_credential_this_step_is_for_may_answer() {
        assert!(must_be_target(b"cred-a", b"cred-a").is_ok());

        let wrong = must_be_target(b"cred-b", b"cred-a").expect_err("a different credential");
        assert!(
            wrong.contains("wasn't the passkey this step is for"),
            "the refusal must say which step went wrong: {wrong}"
        );

        assert!(
            must_be_target(&[1, 2], &[1, 2, 3]).is_err(),
            "a prefix is a different credential, not the same one"
        );
        assert!(
            must_be_target(&[1, 2, 3], &[1, 2]).is_err(),
            "and so is an extension of one"
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
