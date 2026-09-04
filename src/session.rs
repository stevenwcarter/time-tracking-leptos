//! The session cookie's token format.
//!
//! `v1.<b64url(email)>.<issued>.<expires>.<epoch>.<hmac_hex>`, with the MAC
//! taken over the five preceding dot-joined fields.
//!
//! Verification here is deliberately **stateless** — signature and clock
//! only, no database. That is all the page shell needs to decide whether to
//! render a signed-in corner. Revocation lives one layer up:
//! `server_fns::require_user` compares the `epoch` carried here against the
//! user row's `session_epoch`, so bumping that column signs every device out
//! on its next data access. See spec §5.1.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::hmac;

pub const COOKIE_NAME: &str = "tt_session";
/// 30 days.
pub const MAX_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;
const VERSION: &str = "v1";
const SKEW_TOLERANCE_SECS: i64 = 5;

/// What a valid session token asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaims {
    pub email: String,
    pub epoch: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("session token is malformed")]
    Malformed,
    #[error("session token signature does not verify")]
    BadSignature,
    #[error("session token has expired")]
    Expired,
    #[error("session token was issued in the future")]
    InFuture,
}

fn b64(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

fn sign(payload: &str, key: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hex::encode(hmac::sign(&key, payload.as_bytes()).as_ref())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Issues a token valid for [`MAX_AGE_SECONDS`] from `now`.
fn issue_at(email: &str, epoch: i64, now: i64, key: &[u8]) -> String {
    let payload = format!(
        "{VERSION}.{}.{now}.{}.{epoch}",
        b64(email.as_bytes()),
        now + MAX_AGE_SECONDS,
    );
    let mac = sign(&payload, key);
    format!("{payload}.{mac}")
}

/// Verifies signature and clock. Performs no database access.
fn verify_at(raw: &str, now: i64, key: &[u8]) -> Result<SessionClaims, SessionError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 6 || parts[0] != VERSION {
        return Err(SessionError::Malformed);
    }
    let issued: i64 = parts[2].parse().map_err(|_| SessionError::Malformed)?;
    let expires: i64 = parts[3].parse().map_err(|_| SessionError::Malformed)?;
    let epoch: i64 = parts[4].parse().map_err(|_| SessionError::Malformed)?;

    // Signature is checked before any claim is trusted, including the clock
    // fields parsed above — those are only used after this point.
    let payload = parts[..5].join(".");
    if !constant_time_eq(sign(&payload, key).as_bytes(), parts[5].as_bytes()) {
        return Err(SessionError::BadSignature);
    }

    if issued > now + SKEW_TOLERANCE_SECS {
        return Err(SessionError::InFuture);
    }
    if now >= expires {
        return Err(SessionError::Expired);
    }

    let email = URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(SessionError::Malformed)?;

    Ok(SessionClaims { email, epoch })
}

/// The signing key, read once per call from `SESSION_KEY`.
///
/// In release builds an unset or empty key is fatal — refusing to boot beats
/// silently signing every session with a guessable constant. In debug builds
/// a random ephemeral key is generated with a warning, so `cargo leptos
/// watch` works out of the box; sessions then do not survive a restart.
#[cfg(feature = "ssr")]
fn session_key() -> Vec<u8> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| match std::env::var("SESSION_KEY") {
        Ok(k) if !k.is_empty() => k.into_bytes(),
        _ if cfg!(debug_assertions) => {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut buf = [0u8; 32];
            SystemRandom::new()
                .fill(&mut buf)
                .expect("system randomness");
            tracing::warn!(
                "SESSION_KEY is unset; generated an ephemeral key. \
                 Sessions will not survive a restart. Set SESSION_KEY \
                 for anything but local development."
            );
            buf.to_vec()
        }
        _ => panic!("SESSION_KEY must be set to a non-empty value in release builds"),
    })
    .clone()
}

#[cfg(feature = "ssr")]
fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Issues a session token for `email` at the user's current `epoch`.
#[cfg(feature = "ssr")]
pub fn issue(email: &str, epoch: i64) -> String {
    issue_at(email, epoch, now_secs(), &session_key())
}

/// Verifies a session token's signature and clock.
#[cfg(feature = "ssr")]
pub fn verify(raw: &str) -> Result<SessionClaims, SessionError> {
    verify_at(raw, now_secs(), &session_key())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    const KEY: &str = "test-session-key-not-a-real-secret";

    fn issued_at(email: &str, epoch: i64, now: i64) -> String {
        issue_at(email, epoch, now, KEY.as_bytes())
    }

    #[test]
    fn round_trips_claims() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 3, now);
        let claims = verify_at(&tok, now + 60, KEY.as_bytes()).expect("valid");
        assert_eq!(claims.email, "alice@example.com");
        assert_eq!(claims.epoch, 3);
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let mut parts: Vec<&str> = tok.split('.').collect();
        let mut sig = parts[5].to_string();
        let last = sig.pop().expect("non-empty signature");
        sig.push(if last == '0' { '1' } else { '0' });
        parts[5] = &sig;
        assert_eq!(
            verify_at(&parts.join("."), now + 60, KEY.as_bytes()),
            Err(SessionError::BadSignature)
        );
    }

    /// Swapping the email while keeping a valid signature from another token
    /// is the attack the MAC exists to stop.
    #[test]
    fn rejects_a_swapped_email() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let parts: Vec<&str> = tok.split('.').collect();
        let forged = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0],
            b64(b"mallory@example.com"),
            parts[2],
            parts[3],
            parts[4],
            parts[5],
        );
        assert_eq!(
            verify_at(&forged, now + 60, KEY.as_bytes()),
            Err(SessionError::BadSignature)
        );
    }

    #[test]
    fn rejects_an_expired_token() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        let after = now + MAX_AGE_SECONDS + 1;
        assert_eq!(
            verify_at(&tok, after, KEY.as_bytes()),
            Err(SessionError::Expired)
        );
    }

    #[test]
    fn tolerates_small_clock_skew_but_not_large() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        // Verifier's clock 3s behind the issuer: fine.
        assert!(verify_at(&tok, now - 3, KEY.as_bytes()).is_ok());
        // An hour behind: not fine.
        assert_eq!(
            verify_at(&tok, now - 3600, KEY.as_bytes()),
            Err(SessionError::InFuture)
        );
    }

    #[test]
    fn rejects_a_token_signed_with_another_key() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 0, now);
        assert_eq!(
            verify_at(&tok, now + 60, b"a-completely-different-key"),
            Err(SessionError::BadSignature)
        );
    }

    #[test]
    fn rejects_malformed_tokens() {
        let now = 1_788_000_000;
        for junk in ["", "garbage", "v1.a.b.c", "v9.a.b.c.d.e"] {
            assert_eq!(
                verify_at(junk, now, KEY.as_bytes()),
                Err(SessionError::Malformed),
                "{junk:?} must be rejected as malformed"
            );
        }
    }

    /// The epoch must survive verification intact — it is what
    /// `require_user` compares against the database to honour a revocation.
    #[test]
    fn carries_the_issuing_epoch() {
        let now = 1_788_000_000;
        let tok = issued_at("alice@example.com", 41, now);
        assert_eq!(
            verify_at(&tok, now + 60, KEY.as_bytes()).expect("valid").epoch,
            41
        );
    }
}
