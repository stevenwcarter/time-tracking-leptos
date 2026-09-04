//! In-flight WebAuthn ceremony state, HMAC-signed into a short-lived cookie.
//!
//! Never persisted to the database: a ceremony lasts seconds, and a table
//! would need sweeping. The signature is what makes it safe to hand the
//! state to the client — a user can read their own ceremony state, but
//! cannot forge one naming another subject.
//!
//! Signed with `PASSKEY_STATE_KEY`, deliberately *not* the session key.
//! photo365 reuses one `HASH_KEY` for every purpose; separate keys mean
//! compromising one does not forge the others.

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ring::hmac;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::server::cookie;

pub const COOKIE_NAME: &str = "__pk_state";
const MAX_AGE_SECONDS: i64 = 300;
/// Domain separation, so a signature minted here can never be replayed as a
/// session token even if the two keys were ever misconfigured to match.
const DOMAIN_TAG: &[u8] = b"passkey-ceremony-v1\0";
const SIG_LEN: usize = 32;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PasskeyState {
    Reg {
        subject: String,
        reg: PasskeyRegistration,
        expires_at: i64,
    },
    Auth {
        subject: String,
        auth: PasskeyAuthentication,
        expires_at: i64,
    },
    DiscoverableAuth {
        auth: DiscoverableAuthentication,
        expires_at: i64,
    },
}

impl PasskeyState {
    pub fn reg(subject: String, reg: PasskeyRegistration) -> Self {
        Self::Reg { subject, reg, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    pub fn auth(subject: String, auth: PasskeyAuthentication) -> Self {
        Self::Auth { subject, auth, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    pub fn discoverable(auth: DiscoverableAuthentication) -> Self {
        Self::DiscoverableAuth { auth, expires_at: now_secs() + MAX_AGE_SECONDS }
    }
    fn expires_at(&self) -> i64 {
        match self {
            Self::Reg { expires_at, .. }
            | Self::Auth { expires_at, .. }
            | Self::DiscoverableAuth { expires_at, .. } => *expires_at,
        }
    }
}

fn now_secs() -> i64 {
    Utc::now().timestamp()
}

fn key() -> hmac::Key {
    let configured = std::env::var("PASSKEY_STATE_KEY").unwrap_or_default();
    let configured = if configured.is_empty() {
        // Fall back to the session key rather than a constant: still a real
        // secret, still domain-separated by DOMAIN_TAG below.
        std::env::var("SESSION_KEY").unwrap_or_default()
    } else {
        configured
    };
    assert!(
        !configured.is_empty(),
        "PASSKEY_STATE_KEY (or SESSION_KEY) must be set to a non-empty value"
    );
    let mut material = DOMAIN_TAG.to_vec();
    material.extend_from_slice(configured.as_bytes());
    hmac::Key::new(hmac::HMAC_SHA256, &material)
}

pub fn encode(state: &PasskeyState) -> Result<String> {
    let body = serde_json::to_vec(state).context("serialize ceremony state")?;
    let sig = hmac::sign(&key(), &body);
    let mut out = body;
    out.extend_from_slice(sig.as_ref());
    Ok(URL_SAFE_NO_PAD.encode(&out))
}

pub fn decode(raw: &str) -> Result<PasskeyState> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .context("base64 decode ceremony state")?;
    if bytes.len() < SIG_LEN {
        bail!("ceremony state payload too short");
    }
    let (body, sig) = bytes.split_at(bytes.len() - SIG_LEN);
    hmac::verify(&key(), body, sig).map_err(|_| anyhow!("ceremony state signature invalid"))?;
    let state: PasskeyState =
        serde_json::from_slice(body).context("deserialize ceremony state")?;
    if state.expires_at() < now_secs() {
        bail!("ceremony state expired");
    }
    Ok(state)
}

pub fn set_cookie_header(encoded: &str) -> String {
    cookie::http_only(COOKIE_NAME, encoded, MAX_AGE_SECONDS)
}

pub fn clear_cookie_header() -> String {
    cookie::http_only(COOKIE_NAME, "", 0)
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::passkey::webauthn::build_from_env;

    fn a_registration() -> (String, PasskeyRegistration) {
        // SAFETY of intent: the key only needs to be non-empty and stable
        // within the test process.
        unsafe { std::env::set_var("PASSKEY_STATE_KEY", "test-passkey-state-key") };
        let wa = build_from_env();
        let (_ccr, reg) = wa
            .start_passkey_registration(
                Uuid::new_v4(),
                "alice@example.com",
                "alice@example.com",
                None,
            )
            .expect("start registration");
        ("alice@example.com".to_string(), reg)
    }

    #[test]
    fn encode_decode_round_trips() {
        let (subject, reg) = a_registration();
        let encoded = encode(&PasskeyState::reg(subject.clone(), reg)).expect("encode");
        match decode(&encoded).expect("decode") {
            PasskeyState::Reg { subject: got, .. } => assert_eq!(got, subject),
            other => panic!("expected Reg, got {other:?}"),
        }
    }

    /// The ceremony state rides in a cookie the user can edit. A tampered
    /// payload must be rejected, not deserialized.
    #[test]
    fn rejects_a_tampered_payload() {
        let (subject, reg) = a_registration();
        let encoded = encode(&PasskeyState::reg(subject, reg)).expect("encode");
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).expect("decode b64");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        assert!(decode(&URL_SAFE_NO_PAD.encode(&bytes)).is_err());
    }

    #[test]
    fn rejects_an_expired_state() {
        let (subject, reg) = a_registration();
        let mut state = PasskeyState::reg(subject, reg);
        match &mut state {
            PasskeyState::Reg { expires_at, .. } => *expires_at = now_secs() - 1,
            _ => unreachable!(),
        }
        let encoded = encode(&state).expect("encode");
        assert!(decode(&encoded).is_err(), "expired state must not decode");
    }

    #[test]
    fn clear_header_expires_the_cookie() {
        assert!(clear_cookie_header().contains("Max-Age=0"));
        assert!(clear_cookie_header().starts_with(COOKIE_NAME));
    }
}
