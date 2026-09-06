//! The two quotas behind `passkey_login_start`, at the HTTP boundary.
//!
//! **Its own test binary on purpose.** The limiters are process-wide
//! `OnceLock`s keyed by client IP, and no test request carries one, so every
//! caller in a binary shares the key `"unknown"`. Exhausting a bucket is
//! therefore something a test can only do without racing its neighbours if
//! it has the process to itself — and exhausting one is the whole point
//! here. Adding a second test to this file means thinking about that;
//! `tests/passkey_access.rs` is where a test that merely *uses* the endpoint
//! belongs.

#![cfg(feature = "ssr")]

use time_tracking_leptos::rate_limit::MAGIC_CAPACITY;
use time_tracking_leptos::test_support::{TestApp, signed_in_as};
use time_tracking_leptos::{auth, passkey};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::*;

/// Enrols a credential straight against the pool. This file is about the
/// limiter, not the registration ceremony — `tests/passkey_access.rs` covers
/// that — but the signed-in half below needs a credential to exist, or its
/// call would fail the generic "no enrolled passkey" way and prove nothing
/// about quotas.
fn enrol_credential(subject: &str) -> Passkey {
    let wa = passkey::webauthn::build_from_env();
    let (ccr, reg_state) = wa
        .start_passkey_registration(Uuid::new_v4(), subject, subject, None)
        .expect("start registration");
    let mut authenticator = SoftPasskey::new(true);
    let rsp = authenticator
        .do_registration(wa.get_allowed_origins()[0].clone(), ccr)
        .expect("authenticator registration");
    wa.finish_passkey_registration(&rsp, &reg_state)
        .expect("finish registration")
}

/// Phase 2 routed every encryption ceremony through `passkey_login_start`,
/// and adding a passkey to an encrypted account spends two tokens. Sharing
/// one bucket with anonymous sign-in meant a user who signed in, enabled
/// encryption and added a second passkey had spent four of five — and the
/// refusal lands mid-ceremony, after the new credential already exists.
///
/// The anonymous bucket still has to bite, or the fix would be "stop
/// limiting", which gives up invariant I6's anti-enumeration budget.
#[tokio::test]
async fn a_signed_in_ceremony_does_not_draw_on_the_sign_in_quota() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    let anon = app.anonymous();
    for attempt in 0..MAGIC_CAPACITY {
        // Every one of these is refused — the address has no passkeys — but
        // a refusal still costs a token, which is the point.
        let refused = anon
            .passkey_login_start(Some("nobody@example.com"))
            .await
            .expect_err("no account, no challenge");
        assert!(
            !refused.contains("Too many"),
            "attempt {attempt} is still within quota, got: {refused}"
        );
    }
    let over = anon
        .passkey_login_start(Some("nobody@example.com"))
        .await
        .expect_err("over quota");
    assert!(
        over.contains("Too many"),
        "the anonymous bucket must still bite: {over}"
    );
    assert!(
        !over.contains("a minute"),
        "the wait must be the one this bucket imposes, not a rounded guess: {over}"
    );

    alice
        .passkey_login_start(Some("alice@example.com"))
        .await
        .expect("a signed-in caller's ceremony must not be refused by the sign-in quota");
}
