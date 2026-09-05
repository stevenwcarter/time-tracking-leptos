//! Pins invariant I7 for wraps, and spec section 6.6's refusal — at the HTTP
//! boundary, with a real session cookie, same as `tests/entry_access.rs`.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{TestApp, signed_in_as};
use time_tracking_leptos::{auth, passkey};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::*;

/// Enrols a credential through a real (software) authenticator and returns
/// it. This file only needs rows in `passkey_credential` to exist — it does
/// not exercise the registration ceremony itself, which
/// `tests/passkey_access.rs` already covers — so it seeds the row directly
/// against the pool rather than driving `passkey_register_start`/`_finish`
/// over HTTP.
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

/// Wraps are per-account key material. One user reading another's would not
/// leak the key — the wraps are opaque — but it would leak the credential
/// ids and the account's encryption state, and there is no reason to allow it.
#[tokio::test]
async fn wraps_are_scoped_to_the_signed_in_user() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;

    alice
        .encryption_enable(&[1; 40], b"alice-cred", &[2; 40])
        .await
        .expect("enable");

    assert!(mallory.encryption_wraps().await.expect("wraps").is_empty());
    assert_eq!(alice.encryption_wraps().await.expect("wraps").len(), 2);
}

/// A second `encryption_enable` must be caught by the application-level
/// `encrypted_at` guard, not merely by the schema's
/// `idx_entry_key_wrap_one_recovery` unique index tripping on the second
/// recovery-wrap insert underneath it — the guard's own message is asserted
/// here specifically so a deleted guard fails this test with a generic
/// internal-server-error message rather than passing for the wrong reason.
#[tokio::test]
async fn enabling_twice_is_refused() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    alice
        .encryption_enable(&[1; 40], b"cred-1", &[2; 40])
        .await
        .expect("first enable");

    let err = alice
        .encryption_enable(&[3; 40], b"cred-2", &[4; 40])
        .await
        .expect_err("a second enable must be refused");
    assert!(
        err.contains("already enabled"),
        "refusal must come from the encrypted_at guard, got: {err}"
    );
    // A rejected retry must not touch what the first call already wrote.
    assert_eq!(alice.encryption_wraps().await.expect("wraps").len(), 2);
}

#[tokio::test]
async fn status_reports_disabled_before_enabling_and_enabled_after() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let before = alice.encryption_status().await.expect("status");
    assert!(!before.enabled);

    alice
        .encryption_enable(&[1; 40], b"cred-1", &[2; 40])
        .await
        .expect("enable");
    let after = alice.encryption_status().await.expect("status");
    assert!(after.enabled);
}

/// Spec section 6.6. A user with one passkey and a lost recovery code could
/// otherwise destroy their own data with a single click.
#[tokio::test]
async fn deleting_the_last_passkey_wrap_is_refused_while_encrypted() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let cred_id = key.cred_id().to_vec();
    let passkey_id = passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    alice
        .encryption_enable(&[1; 40], &cred_id, &[2; 40])
        .await
        .expect("enable");

    let err = alice
        .passkey_delete(passkey_id)
        .await
        .expect_err("must refuse to delete the only passkey wrap while encrypted");
    assert!(
        err.contains("recovery"),
        "refusal must point at the recovery code, got: {err}"
    );

    // Refused, so both the credential and its wrap must still be there.
    assert_eq!(alice.passkey_list().await.expect("list").len(), 1);
    assert_eq!(alice.encryption_wraps().await.expect("wraps").len(), 2);
}

#[tokio::test]
async fn deleting_a_non_last_passkey_is_allowed_and_removes_its_wrap() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let first = enrol_credential("alice@example.com");
    let first_cred = first.cred_id().to_vec();
    let first_id = passkey::store::insert(&mut conn, uid, &first, true).expect("insert first");
    let second = enrol_credential("alice@example.com");
    let second_cred = second.cred_id().to_vec();
    passkey::store::insert(&mut conn, uid, &second, true).expect("insert second");
    drop(conn);

    alice
        .encryption_enable(&[1; 40], &first_cred, &[2; 40])
        .await
        .expect("enable");
    alice
        .encryption_add_passkey_wrap(&second_cred, &[3; 40])
        .await
        .expect("add second wrap");

    alice
        .passkey_delete(first_id)
        .await
        .expect("deleting a non-last passkey wrap must be allowed");

    assert_eq!(alice.passkey_list().await.expect("list").len(), 1);
    let remaining = alice.encryption_wraps().await.expect("wraps");
    assert_eq!(
        remaining.len(),
        2,
        "the recovery wrap and the second passkey's wrap remain"
    );
    assert!(
        remaining
            .iter()
            .all(|w| w.credential_id.as_deref() != Some(first_cred.as_slice())),
        "the deleted credential's own wrap must be gone too"
    );
}

/// `encryption_add_passkey_wrap` must check that `credential_id` belongs to
/// the caller before inserting anything — a wrap filed under someone else's
/// credential could never be opened by its owner, and the check is the only
/// thing standing between "another user's passkey" and "this account's key
/// material." No other test in this file or `entry_key::store`'s own unit
/// tests attempts the cross-account case, so this is the only guard against
/// a regression here.
#[tokio::test]
async fn add_passkey_wrap_refuses_a_credential_belonging_to_another_user() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let cred_id = key.cred_id().to_vec();
    passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    let err = mallory
        .encryption_add_passkey_wrap(&cred_id, &[9; 40])
        .await
        .expect_err("must refuse to wrap a credential belonging to another account");
    assert!(
        err.contains("does not belong"),
        "refusal must point at credential ownership, got: {err}"
    );

    assert!(alice.encryption_wraps().await.expect("wraps").is_empty());
    assert!(mallory.encryption_wraps().await.expect("wraps").is_empty());
}

/// An unauthenticated caller must reach none of this.
#[tokio::test]
async fn every_encryption_endpoint_requires_a_session() {
    let app = TestApp::new().await;
    let anon = app.anonymous();

    assert!(anon.encryption_status().await.is_err());
    assert!(anon.encryption_wraps().await.is_err());
    assert!(
        anon.encryption_enable(&[1; 40], b"cred", &[2; 40])
            .await
            .is_err()
    );
    assert!(
        anon.encryption_add_passkey_wrap(b"cred", &[2; 40])
            .await
            .is_err()
    );
    assert!(
        anon.encryption_replace_recovery_wrap(&[2; 40])
            .await
            .is_err()
    );

    // Positive control. Phase 1 shipped this exact test posting
    // `application/json` at form-urlencoded server functions, so all four
    // probes failed to deserialize before `require_user` ever ran and the
    // test asserted nothing for four tasks — every assertion above "passed"
    // for the wrong reason. `encryption_enable` takes the most arguments and
    // the trickiest encoding (three `Vec<u8>`s) of anything in this file, so
    // it is the sternest possible proof that a signed-in caller's identical
    // request-shape actually reaches the handler.
    let alice = signed_in_as(&app, "alice@example.com").await;
    alice
        .encryption_enable(&[1; 40], b"cred", &[2; 40])
        .await
        .expect("a signed-in caller must reach encryption_enable");
}
