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
/// `idx_entry_key_wrap_one_encryption_key` unique index tripping on the
/// second encryption-key-wrap insert underneath it — the guard's own message
/// is asserted here specifically so a deleted guard fails this test with a
/// generic internal-server-error message rather than passing for the wrong
/// reason.
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

/// Spec section 6.1's second route. An owner whose browser extension does
/// not implement the WebAuthn PRF extension can enrol passkeys all day and
/// never get a `prf_capable` one, so the two-wrap route is closed to them
/// permanently; the encryption key alone has to be able to turn encryption on.
///
/// Asserts the shape of what lands, not just that the call succeeded: the
/// schema permits an account with one encryption-key wrap and no passkey
/// wrap (`credential_id` is nullable and both unique indexes are partial), and
/// this is what pins that the server actually writes that shape rather than
/// a passkey wrap filed under a null credential.
#[tokio::test]
async fn enabling_without_a_passkey_wrap_leaves_one_encryption_key_wrap() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    alice
        .encryption_enable_key_only(&[2; 40])
        .await
        .expect("an encryption key alone must be able to turn encryption on");

    assert!(
        alice.encryption_status().await.expect("status").enabled,
        "the account must be marked encrypted"
    );

    let wraps = alice.encryption_wraps().await.expect("wraps");
    assert_eq!(wraps.len(), 1, "exactly one wrap, got: {wraps:?}");
    assert_eq!(wraps[0].kind, "encryption_key");
    assert_eq!(wraps[0].credential_id, None);
    assert_eq!(wraps[0].wrapped_key, vec![2; 40]);
}

/// The double-enable guard is on `encrypted_at`, not on the passkey wrap, so
/// it has to hold from an encryption-key-only account too — where the second
/// call would otherwise be the *first* insert of a passkey wrap and slip past
/// nothing at all.
#[tokio::test]
async fn a_second_enable_is_refused_after_an_encryption_key_only_enable() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    alice
        .encryption_enable_key_only(&[2; 40])
        .await
        .expect("first enable");

    let err = alice
        .encryption_enable(&[3; 40], b"cred-1", &[4; 40])
        .await
        .expect_err("a second enable must be refused");
    assert!(
        err.contains("already enabled"),
        "refusal must come from the encrypted_at guard, got: {err}"
    );

    let err = alice
        .encryption_enable_key_only(&[5; 40])
        .await
        .expect_err("and so must a second encryption-key-only enable");
    assert!(
        err.contains("already enabled"),
        "refusal must come from the encrypted_at guard, got: {err}"
    );

    let wraps = alice.encryption_wraps().await.expect("wraps");
    assert_eq!(wraps.len(), 1, "a refused retry must have written nothing");
    assert_eq!(wraps[0].wrapped_key, vec![2; 40]);
}

/// The upgrade path out of encryption-key-only, and the reason the route is
/// not a one-way door: if the owner later gets hold of a PRF-capable passkey,
/// `/account`'s existing "give this passkey a key" flow keys it from the
/// encryption key — `add_passkey_route` already accepts
/// `Opener::EncryptionKey`.
///
/// This is the server half of that, which is the half an encryption-key-only
/// account could plausibly have broken: `encryption_add_passkey_wrap`
/// refuses an account that is not encrypted and a credential that already
/// has a wrap, and neither refusal may fire here.
#[tokio::test]
async fn an_encryption_key_only_account_can_add_a_passkey_wrap_afterwards() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let cred_id = key.cred_id().to_vec();
    passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    alice
        .encryption_enable_key_only(&[2; 40])
        .await
        .expect("enable");
    alice
        .encryption_add_passkey_wrap(&cred_id, &[3; 40])
        .await
        .expect("an encryption-key-only account must still be able to key a passkey");

    let wraps = alice.encryption_wraps().await.expect("wraps");
    assert_eq!(wraps.len(), 2);
    assert!(
        wraps
            .iter()
            .any(|w| w.kind == "passkey" && w.credential_id.as_deref() == Some(cred_id.as_slice())),
        "the new passkey wrap must be filed under its own credential: {wraps:?}"
    );
}

/// Spec section 6.6's refusal, checked where it is vacuous. An
/// encryption-key-only account has zero `kind = 'passkey'` wraps, so removing
/// a passkey removes no unlock route and there is nothing to protect —
/// refusing here would strand a credential the user cannot delete for a
/// reason that does not apply to them.
#[tokio::test]
async fn a_keyless_passkey_on_an_encryption_key_only_account_can_still_be_deleted() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let passkey_id = passkey::store::insert(&mut conn, uid, &key, false).expect("insert passkey");
    drop(conn);

    alice
        .encryption_enable_key_only(&[2; 40])
        .await
        .expect("enable");

    alice
        .passkey_delete(passkey_id)
        .await
        .expect("a passkey that holds no wrap is not an unlock route to protect");

    assert!(alice.passkey_list().await.expect("list").is_empty());
    let wraps = alice.encryption_wraps().await.expect("wraps");
    assert_eq!(
        wraps.len(),
        1,
        "the encryption-key wrap must survive: {wraps:?}"
    );
    assert_eq!(wraps[0].kind, "encryption_key");
}

/// And the other side of the same check: the moment an encryption-key-only
/// account gives a passkey a wrap, that wrap *is* the last passkey route and
/// section 6.6 must start refusing. Without this, "vacuous on an
/// encryption-key-only account" could be implemented as "off on an
/// encryption-key-only account", and
/// the refusal would stay off after the account stopped being one.
#[tokio::test]
async fn the_first_passkey_wrap_on_an_encryption_key_only_account_becomes_protected() {
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
        .encryption_enable_key_only(&[2; 40])
        .await
        .expect("enable");
    alice
        .encryption_add_passkey_wrap(&cred_id, &[3; 40])
        .await
        .expect("add wrap");

    let err = alice
        .passkey_delete(passkey_id)
        .await
        .expect_err("the account's only passkey wrap must now be protected");
    assert!(
        err.contains("encryption key"),
        "refusal must point at the encryption key, got: {err}"
    );
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

/// Spec section 6.6. A user with one passkey and a lost encryption key could
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
        err.contains("encryption key"),
        "refusal must point at the encryption key, got: {err}"
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
        "the encryption-key wrap and the second passkey's wrap remain"
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

/// A wrap is a route *to* a data key, so filing one for an account that has
/// none leaves a stranded blob sitting where the next `encryption_enable`
/// will write beside it. The client never asks for this, which is why the
/// refusal is worth having: nothing else would notice.
#[tokio::test]
async fn add_passkey_wrap_refuses_an_account_that_is_not_encrypted() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let cred_id = key.cred_id().to_vec();
    passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    let err = alice
        .encryption_add_passkey_wrap(&cred_id, &[9; 40])
        .await
        .expect_err("must refuse to wrap a key for an unencrypted account");
    assert!(
        err.contains("isn't encrypted"),
        "the refusal must name the account's state, got: {err}"
    );
    assert!(alice.encryption_wraps().await.expect("wraps").is_empty());
}

/// The second wrap for one credential is ambiguous, not additive, and
/// `idx_entry_key_wrap_cred` says so — but a unique-index violation reaches
/// the caller as "Internal server error", which tells somebody whose passkey
/// is already keyed to go and report a bug. Only a race between two tabs
/// gets here (the client pre-checks), so the message is the whole value.
#[tokio::test]
async fn add_passkey_wrap_refuses_a_credential_that_already_has_one() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let mut conn = app.pool.get().expect("checkout");
    let uid = auth::user::find_or_create(&mut conn, "alice@example.com")
        .expect("user")
        .id;
    let key = enrol_credential("alice@example.com");
    let cred_id = key.cred_id().to_vec();
    passkey::store::insert(&mut conn, uid, &key, true).expect("insert passkey");
    drop(conn);

    alice
        .encryption_enable(&[1; 40], &cred_id, &[2; 40])
        .await
        .expect("enable");

    let err = alice
        .encryption_add_passkey_wrap(&cred_id, &[9; 40])
        .await
        .expect_err("must refuse a second wrap for the same credential");
    assert!(
        err.contains("can already open"),
        "the refusal must say the passkey is already keyed, got: {err}"
    );
    assert!(
        !err.contains("Internal server error"),
        "a unique-index violation must not reach the user as an internal error: {err}"
    );
    assert_eq!(
        alice.encryption_wraps().await.expect("wraps").len(),
        2,
        "the refused insert must have written nothing"
    );
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
    assert!(anon.encryption_replace_key_wrap(&[2; 40]).await.is_err());

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
