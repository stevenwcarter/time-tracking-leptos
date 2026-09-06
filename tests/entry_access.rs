//! Pins invariant I7 where it matters most: at the HTTP boundary, with a
//! real session cookie, not just at the repository.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{SessionClient, TestApp, signed_in_as};

/// What a sealed body actually looks like on the wire, for the tests that
/// care about the difference between "refused for the account" and "refused
/// for the body". Its contents are made up: the server stores the string
/// opaquely and never opens one.
const SEALED_BODY: &str = r#"{"v":2,"alg":"a256gcm","n":"bm9uY2U","ct":"Y2lwaGVy"}"#;

/// Marks this account as encrypted, the way the setup flow does.
///
/// Entry writes require it (invariant E9), so a test that is about
/// something else — cross-account scoping, session revocation — has to get
/// past that precondition before it can reach what it is actually about.
/// The encryption-key-only route is the shorter of the two and needs no
/// enrolled credential; the wrap bytes are arbitrary, since nothing
/// server-side ever opens one.
async fn enable_encryption(client: &SessionClient) {
    client
        .encryption_enable_key_only(&[7; 40])
        .await
        .expect("enable encryption");
}

#[tokio::test]
async fn a_user_cannot_read_another_users_entry() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;
    // The precondition, not the subject: nothing can be written until the
    // account is set up (invariant E9). What this test is about starts at
    // the assertions.
    enable_encryption(&alice).await;

    alice
        .save_entry("2026-09-04", "alice-secret")
        .await
        .expect("save");

    assert_eq!(mallory.load_entry("2026-09-04").await.expect("load"), None);
    assert!(
        mallory
            .entries_in_range("2026-09-01", "2026-09-30")
            .await
            .expect("range")
            .is_empty()
    );
    assert!(
        mallory
            .entry_dates_in_range("2026-09-01", "2026-09-30")
            .await
            .expect("range")
            .is_empty()
    );
}

#[tokio::test]
async fn a_signed_out_caller_is_refused() {
    let app = TestApp::new().await;
    let anon = app.anonymous();
    assert!(anon.load_entry("2026-09-04").await.is_err());
    assert!(anon.save_entry("2026-09-04", "x").await.is_err());
    assert!(
        anon.entries_in_range("2026-09-01", "2026-09-30")
            .await
            .is_err()
    );
}

/// Bumping the epoch must invalidate a cookie that is otherwise still valid.
#[tokio::test]
async fn sign_out_everywhere_invalidates_an_existing_cookie() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    enable_encryption(&alice).await;
    alice.save_entry("2026-09-04", "x").await.expect("save");

    let other_device = alice.clone_session();
    alice
        .sign_out_everywhere()
        .await
        .expect("sign out everywhere");

    assert!(
        other_device.load_entry("2026-09-04").await.is_err(),
        "a token minted under the old epoch must stop working"
    );
}

#[tokio::test]
async fn malformed_dates_and_wide_ranges_are_rejected() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    assert!(alice.load_entry("not-a-date").await.is_err());
    assert!(
        alice
            .entries_in_range("2026-09-30", "2026-09-01")
            .await
            .is_err(),
        "reversed range"
    );
    assert!(
        alice
            .entries_in_range("2020-01-01", "2026-12-31")
            .await
            .is_err(),
        "range too wide"
    );
}

/// Invariant E9, and the whole point of the feature. If this regresses,
/// plaintext storage becomes possible again with nothing else to catch it.
///
/// The body posted here is a well-formed *sealed* envelope, deliberately:
/// the refusal has to come from what the account is, not from what the body
/// looks like. A server that opened the envelope to check its version would
/// be parsing an entry, which is the one thing it must never do (invariant
/// E1) — so this test would pass either way, and
/// [`an_encrypted_account_may_store_any_string_at_all`] is the one that
/// tells the two implementations apart.
#[tokio::test]
async fn entry_save_is_refused_when_the_account_has_no_encryption() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let refused = alice
        .save_entry("2026-09-04", SEALED_BODY)
        .await
        .expect_err("an account with no encryption must not be able to write");
    assert!(
        refused.contains("encryption"),
        "the refusal must name what to set up, not leak internal detail: {refused}"
    );

    assert_eq!(
        alice.load_entry("2026-09-04").await.expect("load"),
        None,
        "a refused save must leave nothing behind"
    );
}

/// The positive control for the test above. A check that never passes is
/// indistinguishable from an endpoint that is simply broken, so the same
/// account makes the same call either side of enabling encryption and the
/// answer has to change.
#[tokio::test]
async fn entry_save_is_accepted_once_encryption_is_enabled() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    assert!(
        alice.save_entry("2026-09-04", SEALED_BODY).await.is_err(),
        "the refusal must be in force before the account is set up"
    );

    enable_encryption(&alice).await;

    alice
        .save_entry("2026-09-04", SEALED_BODY)
        .await
        .expect("an encrypted account must be able to write");
    assert_eq!(
        alice.load_entry("2026-09-04").await.expect("load"),
        Some(SEALED_BODY.to_string()),
        "the body must come back exactly as it was sent"
    );
}

/// Invariant E10: the server enforces on `user.encrypted_at` and never on
/// the body. The string below is not an envelope at all, let alone a sealed
/// one, and it must still round-trip untouched — an implementation that
/// checked the version instead of the account would refuse it.
#[tokio::test]
async fn an_encrypted_account_may_store_any_string_at_all() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    enable_encryption(&alice).await;

    alice
        .save_entry("2026-09-04", "9-10 code1")
        .await
        .expect("save an opaque, unparseable body");
    assert_eq!(
        alice.load_entry("2026-09-04").await.expect("load"),
        Some("9-10 code1".to_string())
    );
}
