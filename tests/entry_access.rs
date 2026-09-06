//! Pins invariant I7 where it matters most: at the HTTP boundary, with a
//! real session cookie, not just at the repository.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{TestApp, signed_in_as};

#[tokio::test]
async fn a_user_cannot_read_another_users_entry() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;

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

/// The read half of the encryption migration pass (spec section 8): no date
/// bounds, and scoped to the caller the same as every other read here.
#[tokio::test]
async fn entries_all_returns_every_row_for_the_caller_only() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;

    alice.save_entry("2020-01-01", "old").await.expect("save");
    alice
        .save_entry("2026-09-04", "recent")
        .await
        .expect("save");
    mallory
        .save_entry("2026-09-04", "mallory-secret")
        .await
        .expect("save");

    assert_eq!(
        alice.entries_all().await.expect("all"),
        vec![
            ("2020-01-01".to_string(), "old".to_string()),
            ("2026-09-04".to_string(), "recent".to_string()),
        ]
    );
}

#[tokio::test]
async fn save_many_writes_every_entry_in_one_call() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    alice
        .save_entries_many(&[
            ("2026-09-01", "one"),
            ("2026-09-02", "two"),
            ("2026-09-03", "three"),
        ])
        .await
        .expect("save many");

    assert_eq!(
        alice.entries_all().await.expect("all"),
        vec![
            ("2026-09-01".to_string(), "one".to_string()),
            ("2026-09-02".to_string(), "two".to_string()),
            ("2026-09-03".to_string(), "three".to_string()),
        ]
    );
}

/// Partial application would leave the migration in a state neither the
/// client nor the server can describe. All or nothing.
#[tokio::test]
async fn save_many_is_atomic_when_one_entry_is_rejected() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    let result = alice
        .save_entries_many(&[
            ("2026-09-01", "one"),
            ("not-a-date", "two"),
            ("2026-09-03", "three"),
        ])
        .await;

    assert!(result.is_err());
    assert!(
        alice.entries_all().await.expect("all").is_empty(),
        "the entries either side of the rejected one must not have landed"
    );
}

/// The same cap `entry_save` applies, applied per body. A bulk endpoint that
/// skipped it would be a way around the limit.
#[tokio::test]
async fn save_many_enforces_the_per_body_length_cap() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    // One byte past `entries::MAX_BODY_BYTES` (256 KiB), mirrored here as a
    // literal rather than imported: that constant is private to the ssr
    // module, same as the boundary a real caller would meet.
    let oversized = "x".repeat(256 * 1024 + 1);

    let result = alice
        .save_entries_many(&[("2026-09-01", "one"), ("2026-09-02", &oversized)])
        .await;

    assert!(result.is_err());
    assert!(alice.entries_all().await.expect("all").is_empty());
}

/// The per-body cap does not bound a batch: 256 KiB times "as many rows as
/// the client sent" is not a limit, and the whole batch is applied inside one
/// SQLite write transaction. Nothing upstream bounds it either — the
/// server-fn route takes `Request<Body>`, so axum's `DefaultBodyLimit` is not
/// in the path.
///
/// Refused before the transaction opens, so an oversized request never takes
/// the write lock: the assertion that nothing landed is what would catch that
/// ordering being lost.
#[tokio::test]
async fn save_many_caps_the_batch_as_well_as_each_body() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;

    // One past `entries::MAX_BATCH_ROWS` (200), mirrored as a literal for
    // the reason the per-body test gives.
    let dates: Vec<String> = (0..201).map(|n| format!("2026-01-01T{n}")).collect();
    let too_many: Vec<(&str, &str)> = dates.iter().map(|d| (d.as_str(), "x")).collect();
    let refused = alice
        .save_entries_many(&too_many)
        .await
        .expect_err("a batch over the row cap must be refused");
    assert!(
        refused.contains("too many entries"),
        "the refusal must name the row count, not the date it never parsed: {refused}"
    );

    // Under the row cap, over the byte cap: 5 bodies of 256 KiB is 1.25 MiB,
    // past `MAX_BATCH_BYTES` (1 MiB), with every individual body legal.
    let body = "x".repeat(256 * 1024);
    let dates: Vec<String> = (1..=5).map(|n| format!("2026-03-{n:02}")).collect();
    let too_large: Vec<(&str, &str)> = dates.iter().map(|d| (d.as_str(), body.as_str())).collect();
    let refused = alice
        .save_entries_many(&too_large)
        .await
        .expect_err("a batch over the byte cap must be refused");
    assert!(
        refused.contains("too large"),
        "the refusal must name the batch's size: {refused}"
    );

    assert!(
        alice.entries_all().await.expect("all").is_empty(),
        "a refused batch must write nothing at all"
    );
}
