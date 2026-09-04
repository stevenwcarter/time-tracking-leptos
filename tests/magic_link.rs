//! End-to-end coverage of the `/magic/{token}` route.

#![cfg(feature = "ssr")]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn a_valid_link_sets_a_session_cookie_and_redirects() {
    let (app, token, _mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get(header::LOCATION).expect("location"), "/");

    let cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("ascii");
    assert!(cookie.starts_with("tt_session="));
    assert!(
        cookie.contains("HttpOnly"),
        "session cookie must be HttpOnly"
    );
    assert!(cookie.contains("SameSite=Lax"));
}

#[tokio::test]
async fn replaying_a_link_does_not_sign_in() {
    let (app, token, _mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = app
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "replay renders the reissue page"
    );
    assert!(
        second.headers().get(header::SET_COOKIE).is_none(),
        "a replayed link must not set a session cookie"
    );
}

#[tokio::test]
async fn an_unknown_token_is_a_404_with_no_cookie() {
    let (app, _, _mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let res = app
        .oneshot(
            Request::builder()
                .uri("/magic/nope")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::SET_COOKIE).is_none());
}

/// Waits for the `tokio::spawn`ed reissue send to land in the capture
/// mailer, so this test doesn't race the response against the send it
/// deliberately does not await.
async fn wait_for_captured(
    mailer: &time_tracking_leptos::email::Mailer,
) -> Vec<time_tracking_leptos::email::OutboundEmail> {
    for _ in 0..100 {
        let sent = mailer.captured();
        if !sent.is_empty() {
            return sent;
        }
        tokio::task::yield_now().await;
    }
    mailer.captured()
}

/// The whole point of the `Stale` branch: replaying a used link must be
/// self-service recovery, not a dead end. This is the positive twin of
/// `replaying_a_link_does_not_sign_in`, which only pins the negative half
/// (no cookie).
#[tokio::test]
async fn a_replayed_link_mails_a_fresh_one_that_signs_in() {
    let (app, token, mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        first.status(),
        StatusCode::SEE_OTHER,
        "first click signs in"
    );

    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "replay renders the reissue page"
    );

    let sent = wait_for_captured(&mailer).await;
    assert_eq!(sent.len(), 1, "exactly one reissued email must be sent");
    assert_eq!(
        sent[0].to, "alice@example.com",
        "must mail the stored address"
    );

    let new_token = sent[0]
        .text
        .split("/magic/")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("reissued email must carry a fresh link");
    assert_ne!(new_token, token, "the reissued link must be a fresh token");

    let signed_in = app
        .oneshot(
            Request::builder()
                .uri(format!("/magic/{new_token}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(
        signed_in.status(),
        StatusCode::SEE_OTHER,
        "the reissued link must itself sign in"
    );
    assert!(
        signed_in.headers().get(header::SET_COOKIE).is_some(),
        "the reissued link must set a session cookie"
    );
}

/// Pins invariant I5. An attacker must not be able to tell a registered
/// address from an unregistered one, or a rate-limited request from an
/// accepted one, by anything in the response. Additionally asserts that the
/// logic actually ran — a valid address results in a captured message.
#[tokio::test]
async fn request_magic_link_responds_identically_for_every_outcome() {
    let app = time_tracking_leptos::test_support::TestApp::new().await;

    // Register one address so the two cases genuinely differ server-side.
    time_tracking_leptos::test_support::signed_in_as(&app, "known@example.com").await;

    /// Helper to post request_link and get the raw response (status + body).
    async fn post_link(router: axum::Router, email: &str) -> (StatusCode, String) {
        let body = format!(
            "email={}",
            email
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect::<String>()
        );
        let res = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/request_link")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    let known = post_link(app.router.clone(), "known@example.com").await;
    let unknown = post_link(app.router.clone(), "nobody@example.com").await;
    let malformed = post_link(app.router.clone(), "not-an-address").await;
    assert_eq!(
        known, unknown,
        "known and unknown addresses must be indistinguishable"
    );
    assert_eq!(
        known, malformed,
        "a malformed address must look the same too"
    );

    // Exhaust the bucket; the over-quota response must still match.
    for _ in 0..10 {
        let _ = post_link(app.router.clone(), "known@example.com").await;
    }
    assert_eq!(
        post_link(app.router.clone(), "known@example.com").await,
        known,
        "rate-limited must look the same"
    );

    // Assert that a valid address produced a captured message — the request
    // actually reached the logic, not just failed at deserialization.
    let sent = wait_for_captured(&app.mailer).await;
    assert!(
        !sent.is_empty(),
        "a valid email must produce a captured message"
    );
    assert_eq!(sent[0].to, "known@example.com");
}
