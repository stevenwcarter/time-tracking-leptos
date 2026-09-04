//! End-to-end coverage of the `/magic/{token}` route.

#![cfg(feature = "ssr")]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

#[tokio::test]
async fn a_valid_link_sets_a_session_cookie_and_redirects() {
    let (app, token) =
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
    let (app, token) =
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
    let (app, _) =
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

/// Pins invariant I5. An attacker must not be able to tell a registered
/// address from an unregistered one, or a rate-limited request from an
/// accepted one, by anything in the response.
#[tokio::test]
async fn request_magic_link_responds_identically_for_every_outcome() {
    let app = time_tracking_leptos::test_support::router().await;

    async fn post(app: axum::Router, email: &str) -> (StatusCode, String) {
        let res = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/session/request_link")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"email":"{email}"}}"#)))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.expect("body");
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    // Register one address so the two cases genuinely differ server-side.
    time_tracking_leptos::test_support::seed_user(&app, "known@example.com").await;

    let known = post(app.clone(), "known@example.com").await;
    let unknown = post(app.clone(), "nobody@example.com").await;
    let malformed = post(app.clone(), "not-an-address").await;
    assert_eq!(known, unknown, "known and unknown addresses must be indistinguishable");
    assert_eq!(known, malformed, "a malformed address must look the same too");

    // Exhaust the bucket; the over-quota response must still match.
    for _ in 0..10 {
        let _ = post(app.clone(), "known@example.com").await;
    }
    assert_eq!(post(app, "known@example.com").await, known, "rate-limited must look the same");
}
