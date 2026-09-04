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
