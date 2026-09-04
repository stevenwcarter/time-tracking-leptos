//! Pins spec invariant I4: adding `/{date}` as a top-level route means any
//! single-segment path now matches the app. Static root assets and the
//! `/account` route must still win.

#![cfg(feature = "ssr")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Builds the router exactly as `main` does. Kept in sync by construction:
/// `time_tracking_leptos::test_support::router()` is the same function main
/// calls.
async fn get(path: &str) -> (StatusCode, String) {
    let app = time_tracking_leptos::test_support::router().await;
    let res = app
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn favicon_is_not_shadowed_by_the_date_route() {
    let (status, body) = get("/favicon.ico").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("<!DOCTYPE html>"),
        "/favicon.ico served the app shell — the /{{date}} route is shadowing \
         the static handler (see ROOT_ASSETS in test_support.rs)"
    );
}

#[tokio::test]
#[ignore = "enabled by Task 19"]
async fn account_route_beats_the_date_route() {
    let (status, body) = get("/account").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Passkeys"),
        "/account rendered the day view instead of the account page"
    );
}

#[tokio::test]
#[ignore = "enabled by Task 19"]
async fn a_real_date_renders_the_day_view() {
    let (status, body) = get("/2026-09-04").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Time Entry"),
        "date route did not render the day view"
    );
}

#[tokio::test]
#[ignore = "enabled by Task 19"]
async fn a_non_date_segment_is_not_found() {
    let (_, body) = get("/definitely-not-a-date").await;
    assert!(
        body.contains("Page not found"),
        "junk segment must render NotFound"
    );
}
