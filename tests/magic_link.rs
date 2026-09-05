//! End-to-end coverage of the `/magic/{token}` route.

#![cfg(feature = "ssr")]

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

/// A `GET` carrying `ip` as its `ConnectInfo`, the way axum supplies one in
/// production (`auth::middleware::attach` reads it from there).
///
/// Every test here passes a *distinct* address, and that is load-bearing:
/// `rate_limit`'s buckets are process-global `OnceLock` statics, so any test
/// that leaves `ConnectInfo` unset falls back to the middleware's `"unknown"`
/// key and shares one quota with every other such test in this binary.
/// `request_magic_link_responds_identically_for_every_outcome` drains that
/// bucket on purpose, and these tests run in parallel — so on a shared
/// address, whichever reissue test lost the race would see a refusal instead
/// of the behaviour it is asserting. Real clients have distinct addresses.
fn get_from(uri: &str, ip: &str) -> Request<Body> {
    let mut req = Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("request");
    let addr: SocketAddr = format!("{ip}:40000").parse().expect("valid socket address");
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

#[tokio::test]
async fn a_valid_link_sets_a_session_cookie_and_redirects() {
    let (app, token, _mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("alice@example.com").await;
    let res = app
        .oneshot(get_from(&format!("/magic/{token}"), "203.0.113.1"))
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
        .oneshot(get_from(&format!("/magic/{token}"), "203.0.113.2"))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let second = app
        .oneshot(get_from(&format!("/magic/{token}"), "203.0.113.2"))
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
        .oneshot(get_from("/magic/nope", "203.0.113.3"))
        .await
        .expect("response");
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(res.headers().get(header::SET_COOKIE).is_none());
}

/// Waits for `n` `tokio::spawn`ed sends to land in the capture mailer, so a
/// test doesn't race the response against sends the handler deliberately
/// does not await.
async fn wait_for_captured(
    mailer: &time_tracking_leptos::email::Mailer,
    n: usize,
) -> Vec<time_tracking_leptos::email::OutboundEmail> {
    for _ in 0..1000 {
        let sent = mailer.captured();
        if sent.len() >= n {
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
        .oneshot(get_from(&format!("/magic/{token}"), "203.0.113.4"))
        .await
        .expect("response");
    assert_eq!(
        first.status(),
        StatusCode::SEE_OTHER,
        "first click signs in"
    );

    let second = app
        .clone()
        .oneshot(get_from(&format!("/magic/{token}"), "203.0.113.4"))
        .await
        .expect("response");
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "replay renders the reissue page"
    );

    let sent = wait_for_captured(&mailer, 1).await;
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
        .oneshot(get_from(&format!("/magic/{new_token}"), "203.0.113.4"))
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

/// The regression this guards against: the `Stale` branch mints and mails a
/// fresh link on *every* replay, and it was the one mail-sending path with no
/// limiter on it — `request_magic_link` had both checks from the start, this
/// handler was written separately and never got them.
///
/// A spent link URL is not a secret: it survives in forwarded mail, shared
/// browser history, and proxy logs. Unlimited, anyone holding one could
/// mail-bomb the address it belongs to indefinitely and grow
/// `magic_link_token` without bound.
#[tokio::test]
async fn replaying_a_link_cannot_mail_without_limit() {
    const IP: &str = "203.0.113.9";
    const REPLAYS: usize = 12;
    let capacity = time_tracking_leptos::rate_limit::MAGIC_CAPACITY as usize;

    let (app, token, mailer) =
        time_tracking_leptos::test_support::app_with_magic_link("bomb@example.com").await;

    // Spend it once, so every request after this takes the `Stale` branch.
    let first = app
        .clone()
        .oneshot(get_from(&format!("/magic/{token}"), IP))
        .await
        .expect("response");
    assert_eq!(first.status(), StatusCode::SEE_OTHER);

    let mut rendered = Vec::with_capacity(REPLAYS);
    for _ in 0..REPLAYS {
        let res = app
            .clone()
            .oneshot(get_from(&format!("/magic/{token}"), IP))
            .await
            .expect("response");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .expect("body");
        rendered.push((status, String::from_utf8_lossy(&bytes).into_owned()));
    }

    let sent = wait_for_captured(&mailer, capacity).await;
    assert_eq!(
        sent.len(),
        capacity,
        "{REPLAYS} replays must mail at most one bucket's worth"
    );

    // The refusal must be byte-identical to the send. A distinguishable one
    // would turn this route into an oracle for whether an address is being
    // limited, and hand an attacker a signal to pace against.
    assert!(
        rendered.windows(2).all(|pair| pair[0] == pair[1]),
        "a rate-limited replay must render exactly what an accepted one does"
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
        let mut req = Request::builder()
            .method("POST")
            .uri("/api/session/request_link")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("request");
        // This test drains its IP bucket on purpose (below), so it needs an
        // address of its own — see `get_from`.
        req.extensions_mut().insert(ConnectInfo(
            "203.0.113.8:40000"
                .parse::<SocketAddr>()
                .expect("valid socket address"),
        ));
        let res = router.oneshot(req).await.expect("response");
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
    let sent = wait_for_captured(&app.mailer, 1).await;
    assert!(
        !sent.is_empty(),
        "a valid email must produce a captured message"
    );
    assert_eq!(sent[0].to, "known@example.com");
}
