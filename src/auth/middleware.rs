//! Axum middleware that turns a cookie into session claims.

use axum::extract::{ConnectInfo, Extension, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum_extra::extract::CookieJar;

use crate::context::AppCtx;
use crate::session::{self, COOKIE_NAME};

/// Verifies the session cookie and attaches the result to the request.
///
/// An absent, malformed, expired, or badly-signed cookie all produce the
/// same outcome — `claims: None` — because none of them is distinguishable
/// to a legitimate visitor and treating them differently only leaks detail.
pub async fn attach(
    Extension(base): Extension<AppCtx>,
    jar: CookieJar,
    mut req: Request,
    next: Next,
) -> Response {
    let claims = jar
        .get(COOKIE_NAME)
        .and_then(|c| session::verify(c.value()).ok());

    let client_ip = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());

    req.extensions_mut()
        .insert(base.with_session(claims, client_ip));
    next.run(req).await
}
