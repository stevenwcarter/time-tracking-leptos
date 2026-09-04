//! Router construction shared by `main` and the integration tests.
//!
//! [`router`] is the whole point of this module: `main` and `tests/routes.rs`
//! call the exact same function, so a route-order test here pins the router
//! that actually serves traffic rather than a copy of it that could drift.
//! [`app_with_magic_link`] builds the same router around a test pool a
//! caller can mint tokens against directly, for tests that need to drive
//! `/magic/{token}`. [`TestApp`] pairs a router with the exact pool and
//! mailer it serves from, so a test can seed rows directly, drive them over
//! HTTP, and inspect captured mail; [`signed_in_as`] builds on it to mint a
//! real session cookie without sending mail or consuming a magic link.

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use leptos::prelude::*;
use leptos_axum::{
    LeptosRoutes, generate_route_list, handle_server_fns_with_context,
    render_app_to_stream_with_context,
};
use tower::ServiceExt;

use crate::app::{App, shell};
use crate::context::AppCtx;
use crate::{auth, db, email, session};

/// Root-level static files that must be routed explicitly.
///
/// The app's `/{date}` route matches **any** single path segment, so it
/// shadows the static-file fallback for anything at the root. Adding a
/// file to `public/` at the top level means adding it here too, or it
/// silently starts serving the app's HTML instead. Nested paths
/// (`/pkg/...`) are unaffected — they have more than one segment.
const ROOT_ASSETS: &[&str] = &["/favicon.ico"];

/// Renders a page with the per-request context in scope.
async fn leptos_routes_handler(
    State(options): State<LeptosOptions>,
    Extension(ctx): Extension<AppCtx>,
    req: Request<Body>,
) -> Response {
    let handler = render_app_to_stream_with_context(
        move || provide_context(ctx.clone()),
        move || shell(options.clone()),
    );
    handler(req).await.into_response()
}

/// Dispatches a server fn with the per-request context in scope.
async fn server_fn_handler(
    Extension(ctx): Extension<AppCtx>,
    req: Request<Body>,
) -> impl IntoResponse {
    handle_server_fns_with_context(move || provide_context(ctx.clone()), req).await
}

/// Fills in `DATABASE_URL`/`SESSION_KEY` defaults for a bare test binary
/// with no `.env`, so the integration test binaries need no environment.
/// A no-op wherever the environment already sets them, so production
/// behaviour under `main` is unaffected.
///
/// `session::session_key()` memoizes in a `OnceLock`, so the default must
/// land before anything else in this module first reads it.
fn ensure_env_defaults() {
    if std::env::var("DATABASE_URL").is_err() {
        // SAFETY of intent: this test binary is single-process; the value
        // only needs to be non-empty and stable for the process lifetime.
        unsafe { std::env::set_var("DATABASE_URL", ":memory:") };
    }
    if std::env::var("SESSION_KEY").is_err() {
        // SAFETY of intent: same as above.
        unsafe { std::env::set_var("SESSION_KEY", "test-support-session-key-not-a-real-secret") };
    }
}

/// Builds the full application router.
pub async fn router() -> Router {
    ensure_env_defaults();

    let pool = db::build_pool().expect("build database pool");
    db::run_migrations(&pool).expect("run migrations");
    let ctx = AppCtx::new(pool, email::Mailer::from_env());

    router_with_ctx(ctx)
}

/// Builds a router with a `Mailer::capture()` and a magic-link token already
/// minted for `email`, against the exact pool the returned router serves
/// from — not a separate one, or the handler's `consume` call would find no
/// such row.
///
/// Returns the router, the raw token, and the capture mailer the router's
/// context holds — cloning a `Mailer::Capture` shares the same underlying
/// `Arc<Mutex<..>>`, so a test can call `.captured()` on the returned handle
/// to read back whatever the router sent, including from a `tokio::spawn`ed
/// send.
pub async fn app_with_magic_link(email: &str) -> (Router, String, email::Mailer) {
    ensure_env_defaults();

    let pool = db::test_pool();
    let token = {
        let mut conn = pool.get().expect("checkout database connection");
        auth::magic_link::mint(&mut conn, email, auth::magic_link::ttl()).expect("mint token")
    };
    let mailer = email::Mailer::capture();
    let ctx = AppCtx::new(pool, mailer.clone());

    (router_with_ctx(ctx), token, mailer)
}

/// A router paired with the exact pool and mailer it serves from.
///
/// Where [`app_with_magic_link`] exists to drive `/magic/{token}`, `TestApp`
/// is for tests that need a user (or several, to prove access is scoped
/// between them) already signed in — see [`signed_in_as`] — and then drive
/// `/api/*` server functions with a real session cookie. The router and
/// mailer are exposed for tests that need to dispatch requests or inspect
/// captured mail.
pub struct TestApp {
    pub router: Router,
    pub pool: db::DbPool,
    pub mailer: email::Mailer,
}

impl TestApp {
    /// Builds a fresh app around its own in-memory database.
    pub async fn new() -> Self {
        ensure_env_defaults();
        let pool = db::test_pool();
        let mailer = email::Mailer::capture();
        let ctx = AppCtx::new(pool.clone(), mailer.clone());
        Self {
            router: router_with_ctx(ctx),
            pool,
            mailer,
        }
    }

    /// A caller with no session cookie, for asserting that anonymous access
    /// is refused.
    pub fn anonymous(&self) -> SessionClient {
        SessionClient {
            router: self.router.clone(),
            cookie: None,
        }
    }
}

/// Creates (or finds) `email`'s user row directly against `app`'s pool and
/// mints a session token for it — no mail sent, no `/magic/{token}` round
/// trip.
///
/// Signs with the row's actual `session_epoch`, never a hardcoded `0`: a
/// user who has already signed out everywhere has a nonzero epoch, and a
/// token minted at `0` would only prove `require_user` rejects a token that
/// happens to be wrong, not one that was genuinely issued and later revoked.
pub async fn signed_in_as(app: &TestApp, email: &str) -> SessionClient {
    let user = {
        let mut conn = app.pool.get().expect("checkout database connection");
        auth::user::find_or_create(&mut conn, email).expect("find or create user")
    };
    let token = session::issue(&user.email, user.session_epoch);
    SessionClient {
        router: app.router.clone(),
        cookie: Some(format!("{}={token}", session::COOKIE_NAME)),
    }
}

/// A caller of `/api/*` server functions, holding a session cookie (or, from
/// [`TestApp::anonymous`], none) and driving requests through the real
/// router — including the session middleware and `require_user` — rather
/// than calling repository functions directly.
#[derive(Clone)]
pub struct SessionClient {
    router: Router,
    cookie: Option<String>,
}

impl SessionClient {
    /// A second handle to the same session, standing in for a second signed-in
    /// device that already holds this cookie. Named rather than left to a
    /// bare `.clone()` so a revocation test reads as "another device kept
    /// this token", not as an incidental struct copy.
    pub fn clone_session(&self) -> Self {
        self.clone()
    }

    pub async fn load_entry(&self, date: &str) -> Result<Option<String>, String> {
        self.call("entries/load", &[("date", date)]).await
    }

    pub async fn save_entry(&self, date: &str, body: &str) -> Result<(), String> {
        self.call("entries/save", &[("date", date), ("body", body)])
            .await
    }

    pub async fn entry_dates_in_range(&self, from: &str, to: &str) -> Result<Vec<String>, String> {
        self.call("entries/dates", &[("from", from), ("to", to)])
            .await
    }

    pub async fn entries_in_range(
        &self,
        from: &str,
        to: &str,
    ) -> Result<Vec<(String, String)>, String> {
        self.call("entries/range", &[("from", from), ("to", to)])
            .await
    }

    /// Bumps this user's `session_epoch`, invalidating every token issued
    /// before the call — including this same client's own cookie.
    pub async fn sign_out_everywhere(&self) -> Result<(), String> {
        self.call("session/logout_all", &[]).await
    }

    /// Posts a URL-encoded form body to `/api/{endpoint}` with this client's
    /// cookie, if any, and decodes a JSON response.
    ///
    /// Server functions here take their default wire encoding —
    /// `application/x-www-form-urlencoded` in, JSON out — not JSON both
    /// ways. A helper that posted JSON args would never reach the handler at
    /// all (deserializing the args would fail first), which would make every
    /// case here look identically rejected whether or not `require_user`
    /// ever ran.
    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        form: &[(&str, &str)],
    ) -> Result<T, String> {
        let body = form
            .iter()
            .map(|(key, value)| format!("{}={}", form_urlencode(key), form_urlencode(value)))
            .collect::<Vec<_>>()
            .join("&");
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/{endpoint}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = &self.cookie {
            req = req.header(header::COOKIE, cookie.clone());
        }
        let res = self
            .router
            .clone()
            .oneshot(req.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
            .await
            .expect("body");
        if status.is_success() {
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())
        } else {
            Err(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

/// Percent-encodes one `application/x-www-form-urlencoded` key or value:
/// unreserved characters pass through, everything else becomes `%XX`. Small
/// hand-rolled encoder rather than a new dependency — the values crossing
/// this boundary are dates and entry bodies, never a type this project
/// already pulls a URL-encoding crate in for.
fn form_urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The router-assembly logic shared by [`router`] and [`app_with_magic_link`],
/// parameterized on the context so a test can reach the exact pool the
/// router serves from.
fn router_with_ctx(ctx: AppCtx) -> Router {
    let conf = get_configuration(None).expect("failed to read Leptos configuration");
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let static_handler = leptos_axum::file_and_error_handler::<LeptosOptions, _>(shell);
    let mut app =
        Router::<LeptosOptions>::new().route("/magic/{token}", get(auth::handler::consume));
    for path in ROOT_ASSETS {
        app = app.route(path, get(static_handler.clone()));
    }

    app.route(
        "/api/{*fn_name}",
        post(server_fn_handler).get(server_fn_handler),
    )
    .leptos_routes_with_handler(routes, get(leptos_routes_handler))
    .fallback(static_handler)
    .layer(middleware::from_fn(auth::middleware::attach))
    .layer(Extension(ctx))
    .with_state(leptos_options)
}
