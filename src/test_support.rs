//! Router construction shared by `main` and the integration tests.
//!
//! [`router`] is the whole point of this module: `main` and `tests/routes.rs`
//! call the exact same function, so a route-order test here pins the router
//! that actually serves traffic rather than a copy of it that could drift.
//! [`app_with_magic_link`] builds the same router around a test pool a
//! caller can mint tokens against directly, for tests that need to drive
//! `/magic/{token}`. [`seed_user`] registers an address against an
//! already-built router's own pool, for tests that need a user to exist
//! without driving any auth flow at all.

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::{Request, StatusCode};
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
use crate::{auth, db, email};

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

/// Creates a user row directly, without minting or consuming a magic link —
/// so a test can register an address with no mail sent and no token to
/// thread through.
///
/// Dispatches an in-process request to `app`'s own debug-only seed route
/// (see [`seed_user_handler`]) rather than opening a second connection: a
/// fresh `db::build_pool()` call would open its own private `:memory:`
/// database, sharing nothing with the one `app` already holds, and `tests/`
/// is a separate crate that cannot reach a `#[cfg(test)]` item in the
/// library to get at it directly.
pub async fn seed_user(app: &Router, email: &str) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/__test_support__/seed_user")
                .body(Body::from(email.to_string()))
                .expect("seed_user request"),
        )
        .await
        .expect("seed_user response");
    assert!(
        res.status().is_success(),
        "seed_user failed with status {}",
        res.status()
    );
}

/// Handler backing [`seed_user`]. Registered only in debug builds — the same
/// `cfg!(debug_assertions)` split `session::session_key` and
/// `cookie::http_only` already use to keep dev/test-only behaviour out of a
/// release binary — so it never reaches a `cargo leptos build --release`
/// image.
#[cfg(debug_assertions)]
async fn seed_user_handler(Extension(ctx): Extension<AppCtx>, email: String) -> StatusCode {
    match ctx
        .conn()
        .and_then(|mut conn| auth::user::find_or_create(&mut conn, &email))
    {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            tracing::error!("seed_user failed: {e:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Builds a router with a `Mailer::capture()` and a magic-link token already
/// minted for `email`, against the exact pool the returned router serves
/// from — not a separate one, or the handler's `consume` call would find no
/// such row.
///
/// Returns the router and the raw token, ready to embed in a
/// `/magic/{token}` request in a test.
pub async fn app_with_magic_link(email: &str) -> (Router, String) {
    ensure_env_defaults();

    let pool = db::test_pool();
    let token = {
        let mut conn = pool.get().expect("checkout database connection");
        auth::magic_link::mint(&mut conn, email, auth::magic_link::ttl()).expect("mint token")
    };
    let ctx = AppCtx::new(pool, email::Mailer::capture());

    (router_with_ctx(ctx), token)
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
    #[cfg(debug_assertions)]
    {
        app = app.route("/__test_support__/seed_user", post(seed_user_handler));
    }
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
