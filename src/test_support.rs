//! Router construction shared by `main` and the integration tests.
//!
//! [`router`] is the whole point of this module: `main` and `tests/routes.rs`
//! call the exact same function, so a route-order test here pins the router
//! that actually serves traffic rather than a copy of it that could drift.

use axum::body::Body;
use axum::extract::{Extension, State};
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};
use leptos::prelude::*;
use leptos_axum::{
    LeptosRoutes, generate_route_list, handle_server_fns_with_context,
    render_app_to_stream_with_context,
};

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

/// Builds the full application router.
///
/// Defaults `DATABASE_URL` to `:memory:` and `SESSION_KEY` to a fixed test
/// value when either is unset, so the integration test binary needs no
/// environment. `session::session_key()` memoizes in a `OnceLock`, so the
/// default must land before anything in this function first calls it.
pub async fn router() -> Router {
    if std::env::var("DATABASE_URL").is_err() {
        // SAFETY of intent: this test binary is single-process; the value
        // only needs to be non-empty and stable for the process lifetime.
        unsafe { std::env::set_var("DATABASE_URL", ":memory:") };
    }
    if std::env::var("SESSION_KEY").is_err() {
        // SAFETY of intent: same as above.
        unsafe { std::env::set_var("SESSION_KEY", "test-support-session-key-not-a-real-secret") };
    }

    let conf = get_configuration(None).expect("failed to read Leptos configuration");
    let leptos_options = conf.leptos_options;
    let routes = generate_route_list(App);

    let pool = db::build_pool().expect("build database pool");
    db::run_migrations(&pool).expect("run migrations");
    let base_ctx = AppCtx::new(pool, email::Mailer::from_env());

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
    .layer(Extension(base_ctx))
    .with_state(leptos_options)
}
