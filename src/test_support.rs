//! Router construction shared by `main` and the integration tests.
//!
//! [`router`] is the whole point of this module: it does no environment
//! defaulting, and `main` calls it directly, so a deployment that forgets
//! `SESSION_KEY` or `DATABASE_URL` gets production's real behaviour rather
//! than a silently-substituted test value. [`test_router`] is the
//! test-only entry point — it applies [`ensure_env_defaults`] and then
//! delegates to the exact same `router`, so a route-order test still pins
//! the router that actually serves traffic rather than a copy of it that
//! could drift. [`app_with_magic_link`] builds the same router around a test pool a
//! caller can mint tokens against directly, for tests that need to drive
//! `/magic/{token}`. [`TestApp`] pairs a router with the exact pool and
//! mailer it serves from, so a test can seed rows directly, drive them over
//! HTTP, and inspect captured mail; [`signed_in_as`] builds on it to mint a
//! real session cookie without sending mail or consuming a magic link.
//! [`app_ctx_with_claims`] skips the router and the pool wiring entirely,
//! for SSR-only tests that just need an `AppCtx` to `provide_context`.

use std::cell::RefCell;
use std::collections::HashMap;

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
use crate::dto::{EncryptionStatus, PasskeyListItem, WrapDto};
use crate::{auth, db, email, entry_key, session};

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
/// **Never call this from a path `main` reaches.** It exists solely to back
/// [`test_router`] and the other test-only builders below; `main` calls
/// [`router`] directly, which applies no defaulting at all.
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

/// Builds the full application router around the environment's actual
/// configuration.
///
/// Does **no** environment defaulting — this is what `main` calls. A
/// deployment that leaves `DATABASE_URL` unset gets `db::build_pool`'s real
/// default (`./data/time-tracking.db`), and one that leaves `SESSION_KEY`
/// unset or empty gets `session::session_key`'s real release-build panic
/// (`main` fails faster than that, see `session::ensure_session_key_configured`).
/// Neither ever silently falls back to a test value. Use [`test_router`] from
/// a test that needs a working router with no `.env` file.
pub async fn router() -> Router {
    let pool = db::build_pool().expect("build database pool");
    db::run_migrations(&pool).expect("run migrations");

    // Fail fast, after migrations but before serving any traffic: a
    // database that survived the `'recovery'` → `'encryption_key'` rename
    // (spec section 1.4) leaves some `entry_key_wrap` rows with a `kind`
    // this build cannot parse. Nothing catches that until the first request
    // that reads them, and then only as an unexplained "Internal server
    // error" — see `entry_key::store::ensure_wrap_kinds_parseable`.
    {
        let mut conn = pool.get().expect("checkout database connection");
        if let Err(msg) = entry_key::store::ensure_wrap_kinds_parseable(&mut conn) {
            tracing::error!("{msg}");
            std::process::exit(1);
        }
    }

    let ctx = AppCtx::new(pool, email::Mailer::from_env());

    router_with_ctx(ctx)
}

/// [`router`], with [`ensure_env_defaults`] applied first.
///
/// The test-only entry point: it delegates to the exact same router
/// construction `main` uses, so route-order tests built on it still pin
/// production's router rather than a copy that could drift.
pub async fn test_router() -> Router {
    ensure_env_defaults();
    router().await
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

/// Builds an `AppCtx` with `claims` already attached, over a fresh in-memory
/// pool and a capture mailer — no router, no request.
///
/// For SSR tests that render `App` directly (`Owner::new().with(...)`) and
/// need to assert on what a signed-in (or signed-out) render looks like,
/// without going through `router_with_ctx` or a real request at all.
pub fn app_ctx_with_claims(claims: Option<session::SessionClaims>) -> AppCtx {
    ensure_env_defaults();
    let pool = db::test_pool();
    let mailer = email::Mailer::capture();
    AppCtx::new(pool, mailer).with_session(claims, None)
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
            extra_cookies: RefCell::new(HashMap::new()),
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
        extra_cookies: RefCell::new(HashMap::from([(session::COOKIE_NAME.to_string(), token)])),
    }
}

/// A caller of `/api/*` server functions, holding a session cookie (or, from
/// [`TestApp::anonymous`], none) and driving requests through the real
/// router — including the session middleware and `require_user` — rather
/// than calling repository functions directly.
///
/// `extra_cookies` is a single keyed jar for *every* cookie this client
/// holds, session cookie included — not just the short-lived ones a
/// ceremony sets. Keying by name is what makes a cookie a client already
/// holds get *replaced* rather than duplicated when a response reissues it
/// (`passkey_login_finish` reissues the session cookie on a passkey
/// sign-in); two "one main cookie plus extras" fields would let a reissued
/// session cookie sit alongside the original and both get sent, which is
/// exactly the bug this design avoids. It is a `RefCell`, not a plain
/// field, so `call` can update it from `&self` — every server-fn method
/// here reads like a stateless request even though this one piece of it is
/// not. `#[derive(Clone)]` still snapshots it by value (a `RefCell<T>`
/// clones `T`, it does not share it), which is what keeps `clone_session`
/// modeling an independent second device rather than a second handle onto
/// the same one.
#[derive(Clone)]
pub struct SessionClient {
    router: Router,
    extra_cookies: RefCell<HashMap<String, String>>,
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

    /// Starts a passkey enrolment ceremony, returning the serialized
    /// creation challenge.
    pub async fn passkey_register_start(&self) -> Result<String, String> {
        self.call("passkey/register_start", &[]).await
    }

    /// Completes a passkey enrolment ceremony.
    pub async fn passkey_register_finish(
        &self,
        response_json: &str,
        prf_capable: bool,
    ) -> Result<(), String> {
        let prf_capable = if prf_capable { "true" } else { "false" };
        self.call(
            "passkey/register_finish",
            &[
                ("response_json", response_json),
                ("prf_capable", prf_capable),
            ],
        )
        .await
    }

    /// Starts a passkey sign-in ceremony, returning the serialized request
    /// challenge. `None` drives the username-less, discoverable flow.
    pub async fn passkey_login_start(&self, email: Option<&str>) -> Result<String, String> {
        match email {
            Some(email) => self.call("passkey/login_start", &[("email", email)]).await,
            None => self.call("passkey/login_start", &[]).await,
        }
    }

    /// Completes a passkey sign-in ceremony.
    pub async fn passkey_login_finish(&self, response_json: &str) -> Result<(), String> {
        self.call("passkey/login_finish", &[("response_json", response_json)])
            .await
    }

    /// This client's enrolled passkeys, newest first.
    pub async fn passkey_list(&self) -> Result<Vec<PasskeyListItem>, String> {
        self.call("passkey/list", &[]).await
    }

    pub async fn passkey_rename(&self, id: i32, name: &str) -> Result<(), String> {
        let id = id.to_string();
        self.call("passkey/rename", &[("id", &id), ("name", name)])
            .await
    }

    pub async fn passkey_delete(&self, id: i32) -> Result<(), String> {
        let id = id.to_string();
        self.call("passkey/delete", &[("id", &id)]).await
    }

    /// This client's encryption status: whether the account is encrypted.
    pub async fn encryption_status(&self) -> Result<EncryptionStatus, String> {
        self.call("encryption/status", &[]).await
    }

    /// This client's wraps — the routes this account's data key can be
    /// opened through.
    pub async fn encryption_wraps(&self) -> Result<Vec<WrapDto>, String> {
        self.call("encryption/wraps", &[]).await
    }

    /// Turns encryption on for this account with both wraps — the route an
    /// account with a PRF-capable passkey takes.
    pub async fn encryption_enable(
        &self,
        passkey_wrap: &[u8],
        credential_id: &[u8],
        encryption_key_wrap: &[u8],
    ) -> Result<(), String> {
        self.call_bytes(
            "encryption/enable",
            &[
                ("passkey[credential_id]", credential_id),
                ("passkey[wrapped_key]", passkey_wrap),
                ("encryption_key_wrap", encryption_key_wrap),
            ],
        )
        .await
    }

    /// Turns encryption on with the encryption-key wrap alone (spec section
    /// 6.1's second route), by omitting the `passkey` field entirely rather
    /// than sending it empty. That absence is what the server reads as "no
    /// passkey wrap", so a test posting an empty field would be exercising a
    /// different case than the browser produces.
    pub async fn encryption_enable_key_only(
        &self,
        encryption_key_wrap: &[u8],
    ) -> Result<(), String> {
        self.call_bytes(
            "encryption/enable",
            &[("encryption_key_wrap", encryption_key_wrap)],
        )
        .await
    }

    /// Adds a wrap for a newly enrolled passkey.
    pub async fn encryption_add_passkey_wrap(
        &self,
        credential_id: &[u8],
        wrapped_key: &[u8],
    ) -> Result<(), String> {
        self.call_bytes(
            "encryption/add_passkey_wrap",
            &[
                ("credential_id", credential_id),
                ("wrapped_key", wrapped_key),
            ],
        )
        .await
    }

    /// Re-issues this account's encryption-key wrap.
    pub async fn encryption_replace_key_wrap(&self, wrapped_key: &[u8]) -> Result<(), String> {
        self.call_bytes(
            "encryption/replace_key_wrap",
            &[("wrapped_key", wrapped_key)],
        )
        .await
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
        self.send(endpoint, body).await
    }

    /// Like [`Self::call`], for the handful of server functions whose
    /// arguments are `Vec<u8>` rather than strings (the encryption wrap
    /// blobs). A plain `&str` value can't stand in for a byte vector, so
    /// this builds the array-indexed form the server macro's default POST
    /// codec (`serde_qs`) expects for a sequence: `key[0]=<byte>&key[1]=...`.
    async fn call_bytes<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        fields: &[(&str, &[u8])],
    ) -> Result<T, String> {
        let body = fields
            .iter()
            .map(|(key, bytes)| form_urlencode_byte_vec(key, bytes))
            .collect::<Vec<_>>()
            .join("&");
        self.send(endpoint, body).await
    }

    /// The transport `call` and `call_bytes` share once each has built the
    /// request body in its own encoding.
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: String,
    ) -> Result<T, String> {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/{endpoint}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        let cookie_header = self.cookie_header();
        if let Some(cookie_header) = &cookie_header {
            req = req.header(header::COOKIE, cookie_header.clone());
        }
        let res = self
            .router
            .clone()
            .oneshot(req.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        self.absorb_set_cookies(res.headers());
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

    /// The `Cookie:` request header value: every cookie in the jar, session
    /// cookie included — see the `extra_cookies` doc comment on why there is
    /// only one jar rather than a session cookie plus extras.
    fn cookie_header(&self) -> Option<String> {
        let jar = self.extra_cookies.borrow();
        if jar.is_empty() {
            return None;
        }
        Some(
            jar.iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Records every `Set-Cookie` a response sent, so the next call on this
    /// same client replays it — a minimal stand-in for a browser's cookie
    /// jar. A cookie cleared with an empty value (`Max-Age=0`, as
    /// `passkey::state::clear_cookie_header` sends) is dropped rather than
    /// stored, matching a browser deleting it.
    fn absorb_set_cookies(&self, headers: &header::HeaderMap) {
        let mut jar = self.extra_cookies.borrow_mut();
        for raw in headers.get_all(header::SET_COOKIE) {
            let Ok(raw) = raw.to_str() else { continue };
            let Some(pair) = raw.split(';').next() else {
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                jar.remove(name);
            } else {
                jar.insert(name.to_string(), value.to_string());
            }
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

/// Encodes one `Vec<u8>` server-fn argument the way `serde_qs` — the
/// default POST codec `#[server]` uses — serializes a byte sequence:
/// `key[0]=<byte>&key[1]=<byte>&...`, brackets unescaped. Confirmed against
/// `serde_qs` itself, not guessed: it does not percent-encode `[`/`]`
/// because it appends them to the key *after* encoding the rest, and its own
/// parser round-trips this exact shape.
///
/// `key` is a `serde_qs` field *path*, taken verbatim: a bare identifier for
/// a top-level argument, or `outer[inner]` for a field of a nested struct
/// (`encryption_enable`'s optional `passkey`). It is not percent-encoded,
/// because `serde_qs` reads brackets as structure — a `%5B` would parse as
/// part of a flat field name and the nested argument would go missing. Every
/// caller passes ASCII identifiers, which need no encoding anyway.
fn form_urlencode_byte_vec(key: &str, bytes: &[u8]) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| format!("{key}[{i}]={b}"))
        .collect::<Vec<_>>()
        .join("&")
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

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// A client that already holds a session cookie, without building a
    /// whole `TestApp` — `cookie_header`/`absorb_set_cookies` never touch
    /// `router`.
    fn client_with_session(token: &str) -> SessionClient {
        SessionClient {
            router: Router::new(),
            extra_cookies: RefCell::new(HashMap::from([(
                session::COOKIE_NAME.to_string(),
                token.to_string(),
            )])),
        }
    }

    /// `passkey_login_finish` reissues the session cookie on a passkey
    /// sign-in; a client that already held one must send exactly the new
    /// value, not both.
    #[test]
    fn a_reissued_session_cookie_replaces_rather_than_accumulates() {
        let client = client_with_session("OLD");

        let mut set_cookie = header::HeaderMap::new();
        set_cookie.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!("{}=NEW; Path=/; HttpOnly", session::COOKIE_NAME))
                .expect("header value"),
        );
        client.absorb_set_cookies(&set_cookie);

        let sent = client.cookie_header().expect("a cookie header");
        let name_eq = format!("{}=", session::COOKIE_NAME);
        assert_eq!(
            sent.matches(&name_eq).count(),
            1,
            "must send exactly one {name_eq}, got: {sent:?}"
        );
        assert!(
            sent.contains(&format!("{name_eq}NEW")),
            "must carry the reissued value, got: {sent:?}"
        );
    }
}
