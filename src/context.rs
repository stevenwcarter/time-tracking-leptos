//! The per-request application context.
//!
//! A base `AppCtx` (pool, mailer, webauthn) is built once at startup and
//! layered onto the router. The session middleware clones it per request,
//! attaching that request's verified claims, and stashes the clone in the
//! request's extensions. Both the page-render handler and the server-fn
//! handler pull it back out and `provide_context` it, so a server fn reaches
//! everything it needs through `use_context::<AppCtx>()`.

use std::sync::Arc;

use anyhow::Context;
use webauthn_rs::prelude::Webauthn;

use crate::db::{DbConn, DbPool};
use crate::email::Mailer;
use crate::session::SessionClaims;

#[derive(Clone)]
pub struct AppCtx {
    pub pool: DbPool,
    pub mailer: Mailer,
    pub webauthn: Arc<Webauthn>,
    /// The verified session claims for this request, if any.
    ///
    /// Verified means signature and clock only — it does **not** mean the
    /// user still exists or has not signed out everywhere. Callers that
    /// touch user data must go through `server_fns::require_user`.
    pub claims: Option<SessionClaims>,
    pub client_ip: Option<String>,
}

impl AppCtx {
    /// Builds the base context. Call once at startup.
    pub fn new(pool: DbPool, mailer: Mailer) -> Self {
        Self {
            pool,
            mailer,
            webauthn: crate::passkey::webauthn::build_from_env(),
            claims: None,
            client_ip: None,
        }
    }

    pub fn conn(&self) -> anyhow::Result<DbConn> {
        self.pool.get().context("checkout database connection")
    }

    /// Clones the base context with this request's session attached.
    pub fn with_session(&self, claims: Option<SessionClaims>, client_ip: Option<String>) -> Self {
        Self {
            claims,
            client_ip,
            ..self.clone()
        }
    }
}
