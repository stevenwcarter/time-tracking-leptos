//! Leptos server functions and their shared helpers.

pub mod entries;
pub mod passkey;
pub mod session;

#[cfg(feature = "ssr")]
mod ssr_helpers {
    use leptos::prelude::*;

    use crate::auth::user::{self, User};
    use crate::context::AppCtx;

    /// A user-facing error. Never carries internal detail.
    pub fn server_err(msg: &str) -> ServerFnError {
        ServerFnError::ServerError(msg.to_string())
    }

    /// Logs `err` with `what` for context and returns an opaque message.
    ///
    /// Curried so it drops straight into `.map_err(...)` without a closure
    /// at every call site.
    pub fn log_and_fail<E: std::fmt::Debug>(
        what: &'static str,
        user_msg: &'static str,
    ) -> impl FnOnce(E) -> ServerFnError {
        move |err| {
            tracing::error!("{what} failed: {err:?}");
            ServerFnError::ServerError(user_msg.to_string())
        }
    }

    pub fn require_ctx() -> Result<AppCtx, ServerFnError> {
        use_context::<AppCtx>().ok_or_else(|| server_err("Internal server error"))
    }

    /// Resolves the session to a live user, enforcing revocation.
    ///
    /// This is the **only** place `session_epoch` is checked. Stateless
    /// token verification (in `session::verify`) says the token is
    /// well-formed and unexpired; it cannot know the user signed out
    /// everywhere afterwards. Every function touching user data must come
    /// through here rather than trusting `ctx.claims` directly.
    pub fn require_user() -> Result<(AppCtx, User), ServerFnError> {
        let ctx = require_ctx()?;
        let claims = ctx
            .claims
            .clone()
            .ok_or_else(|| server_err("Not signed in"))?;
        let mut conn = ctx
            .conn()
            .map_err(log_and_fail("conn", "Internal server error"))?;
        let found = user::find_by_email(&mut conn, &claims.email)
            .map_err(log_and_fail("find_by_email", "Internal server error"))?
            .ok_or_else(|| server_err("Not signed in"))?;
        if found.session_epoch != claims.epoch {
            return Err(server_err("Not signed in"));
        }
        drop(conn);
        Ok((ctx, found))
    }
}

#[cfg(feature = "ssr")]
pub use ssr_helpers::*;
