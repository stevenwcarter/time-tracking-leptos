//! Sign-in, sign-out, and "who am I".

use leptos::prelude::*;

#[cfg(feature = "ssr")]
fn set_cookie(value: String) {
    use axum::http::{HeaderValue, header};
    use leptos_axum::ResponseOptions;
    if let Some(response) = use_context::<ResponseOptions>()
        && let Ok(hv) = HeaderValue::from_str(&value)
    {
        response.insert_header(header::SET_COOKIE, hv);
    }
}

/// The signed-in address, or `None`.
///
/// Cheap by design: the stateless claim is enough to render the account
/// corner, so this does not touch the database.
#[server(endpoint = "session/current")]
pub async fn current_session() -> Result<Option<String>, ServerFnError> {
    let ctx = super::require_ctx()?;
    Ok(ctx.claims.map(|c| c.email))
}

/// Mails a sign-in link.
///
/// Returns `Ok(())` for **every** outcome a caller could use to probe: an
/// unknown address, a known one, a rate-limited request, and a failed SMTP
/// handshake all look identical. That uniformity is the entire
/// account-enumeration defence — a variant returning "no such account"
/// undoes it (spec section 5.2, invariant I5).
#[server(endpoint = "session/request_link")]
pub async fn request_magic_link(email: String) -> Result<(), ServerFnError> {
    use crate::auth::{magic_link, user};
    use crate::email::{self, OutboundEmail};
    use crate::rate_limit;

    let ctx = super::require_ctx()?;

    let Some(normalized) = user::normalize_email(&email) else {
        return Ok(());
    };

    let ip = ctx.client_ip.clone().unwrap_or_else(|| "unknown".to_string());
    if !rate_limit::check_ip(&ip) || !rate_limit::check_email(&normalized) {
        tracing::debug!("magic-link request over quota");
        return Ok(());
    }

    let ttl = magic_link::ttl();
    let token = {
        let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
        match magic_link::mint(&mut conn, &normalized, ttl) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("could not mint magic link: {e:?}");
                return Ok(());
            }
        }
    };

    let url = format!("{}/magic/{token}", email::site_base_url());
    let (text, html) = email::magic_link_email(&url, ttl.num_seconds());
    let mailer = ctx.mailer.clone();

    // Spawned, not awaited: a slow relay must not park the request. The user
    // is told "check your email" either way and can ask again.
    tokio::spawn(async move {
        if let Err(e) = mailer
            .send(OutboundEmail {
                to: normalized,
                subject: "Your Time Tracker sign-in link".to_string(),
                text,
                html: Some(html),
            })
            .await
        {
            tracing::error!("magic-link email failed: {e:?}");
        }
    });

    Ok(())
}

/// Clears the session cookie on this device only.
#[server(endpoint = "session/logout")]
pub async fn logout() -> Result<(), ServerFnError> {
    use crate::server::cookie;
    use crate::session::COOKIE_NAME;
    set_cookie(cookie::http_only(COOKIE_NAME, "", 0));
    Ok(())
}

/// Invalidates every session token issued to this user, on every device.
#[server(endpoint = "session/logout_all")]
pub async fn sign_out_everywhere() -> Result<(), ServerFnError> {
    use crate::auth::user;
    use crate::server::cookie;
    use crate::session::COOKIE_NAME;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx.conn().map_err(super::log_and_fail("conn", "Internal server error"))?;
    user::bump_epoch(&mut conn, me.id)
        .map_err(super::log_and_fail("bump_epoch", "Internal server error"))?;
    set_cookie(cookie::http_only(COOKIE_NAME, "", 0));
    Ok(())
}
