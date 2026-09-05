//! `GET /magic/{token}` — spend a sign-in link and set the session cookie.
//!
//! A plain axum handler rather than a Leptos route: it sets a header and
//! redirects, and never renders the app.

use axum::extract::{Extension, Path};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::auth::magic_link::{self, ConsumeResult};
use crate::auth::user;
use crate::context::AppCtx;
use crate::db::DbConn;
use crate::email::{self, OutboundEmail};
use crate::rate_limit;
use crate::server::cookie;
use crate::session::{self, COOKIE_NAME, MAX_AGE_SECONDS};

pub async fn consume(Extension(ctx): Extension<AppCtx>, Path(token): Path<String>) -> Response {
    let mut conn = match ctx.conn() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("magic link: no database connection: {e:?}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response();
        }
    };

    match magic_link::consume(&mut conn, &token) {
        Ok(ConsumeResult::Consumed { email }) => match user::find_or_create(&mut conn, &email) {
            Ok(u) => {
                tracing::info!(user = %u.email, "signed in via magic link");
                sign_in_response(&u.email, u.session_epoch)
            }
            Err(e) => {
                tracing::error!("magic link: could not create user: {e:?}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response()
            }
        },
        Ok(ConsumeResult::Stale { email }) => reissue(&ctx, &mut conn, &email),
        Ok(ConsumeResult::NotFound) => {
            (StatusCode::NOT_FOUND, "This link is no longer valid.").into_response()
        }
        Err(e) => {
            tracing::error!("magic link consume failed: {e:?}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Try again in a moment.").into_response()
        }
    }
}

fn sign_in_response(email: &str, epoch: i64) -> Response {
    let token = session::issue(email, epoch);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        cookie::http_only(COOKIE_NAME, &token, MAX_AGE_SECONDS)
            .parse()
            .expect("cookie header is ASCII"),
    );
    headers.insert(header::LOCATION, "/".parse().expect("static location"));
    (StatusCode::SEE_OTHER, headers).into_response()
}

/// A used or expired link. Mint a fresh one, mail it, and say so.
///
/// This is the single most common support case — a user clicking yesterday's
/// email — and turning it into "here's a new link" rather than a dead end is
/// most of the value of having the branch at all.
///
/// Rate limited on both keys, exactly as `request_magic_link` is: this is the
/// *second* path that can put a link in someone's inbox, and a spent link URL
/// is not a secret — it survives in forwarded mail, shared browser history,
/// and proxy logs. Unlimited, anyone holding one could mail-bomb its owner
/// and grow `magic_link_token` without bound.
fn reissue(ctx: &AppCtx, conn: &mut DbConn, email: &str) -> Response {
    let ip = ctx.client_ip.as_deref().unwrap_or("unknown");
    // Two independent buckets, checked in the same order and with the same
    // short-circuit as `request_magic_link`: by IP so one host cannot spray
    // many addresses, by address so rotating IPs cannot flood one victim.
    if !rate_limit::check_ip(ip) || !rate_limit::check_email(email) {
        tracing::debug!("magic-link reissue over quota");
        // Byte-identical to the accepted response, minting and sending
        // nothing. A refusal that looked different would turn this route
        // into an oracle for whether an address is being limited, and would
        // hand an attacker a signal to pace against.
        return html_page(StatusCode::OK, sent_page(email));
    }

    let ttl = magic_link::ttl();
    let minted = magic_link::mint(conn, email, ttl);

    let (status, body) = match minted {
        Ok(token) => {
            let url = format!("{}/magic/{token}", email::site_base_url());
            let (text, html) = email::magic_link_email(&url, ttl.num_seconds());
            let mailer = ctx.mailer.clone();
            let to = email.to_string();
            tokio::spawn(async move {
                if let Err(e) = mailer
                    .send(OutboundEmail {
                        to,
                        subject: "Your Time Tracker sign-in link".to_string(),
                        text,
                        html: Some(html),
                    })
                    .await
                {
                    tracing::error!("reissued magic-link email failed: {e:?}");
                }
            });
            (StatusCode::OK, sent_page(email))
        }
        Err(e) => {
            tracing::error!("could not reissue magic link: {e:?}");
            // A failure here is a database outage, not a user mistake — it
            // must not read as an ordinary 200 in metrics/logs, or an outage
            // on this path would never trigger an alert.
            let body = page(
                "Please try again",
                "We couldn't send a new link. Go back and request one.",
            );
            (StatusCode::INTERNAL_SERVER_ERROR, body)
        }
    };

    html_page(status, body)
}

/// The "we've sent you a fresh link" page.
///
/// One function, two call sites — the send and the rate-limited refusal —
/// which is what makes those two responses identical by construction rather
/// than by two authors keeping the same wording in step.
fn sent_page(email: &str) -> String {
    page(
        "Check your email",
        &format!(
            "That link had already been used or had expired, so we've sent a \
             fresh one to <strong>{}</strong>.",
            escape_html(&email::mask(email))
        ),
    )
}

/// Wraps a rendered body in an HTML response.
fn html_page(status: StatusCode, body: String) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8"
            .parse()
            .expect("static content type"),
    );
    (status, headers, body).into_response()
}

/// Escapes the five HTML-significant characters. `page()`'s callers
/// interpolate untrusted values (an email address's domain is user-supplied
/// and `normalize_email` does not reject markup in it) alongside deliberate
/// markup like `<strong>`, so only the untrusted value is passed through
/// this — never the whole assembled body.
fn escape_html(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// A standalone page. This route runs outside the Leptos app, so it carries
/// its own minimal markup rather than reaching for a component.
fn page(heading: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{heading} — Time Tracker</title></head>\
         <body style=\"font-family:system-ui,sans-serif;background:#f9fafb;color:#1f2937;\
         max-width:32rem;margin:4rem auto;padding:1rem;\">\
         <h1 style=\"font-size:1.25rem;\">{heading}</h1><p>{body}</p>\
         <p><a href=\"/\" style=\"color:#2563eb;\">Back to Time Tracker</a></p>\
         </body></html>"
    )
}
