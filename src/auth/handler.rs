//! `GET /magic/{token}` — consumes a magic-link token and signs the user in.
//!
//! Stub: Task 11 replaces this with the real handler (look up the token via
//! `auth::magic_link::consume`, issue a session cookie, and redirect home).

use axum::http::StatusCode;

/// Placeholder so routing and the rest of the server compile before Task 11
/// lands. Always responds `501 Not Implemented`.
pub async fn consume() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
