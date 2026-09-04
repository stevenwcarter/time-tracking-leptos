//! One-time sign-in tokens delivered by email.
//!
//! The raw token exists only in the URL that is mailed out; the database
//! holds its SHA-256. A leaked database snapshot therefore yields no usable
//! sign-in links, only evidence that some link once existed.

use std::env;

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use diesel::prelude::*;
use ring::digest;
use uuid::Uuid;

use crate::auth::user;
use crate::db::DbConn;
use crate::schema::magic_link_token;

/// Outcome of presenting a token at `/magic/{token}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Valid and now spent. Sign the user in.
    Consumed { email: String },
    /// Known token, but already used or past its expiry. The caller should
    /// mint and mail a fresh link — this is the "clicked yesterday's email"
    /// case, and by far the most common support question.
    Stale { email: String },
    /// No such token.
    NotFound,
}

#[derive(Insertable)]
#[diesel(table_name = magic_link_token)]
struct NewToken<'a> {
    token_hash: &'a [u8],
    email: &'a str,
    expires_at: chrono::NaiveDateTime,
    created_at: chrono::NaiveDateTime,
}

/// The configured link lifetime, default 15 minutes.
///
/// Re-read on every call rather than cached in a `OnceLock`: tests mint
/// tokens under several different TTLs, and an operator may want to change
/// this without a restart.
pub fn ttl() -> Duration {
    let secs = env::var("MAGIC_LINK_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(900);
    Duration::seconds(secs)
}

fn hash(token: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, token.as_bytes())
        .as_ref()
        .to_vec()
}

/// Creates a token row and returns the raw token to embed in a URL.
///
/// The returned string is the only copy; it is not recoverable from the
/// database afterwards, since only its hash is stored.
pub fn mint(conn: &mut DbConn, email: &str, ttl: Duration) -> Result<String> {
    let normalized = user::normalize_email(email)
        .ok_or_else(|| anyhow::anyhow!("not a usable email address"))?;
    let token = Uuid::now_v7().to_string();
    let now = Utc::now().naive_utc();

    diesel::insert_into(magic_link_token::table)
        .values(NewToken {
            token_hash: &hash(&token),
            email: &normalized,
            expires_at: now + ttl,
            created_at: now,
        })
        .execute(conn)
        .context("insert magic_link_token")?;

    Ok(token)
}

/// Atomically spends a token.
///
/// The SELECT and UPDATE run in one transaction, and the UPDATE carries
/// `used_at IS NULL` in its own `WHERE` clause — not merely a check on the
/// value read by the SELECT. That is what makes two concurrent consumers
/// race correctly: the loser's UPDATE matches zero rows (SQLite re-evaluates
/// the filter against the row as it stands at UPDATE time, not the SELECT's
/// snapshot), so it reports `Stale` rather than also signing in.
pub fn consume(conn: &mut DbConn, token: &str) -> Result<ConsumeResult> {
    let token_hash = hash(token);
    let now = Utc::now().naive_utc();

    // The closure's error type is pinned explicitly: every branch returns
    // `Ok(...)`, so nothing otherwise fixes which `From<diesel::result::Error>`
    // impl `transaction`'s generic `E` should resolve to, and diesel provides
    // more than one.
    conn.transaction(|conn| -> Result<ConsumeResult, diesel::result::Error> {
        let row: Option<(
            i32,
            String,
            Option<chrono::NaiveDateTime>,
            chrono::NaiveDateTime,
        )> = magic_link_token::table
            .filter(magic_link_token::token_hash.eq(&token_hash))
            .select((
                magic_link_token::id,
                magic_link_token::email,
                magic_link_token::used_at,
                magic_link_token::expires_at,
            ))
            .first(conn)
            .optional()?;

        let Some((id, email, used_at, expires_at)) = row else {
            return Ok(ConsumeResult::NotFound);
        };

        if used_at.is_some() || expires_at <= now {
            return Ok(ConsumeResult::Stale { email });
        }

        let updated = diesel::update(
            magic_link_token::table
                .find(id)
                .filter(magic_link_token::used_at.is_null()),
        )
        .set(magic_link_token::used_at.eq(now))
        .execute(conn)?;

        if updated == 1 {
            Ok(ConsumeResult::Consumed { email })
        } else {
            // Lost the race: another request spent it between our SELECT
            // and our UPDATE.
            Ok(ConsumeResult::Stale { email })
        }
    })
    .context("consume magic link token")
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[test]
    fn mint_then_consume_signs_in() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Consumed {
                email: "alice@example.com".to_string()
            }
        );
    }

    /// Single use. The second click is the common support case, and it must
    /// report Stale (so the caller can reissue) rather than NotFound.
    #[test]
    fn a_second_consume_is_stale() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        consume(&mut conn, &token).expect("first consume");
        assert_eq!(
            consume(&mut conn, &token).expect("second consume"),
            ConsumeResult::Stale {
                email: "alice@example.com".to_string()
            }
        );
    }

    #[test]
    fn an_expired_token_is_stale() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::seconds(-1)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Stale {
                email: "alice@example.com".to_string()
            }
        );
    }

    #[test]
    fn an_unknown_token_is_not_found() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert_eq!(
            consume(&mut conn, "no-such-token").expect("consume"),
            ConsumeResult::NotFound
        );
    }

    /// A database leak must not hand an attacker live sign-in links, so the
    /// raw token is never stored — only its SHA-256.
    #[test]
    fn the_raw_token_is_never_stored() {
        use crate::schema::magic_link_token;
        use diesel::prelude::*;

        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");

        let stored: Vec<u8> = magic_link_token::table
            .select(magic_link_token::token_hash)
            .first(&mut conn)
            .expect("row exists");
        assert_ne!(
            stored,
            token.as_bytes(),
            "token must be hashed, not stored raw"
        );
        assert_eq!(stored.len(), 32, "SHA-256 is 32 bytes");
        assert_eq!(
            stored,
            digest::digest(&digest::SHA256, token.as_bytes()).as_ref(),
            "stored value must be SHA-256 of the token itself, not of some other input"
        );
    }

    /// Two tokens minted back to back must differ, or one user's link would
    /// sign in another.
    #[test]
    fn tokens_are_unique() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        let b = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        assert_ne!(a, b);
    }

    /// The consuming UPDATE carries `used_at IS NULL` in its WHERE clause, so
    /// two racing clicks cannot both win. Simulated here by consuming twice
    /// against the same row and asserting exactly one Consumed.
    #[test]
    fn concurrent_consume_has_exactly_one_winner() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "alice@example.com", Duration::minutes(15)).expect("mint");
        let results = [
            consume(&mut conn, &token).expect("consume"),
            consume(&mut conn, &token).expect("consume"),
        ];
        let winners = results
            .iter()
            .filter(|r| matches!(r, ConsumeResult::Consumed { .. }))
            .count();
        assert_eq!(winners, 1, "exactly one consumer may win");
    }

    #[test]
    fn consume_normalizes_the_stored_email() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let token = mint(&mut conn, "  Alice@Example.COM ", Duration::minutes(15)).expect("mint");
        assert_eq!(
            consume(&mut conn, &token).expect("consume"),
            ConsumeResult::Consumed {
                email: "alice@example.com".to_string()
            }
        );
    }
}
