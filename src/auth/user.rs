//! The `user` table: the single identity anchor.
//!
//! Rows are created lazily, on a successful magic-link consume — never by
//! *requesting* a link. That is what keeps `request_magic_link` free of an
//! account-enumeration signal (spec section 5.2).

use anyhow::{Context, Result};
use chrono::Utc;
use diesel::prelude::*;

use crate::db::DbConn;
use crate::schema::user;

/// An account.
#[derive(Queryable, Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub session_epoch: i64,
    pub created_at: chrono::NaiveDateTime,
    /// When the account switched to client-side encryption; `None` means
    /// its entries are still plaintext (see `entry_key::store`).
    pub encrypted_at: Option<chrono::NaiveDateTime>,
}

#[derive(Insertable)]
#[diesel(table_name = user)]
struct NewUser<'a> {
    email: &'a str,
    session_epoch: i64,
    created_at: chrono::NaiveDateTime,
}

/// Trims and lowercases, and rejects addresses that cannot be real.
///
/// Deliberately *not* provider-aware: no gmail dot-stripping, no plus-tag
/// removal. photo365 needs that to deduplicate customers across checkout
/// flows; here two spellings are simply two accounts, which surprises nobody
/// and costs no dependency.
pub fn normalize_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return None;
    }
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty() || domain.is_empty() || !domain.contains('.') || domain.contains('@') {
        return None;
    }
    Some(trimmed)
}

pub fn find_by_email(conn: &mut DbConn, email: &str) -> Result<Option<User>> {
    let Some(normalized) = normalize_email(email) else {
        return Ok(None);
    };
    user::table
        .filter(user::email.eq(&normalized))
        .first::<User>(conn)
        .optional()
        .context("select user by email")
}

/// Returns the existing account for `email`, creating one if absent.
pub fn find_or_create(conn: &mut DbConn, email: &str) -> Result<User> {
    let normalized =
        normalize_email(email).ok_or_else(|| anyhow::anyhow!("not a usable email address"))?;

    conn.transaction(|conn| {
        if let Some(found) = user::table
            .filter(user::email.eq(&normalized))
            .first::<User>(conn)
            .optional()?
        {
            return Ok(found);
        }
        diesel::insert_into(user::table)
            .values(NewUser {
                email: &normalized,
                session_epoch: 0,
                created_at: Utc::now().naive_utc(),
            })
            .execute(conn)?;
        user::table
            .filter(user::email.eq(&normalized))
            .first::<User>(conn)
    })
    .context("find or create user")
}

/// Invalidates every session token already issued to this user.
pub fn bump_epoch(conn: &mut DbConn, user_id: i32) -> Result<()> {
    diesel::update(user::table.find(user_id))
        .set(user::session_epoch.eq(user::session_epoch + 1))
        .execute(conn)
        .context("bump session_epoch")?;
    Ok(())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::db::test_pool;

    #[test]
    fn normalizes_case_and_whitespace() {
        assert_eq!(
            normalize_email("  Alice@Example.COM \n"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn rejects_impossible_addresses() {
        for junk in [
            "",
            "   ",
            "no-at-sign",
            "@nolocal.com",
            "trailing@",
            "a b@c.com",
        ] {
            assert_eq!(normalize_email(junk), None, "{junk:?} must be rejected");
        }
    }

    /// Two spellings that differ only in case are one account; anything else
    /// is deliberately two accounts (spec section 4.2 — no provider-specific
    /// canonicalization).
    #[test]
    fn find_or_create_is_idempotent_across_case() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = find_or_create(&mut conn, "alice@example.com").expect("create");
        let b = find_or_create(&mut conn, "ALICE@example.com").expect("find");
        assert_eq!(a.id, b.id);
        assert_eq!(b.email, "alice@example.com");
    }

    #[test]
    fn dots_in_the_local_part_are_distinct_accounts() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let a = find_or_create(&mut conn, "a.b@example.com").expect("create");
        let b = find_or_create(&mut conn, "ab@example.com").expect("create");
        assert_ne!(a.id, b.id, "no gmail-style dot canonicalization");
    }

    #[test]
    fn new_users_start_at_epoch_zero() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert_eq!(
            find_or_create(&mut conn, "alice@example.com")
                .expect("create")
                .session_epoch,
            0
        );
    }

    #[test]
    fn find_by_email_misses_cleanly() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        assert!(
            find_by_email(&mut conn, "nobody@example.com")
                .expect("query")
                .is_none()
        );
    }

    /// Bumping the epoch is how "sign out everywhere" works: every issued
    /// token carries the epoch it was minted under, and require_user rejects
    /// a mismatch.
    #[test]
    fn bump_epoch_increments() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let u = find_or_create(&mut conn, "alice@example.com").expect("create");
        bump_epoch(&mut conn, u.id).expect("bump");
        bump_epoch(&mut conn, u.id).expect("bump");
        let after = find_by_email(&mut conn, "alice@example.com")
            .expect("query")
            .expect("exists");
        assert_eq!(after.session_epoch, 2);
    }
}
