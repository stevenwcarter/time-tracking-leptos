//! Diesel CRUD for `entry_key_wrap`, plus the `user.encrypted_at` flag that
//! gates whether an account's entries are read as plaintext or ciphertext.

use anyhow::{Context, Result};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;

use crate::crypto::wire::{KDF_HKDF_SHA256, WRAP_ALG_AESKW256, WrapKind};
use crate::db::DbConn;
use crate::schema::{entry_key_wrap, user};

/// A wrap row's public read shape — one route to the account's data key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapRow {
    pub kind: WrapKind,
    pub credential_id: Option<Vec<u8>>,
    pub wrapped_key: Vec<u8>,
    pub kdf: String,
    pub wrap_alg: String,
}

/// The as-stored shape: `kind` is still the raw column text here, parsed
/// into [`WrapKind`] only once the row is on its way out via [`WrapRow`].
#[derive(Queryable, Debug)]
struct WrapRecord {
    kind: String,
    credential_id: Option<Vec<u8>>,
    wrapped_key: Vec<u8>,
    kdf: String,
    wrap_alg: String,
}

impl WrapRecord {
    fn into_wrap_row(self) -> Result<WrapRow> {
        let kind = WrapKind::parse(&self.kind)
            .with_context(|| format!("unrecognized wrap kind {:?}", self.kind))?;
        Ok(WrapRow {
            kind,
            credential_id: self.credential_id,
            wrapped_key: self.wrapped_key,
            kdf: self.kdf,
            wrap_alg: self.wrap_alg,
        })
    }
}

#[derive(Insertable)]
#[diesel(table_name = entry_key_wrap)]
struct NewWrap<'a> {
    user_id: i32,
    kind: &'a str,
    credential_id: Option<&'a [u8]>,
    wrapped_key: &'a [u8],
    kdf: &'a str,
    wrap_alg: &'a str,
    created_at: NaiveDateTime,
}

/// Inserts a row without its own transaction, so [`replace_recovery_wrap`]
/// can share it with a preceding delete.
fn insert_row(
    conn: &mut DbConn,
    user_id: i32,
    kind: WrapKind,
    credential_id: Option<&[u8]>,
    wrapped_key: &[u8],
) -> Result<(), diesel::result::Error> {
    diesel::insert_into(entry_key_wrap::table)
        .values(NewWrap {
            user_id,
            kind: kind.as_str(),
            credential_id,
            wrapped_key,
            kdf: KDF_HKDF_SHA256,
            wrap_alg: WRAP_ALG_AESKW256,
            created_at: Utc::now().naive_utc(),
        })
        .execute(conn)
        .map(|_| ())
}

/// Marks the account as switched to client-side encryption.
pub fn set_encrypted(conn: &mut DbConn, user_id: i32) -> Result<()> {
    diesel::update(user::table.find(user_id))
        .set(user::encrypted_at.eq(Utc::now().naive_utc()))
        .execute(conn)
        .context("mark account encrypted")?;
    Ok(())
}

/// Whether the account's entries are ciphertext rather than plaintext.
pub fn is_encrypted(conn: &mut DbConn, user_id: i32) -> Result<bool> {
    user::table
        .find(user_id)
        .select(user::encrypted_at.is_not_null())
        .first(conn)
        .context("check encrypted_at")
}

/// Adds one route to the account's data key.
///
/// Fails if `credential_id` is already wrapped for this user — the unique
/// index on `(user_id, credential_id)` makes that ambiguous, not additive.
pub fn insert_wrap(
    conn: &mut DbConn,
    user_id: i32,
    kind: WrapKind,
    credential_id: Option<&[u8]>,
    wrapped_key: &[u8],
) -> Result<()> {
    insert_row(conn, user_id, kind, credential_id, wrapped_key).context("insert entry_key_wrap")
}

/// All routes to the account's data key, in no particular order.
pub fn list_wraps(conn: &mut DbConn, user_id: i32) -> Result<Vec<WrapRow>> {
    let rows: Vec<WrapRecord> = entry_key_wrap::table
        .filter(entry_key_wrap::user_id.eq(user_id))
        .select((
            entry_key_wrap::kind,
            entry_key_wrap::credential_id,
            entry_key_wrap::wrapped_key,
            entry_key_wrap::kdf,
            entry_key_wrap::wrap_alg,
        ))
        .load(conn)
        .context("list entry key wraps")?;
    rows.into_iter().map(WrapRecord::into_wrap_row).collect()
}

/// Whether this credential already has a route to the account's data key.
///
/// Asked before an insert, so a second attempt is refused with a sentence
/// rather than by `idx_entry_key_wrap_cred` — a unique-index violation
/// reaches the caller as "Internal server error", which tells somebody
/// whose passkey is already keyed to go and report a bug.
pub fn has_wrap_for_credential(
    conn: &mut DbConn,
    user_id: i32,
    credential_id: &[u8],
) -> Result<bool> {
    let count: i64 = entry_key_wrap::table
        .filter(entry_key_wrap::user_id.eq(user_id))
        .filter(entry_key_wrap::credential_id.eq(credential_id))
        .count()
        .get_result(conn)
        .context("count wraps for credential")?;
    Ok(count > 0)
}

/// Removes the wrap for one credential, if any. Used when a passkey is
/// deleted, so it stops being an unlock route.
pub fn delete_wrap_for_credential(
    conn: &mut DbConn,
    user_id: i32,
    credential_id: &[u8],
) -> Result<()> {
    diesel::delete(
        entry_key_wrap::table
            .filter(entry_key_wrap::user_id.eq(user_id))
            .filter(entry_key_wrap::credential_id.eq(credential_id)),
    )
    .execute(conn)
    .context("delete entry_key_wrap for credential")?;
    Ok(())
}

/// Replaces the account's recovery wrap, leaving exactly one. Re-issuing a
/// recovery code must not accumulate rows — only the newest one should ever
/// open the data key.
///
/// **Idempotent for a given `wrapped_key`**: submitting the wrap the account
/// already holds reports success without touching the row. That is what
/// makes the client's retry safe, and the client needs one — a reply lost on
/// the way back from a successful replace would otherwise leave the user
/// believing the code they still hold works, when the server had already
/// swapped it for a code they were never shown (see
/// `components::unlock`'s `store_recovery_wrap`).
///
/// The comparison runs inside the same transaction as the write it might
/// skip, so a concurrent re-issue cannot land between them and turn "already
/// done" into a lie.
pub fn replace_recovery_wrap(conn: &mut DbConn, user_id: i32, wrapped_key: &[u8]) -> Result<()> {
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let current: Option<Vec<u8>> = entry_key_wrap::table
            .filter(entry_key_wrap::user_id.eq(user_id))
            .filter(entry_key_wrap::kind.eq(WrapKind::Recovery.as_str()))
            .select(entry_key_wrap::wrapped_key)
            .first(conn)
            .optional()?;
        if current.as_deref() == Some(wrapped_key) {
            return Ok(());
        }
        diesel::delete(
            entry_key_wrap::table
                .filter(entry_key_wrap::user_id.eq(user_id))
                .filter(entry_key_wrap::kind.eq(WrapKind::Recovery.as_str())),
        )
        .execute(conn)?;
        insert_row(conn, user_id, WrapKind::Recovery, None, wrapped_key)
    })
    .context("replace recovery wrap")
}

/// How many passkey-unlockable wraps the account has. Used to decide
/// whether disabling a passkey would leave the account with no way in
/// short of the recovery code.
pub fn passkey_wrap_count(conn: &mut DbConn, user_id: i32) -> Result<i64> {
    entry_key_wrap::table
        .filter(entry_key_wrap::user_id.eq(user_id))
        .filter(entry_key_wrap::kind.eq(WrapKind::Passkey.as_str()))
        .count()
        .get_result(conn)
        .context("count passkey wraps")
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::auth::user as auth_user;
    use crate::db::test_pool;

    fn seed() -> (DbConn, i32) {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = auth_user::find_or_create(&mut conn, "alice@example.com")
            .expect("create user")
            .id;
        (conn, uid)
    }

    fn seed_another_user(conn: &mut DbConn) -> i32 {
        auth_user::find_or_create(conn, "bob@example.com")
            .expect("create user")
            .id
    }

    fn delete_user(conn: &mut DbConn, user_id: i32) -> Result<()> {
        diesel::delete(user::table.find(user_id)).execute(conn)?;
        Ok(())
    }

    #[test]
    fn account_starts_unencrypted() {
        let (mut conn, uid) = seed();
        assert!(!is_encrypted(&mut conn, uid).expect("query"));
    }

    #[test]
    fn enabling_marks_the_account_and_stores_both_wraps() {
        let (mut conn, uid) = seed();
        set_encrypted(&mut conn, uid).expect("mark");
        insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("passkey");
        insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[9; 40]).expect("recovery");

        assert!(is_encrypted(&mut conn, uid).expect("query"));
        let wraps = list_wraps(&mut conn, uid).expect("list");
        assert_eq!(wraps.len(), 2);
        assert_eq!(passkey_wrap_count(&mut conn, uid).expect("count"), 1);
    }

    /// The wrap is what makes a credential able to unlock. Two rows for the
    /// same credential would mean an ambiguous unwrap route.
    #[test]
    fn one_wrap_per_credential() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("first");
        assert!(insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[8; 40]).is_err());
    }

    /// Two accounts may hold the same credential id without colliding — the
    /// unique index is per user, not global.
    #[test]
    fn the_credential_index_is_scoped_to_one_user() {
        let (mut conn, a) = seed();
        let b = seed_another_user(&mut conn);
        insert_wrap(&mut conn, a, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("a");
        insert_wrap(&mut conn, b, WrapKind::Passkey, Some(b"cred-1"), &[8; 40]).expect("b");
    }

    /// Several recovery rows would make "which one does the code open?"
    /// ambiguous. Re-issuing replaces rather than accumulates.
    #[test]
    fn replacing_the_recovery_wrap_leaves_exactly_one() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("first");
        replace_recovery_wrap(&mut conn, uid, &[2; 40]).expect("replace");

        let recovery: Vec<_> = list_wraps(&mut conn, uid)
            .expect("list")
            .into_iter()
            .filter(|w| w.kind == WrapKind::Recovery)
            .collect();
        assert_eq!(recovery.len(), 1);
        assert_eq!(recovery[0].wrapped_key, vec![2; 40]);
    }

    /// The lost-response failure mode, from the server's side. A client that
    /// never learned whether its submit landed must be able to send the same
    /// wrap again: the retry has to *succeed* — reporting failure would send
    /// the user back to a screen telling them their old code still works,
    /// after this row had already been replaced — and it has to leave one
    /// row, not two.
    #[test]
    fn resubmitting_the_same_recovery_wrap_succeeds_and_leaves_one_row() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("first");
        replace_recovery_wrap(&mut conn, uid, &[2; 40]).expect("replace");
        replace_recovery_wrap(&mut conn, uid, &[2; 40]).expect("the retry must succeed");

        let recovery: Vec<_> = list_wraps(&mut conn, uid)
            .expect("list")
            .into_iter()
            .filter(|w| w.kind == WrapKind::Recovery)
            .collect();
        assert_eq!(recovery.len(), 1, "a retry must not accumulate rows");
        assert_eq!(recovery[0].wrapped_key, vec![2; 40]);
    }

    /// The schema, not just `replace_recovery_wrap`'s convention, must stop a
    /// second recovery row from ever existing — a caller that inserts
    /// directly instead of replacing would otherwise leave two, and "which
    /// one does the code open?" becomes ambiguous.
    #[test]
    fn a_second_recovery_wrap_is_rejected() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("first");
        assert!(insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[2; 40]).is_err());
    }

    /// The one-recovery-row index is per user, not global — two accounts
    /// must each be able to hold their own recovery wrap.
    #[test]
    fn the_recovery_index_is_scoped_to_one_user() {
        let (mut conn, a) = seed();
        let b = seed_another_user(&mut conn);
        insert_wrap(&mut conn, a, WrapKind::Recovery, None, &[1; 40]).expect("a");
        insert_wrap(&mut conn, b, WrapKind::Recovery, None, &[2; 40]).expect("b");
    }

    #[test]
    fn deleting_a_credential_wrap_removes_only_that_one() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("one");
        insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-2"), &[8; 40]).expect("two");
        delete_wrap_for_credential(&mut conn, uid, b"cred-1").expect("delete");

        let wraps = list_wraps(&mut conn, uid).expect("list");
        assert_eq!(wraps.len(), 1);
        assert_eq!(wraps[0].credential_id.as_deref(), Some(&b"cred-2"[..]));
    }

    /// The user row owns the flag, so deleting the user must not strand wraps.
    #[test]
    fn wraps_cascade_with_the_user() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Recovery, None, &[1; 40]).expect("wrap");
        delete_user(&mut conn, uid).expect("delete user");
        assert!(list_wraps(&mut conn, uid).expect("list").is_empty());
    }
}
