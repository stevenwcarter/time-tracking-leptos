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

/// Inserts a row without its own transaction, so [`replace_encryption_key_wrap`]
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

/// Replaces the account's encryption-key wrap, leaving exactly one.
/// Re-issuing an encryption key must not accumulate rows — only the newest
/// one should ever open the data key.
///
/// **Idempotent for a given `wrapped_key`**: submitting the wrap the account
/// already holds reports success without touching the row. That is what
/// makes the client's retry safe, and the client needs one — a reply lost on
/// the way back from a successful replace would otherwise leave the user
/// believing the key they still hold works, when the server had already
/// swapped it for a key they were never shown (see
/// `components::unlock`'s `store_encryption_key_wrap`).
///
/// The comparison runs inside the same transaction as the write it might
/// skip, so a concurrent re-issue cannot land between them and turn "already
/// done" into a lie.
pub fn replace_encryption_key_wrap(
    conn: &mut DbConn,
    user_id: i32,
    wrapped_key: &[u8],
) -> Result<()> {
    conn.transaction::<_, diesel::result::Error, _>(|conn| {
        let current: Option<Vec<u8>> = entry_key_wrap::table
            .filter(entry_key_wrap::user_id.eq(user_id))
            .filter(entry_key_wrap::kind.eq(WrapKind::EncryptionKey.as_str()))
            .select(entry_key_wrap::wrapped_key)
            .first(conn)
            .optional()?;
        if current.as_deref() == Some(wrapped_key) {
            return Ok(());
        }
        diesel::delete(
            entry_key_wrap::table
                .filter(entry_key_wrap::user_id.eq(user_id))
                .filter(entry_key_wrap::kind.eq(WrapKind::EncryptionKey.as_str())),
        )
        .execute(conn)?;
        insert_row(conn, user_id, WrapKind::EncryptionKey, None, wrapped_key)
    })
    .context("replace encryption key wrap")
}

/// How many passkey-unlockable wraps the account has. Used to decide
/// whether disabling a passkey would leave the account with no way in
/// short of the encryption key.
pub fn passkey_wrap_count(conn: &mut DbConn, user_id: i32) -> Result<i64> {
    entry_key_wrap::table
        .filter(entry_key_wrap::user_id.eq(user_id))
        .filter(entry_key_wrap::kind.eq(WrapKind::Passkey.as_str()))
        .count()
        .get_result(conn)
        .context("count passkey wraps")
}

/// Given the stored `kind` values for every `entry_key_wrap` row, decides
/// whether startup should refuse to serve traffic, and what to tell whoever
/// is paged.
///
/// Split out from [`ensure_wrap_kinds_parseable`] so this rule has a unit
/// test that does not depend on a real database — mirrors
/// `session::session_key_problem`.
fn unparseable_kinds_problem(kinds: &[String]) -> Option<String> {
    let bad = kinds
        .iter()
        .filter(|kind| WrapKind::parse(kind).is_none())
        .count();
    if bad == 0 {
        return None;
    }
    let (row, have) = if bad == 1 {
        ("row", "has")
    } else {
        ("rows", "have")
    };
    Some(format!(
        "{bad} entry_key_wrap {row} {have} a kind this build does not recognize \
         (expected \"passkey\" or \"encryption_key\"). That means they predate the \
         rename from \"recovery\" to \"encryption_key\" (spec \
         2026-09-06-encryption-required-design.md §1.4), which this build applied by \
         editing a migration in place — safe only against a database wiped before \
         deploy. This database was not wiped. Do not edit these rows by hand: each is \
         the only route to its account's data key, and hand-editing risks destroying \
         it. Restore the deployment this build expects — a freshly wiped database — \
         instead."
    ))
}

/// Every `entry_key_wrap` row's raw, unparsed `kind`.
///
/// Only for [`ensure_wrap_kinds_parseable`], which has to see the exact
/// stored strings to tell a legacy row from a valid one. Every other reader
/// works through [`WrapRow`], which requires a valid `kind` to exist at all.
fn all_wrap_kinds(conn: &mut DbConn) -> Result<Vec<String>> {
    entry_key_wrap::table
        .select(entry_key_wrap::kind)
        .load(conn)
        .context("load entry_key_wrap kind values")
}

/// Fails fast, with an actionable message, when any `entry_key_wrap` row
/// carries a `kind` this build cannot parse.
///
/// Mirrors `session::ensure_session_key_configured`: `main` calls this once
/// at startup, after migrations run and before serving any traffic. A row
/// like this is the telltale of the `'recovery'` → `'encryption_key'` rename
/// in this branch, applied by editing a shipped migration in place (spec
/// sections 1.4 and 5.2) — safe only against a database wiped before
/// deploy. Against a surviving database, nothing catches this until the
/// account's owner first tries to unlock: `WrapRecord::into_wrap_row` fails
/// that one row, and `list_wraps` propagates the failure for the *whole*
/// response rather than skipping just that row (unlike `choose_route`'s
/// handling of a kind newer than this build, see [`crate::dto::WrapDto`]) —
/// so every route to the account's data key disappears behind one "Internal
/// server error", on whichever request happens to ask first, with no
/// explanation reaching anyone of why. This turns that into one refusal to
/// boot, naming the problem instead.
pub fn ensure_wrap_kinds_parseable(conn: &mut DbConn) -> Result<(), String> {
    let kinds = all_wrap_kinds(conn).map_err(|e| e.to_string())?;
    match unparseable_kinds_problem(&kinds) {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
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
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[9; 40]).expect("key");

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

    /// Several encryption-key rows would make "which one does the key open?"
    /// ambiguous. Re-issuing replaces rather than accumulates.
    #[test]
    fn replacing_the_encryption_key_wrap_leaves_exactly_one() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[1; 40]).expect("first");
        replace_encryption_key_wrap(&mut conn, uid, &[2; 40]).expect("replace");

        let rows: Vec<_> = list_wraps(&mut conn, uid)
            .expect("list")
            .into_iter()
            .filter(|w| w.kind == WrapKind::EncryptionKey)
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].wrapped_key, vec![2; 40]);
    }

    /// The lost-response failure mode, from the server's side. A client that
    /// never learned whether its submit landed must be able to send the same
    /// wrap again: the retry has to *succeed* — reporting failure would send
    /// the user back to a screen telling them their old key still works,
    /// after this row had already been replaced — and it has to leave one
    /// row, not two.
    #[test]
    fn resubmitting_the_same_key_wrap_succeeds_and_leaves_one_row() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[1; 40]).expect("first");
        replace_encryption_key_wrap(&mut conn, uid, &[2; 40]).expect("replace");
        replace_encryption_key_wrap(&mut conn, uid, &[2; 40]).expect("the retry must succeed");

        let rows: Vec<_> = list_wraps(&mut conn, uid)
            .expect("list")
            .into_iter()
            .filter(|w| w.kind == WrapKind::EncryptionKey)
            .collect();
        assert_eq!(rows.len(), 1, "a retry must not accumulate rows");
        assert_eq!(rows[0].wrapped_key, vec![2; 40]);
    }

    /// The schema, not just `replace_encryption_key_wrap`'s convention, must
    /// stop a second encryption-key row from ever existing — a caller that
    /// inserts directly instead of replacing would otherwise leave two, and
    /// "which one does the key open?" becomes ambiguous.
    #[test]
    fn a_second_encryption_key_wrap_is_rejected() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[1; 40]).expect("first");
        assert!(insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[2; 40]).is_err());
    }

    /// The one-row index is per user, not global — two accounts must each be
    /// able to hold their own encryption-key wrap.
    #[test]
    fn the_encryption_key_index_is_scoped_to_one_user() {
        let (mut conn, a) = seed();
        let b = seed_another_user(&mut conn);
        insert_wrap(&mut conn, a, WrapKind::EncryptionKey, None, &[1; 40]).expect("a");
        insert_wrap(&mut conn, b, WrapKind::EncryptionKey, None, &[2; 40]).expect("b");
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
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[1; 40]).expect("wrap");
        delete_user(&mut conn, uid).expect("delete user");
        assert!(list_wraps(&mut conn, uid).expect("list").is_empty());
    }

    /// Inserts a row with an arbitrary raw `kind`, bypassing [`WrapKind`] —
    /// the shape a pre-rename database's row actually took, which
    /// `insert_wrap` can no longer produce now that the enum has dropped
    /// `Recovery`.
    fn insert_raw_kind_wrap(conn: &mut DbConn, user_id: i32, kind: &str) {
        diesel::insert_into(entry_key_wrap::table)
            .values(NewWrap {
                user_id,
                kind,
                credential_id: None,
                wrapped_key: &[1; 40],
                kdf: KDF_HKDF_SHA256,
                wrap_alg: WRAP_ALG_AESKW256,
                created_at: Utc::now().naive_utc(),
            })
            .execute(conn)
            .expect("insert raw-kind wrap");
    }

    #[test]
    fn unparseable_kinds_problem_is_none_for_no_rows() {
        assert_eq!(unparseable_kinds_problem(&[]), None);
    }

    #[test]
    fn unparseable_kinds_problem_is_none_when_every_row_parses() {
        let kinds = vec!["passkey".to_string(), "encryption_key".to_string()];
        assert_eq!(unparseable_kinds_problem(&kinds), None);
    }

    #[test]
    fn unparseable_kinds_problem_flags_one_bad_row() {
        let kinds = vec!["passkey".to_string(), "recovery".to_string()];
        let msg = unparseable_kinds_problem(&kinds).expect("must refuse to boot");
        assert!(msg.contains('1'), "message must name the count: {msg:?}");
        assert!(msg.contains("row "), "singular row: {msg:?}");
        assert!(msg.to_lowercase().contains("wiped"), "{msg:?}");
        assert!(msg.to_lowercase().contains("hand"), "{msg:?}");
    }

    /// Several bad rows must be named as plural, not just counted.
    #[test]
    fn unparseable_kinds_problem_flags_several_bad_rows() {
        let kinds = vec![
            "recovery".to_string(),
            "recovery".to_string(),
            "bogus".to_string(),
        ];
        let msg = unparseable_kinds_problem(&kinds).expect("must refuse to boot");
        assert!(msg.contains('3'), "message must name the count: {msg:?}");
        assert!(msg.contains("rows "), "plural rows: {msg:?}");
    }

    /// The end-to-end shape of the startup gate: a database carrying a
    /// pre-rename row must refuse to boot rather than silently proceed with
    /// an account that has no working route to its data key.
    #[test]
    fn ensure_wrap_kinds_parseable_refuses_to_boot_on_a_legacy_kind() {
        let (mut conn, uid) = seed();
        insert_wrap(&mut conn, uid, WrapKind::Passkey, Some(b"cred-1"), &[7; 40]).expect("valid");
        insert_raw_kind_wrap(&mut conn, uid, "recovery");
        assert!(ensure_wrap_kinds_parseable(&mut conn).is_err());
    }

    /// The database this build expects — freshly migrated, nothing written
    /// yet — must boot cleanly, and so must one where every row parses.
    #[test]
    fn ensure_wrap_kinds_parseable_is_ok_on_a_clean_database() {
        let (mut conn, uid) = seed();
        assert!(ensure_wrap_kinds_parseable(&mut conn).is_ok());
        insert_wrap(&mut conn, uid, WrapKind::EncryptionKey, None, &[1; 40]).expect("wrap");
        assert!(ensure_wrap_kinds_parseable(&mut conn).is_ok());
    }
}
