//! Diesel CRUD for `passkey_credential`.
//!
//! Credentials hang off `user_id`, not a free-text email column as in
//! photo365: a foreign key makes the user row the single identity anchor,
//! which matters once phase 2 attaches wrapped data keys to it.

use anyhow::{Context, Result};
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
use webauthn_rs::prelude::*;

use crate::db::DbConn;
use crate::schema::passkey_credential;

/// Longest customer-supplied passkey label we store.
pub const MAX_NAME_LEN: usize = 64;

#[derive(Queryable, Debug, Clone)]
pub struct PasskeyRow {
    pub id: i32,
    pub user_id: i32,
    pub credential_id: Vec<u8>,
    passkey: Vec<u8>,
    pub name: Option<String>,
    pub prf_capable: bool,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}

impl PasskeyRow {
    /// Decodes the stored credential.
    ///
    /// `serde_json`, **not** bincode. `Passkey` flattens a
    /// `BTreeMap<String, serde_cbor_2::Value>` of unknown extension keys,
    /// which needs a self-describing format; bincode calls
    /// `deserialize_any` on the flattened map and fails — and only once a
    /// real authenticator returns an extension, so it survives naive tests.
    pub fn deserialize_passkey(&self) -> Result<Passkey> {
        serde_json::from_slice(&self.passkey).context("decode Passkey blob")
    }

    /// The label to show, falling back to a date-derived default.
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| default_name(self.created_at))
    }
}

/// The label used when the user has not named a credential.
pub fn default_name(created_at: NaiveDateTime) -> String {
    format!("Passkey · {}", created_at.format("%b %-d, %Y"))
}

#[derive(Insertable)]
#[diesel(table_name = passkey_credential)]
struct NewPasskey<'a> {
    user_id: i32,
    credential_id: &'a [u8],
    passkey: &'a [u8],
    name: Option<String>,
    prf_capable: bool,
    created_at: NaiveDateTime,
}

/// Stores a freshly registered credential.
///
/// `prf_capable` records whether the authenticator reported PRF support at
/// creation time. Nothing reads it in phase 1; it exists so phase 2 can tell
/// which credentials can derive an unlock key without making every user
/// delete and re-enrol (spec section 9.3).
pub fn insert(conn: &mut DbConn, user_id: i32, key: &Passkey, prf_capable: bool) -> Result<i32> {
    let blob = serde_json::to_vec(key).context("encode Passkey blob")?;
    let cred_id = key.cred_id().to_vec();
    let now = Utc::now().naive_utc();

    conn.transaction(|conn| -> Result<i32, diesel::result::Error> {
        diesel::insert_into(passkey_credential::table)
            .values(NewPasskey {
                user_id,
                credential_id: &cred_id,
                passkey: &blob,
                name: None,
                prf_capable,
                created_at: now,
            })
            .execute(conn)?;
        passkey_credential::table
            .filter(passkey_credential::credential_id.eq(&cred_id))
            .select(passkey_credential::id)
            .first(conn)
    })
    .context("insert passkey_credential")
}

pub fn list_by_user(conn: &mut DbConn, user_id: i32) -> Result<Vec<PasskeyRow>> {
    passkey_credential::table
        .filter(passkey_credential::user_id.eq(user_id))
        .order(passkey_credential::created_at.desc())
        .load(conn)
        .context("list passkeys")
}

pub fn find_by_credential_id(conn: &mut DbConn, cred_id: &[u8]) -> Result<Option<PasskeyRow>> {
    passkey_credential::table
        .filter(passkey_credential::credential_id.eq(cred_id))
        .first(conn)
        .optional()
        .context("find passkey by credential id")
}

pub fn user_has_passkey(conn: &mut DbConn, user_id: i32) -> Result<bool> {
    let n: i64 = passkey_credential::table
        .filter(passkey_credential::user_id.eq(user_id))
        .count()
        .get_result(conn)
        .context("count passkeys")?;
    Ok(n > 0)
}

/// Deletes a credential. The owning `user_id` is part of the WHERE clause,
/// so another user's request matches no row rather than being rejected after
/// a separate ownership check — no TOCTOU window.
pub fn delete_for_user(conn: &mut DbConn, id: i32, user_id: i32) -> Result<bool> {
    let n = diesel::delete(
        passkey_credential::table
            .filter(passkey_credential::id.eq(id))
            .filter(passkey_credential::user_id.eq(user_id)),
    )
    .execute(conn)
    .context("delete passkey")?;
    Ok(n > 0)
}

/// Renames a credential, scoped the same way as [`delete_for_user`].
pub fn rename_for_user(
    conn: &mut DbConn,
    id: i32,
    user_id: i32,
    name: Option<&str>,
) -> Result<bool> {
    let trimmed = name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_NAME_LEN).collect::<String>());
    let n = diesel::update(
        passkey_credential::table
            .filter(passkey_credential::id.eq(id))
            .filter(passkey_credential::user_id.eq(user_id)),
    )
    .set(passkey_credential::name.eq(trimmed))
    .execute(conn)
    .context("rename passkey")?;
    Ok(n > 0)
}

/// Persists the advanced credential counter after a successful assertion.
pub fn update_after_use(conn: &mut DbConn, row_id: i32, key: &Passkey) -> Result<()> {
    let blob = serde_json::to_vec(key).context("encode Passkey blob")?;
    diesel::update(passkey_credential::table.find(row_id))
        .set((
            passkey_credential::passkey.eq(blob),
            passkey_credential::last_used_at.eq(Utc::now().naive_utc()),
        ))
        .execute(conn)
        .context("update passkey after use")?;
    Ok(())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use crate::auth::user;
    use crate::db::{DbConn, test_pool};
    use crate::passkey::webauthn::build_from_env;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    /// Enrols a credential through a real software authenticator, so the
    /// stored blob is the same shape a browser produces.
    fn enrol(subject: &str) -> Passkey {
        let wa = build_from_env();
        let (ccr, reg_state) = wa
            .start_passkey_registration(Uuid::new_v4(), subject, subject, None)
            .expect("start registration");
        // `WebauthnAuthenticator` is a sealed trait blanket-implemented for
        // any `AuthenticatorBackend`, not a wrapper type — `SoftPasskey`
        // itself is the authenticator; bring the trait into scope to call
        // `do_registration` on it directly.
        let mut authenticator = SoftPasskey::new(true);
        let rsp = authenticator
            .do_registration(wa.get_allowed_origins()[0].clone(), ccr)
            .expect("authenticator registration");
        wa.finish_passkey_registration(&rsp, &reg_state)
            .expect("finish registration")
    }

    fn user_id(conn: &mut DbConn, email: &str) -> i32 {
        user::find_or_create(conn, email).expect("create user").id
    }

    #[test]
    fn insert_then_list_round_trips() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");

        let rows = list_by_user(&mut conn, uid).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].credential_id, key.cred_id().to_vec());
    }

    /// The blob must deserialize back into a usable Passkey. This is the
    /// test that catches a bincode/serde_json mix-up: bincode cannot handle
    /// Passkey's flattened extension map and fails only at read time.
    #[test]
    fn stored_blob_deserializes_back_to_a_passkey() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");

        let rows = list_by_user(&mut conn, uid).expect("list");
        let restored = rows[0].deserialize_passkey().expect("blob decodes");
        assert_eq!(restored.cred_id(), key.cred_id());
    }

    #[test]
    fn find_by_credential_id_locates_the_row() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        let key = enrol("alice@example.com");
        insert(&mut conn, uid, &key, false).expect("insert");
        let found = find_by_credential_id(&mut conn, key.cred_id().as_ref())
            .expect("query")
            .expect("row found");
        assert_eq!(found.user_id, uid);
    }

    #[test]
    fn user_has_passkey_reflects_enrolment() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        assert!(!user_has_passkey(&mut conn, uid).expect("query"));
        insert(&mut conn, uid, &enrol("alice@example.com"), false).expect("insert");
        assert!(user_has_passkey(&mut conn, uid).expect("query"));
    }

    #[test]
    fn prf_capability_is_persisted() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let uid = user_id(&mut conn, "alice@example.com");
        insert(&mut conn, uid, &enrol("alice@example.com"), true).expect("insert");
        assert!(list_by_user(&mut conn, uid).expect("list")[0].prf_capable);
    }

    /// Pins invariant I7 for passkeys. The owning user is part of the
    /// DELETE's WHERE clause, so another user's delete matches no row.
    #[test]
    fn delete_is_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        insert(&mut conn, alice, &enrol("alice@example.com"), false).expect("insert");
        let row_id = list_by_user(&mut conn, alice).expect("list")[0].id;

        assert!(!delete_for_user(&mut conn, row_id, mallory).expect("delete"));
        assert_eq!(list_by_user(&mut conn, alice).expect("list").len(), 1);
        assert!(delete_for_user(&mut conn, row_id, alice).expect("delete"));
        assert!(list_by_user(&mut conn, alice).expect("list").is_empty());
    }

    #[test]
    fn rename_is_scoped_to_the_owning_user() {
        let pool = test_pool();
        let mut conn = pool.get().expect("checkout");
        let alice = user_id(&mut conn, "alice@example.com");
        let mallory = user_id(&mut conn, "mallory@example.com");
        insert(&mut conn, alice, &enrol("alice@example.com"), false).expect("insert");
        let row_id = list_by_user(&mut conn, alice).expect("list")[0].id;

        assert!(!rename_for_user(&mut conn, row_id, mallory, Some("pwned")).expect("rename"));
        assert!(rename_for_user(&mut conn, row_id, alice, Some("Laptop")).expect("rename"));
        assert_eq!(
            list_by_user(&mut conn, alice).expect("list")[0]
                .name
                .as_deref(),
            Some("Laptop")
        );
    }

    #[test]
    fn default_name_is_date_derived() {
        let when = chrono::NaiveDate::from_ymd_opt(2026, 9, 4)
            .expect("valid date")
            .and_hms_opt(12, 0, 0)
            .expect("valid time");
        assert_eq!(default_name(when), "Passkey · Sep 4, 2026");
    }
}
