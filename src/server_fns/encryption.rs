//! Moving wrapped-key blobs between the browser and `entry_key_wrap`.
//!
//! Every function here handles opaque bytes end to end: none can derive a
//! data key, and none reads an entry body (spec section 7.6, invariant E1).
//! The repository underneath (`entry_key::store`) owns the schema-level
//! invariants (one recovery wrap, a wrap per credential); this module's own
//! job is authorization — whose wraps these are, and the one refusal spec
//! section 6.6 requires.

use leptos::prelude::*;

use crate::dto::WrapDto;

/// Whether the signed-in account is encrypted, and which account that is.
///
/// The address is part of the answer rather than assumed by the caller: the
/// session cookie decides who this is about, and a browser tab that was
/// opened before somebody else signed in has no other way to find out it is
/// now asking about a different account (see [`crate::dto::EncryptionStatus`]).
///
/// The return type is spelled out with its full path rather than `use`d:
/// `#[server]` generates a same-named arguments struct in this module for
/// every function it wraps, and `encryption_status`'s would collide with a
/// `use`d `dto::EncryptionStatus` — the two are different items sharing one
/// name, which only `use` (not a qualified path) actually conflates.
#[server(endpoint = "encryption/status")]
pub async fn encryption_status() -> Result<crate::dto::EncryptionStatus, ServerFnError> {
    use crate::dto::EncryptionStatus;
    use crate::entry_key::store;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    let enabled = store::is_encrypted(&mut conn, me.id)
        .map_err(super::log_and_fail("is_encrypted", "Internal server error"))?;

    Ok(EncryptionStatus {
        account: me.email,
        enabled,
    })
}

/// The signed-in user's own wraps. Scoped by `require_user`'s `me.id`, not
/// anything the caller supplies — there is no argument to get wrong here.
#[server(endpoint = "encryption/wraps")]
pub async fn encryption_wraps() -> Result<Vec<WrapDto>, ServerFnError> {
    use crate::entry_key::store;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    Ok(store::list_wraps(&mut conn, me.id)
        .map_err(super::log_and_fail("list wraps", "Internal server error"))?
        .into_iter()
        .map(WrapDto::from)
        .collect())
}

/// Turns encryption on: one transaction that marks the account and inserts
/// both starting wraps (spec section 6.1 step 4).
///
/// Errors if `encrypted_at` is already set, checked inside the same
/// transaction as the writes rather than before it — a double-submit must
/// see one consistent account state, not a check and a write that could
/// straddle two different ones.
#[server(endpoint = "encryption/enable")]
pub async fn encryption_enable(
    passkey_wrap: Vec<u8>,
    credential_id: Vec<u8>,
    recovery_wrap: Vec<u8>,
) -> Result<(), ServerFnError> {
    use diesel::prelude::*;

    use crate::crypto::wire::WrapKind;
    use crate::entry_key::store;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    // `store`'s functions return `anyhow::Result`, so the transaction's
    // error type is `anyhow::Error` rather than `diesel::result::Error` —
    // still explicit, still satisfies Diesel's `From<diesel::result::Error>`
    // bound, just composed from calls that already carry their own context.
    // The inner `Result<(), &str>` is the outcome the caller sees: `Err` is
    // an expected, user-facing refusal, never something worth logging.
    let outcome = conn
        .transaction::<Result<(), &'static str>, anyhow::Error, _>(|conn| {
            if store::is_encrypted(conn, me.id)? {
                return Ok(Err("Encryption is already enabled for this account."));
            }
            store::set_encrypted(conn, me.id)?;
            store::insert_wrap(
                conn,
                me.id,
                WrapKind::Passkey,
                Some(&credential_id),
                &passkey_wrap,
            )?;
            store::insert_wrap(conn, me.id, WrapKind::Recovery, None, &recovery_wrap)?;
            Ok(Ok(()))
        })
        .map_err(super::log_and_fail(
            "encryption enable",
            "Internal server error",
        ))?;

    outcome.map_err(super::server_err)
}

/// Adds a route to the account's data key for a newly enrolled passkey
/// (spec section 6.5).
///
/// Verifies `credential_id` is the caller's own before inserting anything —
/// a wrap filed under someone else's credential id could never be opened by
/// its supposed owner and would only leak that the id exists.
#[server(endpoint = "encryption/add_passkey_wrap")]
pub async fn encryption_add_passkey_wrap(
    credential_id: Vec<u8>,
    wrapped_key: Vec<u8>,
) -> Result<(), ServerFnError> {
    use crate::crypto::wire::WrapKind;
    use crate::entry_key::store as key_store;
    use crate::passkey::store as passkey_store;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    let owner = passkey_store::find_by_credential_id(&mut conn, &credential_id)
        .map_err(super::log_and_fail(
            "find credential",
            "Internal server error",
        ))?
        .map(|row| row.user_id);
    // "Not found" and "belongs to someone else" get the same message, same
    // as the passkey sign-in ceremony's account-existence guard — neither
    // case should tell the caller which one it hit.
    if owner != Some(me.id) {
        return Err(super::server_err(
            "That passkey does not belong to your account.",
        ));
    }

    key_store::insert_wrap(
        &mut conn,
        me.id,
        WrapKind::Passkey,
        Some(&credential_id),
        &wrapped_key,
    )
    .map_err(super::log_and_fail(
        "insert passkey wrap",
        "Internal server error",
    ))
}

/// Re-issues the recovery wrap after a recovery unlock (spec section 6.4).
/// `entry_key::store::replace_recovery_wrap` already deletes-then-inserts in
/// its own transaction, so there is nothing more to wrap here.
///
/// Idempotent for a given `wrapped_key`, which the store guarantees rather
/// than this layer: a client whose first response was lost may resend the
/// same bytes and will be told it succeeded. Without that, a reply dropped
/// after a successful replace leaves the user holding a recovery code that
/// no longer opens anything, believing it does — the one failure in this
/// design that ends in permanently unreadable entries.
#[server(endpoint = "encryption/replace_recovery_wrap")]
pub async fn encryption_replace_recovery_wrap(wrapped_key: Vec<u8>) -> Result<(), ServerFnError> {
    use crate::entry_key::store;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    store::replace_recovery_wrap(&mut conn, me.id, &wrapped_key).map_err(super::log_and_fail(
        "replace recovery wrap",
        "Internal server error",
    ))
}
