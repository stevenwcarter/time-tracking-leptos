//! WebAuthn ceremonies and passkey management.
//!
//! Ported from photo365 with one identity change: credentials key off
//! `user_id` rather than a free-text email subject.

use leptos::prelude::*;

use crate::dto::PasskeyListItem;

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

/// Adds the options webauthn-rs does not emit, by editing the serialized
/// challenge before it reaches the browser.
///
/// Two edits, both load-bearing:
///
/// 1. `residentKey: required`. webauthn-rs ships `requireResidentKey: false`,
///    which lets some providers store a **non-discoverable** credential.
///    That silently breaks the username-less "Use a passkey" flow, because
///    the credential never surfaces without an `allowCredentials` list. The
///    stored registration state is unaffected; verification works either way.
/// 2. `extensions.prf`. Requesting PRF is only possible at *creation* time,
///    and webauthn-rs 0.6 has no typed API for it. Phase 1 ignores the
///    result; phase 2 derives an encryption key from it. Without this, every
///    passkey enrolled now would have to be deleted and re-added later
///    (spec section 9.3).
#[cfg(feature = "ssr")]
fn augment_creation_options(ccr: &mut serde_json::Value) {
    let Some(public_key) = ccr.get_mut("publicKey").and_then(|v| v.as_object_mut()) else {
        tracing::error!("creation options had no publicKey object");
        return;
    };

    let selection = public_key
        .entry("authenticatorSelection")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(sel) = selection.as_object_mut() {
        sel.insert("residentKey".into(), serde_json::json!("required"));
        sel.insert("requireResidentKey".into(), serde_json::json!(true));
    }

    let extensions = public_key
        .entry("extensions")
        .or_insert_with(|| serde_json::json!({}));
    if let Some(ext) = extensions.as_object_mut() {
        ext.insert("prf".into(), serde_json::json!({}));
    }
}

/// Begins enrolling a passkey for the signed-in user.
#[server(endpoint = "passkey/register_start")]
pub async fn passkey_register_start() -> Result<String, ServerFnError> {
    use crate::passkey::state::{PasskeyState, encode, set_cookie_header};
    use crate::passkey::store;
    use webauthn_rs::prelude::*;

    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    // Excluding the user's existing credentials stops a double-enrolment of
    // the same authenticator, which would otherwise show up as a duplicate
    // row the user cannot tell apart.
    let exclude: Vec<CredentialID> = store::list_by_user(&mut conn, me.id)
        .map_err(super::log_and_fail(
            "list passkeys",
            "Internal server error",
        ))?
        .into_iter()
        .map(|row| row.credential_id)
        .collect();

    // A stable per-user UUID, so re-registering does not create a second
    // WebAuthn "user" in the authenticator's UI.
    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_URL, me.email.as_bytes());

    let (ccr, reg) = ctx
        .webauthn
        .start_passkey_registration(uuid, &me.email, &me.email, Some(exclude))
        .map_err(super::log_and_fail(
            "start registration",
            "Could not start passkey registration",
        ))?;

    let mut ccr_json = serde_json::to_value(&ccr).map_err(super::log_and_fail(
        "serialize ccr",
        "Internal server error",
    ))?;
    augment_creation_options(&mut ccr_json);

    let encoded = encode(&PasskeyState::reg(me.email.clone(), reg))
        .map_err(super::log_and_fail("encode state", "Internal server error"))?;
    set_cookie(set_cookie_header(&encoded));

    serde_json::to_string(&ccr_json).map_err(super::log_and_fail(
        "serialize ccr json",
        "Internal server error",
    ))
}

/// Completes enrolment. `prf_capable` is what the browser reported from
/// `getClientExtensionResults()`; see `webauthn_browser::register`.
#[server(endpoint = "passkey/register_finish")]
pub async fn passkey_register_finish(
    response_json: String,
    prf_capable: bool,
) -> Result<(), ServerFnError> {
    use crate::passkey::state::{COOKIE_NAME, PasskeyState, clear_cookie_header, decode};
    use crate::passkey::store;
    use webauthn_rs::prelude::*;

    let (ctx, me) = super::require_user()?;

    let jar = leptos_axum::extract::<axum_extra::extract::CookieJar>()
        .await
        .map_err(|_| super::server_err("Could not read cookies"))?;
    let raw = jar
        .get(COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or_else(|| super::server_err("Your passkey session expired. Please retry."))?;
    let state = decode(&raw)
        .map_err(|_| super::server_err("Your passkey session is invalid. Please retry."))?;
    set_cookie(clear_cookie_header());

    let PasskeyState::Reg { subject, reg, .. } = state else {
        return Err(super::server_err("Wrong ceremony type."));
    };
    // The ceremony state is signed, but it is still client-held: bind it to
    // the session that is finishing it.
    if subject != me.email {
        return Err(super::server_err("Wrong ceremony type."));
    }

    let rpc: RegisterPublicKeyCredential = serde_json::from_str(&response_json)
        .map_err(|_| super::server_err("Malformed credential response."))?;
    let key = ctx
        .webauthn
        .finish_passkey_registration(&rpc, &reg)
        .map_err(|e| {
            tracing::warn!("finish_passkey_registration: {e:?}");
            super::server_err("Could not verify your passkey.")
        })?;

    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    store::insert(&mut conn, me.id, &key, prf_capable).map_err(super::log_and_fail(
        "insert passkey",
        "Internal server error",
    ))?;
    Ok(())
}

/// Begins a sign-in ceremony.
///
/// `Some(email)` builds a ceremony over that address's credentials; `None`
/// starts the discoverable flow behind the "Use a passkey" button.
///
/// SECURITY: an unregistered address and a registered one with no enrolled
/// passkeys both fall through to the same generic error below. That equality
/// — not any earlier check — is what stops account enumeration (invariant I6).
#[server(endpoint = "passkey/login_start")]
pub async fn passkey_login_start(email: Option<String>) -> Result<String, ServerFnError> {
    use crate::auth::user;
    use crate::passkey::state::{PasskeyState, encode, set_cookie_header};
    use crate::passkey::store;
    use crate::rate_limit;
    use webauthn_rs::prelude::*;

    let ctx = super::require_ctx()?;
    let ip = ctx
        .client_ip
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    if !rate_limit::check_ip(&ip) {
        return Err(super::server_err(
            "Too many attempts. Please wait a minute.",
        ));
    }

    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    let (rcr, state) = match email {
        Some(raw) => {
            let generic = || super::server_err("We couldn't verify your passkey.");
            let normalized = user::normalize_email(&raw).ok_or_else(generic)?;
            let found = user::find_by_email(&mut conn, &normalized)
                .map_err(super::log_and_fail("find user", "Internal server error"))?
                .ok_or_else(generic)?;
            let rows = store::list_by_user(&mut conn, found.id).map_err(super::log_and_fail(
                "list passkeys",
                "Internal server error",
            ))?;
            if rows.is_empty() {
                return Err(generic());
            }
            let keys: Vec<Passkey> = rows
                .iter()
                .map(|r| r.deserialize_passkey())
                .collect::<Result<_, _>>()
                .map_err(super::log_and_fail(
                    "decode passkey",
                    "Internal server error",
                ))?;
            let (rcr, auth) = ctx
                .webauthn
                .start_passkey_authentication(&keys)
                .map_err(|e| {
                    tracing::warn!("start_passkey_authentication: {e:?}");
                    generic()
                })?;
            (rcr, PasskeyState::auth(normalized, auth))
        }
        None => {
            let (rcr, auth) = ctx
                .webauthn
                .start_discoverable_authentication()
                .map_err(|e| {
                    tracing::warn!("start_discoverable_authentication: {e:?}");
                    super::server_err("We couldn't verify your passkey.")
                })?;
            (rcr, PasskeyState::discoverable(auth))
        }
    };

    let encoded =
        encode(&state).map_err(super::log_and_fail("encode state", "Internal server error"))?;
    set_cookie(set_cookie_header(&encoded));
    serde_json::to_string(&rcr).map_err(super::log_and_fail(
        "serialize rcr",
        "Internal server error",
    ))
}

/// Completes a sign-in ceremony and sets the session cookie.
#[server(endpoint = "passkey/login_finish")]
pub async fn passkey_login_finish(response_json: String) -> Result<(), ServerFnError> {
    use crate::auth::user;
    use crate::passkey::state::{COOKIE_NAME, PasskeyState, clear_cookie_header, decode};
    use crate::passkey::store;
    use crate::server::cookie;
    use crate::session::{self, COOKIE_NAME as SESSION_COOKIE, MAX_AGE_SECONDS};
    use webauthn_rs::prelude::*;

    let ctx = super::require_ctx()?;
    let generic = || super::server_err("We couldn't verify your passkey.");

    let jar = leptos_axum::extract::<axum_extra::extract::CookieJar>()
        .await
        .map_err(|_| super::server_err("Could not read cookies"))?;
    let raw = jar
        .get(COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or_else(|| super::server_err("Your sign-in session expired. Please retry."))?;
    let state = decode(&raw)
        .map_err(|_| super::server_err("Your sign-in session is invalid. Please retry."))?;
    set_cookie(clear_cookie_header());

    let pkc: PublicKeyCredential = serde_json::from_str(&response_json)
        .map_err(|_| super::server_err("Malformed credential response."))?;

    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;

    let (row, updated) = match state {
        PasskeyState::Auth { subject, auth, .. } => {
            let result = ctx
                .webauthn
                .finish_passkey_authentication(&pkc, &auth)
                .map_err(|e| {
                    tracing::warn!("finish_passkey_authentication: {e:?}");
                    generic()
                })?;
            let row = store::find_by_credential_id(&mut conn, result.cred_id().as_ref())
                .map_err(super::log_and_fail(
                    "find credential",
                    "Internal server error",
                ))?
                .ok_or_else(generic)?;
            let owner = user::find_by_email(&mut conn, &subject)
                .map_err(super::log_and_fail("find user", "Internal server error"))?
                .ok_or_else(generic)?;
            // The ceremony named a subject; the credential must belong to it.
            if row.user_id != owner.id {
                tracing::warn!("passkey subject mismatch");
                return Err(generic());
            }
            let mut key = row.deserialize_passkey().map_err(super::log_and_fail(
                "decode passkey",
                "Internal server error",
            ))?;
            key.update_credential(&result);
            (row, key)
        }
        PasskeyState::DiscoverableAuth { auth, .. } => {
            let (_uuid, cred_id) = ctx
                .webauthn
                .identify_discoverable_authentication(&pkc)
                .map_err(|e| {
                    tracing::warn!("identify_discoverable_authentication: {e:?}");
                    generic()
                })?;
            let row = store::find_by_credential_id(&mut conn, cred_id)
                .map_err(super::log_and_fail(
                    "find credential",
                    "Internal server error",
                ))?
                .ok_or_else(generic)?;
            let mut key = row.deserialize_passkey().map_err(super::log_and_fail(
                "decode passkey",
                "Internal server error",
            ))?;
            // `finish_discoverable_authentication` takes the candidate credential
            // list separately from the stored state; the only candidate here is
            // the one row `identify_discoverable_authentication` already found.
            let result = ctx
                .webauthn
                .finish_discoverable_authentication(&pkc, auth, &[key.clone().into()])
                .map_err(|e| {
                    tracing::warn!("finish_discoverable_authentication: {e:?}");
                    generic()
                })?;
            key.update_credential(&result);
            (row, key)
        }
        PasskeyState::Reg { .. } => return Err(super::server_err("Wrong ceremony type.")),
    };

    store::update_after_use(&mut conn, row.id, &updated).map_err(super::log_and_fail(
        "update passkey",
        "Internal server error",
    ))?;

    let owner: crate::auth::user::User = {
        use crate::schema::user as user_table;
        use diesel::prelude::*;
        user_table::table
            .find(row.user_id)
            .first(&mut conn)
            .map_err(super::log_and_fail("load user", "Internal server error"))?
    };

    let token = session::issue(&owner.email, owner.session_epoch);
    set_cookie(cookie::http_only(SESSION_COOKIE, &token, MAX_AGE_SECONDS));
    tracing::info!(user = %owner.email, "signed in via passkey");
    Ok(())
}

/// The signed-in user's passkeys, newest first.
#[server(endpoint = "passkey/list")]
pub async fn passkey_list() -> Result<Vec<PasskeyListItem>, ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    Ok(store::list_by_user(&mut conn, me.id)
        .map_err(super::log_and_fail(
            "list passkeys",
            "Internal server error",
        ))?
        .into_iter()
        .map(|row| PasskeyListItem {
            id: row.id,
            name: row.display_name(),
            added: row.created_at.format("%b %-d, %Y").to_string(),
            last_used: row.last_used_at.map(|t| t.format("%b %-d, %Y").to_string()),
        })
        .collect())
}

/// Renames a passkey, or resets it to the date-derived default when `name`
/// is blank.
#[server(endpoint = "passkey/rename")]
pub async fn passkey_rename(id: i32, name: String) -> Result<(), ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    // `id` and `me.id` both land in the UPDATE's WHERE clause (invariant
    // I7): another user's id matches no row rather than being rejected
    // after a separate ownership check.
    let renamed = store::rename_for_user(&mut conn, id, me.id, Some(&name)).map_err(
        super::log_and_fail("rename passkey", "Internal server error"),
    )?;
    if renamed {
        Ok(())
    } else {
        Err(super::server_err("That passkey no longer exists."))
    }
}

/// Removes a passkey.
#[server(endpoint = "passkey/delete")]
pub async fn passkey_delete(id: i32) -> Result<(), ServerFnError> {
    use crate::passkey::store;
    let (ctx, me) = super::require_user()?;
    let mut conn = ctx
        .conn()
        .map_err(super::log_and_fail("conn", "Internal server error"))?;
    // Same scoping as `passkey_rename` above (invariant I7).
    let deleted = store::delete_for_user(&mut conn, id, me.id).map_err(super::log_and_fail(
        "delete passkey",
        "Internal server error",
    ))?;
    if deleted {
        Ok(())
    } else {
        Err(super::server_err("That passkey no longer exists."))
    }
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use webauthn_rs::prelude::*;

    use super::*;
    use crate::passkey::webauthn::build_from_env;

    /// Pins the two wire-format edits `augment_creation_options` makes,
    /// against a *real* serialized challenge from the current webauthn-rs —
    /// not a hand-rolled JSON literal, so a dependency upgrade that renames
    /// a field (e.g. `residentKey`, or drops the unmodeled `prf` extension
    /// slot) fails this test instead of silently shipping. Both failure
    /// modes are silent otherwise: a missing `residentKey` breaks
    /// username-less sign-in only for providers that honor it, and a
    /// missing `extensions.prf` is not discoverable until phase 2, by which
    /// point affected credentials would need deleting and re-enrolling
    /// (spec section 9.3).
    ///
    /// Asserted on the serialized JSON, not the Rust struct — the whole
    /// point is that this is an edit webauthn-rs has no typed API for, so a
    /// struct-level assertion would not catch a serde rename either.
    #[test]
    fn augments_a_real_creation_challenge_with_both_edits() {
        let wa = build_from_env();
        let (ccr, _reg) = wa
            .start_passkey_registration(
                Uuid::new_v4(),
                "alice@example.com",
                "alice@example.com",
                None,
            )
            .expect("start registration");
        let mut ccr_json = serde_json::to_value(&ccr).expect("serialize ccr");

        augment_creation_options(&mut ccr_json);

        let selection = &ccr_json["publicKey"]["authenticatorSelection"];
        assert_eq!(selection["residentKey"], "required");
        assert_eq!(selection["requireResidentKey"], true);
        assert!(
            ccr_json["publicKey"]["extensions"]["prf"].is_object(),
            "extensions.prf missing: {ccr_json}"
        );
    }
}
