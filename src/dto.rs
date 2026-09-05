//! Types crossing the server-fn boundary. Shared by both targets.

use serde::{Deserialize, Serialize};

/// One row of the `/account` passkey list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyListItem {
    pub id: i32,
    /// Already resolved to the date-derived default when unnamed, so the
    /// view never has to know the fallback rule.
    pub name: String,
    pub added: String,
    pub last_used: Option<String>,
    /// The credential's own id, so the encryption panel can join this row
    /// against [`WrapDto::credential_id`] and say whether this passkey has
    /// a route to the account's data key (spec section 6.5).
    ///
    /// Not a new disclosure: `encryption_wraps` already returns the caller
    /// their own credential ids, and both calls are scoped to the signed-in
    /// user.
    pub credential_id: Vec<u8>,
    /// What the browser reported about PRF support when this credential was
    /// enrolled.
    ///
    /// Distinct from "has a wrap", and the panel needs both. A passkey with
    /// no wrap and `prf_capable = false` can *never* unlock; one with no
    /// wrap and `prf_capable = true` simply has not been given a key yet,
    /// which is a thing the user can fix. Reporting the two the same way
    /// would either offer a repair that cannot work or hide one that can.
    pub prf_capable: bool,
}

/// One route to the account's data key, as seen from the browser.
///
/// `kind` travels as the stored `String` rather than as
/// [`crate::crypto::wire::WrapKind`], and stays one: a row whose kind a
/// future build writes and this one does not know still deserializes, and
/// `crypto::choose_route` skips that row instead of the whole response
/// failing to parse.
///
/// That forward compatibility runs one direction only: an *older* client
/// reading a row a *newer* server wrote. On a rollback — an older server
/// reading a row a newer client's server-side counterpart already wrote —
/// `entry_key::store`'s `WrapRecord::into_wrap_row` parses `kind` back into
/// `WrapKind` before this type ever gets built, and returns `Err` on an
/// unrecognized one. `list_wraps` propagates that `Err` for the whole call,
/// so one row of an unknown kind fails the entire response rather than being
/// skipped the way `choose_route` skips it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrapDto {
    pub kind: String,
    pub credential_id: Option<Vec<u8>>,
    pub wrapped_key: Vec<u8>,
    pub kdf: String,
    pub wrap_alg: String,
}

#[cfg(feature = "ssr")]
impl From<crate::entry_key::store::WrapRow> for WrapDto {
    fn from(row: crate::entry_key::store::WrapRow) -> Self {
        WrapDto {
            kind: row.kind.as_str().to_string(),
            credential_id: row.credential_id,
            wrapped_key: row.wrapped_key,
            kdf: row.kdf,
            wrap_alg: row.wrap_alg,
        }
    }
}

/// The signed-in account's encryption state, as seen from the browser.
///
/// Just `enabled`: a server-computed "is migration pending" hint was
/// considered and dropped. The server never parses an entry body (invariant
/// E1), so the best it could report was "encrypted and has any entry at
/// all" — true forever once an account has saved anything, including long
/// after migration finishes. Getting it exact would mean a client-written
/// schema column recording envelope versions, which is a real compatibility
/// surface for one rarely-visited page. `/account` instead calls
/// `entries_all` and runs the real, pure-function check
/// (`rows_needing_migration`) itself when it needs the count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionStatus {
    pub enabled: bool,
}
