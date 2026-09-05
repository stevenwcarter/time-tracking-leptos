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
/// `unmigrated_hint` is deliberately a hint, not a count: the server never
/// parses an entry body (invariant E1), so it cannot know *which* rows are
/// still v1, only whether the account has both been encrypted and has any
/// entry at all — `true` whenever it is worth the client asking `entries_all`
/// and running the real, pure-function check (`rows_needing_migration`)
/// itself. It can read `true` after every row has actually been migrated;
/// that costs one wasted client-side check, never a missed migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionStatus {
    pub enabled: bool,
    pub unmigrated_hint: bool,
}
