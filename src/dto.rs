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
/// `kind` travels as a `String` rather than `entry_key::WrapKind`: that enum
/// lives behind Diesel, which does not exist in the wasm bundle, so this
/// type — not that one — is what a server function can return and the
/// browser can select a route from.
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
