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
