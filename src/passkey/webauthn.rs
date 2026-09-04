//! The `Webauthn` instance, built once from env at startup.

use std::sync::Arc;

use webauthn_rs::prelude::*;

/// Builds the relying-party configuration.
///
/// Defaults suit local development against `cargo leptos watch`. In
/// production `WEBAUTHN_RP_ORIGIN` must match the browser's origin exactly,
/// scheme included, or every ceremony fails with an origin mismatch.
pub fn build_from_env() -> Arc<Webauthn> {
    let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin_str =
        std::env::var("WEBAUTHN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let rp_origin = Url::parse(&rp_origin_str)
        .unwrap_or_else(|e| panic!("invalid WEBAUTHN_RP_ORIGIN={rp_origin_str:?}: {e}"));
    let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "Time Tracker".to_string());

    Arc::new(
        WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("WebauthnBuilder::new")
            .rp_name(&rp_name)
            .build()
            .expect("Webauthn::build"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_with_defaults() {
        let _wa: Arc<Webauthn> = build_from_env();
    }
}
