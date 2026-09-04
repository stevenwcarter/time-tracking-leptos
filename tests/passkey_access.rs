//! Pins invariant I6 and passkey ownership scoping.

#![cfg(feature = "ssr")]

use time_tracking_leptos::test_support::{SessionClient, TestApp, signed_in_as};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::*;

/// Drives a real (software) authenticator through the registration wire
/// protocol, so a test can get a signed-in user to "have a passkey" without
/// hand-rolling a credential response.
///
/// Lives here rather than on `SessionClient` itself: `webauthn-authenticator-rs`
/// is a dev-dependency, available to this integration test crate directly,
/// but *not* to `src/test_support.rs` — that module compiles as part of the
/// ordinary library (the `main` binary links it too), and `tests/*.rs` files
/// link against that same ordinary build, not a `#[cfg(test)]` one. A dev-only
/// import there would either fail to build the library at all, or (if
/// `#[cfg(test)]`-gated) compile but be invisible from here — the same
/// reason `test_support`'s own doc comment gives for why it isn't
/// `#[cfg(test)]`.
trait EnrolPasskey {
    /// Enrols one passkey for this session and returns its row id.
    async fn enrol_passkey(&self) -> Result<i32, String>;
}

impl EnrolPasskey for SessionClient {
    async fn enrol_passkey(&self) -> Result<i32, String> {
        let ccr_json = self.passkey_register_start().await?;
        let mut ccr: CreationChallengeResponse =
            serde_json::from_str(&ccr_json).map_err(|e| e.to_string())?;

        // `augment_creation_options` forces `requireResidentKey: true` so a
        // real platform authenticator creates a discoverable credential —
        // see its doc comment. `SoftPasskey` is a plain, non-resident-key
        // test double that hard-errors rather than honor that hint, so it
        // stands in here for a real authenticator that ignores the request
        // rather than one that satisfies it. That only changes what the
        // *authenticator* is asked to do: `finish_passkey_registration`
        // does not re-check residency (the same doc comment notes
        // verification works either way), so this still exercises the real
        // server-side ceremony end to end.
        if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
            sel.require_resident_key = false;
            sel.resident_key = None;
        }

        // The same relying-party origin the server itself builds from env,
        // so the authenticator's ceremony matches what `passkey_register_finish`
        // will verify against.
        let wa = time_tracking_leptos::passkey::webauthn::build_from_env();
        let origin = wa.get_allowed_origins()[0].clone();
        let mut authenticator = SoftPasskey::new(true);
        let rpc = authenticator
            .do_registration(origin, ccr)
            .map_err(|e| format!("authenticator registration: {e:?}"))?;
        let rpc_json = serde_json::to_string(&rpc).map_err(|e| e.to_string())?;

        self.passkey_register_finish(&rpc_json, true).await?;

        // Newest first, and this is the only credential this session has
        // just created, so it is the first row.
        self.passkey_list()
            .await?
            .into_iter()
            .next()
            .map(|row| row.id)
            .ok_or_else(|| "no passkey after enrolment".to_string())
    }
}

/// An unregistered address and a registered address with no enrolled
/// passkeys must be indistinguishable. If they ever differ, `passkey_login_start`
/// becomes an account-existence oracle.
#[tokio::test]
async fn login_start_cannot_distinguish_unknown_from_passkey_less() {
    let app = TestApp::new().await;
    // Registered, but has enrolled no passkeys.
    let _ = signed_in_as(&app, "known@example.com").await;

    let known = app
        .anonymous()
        .passkey_login_start(Some("known@example.com"))
        .await;
    let unknown = app
        .anonymous()
        .passkey_login_start(Some("nobody@example.com"))
        .await;

    let (Err(a), Err(b)) = (known, unknown) else {
        panic!("both must fail: neither address has an enrolled passkey");
    };
    assert_eq!(a, b, "error text must be identical");
}

#[tokio::test]
async fn passkey_management_requires_a_session() {
    let app = TestApp::new().await;
    let anon = app.anonymous();
    assert!(anon.passkey_list().await.is_err());
    assert!(anon.passkey_delete(1).await.is_err());
    assert!(anon.passkey_rename(1, "x").await.is_err());
}

#[tokio::test]
async fn a_user_cannot_delete_another_users_passkey() {
    let app = TestApp::new().await;
    let alice = signed_in_as(&app, "alice@example.com").await;
    let mallory = signed_in_as(&app, "mallory@example.com").await;
    let id = alice.enrol_passkey().await.expect("enrol");

    assert!(mallory.passkey_delete(id).await.is_err());
    assert_eq!(alice.passkey_list().await.expect("list").len(), 1);
}
