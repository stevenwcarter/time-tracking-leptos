//! Client-side encryption of entry bodies.
//!
//! See `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`.
//!
//! This file is the orchestration layer over the four modules below: the
//! [`SessionKey`] components hold, the ceremonies of spec section 6 that
//! create, open and re-wrap it, and the one decision in the whole feature
//! that is both load-bearing and pure — [`choose_route`], which says *which*
//! stored wrap to open.

/// Per-device storage of the unlocked data key. Browser-only: IndexedDB has
/// no host equivalent, so this module exists solely in the wasm bundle.
#[cfg(feature = "hydrate")]
pub mod keystore;
pub mod recovery;
/// The `SubtleCrypto` calls. Browser-only: WebCrypto has no host equivalent,
/// so this module exists solely in the wasm bundle.
#[cfg(feature = "hydrate")]
pub mod subtle;
pub mod wire;

#[cfg(any(feature = "hydrate", test))]
use self::wire::WrapKind;
#[cfg(any(feature = "hydrate", test))]
use crate::dto::WrapDto;

#[cfg(feature = "hydrate")]
pub use self::ceremony::{
    Enabled, Opener, SessionKey, UnlockError, add_passkey_route, enable, reissue_recovery,
    unlock_with_prf, unlock_with_recovery,
};

/// The wrap this device is going to try to open, picked out of the rows the
/// server offered.
///
/// Owned rather than borrowed from the [`WrapDto`] it was chosen from: its
/// consumer is an effect that hands the route to `spawn_local`, which needs
/// `'static`, and forty-odd bytes is not worth a lifetime parameter reaching
/// through every caller.
#[cfg(any(feature = "hydrate", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapRoute {
    /// Which secret opens it, and so which HKDF `info` derives its KEK.
    pub kind: WrapKind,
    /// The credential whose PRF output derives the KEK, on a passkey route;
    /// `None` on the recovery route.
    pub credential_id: Option<Vec<u8>>,
    /// The wrapped data key itself.
    pub wrapped_key: Vec<u8>,
}

/// Picks the wrap to open, given the credential that just asserted.
///
/// `credential_id` is `Some` after a passkey assertion and `None` when the
/// user is unlocking with a recovery code, and the two do not fall back to
/// one another in either direction. A credential with no wrap of its own —
/// enrolled before encryption was turned on, or living on an authenticator
/// with no PRF — gets `None` rather than somebody else's wrap: its PRF
/// output derives a KEK that cannot open another credential's wrap, so the
/// fallback would not work, and it would fail as an `unwrapKey` error
/// indistinguishable from a corrupt row (spec section 6.4).
///
/// A row whose `kind` this build does not recognise is skipped rather than
/// guessed at, so a future third kind of route cannot be mistaken for one of
/// these two. A row whose `kdf` or `wrap_alg` this build does not recognise
/// is skipped the same way (spec section 5.2): each column names an
/// algorithm precisely so that a future change is a new value to add support
/// for, not a guess made under the wrong one.
#[cfg(any(feature = "hydrate", test))]
pub fn choose_route(wraps: &[WrapDto], credential_id: Option<&[u8]>) -> Option<WrapRoute> {
    wraps.iter().find_map(|wrap| {
        let kind = WrapKind::parse(&wrap.kind)?;
        if wrap.kdf != wire::KDF_HKDF_SHA256 || wrap.wrap_alg != wire::WRAP_ALG_AESKW256 {
            return None;
        }
        let selected = match (kind, credential_id) {
            (WrapKind::Passkey, Some(id)) => wrap.credential_id.as_deref() == Some(id),
            (WrapKind::Recovery, None) => true,
            _ => false,
        };
        selected.then(|| WrapRoute {
            kind,
            credential_id: wrap.credential_id.clone(),
            wrapped_key: wrap.wrapped_key.clone(),
        })
    })
}

/// The ceremonies of spec section 6. Browser-only: every one of them reaches
/// WebCrypto, so this module exists solely in the wasm bundle.
#[cfg(feature = "hydrate")]
mod ceremony {
    use leptos::logging::error;

    use super::keystore;
    use super::recovery::{self, CODE_BYTES, RecoveryError};
    use super::subtle::{self, CryptoError, DataKey, Kek};
    use super::wire::{self, WrapKind};

    /// The unlocked data key for this session, plus who it belongs to.
    ///
    /// Cloneable because the handle inside is a JS `CryptoKey` reference: a
    /// clone duplicates the reference, not the key. Components receive one
    /// through context and can [`seal`](Self::seal) and [`open`](Self::open)
    /// with it, but there is no accessor for the key and no way to derive a
    /// `subtle::RawDataKey` from it, so nothing holding a `SessionKey` can
    /// export the data key (invariant E5).
    #[derive(Clone)]
    pub struct SessionKey {
        key: DataKey,
        user: String,
    }

    impl SessionKey {
        /// Picks the key back up from this device's keystore, if it holds one
        /// for `user`.
        ///
        /// The `Unlocked`-or-`Locked` decision of spec section 7.4. `Ok(None)`
        /// is the ordinary "no key on this device for this account" — a first
        /// visit, a private window, cleared site data, another account's
        /// record — and means `Locked`, not a failure.
        pub async fn restore(user: &str) -> Result<Option<Self>, CryptoError> {
            Ok(keystore::get(user).await?.map(|key| Self {
                key,
                user: user.to_string(),
            }))
        }

        /// Remembers `key` on this device and wraps it in a session handle.
        ///
        /// A keystore write that fails is logged and otherwise ignored, which
        /// is why this returns `Self` and not `Result`. The key is usable for
        /// this page load either way and the only cost of not persisting it
        /// is one more unlock prompt after a reload; refusing the user their
        /// entries because a cache write failed would be the worse trade
        /// (spec section 12's private-window row).
        async fn adopt(user: &str, key: DataKey) -> Self {
            if let Err(e) = keystore::put(user, &key).await {
                error!("could not remember the data key on this device: {e}");
            }
            Self {
                key,
                user: user.to_string(),
            }
        }

        /// The account this key belongs to.
        ///
        /// Read by the encryption context (spec section 7.4) when
        /// `AuthCtx::user` changes: an in-memory handle unlocked for the
        /// previous account outlives the keystore's own user check, which
        /// only runs on a read.
        pub fn user(&self) -> &str {
            &self.user
        }

        /// Encrypts one entry body.
        pub async fn seal(&self, plaintext: &str) -> Result<wire::Sealed, CryptoError> {
            subtle::seal(&self.key, plaintext).await
        }

        /// Decrypts one entry body.
        pub async fn open(&self, sealed: &wire::Sealed) -> Result<String, CryptoError> {
            subtle::open(&self.key, sealed).await
        }
    }

    /// A stored wrap together with the secret that opens it.
    ///
    /// The two travel as one value because they have to correspond. A KEK
    /// derived from the recovery code and pointed at a passkey's wrap fails
    /// with the same authenticated-`unwrapKey` error as a wrong code, so
    /// mismatching them at a call site would produce a bug reported as "that
    /// recovery code didn't work". Pairing them in the type removes the
    /// chance.
    pub enum Opener<'a> {
        /// One credential's PRF output, against that credential's wrap.
        Passkey {
            prf_output: &'a [u8],
            wrap: &'a [u8],
        },
        /// A recovery code as the user typed it, against the recovery wrap.
        Recovery { code: &'a str, wrap: &'a [u8] },
    }

    impl Opener<'_> {
        /// The wrapped data key this opener unwraps.
        fn wrap(&self) -> &[u8] {
            match *self {
                Opener::Passkey { wrap, .. } | Opener::Recovery { wrap, .. } => wrap,
            }
        }
    }

    /// A ceremony that had to open an existing wrap did not get there.
    #[derive(Debug, Clone, thiserror::Error)]
    pub enum UnlockError {
        /// What the user typed is not a recovery code at all: the wrong
        /// number of characters, or a character outside the alphabet.
        ///
        /// Deliberately a separate variant from [`UnlockError::Crypto`].
        /// "That doesn't look like a recovery code" and "that code isn't this
        /// account's" send the user to two different places, and normalizing
        /// is the only step that can tell them apart — past it, every failure
        /// looks the same by design.
        #[error("that doesn't look like a recovery code: {0}")]
        Malformed(#[from] RecoveryError),
        /// The derivation or the unwrap failed: a wrong recovery code, the
        /// wrong credential's wrap, a corrupt row, or a browser that could
        /// not do the operation at all. AES-KW authenticates, so the first
        /// three are indistinguishable here — which is what makes the code
        /// safe to carry no checksum (spec section 6.4).
        #[error(transparent)]
        Crypto(#[from] CryptoError),
    }

    /// Derives the key-encryption key for one route from that route's secret.
    ///
    /// Every derivation in this file goes through here — and through
    /// [`subtle::derive_kek`], which takes a [`WrapKind`] rather than a raw
    /// `info` byte string — so `info` is never chosen at a call site: it can
    /// only come from [`WrapKind::info`], the single table, pinned on the
    /// host by `wire`'s `each_kind_keeps_its_own_info_string` (invariant E6).
    async fn derive(kind: WrapKind, ikm: &[u8]) -> Result<Kek, CryptoError> {
        subtle::derive_kek(ikm, kind).await
    }

    /// Derives the key-encryption key that opens `opener`.
    ///
    /// The recovery arm normalizes first, so a code that is not a code at all
    /// is reported as such instead of being HKDF'd into a KEK that was never
    /// going to open anything.
    async fn kek_for(opener: &Opener<'_>) -> Result<Kek, UnlockError> {
        let kek = match *opener {
            Opener::Passkey { prf_output, .. } => derive(WrapKind::Passkey, prf_output).await?,
            Opener::Recovery { code, .. } => {
                derive(WrapKind::Recovery, &recovery::normalize(code)?).await?
            }
        };
        Ok(kek)
    }

    /// A fresh recovery code and the bytes whose KEK wraps the data key.
    ///
    /// Both come from the same twenty random bytes, and the KEK is derived
    /// from `bytes` rather than by re-normalizing the string. That the two
    /// agree — that the code the user types back derives this same KEK — is
    /// `format_code` and `normalize` being exact inverses, which `recovery`'s
    /// round-trip and known-answer tests pin.
    fn new_recovery_code() -> Result<(String, [u8; CODE_BYTES]), CryptoError> {
        // The discarded `Err` payload is the random bytes themselves; the
        // message says only that the length was wrong.
        let bytes: [u8; CODE_BYTES] = subtle::random_bytes(CODE_BYTES)?
            .try_into()
            .map_err(|_| CryptoError("getRandomValues returned the wrong length".to_string()))?;
        Ok((recovery::format_code(&bytes), bytes))
    }

    /// Everything the enable ceremony produced.
    ///
    /// A struct rather than the tuple the plan sketched, because
    /// `passkey_wrap` and `recovery_wrap` are both `Vec<u8>` and
    /// `encryption_enable` takes them one after the other: swapping them at
    /// the call site would compile, file each wrap under the other's route,
    /// and leave the account openable by neither secret.
    pub struct Enabled {
        /// Unlocked, and already remembered on this device.
        pub session_key: SessionKey,
        /// Shown once and never again (spec section 6.1 step 5).
        pub recovery_code: String,
        /// The data key wrapped under the enrolling credential's KEK.
        pub passkey_wrap: Vec<u8>,
        /// The data key wrapped under the recovery code's KEK.
        pub recovery_wrap: Vec<u8>,
    }

    /// Turns encryption on for an account (spec section 6.1).
    ///
    /// `prf_output` is the PRF result of an assertion against the credential
    /// being enrolled; `user` is the signed-in identity the keystore record
    /// is filed under. The caller sends the two wraps to `encryption_enable`,
    /// shows the recovery code, and then runs the migration.
    ///
    /// That server call happens *after* this function has written the
    /// keystore record, inverting spec section 6.1's step order. The
    /// inversion is harmless: a key stored for an account whose
    /// `encryption_enable` then failed is never consulted, because the next
    /// probe asks `encryption_status`, is told the account is not encrypted,
    /// and lands on `Disabled` — and a retry replaces the record.
    pub async fn enable(prf_output: &[u8], user: &str) -> Result<Enabled, CryptoError> {
        let (recovery_code, code_bytes) = new_recovery_code()?;

        let raw_key = subtle::generate_dek_extractable().await?;
        let passkey_kek = derive(WrapKind::Passkey, prf_output).await?;
        let recovery_kek = derive(WrapKind::Recovery, &code_bytes).await?;
        let passkey_wrap = subtle::wrap_dek(&raw_key, &passkey_kek).await?;
        let recovery_wrap = subtle::wrap_dek(&raw_key, &recovery_kek).await?;

        // The extractable handle's whole life runs from `generate` above to
        // the `drop` below: generated, wrapped once per route, read out, and
        // released before the sealed key even exists. It cannot escape this
        // function either — `Enabled` carries a `SessionKey`, and nothing can
        // turn one of those back into a `RawDataKey` (invariant E5, spec
        // section 4.3).
        let key = {
            let raw = subtle::export_raw(&raw_key).await?;
            drop(raw_key);
            subtle::import_dek_non_extractable(&raw).await?
        };

        Ok(Enabled {
            session_key: SessionKey::adopt(user, key).await,
            recovery_code,
            passkey_wrap,
            recovery_wrap,
        })
    }

    /// Opens a wrap into a sealed key and remembers it on this device.
    async fn unlock(opener: Opener<'_>, user: &str) -> Result<SessionKey, UnlockError> {
        let kek = kek_for(&opener).await?;
        let key = subtle::unwrap_dek_sealed(opener.wrap(), &kek).await?;
        Ok(SessionKey::adopt(user, key).await)
    }

    /// Unlocks with a passkey's PRF output (spec sections 6.2 and 6.3).
    ///
    /// `wrap` is the wrapped key from *that credential's* row — see
    /// [`super::choose_route`], which is what picks it.
    pub async fn unlock_with_prf(
        prf_output: &[u8],
        wrap: &[u8],
        user: &str,
    ) -> Result<SessionKey, UnlockError> {
        unlock(Opener::Passkey { prf_output, wrap }, user).await
    }

    /// Unlocks with a typed recovery code (spec section 6.4).
    ///
    /// Works on a browser with no PRF support at all, which is the point of
    /// the route.
    pub async fn unlock_with_recovery(
        code: &str,
        wrap: &[u8],
        user: &str,
    ) -> Result<SessionKey, UnlockError> {
        unlock(Opener::Recovery { code, wrap }, user).await
    }

    /// Re-wraps the account's data key under a new key-encryption key.
    ///
    /// **The only [`subtle::unwrap_dek_raw`] call site in the crate**, and so
    /// the only place a second extractable handle on the data key comes into
    /// existence. `wrapKey` refuses a sealed key, and the `SessionKey` every
    /// other holder has cannot become an extractable one — so adding a route
    /// means re-opening an existing route at that moment, which is exactly
    /// what spec section 6.5 describes. The handle cannot escape: this
    /// returns `Vec<u8>`.
    async fn rewrap(
        existing: &Opener<'_>,
        new_kind: WrapKind,
        new_ikm: &[u8],
    ) -> Result<Vec<u8>, UnlockError> {
        let existing_kek = kek_for(existing).await?;
        let raw_key = subtle::unwrap_dek_raw(existing.wrap(), &existing_kek).await?;
        let new_kek = derive(new_kind, new_ikm).await?;
        Ok(subtle::wrap_dek(&raw_key, &new_kek).await?)
    }

    /// Wraps the data key under a newly enrolled passkey's KEK (spec 6.5).
    ///
    /// Returns the blob for `encryption_add_passkey_wrap`. `existing` is any
    /// route this device can open right now — an `Opener` is required
    /// regardless of whether the session is locked or unlocked, because an
    /// unlocked session holds only a *sealed* [`SessionKey`], which cannot
    /// yield the raw bytes `wrapKey` needs. Adding a passkey therefore costs
    /// three authenticator interactions every time: creating the new
    /// credential, asserting against `existing`'s credential to re-derive the
    /// raw key, and asserting against the new credential for its PRF output.
    pub async fn add_passkey_route(
        existing: &Opener<'_>,
        new_prf_output: &[u8],
    ) -> Result<Vec<u8>, UnlockError> {
        rewrap(existing, WrapKind::Passkey, new_prf_output).await
    }

    /// Issues a fresh recovery code and wraps the data key under it (6.4).
    ///
    /// Returns the code to show once and the blob for
    /// `encryption_replace_recovery_wrap`. Offered after a recovery unlock,
    /// because the old code has just been typed and possibly left somewhere
    /// careless; the old code keeps working until the server has replaced the
    /// row, so declining costs the user nothing.
    pub async fn reissue_recovery(existing: &Opener<'_>) -> Result<(String, Vec<u8>), UnlockError> {
        let (code, bytes) = new_recovery_code()?;
        Ok((code, rewrap(existing, WrapKind::Recovery, &bytes).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tag` fills `wrapped_key` with a byte distinct from every other row's,
    /// so a test can tell *which* row's bytes `choose_route` returned rather
    /// than only which row's `kind`/`credential_id` it returned. Every row in
    /// this module's tests used to share the same all-zero `wrapped_key`,
    /// which meant an implementation that picked the right row and returned
    /// the wrong one's bytes still passed.
    fn wrap(kind: WrapKind, cred: Option<&[u8]>, tag: u8) -> WrapDto {
        WrapDto {
            kind: kind.as_str().to_string(),
            credential_id: cred.map(<[u8]>::to_vec),
            wrapped_key: vec![tag; wire::WRAPPED_KEY_LEN],
            kdf: wire::KDF_HKDF_SHA256.to_string(),
            wrap_alg: wire::WRAP_ALG_AESKW256.to_string(),
        }
    }

    /// The credential that just asserted is the one whose wrap must be used.
    /// Picking any other passkey's wrap would derive the wrong KEK and fail
    /// to unwrap — with an error indistinguishable from a corrupt row.
    ///
    /// Asserts on `wrapped_key`, not just `credential_id`: `wrapped_key` is
    /// the only field the ceremonies consume, so it is the one field a wrong
    /// selection would corrupt without this failing.
    #[test]
    fn the_asserting_credential_selects_its_own_wrap() {
        let rows = vec![
            wrap(WrapKind::Passkey, Some(b"cred-a"), 1),
            wrap(WrapKind::Passkey, Some(b"cred-b"), 2),
            wrap(WrapKind::Recovery, None, 3),
        ];
        let chosen = choose_route(&rows, Some(b"cred-b")).expect("route");
        assert_eq!(chosen.credential_id.as_deref(), Some(&b"cred-b"[..]));
        assert_eq!(chosen.wrapped_key, vec![2; wire::WRAPPED_KEY_LEN]);
    }

    /// A passkey enrolled before encryption was enabled, or one whose
    /// authenticator has no PRF, has no wrap. That is a clean "this passkey
    /// cannot unlock", not a fallback to someone else's wrap.
    #[test]
    fn a_credential_with_no_wrap_has_no_route() {
        let rows = vec![
            wrap(WrapKind::Passkey, Some(b"cred-a"), 1),
            wrap(WrapKind::Recovery, None, 2),
        ];
        assert!(choose_route(&rows, Some(b"unknown")).is_none());
    }

    #[test]
    fn no_credential_selects_the_recovery_route() {
        let rows = vec![
            wrap(WrapKind::Passkey, Some(b"cred-a"), 1),
            wrap(WrapKind::Recovery, None, 2),
        ];
        let chosen = choose_route(&rows, None).expect("route");
        assert_eq!(chosen.kind, WrapKind::Recovery);
        assert_eq!(chosen.wrapped_key, vec![2; wire::WRAPPED_KEY_LEN]);
    }

    #[test]
    fn an_account_with_no_recovery_wrap_has_no_recovery_route() {
        let rows = vec![wrap(WrapKind::Passkey, Some(b"cred-a"), 1)];
        assert!(choose_route(&rows, None).is_none());
    }

    /// A row this build cannot classify is not a route. The alternative —
    /// treating an unknown kind as one of the two known ones — would derive
    /// under the wrong `info` and fail as a corrupt row.
    ///
    /// Covers both wrong defaults, not just one: a recovery-shaped row with
    /// an unrecognized `kind` would slip past an implementation that defaults
    /// to `WrapKind::Recovery`, and a passkey-shaped row whose credential
    /// matches the query would slip past one that defaults to
    /// `WrapKind::Passkey`.
    #[test]
    fn a_row_of_an_unrecognized_kind_is_skipped() {
        let mut recovery_shaped = wrap(WrapKind::Recovery, None, 1);
        recovery_shaped.kind = "future".to_string();
        assert!(choose_route(&[recovery_shaped.clone()], None).is_none());
        assert!(choose_route(&[recovery_shaped], Some(b"cred-a")).is_none());

        let mut passkey_shaped = wrap(WrapKind::Passkey, Some(b"cred-x"), 2);
        passkey_shaped.kind = "future".to_string();
        assert!(choose_route(&[passkey_shaped], Some(b"cred-x")).is_none());
    }

    /// The credential id must match exactly. `starts_with` would let
    /// `"cred"` open either row below, deriving a KEK from whichever
    /// credential's PRF output the browser happened to hand over — not the
    /// one the wrap was actually made for.
    #[test]
    fn a_credential_id_prefix_is_not_a_match() {
        let rows = vec![
            wrap(WrapKind::Passkey, Some(b"cred-a"), 1),
            wrap(WrapKind::Passkey, Some(b"cred-b"), 2),
        ];
        assert!(choose_route(&rows, Some(b"cred")).is_none());
    }

    /// A row whose `kdf` this build does not recognise is skipped, the same
    /// way an unrecognised `kind` is: deriving with today's HKDF-SHA256
    /// anyway would be a guess about an algorithm the row never claimed to
    /// use (spec section 5.2).
    #[test]
    fn a_row_with_an_unrecognized_kdf_is_skipped() {
        let mut rows = vec![wrap(WrapKind::Recovery, None, 1)];
        rows[0].kdf = "future-kdf".to_string();
        assert!(choose_route(&rows, None).is_none());
    }

    /// The same, for `wrap_alg`.
    #[test]
    fn a_row_with_an_unrecognized_wrap_alg_is_skipped() {
        let mut rows = vec![wrap(WrapKind::Recovery, None, 1)];
        rows[0].wrap_alg = "future-wrap-alg".to_string();
        assert!(choose_route(&rows, None).is_none());
    }
}
