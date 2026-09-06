//! Client-side encryption of entry bodies.
//!
//! See `docs/superpowers/specs/2026-09-05-client-side-encryption-design.md`.
//!
//! This file is the orchestration layer over the four modules below: the
//! [`SessionKey`] components hold, the ceremonies of spec section 6 that
//! create, open and re-wrap it, and the one decision in the whole feature
//! that is both load-bearing and pure — [`choose_route`], which says *which*
//! stored wrap to open.

/// The ceremony steps that need the authenticator and the server at once,
/// shared by every component that runs one. `test` as well as `hydrate`:
/// `flow::credential_id_from_response` is pure and host-tested, the same
/// split `storage::local` makes for the same reason.
#[cfg(any(feature = "hydrate", test))]
pub mod flow;
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

use std::cell::Cell;

#[cfg(any(feature = "hydrate", test))]
use self::wire::WrapKind;
#[cfg(any(feature = "hydrate", test))]
use crate::dto::WrapDto;

#[cfg(feature = "hydrate")]
pub use self::ceremony::{
    Enabled, Opener, SessionKey, UnlockError, add_passkey_route, enable, enable_recovery_only,
    reissue_recovery, unlock_with_prf, unlock_with_recovery,
};

thread_local! {
    /// How many times this page load has been told to forget the device
    /// key. See [`Forgets`].
    static FORGETS: Cell<u64> = const { Cell::new(0) };
}

/// How many times this device had been told to forget its data key at some
/// earlier moment: captured when a ceremony starts, checked when it writes.
///
/// Every unlock is several awaits long — a WebAuthn prompt, a network round
/// trip, a WebCrypto unwrap — and both "Sign out" and "Lock now" are live
/// toggles for all of it. Without this, a ceremony that started before
/// either one still ends in a keystore write, and that write lands *after*
/// the delete, leaving the device holding exactly the key the user asked it
/// to forget. No identity check catches that: the key really does belong to
/// the account that was signed in when the ceremony began.
///
/// "When a ceremony starts" means the whole thing, from the caller's first
/// await — a wraps fetch, a WebAuthn assertion — not merely the first await
/// inside this module. [`enable`] and the private `unlock` both take a
/// `Forgets` as a parameter rather than calling [`now`](Self::now)
/// themselves for exactly this reason: by the time either function runs,
/// its caller may already have awaited the server and the authenticator,
/// and capturing here would miss anything asked to forget during that
/// window.
///
/// A thread-local counter rather than a signal because it has to be readable
/// from every path that writes the keystore, including
/// `account_menu::unlock_after_sign_in`, which runs with no reactive context
/// at all — the page has not reloaded yet, so there is no `AuthCtx` there to
/// compare against either. wasm is single-threaded, so there is nothing to
/// share the counter with; the server never touches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Forgets(u64);

impl Forgets {
    /// The count as of now, to be captured at the *true* start of a ceremony
    /// that will end in a keystore write — the caller's first await, not
    /// necessarily this module's — and threaded in from there. See this
    /// type's doc comment.
    pub fn now() -> Self {
        Self(FORGETS.with(Cell::get))
    }

    /// Records that this device has been asked to forget its key, which
    /// invalidates every ceremony already under way.
    pub fn record() {
        FORGETS.with(|count| count.set(count.get() + 1));
    }

    /// Whether nothing has asked this device to forget its key since this
    /// count was taken.
    pub fn still_current(self) -> bool {
        self == Self::now()
    }
}

/// Forgets this device's data key, and invalidates every ceremony that would
/// otherwise go on to write another.
///
/// One function does both because doing only the delete is the bug: an
/// unlock started before the user asked to forget is still several awaits
/// from its own keystore write, and that write would land afterwards. Both
/// callers — sign-out and "Lock now" — go through here.
///
/// The count is bumped *before* the delete, because the delete is itself a
/// round trip through IndexedDB and a ceremony finishing inside it would
/// otherwise slip past.
#[cfg(feature = "hydrate")]
pub async fn forget_device_key() -> Result<(), subtle::CryptoError> {
    Forgets::record();
    keystore::clear().await
}

/// The unlocked data key, on a target that has no WebCrypto.
///
/// Uninhabited on purpose. The storage seam takes `Option<&SessionKey>` on
/// every target so that its signatures — and the `ssr` tests that call them —
/// do not fork on cfg. Giving the non-browser build a type with no values
/// turns "there is no session key outside the browser" into something the
/// compiler enforces rather than something each `ssr` branch has to remember:
/// `Some` is not constructible here, so a server render cannot come to hold a
/// key even by mistake (spec sections 7.4, 9.1).
#[cfg(not(feature = "hydrate"))]
#[derive(Clone)]
pub enum SessionKey {}

/// Which secret a ceremony will open the account's data key with.
///
/// The user's half of an [`Opener`]: the wrap each one pairs with comes out
/// of [`choose_route`] once the account's rows have been fetched, so the two
/// can only be joined inside the ceremony itself.
///
/// It is a choice the caller has to make because there is not always one to
/// fall back on. A user who lost every passkey and got back in with their
/// recovery code has no passkey that can open anything, so a ceremony that
/// only ever asks a passkey would leave that account unable to key a new one
/// — recovery-code-only, on every device, permanently. See
/// [`flow::add_passkey_key`].
///
/// Ungated, unlike `Opener` and the ceremonies that consume it: the panel's
/// view has to name this type on every target, and the choice is plain data.
/// Only acting on it needs a browser.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeySource {
    /// Assert against an enrolled passkey that already holds a wrap.
    Passkey,
    /// The recovery code, as the user typed it.
    Recovery(String),
}

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
    use super::Forgets;
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
        /// How many times this device had been told to forget its key when
        /// the ceremony that produced this one began. Read only by
        /// [`remember`](Self::remember), which is the sole keystore write in
        /// the crate.
        forgets: Forgets,
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
            let forgets = Forgets::now();
            Ok(keystore::get(user).await?.map(|key| Self {
                key,
                user: user.to_string(),
                forgets,
            }))
        }

        /// Wraps a freshly opened data key in a session handle, writing
        /// nothing.
        ///
        /// Persisting it is [`remember`](Self::remember), and the two are
        /// deliberately not one step. Folding the write in here put it
        /// *ahead* of the caller's own identity check, so an unlock that
        /// resolved after a sign-out left the previous account's record on
        /// the device — see
        /// [`EncryptionCtx::unlock`](crate::encryption_ctx::EncryptionCtx::unlock).
        fn held(user: &str, key: DataKey, forgets: Forgets) -> Self {
            Self {
                key,
                user: user.to_string(),
                forgets,
            }
        }

        /// Remembers this key on this device, so the next load of it finds a
        /// key and never prompts.
        ///
        /// Refuses when the device has been asked to forget its key since
        /// the ceremony that produced this one started — its true start, at
        /// the caller's first await, which is what the `forgets` each
        /// producer is handed must have been captured against (see
        /// [`Forgets`]); a value captured any later would still compare
        /// "current" against a forget that landed in the gap. That guard
        /// lives here, at the write, rather than only at the one caller that
        /// can compare accounts: `account_menu::unlock_after_sign_in` writes
        /// the keystore too, and pre-reload it has no live `AuthCtx` to
        /// compare against, so an identity check is not something that path
        /// can make. What every path can honour is that a sign-out or a
        /// "Lock now" issued after this started outranks it (spec section
        /// 6.7).
        ///
        /// A failure is the caller's to log and otherwise ignore: the key
        /// works for this page load either way, and the only cost of not
        /// persisting it is one more unlock prompt after a reload. Refusing
        /// the user their entries because a cache write failed would be the
        /// worse trade (spec section 12's private-window row).
        pub async fn remember(&self) -> Result<(), CryptoError> {
            if !self.forgets.still_current() {
                return Err(CryptoError(
                    "this device was asked to forget its key while the unlock was still running"
                        .to_string(),
                ));
            }
            keystore::put(&self.user, &self.key).await
        }

        /// The account this key belongs to.
        ///
        /// Read by `EncryptionCtx::unlock` (spec section 7.4), which refuses
        /// a key that does not belong to the account signed in *now*, and
        /// only then lets [`remember`](Self::remember) run. An unlock
        /// ceremony is async and the account menu stays mounted throughout
        /// it, so a sign-out can land in the middle; the keystore's own user
        /// check would not catch that, because it runs on the read that
        /// already happened. That one call is why this accessor exists — the
        /// storage seam deliberately never asks (see `storage`'s header).
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
    /// `passkey_wrap` and `recovery_wrap` were both `Vec<u8>` and
    /// `encryption_enable` took them one after the other: swapping them at
    /// the call site would compile, file each wrap under the other's route,
    /// and leave the account openable by neither secret. The `Option` the
    /// second route added now separates them by type as well, but the reason
    /// the struct exists is the one above.
    pub struct Enabled {
        /// Unlocked, but **not** yet remembered on this device: nothing here
        /// touches the keystore, and the caller reaches it only by handing
        /// this to `EncryptionCtx::unlock` once the server has confirmed.
        pub session_key: SessionKey,
        /// Shown once and never again (spec section 6.1 step 5).
        pub recovery_code: String,
        /// The data key wrapped under the enrolling credential's KEK, or
        /// `None` on the recovery-code-only route — see
        /// [`enable_recovery_only`].
        pub passkey_wrap: Option<Vec<u8>>,
        /// The data key wrapped under the recovery code's KEK. Never
        /// optional: an account whose recovery code opens nothing is one no
        /// lost passkey can be recovered from.
        pub recovery_wrap: Vec<u8>,
    }

    /// Generates the account's data key and wraps it under every route it is
    /// going to have (spec section 6.1 steps 2 and 3).
    ///
    /// `prf_output` is `Some` on the ordinary route and `None` on the
    /// recovery-code-only one; everything else about the two is identical,
    /// which is why they share this rather than each minting a code and a
    /// key of their own. The recovery wrap is produced unconditionally.
    async fn enable_with(
        prf_output: Option<&[u8]>,
        user: &str,
        forgets: Forgets,
    ) -> Result<Enabled, CryptoError> {
        let (recovery_code, code_bytes) = new_recovery_code()?;

        let raw_key = subtle::generate_dek_extractable().await?;
        let passkey_wrap = match prf_output {
            Some(prf_output) => {
                let passkey_kek = derive(WrapKind::Passkey, prf_output).await?;
                Some(subtle::wrap_dek(&raw_key, &passkey_kek).await?)
            }
            None => None,
        };
        let recovery_kek = derive(WrapKind::Recovery, &code_bytes).await?;
        let recovery_wrap = subtle::wrap_dek(&raw_key, &recovery_kek).await?;

        // The extractable handle's whole life runs from `generate` above to
        // the `drop` below: generated, wrapped once per route, read out, and
        // released before the sealed key even exists. It cannot escape this
        // function either — `Enabled` carries a `SessionKey`, and nothing can
        // turn one of those back into a `RawDataKey` (invariant E5, spec
        // section 4.3). Skipping the passkey wrap shortens that life; it does
        // not change where it ends.
        let key = {
            let raw = subtle::export_raw(&raw_key).await?;
            drop(raw_key);
            subtle::import_dek_non_extractable(&raw).await?
        };

        Ok(Enabled {
            session_key: SessionKey::held(user, key, forgets),
            recovery_code,
            passkey_wrap,
            recovery_wrap,
        })
    }

    /// Turns encryption on for an account (spec section 6.1).
    ///
    /// `prf_output` is the PRF result of an assertion against the credential
    /// being enrolled; `user` is the signed-in identity the key belongs to.
    /// The caller shows the recovery code and waits for the user to confirm
    /// it, *then* sends the two wraps to `encryption_enable`, and then hands
    /// the key to `EncryptionCtx::unlock`, which is where step 6's keystore
    /// write happens.
    ///
    /// So as shipped, spec section 6.1's steps run 1 → 2 → 3 → 5 → 4 → 6:
    /// the caller holds step 5's code screen ahead of step 4's server call,
    /// which is the one departure §6.1 is amended for. Ordering the code
    /// screen first is what makes a lost response survivable — whichever way
    /// the call went, the code in the user's hands is the account's.
    ///
    /// Nothing here reaches the keystore, deliberately. This function once
    /// wrote the record on the way past, before the account existed
    /// server-side and before anyone had asked whose account it was, which
    /// is the ordering `SessionKey::remember` exists to undo.
    ///
    /// `forgets` is a parameter rather than [`Forgets::now`] called here,
    /// because this is not the ceremony's first step from the user's side —
    /// the caller has already run the PRF assertion this needs `prf_output`
    /// from. Capturing here would miss a sign-out or a "Lock now" issued
    /// during that assertion; see [`Forgets`].
    pub async fn enable(
        prf_output: &[u8],
        user: &str,
        forgets: Forgets,
    ) -> Result<Enabled, CryptoError> {
        enable_with(Some(prf_output), user, forgets).await
    }

    /// Turns encryption on with the recovery code as the account's *only*
    /// route to its data key (spec section 6.1's second route).
    ///
    /// For an account that cannot take [`enable`] at all: the PRF extension
    /// is a browser-and-authenticator capability, and one that is missing is
    /// missing permanently — an authenticator that does not implement it
    /// will not start, so "enrol a better passkey first" is advice with
    /// nowhere to go. The alternative to this route is not a safer account,
    /// it is a plaintext one.
    ///
    /// The cost is real and belongs in the caller's copy, not softened here:
    /// there is no second wrap and no passkey to fall back on, so losing the
    /// code loses the entries outright. It is not a dead end, though — a
    /// PRF-capable passkey enrolled later is keyed from the recovery code
    /// through [`add_passkey_route`], the same path a user who recovered
    /// from a total passkey loss takes (spec section 6.5).
    ///
    /// `forgets` is a parameter for consistency with [`enable`] rather than
    /// out of need: this route runs no assertion, so the caller's first await
    /// really is this call. Reading [`Forgets::now`] here would be correct
    /// today and silently wrong the day a caller awaits something first.
    pub async fn enable_recovery_only(
        user: &str,
        forgets: Forgets,
    ) -> Result<Enabled, CryptoError> {
        enable_with(None, user, forgets).await
    }

    /// Opens a wrap into a sealed key.
    ///
    /// Remembering it on this device is the caller's separate step, and
    /// belongs behind whatever identity check that caller can make — see
    /// [`SessionKey::remember`].
    ///
    /// `forgets` is a parameter for the reason `enable` gives: every caller
    /// of this reaches it only after a wraps fetch and, on the passkey
    /// route, a WebAuthn assertion — neither of which is an await this
    /// function itself makes — so [`Forgets::now`] belongs at the caller's
    /// true first step, not here.
    async fn unlock(
        opener: Opener<'_>,
        user: &str,
        forgets: Forgets,
    ) -> Result<SessionKey, UnlockError> {
        let kek = kek_for(&opener).await?;
        let key = subtle::unwrap_dek_sealed(opener.wrap(), &kek).await?;
        Ok(SessionKey::held(user, key, forgets))
    }

    /// Unlocks with a passkey's PRF output (spec sections 6.2 and 6.3).
    ///
    /// `wrap` is the wrapped key from *that credential's* row — see
    /// [`super::choose_route`], which is what picks it. `forgets` must be
    /// [`Forgets::now`] read by the caller before *its own* first await —
    /// see this module's header on [`Forgets`] — not a value captured here.
    pub async fn unlock_with_prf(
        prf_output: &[u8],
        wrap: &[u8],
        user: &str,
        forgets: Forgets,
    ) -> Result<SessionKey, UnlockError> {
        unlock(Opener::Passkey { prf_output, wrap }, user, forgets).await
    }

    /// Unlocks with a typed recovery code (spec section 6.4).
    ///
    /// Works on a browser with no PRF support at all, which is the point of
    /// the route. `forgets`: see [`unlock_with_prf`].
    pub async fn unlock_with_recovery(
        code: &str,
        wrap: &[u8],
        user: &str,
        forgets: Forgets,
    ) -> Result<SessionKey, UnlockError> {
        unlock(Opener::Recovery { code, wrap }, user, forgets).await
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

    /// The guard on the keystore write, at the only level a host can reach:
    /// the IndexedDB call itself is browser-only, but the decision in front
    /// of it is ordinary state, and it is the part a later edit could
    /// quietly get wrong.
    ///
    /// The failure it stands against is an unlock that started before the
    /// user pressed "Sign out" and finished after it — a whole WebAuthn
    /// prompt and network round trip later — writing the key back onto a
    /// device that had just been told to forget it.
    ///
    /// What it does *not* guard, said plainly: that each ceremony captures
    /// its `Forgets` at its own true first step rather than somewhere later
    /// inside `crypto`. The capture point is a property of five call sites,
    /// and this drives the type, not them. Reading them is the guard.
    #[test]
    fn a_forget_outranks_a_ceremony_that_started_before_it() {
        let started = Forgets::now();
        assert!(started.still_current(), "nothing has been forgotten yet");

        Forgets::record();
        assert!(
            !started.still_current(),
            "a ceremony that began before the forget must not write afterwards"
        );

        // The other direction, and the reason this is a counter rather than
        // a latch: signing out and straight back in on the same page load
        // must still leave the new account's key remembered.
        assert!(Forgets::now().still_current());
    }

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
