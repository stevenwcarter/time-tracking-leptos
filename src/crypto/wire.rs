//! The on-the-wire shapes and the constants that derive keys.
//!
//! Pure by design: no `web_sys`, no `wasm_bindgen`. WebCrypto exists only in
//! a browser and this project has no wasm test runner, so everything that can
//! be decided without a browser lives here where `cargo test` can reach it
//! (spec section 10).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

/// Envelope version written by this build.
pub const V2: u8 = 2;
/// The only body algorithm this build understands.
pub const ALG_V2: &str = "a256gcm";
/// AES-GCM nonce length, in bytes. Fresh per write, never reused.
pub const NONCE_LEN: usize = 12;
/// AES-KW of a 256-bit key: 32 bytes plus AES-KW's 8-byte integrity block.
pub const WRAPPED_KEY_LEN: usize = 40;

/// HKDF `info` for the passkey-PRF route.
///
/// Not `pub`: [`WrapKind::info`] is the only thing that hands this out, so a
/// caller reaches an `info` string only by going through the route it
/// belongs to, never by passing an arbitrary one in.
const INFO_PASSKEY: &[u8] = b"tt/entry-kek/passkey/v1";
/// HKDF `info` for the recovery-code route. See [`INFO_PASSKEY`].
const INFO_RECOVERY: &[u8] = b"tt/entry-kek/recovery/v1";

/// The only KDF this build derives key-encryption keys with, and the value
/// every stored row's `kdf` column must carry to be trusted.
///
/// Recorded per row (`entry_key_wrap.kdf`, spec section 5.2) for the same
/// reason the envelope carries `alg`: a future change is a new value rather
/// than a guess about old rows. Lives here rather than in `entry_key::store`
/// so [`super::choose_route`] can check it too — both sides need the same
/// string, and `entry_key` is `ssr`-only.
pub const KDF_HKDF_SHA256: &str = "hkdf-sha256";
/// The only key-wrap algorithm this build uses. See [`KDF_HKDF_SHA256`].
pub const WRAP_ALG_AESKW256: &str = "aeskw256";

/// HKDF salt: SHA-256 of `time-tracking-leptos/entry-key/v1`.
///
/// A constant rather than a per-account value, and that is deliberate. The
/// PRF secret is already per-credential, so the salt only separates this
/// application and this purpose from others. A per-account salt would have to
/// be fetched before the assertion, and at sign-in the account is not yet
/// known — the discoverable flow identifies the user *from* the assertion.
/// That would cost the one-gesture unlock to buy nothing (spec section 4.2).
pub const APP_SALT: &[u8; 32] = &[
    0x2c, 0xa0, 0x0a, 0xc6, 0xac, 0xc6, 0x6a, 0x1b, 0xf5, 0x8d, 0x30, 0x57, 0x8c, 0xa3, 0x16, 0xa1,
    0x7b, 0x28, 0x57, 0x11, 0x63, 0xc3, 0xd9, 0x2e, 0x8c, 0x00, 0x83, 0xcd, 0x3a, 0xb1, 0x34, 0xa9,
];

/// How a wrap is opened: which secret derives the key-encryption key that
/// unwraps it.
///
/// Lives here, beside the two `info` strings it selects between, rather than
/// in `entry_key`. Both halves of the app need it — the server writes and
/// reads it as the `entry_key_wrap.kind` column, the browser parses it back
/// out of [`crate::dto::WrapDto`] to choose a route — and `entry_key` is
/// `ssr`-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapKind {
    /// Unwrapped by a key derived from one credential's PRF output.
    Passkey,
    /// Unwrapped by a key derived from the account's recovery code.
    Recovery,
}

impl WrapKind {
    /// The stored form, in the column and on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            WrapKind::Passkey => "passkey",
            WrapKind::Recovery => "recovery",
        }
    }

    /// Reads the stored form back. `None` for anything this build does not
    /// know, which each caller handles rather than guesses at.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "passkey" => Some(WrapKind::Passkey),
            "recovery" => Some(WrapKind::Recovery),
            _ => None,
        }
    }

    /// The HKDF `info` this route's key-encryption key is derived with.
    ///
    /// The only mapping between a route and its `info`, and the reason it is
    /// a mapping at all: `deriveKey` takes `info` as a plain byte string and
    /// cannot tell the two apart, so a wrap made under the other route's
    /// `info` is a well-formed wrap that no device will ever open, failing
    /// exactly the way a corrupt row does (invariant E6).
    pub fn info(self) -> &'static [u8] {
        match self {
            WrapKind::Passkey => INFO_PASSKEY,
            WrapKind::Recovery => INFO_RECOVERY,
        }
    }
}

/// A nonce and the AES-GCM output that goes with it. WebCrypto returns
/// `ciphertext ‖ tag` as a single buffer, so `ciphertext` includes the tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A stored v2 envelope could not be interpreted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("envelope is not valid JSON: {0}")]
    Malformed(String),
    #[error("field `{0}` is not valid base64")]
    Base64(String),
    #[error("nonce is {0} bytes, expected 12")]
    NonceLength(usize),
    #[error("algorithm `{0}` is not supported by this build")]
    UnsupportedAlg(String),
    #[error("envelope version {0} is not supported by this build")]
    UnsupportedVersion(u8),
}

/// The written shape. A separate type from the read shape below: encoding
/// always writes the current version tag, while decoding tolerates whatever
/// fields a future version might add around `alg`/`n`/`ct`.
#[derive(Serialize)]
struct WireEnvelopeOut<'a> {
    v: u8,
    alg: &'a str,
    n: String,
    ct: String,
}

/// The read shape. `v` is checked here even though today's only caller has
/// already dispatched on it before reaching this function — `decode_v2` must
/// stay correct if a future caller ever invokes it directly with an
/// unvalidated envelope.
#[derive(Deserialize)]
struct WireEnvelopeIn {
    v: u8,
    alg: String,
    n: String,
    ct: String,
}

/// Wraps a sealed body for storage.
pub fn encode_v2(sealed: &Sealed) -> String {
    let env = WireEnvelopeOut {
        v: V2,
        alg: ALG_V2,
        n: B64.encode(&sealed.nonce),
        ct: B64.encode(&sealed.ciphertext),
    };
    // Every field is a plain string/u8; serialization cannot fail.
    serde_json::to_string(&env).expect("envelope must serialize")
}

/// Reads a sealed body back out of a stored v2 envelope.
///
/// Validates in this order: JSON shape, version, algorithm, base64, nonce
/// length — so a caller sees the most fundamental problem first. The version
/// check comes before `alg` because it is the coarsest discriminator: an
/// envelope from a future version may not even use `alg` the same way.
pub fn decode_v2(raw: &str) -> Result<Sealed, WireError> {
    let env: WireEnvelopeIn =
        serde_json::from_str(raw).map_err(|e| WireError::Malformed(e.to_string()))?;
    if env.v != V2 {
        return Err(WireError::UnsupportedVersion(env.v));
    }
    if env.alg != ALG_V2 {
        return Err(WireError::UnsupportedAlg(env.alg));
    }
    let nonce = B64
        .decode(&env.n)
        .map_err(|_| WireError::Base64("n".to_string()))?;
    let ciphertext = B64
        .decode(&env.ct)
        .map_err(|_| WireError::Base64("ct".to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(WireError::NonceLength(nonce.len()));
    }
    Ok(Sealed { nonce, ciphertext })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_of(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Spec E6. These bytes are load-bearing: changing any of them makes
    /// every existing wrapped key unopenable, with no error that says so.
    /// This test exists to make that change impossible to do by accident.
    #[test]
    fn derivation_inputs_are_pinned() {
        assert_eq!(INFO_PASSKEY, b"tt/entry-kek/passkey/v1");
        assert_eq!(INFO_RECOVERY, b"tt/entry-kek/recovery/v1");
        assert_eq!(ALG_V2, "a256gcm");
        assert_eq!(NONCE_LEN, 12);
        assert_eq!(WRAPPED_KEY_LEN, 40);

        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"time-tracking-leptos/entry-key/v1");
        assert_eq!(APP_SALT, expected.as_slice());
    }

    /// The other half of E6. [`derivation_inputs_are_pinned`] fixes the two
    /// `info` strings; this fixes which route uses which. Nothing downstream
    /// could catch them swapped — `deriveKey` would succeed, the wrap would
    /// be well-formed, and it would simply never open.
    #[test]
    fn each_kind_keeps_its_own_info_string() {
        assert_eq!(WrapKind::Passkey.info(), INFO_PASSKEY);
        assert_eq!(WrapKind::Recovery.info(), INFO_RECOVERY);
    }

    #[test]
    fn as_str_and_parse_round_trip() {
        for kind in [WrapKind::Passkey, WrapKind::Recovery] {
            assert_eq!(WrapKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(WrapKind::parse("bogus"), None);
    }

    #[test]
    fn v2_round_trips() {
        let sealed = Sealed {
            nonce: vec![3; NONCE_LEN],
            ciphertext: b"abc".to_vec(),
        };
        let decoded = decode_v2(&encode_v2(&sealed)).expect("round trip");
        assert_eq!(decoded, sealed);
    }

    #[test]
    fn v2_shape_is_pinned() {
        let raw = encode_v2(&Sealed {
            nonce: vec![0; NONCE_LEN],
            ciphertext: vec![1, 2, 3],
        });
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        assert_eq!(v["v"], 2);
        assert_eq!(v["alg"], "a256gcm");
        assert!(v["n"].is_string());
        assert!(v["ct"].is_string());
        assert!(
            v.get("body").is_none(),
            "v2 must not carry a plaintext body field"
        );
    }

    #[test]
    fn a_wrong_nonce_length_is_rejected() {
        let raw = r#"{"v":2,"alg":"a256gcm","n":"AAAA","ct":"AAAA"}"#;
        assert!(matches!(decode_v2(raw), Err(WireError::NonceLength(3))));
    }

    /// An otherwise-valid v2 body under the wrong version tag must not be
    /// accepted — `decode_v2` is not the only place that has ever dispatched
    /// on `v`, and a future direct caller must not find this a silent no-op.
    #[test]
    fn a_wrong_version_is_rejected() {
        let raw = format!(
            r#"{{"v":99,"alg":"a256gcm","n":"{}","ct":"AAAA"}}"#,
            base64_of(&[0u8; NONCE_LEN])
        );
        assert!(matches!(
            decode_v2(&raw),
            Err(WireError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn a_foreign_algorithm_is_rejected() {
        let raw = format!(
            r#"{{"v":2,"alg":"rot13","n":"{}","ct":"AAAA"}}"#,
            base64_of(&[0u8; NONCE_LEN])
        );
        assert!(matches!(decode_v2(&raw), Err(WireError::UnsupportedAlg(_))));
    }

    #[test]
    fn non_base64_is_rejected() {
        let raw = r#"{"v":2,"alg":"a256gcm","n":"!!!!","ct":"AAAA"}"#;
        assert!(matches!(decode_v2(raw), Err(WireError::Base64(_))));
    }

    /// The browser's WebCrypto is not available here, so a second,
    /// independent AES-256-GCM implementation stands in for it. Nonce
    /// placement and tag handling are `aes-gcm`'s responsibility, not this
    /// module's — `wire.rs` only moves opaque bytes. What these tests pin is
    /// that *our* part, the envelope's base64 encoding and field layout,
    /// round-trips through a second implementation rather than only ever
    /// being read back by the code that wrote it (spec section 10).
    mod cross_implementation {
        use super::*;
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        fn cipher() -> Aes256Gcm {
            Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&[42u8; 32]))
        }

        /// WebCrypto's `encrypt` returns `ciphertext ‖ tag` as one buffer, and
        /// `aes-gcm`'s `encrypt` produces the same layout. An envelope built
        /// from one must decrypt with the other.
        #[test]
        fn an_envelope_we_encode_decrypts_with_a_second_implementation() {
            let nonce = [7u8; NONCE_LEN];
            let ct = cipher()
                .encrypt(Nonce::from_slice(&nonce), b"11:45-12:15 code1".as_ref())
                .expect("encrypt");

            let raw = encode_v2(&Sealed {
                nonce: nonce.to_vec(),
                ciphertext: ct,
            });
            let decoded = decode_v2(&raw).expect("decode");

            let plain = cipher()
                .decrypt(
                    Nonce::from_slice(&decoded.nonce),
                    decoded.ciphertext.as_ref(),
                )
                .expect("decrypt");
            assert_eq!(plain, b"11:45-12:15 code1");
        }

        /// A tampered ciphertext must fail authentication, not decrypt to
        /// something. This is what makes a corrupted or substituted row a loud
        /// error rather than silent garbage on screen.
        #[test]
        fn tampering_is_detected() {
            let nonce = [7u8; NONCE_LEN];
            let mut ct = cipher()
                .encrypt(Nonce::from_slice(&nonce), b"secret".as_ref())
                .expect("encrypt");
            ct[0] ^= 0x01;

            let decoded = decode_v2(&encode_v2(&Sealed {
                nonce: nonce.to_vec(),
                ciphertext: ct,
            }))
            .expect("decode");
            assert!(
                cipher()
                    .decrypt(
                        Nonce::from_slice(&decoded.nonce),
                        decoded.ciphertext.as_ref()
                    )
                    .is_err()
            );
        }

        /// The stored `wrapped_key` column (`entry_key_wrap.wrapped_key`) is
        /// sized to exactly [`WRAPPED_KEY_LEN`] bytes, not an upper bound, so
        /// AES-KW must produce that many bytes for a 256-bit key every time,
        /// and must give the original key back unchanged.
        #[test]
        fn wrapping_a_256_bit_key_is_exactly_wrapped_key_len_bytes_and_round_trips() {
            use aes_kw::KekAes256;

            let kek = KekAes256::from([9u8; 32]);
            let dek = [1u8; 32];

            let mut wrapped = [0u8; WRAPPED_KEY_LEN];
            kek.wrap(&dek, &mut wrapped).expect("wrap");

            let mut unwrapped = [0u8; 32];
            kek.unwrap(&wrapped, &mut unwrapped).expect("unwrap");
            assert_eq!(unwrapped, dek);
        }

        /// HKDF with our exact salt and info strings, against the RustCrypto
        /// implementation. If `APP_SALT` or an info string drifted, the derived
        /// KEK would change and every stored wrap would stop opening — this
        /// pins the derivation, not just the constants.
        #[test]
        fn passkey_and_recovery_derivations_differ_and_are_stable() {
            use hkdf::Hkdf;
            use sha2::Sha256;

            let ikm = [1u8; 32];
            let derive = |info: &[u8]| {
                let mut out = [0u8; 32];
                Hkdf::<Sha256>::new(Some(APP_SALT), &ikm)
                    .expand(info, &mut out)
                    .expect("expand");
                out
            };

            let passkey = derive(INFO_PASSKEY);
            let recovery = derive(INFO_RECOVERY);
            assert_ne!(passkey, recovery, "the two routes must not share a KEK");

            // Pinned so a change to APP_SALT or the info strings fails loudly
            // here rather than silently in a browser.
            assert_eq!(
                hex_of(&passkey),
                "02969bab8b9bfa229afd3bfdef468328a6d8b518fbd984cc8e9bd20f1c4c16f5"
            );
        }
    }
}
