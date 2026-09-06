//! In-memory token buckets guarding the magic-link and passkey entry points.
//!
//! The magic-link path applies two independent limiters, both of them. By
//! IP, so one host cannot spray many addresses; by email, so an attacker
//! rotating IPs cannot mail-bomb one victim. Either limit alone leaves the
//! other attack open.
//!
//! `passkey_login_start` shares the IP bucket only with its *anonymous*
//! callers. A caller holding a valid session draws on a bucket of its own —
//! see [`PasskeyQuota`], and [`CEREMONY_CAPACITY`] for what phase 2 did to
//! the arithmetic.
//!
//! In-memory is sufficient: this is a single process, and a restart clearing
//! the buckets is not a useful window against a 15-minute token.

use std::collections::HashMap;
use std::sync::Mutex;

/// Magic-link requests, and passkey sign-ins by a caller who has not proved
/// who they are: 5 immediately, then one back every 30s.
///
/// `pub` so the tests that pin the limit can name it rather than restating
/// the number, and drift into asserting a quota that is no longer the one
/// the app enforces.
pub const MAGIC_CAPACITY: u32 = 5;
const MAGIC_REFILL_PER_SEC: f64 = 1.0 / 30.0;

/// Passkey ceremonies run by a caller who is already signed in: 30
/// immediately, then one back every 5s.
///
/// A second bucket rather than a bigger shared one, because the quota above
/// is sized for what it defends — account enumeration and mail-bombing
/// (invariant I6), neither of which a caller holding a valid session is
/// attempting, since they had to authenticate to get one.
///
/// Phase 2 is what made the sharing untenable. Every encryption ceremony
/// runs through `flow::assert_with_prf`, which reuses
/// `passkey_login_start`, so enabling encryption, unlocking, and re-issuing
/// a recovery code each cost a token — and **adding a passkey to an
/// encrypted account costs two**, since it asserts against an existing
/// credential and then against the new one. Sign in, enable, add a passkey
/// and four of the five sign-in tokens are gone; the fifth buys one more
/// ceremony, and a cancelled or mis-chosen assertion spends one too. The
/// failure lands mid-ceremony, after the credential already exists. Behind
/// office NAT a whole team shares the bucket.
const CEREMONY_CAPACITY: u32 = 30;
const CEREMONY_REFILL_PER_SEC: f64 = 1.0 / 5.0;

struct Bucket {
    tokens: f64,
    last_seen: f64,
}

/// A keyed token-bucket limiter.
pub struct Limiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

impl Limiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_per_sec,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// How long an exhausted bucket takes to hand back one token, in whole
    /// seconds, rounded up.
    ///
    /// Derived rather than written out beside the refusal, so the sentence
    /// the user reads cannot come to quote a wait this limiter stopped
    /// imposing. See [`PasskeyQuota::too_many`].
    pub fn retry_after_secs(&self) -> u32 {
        (1.0 / self.refill_per_sec).ceil().max(1.0) as u32
    }

    /// Consumes one token for `key` at time `now` (unix seconds, fractional).
    /// Returns `false` when the bucket is empty.
    ///
    /// `now` is a parameter rather than read from the clock so the refill
    /// behaviour is testable without sleeping.
    pub fn check_at(&self, key: &str, now: f64) -> bool {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let bucket = buckets.entry(key.to_owned()).or_insert(Bucket {
            tokens: self.capacity,
            last_seen: now,
        });

        let elapsed = (now - bucket.last_seen).max(0.0);
        // Capped at capacity: idling must not bank tokens without limit.
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(feature = "ssr")]
fn now_secs_f64() -> f64 {
    chrono::Utc::now().timestamp_millis() as f64 / 1000.0
}

#[cfg(feature = "ssr")]
fn magic_ip() -> &'static Limiter {
    use std::sync::OnceLock;
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(MAGIC_CAPACITY, MAGIC_REFILL_PER_SEC))
}

#[cfg(feature = "ssr")]
fn magic_email() -> &'static Limiter {
    use std::sync::OnceLock;
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(MAGIC_CAPACITY, MAGIC_REFILL_PER_SEC))
}

#[cfg(feature = "ssr")]
fn ceremony_ip() -> &'static Limiter {
    use std::sync::OnceLock;
    static L: OnceLock<Limiter> = OnceLock::new();
    L.get_or_init(|| Limiter::new(CEREMONY_CAPACITY, CEREMONY_REFILL_PER_SEC))
}

/// Which quota a passkey ceremony draws on.
///
/// `passkey_login_start` has two kinds of caller and phase 2 is what made
/// the difference matter: an anonymous sign-in attempt, and a signed-in
/// client running an encryption ceremony through `flow::assert_with_prf`.
/// See [`CEREMONY_CAPACITY`] for why one bucket could not serve both.
#[cfg(feature = "ssr")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyQuota {
    /// A caller who has not proved who they are. Shares the magic-link
    /// bucket, which exists to stop exactly this caller enumerating
    /// accounts.
    SignIn,
    /// A caller holding a valid session.
    Ceremony,
}

#[cfg(feature = "ssr")]
impl PasskeyQuota {
    fn limiter(self) -> &'static Limiter {
        match self {
            PasskeyQuota::SignIn => magic_ip(),
            PasskeyQuota::Ceremony => ceremony_ip(),
        }
    }

    /// `true` when this client IP is within quota for this kind of call.
    pub fn check_ip(self, ip: &str) -> bool {
        self.limiter().check_at(ip, now_secs_f64())
    }

    /// The refusal, quoting the wait this quota actually imposes.
    ///
    /// Built from the limiter rather than written out, because the two
    /// buckets refill at very different rates and the message used to say
    /// "wait a minute" for both — a full minute short of the truth on the
    /// sign-in bucket, and six times too long on this one.
    ///
    /// Still starts with "Too many": `webauthn_browser::friendly_error`
    /// passes a server message through on that prefix, and anything else
    /// collapses to the generic "couldn't complete that passkey step".
    pub fn too_many(self) -> String {
        format!(
            "Too many attempts. Please wait {} seconds and try again.",
            self.limiter().retry_after_secs()
        )
    }
}

/// `true` when this client IP is within quota.
#[cfg(feature = "ssr")]
pub fn check_ip(ip: &str) -> bool {
    magic_ip().check_at(ip, now_secs_f64())
}

/// `true` when this recipient address is within quota.
#[cfg(feature = "ssr")]
pub fn check_email(email: &str) -> bool {
    magic_email().check_at(email, now_secs_f64())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_capacity_then_denies() {
        let lim = Limiter::new(3, 0.1);
        for i in 0..3 {
            assert!(lim.check_at("a", 0.0), "request {i} should be allowed");
        }
        assert!(!lim.check_at("a", 0.0), "the 4th request must be denied");
    }

    #[test]
    fn refills_over_time() {
        let lim = Limiter::new(2, 1.0); // one token per second
        assert!(lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 0.0));
        assert!(!lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 1.0), "one second refills one token");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let lim = Limiter::new(2, 1.0);
        assert!(lim.check_at("a", 0.0));
        assert!(lim.check_at("a", 0.0));
        // A long idle period must not bank unlimited tokens.
        assert!(lim.check_at("a", 10_000.0));
        assert!(lim.check_at("a", 10_000.0));
        assert!(!lim.check_at("a", 10_000.0), "capacity is still 2");
    }

    /// The refusal quotes a wait the limiter actually imposes. Before this,
    /// both entry points said "wait a minute" — which was 30 seconds short
    /// of the truth on one bucket and five times over it on the other, and a
    /// user told to wait the wrong amount either gives up early or retries
    /// into the same refusal.
    #[test]
    fn the_refusal_quotes_this_buckets_own_wait() {
        assert_eq!(Limiter::new(5, 1.0 / 30.0).retry_after_secs(), 30);
        assert_eq!(Limiter::new(30, 1.0 / 5.0).retry_after_secs(), 5);
        // A bucket that refills faster than once a second still has to name
        // a whole number of seconds, and "0 seconds" would read as broken.
        assert_eq!(Limiter::new(1, 10.0).retry_after_secs(), 1);
    }

    /// The two quotas must not share a bucket. Every phase-2 encryption
    /// ceremony runs through `passkey_login_start`, and adding a passkey
    /// spends two tokens — enough that a signed-in user doing ordinary
    /// things would exhaust a bucket sized to stop anonymous account
    /// enumeration.
    #[test]
    fn a_signed_in_ceremony_does_not_spend_the_sign_in_quota() {
        for _ in 0..MAGIC_CAPACITY {
            assert!(PasskeyQuota::SignIn.check_ip("198.51.100.7"));
        }
        assert!(
            !PasskeyQuota::SignIn.check_ip("198.51.100.7"),
            "the sign-in bucket is exhausted"
        );
        assert!(
            PasskeyQuota::Ceremony.check_ip("198.51.100.7"),
            "a caller who has already authenticated must not be refused by it"
        );
    }

    /// Buckets must not bleed between keys, or one busy user locks out all.
    #[test]
    fn keys_are_independent() {
        let lim = Limiter::new(1, 0.1);
        assert!(lim.check_at("a", 0.0));
        assert!(!lim.check_at("a", 0.0));
        assert!(lim.check_at("b", 0.0), "a different key has its own bucket");
    }
}
