//! In-memory token buckets guarding the magic-link and passkey entry points.
//!
//! Two independent limiters, both applied. By IP, so one host cannot spray
//! many addresses; by email, so an attacker rotating IPs cannot mail-bomb one
//! victim. Either limit alone leaves the other attack open.
//!
//! In-memory is sufficient: this is a single process, and a restart clearing
//! the buckets is not a useful window against a 15-minute token.

use std::collections::HashMap;
use std::sync::Mutex;

/// Magic-link requests: 5 immediately, then one back every 30s.
///
/// `pub` so the tests that pin the limit can name it rather than restating
/// the number, and drift into asserting a quota that is no longer the one
/// the app enforces.
pub const MAGIC_CAPACITY: u32 = 5;
const MAGIC_REFILL_PER_SEC: f64 = 1.0 / 30.0;

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

    /// Buckets must not bleed between keys, or one busy user locks out all.
    #[test]
    fn keys_are_independent() {
        let lim = Limiter::new(1, 0.1);
        assert!(lim.check_at("a", 0.0));
        assert!(!lim.check_at("a", 0.0));
        assert!(lim.check_at("b", 0.0), "a different key has its own bucket");
    }
}
