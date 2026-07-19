//! Rate-limiting primitives (spec §7.3 / §11.2 P7): a monotonic token bucket + a bounded,
//! idle-evicting per-endpoint bucket map. PURE and FAIL-SAFE by construction — an over-limit check
//! DENIES (returns a retry hint), never serves-more; the bucket map self-prunes so a churn of distinct
//! AUTHENTICATED endpoints cannot grow memory without bound (the AC's "no unbounded memory"). Keyed
//! ONLY on the authenticated `EndpointId` (never a self-asserted name — SECURITY invariant 1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mcpmesh_net::EndpointId;

/// A monotonic token bucket: at most `capacity` tokens (the burst), refilling at `refill_per_sec`.
/// One request costs one token. `try_take` refills lazily from elapsed wall time via a monotonic
/// `Instant`, so it needs no background timer and cannot go backwards.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// A FULL bucket. `capacity` = the burst allowance; `refill_per_sec` = the sustained rate.
    pub fn new(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_refill: now,
        }
    }

    /// Refill lazily, then take one token if available. `Ok(())` = a token was spent; `Err(ms)` =
    /// empty, where `ms` is the ceil-milliseconds until the NEXT token (FAIL-SAFE deny — never a
    /// spend on empty, never negative). A zero refill rate reports a long, bounded wait.
    pub fn try_take(&mut self, now: Instant) -> Result<(), u64> {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let deficit = 1.0 - self.tokens;
            let secs = if self.refill_per_sec > 0.0 {
                deficit / self.refill_per_sec
            } else {
                f64::from(u32::MAX)
            };
            Err((secs * 1000.0).ceil() as u64)
        }
    }
}

/// A bucket unused for this long is evictable — the map self-prunes so a churn of distinct
/// authenticated endpoints cannot grow memory without bound (the AC's core property).
const IDLE_TTL: Duration = Duration::from_secs(600);
/// Hard cap on tracked buckets (defense-in-depth). Only gate-resolved endpoints ever reach the
/// limiter — strangers are refused pre-gate — so the live set is already roster/allowlist-bounded;
/// at the cap, a newcomer LRU-evicts the least-recently-seen bucket. The map NEVER exceeds this.
const MAX_BUCKETS: usize = 4096;

struct Tracked {
    bucket: TokenBucket,
    last_seen: Instant,
}

/// A bounded, idle-evicting map of per-endpoint token buckets (spec §11.2 P7 "per-identity token
/// buckets"; the AC's "no unbounded memory"). Keyed ONLY on the authenticated `EndpointId`.
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    buckets: Mutex<HashMap<EndpointId, Tracked>>,
}

impl RateLimiter {
    /// Build from a per-minute rate (spec §12 `[limits].rate_limit_per_min`). `burst` = bucket
    /// capacity (the instantaneous allowance); sustained rate = `per_min / 60` tokens·s⁻¹.
    pub fn per_minute(per_min: u32, burst: u32) -> Self {
        Self {
            capacity: f64::from(burst.max(1)),
            refill_per_sec: f64::from(per_min.max(1)) / 60.0,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// An effectively-unlimited limiter (control-only test daemon / the `None`-identity path).
    pub fn unlimited_shared() -> Arc<Self> {
        Arc::new(Self::per_minute(u32::MAX, u32::MAX))
    }

    /// Check-and-consume one token for `endpoint` at `now`. `Ok(())` = admit; `Err(ms)` = over limit
    /// (FAIL-SAFE deny). Lazily creates the endpoint's bucket, records `last_seen`, and prunes idle
    /// buckets so the map stays bounded (idle-TTL retain + a hard LRU cap).
    pub fn check(&self, endpoint: &EndpointId, now: Instant) -> Result<(), u64> {
        let mut map = self.buckets.lock().expect("rate limiter mutex");
        if !map.contains_key(endpoint) {
            make_room(&mut map, now);
            map.insert(
                *endpoint,
                Tracked {
                    bucket: TokenBucket::new(self.capacity, self.refill_per_sec, now),
                    last_seen: now,
                },
            );
        }
        let t = map
            .get_mut(endpoint)
            .expect("present after the insert above");
        t.last_seen = now;
        t.bucket.try_take(now)
    }

    /// Number of tracked buckets (the AC's bounded-memory assertion reads this).
    pub fn tracked(&self) -> usize {
        self.buckets.lock().expect("rate limiter mutex").len()
    }
}

/// Prune idle buckets (`last_seen` older than IDLE_TTL); if the map is STILL at the hard cap, evict
/// the single least-recently-seen entry so a newcomer fits. O(n) under the lock; `n ≤ MAX_BUCKETS`.
fn make_room(map: &mut HashMap<EndpointId, Tracked>, now: Instant) {
    map.retain(|_, t| now.saturating_duration_since(t.last_seen) < IDLE_TTL);
    if map.len() >= MAX_BUCKETS
        && let Some(oldest) = map.iter().min_by_key(|(_, t)| t.last_seen).map(|(k, _)| *k)
    {
        map.remove(&oldest);
    }
}

/// Per-session rate-limit handle for the pump: the shared per-endpoint limiter + THIS session's
/// authenticated endpoint. A `None` endpoint (the reserved no-identity path) is never limited.
/// Consulted once per inbound proxied request line.
pub struct RateGate {
    limiter: Arc<RateLimiter>,
    endpoint: Option<EndpointId>,
}

impl RateGate {
    pub fn new(limiter: Arc<RateLimiter>, endpoint: Option<EndpointId>) -> Self {
        Self { limiter, endpoint }
    }

    /// Try to admit one request now. `Ok(())` = forward it; `Err(retry_after_ms)` = throttle (DENY).
    pub fn admit(&self) -> Result<(), u64> {
        self.admit_at(Instant::now())
    }

    /// `admit` at an explicit instant (deterministic tests).
    pub fn admit_at(&self, now: Instant) -> Result<(), u64> {
        match self.endpoint {
            Some(eid) => self.limiter.check(&eid, now),
            None => Ok(()),
        }
    }
}

/// Global pair-ALPN accept rate (spec §7.1/§4.2, the M2b-deferred per-connection limit). The pair
/// ALPN accepts strangers by design, who pick fresh ids — so a SINGLE global bucket bounds a
/// distinct-id flood (a per-endpoint map would be defeated by fresh ids). NOT the removed per-invite
/// attempt cap; the 32-byte secret is the security.
const PAIR_ACCEPT_PER_MIN: u32 = 30;
/// Per-authenticated-endpoint app-blob CONNECTION rate (spec §9, the M4a-deferred bound): a valid
/// roster member with no scope grant can open blob connections whose GETs are denied — this bounds
/// that churn per endpoint.
const BLOB_CONN_PER_MIN: u32 = 60;

/// The daemon's rate/concurrency limiter bundle (spec §11.2 P7), built ONCE from config and carried
/// on `MeshState`. Bundled so `MeshState` gains ONE handle. Every map is bounded (T1). T9 extends
/// this with the pair-accept + blob-connection limiters.
pub struct MeshLimiters {
    /// Per-authenticated-endpoint proxied-request buckets (`[limits].rate_limit_per_min`).
    pub requests: Arc<RateLimiter>,
    /// A GLOBAL pair-ALPN accept bucket (bounds a distinct-id stranger flood).
    pair_accept: Mutex<TokenBucket>,
    /// Per-authenticated-endpoint app-blob connection buckets.
    blob_conn: Arc<RateLimiter>,
}

impl MeshLimiters {
    /// Build from `[limits]`. Burst == the per-minute rate (a full minute of instantaneous allowance,
    /// then the sustained rate caps at `per_min`).
    pub fn from_config(limits: &crate::config::LimitsCfg) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            requests: Arc::new(RateLimiter::per_minute(
                limits.rate_limit_per_min,
                limits.rate_limit_per_min,
            )),
            pair_accept: Mutex::new(TokenBucket::new(
                f64::from(PAIR_ACCEPT_PER_MIN),
                f64::from(PAIR_ACCEPT_PER_MIN) / 60.0,
                now,
            )),
            blob_conn: Arc::new(RateLimiter::per_minute(
                BLOB_CONN_PER_MIN,
                BLOB_CONN_PER_MIN,
            )),
        })
    }

    /// An effectively-unlimited bundle (control-only test daemon / `build_services` default).
    pub fn unlimited() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            requests: RateLimiter::unlimited_shared(),
            pair_accept: Mutex::new(TokenBucket::new(
                f64::from(u32::MAX),
                f64::from(u32::MAX),
                now,
            )),
            blob_conn: RateLimiter::unlimited_shared(),
        })
    }

    /// Admit one pair-ALPN accept (FAIL-SAFE: `false` = over-limit → close the connection).
    pub fn admit_pair_accept(&self) -> bool {
        self.admit_pair_accept_at(Instant::now())
    }
    pub fn admit_pair_accept_at(&self, now: Instant) -> bool {
        self.pair_accept
            .lock()
            .expect("pair-accept bucket")
            .try_take(now)
            .is_ok()
    }

    /// Admit one app-blob connection from `endpoint` (FAIL-SAFE: `false` = over-limit → close).
    pub fn admit_blob_conn(&self, endpoint: &EndpointId) -> bool {
        self.admit_blob_conn_at(endpoint, Instant::now())
    }
    pub fn admit_blob_conn_at(&self, endpoint: &EndpointId, now: Instant) -> bool {
        self.blob_conn.check(endpoint, now).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn bucket_bursts_then_throttles_then_refills() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3.0, 1.0, t0); // burst 3, 1 token/s
        assert!(b.try_take(t0).is_ok());
        assert!(b.try_take(t0).is_ok());
        assert!(b.try_take(t0).is_ok());
        let retry = b.try_take(t0).unwrap_err(); // empty → deny with a retry hint
        assert!(
            (900..=1000).contains(&retry),
            "≈1s until the next token, got {retry}"
        );
        let t1 = t0 + Duration::from_secs(1); // exactly one token refilled
        assert!(b.try_take(t1).is_ok());
        assert!(b.try_take(t1).is_err());
    }

    #[test]
    fn buckets_are_per_endpoint() {
        let t0 = Instant::now();
        let rl = RateLimiter::per_minute(60, 2); // burst 2, 60/min
        let (a, b) = (EndpointId::from([1u8; 32]), EndpointId::from([2u8; 32]));
        assert!(rl.check(&a, t0).is_ok());
        assert!(rl.check(&a, t0).is_ok());
        assert!(rl.check(&a, t0).is_err(), "a exhausted its own bucket");
        assert!(rl.check(&b, t0).is_ok(), "b has an independent bucket");
    }

    #[test]
    fn map_self_prunes_idle_buckets() {
        let t0 = Instant::now();
        let rl = RateLimiter::per_minute(60, 60);
        assert!(rl.check(&[1u8; 32].into(), t0).is_ok());
        assert!(rl.check(&[2u8; 32].into(), t0).is_ok());
        assert_eq!(rl.tracked(), 2);
        // A check far past IDLE_TTL prunes the two idle buckets before inserting the third.
        let later = t0 + IDLE_TTL + Duration::from_secs(1);
        assert!(rl.check(&[3u8; 32].into(), later).is_ok());
        assert_eq!(
            rl.tracked(),
            1,
            "idle buckets evicted; only the fresh one remains"
        );
    }

    #[test]
    fn unlimited_never_throttles() {
        let t0 = Instant::now();
        let rl = RateLimiter::unlimited_shared();
        for _ in 0..10_000 {
            assert!(rl.check(&[9u8; 32].into(), t0).is_ok());
        }
    }

    #[test]
    fn rate_gate_admits_then_throttles_and_none_endpoint_is_unlimited() {
        let t = Instant::now();
        let limiter = Arc::new(RateLimiter::per_minute(60, 2));
        let gate = RateGate::new(limiter, Some([5u8; 32].into()));
        assert!(gate.admit_at(t).is_ok());
        assert!(gate.admit_at(t).is_ok());
        assert!(
            gate.admit_at(t).is_err(),
            "third over the burst is throttled"
        );
        // A None-endpoint session (reserved no-identity path) is never rate-limited.
        let open = RateGate::new(RateLimiter::unlimited_shared(), None);
        for _ in 0..1000 {
            assert!(open.admit_at(t).is_ok());
        }
    }

    #[test]
    fn mesh_limiters_from_config_uses_the_request_rate() {
        let cfg = crate::config::LimitsCfg {
            rate_limit_per_min: 5,
            max_inflight: 16,
            max_sessions: 4,
        };
        let ml = MeshLimiters::from_config(&cfg);
        let t = Instant::now();
        let eid = EndpointId::from([7u8; 32]);
        // burst == rate == 5 → five admits, then throttle.
        for _ in 0..5 {
            assert!(ml.requests.check(&eid, t).is_ok());
        }
        assert!(
            ml.requests.check(&eid, t).is_err(),
            "the request limiter engages at the config rate"
        );
    }

    #[test]
    fn pair_accept_and_blob_conn_limiters_engage() {
        let t = Instant::now();
        let ml = MeshLimiters::from_config(&crate::config::LimitsCfg {
            rate_limit_per_min: 120,
            max_inflight: 16,
            max_sessions: 4,
        });
        // The GLOBAL pair-accept bucket engages after its burst (bounds a distinct-id stranger flood).
        let mut admitted = 0;
        for _ in 0..1000 {
            if ml.admit_pair_accept_at(t) {
                admitted += 1;
            }
        }
        assert!(
            admitted > 0 && admitted < 1000,
            "pair-accept limiter engages: admitted {admitted}"
        );
        // The per-endpoint blob-conn limiter engages per endpoint.
        let eid = EndpointId::from([4u8; 32]);
        let mut blob_ok = 0;
        for _ in 0..1000 {
            if ml.admit_blob_conn_at(&eid, t) {
                blob_ok += 1;
            }
        }
        assert!(
            blob_ok > 0 && blob_ok < 1000,
            "blob-conn limiter engages: ok {blob_ok}"
        );
    }
}
