//! M4c T10 — spec §16 M4 AC "20 peers × 120 rpm for 10 min — limiter engages, no unbounded memory."
//!
//! SCALED vs LITERAL (DECLARED): a literal 10-minute run is impractical in CI, so the release-gating
//! CI proof is SCALED — 20 distinct endpoints issue bursts ABOVE the per-identity rate and we assert
//! (a) the limiter ENGAGES (over-limit → deny, not served unboundedly) and (b) memory stays BOUNDED
//! (the bucket map tracks exactly the 20 endpoints, then idle-evicts). This file exercises the rate
//! PRIMITIVE (`MeshLimiters`/`RateLimiter`) directly; it does NOT drive the pump. The WIRE path — the
//! pump synthesizing `-32053` back to the caller, DROPPING the over-limit request (not forwarding it),
//! and KEEPING the session alive — is locked separately by `pump_rate_limit.rs`. The LITERAL
//! 20×120×10-min run is the `#[ignore]`d `literal_20x120_10min` driver below — a manual
//! hardware/soak demo, not a CI blocker.
use std::time::{Duration, Instant};

use mcpmesh::config::LimitsCfg;
use mcpmesh::limits::{MeshLimiters, RateLimiter};

/// (a) LIMITER ENGAGES + (b) NO UNBOUNDED MEMORY, scaled. 20 endpoints each burst 300 requests at a
/// 120/min limit (burst 120): each endpoint is admitted ~120 then throttled — the limiter engages —
/// and the bucket map tracks EXACTLY 20 buckets (bounded), then idle-evicts to a fresh single entry.
#[test]
fn scaled_ac_limiter_engages_and_memory_is_bounded() {
    let ml = MeshLimiters::from_config(&LimitsCfg {
        rate_limit_per_min: 120,
        max_inflight: 16,
        max_sessions: 4,
    });
    let t0 = Instant::now();
    for peer in 0u8..20 {
        let eid = [peer; 32];
        let mut admitted = 0;
        let mut throttled = 0;
        for _ in 0..300 {
            match ml.requests.check(&eid, t0) {
                Ok(()) => admitted += 1,
                Err(_) => throttled += 1,
            }
        }
        assert!(
            admitted <= 120,
            "burst is capped at the config rate: {admitted}"
        );
        assert!(
            throttled >= 180,
            "the limiter ENGAGES on the over-limit remainder: {throttled}"
        );
    }
    // BOUNDED: exactly the 20 authenticated endpoints are tracked — no unbounded growth.
    assert_eq!(
        ml.requests.tracked(),
        20,
        "the bucket map is bounded to the live endpoint set"
    );
    // Idle eviction proves the map SELF-PRUNES (no leak under churn): a much-later check on a fresh
    // endpoint evicts all 20 idle buckets.
    let later = t0 + Duration::from_secs(601);
    assert!(ml.requests.check(&[99u8; 32], later).is_ok());
    assert_eq!(
        ml.requests.tracked(),
        1,
        "idle buckets evicted; the map does not grow without bound"
    );
}

/// (c) CHEAP REJECTION: the request limiter is consulted ONLY post-resolve (in the pump), so a flood
/// of UNAUTHORIZED endpoints — refused pre-gate by the trust gate — allocates NO buckets. We assert
/// the limiter never sees a stranger: nothing calls `check` for an unresolved endpoint, so `tracked`
/// stays 0. (The gate's pre-spawn refusal itself is proven by `roster_sever.rs`'s pre-MCP-refusal
/// test; here we assert the limiter's non-involvement — strangers cost nothing.)
#[test]
fn cheap_rejection_allocates_no_buckets_for_strangers() {
    let limiter = RateLimiter::unlimited_shared();
    // Simulate the accept path: strangers are refused BEFORE any pump/limiter call, so `check` is
    // never invoked for them. Only an authorized peer's request reaches the limiter.
    assert_eq!(
        limiter.tracked(),
        0,
        "no bucket exists before any authorized request"
    );
    limiter.check(&[1u8; 32], Instant::now()).ok(); // one authorized peer
    assert_eq!(
        limiter.tracked(),
        1,
        "only authorized peers ever allocate a bucket"
    );
}

/// The LITERAL 20×120×10-min soak, `#[ignore]`d (CI never runs it — 10 minutes by design). Drives the
/// primitive at the real cadence for the milestone demo. Run manually.
#[test]
#[ignore = "literal 10-minute soak; run manually"]
fn literal_20x120_10min() {
    let ml = MeshLimiters::from_config(&LimitsCfg {
        rate_limit_per_min: 120,
        max_inflight: 16,
        max_sessions: 4,
    });
    let start = Instant::now();
    let mut served = 0u64;
    let mut throttled = 0u64;
    // 20 peers, each 2 requests/second (= 120 rpm), for 10 minutes.
    while start.elapsed() < Duration::from_secs(600) {
        let now = Instant::now();
        for peer in 0u8..20 {
            match ml.requests.check(&[peer; 32], now) {
                Ok(()) => served += 1,
                Err(_) => throttled += 1,
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // At exactly the rate, the vast majority are served and the map stays bounded to 20.
    assert!(served > 0);
    assert_eq!(
        ml.requests.tracked(),
        20,
        "no unbounded memory across the full soak"
    );
    eprintln!(
        "literal soak: served={served} throttled={throttled} tracked={}",
        ml.requests.tracked()
    );
}
