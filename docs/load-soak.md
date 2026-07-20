# Load soak: 20 peers × 120 rpm × 10 min (spec §16 M4 AC)

Validates the M4 acceptance clause CI does not run in full —
**"20 peers × 120 rpm for 10 min — limiter engages, no unbounded memory."**

CI proves this SCALED (`cli/tests/load_ac.rs::scaled_ac_limiter_engages_and_memory_is_bounded`):
20 endpoints burst above the per-identity rate → the limiter engages (over-limit denied) and the
bucket map is bounded to 20, then idle-evicts. This runbook is the LITERAL 10-minute soak — a
milestone demo, not a CI blocker (like the two-machine NAT smoke test in `dev-two-machine-smoke.md`).

## Run

```bash
cargo test -p mcpmesh --test load_ac literal_20x120_10min -- --ignored --nocapture
```

Expected: completes in ~10 minutes and prints a final line like
`literal soak: served=… throttled=… tracked=20`. The load-bearing assertion is `tracked == 20` for
the whole soak — the bucket map never grows beyond the live endpoint set (no unbounded memory).

## Optional: end-to-end soak against a live daemon

For a wire-level soak (a real daemon + 20 authorized peers each issuing 120 `tools/call`/min for
10 min against a `run` service), drive `mcpmesh connect <peer>/<svc>` from 20 seeded identities and
watch `mcpmesh status` for steady RSS and the daemon logs for `-32053` throttles once a peer exceeds
`[limits].rate_limit_per_min`. Steady RSS + throttles-on-excess + no OOM = the AC met live.

> **House rule:** one `cargo` invocation at a time per target dir.
