# A throttled probe is not evidence the peer is down (#89, PR #142 gate item 1)

Date: 2026-07-29. Scope: the remaining required-before-merge work on PR #142.

## Problem

The ping limiter's refusal (`accept.rs`) reuses `CLOSE_UNAUTHORIZED` + `b"unauthorized"`, so the
prober cannot tell "throttled" from "unpaired". A refused probe therefore commits
`reachable: false` to the cache and can broadcast a false offline transition for a healthy, paired
peer. `probe_peer_cached` (21df648) removed the realistic trigger in `peer_services` but not the
mechanism, and the `peer_services` call-site change itself is pinned by no test.

## Design call: the distinguishable close leaks nothing

The arm's comment claims the indistinguishable refusal means "a flooding peer learns nothing".
That property is already vacuous for the throttle case: the limiter runs AFTER the trust gate, so
only an authenticated paired peer can ever be throttled — and a flooding peer interleaves refusals
with successful pongs (the bucket refills), so it already holds proof it is paired and the peer is
up. An unpaired scanner still gets `b"unauthorized"`, unchanged. The cost of the ambiguity is
concrete and shipped (false offline); the leak it prevents is empty.

## Changes

1. **Responder** (`accept.rs` ping arm): refuse with `0u32` + `b"ping rate limited"` — the exact
   sibling idiom (`b"pair rate limited"`, `b"blob rate limited"`). Count the refusal on the
   limiter (`MeshLimiters` atomic + accessor) and log it at debug (no endpoint id — surface-leak
   discipline). Fixes "unlogged, uncounted, indistinguishable".
2. **Prober** (`reach.rs`): when the exchange fails and `conn.close_reason()` is an application
   close with reason `b"ping rate limited"`, the probe commits NOTHING — no cache write, no
   transition broadcast. It returns the previous cache entry if one exists, else an uncommitted
   `reachable: false` entry. A rate-limit refusal is not evidence in either direction.
3. **Shared constant** `PING_THROTTLE_CLOSE: &[u8]` so responder and prober cannot drift.

## Tests (each mutation-verified)

- **Flood test rework** (`cli/tests/reachability.rs`): 90 probes past the cap must now ALL report
  reachable (the throttled ones return the fresh cached entry), while the responder-side refusal
  counter is > 0. Mutations caught: remove `admit_ping` from the arm → counter 0; revert the close
  reason to `b"unauthorized"` → throttled probes write false → reachable assertions fail; drop the
  prober-side throttle check → same failure.
- **`peer_services` freshness pin** (closes 21df648's stated gap): probe A while up (cache
  populated with A's granted service), take A down, call the real `peer_services` control verb
  within the TTL → must succeed from cache. Reverting `probe_peer_cached` to `probe_peer` probes
  the dead peer and fails the verb. No test accessor needed — the down-peer arrangement pins the
  call site through public API only.

## Non-goals

Ask 2 of #89 (`presence_mode`) and ask 3 (rate-limit advertisement on the pong) stay open on the
issue. No config key for `PING_PER_MIN` yet. Audit-summary integration of refusals not included —
the counter + debug log are the diagnosis surface for now.
