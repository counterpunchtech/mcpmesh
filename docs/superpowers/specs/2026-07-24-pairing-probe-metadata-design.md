# Pairing-mode app-metadata on the reachability probe (issue #40) — design

**Date:** 2026-07-24 · **Status:** Approved · **Ships in:** 0.9.1 (additive — new optional pong field + `PeerReachability.meta`; no breaking wire change)

## Problem

#39 gave embedders a fleet-wide app-metadata slot, but it rides the roster presence
heartbeat — **pairing-mode** deployments (bolo's fleet, most person-to-person setups) have
no presence channel, so paired peers can't see each other's metadata at all. Today the only
option is dialing every peer's MCP service on a timer (a session per poll, which perturbs
the peers' idle detection).

## Design

Fold the SAME metadata value (`set_app_metadata` from #39, already on `MeshState`) into the
`mcpmesh/ping/1` reachability probe response, which already flows periodically between paired
peers. One value, two carriers: presence beats in roster mode (#39), pong responses in
pairing mode (#40).

### Why no signature (the simplification over #39)

The probe runs over an authenticated QUIC/TLS session, and the responder pongs ONLY to a
trust-gated (paired) peer (default-deny at the gate, `net::run` ping handler). So metadata on
the pong is already cryptographically attributable to the authenticated responder — no
per-blob signature is needed. (#39 needed one only because gossip is a broadcast medium.)

### 1. Responder (the pong)

The ping accept handler already writes `{"stack_version": "..."}` back. It gains
`"meta": <mesh.app_metadata()>` (skipped when empty). The value is the ≤256B blob #39 caps at
set time — no new set path, no second source of truth.

### 2. Prober (`node/src/daemon/reach.rs`)

`probe_once` currently ignores the pong body (`Some(Inbound::Frame(_)) => Ok(())`). It now
parses `stack_version`-shaped frames for an optional `meta`, and — **defense in depth against
a compromised paired peer** — re-applies #39's receive hardening: cap `meta.len() <= 256`
(over-cap → treat meta as empty, still reachable), so a hostile pong cannot inject an
unbounded blob. `ReachEntry` gains `meta: String`; `probe_peer` caches it.

### 3. Surface

`PeerReachability` gains `meta: String` (additive, skip-if-empty); `reachability_of()` carries
the cached value through. `status` render shows it control-char-stripped (reuse #39's
`sanitize_meta`), and `--json` carries it raw (JSON escapes control chars). `API_MINOR` → 5.

## Liveness semantics (a documented difference from #39)

Reachability probes are on-demand with a 20s TTL cache, refreshed lazily when `status` is read
— so pairing metadata is "near-real-time when someone reads status," slightly less live than
roster gossip's steady ~60s beat. This matches bolo's GUI-polling use case; it is stated in
the verb/field docs so no one expects push semantics.

## Non-goals

A new set API (the #39 verb + value are reused unchanged); a signed pong (the channel is
authenticated); changing roster-mode behavior (#39 is untouched).

## Testing

- Prober parses `meta` from a pong; caches it in `ReachEntry`; over-cap `meta` from a hostile
  pong is dropped (the receive cap), reachability still true.
- Responder pong includes `meta` when set, omits it when empty.
- `PeerReachability.meta` additive serde round-trip.
- `status` render strips control chars in the reachability line (reuses/extends #39's test).
- Integration: a probe round-trip between two nodes where the responder set metadata surfaces
  it in the prober's `status` reachability (extends the existing reachability test).
- Adversarial review of the diff before shipping (the receive-side peer-bytes hardening is the
  exact class #39's review caught — re-verify it here).
