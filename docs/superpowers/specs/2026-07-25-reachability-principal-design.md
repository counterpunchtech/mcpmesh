# PeerReachability.principal (issue #42) — design

**Date:** 2026-07-25 · **Status:** Approved · **Ships in:** 0.9.3 (additive; no breaking change)

## Problem

#41 added `PeerInfo.principal` so embedders key caller-scoped decisions on the exact
authenticated endpoint. But `PeerReachability` (probe result + the #40 pairing-mode `meta`)
still has no principal, so those rows can only be joined back to a peer by nickname — and
nicknames are not unique. With two peers under one nickname, an embedder's per-peer view
collapses both endpoints' reachability/app-version into one lossy name-keyed row (bolo now
conservatively suppresses probe/version detail on collision — correct but worse UX).

## Design

A one-field mirror of #41: `PeerReachability` gains `principal: Option<String>` carrying the
peer's `eid:<hex>` device principal — the SAME `EndpointId::principal()` rendering used by
`PeerInfo.principal`, the `_meta["mcpmesh/peer"]` injection, and the allow lists. Populated
for every row (the endpoint id is already in scope in `reachability_of`, which iterates
`(nickname, endpoint_id)`); `Option` only for serde additivity. Machine surface only — the
human `status` reachability line is unchanged (nickname + latency, no raw id).

`API_MINOR` → 7. This completes the #41 story: every per-peer status row (info +
reachability) is exactly principal-keyed.

## Non-goals

Changing probe behavior; human-porcelain exposure of the raw eid; any authz change (the
principal is already the documented machine-surface authz vocabulary).

## Testing

- `PeerReachability.principal` populated with the peer's eid in `reachability_of`; additive
  serde round-trip; present alongside the #40 `meta` so an embedder joins probe + version on
  the principal.
- Extend the existing two-node reachability integration test to assert the surfaced row
  carries the target's eid principal.
- Human `status` render still shows no raw eid (surface-discipline regression).
