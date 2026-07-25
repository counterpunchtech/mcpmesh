# Expose the eid: principal + dial by eid: (issue #41) — design

**Date:** 2026-07-25 · **Status:** Approved · **Ships in:** 0.9.2 (additive — new optional `PeerInfo` field + new dial vocabulary; no breaking change)

## Problem

Since #38, authz keys on stable principals and the socket backend injects the caller's
`eid:<hex>` device principal into `_meta["mcpmesh/peer"]`. But that `eid:` is a dead end
beyond the injection:
- `status` (`PeerInfo`) exposes a peer's nickname and (when bound) its `b64u:` user_id, but
  NEVER its `eid:` device principal — so an embedder can't map a status peer back to the
  authenticated endpoint it holds from the injection.
- `dial_service` resolves targets by nickname / `b64u:` user_id / roster name only — an
  `eid:` is not a dial vocabulary.

Nicknames are NOT unique (first-match wins; a peer's petname is its self-asserted display
name at pairing), so any caller-keyed decision forced onto the nickname either misdirects
(dials the other same-named endpoint) or leaks (returns the other endpoint's data). bolo
works around this by refusing whenever a nickname resolves to >1 peer — safe but degrades
honest same-name setups.

## Design

Two additive changes; either helps, both together let embedders retire nickname-keyed
decisions.

### 1. `PeerInfo.principal` — the eid: device principal

`PeerInfo` gains `principal: Option<String>` carrying the peer's `eid:<hex>` device
principal (`format!("eid:{}", EndpointId)` — the SAME rendering `_meta` injects and allow
lists use). Populated for every real peer; `Option` only for serde additivity.

- This is the DEVICE principal, always present — deliberately distinct from the existing
  `user_id` (the person-level `b64u:`, present only when bound). Together they give the
  embedder both granularities and let it reconstruct the exact allow-list grant principal
  (`user_id` if `Some`, else `principal`).
- **Surface discipline:** exposed on the MACHINE surface (`--json` / the local-api struct)
  only — it is the sanctioned authz principal (identical to what already appears in
  `ServiceInfo.allow`), consistent with the #38 SECURITY.md carve-out (principals are a
  machine namespace; porcelain renders display names). The HUMAN `status` render is
  unchanged — it still shows nicknames and never prints a raw eid.

### 2. Dial by eid: — exact-endpoint targeting

`dial_service` accepts a `peer` of the form `eid:<64-hex>`, resolved FIRST (before the
roster person→device and nickname/user_id paths): decode the hex to the 32-byte endpoint
id, dial that EXACT authenticated endpoint. No nickname/user_id ambiguity, no person→device
race — it targets one device precisely, which is the point.

- A stored `PeerEntry` at that endpoint id supplies the pairing-persisted `last_addr` hint
  (cold-dial reachability, issue #27); an unknown eid degrades to a bare-id discovery dial
  (the peer's own gate remains the security boundary — dialing is outbound and authorizes
  nothing on our side).
- `split_target` needs no change: an `eid:` carries no `/`, so `eid:<hex>/<service>` splits
  cleanly. Invalid hex / wrong length → a clear resolution error.

`api_minor` → 6.

## Non-goals

Changing nickname/user_id/roster dial paths (unchanged); human porcelain exposure of raw
eids (machine surface only); any authz/gating change (dial is outbound; the principal is
already the documented authz vocabulary).

## Testing

- `PeerInfo.principal` populated with the eid: for a stored peer; additive serde round-trip;
  present alongside `user_id` for a bound peer.
- `dial_service` with `eid:<hex>` reaches the exact endpoint (a two-node probe/dial where the
  target is addressed by eid, not nickname); an eid whose nickname collides still lands on
  the right endpoint; invalid-hex eid → error.
- `split_target` handles `eid:<hex>/<service>`.
- Human `status` render still shows NO raw eid (surface-discipline regression).
- Inline security review of the diff (exposing eid: on the surface; the new dial vocabulary).
