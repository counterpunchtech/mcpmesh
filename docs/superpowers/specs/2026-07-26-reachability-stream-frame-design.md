# `StreamFrame::Reachability` — a pushed liveness signal (#58)

**Status:** accepted · **Issue:** #58 · **Target:** 0.12.1 (additive → PATCH)

## Problem

`subscribe` carries reachability **only** in the opening `Snapshot`. After that there is no pushed
signal when a peer goes reachable or unreachable, so an embedder wanting a live online/offline
indicator has to poll `status` on a timer — which is the exact trade `subscribe` exists to remove.

The sharper cost is latency on *reconnect*: anything queued for an unreachable peer wants to flush
the moment they return. With polling, flush latency is the poll interval; with an event, it is
immediate.

## Approach

A fourth variant, reusing the type the snapshot already carries:

```rust
Reachability { peer: PeerReachability },
```

emitted when a peer's probe result **transitions**.

### Where the transition is detected

`probe_peer` (`node/src/daemon/reach.rs:46`) is the single writer of `MeshState.reachability`. It
already computes the new `ReachEntry` and inserts it, so the comparison is local: read the prior
entry under the same lock, and emit iff

- there was **no** prior entry (first knowledge of this peer's liveness), **or**
- `prior.reachable != new.reachable`.

A refreshed probe with an unchanged verdict emits nothing, so a peer that stays up does not
generate a frame per TTL refresh. `rtt_ms`/`meta`/`services` changes alone are not transitions —
they are advisory detail, and treating them as events would make the stream chatty for no decision.

### How it reaches subscribers

A **second** broadcast channel, `MeshState.reach_bcast: broadcast::Sender<PeerReachability>`,
rather than widening the audit hub. The audit `bcast` carries `AuditRecord` and is the same call
that appends to the on-disk log; putting reachability through it would either write probe results
into the audit file or require splitting record-vs-broadcast, entangling two concerns. A separate
ring keeps the audit log's schema exactly as it is.

The `subscribe` loop `tokio::select!`s over both receivers. Lag is reported per-ring with the
existing `Lagged` frame — a reachability-ring lag is far less likely (transitions are rare relative
to audit records), but it is handled identically rather than silently dropped.

`reach_bcast` lives on `MeshState`, so a control-only daemon (no mesh) simply never emits — the
existing `Snapshot`-then-end path for a disabled sink is unchanged.

### Building the frame

`probe_peer` has the endpoint id; the nickname comes from the peer store and the principal from
`EndpointId::principal()` — the same three fields `reachability_of` already assembles. That
construction is factored into one helper so the snapshot and the event cannot drift in shape.

`age_secs` is `Some(0)` on an event: the probe just completed, which is the honest value and
matches what a `status` read one instant later would report.

## Surface + versioning

- `StreamFrame::Reachability { peer: PeerReachability }` — additive. Serde is internally tagged on
  `type`, so an existing consumer sees an unrecognized `"type":"reachability"` and, per the
  documented stream contract, ignores frames it does not know.
- `API_MINOR` 11 → 12, `API_VERSION` "1.11" → "1.12".
- `docs/local-protocol.md`: the "Live event stream" section gains the variant, its emission rule,
  and the explicit note that it fires on transition only.
- Workspace version → **0.12.1** (additive → PATCH).

Note: PR #72 (#57) also claims `API_MINOR` 12 on its own branch. Whichever lands second rebases to
13 — they are independent surfaces and the ordering does not matter.

## Testing (TDD, RED first)

1. **Unit (serde)** — the variant round-trips and tags as `{"type":"reachability","peer":{…}}`,
   alongside the existing `StreamFrame` serde test.
2. **Unit (transition rule)** — the emit predicate: no prior entry → emit; `false`→`true` → emit;
   `true`→`false` → emit; `true`→`true` (refresh) → **no** emit; an `rtt_ms`-only change → no emit.
3. **Integration** — a live `subscribe` connection receives a `reachability` frame when a probed
   peer transitions, without polling `status`. Fails today: the variant does not exist.
4. **Regression** — the opening `Snapshot` still carries the full reachability list, and a
   subscriber with no mesh still gets `Snapshot`-then-end.

## Out of scope

Emitting on `rtt_ms`/`meta`/`services` drift (advisory detail, not a decision point). Presence-topic
(roster-mode gossip) events — a different mechanism with its own surface; this issue is about the
pairing-mode probe.
