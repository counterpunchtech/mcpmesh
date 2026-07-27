# `StreamFrame::Reachability` — a pushed liveness signal (#58)

**Status:** accepted · **Issue:** #58 · **Target:** 0.13.0 (breaking for Rust consumers → MINOR)

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

- there was **no** prior entry **and the peer is UP**, **or**
- `prior.reachable != new.reachable`.

**Corrected in review.** The original rule emitted on *any* first knowledge, including a first
probe confirming "down". But the snapshot already reports an unprobed peer as `reachable: false`,
so that frame restates what the subscriber was just told — and because building the snapshot
*itself* spawns those probes, subscribing produced a burst of spurious "is now offline" frames
immediately after a snapshot saying exactly that, on every daemon restart.

**Stale results are discarded.** Probes of one peer overlap routinely (`reachability_of` spawns a
refresh per stale peer, and both `status` and `subscribe` call it) and complete out of order. Each
probe takes a monotonic ticket at START; a result whose ticket is older than what the cache already
holds is dropped, and the caller is handed the newer value. Without this a 3s timeout could land
after a 50ms pong and overwrite it — poisoning the cache for a full TTL and pushing a false "went
offline" for a peer that is up, which is precisely the signal this feature exists to make
trustworthy.

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

`reach_bcast` lives on `MeshState`, so a control-only daemon (no mesh) never emits and still gets
`Snapshot`-then-end. But a mesh daemon with auditing DISABLED must now keep the stream OPEN for
reachability: the loop lives as long as EITHER tap does, dropping a closed tap rather than ending
the stream. Auditing and liveness are independent signals, and the first version wrongly gated one
on the other (caught by the integration test).

### Building the frame

`probe_peer` has the endpoint id; the nickname comes from a peer-store POINT read and the principal
from `EndpointId::principal()`. `reachability_row` is now the single constructor of
`PeerReachability` — `reachability_of` calls it for both its arms — so the snapshot and the event
genuinely cannot drift. (The first version merely *claimed* this while `reachability_of` still built
its rows inline; review caught that they had already drifted on the empty-name case.)

**Only peers the store knows emit.** `probe_peer` is also reachable through `peer_services`, which
accepts a bare `eid:` with no stored row. Emitting for one of those pushed a NAMELESS frame for an
endpoint the snapshot's store-driven list can never contain — the stream asserting state `status`
contradicts at the same instant.

`age_secs` is `Some(0)` on an event: the probe just completed, which is the honest value and
matches what a `status` read one instant later would report.

## Surface + versioning

- `StreamFrame::Reachability { peer: PeerReachability }`. Additive **on the JSON wire** — serde is
  internally tagged on `type`, so an existing consumer ignores a frame kind it does not know.
  **Breaking for Rust consumers**, though: `StreamFrame` was not `#[non_exhaustive]`, so adding a
  variant breaks any exhaustive `match` on a plain `cargo update` — the repo proved it, since
  `examples/watch.rs` had to gain an arm. `RELEASING.md` puts breaking changes on the MINOR, hence
  0.13.0 rather than 0.12.1. The enum is now `#[non_exhaustive]` so later variants are additive for
  Rust too.
- `API_MINOR` 11 → 12, `API_VERSION` "1.11" → "1.12".
- `docs/local-protocol.md`: the "Live event stream" section gains the variant, its emission rule,
  and the explicit note that it fires on transition only.
- Workspace version → **0.13.0** (breaking for Rust consumers → MINOR, per `RELEASING.md`).

Note: PR #72 (#57) also claims `API_MINOR` 12 on its own branch. This one lands first, so #72
rebases to 13 — they are independent surfaces.

## Testing (TDD, RED first)

1. **Unit (serde)** — the variant round-trips and tags as `{"type":"reachability","peer":{…}}`,
   alongside the existing `StreamFrame` serde test.
2. **Unit (transition rule)** — no prior entry + UP → emit; no prior entry + DOWN → **no** emit;
   `false`→`true` → emit; `true`→`false` → emit; `true`→`true` (refresh) → no emit; `rtt_ms`/`meta`
   drift alone → no emit.
2b. **Unit (stale-result guard)** — an older probe ticket must not overwrite a newer entry.
3. **Integration** — a live `subscribe` connection receives a frame when a real peer comes UP and
   another when it goes DOWN, without polling `status`, on a mesh with auditing ENABLED (so the
   two-ring `select!` is the path under test). Must fail when flip detection is deleted — the first
   version of this test drove only `unknown → unreachable` and survived that mutation, proving it
   tested nothing.
4. **Regression** — the opening `Snapshot` still carries the full reachability list, and a
   subscriber with no mesh still gets `Snapshot`-then-end.

## Out of scope

Emitting on `rtt_ms`/`meta`/`services` drift (advisory detail, not a decision point). Presence-topic
(roster-mode gossip) events — a different mechanism with its own surface; this issue is about the
pairing-mode probe.
