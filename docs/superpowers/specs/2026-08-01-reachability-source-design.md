# `StreamFrame::Reachability.source` — which producer emitted this frame (#150)

**Status:** accepted · **Target:** 0.25.0 (MINOR) · **`api_minor`:** 30

## Problem

Since API 1.22 `StreamFrame::Reachability` has two producers and no discriminator:

- a **probe** completing (`status`/`subscribe` refreshing a stale entry) — `node/src/daemon/reach.rs`;
- a **live session** whose selected path changed under it (#92 item 2) — `node/src/daemon/path_watch.rs`.

They license different claims. Probe-sourced means "a fresh throwaway dial toward this peer went via
a relay" — it says nothing about the connection anyone is using. Session-sourced means "the
connection this peer's traffic is actually on just degraded Direct→Relay", which is the actionable
statement the second producer was added to enable.

An embedder (bolo #98/#79) wants to warn a user when a link that WAS direct silently is not any
more. It cannot, because it cannot tell the two apart, and hedging every message down to the weaker
probe-level claim discards the whole value of the session watcher.

## `rtt_ms` is not a usable discriminator

The issue offered documenting `rtt_ms: None` as a hard guarantee for session-sourced frames as a
cheap option. **It is factually unavailable**, and we should say so rather than let a consumer build
on it:

`commit_observation` (`path_watch.rs`) has two arms. The `None` arm — first knowledge of a peer, from
a live session — seeds `rtt_ms: None`, which is where the current doc's wording comes from. But the
`Some(entry)` arm updates `entry.path` on a peer that has **already been probed**, and deliberately
leaves the probe's `rtt_ms`/`meta`/`services`/`probed_at` alone (refreshing `probed_at` would stamp a
stale RTT as `age_secs: 0` and suppress the corrective refresh — #92 review).

So a session-sourced frame for a previously-probed peer carries `rtt_ms: Some(..)`. That is the
common case for the exact scenario bolo cares about: a peer probed at pairing time, then watched
through a long call. Option 3 would have documented a guarantee the code does not keep.

## Design

Take the issue's preferred option 1: an explicit field on the frame.

```rust
/// WHICH producer emitted a `StreamFrame::Reachability` (#150).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReachabilitySource {
    /// A probe completed — a fresh throwaway dial. Says nothing about any live connection.
    Probe,
    /// A live session's selected path changed under it. A claim about the link in use.
    Session,
    /// The daemon did not say (`api_minor < 30`), or named a producer this client predates.
    #[default]
    Unknown,
}

Reachability {
    peer: PeerReachability,
    #[serde(default)]
    source: ReachabilitySource,
}
```

### Unknown is the default, not Probe

The issue asked for `Probe` as the `serde(default)` so "older payloads keep their current meaning".
Their current meaning is *ambiguous*, not probe: a daemon at `api_minor` 22–29 already has both
producers, so defaulting an absent field to `Probe` asserts "probe" for every session-sourced frame
such a daemon emits. That is the false claim this issue exists to remove, reintroduced one layer
down. `Unknown` costs the consumer one match arm and states what is true.

This follows `PeerPath`'s precedent verbatim — `#[default] Unknown`, and its rule that `Unknown`
means "we do not know" and must never be rendered as the confident case.

### Unknown is also the unknown-string landing spot

`PeerPath` uses `#[serde(other)]` for this, which serde allows only on internally/adjacently tagged
enums. `ReachabilitySource` is a plain string enum, so `#[serde(other)]` will not compile. It gets a
hand-written `Deserialize` that reads a string and maps anything unrecognized to `Unknown`.

Without it a future third producer would make every `Reachability` frame fail to deserialize on
older clients — the whole-payload failure mode `PeerPath`'s doc calls out at length. `Serialize`
stays derived.

### Not carried on `PeerReachability`

`source` describes an *event*, not a peer. `PeerReachability` also appears in `status.reachability`
and in `Snapshot.reachability`, which are cache reads with no producer to name. The field belongs on
the frame variant only.

### Plumbing

`MeshState.reach_bcast` currently carries a bare `PeerReachability`. It becomes a
`ReachTransition { peer, source }` (node-internal), set at each of the two `send` sites:
`reach.rs:187` → `Probe`, `path_watch.rs:205` → `Session`. `run_subscription`'s `reach_frame` maps it
straight onto the frame. `reach_bcast_for_test` and its three `cli/tests/live_path_events.rs`
call sites move with it.

## Versioning

**MINOR → 0.25.0.** Adding a field to the `Reachability { peer }` struct variant breaks every
exhaustive Rust pattern downstream, exactly as adding the variant itself did in 0.13.0. The variant
is deliberately *not* marked `#[non_exhaustive]`: that would forbid downstream construction and break
consumers' own tests, a worse trade than a rare re-break.

`API_MINOR` 29 → **30**, `API_VERSION` "1.30", history line added. `docs/local-protocol.md` gains the
field and the `rtt_ms` correction.

## Testing

1. **Probe-sourced frame carries `Probe`** — drive a probe transition, assert `source == Probe`.
2. **Session-sourced frame carries `Session`** — drive a path change through `commit_observation`,
   assert `source == Session`.
3. **The `rtt_ms: Some` + `Session` combination** — probe a peer, then change its path; assert the
   frame is `Session` *and* `rtt_ms.is_some()`. This is the case that makes `rtt_ms` unusable as a
   discriminator; the test pins it so the claim in the docs stays true.
4. **Wire additivity** — a payload with no `source` deserializes to `Unknown`; a payload with
   `"source":"future_thing"` deserializes to `Unknown` rather than failing the whole frame.
5. **Round-trip** — `Probe`/`Session`/`Unknown` serialize and deserialize back.

Each is mutation-tested: swapping the two producers' `source` values must fail 1, 2 and 3; deleting
the hand-written `Deserialize` must fail 4.

## Out of scope

No change to when a frame is emitted, to `PeerReachability`, to `status`, or to the snapshot.
