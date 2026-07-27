# `PeerReachability.path` — direct vs relay (#64)

**Status:** accepted · **Issue:** #64 · **Target:** 0.13.1 (additive → PATCH)

## Problem

`PeerReachability` says *whether* a peer is reachable and *how fast*, but not **how** it is reached:
directly over the LAN or a hole-punched path, versus through a relay. iroh knows — it is the
distinction connection establishment is organized around — and the fact is dropped at the mcpmesh
boundary.

Three things depend on it, per the issue:

1. **A truthful locality claim.** "This traffic never left the building" is checkable when the path
   is direct and false when it is relayed. Today an embedder either overclaims or stays silent.
2. **Honest dependency disclosure.** A relayed path depends on third-party infrastructure.
3. **Diagnostics.** "Slow" has a different cause and fix in each case.

`rtt_ms` is not a proxy — a fast relay beats a slow direct path.

## Approach

```rust
#[non_exhaustive]
pub enum PeerPath {
    Direct,
    Relay { url: Option<String> },
    #[default]
    Unknown,
}
```

on `PeerReachability`, `#[serde(default)]` so older rows and clients are unaffected.

`#[non_exhaustive]` from the start — the #58 lesson: adding a variant to a public enum later breaks
every downstream exhaustive `match` and costs a MINOR. iroh already has a third address kind
(`TransportAddr::Custom`) that could warrant one.

### Deriving it from iroh 1.0.3

`Endpoint::remote_info(id)` yields `RemoteInfo`, whose `addrs()` are `TransportAddrInfo` — each a
`TransportAddr` (`Relay(RelayUrl)` / `Ip(SocketAddr)` / `Custom`) plus a `usage()` of `Active` or
`Inactive`. Only **active** addresses are considered; inactive ones are stale candidates.

**The rule is deliberately conservative, and the ordering matters:**

1. any active address `is_relay()` → **`Relay { url }`**
2. else any active address `is_ip()` → **`Direct`**
3. else (no active addresses, or only `Custom`) → **`Unknown`**

Relay is checked FIRST. During hole-punching both paths can be active, and the dangerous direction
is claiming `Direct` while a relay is in use — that turns reason (1), the locality claim, into a
false statement about where user data went. Reporting `Relay` when a direct path also exists merely
understates; reporting `Direct` when a relay is live is a lie. A privacy indicator must fail safe.

`Custom` maps to `Unknown` rather than being guessed at: mcpmesh does not install custom transports,
so encountering one means something we do not model.

### Where it is captured

In `probe_peer`, right after the probe, from the same endpoint the probe used. The path becomes part
of the cached `ReachEntry`, so it inherits exactly the freshness semantics of `reachable` and
`rtt_ms` — one TTL, one `age_secs`, no second staleness rule to reason about. `Unknown` then covers
"never probed" for free.

`reachability_row` (made the single `PeerReachability` constructor by #58) reads it, so the snapshot,
the `status` list, and the #58 transition event all carry it without a second code path.

**A path change alone is not a transition.** #58 emits on the `reachable` verdict flipping; a peer
that migrates relay→direct while staying up does not push a frame. Consistent with `rtt_ms`/`meta`
drift being advisory, and it keeps the stream quiet during hole-punching, which flaps by nature. A
consumer that wants the current path reads `status`, or sees it on the next real transition.

## Surface + versioning

- `PeerReachability.path: PeerPath` — additive (`#[serde(default)]`, defaults to `Unknown`).
- `API_MINOR` 12 → 13, `API_VERSION` "1.12" → "1.13".
- `docs/local-protocol.md`: the `PeerReachability` shape, the derivation rule, and an explicit
  warning that `Direct` is the only value that supports a locality claim — `Unknown` must never be
  rendered as "private".
- Workspace version → **0.13.1** (additive → PATCH).

Note: draft PR #72 (#57) is parked and claims `api_minor` 12, already taken by #58; it rebases to 14
when it lands.

## Testing (TDD, RED first)

1. **Unit (derivation rule)** — active relay only → `Relay{url}`; active IP only → `Direct`; BOTH
   active → `Relay` (the fail-safe ordering, the assertion that matters most); no active → `Unknown`;
   only `Custom` → `Unknown`; inactive relay + active IP → `Direct` (usage is honoured).
2. **Unit (serde)** — each variant tags as `{"kind":"direct"}` / `{"kind":"relay","url":…}` /
   `{"kind":"unknown"}`, and a row serialized WITHOUT `path` deserializes to `Unknown`.
3. **Integration** — a real loopback probe reports `Direct` (relays are disabled in the test
   harness, so the path is genuinely direct), and the value appears on the `status` reachability row.
4. **Regression** — the #58 transition event still fires only on a `reachable` flip, not on a path
   change.

## Out of scope

Emitting a stream event on path change (see above). Per-session path attribution — this is
per-peer, matching where `PeerReachability` already sits.
