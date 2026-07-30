# Self-network state on `status`, and a SelfNetwork stream frame (#90)

Date: 2026-07-30. Scope: the full ask minus per-relay RTT (blocked on iroh's unstable
`net_report` API — noted on the issue).

## Problem

Every reachability signal in the API is about a peer. A node newly behind CGNAT, a captive
portal, or a total relay outage has no signal of any kind that IT is unreachable — `status`
returns a clean payload throughout, and `set_relays` (#53) has no signal telling anyone to use
it. The information exists in-process (`endpoint.online()` is already awaited on the invite
path) but `mesh()` is private to embedders.

## Design

All stable-API point reads; no `unstable-net-report` feature.

### Wire types (`API_MINOR 27 → 28`, additive → PATCH `0.23.5 → 0.23.6`)

```
SelfNetwork {
  online: bool,                  // any home relay connection established (iroh's own semantics)
  home_relay: Option<String>,    // the CONNECTED home relay, sanitized (scheme+host+port)
  relays: [{ url, connected }],  // every known home relay and its connection state
  direct_addrs: [String],        // this endpoint's direct socket addresses (own info; invites
                                 // already carry them)
  last_change_epoch: Option<i64> // when the watcher last saw the block change; None before
}                                // the first observed change
```

- `StatusResult.self_network: Option<SelfNetwork>` — additive; `None` in control-only mode.
- `StreamFrame::SelfNetwork { self_network }` — pushed on a CHANGE of `online`, `home_relay`,
  or the relay set/connection states (`direct_addrs` drift alone does not emit: address churn
  is chatty and not a decision point; it rides the next frame).
- `StreamFrame::Snapshot` gains `self_network: Option<SelfNetwork>` (additive) so a fresh
  subscriber renders without a poll.

**`online` semantics stated, not implied**: it is iroh's definition — a home relay connection
exists. In `relay_mode = "disabled"` it is always `false` and the relay list is empty; that is
truthful (WAN reachability via relay is not configured), documented, and NOT a health warning.
Relay URLs are sanitized with the existing `sanitize_relay_url` (operator-supplied URLs can
carry userinfo tokens; `status` output gets screenshotted).

### Mechanics

- `status`: computes the block LIVE off `endpoint.home_relay_status().get()` +
  `endpoint.addr()` (both non-blocking point reads), merging `last_change_epoch` from the
  watcher's stored state on `MeshState`.
- A boot watcher task (the `path_watch` idiom, in `daemon/self_net.rs`) loops on
  `home_relay_status().updated()`, projects the block, compares against the previous
  projection, and on change: stamps `last_change_epoch` on `MeshState` and broadcasts on a new
  `self_net_bcast` ring (`subscribe` merges it as a third tap alongside audit + reachability).
  The projection is a pure function over `(url, connected)` pairs + addresses, unit-testable
  without constructing iroh's `RelayStatus`.

## Tests (mutation-verified)

- e2e with a REAL in-process relay (`iroh::test_utils::run_relay_server`, the `peer_path.rs`
  harness): a relay-enabled node's `status.self_network` reports `online: true`, the relay's
  sanitized URL as `home_relay`, and `connected: true` in `relays`; a `relay_mode = "disabled"`
  node reports `online: false`, empty `relays`, non-empty `direct_addrs`.
- Stream: a subscriber sees the offline→online `SelfNetwork` frame when the endpoint connects
  to the relay after subscribe; the snapshot carries the block. Mutations: drop the change
  comparison (emit always) → frame-count assertion fails; drop the broadcast → no frame.
- Sanitization unit: a `https://user:token@relay/` home relay renders without the token.
- `last_change_epoch`: None before any change, set after the first observed transition.

## Non-goals (noted on #90)

Per-relay RTT / latency (`net_report` is `unstable-net-report`-gated in iroh 1.0.3 — revisit
when stabilized), captive-portal detection, automated relay failover (#53 remediation stays
operator-driven — this issue only supplies the missing signal).
