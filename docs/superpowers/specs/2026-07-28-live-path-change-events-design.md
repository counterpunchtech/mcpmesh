# Live path-change events (#92 item 2)

**Status:** accepted · **Issue:** #92 item (2) · **Target:** 0.20.0 (surface change → MINOR)

## Problem

#92 item (1) shipped in 0.19.0: `is_transition` now compares `path` as well as `reachable`, so a
probe that observes a changed path emits a `Reachability` frame. That removed "no event, ever".

It did not give **live** signal. The event fires only when something probes, and probes are
TTL-gated (`REACH_TTL_SECS` = 20) and only run when `reachability_of` is called by `status` or
`subscribe`. So a session that degrades Direct→Relay mid-call is silent until something asks —
possibly never.

That matters because mcpmesh documents `path` as a **truth claim**, not drift: `Direct` is the only
value supporting a locality claim, and rendering `Unknown` as private is "the one misuse that turns
this field into a false privacy statement". An embedder can render the indicator correctly at dial
time and have it silently become wrong for the rest of a long-lived session. For a call, that is a
privacy indicator that lies partway through.

## Approach — one watcher per admitted connection

iroh 1.0.3 exposes a per-connection watcher. The accept path already holds a `Registration` RAII
guard for exactly the connection's lifetime (`net/src/registry.rs:64`), which is the seam: spawn the
watcher alongside it, and let it end when the connection does.

### Use `path_events()`, NOT `paths_stream()`

The issue names `paths_stream()`. That is the wrong one, and the difference is load-bearing —
verified against iroh 1.0.3's source, not assumed:

| | `paths_stream()` | `path_events()` |
|---|---|---|
| yields | `PathList` snapshots | individual `PathEvent`s |
| borrows the `Connection` | **yes** (`PathListStream<'_>`) | **no** (`PathEventStream`) |
| spawnable | only by moving a `Connection` clone in and calling it *inside* the task | directly |

`paths_stream()` borrowing means a watcher task built on it needs a cloned `Connection` held for the
task's life — which keeps the connection alive and defeats the "dies with its connection" property
test 6 exists to prove. `path_events()` is documented as movable into a spawned task and its stream
**ends when the connection closes**, which is exactly the lifetime contract we want.

`PathEvent::Selected { remote_addr, .. }` fires precisely on "this path was selected for
transmission of application data" — the same `is_selected()` semantics #64 settled on — so the
watcher filters for that variant and maps `remote_addr` through the existing classification, rather
than diffing snapshots.

**`PathEvent::Lagged { missed }` must be handled.** A watcher that ignores it silently misses the
transition it exists to report. On `Lagged`, re-read `Connection::paths()` (iroh documents the
current selected path as recoverable there) and treat the result as an observation. Dropping the
event because "we'll catch the next one" is how a privacy indicator stays wrong — there may be no
next one on a stable connection.

```
accept → trust gate → register_checked → Registration (RAII)
                                       └→ spawn path watcher (ends when the stream ends)
```

The watcher observes selected-path changes and, on a **settled** change, updates the reachability
cache and emits `StreamFrame::Reachability` — the same frame `status` and the probe path already
produce.

### BOTH directions, or the reported use case stays broken

There are **two** connection seams, and the issue's framing only implies one:

| direction | seam | lifetime holder |
|---|---|---|
| inbound | `gate_and_register` (`node/src/daemon/accept.rs:33`) — the single gate for ALL gated ALPNs | `Registration` RAII |
| outbound | `mcpmesh_net::connect` (`net/src/endpoint.rs:490`), via `connect_with_timeout` (`node/src/daemon/dial.rs:173`) | the returned `SessionTransport` |

**The outbound seam requires a `mcpmesh-net` surface change.** `connect` returns only
`SessionTransport` — an alias for `NdjsonTransport<RecvStream, SendStream>`, i.e. the QUIC streams
— and DROPS the `Connection` at `endpoint.rs:497`. Nothing upstream can call `path_events()` on it.
`connect` must return the connection alongside the transport. That is a **BREAKING change to a
published crate**, which `RELEASING.md` makes MINOR on its own; 0.20.0 is already MINOR, so it adds
no version cost, but it is an embedder-visible break and belongs in the release notes rather than
being discovered on a `cargo update`.

The watcher stays in `node`, not `net`: net has no knowledge of the reachability cache, and pushing
it down would mean plumbing a callback through net for one caller's benefit.

Installing the watcher only at the accept path would cover sessions *others* open to us and miss
every session *we* open. That is backwards for the reported use case: an embedder rendering a
privacy indicator for a call it initiated is on the **outbound** path. Shipping inbound-only would
close the issue while leaving the motivating scenario silent — a fix that reads as done and is not.

Both seams install the same watcher. The inbound one ties to `Registration`; the outbound one ties
to the session transport. Neither needs a new lifetime concept, because `path_events()` ends when
its connection closes.

**Probe connections are deliberately excluded.** `probe_peer`'s 600ms connection (`reach.rs:327`)
already classifies its own path and writes the cache through the ticket discipline; attaching a
watcher to it would double-write the same observation and emit a frame for a connection that exists
only to measure. The pairing (`rendezvous.rs:517`) and app-blob (`provider.rs:446`) dials are
likewise out of scope — they are not user sessions and their path carries no privacy claim.

### Per-peer, not per-session — and the collapse is real

`PeerReachability` is keyed per peer. A connection is per session, and two concurrent sessions to
one peer can sit on different paths, so a per-connection watcher feeding a per-peer frame
**collapses** them: last writer wins, and the reported path is one session's, not the peer's.

Emitting per-peer anyway, for two reasons: it matches every existing consumer of `Reachability`,
and the reachability cache it must stay coherent with is itself per-peer. Inventing a per-session
frame now would fork the model and duplicate #73's unfinished work (`ActiveSession` carries no
stable principal). **Documented as a known limit**, not glossed: with multiple sessions to one peer,
`path` reports the most recently observed session's path.

When #73 lands a stable principal on `ActiveSession`, per-session path belongs there, in one wire
bump, as #92's own filing suggests.

### Cache coherence is the hazard, not the emission

The watcher must write `MeshState::reachability`, or `status` and the stream disagree — the exact
class of defect #58 hit and the reason `reachability_row` became the single constructor.

It must take a `probe_seq` ticket **before** observing, exactly as `probe_peer` does, and commit
under the same `supersedes` check. Without that, an in-flight 3s probe that started earlier can
land later and overwrite a fresher live observation, re-poisoning the cache for a full TTL. The
ticket discipline already exists; this is a second writer joining it, not a new mechanism.

The watcher updates `path` only. `reachable`/`rtt_ms`/`meta`/`services` come from a probe's pong and
have no meaning here; a live connection carrying data is evidence of reachability, but inventing an
`rtt_ms` from a path event would be a fabricated measurement. On a watcher update with no cache
entry yet, seed one with `reachable: true` (a live admitted connection **is** reachability
evidence) and `rtt_ms: None`.

### Debouncing, and why the existing window is not enough

Hole-punching flaps by nature — that was #64's stated reason for excluding `path` from transitions
in the first place. `PATH_SETTLE` (600ms) damps it inside a probe, but a `paths_stream()` watcher
sees every change, including the relay→direct transition of a healthy dial.

The watcher applies its own settle window: on observing a change, wait `PATH_CHANGE_SETTLE`
(600ms, reusing `PATH_SETTLE`'s value and rationale) and re-read; emit only if the new value still
holds and still differs from what the cache reports. A path that flaps and returns emits nothing.

This is deliberately **not** a general debouncer with a queue — one pending change per connection,
coalesced. A flapping connection produces at most one frame per settle window.

## Surface + versioning

- No new `StreamFrame` variant. `Reachability` gains a live producer.
- **`StreamFrame::Reachability`'s doc comment is currently FALSE** and is corrected in this change:
  `local-api/src/protocol.rs:1020` still says "Emitted on a CHANGE of `reachable` only", which
  stopped being true in 0.19.0 when item (1) added `path`. A consumer reading it would treat
  same-verdict frames as impossible.
- `API_MINOR` 21 → 22, `API_VERSION` "1.21" → "1.22": a consumer can now receive `Reachability`
  frames that no probe produced, at a cadence probes never had.
- Workspace → **0.20.0** (behaviour change → MINOR).

Release note, explicitly: consumers treating every `Reachability` frame as an up/down toggle will
see same-verdict frames. Item (1) already introduced that in 0.19.0; this raises the rate.

## Explicitly NOT here

Per-session path (needs #73's stable principal — one wire bump, not two). A `PathChanged` variant
distinct from `Reachability` (forks the model for no consumer benefit). Changing probe cadence or
the TTL. Emitting on *open-path* changes rather than selected-path changes — only the selected path
carries data, which is #64's whole finding.

## Testing (TDD, RED first)

The infrastructure #110 just landed is what makes these testable: `iroh::test_utils::run_relay_server()`
plus the hold-ONE-connection pattern, proven green on Linux, macOS and Windows. Sampling fresh
probes cannot observe a live transition by construction.

1. **Integration — a live relay→direct transition emits a frame.** Hold one connection, subscribe,
   force the dial to start relayed (relay-only `last_addr`), and assert a `Reachability` frame with
   `path: Direct` arrives WITHOUT any probe running. This is the issue; it fails today.
2. **Integration — `status` agrees with the frame that was just pushed.** Read `status` after the
   event and assert the same `path`. Fails if the watcher emits without writing the cache — the
   #58 defect class.
3. **Unit — a flap inside the settle window emits nothing.** Drive the settle logic over a closure
   (the `settle` seam #110 added): Direct→Relay→Direct within the window produces no emission.
   Fails if the watcher emits on raw stream events.
4. **Unit — an older probe does not overwrite a newer watcher observation.** Ticket ordering, the
   `supersedes` rule, with the watcher as one of the two writers. Fails if the watcher commits
   without a ticket.
5. **Unit — the watcher seeds a missing cache entry as reachable** with `rtt_ms: None`, and never
   fabricates an RTT.
6. **Regression — the watcher task dies with its connection.** Close the connection and assert the
   task ends (no leaked task, no cache writes afterwards). #61 cost a release to a detached task
   holding a lock; a per-connection task is exactly that shape and must be proven bounded. This is
   also why `path_events()` is required over `paths_stream()`: the latter's borrow forces a
   `Connection` clone into the task, which would keep the connection alive and make this test
   unpassable by construction.
8. **Unit — a `Lagged` event is not dropped.** Feed `PathEvent::Lagged` and assert the watcher
   re-reads current state rather than skipping. Fails if the match arm is a silent `continue` —
   the failure mode where the one transition that mattered is the one that was missed.
7. **Regression — a peer with no path change produces no frame**, so a healthy long-lived session
   stays quiet.
9. **Integration — an OUTBOUND session emits too.** Same as test 1 but with the local node dialing
   the peer rather than accepting from it. This is the motivating scenario, and an inbound-only
   implementation passes test 1 while failing this one — which is precisely the "reads as done, is
   not" outcome the design section warns about.
10. **Regression — a probe connection emits NOTHING.** Run `probe_peer` against a peer with no user
   session and assert no frame is pushed beyond the probe's own transition. Fails if the watcher
   was attached indiscriminately to every `connect`.
