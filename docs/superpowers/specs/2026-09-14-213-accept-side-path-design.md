# #213 — accept-side `is_selected()` is false while traffic flows: root cause, fix, open items

Issue: [#213](https://github.com/loop-layer/mcpmesh/issues/213). Reporter: bolo (`app/bolo-media/1`
over `Node::accept_protocol` / `Node::connect_protocol`), on `mcpmesh-node =0.53.0`, `iroh =1.0.3`.

## 1. Root cause (iroh 1.0.3, confirmed)

iroh keeps **one selected four-tuple per remote endpoint**, not per connection.

- `src/socket/remote_map/remote_state.rs:154` — `State::selected_path: Option<FourTuple>` is
  endpoint-level state, shared by every connection to that remote.
- `remote_state.rs:650-673` `select_path` runs the `BiasedRttPathSelector` over the paths of
  **all** connections (`PathSelectionContext::paths`, `remote_state.rs:1329-1344`) and keeps the
  current tuple unless another is a full tier better or ≥5ms faster
  (`biased_rtt_path_selector.rs:170-190`). A second connection whose only path is a *different*
  tuple to the same remote therefore never displaces the current one.
- `remote_state.rs:682-736` `apply_selected_path`: for each connection it calls
  `open_path_on_conn` (a **no-op on the server side** — `remote_state.rs:1036-1040`: "Only the
  client opens paths"), sets every non-selected path to `PathStatus::Backup`
  (`remote_state.rs:1004-1026`), then `record_selected(&selected)`.
- `remote_state/path_watcher.rs:224-249` `record_selected` looks the tuple up **on that
  connection** by `(remote_addr, local_addr)`; no match ⇒ `state.selected = None`. That is what
  `Path::is_selected()` (`path_watcher.rs:470`) reads.
- `remote_state.rs:479-490` `handle_connection_close` does **not** re-select when a connection
  closes unless it was the last one, so a tuple that belonged to a closed connection stays
  "selected" and the surviving connection stays unmatched until the next path event.

The tuple includes the **local IP**, and a client's initial path may use any of the peer's
advertised addresses. So two connections to the same peer routinely settle on different tuples
on a host with several addresses (IPv4 + several IPv6, the reporter's single-machine case, any
macOS/Windows dual-stack LAN). The accept side can neither open the endpoint-selected tuple nor
be re-selected, so its only path sits at `Backup`, unselected, for the life of the mismatch —
while carrying every byte (noq sends on `Backup` paths when no `Available` path exists,
`noq-proto-1.1.0/src/connection/mod.rs:1189-1195`).

Reporter's theory: **confirmed**, with two refinements — (1) it is not specific to a mesh
session + app connection; any second connection to the same remote can hit it (the pairing
connection that just closed did, in the traced run); (2) the ~5s timing is
`HOLEPUNCH_ATTEMPTS_INTERVAL` (`remote_state.rs:51`): the second hole-punch round's
`Established`/`Abandoned` events are the next `select_path`, which can either heal or break the
match.

Traced on this branch (`MCPMESH_213_TRACE=1 cargo test -p mcpmesh-node --test accept_side_path
single_connection -- --ignored --nocapture`): acceptor holds selected tuple
`Ip(…::6bb2 -> […::6bb2]:59091)` from a connection that closed at 19:09:54.363; the app
connection added at 19:09:54.383 has PathId(0) = `Ip(…:16d5 -> […:16d5]:59091)`; `select_path`
logs `keeping current path`; `is_selected()` is false until the 5s hole-punch round.

## 2. iroh 1.2.0 and upstream status

`diff iroh-1.0.3 iroh-1.2.0` for `remote_state.rs` is renames/comments only (`MappedAddrs`
refactor, `path_remote` → `path_fourtuple`); `path_watcher.rs` is byte-identical. The selector is
unchanged. **1.2.0 does not change this.** 1.2.0 adds a comment on `ConnectionState::paths`
acknowledging the local-IP-in-the-tuple subtlety but no behaviour change.

Measured on 1.2.0 after rebasing onto 0.53.2 (`--ignored`): `two_connections_opposite_directions`
had both accept sides unselected for 28 of 77 samples (clients 0); the single- and same-direction
cases passed that run. The defect is present in 1.2.0.

Upstream: [n0-computer/iroh#4303](https://github.com/n0-computer/iroh/issues/4303) "Opening
multiple connections to the same endpoint results in an invalid(?) path state" (OPEN, `bug`) is
the same mechanism — second connection reports `selected: None` on both sides. Maintainer comment
says it "works on main" after #4296 (in 1.0.0+); our measurement on 1.0.3 shows the **accept-side**
case persists. Not filed separately for the accept side; a follow-up comment on #4303 with the
trace above and the `two_connections_opposite_directions_accept_sides_stay_selected`
reproduction is the right upstream action. A candidate upstream fix: in `apply_selected_path`, when
`selected` is absent from a **server-side** connection, select that connection's best path by
the same selector (per-connection fallback) instead of recording `None` and leaving every path
`Backup`.

## 3. Reproduction (`node/tests/accept_side_path.rs`, `#[ignore]`d, iroh 1.0.3)

Two `NodeBuilder` nodes, `relay_mode = "disabled"`, paired via the control API; app-protocol
connections with datagrams both ways; `conn.paths()` sampled every 100ms for 8s.

```
single_connection_accept_side_stays_selected
  t+0.000s server ["0:Ip([2601:…::6bb2]:61078)<-Ip(Some(2601:…::6bb2)):selected=false"]
  t+0.000s client ["0:Ip([2601:…::6bb2]:61758)<-Ip(Some(2601:…::6bb2)):selected=true"]
  t+5.005s server ["0:Ip([2601:…::6bb2]:61078)<-Ip(Some(2601:…::6bb2)):selected=true"]
  samples=79 unselected=[("server", 49), ("client", 0)]                         FAILED
two_connections_opposite_directions_accept_sides_stay_selected
  a-server1 selected=false, b-client1 true, b-server2 false, a-client2 true — for all 8s
  samples=79 unselected=[("a-server1", 79), ("b-client1", 0), ("b-server2", 79), ("a-client2", 0)]  FAILED
two_connections_same_direction_accept_sides_stay_selected
  samples=79 unselected=[all 0]                                                  ok
```

Whether a run hits the defect depends on which host address each connection's initial path
lands on (an earlier run of the single case started on IPv4, switched to IPv6 at t+5.0s on both
sides, and passed). The tests are `#[ignore]`d for that reason and because they fail by design
on 1.0.3; run with `--ignored` to re-measure after an iroh upgrade.

## 4. mcpmesh's own `path_watch` (issue's "why this is not just our problem")

**Affected, by construction.** `daemon/path_watch.rs` acts only on `PathEvent::Selected`.
`record_selected` emits `Selected` only when the connection's selected id *changes to Some*
(`path_watcher.rs:234-240`); on a mismatched accept-side connection it never does, so a mesh
session accepted in that shape emits no `Reachability { source: Session }` frame for any change
that does not happen to re-match the endpoint tuple. The opposite-directions reproduction is
exactly the accept-side shape `accept.rs:122` spawns the watcher on.

Not fixed in this change, deliberately:

- Acting on `Opened`/`Closed` or taking an initial reading at spawn would help **only** when the
  mismatched connection has exactly one path (relay disabled). With a standby relay path plus a
  direct path and nothing selected, the structural reading is `Unknown`, `decide` drops it, and
  nothing is emitted either way.
- Both variants re-read during the hole-punch, where a >600ms punch settles on `Relay` and then
  flips to `Direct` — a spurious relay frame at the start of every slow dial, the flap #92
  excluded on purpose. That is a product-visible tradeoff, not a contained fix.

Options, for a decision: (a) wait for the upstream fix (the watcher is correct once `Selected`
fires per connection); (b) drive the watcher from `measured_path` on a timer (e.g. every 2s while
the session lives) instead of from events — honest and complete, at the cost of one counter read
per session per tick; (c) initial reading + `Opened`/`Closed` with a longer settle window.
Recommendation: (a) now, (b) if the upstream fix does not land within a release or two.

## 5. The shipped fix (this branch)

1. `reach::classify_paths` — the structural rule gains one inference: a connection with
   **exactly one open path** sends everything on it, selected or not. Several open, none selected
   stays `Unknown`. `reach::selected_path` (probes, `path_watch`) uses it. It does **not** check
   `close_reason()`: a probe classifies a connection the ping responder closes right after the pong,
   and a close check there made every relayed peer's probe `Unknown` (round-3 review, measured
   10/10) — pinned by `peer_path.rs` `a_probe_of_a_relay_only_peer_reports_the_relay`.
2. `reach::measured_path` — per window (`PATH_MEASURE_WINDOW`, 250ms), through the `WindowSource`
   seam: subscribe to `conn.path_events()`, sample every open path's **application frames** (STREAM
   + DATAGRAM, tx + rx; PINGs/ACKs on a standby relay path do not count), drain events for the whole
   window, sample again, drain what is already queued. iroh's `PathEvent` is projected one-to-one
   into `ObservedEvent` (no policy); `WindowEvent::from_observed` drops only `Selected` and keeps
   `Lagged` and unrecognised variants. `classify_window` relies on iroh adding a path to the list
   before sending `Opened` and removing it before sending `Closed`:
   - a path in `before` moved by (its `after` count or `Closed { last_stats }`) − baseline;
   - a path with an `Opened` event moved by its whole count;
   - a `Closed` with no baseline and no `Opened` was removed BEFORE the baseline → ignored
     (round 4: counting its lifetime read a pre-window close as live traffic);
   - any relay path moved ⇒ `Relay`; `Lagged`/unrecognised event, a moving unmodelled path, or a
     path in `before` or `Opened` that is neither in `after` nor `Closed` (round 4: an opened path
     whose `Closed` has not arrived) ⇒ unobservable; else a direct path moved ⇒ `Direct`; nothing
     moved ⇒ the structural reading;
   - the event stream ending while the window is open, or a closed connection ⇒ unobservable.

   `combine_windows` answers `Moved`/known `Idle` at once, answers `Unknown` at once on an
   unobservable window (so a window that may have carried relayed frames is never followed by
   `Direct`), and retries only `Idle(Unknown)`, up to `PATH_MEASURE_WINDOWS` (3, compile-time
   asserted > 1). This is what answers the reporter's production shape (relay enabled, accept side,
   relay + direct paths, none selected): only the counters know which path noq used.

   **Best-effort, not a guarantee** (documented on `Node::connection_path` and in
   `docs/embedding.md`, with the advice to treat `Direct` as advisory and re-check during a call):
   noq can send on a newly validated path before iroh's actor records it, and iroh's actor can drop
   a noq path event (`remote_state.rs` `Lagged` arm, no recovery). Frames in either gap are
   attributed to no path.

   The round-2 design cross-checked `Connection::stats()` against the per-path sum. Round-3 review
   measured that as unsound: per-path and connection stats are read under separate noq lock
   acquisitions, so frames landing between them masked real movement in 21–25% of windows under
   load (a relay path closing mid-window read `Direct`) and invented it in 34–35%. Reversing the
   read order removes the masking but makes a busy connection `Unknown` about half the time. Path
   events replace it: they are an exact per-path record.
3. `Node::connection_path(&Connection) -> PeerPath` (async, additive) — `measured_path` with the
   default window. Documented in `docs/embedding.md`.

Soundness of the single-path rule: "open path" is iroh's list of the connection's validated paths
(`record_opened` on `Established`, `record_abandoned` on `Abandoned`), which is complete unless
iroh's actor lagged — `remote_state.rs` `handle_path_event`'s `Lagged` arm drops the event with no
recovery, so a path can in principle be missing from the list. Event delivery lag is otherwise
inside the 250ms window for the measured reading and inside `PATH_SETTLE` for probes.

Mutations run (each restored from a backup copy, not `git checkout`):

| mutation | caught by |
|---|---|
| drop the single-path rule | `a_single_unselected_path_is_where_the_bytes_go`; `connection_path_reads_direct_on_an_idle_accept_side` |
| count UDP bytes instead of app frames; add `frame_tx.path_acks` | `keepalives_on_a_standby_relay_path_are_not_application_data` (every non-app counter seeded) |
| ignore `Closed` events | `a_relay_path_that_closed_mid_window_is_attributed_from_its_closed_event`, `a_relay_path_that_opened_mid_window_and_carried_frames_is_relay`, both scripted-source ordering tests |
| count a no-baseline, no-`Opened` `Closed` (pre-window close) | `a_close_from_before_the_window_is_not_traffic` |
| ignore an `Opened` path that disappeared | `a_path_opened_in_the_window_that_disappeared_is_unobservable` |
| ignore a `before` path that disappeared | `a_path_that_vanished_without_a_closed_event_is_unobservable` |
| `Lagged` ⇒ `None`; unrecognised ⇒ `None` (in `from_observed`) | `every_path_event_kind_has_an_explicit_policy` |
| ignore `Lagged`/unrecognised in classification | `lagged_path_events_make_the_window_unobservable`, `every_path_event_kind_has_an_explicit_policy` |
| subscribe AFTER the baseline sample | `the_subscription_is_taken_before_the_baseline` (scripted source) |
| no final drain after the last sample | `events_queued_after_the_final_sample_are_drained` (scripted source) |
| stream end mid-window treated as a shorter window | `an_event_stream_that_ends_early_is_unobservable` |
| retry on `Moved(Direct)`; retry after an unobservable window | `only_an_idle_unknown_window_is_retried` |
| `PATH_MEASURE_WINDOWS = 1` | compile error (const assertion) |
| re-add `close_reason` check to `selected_path` | `a_probe_of_a_relay_only_peer_reports_the_relay` (`Unknown` vs `Relay { url }`) |
| drop `close_reason` checks from the measured reading | `connection_path_reads_unknown_on_a_closed_connection` (`Direct` vs `Unknown`) |
| `connection_path` returns `Unknown` | both `connection_path_reads_direct_*` tests |

The two `connection_path_reads_direct_*` integration tests assert the property #213 is about, not
"every sample is Direct" (a single `Unknown` during iroh's hole-punch round is inside the contract):
never `Relay` with relays disabled; `Direct` for ≥ 80% of readings and on the last one; no run of
non-`Direct` readings spanning more than 1.5s. Every non-`Direct` reading is printed with the
connection's path list (`id:kind:selected`) before and after it.

Their fixture seeks the #213 shape: fresh node pairs, three at a time, up to two batches, keeping the
first whose accept sides are BOTH unselected across three checks (measured on iroh 1.2.0: a fresh
pair reaches it in ~1 of 3 trials; redialing on the same nodes reaches it only on the first dial).
Measured discrimination, not assumed: `connection_path ⇒ Unknown` fails both tests; dropping the
single-path rule failed the idle test in exactly the runs whose fixture reached the shape (2 of 4 —
the other two reached it in none of their six pairs; misses cluster, which points at host address
state no harness knob controls). A run that misses says so (`FIXTURE: did NOT reach`). **The unit
tests are the real pin**; the integration tests prove the API reads a real accept side in the #213
shape when the host produces it.

Not covered by any test: the `From<iroh::endpoint::PathEvent> for ObservedEvent` projection. iroh
marks every `PathEvent` variant `#[non_exhaustive]`, so no code outside iroh can construct one
(E0639, checked); the projection is kept policy-free so a mistake there is a mis-wiring, not a
policy error. Draining events only at the end of the window instead of during it (a `Lagged` rate
question, safe direction). A fixture where the structural reading is `Unknown` while the
measurement says `Direct` on a **stable** connection (relay + direct, none selected): loopback
cannot produce it (`boot.rs` #116 note), so that composition is pinned on synthetic samples.

A stated residual: attribution is as complete as iroh's own path events. A path whose noq
`Established`/`Abandoned` event iroh's actor dropped (`remote_state.rs` `Lagged` arm) never enters
the path list and never produces a `Closed`, so frames on it are invisible to both readings.
