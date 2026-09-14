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

1. `reach::classify_paths` — the structural rule gains the one inference that cannot lie: a
   connection with **exactly one open path** sends everything on it, selected or not. Several
   open, none selected stays `Unknown`. `reach::selected_path` (probes, `path_watch`) now uses it.
2. `reach::measured_path` — samples every open path's **application frames** (STREAM + DATAGRAM,
   tx + rx; PINGs/ACKs on a standby relay path do not count) over `PATH_MEASURE_WINDOW` (250ms).
   Any relay path that moved ⇒ `Relay`; else a direct path moved ⇒ `Direct`; nothing moved ⇒
   the structural reading. This is what answers the reporter's production shape (relay enabled,
   accept side, relay + direct paths, none selected): only the counters know which path noq used.
3. `Node::connection_path(&Connection) -> PeerPath` (async, additive) — `measured_path` with the
   default window. Documented in `docs/embedding.md`.

Soundness of the single-path rule: QUIC cannot send on a path the connection does not have, and
`conn.paths()` is iroh's list of the connection's open paths (`record_opened` on `Established`,
`record_abandoned` on `Abandoned`). The only lag is event delivery inside iroh's actor, which is
inside the 250ms window for the measured reading and inside `PATH_SETTLE` for probes.

Mutations run (each restored from a backup copy, not `git checkout`):

| mutation | caught by |
|---|---|
| drop the single-path rule | `a_single_unselected_path_is_where_the_bytes_go`; `connection_path_reads_direct_on_an_idle_accept_side` (both accept sides read `Unknown` at every sample) |
| relay movement not decisive | `the_path_that_moved_application_frames_carried_the_data` |
| count UDP bytes instead of app frames | `keepalives_on_a_standby_relay_path_are_not_application_data` |
| `connection_path` structural-only (no window) | `connection_path_reads_direct_on_a_busy_accept_side` (`Unknown` at t+4.96s: the hole-punch round's transient probe paths) |
| `connection_path` returns `Unknown` | both `connection_path_*` tests |

Not covered: a fixture where the structural reading is `Unknown` while the measurement says
`Direct` on a **stable** connection (relay + direct, none selected). Loopback cannot produce it
(`boot.rs` #116 note: no relay path is opened on loopback even with an in-process relay), so the
composition is pinned on synthetic samples in `classify_traffic`'s test and the busy integration
test pins that the API measures rather than snapshots.
