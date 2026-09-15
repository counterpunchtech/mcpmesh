# #215: one client connection per remote — design

Date: 2026-09-14
Issue: #215 (`Long-lived node reaches 6.3 GB and 70% of a core on macOS: iroh#4390's unbounded
pending_open_paths, unfixed in every released iroh`)
Release: 0.54.0 (**MINOR** — see Versioning). Nothing in this document is shipped yet; it is the
design and the judgement the reply to #215 rests on.

## The problem, restated in our terms

iroh#4390: `State::open_path_on_conn` (`iroh-1.0.3/src/socket/remote_map/remote_state.rs:1029`)
re-queues an address onto `pending_open_paths` every time `open_path_ensure` fails with
`RemoteCidsExhausted` or `MaxPathIdReached`. The 333 ms retry (`remote_state.rs:307`) drains the
queue and calls `open_path_on_all_conns` for each entry, which tries the address on **every**
connection to that remote (`remote_state.rs:738`). Each failing connection pushes the same address
back. No dedup, no cap.

So the multiplier is **K = the number of live client-side connections to one remote on which the
open fails**. `open_path_on_conn` returns at once for a server-side connection
(`remote_state.rs:1038`), so connections *accepted* from a peer never count. At K = 1 the queue is
steady (drain N, requeue N). At K ≥ 2 it doubles per tick.

The reporter's question 2 is therefore the right one: does mcpmesh-node ever need more than one
client connection to a remote? The inventory below says no — for MCP sessions it never did, and the
accept side has multiplexed sessions on one connection since 0.1.0. The dial side simply never
used that.

## Connection inventory

Every `Endpoint::connect` in `net/src` and `node/src`, excluding `#[cfg(test)]` bodies
(`handlers.rs:4367` and `:4473` are inside tests and dial a loopback fixture; `boot.rs:1527` is a
test of the relay-only selector). All of these are **client-side** connections — the accept side
(`node/src/daemon/accept.rs`) is where the peer's dials land, and those are server-side on us.

| Site | ALPN | Trigger | Lifetime | Counts toward K? |
|---|---|---|---|---|
| `net/src/endpoint.rs:576` via `node/src/daemon/dial.rs:570` (`connect_with_timeout` → `dial_service_with_idle_timeout`, `dial_by_eid`, `race_dial`/`dial_one`) | `mcpmesh/mcp/1` | **One per `open_session`** — one per `mcpmesh connect` process, one per embedder session. `connect` + `open_bi` = one connection carrying exactly one bi-stream. | Until the session ends: `pipe_session` returns → `SessionTransport` dropped → last strong handle dropped → noq closes implicitly (error code 0, `noq-1.1.0/src/connection.rs:298`, `ConnectionRef::drop` → `implicit_close`). `path_watch::spawn` holds only a `WeakConnectionHandle`. | **Yes, sustained**, one per concurrent session to that peer. |
| `node/src/daemon/reach.rs:484` (`probe_once`) | `mcpmesh/ping/1` | Per probe. A probe runs only when `status` / `subscribe` (`control.rs:515`, `:1419` → `reachability_of`) or `peer_services` (`handlers.rs:1508` → `probe_peer_cached`) reads a cache row older than `REACH_TTL_SECS = 20`. One in flight per peer (`InFlight` claim, #176). No timer of its own: **no poll, no probe.** | Dial → ping → pong (bounded by `PROBE_TIMEOUT = 3s`) then `settled_path` (≤ `PATH_SETTLE = 600 ms`, returns at once on `Direct`), then the `Connection` goes out of scope in `classify` and closes implicitly. Typical LAN-direct life ≈ 100–300 ms; worst case ≈ 3.6 s. | **Yes, transient**: ≤ 3 per minute, each alive ≤ 3.6 s. |
| `node/src/node.rs:431` (`Node::connect_protocol`) | embedder's | Per embedder call — for bolo, one per media call (`app/bolo-media/1`). | Whatever the embedder does with the returned `Connection`. | **Yes, sustained for the embedder's own lifetime.** mcpmesh cannot pool this: the ALPN is negotiated at handshake, so an app-protocol connection can never share the mesh connection. |
| `node/src/blobs/provider.rs:1212` (`race_a_connection`) | `APP_BLOB_ALPN` | Per blob fetch (`blob_fetch`, roster distribution `roster/transport.rs:453`, `distribute.rs:174`). Hedged: the first source is never delayed, so a live publisher yields exactly one connection. | Consumed by `transfer_from`; dropped when the transfer ends. Losing hedged dials are dropped when the flight is. | **Yes, transient**, and to whichever peer serves the blob — normally not the session peer. |
| `node/src/pairing/rendezvous.rs:1218` (`redeem_invite`), `:2401` (`attest_to`) | `mcpmesh/pair/1` | One per pairing / attestation ceremony. | Closed with `b"done"` (`rendezvous.rs:2500`) or dropped on error. | One-shot. Irrelevant to a paired peer's steady state. |

### K for the shape the issue asks about

An idle node, **one paired peer, one live mcpmesh session**, a 60-second window:

- **Sustained K = 1** — the session's connection, on the side that dialled it. On the peer that
  accepted it, that same connection is server-side and does not count.
- **Transient K = 2** for the life of a probe, at most 3 times per minute, only while something
  polls `status`/`subscribe`/`peer_services`. Each probe holds a second client connection for
  ≈ 0.1–3.6 s, i.e. 1–11 of iroh's 333 ms retry ticks. Nothing polling → **K = 1 flat**.
- The probe connection leaves the fan-out set as soon as it dies: `Connection` drop → noq
  `implicit_close` → the `OnClosed` future in `connections_close` resolves →
  `handle_connection_close` removes the `ConnId` from `connections` (`remote_state.rs:473-490`).
  `open_path_on_all_conns` iterates only `self.connections`, and skips any entry whose weak handle
  no longer upgrades (`remote_state.rs:740`). So a dead connection is never retried on.
- A transient connection contributes to the multiplier only if *its own* `open_path_ensure`
  fails during its short life. The reporter's trace shows exactly that happening — the same
  `open_addr` requeued from two `ConnId`s within 300 µs, two minutes after boot — so "short-lived"
  is not "harmless". It is bounded: each K = 2 tick at most doubles the queue, and K = 1 between
  probes holds the level rather than shrinking it, so probe windows ratchet.

For **bolo's normal shape** the numbers are worse and are the ones that matter:

- Two concurrent `bolo-mcp --peer` sessions to one peer = **K = 2 sustained** (one connection per
  `open_session`), which is what the reporter saw.
- A media call adds the `app/bolo-media/1` connection on the caller's side: **K = 3**.
- A probe on top: **K = 4** peaks.

The Linux peer's `VmHWM == VmRSS` control fits: it is mostly the *accepting* side, so its K is
close to 0 and the loop has nothing to fan out over.

### What is deliberately NOT counted

The reporter's "`Established`/`Abandoned` bursts every ~27 s" and the ~26 path ids/min burned on
the long-lived connection are iroh's own path lifecycle (`check_connections` on
`UPGRADE_INTERVAL = 60s`, holepunch retries, macOS temporary-IPv6 churn on the local side). No
mcpmesh code opens or abandons paths. That supply of `RemoteCidsExhausted` is what any K ≥ 2 turns
into growth, and nothing below removes it.

## Upstream state (verified 2026-09-14)

- **iroh#4390** open since 2026-07-03. Author `cbenhagen` posted the dedup + cap hot-fix they run
  on their fleet. Second report from iOS (`danscan`, iroh-ffi 1.0.0, hard abort under memory
  pressure, trigger: pooled connections briefly doubled on a network roam). No maintainer comment.
- **iroh#4522** (`fix(iroh): bound and deduplicate pending_open_paths`, `fcttechnologies`, opened
  2026-09-10, base `main`, not draft). Shape: (1) `pending_open_paths` bounded at 64 with dedup,
  oldest dropped at the bound, queueing centralised in `State::queue_pending_open_path`; (2)
  `open_path_on_conn` returns an `OpenPathOutcome` and the *caller* queues the address once per
  loop — the address is retried, not the connection, so K failures cost one entry; (3) a
  connection that reports `MaxPathIdReached` sets `ConnectionState::max_path_id_reached` and is
  skipped thereafter. Three unit tests on `State`. **Review status: `REVIEW_REQUIRED`, zero
  reviews, zero comments, no milestone, no labels.** The author runs it as a `[patch.crates-io]`
  over 1.0.3 on macOS and iOS and asks two questions of the maintainers (is 64 right; is
  skip-forever on `MaxPathIdReached` right).
- **Released iroh**: `v1.2.0` (2026-09-11) is the latest. Its `remote_state.rs` still has the bare
  `self.pending_open_paths.push_back(open_4tuple.clone())` at line 1063; `main` has it at
  line 1083. **There is no fixed release to bump to**, and 1.2.0 is not a fix.
- Earlier attempts #4398 and #4414 were closed unmerged, per the issue.

## Patch propagation — the fact that decides question 1

The Cargo reference (`overriding-dependencies.html`, "The `[patch]` section"): *"`[patch]` is
applicable transitively but can only be defined at the top level, so the consumers of my-library
have to repeat the `[patch]` section if necessary."*

A `[patch.crates-io]` in mcpmesh's workspace `Cargo.toml` rewrites the graph **of that workspace's
builds only**: the `mcpmesh` CLI binary and our own tests. A downstream crate that depends on
`mcpmesh-node = "=0.53.0"` from crates.io resolves `iroh 1.0.3` from crates.io — our patch table
is not published with the crate and would not apply if it were. Only bolo's own root `Cargo.toml`
can patch bolo's iroh, and the reporter has said plainly they will not do that.

So "carry a patch" splits the two things we ship: a CLI that has the fix and a library that does
not, with the same version number. That is worse than either alternative.

## Options

### A. Per-remote client connection reuse (dial side only)

A small cache in `MeshState`, keyed by `(EndpointId, ALPN_MCP)`, holding a
`WeakConnectionHandle`. `dial_service_with_idle_timeout` consults it before any dial: an entry
whose handle upgrades and whose `close_reason()` is `None` gets a fresh `open_bi` and returns a
`SessionTransport` on the existing connection. Otherwise it dials as today and records the
winner. **Sessions that carry a per-session transport config (#166 `idle_timeout_secs`) are never
pooled** — `ConnectOptions::with_transport_config` is per connection, so a session that asked for
its own idle timeout gets its own connection, and the #166 contract is unchanged.

Weak, not strong: the connection lives exactly as long as some session holds it and dies with the
last one, as today. No idle connection is kept warm, no new keepalive semantics, no "pooled
connection the peer closed an hour ago" — a stale handle fails to upgrade or fails `open_bi`, and
the dial falls through to a fresh connection.

- **K becomes**: 1 sustained per peer for any number of concurrent MCP sessions. Probe transients
  unchanged (see B). App-protocol connections unchanged — they cannot share (different ALPN).
- **On the wire**: nothing. `run_mesh_connection` has looped `while let Ok((send, recv)) =
  conn.accept_bi().await` since 0.1.0 (`net/src/endpoint.rs:350`, "a connection may carry
  several"), so every deployed peer already accepts this. Service selection is per stream, and the
  live-registry read per session (#54) already assumes several sessions per connection.
- **Embedders / pub API**: `open_session` is unchanged in signature and in what it returns. What
  changes is observable only as topology: a second session to the same peer no longer produces a
  second QUIC connection (the peer sees one accept, not two), and a connection-level event (idle
  timeout, sever, peer close) now ends every session on that connection at once instead of one.
  `accept_protocol`/`connect_protocol` are untouched. Not a breaking API change.
- **`path_watch`**: today one watcher per session; under A one per *connection* is enough
  (`decide` already suppresses duplicates against the cache, so a per-session watcher would only
  cost tasks). **Sever did NOT reach these connections** (corrected in review):
  `ConnRegistry::sever_matching` holds only connections this node ACCEPTED. As built, #229's
  endpoint hooks register every non-pairing OUTBOUND connection and close those to a
  newly refused device on the revoke verbs and roster installs, which covers the cached MCP
  connection; see "As built".
- **Racing dials**: consulted before `race_dial`; the winner is recorded. A race in flight while
  another session is dialling the same peer can still produce two connections briefly; the second
  to land is not pooled and dies with its session. Acceptable — it is the transient case, not the
  sustained one.
- **Interaction with #213**: #213 is the accept side of a *second* connection to a peer that
  already holds a mesh session — the same K ≥ 2 shape, seen from the other end. A removes the
  second connection when both are MCP sessions, so pure-mcpmesh users stop producing the #213
  shape. It does **not** help bolo's case, where the second connection is `app/bolo-media/1` and
  cannot be merged. #213 still needs its own fix at `record_selected`.
- **Risks, stated**: (1) *Blast radius* — one connection's death takes N sessions instead of one.
  (2) *Path-id concentration* — a pooled connection that is never without a session lives for the
  whole day and burns the reporter's ~26 path ids/min on **one** connection. Today a fresh session
  gets a fresh path-id space. Without #4522's skip-on-`MaxPathIdReached` that connection eventually
  stops opening new paths and cannot upgrade relay→direct for its remaining life; with #4522 it is
  skipped cleanly. This is the one place where A trades a memory blow-up for a reachability
  degradation, and it must be in the release notes. A generation cap ("recycle the pooled
  connection after N minutes") would paper over iroh's path lifecycle and is deliberately not
  proposed. (3) *Head-of-line* — none; QUIC streams are independent.

### B. Probe without dialling when a live connection exists

> **Not built.** Implemented, found unreachable in review, and removed — see "As built". The text
> below is the original proposal.

`probe_peer` checks the A cache first. If a client connection to the peer upgrades and is open,
it reads `selected_path(conn)` (the same `Connection::paths()` + `is_selected()` reading the probe
already uses) and `Connection::rtt(path_id)` for the selected path (`iroh-1.0.3/src/endpoint/connection.rs:1016`), commits `reachable: true`, and keeps the previous entry's
`meta`/`services` — the pong payload is not re-fetched. A dial over `ALPN_PING` happens only when
no live connection exists. A ping frame cannot be sent on the mesh connection: its accept loop
treats every bi-stream as an MCP session and would refuse the frame as a malformed `initialize`,
so B is "do not dial", not "piggyback the ping".

- **K would become** (as proposed): the probe stops adding a transient second connection while a
  session is live. Not built; the probe dials ping once per TTL while polled, as before.
- **What changes for consumers**: `meta`, `services` and `stack_version` on a peer with a live
  session are as fresh as the last dialled probe, not 20 s. A live admitted session is stronger
  evidence of "up and paired" than a pong, so `reachable` does not get weaker. Presence policy
  (#89) is unaffected: a hidden peer already refused the session.
- **Only worth doing after A.** Without A the session connection is not findable from `reach`,
  and the probe transient is the smaller of the two problems.

### C. Back #4522 upstream, bump when it ships, change nothing here

- **K stays**: 2+ sustained for two concurrent sessions, which is bolo's ordinary usage.
- **What changes**: nothing until n0 merges and releases; the PR has had no maintainer attention
  in four days and asks two design questions of them. A `[patch.crates-io]` on our side reaches
  only the CLI (see above).
- **Risk**: the reporter's install stays at 6 GB for an unbounded time, and the memory of two
  independent reports (macOS 171 GB request, iOS hard abort) says the bug is not rare.

## Recommendation

**A, then B, and C in parallel from today.** Reasoning:

1. Question 2 has a clean answer: **no**, mcpmesh-node never needed more than one client
   connection per remote for MCP sessions. The wire protocol has carried several sessions per
   connection since 0.1.0; the dial side opens one connection per session out of nothing but
   convenience. Fixing that is fixing our own inefficiency, not shimming iroh — it is the
   exposure reduction the reporter asked whether there was, and it does not touch iroh.
2. A is dial-side only and wire-compatible with every deployed peer, so it ships without a
   protocol version and without waiting for the other end to upgrade.
3. C is the actual fix and A does not replace it. The path-id burn (~26/min), the recurring
   `RemoteCidsExhausted`, and iroh#4390's "why is `MaxPathIdReached` persistent" question all
   survive A untouched; at K = 1 they are a steady-state queue and a slowly degrading connection
   rather than a doubling deque. We should comment on #4522 with the reproduction data from #215
   (the 40 × 2ⁿ series, the requeue rates, the SIGSTOP recipe) and ask for a backport to 1.0.x,
   because a fix on `main` alone leaves us and bolo pinned to a broken 1.0.3.
4. No `[patch.crates-io]`. It cannot reach bolo and would make the CLI and the crate disagree.

### What reuse does NOT fix

Written here so the release notes cannot overclaim:

- The ~26 path ids/min burn on the long-lived connection and the `RemoteCidsExhausted` it
  produces are iroh's, upstream of anything mcpmesh does, and continue at K = 1.
- Under A the burn lands on one connection for as long as any session is up. Without #4522 that
  connection can reach `MaxPathIdReached` and stop opening paths; A makes that *more* likely, not
  less. This is the trade.
- bolo's media connection is a sustained second client connection for the length of every call.
  During a call bolo is at K ≥ 2 by construction, and the doubling loop is live for them until
  iroh ships the fix. mcpmesh cannot pool an app-protocol connection into the mesh connection.
- #213 is not fixed by A for bolo, for the same reason.
- The 20 s probe still dials while something polls, session or not (B was not built).

## As built — corrections from adversarial review

Every claim above that reads "exactly K = 1" is the design, not the build. What ships, on top of
#222, #223 and #229:

- **Shared connection per peer for plain sessions** (`node/src/daemon/conn_cache.rs`): weak handles,
  keyed by device, `ALPN_MCP` only. Single-flight per device — a `b64u:` race and an `eid:` dial to
  one of the same devices wait on each other rather than dialling side by side. A closed or
  non-upgrading entry is skipped and replaced by a fresh dial.
- **Not shared:** `idle_timeout_secs` sessions (own connection); a session past the peer's
  `max_concurrent_bidi_streams` (own uncached connection after `REUSE_OPEN_TIMEOUT` = 1 s).
- **B was removed.** The first build read reachability off the live connection and carried the
  cached `meta`/`services` forward, which made a session-first `peer_services` answer `[]` for the
  whole session and re-stamped aged payloads as fresh. Gating the live read on a fresh pong fixed
  that but made the branch unreachable (refreshes fire only once `probed_at` is past the TTL, and a
  pong is never newer than that), and a longer pong window would reintroduce stale services. So the
  probe dials `mcpmesh/ping/1` exactly as before, and **every K reduction in this change comes from
  session connection reuse**: a polled peer is still at K = 2 for ≤ 3.6 s once per TTL.
- **`ReachEntry.pong_at` stays.** Independent of B: a live session's path watcher writes a reachable
  row with no pong — since #225 at the moment the session opens — and `peer_services` answered `[]`
  from it for up to a TTL. The field marks whether a row carries a pong, and `peer_services` treats
  a reachable row without one as stale.
- **Revocation — three guards.** (1) The dial paths ask `dial_refused` before the cache
  (`refuse_if_revoked`; `hinted_addrs` for a race). (2) The cache asks it again at the moment it hands
  a connection out, which covers a session that passed (1) and then waited on another caller's dial
  while the device was revoked, and a revocation written without a revoke verb. (3) #229's close
  pass, run by `sever_principals` and roster installs, closes the cached connection; a closed
  connection reads as dead to the cache. The pre-#229 `close_to` / `sever_revoked` helper that did
  (3) for the cache alone was dropped when #229 landed. For a raced dial, (1)'s ordering and (2)
  cover each other — either alone keeps a revoked device's connection from being reused — so they
  are pinned only together.
- **#222 landed.** The accepting side resolves the caller's principals per stream, so a reused
  connection is authorized exactly as a fresh one. A peer still on mcpmesh ≤ 0.53.2 resolves them
  once per connection, and against it sharing stretches a lost principal's window from one session
  to the shared connection's lifetime.
- **Peer death without close:** a new session opens instantly on the dead connection and ends at
  the idle timeout instead of failing at open. noq/iroh expose no last-receive timestamp, so this is
  documented rather than detected.

## Versioning: MINOR

`API_MINOR` 66: no request/response shape changed, but two meanings did — a connection-level event
ends every session to that device at once, and `peer_services` requires a row that carries a pong.
`ReachEntry` (pub, in `mcpmesh-node`) gained `pong_at`, which breaks code constructing it. Beyond
those, the observable topology changes — N sessions to a peer become one connection — and #210's
precedent is that an observable behaviour change for existing deployments goes out as MINOR with
release notes that say so, rather than as a PATCH that reads as routine. The release notes must
carry the path-id concentration trade explicitly.

## Testing (for the implementing change, not this document)

1. **Two sessions, one connection.** Open two sessions to one peer against a fixture whose
   accept loop counts connections; assert exactly one accept, and that both sessions round-trip
   independently. (`Endpoint::remote_info` exposes addresses, not a connection count, so the
   accept counter is the only honest reading.) Delete the cache lookup → must fail (two accepts).
2. **The pooled connection dies with the last session.** End both sessions; assert the
   connection closes (`closed()` resolves) and `LIVE_WATCHERS` returns to zero. Hold a strong
   handle in the cache instead of a weak one → must fail.
3. **A stale entry is not reused.** Peer closes the connection; the next `open_session` dials
   fresh and succeeds. Skip the `close_reason()`/`open_bi` fallback → must fail.
4. **#166 sessions are never pooled.** A session with `idle_timeout_secs` set gets its own
   connection, and a plain session opened afterwards does not join it. Drop the
   `transport.is_some()` exclusion → must fail.
5. ~~**(B) A live session suppresses the probe dial.**~~ B was not built; no test.

Each mutation must fail at least one test; a suite green under all four mutations measures
nothing (the #110/#92/#124 lesson).
