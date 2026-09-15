# One client connection per remote (#215) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A node holding any number of MCP sessions to one peer keeps exactly ONE client-side QUIC
connection to it (K = 1), and the reachability probe stops dialling while that connection is live.

> **As built (review):** not every session shares the connection (`idle_timeout_secs`, stream-limit
> overflow). **Task 9 (option B) was implemented and then removed** — the probe dials ping exactly as
> before. See the design doc's "As built" section; this plan records the original intent.

**Architecture:** A dial-side cache on `MeshState` keyed by peer endpoint id, holding a
`WeakConnectionHandle` per peer for the `mcpmesh/mcp/1` ALPN only. `dial_service_with_idle_timeout`
consults it before every dial: a live entry gets a fresh `open_bi`; a missing/stale entry is dialled
under a per-peer SINGLE-FLIGHT slot so two simultaneous first dials produce one connection. Sessions
carrying a per-session transport config (#166) bypass the cache. `probe_once` reads liveness, RTT and
the selected path off the cached connection when one is live, and dials `mcpmesh/ping/1` only when
none is.

**Tech Stack:** Rust, tokio (`sync::watch` for the single-flight slot), iroh 1.0.3
(`Connection::weak_handle`/`close_reason`/`paths`/`rtt`), the existing loopback test idiom
(`build_endpoint` + `run_mesh_connection`).

**Spec:** `docs/superpowers/specs/2026-09-14-215-connection-reuse-design.md` (options A and B).

**Policy:** MINOR release (0.54.0) — do NOT bump the workspace version or `API_MINOR` in this
change. No push, no PR. `CARGO_BUILD_JOBS=3` on every cargo command.

---

## File Structure

| File | Responsibility |
|---|---|
| `node/src/daemon/conn_cache.rs` | **NEW.** `McpConnCache`: the weak-handle map, `live`, `record`, the single-flight `session_on`, the open-bi-on-existing helper, and (cfg(test)) the loopback peer fixture every test in this change uses. |
| `node/src/daemon.rs` | Declare `mod conn_cache;`; add the `conn_cache` field to `MeshState` and construct it in `new`. |
| `node/src/daemon/dial.rs` | Route the single-target paths through the cache; reuse-before-race and record-after-race on the racing paths; `inject_service` becomes `pub(crate)` for the tests. |
| `node/src/daemon/reach.rs` | `probe_once` short-circuits on a live cached connection; `Exchange` struct replaces the growing tuple; `selected_rtt_ms`; the live branch's frames are `Session`-sourced. |
| `docs/local-protocol.md` | Sessions section: one connection per peer; producer table: the `session` source now also covers a refresh read off the live connection. |
| `local-api/src/protocol.rs` | `OpenSessionParams::idle_timeout_secs` doc: such a session gets its own connection. Doc only. |

---

### Task 1: The cache type, the `MeshState` field, and the loopback peer fixture — RED

**Files:**
- Create: `node/src/daemon/conn_cache.rs`
- Modify: `node/src/daemon.rs` (mod list at line 24-38; `MeshState` fields near line 452; `new` near line 660)
- Modify: `node/src/daemon/dial.rs:860` (`fn inject_service` → `pub(crate) fn`)

- [ ] **Step 1: Create `node/src/daemon/conn_cache.rs` with the type and the test fixture.**

```rust
//! One client connection per remote for MCP sessions (#215).
//!
//! The accept side has multiplexed sessions as separate bi-streams on one connection since 0.1.0
//! (`run_mesh_connection` loops `accept_bi`). The dial side opened one connection per
//! `open_session` out of nothing but convenience, and that is the K ≥ 2 that iroh#4390 turns into
//! an unbounded `pending_open_paths` deque. This cache makes a second session to the same peer a
//! second bi-stream on the connection the first one is already using.
//!
//! **Weak, not strong.** Each entry is a [`WeakConnectionHandle`]: the connection lives exactly as
//! long as some session's streams hold it and dies with the last one, as before. No idle connection
//! is kept warm, so no new keepalive or idle-timeout semantics appear. A stale entry — one that no
//! longer upgrades, or whose `close_reason()` is set — is skipped and replaced by a fresh dial.
//!
//! **Keyed by peer endpoint id, for `ALPN_MCP` only.** Nothing else is ever inserted: app-protocol
//! connections negotiate their own ALPN at handshake and can never share, and the ping probe never
//! dials while an entry here is live (see `reach::probe_once`).
//!
//! **Single-flight first dial.** Two sessions opened at the same instant to a peer with no live
//! connection would each dial. The first caller to find no entry inserts a `Dialing` slot and
//! becomes the leader; later callers wait on that slot and retry once it resolves. The std mutex
//! is held only for the map lookup/insert — never across an await. A leader that fails, or is
//! cancelled mid-dial, clears its slot on drop so waiters dial for themselves.
//!
//! [`WeakConnectionHandle`]: iroh::endpoint::WeakConnectionHandle

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use mcpmesh_net::SessionTransport;
use mcpmesh_net::framing::MAX_FRAME_BYTES;

type Connection = iroh::endpoint::Connection;

enum Slot {
    /// A connection some session may still be holding open.
    Live(iroh::endpoint::WeakConnectionHandle),
    /// A dial in flight; waiters block on the receiver until the leader settles or gives up.
    Dialing(tokio::sync::watch::Receiver<()>),
}

/// The per-peer client-connection cache. `Clone` shares the map (the dial guard needs a handle).
#[derive(Clone, Default)]
pub(crate) struct McpConnCache {
    inner: Arc<Mutex<HashMap<[u8; 32], Slot>>>,
}

/// What [`McpConnCache::session_on`] produced.
pub(crate) enum Opened {
    /// A bi-stream on a connection that already existed. No new connection, no new watcher.
    Reused(SessionTransport),
    /// A freshly dialled connection, handed back so the caller can attach its path watcher.
    Fresh(SessionTransport, Connection),
}

enum Claim {
    Live(Connection),
    Wait(tokio::sync::watch::Receiver<()>),
    Lead(DialGuard),
}

impl McpConnCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The live connection to `peer`, if the cache holds one that still upgrades and is not closed.
    /// A stale entry is dropped on the way out.
    pub(crate) fn live(&self, peer: [u8; 32]) -> Option<Connection> {
        let mut map = self.inner.lock().expect("conn cache lock not poisoned");
        match map.get(&peer) {
            Some(Slot::Live(weak)) => match open(weak) {
                Some(conn) => Some(conn),
                None => {
                    map.remove(&peer);
                    None
                }
            },
            _ => None,
        }
    }

    /// A session bi-stream on the live connection to `peer`, or `None` when there is none — or
    /// when `open_bi` fails on it, in which case the entry is forgotten so the next dial is fresh.
    pub(crate) async fn reuse(&self, peer: [u8; 32]) -> Option<SessionTransport> {
        let conn = self.live(peer)?;
        self.open_on(peer, &conn).await
    }

    /// Open a bi-stream on a connection this cache handed out. On failure the entry is removed if
    /// it still names this connection, so a caller retrying its claim leads a fresh dial rather
    /// than looping on a handle that upgrades but cannot open streams.
    async fn open_on(&self, peer: [u8; 32], conn: &Connection) -> Option<SessionTransport> {
        match conn.open_bi().await {
            Ok((send, recv)) => Some(SessionTransport::new(recv, send, MAX_FRAME_BYTES)),
            Err(e) => {
                tracing::debug!(%e, "cached mesh connection refused a new stream; dialling fresh");
                let mut map = self.inner.lock().expect("conn cache lock not poisoned");
                if let Some(Slot::Live(weak)) = map.get(&peer)
                    && weak
                        .upgrade()
                        .is_some_and(|c| c.stable_id() == conn.stable_id())
                {
                    map.remove(&peer);
                }
                None
            }
        }
    }

    fn claim(&self, peer: [u8; 32]) -> Claim {
        let mut map = self.inner.lock().expect("conn cache lock not poisoned");
        match map.get(&peer) {
            Some(Slot::Live(weak)) => {
                if let Some(conn) = open(weak) {
                    return Claim::Live(conn);
                }
            }
            Some(Slot::Dialing(rx)) => return Claim::Wait(rx.clone()),
            None => {}
        }
        let (tx, rx) = tokio::sync::watch::channel(());
        map.insert(peer, Slot::Dialing(rx));
        Claim::Lead(DialGuard {
            cache: self.clone(),
            peer,
            settled: false,
            _tx: tx,
        })
    }

    /// A session to `peer`: a new bi-stream on the live connection if there is one, else ONE dial
    /// via `dial` shared with every other caller that arrives while it is in flight.
    ///
    /// `dial` runs at most once per call, and only when this caller leads. A waiter woken by a
    /// leader that failed retries its claim and may lead itself; the caller bounds the whole thing
    /// with `DIAL_TIMEOUT`, so a dead peer costs the same wait it did before.
    pub(crate) async fn session_on<F, Fut>(&self, peer: [u8; 32], dial: F) -> Result<Opened>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<(SessionTransport, Connection)>>,
    {
        let mut dial = Some(dial);
        loop {
            match self.claim(peer) {
                Claim::Live(conn) => {
                    if let Some(t) = self.open_on(peer, &conn).await {
                        return Ok(Opened::Reused(t));
                    }
                    // The stale entry was removed; the next claim leads.
                }
                Claim::Wait(mut rx) => {
                    // Ok: the leader settled. Err: the leader dropped its slot without settling
                    // (a failed or cancelled dial). Either way, look again.
                    let _ = rx.changed().await;
                }
                Claim::Lead(guard) => {
                    let dial = dial.take().expect("a caller leads at most once");
                    let (transport, conn) = dial().await?; // Err: the guard's drop clears the slot
                    guard.settle(&conn);
                    return Ok(Opened::Fresh(transport, conn));
                }
            }
        }
    }

    /// Remember a connection that arrived outside [`session_on`](Self::session_on) — a racing
    /// dial's winner — unless the peer already has a live entry or a dial in flight, in which case
    /// this one is the transient second connection the design accepts and it dies with its session.
    pub(crate) fn record(&self, conn: &Connection) {
        let peer = *conn.remote_id().as_bytes();
        let mut map = self.inner.lock().expect("conn cache lock not poisoned");
        match map.get(&peer) {
            Some(Slot::Live(weak)) if open(weak).is_some() => {}
            Some(Slot::Dialing(_)) => {}
            _ => {
                map.insert(peer, Slot::Live(conn.weak_handle()));
            }
        }
    }
}

/// Upgrade a cached handle, treating a connection that is closed but not yet dropped as absent.
fn open(weak: &iroh::endpoint::WeakConnectionHandle) -> Option<Connection> {
    weak.upgrade().filter(|c| c.close_reason().is_none())
}

/// The leader's claim on a peer's `Dialing` slot. Dropping it without `settle` — a failed or
/// cancelled dial — removes the slot; dropping the sender either way wakes the waiters.
struct DialGuard {
    cache: McpConnCache,
    peer: [u8; 32],
    settled: bool,
    _tx: tokio::sync::watch::Sender<()>,
}

impl DialGuard {
    fn settle(mut self, conn: &Connection) {
        self.cache
            .inner
            .lock()
            .expect("conn cache lock not poisoned")
            .insert(self.peer, Slot::Live(conn.weak_handle()));
        self.settled = true;
        // `self` drops here: the sender goes with it and every waiter re-claims, finding `Live`.
    }
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let mut map = self.cache.inner.lock().expect("conn cache lock not poisoned");
        if matches!(map.get(&self.peer), Some(Slot::Dialing(_))) {
            map.remove(&self.peer);
        }
    }
}

/// A loopback peer that runs the REAL per-connection mesh path (`run_mesh_connection`) and the
/// ping arm's pong, counting every accepted connection per ALPN. The accepted-connection count is
/// the only honest reading of "how many connections did we open" — `Endpoint::remote_info` reports
/// addresses, not connections, and the cache's own map is the thing under test.
#[cfg(test)]
pub(crate) mod testpeer {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use mcpmesh_net::registry::ConnRegistry;
    use mcpmesh_net::{
        ALPN_MCP, ALPN_PING, LiveServices, ServiceEntry, ServiceKind, Services, SessionBackend,
        SessionTransport, TrustGate,
    };

    use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};

    /// The pong `meta` this peer answers with — distinct from anything a test seeds into the
    /// dialer's cache, so "read off the live connection" and "dialled a ping" are distinguishable.
    pub(crate) const PONG_META: &str = "pong-meta";

    pub(crate) struct LoopbackPeer {
        pub(crate) id: [u8; 32],
        pub(crate) addr: iroh::EndpointAddr,
        pub(crate) mcp_accepts: Arc<AtomicUsize>,
        pub(crate) ping_accepts: Arc<AtomicUsize>,
        /// The peer's live MCP connections, registered by `run_mesh_connection` and deregistered
        /// when the connection closes — the peer-side reading of "the connection is gone".
        pub(crate) registry: Arc<ConnRegistry>,
        _accept: tokio::task::JoinHandle<()>,
    }

    /// Echoes the (already service-stripped) initialize, then every frame, until the dialer's
    /// half-close.
    struct Echo;

    #[async_trait::async_trait]
    impl SessionBackend for Echo {
        async fn run(
            &self,
            _identity: Option<mcpmesh_net::PeerIdentity>,
            initialize: serde_json::Value,
            mut transport: SessionTransport,
        ) -> anyhow::Result<()> {
            transport.send_value(initialize).await?;
            while let Ok(Some(f)) = transport.recv_value().await {
                transport.send_value(f).await?;
            }
            let _ = transport.shutdown().await;
            Ok(())
        }
    }

    /// Bind a peer on key `[seed; 32]` that trusts `dialer` and serves `services` as
    /// `(name, allow)` pairs, every one backed by [`Echo`].
    pub(crate) async fn loopback_peer(
        dir: &std::path::Path,
        seed: u8,
        dialer: [u8; 32],
        services: &[(&str, &[&str])],
    ) -> LoopbackPeer {
        let store = Arc::new(PeerStore::open(&dir.join(format!("peer-{seed}.redb"))).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: dialer,
                nickname: "dialer".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store));
        let services = Arc::new(LiveServices::new(Arc::new(Services::new(
            services
                .iter()
                .map(|(name, allow)| {
                    (
                        (*name).to_string(),
                        ServiceEntry {
                            backend: Arc::new(Echo),
                            allow: allow.iter().map(|a| (*a).to_string()).collect(),
                            kind: ServiceKind::Run,
                            ephemeral: false,
                        },
                    )
                })
                .collect(),
        ))));
        let hermetic = crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            ..Default::default()
        };
        let endpoint = crate::daemon::boot::build_endpoint(
            iroh::SecretKey::from_bytes(&[seed; 32]),
            &hermetic,
            false,
        )
        .await
        .unwrap();
        let id = *endpoint.id().as_bytes();
        let addr = endpoint.addr();
        let mcp_accepts = Arc::new(AtomicUsize::new(0));
        let ping_accepts = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(ConnRegistry::new());
        let accept = {
            let (endpoint, mcp, ping, registry) = (
                endpoint.clone(),
                mcp_accepts.clone(),
                ping_accepts.clone(),
                registry.clone(),
            );
            tokio::spawn(async move {
                while let Some(incoming) = endpoint.accept().await {
                    let Ok(conn) = incoming.await else { continue };
                    let alpn = conn.alpn().to_vec();
                    if alpn == ALPN_MCP {
                        mcp.fetch_add(1, Ordering::SeqCst);
                        let (gate, services, registry) =
                            (gate.clone(), services.clone(), registry.clone());
                        tokio::spawn(mcpmesh_net::run_mesh_connection(
                            conn, gate, services, registry,
                        ));
                    } else if alpn == ALPN_PING {
                        ping.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            if let Ok((mut send, _recv)) = conn.accept_bi().await {
                                let pong = serde_json::json!({
                                    "stack_version": "test",
                                    "meta": PONG_META,
                                    "services": ["echo"],
                                });
                                if mcpmesh_net::framing::write_frame(&mut send, &pong)
                                    .await
                                    .is_ok()
                                {
                                    let _ = send.finish();
                                    let _ = send.stopped().await;
                                }
                            }
                        });
                    } else {
                        conn.close(0u32.into(), b"unexpected alpn");
                    }
                }
            })
        };
        LoopbackPeer {
            id,
            addr,
            mcp_accepts,
            ping_accepts,
            registry,
            _accept: accept,
        }
    }

    /// A hermetic dialer mesh with `peer` stored as nickname `bob`, hinted at its real address.
    pub(crate) async fn dialer_mesh(
        dir: &std::path::Path,
        peer: &LoopbackPeer,
    ) -> Arc<crate::daemon::MeshState> {
        let cfg = dir.join("dialer.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        mesh.store
            .add(PeerEntry {
                endpoint_id: peer.id,
                nickname: "bob".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: Some(serde_json::to_string(&peer.addr).unwrap()),
            })
            .unwrap();
        mesh
    }

    /// The dialer's own endpoint id — `hermetic_mesh` binds on `[7u8; 32]`.
    pub(crate) fn dialer_id() -> [u8; 32] {
        *iroh::SecretKey::from_bytes(&[7u8; 32]).public().as_bytes()
    }

    /// Send a service-named `initialize` and return the first frame back.
    pub(crate) async fn first_reply(t: &mut SessionTransport, service: &str) -> serde_json::Value {
        let init = crate::daemon::dial::inject_service(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            service,
        );
        t.send_value(init).await.expect("send initialize");
        tokio::time::timeout(std::time::Duration::from_secs(10), t.recv_value())
            .await
            .expect("a reply within 10s")
            .expect("a readable reply")
            .expect("a frame, not EOF")
    }

    /// Wait, sleeping, up to 10s for `cond` — never a `yield_now` spin.
    pub(crate) async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        cond()
    }
}

#[cfg(test)]
mod tests {
    use super::testpeer::{dialer_id, dialer_mesh, first_reply, loopback_peer};
    use crate::daemon::dial::dial_service;
    use std::sync::atomic::Ordering;

    /// #215, the property: two sessions to one peer are two bi-streams on ONE connection.
    ///
    /// Asserted on the PEER's accepted-connection count — the one observable the cache cannot
    /// fake — and on both sessions round-tripping independently, so a "reuse" that shares a
    /// stream would also fail. Mutation: delete the cache lookup in `dial_single` (always dial)
    /// → two accepts.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_sessions_to_one_peer_share_one_connection() {
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 41, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;
        // (Task 7 tightens the allow to the dialer's principal; `b64u:anyone` is never matched, so
        // the sessions below are refused — this RED test only counts connections.)

        let mut a = dial_service(&mesh, "bob", "echo").await.expect("session A");
        let mut b = dial_service(&mesh, "bob", "echo").await.expect("session B");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            1,
            "a second session to the same peer must ride the first session's connection"
        );
        let ra = first_reply(&mut a, "echo").await;
        let rb = first_reply(&mut b, "echo").await;
        assert_eq!(ra["id"], 1, "session A answers on its own stream: {ra}");
        assert_eq!(rb["id"], 1, "session B answers on its own stream: {rb}");
    }
}
```

- [ ] **Step 2: Declare the module and the field.**

In `node/src/daemon.rs` add `mod conn_cache;` after `mod accept;` (line 24). In `MeshState`, after
`probes_inflight` (line ~452):

```rust
    /// The per-peer client connection cache for MCP sessions (#215) — see `conn_cache`.
    pub(crate) conn_cache: conn_cache::McpConnCache,
```

In `MeshState::new`, after `probes_inflight: ...` (line ~660):

```rust
            conn_cache: conn_cache::McpConnCache::new(),
```

In `node/src/daemon/dial.rs:860` change `fn inject_service(` to `pub(crate) fn inject_service(`.

- [ ] **Step 3: Run the RED test.**

Run: `CARGO_BUILD_JOBS=3 cargo test -p mcpmesh-node --lib conn_cache::tests::two_sessions -- --nocapture`
Expected: FAIL at the `mcp_accepts == 1` assertion with `left: 2` (dial.rs still dials per session).
If it fails to COMPILE, fix the fixture first — the RED must be the assertion.

---

### Task 2: Route the single-target dials through the cache — GREEN

**Files:**
- Modify: `node/src/daemon/dial.rs:170-316`

- [ ] **Step 1: Add `dial_single` and use it from both single-target paths.**

Replace the tail of `dial_service_with_idle_timeout` (from `let entry = single...` to the end) with:

```rust
    let entry = single.with_context(|| format!("peer '{peer}' is not in the allowlist"))?;
    refuse_if_revoked(mesh, &entry.endpoint_id, peer)?;
    let endpoint_id = iroh::EndpointId::from_bytes(&entry.endpoint_id)
        .map_err(|e| anyhow::anyhow!("stored endpoint id for '{peer}' is invalid: {e}"))?;
    let addr = stored_dial_addr(entry.last_addr.as_deref(), endpoint_id);
    dial_single(mesh, addr, service, per_conn)
        .await
        .with_context(|| format!("dial {peer}/{service}"))
}

/// ONE session to ONE device, on the connection this node already holds to it when there is one
/// (#215).
///
/// A session with a per-connection transport config (#166) is dialled as before and never cached:
/// `ConnectOptions::with_transport_config` is per CONNECTION, so a session that asked for its own
/// idle timeout needs its own connection — sharing would either apply that timeout to sessions
/// that never asked for it or silently drop it, and #166 refuses the silent drop twice over.
///
/// The `DIAL_TIMEOUT` around the whole thing covers the wait on another caller's in-flight dial as
/// well as our own, so a dead peer costs a second session the same bounded wait it always did.
async fn dial_single(
    mesh: &Arc<MeshState>,
    addr: iroh::EndpointAddr,
    service: &str,
    per_conn: Option<iroh::endpoint::QuicTransportConfig>,
) -> Result<SessionTransport> {
    if per_conn.is_some() {
        let (transport, conn) =
            connect_with_timeout(&mesh.endpoint, addr, service, DIAL_TIMEOUT, per_conn).await?;
        return Ok(watch_session(mesh, transport, conn));
    }
    let peer = *addr.id.as_bytes();
    let endpoint = mesh.endpoint.clone();
    let opened = tokio::time::timeout(
        DIAL_TIMEOUT,
        mesh.conn_cache.session_on(peer, || async move {
            connect_with_timeout(&endpoint, addr, service, DIAL_TIMEOUT, None).await
        }),
    )
    .await
    .unwrap_or_else(|_| anyhow::bail!("dial timed out after {DIAL_TIMEOUT:?}"))?;
    Ok(match opened {
        super::conn_cache::Opened::Reused(transport) => transport,
        // One path watcher per CONNECTION: `decide` already suppresses repeat observations, so a
        // watcher per session on a shared connection would only cost tasks.
        super::conn_cache::Opened::Fresh(transport, conn) => watch_session(mesh, transport, conn),
    })
}
```

In `dial_by_eid`, replace the final `connect_with_timeout(...)` / `watch_session` with:

```rust
    let addr = stored_dial_addr(last_addr.as_deref(), endpoint_id);
    dial_single(mesh, addr, service, per_conn)
        .await
        .with_context(|| format!("dial eid:{hex}/{service}"))
```

- [ ] **Step 2: Run the test; it must pass.**

Run: `CARGO_BUILD_JOBS=3 cargo test -p mcpmesh-node --lib conn_cache::tests::two_sessions`
Expected: PASS.

- [ ] **Step 3: Mutation check.** In `dial_single`, temporarily replace the `session_on` call with
a direct `connect_with_timeout` + `watch_session`. Run the test: it must FAIL with `left: 2`.
Restore. Record: *mutation "always dial" → caught by `two_sessions_to_one_peer_share_one_connection`*.

- [ ] **Step 4: Commit.**

```bash
git add node/src/daemon/conn_cache.rs node/src/daemon.rs node/src/daemon/dial.rs
git commit -m "feat: one client connection per remote for MCP sessions (#215)"
```
(with the Co-Authored-By / Claude-Session trailers.)

---

### Task 3: The pooled connection dies with its last session

**Files:**
- Modify: `node/src/daemon/conn_cache.rs` (tests)

- [ ] **Step 1: Add the test.**

```rust
    /// Weak semantics: no session, no connection. The cache must not keep a warm idle connection —
    /// that would be a NEW connection lifetime nobody configured, and iroh#4390 counts live client
    /// connections. Read on the PEER: its registry drops the connection when `accept_bi` ends.
    /// Mutation: hold a strong `Connection` in `Slot::Live` → the peer's registry stays at 1 and
    /// the bounded wait expires.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_shared_connection_closes_when_its_last_session_ends() {
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 42, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;

        let a = dial_service(&mesh, "bob", "echo").await.expect("session A");
        let b = dial_service(&mesh, "bob", "echo").await.expect("session B");
        assert!(
            eventually(|| peer.registry.len() == 1).await,
            "precondition: the peer tracks the one shared connection"
        );
        drop(a);
        assert!(
            mesh.conn_cache.live(peer.id).is_some(),
            "one session still holds the connection open"
        );
        drop(b);
        assert!(
            eventually(|| peer.registry.len() == 0).await,
            "the peer must see the connection close once the last session ends — a strong handle \
             in the cache keeps it open forever"
        );
        assert!(
            mesh.conn_cache.live(peer.id).is_none(),
            "and the cache must report no live connection"
        );
    }
```
(add `eventually` to the `use super::testpeer::{...}` line.)

- [ ] **Step 2: Run it.** Expected: PASS.
- [ ] **Step 3: Mutation.** Change `Slot::Live(iroh::endpoint::WeakConnectionHandle)` to hold a
`Connection` clone (adjust `open` to `Some(c.clone()).filter(...)`, `settle`/`record` to store
`conn.clone()`). Run: must FAIL at "the peer must see the connection close". Restore. Record.
- [ ] **Step 4: Commit** `test: the shared connection dies with its last session (#215)`.

---

### Task 4: A dead cached connection is not reused

**Files:**
- Modify: `node/src/daemon/conn_cache.rs` (tests)

- [ ] **Step 1: Add the test.**

```rust
    /// A closed connection whose handle still upgrades (session A is still holding its streams)
    /// must not be reused. The peer closes it — a sever, the realistic case — and the next session
    /// must dial fresh and WORK. Values: a reused stale handle fails `open_bi` and the dial errors;
    /// a fresh dial succeeds and the peer's accept count reads 2. Mutation: in `open`, drop the
    /// `close_reason().is_none()` filter AND make `open_on` return the error instead of falling
    /// through → session B fails.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_closed_connection_is_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 43, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;

        let mut a = dial_service(&mesh, "bob", "echo").await.expect("session A");
        assert!(eventually(|| peer.registry.len() == 1).await);
        // The peer severs it (what a revoke does), and we wait until OUR side has observed the
        // close — the stream read fails — so the stale handle is genuinely closed, not merely
        // about to be.
        assert_eq!(peer.registry.sever_matching(401, b"test sever", |_, _| true), 1);
        let observed = tokio::time::timeout(std::time::Duration::from_secs(10), a.recv_value())
            .await
            .expect("the close reaches the dialer within 10s");
        assert!(
            !matches!(observed, Ok(Some(_))),
            "precondition: session A's stream is dead: {observed:?}"
        );

        let mut b = dial_service(&mesh, "bob", "echo")
            .await
            .expect("a fresh dial after the peer closed the pooled connection");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            2,
            "session B must be a NEW connection, not a stream on the closed one"
        );
        assert_eq!(first_reply(&mut b, "echo").await["id"], 1);
        drop(a);
    }
```

- [ ] **Step 2: Run.** Expected: PASS.
- [ ] **Step 3: Mutation** as described. Expected: FAIL at "a fresh dial after…". Restore. Record.
- [ ] **Step 4: Commit** `test: a closed pooled connection is never reused (#215)`.

---

### Task 5: A per-session idle timeout gets its own connection

**Files:**
- Modify: `node/src/daemon/conn_cache.rs` (tests)

- [ ] **Step 1: Add the test.**

```rust
    /// #166 sessions are never pooled, in either direction: the timed session gets its own
    /// connection (accept 1), a plain session after it does not join it (accept 2), and a second
    /// plain session joins the plain one (still 2). Mutation: drop the `per_conn.is_some()` early
    /// return in `dial_single` → the plain session rides the timed connection and the count stays 1.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_with_its_own_idle_timeout_keeps_its_own_connection() {
        use crate::daemon::dial::dial_service_with_idle_timeout;
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 44, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;
        let secs = mesh.keep_alive_secs() + 25;

        let timed = dial_service_with_idle_timeout(&mesh, "bob", "echo", Some(secs))
            .await
            .expect("timed session");
        assert_eq!(peer.mcp_accepts.load(Ordering::SeqCst), 1);
        assert!(
            mesh.conn_cache.live(peer.id).is_none(),
            "a per-session connection must never enter the shared cache"
        );
        let plain = dial_service(&mesh, "bob", "echo").await.expect("plain session");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            2,
            "a plain session must not join a connection carrying someone else's idle timeout"
        );
        let plain2 = dial_service(&mesh, "bob", "echo").await.expect("second plain session");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            2,
            "…but it does share the plain connection"
        );
        let timed2 = dial_service_with_idle_timeout(&mesh, "bob", "echo", Some(secs))
            .await
            .expect("second timed session");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            3,
            "and a second timed session dials its own connection rather than reusing the plain one"
        );
        drop((timed, plain, plain2, timed2));
    }
```

- [ ] **Step 2: Run.** PASS. **Step 3: Mutation** (remove the early return). FAIL at "must not join".
Restore. Record. **Step 4: Commit** `test: #166 sessions keep their own connection (#215)`.

---

### Task 6: Two simultaneous first dials produce one connection (single-flight)

**Files:**
- Modify: `node/src/daemon/conn_cache.rs` (tests)

- [ ] **Step 1: Add the test — deterministic, through the real `session_on` with a gated dial.**

```rust
    /// The first-dial race: two callers, no live connection, both claim at once. The single-flight
    /// slot makes the second WAIT rather than dial. Deterministic: the leader's dial is held on a
    /// gate the test controls, so the follower provably arrives while the dial is in flight; its
    /// own dial closure counts how often it is invoked. Mutation: make `claim` return `Lead` for a
    /// `Dialing` slot (no waiting) → the follower dials, two accepts.
    #[tokio::test(flavor = "multi_thread")]
    async fn simultaneous_first_dials_share_one_connection() {
        use crate::daemon::dial::{DIAL_TIMEOUT, connect_with_timeout};
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 45, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let follower_dials = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let leader = {
            let (mesh, addr) = (mesh.clone(), peer.addr.clone());
            tokio::spawn(async move {
                mesh.conn_cache
                    .session_on(peer.id, || async move {
                        let _ = gate.await;
                        connect_with_timeout(&mesh.endpoint, addr, "echo", DIAL_TIMEOUT, None).await
                    })
                    .await
            })
        };
        // Let the leader claim its slot (its dial is parked on the gate).
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let follower = {
            let (mesh, addr, dials) = (mesh.clone(), peer.addr.clone(), follower_dials.clone());
            tokio::spawn(async move {
                mesh.conn_cache
                    .session_on(peer.id, || async move {
                        dials.fetch_add(1, Ordering::SeqCst);
                        connect_with_timeout(&mesh.endpoint, addr, "echo", DIAL_TIMEOUT, None).await
                    })
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            0,
            "nothing is dialled while the leader's dial is parked — the follower must be waiting"
        );
        release.send(()).unwrap();
        let (l, f) = tokio::join!(leader, follower);
        let l = l.unwrap().expect("leader session");
        let f = f.unwrap().expect("follower session");
        assert!(matches!(l, super::Opened::Fresh(..)), "the leader dialled");
        assert!(matches!(f, super::Opened::Reused(_)), "the follower reused");
        assert_eq!(follower_dials.load(Ordering::SeqCst), 0, "the follower never dialled");
        assert_eq!(peer.mcp_accepts.load(Ordering::SeqCst), 1);
    }

    /// A leader that FAILS must not strand its waiters: the slot is cleared on drop and the waiter
    /// dials for itself. Mutation: remove `DialGuard::drop`'s removal → the follower waits forever
    /// (bounded here by the timeout).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_leader_releases_its_waiters() {
        use crate::daemon::dial::{DIAL_TIMEOUT, connect_with_timeout};
        let dir = tempfile::tempdir().unwrap();
        let peer = loopback_peer(dir.path(), 46, dialer_id(), &[("echo", &["b64u:anyone"])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;
        let (release, gate) = tokio::sync::oneshot::channel::<()>();

        let leader = {
            let mesh = mesh.clone();
            tokio::spawn(async move {
                mesh.conn_cache
                    .session_on(peer.id, || async move {
                        let _ = gate.await;
                        anyhow::bail!("leader's dial failed")
                    })
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let follower = {
            let (mesh, addr) = (mesh.clone(), peer.addr.clone());
            tokio::spawn(async move {
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    mesh.conn_cache.session_on(peer.id, || async move {
                        connect_with_timeout(&mesh.endpoint, addr, "echo", DIAL_TIMEOUT, None).await
                    }),
                )
                .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        release.send(()).unwrap();
        assert!(leader.await.unwrap().is_err());
        let f = follower
            .await
            .unwrap()
            .expect("the follower must be woken when the leader fails")
            .expect("and then dial for itself");
        assert!(matches!(f, super::Opened::Fresh(..)));
        assert_eq!(peer.mcp_accepts.load(Ordering::SeqCst), 1);
    }
```

Make `DIAL_TIMEOUT` and `connect_with_timeout` reachable: they are already `pub(crate)`.

- [ ] **Step 2: Run both.** PASS. **Step 3: Mutations** as described; each must FAIL. Restore.
Record. **Step 4: Commit** `test: single-flight first dial (#215)`.

---

### Task 7: Per-stream authz still applies on a shared connection

**Files:**
- Modify: `node/src/daemon/conn_cache.rs` (tests)

- [ ] **Step 1: Add the test.**

```rust
    /// Nothing about authz changes: the accept path resolves the allow list PER BI-STREAM, so a
    /// second session on the shared connection to a service the caller is not granted is refused
    /// with -32054 exactly as a fresh connection would be — and it IS the shared connection
    /// (accept count 1). Mutation (fixture): add the dialer's principal to `private`'s allow →
    /// the refusal assertion fails, proving it discriminates. Mutation (code): delete the cache
    /// lookup → accept count 2.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_stream_on_a_shared_connection_is_still_authorized_per_stream() {
        let dir = tempfile::tempdir().unwrap();
        let me = mcpmesh_net::EndpointId::from_bytes(dialer_id()).principal();
        let peer = loopback_peer(
            dir.path(),
            47,
            dialer_id(),
            &[("echo", &[me.as_str()]), ("private", &["eid:nobody"])],
        )
        .await;
        let mesh = dialer_mesh(dir.path(), &peer).await;

        let mut ok = dial_service(&mesh, "bob", "echo").await.expect("granted session");
        let reply = first_reply(&mut ok, "echo").await;
        assert_eq!(reply["method"], "initialize", "the granted service answers: {reply}");

        let mut refused = dial_service(&mesh, "bob", "private").await.expect("stream opens");
        assert_eq!(peer.mcp_accepts.load(Ordering::SeqCst), 1, "same connection");
        let reply = first_reply(&mut refused, "private").await;
        assert_eq!(
            reply["error"]["code"],
            mcpmesh_net::errors::ERR_SERVICE,
            "an ungranted service on a SHARED connection must still be refused: {reply}"
        );
    }
```

Then update the earlier tests' fixtures from `"b64u:anyone"` to the dialer's principal so their
round-trips are real echoes (assert `reply["method"] == "initialize"` in Task 1's test instead of
`id`).

- [ ] **Step 2: Run.** PASS. **Step 3: Mutations.** Record both. **Step 4: Commit**
`test: per-stream authz holds on a shared connection (#215)`.

---

### Task 8: Racing dials — reuse before the race, record the winner

**Files:**
- Modify: `node/src/daemon/dial.rs:194-246`

- [ ] **Step 1: Add the test (in `conn_cache.rs` tests).**

```rust
    /// The racing paths (a `b64u:` user with several devices): a live connection to any candidate
    /// device is reused without racing, and a race's WINNER is recorded so the next session reuses
    /// it. Mutation: delete `record` after the race → the second dial races again (accept 2).
    /// Mutation: delete the reuse loop → same.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_raced_dial_reuses_and_records_the_winner() {
        let dir = tempfile::tempdir().unwrap();
        let me = mcpmesh_net::EndpointId::from_bytes(dialer_id()).principal();
        let peer = loopback_peer(dir.path(), 48, dialer_id(), &[("echo", &[me.as_str()])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;
        // A second device of the same person that nobody answers for.
        let dead = *iroh::SecretKey::from_bytes(&[49u8; 32]).public().as_bytes();
        // The store must hold ONLY the two `b64u:bob` rows, so the `b64u:` path races.
        assert!(mesh.store.remove("bob").unwrap());
        for (eid, nick, hint) in [
            (dead, "bob-dead", None),
            (peer.id, "bob-live", Some(serde_json::to_string(&peer.addr).unwrap())),
        ] {
            mesh.store
                .add(crate::allowlist::PeerEntry {
                    endpoint_id: eid,
                    nickname: nick.into(),
                    services: vec![],
                    paired_at: None,
                    user_id: Some("b64u:bob".into()),
                    last_addr: hint,
                })
                .unwrap();
        }
        let a = dial_service(&mesh, "b64u:bob", "echo").await.expect("raced session");
        assert_eq!(peer.mcp_accepts.load(Ordering::SeqCst), 1);
        let b = dial_service(&mesh, "b64u:bob", "echo").await.expect("second session");
        assert_eq!(
            peer.mcp_accepts.load(Ordering::SeqCst),
            1,
            "the race's winner must be recorded and reused — racing again is a second connection"
        );
        drop((a, b));
    }
```
- [ ] **Step 2: Run.** Expected: FAIL at the second assertion (`left: 2`).

- [ ] **Step 3: Implement `race_or_reuse` and call it from both racing paths.**

```rust
/// The racing paths' share of #215: a live connection to ANY candidate device is reused without
/// a race, and a race's winner is recorded for the next session.
///
/// Reuse is checked AFTER `hinted_addrs`, which drops revoked devices — a revoked device's
/// connection is severed on revoke, but "never reuse it" should not depend on that ordering.
/// The record is best-effort: a race landing while another caller's single-flight dial is in
/// progress is the transient second connection the design accepts, and it dies with its session.
async fn race_or_reuse(
    mesh: &Arc<MeshState>,
    candidates: Vec<[u8; 32]>,
    service: &str,
) -> Result<SessionTransport> {
    let addrs = hinted_addrs(mesh, candidates).await?;
    for addr in &addrs {
        if let Some(transport) = mesh.conn_cache.reuse(*addr.id.as_bytes()).await {
            return Ok(transport);
        }
    }
    let (transport, conn) = race_dial(&mesh.endpoint, addrs, service).await?;
    mesh.conn_cache.record(&conn);
    Ok(watch_session(mesh, transport, conn))
}
```

Replace both `let candidates = hinted_addrs(...)…race_dial…watch_session` blocks with
`return race_or_reuse(mesh, candidates, service).await.with_context(|| format!("dial {peer}/{service}"));`
(the roster path keeps its `warn_if_per_session_dropped` line first; the `multi` path likewise).

- [ ] **Step 4: Run.** PASS. **Step 5: Mutations** (delete `record`; delete the loop). Each FAIL.
Restore. Record. **Step 6: Commit** `feat: racing dials reuse and record the winner (#215)`.

---

### Task 9: The probe reads off the live connection (option B) — REMOVED in review, not shipped

**Files:**
- Modify: `node/src/daemon/reach.rs:460-597` and its tests

- [ ] **Step 1: Add the tests (in `reach.rs`'s test module).**

```rust
    /// #215 (B): while a session connection to the peer is live, `probe_peer` reads liveness, the
    /// selected path and the RTT off THAT connection and dials no `mcpmesh/ping/1` at all. The two
    /// branches are distinguishable by the peer's ping accept count AND by `meta`: the live branch
    /// keeps the cached row's meta, the dialled branch takes the pong's. Mutation: remove the
    /// `conn_cache.live` check in `probe_once` → the first probe dials (count 1, meta "pong-meta").
    #[tokio::test(flavor = "multi_thread")]
    async fn a_live_session_suppresses_the_probe_dial_and_no_session_restores_it() {
        use crate::daemon::conn_cache::testpeer::{
            PONG_META, dialer_id, dialer_mesh, eventually, loopback_peer,
        };
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let me = mcpmesh_net::EndpointId::from_bytes(dialer_id()).principal();
        let peer = loopback_peer(dir.path(), 50, dialer_id(), &[("echo", &[me.as_str()])]).await;
        let mesh = dialer_mesh(dir.path(), &peer).await;

        // A STALE cached row from an earlier dialled probe: its meta/services must survive the
        // live read (the pong is not re-fetched), and it is Unknown-pathed so the live read's
        // Direct is a transition — whose `source` must say it came off the live link.
        let mut seeded = entry(true, Some(7));
        seeded.meta = "seeded-meta".into();
        seeded.services = vec!["seeded".into()];
        seeded.probed_at = 1;
        mesh.reachability.lock().unwrap().insert(peer.id, seeded);
        let mut rx = mesh.reach_bcast.subscribe();

        let session = crate::daemon::dial::dial_service(&mesh, "bob", "echo")
            .await
            .expect("session");
        let got = super::probe_peer(&mesh, peer.id).await;
        assert_eq!(
            peer.ping_accepts.load(Ordering::SeqCst),
            0,
            "with a live session the probe must not dial the ping ALPN"
        );
        assert!(got.reachable, "a live session is reachability evidence");
        assert_eq!(got.meta, "seeded-meta", "the pong is not re-fetched; the row's meta stays");
        assert_eq!(got.services, vec!["seeded".to_string()]);
        assert_eq!(got.path, mcpmesh_local_api::PeerPath::Direct, "read off the live link");
        assert!(got.rtt_ms.is_some(), "RTT comes from the connection's selected path");
        let t = rx.try_recv().expect("Unknown -> Direct is a transition");
        assert_eq!(
            t.source,
            mcpmesh_local_api::ReachabilitySource::Session,
            "a reading off the live connection is a claim about the live link, not a probe dial"
        );

        // No session → the probe dials exactly as before, and the pong's meta lands.
        drop(session);
        assert!(eventually(|| mesh.conn_cache.live(peer.id).is_none()).await);
        let got = super::probe_peer(&mesh, peer.id).await;
        assert_eq!(peer.ping_accepts.load(Ordering::SeqCst), 1, "no live connection: dial");
        assert!(got.reachable);
        assert_eq!(got.meta, PONG_META, "the dialled branch takes the pong's payload");
    }
```

- [ ] **Step 2: Run.** Expected: FAIL at `ping_accepts == 0` (`left: 1`).

- [ ] **Step 3: Implement.** In `reach.rs`:

Replace the tuple with a struct and thread `source`:

```rust
/// What a probe exchange produced — off a pong, or (#215) off the live session connection.
struct Exchange<C> {
    meta: String,
    services: Vec<String>,
    conn: C,
    /// Stamped at the pong (#123), or the live connection's selected-path RTT; `None` only when
    /// the live connection has no selected path yet — never fabricated.
    rtt_ms: Option<u64>,
    /// Which producer this is (#150): `Probe` for a dial, `Session` for a live-connection read.
    source: mcpmesh_local_api::ReachabilitySource,
}

type ExchangeOutcome<C> = std::result::Result<Result<Exchange<C>>, tokio::time::error::Elapsed>;
```

`probe_once` returns `Result<Exchange<iroh::endpoint::Connection>>` and starts with:

```rust
    // #215 (B): a live session connection is stronger evidence than a pong — we are talking to
    // the peer right now — and dialling a second connection beside it is exactly the K ≥ 2 that
    // iroh#4390 multiplies. Read the selected path and its RTT off that connection, keep the
    // cached row's pong payload (a ping frame cannot ride the mesh connection: its accept loop
    // would read it as a malformed `initialize`), and dial only when no connection is live.
    if let Some(conn) = mesh.conn_cache.live(endpoint_id) {
        let (meta, services) = mesh
            .reachability
            .lock()
            .expect("reachability lock not poisoned")
            .get(&endpoint_id)
            .map(|e| (e.meta.clone(), e.services.clone()))
            .unwrap_or_default();
        let rtt_ms = selected_rtt_ms(&conn);
        return Ok(Exchange {
            meta,
            services,
            conn,
            rtt_ms,
            source: mcpmesh_local_api::ReachabilitySource::Session,
        });
    }
```

and its dialled arm becomes
`Ok((meta, services, rtt_ms)) => Ok(Exchange { meta, services, conn, rtt_ms: Some(rtt_ms), source: Probe })`.

Add next to `selected_path`:

```rust
/// The RTT estimate of the SELECTED path (#215) — the same "which path carries data" reading as
/// [`selected_path`], so the number describes the link in use rather than a relay standby.
pub(crate) fn selected_rtt_ms(conn: &iroh::endpoint::Connection) -> Option<u64> {
    let paths = conn.paths();
    let selected = paths.iter().find(|p| p.is_selected())?;
    conn.rtt(selected.id()).map(|d| d.as_millis() as u64)
}
```

`classify` returns the source as a sixth element (default `Probe` on the unreachable arm), and
`probe_peer` uses it in the `reach_bcast.send` instead of the literal `Probe`. Update the existing
`classification_costs_neither_the_verdict_nor_the_rtt` test to build `Exchange { .. }` values.

- [ ] **Step 4: Run the reach tests.** All PASS. **Step 5: Mutation** (remove the live check;
separately, source `Probe`). Each FAIL. Restore. Record.
- [ ] **Step 6: Commit** `feat: the reach probe reads off a live session connection instead of dialling (#215)`.

---

### Task 10: Docs

**Files:**
- Modify: `docs/local-protocol.md` (Sessions section ~line 763; producer table ~line 1297)
- Modify: `local-api/src/protocol.rs:947-978` (doc only)

- [ ] **Step 1: Sessions section.** After the paragraph ending "until either side closes." add:

```markdown
**One connection per peer (0.54.0, #215).** Every `open_session` to the same peer rides ONE QUIC
connection as its own bi-stream — the accept side has multiplexed sessions this way since 0.1.0;
the dial side now uses it. The connection lives exactly as long as some session holds it: no idle
connection is kept warm, and nothing about keepalives or idle timeouts changes. Two consequences an
embedder should know: a connection-level event (idle timeout, the peer closing, a revoke severing)
ends every session on that connection at once rather than one; and a session that sets
`idle_timeout_secs` keeps its OWN connection, because that knob is per connection.
```

- [ ] **Step 2: Producer table.** Change the `"session"` row's *when* cell to
`its selected path changed under it (0.20.0), or a refresh read the live connection instead of dialling (0.54.0, #215)`
and the `"probe"` row's *when* cell to append `— and no session connection to the peer is live (0.54.0: with one, the refresh reads it and emits as `session`)`.

- [ ] **Step 3: `idle_timeout_secs` doc.** Append a paragraph:

```rust
    /// **Its own connection (0.54.0, #215).** Sessions to one peer normally share a single QUIC
    /// connection; a session that sets this cannot, because the timeout is a property of the
    /// connection. It dials its own, and plain sessions never join it.
```

- [ ] **Step 4: Commit** `docs: one connection per peer, and what the probe reads (#215)`.

---

### Task 11: Verify, untruncated

- [ ] `CARGO_BUILD_JOBS=3 cargo fmt --all`
- [ ] `CARGO_BUILD_JOBS=3 cargo clippy --workspace --all-targets` — zero warnings.
- [ ] `CARGO_BUILD_JOBS=3 cargo test --workspace --locked 2>&1 | tee /tmp/suite-215.log | grep -E "^test result|FAILED|panicked at"` — count `test result: ok` lines; report every failure verbatim. Foreground, timeout 600000 (use Monitor if it runs longer).
- [ ] Commit any fmt fallout.

### Task 12: Self-adversarial pass over `git diff 009118c..HEAD`

Check, and fix each with a regression test: a std lock held across an await on the session-open
path; a stale handle reused (upgrade ok, `close_reason` set); the first-dial race; authz bypass via
the shared connection; comments that overclaim; tests that pass with the feature deleted. Re-run
Task 11. Commit.
