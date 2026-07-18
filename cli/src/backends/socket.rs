//! The `socket` backend (spec §6.2/§6.3): the daemon dials a long-running local
//! MCP server on its local endpoint (a UDS path on unix; a `\\.\pipe\…` name on
//! windows) per session and injects the resolved caller identity into the forwarded
//! `initialize` as `_meta["mcpmesh/peer"]`.
//!
//! The injection is AUTHORITATIVE — it REPLACES, never merges (§6.3). The value the
//! backend writes is the daemon-authored one; a caller-forged `_meta["mcpmesh/peer"]`
//! must never survive. In the real flow `select_service` has already STRIPPED every
//! caller `mcpmesh/*` key upstream, so the forged key is already gone — this REPLACE is
//! both defense-in-depth AND the single authoritative source of the value the warm
//! server trusts.
//!
//! Unlike the `run` backend, the server is a warm, shared process (e.g. the kb
//! daemon in M2+), so identity cannot travel as per-process env vars; it rides in
//! the MCP `initialize` `_meta` instead (§6.3). Once the socket is dialed and the
//! augmented `initialize` sent, the session is the SAME bidirectional frame pump the
//! spawn backend uses ([`super::pump`], one codec).
use anyhow::{Context, Result};
use mcpmesh_net::transport::NdjsonTransport;
use mcpmesh_net::{PeerIdentity, SessionBackend, SessionTransport};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::audit::{AuditSink, RequestAuditor};

/// The `socket` backend for one registered service. `path` is the long-running
/// local MCP server's endpoint (a UDS path on unix; a `\\.\pipe\…` name on windows),
/// dialed fresh per session. The caller
/// identity is NOT a field — it is threaded per-session through
/// [`SessionBackend::run`] (`Some` iff the peer resolved through the trust gate,
/// spec §6.3), because `serve` shares this backend across all callers (Task 9).
///
/// No per-session concurrency cap (conscious decision, spec §6.2): the cap scopes to
/// `run` (spawn) backends — one child per session, so unbounded sessions mean
/// unbounded processes. A `socket` backend dials ONE long-running server that
/// multiplexes its own sessions, so the daemon adds no per-session limit here; the
/// general per-identity defense against abuse is the M4 token bucket (§5). Hence no
/// `concurrency` field, unlike [`super::spawn::SpawnBackend`].
pub struct SocketBackend {
    pub path: String,
    /// This service's name (the registry key) — recorded as `service` in audit records (spec §11.3).
    pub service: String,
    /// The audit sink (spec §11.3). `AuditSink::disabled()` in tests / a non-audited build.
    pub audit: AuditSink,
    /// The per-authenticated-endpoint request limiter (spec §11.2 P7), shared across all backends.
    /// Consulted per proxied request line in [`pump`](super::pump). Keyed on `identity.endpoint`.
    pub limiter: std::sync::Arc<crate::limits::RateLimiter>,
}

#[async_trait::async_trait]
impl SessionBackend for SocketBackend {
    /// Drive one mesh session against a freshly dialed local MCP server. As with the
    /// spawn backend, the concrete `SessionTransport` alias is iroh-typed, so the
    /// dial + inject + pump body lives in the transport-generic [`SocketBackend::run_over`]
    /// so it is exercisable over an in-memory pipe + a stub UDS server in tests.
    async fn run(
        &self,
        identity: Option<PeerIdentity>,
        initialize: Value,
        transport: SessionTransport,
    ) -> anyhow::Result<()> {
        self.run_over(identity, initialize, transport).await
    }
}

impl SocketBackend {
    /// The transport-generic core of [`SessionBackend::run`]: dial the server's local
    /// endpoint (UDS on unix; named pipe on windows), inject the daemon-authored identity
    /// into the `initialize` `_meta`
    /// authoritatively (REPLACE-not-merge), then pump frames both ways until either
    /// side ends. Generic over the transport's byte substrate so the real path (iroh
    /// streams) and the test path (`tokio::io::duplex`) share one implementation.
    pub async fn run_over<R, W>(
        &self,
        identity: Option<PeerIdentity>,
        mut initialize: Value,
        mut transport: NdjsonTransport<R, W>,
    ) -> Result<()>
    where
        R: AsyncRead + Send + Unpin,
        W: AsyncWrite + Send + Unpin,
    {
        let server = mcpmesh_local_api::transport::connect_local(std::path::Path::new(&self.path))
            .await
            .with_context(|| format!("dial socket backend at {}", self.path))?;

        if let Some(id) = &identity {
            // REPLACE-not-merge (§6.3 + the Task 9 seam note): a caller-forged
            // `mcpmesh/peer` must never survive. Guard non-object shapes before indexing
            // — `Value`'s IndexMut PANICS on a non-object base — building each level:
            //   * root: a bare array/string/number/bool first frame would panic on the
            //     `initialize["params"]` write below (reachable once T9 wires this:
            //     select_service's key-absent default forwards even a non-object frame).
            //     A fresh object discards it; a null root is coerced by IndexMut anyway.
            //   * params / _meta: absent or non-object → build an empty object.
            if !initialize.is_object() {
                initialize = serde_json::json!({});
            }
            if !initialize["params"].is_object() {
                initialize["params"] = serde_json::json!({});
            }
            if !initialize["params"]["_meta"].is_object() {
                initialize["params"]["_meta"] = serde_json::json!({});
            }
            // Whole-value overwrite: forged `groups`/`user_id` (authorization-relevant,
            // §6.3) are dropped along with a forged `name`, not merged over.
            initialize["params"]["_meta"]["mcpmesh/peer"] = serde_json::json!({
                "name": id.name,
                // The peer's self-sovereign user_id: the org roster value in roster mode, else the
                // one proven by a verified device->user binding at pairing (null only for a pairing
                // peer that presented no binding). A service (e.g. kb) may key an audience on it so
                // all of a person's devices resolve together — forge-proof, since this whole object
                // is authoritatively OVERWRITTEN here, never merged over a caller-forged one.
                "user_id": id.user_id,
                "groups": id.groups,
            });
        }

        // Session lifecycle audit (spec §11.3): attribute to the gate-resolved identity — the roster
        // user_id when present, else the petname (endpoint_id-keyed authenticated name, never a
        // self-asserted one). `None` only on a hypothetical no-identity path.
        let peer = identity
            .as_ref()
            .map(|id| id.user_id.clone().unwrap_or_else(|| id.name.clone()));
        // Session lifecycle via the RAII guard: it emits `session_open` now and, on drop (every exit
        // path — EOF, error, panic), emits `session_close` and removes the live-table row. Held for
        // the whole session scope, so it MUST outlive the pump below.
        let _session = self
            .audit
            .session(peer.clone().unwrap_or_default(), self.service.clone());
        // The per-request-line auditor (Task 4): hashes each caller request's args and correlates
        // the response. Threaded into the shared pump.
        let auditor = RequestAuditor::new(self.audit.clone(), peer.clone(), self.service.clone());

        // Split the endpoint: the read half is consumed by the pump's outbound direction
        // (its FrameReader), the write half by the inbound direction. Both are owned
        // by their respective concurrent loops; on EOF they drop here, closing the
        // connection to the server.
        let (server_read, server_write) = mcpmesh_local_api::transport::split_local(server);
        let outcome = super::pump(
            initialize,
            &mut transport,
            server_read,
            server_write,
            auditor,
            crate::limits::RateGate::new(
                self.limiter.clone(),
                identity.as_ref().map(|i| i.endpoint),
            ),
        )
        .await;
        // `_session` drops here (or on any early return above), emitting `session_close`.
        outcome
    }
}

// Unix-only: every stub MCP server binds a raw `UnixListener` and uses `into_split()`.
// Production `SocketBackend` dials through the cross-platform seam
// (`transport::connect_local`); these fixtures exercise it against a UDS stub. On the
// windows CI leg the seam's pipe path is covered by `transport::windows`' own tests.
#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use mcpmesh_net::PeerIdentity;
    use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
    use serde_json::{Value, json};
    use tokio::io::{BufReader, duplex, split};
    use tokio::net::UnixListener;
    use tokio::time::timeout;

    use super::SocketBackend;

    const MAX_FRAME: usize = 16 * 1024 * 1024;

    /// A stub long-running MCP server on a UDS: accept one connection, read the
    /// `initialize`, reply with an InitializeResult, then echo a single `tools/call`
    /// (mirroring the frame's `text` back). Returns the observed `initialize` so the
    /// test can assert what the backend forwarded (the injected identity, or verbatim
    /// passthrough when identity is None). The whole exchange completes before the
    /// returned value resolves, so awaiting the handle sequences correctly.
    async fn stub_server(listener: UnixListener) -> Value {
        let (stream, _) = listener.accept().await.expect("stub accept");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = FrameReader::new(BufReader::new(read_half), MAX_FRAME);

        let init = match reader
            .next()
            .await
            .expect("read initialize")
            .expect("initialize frame")
        {
            Inbound::Frame(v) => v,
            Inbound::Violation(_) => panic!("stub saw a framing violation on initialize"),
        };
        write_frame(
            &mut write_half,
            &json!({
                "jsonrpc": "2.0", "id": init["id"].clone(),
                "result": {"serverInfo": {"name": "socket-stub"}}
            }),
        )
        .await
        .expect("reply initialize");

        let call = match reader
            .next()
            .await
            .expect("read tools/call")
            .expect("tools/call frame")
        {
            Inbound::Frame(v) => v,
            Inbound::Violation(_) => panic!("stub saw a framing violation on tools/call"),
        };
        write_frame(
            &mut write_half,
            &json!({
                "jsonrpc": "2.0", "id": call["id"].clone(),
                "result": {"content": [{"text": call["params"]["arguments"]["text"].clone()}]}
            }),
        )
        .await
        .expect("echo tools/call");

        init
    }

    /// A caller-forged `_meta["mcpmesh/peer"]` in the incoming `initialize` is
    /// OVERWRITTEN (not merged) by the daemon-authored identity, the stub sees the
    /// real peer, and the bidirectional echo works.
    #[tokio::test]
    async fn socket_backend_injects_authoritative_peer_and_echoes() {
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "test".into(),
                audit: crate::audit::AuditSink::disabled(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });

            // A FORGED mcpmesh/peer rides in the incoming initialize — carrying not just a
            // fake `name` but forged AUTHORIZATION fields (`groups`, `user_id`).
            // select_service strips it upstream in the real flow; here it is present to
            // prove the backend itself REPLACES the whole value (defense-in-depth +
            // authoritative source), so forged authz can never leak to the server.
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "_meta": {"mcpmesh/peer": {
                        "name": "attacker", "groups": ["admin"], "user_id": "root"
                    }}
                }
            });

            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            // The forwarded initialize draws the stub's InitializeResult back.
            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["id"], 1);
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");

            // Drive a tools/call; the echo proves the pump is live both directions.
            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "hello mesh"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["id"], 2);
            assert_eq!(call_resp["result"]["content"][0]["text"], "hello mesh");

            // The stub observed the daemon-authored identity — whole-value REPLACE held:
            // the forged name AND the forged authorization fields were all dropped.
            let observed_init = stub.await.unwrap();
            let peer = &observed_init["params"]["_meta"]["mcpmesh/peer"];
            assert_eq!(
                peer["name"], "bob",
                "forged 'attacker' name must be overwritten"
            );
            assert_eq!(
                peer["groups"],
                json!([]),
                "forged groups ['admin'] must be dropped, not merged"
            );
            assert_eq!(
                peer["user_id"],
                json!(null),
                "forged user_id 'root' must be dropped (pairing-mode identity is null)"
            );

            // Closing the client EOFs the transport → the backend drops the server
            // connection and returns Ok — the session-close teardown path.
            drop(client);
            session
                .await
                .unwrap()
                .expect("run_over returns Ok on transport EOF");
        })
        .await
        .expect("socket backend test timed out");
    }

    /// `params` absent entirely: the backend builds `params` then `_meta` and injects
    /// cleanly (the Task 9 seam note — params may be non-object, guard it).
    #[tokio::test]
    async fn socket_backend_builds_params_when_absent() {
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "test".into(),
                audit: crate::audit::AuditSink::disabled(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });

            // No `params` key at all — the backend must synthesize params + _meta.
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize"
            });

            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");

            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "built params"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["result"]["content"][0]["text"], "built params");

            let observed_init = stub.await.unwrap();
            assert_eq!(
                observed_init["params"]["_meta"]["mcpmesh/peer"]["name"],
                "bob"
            );

            drop(client);
            session
                .await
                .unwrap()
                .expect("run_over returns Ok on transport EOF");
        })
        .await
        .expect("socket params-build test timed out");
    }

    /// A non-object root first frame (a bare array) with identity `Some` must NOT
    /// panic: the root guard replaces it with a fresh object and injects cleanly.
    /// Reachable once T9 wires this backend (select_service's key-absent default
    /// forwards even a non-object frame), and `Value`'s IndexMut panics on a
    /// non-object base — so the guard is load-bearing, not cosmetic.
    #[tokio::test]
    async fn socket_backend_guards_non_object_root() {
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "test".into(),
                audit: crate::audit::AuditSink::disabled(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });

            // A bare JSON array as the first frame — `initialize["params"]` would panic
            // without the root guard.
            let initialize = json!([1, 2, 3]);

            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            // The stub replies to the forwarded (rebuilt) frame with an id of null.
            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");

            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "fresh object"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["result"]["content"][0]["text"], "fresh object");

            // The bare array was discarded; a fresh object carries only the injected id.
            let observed_init = stub.await.unwrap();
            assert_eq!(
                observed_init["params"]["_meta"]["mcpmesh/peer"]["name"],
                "bob"
            );

            drop(client);
            session
                .await
                .unwrap()
                .expect("run_over returns Ok on transport EOF");
        })
        .await
        .expect("socket non-object-root test timed out");
    }

    /// identity `None` (an unresolved/pairing-less caller): NO injection at all — the
    /// initialize is forwarded VERBATIM, including any `_meta` the caller carried. The
    /// passthrough path, matching the spawn backend's non-object-verbatim behavior.
    #[tokio::test]
    async fn socket_backend_no_identity_forwards_verbatim() {
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "test".into(),
                audit: crate::audit::AuditSink::disabled(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity: Option<PeerIdentity> = None;

            // Carries a `_meta` that the backend must NOT touch (no injection when None).
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"capabilities": {}, "_meta": {"caller": "kept"}}
            });

            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");

            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "no id"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["result"]["content"][0]["text"], "no id");

            // Verbatim: no `mcpmesh/peer` was injected, and the caller's `_meta` survived.
            let observed_init = stub.await.unwrap();
            assert!(
                observed_init["params"]["_meta"]["mcpmesh/peer"].is_null(),
                "identity None must inject nothing"
            );
            assert_eq!(observed_init["params"]["_meta"]["caller"], "kept");

            drop(client);
            session
                .await
                .unwrap()
                .expect("run_over returns Ok on transport EOF");
        })
        .await
        .expect("socket no-identity test timed out");
    }

    /// A stub that emits a LARGE server-initiated notification BEFORE reading the
    /// client's large `tools/call` — forcing simultaneous large writes in BOTH
    /// directions. A single-loop pump (write awaited inside the `select!` arm) would
    /// wedge here: forwarding the client's large request blocks because we are not
    /// draining our large notification, and we cannot drain it because we are blocked
    /// forwarding — a classic full-duplex deadlock. The concurrent pump keeps both
    /// directions moving. Echoes the tools/call text on the way out.
    async fn deadlock_stub(listener: UnixListener, big: String) {
        let (stream, _) = listener.accept().await.expect("stub accept");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = FrameReader::new(BufReader::new(read_half), MAX_FRAME);

        let init = match reader.next().await.unwrap().unwrap() {
            Inbound::Frame(v) => v,
            Inbound::Violation(_) => panic!("violation on initialize"),
        };
        write_frame(
            &mut write_half,
            &json!({
                "jsonrpc": "2.0", "id": init["id"].clone(),
                "result": {"serverInfo": {"name": "socket-stub"}}
            }),
        )
        .await
        .unwrap();

        // Large server-initiated notification, written before reading the request.
        write_frame(
            &mut write_half,
            &json!({
                "jsonrpc": "2.0", "method": "notifications/message",
                "params": {"data": big}
            }),
        )
        .await
        .unwrap();

        let call = match reader.next().await.unwrap().unwrap() {
            Inbound::Frame(v) => v,
            Inbound::Violation(_) => panic!("violation on tools/call"),
        };
        write_frame(
            &mut write_half,
            &json!({
                "jsonrpc": "2.0", "id": call["id"].clone(),
                "result": {"content": [{"text": call["params"]["arguments"]["text"].clone()}]}
            }),
        )
        .await
        .unwrap();
    }

    /// The pump survives simultaneous large bidirectional traffic — proving the
    /// concurrent-directions fix. A single-loop pump would hang to the 30s timeout
    /// (and, in the spawn backend, leak the child + the concurrency permit). 2 MiB
    /// exceeds both the 64 KiB transport duplex and any AF_UNIX socket buffer, so the
    /// writes genuinely block, which is the deadlock precondition.
    #[tokio::test]
    async fn pump_survives_simultaneous_large_bidirectional_traffic() {
        timeout(Duration::from_secs(30), async {
            let big = "x".repeat(2 * 1024 * 1024);
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(deadlock_stub(listener, big.clone()));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "test".into(),
                audit: crate::audit::AuditSink::disabled(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"capabilities": {}}
            });
            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            // Send the large request CONCURRENTLY with draining incoming frames (using
            // the transport's own writer split), so the TEST itself doesn't serialize
            // send-then-recv and mask the deadlock the pump must avoid.
            let client_writer = client.writer();
            let big_arg = big.clone();
            let sender = tokio::spawn(async move {
                client_writer
                    .send_value(json!({
                        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"arguments": {"text": big_arg}}
                    }))
                    .await
            });

            let (mut saw_init, mut saw_notification, mut saw_echo) = (false, false, false);
            while !(saw_init && saw_notification && saw_echo) {
                let frame = client.recv_value().await.unwrap().unwrap();
                if frame["method"] == "notifications/message" {
                    assert_eq!(frame["params"]["data"].as_str().unwrap().len(), big.len());
                    saw_notification = true;
                } else if frame["id"] == 2 {
                    assert_eq!(
                        frame["result"]["content"][0]["text"]
                            .as_str()
                            .unwrap()
                            .len(),
                        big.len()
                    );
                    saw_echo = true;
                } else if frame["id"] == 1 {
                    assert_eq!(frame["result"]["serverInfo"]["name"], "socket-stub");
                    saw_init = true;
                }
            }

            sender.await.unwrap().unwrap();
            stub.await.unwrap();

            drop(client);
            session
                .await
                .unwrap()
                .expect("run_over returns Ok on transport EOF");
        })
        .await
        .expect("large-frame pump deadlocked (the old single-loop pump would hang here)");
    }

    /// A driven session emits exactly one `session_open` and one `session_close` record for the
    /// resolved peer + service (spec §11.3 session lifecycle). Uses a real temp-dir AuditLog.
    #[tokio::test]
    async fn socket_backend_records_session_open_and_close() {
        use crate::audit::{AuditLog, AuditSink};
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let audit_dir = dir.path().join("audit");
            let sink = AuditSink::new(AuditLog::spawn(audit_dir.clone()));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "notes".into(),
                audit: sink,
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"capabilities": {}}
            });
            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");
            // Drive one tools/call so the stub's exchange completes cleanly before teardown (the
            // stub reads exactly one tools/call after initialize). The session still opens once and
            // closes once — the lifecycle records under test are unaffected.
            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "lifecycle"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["result"]["content"][0]["text"], "lifecycle");
            drop(client); // EOF → the backend returns → session_close is recorded
            session.await.unwrap().expect("run_over Ok on EOF");
            stub.await.unwrap();

            // Poll the audit file until both lifecycle records land.
            let month = &crate::audit::now_ts()[..7];
            let file = audit_dir.join(format!("{month}.jsonl"));
            let mut opens = 0;
            let mut closes = 0;
            for _ in 0..50 {
                if let Ok(body) = std::fs::read_to_string(&file) {
                    opens = body.matches("\"kind\":\"session_open\"").count();
                    closes = body.matches("\"kind\":\"session_close\"").count();
                    if opens == 1 && closes == 1 {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                (opens, closes),
                (1, 1),
                "one open + one close for the session"
            );
            let body = std::fs::read_to_string(&file).unwrap();
            assert!(
                body.contains("\"peer\":\"bob\""),
                "attributed to the resolved peer"
            );
            assert!(body.contains("\"service\":\"notes\""));
        })
        .await
        .expect("session lifecycle audit test timed out");
    }

    /// While a session is live the audit sink's live-session table has exactly one row for the
    /// resolved peer + service, and it is emptied once the session ends — proving the backend drives
    /// the RAII session guard (not two bare open/close records) so the telemetry snapshot sees it.
    #[tokio::test(flavor = "multi_thread")]
    async fn socket_backend_populates_active_sessions_while_open() {
        use crate::audit::{AuditLog, AuditSink};
        timeout(Duration::from_secs(30), async {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("server.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stub = tokio::spawn(stub_server(listener));

            let sink = AuditSink::new(AuditLog::spawn(dir.path().join("audit")));

            let (server_io, client_io) = duplex(64 * 1024);
            let (sr, sw) = split(server_io);
            let backend_transport = mcpmesh_net::transport::NdjsonTransport::new(sr, sw, MAX_FRAME);
            let (cr, cw) = split(client_io);
            let mut client = mcpmesh_net::transport::NdjsonTransport::new(cr, cw, MAX_FRAME);

            let backend = SocketBackend {
                path: sock.to_str().unwrap().to_string(),
                service: "notes".into(),
                audit: sink.clone(),
                limiter: crate::limits::RateLimiter::unlimited_shared(),
            };
            let identity = Some(PeerIdentity {
                endpoint: [0u8; 32],
                name: "bob".into(),
                user_id: None,
                groups: vec![],
            });
            let initialize = json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"capabilities": {}}
            });

            assert!(
                sink.active_sessions().is_empty(),
                "no live session before the backend runs"
            );

            let session = tokio::spawn(async move {
                backend
                    .run_over(identity, initialize, backend_transport)
                    .await
            });

            // Complete the handshake so the session's guard is definitely created (it is built before
            // the pump, which forwards this initialize).
            let init_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(init_resp["result"]["serverInfo"]["name"], "socket-stub");

            // DURING the session: exactly one live row for the resolved peer + service.
            let live = sink.active_sessions();
            assert_eq!(live.len(), 1, "one live session while open");
            assert_eq!(live[0].peer, "bob");
            assert_eq!(live[0].service, "notes");

            // Drive one tools/call so the stub's exchange completes cleanly before teardown.
            client
                .send_value(json!({
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"arguments": {"text": "live"}}
                }))
                .await
                .unwrap();
            let call_resp = client.recv_value().await.unwrap().unwrap();
            assert_eq!(call_resp["result"]["content"][0]["text"], "live");

            drop(client); // EOF → the backend returns → the guard drops → the row is removed
            session.await.unwrap().expect("run_over Ok on EOF");
            stub.await.unwrap();

            // AFTER the session: the live table is empty again.
            assert!(
                sink.active_sessions().is_empty(),
                "the guard drop removed the live session"
            );
        })
        .await
        .expect("active-sessions telemetry test timed out");
    }
}
