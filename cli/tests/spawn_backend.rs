//! Task 7: the `run` (spawn) backend — one child MCP server per session, stdio
//! pumped to/from the QUIC-framed transport, resolved identity injected as env
//! vars, child killed on session close, concurrent spawns bounded per service.
//!
//! Hermetic: the child is `echo_mcp_stub` (a std-only in-crate binary reached via
//! `CARGO_BIN_EXE_echo_mcp_stub`), so the test needs no python3/node. The concrete
//! `SessionTransport` alias is iroh-typed, so `run()` cannot be driven over an
//! in-memory pipe; instead the test drives the generic seam `SpawnBackend::run_over`
//! (which `run()` delegates to) over a `tokio::io::duplex`. This exercises the REAL
//! spawn + env-injection + bidirectional pump — only the transport's byte substrate
//! differs from the iroh path.
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::backends::spawn::SpawnBackend;
use mcpmesh_net::PeerIdentity;
use mcpmesh_net::transport::NdjsonTransport;
use serde_json::json;
use tokio::io::{duplex, split};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const MAX_FRAME: usize = 16 * 1024 * 1024;
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

#[tokio::test]
async fn run_backend_pumps_frames_and_injects_identity() {
    timeout(Duration::from_secs(30), async {
        // Two ends of one in-memory pipe: the backend consumes the server end; the
        // test drives the client end as the AI-side peer would over the mesh.
        let (server_io, client_io) = duplex(64 * 1024);
        let (sr, sw) = split(server_io);
        let backend_transport = NdjsonTransport::new(sr, sw, MAX_FRAME);
        let (cr, cw) = split(client_io);
        let mut client = NdjsonTransport::new(cr, cw, MAX_FRAME);

        let backend = SpawnBackend {
            cmd: vec![STUB.to_string()],
            concurrency: Arc::new(Semaphore::new(4)),
            service: "test".into(),
            audit: mcpmesh::audit::AuditSink::disabled(),
            limiter: mcpmesh::limits::RateLimiter::unlimited_shared(),
        };
        // The gate-resolved identity, threaded through run_over per-caller (Task 9).
        let identity = Some(PeerIdentity {
            endpoint: [0u8; 32],
            name: "bob".into(),
            user_id: None,
            groups: vec![],
        });

        // The reserved-`_meta`-stripped initialize the daemon hands the backend.
        let initialize = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        });

        let session = tokio::spawn(async move {
            backend
                .run_over(identity, initialize, backend_transport)
                .await
        });

        // The forwarded initialize draws the child's InitializeResult back through
        // the transport — the first proof the child spawned and the pump is live.
        let init_resp = client.recv_value().await.unwrap().unwrap();
        assert_eq!(init_resp["id"], 1);
        assert_eq!(init_resp["result"]["serverInfo"]["name"], "echo-stub");

        // Drive a tools/call; assert the echo AND that the child saw MCPMESH_PEER_NAME.
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
        // Env injection proven: the child echoed back the injected identity name.
        assert_eq!(call_resp["result"]["peer_name"], "bob");

        // Closing the client end EOFs the transport → the backend drops the child
        // (kill_on_drop) and returns Ok — the session-close teardown path.
        drop(client);
        session
            .await
            .unwrap()
            .expect("run_over returns Ok on transport EOF");
    })
    .await
    .expect("spawn backend test timed out");
}

#[tokio::test]
async fn concurrency_cap_is_enforced() {
    timeout(Duration::from_secs(30), async {
        // Cap of one: the first session takes the only permit; a second overlapping
        // session must be refused with the concurrency-cap error (spec §6.2).
        let sem = Arc::new(Semaphore::new(1));

        let (server_io, client_io) = duplex(64 * 1024);
        let (sr, sw) = split(server_io);
        let backend_transport = NdjsonTransport::new(sr, sw, MAX_FRAME);
        let (cr, cw) = split(client_io);
        let mut client = NdjsonTransport::new(cr, cw, MAX_FRAME);

        let backend1 = SpawnBackend {
            cmd: vec![STUB.to_string()],
            concurrency: sem.clone(),
            service: "test".into(),
            audit: mcpmesh::audit::AuditSink::disabled(),
            limiter: mcpmesh::limits::RateLimiter::unlimited_shared(),
        };
        let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let session1 =
            tokio::spawn(async move { backend1.run_over(None, init, backend_transport).await });

        // Reading the first session's initialize response guarantees it has acquired
        // the permit and spawned its child — the two sessions now overlap.
        let resp = client.recv_value().await.unwrap().unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "echo-stub");

        // Second session against the same (exhausted) semaphore → refused before spawn.
        let (server_io2, client_io2) = duplex(64 * 1024);
        let (sr2, sw2) = split(server_io2);
        let backend_transport2 = NdjsonTransport::new(sr2, sw2, MAX_FRAME);
        let (cr2, cw2) = split(client_io2);
        let mut client2 = NdjsonTransport::new(cr2, cw2, MAX_FRAME);
        let backend2 = SpawnBackend {
            cmd: vec![STUB.to_string()],
            concurrency: sem.clone(),
            service: "test".into(),
            audit: mcpmesh::audit::AuditSink::disabled(),
            limiter: mcpmesh::limits::RateLimiter::unlimited_shared(),
        };
        // The backend HANDLES the cap: it sends -32053 + closes and returns Ok(()) — a clean
        // refusal, NOT a session error (so `serve` does not warn!("session ended with error")
        // for a normal, load-triggered refusal).
        backend2
            .run_over(
                None,
                json!({"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}}),
                backend_transport2,
            )
            .await
            .expect("cap refusal is handled cleanly (Ok), not a session error");
        // The caller RECEIVES a well-formed -32053 refusal (echoing the initialize id), not a
        // hang — the backend fully answers before returning.
        let refusal = client2
            .recv_value()
            .await
            .unwrap()
            .expect("a -32053 refusal frame, not EOF");
        assert_eq!(refusal["error"]["code"], -32053);
        assert_eq!(refusal["error"]["data"]["source"], "mcpmesh");
        assert_eq!(refusal["id"], 7, "the refusal echoes the initialize id");

        // Release the first session; it returns cleanly.
        drop(client);
        session1.await.unwrap().expect("first session returns Ok");
    })
    .await
    .expect("concurrency test timed out");
}
