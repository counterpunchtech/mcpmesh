//! M4c T4 (spec §16 M4 AC "spawn-bomb attempts hit the concurrency cap"; §11.2 P7): a `run` service
//! whose per-service concurrency permit is already exhausted answers a new session with a well-formed
//! -32053 carrying `retry_after_ms` and spawns NO child (FAIL-SAFE deny). Deterministic: the single
//! permit is pre-acquired and HELD, so `try_acquire_owned` in the backend fails immediately.
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
async fn concurrency_cap_refuses_with_retry_after_ms_and_spawns_no_child() {
    timeout(Duration::from_secs(30), async {
        // A one-permit semaphore, EXHAUSTED before the session runs (a spawn already in flight).
        let sem = Arc::new(Semaphore::new(1));
        let _held = sem
            .clone()
            .try_acquire_owned()
            .expect("take the only permit");

        let (server_io, client_io) = duplex(64 * 1024);
        let (sr, sw) = split(server_io);
        let backend_transport = NdjsonTransport::new(sr, sw, MAX_FRAME);
        let (cr, cw) = split(client_io);
        let mut client = NdjsonTransport::new(cr, cw, MAX_FRAME);

        let backend = SpawnBackend {
            cmd: vec![STUB.to_string()],
            concurrency: sem,
            service: "test".into(),
            audit: mcpmesh::audit::AuditSink::disabled(),
            limiter: mcpmesh::limits::RateLimiter::unlimited_shared(),
        };
        let identity = Some(PeerIdentity {
            endpoint: [1u8; 32],
            name: "bob".into(),
            user_id: None,
            groups: vec![],
        });
        let initialize = json!({
            "jsonrpc": "2.0", "id": 7, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        });

        let session = tokio::spawn(async move {
            backend
                .run_over(identity, initialize, backend_transport)
                .await
        });

        // The client observes the cap refusal: -32053 with data.retry_after_ms and the mcpmesh marker.
        let reply = client.recv_value().await.unwrap().unwrap();
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"]["code"], -32053);
        assert_eq!(reply["error"]["data"]["source"], "mcpmesh");
        assert!(reply["error"]["data"]["retry_after_ms"].as_u64().unwrap() >= 1);
        // The refused session returns Ok(()) (a clean, load-triggered refusal, not a session error).
        assert!(session.await.unwrap().is_ok());
    })
    .await
    .expect("concurrency cap test timed out");
}
