//! M4c: LOCK the per-identity request rate-limit's PUMP WIRE BEHAVIOR (spec §7.3 / §11.2 P7).
//!
//! The rate-limit PRIMITIVE (`TokenBucket`/`RateLimiter`/`RateGate`) is unit-tested in `limits.rs`,
//! and the §16 M4 AC's "limiter engages + no unbounded memory" is proven at the primitive level in
//! `load_ac.rs`. This test locks the thing NEITHER of those covers: the actual WIRE integration in
//! `backends::pump`. A single session whose authenticated identity has a TINY token bucket is driven
//! through the REAL `SpawnBackend::run_over` seam — which builds the `RateGate` from the shared
//! limiter + the caller's `endpoint` exactly as production does — and we assert the three fail-safe
//! properties the pump owes an OVER-LIMIT proxied request:
//!   1. the caller gets a synthesized `-32053` throttle carrying `retry_after_ms` + `data.source="mcpmesh"`,
//!   2. the over-limit request is NOT forwarded to the server (DROPPED, never proxied through),
//!   3. the SESSION SURVIVES — after the bucket refills, a later under-limit request still round-trips
//!      (a throttle is bounded backpressure, NOT a session close).
//!
//! Harness mirrors `concurrency_cap.rs`/`spawn_backend.rs`: the hermetic `echo_mcp_stub` child + a
//! `tokio::io::duplex` standing in for the QUIC-framed transport. Only the byte substrate differs from
//! the iroh path; the `run_over` → `pump` logic (including the rate branch) is identical.
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::backends::spawn::SpawnBackend;
use mcpmesh::limits::RateLimiter;
use mcpmesh_net::PeerIdentity;
use mcpmesh_net::transport::NdjsonTransport;
use serde_json::json;
use tokio::io::{duplex, split};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const MAX_FRAME: usize = 16 * 1024 * 1024;
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

#[tokio::test]
async fn over_limit_request_is_throttled_dropped_and_the_session_survives() {
    timeout(Duration::from_secs(30), async {
        // Two ends of one in-memory pipe: the backend consumes the server end; the test drives the
        // client end as the AI-side peer would over the mesh (mirrors spawn_backend.rs).
        let (server_io, client_io) = duplex(64 * 1024);
        let (sr, sw) = split(server_io);
        let backend_transport = NdjsonTransport::new(sr, sw, MAX_FRAME);
        let (cr, cw) = split(client_io);
        let mut client = NdjsonTransport::new(cr, cw, MAX_FRAME);

        // A TINY per-identity bucket: burst 1, refilling 1 token/sec (per_minute = 60). Exactly one
        // proxied request is admitted; the next (issued before a refill) is over-limit; a token
        // returns after ~1s. `run_over` shares this limiter across callers and keys THIS session's
        // `RateGate` on the resolved `endpoint` — the production wiring under test.
        let limiter = Arc::new(RateLimiter::per_minute(60, 1));
        let backend = SpawnBackend {
            cmd: vec![STUB.to_string()],
            concurrency: Arc::new(Semaphore::new(4)),
            service: "test".into(),
            audit: mcpmesh::audit::AuditSink::disabled(),
            limiter,
        };
        // A resolved caller identity — the RateGate is keyed on `endpoint` (SECURITY invariant 1:
        // the authenticated id, never the self-asserted name).
        let identity = Some(PeerIdentity {
            endpoint: [7u8; 32],
            name: "bob".into(),
            user_id: None,
            groups: vec![],
        });
        let initialize = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {}}
        });

        let session = tokio::spawn(async move {
            backend
                .run_over(identity, initialize, backend_transport)
                .await
        });

        // `initialize` is forwarded pre-loop and is NEVER rate-checked: the child answers its
        // InitializeResult back through the pump. (Also confirms the child spawned + the pump is live.)
        let init = client.recv_value().await.unwrap().unwrap();
        assert_eq!(init["id"], 1);
        assert_eq!(init["result"]["serverInfo"]["name"], "echo-stub");

        // Baseline: the FIRST proxied request spends the bucket's only token → admitted → forwarded →
        // echoed back. Proves the gate is not blanket-blocking (and empties the bucket for the next).
        client
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"arguments": {"text": "first"}}
            }))
            .await
            .unwrap();
        let first = client.recv_value().await.unwrap().unwrap();
        assert_eq!(first["id"], 2);
        assert_eq!(
            first["result"]["content"][0]["text"], "first",
            "the under-limit request round-trips through the server"
        );

        // (1)+(2) The SECOND request (bucket now empty, no refill yet) is OVER LIMIT. The pump must
        // synthesize a -32053 back to the caller AND drop the request — never forward it to the child.
        client
            .send_value(json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"arguments": {"text": "over-the-limit"}}
            }))
            .await
            .unwrap();
        let throttled = client.recv_value().await.unwrap().unwrap();
        // (1) the fail-safe throttle answer: -32053 + an actionable retry hint + the mcpmesh marker,
        // echoing the over-limit request id.
        assert_eq!(
            throttled["id"], 3,
            "the throttle echoes the over-limit request id"
        );
        assert_eq!(throttled["error"]["code"], -32053);
        assert_eq!(throttled["error"]["data"]["source"], "mcpmesh");
        assert!(
            throttled["error"]["data"]["retry_after_ms"]
                .as_u64()
                .unwrap()
                >= 1,
            "the throttle carries a retry_after_ms hint"
        );
        // (2) DROPPED, not proxied: the answer is the SYNTHESIZED error, never the child's echo. Had
        // id=3 reached the echo stub it would have returned `result.content[0].text == "over-the-limit"`;
        // instead we got an error frame with no `result`. (The id=4 round-trip below is a second guard:
        // a stray forwarded echo of id=3 would arrive out of band and fail the `id == 4` assertion.)
        assert!(
            throttled.get("result").is_none(),
            "the over-limit request was dropped, not forwarded to the server: {throttled}"
        );

        // (3) SESSION SURVIVES: the throttle `continue`s the pump (no teardown). After the bucket
        // refills (~1s at 1 token/sec), a fresh under-limit request must still round-trip end-to-end.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        client
            .send_value(json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"arguments": {"text": "after-throttle"}}
            }))
            .await
            .unwrap();
        let survived = client.recv_value().await.unwrap().unwrap();
        assert_eq!(
            survived["id"], 4,
            "the next frame is id=4 — no stray forwarded echo of the dropped id=3"
        );
        assert_eq!(
            survived["result"]["content"][0]["text"], "after-throttle",
            "the session stayed alive: a post-throttle request round-trips"
        );

        // Closing the client EOFs the transport → run_over drops the child (kill_on_drop) and returns Ok.
        drop(client);
        session
            .await
            .unwrap()
            .expect("run_over returns Ok on transport EOF");
    })
    .await
    .expect("pump rate-limit wire test timed out");
}
