//! Task 9 acceptance: the daemon's serving composition end-to-end over a real (localhost)
//! Iroh mesh. This drives the SAME wiring `daemon::run()` builds — config `[services.*]` →
//! [`mcpmesh::daemon::build_services`] (`run` = [`SpawnBackend`]) → [`AllowlistGate`] over a
//! [`PeerStore`] → `mcpmesh_net::serve` — but against in-process endpoints, so it can assert
//! the whole chain including the ENV IDENTITY INJECTION the child sees, without a daemon
//! subprocess or the pairing ceremony (trust is populated via the store, the `internal peer
//! add` stand-in).
//!
//! The proof of injection is end-to-end: the served child is `echo_mcp_stub`, which echoes
//! back `getenv("MCPMESH_PEER_NAME")` as `result.peer_name`. The connecting peer resolves (at
//! the gate) to petname `tester`; asserting `peer_name == "tester"` at the far end proves the
//! gate-resolved identity threaded through `SessionBackend::run` all the way into the child's
//! environment across the mesh.
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::build_services;
use mcpmesh_net::{SessionTransport, TrustGate, connect, serve};
use serde_json::{Value, json};
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only endpoint carrying the mcpmesh/mcp/1 ALPN (relay disabled — hermetic, no
/// network egress; matches the daemon's `relay_mode = "disabled"` path).
async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

#[tokio::test]
async fn daemon_serves_run_service_and_injects_caller_identity_over_the_mesh() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // Config: one `run` service `echo` = the hermetic stub, admitting petname `tester`.
        // A TOML literal string ('..') for the path avoids any escape concerns.
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"tester\"]\n"
        ))
        .expect("parse config");

        // The "client machine": a second in-process endpoint. Its endpoint id is the trust
        // key we populate (the `internal peer add` stand-in).
        let client = local_endpoint().await;
        let client_id = *client.id().as_bytes();

        // Populate trust: `internal peer add tester <client id>` → a PeerEntry in the store.
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        store
            .add(PeerEntry {
                endpoint_id: client_id,
                petname: "tester".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(store)));

        // The "server machine": build the endpoint + registry + gate the daemon would, and
        // serve.
        let server = local_endpoint().await;
        let addr = server.addr();
        let _handle = serve(server, gate, build_services(&cfg));

        // Connect as the trusted peer and complete initialize + tools/call.
        let mut transport = connect(&client, addr, "echo").await.unwrap();
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "_meta": {"mcpmesh/service": "echo"},
                    "capabilities": {}, "clientInfo": {"name": "tester", "version": "0"}
                }
            }))
            .await
            .unwrap();
        let init_res = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init_res["result"]["serverInfo"]["name"], "echo-stub",
            "the served child answered initialize over the mesh"
        );

        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "over the mesh"}}
            }))
            .await
            .unwrap();
        let call_res = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            call_res["result"]["content"][0]["text"], "over the mesh",
            "the served child echoed the tools/call payload"
        );
        // The end-to-end env-injection proof: the child saw MCPMESH_PEER_NAME=tester — the
        // gate-resolved identity flowed through run() into the spawned child's environment.
        assert_eq!(
            call_res["result"]["peer_name"], "tester",
            "the child's MCPMESH_PEER_NAME carried the gate-resolved petname across the mesh"
        );
    })
    .await
    .expect("daemon serve integration test timed out");
}

/// Send an `initialize` naming `service` and return the first response frame (an
/// InitializeResult, or a synthesized refusal like -32054).
async fn send_initialize(transport: &mut SessionTransport, service: &str) -> Value {
    transport
        .send_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "_meta": {"mcpmesh/service": service},
                "capabilities": {}
            }
        }))
        .await
        .unwrap();
    transport.recv_value().await.unwrap().unwrap()
}

/// The hot-reload's real purpose: after the live serve loop is SWAPPED (the exact mechanic
/// `register_service` uses — `old.shutdown()` + `serve(endpoint.clone(), gate,
/// build_services(new_cfg))`), a NEWLY-registered service is actually SERVED over the mesh.
/// Before the swap the service is refused (-32054, not in the registry); after the swap a real
/// second endpoint completes initialize + tools/call against it (with identity injected).
/// This guards the FIX-1 reload path — a torn or lost-update config would yield a dead/wrong
/// registry — and proves the swap installs a LIVE serve, not just a fresh accept loop.
#[tokio::test]
async fn hot_reload_serves_a_newly_registered_service_over_the_mesh() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // Two connectors, both trusted as `tester`. Distinct endpoints → distinct
        // connections, so the post-swap dial cannot reuse the pre-swap (old-registry) one.
        let before = local_endpoint().await;
        let after = local_endpoint().await;
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        for c in [&before, &after] {
            store
                .add(PeerEntry {
                    endpoint_id: *c.id().as_bytes(),
                    petname: "tester".into(),
                    services: vec!["echo".into()],
                    paired_at: None,
                    user_id: None,
                })
                .unwrap();
        }
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(store)));

        let server = local_endpoint().await;

        // Serve an EMPTY registry first — `echo` is not yet registered.
        let handle = serve(
            server.clone(),
            gate.clone(),
            build_services(&Config::from_toml_str("").unwrap()),
        );

        // Pre-swap: `echo` is refused (unknown/unauthorized service, §5).
        let mut t_before = connect(&before, server.addr(), "echo").await.unwrap();
        let refused = send_initialize(&mut t_before, "echo").await;
        assert_eq!(
            refused["error"]["code"], -32054,
            "echo must be UNSERVED before the reload: {refused}"
        );

        // Hot-reload swap (the register_service mechanic): stop the old loop, serve a registry
        // that now carries `echo` on the SAME endpoint.
        handle.shutdown();
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"tester\"]\n"
        ))
        .unwrap();
        let _new_handle = serve(server.clone(), gate.clone(), build_services(&cfg));

        // Post-swap: a real second endpoint completes initialize + tools/call against the
        // newly-served `echo`, identity injected.
        let mut t_after = connect(&after, server.addr(), "echo").await.unwrap();
        let init = send_initialize(&mut t_after, "echo").await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "echo must be SERVED after the reload: {init}"
        );
        t_after
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"arguments": {"text": "after reload"}}
            }))
            .await
            .unwrap();
        let call = t_after.recv_value().await.unwrap().unwrap();
        assert_eq!(call["result"]["content"][0]["text"], "after reload");
        assert_eq!(
            call["result"]["peer_name"], "tester",
            "identity injection still holds through the reloaded serve loop"
        );
    })
    .await
    .expect("hot-reload serve test timed out");
}
