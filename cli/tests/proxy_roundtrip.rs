//! Task 10 acceptance: the connect proxy round-trip — the first real end-to-end AI-client
//! path through the mcpmesh stack (the T12 hero flow builds on it).
//!
//! DECLARED test shape (the plan's blessed in-process variant): a REAL `mcpmesh connect`
//! subprocess drives its stdin/stdout against a control socket served by an in-process daemon
//! (`daemon::serving_state` + the REAL `serve_control`), which dials an in-process "server
//! machine" endpoint serving an echo `run` service over the mesh. This exercises the actual
//! surfaces T10 delivers — the proxy's stdin/stdout pump, the control server's `open_session`
//! routing, the daemon's dial-by-id, and the session pipe — without a two-daemon subprocess
//! mesh (which would need discovery seeding INSIDE the daemon subprocess; see below).
//!
//! Dial-by-id reconcile: production dials an id-only `iroh::EndpointAddr` and lets iroh's
//! DNS/pkarr discovery (N0 preset) resolve addresses from the id (spec §10.2). On localhost
//! (relay disabled, no discovery) the connecting endpoint is seeded with the target's
//! addresses via a `MemoryLookup` on `endpoint.address_lookup()` — the runtime equivalent of
//! iroh's (absent in 1.0.1) addressbook-add, so the SAME id-only dial resolves locally and
//! the production `dial_service` code is unchanged.
// Unix-only: this suite hand-binds the control endpoint in-process
// (`bind_control_socket`) at a filesystem socket path a child resolves, which a windows
// named pipe cannot be. Windows coverage for the control path lives at the transport layer
// (local-api transport::windows pipe tests) and the client protocol layer (local-api
// client.rs seam tests); a windows daemon-subprocess round-trip is deferred — see the
// plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{self, build_services};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::{TrustGate, serve};
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");
const MCPMESH: &str = env!("CARGO_BIN_EXE_mcpmesh");
const MAX_FRAME: usize = 16 * 1024 * 1024;

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
async fn connect_proxy_round_trips_an_echo_service_over_the_mesh() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // --- The "server machine": serves an echo `run` service to petname `daemon`. ---
        let server_ep = local_endpoint().await;
        let server_id = *server_ep.id().as_bytes();
        let server_addr = server_ep.addr();

        // The connecting side is the in-process daemon's endpoint; capture its id first so the
        // server's gate can trust it (the mesh peer the server sees is the daemon endpoint).
        let daemon_ep = local_endpoint().await;
        let daemon_id = *daemon_ep.id().as_bytes();

        let server_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"daemon\"]\n"
        ))
        .expect("parse server config");
        let server_store = PeerStore::open(&dir.path().join("server_state.redb")).unwrap();
        server_store
            .add(PeerEntry {
                endpoint_id: daemon_id,
                petname: "daemon".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let server_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(server_store)));
        let _server_handle = serve(server_ep, server_gate, build_services(&server_cfg));

        // --- The "daemon machine": resolves petname `tester` -> the server endpoint, dials. ---
        // Seed dial-by-id resolution: the daemon endpoint learns the server's addrs via a
        // MemoryLookup (the localhost stand-in for DNS/pkarr discovery).
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(server_addr);
        daemon_ep
            .address_lookup()
            .expect("address lookup services")
            .add(mem);

        let daemon_store =
            Arc::new(PeerStore::open(&dir.path().join("daemon_state.redb")).unwrap());
        daemon_store
            .add(PeerEntry {
                endpoint_id: server_id,
                petname: "tester".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();

        // Bind the control socket at the path a subprocess with XDG_RUNTIME_DIR=<tmp> resolves
        // (default_socket_path = <XDG_RUNTIME_DIR>/mcpmesh/mcpmesh.sock), and run the REAL control
        // server over the composed serving state.
        let socket = dir.path().join("mcpmesh").join("mcpmesh.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = daemon::serving_state(daemon_ep, daemon_store);
        let control = tokio::spawn(mcpmesh::control::serve_control(listener, state));

        // --- The AI client: run `mcpmesh connect tester/echo` as a real subprocess. ---
        let mut child = Command::new(MCPMESH)
            .arg("connect")
            .arg("tester/echo")
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mcpmesh connect");
        let mut child_in = child.stdin.take().unwrap();
        let mut child_out =
            FrameReader::new(BufReader::new(child.stdout.take().unwrap()), MAX_FRAME);

        // initialize (no mcpmesh/service meta — the daemon injects it): the served echo-stub
        // answers over the mesh, byte-faithfully back to the proxy's stdout.
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "ai", "version": "0"}}
            }),
        )
        .await
        .unwrap();
        let init = next_frame(&mut child_out).await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "the served child answered initialize back through the proxy: {init}"
        );

        // tools/call → the payload is echoed verbatim, and MCPMESH_PEER_NAME carried the
        // gate-resolved petname (`daemon`) into the child across the mesh.
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "through the proxy"}}
            }),
        )
        .await
        .unwrap();
        let call = next_frame(&mut child_out).await;
        assert_eq!(
            call["result"]["content"][0]["text"], "through the proxy",
            "the echoed tools/call payload round-tripped byte-faithfully: {call}"
        );
        assert_eq!(
            call["result"]["peer_name"], "daemon",
            "the child saw the gate-resolved identity across the mesh"
        );

        // Closing stdin ends the proxy cleanly (spec §8) — no hang.
        child_in.shutdown().await.unwrap();
        drop(child_in);
        let status = timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("proxy did not exit after stdin close")
            .unwrap();
        assert!(status.success(), "proxy exited non-zero: {status}");

        control.abort();
    })
    .await
    .expect("proxy round-trip test timed out");
}

/// The unreachable path (spec §8): `connect` for a peer that is NOT in the allowlist must hand
/// the AI client a well-formed `-32055` error frame — not a hang — then exit cleanly.
#[tokio::test]
async fn connect_proxy_answers_unreachable_with_minus_32055() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let daemon_ep = local_endpoint().await;
        // Empty store: `ghost` resolves to no endpoint → dial establishment fails.
        let daemon_store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());

        let socket = dir.path().join("mcpmesh").join("mcpmesh.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = daemon::serving_state(daemon_ep, daemon_store);
        let control = tokio::spawn(mcpmesh::control::serve_control(listener, state));

        let mut child = Command::new(MCPMESH)
            .arg("connect")
            .arg("ghost/whatever")
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("XDG_CONFIG_HOME", dir.path())
            .env("XDG_DATA_HOME", dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mcpmesh connect");
        let mut child_in = child.stdin.take().unwrap();
        let mut child_out =
            FrameReader::new(BufReader::new(child.stdout.take().unwrap()), MAX_FRAME);

        // The AI client sends its initialize; the daemon's dial fails, so a -32055 comes back.
        write_frame(
            &mut child_in,
            &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        )
        .await
        .unwrap();
        let err = next_frame(&mut child_out).await;
        assert_eq!(
            err["error"]["code"], -32055,
            "unreachable peer → -32055: {err}"
        );
        assert_eq!(err["error"]["data"]["source"], "mcpmesh");

        child_in.shutdown().await.unwrap();
        drop(child_in);
        let status = timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("proxy did not exit")
            .unwrap();
        assert!(status.success());
        control.abort();
    })
    .await
    .expect("unreachable test timed out");
}

/// Read one JSON-RPC frame from the proxy's stdout, panicking on EOF/violation.
async fn next_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut FrameReader<R>) -> Value {
    match reader.next().await.unwrap() {
        Some(Inbound::Frame(v)) => v,
        other => panic!("expected a frame from the proxy, got {other:?}"),
    }
}
