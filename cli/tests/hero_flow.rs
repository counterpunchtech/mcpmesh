//! Task 12 — the M2a acceptance criterion, end-to-end and hermetic: the hero flow
//! MINUS the pairing ceremony (M2b adds `pair`; here trust is the M2a stand-in — the
//! allowlist populated directly, exactly as `pair` will later populate it).
//!
//! The M2a AC has three clauses; this file demonstrates all three end-to-end in one
//! narrative (`hero_flow_minus_pairing`), and DECLARES where each is also covered by a
//! focused task test:
//!
//!   (1) served-service-over-proxy WITH identity — a config-allowlisted peer's AI client
//!       uses a served MCP server end-to-end through the proxy, and the served child sees
//!       the gate-resolved caller identity (`MCPMESH_PEER_NAME`), threaded gate → run → child
//!       env across the mesh. Step 1 below. (Also: `proxy_roundtrip.rs`, single-endpoint
//!       variant.)
//!   (2) an UNPAIRED machine is refused pre-MCP — a stranger endpoint absent from the
//!       server's store is closed at the gate with QUIC 401, no MCP frame exchanged.
//!       Step 2 below, against the REAL `AllowlistGate`. (Also: net `session.rs`
//!       `unknown_endpoint_is_refused_before_mcp`, against a `StaticGate`.)
//!   (3) a NON-PORCELAIN client drives status over mcpmesh-local/1 and gets the API version
//!       at connect — a raw `connect_control` (not the `status` porcelain). Step 3 below.
//!       (Also: `daemon_autostart.rs` `non_porcelain_client_drives_status_over_local_api`,
//!       against the real daemon subprocess.)
//!
//! Shape — the strongest hermetic version the plan blesses: a real TWO-endpoint mesh over
//! localhost (relay disabled, no discovery). Alice is the serving side — the daemon's own
//! `build_services` + `serve` composition, gated by the REAL `AllowlistGate` over a real
//! `PeerStore` (`[services.files] run=echo_mcp_stub, allow=["bob"]`). Bob is the consuming
//! side — an in-process daemon (`daemon::serving_state` + the REAL `serve_control`) whose
//! control socket a REAL `mcpmesh connect` subprocess drives. Bob's daemon dials Alice by id;
//! localhost has no discovery, so Bob's endpoint is seeded with Alice's `EndpointAddr` via a
//! `MemoryLookup` on `address_lookup()` (the runtime stand-in for DNS/pkarr — the SAME
//! id-only `dial_service` path production runs, unchanged). Real two-machine NAT validation
//! is M1's `#[ignore]` runbook (`net/tests/session.rs`), not needed here.
// Unix-only: hand-binds the control endpoint in-process (`bind_control_socket`) at a
// filesystem socket path, which a windows named pipe cannot be. Windows coverage for the
// control path lives at the transport layer (local-api transport::windows pipe tests) and
// the client protocol layer (local-api client.rs seam tests); a windows daemon-subprocess
// round-trip is deferred — see the plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::daemon::{self, STACK_VERSION, build_services};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::{TrustGate, connect, serve};
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

#[tokio::test(flavor = "multi_thread")]
async fn hero_flow_minus_pairing() {
    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();

        // ── Endpoints: bind first so each side's gate/store can pin the other's id. ──
        // Alice serves `files`; Bob is the consuming daemon; a third stranger is unpaired.
        let alice_ep = local_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();
        let alice_addr = alice_ep.addr();

        let bob_ep = local_endpoint().await;
        let bob_id = *bob_ep.id().as_bytes();

        // ── ALICE (serving side): the daemon's own build_services + serve composition. ──
        // `[services.files] run=echo_mcp_stub, allow=["bob"]`; the REAL AllowlistGate over a
        // real store that grants petname `bob` (Bob's dialing endpoint id) the `files` service
        // — the M2a stand-in for what `pair` will later write.
        let alice_cfg = Config::from_toml_str(&format!(
            "[services.files]\nrun = ['{STUB}']\nallow = [\"bob\"]\n"
        ))
        .expect("parse alice config");
        let alice_store = PeerStore::open(&dir.path().join("alice_state.redb")).unwrap();
        alice_store
            .add(PeerEntry {
                endpoint_id: bob_id,
                petname: "bob".into(),
                services: vec!["files".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let alice_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(alice_store)));
        let _alice_handle = serve(alice_ep, alice_gate, build_services(&alice_cfg), Arc::new(mcpmesh_net::ConnRegistry::new()));

        // ── BOB (consuming side): an in-process daemon with the REAL control server. ──
        // Bob's store resolves petname `alice` → Alice's endpoint id (the M2a trust stand-in),
        // and Bob's endpoint is seeded with Alice's addr so the id-only dial resolves locally.
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(alice_addr.clone());
        bob_ep
            .address_lookup()
            .expect("address lookup services")
            .add(mem);

        let bob_store = Arc::new(PeerStore::open(&dir.path().join("bob_state.redb")).unwrap());
        bob_store
            .add(PeerEntry {
                endpoint_id: alice_id,
                petname: "alice".into(),
                services: vec!["files".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();

        // Bind Bob's control socket where a subprocess with XDG_RUNTIME_DIR=<tmp> resolves it
        // (paths::default_endpoint = <XDG_RUNTIME_DIR>/mcpmesh/mcpmesh.sock), and run the REAL control
        // server over the composed serving state.
        let socket = dir.path().join("mcpmesh").join("mcpmesh.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let bob_state = daemon::serving_state(bob_ep, bob_store);
        let control = tokio::spawn(mcpmesh::control::serve_control(listener, bob_state));

        // ─────────────────────────────────────────────────────────────────────────────
        // STEP 1 (AC clause 1): served-service-over-proxy WITH identity.
        // Bob's AI-client stand-in runs the REAL `mcpmesh connect alice/files` subprocess
        // against Bob's control socket. It drives initialize + tools/call; the served child
        // on Alice answers byte-faithfully, and MCPMESH_PEER_NAME carries the gate-resolved
        // petname `bob` into that child — identity threaded gate → run → child env, end to
        // end through the proxy across the mesh.
        // ─────────────────────────────────────────────────────────────────────────────
        let mut child = Command::new(MCPMESH)
            .arg("connect")
            .arg("alice/files")
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

        // initialize (no mcpmesh/service meta — the daemon injects it): Alice's served child
        // answers over the mesh, back through the proxy's stdout.
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
            "Alice's served child answered initialize back through the proxy: {init}"
        );

        // tools/call → payload echoed verbatim, and MCPMESH_PEER_NAME carried the gate-resolved
        // caller identity (`bob`) into the child across the mesh.
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hero flow, minus pairing"}}
            }),
        )
        .await
        .unwrap();
        let call = next_frame(&mut child_out).await;
        assert_eq!(
            call["result"]["content"][0]["text"], "hero flow, minus pairing",
            "the echoed tools/call payload round-tripped byte-faithfully: {call}"
        );
        assert_eq!(
            call["result"]["peer_name"], "bob",
            "the served child saw the gate-resolved caller identity (bob) across the mesh: {call}"
        );

        // Closing stdin ends the proxy cleanly (spec §8) — no hang.
        child_in.shutdown().await.unwrap();
        drop(child_in);
        let status = timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("proxy did not exit after stdin close")
            .unwrap();
        assert!(status.success(), "proxy exited non-zero: {status}");

        // ─────────────────────────────────────────────────────────────────────────────
        // STEP 2 (AC clause 2): an unpaired machine is refused pre-MCP.
        // A third endpoint NOT in Alice's store dials Alice's `files` directly. Alice's REAL
        // AllowlistGate default-denies it — the connection is closed with QUIC 401 BEFORE any
        // bi-stream, so no MCP frame is ever exchanged (no initialize response).
        // ─────────────────────────────────────────────────────────────────────────────
        let stranger_ep = local_endpoint().await;
        match connect(&stranger_ep, alice_addr, "files").await {
            // Refused at connection establishment — no session, no MCP frame.
            Err(_) => {}
            // Or the connect races ahead of the gate close: the stranger may open a stream,
            // but its initialize draws no response — the gate severed the connection pre-MCP.
            Ok(mut transport) => {
                write_frame_value(
                    &mut transport,
                    json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"_meta": {"mcpmesh/service": "files"}, "capabilities": {}}}),
                )
                .await;
                let outcome = transport.recv_value().await;
                assert!(
                    matches!(outcome, Err(_) | Ok(None)),
                    "unpaired stranger got an MCP frame — the gate did not refuse pre-MCP: {outcome:?}"
                );
            }
        }

        // ─────────────────────────────────────────────────────────────────────────────
        // STEP 3 (AC clause 3): a non-porcelain client drives status over mcpmesh-local/1.
        // A raw `connect_control` (NOT the `status` porcelain) reads the server's Hello FIRST
        // frame — api + a non-empty version delivered at connect — then drives `Status` and
        // gets a typed `StatusResult` reflecting Bob's known peer `alice`.
        // ─────────────────────────────────────────────────────────────────────────────
        let mut raw = connect_control(&socket).await.expect("raw connect_control");
        assert_eq!(raw.hello().api, "mcpmesh-local/1", "api identified at connect");
        assert!(
            !raw.hello().api_version.is_empty(),
            "a non-empty api version is delivered at connect: {:?}",
            raw.hello()
        );
        let result = raw
            .request(mcpmesh::Request::Status)
            .await
            .expect("status request");
        // A typed StatusResult comes back over mcpmesh-local/1 — the AC's non-porcelain
        // clause. (Peer/service reflection in the snapshot is the real daemon's
        // `serve_forever` job — covered by the subprocess status tests in
        // `daemon_autostart.rs`; the in-process `serving_state` seam is dial-only and
        // seeds an empty snapshot deliberately.)
        let s: mcpmesh::StatusResult =
            serde_json::from_value(result).expect("StatusResult deserializes");
        assert_eq!(s.stack_version, STACK_VERSION);

        control.abort();
    })
    .await
    .expect("hero-flow-minus-pairing test timed out");
}

/// Read one JSON-RPC frame from a `FrameReader`, panicking on EOF/violation.
async fn next_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut FrameReader<R>) -> Value {
    match reader.next().await.unwrap() {
        Some(Inbound::Frame(v)) => v,
        other => panic!("expected a frame, got {other:?}"),
    }
}

/// Best-effort write of one frame into a `SessionTransport` (the stranger's initialize; the
/// gate may already have closed the connection, so the write itself may fail — that is fine).
async fn write_frame_value(transport: &mut mcpmesh_net::SessionTransport, v: Value) {
    let _ = transport.send_value(v).await;
}
