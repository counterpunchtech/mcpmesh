//! Task 6 acceptance: the `subscribe` live event stream (pairing liveness & health telemetry).
//!
//! Two-node hermetic (relay disabled → no network egress), modeled on `proxy_roundtrip.rs` /
//! `reachability.rs`: a SERVING node S runs an audited `echo` backend over the mesh AND a control
//! server whose `MeshState` shares S's audit sink; a DIALING node D runs `serving_state` + control
//! and drives a REAL session against S over the mesh.
//!
//! Proves the `subscribe` connection-upgrade:
//!  1. The FIRST frame the daemon pushes is a `snapshot` (mirrors `open_session`'s upgrade).
//!  2. As a REAL session opens and closes on S's backend, `session_open` then `session_close`
//!     AuditRecords arrive as `event` frames on the live stream.
//!
//! Unix-only: `SubClient` dials the control endpoint as a raw `UnixStream` (with hardcoded
//! `OwnedReadHalf`/`OwnedWriteHalf` halves) rather than through the platform seam, so the
//! whole binary is gated to unix. Windows coverage for the control path lives at the
//! transport layer (local-api transport::windows pipe tests) and the client protocol layer
//! (local-api client.rs seam tests); a windows daemon-subprocess round-trip is deferred —
//! see the plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::audit::{AuditLog, AuditSink};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{self, MeshState, STACK_VERSION, build_services_audited};
use mcpmesh::limits::MeshLimiters;
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, TrustGate, serve};
use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A localhost-only endpoint carrying the mesh ALPN (relay disabled — hermetic).
async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

fn assemble_mesh(
    endpoint: iroh::Endpoint,
    store: Arc<PeerStore>,
    config_path: std::path::PathBuf,
) -> Arc<MeshState> {
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    MeshState::new(
        endpoint,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "self".into(),
        config_path,
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    )
}

/// A raw subscribe client: connects to a control socket, consumes the `Hello`, sends the
/// parameterless `subscribe` request, and reads the pushed `StreamFrame`s off the wire.
struct SubClient {
    reader: FrameReader<BufReader<OwnedReadHalf>>,
    // Held for the client's lifetime so the connection stays open; dropped cleanly at test end.
    _write_half: OwnedWriteHalf,
}

impl SubClient {
    async fn connect(socket: &std::path::Path) -> Self {
        let stream = UnixStream::connect(socket).await.expect("connect control");
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = FrameReader::new(BufReader::new(read_half), MAX_FRAME);
        // The server speaks first with a Hello frame; consume it.
        match reader.next().await.expect("hello read") {
            Some(Inbound::Frame(_hello)) => {}
            other => panic!("expected Hello, got {other:?}"),
        }
        write_frame(&mut write_half, &json!({ "method": "subscribe" }))
            .await
            .expect("send subscribe");
        Self {
            reader,
            _write_half: write_half,
        }
    }

    async fn next(&mut self) -> Value {
        match timeout(Duration::from_secs(5), self.reader.next())
            .await
            .expect("stream frame within timeout")
            .expect("stream read")
        {
            Some(Inbound::Frame(v)) => v,
            other => panic!("expected a stream frame, got {other:?}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribe_pushes_snapshot_then_live_session_events() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // --- Serving node S: an audited `echo` backend over the mesh + a control API subscribing
        //     to the SAME audit sink (so session_open/close fan out to the live stream). ---
        let server_ep = local_endpoint().await;
        let server_id = *server_ep.id().as_bytes();
        let server_addr = server_ep.addr();

        // Dialing node D's endpoint id — S's gate must trust it (the mesh peer S sees).
        let daemon_ep = local_endpoint().await;
        let daemon_id = *daemon_ep.id().as_bytes();

        let server_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"daemon\"]\n"
        ))
        .expect("parse server config");
        let server_store = Arc::new(PeerStore::open(&dir.path().join("server.redb")).unwrap());
        server_store
            .add(PeerEntry {
                endpoint_id: daemon_id,
                nickname: "daemon".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        // The audit sink shared by the backend (emits records) and S's control MeshState (taps them).
        let audit = AuditSink::new(AuditLog::spawn(dir.path().join("audit")));
        let limiters = MeshLimiters::unlimited();
        let server_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(server_store.clone()));
        let _serve = serve(
            server_ep.clone(),
            server_gate,
            build_services_audited(&server_cfg, &audit, &limiters),
            Arc::new(ConnRegistry::new()),
        );

        let s_mesh = assemble_mesh(server_ep, server_store, config.clone());
        s_mesh.set_audit(audit.clone());
        let s_socket = dir.path().join("s.sock");
        let s_listener = mcpmesh::ipc::bind_control_socket(&s_socket).await.unwrap();
        let s_state = Arc::new(DaemonState::with_mesh(STACK_VERSION, s_mesh));
        let s_control = tokio::spawn(serve_control(s_listener, s_state));

        // --- Dialing node D: resolves `tester` -> S's endpoint and dials over the mesh. ---
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(server_addr);
        daemon_ep
            .address_lookup()
            .expect("address lookup services")
            .add(mem);
        let daemon_store = Arc::new(PeerStore::open(&dir.path().join("daemon.redb")).unwrap());
        daemon_store
            .add(PeerEntry {
                endpoint_id: server_id,
                nickname: "tester".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let d_socket = dir.path().join("d.sock");
        let d_listener = mcpmesh::ipc::bind_control_socket(&d_socket).await.unwrap();
        let d_state = daemon::serving_state(daemon_ep, daemon_store);
        let d_control = tokio::spawn(serve_control(d_listener, d_state));

        // --- Subscribe to S's live stream; the FIRST frame must be a snapshot. ---
        let mut sub = SubClient::connect(&s_socket).await;
        let snapshot = sub.next().await;
        assert_eq!(
            snapshot["type"], "snapshot",
            "the first pushed frame must be a snapshot: {snapshot}"
        );

        // --- Drive a REAL session D -> S over the mesh: open_session, initialize, then CLOSE it. ---
        {
            let client = connect_control(&d_socket)
                .await
                .expect("connect to D control");
            let (mut reader, mut writer) = client
                .open_session("tester".into(), "echo".into())
                .await
                .expect("open_session upgrade");
            write_frame(
                &mut writer,
                &json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "ai", "version": "0"}}
                }),
            )
            .await
            .expect("send initialize");
            let init = match timeout(Duration::from_secs(10), reader.next())
                .await
                .expect("initialize response within timeout")
                .expect("initialize read")
            {
                Some(Inbound::Frame(v)) => v,
                other => panic!("expected initialize response, got {other:?}"),
            };
            assert_eq!(
                init["result"]["serverInfo"]["name"], "echo-stub",
                "the served child answered initialize over the mesh: {init}"
            );
            // Dropping both halves ends the session cleanly → S emits session_close.
        }

        // --- The live stream must carry session_open then session_close as `event` frames. ---
        let mut saw_open = false;
        let mut saw_close = false;
        for _ in 0..50 {
            let f = sub.next().await;
            if f["type"] == "event" && f["record"]["kind"] == "session_open" {
                saw_open = true;
            }
            if f["type"] == "event" && f["record"]["kind"] == "session_close" {
                saw_close = true;
                break;
            }
        }
        assert!(
            saw_open && saw_close,
            "the live stream must carry session_open then session_close events (open={saw_open}, close={saw_close})"
        );

        s_control.abort();
        d_control.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("subscribe test timed out");
}

/// Task 7: a FAILED dial reaches no backend, so the far side's session guard never audits it.
/// The daemon must emit a synthesized `session_open` record with `status: "error"` on the
/// dial-failure branch, so the live stream shows attempted-and-failed reaches. One node suffices:
/// subscribe to its stream, then `open_session` a NON-EXISTENT peer (unresolvable → clean -32055),
/// and assert a `session_open` `event` with `record.status == "error"` arrives.
#[tokio::test(flavor = "multi_thread")]
async fn dial_failure_emits_error_event() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // One node with a mesh whose audit sink the subscriber taps (a failed dial emits HERE).
        let ep = local_endpoint().await;
        let store = Arc::new(PeerStore::open(&dir.path().join("node.redb")).unwrap());
        let mesh = assemble_mesh(ep, store, config.clone());
        let audit = AuditSink::new(AuditLog::spawn(dir.path().join("audit")));
        mesh.set_audit(audit.clone());
        let socket = dir.path().join("node.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh));
        let control = tokio::spawn(serve_control(listener, state));

        // Subscribe; consume the snapshot (this also registers the broadcast receiver, so the
        // subsequent error record is guaranteed to be observed — no register-after-emit race).
        let mut sub = SubClient::connect(&socket).await;
        let snapshot = sub.next().await;
        assert_eq!(
            snapshot["type"], "snapshot",
            "the first pushed frame must be a snapshot: {snapshot}"
        );

        // Request open_session for a NON-EXISTENT peer/service → unresolvable → synthesized -32055.
        {
            let client = connect_control(&socket).await.expect("connect control");
            let (mut reader, _writer) = client
                .open_session("ghost".into(), "nope".into())
                .await
                .expect("open_session upgrade");
            // Drain the synthesized -32055 error frame (best-effort; the point is the dial failed).
            let _ = timeout(Duration::from_secs(5), reader.next()).await;
        }

        // The live stream must carry a `session_open` event with `status == "error"`.
        let mut saw_error = false;
        for _ in 0..50 {
            let f = sub.next().await;
            if f["type"] == "event"
                && f["record"]["kind"] == "session_open"
                && f["record"]["status"] == "error"
            {
                // Pin that the REQUESTED dial target surfaced (not some unrelated error record).
                assert_eq!(
                    f["record"]["peer"], "ghost",
                    "the error record must name the requested dial target: {f}"
                );
                saw_error = true;
                break;
            }
        }
        assert!(
            saw_error,
            "a failed dial must emit a session_open event with status=error on the live stream"
        );

        control.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("dial-failure test timed out");
}
