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
        // allow holds the STABLE eid: principal of the dialing endpoint (nicknames never admit).
        let daemon_ep = local_endpoint().await;
        let daemon_id = *daemon_ep.id().as_bytes();
        let daemon_eid = format!("eid:{}", daemon_ep.id());

        let server_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"{daemon_eid}\"]\n"
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
                    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
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

/// #58: a reachability FLIP is pushed to a live subscriber — no `status` poll needed.
///
/// Covers the issue's headline case end to end: a peer that comes UP produces a pushed frame, and
/// one that goes DOWN produces another. An earlier version of this test only ever drove
/// `unknown → unreachable`, and review proved it still passed with flip detection deleted
/// entirely — so it is deliberately built around real transitions in both directions.
///
/// The mesh here has auditing ENABLED, so the subscribe loop is running its two-ring `select!`
/// (audit + reachability) rather than the single-tap path.
/// #82 gate: a `BlobTransfer` frame must actually REACH a subscriber.
///
/// The producer side is covered end to end in `blob_ac.rs`; this pins the other half — the
/// `blob_frame` mapping and the `select!` arm in `run_subscription`. Making `blob_frame` return
/// `None` for every value passed the entire workspace: frames were produced and silently dropped
/// on the way out.
#[tokio::test(flavor = "multi_thread")]
async fn blob_transfer_frames_reach_a_subscriber() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();
        let ep = local_endpoint().await;
        let store = Arc::new(PeerStore::open(&dir.path().join("s.redb")).unwrap());
        let mesh = assemble_mesh(ep, store, config);
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));

        let socket = dir.path().join("s.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let _control = tokio::spawn(serve_control(listener, state));

        let mut sub = SubClient::connect(&socket).await;
        assert_eq!(sub.next().await["type"], "snapshot");

        // Push one observation onto the ring the provider writes to.
        mesh.blob_bcast_for_test()
            .send(mcpmesh::daemon::BlobTransfer {
                direction: mcpmesh_local_api::BlobDirection::Serve,
                hash: "abc123".into(),
                bytes_done: 512,
                bytes_total: Some(2048),
                state: mcpmesh_local_api::BlobTransferState::Progress,
                peer: Some("eid:deadbeef".into()),
            })
            .expect("a subscriber is attached, so the send has a receiver");

        let frame = sub.next().await;
        assert_eq!(
            frame["type"], "blob_transfer",
            "the frame must arrive tagged `blob_transfer`, or no non-Rust client can dispatch on \
             it: {frame}"
        );
        assert_eq!(frame["direction"], "serve");
        assert_eq!(frame["hash"], "abc123");
        assert_eq!(frame["bytes_done"], 512);
        assert_eq!(frame["bytes_total"], 2048);
        assert_eq!(frame["state"], "progress");
        assert_eq!(frame["peer"], "eid:deadbeef");
    })
    .await
    .expect("blob frame subscribe test timed out");
}

/// #167 ask 2: a RESUME frame must actually reach a subscriber, carrying the sleep's length.
///
/// Driven through `resume_tick_for_test`, which is the watcher's real per-tick body — so this
/// covers detection, the broadcast, the `resume_frame` mapping and the `select!` arm together. Only
/// the two clock reads are outside it, and staging those would mean suspending the machine running
/// the suite.
///
/// It also pins the number: `suspended_secs` must be the SLEEP, not the tick that observed it.
/// Those differ by three orders of magnitude here, so an implementation reporting the wall delta
/// (or the tick period) fails rather than looking plausible.
#[tokio::test(flavor = "multi_thread")]
async fn a_resume_frame_reaches_a_subscriber_carrying_the_sleep_length() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();
        let ep = local_endpoint().await;
        let store = Arc::new(PeerStore::open(&dir.path().join("s.redb")).unwrap());
        let mesh = assemble_mesh(ep, store, config);
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));

        let socket = dir.path().join("s.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let _control = tokio::spawn(serve_control(listener, state));

        let mut sub = SubClient::connect(&socket).await;
        assert_eq!(sub.next().await["type"], "snapshot");

        // An ORDINARY tick first: the watcher runs every 2s forever, and if this emitted, the
        // subscriber below would read that frame instead and the assertions would still pass. It
        // is the guard that makes the rest of this test mean anything.
        assert_eq!(
            mesh.resume_tick_for_test(2, 2, 1_700_000_000),
            None,
            "an ordinary tick must not emit — otherwise every embedder is told to re-dial its \
             whole mesh every two seconds",
        );

        // Now a two-hour lid close: the monotonic clock froze, the wall clock did not.
        let sent = mesh
            .resume_tick_for_test(2, 7202, 1_700_007_202)
            .expect("a 2h wall/monotonic skew is a suspend");
        assert_eq!(sent.suspended_secs, 7200);

        let frame = sub.next().await;
        assert_eq!(
            frame["type"], "resumed",
            "the frame must arrive tagged `resumed`, or no non-Rust client can dispatch on it: \
             {frame}"
        );
        assert_eq!(
            frame["suspended_secs"], 7200,
            "the machine slept 7200s; the tick that noticed took 2s. Reporting anything but the \
             sleep tells an embedder the wrong thing about what its peers did in the meantime: \
             {frame}"
        );
        assert_eq!(frame["at_epoch"], 1_700_007_202i64);
    })
    .await
    .expect("resume frame subscribe test timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn reachability_flips_are_pushed_to_subscribers() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // --- The peer we probe: a real node running the daemon accept loop, so it answers the
        //     trust-gated `mcpmesh/ping/1` probe. ---
        let peer_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN_MCP.to_vec(), mcpmesh_net::ALPN_PING.to_vec()])
            .bind()
            .await
            .expect("bind peer endpoint");
        let peer_id = *peer_ep.id().as_bytes();
        let peer_addr = peer_ep.addr();

        // --- Our node. ---
        let our_ep = local_endpoint().await;
        let our_id = *our_ep.id().as_bytes();
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(peer_addr);
        let our_ep = our_ep;

        // Each side trusts the other (the ping probe is trust-gated on both ends).
        let peer_store = Arc::new(PeerStore::open(&dir.path().join("peer.redb")).unwrap());
        peer_store
            .add(PeerEntry {
                endpoint_id: our_id,
                nickname: "us".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let our_store = Arc::new(PeerStore::open(&dir.path().join("our.redb")).unwrap());
        our_store
            .add(PeerEntry {
                endpoint_id: peer_id,
                nickname: "bob".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: Some(
                    serde_json::to_string(&peer_ep.addr()).expect("serialize peer addr"),
                ),
            })
            .unwrap();

        let peer_mesh = assemble_mesh(peer_ep, peer_store, dir.path().join("peer.toml"));
        std::fs::write(dir.path().join("peer.toml"), "").unwrap();
        let peer_accept = daemon::spawn_accept_loop(
            peer_mesh.clone(),
            Arc::new(build_services_audited(
                &Config::default(),
                &AuditSink::disabled(),
                &MeshLimiters::unlimited(),
            )),
        );

        let mesh = assemble_mesh(our_ep, our_store, config);
        // Auditing ON, so the subscribe loop runs the two-ring select.
        mesh.set_audit(AuditSink::new(AuditLog::spawn(dir.path().join("audit"))));

        let socket = dir.path().join("s.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));
        let _control = tokio::spawn(serve_control(listener, state));

        let mut sub = SubClient::connect(&socket).await;
        assert_eq!(sub.next().await["type"], "snapshot");

        // --- UP: first probe finds the peer reachable. That IS news (the snapshot reports an
        //     unprobed peer as offline), so it must be pushed. ---
        let up = daemon::probe_peer(&mesh, peer_id).await;
        assert!(up.reachable, "the live peer must probe reachable");
        // #64: relays are DISABLED in this harness, so a reachable peer here is genuinely direct.
        // But the FIRST probe of a brand-new connection may still report `Unknown` — a path is not
        // selected the instant the pong lands, and under parallel test load it can exceed the
        // probe's settle window. That is honest (`Unknown` means "we do not know", and it is the
        // fail-safe answer), so the contract is "eventually Direct", not "Direct immediately".
        // Asserting the latter made this test flaky under full-suite load.
        let mut path = up.path.clone();
        for _ in 0..10 {
            if path == mcpmesh_local_api::PeerPath::Direct {
                break;
            }
            assert_ne!(
                path,
                mcpmesh_local_api::PeerPath::Relay { url: None },
                "no relay is configured, so a relay verdict would be wrong"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
            path = daemon::probe_peer(&mesh, peer_id).await.path;
        }
        assert_eq!(
            path,
            mcpmesh_local_api::PeerPath::Direct,
            "a loopback peer with relays disabled must settle on Direct"
        );
        let frame = sub.next().await;
        assert_eq!(frame["type"], "reachability", "got {frame}");
        assert_eq!(frame["peer"]["reachable"], true, "came online: {frame}");
        assert_eq!(frame["peer"]["name"], "bob", "got {frame}");
        // #150: a probe drove this, and the frame must say so on the WIRE — this is the whole
        // path (producer -> ring -> run_subscription -> JSON), not just the enum. `probe` is the
        // weaker claim: it describes this throwaway dial, not any session's link.
        assert_eq!(
            frame["source"], "probe",
            "a probe-driven transition must attribute itself to the probe producer: {frame}"
        );
        // The frame's path is whatever was known at transition time — `direct` or, if the path
        // had not settled yet, `unknown`. Never `relay`: none is configured.
        assert_ne!(frame["peer"]["path"]["kind"], "relay", "got {frame}");
        // The row carries the peer's authenticated endpoint id, rendered independently of the
        // implementation's own helper so this pins the VALUE, not just the call.
        assert_eq!(
            frame["peer"]["principal"],
            format!(
                "eid:{}",
                peer_id
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            "got {frame}"
        );

        // --- Steady state: a re-probe that re-confirms UP is not a transition. ---
        //
        // Drain first. The settle loop above re-probes until the path reaches Direct, and each
        // Unknown->Direct step is a genuine transition that queues its own frame — so on a run
        // where the first probe reported Unknown there is a SECOND frame already waiting, which
        // the silence check below would read and blame on the re-probe. That is a fixture race,
        // not the property under test, and it failed this suite under full-workspace load. The
        // drain is bounded by the same window as the assertion, so a daemon that pushes
        // unboundedly still fails.
        while timeout(Duration::from_millis(600), sub.reader.next())
            .await
            .is_ok()
        {}
        let _ = daemon::probe_peer(&mesh, peer_id).await;
        assert!(
            timeout(Duration::from_millis(600), sub.reader.next())
                .await
                .is_err(),
            "an unchanged re-probe must push nothing"
        );

        // --- DOWN: kill the peer, probe again. ---
        peer_accept.abort();
        drop(peer_mesh);
        let down = daemon::probe_peer(&mesh, peer_id).await;
        assert!(!down.reachable, "the dead peer must probe unreachable");
        let frame = sub.next().await;
        assert_eq!(frame["type"], "reachability", "got {frame}");
        assert_eq!(frame["peer"]["reachable"], false, "went offline: {frame}");
        assert_eq!(frame["peer"]["name"], "bob", "got {frame}");

        let _ = mem;
    })
    .await
    .expect("reachability flip test timed out");
}
