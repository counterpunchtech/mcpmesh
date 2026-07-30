//! #90 acceptance: a node can tell whether IT is reachable — `status.self_network` over a REAL
//! in-process relay, the `StreamFrame::SelfNetwork` transition, and the snapshot's copy.
//!
//! Harness: the `peer_path.rs` relay shape (`iroh::test_utils::run_relay_server` + a
//! `RelayMode::Custom` endpoint trusting the test relay's self-signed cert) plus the
//! `reachability.rs` control-socket shape. The transition test subscribes BEFORE the watcher
//! task spawns — the watcher's baseline is offline-empty, so the first online projection always
//! emits exactly one frame, making the test deterministic instead of racing the relay handshake.
#![cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{MeshState, STACK_VERSION, spawn_self_net_watch};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh::{Request, StatusResult};
use mcpmesh_local_api::StreamFrame;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, TrustGate};
use tokio::time::timeout;

fn assemble(ep: iroh::Endpoint, dir: &std::path::Path) -> Arc<MeshState> {
    let store = Arc::new(PeerStore::open(&dir.join("state.redb")).unwrap());
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    MeshState::new(
        ep,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "self".into(),
        dir.join("config.toml"),
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    )
}

/// `status.self_network` over a REAL relay: a relay-enabled node reports `online: true`, the
/// relay's sanitized URL as `home_relay`, and its connection state in `relays`; a
/// `relay_mode = "disabled"` node reports `online: false` with empty `relays` — truthful, not a
/// health warning — and still lists its `direct_addrs`.
#[tokio::test(flavor = "multi_thread")]
async fn status_reports_self_network_over_a_real_relay() {
    timeout(Duration::from_secs(90), async {
        let dir = tempfile::tempdir().unwrap();
        let (relay_map, relay_url, _relay_guard) = iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

        let relayed = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Custom(relay_map))
            .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN_MCP.to_vec()])
            .bind()
            .await
            .expect("bind relayed endpoint");
        // Deterministic precondition: don't race the relay handshake.
        relayed.online().await;
        let mesh = assemble(relayed, dir.path());

        let socket = dir.path().join("a.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh));
        let control = tokio::spawn(serve_control(listener, state));
        let status: StatusResult = serde_json::from_value(
            connect_control(&socket)
                .await
                .expect("connect")
                .request(Request::Status)
                .await
                .expect("status"),
        )
        .expect("StatusResult deserializes");
        let net = status
            .self_network
            .expect("a mesh daemon reports self_network (#90)");
        assert!(net.online, "a relay-connected node is online: {net:?}");
        // Sanitized: scheme + host + port only — the test relay URL carries no userinfo, but the
        // shape must match `sanitize_relay_url`'s rendering (no trailing slash, no path).
        let expected = match (relay_url.host_str(), relay_url.port()) {
            (Some(h), Some(p)) => format!("{}://{h}:{p}", relay_url.scheme()),
            (Some(h), None) => format!("{}://{h}", relay_url.scheme()),
            _ => panic!("test relay url has a host"),
        };
        assert_eq!(
            net.home_relay.as_deref(),
            Some(expected.as_str()),
            "home_relay is the connected relay, sanitized: {net:?}"
        );
        assert!(
            net.relays.iter().any(|r| r.url == expected && r.connected),
            "the relay list carries the connected home relay: {net:?}"
        );
        control.abort();

        // The hermetic node: relays disabled is a CONFIGURATION, not an outage.
        let hermetic = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![ALPN_MCP.to_vec()])
            .bind()
            .await
            .expect("bind hermetic endpoint");
        let dir2 = tempfile::tempdir().unwrap();
        let mesh = assemble(hermetic, dir2.path());
        let socket = dir2.path().join("b.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh));
        let control = tokio::spawn(serve_control(listener, state));
        let status: StatusResult = serde_json::from_value(
            connect_control(&socket)
                .await
                .expect("connect")
                .request(Request::Status)
                .await
                .expect("status"),
        )
        .expect("StatusResult deserializes");
        let net = status.self_network.expect("self_network present");
        assert!(!net.online, "no relay configured -> not online: {net:?}");
        assert!(net.relays.is_empty(), "no relays configured: {net:?}");
        assert!(
            !net.direct_addrs.is_empty(),
            "a bound endpoint has direct addresses even with relays disabled: {net:?}"
        );
        control.abort();
    })
    .await
    .expect("self_network status test timed out");
}

/// The `SelfNetwork` transition (#90): a subscriber attached BEFORE the watcher spawns sees the
/// snapshot's block AND exactly the offline→online frame once the watcher observes the
/// connected relay — plus `status.self_network.last_change_epoch` becomes `Some` after it.
#[tokio::test(flavor = "multi_thread")]
async fn subscribe_pushes_a_self_network_frame_on_the_online_transition() {
    timeout(Duration::from_secs(90), async {
        let dir = tempfile::tempdir().unwrap();
        let (relay_map, _relay_url, _relay_guard) = iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");
        let ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Custom(relay_map))
            .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN_MCP.to_vec()])
            .bind()
            .await
            .expect("bind endpoint");
        ep.online().await; // the relay connection exists; the WATCHER has not looked yet
        let mesh = assemble(ep, dir.path());

        let socket = dir.path().join("c.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));
        let control = tokio::spawn(serve_control(listener, state));

        // Subscribe FIRST. The snapshot must already carry the block (live-computed).
        let mut sub = connect_control(&socket)
            .await
            .expect("connect")
            .subscribe()
            .await
            .expect("subscribe");
        let first = sub
            .next()
            .await
            .expect("read frame")
            .expect("snapshot frame");
        let StreamFrame::Snapshot { self_network, .. } = first else {
            panic!("first frame is the snapshot, got {first:?}");
        };
        assert!(
            self_network
                .expect("snapshot carries self_network (#90)")
                .online,
            "the snapshot's block is computed live, not from the (not yet spawned) watcher"
        );

        // NOW spawn the watcher. Its baseline is offline-empty, so the already-online endpoint
        // is a change on first observation -> exactly one frame, no relay-handshake race.
        let _watch = spawn_self_net_watch(mesh.clone());
        let frame = match sub.next().await.expect("read frame").expect("stream frame") {
            StreamFrame::SelfNetwork { self_network } => self_network,
            other => panic!("expected the SelfNetwork frame, got {other:?}"),
        };
        assert!(
            frame.online,
            "the transition frame reports online: {frame:?}"
        );
        assert!(
            frame.last_change_epoch.is_some(),
            "the frame stamps when the change was observed: {frame:?}"
        );

        // And status now merges the watcher's stamp.
        let status: StatusResult = serde_json::from_value(
            connect_control(&socket)
                .await
                .expect("connect 2")
                .request(Request::Status)
                .await
                .expect("status"),
        )
        .expect("StatusResult deserializes");
        assert!(
            status
                .self_network
                .expect("self_network")
                .last_change_epoch
                .is_some(),
            "status carries the watcher's last-change stamp after the transition"
        );

        control.abort();
    })
    .await
    .expect("self_network stream test timed out");
}
