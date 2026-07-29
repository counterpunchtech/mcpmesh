//! #124: the persisted dial hint self-heals from a live session, and never becomes a relay URL.
//!
//! `PeerEntry::last_addr` was written only at pairing and never refreshed, so a peer that changed
//! networks was dialed at a dead address forever and every session fell back to the relay. This
//! drives a REAL session and asserts the STORED value — the coverage the first attempt lacked, when
//! its unit test called the store helper directly and deleting the sole production call site left
//! the whole suite green.
//!
//! **Its own test binary, deliberately.** Each of these tests stands up a relay plus two endpoints
//! and waits on a real hole-punch; cargo runs a binary's tests concurrently, so adding a fourth to
//! `live_path_events.rs` pushed a Windows runner past the window that suite's watcher-lifetime test
//! needs and failed a job that had been green. Heavyweight network fixtures do not share a binary.

use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{self, MeshState, build_services_audited};
use mcpmesh::limits::MeshLimiters;
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PING, TrustGate};
use tokio::time::timeout;

fn assemble(
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

/// Stand up a relay + two nodes, with the peer's address known ONLY via the relay so a session
/// provably starts relayed and hole-punches mid-flight. Returns the guards that must outlive the
/// test (tempdir, accept task, relay), our mesh, and the peer's.
///
/// Shared because all three tests need the identical situation and it is 60 lines of setup; the
/// relay-only `last_addr` in particular is load-bearing — without it the dial may come up direct
/// and there is no transition to observe.
#[allow(clippy::type_complexity)]
async fn live_session_harness() -> (
    (
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
        Box<dyn std::any::Any + Send>,
    ),
    Arc<MeshState>,
    Arc<MeshState>,
    Arc<PeerStore>,
) {
    let dir = tempfile::tempdir().unwrap();
    let (relay_map, relay_url, relay_guard) = iroh::test_utils::run_relay_server()
        .await
        .expect("run in-process relay");

    let mk = || {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Custom(relay_map.clone()))
            .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
            .alpns(vec![ALPN_MCP.to_vec(), ALPN_PING.to_vec()])
            .bind()
    };
    let peer_ep = mk().await.expect("bind peer");
    let our_ep = mk().await.expect("bind ours");
    let peer_id = *peer_ep.id().as_bytes();
    let our_id = *our_ep.id().as_bytes();

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
            // RELAY-ONLY hint: the session STARTS relayed, so the direct path is selected later,
            // mid-session. That later selection is the event under test.
            last_addr: Some(
                serde_json::to_string(
                    &iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&peer_id).unwrap())
                        .with_relay_url(relay_url.clone()),
                )
                .expect("serialize relay addr"),
            ),
        })
        .unwrap();

    let peer_cfg = dir.path().join("peer.toml");
    std::fs::write(&peer_cfg, "").unwrap();
    let peer_mesh = assemble(peer_ep, peer_store, peer_cfg);
    let accept = daemon::spawn_accept_loop(
        peer_mesh.clone(),
        Arc::new(build_services_audited(
            &Config::default(),
            &mcpmesh::audit::AuditSink::disabled(),
            &MeshLimiters::unlimited(),
        )),
    );

    let our_cfg = dir.path().join("our.toml");
    std::fs::write(&our_cfg, "").unwrap();
    let mesh = assemble(our_ep, our_store.clone(), our_cfg);

    (
        (dir, accept, Box::new(relay_guard)),
        mesh,
        peer_mesh,
        our_store,
    )
}

/// #124: the persisted dial hint must self-heal from a LIVE session, and must never become a relay
/// URL.
///
/// This drives a real session and asserts the STORED value, which is the coverage the first attempt
/// lacked: its unit test called the store helper directly, so deleting the sole production call
/// site left the whole suite green and the relay-URL defect had nothing that could see it.
///
/// The session provably starts relayed (relay-only `last_addr`), so at accept time the only path is
/// the relay. A hint sampled then would BE the relay URL — and since `stored_dial_addr` replaces the
/// bare-id dial, that leaves no direct candidate at all, self-inflicting the very bug #124 reports.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_session_refreshes_the_dial_hint_and_never_stores_a_relay() {
    timeout(Duration::from_secs(120), async {
        let (harness, mesh, _peer_mesh, our_store) = live_session_harness().await;
        let peer_id = our_store
            .list()
            .unwrap()
            .into_iter()
            .find(|e| e.nickname == "bob")
            .expect("peer seeded")
            .endpoint_id;

        // Seeded relay-only, which is exactly the degraded state #124 describes.
        let before = our_store.resolve(&peer_id).unwrap().unwrap().last_addr;
        assert!(
            before.as_deref().is_some_and(|s| s.contains("Relay")),
            "fixture must start from a relay-only hint, or this proves nothing: {before:?}"
        );

        let _session = daemon::dial_service(&mesh, "bob", "echo")
            .await
            .expect("open a mesh session to the peer");

        // The watcher refreshes once the direct path is SELECTED, so wait for the hint to change.
        let mut healed = None;
        for _ in 0..80 {
            let now = our_store.resolve(&peer_id).unwrap().unwrap().last_addr;
            if now != before {
                healed = now;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let healed = healed.expect(
            "a live session must refresh the stale dial hint — leaving it is #124: the peer is \
             dialed at a dead address forever and every session falls back to the relay",
        );
        assert!(
            !healed.contains("Relay"),
            "a relay URL must NEVER become a dial hint — it replaces the bare-id dial, so the \
             direct-candidate set becomes empty and the fix inflicts the bug it exists to fix: \
             {healed}"
        );
        assert!(
            healed.contains("Ip"),
            "the refreshed hint must carry the peer's DIRECT address: {healed}"
        );

        // Identity fields the pairing path protects must survive a hint refresh.
        let row = our_store.resolve(&peer_id).unwrap().unwrap();
        assert_eq!(
            row.nickname, "bob",
            "a hint refresh must not touch identity"
        );
        drop(harness);
    })
    .await
    .expect("dial hint refresh test timed out");
}
