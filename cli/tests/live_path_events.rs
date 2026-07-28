//! #92 item 2: a live session whose selected path changes pushes a frame WHEN IT HAPPENS.
//!
//! #92 item (1) shipped in 0.19.0 and made `is_transition` compare `path`, so a PROBE that observes
//! a changed path emits. That removed "no event, ever" — it did not give live signal. Probes are
//! TTL-gated (20s) and only run when `status`/`subscribe` asks, so a session that degrades
//! Direct→Relay mid-call stays silently mislabelled until something probes, possibly never.
//!
//! **Ordering follows `peer_path.rs` (#110): hold ONE connection across the transition.** Sampling
//! fresh probes cannot observe a live change by construction — each probe dials, waits 600ms, and
//! drops the connection, so the transition happens on a connection nobody is watching. That is the
//! whole reason this suite is separate from `peer_path.rs`.
//!
//! The assertion that makes this about LIVE signal rather than probing: `rtt_ms` must be `None`. A
//! probe measures a round trip and reports `Some(rtt)`; the watcher observes a path and never
//! fabricates a measurement. `probe_seq` is NOT the discriminator — the watcher shares that counter
//! with `probe_peer` on purpose, so a correct implementation advances it.

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
    (),
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
    let mesh = assemble(our_ep, our_store, our_cfg);

    ((dir, accept, Box::new(relay_guard)), mesh, peer_mesh, ())
}

/// A session we OPEN (the reported use case: an embedder rendering a privacy indicator for a call
/// it initiated) must push a `Reachability` frame when its selected path changes under it.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_relay_to_direct_transition_pushes_a_frame() {
    timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let (relay_map, relay_url, _relay_guard) = iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

        // Both endpoints use the relay; loopback means a direct path is also available, so iroh
        // hole-punches and re-SELECTS mid-session. That transition is the event under test.
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
                // RELAY-ONLY hint, so the session provably STARTS relayed and the direct path is
                // selected later, mid-session. Without this the dial may come up direct and there
                // is no transition to observe.
                last_addr: Some(
                    serde_json::to_string(
                        &iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&peer_id).unwrap())
                            .with_relay_url(relay_url.clone()),
                    )
                    .expect("serialize relay addr"),
                ),
            })
            .unwrap();

        // The peer serves an echo service so we have a real mesh session to hold open.
        let peer_cfg = dir.path().join("peer.toml");
        std::fs::write(&peer_cfg, "").unwrap();
        let peer_mesh = assemble(peer_ep, peer_store, peer_cfg);
        let _peer_accept = daemon::spawn_accept_loop(
            peer_mesh.clone(),
            Arc::new(build_services_audited(
                &Config::default(),
                &mcpmesh::audit::AuditSink::disabled(),
                &MeshLimiters::unlimited(),
            )),
        );

        let our_cfg = dir.path().join("our.toml");
        std::fs::write(&our_cfg, "").unwrap();
        let mesh = assemble(our_ep, our_store, our_cfg);

        // Subscribe BEFORE the session exists, so no transition can be missed between open and
        // subscribe.
        let mut rx = mesh.reach_bcast_for_test().subscribe();
        let seq_before = mesh.probe_seq_for_test();

        // Open ONE outbound session and HOLD it. This is the seam the watcher must cover: the
        // reported use case is a call the embedder initiated, not one it accepted.
        let _session = daemon::dial_service(&mesh, "bob", "echo")
            .await
            .expect("open a mesh session to the peer");

        // The event under test. Generous: this waits on a real hole-punch, it does not assert a
        // latency budget — a tight bound here is what made #110 flaky.
        let frame = timeout(Duration::from_secs(45), rx.recv())
            .await
            .expect(
                "a live path change must push a Reachability frame — with no watcher on the \
                 session this times out, which is exactly the #92 item 2 defect",
            )
            .expect("broadcast channel alive");

        assert_eq!(
            frame.path,
            mcpmesh_local_api::PeerPath::Direct,
            "the frame must report the path the session ACTUALLY moved to"
        );

        // The point of the suite: this came from the LIVE session, not a probe. If a probe drove
        // it, item (1) already emits and this test proves nothing about item (2).
        //
        // `rtt_ms` is the discriminator, NOT the probe ticket. An earlier draft asserted
        // `probe_seq` was unchanged; that was wrong, because the watcher deliberately SHARES the
        // ticket counter with `probe_peer` — that shared ordering is what stops an in-flight probe
        // overwriting a fresher live observation. A correct implementation therefore advances it.
        //
        // A probe measures a round trip and reports `Some(rtt)`. The watcher observes a path and
        // never fabricates a measurement, so a watcher-seeded entry carries `None`.
        assert_eq!(
            frame.rtt_ms, None,
            "the frame must be watcher-seeded: a probe-driven row carries a measured rtt_ms, and \
             a probe-driven path frame is item (1), already shipped in 0.19.0"
        );
        assert!(
            mesh.probe_seq_for_test() > seq_before,
            "the watcher must TAKE a ticket — sharing probe_peer's counter is what keeps an \
             in-flight probe from overwriting this observation"
        );
    })
    .await
    .expect("live path event test timed out");
}

/// The #58 defect class: the stream and `status` must not disagree. A watcher that emits without
/// writing the cache leaves `status` reporting the OLD path — so a consumer that re-reads after the
/// event sees the frame contradicted by the very surface it would use to confirm it.
///
/// **Measured coverage, not assumed.** In this scenario the watcher SEEDS the cache entry (no probe
/// has run, so there is no prior row), which means only `commit_observation`'s insert branch
/// executes. Mutating that branch to store the wrong path fails this suite; mutating the UPDATE
/// branch to emit without persisting does NOT — it is never reached here. Covering the update
/// branch needs a prior entry, i.e. a probe first and a path change second, which is a different
/// fixture and is not pretended to be covered by this one.
#[tokio::test(flavor = "multi_thread")]
async fn status_agrees_with_the_frame_the_watcher_just_pushed() {
    timeout(Duration::from_secs(120), async {
        let (harness, mesh, _peer_mesh, _relay) = live_session_harness().await;
        let mut rx = mesh.reach_bcast_for_test().subscribe();

        let _session = daemon::dial_service(&mesh, "bob", "echo")
            .await
            .expect("open a mesh session to the peer");

        let frame = timeout(Duration::from_secs(45), rx.recv())
            .await
            .expect("a live path change must push a frame")
            .expect("broadcast channel alive");

        // `reachability_of` is what `status` projects from. It must already reflect the pushed
        // value, with NO probe needed to reconcile them.
        let rows = daemon::reachability_of(&mesh);
        let row = rows
            .iter()
            .find(|r| r.name == "bob")
            .expect("the peer must appear in the status projection");
        assert_eq!(
            row.path, frame.path,
            "status must agree with the frame that was just pushed — a watcher that emits without \
             writing the cache leaves status contradicting its own event stream"
        );
        drop(harness);
    })
    .await
    .expect("status coherence test timed out");
}

/// #61 cost a release to a detached task holding a lock. A watcher is exactly that shape, so its
/// boundedness is a regression test, not an assumption.
///
/// **This asserts the TASK ENDS, not that side-effects stop.** The first version watched
/// `probe_seq` and was vacuous: a leaked watcher parked on `events.next()` forever emits nothing,
/// which is indistinguishable from a settled connection. The #92 review proved it by moving a
/// strong `Connection` into the task — the exact leak the design forbids — and the test still
/// passed. Joining the handle is the only thing that tells the two apart.
#[tokio::test(flavor = "multi_thread")]
async fn the_watcher_stops_when_its_session_closes() {
    timeout(Duration::from_secs(120), async {
        let (harness, mesh, _peer_mesh, _relay) = live_session_harness().await;
        let mut rx = mesh.reach_bcast_for_test().subscribe();

        let session = daemon::dial_service(&mesh, "bob", "echo")
            .await
            .expect("open a mesh session to the peer");
        let _ = timeout(Duration::from_secs(45), rx.recv())
            .await
            .expect("a live path change must push a frame");

        // Close the session; the watcher's event stream must end with it.
        drop(session);

        // Deliberately NOT closing the endpoint: that tears down every connection regardless of
        // who holds a handle, which MASKS the leak this test exists to catch. The watcher must end
        // because the SESSION ended.

        // Whatever else is true, the watcher must not keep running. A task still parked here is
        // holding an Arc<MeshState> — and through it the peer store's redb handle — past the
        // lifetime of the thing it watches. That is #61.
        let ended = timeout(Duration::from_secs(20), async {
            loop {
                if daemon::live_path_watchers_for_test() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        assert!(
            ended.is_ok(),
            "the watcher must END with its connection — a task outliving what it watches is the \
             #61 shape, and it holds the peer store's redb handle open"
        );
        drop(harness);
    })
    .await
    .expect("watcher lifetime test timed out");
}
