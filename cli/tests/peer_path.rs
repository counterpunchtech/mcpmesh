//! #64: `PeerReachability.path` reports the path that actually carries data.
//!
//! This suite exists because the FIRST implementation derived the answer from the endpoint's
//! remote-address map, filtered to `TransportAddrUsage::Active`. iroh deliberately keeps a relay
//! path OPEN as a standby after hole-punching succeeds ("Relay and custom paths are kept open"),
//! so that version reported `Relay` for a connection whose data provably flowed direct — making
//! `Direct` unreachable on any relay-enabled node, which is every real deployment.
//!
//! The suite the change originally shipped with ran only with relays DISABLED, so it could not
//! observe that at all. Here a REAL relay runs in-process.
//!
//! **Ordering matters (#110).** The connection that proves a direct path exists is established
//! BEFORE the probe assertions and held open across them. Probing first was flaky on Windows and
//! Linux CI: each `probe_peer` dials fresh, waits 600ms for hole-punching, and drops the
//! connection, so a punch that misses the window leaves nothing cached and the next probe restarts.
//! Twelve probes are twelve independent attempts, not one cumulative wait.
//!
//! **Known coverage limit.** This suite pins that a relayed peer eventually reports `Direct` once
//! hole-punching completes, which catches the address-map derivation bug. It NO LONGER catches the
//! other #64 bug, classifying before the path settles: holding the connection open means a probe's
//! fresh dial finds an already-validated direct address, so a zeroed `PATH_SETTLE` passes here.
//! That property moved to `reach.rs`'s
//! `the_probe_waits_for_the_direct_path_instead_of_classifying_immediately`, which drives it on
//! tokio's test clock instead of a real hole-punch. Verified by mutation, in both directions.
//! It also does NOT distinguish a classifier that reads the
//! SELECTED path from one that reads open paths in iteration order: mutating `is_selected()` away
//! still passes, because the probe connection surfaces the direct path first. That guarantee rests
//! on iroh's documented semantics for `Path::is_selected()` and on reading its source, not on a
//! test. Worth revisiting if iroh exposes a way to force path ordering.

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

/// With a real relay in play, a probe must report the path DATA is on — and it must be able to
/// report `Direct` once a direct path is selected, even though the relay path stays open beside it.
#[tokio::test(flavor = "multi_thread")]
async fn the_path_reports_the_route_data_actually_takes() {
    timeout(Duration::from_secs(90), async {
        let dir = tempfile::tempdir().unwrap();
        let (relay_map, relay_url, _relay_guard) = iroh::test_utils::run_relay_server()
            .await
            .expect("run in-process relay");

        // Both endpoints use the relay. Loopback means a direct path is also available, so iroh
        // will hole-punch and SELECT it — the exact situation the first implementation got wrong.
        let mk = || {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Custom(relay_map.clone()))
                // The in-process relay serves a self-signed cert; trust it for the test only.
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
                // ONLY the relay address is known, so the first path iroh opens is the relay
                // one. That is exactly what pins a naive implementation to `Relay` forever, even
                // after hole-punching finds the loopback path.
                last_addr: Some(
                    serde_json::to_string(
                        &iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&peer_id).unwrap())
                            .with_relay_url(relay_url.clone()),
                    )
                    .expect("serialize relay addr"),
                ),
            })
            .unwrap();

        std::fs::write(dir.path().join("peer.toml"), "").unwrap();
        let peer_mesh = assemble(peer_ep, peer_store, dir.path().join("peer.toml"));
        let _peer_accept = daemon::spawn_accept_loop(
            peer_mesh.clone(),
            Arc::new(build_services_audited(
                &Config::default(),
                &mcpmesh::audit::AuditSink::disabled(),
                &MeshLimiters::unlimited(),
            )),
        );
        std::fs::write(dir.path().join("our.toml"), "").unwrap();
        let mesh = assemble(our_ep, our_store, dir.path().join("our.toml"));

        // SETUP FIRST, and HOLD the connection open for the rest of the test (#110).
        //
        // This ordering is the whole point. `probe_peer` dials a FRESH connection, waits at most
        // `PATH_SETTLE` (600ms) for hole-punching, then DROPS it. When the punch does not land
        // inside that window — routine on a loaded CI runner — the connection dies before the
        // direct path is validated, so nothing is cached and the next probe starts over. Probing in
        // a loop therefore does not converge: it is twelve independent 600ms attempts, not one
        // cumulative 6s wait, and it reported Relay twelve times on both Windows and Linux.
        //
        // Holding ONE connection lets the punch complete once. The endpoint then has a validated
        // direct address for this peer, so every later dial selects it promptly. That is also what
        // production does — real sessions are long-lived, not 600ms probes.
        let probe_conn = mesh_endpoint_dial(&mesh, peer_id, &relay_url).await;
        let (mut relay_open, mut direct_selected) = (false, false);
        // Generous: this is waiting for the NETWORK, not asserting a latency budget. A tight bound
        // here is what made this suite flaky in the first place.
        for _ in 0..120 {
            for path in &probe_conn.paths() {
                if path.is_relay() {
                    relay_open = true;
                }
                if path.is_ip() && path.is_selected() {
                    direct_selected = true;
                }
            }
            if relay_open && direct_selected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        // A SETUP check, not a behavioural one — be clear about which. It proves the scenario is
        // the interesting one: a relay path OPEN alongside a SELECTED direct path, which is the
        // configuration where reading open addresses and reading the selected path disagree.
        //
        // It does NOT pin the classifier: a version that ignores `is_selected()` still passes this
        // whole test, because the probe connection's path iteration happens to surface the direct
        // path first. The guarantee that we read the SELECTED path is enforced by construction and
        // by iroh's own documented semantics ("selected for application data transmission"), not
        // by this test. See the module header.
        assert!(
            relay_open && direct_selected,
            "setup: expected an OPEN relay path alongside a SELECTED direct one \
             (relay_open={relay_open}, direct_selected={direct_selected}) — without that overlap \
             this test cannot distinguish reading the selected path from reading open addresses"
        );

        // Now the behavioural assertion, with the punch already landed. A probe still opens its own
        // connection, so it must still classify correctly — but it is no longer racing the network.
        let mut seen = Vec::new();
        let mut got_direct = false;
        for _ in 0..12 {
            let entry = daemon::probe_peer(&mesh, peer_id).await;
            assert!(entry.reachable, "the peer must be reachable over the relay");
            seen.push(entry.path.clone());
            if entry.path == mcpmesh_local_api::PeerPath::Direct {
                got_direct = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(
            got_direct,
            "with a direct path available, the field must eventually report Direct — reporting \
             Relay forever is the bug this suite exists to catch. Saw: {seen:?}"
        );
        // Keep the connection alive to here: dropping it earlier would let the endpoint discard the
        // validated direct path mid-test and reintroduce exactly the race this fix removes.
        drop(probe_conn);

        // Whatever it reported along the way, it must never have been a value we do not model.
        for p in &seen {
            assert!(
                matches!(
                    p,
                    mcpmesh_local_api::PeerPath::Direct | mcpmesh_local_api::PeerPath::Relay { .. }
                ),
                "a live connection must classify, got {p:?}"
            );
        }

        // A relay URL that DOES reach the wire carries no credentials (scheme://host[:port]).
        for p in &seen {
            if let mcpmesh_local_api::PeerPath::Relay { url: Some(u) } = p {
                assert!(!u.contains('@'), "userinfo must never ship: {u}");
                assert_eq!(u.matches('/').count(), 2, "scheme://host only, got {u}");
            }
        }
    })
    .await
    .expect("peer path test timed out");
}

/// Dial the peer from the mesh's own endpoint, so the test can inspect the path set the daemon's
/// probe would see.
async fn mesh_endpoint_dial(
    mesh: &Arc<MeshState>,
    peer_id: [u8; 32],
    relay_url: &iroh::RelayUrl,
) -> iroh::endpoint::Connection {
    let addr = iroh::EndpointAddr::new(iroh::EndpointId::from_bytes(&peer_id).unwrap())
        .with_relay_url(relay_url.clone());
    mesh.endpoint_for_test()
        .connect(addr, ALPN_PING)
        .await
        .expect("dial peer for path inspection")
}
