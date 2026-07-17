//! Task 4 acceptance: the `mcpmesh/ping/1` reachability probe (pairing-mode liveness).
//!
//! Two-node hermetic (relay disabled → no network egress), modeled on `daemon_dispatch.rs` /
//! `pairing_porcelain.rs`: assemble in-process `MeshState`s over localhost endpoints, SEED the
//! allowlist directly (the same shortcut the sibling in-process tests use — no live rendezvous),
//! and drive the REAL [`probe_peer`] / [`reachability_of`] the daemon exposes. Proves:
//!
//!  1. A probe of a PAIRED peer → reachable, with a measured RTT.
//!  2. [`reachability_of`] projects the cache to the peer's PETNAME (never the endpoint-id, §1.5)
//!     and never blocks the caller.
//!  3. A probe from an UNPAIRED endpoint → NOT reachable — the responder's trust gate closes the
//!     connection with NO pong (no presence leak; the SECURITY property of the probe).
//!  4. After the target endpoint is taken down → NOT reachable (a dead dial times out to false).
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{
    MeshState, STACK_VERSION, build_services, probe_peer, reachability_of, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh::{Request, StatusResult};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, ALPN_PING, TrustGate};
use tokio::time::timeout;

/// The target endpoint: advertises the mesh + pair + PING ALPNs (mirrors `build_endpoint`'s list
/// once `ALPN_PING` is added), so the daemon's own accept loop can serve the ping arm in-process.
async fn target_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            ALPN_MCP.to_vec(),
            ALPN_PAIR.to_vec(),
            ALPN_PING.to_vec(),
        ])
        .bind()
        .await
        .expect("bind target endpoint")
}

/// A dialing endpoint. It only *accepts* the mesh ALPN (it never serves ping); the ALPN it *dials*
/// is chosen per-connect, so it can still probe over `mcpmesh/ping/1`.
async fn dialer_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind dialer endpoint")
}

/// Seed `dialer`'s id-only dial resolution with `target_addr` — the localhost stand-in for the
/// DNS/pkarr discovery that resolves an address FROM an endpoint-id in production (spec §10.2).
fn seed_lookup(dialer: &iroh::Endpoint, target_addr: iroh::EndpointAddr) {
    let mem = MemoryLookup::new();
    mem.add_endpoint_info(target_addr);
    dialer
        .address_lookup()
        .expect("address lookup services")
        .add(mem);
}

fn seed_peer(store: &PeerStore, endpoint_id: [u8; 32], petname: &str) {
    store
        .add(PeerEntry {
            endpoint_id,
            petname: petname.into(),
            services: vec![],
            paired_at: None,
            user_id: None,
        })
        .unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn ping_probe_reports_paired_peer_reachable_stranger_and_down_peer_not() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // --- Target A: serves the ping arm; its gate trusts B (paired) but not the stranger C. ---
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_ep_handle = a_ep.clone(); // kept so we can close A for the down-peer case
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // --- Prober B: paired with A (A's store trusts B; B's store dials A back as "alice"). ---
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice"); // B's dial-back directory names A "alice"
        seed_peer(&a_store, b_id, "beacon-b"); // A trusts B → its ping arm will pong B

        // --- Stranger C: NOT in A's store → the ping gate must refuse it. ---
        let c_ep = dialer_endpoint().await;
        seed_lookup(&c_ep, a_addr.clone());
        let c_store = Arc::new(PeerStore::open(&dir.path().join("c.redb")).unwrap());

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let c_mesh = assemble_mesh(c_ep, c_store, config.clone());

        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // 1. A PAIRED peer probes A → reachable, with an RTT.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(entry.reachable, "a paired peer's probe must be reachable");
        assert!(
            entry.rtt_ms.is_some(),
            "a reachable probe records a round-trip time"
        );

        // 2. reachability_of projects the cache to the PETNAME (never the endpoint-id, §1.5) and
        //    returns the cached result immediately (non-blocking).
        let list = reachability_of(&b_mesh);
        let alice = list
            .iter()
            .find(|r| r.name == "alice")
            .expect("reachability_of surfaces the paired peer by petname");
        assert!(alice.reachable, "the cached probe result is surfaced");
        assert!(alice.rtt_ms.is_some(), "the cached RTT is surfaced");

        // 3. An UNPAIRED endpoint probes A → the trust gate closes it, no pong → NOT reachable.
        let stranger = probe_peer(&c_mesh, a_id).await;
        assert!(
            !stranger.reachable,
            "an unpaired peer gets no pong (trust gate closed the connection)"
        );
        assert!(stranger.rtt_ms.is_none());

        // 4. Take A down (stop accepting + close the endpoint) → B's next probe times out to false.
        accept.abort();
        a_ep_handle.close().await;
        let down = probe_peer(&b_mesh, a_id).await;
        assert!(
            !down.reachable,
            "a probe of a down peer must be unreachable"
        );

        std::mem::forget(dir);
    })
    .await
    .expect("reachability test timed out");
}

/// Task 5: the `status` control response surfaces paired-peer reachability. Drives the REAL
/// `status` request over `mcpmesh-local/1` (a raw `connect_control` client, like
/// `daemon_autostart.rs`) against an in-process daemon whose probe cache was just populated, and
/// asserts the paired peer appears BY PETNAME in `status.reachability` (§1.5: name + numbers only,
/// never an endpoint-id).
#[tokio::test(flavor = "multi_thread")]
async fn status_includes_reachability() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // Target A serves the ping arm; its gate trusts B.
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // Prober B, paired with A (B's directory names A "alice").
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");
        seed_peer(&a_store, b_id, "beacon-b");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());

        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Populate B's probe cache: A is reachable.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(
            entry.reachable,
            "precondition: the paired peer must probe reachable"
        );

        // Serve B's control API and drive the REAL `status` request over mcpmesh-local/1.
        let socket = dir.path().join("control.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(
            STACK_VERSION,
            b_mesh.clone(),
            Vec::new(),
            Vec::new(),
        ));
        let control = tokio::spawn(serve_control(listener, state));

        let mut client = connect_control(&socket)
            .await
            .expect("raw connect_control to B");
        let value = client
            .request(Request::Status)
            .await
            .expect("status over mcpmesh-local/1");
        let status: StatusResult =
            serde_json::from_value(value).expect("StatusResult deserializes");

        assert!(
            status.reachability.iter().any(|r| r.name == "alice"),
            "status.reachability must surface the paired peer by petname: {:?}",
            status.reachability
        );

        control.abort();
        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("status reachability test timed out");
}
