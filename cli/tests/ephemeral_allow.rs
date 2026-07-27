//! #55 / #69: `service_allow_grant` and `service_allow_revoke` work on EPHEMERAL services.
//!
//! An ephemeral registration (#36) keeps its `allow` in memory only. Both verbs edited
//! `config.toml`, found no `[services.<name>]` entry, and returned `{}` — so a grant admitted
//! nobody and a revoke was undone by the next hot-reload's overlay, both while reporting success.
//!
//! These tests drive the REAL `grant_service_access` / `revoke_service_allow` pipelines against a
//! real in-process accept loop, so they also pin the #54 live-registry behavior for the ephemeral
//! path: a grant reaches an ALREADY-OPEN connection, and a revoke severs it.

use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{
    EphemeralService, MeshState, build_services, grant_service_access, revoke_service_allow,
    spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, MAX_FRAME_BYTES, SessionTransport, TrustGate, framing::write_frame};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

async fn server_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind server endpoint")
}

async fn client_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint")
}

fn initialize_frame(service: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "_meta": {"mcpmesh/service": service},
            "capabilities": {}, "clientInfo": {"name": "tester", "version": "0"}
        }
    })
}

/// A mesh with ONE paired peer and ONE **ephemeral** service `room` that admits nobody yet.
/// The config carries an unrelated `[services.kept]` so the config path is exercised alongside.
async fn mesh_with_ephemeral_room() -> (
    Arc<MeshState>,
    iroh::EndpointAddr,
    iroh::Endpoint,
    String,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());

    let peer = client_endpoint().await;
    let principal = format!("eid:{}", peer.id());
    store
        .add(PeerEntry {
            endpoint_id: *peer.id().as_bytes(),
            nickname: "alice".into(),
            services: vec!["room".into()],
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();

    let config_path = dir.path().join("config.toml");
    let toml = format!("[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n");
    std::fs::write(&config_path, &toml).unwrap();
    let cfg = Config::from_toml_str(&toml).expect("parse config");

    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    let conn_registry = Arc::new(ConnRegistry::new());
    let server = server_endpoint().await;
    let addr = server.addr();
    let mesh = MeshState::new(
        server,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "server".into(),
        config_path,
        Arc::new(RosterGate::empty()),
        conn_registry,
        None,
        None,
        None,
        None,
    );

    // The ephemeral service: in-memory only, admitting nobody yet.
    mesh.register_ephemeral(
        "room".to_string(),
        EphemeralService {
            backend: mcpmesh_local_api::BackendSpec::Run {
                cmd: vec![STUB.to_string()],
                env: Default::default(),
                cwd: None,
            },
            allow: vec![],
            rate_limit_per_min: None,
        },
    );

    // Start from the CONFIG-only registry. Every grant/revoke below runs the real
    // `reload_services_from_disk`, which re-overlays the ephemeral map — so the overlay path is
    // exercised for real rather than pre-baked here.
    mesh.set_accept_task(spawn_accept_loop(
        mesh.clone(),
        Arc::new(build_services(&cfg)),
    ))
    .await;
    (mesh, addr, peer, principal, dir)
}

async fn dial(client: &iroh::Endpoint, addr: iroh::EndpointAddr) -> iroh::endpoint::Connection {
    client.connect(addr, ALPN_MCP).await.expect("dial mesh")
}

async fn open_session(
    conn: &iroh::endpoint::Connection,
    service: &str,
) -> Option<SessionTransport> {
    let (mut send, recv) = conn.open_bi().await.ok()?;
    write_frame(&mut send, &initialize_frame(service))
        .await
        .ok()?;
    Some(SessionTransport::new(recv, send, MAX_FRAME_BYTES))
}

async fn session_served(t: Option<&mut SessionTransport>) -> bool {
    let Some(t) = t else { return false };
    match timeout(Duration::from_secs(5), t.recv_value()).await {
        Ok(Ok(Some(v))) => v["result"]["serverInfo"]["name"] == "echo-stub",
        _ => false,
    }
}

/// #55: granting on an ephemeral service actually admits the peer — and does so on a connection
/// that is ALREADY open (the #54 live registry, via the ephemeral overlay).
#[tokio::test]
async fn granting_an_ephemeral_service_admits_the_peer() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        let conn = dial(&peer, addr).await;

        let mut before = open_session(&conn, "room").await;
        assert!(
            !session_served(before.as_mut()).await,
            "not served before the grant (setup) — the ephemeral service is not in the registry \
             yet and admits nobody"
        );

        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant succeeds");

        let mut after = open_session(&conn, "room").await;
        assert!(
            session_served(after.as_mut()).await,
            "a grant on an EPHEMERAL service must actually admit the peer — this returned success \
             and admitted nobody before #55"
        );
    })
    .await
    .expect("ephemeral grant test timed out");
}

/// #69: revoking on an ephemeral service actually withdraws access — and severs the live
/// connection, rather than being undone by the next hot-reload's overlay.
#[tokio::test]
async fn revoking_an_ephemeral_service_withdraws_access_and_severs() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant succeeds");

        let conn = dial(&peer, addr.clone()).await;
        let mut session = open_session(&conn, "room").await;
        assert!(session_served(session.as_mut()).await, "served after grant");

        revoke_service_allow(&mesh, "room".into(), principal.clone())
            .await
            .expect("revoke succeeds");

        // The live connection is cut (#54's sever, now reachable for ephemeral services)...
        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("an ephemeral revoke must sever the live connection");

        // ...and a fresh connection is refused, proving the in-memory allow really changed and was
        // not restored by the reload overlay.
        let conn2 = dial(&peer, addr).await;
        let mut after = open_session(&conn2, "room").await;
        assert!(
            !session_served(after.as_mut()).await,
            "a revoked principal must not be re-admitted by the ephemeral overlay"
        );
    })
    .await
    .expect("ephemeral revoke test timed out");
}

/// The pairing ceremony stays LENIENT: an unknown service name in the list must not fail the
/// grant, and the known ones must still be granted. Only the single-service verb is strict.
#[tokio::test]
async fn the_pairing_grant_still_tolerates_an_unknown_service() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;

        grant_service_access(
            &mesh,
            &principal,
            &principal,
            &["room".to_string(), "no-such-service".to_string()],
        )
        .await
        .expect("a pairing grant must not fail on an unknown service name");

        let conn = dial(&peer, addr).await;
        let mut s = open_session(&conn, "room").await;
        assert!(
            session_served(s.as_mut()).await,
            "the KNOWN service in the list must still have been granted"
        );
    })
    .await
    .expect("lenient pairing grant test timed out");
}

/// An unrelated grant must not drop the ephemeral registration — the overlay-survives-a-swap
/// regression the #54 review flagged as untested.
#[tokio::test]
async fn an_ephemeral_registration_survives_an_unrelated_swap() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant room");

        // A grant against the CONFIG service for a DIFFERENT principal — so the config append
        // really changes something and a full reload+swap actually fires. Re-granting `principal`
        // here would be idempotent (`changed == false`), no swap would happen, and this test would
        // pass without ever exercising the overlay (caught in review).
        grant_service_access(
            &mesh,
            "eid:0000000000000000000000000000000000000000000000000000000000000000",
            "someone-else",
            &["kept".to_string()],
        )
        .await
        .expect("grant kept");

        let conn = dial(&peer, addr).await;
        let mut s = open_session(&conn, "room").await;
        assert!(
            session_served(s.as_mut()).await,
            "the ephemeral service (and its granted allow) must survive an unrelated config swap"
        );
    })
    .await
    .expect("overlay survival test timed out");
}
