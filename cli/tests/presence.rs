//! M3c Task 11 acceptance: the person→device STAGGERED-RACE dial (spec §10.1). A roster user
//! "alice" owns TWO devices — a DEAD `primary` (a valid endpoint_id no live endpoint holds, so its
//! dial fails/stalls) and a LIVE `mirror` on localhost. `dial_service("alice", …)` must fall through
//! the staggered race to the mirror and establish a real session — proven by an `initialize` +
//! `tools/call` round-trip through the returned transport.
//!
//! This is the load-bearing proof of the "absence never removes a candidate" property: no presence
//! is published, so the candidate order is pure roster order (primary→mirror). The dead primary is
//! FIRST and still dialed; the race does NOT drop it — it simply falls to the mirror when the primary
//! does not win. Assert-on-convergence-with-timeout (never a fixed sleep): the whole dial + round-trip
//! is wrapped in a generous timeout, and success is the mirror answering.
//!
//! Localhost dial-by-id reconcile (as in `proxy_roundtrip.rs`): the client endpoint learns the
//! mirror's addresses via a `MemoryLookup` (the stand-in for the absent DNS/pkarr discovery), so the
//! id-only dial resolves locally. The dead primary is deliberately NOT seeded, so it is unreachable.
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{self, MeshState, build_services};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, TrustGate, serve};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only endpoint carrying the mcpmesh/mcp/1 ALPN (relay disabled — hermetic).
async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

/// Sign + load a one-user roster: "alice" with a primary + a mirror device (in that roster order).
fn alice_two_device_view(root: &SigningKey, primary: [u8; 32], mirror: [u8; 32]) -> RosterView {
    let signed = mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial: 1,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["all".into()],
            users: vec![RosterUser {
                user_id: "alice".into(),
                display_name: "Alice".into(),
                user_pk: encode_b64u(&[1u8; 32]),
                groups: vec!["all".into()],
                devices: vec![
                    RosterDevice {
                        endpoint_id: encode_b64u(&primary),
                        label: "laptop".into(),
                        role: "primary".into(),
                    },
                    RosterDevice {
                        endpoint_id: encode_b64u(&mirror),
                        label: "desktop".into(),
                        role: "mirror".into(),
                    },
                ],
            }],
            revoked_endpoints: vec![],
            sig: String::new(),
        },
    );
    load_installed(&signed, &root.verifying_key()).expect("valid alice roster view")
}

/// The `initialize` frame naming `service` in the reserved `_meta` (spec §7.2).
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

#[tokio::test]
async fn dial_service_races_a_person_to_the_live_mirror_when_the_primary_is_dead() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);

        // --- The LIVE mirror: a localhost endpoint serving an echo `run` service. ---
        let mirror_ep = local_endpoint().await;
        let mirror_id = *mirror_ep.id().as_bytes();
        let mirror_addr = mirror_ep.addr();

        // --- The client (dialer) endpoint. Capture its id so the mirror's gate can trust it. ---
        let client_ep = local_endpoint().await;
        let client_id = *client_ep.id().as_bytes();
        let client_eid = format!("eid:{}", client_ep.id());

        // The mirror's gate authorizes the client by its STABLE eid principal (#38 — the nickname
        // "client" is display-only and never admits) for the echo service.
        let mirror_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"{client_eid}\"]\n"
        ))
        .expect("parse mirror config");
        let mirror_store = PeerStore::open(&dir.path().join("mirror_state.redb")).unwrap();
        mirror_store
            .add(PeerEntry {
                endpoint_id: client_id,
                nickname: "client".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let mirror_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(mirror_store)));
        let _mirror_serve = serve(
            mirror_ep,
            mirror_gate,
            build_services(&mirror_cfg),
            Arc::new(mcpmesh_net::ConnRegistry::new()),
        );

        // --- The DEAD primary: a valid endpoint_id no live endpoint holds (unreachable). ---
        let primary_dead = SigningKey::from_bytes(&[50u8; 32])
            .verifying_key()
            .to_bytes();

        // Seed the client's dial-by-id resolution with the MIRROR's addrs ONLY (the dead primary is
        // deliberately unseeded → unreachable, so its dial fails/stalls and the race falls to mirror).
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(mirror_addr);
        client_ep
            .address_lookup()
            .expect("address lookup services")
            .add(mem);

        // The client MeshState: a roster mapping "alice" → [primary(dead), mirror(live)]. No presence
        // is published, so the candidate order is pure roster order (primary→mirror) — the dead
        // primary is FIRST and still a candidate (absence never removes it); the race falls to mirror.
        let roster = Arc::new(RosterGate::empty());
        roster.install(alice_two_device_view(&root, primary_dead, mirror_id));
        let client_store =
            Arc::new(PeerStore::open(&dir.path().join("client_state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(client_store.clone()));
        let mesh = MeshState::new(
            client_ep,
            gate,
            client_store,
            Arc::new(LiveInvites::new()),
            "client".into(),
            dir.path().join("config.toml"),
            roster.clone(),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );

        // Convergence: the staggered race establishes a session to the LIVE mirror (the dead primary
        // never wins). A fixed sleep is deliberately avoided — the timeout wrapper IS the convergence
        // bound, and the mirror answering the round-trip is the success signal.
        let mut transport = daemon::dial_service(&mesh, "alice", "echo")
            .await
            .expect("staggered race establishes a session to the live mirror");

        // Prove it is genuinely the MIRROR (a session to the dead primary could never round-trip):
        // the echo stub answers `initialize`, then echoes a `tools/call` payload verbatim.
        transport
            .send_value(initialize_frame("echo"))
            .await
            .unwrap();
        let init = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "the live mirror answered initialize through the raced session: {init}"
        );
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "to the mirror"}}
            }))
            .await
            .unwrap();
        let call = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            call["result"]["content"][0]["text"], "to the mirror",
            "the mirror echoed the payload byte-faithfully: {call}"
        );
        assert_eq!(
            call["result"]["peer_name"], "client",
            "the mirror saw the client's gate-resolved identity"
        );
    })
    .await
    .expect("person→device race test timed out");
}

/// #39 — app-metadata end to end through the REAL control path: a roster-mode node sets its
/// app metadata via `set_app_metadata`, and `status` presence surfaces it on the node's own
/// device (the self-meta path); the ≤256B cap is enforced. The signed beat/accept/table chain
/// that carries a PEER's metadata is covered by the presence unit tests; this proves the
/// control verb, storage, cap, and status surfacing against the live control server.
#[tokio::test]
async fn set_app_metadata_surfaces_in_status_presence() {
    use mcpmesh::control::{DaemonState, serve_control_io};
    use mcpmesh_local_api::connect_control_io;

    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);

        // A roster where THIS node's own endpoint is alice's primary device, so its own
        // device appears in `status` presence (where the self-meta is surfaced).
        let self_ep = local_endpoint().await;
        let self_id = *self_ep.id().as_bytes();
        let other = [7u8; 32]; // a second (unused) device so the view is well-formed
        let roster = Arc::new(RosterGate::empty());
        roster.install(alice_two_device_view(&root, self_id, other));

        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let mesh = MeshState::new(
            self_ep,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "self".into(),
            dir.path().join("config.toml"),
            roster.clone(),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let state = Arc::new(DaemonState::with_mesh("test", mesh));

        // Drive the REAL control verb + status over an in-memory control connection.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server_io);
        tokio::spawn(serve_control_io(sr, sw, state));
        let (cr, cw) = tokio::io::split(client_io);
        let mut ctl = connect_control_io(cr, cw).await.expect("hello");

        // Before: no metadata → the self device carries none.
        let before = ctl.status().await.expect("status");
        let self_dev = |s: &mcpmesh_local_api::StatusResult| {
            s.presence
                .iter()
                .find(|p| p.device_label == "laptop") // self is alice's primary "laptop"
                .cloned()
                .expect("self device present in status")
        };
        assert_eq!(self_dev(&before).meta, "", "no metadata before set");

        // Set it, then status surfaces it live — no restart.
        ctl.set_app_metadata("v=1.2.3")
            .await
            .expect("set_app_metadata");
        let after = ctl.status().await.expect("status");
        assert_eq!(
            self_dev(&after).meta,
            "v=1.2.3",
            "metadata visible in status presence"
        );

        // Clearing works.
        ctl.set_app_metadata("").await.expect("clear");
        assert_eq!(self_dev(&ctl.status().await.unwrap()).meta, "", "cleared");

        // The ≤256B cap is enforced (257 bytes → a control error, nothing stored).
        let toobig = "x".repeat(257);
        assert!(
            ctl.set_app_metadata(&toobig).await.is_err(),
            "over-cap metadata must be refused"
        );
        assert_eq!(
            self_dev(&ctl.status().await.unwrap()).meta,
            "",
            "a refused set stores nothing"
        );
    })
    .await
    .expect("app-metadata status test timed out");
}

/// #41 — dial by `eid:` targets the EXACT authenticated endpoint, unambiguously, even when a
/// DIFFERENT stored peer shares the nickname (nicknames are not unique; first-match wins).
/// A target serves echo (gated to the client's eid). The client's store holds two peers both
/// nicknamed "twin" — the real target and a decoy — so a nickname dial is ambiguous, but
/// `dial_service("eid:<target-hex>", …)` reaches the real endpoint and round-trips.
#[tokio::test(flavor = "multi_thread")]
async fn dial_by_eid_targets_the_exact_endpoint_despite_a_nickname_collision() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // The target serves echo, authorizing the client by its stable eid principal (#38).
        let target_ep = local_endpoint().await;
        let target_id = *target_ep.id().as_bytes();
        let target_addr = target_ep.addr();
        let eid_target = format!("eid:{}", target_ep.id());
        let client_ep = local_endpoint().await;
        let client_id = *client_ep.id().as_bytes();
        let client_eid = format!("eid:{}", client_ep.id());
        let target_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"{client_eid}\"]\n"
        ))
        .expect("parse target config");
        let target_store = PeerStore::open(&dir.path().join("target.redb")).unwrap();
        target_store
            .add(PeerEntry {
                endpoint_id: client_id,
                nickname: "client".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let target_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(target_store)));
        let _target_serve = serve(
            target_ep,
            target_gate,
            build_services(&target_cfg),
            Arc::new(mcpmesh_net::ConnRegistry::new()),
        );

        // The client learns the target's addr (stand-in for discovery), then stores TWO peers
        // both nicknamed "twin": the real target and a decoy endpoint → "twin" is ambiguous.
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(target_addr);
        client_ep.address_lookup().unwrap().add(mem);
        let client_store = Arc::new(PeerStore::open(&dir.path().join("client.redb")).unwrap());
        for eid in [target_id, [200u8; 32]] {
            client_store
                .add(PeerEntry {
                    endpoint_id: eid,
                    nickname: "twin".into(), // SAME nickname on two endpoints
                    services: vec!["echo".into()],
                    paired_at: None,
                    user_id: None,
                    last_addr: None,
                })
                .unwrap();
        }
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(client_store.clone()));
        let mesh = MeshState::new(
            client_ep,
            gate,
            client_store,
            Arc::new(LiveInvites::new()),
            "client".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );

        // Dial by the target's EXACT eid principal → reaches the real target, not the decoy.
        let mut transport = daemon::dial_service(&mesh, &eid_target, "echo")
            .await
            .expect("eid dial reaches the exact endpoint despite the nickname collision");
        transport
            .send_value(initialize_frame("echo"))
            .await
            .unwrap();
        let init = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "the eid dial landed on the serving target: {init}"
        );

        // An invalid eid principal is a clean resolution error (never a panic).
        assert!(
            daemon::dial_service(&mesh, "eid:nothex", "echo")
                .await
                .is_err(),
            "an invalid eid principal must error, not panic"
        );

        std::mem::forget(dir);
    })
    .await
    .expect("dial-by-eid test timed out");
}
