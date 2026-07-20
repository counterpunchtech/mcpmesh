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
            "protocolVersion": "2025-06-18",
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

        // The mirror's gate authorizes the client (nickname "client") for the echo service.
        let mirror_cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"client\"]\n"
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
