//! M4c T7 (spec §4.3 P13, §16 M4 hardening): when a node's roster crosses `last_confirmed +
//! max_staleness + grace` (effective_state == DegradedStopped), the periodic staleness sweep cuts an
//! EXISTING roster-authorized live session, while a PAIRING-only session is untouched. In-process
//! localhost; the sweep is driven directly via `staleness_sweep_once` (the loop's per-tick body).
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{MeshState, build_services, spawn_accept_loop, staleness_sweep_once};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, connect};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

async fn dual_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind dual-ALPN endpoint")
}
async fn client_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint")
}
fn mint_view(root: &SigningKey, serial: u64, eid: [u8; 32], uid: &str) -> RosterView {
    let r = mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into()],
            users: vec![RosterUser {
                user_id: uid.into(),
                display_name: uid.into(),
                user_pk: encode_b64u(&[1u8; 32]),
                groups: vec!["team-eng".into()],
                devices: vec![RosterDevice {
                    endpoint_id: encode_b64u(&eid),
                    label: "d".into(),
                    role: "primary".into(),
                }],
            }],
            revoked_endpoints: vec![],
            sig: String::new(),
        },
    );
    load_installed(&r, &root.verifying_key()).expect("valid view")
}
fn initialize_frame(service: &str) -> serde_json::Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","_meta":{"mcpmesh/service":service},
        "capabilities":{},"clientInfo":{"name":"t","version":"0"}}})
}

#[tokio::test]
async fn staleness_sweep_cuts_roster_session_but_not_pairing() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"alice\", \"bob\"]\n"
        ))
        .unwrap();

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let alice_client = client_endpoint().await;
        let bob_client = client_endpoint().await;
        let alice_id = *alice_client.id().as_bytes();
        let bob_id = *bob_client.id().as_bytes();

        // bob is a pairing peer; alice is rostered.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: bob_id,
                petname: "bob".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store.clone()));

        // A gate WITH a freshness bound (1s max_staleness) — starts unconstrained (last_confirmed None
        // → Approved), so both peers connect; then we force it DegradedStopped.
        let roster = Arc::new(RosterGate::with_freshness(72 * 3600, 1));
        roster.install(mint_view(&root, 1, alice_id, "alice"));
        let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
        let conn_registry = Arc::new(ConnRegistry::new());

        let server = dual_alpn_endpoint().await;
        let addr = server.addr();
        let mesh = MeshState::new(
            server,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "server".into(),
            dir.path().join("config.toml"),
            roster.clone(),
            conn_registry.clone(),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));

        // Both complete a live session while the roster is fresh.
        let mut alice_t = connect(&alice_client, addr.clone(), "echo").await.unwrap();
        alice_t.send_value(initialize_frame("echo")).await.unwrap();
        assert_eq!(
            alice_t.recv_value().await.unwrap().unwrap()["result"]["serverInfo"]["name"],
            "echo-stub"
        );
        let mut bob_t = connect(&bob_client, addr.clone(), "echo").await.unwrap();
        bob_t.send_value(initialize_frame("echo")).await.unwrap();
        assert_eq!(
            bob_t.recv_value().await.unwrap().unwrap()["result"]["serverInfo"]["name"],
            "echo-stub"
        );

        // Both are registered (register-check happens-before the init reply).
        for _ in 0..50 {
            if conn_registry.len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(conn_registry.len(), 2);

        // Force staleness: confirm far in the past so effective_state == DegradedStopped now.
        // `now` is computed locally (epoch seconds) so the test does not depend on widening the
        // crate-private `daemon::epoch_now` — matching Step 7's decision.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        roster.set_last_confirmed(now - 1_000_000);
        assert_eq!(
            roster.effective_state(now),
            Some(mcpmesh_trust::roster::validate::RosterState::DegradedStopped)
        );

        // Sweep: exactly the roster-authorized session (alice) is cut; bob (pairing) is spared.
        let severed = staleness_sweep_once(&mesh, now);
        assert_eq!(severed, 1, "only the roster-authorized session is swept");

        // alice's transport observes the close; bob still round-trips a follow-up request.
        let alice_closed = alice_t.recv_value().await;
        assert!(
            matches!(alice_closed, Ok(None) | Err(_)),
            "roster session severed: {alice_closed:?}"
        );
        bob_t
            .send_value(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}))
            .await
            .unwrap();
        assert!(
            bob_t.recv_value().await.unwrap().is_some(),
            "pairing session survives the sweep"
        );
    })
    .await
    .expect("staleness sweep test timed out");
}
