//! M3a D8 (spec §4.3 rule 6, §4.5 AC; §16 M3 AC "revoked device cut from live sessions — including
//! one holding a stale pair entry"): installing a roster that REVOKES a currently-roster-resolved
//! endpoint DROPS that endpoint's live mesh session across all ALPNs, while a PAIRING-only peer's
//! live session is NOT severed by the same install; AND a connection dialing a server whose roster
//! already revokes it is refused PRE-MCP (no session, no registry entry — the TOCTOU close).
//!
//! In-process localhost (the 3-node gossip-timing test is M3c); here the install path calls the
//! registry sever directly via [`install_roster_view_and_sever`], the SAME pipeline the T10 control
//! handler drives.
//!
//! **Folded T6 `roster_gate.rs` assertions (DECLARED).** The two composed-gate acceptance clauses
//! the T6 plan deferred are proven here rather than in a separate file:
//!  - "a rostered peer completes a session under the composed gate" → the sever test's SETUP: alice
//!    (rostered, resolved by `ComposedGate` to `user_id = "alice"`) completes a real `initialize`
//!    round-trip before the revoke;
//!  - "a revoked peer is refused pre-MCP" → [`a_peer_the_roster_revokes_is_refused_pre_mcp`].
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{
    MeshState, build_services, install_roster_view_and_sever, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only server endpoint advertising BOTH mesh + pair ALPNs (mirrors `build_endpoint`),
/// so we can drive the daemon's real `spawn_accept_loop` in-process (as `daemon_dispatch.rs` does).
async fn dual_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind dual-ALPN endpoint")
}

/// A localhost-only client endpoint (dials mesh; never accepts).
async fn client_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint")
}

/// Mint + load a signed roster view: each `(device_endpoint_id, user_id)` is a one-device user in
/// group `team-eng`; `revoked` lists revoked endpoints. Built via `load_installed` (sig + structural
/// rules; no serial/expiry gate) with a far-future expiry — a valid, resolvable view the gate reads.
fn mint_view(
    root: &SigningKey,
    serial: u64,
    users: &[([u8; 32], &str)],
    revoked: &[[u8; 32]],
) -> RosterView {
    let roster_users = users
        .iter()
        .map(|(eid, uid)| RosterUser {
            user_id: (*uid).into(),
            display_name: (*uid).into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: vec!["team-eng".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(eid),
                label: "device".into(),
                role: "primary".into(),
            }],
        })
        .collect();
    let r = mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into()],
            users: roster_users,
            revoked_endpoints: revoked.iter().map(|e| encode_b64u(e)).collect(),
            sig: String::new(),
        },
    );
    load_installed(&r, &root.verifying_key()).expect("mint a valid roster view")
}

/// The `initialize` frame naming `service` in the reserved `_meta` (spec §7.2, so `select_service`
/// routes it) — mirrors `daemon_dispatch.rs`.
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

/// A `tools/call` frame whose `arguments.text` the echo stub echoes back — a live-session probe.
fn tools_call_frame(text: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": text}}
    })
}

/// Poll `registry.len()` to `target` (up to ~5s). Used ONLY as a secondary check AFTER a
/// connection-close observation: `sever_matching` closes connections but defers map removal to the
/// severed handler task's RAII Drop (T8 review caveat), so a synchronous `len()` right after sever
/// can transiently overcount — we assert on the close first, then let `len()` settle here.
async fn wait_for_len(registry: &ConnRegistry, target: usize) {
    for _ in 0..50 {
        if registry.len() == target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "conn registry len did not settle to {target} (still {})",
        registry.len()
    );
}

/// THE load-bearing AC proof. A ROSTERED peer (roster-resolved as "alice" AND ALSO holding a stale
/// pair entry) and a PAIRING-only peer each complete a live mesh session. Installing a NEW roster
/// that REVOKES the rostered peer's endpoint SEVERS its live session (its transport observes the
/// close) while the pairing-only session is NOT severed (it still round-trips a follow-up request).
#[tokio::test]
async fn install_severs_a_revoked_roster_session_but_not_a_pairing_session() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        // One `echo` service admits BOTH the roster user_id "alice" and the pairing petname "bob".
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"alice\", \"bob\"]\n"
        ))
        .expect("parse config");

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let alice_client = client_endpoint().await;
        let bob_client = client_endpoint().await;
        let alice_id = *alice_client.id().as_bytes();
        let bob_id = *bob_client.id().as_bytes();

        // The store carries a STALE pair entry for alice's endpoint (the AC's "including one holding
        // a stale pair entry") — masked by the roster identity — plus bob's real pairing entry.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: alice_id,
                petname: "alice-stale".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        store
            .add(PeerEntry {
                endpoint_id: bob_id,
                petname: "bob".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store.clone()));

        // The composed gate over a roster that lists alice's endpoint as her active device.
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(&root, 1, &[(alice_id, "alice")], &[]));
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
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

        // alice (rostered) completes a live session — proves a rostered peer serves under the
        // composed gate (the folded T6 assertion).
        let mut alice_t = connect(&alice_client, addr.clone(), "echo").await.unwrap();
        alice_t.send_value(initialize_frame("echo")).await.unwrap();
        let alice_init = alice_t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            alice_init["result"]["serverInfo"]["name"], "echo-stub",
            "rostered peer must complete a session under the composed gate: {alice_init}"
        );

        // bob (pairing-only) completes a live session.
        let mut bob_t = connect(&bob_client, addr.clone(), "echo").await.unwrap();
        bob_t.send_value(initialize_frame("echo")).await.unwrap();
        let bob_init = bob_t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            bob_init["result"]["serverInfo"]["name"], "echo-stub",
            "pairing peer must complete a session: {bob_init}"
        );

        // Both live connections are now registered (register-check happens-before the init reply).
        wait_for_len(&conn_registry, 2).await;

        // Install a NEW roster (serial 2) that REVOKES alice's endpoint. Swap-before-sever runs
        // inside; returns the count severed.
        let revoking = mint_view(&root, 2, &[(alice_id, "alice")], &[alice_id]);
        let severed = install_roster_view_and_sever(&mesh, revoking);
        assert_eq!(
            severed, 1,
            "exactly the revoked rostered session is severed"
        );

        // alice's live session is SEVERED: its next recv observes the close (an error/EOF, never a
        // frame). Assert on the CONNECTION close, not a synchronous len() (T8 review caveat).
        let alice_after = timeout(Duration::from_secs(5), alice_t.recv_value())
            .await
            .expect("alice's severed session must close promptly, not hang");
        assert!(
            !matches!(alice_after, Ok(Some(_))),
            "the revoked rostered session must be severed (closed), got a frame: {alice_after:?}"
        );

        // bob's pairing session is NOT severed — a follow-up request still round-trips.
        bob_t
            .send_value(tools_call_frame("still-alive"))
            .await
            .expect("bob's session is still live");
        let bob_reply = timeout(Duration::from_secs(5), bob_t.recv_value())
            .await
            .expect("bob's kept session must answer promptly")
            .expect("bob transport ok")
            .expect("bob reply frame");
        assert_eq!(
            bob_reply["result"]["content"][0]["text"], "still-alive",
            "the pairing-only session must NOT be severed by the roster install: {bob_reply}"
        );

        // Secondary: after alice's handler task unwinds, the registry settles to just bob.
        wait_for_len(&conn_registry, 1).await;
    })
    .await
    .expect("D8 sever test timed out");
}

/// The TOCTOU close, outcome-observed: a server whose installed roster ALREADY revokes the client's
/// endpoint refuses the dial PRE-MCP — the composed gate's `resolve` (is_revoked first) rejects it,
/// so no session is served and NO registry entry is created. This is the register-after-revoke race
/// closed at the source: a connection reading the revoked view never establishes.
#[tokio::test]
async fn a_peer_the_roster_revokes_is_refused_pre_mcp() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"alice\"]\n"
        ))
        .expect("parse config");

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let client = client_endpoint().await;
        let client_id = *client.id().as_bytes();

        // Empty store (no pairing entry). The roster lists the client's endpoint as alice's device
        // BUT revokes it — so the composed gate refuses it (revocation wins).
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(&root, 1, &[(client_id, "alice")], &[client_id]));
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
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

        // Dial mesh + attempt to initialize. The server refuses at the gate (QUIC 401) before any
        // stream is served → the client observes the connection end without a session frame.
        match connect(&client, addr, "echo").await {
            Err(_) => {} // refused at/near handshake — a valid "closed" outcome
            Ok(mut transport) => {
                let _ = transport.send_value(initialize_frame("echo")).await;
                let res = timeout(Duration::from_secs(5), transport.recv_value())
                    .await
                    .expect("a revoked dial must close promptly, not hang");
                assert!(
                    !matches!(res, Ok(Some(_))),
                    "a peer the roster revokes must be refused pre-MCP (no session frame), got: {res:?}"
                );
            }
        }

        // The refused connection never check-registered → the registry stays empty.
        wait_for_len(&conn_registry, 0).await;
    })
    .await
    .expect("TOCTOU pre-MCP refusal test timed out");
}

/// The OTHER `should_sever` branch, end-to-end (spec §4.3 rule 6, benign DEPARTURE): an endpoint
/// "previously resolved via the roster" that is ABSENT from the NEW roster — but NOT revoked (the
/// user was simply removed from the org, not compromised) — has its live session SEVERED too. This
/// exercises `roster_user.is_some() && !active_devices.contains(eid)` (the AC test hits the REVOKED
/// branch; this hits the dropped branch). It tests the SEVER PASS over an ALREADY-registered
/// connection (caught deterministically); the benign register-AFTER-sever race for this same case is
/// the consciously-deferred M3c hardening — distinct, and not what this asserts.
#[tokio::test]
async fn install_severs_a_dropped_roster_session_but_keeps_a_still_listed_one() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        // `echo` admits both roster user_ids "carol" and "dave".
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"carol\", \"dave\"]\n"
        ))
        .expect("parse config");

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let carol_client = client_endpoint().await;
        let dave_client = client_endpoint().await;
        let carol_id = *carol_client.id().as_bytes();
        let dave_id = *dave_client.id().as_bytes();

        // No pairing entries — both peers are ROSTER-resolved (roster_user = Some), the precondition
        // for the dropped-branch sever. Serial-1 roster lists BOTH carol/D and dave/E as active.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(
            &root,
            1,
            &[(carol_id, "carol"), (dave_id, "dave")],
            &[],
        ));
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
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

        // Both rostered peers open a live session (each registered as roster_user = Some(..)).
        let mut carol_t = connect(&carol_client, addr.clone(), "echo").await.unwrap();
        carol_t.send_value(initialize_frame("echo")).await.unwrap();
        let carol_init = carol_t.recv_value().await.unwrap().unwrap();
        assert_eq!(carol_init["result"]["serverInfo"]["name"], "echo-stub");

        let mut dave_t = connect(&dave_client, addr.clone(), "echo").await.unwrap();
        dave_t.send_value(initialize_frame("echo")).await.unwrap();
        let dave_init = dave_t.recv_value().await.unwrap().unwrap();
        assert_eq!(dave_init["result"]["serverInfo"]["name"], "echo-stub");

        wait_for_len(&conn_registry, 2).await;

        // Serial-2 roster REMOVES carol/D entirely — carol is NOT a user and NOT in
        // revoked_endpoints (a clean departure). dave/E stays listed.
        let dropped = mint_view(&root, 2, &[(dave_id, "dave")], &[]);
        let severed = install_roster_view_and_sever(&mesh, dropped);
        assert_eq!(
            severed, 1,
            "the dropped (roster-resolved, now-absent, NOT revoked) session is severed"
        );

        // carol's live session is SEVERED via the dropped branch: its next recv observes the close.
        let carol_after = timeout(Duration::from_secs(5), carol_t.recv_value())
            .await
            .expect("carol's dropped session must close promptly, not hang");
        assert!(
            !matches!(carol_after, Ok(Some(_))),
            "a roster-resolved endpoint dropped from the new roster must be severed, got: {carol_after:?}"
        );

        // dave (still listed on the same install) is KEPT — a follow-up request round-trips.
        dave_t
            .send_value(tools_call_frame("still-listed"))
            .await
            .expect("dave's session is still live");
        let dave_reply = timeout(Duration::from_secs(5), dave_t.recv_value())
            .await
            .expect("dave's kept session must answer promptly")
            .expect("dave transport ok")
            .expect("dave reply frame");
        assert_eq!(
            dave_reply["result"]["content"][0]["text"], "still-listed",
            "a still-listed roster device must NOT be severed by the same install: {dave_reply}"
        );

        // Secondary: after carol's handler unwinds, the registry settles to just dave.
        wait_for_len(&conn_registry, 1).await;
    })
    .await
    .expect("dropped-branch sever test timed out");
}
