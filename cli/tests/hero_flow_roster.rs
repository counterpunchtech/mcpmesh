//! M3a Task 12 — the minted-roster CAPSTONE E2E (spec §16 M3 AC), proving the whole roster
//! ENFORCEMENT CORE end to end over a REAL localhost mesh with a hand-minted, org-root-signed
//! roster. This is the roster analogue of M2b's `hero_flow_pairing.rs`: it drives the daemon's own
//! `spawn_accept_loop` (mesh dispatch), the composed gate, `select_service`'s group arm, the §6.3
//! identity injection, and the D8 sever pipeline in process.
//!
//! ── AC-clause → sub-test mapping (DECLARED; mirrors M2b's T8 decomposition) ──
//!   * **"group-based allow works"** →
//!     [`group_based_allow_admits_a_rostered_caller_and_injects_full_identity`]: a service that
//!     admits a GROUP (`allow = ["team-eng"]`, NOT a user_id or nickname) admits a rostered caller
//!     resolved into that group, and the served child sees the full §6.3 identity env
//!     (`MCPMESH_PEER_NAME` + `MCPMESH_PEER_USER` + `MCPMESH_PEER_GROUPS`).
//!   * **"revoked device cut from live sessions — including one holding a stale pair entry"** →
//!     [`revoking_a_rostered_device_severs_its_live_session_and_a_stale_pair_entry_does_not_save_it`]:
//!     a live rostered session (whose endpoint ALSO holds a stale pair entry) is SEVERED by a
//!     serial+1 roster revoking it, while a pairing-only peer's live session is untouched; a fresh
//!     re-dial from the revoked endpoint is then refused PRE-MCP (revocation wins over the pair
//!     entry, §4.1(1)). Assert-on-close, never sync `len()`.
//!   * **the roster status surface (§4.4)** →
//!     [`status_reports_the_installed_roster_over_the_control_api`]: a raw (non-porcelain)
//!     `connect_control` client reads `status.roster` = org_id / serial / approved / org-root
//!     fingerprint words over `mcpmesh-local/1`.
//!
//! (The full-enrollment-via-porcelain AC clause is M3b org porcelain; M3a uses the manual mint +
//! `install_roster_view_and_sever` path per scope — the SAME `sign`/`mint_signed` production path
//! M3b's `org approve` will drive.) In-process localhost; the 3-node 60s-propagation timing test is
//! M3c (M3a proves the sever MECHANISM here, not cross-node timing).
// Unix-only: hand-binds the control endpoint in-process (`bind_control_socket`) at a
// filesystem socket path and connects to it via `connect_control`, which a windows named
// pipe cannot be. Windows coverage for the control path lives at the transport layer
// (local-api transport::windows pipe tests) and the client protocol layer (local-api
// client.rs seam tests); a windows daemon-subprocess round-trip is deferred — see the
// plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::Request;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{
    self, MeshState, build_services, install_roster_view_and_sever, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::pairing::sas::fingerprint_words;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

/// The hermetic echo MCP stub — echoes a `tools/call` payload plus the injected identity env
/// (`peer_name`/`peer_user`/`peer_groups`), so the E2E can assert the §6.3 injection at the child.
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only server endpoint advertising BOTH mesh + pair ALPNs (mirrors `build_endpoint`),
/// so we can drive the daemon's real `spawn_accept_loop` in-process (as `roster_sever.rs` does).
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

/// Mint + load a signed roster view. `groups` are the top-level declared groups (rule 5b); each
/// `(endpoint, user_id, user_groups)` is a one-device user; `revoked` lists revoked endpoints.
/// Built via `load_installed` (sig + structural rules, no serial/expiry gate) with a far-future
/// expiry — a currently-valid, resolvable view the gate reads, signed by the production mint path.
fn mint_view(
    root: &SigningKey,
    serial: u64,
    groups: &[&str],
    users: &[([u8; 32], &str, &[&str])],
    revoked: &[[u8; 32]],
) -> RosterView {
    let roster_users = users
        .iter()
        .map(|(eid, uid, ugroups)| RosterUser {
            user_id: (*uid).into(),
            display_name: (*uid).into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: ugroups.iter().map(|g| (*g).to_string()).collect(),
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
            groups: groups.iter().map(|g| (*g).to_string()).collect(),
            users: roster_users,
            revoked_endpoints: revoked.iter().map(|e| encode_b64u(e)).collect(),
            sig: String::new(),
        },
    );
    load_installed(&r, &root.verifying_key()).expect("mint a valid roster view")
}

/// The `initialize` frame naming `service` in the reserved `_meta` (spec §7.2, so `select_service`
/// routes it) — mirrors `roster_sever.rs`.
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

/// Poll `registry.len()` to `target` (up to ~5s). A secondary check AFTER a connection-close
/// observation: `sever_matching` closes connections but defers map removal to the severed handler's
/// RAII Drop, so a synchronous `len()` right after sever can transiently overcount — we assert on
/// the close first, then let `len()` settle here (the roster_sever.rs discipline).
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

/// **(AC: group-based allow works.)** A service that admits a GROUP (`allow = ["team-eng"]` — not a
/// user_id, not a nickname) admits a rostered caller resolved into that group, over a REAL session,
/// and the served child sees the full §6.3 identity env: `MCPMESH_PEER_NAME` = user_id,
/// `MCPMESH_PEER_USER` = user_id, `MCPMESH_PEER_GROUPS` = the comma-joined groups.
#[tokio::test(flavor = "multi_thread")]
async fn group_based_allow_admits_a_rostered_caller_and_injects_full_identity() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        // The service admits a GROUP, not a user_id or nickname (the AC's "group-based allow works").
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"team-eng\"]\n"
        ))
        .expect("parse config");

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let alice_client = client_endpoint().await;
        let alice_id = *alice_client.id().as_bytes();

        // Empty pairing store — alice is admitted PURELY by the roster group, nothing else.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));

        // Roster: user "alice" in groups [team-eng, all] (both declared), device = alice's endpoint.
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(
            &root,
            1,
            &["team-eng", "all"],
            &[(alice_id, "alice", &["team-eng", "all"])],
            &[],
        ));
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

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
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));

        // alice dials echo: the composed gate resolves her to {name:"alice", user_id:Some("alice"),
        // groups:[team-eng, all]}; select_service admits via the GROUP arm (allow=["team-eng"]).
        let mut alice_t = connect(&alice_client, addr, "echo").await.unwrap();
        alice_t.send_value(initialize_frame("echo")).await.unwrap();
        let init = alice_t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "group-based allow must admit the rostered caller to a live session: {init}"
        );

        // tools/call → the echo child answers AND reports the injected §6.3 identity env. Full
        // injection: PEER_NAME + PEER_USER (roster user_id) + PEER_GROUPS (comma-joined).
        alice_t
            .send_value(tools_call_frame("group-allow"))
            .await
            .unwrap();
        let reply = timeout(Duration::from_secs(5), alice_t.recv_value())
            .await
            .expect("echo reply must arrive promptly")
            .expect("transport ok")
            .expect("reply frame");
        assert_eq!(reply["result"]["content"][0]["text"], "group-allow");
        assert_eq!(
            reply["result"]["peer_name"], "alice",
            "MCPMESH_PEER_NAME = the roster user_id: {reply}"
        );
        assert_eq!(
            reply["result"]["peer_user"], "alice",
            "MCPMESH_PEER_USER = the roster user_id (roster mode): {reply}"
        );
        let groups = reply["result"]["peer_groups"].as_str().unwrap_or_default();
        assert!(
            groups.split(',').any(|g| g == "team-eng"),
            "MCPMESH_PEER_GROUPS must contain the admitting group `team-eng`, got {groups:?}: {reply}"
        );
    })
    .await
    .expect("group-allow E2E timed out");
}

/// **(AC: revoked device cut from live sessions — including one holding a stale pair entry.)** A
/// rostered peer (group-admitted, and ALSO holding a stale pair entry) and a pairing-only peer each
/// complete a live session. A serial+1 roster REVOKING the rostered endpoint SEVERS its live session
/// (observed via the close) but leaves the pairing-only session untouched; a fresh re-dial from the
/// revoked endpoint — which still holds its stale pair entry — is then refused PRE-MCP (revocation
/// wins over the pair entry, §4.1(1)).
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_rostered_device_severs_its_live_session_and_a_stale_pair_entry_does_not_save_it()
 {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        // echo admits the roster GROUP `team-eng` (alice) AND the pairing nickname `bob`.
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"team-eng\", \"bob\"]\n"
        ))
        .expect("parse config");

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let alice_client = client_endpoint().await;
        let bob_client = client_endpoint().await;
        let alice_id = *alice_client.id().as_bytes();
        let bob_id = *bob_client.id().as_bytes();

        // The store holds a STALE pair entry for alice's endpoint (the AC's "one holding a stale pair
        // entry" — masked by her roster identity) plus bob's real pairing entry.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: alice_id,
                nickname: "alice-stale".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        store
            .add(PeerEntry {
                endpoint_id: bob_id,
                nickname: "bob".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store.clone()));

        // Roster (serial 1): alice in group team-eng, device = alice's endpoint. bob is NOT rostered.
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(
            &root,
            1,
            &["team-eng"],
            &[(alice_id, "alice", &["team-eng"])],
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

        // alice (rostered, group-admitted, and ALSO holding a stale pair entry) completes a session.
        let mut alice_t = connect(&alice_client, addr.clone(), "echo").await.unwrap();
        alice_t.send_value(initialize_frame("echo")).await.unwrap();
        assert_eq!(
            alice_t.recv_value().await.unwrap().unwrap()["result"]["serverInfo"]["name"],
            "echo-stub",
            "the rostered group-admitted peer must complete a session"
        );

        // bob (pairing-only) completes a session.
        let mut bob_t = connect(&bob_client, addr.clone(), "echo").await.unwrap();
        bob_t.send_value(initialize_frame("echo")).await.unwrap();
        assert_eq!(
            bob_t.recv_value().await.unwrap().unwrap()["result"]["serverInfo"]["name"],
            "echo-stub",
            "the pairing-only peer must complete a session"
        );

        wait_for_len(&conn_registry, 2).await;

        // Install a serial-2 roster REVOKING alice's endpoint (listed as her device AND revoked →
        // revocation wins in build_view). Swap-before-sever runs inside; returns the count severed.
        let severed = install_roster_view_and_sever(
            &mesh,
            mint_view(
                &root,
                2,
                &["team-eng"],
                &[(alice_id, "alice", &["team-eng"])],
                &[alice_id],
            ),
        );
        assert_eq!(
            severed, 1,
            "exactly the revoked rostered session is severed (not bob's pairing session)"
        );

        // alice's live session is SEVERED — its next recv observes the close (assert on the CLOSE,
        // not a synchronous len()). This is the revoked-device-with-a-stale-pair-entry AC clause.
        let alice_after = timeout(Duration::from_secs(5), alice_t.recv_value())
            .await
            .expect("alice's severed session must close promptly, not hang");
        assert!(
            !matches!(alice_after, Ok(Some(_))),
            "the revoked rostered session must be severed even though it holds a stale pair entry, got: {alice_after:?}"
        );

        // bob's pairing session is NOT severed by the roster install — a follow-up still round-trips.
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

        // A FRESH dial from alice's (now-revoked) endpoint — which STILL holds the stale pair entry —
        // is refused PRE-MCP: revocation wins over the pair entry (§4.1(1)). The composed gate's
        // is_revoked check rejects it before any session frame.
        match connect(&alice_client, addr, "echo").await {
            Err(_) => {} // refused at/near handshake — a valid "closed" outcome
            Ok(mut t) => {
                let _ = t.send_value(initialize_frame("echo")).await;
                let res = timeout(Duration::from_secs(5), t.recv_value())
                    .await
                    .expect("a revoked re-dial must close promptly, not hang");
                assert!(
                    !matches!(res, Ok(Some(_))),
                    "a revoked endpoint holding a stale pair entry must be refused pre-MCP, got: {res:?}"
                );
            }
        }

        // Secondary: after alice's handler task unwinds, the registry settles to just bob.
        wait_for_len(&conn_registry, 1).await;
    })
    .await
    .expect("revocation-sever E2E timed out");
}

/// **(status, §4.4.)** A raw (non-porcelain) `connect_control` client reads `status.roster` over
/// `mcpmesh-local/1`: org_id + serial + the plain state word (`approved`) + the pinned org-root
/// FINGERPRINT in short words. Computed live from `mesh.roster.view()` + the config-pinned org root.
#[tokio::test(flavor = "multi_thread")]
async fn status_reports_the_installed_roster_over_the_control_api() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        // A config carrying the pinned org root — `roster_status` derives the fingerprint from it.
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[network]\nrelay_mode = \"disabled\"\n[identity]\norg_root_pk = \"{org_root_pk}\"\norg_id = \"acme\"\n"
            ),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));
        let roster = Arc::new(RosterGate::empty());
        roster.install(mint_view(
            &root,
            7,
            &["team-eng"],
            &[([2u8; 32], "alice", &["team-eng"])],
            &[],
        ));
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

        let endpoint = client_endpoint().await;
        let mesh = MeshState::new(
            endpoint,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "server".into(),
            config_path,
            roster.clone(),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );

        // Bind a control socket + serve the real control API over the roster-installed mesh.
        let socket = dir.path().join("control.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(daemon::STACK_VERSION, mesh));
        let control = tokio::spawn(serve_control(listener, state));

        // A raw (non-porcelain) client reads status.roster over mcpmesh-local/1.
        let mut client = connect_control(&socket)
            .await
            .expect("raw connect_control");
        assert_eq!(client.hello().api, "mcpmesh-local/1");
        let status = client
            .request(Request::Status)
            .await
            .expect("status over mcpmesh-local/1");
        let roster_status = &status["roster"];
        assert_eq!(
            roster_status["org_id"], "acme",
            "status shows the org id (from the installed view): {status}"
        );
        assert_eq!(
            roster_status["serial"], 7,
            "status shows the installed serial: {status}"
        );
        assert_eq!(
            roster_status["state"], "approved",
            "a currently-valid (unexpired) roster is `approved`: {status}"
        );
        assert_eq!(
            roster_status["org_root_fingerprint"],
            fingerprint_words(&root.verifying_key().to_bytes()),
            "status shows the pinned org-root fingerprint in short words: {status}"
        );
        assert!(
            !roster_status["org_root_fingerprint"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "the org-root fingerprint is present (a pin was configured): {status}"
        );

        control.abort();
    })
    .await
    .expect("roster-status E2E timed out");
}
