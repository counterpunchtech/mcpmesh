//! Task 9 acceptance: the daemon's serving composition end-to-end over a real (localhost)
//! Iroh mesh. This drives the SAME wiring `daemon::run()` builds — config `[services.*]` →
//! [`mcpmesh::daemon::build_services`] (`run` = [`SpawnBackend`]) → [`AllowlistGate`] over a
//! [`PeerStore`] → `mcpmesh_net::serve` — but against in-process endpoints, so it can assert
//! the whole chain including the ENV IDENTITY INJECTION the child sees, without a daemon
//! subprocess or the pairing ceremony (trust is populated via the store, the `internal peer
//! add` stand-in).
//!
//! Authorization is by STABLE principal (#38): `[services.*].allow` holds the caller's
//! `eid:` device principal (or a user_id / roster group name), never its display nickname.
//! The nickname remains display-only — the proof of injection is still end-to-end: the
//! served child is `echo_mcp_stub`, which echoes back `getenv("MCPMESH_PEER_NAME")` as
//! `result.peer_name`. The connecting peer resolves (at the gate) to nickname `tester`;
//! asserting `peer_name == "tester"` at the far end proves the gate-resolved identity
//! threaded through `SessionBackend::run` all the way into the child's environment across
//! the mesh — while its ADMISSION rode the `eid:` principal in `allow`.
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control_io};
use mcpmesh::daemon::{MeshState, STACK_VERSION, build_services, spawn_accept_loop};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_local_api::{BackendSpec, connect_control_io};
use mcpmesh_net::{SessionTransport, TrustGate, connect, serve};
use serde_json::{Value, json};
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only endpoint carrying the mcpmesh/mcp/1 ALPN (relay disabled — hermetic, no
/// network egress; matches the daemon's `relay_mode = "disabled"` path).
async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

#[tokio::test]
async fn daemon_serves_run_service_and_injects_caller_identity_over_the_mesh() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // The "client machine": a second in-process endpoint, bound FIRST — its endpoint id
        // is both the trust key we populate (the `internal peer add` stand-in) and, rendered
        // as `eid:<hex>`, the STABLE principal the service's allow list names (#38).
        let client = local_endpoint().await;
        let client_id = *client.id().as_bytes();
        let client_eid = format!("eid:{}", client.id());

        // Config: one `run` service `echo` = the hermetic stub, admitting the client's
        // `eid:` device principal (never the nickname — #38). A TOML literal string ('..')
        // for the path avoids any escape concerns.
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"{client_eid}\"]\n"
        ))
        .expect("parse config");

        // Populate trust: `internal peer add tester <client id>` → a PeerEntry in the store.
        // The nickname `tester` is DISPLAY-ONLY; admission above is by eid.
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        store
            .add(PeerEntry {
                endpoint_id: client_id,
                nickname: "tester".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(Arc::new(store)));

        // The "server machine": build the endpoint + registry + gate the daemon would, and
        // serve.
        let server = local_endpoint().await;
        let addr = server.addr();
        let _handle = serve(
            server,
            gate,
            build_services(&cfg),
            Arc::new(mcpmesh_net::ConnRegistry::new()),
        );

        // Connect as the trusted peer and complete initialize + tools/call.
        let mut transport = connect(&client, addr, "echo").await.unwrap().0;
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "_meta": {"mcpmesh/service": "echo"},
                    "capabilities": {}, "clientInfo": {"name": "tester", "version": "0"}
                }
            }))
            .await
            .unwrap();
        let init_res = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init_res["result"]["serverInfo"]["name"], "echo-stub",
            "the served child answered initialize over the mesh"
        );

        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "over the mesh"}}
            }))
            .await
            .unwrap();
        let call_res = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            call_res["result"]["content"][0]["text"], "over the mesh",
            "the served child echoed the tools/call payload"
        );
        // The end-to-end env-injection proof: the child saw MCPMESH_PEER_NAME=tester — the
        // gate-resolved DISPLAY identity flowed through run() into the spawned child's
        // environment, even though admission rode the eid principal.
        assert_eq!(
            call_res["result"]["peer_name"], "tester",
            "the child's MCPMESH_PEER_NAME carried the gate-resolved nickname across the mesh"
        );
        // #60: and the STABLE device principal, which is what a `run` server must key per-caller
        // scoping on. It is UNCONDITIONAL — this caller presented no device->user binding, so
        // `peer_user` is empty and the nickname was previously the ONLY identifier the child had.
        assert_eq!(
            call_res["result"]["peer_eid"], client_eid,
            "the child's MCPMESH_PEER_EID carried the authenticated endpoint principal"
        );
        assert_eq!(
            call_res["result"]["peer_user"], "",
            "setup: an unbound pairing caller — exactly the case that had no stable principal"
        );
    })
    .await
    .expect("daemon serve integration test timed out");
}

/// Send an `initialize` naming `service` and return the first response frame (an
/// InitializeResult, or a synthesized refusal like -32054).
async fn send_initialize(transport: &mut SessionTransport, service: &str) -> Value {
    transport
        .send_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "_meta": {"mcpmesh/service": service},
                "capabilities": {}
            }
        }))
        .await
        .unwrap();
    transport.recv_value().await.unwrap().unwrap()
}

/// The hot-reload's real purpose, driven through the REAL `register_service` control verb
/// (in-process `serve_control_io` over a duplex): after the daemon's live accept loop is
/// hot-swapped, a NEWLY-registered service is actually SERVED over the mesh. Before the
/// registration the service is refused (-32054, not in the registry); after it a real second
/// endpoint completes initialize + tools/call against it (with identity injected). This
/// guards the FIX-1 reload path — a torn or lost-update config would yield a dead/wrong
/// registry — and proves the swap installs a LIVE serve, not just a fresh accept loop.
///
/// It is ALSO the canonical operator-input coverage (#38): allow entries are stored VERBATIM
/// — the operator names the caller's `eid:` device principal (which admits it, resilient to
/// any later rename) plus a bare roster name `ghost` (kept verbatim). A peer merely NICKNAMED
/// `ghost` is NOT admitted — the display nickname never authorizes, and the daemon does no
/// nickname→principal resolution (a self-asserted nickname could shadow roster vocabulary).
#[tokio::test]
async fn hot_reload_serves_a_newly_registered_service_over_the_mesh() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // Two connectors: `prober` dials pre-swap, `tester` post-swap. Distinct endpoints →
        // distinct connections, so the post-swap dial cannot reuse the pre-swap
        // (old-registry) one.
        let before = local_endpoint().await;
        let after = local_endpoint().await;
        let tester_eid = format!("eid:{}", after.id());
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        for (ep, nick) in [(&before, "prober"), (&after, "tester")] {
            store
                .add(PeerEntry {
                    endpoint_id: *ep.id().as_bytes(),
                    nickname: nick.into(),
                    services: vec!["echo".into()],
                    paired_at: None,
                    user_id: None,
                    last_addr: None,
                })
                .unwrap();
        }
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));

        // The serving daemon: a real MeshState + its own accept loop over an EMPTY registry
        // (`echo` is not yet registered), plus the control API served in-process — the exact
        // composition `register_service` hot-reloads.
        let server = local_endpoint().await;
        let addr = server.addr();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mesh = MeshState::new(
            server,
            gate,
            store.clone(),
            Arc::new(LiveInvites::new()),
            "server".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(mcpmesh_net::ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let accept_task = spawn_accept_loop(
            mesh.clone(),
            Arc::new(build_services(&Config::load(&config_path).unwrap())),
        );
        mesh.set_accept_task(accept_task).await;

        // Pre-swap: `echo` is refused (unknown/unauthorized service, §5).
        let mut t_before = connect(&before, addr.clone(), "echo").await.unwrap().0;
        let refused = send_initialize(&mut t_before, "echo").await;
        assert_eq!(
            refused["error"]["code"], -32054,
            "echo must be UNSERVED before the reload: {refused}"
        );

        // The REAL hot-reload: `register_service` over the control API. The operator names
        // the caller's stable `eid:` principal (admits it) plus a bare roster name `ghost`;
        // both are stored VERBATIM (#38), persisted, and the accept loop hot-swaps.
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));
        let (ctl_side, daemon_side) = tokio::io::duplex(64 * 1024);
        let (d_read, d_write) = tokio::io::split(daemon_side);
        tokio::spawn(serve_control_io(d_read, d_write, state));
        let (c_read, c_write) = tokio::io::split(ctl_side);
        let mut ctl = connect_control_io(c_read, c_write).await.unwrap();
        ctl.register_service(
            "echo",
            BackendSpec::Run {
                cmd: vec![STUB.into()],
                env: Default::default(),
                cwd: None,
            },
            vec![tester_eid.clone(), "ghost".into()],
        )
        .await
        .expect("register_service");

        // Stored VERBATIM (#38): exactly what the operator typed — the eid principal and the
        // bare roster name, no resolution, no rewriting.
        let persisted = Config::load(&config_path).unwrap();
        assert_eq!(
            persisted.services["echo"].allow,
            vec![tester_eid.clone(), "ghost".to_string()],
            "operator-typed allow is stored verbatim (#38)"
        );

        // Post-swap: a real second endpoint completes initialize + tools/call against the
        // newly-served `echo` — admitted via its eid principal, identity injected.
        let mut t_after = connect(&after, addr.clone(), "echo").await.unwrap().0;
        let init = send_initialize(&mut t_after, "echo").await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "echo must be SERVED after the reload: {init}"
        );
        t_after
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"arguments": {"text": "after reload"}}
            }))
            .await
            .unwrap();
        let call = t_after.recv_value().await.unwrap().unwrap();
        assert_eq!(call["result"]["content"][0]["text"], "after reload");
        assert_eq!(
            call["result"]["peer_name"], "tester",
            "identity injection still holds through the reloaded serve loop"
        );

        // The verbatim `ghost` entry is roster vocabulary, NOT a nickname grant: a peer
        // added to the store AFTER the registration with nickname `ghost` (no user_id, no
        // groups) is trusted onto the mesh but NOT admitted to `echo` — the display
        // nickname never admits (#38).
        let ghost = local_endpoint().await;
        store
            .add(PeerEntry {
                endpoint_id: *ghost.id().as_bytes(),
                nickname: "ghost".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let mut t_ghost = connect(&ghost, addr, "echo").await.unwrap().0;
        let ghost_refused = send_initialize(&mut t_ghost, "echo").await;
        assert_eq!(
            ghost_refused["error"]["code"], -32054,
            "a bare allow entry kept verbatim must not admit a peer by NICKNAME: {ghost_refused}"
        );
    })
    .await
    .expect("hot-reload serve test timed out");
}
