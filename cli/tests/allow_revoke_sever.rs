//! #54: a revoke reaches a peer that is ALREADY connected.
//!
//! Two independent holes, one test each:
//!  - **New sessions.** Each connection used to carry an `Arc<Services>` captured when the accept
//!    loop was spawned, so a revoked peer kept opening ADMITTED sessions on its existing connection
//!    for that connection's whole lifetime. The live registry (`LiveServices`, read per bi-stream)
//!    closes it.
//!  - **In-flight sessions.** Neither revoke handler called `sever_matching`, so sessions already
//!    running continued regardless. `sever_principal` closes it.
//!
//! Plus the two regressions that keep the sever honest: an unrelated peer is untouched, and
//! `peer_remove` severs the peer it removes.
//!
//! In-process localhost, driving the daemon's REAL `spawn_accept_loop` + the REAL
//! `revoke_service_allow` / `remove_peer` pipelines (mirrors `roster_sever.rs`).

use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{MeshState, build_services, revoke_service_allow, spawn_accept_loop};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, MAX_FRAME_BYTES, SessionTransport, TrustGate, framing::write_frame};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only server endpoint advertising the mesh ALPN (mirrors `roster_sever.rs`).
async fn server_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind server endpoint")
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

/// The `initialize` frame naming `service` in the reserved `_meta` (so `select_service` routes it).
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

/// A `tools/call` frame the echo stub answers — a live-session probe.
fn tools_call_frame(text: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": text}}
    })
}

/// A paired peer allowed on `echo`, its `PeerEntry` written to the store.
struct Peer {
    endpoint: iroh::Endpoint,
    principal: String,
}

/// Build a PAIRING-mode mesh (empty roster) serving one `run` service `echo` whose `allow` lists
/// every peer's stable `eid:` principal, with a `PeerEntry` per peer so the gate resolves them.
/// Returns the mesh, its addr, the peers, and the temp dir (kept alive by the caller).
async fn paired_mesh(
    nicknames: &[&str],
) -> (
    Arc<MeshState>,
    iroh::EndpointAddr,
    Arc<ConnRegistry>,
    Vec<Peer>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());

    let mut peers = Vec::new();
    for nickname in nicknames {
        let endpoint = client_endpoint().await;
        let id = *endpoint.id().as_bytes();
        store
            .add(PeerEntry {
                endpoint_id: id,
                nickname: (*nickname).to_string(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        peers.push(Peer {
            principal: format!("eid:{}", endpoint.id()),
            endpoint,
        });
    }

    // The config `allow` lists every peer's STABLE principal (#38 — nicknames never admit).
    let allow = peers
        .iter()
        .map(|p| format!("\"{}\"", p.principal))
        .collect::<Vec<_>>()
        .join(", ");
    // `later` exists but admits NOBODY yet — the grant test turns it on mid-connection, which is
    // how Part A (the live registry) gets isolated from Part B (the sever).
    let config_path = dir.path().join("config.toml");
    let toml = format!(
        "[services.echo]\nrun = ['{STUB}']\nallow = [{allow}]\n\
         \n[services.later]\nrun = ['{STUB}']\nallow = []\n"
    );
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
        conn_registry.clone(),
        None,
        None,
        None,
        None,
    );
    mesh.set_accept_task(spawn_accept_loop(
        mesh.clone(),
        Arc::new(build_services(&cfg)),
    ))
    .await;
    (mesh, addr, conn_registry, peers, dir)
}

/// Dial the mesh ALPN and hold the QUIC CONNECTION, so the test can open several sessions
/// (bi-streams) on the SAME connection — which `mcpmesh_net::connect` cannot do (it dials and opens
/// exactly one). That distinction is the whole point of the new-session test.
async fn dial(client: &iroh::Endpoint, addr: iroh::EndpointAddr) -> iroh::endpoint::Connection {
    client
        .connect(addr, ALPN_MCP)
        .await
        .expect("dial the mesh ALPN")
}

/// Open ONE session (bi-stream) on an existing connection and send `initialize` for `service`.
/// `None` when the connection is already gone — opening a stream on a severed connection is a
/// legitimate outcome here, not a test failure, and quinn may or may not have processed the peer's
/// CONNECTION_CLOSE yet, so this must never `expect()`.
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

/// Did this session get SERVED? A served session answers `initialize` with the stub's serverInfo;
/// a refused one yields an error frame or a closed stream. `None` (the stream never opened) is
/// not served.
async fn session_served(transport: Option<&mut SessionTransport>) -> bool {
    let Some(transport) = transport else {
        return false;
    };
    match timeout(Duration::from_secs(5), transport.recv_value()).await {
        Ok(Ok(Some(v))) => v["result"]["serverInfo"]["name"] == "echo-stub",
        _ => false,
    }
}

/// THE Part-A proof, in ISOLATION. A **grant** reaches an already-open connection.
///
/// This is the test that pins the live registry, and it is deliberately built on the GRANT path
/// because a grant never severs anything: the only way the second session can be served is if the
/// connection re-read the registry. The revoke-side test below cannot do this job — the sever
/// closes the connection, so its refusal is explained by Part B alone and it keeps passing with
/// Part A reverted (found by adversarial review; the earlier version of this file had no coverage
/// of Part A at all).
///
/// Alice holds an open connection. `later` admits nobody, so her session is refused. She is then
/// granted `later`, and a NEW session on the SAME connection must be SERVED — while the connection
/// stays up throughout, which is what proves no sever was involved.
#[tokio::test]
async fn a_grant_is_live_on_an_already_open_connection() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut before = open_session(&conn, "later").await;
        assert!(
            !session_served(before.as_mut()).await,
            "`later` admits nobody yet, so this session must be refused (setup)"
        );

        // The grant path: append to allow + swap the live registry. No sever anywhere.
        mcpmesh::daemon::grant_service_access(
            &mesh,
            &alice.principal,
            &alice.principal,
            &["later".to_string()],
        )
        .await
        .expect("grant succeeds");

        assert!(
            conn.close_reason().is_none(),
            "a grant must not disturb the connection — if it closed, this test is not isolating \
             the live registry"
        );

        let mut after = open_session(&conn, "later").await;
        assert!(
            session_served(after.as_mut()).await,
            "a grant must be visible to the NEXT session on an ALREADY-OPEN connection"
        );
    })
    .await
    .expect("grant-goes-live test timed out");
}

/// THE new-session proof on the revoke side. Alice is connected and served. Her grant is revoked.
/// A NEW session on the SAME connection must be REFUSED — before #54 it was admitted for the whole
/// lifetime of that connection, because the connection held a snapshot of the allow list.
///
/// Note this one is satisfied by EITHER half of the fix (the sever also closes the connection), so
/// it is a contract test, not a Part-A regression test — see the grant test above for that.
#[tokio::test]
async fn a_new_session_on_an_open_connection_is_refused_after_revoke() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut first = open_session(&conn, "echo").await;
        assert!(
            session_served(first.as_mut()).await,
            "the granted peer must be served BEFORE the revoke (setup)"
        );

        revoke_service_allow(&mesh, "echo".into(), alice.principal.clone())
            .await
            .expect("revoke succeeds");

        // SAME connection, NEW bi-stream. The connection may also have been severed — either way
        // this session must NOT be served.
        let mut second = open_session(&conn, "echo").await;
        assert!(
            !session_served(second.as_mut()).await,
            "a revoked peer must not open a NEW session on its already-open connection"
        );
    })
    .await
    .expect("new-session-after-revoke test timed out");
}

/// THE in-flight proof. Alice holds a live session; the revoke must CLOSE her connection, not
/// merely refuse her next session.
#[tokio::test]
async fn revoke_severs_the_live_connection() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut session = open_session(&conn, "echo").await;
        assert!(
            session_served(session.as_mut()).await,
            "served before revoke"
        );

        revoke_service_allow(&mesh, "echo".into(), alice.principal.clone())
            .await
            .expect("revoke succeeds");

        // The server closes the QUIC connection from its side.
        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("a revoke must SEVER the live connection, not leave it running");
    })
    .await
    .expect("sever test timed out");
}

/// The regression that keeps the sever honest: revoking alice must not disturb bob, who is
/// connected, served, and still granted. Over-severing would be a self-inflicted outage.
#[tokio::test]
async fn revoke_does_not_sever_an_unrelated_peer() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice", "bob"]).await;
        let (alice, bob) = (&peers[0], &peers[1]);

        let alice_conn = dial(&alice.endpoint, addr.clone()).await;
        let mut alice_session = open_session(&alice_conn, "echo").await;
        assert!(session_served(alice_session.as_mut()).await, "alice served");

        let bob_conn = dial(&bob.endpoint, addr).await;
        let mut bob_session = open_session(&bob_conn, "echo").await;
        assert!(session_served(bob_session.as_mut()).await, "bob served");

        revoke_service_allow(&mesh, "echo".into(), alice.principal.clone())
            .await
            .expect("revoke alice");

        // bob's in-flight session still round-trips...
        let bob_session = bob_session.as_mut().expect("bob's session opened");
        bob_session
            .send_value(tools_call_frame("still-alive"))
            .await
            .expect("bob's session is still live");
        let reply = timeout(Duration::from_secs(5), bob_session.recv_value())
            .await
            .expect("bob's kept session must answer promptly")
            .expect("bob transport ok")
            .expect("bob reply frame");
        assert_eq!(
            reply["result"]["content"][0]["text"], "still-alive",
            "revoking alice must NOT sever bob's live session: {reply}"
        );

        // ...and bob can still open a NEW session on his connection.
        let mut bob_second = open_session(&bob_conn, "echo").await;
        assert!(
            session_served(bob_second.as_mut()).await,
            "revoking alice must not affect bob's new sessions"
        );
    })
    .await
    .expect("unrelated-peer regression timed out");
}

/// `peer_remove`'s authorization half severs the removed peer's live connection too — the same
/// guarantee as `service_allow_revoke`, via the shared resolve→sever helper.
#[tokio::test]
async fn removing_a_peer_severs_its_live_connection() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice", "bob"]).await;
        let (alice, bob) = (&peers[0], &peers[1]);

        let alice_conn = dial(&alice.endpoint, addr.clone()).await;
        let mut alice_session = open_session(&alice_conn, "echo").await;
        assert!(session_served(alice_session.as_mut()).await, "alice served");

        let bob_conn = dial(&bob.endpoint, addr).await;
        let mut bob_session = open_session(&bob_conn, "echo").await;
        assert!(session_served(bob_session.as_mut()).await, "bob served");

        // `revoke_service_allow` is per-service; `peer_remove`'s authorization half strips the
        // peer from EVERY service and severs — drive it through the same public entry the daemon
        // uses for the removal's authorization step.
        mcpmesh::daemon::revoke_service_access(&mesh, "alice")
            .await
            .expect("revoke alice's authorization");

        timeout(Duration::from_secs(5), alice_conn.closed())
            .await
            .expect("removing a peer must sever its live connection");

        // bob is untouched.
        let bob_session = bob_session.as_mut().expect("bob's session opened");
        bob_session
            .send_value(tools_call_frame("bob-ok"))
            .await
            .expect("bob's session is still live");
        let reply = timeout(Duration::from_secs(5), bob_session.recv_value())
            .await
            .expect("bob answers")
            .expect("bob transport ok")
            .expect("bob reply frame");
        assert_eq!(reply["result"]["content"][0]["text"], "bob-ok");
    })
    .await
    .expect("peer-remove sever test timed out");
}
