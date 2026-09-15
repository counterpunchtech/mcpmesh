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
use mcpmesh::daemon::{
    MeshState, build_services, revoke_service_access, revoke_service_allow, spawn_accept_loop,
};
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

/// Hang guard for a session's answer (#228) — NOT a latency budget.
///
/// Serving means the server spawning `echo_mcp_stub` and relaying its `initialize` reply. Measured
/// on macOS: ~10–300ms normally, but the FIRST exec of a freshly linked stub waits for the OS's
/// first-exec code assessment, which queues behind every other freshly linked binary being
/// assessed — and a suite run after any change relinks dozens of them. Reproduced by replacing the
/// stub with a fresh copy and exec'ing 8 fresh copies of a 66MB test binary alongside: the round trip
/// took 12–21s, while the server accepted the stream, read `initialize` and returned from `spawn`
/// within 2ms — the wait was the child's first exec. The old 5s bound failed all 8 tests at once in
/// 11 of 12 such runs; a warm stub answers in milliseconds, which is why the same binary passed alone.
///
/// No test here is ABOUT that latency, so the bound only separates slow from hung. It is also the
/// refusal bound: a refusal spawns nothing and answers at once, so it waits this long only when
/// something is broken.
const SESSION_ANSWER_GUARD: Duration = Duration::from_secs(60);

/// Assert this session was REFUSED — definitively (#228).
///
/// A refusal is an answer that is not the stub's serverInfo (the -32054 error frame), a closed
/// stream, a transport error, or a stream that never opened. Running out of time is NOT a refusal:
/// the old `session_served` read a 5s timeout as "not served", so under the same load that broke the
/// preconditions, a session that WAS about to be served — the exact defect these tests exist to
/// catch — would have read as refused and passed. The bound is the same hang guard, and expiry
/// fails the test.
async fn assert_refused(transport: Option<&mut SessionTransport>, what: &str) {
    let Some(transport) = transport else {
        return; // the stream never opened: refused at the connection
    };
    match timeout(SESSION_ANSWER_GUARD, transport.recv_value()).await {
        Ok(Ok(Some(v))) => assert!(
            v["result"]["serverInfo"]["name"] != "echo-stub",
            "{what}: the session was SERVED: {v}"
        ),
        Ok(Ok(None) | Err(_)) => {}
        Err(_) => panic!(
            "{what}: neither served nor refused within {SESSION_ANSWER_GUARD:?} — a hang is \
             not a refusal"
        ),
    }
}

/// Assert this session was SERVED, logging how long it took (#228).
///
/// On expiry it reports which stage it was stuck in, so the next failure is a diagnosis rather
/// than a rerun: whether the stream opened at all, whether the server had spawned a stub child
/// (spawned-but-silent vs never-spawned), and how long a DIRECT stub round trip takes right now
/// (a slow one means process spawn is the cost, not the daemon).
async fn assert_served(transport: Option<&mut SessionTransport>, what: &str) {
    let started = std::time::Instant::now();
    let Some(transport) = transport else {
        panic!("{what}: the session stream never opened (open_bi or the initialize write failed)");
    };
    match timeout(SESSION_ANSWER_GUARD, transport.recv_value()).await {
        Ok(Ok(Some(v))) if v["result"]["serverInfo"]["name"] == "echo-stub" => {
            eprintln!("#228 `{what}`: served in {:?}", started.elapsed());
        }
        Ok(Ok(Some(v))) => panic!(
            "{what}: answered but NOT served after {:?}: {v}",
            started.elapsed()
        ),
        Ok(Ok(None)) => panic!(
            "{what}: stream closed without a reply after {:?}",
            started.elapsed()
        ),
        Ok(Err(e)) => panic!("{what}: transport error after {:?}: {e}", started.elapsed()),
        Err(_) => panic!(
            "{what}: no initialize reply within {SESSION_ANSWER_GUARD:?} (stream opened, \
             initialize sent). Stub children of this process: {}. Direct stub round trip now: {}",
            stub_children(),
            direct_stub_round_trip()
        ),
    }
}

/// The `echo_mcp_stub` children of this test process, via `pgrep` — diagnostic only.
fn stub_children() -> String {
    match std::process::Command::new("pgrep")
        .args(["-P", &std::process::id().to_string(), "-f", "echo_mcp_stub"])
        .output()
    {
        Ok(out) if out.stdout.is_empty() => "none (the server never spawned one)".into(),
        Ok(out) => format!(
            "pids {}",
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(",")
        ),
        Err(e) => format!("unknown (pgrep failed: {e})"),
    }
}

/// Spawn the stub directly and time one `initialize` round trip, bounded — diagnostic only.
fn direct_stub_round_trip() -> String {
    use std::io::{BufRead, Write};
    let started = std::time::Instant::now();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = (|| -> std::io::Result<String> {
            let mut child = std::process::Command::new(STUB)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let spawned = started.elapsed();
            let mut stdin = child.stdin.take().expect("piped");
            writeln!(stdin, "{}", initialize_frame("echo"))?;
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().expect("piped")).read_line(&mut line)?;
            drop(stdin);
            let _ = child.wait();
            Ok(format!(
                "spawn {spawned:?}, reply after {:?}",
                started.elapsed()
            ))
        })();
        let _ = tx.send(outcome);
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(timing)) => timing,
        Ok(Err(e)) => format!("failed: {e}"),
        Err(_) => "no reply within 10s".into(),
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
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut before = open_session(&conn, "later").await;
        assert_refused(
            before.as_mut(),
            "`later` admits nobody yet, so this session must be refused (setup)",
        )
        .await;

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
        assert_served(
            after.as_mut(),
            "a grant must be visible to the NEXT session on an ALREADY-OPEN connection",
        )
        .await;
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
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut first = open_session(&conn, "echo").await;
        assert_served(
            first.as_mut(),
            "the granted peer must be served BEFORE the revoke (setup)",
        )
        .await;

        revoke_service_allow(&mesh, "echo".into(), alice.principal.clone())
            .await
            .expect("revoke succeeds");

        // SAME connection, NEW bi-stream. The connection may also have been severed — either way
        // this session must NOT be served.
        let mut second = open_session(&conn, "echo").await;
        assert_refused(
            second.as_mut(),
            "a revoked peer must not open a NEW session on its already-open connection",
        )
        .await;
    })
    .await
    .expect("new-session-after-revoke test timed out");
}

/// THE in-flight proof. Alice holds a live session; the revoke must CLOSE her connection, not
/// merely refuse her next session.
#[tokio::test]
async fn revoke_severs_the_live_connection() {
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut session = open_session(&conn, "echo").await;
        assert_served(session.as_mut(), "served before revoke").await;

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
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice", "bob"]).await;
        let (alice, bob) = (&peers[0], &peers[1]);

        let alice_conn = dial(&alice.endpoint, addr.clone()).await;
        let mut alice_session = open_session(&alice_conn, "echo").await;
        assert_served(alice_session.as_mut(), "alice served").await;

        let bob_conn = dial(&bob.endpoint, addr).await;
        let mut bob_session = open_session(&bob_conn, "echo").await;
        assert_served(bob_session.as_mut(), "bob served").await;

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
        assert_served(
            bob_second.as_mut(),
            "revoking alice must not affect bob's new sessions",
        )
        .await;
    })
    .await
    .expect("unrelated-peer regression timed out");
}

/// `peer_remove`'s authorization half severs the removed peer's live connection too — the same
/// guarantee as `service_allow_revoke`, via the shared resolve→sever helper.
#[tokio::test]
async fn removing_a_peer_severs_its_live_connection() {
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice", "bob"]).await;
        let (alice, bob) = (&peers[0], &peers[1]);

        let alice_conn = dial(&alice.endpoint, addr.clone()).await;
        let mut alice_session = open_session(&alice_conn, "echo").await;
        assert_served(alice_session.as_mut(), "alice served").await;

        let bob_conn = dial(&bob.endpoint, addr).await;
        let mut bob_session = open_session(&bob_conn, "echo").await;
        assert_served(bob_session.as_mut(), "bob served").await;

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

/// #99: SWAP-BEFORE-SEVER on the UNPAIR path (`revoke_service_access`), which reaches the sever
/// through the config rebuild rather than #94's targeted swap.
///
/// Same invariant, different branch: the new registry must be installed before any connection is
/// cut, so a peer racing a redial across the sever meets the post-revoke registry. The observer
/// fires at the top of the sever with the live registry as of that instant.
#[tokio::test]
async fn the_unpair_path_swaps_the_registry_before_it_severs() {
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];

        let conn = dial(&alice.endpoint, addr).await;
        let mut session = open_session(&conn, "echo").await;
        assert_served(session.as_mut(), "served before revoke").await;

        // Record EVERY sever, not just the last: a reversal that severs twice would otherwise
        // hide the stale first observation behind a fresh second one.
        let seen: Arc<std::sync::Mutex<Vec<Vec<String>>>> = Arc::new(std::sync::Mutex::new(vec![]));
        let sink = seen.clone();
        mesh.set_sever_observer(move |live| {
            sink.lock().expect("observer sink not poisoned").push(
                live.get("echo")
                    .map(|e| e.allow.clone())
                    .unwrap_or_default(),
            );
        });

        revoke_service_access(&mesh, "alice")
            .await
            .expect("unpair revoke succeeds");

        let observed = seen.lock().expect("observer sink not poisoned").clone();
        assert!(
            !observed.is_empty(),
            "the unpair must have severed, firing the observer"
        );
        for at_sever in &observed {
            assert!(
                !at_sever.contains(&alice.principal),
                "the rebuilt registry must be installed BEFORE every sever — at one sever `echo` \
                 still admitted {at_sever:?}, so the peer that sever cut could have redialled \
                 straight back in (all observations: {observed:?})"
            );
        }
    })
    .await
    .expect("unpair swap-before-sever test timed out");
}

/// #85 ask 4: `peer_revoke` severs the live connection AND refuses the next dial.
///
/// The severance half is #54's contract, and it matters more here than for a service revoke: the
/// endpoint being cut is one somebody has physically taken. A revocation that waited for the peer
/// to disconnect would be unbounded — MCP sessions are long-lived by design, so "eventually" can
/// mean days on the machine you are trying to lock out.
///
/// The refusal half is what distinguishes revocation from `peer_remove`: the pair row is still
/// there, untouched, and the peer is still refused. Without that assertion this test would pass on
/// an implementation that simply deleted the row.
#[tokio::test]
async fn peer_revoke_severs_the_live_connection_and_refuses_the_next_dial() {
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, dir) = paired_mesh(&["alice"]).await;
        let alice = &peers[0];
        let state = mcpmesh::control::DaemonState::with_mesh("test", mesh.clone());

        let conn = dial(&alice.endpoint, addr.clone()).await;
        let mut session = open_session(&conn, "echo").await;
        assert_served(
            session.as_mut(),
            "precondition: served before the revoke — otherwise the sever below proves nothing",
        )
        .await;

        let out = mcpmesh::daemon::peer_revoke(
            &state,
            mcpmesh_local_api::PeerRevokeParams {
                peer: alice.principal.clone(),
                reason: Some("laptop stolen".into()),
            },
        )
        .await
        .expect("revoke succeeds");
        assert_eq!(out.revoked, vec![alice.principal.clone()]);
        assert_eq!(
            out.severed, 1,
            "the result must REPORT the severance, not merely perform it — an embedder showing a \
             user 'device cut off' needs the count"
        );

        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("a revoke must SEVER the live connection, not leave it running");

        // The peer is STILL refused on a fresh connection, even though its pair row is intact.
        // (That the row survived is not asserted directly — the store is not exposed here — but
        // the unrevoke below restores service, which is only possible if the row was never
        // deleted. That is the stronger statement anyway: it is about behaviour, not storage.)
        let redial = dial(&alice.endpoint, addr.clone()).await;
        let mut refused = open_session(&redial, "echo").await;
        assert_refused(
            refused.as_mut(),
            "a revoked peer must be refused on a FRESH connection too, even though its pair row is \
             intact",
        )
        .await;

        // …and lifting it restores service, which is the whole reason the row survived.
        mcpmesh::daemon::peer_unrevoke(
            &state,
            mcpmesh_local_api::PeerUnrevokeParams {
                peer: alice.principal.clone(),
            },
        )
        .await
        .expect("unrevoke succeeds");
        let back = dial(&alice.endpoint, addr).await;
        let mut s = open_session(&back, "echo").await;
        assert_served(
            s.as_mut(),
            "unrevoking must restore the peer — the pair row was never touched",
        )
        .await;
        drop(dir);
    })
    .await
    .expect("peer revoke sever test timed out");
}

/// Revoking one person must not disturb anybody else. Over-severing is a self-inflicted outage, and
/// on this path it would cut a peer the operator never named while telling them it worked.
#[tokio::test]
async fn peer_revoke_does_not_sever_an_unrelated_peer() {
    timeout(Duration::from_secs(180), async {
        let (mesh, addr, _registry, peers, _dir) = paired_mesh(&["alice", "bob"]).await;
        let (alice, bob) = (&peers[0], &peers[1]);
        let state = mcpmesh::control::DaemonState::with_mesh("test", mesh.clone());

        let bob_conn = dial(&bob.endpoint, addr).await;
        let mut bob_session = open_session(&bob_conn, "echo").await;
        assert_served(bob_session.as_mut(), "bob served first").await;

        mcpmesh::daemon::peer_revoke(
            &state,
            mcpmesh_local_api::PeerRevokeParams {
                peer: alice.principal.clone(),
                reason: None,
            },
        )
        .await
        .expect("revoke alice");

        assert!(
            timeout(Duration::from_secs(2), bob_conn.closed())
                .await
                .is_err(),
            "bob's connection must survive alice's revocation"
        );
        // Round-trip on the ALREADY-OPEN session, exactly as `revoke_does_not_sever_an_unrelated_peer`
        // does: `assert_served` consumes the one `initialize` reply the stream carries, so checking
        // it twice would report a dead session whether or not the sever was over-broad — a test that
        // fails for its own reasons proves nothing about the code.
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
    })
    .await
    .expect("unrelated peer test timed out");
}
