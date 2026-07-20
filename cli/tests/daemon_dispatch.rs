//! M2b Task 4 acceptance: the daemon's OWN accept loop ([`mcpmesh::daemon::spawn_accept_loop`])
//! dispatches each inbound connection by its negotiated ALPN (spec §7.1). This drives the SAME
//! loop `serve_forever` runs, against in-process localhost endpoints, and proves BOTH routes:
//!
//!  - `mcpmesh/mcp/1` (mesh) still flows through net's gated per-connection handler and completes
//!    a real session (behavior-preserving regression over the M2a serve path); and
//!  - `mcpmesh/pair/1` (pairing) reaches the GATE-EXEMPT (D8) rendezvous — a peer that is NOT in
//!    the allowlist is nonetheless accepted onto pair/1 and reaches the rendezvous, which
//!    refuses it by INVITE-SECRET (no matching invite) with a reply frame, NOT by the gate's
//!    QUIC-401 "unauthorized". That contrast is the whole point of dispatching by ALPN: the pair
//!    ALPN must bypass the AllowlistGate. (Since T5 the rendezvous is real — it reads a hello
//!    and replies — rather than the T4 stub's bare close.)
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{MeshState, build_services, spawn_accept_loop};
use mcpmesh::pairing::{Invite, LiveInvites};
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use serde_json::json;
use tokio::io::BufReader;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only endpoint advertising BOTH the mesh + pair ALPNs — this intentionally
/// mirrors `build_endpoint`'s advertised list (`vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()]`)
/// so this test can drive `spawn_accept_loop` in-process; the duplication is deliberate. Real
/// end-to-end drift against the daemon's actual `build_endpoint` is caught by the subprocess
/// tests in `daemon_serve.rs` (relay disabled → hermetic, no network egress).
async fn dual_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind dual-ALPN endpoint")
}

/// A localhost-only client endpoint. It advertises only the mesh ALPN (it never *accepts*
/// pair connections); the ALPN it *dials* is chosen per-connect, so it can still dial pair.
async fn client_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint")
}

/// The mesh ALPN still routes to a gated, working session under the daemon's own accept loop
/// (regression: the M2a serve path is preserved for `mcpmesh/mcp/1`).
#[tokio::test]
async fn accept_loop_routes_mesh_alpn_to_a_gated_session() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"tester\"]\n"
        ))
        .expect("parse config");

        // The dialing peer, trusted as `tester` for `echo`.
        let client = client_endpoint().await;
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: *client.id().as_bytes(),
                petname: "tester".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));

        // Run the daemon's OWN accept loop on a dual-ALPN endpoint. The pair branch never fires
        // here (mesh dial only), so `config_path`/petname are inert.
        let server = dual_alpn_endpoint().await;
        let addr = server.addr();
        let mesh = MeshState::new(
            server,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "server".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));

        // Dial mcp/1 and complete initialize → the mesh handler served the session.
        let mut transport = connect(&client, addr, "echo").await.unwrap();
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "_meta": {"mcpmesh/service": "echo"},
                    "capabilities": {}, "clientInfo": {"name": "tester", "version": "0"}
                }
            }))
            .await
            .unwrap();
        let init = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "mcp/1 must route to a gated mesh session under the daemon's accept loop: {init}"
        );
    })
    .await
    .expect("mesh-dispatch test timed out");
}

/// A far-future expiry for a decoy live invite (avoid a real clock in assertions).
const FUTURE: u64 = 4_000_000_000;

/// Build a decoy live invite so the live-invite accept-gate (`count() >= 1`) OPENS the pair
/// window — its `secret` deliberately differs from any hello the test then sends, so the dial
/// reaches the rendezvous and is refused THERE (by secret), never redeemed. `inviter_id`/addr are
/// irrelevant (the decoy is never redeemed).
fn decoy_invite(secret: [u8; 32]) -> Invite {
    Invite {
        secret,
        inviter_id: [0xEEu8; 32],
        inviter_addr_json: "{}".into(),
        petname: "server".into(),
        services: vec!["x".into()],
        expires_at_epoch: FUTURE,
    }
}

/// The pair ALPN routes to the gate-exempt rendezvous (D8): a peer that is NOT in the allowlist
/// is accepted onto pair/1 and reaches the rendezvous, which refuses it by INVITE-SECRET (a
/// non-matching secret) with a `{"result":"refused"}` reply FRAME — never gate-refused with a
/// QUIC-401 "unauthorized" close. Receiving a refusal frame at all is the proof: a gated ALPN
/// would tear the connection down before any frame. This is the observable contrast dispatching
/// by ALPN buys.
///
/// A live DECOY invite is minted first so the live-invite accept-gate (`count() == 0` → early
/// close; see [`accept_loop_pair_alpn_with_no_live_invite_is_closed_early`]) OPENS the window;
/// the dialer then sends a DIFFERENT secret, so it reaches the rendezvous and is refused by
/// secret — exactly the gate-exemption contrast this test asserts.
#[tokio::test]
async fn accept_loop_routes_pair_alpn_to_the_gate_exempt_rendezvous() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // An EMPTY store — the pair dialer is NOT allowlisted. If pair traffic were (wrongly)
        // gated, this peer would be QUIC-401'd before any stream; instead — with a live invite
        // opening the window — the rendezvous replies with a by-secret refusal frame.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));

        // A live DECOY invite (secret [1u8; 32]) opens the accept-gate; the hello below sends a
        // DIFFERENT secret ([0u8; 32]), so it reaches the rendezvous and is refused by secret.
        let invites = Arc::new(LiveInvites::new());
        invites.mint(decoy_invite([1u8; 32]));

        let server = dual_alpn_endpoint().await;
        let addr = server.addr();
        let mesh = MeshState::new(
            server,
            gate,
            store,
            invites,
            "server".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(
            mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Dial pair/1 (not mesh), open a bi-stream, and send a well-formed hello with an unknown
        // secret (redeemer_id == our real TLS id, so P3 passes and we reach the redeem step).
        let client = client_endpoint().await;
        let conn = client
            .connect(addr, ALPN_PAIR)
            .await
            .expect("pair/1 dial is accepted (gate-exempt)");
        let (mut send, recv) = conn.open_bi().await.expect("open bi-stream");
        let hello = json!({
            "secret": vec![0u8; 32],
            "redeemer_id": client.id().as_bytes().to_vec(),
            "redeemer_petname": "stranger",
        });
        write_frame(&mut send, &hello).await.expect("send hello");
        let _ = send.finish();

        let mut reader = FrameReader::new(BufReader::new(recv), 64 * 1024);
        let reply = match reader.next().await.expect("read reply frame") {
            Some(Inbound::Frame(v)) => v,
            other => panic!("pair/1 must reply with a refusal frame, got: {other:?}"),
        };
        assert_eq!(
            reply["result"], "refused",
            "pair/1 must reach the gate-exempt rendezvous and refuse by invite, got: {reply}"
        );
        assert_eq!(
            reply["reason"], "pairing refused",
            "an unknown secret gets the generic refusal reason, got: {reply}"
        );
    })
    .await
    .expect("pair-dispatch test timed out");
}

/// The live-invite ACCEPT-GATE (spec §7.1/§4.2/D8 windowed listener): with ZERO outstanding
/// invites, a pair dial is closed IMMEDIATELY — the accept loop's `ALPN_PAIR` branch sees
/// `mesh.invites.count() == 0` and closes the connection ("no pairing in progress") WITHOUT
/// spawning the rendezvous handler, so no bi-stream is served, no hello is read, and no
/// `PeerEntry` is ever written. The pair ALPN stays permanently advertised (iroh can't cheaply
/// toggle a live endpoint's ALPN); this gate realizes the "open only while an invite is live"
/// semantics. Contrast with [`accept_loop_routes_pair_alpn_to_the_gate_exempt_rendezvous`], where
/// a live invite opens the window and the dial reaches the rendezvous.
#[tokio::test]
async fn accept_loop_pair_alpn_with_no_live_invite_is_closed_early() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        // ZERO live invites — the accept-gate must close the pair dial before any handler runs.
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));

        let server = dual_alpn_endpoint().await;
        let addr = server.addr();
        let mesh = MeshState::new(
            server,
            gate,
            store.clone(),
            Arc::new(LiveInvites::new()), // empty: count() == 0
            "server".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(
            mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Dial pair/1 and try to drive the rendezvous. The server closes the connection with no
        // handler, so we get NO reply frame — whether the close preempts the dial, the bi-stream
        // open, or the read. Any of those "no valid rendezvous reply" outcomes proves the early
        // close (the rendezvous ALWAYS replies with at least a refusal frame when it is reached).
        let client = client_endpoint().await;
        let client_id = *client.id().as_bytes();
        let got_reply: Option<serde_json::Value> = match client.connect(addr, ALPN_PAIR).await {
            Err(_) => None, // closed at/near handshake
            Ok(conn) => match conn.open_bi().await {
                Err(_) => None, // stream refused — server already closed
                Ok((mut send, recv)) => {
                    let hello = json!({
                        "secret": vec![0u8; 32],
                        "redeemer_id": client_id.to_vec(),
                        "redeemer_petname": "stranger",
                    });
                    let _ = write_frame(&mut send, &hello).await;
                    let _ = send.finish();
                    let mut reader = FrameReader::new(BufReader::new(recv), 64 * 1024);
                    match reader.next().await {
                        Ok(Some(Inbound::Frame(v))) => Some(v),
                        _ => None, // EOF / violation / IO error — the early close
                    }
                }
            },
        };
        assert!(
            got_reply.is_none(),
            "a pair dial with no live invite must be closed early (no rendezvous reply), got: {got_reply:?}"
        );

        // The handler never ran, so no PeerEntry was written for the dialer.
        assert!(
            store.resolve(&client_id).unwrap().is_none(),
            "the accept-gate must not let any PeerEntry be written when no invite is live"
        );
    })
    .await
    .expect("no-live-invite accept-gate test timed out");
}

/// A pairing grant emits exactly one `trust(event="pair")` audit record for the redeemer petname
/// (spec §11.3 trust-event class — pair). Builds a hermetic serving `MeshState`, installs a real
/// temp-dir `AuditLog` via `set_audit`, and drives `grant_service_access`; the hook fires on
/// `mesh.audit()` and lands one pair record targeted at the petname. No secret material is written.
#[tokio::test]
async fn trust_mutations_emit_audit_events() {
    use mcpmesh::audit::{AuditLog, AuditSink};
    use mcpmesh::daemon::grant_service_access;
    timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        // A config with a `notes` service so the grant is a real allow-append (changed=true).
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();

        let server = dual_alpn_endpoint().await;
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let mesh = MeshState::new(
            server,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "server".into(),
            config_path,
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let audit_dir = dir.path().join("audit");
        mesh.set_audit(AuditSink::new(AuditLog::spawn(audit_dir.clone())));

        // A pairing grant → one trust(event="pair") record targeted at "bob".
        grant_service_access(&mesh, "bob", &["notes".to_string()])
            .await
            .unwrap();

        let month = &mcpmesh::audit::now_ts()[..7];
        let file = audit_dir.join(format!("{month}.jsonl"));
        let mut pair = 0;
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file) {
                pair = b.matches("\"event\":\"pair\"").count();
                if pair >= 1 {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(pair, 1, "the pairing grant recorded one trust(pair) event");
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(body.contains("\"kind\":\"trust\""));
        assert!(body.contains("\"target\":\"bob\""));
    })
    .await
    .expect("trust audit test timed out");
}
