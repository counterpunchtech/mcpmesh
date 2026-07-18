//! M2b Task 8 — the capstone: the §1.5 FOUR-COMMAND hero flow, end to end and hermetic, over a
//! REAL localhost mesh, driven through the REAL porcelain/control API where possible.
//!
//! This is the M2a `hero_flow` (which STOOD IN for pairing by populating the allowlist directly)
//! completed: here the trust is written by the REAL pairing ceremony — `invite` mints, `pair`
//! redeems over `mcpmesh/pair/1`, the inviter-side grant appends the redeemer to the service allow,
//! and only THEN can the redeemer use the service. The literal four commands are `serve` (Alice's
//! `[services.notes]`), `invite`, `pair`, and `connect` (`connect` is what `pair`'s printed
//! instructions tell the AI client to run).
//!
//! ── 5-clause decomposition (all in the ONE narrative `four_command_hero_flow`, per the plan's
//!    "strongest single flow" preference; each step is banner-marked) ──
//!   1. Alice registers `notes` (allow=[]) and mints an invite → capture the `invite_line`. The
//!      mint is driven by a raw `connect_control` client over `mcpmesh-local/1` (NON-porcelain).
//!   2. Bob redeems `pair <invite_line>` (raw `connect_control`, NON-porcelain) → asserts the
//!      mutual asymmetric trust on DISK (both PeerStores + Alice's `[services.notes].allow`) and
//!      that BOTH sides computed the SAME order-independent SAS.
//!   3. Bob USES it: the REAL `mcpmesh connect alice/notes` SUBPROCESS → initialize + tools/call →
//!      Alice's served echo child answers AND saw `MCPMESH_PEER_NAME=bob` (identity threaded through
//!      the freshly-paired trust, end to end across the mesh).
//!   4. Unpaired refused: a THIRD endpoint that never paired dials Alice's `notes` → refused
//!      pre-MCP by the real `AllowlistGate` (QUIC 401, no MCP frame).
//!   5. Non-porcelain over `mcpmesh-local/1`: clauses 1 & 2 ARE this (raw `connect_control` drives
//!      `Invite`/`Pair`); we additionally assert the `Hello` api + version at connect and drive a
//!      `Status`, so the AC's "a non-porcelain client drives invite/pair/status over
//!      mcpmesh-local/1 and receives the API version at connect" is nailed explicitly.
//!
//! ── The post-pair mesh-dial address resolution (DECLARED — this gates the closeout's honesty) ──
//! Clause 3 needs Bob's daemon to dial Alice BY ID (`connect alice/notes`): pairing wrote Alice's
//! `endpoint_id` into Bob's PeerStore, but NOT her addr (`PeerEntry` has no addr field). The dial
//! builds an id-only `EndpointAddr` and lets iroh discovery resolve it. In PRODUCTION the daemon's
//! `build_endpoint` uses `iroh::endpoint::presets::N0`, which (verified against iroh 1.0.1
//! `presets.rs`) wires `PkarrPublisher::n0_dns()` + `DnsAddressLookup::n0_dns()` + n0 relays — so
//! a paired peer's later mesh dial resolves EndpointId → EndpointAddr via discovery. This test runs
//! relay-disabled (`presets::Minimal`, no discovery), so it seeds Bob's endpoint with Alice's
//! `EndpointAddr` via a `MemoryLookup` on `address_lookup()` — the SAME id-only `dial_service` path
//! production runs, unchanged; `MemoryLookup` is the localhost stand-in for discovery, NOT a
//! production dependency. (The invite ALSO carries Alice's addr, used for the PAIR dial, which
//! needs no discovery; persisting that addr into the dial-back `PeerEntry` so the FIRST post-pair
//! mesh dial also needs no discovery is a noted robustness follow-up — see the plan.)
// Unix-only: hand-binds the control endpoint in-process (`bind_control_socket`) at a
// filesystem socket path, which a windows named pipe cannot be. Windows coverage for the
// control path lives at the transport layer (local-api transport::windows pipe tests) and
// the client protocol layer (local-api client.rs seam tests); a windows daemon-subprocess
// round-trip is deferred — see the plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::Request;
use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{self, MeshState, build_services, spawn_accept_loop};
use mcpmesh::pairing::sas::short_auth_code;
use mcpmesh::pairing::{Invite, LiveInvites};
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_local_api::{InviteResult, PairResult, StatusResult};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{TrustGate, connect};
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

/// The hermetic echo MCP stub (echoes `tools/call` payloads + `getenv("MCPMESH_PEER_NAME")`).
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");
/// The real `mcpmesh` binary — clause 3 drives the actual `mcpmesh connect` proxy subprocess.
const MCPMESH: &str = env!("CARGO_BIN_EXE_mcpmesh");
const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A localhost-only endpoint advertising BOTH the mesh + pair ALPNs (mirrors the daemon's
/// `build_endpoint` list on the `relay_mode = "disabled"` path so the accept loop routes as
/// production does). Relay disabled → hermetic, no network egress.
async fn dual_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            mcpmesh_net::ALPN_MCP.to_vec(),
            mcpmesh_net::ALPN_PAIR.to_vec(),
        ])
        .bind()
        .await
        .expect("bind dual-ALPN endpoint")
}

/// A localhost-only mesh-side endpoint. It never *accepts* pair/mesh connections here (Bob dials;
/// the stranger dials), and the ALPN it *dials* is chosen per-connect, so advertising only the
/// mesh ALPN is fine.
async fn mesh_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind mesh endpoint")
}

#[tokio::test(flavor = "multi_thread")]
async fn four_command_hero_flow() {
    timeout(Duration::from_secs(90), async {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        // ══════════════════════════════════════════════════════════════════════════════════
        // COMMAND 1 — `serve`: ALICE is a REAL serving daemon (own ALPN-dispatch accept loop +
        // control API). `[services.notes] run=echo_stub, allow=[]` (local-only until a pairing
        // grant), gated by the REAL AllowlistGate over a real PeerStore. self_petname "alice".
        // ══════════════════════════════════════════════════════════════════════════════════
        let alice_ep = dual_alpn_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();
        let alice_addr = alice_ep.addr();

        let alice_config = alice_dir.path().join("config.toml");
        std::fs::write(
            &alice_config,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();
        let alice_store = Arc::new(PeerStore::open(&alice_dir.path().join("state.redb")).unwrap());
        let alice_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(alice_store.clone()));
        let alice_cfg = Config::load(&alice_config).unwrap();
        let alice_mesh = MeshState::new(
            alice_ep,
            alice_gate,
            alice_store.clone(),
            Arc::new(LiveInvites::new()),
            "alice".into(),
            alice_config.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let alice_task = spawn_accept_loop(alice_mesh.clone(), Arc::new(build_services(&alice_cfg)));
        alice_mesh.set_accept_task(alice_task).await;

        // Alice's control socket (driven only in-process, so any path works).
        let alice_socket = alice_dir.path().join("control.sock");
        let alice_listener = mcpmesh::ipc::bind_control_socket(&alice_socket).await.unwrap();
        let alice_state = Arc::new(DaemonState::with_mesh(
            daemon::STACK_VERSION,
            alice_mesh,
            Vec::new(),
            Vec::new(),
        ));
        let alice_control = tokio::spawn(serve_control(alice_listener, alice_state));

        // ── BOB: a REAL daemon (control API) that DIALS. No accept loop — Bob only redeems and
        // connects outbound. self_petname "bob" (becomes Alice's local name for Bob). Bob's
        // endpoint is seeded with Alice's addr so the post-pair id-only mesh dial resolves on
        // localhost (the DECLARED discovery stand-in; see the module header). Bob's control socket
        // is bound where a subprocess with XDG_RUNTIME_DIR=<bob_dir> resolves it. ──
        let bob_ep = mesh_endpoint().await;
        let bob_id = *bob_ep.id().as_bytes();
        let mem = MemoryLookup::new();
        mem.add_endpoint_info(alice_addr.clone());
        bob_ep
            .address_lookup()
            .expect("address lookup services")
            .add(mem);

        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let bob_gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(bob_store.clone()));
        let bob_mesh = MeshState::new(
            bob_ep,
            bob_gate,
            bob_store.clone(),
            Arc::new(LiveInvites::new()),
            "bob".into(),
            bob_dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let bob_socket = bob_dir.path().join("mcpmesh").join("mcpmesh.sock");
        let bob_listener = mcpmesh::ipc::bind_control_socket(&bob_socket).await.unwrap();
        let bob_state = Arc::new(DaemonState::with_mesh(
            daemon::STACK_VERSION,
            bob_mesh,
            Vec::new(),
            Vec::new(),
        ));
        let bob_control = tokio::spawn(serve_control(bob_listener, bob_state));

        // ══════════════════════════════════════════════════════════════════════════════════
        // COMMAND 2 — `invite` (clause 1 + the non-porcelain half of clause 5): a raw
        // `connect_control` client (NOT the porcelain) drives `Request::Invite{[notes]}` over
        // mcpmesh-local/1 and gets a typed `InviteResult` carrying the copyable `mcpmesh-invite:` line.
        // We assert the Hello api + version delivered at connect (clause 5's "receives the API
        // version at connect").
        // ══════════════════════════════════════════════════════════════════════════════════
        let mut alice_client = connect_control(&alice_socket)
            .await
            .expect("raw connect_control to Alice");
        assert_eq!(
            alice_client.hello().api,
            "mcpmesh-local/1",
            "the non-porcelain client is told the api at connect"
        );
        assert!(
            !alice_client.hello().api_version.is_empty(),
            "a non-empty api version is delivered at connect: {:?}",
            alice_client.hello()
        );
        // A Status over the same non-porcelain client (the AC lists invite/pair/STATUS).
        let status = alice_client
            .request(Request::Status)
            .await
            .expect("status over mcpmesh-local/1");
        assert_eq!(status["stack_version"], daemon::STACK_VERSION);

        let invite_value = alice_client
            .request(Request::Invite {
                services: vec!["notes".into()],
            })
            .await
            .expect("invite over mcpmesh-local/1");
        let invite: InviteResult =
            serde_json::from_value(invite_value).expect("typed InviteResult decodes");
        assert!(
            invite.invite_line.starts_with("mcpmesh-invite:"),
            "the invite line is the §1.5 surface-#2 copyable artifact: {}",
            invite.invite_line
        );

        // ══════════════════════════════════════════════════════════════════════════════════
        // COMMAND 3 — `pair` (clause 2 + the pair half of clause 5): a raw `connect_control` client
        // on BOB drives `Request::Pair{invite_line}` over mcpmesh-local/1. Bob's daemon dials Alice
        // on pair/1 at the invite's embedded addr (no discovery), proves the secret, and both sides
        // write the mutual asymmetric trust. We assert the typed PairResult, the SAME
        // order-independent SAS, and the FUNCTIONAL truth on DISK (stores + config — NOT `status`).
        // ══════════════════════════════════════════════════════════════════════════════════
        let mut bob_client = connect_control(&bob_socket)
            .await
            .expect("raw connect_control to Bob");
        assert_eq!(bob_client.hello().api, "mcpmesh-local/1");
        let pair_value = bob_client
            .request(Request::Pair {
                invite_line: invite.invite_line.clone(),
            })
            .await
            .expect("pair over mcpmesh-local/1");
        let paired: PairResult =
            serde_json::from_value(pair_value).expect("typed PairResult decodes");
        assert_eq!(paired.peer_petname, "alice", "Bob's local name for the inviter");
        assert_eq!(
            paired.services,
            vec!["notes".to_string()],
            "the pairing granted Bob `notes` (mountable as alice/notes)"
        );

        // BOTH sides computed the SAME SAS. We decode the invite (its fields are pub) to recover
        // the secret + inviter_id, then compute the code Alice computes — `short_auth_code(inviter,
        // redeemer, secret)` — and its order-swap. Bob's `PairResult.sas_code` equals BOTH, so
        // Bob's code equals Alice's (order-independent): both humans read the same words.
        let decoded = Invite::decode(&invite.invite_line).unwrap();
        assert_eq!(decoded.inviter_id, alice_id, "the invite names Alice's id");
        let alice_sas = short_auth_code(&decoded.inviter_id, &bob_id, &decoded.secret);
        assert_eq!(
            paired.sas_code, alice_sas,
            "Bob's SAS equals the code Alice computes"
        );
        assert_eq!(
            short_auth_code(&bob_id, &decoded.inviter_id, &decoded.secret),
            alice_sas,
            "the SAS is endpoint-order-independent (both sides read the same words)"
        );

        // ── The INVITER's ceremony surface (§4.2 "both humans compare the code"): Alice's
        // `status` now carries the completed pairing under `recent_pairings`, petname'd "bob",
        // with the SAME sas_code Bob's PairResult reported — so Alice's human can read the code
        // without grepping daemon logs. Display-only + in-memory (a restart clears it). ──
        let status_after = alice_client
            .request(Request::Status)
            .await
            .expect("status over mcpmesh-local/1 after pairing");
        let status_after: StatusResult =
            serde_json::from_value(status_after).expect("typed StatusResult decodes");
        let recent = status_after
            .recent_pairings
            .first()
            .expect("the inviter's status must surface the completed pairing");
        assert_eq!(recent.peer_petname, "bob", "the pairing is listed under Bob's petname");
        assert_eq!(
            recent.sas_code, paired.sas_code,
            "the inviter's status shows the SAME code the redeemer's pair printed"
        );

        // ── Mutual asymmetric trust on DISK (§4.2). Bob's alice-entry: services=[notes] (what Bob
        // may dial), paired_at set. Alice's bob-entry: services=[] (dial-back identity only),
        // paired_at set. ──
        let bob_side = bob_store
            .resolve(&alice_id)
            .unwrap()
            .expect("Bob's store has an alice entry");
        assert_eq!(bob_side.petname, "alice");
        assert_eq!(bob_side.services, vec!["notes".to_string()]);
        assert!(bob_side.paired_at.is_some());
        let alice_side = alice_store
            .resolve(&bob_id)
            .unwrap()
            .expect("Alice's store has a bob dial-back entry");
        assert_eq!(alice_side.petname, "bob");
        assert!(
            alice_side.services.is_empty(),
            "Alice's dial-back entry carries no service grants (§4.2): {:?}",
            alice_side.services
        );
        assert!(alice_side.paired_at.is_some());

        // ── The load-bearing authorization grant on DISK: `[services.notes].allow` now lists bob
        // (functional truth, NOT `status`). Without this the paired peer is known-but-forbidden. ──
        let after = Config::load(&alice_config).unwrap();
        assert_eq!(
            after.services.get("notes").unwrap().allow,
            vec!["bob".to_string()],
            "the pairing grant appended bob to [services.notes].allow"
        );

        // Bob's raw client has done its job; drop it (independent from the subprocess connection).
        drop(bob_client);

        // ══════════════════════════════════════════════════════════════════════════════════
        // COMMAND 4 — `connect` (clause 3, THE PAYOFF): the REAL `mcpmesh connect alice/notes`
        // subprocess drives its stdio against Bob's control socket. Bob's daemon resolves petname
        // `alice` → Alice's id (written by pairing), dials her `notes` by id (MemoryLookup resolves
        // it on localhost), Alice's gate resolves Bob → `bob`, `select_service` ADMITS `bob` (now in
        // allow, live after the grant's reload), the echo child answers, and MCPMESH_PEER_NAME=bob is
        // injected — identity threaded through the freshly-paired trust, end to end.
        // ══════════════════════════════════════════════════════════════════════════════════
        let mut child = Command::new(MCPMESH)
            .arg("connect")
            .arg("alice/notes")
            .env("XDG_RUNTIME_DIR", bob_dir.path())
            .env("XDG_CONFIG_HOME", bob_dir.path())
            .env("XDG_DATA_HOME", bob_dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn mcpmesh connect alice/notes");
        let mut child_in = child.stdin.take().unwrap();
        let mut child_out =
            FrameReader::new(BufReader::new(child.stdout.take().unwrap()), MAX_FRAME);

        // initialize → Alice's served child answers back through the proxy across the mesh.
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "ai", "version": "0"}}
            }),
        )
        .await
        .unwrap();
        let init = next_frame(&mut child_out).await;
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "the paired peer reached Alice's served notes child (not -32054'd): {init}"
        );

        // tools/call → payload echoed verbatim, and MCPMESH_PEER_NAME carried the gate-resolved
        // caller identity (`bob`, from the pairing) into the child across the mesh.
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "four-command hero flow"}}
            }),
        )
        .await
        .unwrap();
        let call = next_frame(&mut child_out).await;
        assert_eq!(
            call["result"]["content"][0]["text"], "four-command hero flow",
            "the echoed tools/call payload round-tripped byte-faithfully: {call}"
        );
        assert_eq!(
            call["result"]["peer_name"], "bob",
            "the served child saw the paired identity `bob` across the mesh: {call}"
        );

        // Closing stdin ends the proxy cleanly (spec §8) — no hang.
        child_in.shutdown().await.unwrap();
        drop(child_in);
        let exit = timeout(Duration::from_secs(10), child.wait())
            .await
            .expect("proxy did not exit after stdin close")
            .unwrap();
        assert!(exit.success(), "proxy exited non-zero: {exit}");

        // ══════════════════════════════════════════════════════════════════════════════════
        // CLAUSE 4 — an UNPAIRED machine is refused pre-MCP. A THIRD endpoint that never paired
        // dials Alice's `notes` directly. Alice's REAL AllowlistGate default-denies it: the
        // connection is closed with QUIC 401 BEFORE any bi-stream, so no MCP frame is exchanged.
        // ══════════════════════════════════════════════════════════════════════════════════
        let stranger_ep = mesh_endpoint().await;
        match connect(&stranger_ep, alice_addr.clone(), "notes").await {
            // Refused at connection establishment — no session, no MCP frame.
            Err(_) => {}
            // Or the connect races ahead of the gate close: the stranger may open a stream, but its
            // initialize draws no response — the gate severed the connection pre-MCP.
            Ok(mut transport) => {
                let _ = transport
                    .send_value(json!({
                        "jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"_meta": {"mcpmesh/service": "notes"}, "capabilities": {}}
                    }))
                    .await;
                let outcome = transport.recv_value().await;
                assert!(
                    matches!(outcome, Err(_) | Ok(None)),
                    "unpaired stranger got an MCP frame — the gate did not refuse pre-MCP: {outcome:?}"
                );
            }
        }

        alice_control.abort();
        bob_control.abort();
        drop(alice_dir);
        drop(bob_dir);
    })
    .await
    .expect("four-command hero-flow test timed out");
}

/// Read one JSON-RPC frame from a `FrameReader`, panicking on EOF/violation.
async fn next_frame<R: tokio::io::AsyncRead + Unpin>(reader: &mut FrameReader<R>) -> Value {
    match reader.next().await.unwrap() {
        Some(Inbound::Frame(v)) => v,
        other => panic!("expected a frame, got {other:?}"),
    }
}
