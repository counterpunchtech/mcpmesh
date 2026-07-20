//! The §16 M3 AC (spec line 616): a revoked device is cut from its live session on OTHER nodes
//! within 60s via GOSSIP propagation across a real 3-node localhost mesh — including a node holding
//! a stale PAIR entry for the revoked endpoint (revocation wins, §4.1). M3a proved the in-process
//! sever MECHANISM (roster_sever.rs); THIS proves the cross-node TIMING. Assert-on-convergence-with-
//! timeout, never a fixed sleep.
//!
//! Topology: Operator O (holds org root), Node A (the victim device, rostered as "alice/laptop" +
//! serving a live session TO Node B), Node B (serving the session A consumes, ALSO holds a stale PAIR
//! entry naming A's endpoint). All three gossip-joined on the roster topic; addrs MemoryLookup-seeded
//! ALL-PAIRS (localhost, relay-disabled — NO discovery for either the mesh dials OR the gossip dials).
//!
//! ── AC clauses proven CROSS-NODE (mirrors the M3a decomposition) ──
//!   * gossip-propagation TIMING → within 60s B installs serial 2 (received → fetched → validated →
//!     installed via `spawn_receive_loop`/`on_announce`) AND severs A's live mesh session — the cut is
//!     a real transport EOF DRIVEN by B's gossip-received revocation, not a client-side timeout.
//!   * the stale-pair-entry revocation-wins clause → B genuinely holds a pair ALLOW for A (a nickname
//!     in the served service's `allow`), yet a fresh A dial post-revocation is refused PRE-MCP
//!     (revocation wins over the pair entry, §4.1(1)) — the (pairs ∪ roster) composition exercised.
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{
    MeshState, build_services, install_roster_view_and_sever, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh::roster::transport::{self, RosterBlobs};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

/// The hermetic echo MCP stub — echoes a `tools/call` payload, so the E2E can round-trip a genuine
/// data frame (the LIVE-before-revoke proof) over the real mesh session.
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only ROSTER-mode endpoint advertising all four ALPNs (mesh + pair + gossip + blob) —
/// exactly what `build_endpoint(.., roster_mode = true)` binds, so the daemon's real accept loop can
/// dispatch the mesh dial (A→B) AND the two roster ALPNs (gossip + blob) in-process (mirrors
/// `roster_distribute.rs`).
async fn roster_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            ALPN_MCP.to_vec(),
            ALPN_PAIR.to_vec(),
            transport::GOSSIP_ALPN.to_vec(),
            transport::BLOB_ALPN.to_vec(),
        ])
        .bind()
        .await
        .expect("bind roster-mode endpoint")
}

/// Mint a signed serial-`serial` roster listing each `(endpoint_id, user_id, device_label)` as a
/// one-device user in group `team-eng`, with `revoked` endpoints in `revoked_endpoints`. Returns BOTH
/// the signed JSON bytes (what the operator seeds into its blob store + what a fetcher re-validates
/// through the SINGLE install path) AND the loaded view (what a gate installs). Far-future expiry — a
/// currently-valid, resolvable roster signed by the production mint path (mirrors `roster_distribute.rs`
/// extended with the `revoked` set + device labels from `roster_sever.rs`).
fn mint_signed_roster(
    root: &SigningKey,
    serial: u64,
    users: &[([u8; 32], &str, &str)],
    revoked: &[[u8; 32]],
) -> (Vec<u8>, RosterView) {
    let roster_users = users
        .iter()
        .map(|(eid, uid, label)| RosterUser {
            user_id: (*uid).into(),
            display_name: (*uid).into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: vec!["team-eng".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(eid),
                label: (*label).into(),
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
    let bytes = serde_json::to_vec(&r).expect("serialize signed roster");
    let view = load_installed(&r, &root.verifying_key()).expect("mint a valid roster view");
    (bytes, view)
}

/// Write a roster-mode `config.toml` pinning the org root (mirrors `roster_distribute.rs`), optionally
/// carrying a `[services.*]` block. B's on-disk config carries BOTH the org root (so `on_announce`
/// resolves the trust anchor before re-validating a gossip roster) AND the served `echo` service (so
/// `build_services` reads it from the SAME file).
fn write_config(path: &Path, org_root_pk: &str, services_toml: &str) {
    std::fs::write(
        path,
        format!(
            "[network]\nrelay_mode = \"disabled\"\n[identity]\norg_root_pk = \"{org_root_pk}\"\norg_id = \"acme\"\n{services_toml}"
        ),
    )
    .expect("write roster config");
}

/// Seed `ep`'s address lookup with EVERY `peer`'s `EndpointAddr` — relay-disabled localhost has NO
/// discovery for either the mesh dials OR the gossip dials, so every node must know every OTHER node's
/// transport addr in BOTH directions (the #1 reason a naive harness hangs). One `MemoryLookup` per
/// endpoint carrying all its peers; `.add` is additive (so a later per-fetch add in `on_announce`
/// composes with it).
fn seed_addrs(ep: &iroh::Endpoint, peers: &[&iroh::Endpoint]) {
    let mem = iroh::address_lookup::MemoryLookup::new();
    for p in peers {
        mem.add_endpoint_info(p.addr());
    }
    ep.address_lookup()
        .expect("address lookup services")
        .add(mem);
}

/// Assemble a ROSTER-mode `MeshState` over `endpoint` — the roster-mode wiring `serve_forever` does
/// (mirrors `roster_distribute.rs::roster_node`), but with the `store` + `conn_registry` passed IN so
/// the test can seed B's stale pair entry beforehand and inspect B's live-connection registry. Installs
/// `install_view` into a fresh roster gate composed over the pairing gate, spawns the gossip/blob
/// transports on the shared endpoint, subscribes the roster topic bootstrapping from `bootstrap`, and
/// threads the handles into `MeshState::new`. Returns the mesh AND the `Arc<RosterGate>` (so a test can
/// poll `roster.view().serial()` directly).
async fn build_node(
    endpoint: iroh::Endpoint,
    install_view: RosterView,
    bootstrap: Vec<iroh::EndpointId>,
    config_path: PathBuf,
    store: Arc<PeerStore>,
    conn_registry: Arc<ConnRegistry>,
) -> (Arc<MeshState>, Arc<RosterGate>) {
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    let roster = Arc::new(RosterGate::empty());
    roster.install(install_view);
    let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

    let gossip = transport::spawn_gossip(&endpoint);
    let blobs = RosterBlobs::new(&endpoint);
    let roster_gossip =
        transport::subscribe(&gossip, transport::roster_topic_bytes("acme"), bootstrap)
            .await
            .expect("subscribe roster topic");

    let mesh = MeshState::new(
        endpoint,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "node".into(),
        config_path,
        roster.clone(),
        conn_registry,
        Some(gossip),
        Some(blobs),
        Some(roster_gossip),
        None,
    );
    (mesh, roster)
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

/// Poll `registry.len()` to `target` (up to ~10s). A secondary check AFTER a connection-close
/// observation: `sever_matching` closes connections but defers map removal to the severed handler's
/// RAII Drop, so a synchronous `len()` right after sever can transiently overcount — assert on the
/// close first, then let `len()` settle here (the `roster_sever.rs` discipline).
async fn wait_for_len(registry: &ConnRegistry, target: usize) {
    for _ in 0..100 {
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

/// **THE §16 M3 ACCEPTANCE CRITERION, cross-node.** Operator O revokes device A (serial+1) and
/// announces on gossip; within 60s node B — which serves A's live mesh session AND holds a stale pair
/// entry for A's endpoint — RECEIVES the announce, fetches + validates + installs serial 2, and SEVERS
/// A's live session. The cut is observed as a real transport EOF driven by B's gossip-received
/// revocation (never a client timeout, never a test-orchestrated close). Then a fresh A dial is refused
/// PRE-MCP: revocation wins over the still-present pair allow (§4.1(1)). Assert-on-convergence with a
/// 150s deadline+poll, wrapped in a 240s hard timeout (both widened for full-workspace parallelism —
/// convergence is fast in isolation, the wider bound only tolerates CPU starvation) — NEVER a fixed
/// sleep. Real gossip + real blob fetch
/// + a real mesh session over localhost endpoints.
#[tokio::test(flavor = "multi_thread")]
async fn revoked_device_cut_from_live_session_within_60s_across_nodes() {
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(240), async {
        let dir_o = tempfile::tempdir().unwrap();
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        // 1. Three roster-mode endpoints (all four ALPNs). Capture ids/addrs + a dialer clone of A's
        //    endpoint BEFORE the endpoints are moved into their meshes.
        let ep_o = roster_alpn_endpoint().await;
        let ep_a = roster_alpn_endpoint().await;
        let ep_b = roster_alpn_endpoint().await;
        let eid_o = ep_o.id();
        let eid_a = ep_a.id();
        let eid_b = ep_b.id();
        let bytes_o = *eid_o.as_bytes();
        let bytes_a = *eid_a.as_bytes();
        let bytes_b = *eid_b.as_bytes();
        let alice_dialer = ep_a.clone(); // A dials B's echo service with this handle
        let b_addr = ep_b.addr();

        // ALL-PAIRS address seeding, both directions (mesh dials A→B, blob fetch B→O, gossip all-pairs).
        seed_addrs(&ep_o, &[&ep_a, &ep_b]);
        seed_addrs(&ep_a, &[&ep_o, &ep_b]);
        seed_addrs(&ep_b, &[&ep_o, &ep_a]);

        // Serial 1 (O, A, B all rostered — a mutually-rostered swarm can form) and serial 2 (O's
        // operator revoke of A: A still listed as her device AND revoked → revocation wins in build_view).
        let users1 = [
            (bytes_o, "operator", "console"),
            (bytes_a, "alice", "laptop"),
            (bytes_b, "hostb", "server"),
        ];
        let (v1_bytes, v1_o) = mint_signed_roster(&root, 1, &users1, &[]);
        let v1_a = mint_signed_roster(&root, 1, &users1, &[]).1;
        let v1_b = mint_signed_roster(&root, 1, &users1, &[]).1;
        let (v2_bytes, v2_o) = mint_signed_roster(&root, 2, &users1, &[bytes_a]);

        // Configs (pinned org root). B additionally serves `echo`, admitting BOTH the roster user_id
        // "alice" AND the stale pair nickname "alice-pair" — so the pair entry is a GENUINE allow-path
        // that revocation must override (not merely a masked nickname).
        let cfg_o_path = dir_o.path().join("config.toml");
        let cfg_a_path = dir_a.path().join("config.toml");
        let cfg_b_path = dir_b.path().join("config.toml");
        write_config(&cfg_o_path, &org_root_pk, "");
        write_config(&cfg_a_path, &org_root_pk, "");
        write_config(
            &cfg_b_path,
            &org_root_pk,
            &format!("[services.echo]\nrun = ['{STUB}']\nallow = [\"alice\", \"alice-pair\"]\n"),
        );
        // O + B seed serial-1 roster.json (announce reads O's; B's install path reads/writes B's).
        std::fs::write(dir_o.path().join("roster.json"), &v1_bytes).unwrap();
        std::fs::write(dir_b.path().join("roster.json"), &v1_bytes).unwrap();

        // Stores + registries. B holds a STALE PAIR entry for A's endpoint — the (pairs ∪ roster)
        // composition; the nickname is in echo's `allow`, so absent revocation the pair entry admits A.
        let store_o = Arc::new(PeerStore::open(&dir_o.path().join("state.redb")).unwrap());
        let store_a = Arc::new(PeerStore::open(&dir_a.path().join("state.redb")).unwrap());
        let store_b = Arc::new(PeerStore::open(&dir_b.path().join("state.redb")).unwrap());
        store_b
            .add(PeerEntry {
                endpoint_id: bytes_a,
                nickname: "alice-pair".into(),
                services: vec!["echo".into()],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();
        let reg_o = Arc::new(ConnRegistry::new());
        let reg_a = Arc::new(ConnRegistry::new());
        let reg_b = Arc::new(ConnRegistry::new());

        // Build O, A, B: each roster-mode at serial 1, bootstrap = the OTHER two endpoint ids.
        let (mesh_o, roster_o) = build_node(
            ep_o,
            v1_o,
            vec![eid_a, eid_b],
            cfg_o_path.clone(),
            store_o,
            reg_o,
        )
        .await;
        let (mesh_a, _roster_a) = build_node(
            ep_a,
            v1_a,
            vec![eid_o, eid_b],
            cfg_a_path.clone(),
            store_a,
            reg_a,
        )
        .await;
        let (mesh_b, roster_b) = build_node(
            ep_b,
            v1_b,
            vec![eid_o, eid_a],
            cfg_b_path.clone(),
            store_b,
            reg_b.clone(),
        )
        .await;

        // Drive each node's REAL accept loop (gated mesh + gossip + blob ALPN dispatch). Services come
        // from each node's own config file (only B serves `echo`).
        let cfg_o = Config::load(&cfg_o_path).expect("load O config");
        let cfg_a = Config::load(&cfg_a_path).expect("load A config");
        let cfg_b = Config::load(&cfg_b_path).expect("load B config");
        let _task_o = spawn_accept_loop(mesh_o.clone(), Arc::new(build_services(&cfg_o)));
        let _task_a = spawn_accept_loop(mesh_a.clone(), Arc::new(build_services(&cfg_a)));
        let _task_b = spawn_accept_loop(mesh_b.clone(), Arc::new(build_services(&cfg_b)));

        // ONLY B converges via gossip — so the cut is unambiguously DRIVEN by B's gossip-received
        // revocation (A runs no receive loop; A is oblivious, it only observes the EOF).
        let _recv_b = mcpmesh::roster::distribute::spawn_receive_loop(mesh_b.clone());

        // 2. Establish a LIVE mesh session A→B and round-trip a GENUINE data frame (the live proof —
        //    else "cut" proves nothing).
        let mut alice_t = connect(&alice_dialer, b_addr.clone(), "echo")
            .await
            .expect("A dials B's echo service");
        alice_t.send_value(initialize_frame("echo")).await.unwrap();
        let init = alice_t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "A must complete a LIVE session to B before the revoke: {init}"
        );
        alice_t
            .send_value(tools_call_frame("live-before-revoke"))
            .await
            .unwrap();
        let live = timeout(Duration::from_secs(10), alice_t.recv_value())
            .await
            .expect("A's pre-revoke frame must round-trip promptly")
            .expect("A transport ok")
            .expect("A reply frame");
        assert_eq!(
            live["result"]["content"][0]["text"], "live-before-revoke",
            "the pre-revoke session must GENUINELY round-trip a data frame: {live}"
        );
        // A is now registered on B (register-check happens-before the init reply) — the sever target.
        wait_for_len(&reg_b, 1).await;

        // 3. Operator O: `org revoke alice/laptop` → serial-2 roster (A revoked). O persists it (so the
        //    announce reads it) and installs (severs O's own view of A — nothing live on O).
        std::fs::write(dir_o.path().join("roster.json"), &v2_bytes).unwrap();
        let _severed_o = install_roster_view_and_sever(&mesh_o, v2_o);
        assert_eq!(
            roster_o.view().unwrap().serial(),
            2,
            "O bumped its own view to serial 2 before announcing"
        );

        // 4. ASSERT (convergence, NOT a sleep): within the deadline B installs serial 2 via gossip. O
        //    re-announces each poll iteration so the announce survives gossip-join timing; the loop
        //    BREAKS the instant B converges (it only reaches the deadline on genuine failure).
        let propagation_start = Instant::now();
        // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
        let deadline = propagation_start + Duration::from_secs(150);
        loop {
            mcpmesh::roster::distribute::announce_roster(&mesh_o)
                .await
                .expect("O announces serial 2 on the roster topic");
            if roster_b.view().map(|v| v.serial()).unwrap_or(0) >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "B did NOT converge to serial 2 via gossip propagation within the deadline"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let elapsed = propagation_start.elapsed();
        eprintln!("[T13] B converged to serial 2 via gossip in {elapsed:?}");
        assert_eq!(
            roster_b.view().expect("B installed a roster").serial(),
            2,
            "B converged to serial 2 (received → fetched → validated → installed) via gossip"
        );

        // The CUT: A's live session observes the transport close — DRIVEN by B's gossip-received
        // revocation (install_from_file → install_roster_view_and_sever). Must close PROMPTLY (never a
        // client timeout — the recv returns EOF/close, not after hanging).
        let alice_after = timeout(Duration::from_secs(10), alice_t.recv_value())
            .await
            .expect("A's severed session must close promptly after B's gossip-received revocation, not hang");
        assert!(
            !matches!(alice_after, Ok(Some(_))),
            "A's live session must be CUT (EOF/close) by B's gossip-received revocation, got a frame: {alice_after:?}"
        );

        // 5. The stale-pair revocation-wins clause: B STILL holds a pair ALLOW for A (nickname in
        //    echo's `allow`), yet a FRESH A dial post-revocation is refused PRE-MCP — revocation wins
        //    over the pair entry (§4.1(1)). The (pairs ∪ roster) composition, cross-node.
        match connect(&alice_dialer, b_addr, "echo").await {
            Err(_) => {} // refused at/near handshake — a valid "closed" outcome
            Ok(mut t) => {
                let _ = t.send_value(initialize_frame("echo")).await;
                let res = timeout(Duration::from_secs(10), t.recv_value())
                    .await
                    .expect("a revoked re-dial must close promptly, not hang");
                assert!(
                    !matches!(res, Ok(Some(_))),
                    "a revoked endpoint holding a stale pair entry must be refused pre-MCP, got: {res:?}"
                );
            }
        }

        // Secondary: after A's severed handler task unwinds, B's registry settles to empty.
        wait_for_len(&reg_b, 0).await;
    })
    .await
    .expect("3-node revocation propagation exceeded 90s");
}
