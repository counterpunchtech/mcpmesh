//! In-process gossip/blob composition (M3c T5): two roster-mode daemons subscribe the roster topic
//! bootstrapping from each other and FORM A GOSSIP NEIGHBORHOOD through the daemon's UNIFIED, GATED
//! accept loop (the new `GOSSIP_ALPN` arm — each inbound gossip connection is resolved by the trust
//! gate + check-registered before it reaches the gossip protocol handler, D8 across all ALPNs).
//! Localhost, relay-disabled, `MemoryLookup`-seeded — the SAME harness as `roster_sever.rs` /
//! `hero_flow_roster.rs`, extended with the gossip+blob ALPNs. Assert-on-convergence-with-timeout,
//! never a fixed sleep. (The full fetch→converge assertion is T6; this task lands the composition +
//! a neighborhood-formation smoke.)
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{MeshState, build_services, spawn_accept_loop};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh::roster::transport::{self, RosterBlobs};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use tokio::time::timeout;

/// A localhost-only ROSTER-mode endpoint advertising all four ALPNs (mesh + pair + gossip + blob) —
/// exactly what `build_endpoint(.., roster_mode = true)` binds, so the daemon's real accept loop can
/// dispatch the two new ALPNs in-process.
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

/// Mint a signed serial-`serial` roster listing each `(endpoint_id, user_id)` as a one-device user
/// in group `team-eng`, returning BOTH the signed JSON bytes (what an operator seeds into its blob
/// store + what a fetcher re-validates through the SINGLE install path) AND the loaded view (what a
/// gate installs). Far-future expiry — a currently-valid, resolvable roster signed by the production
/// mint path. The bytes + view describe the SAME document, so on-disk serial and gate serial agree.
fn mint_signed_roster(
    root: &SigningKey,
    serial: u64,
    users: &[([u8; 32], &str)],
) -> (Vec<u8>, RosterView) {
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
            revoked_endpoints: vec![],
            sig: String::new(),
        },
    );
    let bytes = serde_json::to_vec(&r).expect("serialize signed roster");
    let view = load_installed(&r, &root.verifying_key()).expect("mint a valid roster view");
    (bytes, view)
}

/// The view-only projection (mirrors `roster_sever.rs`) for sites that install into a gate without
/// needing the on-disk bytes.
fn mint_view(root: &SigningKey, serial: u64, users: &[([u8; 32], &str)]) -> RosterView {
    mint_signed_roster(root, serial, users).1
}

/// Write a roster-mode `config.toml` pinning the org root (mirrors `hero_flow_roster.rs`) — the
/// converge path (`on_announce`) reads `[identity].org_root_pk` to resolve the trust anchor before
/// it re-validates a gossip roster through the single install path.
fn write_roster_config(path: &std::path::Path, org_root_pk: &str) {
    std::fs::write(
        path,
        format!(
            "[network]\nrelay_mode = \"disabled\"\n[identity]\norg_root_pk = \"{org_root_pk}\"\norg_id = \"acme\"\n"
        ),
    )
    .expect("write roster config");
}

/// Assemble a ROSTER-mode `MeshState` over `endpoint` — exactly the roster-mode wiring
/// `serve_forever` does: install `install_view` into a fresh roster gate (the two nodes are MUTUALLY
/// rostered — the gated gossip arm admits each other's gossip connection), spawn the gossip/blob
/// transports on the shared endpoint, subscribe the roster topic bootstrapping from `bootstrap`, and
/// thread the handles into `MeshState::new`. Returns the mesh AND the `Arc<RosterGate>` it installed,
/// so a test can poll `roster.view().serial()` directly (the `MeshState` fields are `pub(crate)`).
async fn roster_node(
    endpoint: iroh::Endpoint,
    install_view: RosterView,
    bootstrap: Vec<iroh::EndpointId>,
    config_path: PathBuf,
) -> (Arc<MeshState>, Arc<RosterGate>) {
    let store = Arc::new(
        PeerStore::open(&config_path.parent().unwrap().join("state.redb")).expect("open store"),
    );
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    let roster = Arc::new(RosterGate::empty());
    roster.install(install_view);
    let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

    // Roster-mode composition: one Gossip + one RosterBlobs on the daemon's ONE endpoint, then a
    // roster-topic subscription bootstrapping from the peer (the accept loop dispatches inbound
    // gossip/blob connections to these handlers).
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
        Arc::new(ConnRegistry::new()),
        Some(gossip),
        Some(blobs),
        Some(roster_gossip),
        None,
    );
    (mesh, roster)
}

/// Two roster-mode daemons, MemoryLookup-seeded to each other, each subscribing the roster topic
/// bootstrapping from the other's endpoint id, form a gossip neighborhood: each receives a
/// `NeighborUp` (via `GossipReceiver::joined`) within the timeout — the swarm forms THROUGH the
/// gated `GOSSIP_ALPN` accept arm (each node resolves the other via their mutual roster). Real
/// endpoints, assert-on-convergence — no fixed sleep.
#[tokio::test(flavor = "multi_thread")]
async fn two_roster_daemons_form_a_gossip_neighborhood() {
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(90), async {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);

        let ep_a = roster_alpn_endpoint().await;
        let ep_b = roster_alpn_endpoint().await;
        let id_a = *ep_a.id().as_bytes();
        let id_b = *ep_b.id().as_bytes();
        let bootstrap_a = ep_a.id(); // A's endpoint id — B bootstraps from it
        let bootstrap_b = ep_b.id(); // B's endpoint id — A bootstraps from it

        // Cross-seed each endpoint's address lookup with the other's addr (localhost has no
        // discovery), so the bootstrap dial can reach the peer.
        let mem_a = iroh::address_lookup::MemoryLookup::new();
        mem_a.add_endpoint_info(ep_b.addr());
        ep_a.address_lookup()
            .expect("address lookup services")
            .add(mem_a);
        let mem_b = iroh::address_lookup::MemoryLookup::new();
        mem_b.add_endpoint_info(ep_a.addr());
        ep_b.address_lookup()
            .expect("address lookup services")
            .add(mem_b);

        let users = [(id_a, "node-a"), (id_b, "node-b")];
        let (mesh_a, _roster_a) = roster_node(
            ep_a,
            mint_view(&root, 1, &users),
            vec![bootstrap_b],
            dir_a.path().join("config.toml"),
        )
        .await;
        let (mesh_b, _roster_b) = roster_node(
            ep_b,
            mint_view(&root, 1, &users),
            vec![bootstrap_a],
            dir_b.path().join("config.toml"),
        )
        .await;

        // Drive the daemon's REAL accept loop on both nodes so the new gated GOSSIP_ALPN arm
        // dispatches inbound gossip connections to each node's gossip handler.
        let services = Arc::new(build_services(
            &Config::from_toml_str("").expect("empty config"),
        ));
        let _task_a = spawn_accept_loop(mesh_a.clone(), services.clone());
        let _task_b = spawn_accept_loop(mesh_b.clone(), services.clone());

        // Observe neighborhood formation on each node's roster-topic receiver.
        let mut recv_a = mesh_a
            .take_roster_topic_receiver()
            .await
            .expect("node A has a roster-topic receiver");
        let mut recv_b = mesh_b
            .take_roster_topic_receiver()
            .await
            .expect("node B has a roster-topic receiver");

        // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
        let (ra, rb) = tokio::join!(
            timeout(Duration::from_secs(75), recv_a.joined()),
            timeout(Duration::from_secs(75), recv_b.joined()),
        );
        ra.expect("node A must form a gossip neighbor within the timeout")
            .expect("node A join ok");
        rb.expect("node B must form a gossip neighbor within the timeout")
            .expect("node B join ok");
    })
    .await
    .expect("gossip neighborhood formation timed out");
}

/// **The M3c convergence (spec §4.3 distribution).** Node A (operator) + node B, both roster-mode at
/// serial 1, gossip-joined. A "publishes" serial 2 (a signed roster ADDING a device) through the REAL
/// publish path [`announce_roster`]: add the doc to A's blob store + broadcast a `RosterAnnounce`
/// on the roster topic. B's [`spawn_receive_loop`] receives the announce, seeds the provider's addr,
/// FETCHES the blob (T3 hash-verify), and CONVERGES through M3a's SINGLE install path
/// (`install_from_file` → `install_roster_view_and_sever`: validate rules 1–6 incl. the org-root sig
/// + serial>installed → persist → hot-swap → D8 sever). ASSERT-on-convergence (poll B's installed
/// serial), never a fixed sleep — A re-announces each poll so the announce is not lost to gossip-join
/// timing. Real gossip + real blob fetch over localhost endpoints; run 2–3× (non-flaky).
#[tokio::test(flavor = "multi_thread")]
async fn a_gossip_announce_converges_a_second_node_to_the_new_roster() {
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(150), async {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        let ep_a = roster_alpn_endpoint().await;
        let ep_b = roster_alpn_endpoint().await;
        let id_a = *ep_a.id().as_bytes();
        let id_b = *ep_b.id().as_bytes();
        let bootstrap_a = ep_a.id(); // A's endpoint id — B bootstraps + fetches from it
        let bootstrap_b = ep_b.id();

        // Cross-seed each endpoint's address lookup with the other's addr (localhost has no
        // discovery) so the gossip bootstrap dial — and the blob fetch — can reach the peer.
        let mem_a = iroh::address_lookup::MemoryLookup::new();
        mem_a.add_endpoint_info(ep_b.addr());
        ep_a.address_lookup()
            .expect("address lookup services")
            .add(mem_a);
        let mem_b = iroh::address_lookup::MemoryLookup::new();
        mem_b.add_endpoint_info(ep_a.addr());
        ep_b.address_lookup()
            .expect("address lookup services")
            .add(mem_b);

        // serial 1 (both nodes) and serial 2 (A's operator bump — ADDS device node-c). The bytes are
        // written to each node's roster.json (the install path reads/writes the config-derived path);
        // the views are what each gate installs.
        let users1 = [(id_a, "node-a"), (id_b, "node-b")];
        let (v1_bytes, v1_view_a) = mint_signed_roster(&root, 1, &users1);
        let v1_view_b = mint_signed_roster(&root, 1, &users1).1;
        let users2 = [(id_a, "node-a"), (id_b, "node-b"), ([7u8; 32], "node-c")];
        let (v2_bytes, v2_view) = mint_signed_roster(&root, 2, &users2);

        // Node A: pinned config + serial-1 on disk + gate, then the operator serial bump to 2 (disk +
        // gate) — exactly the post-`install_roster` state from which `announce_roster` publishes.
        let cfg_a = dir_a.path().join("config.toml");
        write_roster_config(&cfg_a, &org_root_pk);
        std::fs::write(dir_a.path().join("roster.json"), &v1_bytes).unwrap();
        let (mesh_a, roster_a) = roster_node(ep_a, v1_view_a, vec![bootstrap_b], cfg_a).await;
        std::fs::write(dir_a.path().join("roster.json"), &v2_bytes).unwrap();
        roster_a.install(v2_view); // A is now at serial 2, ready to announce

        // Node B: pinned config + serial-1 on disk + gate. Stays at serial 1 until it converges.
        let cfg_b = dir_b.path().join("config.toml");
        write_roster_config(&cfg_b, &org_root_pk);
        std::fs::write(dir_b.path().join("roster.json"), &v1_bytes).unwrap();
        let (mesh_b, roster_b) = roster_node(ep_b, v1_view_b, vec![bootstrap_a], cfg_b).await;

        // Drive the daemon's REAL accept loop on both nodes (gated gossip + blob ALPN dispatch).
        let services = Arc::new(build_services(
            &Config::from_toml_str("").expect("empty config"),
        ));
        let _task_a = spawn_accept_loop(mesh_a.clone(), services.clone());
        let _task_b = spawn_accept_loop(mesh_b.clone(), services.clone());

        // B's convergence loop: receive announce → fetch → single-validate → install (+ re-announce).
        let _receive = mcpmesh::roster::distribute::spawn_receive_loop(mesh_b.clone());

        // A publishes serial 2 via the REAL publish path, re-announcing each poll iteration so the
        // announce survives gossip-join timing. Assert-on-convergence: poll B's installed serial.
        loop {
            mcpmesh::roster::distribute::announce_roster(&mesh_a)
                .await
                .expect("A announces serial 2");
            if roster_b.view().map(|v| v.serial()).unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(
            roster_b.view().expect("B installed a roster").serial(),
            2,
            "B converged to serial 2 via gossip: received → fetched → validated → installed"
        );
    })
    .await
    .expect("gossip convergence timed out");
}

/// A one-shot-ish localhost HTTP/1.1 server (std only — no new dep) that serves `body` as the roster
/// document for EVERY request until stopped. Returns `(url, stop_flag, join_handle)`; set the flag +
/// join to shut it down. Non-blocking accept + a poll so a clean shutdown never hangs the test thread.
fn serve_roster_over_http(body: Vec<u8>) -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        while !stop_thread.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Read to END-OF-HEADERS, not just one read: a GET can arrive split across TCP
                    // segments, and responding + dropping with unread request bytes still buffered
                    // makes the close an RST that can destroy the in-flight response (the macOS CI
                    // flake: reqwest "received unexpected message from connection"). Short timeout so
                    // a half-open peer never wedges the loop.
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = [0u8; 4096];
                    let mut total = 0;
                    while total < buf.len() {
                        match stream.read(&mut buf[total..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                total += n;
                                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&body);
                    let _ = stream.flush();
                    // Half-close, then drain until the peer closes: no unread bytes may remain at
                    // drop, so the final close is a FIN (never a response-killing RST).
                    let _ = stream.shutdown(std::net::Shutdown::Write);
                    let _ = stream.read(&mut buf);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://127.0.0.1:{port}/roster.json"), stop, handle)
}

/// **The M3c URL-poll convergence (spec §4.3 HTTPS fallback).** Node B is roster-mode at serial 1
/// (org root pinned; serial-1 on disk + gate). A static host serves a signed serial-2 roster over
/// HTTP. `poll_roster_url_once` GETs it and CONVERGES through the SAME single install path the gossip
/// channel uses (`install_from_file` → `install_roster_view_and_sever`) — B lands at serial 2 on disk
/// AND in the gate. A SECOND poll of the SAME serial-2 URL takes the EQUAL-serial branch: it does NOT
/// re-install (no bump, no error) — it CONFIRMS currency (`confirm_roster_current`, the freshness
/// signal only the URL poll gives, T9). Real reqwest over localhost; no fixed sleep — a direct assert.
#[tokio::test(flavor = "multi_thread")]
async fn a_url_poll_converges_a_node_then_confirms_on_an_equal_serial() {
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(90), async {
        // The daemon installs this at startup (T7); the test mirrors it so reqwest's client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        let ep_b = roster_alpn_endpoint().await;
        let id_b = *ep_b.id().as_bytes();

        // serial 1 (B's starting roster) and serial 2 (the served roster, ADDS device node-c).
        let users1 = [(id_b, "node-b")];
        let (v1_bytes, v1_view) = mint_signed_roster(&root, 1, &users1);
        let users2 = [(id_b, "node-b"), ([7u8; 32], "node-c")];
        let (v2_bytes, _v2_view) = mint_signed_roster(&root, 2, &users2);

        // Node B: pinned config + serial-1 on disk + gate — the pre-first-poll joiner/rostered state.
        let cfg_b = dir_b.path().join("config.toml");
        write_roster_config(&cfg_b, &org_root_pk);
        std::fs::write(dir_b.path().join("roster.json"), &v1_bytes).unwrap();
        let (mesh_b, roster_b) = roster_node(ep_b, v1_view, vec![], cfg_b).await;
        assert_eq!(roster_b.view().unwrap().serial(), 1, "B starts at serial 1");

        // Serve serial 2; poll once → CONVERGE to 2 (the same install_from_file the gossip path uses).
        let (url, stop, handle) = serve_roster_over_http(v2_bytes);
        mcpmesh::roster::distribute::poll_roster_url_once(&mesh_b, &url)
            .await
            .expect("URL poll converges to the newer roster");
        assert_eq!(
            roster_b.view().unwrap().serial(),
            2,
            "the URL poll converged B to serial 2 (single install path, no second validator)"
        );
        let on_disk: Roster =
            serde_json::from_slice(&std::fs::read(dir_b.path().join("roster.json")).unwrap())
                .unwrap();
        assert_eq!(on_disk.serial, 2, "the newer roster is persisted on disk");

        // Poll the SAME serial-2 URL again → the EQUAL-serial branch: confirm currency, no re-install,
        // no error, no regression (the freshness path — the only channel that confirms without a bump).
        mcpmesh::roster::distribute::poll_roster_url_once(&mesh_b, &url)
            .await
            .expect("an equal-serial poll confirms currency (never errors)");
        assert_eq!(
            roster_b.view().unwrap().serial(),
            2,
            "an equal-serial poll keeps serial 2 (freshness confirm, not a re-install)"
        );

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    })
    .await
    .expect("url poll convergence timed out");
}

/// **M3c equal-serial currency confirm authentication (invariant #1).** The equal-serial URL-poll
/// freshness confirm MUST fire ONLY on org-root-AUTHENTICATED bytes — the pinned HTTPS host is
/// UNTRUSTED, so a compromised/spoofed host serving an unsigned/wrong-org body at the INSTALLED serial
/// must NOT be able to forge currency (`confirm_roster_current`) and defeat the P13 staleness fail-safe.
/// This proves BOTH directions with `last_confirmed` armed to a distinctive OLD sentinel:
///   (1) a WRONG-ORG-signed body at serial == installed (a "valid cert for a spoofed host" that holds
///       its OWN key, but NOT B's pinned org root) does NOT bump `last_confirmed` (sentinel stands) and
///       does NOT error the node (fail-safe: log + skip);
///   (2) B's OWN org-root-signed body at serial == installed DOES confirm — `last_confirmed` moves off
///       the sentinel — so the authenticated freshness path still works.
/// Assert on `last_confirmed` state, never a sleep. Real reqwest over localhost.
#[tokio::test(flavor = "multi_thread")]
async fn an_equal_serial_poll_confirms_only_on_org_root_authenticated_bytes() {
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(90), async {
        // The daemon installs this at startup (T7); the test mirrors it so reqwest's client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        let ep_b = roster_alpn_endpoint().await;
        let id_b = *ep_b.id().as_bytes();

        // B is rostered at serial 1 (B's pinned org root; serial-1 on disk + gate).
        let users1 = [(id_b, "node-b")];
        let (v1_bytes, v1_view) = mint_signed_roster(&root, 1, &users1);
        let cfg_b = dir_b.path().join("config.toml");
        write_roster_config(&cfg_b, &org_root_pk);
        std::fs::write(dir_b.path().join("roster.json"), &v1_bytes).unwrap();
        let (mesh_b, roster_b) = roster_node(ep_b, v1_view, vec![], cfg_b).await;
        assert_eq!(roster_b.view().unwrap().serial(), 1, "B starts at serial 1");

        // Arm a KNOWN old freshness baseline so a (non-)confirm is directly observable.
        const SENTINEL: i64 = 1_000_000_000; // 2001 — distinctively older than any real `now`
        roster_b.set_last_confirmed(SENTINEL);

        // (1) UNAUTHENTICATED equal-serial body: a DIFFERENT org root signs a serial-1 roster (a
        // structurally valid, validly-SIGNED body — but NOT against B's pinned org root). It parses,
        // its serial == installed → the equal-serial branch — but rule 1 against the pinned pk fails.
        let evil = SigningKey::from_bytes(&[1u8; 32]);
        let (evil_v1_bytes, _) = mint_signed_roster(&evil, 1, &users1);
        let (evil_url, evil_stop, evil_handle) = serve_roster_over_http(evil_v1_bytes);
        mcpmesh::roster::distribute::poll_roster_url_once(&mesh_b, &evil_url)
            .await
            .expect("an unauthenticated equal-serial poll must NOT error (fail-safe: log + skip)");
        assert_eq!(
            roster_b.last_confirmed(),
            Some(SENTINEL),
            "a WRONG-ORG-signed equal-serial body must NOT confirm currency (last_confirmed unchanged)"
        );
        assert_eq!(
            roster_b.view().unwrap().serial(),
            1,
            "the unauthenticated body neither installs nor regresses the installed roster"
        );
        evil_stop.store(true, Ordering::Relaxed);
        let _ = evil_handle.join();

        // (2) AUTHENTICATED equal-serial body: B's OWN org-root-signed serial-1 roster → CONFIRMS
        // currency, bumping last_confirmed OFF the sentinel to ~now (the freshness path still works).
        let (good_url, good_stop, good_handle) = serve_roster_over_http(v1_bytes);
        mcpmesh::roster::distribute::poll_roster_url_once(&mesh_b, &good_url)
            .await
            .expect("an authenticated equal-serial poll confirms currency (never errors)");
        let lc = roster_b.last_confirmed().expect("freshness is armed");
        assert!(
            lc > SENTINEL,
            "an AUTHENTICATED equal-serial body confirms currency (last_confirmed bumped off {SENTINEL}, got {lc})"
        );
        assert_eq!(
            roster_b.view().unwrap().serial(),
            1,
            "an authenticated equal-serial confirm is a freshness bump, not a re-install"
        );
        good_stop.store(true, Ordering::Relaxed);
        let _ = good_handle.join();
    })
    .await
    .expect("equal-serial authentication test timed out");
}

/// **M4b — an AUTOMATIC roster convergence audits its hot-swap (spec §11.3 / P14).** The
/// `roster_install` trust record is emitted at the SHARED install choke point
/// (`install_roster_view_and_sever`), which ALL three channels funnel through — so a node that
/// converges via the URL poll (never the manual `roster_install` verb) STILL logs the swap that hot-
/// swaps its gate + severs sessions. Node B is roster-mode at serial 1 with a REAL AuditLog; a host
/// serves a signed serial-2 roster; one `poll_roster_url_once` converges B → the audit file gains
/// EXACTLY one `trust(event="roster_install", target="acme/2")` record. Surface-clean: org/serial
/// only, no keys/EndpointIds (§1.5). Real reqwest over localhost; assert-on-convergence.
#[tokio::test(flavor = "multi_thread")]
async fn a_url_poll_convergence_audits_the_roster_install() {
    use mcpmesh::audit::{AuditLog, AuditSink, now_ts};
    // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
    timeout(Duration::from_secs(90), async {
        // The daemon installs this at startup (T7); the test mirrors it so reqwest's client builds.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir_b = tempfile::tempdir().unwrap();
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        let ep_b = roster_alpn_endpoint().await;
        let id_b = *ep_b.id().as_bytes();

        // serial 1 (B's starting roster) and serial 2 (the served roster, ADDS device node-c).
        let users1 = [(id_b, "node-b")];
        let (v1_bytes, v1_view) = mint_signed_roster(&root, 1, &users1);
        let users2 = [(id_b, "node-b"), ([7u8; 32], "node-c")];
        let (v2_bytes, _v2_view) = mint_signed_roster(&root, 2, &users2);

        // Node B: pinned config + serial-1 on disk + gate — the pre-first-poll rostered state.
        let cfg_b = dir_b.path().join("config.toml");
        write_roster_config(&cfg_b, &org_root_pk);
        std::fs::write(dir_b.path().join("roster.json"), &v1_bytes).unwrap();
        let (mesh_b, roster_b) = roster_node(ep_b, v1_view, vec![], cfg_b).await;

        // Install a real AuditLog so the shared choke point's roster_install record persists to disk.
        let audit_dir = dir_b.path().join("audit");
        mesh_b.set_audit(AuditSink::new(AuditLog::spawn(audit_dir.clone())));

        // Serve serial 2; one poll converges B through install_roster_view_and_sever via the URL path
        // (NOT the manual verb) — proving the AUTOMATIC convergence path now audits its swap.
        let (url, stop, handle) = serve_roster_over_http(v2_bytes);
        mcpmesh::roster::distribute::poll_roster_url_once(&mesh_b, &url)
            .await
            .expect("URL poll converges to serial 2");
        assert_eq!(
            roster_b.view().unwrap().serial(),
            2,
            "the URL poll converged B to serial 2"
        );

        // The shared choke point logged EXACTLY one roster_install for org/serial "acme/2".
        let month = &now_ts()[..7];
        let file = audit_dir.join(format!("{month}.jsonl"));
        let mut installs = 0;
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file) {
                installs = b.matches("\"event\":\"roster_install\"").count();
                if installs >= 1 {
                    assert!(
                        b.contains("\"kind\":\"trust\"") && b.contains("\"target\":\"acme/2\""),
                        "the roster_install record is a trust event with org/serial acme/2: {b}"
                    );
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            installs, 1,
            "the URL convergence emitted exactly one roster_install audit record"
        );

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
    })
    .await
    .expect("url poll convergence audit test timed out");
}
