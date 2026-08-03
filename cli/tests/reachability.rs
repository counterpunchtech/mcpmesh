//! Task 4 acceptance: the `mcpmesh/ping/1` reachability probe (pairing-mode liveness).
//!
//! Two-node hermetic (relay disabled → no network egress), modeled on `daemon_dispatch.rs` /
//! `pairing_porcelain.rs`: assemble in-process `MeshState`s over localhost endpoints, SEED the
//! allowlist directly (the same shortcut the sibling in-process tests use — no live rendezvous),
//! and drive the REAL [`probe_peer`] / [`reachability_of`] the daemon exposes. Proves:
//!
//!  1. A probe of a PAIRED peer → reachable, with a measured RTT.
//!  2. [`reachability_of`] projects the cache to the peer's NICKNAME (never the endpoint-id, §1.5)
//!     and never blocks the caller.
//!  3. A probe from an UNPAIRED endpoint → NOT reachable — the responder's trust gate closes the
//!     connection with NO pong (no presence leak; the SECURITY property of the probe).
//!  4. After the target endpoint is taken down → NOT reachable (a dead dial times out to false).
// Unix-only: hand-binds the control endpoint in-process (`bind_control_socket`) at a
// filesystem socket path and connects to it via `connect_control`, which a windows named
// pipe cannot be. Windows coverage for the control path lives at the transport layer
// (local-api transport::windows pipe tests) and the client protocol layer (local-api
// client.rs seam tests); a windows daemon-subprocess round-trip is deferred — see the
// plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use iroh::address_lookup::MemoryLookup;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{
    MeshState, PresenceMode, STACK_VERSION, build_services, probe_peer, reachability_of,
    spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh::{Request, StatusResult};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, ALPN_PING, TrustGate};
use tokio::time::timeout;

/// Serializes the timing-sensitive tests in this binary (the #138 idiom): the flood test races
/// 90 real dials against `PROBE_TIMEOUT`, and the cache-freshness test races its teardown +
/// control round-trip against `REACH_TTL_SECS`. Both assert booleans, not latencies, but both
/// lose their margins under parallel-test contention.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The target endpoint: advertises the mesh + pair + PING ALPNs (mirrors `build_endpoint`'s list
/// once `ALPN_PING` is added), so the daemon's own accept loop can serve the ping arm in-process.
async fn target_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            ALPN_MCP.to_vec(),
            ALPN_PAIR.to_vec(),
            ALPN_PING.to_vec(),
        ])
        .bind()
        .await
        .expect("bind target endpoint")
}

/// A dialing endpoint. It only *accepts* the mesh ALPN (it never serves ping); the ALPN it *dials*
/// is chosen per-connect, so it can still probe over `mcpmesh/ping/1`.
async fn dialer_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind dialer endpoint")
}

/// Seed `dialer`'s id-only dial resolution with `target_addr` — the localhost stand-in for the
/// DNS/pkarr discovery that resolves an address FROM an endpoint-id in production (spec §10.2).
fn seed_lookup(dialer: &iroh::Endpoint, target_addr: iroh::EndpointAddr) {
    let mem = MemoryLookup::new();
    mem.add_endpoint_info(target_addr);
    dialer
        .address_lookup()
        .expect("address lookup services")
        .add(mem);
}

fn seed_peer(store: &PeerStore, endpoint_id: [u8; 32], nickname: &str) {
    store
        .add(PeerEntry {
            endpoint_id,
            nickname: nickname.into(),
            services: vec![],
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();
}

/// Seed a peer carrying the pairing-persisted `last_addr` dial hint — the address the redeemer
/// stores from `invite.inviter_addr_json`, already PROVEN dialable because the pairing handshake
/// just completed over it.
fn seed_peer_with_addr(
    store: &PeerStore,
    endpoint_id: [u8; 32],
    nickname: &str,
    addr: &iroh::EndpointAddr,
) {
    store
        .add(PeerEntry {
            endpoint_id,
            nickname: nickname.into(),
            services: vec![],
            paired_at: None,
            user_id: None,
            last_addr: Some(serde_json::to_string(addr).expect("addr serializes")),
        })
        .unwrap();
}

fn assemble_mesh(
    endpoint: iroh::Endpoint,
    store: Arc<PeerStore>,
    config_path: std::path::PathBuf,
) -> Arc<MeshState> {
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    MeshState::new(
        endpoint,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "self".into(),
        config_path,
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    )
}

/// Dial the target's `ALPN_PING` and report the close reason bytes, or `None` if a pong arrived.
///
/// #89 needs the RAW bytes, not just "unreachable": the whole property is that a hidden node's
/// refusal is INDISTINGUISHABLE from the trust gate's, and `probe_peer` collapses every refusal to
/// `reachable: false` — which would pass even if the close said "presence disabled".
async fn ping_refusal_reason(dialer: &iroh::Endpoint, target: [u8; 32]) -> Option<Vec<u8>> {
    let conn = match dialer
        .connect(iroh::EndpointId::from_bytes(&target).unwrap(), ALPN_PING)
        .await
    {
        Ok(c) => c,
        // A refusal at handshake carries the reason too.
        Err(e) => return Some(format!("{e}").into_bytes()),
    };
    let Ok((mut send, mut recv)) = conn.open_bi().await else {
        return close_reason_bytes(&conn);
    };
    let _ = mcpmesh_net::framing::write_frame(&mut send, &serde_json::json!({"ping": 1})).await;
    let _ = send.finish();
    let mut buf = Vec::new();
    match tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut buf).await {
        Ok(_) if !buf.is_empty() => None, // a pong arrived
        _ => close_reason_bytes(&conn),
    }
}

/// The close CODE as well as the reason. Reading only the reason let a mutation that changed the
/// policy close from 401 to 0 pass the whole suite — the code is on the wire and is just as
/// distinguishable to a prober (#89 gate).
fn close_reason_bytes(conn: &iroh::endpoint::Connection) -> Option<Vec<u8>> {
    match conn.close_reason() {
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(ac)) => Some(
            format!(
                "code={} reason={}",
                ac.error_code,
                String::from_utf8_lossy(&ac.reason)
            )
            .into_bytes(),
        ),
        other => Some(format!("{other:?}").into_bytes()),
    }
}

/// #89: the presence policy must be consulted BEFORE the rate limiter.
///
/// `PING_THROTTLE_CLOSE` is distinguishable ON PURPOSE (#142 — a throttled probe must not be
/// written down as "peer offline"). So if a hidden node metered first, a prober that exhausted the
/// bucket would get "ping rate limited" back and learn the peer is online and merely hiding. The
/// ordering IS the property; asserting the constant differs is not enough, because with an
/// unlimited bucket the throttle branch is never reached and the assertion is vacuous.
#[tokio::test(flavor = "multi_thread")]
async fn a_hidden_node_never_leaks_presence_through_the_throttle_close() {
    timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("ta.redb")).unwrap());

        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        seed_peer(&a_store, b_id, "flooder");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        // A REAL limiter — `unlimited()` would make the throttle branch unreachable and the whole
        // test vacuous, which is the trap the sibling throttle test documents.
        let a_limits =
            mcpmesh::limits::MeshLimiters::from_config(&mcpmesh::config::LimitsCfg::default());
        a_mesh.set_limits(a_limits.clone());
        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Drain the per-endpoint ping bucket while still in `paired`, so tokens are actually
        // consumed (under `off` the policy refuses first and spends nothing — which is the point).
        let mut throttled = None;
        for _ in 0..120 {
            if let Some(reason) = ping_refusal_reason(&b_ep, a_id).await
                && String::from_utf8_lossy(&reason).contains("ping rate limited")
            {
                throttled = Some(reason);
                break;
            }
        }
        assert!(
            throttled.is_some(),
            "the bucket must actually be exhausted, or the ordering below proves nothing"
        );

        // NOW hide. The refusal must be the gate's, not the throttle's.
        a_mesh.set_presence_mode(PresenceMode::Off);
        let hidden = ping_refusal_reason(&b_ep, a_id)
            .await
            .expect("an off node must refuse");
        assert_eq!(
            String::from_utf8_lossy(&hidden),
            "code=401 reason=unauthorized",
            "a hidden node with an EXHAUSTED bucket must still answer like the trust gate. Got \
             {:?} — if this is the throttle close, the policy is being consulted after the limiter \
             and 'appear offline' announces itself to anyone who floods first.",
            String::from_utf8_lossy(&hidden)
        );

        // A REFUSED probe must still SPEND a token. Returning early without metering left the arm
        // completely unmetered for exactly the peers a hidden node most wants bounded — undoing
        // #89 ask 1 for this mode (#89 gate).
        //
        // Observed on the limiter's own counter, NOT on "is a later probe throttled": the bucket
        // is already drained here, so on loopback 80 dials finish faster than one token refills
        // and a later probe is throttled either way. That assertion passed with the metering
        // deleted — insensitive, which is indistinguishable from correct until you mutate it.
        let refused_before = a_limits.pings_refused();
        for _ in 0..20 {
            let _ = ping_refusal_reason(&b_ep, a_id).await;
        }
        assert!(
            a_limits.pings_refused() > refused_before,
            "a hidden node must still consult the limiter for refused probes — the counter did \
             not move across 20 of them ({refused_before} → {}), so a revoked peer can flood a \
             hidden node for free",
            a_limits.pings_refused()
        );

        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("throttle-ordering test timed out");
}

/// #89 ask 2: `[network].presence_mode` makes presence REVOCABLE.
///
/// The ping arm is gated by pairing alone, so `service_allow_revoke` never reached it: a peer whose
/// every service was revoked still learned you were online, your RTT, your stack_version and your
/// app metadata, on demand and forever. The only lever was a full unpair.
///
/// The load-bearing assertion is 4 — a refusal must not say WHY. If a hidden node answered
/// distinguishably, a prober would learn "online and deliberately hiding", which is the exact fact
/// the mode withholds.
#[tokio::test(flavor = "multi_thread")]
async fn presence_mode_controls_who_gets_a_pong_and_never_says_why() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("pa.redb")).unwrap());

        // B is PAIRED with A and holds a service grant.
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("pb.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");
        seed_peer(&a_store, b_id, "granted-peer");

        // D is PAIRED with A but holds NO grant — the revoked-peer case.
        let d_ep = dialer_endpoint().await;
        let d_id = *d_ep.id().as_bytes();
        seed_lookup(&d_ep, a_addr.clone());
        let d_store = Arc::new(PeerStore::open(&dir.path().join("pd.redb")).unwrap());
        seed_peer(&d_store, a_id, "alice");
        seed_peer(&a_store, d_id, "revoked-peer");

        // C is a STRANGER — the existing trust-gate refusal, and the reference bytes.
        let c_ep = dialer_endpoint().await;
        seed_lookup(&c_ep, a_addr.clone());

        // One service, admitting B's stable principal only.
        let b_principal = mcpmesh_net::EndpointId::from_bytes(b_id).principal();
        let toml = format!("[services.notes]\nrun = [\"true\"]\nallow = [\"{b_principal}\"]\n");
        // Clones kept so the raw-dial helper can reach each prober's endpoint after the mesh
        // takes ownership.
        let (b_dial, d_dial) = (b_ep.clone(), d_ep.clone());
        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let d_mesh = assemble_mesh(d_ep, d_store, config.clone());
        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str(&toml).unwrap())),
        );

        // The reference refusal: an unpaired stranger, closed by the trust gate.
        let stranger_refusal = ping_refusal_reason(&c_ep, a_id)
            .await
            .expect("an unpaired stranger must never get a pong");
        // Pin the LITERAL, not just mutual equality: three identical dial FAILURES would satisfy
        // "all refusals match" while proving nothing about the anti-oracle property (#89 gate).
        assert_eq!(
            String::from_utf8_lossy(&stranger_refusal),
            "code=401 reason=unauthorized",
            "the reference refusal must be the trust gate's application close, not a dial failure"
        );

        // 1. `paired` (the default) pongs a paired caller EVEN WITH NO GRANT — today's behaviour.
        assert_eq!(a_mesh.presence_mode(), PresenceMode::Paired, "the default");
        assert!(
            probe_peer(&d_mesh, a_id).await.reachable,
            "presence_mode = paired must pong a paired peer holding no grant (today's behaviour)"
        );

        // 2. `granted` pongs the caller WITH a grant, and refuses the one without.
        a_mesh.set_presence_mode(PresenceMode::Granted);
        assert!(
            probe_peer(&b_mesh, a_id).await.reachable,
            "presence_mode = granted must still pong a caller holding a service grant"
        );
        let revoked_refusal = ping_refusal_reason(&d_dial, a_id)
            .await
            .expect("granted must refuse a paired caller holding NO grant — this is the whole ask");

        // 3. `off` refuses even the caller holding a grant — the mode overrides everything.
        a_mesh.set_presence_mode(PresenceMode::Off);
        let off_refusal = ping_refusal_reason(&b_dial, a_id)
            .await
            .expect("presence_mode = off must refuse even a granted caller");

        // 4. THE ANTI-ORACLE PROPERTY. All three refusals are byte-identical, so a prober cannot
        //    tell "not paired" from "hidden" from "no grants" — every one reads as offline.
        assert_eq!(
            revoked_refusal, stranger_refusal,
            "a granted-mode refusal must be byte-identical to the trust gate's, or the prober \
             learns the peer is online and merely ungranted"
        );
        assert_eq!(
            off_refusal, stranger_refusal,
            "an off-mode refusal must be byte-identical to the trust gate's, or 'appear offline' \
             announces itself"
        );
        // 5. And in particular it is never the THROTTLE close, which is distinguishable ON PURPOSE
        //    (#142) — so the policy must be consulted BEFORE the limiter.
        assert!(
            !String::from_utf8_lossy(&off_refusal).contains("ping rate limited"),
            "a hidden node must not leak presence through the throttle close"
        );

        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("presence_mode test timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn ping_probe_reports_paired_peer_reachable_stranger_and_down_peer_not() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // --- Target A: serves the ping arm; its gate trusts B (paired) but not the stranger C. ---
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_ep_handle = a_ep.clone(); // kept so we can close A for the down-peer case
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // --- Prober B: paired with A (A's store trusts B; B's store dials A back as "alice"). ---
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice"); // B's dial-back directory names A "alice"
        seed_peer(&a_store, b_id, "beacon-b"); // A trusts B → its ping arm will pong B

        // --- Stranger C: NOT in A's store → the ping gate must refuse it. ---
        let c_ep = dialer_endpoint().await;
        seed_lookup(&c_ep, a_addr.clone());
        let c_store = Arc::new(PeerStore::open(&dir.path().join("c.redb")).unwrap());

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let c_mesh = assemble_mesh(c_ep, c_store, config.clone());

        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // 1. A PAIRED peer probes A → reachable, with an RTT.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(entry.reachable, "a paired peer's probe must be reachable");
        assert!(
            entry.rtt_ms.is_some(),
            "a reachable probe records a round-trip time"
        );

        // 2. reachability_of projects the cache to the NICKNAME (never the endpoint-id, §1.5) and
        //    returns the cached result immediately (non-blocking).
        let list = reachability_of(&b_mesh);
        let alice = list
            .iter()
            .find(|r| r.name == "alice")
            .expect("reachability_of surfaces the paired peer by nickname");
        assert!(alice.reachable, "the cached probe result is surfaced");
        assert!(alice.rtt_ms.is_some(), "the cached RTT is surfaced");

        // 3. An UNPAIRED endpoint probes A → the trust gate closes it, no pong → NOT reachable.
        let stranger = probe_peer(&c_mesh, a_id).await;
        assert!(
            !stranger.reachable,
            "an unpaired peer gets no pong (trust gate closed the connection)"
        );
        assert!(stranger.rtt_ms.is_none());

        // 4. Take A down (stop accepting + close the endpoint) → B's next probe times out to false.
        accept.abort();
        a_ep_handle.close().await;
        let down = probe_peer(&b_mesh, a_id).await;
        assert!(
            !down.reachable,
            "a probe of a down peer must be unreachable"
        );

        std::mem::forget(dir);
    })
    .await
    .expect("reachability test timed out");
}

/// Task 5: the `status` control response surfaces paired-peer reachability. Drives the REAL
/// `status` request over `mcpmesh-local/1` (a raw `connect_control` client, like
/// `daemon_autostart.rs`) against an in-process daemon whose probe cache was just populated, and
/// asserts the paired peer appears BY NICKNAME in `status.reachability` (§1.5: name + numbers only,
/// never an endpoint-id).
#[tokio::test(flavor = "multi_thread")]
async fn status_includes_reachability() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // Target A serves the ping arm; its gate trusts B.
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // Prober B, paired with A (B's directory names A "alice").
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");
        seed_peer(&a_store, b_id, "beacon-b");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());

        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Populate B's probe cache: A is reachable.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(
            entry.reachable,
            "precondition: the paired peer must probe reachable"
        );

        // Serve B's control API and drive the REAL `status` request over mcpmesh-local/1.
        let socket = dir.path().join("control.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, b_mesh.clone()));
        let control = tokio::spawn(serve_control(listener, state));

        let mut client = connect_control(&socket)
            .await
            .expect("raw connect_control to B");
        let value = client
            .request(Request::Status)
            .await
            .expect("status over mcpmesh-local/1");
        let status: StatusResult =
            serde_json::from_value(value).expect("StatusResult deserializes");

        assert!(
            status.reachability.iter().any(|r| r.name == "alice"),
            "status.reachability must surface the paired peer by nickname: {:?}",
            status.reachability
        );

        control.abort();
        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("status reachability test timed out");
}

/// **The redeemer's cold probe must use the pairing-proven address hint (issue #27, probe arm).**
///
/// `dial_service` already attaches the stored `last_addr` so a cold daemon does not depend on
/// external discovery to reach a paired peer. `probe_peer` was never given the same treatment: it
/// dials the bare endpoint-id, so its reachability answer depends entirely on discovery having
/// already resolved the peer.
///
/// That asymmetry is user-visible and was caught on real hardware. Pairing across two carrier NATs
/// succeeded in ~1s, but `status` on the REDEEMER then reported the peer `offline` while sessions
/// to that same peer worked — because the redeemer's first probe began a fresh id-only dial needing
/// full discovery resolution, which blew the 3s `PROBE_TIMEOUT`. The INVITER, already holding a
/// live path back, probed in 11ms. So the side that just redeemed an invite — precisely the person
/// most likely to run `status` — is told their brand-new peer is offline.
///
/// The invite carries an address the handshake just proved dialable, so the probe never needed
/// discovery at all. This models exactly that: `last_addr` is stored, discovery is NOT seeded
/// (no `seed_lookup`), so an id-only dial cannot resolve the target and only a hint-carrying
/// dial can reach it.
#[tokio::test(flavor = "multi_thread")]
async fn cold_probe_uses_the_pairing_proven_address_hint_without_discovery() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // Target A serves the ping arm and trusts B.
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // Prober B is the REDEEMER: it holds A's pairing-proven address, but NO discovery is
        // seeded — `seed_lookup` is deliberately not called, standing in for a peer that
        // discovery has not resolved yet (the cold, just-paired state).
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer_with_addr(&b_store, a_id, "alice", &a_addr);
        seed_peer(&a_store, b_id, "beacon-b");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        let entry = probe_peer(&b_mesh, a_id).await;

        assert!(
            entry.reachable,
            "a cold probe must reach the peer using the pairing-proven `last_addr` hint rather \
             than depending on discovery to resolve the bare endpoint-id"
        );
        assert!(
            entry.rtt_ms.is_some(),
            "a reachable probe reports a measured RTT"
        );

        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("cold-probe address-hint test timed out");
}

/// #40 — pairing-mode app metadata on the probe pong, end to end: target A sets its app
/// metadata via the REAL `set_app_metadata` control verb; prober B probes A over
/// `mcpmesh/ping/1`, reads the metadata off the pong, and surfaces it per-peer in
/// `reachability_of`. Proves the pairing-mode path #40 adds (no presence gossip involved).
#[tokio::test(flavor = "multi_thread")]
async fn probe_carries_peer_app_metadata_into_reachability() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        // Target A serves the ping arm; its gate trusts B.
        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_eid = format!("eid:{}", a_ep.id());
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());

        // Prober B, paired with A (B names A "alice").
        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");
        seed_peer(&a_store, b_id, "beacon-b");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // A sets its app metadata through the REAL control verb (A's own control server).
        let a_socket = dir.path().join("a-control.sock");
        let a_listener = mcpmesh::ipc::bind_control_socket(&a_socket).await.unwrap();
        let a_state = Arc::new(DaemonState::with_mesh(STACK_VERSION, a_mesh.clone()));
        let a_control = tokio::spawn(serve_control(a_listener, a_state));
        connect_control(&a_socket)
            .await
            .expect("connect A control")
            .set_app_metadata("v=4.2.0")
            .await
            .expect("A sets its app metadata");

        // B probes A → the pong carries A's metadata, surfaced per-peer in reachability.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(entry.reachable, "the paired peer is reachable");
        assert_eq!(
            entry.meta, "v=4.2.0",
            "the probe carried the peer's app metadata off the pong"
        );
        let list = reachability_of(&b_mesh);
        let alice = list.iter().find(|r| r.name == "alice").expect("A surfaced");
        assert_eq!(
            alice.meta, "v=4.2.0",
            "reachability surfaces the peer's app metadata"
        );
        // #42: the row carries A's stable eid principal, so an embedder joins probe + meta on
        // the authenticated endpoint rather than the non-unique nickname.
        assert_eq!(
            alice.principal.as_deref(),
            Some(a_eid.as_str()),
            "reachability row carries the peer's eid principal"
        );

        a_control.abort();
        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("probe-metadata test timed out");
}

/// #52 — a peer's currently-granted services surface on the probe, end to end: A's config grants
/// B's eid a service; B probes A over `mcpmesh/ping/1` and its `ReachEntry.services` reports it,
/// while a service A does NOT grant B is absent (only caller-admitted).
#[tokio::test(flavor = "multi_thread")]
async fn probe_surfaces_the_services_the_peer_grants_the_caller() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();

        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        let b_eid = format!("eid:{}", b_ep.id());
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");

        // A's config: `shared` grants B's eid; `private` grants someone else. A trusts B (ping gate).
        let config = dir.path().join("a-config.toml");
        std::fs::write(
            &config,
            format!(
                "[services.shared]\nsocket = \"/run/s.sock\"\nallow = [\"{b_eid}\"]\n\
                 [services.private]\nsocket = \"/run/p.sock\"\nallow = [\"eid:someoneelse\"]\n"
            ),
        )
        .unwrap();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());
        seed_peer(&a_store, b_id, "beacon-b");
        let a_cfg = Config::load(&config).expect("A's config parses");
        let a_mesh = assemble_mesh(a_ep, a_store, config);
        let b_mesh = assemble_mesh(b_ep, b_store, dir.path().join("b-config.toml"));
        // A's LIVE registry is built from A's OWN config, as a real daemon's boot does. #100 made
        // this load-bearing: the probe answer now comes from the live registry, so a harness that
        // booted an EMPTY registry while claiming config-granted services was asserting a state
        // the daemon reports — deliberately — as not servable.
        let accept = spawn_accept_loop(a_mesh.clone(), Arc::new(build_services(&a_cfg)));

        // B probes A → the pong reports the services A grants B: only `shared`.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(entry.reachable);
        assert_eq!(
            entry.services,
            vec!["shared".to_string()],
            "probe surfaces exactly the caller-admitted services (#52)"
        );
        assert!(
            !entry.services.contains(&"private".to_string()),
            "never a service the peer does not grant the caller"
        );

        accept.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("peer-services probe test timed out");
}

/// #89: the ping accept arm METERS probes per endpoint — pinned at the ARM — and a throttled
/// probe is NOT evidence the peer is down.
///
/// Two properties, deliberately in one flood because each is the other's failure mode:
///
/// 1. **Metering, pinned at the call site.** The limiter's unit test proves the bucket; it does
///    not prove the arm consults it. A refused probe now returns the prober's CACHED entry
///    (same `seq`), so "some probe came back stale" is the enforcement — removing `admit_ping`
///    from the arm, or ignoring its verdict, answers all 90 with fresh pongs and fails the
///    stale-count assertion.
/// 2. **A refusal with a warm cache never reports a healthy peer offline** (PR #142 gate, HIGH).
///    The arm closes with the distinguishable `b"ping rate limited"` and the prober commits
///    NOTHING for it — no cache write, no transition. Reverting the close reason to
///    `b"unauthorized"`, or dropping the prober-side throttle check, writes `reachable: false`
///    for a live paired peer and fails the all-reachable assertion.
///
/// "Warm cache" is a real bound, not hedging: a throttled probe with NO previous entry returns
/// an uncommitted `reachable: false` row (never cached, never broadcast), so a caller CAN see a
/// transient "unreachable" for a live peer in the cold-cache + pre-drained-bucket corner — e.g.
/// a daemon restart inside the responder bucket's 600s idle TTL. Bounded (retry after refill
/// succeeds; nothing is poisoned) and accepted; this test's first probe is always admitted, so
/// it deliberately does not exercise that corner.
#[tokio::test(flavor = "multi_thread")]
async fn a_throttled_probe_is_refused_but_never_reports_the_peer_offline() {
    // Serialized (the #138 idiom): 90 sequential real dials against a 3s per-probe deadline —
    // ONE admitted probe blowing PROBE_TIMEOUT under parallel-test contention would commit a
    // real `reachable: false` and fail the all-reachable assertion for a reason this test is
    // not about.
    let _serial = SERIAL.lock().await;
    timeout(Duration::from_secs(120), async {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(&config, "").unwrap();

        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("fa.redb")).unwrap());

        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("fb.redb")).unwrap());

        // A trusts B, so every refusal below is the LIMITER, never the gate.
        seed_peer(&a_store, b_id, "b");
        seed_peer(&b_store, a_id, "a");

        let a_mesh = assemble_mesh(a_ep, a_store, config.clone());
        // MUST set limits explicitly: `MeshState::limits()` falls back to `unlimited()` on a
        // OnceCell miss, so without this the accept arm consults an unlimited bucket and this test
        // cannot distinguish a working limiter from an absent one. That fail-open accessor is worth
        // fixing in its own right (flagged in #84a's review) — a security control defaulting to
        // "no limits" on a wiring mistake.
        let a_limits =
            mcpmesh::limits::MeshLimiters::from_config(&mcpmesh::config::LimitsCfg::default());
        a_mesh.set_limits(a_limits.clone());
        let b_mesh = assemble_mesh(b_ep, b_store, config.clone());
        let _accept = spawn_accept_loop(
            a_mesh.clone(),
            Arc::new(build_services(&Config::from_toml_str("").unwrap())),
        );

        // Probe well past the per-minute cap. An ADMITTED probe writes a fresh cache entry (new
        // `seq`); a REFUSED one returns the previous entry untouched — so `seq` staying put is the
        // observable for "the arm refused us and the prober treated it as non-evidence".
        let mut reachable = 0usize;
        let mut fresh = 0usize;
        let mut stale = 0usize;
        let mut last_seq: Option<u64> = None;
        for _ in 0..90 {
            let entry = probe_peer(&b_mesh, a_id).await;
            if entry.reachable {
                reachable += 1;
            }
            if last_seq == Some(entry.seq) {
                stale += 1;
            } else {
                fresh += 1;
            }
            last_seq = Some(entry.seq);
        }

        assert_eq!(
            reachable, 90,
            "a rate-limit refusal is not evidence the peer is down: every probe of a live, paired \
             peer must report reachable — the refused ones from the still-fresh cache. A false \
             count here means a refusal wrote `reachable: false` (PR #142 gate, HIGH). \
             reachable={reachable} fresh={fresh} stale={stale}"
        );
        // No separate `fresh > 0` assertion: it cannot test "real pongs were admitted" — the
        // first iteration always counts fresh (`last_seq == None`), and a refuse-everything
        // limiter over a cold cache yields fresh=90 (every uncommitted fallback row carries a
        // new seq). The refuse-everything mutation is caught by `reachable == 90` instead: with
        // nothing ever admitted the cache never warms, so every probe reports unreachable.
        assert!(
            stale > 0,
            "a paired peer flooding past the cap must eventually be REFUSED (#89), observable as \
             the cached entry returned unchanged. Zero stale answers means the accept arm never \
             consulted the limiter — the unmetered pong-flood this issue reports. \
             fresh={fresh} stale={stale}"
        );
        assert!(
            a_limits.pings_refused() > 0,
            "the responder must COUNT its refusals (#89 defect 3: unmetered AND unrecorded) — \
             the count is the refusal's only footprint besides the debug log"
        );
    })
    .await
    .expect("ping flood test timed out");
}

/// PR #142 gate (21df648's stated gap): `peer_services` answers from the FRESH cache rather than
/// probing unconditionally — pinned at the call site, through the real control verb.
///
/// B probes A while A is up (cache populated, carrying the service A grants B), then A goes DOWN,
/// then B's `peer_services` runs inside `REACH_TTL_SECS`. It must succeed from the cache: the
/// verb's freshness contract is "no staler than `status` would report", not "a fresh probe".
/// Reverting `probe_peer_cached` to `probe_peer` in the handler probes the dead peer and fails
/// the verb — which is also the shape that made the verb collide with the ping limiter and
/// report healthy peers offline.
#[tokio::test(flavor = "multi_thread")]
async fn peer_services_answers_from_the_fresh_cache_without_probing() {
    // Serialized (the #138 idiom): everything from the priming probe to the verb call must fit
    // inside REACH_TTL_SECS, and contention eats that margin.
    let _serial = SERIAL.lock().await;
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();

        let a_ep = target_endpoint().await;
        let a_id = *a_ep.id().as_bytes();
        let a_addr = a_ep.addr();
        let a_ep_handle = a_ep.clone();

        let b_ep = dialer_endpoint().await;
        let b_id = *b_ep.id().as_bytes();
        let b_eid = format!("eid:{}", b_ep.id());
        seed_lookup(&b_ep, a_addr.clone());
        let b_store = Arc::new(PeerStore::open(&dir.path().join("b.redb")).unwrap());
        seed_peer(&b_store, a_id, "alice");

        // A grants B the `shared` service (the #52 arrangement), and trusts B at the ping gate.
        let config = dir.path().join("a-config.toml");
        std::fs::write(
            &config,
            format!("[services.shared]\nsocket = \"/run/s.sock\"\nallow = [\"{b_eid}\"]\n"),
        )
        .unwrap();
        let a_store = Arc::new(PeerStore::open(&dir.path().join("a.redb")).unwrap());
        seed_peer(&a_store, b_id, "beacon-b");
        let a_cfg = Config::load(&config).expect("A's config parses");
        let a_mesh = assemble_mesh(a_ep, a_store, config);
        let b_mesh = assemble_mesh(b_ep, b_store, dir.path().join("b-config.toml"));
        let accept = spawn_accept_loop(a_mesh.clone(), Arc::new(build_services(&a_cfg)));

        // Populate B's cache with a real probe while A is up.
        let entry = probe_peer(&b_mesh, a_id).await;
        assert!(entry.reachable, "precondition: A must probe reachable");
        assert_eq!(
            entry.services,
            vec!["shared".to_string()],
            "precondition: the cached entry carries the granted service"
        );

        // Stand up B's control server and client BEFORE taking A down, so the TTL margin is
        // spent only on the teardown + one verb round-trip, not on socket setup too.
        let socket = dir.path().join("control.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, b_mesh.clone()));
        let control = tokio::spawn(serve_control(listener, state));
        let mut client = connect_control(&socket).await.expect("connect B control");

        // Take A DOWN. The cache entry is still younger than REACH_TTL_SECS.
        accept.abort();
        a_ep_handle.close().await;

        // The real control verb must answer from the cache — a probe here would dial a dead
        // endpoint, time out, and fail the verb for a peer the caller was just told is fine.
        let services = client.peer_services("alice").await.expect(
            "peer_services must answer from the fresh cache rather than probing — an \
                 unconditional probe is the #142-gate shape that reported healthy peers offline",
        );
        assert_eq!(services, vec!["shared".to_string()]);

        control.abort();
        std::mem::forget(dir);
    })
    .await
    .expect("peer_services cache-freshness test timed out");
}
