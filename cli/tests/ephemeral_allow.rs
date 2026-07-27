//! #55 / #69: `service_allow_grant` and `service_allow_revoke` work on EPHEMERAL services.
//!
//! An ephemeral registration (#36) keeps its `allow` in memory only. Both verbs edited
//! `config.toml`, found no `[services.<name>]` entry, and returned `{}` — so a grant admitted
//! nobody and a revoke was undone by the next hot-reload's overlay, both while reporting success.
//!
//! These tests drive the REAL `grant_service_access` / `revoke_service_allow` pipelines against a
//! real in-process accept loop, so they also pin the #54 live-registry behavior for the ephemeral
//! path: a grant reaches an ALREADY-OPEN connection, and a revoke severs it.

use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{
    EphemeralService, MeshState, build_services, grant_service_access, grant_service_allow,
    revoke_service_allow, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, MAX_FRAME_BYTES, SessionTransport, TrustGate, framing::write_frame};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

async fn server_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind server endpoint")
}

async fn client_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind client endpoint")
}

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

/// A mesh with ONE paired peer and ONE **ephemeral** service `room` that admits nobody yet.
/// The config carries an unrelated `[services.kept]` so the config path is exercised alongside.
async fn mesh_with_ephemeral_room() -> (
    Arc<MeshState>,
    iroh::EndpointAddr,
    iroh::Endpoint,
    String,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());

    let peer = client_endpoint().await;
    let principal = format!("eid:{}", peer.id());
    store
        .add(PeerEntry {
            endpoint_id: *peer.id().as_bytes(),
            nickname: "alice".into(),
            services: vec!["room".into()],
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();

    let config_path = dir.path().join("config.toml");
    let toml = format!("[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n");
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
        conn_registry,
        None,
        None,
        None,
        None,
    );

    // The ephemeral service: in-memory only, admitting nobody yet.
    mesh.register_ephemeral(
        "room".to_string(),
        EphemeralService {
            backend: mcpmesh_local_api::BackendSpec::Run {
                cmd: vec![STUB.to_string()],
                env: Default::default(),
                cwd: None,
            },
            allow: vec![],
        },
    );

    // Start from the CONFIG-only registry. Every grant/revoke below runs the real
    // `reload_services_from_disk`, which re-overlays the ephemeral map — so the overlay path is
    // exercised for real rather than pre-baked here.
    mesh.set_accept_task(spawn_accept_loop(
        mesh.clone(),
        Arc::new(build_services(&cfg)),
    ))
    .await;
    (mesh, addr, peer, principal, dir)
}

async fn dial(client: &iroh::Endpoint, addr: iroh::EndpointAddr) -> iroh::endpoint::Connection {
    client.connect(addr, ALPN_MCP).await.expect("dial mesh")
}

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

async fn session_served(t: Option<&mut SessionTransport>) -> bool {
    let Some(t) = t else { return false };
    match timeout(Duration::from_secs(5), t.recv_value()).await {
        Ok(Ok(Some(v))) => v["result"]["serverInfo"]["name"] == "echo-stub",
        _ => false,
    }
}

/// #55: granting on an ephemeral service actually admits the peer — and does so on a connection
/// that is ALREADY open (the #54 live registry, via the ephemeral overlay).
#[tokio::test]
async fn granting_an_ephemeral_service_admits_the_peer() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        let conn = dial(&peer, addr).await;

        let mut before = open_session(&conn, "room").await;
        assert!(
            !session_served(before.as_mut()).await,
            "not served before the grant (setup) — the ephemeral service is not in the registry \
             yet and admits nobody"
        );

        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant succeeds");

        let mut after = open_session(&conn, "room").await;
        assert!(
            session_served(after.as_mut()).await,
            "a grant on an EPHEMERAL service must actually admit the peer — this returned success \
             and admitted nobody before #55"
        );
    })
    .await
    .expect("ephemeral grant test timed out");
}

/// #69: revoking on an ephemeral service actually withdraws access — and severs the live
/// connection, rather than being undone by the next hot-reload's overlay.
#[tokio::test]
async fn revoking_an_ephemeral_service_withdraws_access_and_severs() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant succeeds");

        let conn = dial(&peer, addr.clone()).await;
        let mut session = open_session(&conn, "room").await;
        assert!(session_served(session.as_mut()).await, "served after grant");

        revoke_service_allow(&mesh, "room".into(), principal.clone())
            .await
            .expect("revoke succeeds");

        // The live connection is cut (#54's sever, now reachable for ephemeral services)...
        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("an ephemeral revoke must sever the live connection");

        // ...and a fresh connection is refused, proving the in-memory allow really changed and was
        // not restored by the reload overlay.
        let conn2 = dial(&peer, addr).await;
        let mut after = open_session(&conn2, "room").await;
        assert!(
            !session_served(after.as_mut()).await,
            "a revoked principal must not be re-admitted by the ephemeral overlay"
        );
    })
    .await
    .expect("ephemeral revoke test timed out");
}

/// The pairing ceremony stays LENIENT: an unknown service name in the list must not fail the
/// grant, and the known ones must still be granted. Only the single-service verb is strict.
#[tokio::test]
async fn the_pairing_grant_still_tolerates_an_unknown_service() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;

        grant_service_access(
            &mesh,
            &principal,
            &principal,
            &["room".to_string(), "no-such-service".to_string()],
        )
        .await
        .expect("a pairing grant must not fail on an unknown service name");

        let conn = dial(&peer, addr).await;
        let mut s = open_session(&conn, "room").await;
        assert!(
            session_served(s.as_mut()).await,
            "the KNOWN service in the list must still have been granted"
        );
    })
    .await
    .expect("lenient pairing grant test timed out");
}

/// An unrelated grant must not drop the ephemeral registration — the overlay-survives-a-swap
/// regression the #54 review flagged as untested.
#[tokio::test]
async fn an_ephemeral_registration_survives_an_unrelated_swap() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant room");

        // A grant against the CONFIG service for a DIFFERENT principal — so the config append
        // really changes something and a full reload+swap actually fires. Re-granting `principal`
        // here would be idempotent (`changed == false`), no swap would happen, and this test would
        // pass without ever exercising the overlay (caught in review).
        grant_service_access(
            &mesh,
            "eid:0000000000000000000000000000000000000000000000000000000000000000",
            "someone-else",
            &["kept".to_string()],
        )
        .await
        .expect("grant kept");

        let conn = dial(&peer, addr).await;
        let mut s = open_session(&conn, "room").await;
        assert!(
            session_served(s.as_mut()).await,
            "the ephemeral service (and its granted allow) must survive an unrelated config swap"
        );
    })
    .await
    .expect("overlay survival test timed out");
}

/// #94's central safety question. A name held by BOTH an ephemeral registration and `config.toml`
/// must have the principal stripped from BOTH — the #55 review's finding, and the reason
/// `revoke_service_allow` does NOT take an ephemeral fast path even though it has already computed
/// `is_ephemeral`.
///
/// Stripping only the shadowing overlay leaves the config copy holding the principal: invisible
/// while the overlay shadows it, then LIVE with the stale allow the instant the registering control
/// connection drops the ephemeral entry. The revoke reported success; the peer walks back in.
///
/// This test fails if the config pass is skipped for an ephemeral name — the exact optimization
/// #94 asked for.
#[tokio::test]
async fn a_revoke_strips_a_name_held_by_both_config_and_the_overlay() {
    timeout(Duration::from_secs(90), async {
        let (mesh, addr, peer, principal, dir) = mesh_with_ephemeral_room().await;

        // `room` now exists in BOTH places, with the principal in each: the hand-edited config
        // under the live ephemeral registration.
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.room]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();
        grant_service_access(&mesh, &principal, "alice", &["room".to_string()])
            .await
            .expect("grant");

        revoke_service_allow(&mesh, "room".to_string(), principal.clone())
            .await
            .expect("revoke");

        // Locate a failure rather than just observing one: the config strip is the step this test
        // exists to protect, so assert it directly before going over the wire. If THIS fires, the
        // config pass regressed; if only the wire assertion below fires, the registry did.
        let on_disk = std::fs::read_to_string(&config_path).expect("read config back");
        let room_section = on_disk
            .split("[services.room]")
            .nth(1)
            .expect("room section present");
        assert!(
            !room_section.contains(&principal),
            "the revoke must strip the principal from the CONFIG copy too — config after \
             revoke:\n{on_disk}"
        );

        // Drop the overlay. The config copy is now the live one — and must NOT admit the peer.
        mcpmesh::daemon::unregister_ephemeral(&mesh, &["room".to_string()]).await;

        // The reload inside `unregister_ephemeral` only WARNS on failure, so assert the live
        // registry really reflects the strip — otherwise a silently-failed reload would look
        // identical to a correct denial.
        let live = mesh.live_services();
        let room_allow = live.get("room").map(|e| e.allow.clone());
        assert_eq!(
            room_allow,
            Some(Vec::<String>::new()),
            "after dropping the overlay, the live `room` must be the CONFIG entry with an empty \
             allow (got {room_allow:?})"
        );

        let conn = dial(&peer, addr).await;
        let mut t = open_session(&conn, "room").await;
        assert!(
            !session_served(t.as_mut()).await,
            "the config copy of a both-held name must not survive the revoke — this is #55's \
             defect: a revoke that reported success, then re-admitted the peer the moment the \
             ephemeral registration dropped"
        );
    })
    .await
    .expect("both-held revoke test timed out");
}

/// #94 changes behaviour in one visible way, and this pins it: an allow edit that lands only in the
/// ephemeral overlay no longer rebuilds the registry from disk, so it no longer picks up unrelated
/// edits to `config.toml` as a side effect.
///
/// That side effect was incidental, not contractual — applying an operator's unrelated, possibly
/// half-finished config edit because someone was granted access to a different service is
/// surprising. `register_service` and the explicit reload remain the ways to pick config up.
///
/// Scoped to `service_allow_grant`/`service_allow_revoke`, the two verbs #94 names. The
/// multi-service PAIRING grant (`grant_service_access`) still rebuilds from disk — see the
/// regression test below, which pins that it was not changed by accident.
#[tokio::test]
async fn an_overlay_only_grant_does_not_apply_an_unrelated_config_edit() {
    timeout(Duration::from_secs(90), async {
        let (mesh, addr, peer, principal, dir) = mesh_with_ephemeral_room().await;

        // First grant: `room` is not in the live registry yet (the harness boots config-only), so
        // this one legitimately rebuilds — `with_allow_replaced` refuses to invent an entry.
        grant_service_allow(&mesh, "room".to_string(), "b64u:carol".to_string())
            .await
            .expect("first grant");

        // A new config service appears on disk AFTER that, unrelated to the grant below.
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.late]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();

        // Second grant, on the SAME already-live ephemeral service. Nothing changes on disk, so
        // this takes the targeted-swap path — and it grants the peer we then dial with, so the
        // assertion below fails if the swap does not reach the live registry.
        grant_service_allow(&mesh, "room".to_string(), principal.clone())
            .await
            .expect("second grant");

        let conn = dial(&peer, addr).await;
        let mut room = open_session(&conn, "room").await;
        assert!(
            session_served(room.as_mut()).await,
            "the targeted swap must reach the live registry — this grant never touched disk"
        );

        let mut late = open_session(&conn, "late").await;
        assert!(
            !session_served(late.as_mut()).await,
            "an overlay-only grant must NOT hot-load an unrelated config service — the disk \
             reload is deliberately skipped (#94)"
        );
    })
    .await
    .expect("unrelated config edit test timed out");
}

/// A revoke leaves the LIVE registry denying by the time it returns — on the #94 fast path, where
/// the deny comes from the targeted swap rather than a rebuild.
///
/// **What this does NOT prove, stated because the obvious reading is wrong:** it does not pin
/// #54's SWAP-BEFORE-SEVER *ordering*. Moving the swap after `sever_principal` still passes this
/// test — verified by mutation, not assumed — because by the time the verb returns both have
/// happened either way. Ordering is only observable from inside the verb, and pinning it needs a
/// test seam this change does not add. Tracked separately; the ordering itself is still correct in
/// the code (`handlers.rs`), just not test-enforced.
///
/// What it does catch: a fast path that severs but never installs the new registry, which would
/// leave the principal admitted on the next dial.
#[tokio::test]
async fn a_revoke_leaves_the_live_registry_denying_when_it_returns() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant");

        let conn = dial(&peer, addr).await;
        let mut session = open_session(&conn, "room").await;
        assert!(session_served(session.as_mut()).await, "served after grant");

        revoke_service_allow(&mesh, "room".into(), principal.clone())
            .await
            .expect("revoke");

        // The verb has returned, so the sever has run. The registry it severed against must
        // already have been the post-revoke one: a session opened right now — on the connection
        // that was live throughout — must be refused by the LIVE registry, not by the sever.
        let live = mesh.live_services();
        let room_allow = live.get("room").map(|e| e.allow.clone());
        assert_eq!(
            room_allow,
            Some(Vec::<String>::new()),
            "the revoke must leave the live registry denying — a fast path that severed without \
             installing the new registry would re-admit on the next dial (got {room_allow:?})"
        );
    })
    .await
    .expect("registry-denies-on-return test timed out");
}

/// #99: #54's SWAP-BEFORE-SEVER ordering, pinned deterministically.
///
/// `revoke_service_allow` must install the new registry BEFORE cutting live connections. Swap
/// first and no NEW session can be admitted under the pre-revoke allow while the in-flight ones
/// are being cut; sever first and there is a window where the peer just cut can redial into a
/// registry that still admits it.
///
/// The ordering is invisible from outside the verb — by the time it returns, both have happened
/// (see `a_revoke_leaves_the_live_registry_denying_when_it_returns`, which does NOT catch a
/// reversal). So observe from INSIDE: the sever observer fires at the top of the sever, and
/// records what the live registry admitted at that instant.
#[tokio::test]
async fn the_registry_already_denies_at_the_moment_of_the_sever() {
    timeout(Duration::from_secs(60), async {
        let (mesh, addr, peer, principal, _dir) = mesh_with_ephemeral_room().await;
        grant_service_access(&mesh, &principal, &principal, &["room".to_string()])
            .await
            .expect("grant");

        let conn = dial(&peer, addr).await;
        let mut session = open_session(&conn, "room").await;
        assert!(session_served(session.as_mut()).await, "served after grant");

        // Capture the live `room` allow at the exact instant EVERY sever begins — not just the
        // last. A reversal that severs twice would otherwise hide the stale first observation
        // behind a fresh second one, which is how the first version of this test went vacuous.
        let seen: Arc<std::sync::Mutex<Vec<Vec<String>>>> = Arc::new(std::sync::Mutex::new(vec![]));
        let sink = seen.clone();
        mesh.set_sever_observer(move |live| {
            sink.lock().expect("observer sink not poisoned").push(
                live.get("room")
                    .map(|e| e.allow.clone())
                    .unwrap_or_default(),
            );
        });

        revoke_service_allow(&mesh, "room".into(), principal.clone())
            .await
            .expect("revoke");

        let observed = seen.lock().expect("observer sink not poisoned").clone();
        assert!(
            !observed.is_empty(),
            "the revoke must have severed, firing the observer"
        );
        for at_sever in &observed {
            assert!(
                at_sever.is_empty(),
                "the new registry must be installed BEFORE every sever — at one sever `room` \
                 still admitted {at_sever:?}, so a peer cut by that sever could have redialled \
                 straight back in (all observations: {observed:?})"
            );
        }
    })
    .await
    .expect("swap-before-sever test timed out");
}

/// #100: `peer_services` must not report a service the accept path would refuse.
///
/// It answered from `config.toml` + the ephemeral map, while admission comes from the LIVE
/// registry. A config service added by hand and not yet reloaded was reported as usable and then
/// refused — indistinguishable, from the caller's side, from a transient network failure.
///
/// #94 made this durable rather than incidental: an overlay-only grant no longer reloads, so the
/// hand-added service stays reported-but-unservable indefinitely.
#[tokio::test]
async fn peer_services_does_not_report_a_config_service_pending_a_reload() {
    timeout(Duration::from_secs(60), async {
        let (mesh, _addr, peer, principal, dir) = mesh_with_ephemeral_room().await;

        // Get `room` live (first grant rebuilds — it is not in the registry yet).
        grant_service_allow(&mesh, "room".to_string(), principal.clone())
            .await
            .expect("first grant");

        // A config service appears on disk afterwards and is never reloaded.
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.late]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();
        // Overlay-only grant: nothing changes on disk, so nothing reloads (#94).
        grant_service_allow(&mesh, "room".to_string(), "b64u:carol".to_string())
            .await
            .expect("second grant");

        let identity = mcpmesh_net::PeerIdentity {
            endpoint: mcpmesh_net::EndpointId::from_bytes(*peer.id().as_bytes()),
            name: "alice".into(),
            user_id: None,
            groups: vec![],
        };
        let admitted = mcpmesh::daemon::admitted_services_for_test(&mesh, &identity);

        assert!(
            admitted.contains(&"room".to_string()),
            "the live ephemeral service must still be reported (got {admitted:?})"
        );
        // Positive control on the CONFIG path: without this, an implementation that answered only
        // from the ephemeral map would still pass. `kept` is a config service in the live registry
        // whose allow admits this caller.
        assert!(
            admitted.contains(&"kept".to_string()),
            "a LIVE config service that admits the caller must still be reported (got {admitted:?})"
        );
        assert!(
            !admitted.contains(&"late".to_string()),
            "a config service that is not in the live registry must NOT be reported as usable — \
             the accept path would refuse it, and the caller cannot tell that from a network \
             failure (got {admitted:?})"
        );
    })
    .await
    .expect("peer_services live-registry test timed out");
}

/// #100: `status` is a separate code path from `peer_services` and was separately wrong — it also
/// answered from `config.toml`. Same setup, distinct assertion.
///
/// Also pins the deliberate split: `mint_invite` keeps the KNOWN-names view, so an invite for a
/// config service pending a reload must still mint. Switching that to the live registry would
/// reject an invite for a service the operator has just added.
#[tokio::test]
async fn status_hides_a_pending_service_but_an_invite_can_still_name_it() {
    timeout(Duration::from_secs(60), async {
        let (mesh, _addr, _peer, principal, dir) = mesh_with_ephemeral_room().await;
        grant_service_allow(&mesh, "room".to_string(), principal.clone())
            .await
            .expect("first grant");
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.late]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();
        grant_service_allow(&mesh, "room".to_string(), "b64u:carol".to_string())
            .await
            .expect("second grant");

        let listed = mcpmesh::daemon::service_infos_for_test(&mesh);
        let names: Vec<&str> = listed.iter().map(|s| s.name.as_str()).collect();
        assert!(
            !names.contains(&"late"),
            "status must not list a config service absent from the live registry (got {names:?})"
        );
        assert!(
            names.contains(&"room"),
            "the live ephemeral service must still be listed (got {names:?})"
        );

        // Metadata survives the move to the live registry: `room` is ephemeral, `kept` is not.
        let room = listed.iter().find(|s| s.name == "room").expect("room");
        assert!(
            room.ephemeral,
            "an ephemeral registration must report as such"
        );
        let kept = listed.iter().find(|s| s.name == "kept").expect("kept");
        assert!(
            !kept.ephemeral,
            "a config service must not report as ephemeral"
        );

        // The split: an invite may still name the not-yet-live config service.
        mcpmesh::daemon::mint_invite_for_test(&mesh, &["late".to_string()])
            .await
            .expect(
                "mint_invite must accept a config service pending a reload — an invite is \
                 redeemed later, after reloads",
            );
        // ...and still REJECT a name in neither source. Without this, dropping the existence
        // check entirely (or returning a superset) would pass the positive case above.
        mcpmesh::daemon::mint_invite_for_test(&mesh, &["nope".to_string()])
            .await
            .expect_err(
                "mint_invite must still reject a service in neither config nor the overlay",
            );
    })
    .await
    .expect("status live-registry test timed out");
}

/// #100 metadata, the two cases the first round of tests missed.
///
/// 1. **Overlay precedence.** A name held by BOTH config and an ephemeral registration must report
///    `ephemeral: true` — the live entry IS the overlay's (`build_services_with_ephemeral` inserts
///    it last). With no both-held name in the fixture, inverting the precedence went undetected.
/// 2. **`BackendKind::Socket`.** Every earlier fixture used a `run` backend, so the socket arm had
///    zero coverage and could have returned `Run` unnoticed.
#[tokio::test]
async fn status_metadata_honours_overlay_precedence_and_the_socket_backend() {
    timeout(Duration::from_secs(90), async {
        let (mesh, _addr, _peer, principal, dir) = mesh_with_ephemeral_room().await;

        // `room` exists in config too — with a DIFFERENT backend shape, so a precedence inversion
        // shows up in `backend` as well as in the `ephemeral` flag.
        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.room]\nsocket = \"/run/room.sock\"\nallow = [\"{principal}\"]\n\
                 [services.sock]\nsocket = \"/run/s.sock\"\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();
        // A config-changing grant forces the real rebuild, so the registry sees all three.
        grant_service_allow(&mesh, "sock".to_string(), "b64u:carol".to_string())
            .await
            .expect("grant on the socket service");

        let listed = mcpmesh::daemon::service_infos_for_test(&mesh);
        let room = listed.iter().find(|s| s.name == "room").expect("room");
        assert!(
            room.ephemeral,
            "a name held by BOTH sources must report the OVERLAY's entry — the overlay is what the \
             accept path serves"
        );
        assert_eq!(
            room.backend,
            mcpmesh_local_api::BackendKind::Run,
            "and the overlay's BACKEND SHAPE too — config declares this name as a socket, the \
             ephemeral registration as run, and the registry holds the latter"
        );

        let sock = listed.iter().find(|s| s.name == "sock").expect("sock");
        assert_eq!(
            sock.backend,
            mcpmesh_local_api::BackendKind::Socket,
            "a socket-backed config service must report Socket, not Run"
        );
        assert!(!sock.ephemeral, "a config service is not ephemeral");
    })
    .await
    .expect("status metadata test timed out");
}

/// #100 withholds only what is genuinely not live: after a REAL reload the previously-pending
/// config service IS reported. Without this, an implementation that simply never reported config
/// services would pass every other test here.
#[tokio::test]
async fn a_pending_config_service_is_reported_once_it_is_actually_live() {
    timeout(Duration::from_secs(90), async {
        let (mesh, _addr, _peer, principal, dir) = mesh_with_ephemeral_room().await;
        grant_service_allow(&mesh, "room".to_string(), principal.clone())
            .await
            .expect("first grant");

        std::fs::write(
            dir.path().join("config.toml"),
            format!(
                "[services.kept]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n\
                 [services.late]\nrun = ['{STUB}']\nallow = [\"{principal}\"]\n"
            ),
        )
        .unwrap();
        // Overlay-only grant: no reload, so `late` is still not live.
        grant_service_allow(&mesh, "room".to_string(), "b64u:carol".to_string())
            .await
            .expect("overlay-only grant");
        let before = mcpmesh::daemon::service_infos_for_test(&mesh);
        assert!(
            !before.iter().any(|s| s.name == "late"),
            "not live yet, so not reported"
        );

        // A CONFIG-changing grant takes the rebuild path, making `late` genuinely live.
        grant_service_allow(&mesh, "late".to_string(), "b64u:dave".to_string())
            .await
            .expect("config grant reloads");

        let after = mcpmesh::daemon::service_infos_for_test(&mesh);
        assert!(
            after.iter().any(|s| s.name == "late"),
            "once the registry actually holds it, it MUST be reported — #100 withholds only what \
             is not live, it does not stop reporting config services (got {:?})",
            after.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    })
    .await
    .expect("pending-then-live test timed out");
}
