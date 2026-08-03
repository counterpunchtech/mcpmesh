//! M2b Task 5 acceptance: the INVITER-side pairing rendezvous
//! ([`mcpmesh::pairing::rendezvous::handle_inviter_side`]) over ALPN `mcpmesh/pair/1`, driven
//! against a REAL localhost endpoint pair (relay disabled → hermetic, no network egress), the
//! same in-process style as `daemon_dispatch.rs`. The inviter runs the daemon's OWN accept loop
//! ([`spawn_accept_loop`]) so the pair ALPN is routed exactly as production routes it; a
//! hand-driven redeemer dials pair/1, opens a bi-stream, sends a `RedeemerHello`, and reads the
//! reply. We assert the redemption PROTOCOL: the trust grant is written on success (T5 scope —
//! the `[services.*].allow` authorization grant is T6), the inviter identity is returned, the
//! SAS computes order-independently, and every refusal path writes NO entry and leaks NO peer
//! EndpointId (surface discipline, spec §1.5/§4.2/P3).
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{MeshState, build_services, spawn_accept_loop};
use mcpmesh::pairing::rendezvous::{GrantBackFn, SelfBinding, redeem_invite};
use mcpmesh::pairing::sas::short_auth_code;
use mcpmesh::pairing::{Invite, LiveInvites};
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use serde_json::{Value, json};
use tokio::io::BufReader;
use tokio::time::timeout;

const MAX_PAIR_FRAME: usize = 64 * 1024;

/// The hermetic echo MCP stub (echoes `tools/call` payloads + `getenv("MCPMESH_PEER_NAME")`) —
/// the same served child the mesh-session tests use, for the E2E admission proof.
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// A localhost-only inviter endpoint advertising both mesh + pair ALPNs (mirrors the daemon's
/// `build_endpoint` list so the accept loop routes as production does).
async fn inviter_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind inviter endpoint")
}

/// A localhost-only redeemer endpoint. It never *accepts* pair connections; the ALPN it *dials*
/// is chosen per-connect, so advertising only the mesh ALPN is fine.
async fn redeemer_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind redeemer endpoint")
}

/// Build a synthetic live invite for a known secret (the T5 tests mint directly via
/// `LiveInvites::mint`, not through the daemon's `mint_invite`, which is covered separately).
fn make_invite(
    secret: [u8; 32],
    inviter_id: [u8; 32],
    services: &[&str],
    expires_at_epoch: u64,
) -> Invite {
    Invite {
        secret,
        inviter_id,
        inviter_addr_json: "{}".into(), // unused by the inviter side; T6 dials it
        nickname: "alice".into(),
        services: services.iter().map(|s| s.to_string()).collect(),
        expires_at_epoch,
        app_label: None,
        uses_remaining: 1,
        peer_nickname: None,
    }
}

fn hello_frame(secret: &[u8; 32], redeemer_id: &[u8; 32], nickname: &str) -> Value {
    json!({
        "secret": secret.to_vec(),
        "redeemer_id": redeemer_id.to_vec(),
        "redeemer_nickname": nickname,
    })
}

/// Drive a full redeemer exchange over pair/1: dial, open a bi-stream, send `hello`, read the
/// single reply frame, and return it as a raw JSON value. The `conn` is held until after the
/// reply is read (dropping it early would tear the streams down).
async fn drive_redeemer(
    redeemer: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
    hello: Value,
) -> Value {
    let conn = redeemer
        .connect(addr, ALPN_PAIR)
        .await
        .expect("dial pair/1");
    let (mut send, recv) = conn.open_bi().await.expect("open bi-stream");
    write_frame(&mut send, &hello).await.expect("send hello");
    let _ = send.finish();
    let mut reader = FrameReader::new(BufReader::new(recv), MAX_PAIR_FRAME);
    let reply = match reader.next().await.expect("read reply frame") {
        Some(Inbound::Frame(v)) => v,
        other => panic!("expected a reply frame, got {other:?}"),
    };
    drop(conn);
    reply
}

/// Assemble an inviter running the daemon's accept loop over a fresh store + shared invite
/// registry, returning (redeemer endpoint, inviter addr, store, invites, inviter id). Empty
/// config — the T5 refusal/trust assertions grant into no service.
async fn setup() -> (
    iroh::Endpoint, // redeemer
    iroh::EndpointAddr,
    Arc<PeerStore>,
    Arc<LiveInvites>,
    [u8; 32], // inviter id
) {
    let (redeemer, addr, store, invites, inviter_id, _cfg) = setup_full("").await;
    (redeemer, addr, store, invites, inviter_id)
}

/// Like [`setup`], but writes `config_toml` to the inviter's `config_path` first (so the
/// nickname-collision orphan-allow check + the grant can read real `[services.*].allow` entries)
/// and ALSO returns that `config_path` so a test can re-read it after a grant. The store is the
/// SAME `Arc` the accept-loop handler reads, so a test can pre-seed peers into it.
async fn setup_full(
    config_toml: &str,
) -> (
    iroh::Endpoint, // redeemer
    iroh::EndpointAddr,
    Arc<PeerStore>,
    Arc<LiveInvites>,
    [u8; 32], // inviter id
    std::path::PathBuf,
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("state.redb");
    let config_path = dir.path().join("config.toml");
    if !config_toml.is_empty() {
        std::fs::write(&config_path, config_toml).unwrap();
    }
    let store = Arc::new(PeerStore::open(&db_path).unwrap());
    // Leak the tempdir handle so the redb file + config outlive this helper (the store keeps the
    // redb open; the test process is short-lived — the OS reclaims the temp dir).
    std::mem::forget(dir);
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    let invites = Arc::new(LiveInvites::new());

    let inviter = inviter_endpoint().await;
    let inviter_id = *inviter.id().as_bytes();
    let addr = inviter.addr();
    // The accept loop owns `inviter` (inside the mesh) and holds an `Arc<MeshState>` clone, so
    // both keep serving after this helper returns; the loop stops at process exit.
    let cfg = Config::load(&config_path).unwrap();
    let mesh = MeshState::new(
        inviter,
        gate,
        store.clone(),
        invites.clone(),
        "alice".into(),
        config_path.clone(),
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    );
    let task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
    mesh.set_accept_task(task).await;

    let redeemer = redeemer_endpoint().await;
    (redeemer, addr, store, invites, inviter_id, config_path)
}

/// Far-future / already-past epochs for expiry control (avoid a real clock in assertions).
const FUTURE: u64 = 4_000_000_000;
const PAST: u64 = 1_000;

#[tokio::test]
async fn happy_path_writes_the_trust_grant_and_returns_the_inviter_identity() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        let secret = [7u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["notes", "kb"], FUTURE))
            .await
            .unwrap();
        assert_eq!(invites.count(), 1);

        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        // The reply is PairReply::Ok carrying the inviter's identity (from the redeemed invite).
        assert_eq!(reply["result"], "ok", "expected Ok reply, got {reply}");
        assert_eq!(reply["inviter_nickname"], "alice");
        let reply_inviter_id: Vec<u64> = reply["inviter_id"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect();
        assert_eq!(
            reply_inviter_id,
            inviter_id.iter().map(|b| *b as u64).collect::<Vec<_>>()
        );

        // The TRUST/identity grant: a PeerEntry keyed by the TLS-authenticated redeemer id (P3),
        // stamped paired_at, named by the redeemer's nickname. Per §4.2's ASYMMETRIC grant, the
        // INVITER's entry for the redeemer carries NO service grants (`services == []`) — it is a
        // dial-back identity row, not a client-side dial directory. (T6 corrected this from T5's
        // earlier `invite.services`; `PeerEntry.services` is never an admission input, so this is
        // semantic cleanliness matching the spec, and authorization lives in config `allow`.)
        let entry = store
            .resolve(&redeemer_id)
            .unwrap()
            .expect("a PeerEntry must be written for the redeemer");
        assert_eq!(entry.nickname, "bob");
        assert!(
            entry.services.is_empty(),
            "the inviter's dial-back entry carries no service grants (§4.2): {:?}",
            entry.services
        );
        assert!(entry.paired_at.is_some(), "pairing must stamp paired_at");
        // The invite is burned (redeemed once).
        assert_eq!(invites.count(), 0, "a successful redeem burns the invite");

        // The SAS computes and is order-independent: the redeemer computes it with swapped
        // args and MUST get the same words (both sides read the same code aloud).
        let inviter_sas = short_auth_code(&inviter_id, &redeemer_id, &secret);
        let redeemer_sas = short_auth_code(&redeemer_id, &inviter_id, &secret);
        assert_eq!(
            inviter_sas, redeemer_sas,
            "SAS must be endpoint-order-independent"
        );
        assert_eq!(inviter_sas.split('-').count(), 3, "SAS is three words");
    })
    .await
    .expect("happy-path test timed out");
}

#[tokio::test]
async fn wrong_secret_is_refused_and_leaves_the_live_invite_untouched() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        // A real live invite exists under secret A; the redeemer sends secret B.
        invites
            .mint(make_invite([1u8; 32], inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();
        assert_eq!(invites.count(), 1);

        let reply = drive_redeemer(
            &redeemer,
            addr,
            hello_frame(&[2u8; 32], &redeemer_id, "bob"),
        )
        .await;

        assert_eq!(reply["result"], "refused", "wrong secret must be refused");
        // Generic reason — no unknown-vs-expired oracle (P3).
        assert_eq!(reply["reason"], "pairing refused");
        assert!(
            reply.get("inviter_id").is_none(),
            "a refusal leaks no inviter id"
        );
        // No entry written; the real invite is UNTOUCHED (unknown secret never burns, T2).
        assert!(store.resolve(&redeemer_id).unwrap().is_none());
        assert_eq!(
            invites.count(),
            1,
            "an unknown secret must not burn the live invite"
        );
    })
    .await
    .expect("wrong-secret test timed out");
}

#[tokio::test]
async fn expired_invite_is_refused_and_writes_no_entry() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        let secret = [3u8; 32];
        // Minted already-expired: correct secret, but expiry in the past.
        invites
            .mint(make_invite(secret, inviter_id, &["notes"], PAST))
            .await
            .unwrap();

        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        assert_eq!(
            reply["result"], "refused",
            "an expired invite must be refused"
        );
        assert_eq!(reply["reason"], "pairing refused");
        assert!(store.resolve(&redeemer_id).unwrap().is_none());
    })
    .await
    .expect("expired test timed out");
}

#[tokio::test]
async fn id_mismatch_is_refused_writes_no_entry_and_logs_no_peer_id() {
    timeout(Duration::from_secs(60), async {
        // Install the process-global INFO capture subscriber BEFORE the refusal happens. A global
        // (not thread-local) subscriber captures the handler's log regardless of which iroh/tokio
        // thread it runs on — the thread-local approach is racy across iroh's async. The refusal
        // is logged BEFORE the reply is sent, so by the time `drive_redeemer` returns the line is
        // deterministically in the buffer.
        let log_buf = global_log_buf();

        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        let secret = [5u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();

        // The redeemer LIES about its own id (claims all-9s, its real TLS id differs). The
        // inviter binds to the TLS id (P3) and refuses.
        let fake_id = [9u8; 32];
        assert_ne!(
            fake_id, redeemer_id,
            "the fake id must differ from the real TLS id"
        );
        let reply = drive_redeemer(&redeemer, addr, hello_frame(&secret, &fake_id, "bob")).await;

        assert_eq!(reply["result"], "refused", "an id mismatch must be refused");
        assert_eq!(reply["reason"], "id mismatch");
        // No entry under EITHER the real or the claimed id.
        assert!(store.resolve(&redeemer_id).unwrap().is_none());
        assert!(store.resolve(&fake_id).unwrap().is_none());
        // The invite is untouched — a lying redeemer neither burns nor decrements it (we refuse
        // before redeem).
        assert_eq!(
            invites.count(),
            1,
            "an id mismatch must not touch the invite"
        );

        // Surface discipline: the peer's (TLS-resolved) EndpointId never appears in OUR logs. We
        // isolate this crate's lines by target (`mcpmesh_node::…` — the daemon core lives in
        // the mcpmesh-node crate) so iroh's internal INFO logging — which may print endpoint
        // ids and is not our surface — can't pollute the assertion. The id-mismatch refusal
        // line is unique to THIS test (others log a different reason), so its presence
        // confirms our handler's refusal log was captured.
        let logs = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        let ours: String = logs
            .lines()
            .filter(|l| l.contains("mcpmesh_node::"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            ours.contains("pair attempt refused: id mismatch"),
            "our id-mismatch refusal must be logged: {logs:?}"
        );
        // base32 rendering of the redeemer's real EndpointId (the bytes are a valid id).
        let real_b32 = iroh::EndpointId::from_bytes(&redeemer_id)
            .unwrap()
            .to_string();
        assert!(
            !ours.contains(&real_b32),
            "the redeemer's EndpointId must never appear in our logs: {ours:?}"
        );
    })
    .await
    .expect("id-mismatch test timed out");
}

#[tokio::test]
async fn malformed_hello_is_refused_without_panicking_and_writes_no_entry() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        // A live invite exists, but the redeemer never sends a valid RedeemerHello.
        invites
            .mint(make_invite([4u8; 32], inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();

        // Send raw GARBAGE bytes (not JSON) on the pair stream — the attacker-reachable parse
        // path must survive it: a framing violation, refused with "malformed request", no panic.
        let conn = redeemer
            .connect(addr, ALPN_PAIR)
            .await
            .expect("dial pair/1");
        let (mut send, recv) = conn.open_bi().await.expect("open bi-stream");
        send.write_all(b"this is not a valid hello at all\n")
            .await
            .expect("write garbage");
        let _ = send.finish();
        let mut reader = FrameReader::new(BufReader::new(recv), MAX_PAIR_FRAME);
        let reply = match reader.next().await.expect("read reply frame") {
            Some(Inbound::Frame(v)) => v,
            other => panic!("expected a refusal frame, got {other:?}"),
        };
        drop(conn);

        assert_eq!(reply["result"], "refused", "garbage must be refused");
        assert_eq!(reply["reason"], "malformed request");
        // No entry written; the live invite is untouched (we never reached redeem).
        assert!(store.resolve(&redeemer_id).unwrap().is_none());
        assert_eq!(
            invites.count(),
            1,
            "a malformed hello must not touch the invite"
        );
    })
    .await
    .expect("malformed-hello test timed out");
}

// ---------------------------------------------------------------------------------------------
// Display-uniqueness guard (#38 rework). Grants are principal-keyed, so a nickname confers NO
// access anymore — the guard's residual purpose is display/routing clarity: a redeemer's
// self-asserted name held by a DIFFERENT stored peer is refused before any write. These cases
// lock in that residual property AND that legitimate (re-)pairing still works, with grants
// landing as STABLE principals.
// ---------------------------------------------------------------------------------------------

/// A pre-seeded store peer (the `internal peer add` shape — no `paired_at`).
fn seed_peer(store: &PeerStore, endpoint_id: [u8; 32], nickname: &str, services: &[&str]) {
    store
        .add(PeerEntry {
            endpoint_id,
            nickname: nickname.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();
}

/// Case 1 — a fresh, unique nickname not present in any store peer or any config allow is ALLOWED
/// (the guard must not break the normal first-pair path).
#[tokio::test]
async fn collision_guard_allows_a_fresh_unique_nickname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) =
            setup_full(&format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n")).await;
        let redeemer_id = *redeemer.id().as_bytes();
        let secret = [21u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();

        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        assert_eq!(
            reply["result"], "ok",
            "a fresh unique name must pair: {reply}"
        );
        // Entry written; grant applied on disk.
        let entry = store
            .resolve(&redeemer_id)
            .unwrap()
            .expect("bob entry written");
        assert_eq!(entry.nickname, "bob");
        // The grant lands as the STABLE eid principal (#38) — never the display name.
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(
            cfg.services.get("notes").unwrap().allow,
            vec![format!("eid:{}", redeemer.id())]
        );
    })
    .await
    .expect("fresh-unique test timed out");
}

/// Case 2 — the SAME peer (same endpoint_id) re-pairing to the same service is ALLOWED: its
/// existing same-id entry is not impersonation, and its own name is not an orphan allow.
#[tokio::test]
async fn collision_guard_allows_same_peer_re_pair() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, _cfg) = setup_full(&format!(
            "[services.notes]\nrun = ['{STUB}']\nallow = [\"bob\"]\n"
        ))
        .await;
        let redeemer_id = *redeemer.id().as_bytes();
        // Bob already paired once (SAME id as the redeemer we drive).
        seed_peer(&store, redeemer_id, "bob", &[]);

        let secret = [22u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        assert_eq!(
            reply["result"], "ok",
            "the same peer re-pairing to the same service must be allowed: {reply}"
        );
        assert_eq!(invites.count(), 0, "the invite is consumed");
    })
    .await
    .expect("same-peer re-pair test timed out");
}

/// Case 3 — the SAME peer re-pairing to an ADDITIONAL service is ALLOWED, and each grant is
/// its own principal append: the first service's existing eid grant is untouched, the new
/// service gains the same eid (#38 — one principal, appended per granted service).
#[tokio::test]
async fn collision_guard_allows_same_peer_additional_service() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) = setup_full(&format!(
            "[services.notes]\nrun = ['{STUB}']\nallow = []\n\
             [services.kb]\nrun = ['{STUB}']\nallow = []\n"
        ))
        .await;
        let redeemer_id = *redeemer.id().as_bytes();
        // Bob already paired to notes (SAME id).
        seed_peer(&store, redeemer_id, "bob", &["notes"]);
        // Pre-existing grant shape: notes already holds bob's eid principal (first
        // `allow = []` in the config text above is notes').
        let eid = format!("eid:{}", redeemer.id());
        let cfg_text = std::fs::read_to_string(&config_path).unwrap();
        std::fs::write(
            &config_path,
            cfg_text.replacen("allow = []", &format!("allow = [\"{eid}\"]"), 1),
        )
        .unwrap();

        let secret = [23u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["kb"], FUTURE))
            .await
            .unwrap();
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        assert_eq!(
            reply["result"], "ok",
            "the same peer pairing to an additional service must be allowed: {reply}"
        );
        // The grant added bob's eid to kb's allow (and left notes' as-is).
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(cfg.services.get("kb").unwrap().allow, vec![eid.clone()]);
        assert_eq!(cfg.services.get("notes").unwrap().allow, vec![eid.clone()]);
    })
    .await
    .expect("additional-service re-pair test timed out");
}

/// #87: ONE multi-use invite really pairs two different peers, and a later collision on it is
/// still refused recoverably.
///
/// Every other rendezvous case uses a single-use invite, so "every existing guard applies per
/// redemption" was asserted in prose and never executed. This executes it.
///
/// **Scope, stated because the first version of this docstring overclaimed it.** The collision here
/// is caught by the PRE-check (`peek_live` before `try_redeem`), not by the post-redeem race guard.
/// That guard also carried a defect — a hardcoded `invite_survived = false`, which told the loser of
/// a race to fetch a fresh invite while holding one with uses left, and dropped the branchable
/// ERR_NICKNAME_TAKEN exactly where renaming WOULD work — and it is fixed, but it is NOT covered
/// here: flipping it back leaves this test green. Reaching it needs a store write interleaved
/// between peek and burn, and no seam exists for that, which is the same gap #87/#147 recorded for
/// that arm. Multi-use makes the race routine rather than rare, which is why the fix matters even
/// unpinned.
#[tokio::test]
async fn one_multi_use_invite_pairs_two_peers_and_tells_a_loser_the_truth() {
    timeout(Duration::from_secs(90), async {
        let (redeemer, addr, store, invites, inviter_id, _config_path) =
            setup_full(&format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n")).await;
        let first_id = *redeemer.id().as_bytes();

        let secret = [31u8; 32];
        let mut inv = make_invite(secret, inviter_id, &["notes"], FUTURE);
        inv.uses_remaining = 3;
        invites.mint(inv).await.unwrap();

        // First redemption: an ordinary pairing off a multi-use line.
        let reply = drive_redeemer(
            &redeemer,
            addr.clone(),
            hello_frame(&secret, &first_id, "alpha"),
        )
        .await;
        assert_eq!(reply["result"], "ok", "first redemption must pair: {reply}");
        assert!(
            store.resolve(&first_id).unwrap().is_some(),
            "and must write a real peer row"
        );

        // SECOND redemption of the SAME line by a DIFFERENT endpoint — the point of the feature.
        let second = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[77u8; 32]))
            .bind()
            .await
            .expect("bind a second redeemer");
        let second_id = *second.id().as_bytes();
        assert_ne!(second_id, first_id);
        let reply = drive_redeemer(
            &second,
            addr.clone(),
            hello_frame(&secret, &second_id, "beta"),
        )
        .await;
        assert_eq!(
            reply["result"], "ok",
            "the SAME invite must pair a second, independent peer: {reply}"
        );
        let a = store.resolve(&first_id).unwrap().expect("first peer");
        let b = store.resolve(&second_id).unwrap().expect("second peer");
        assert_ne!(
            a.endpoint_id, b.endpoint_id,
            "two independent pairings, not one shared identity"
        );

        // Third redemption, colliding on a name the FIRST redeemer already holds. The invite still
        // has a use left, so the refusal must say RENAME-AND-RETRY, not "get a fresh invite".
        let third = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .secret_key(iroh::SecretKey::from_bytes(&[78u8; 32]))
            .bind()
            .await
            .expect("bind a third redeemer");
        let third_id = *third.id().as_bytes();
        let reply = drive_redeemer(
            &third,
            addr.clone(),
            hello_frame(&secret, &third_id, "alpha"),
        )
        .await;
        assert_eq!(
            reply["result"], "refused",
            "the collision must refuse: {reply}"
        );
        let reason = reply["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("rename this node"),
            "a collision on a live multi-use invite is recoverable by renaming — the invite is \
             untouched, since the pre-check refuses before try_redeem spends a use: {reason}"
        );
        assert!(
            !reason.contains("ask the inviter for a fresh invite"),
            "and must NOT send it back to the inviter: {reason}"
        );
        assert_eq!(
            reply["code"], "nickname_taken",
            "and must stay BRANCHABLE — the code exists exactly for the recoverable case, which \
             this is: {reply}"
        );
    })
    .await
    .expect("multi-use rendezvous test timed out");
}

/// Case 4 — collision: a peer "carol" (a DIFFERENT endpoint_id) already exists; a redeemer that
/// names itself "carol" is REFUSED (blocks assuming another peer's display identity). No entry
/// is written under the redeemer's id and no grant happens — and since #87 the invite SURVIVES
/// (the collision is checked via `peek` BEFORE `try_redeem` burns the secret) with a
/// distinguishable reason, because in the field this is two same-hostname machines on their
/// FIRST pairing attempt, not an attack worth spending the invite on.
#[tokio::test]
async fn collision_guard_refuses_impersonating_an_existing_peer() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) =
            setup_full(&format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n")).await;
        let redeemer_id = *redeemer.id().as_bytes();
        // A DIFFERENT peer already holds the name "carol".
        let carol_id = [0xC0u8; 32];
        assert_ne!(carol_id, redeemer_id);
        seed_peer(&store, carol_id, "carol", &["notes"]);

        let secret = [24u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["notes"], FUTURE))
            .await
            .unwrap();
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "carol")).await;

        assert_eq!(
            reply["result"], "refused",
            "a colliding nickname must be refused: {reply}"
        );
        // Distinguishable, actionable reason (#87): the caller proved possession of a live
        // secret, so naming the collision is not an oracle — and it must say the invite
        // survived, because that is what makes the refusal recoverable without a new ceremony.
        let reason = reply["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("carol") && reason.contains("already taken"),
            "the reason must name the colliding nickname (#87 — a generic refusal left \
             first-time pairs of same-hostname machines undiagnosable): {reason}"
        );
        // #147: the recovery clause names the ACTION, never a control verb. `set_nickname` is our
        // API vocabulary — a GUI user cannot type it, see it, or find it, and because this string
        // is built INVITER-side and travels to the redeemer, the embedder that displays it cannot
        // rewrite it except by substring-matching our prose.
        assert!(
            !reason.contains("set_nickname"),
            "the refusal must not name a control verb — an embedder's user cannot invoke one: \
             {reason}"
        );
        assert!(
            reason.contains("rename this node"),
            "the recovery clause must state the action, the way its 'ask the inviter for a fresh \
             invite' sibling already does: {reason}"
        );
        // #147: and it carries the machine-readable kind, so a redeemer raises a typed error
        // rather than parsing the sentence above — which would break the moment we reword it.
        assert_eq!(
            reply["code"], "nickname_taken",
            "the collision refusal must be branchable on the wire: {reply}"
        );
        assert!(
            store.resolve(&redeemer_id).unwrap().is_none(),
            "no entry may be written under the colliding redeemer's id"
        );
        let cfg = Config::load(&config_path).unwrap();
        assert!(
            cfg.services.get("notes").unwrap().allow.is_empty(),
            "no grant may be applied for a refused pairing"
        );
        assert_eq!(
            invites.count(),
            1,
            "the invite must SURVIVE a nickname collision (#87): the collision is checked \
             before the burn, so the redeemer can rename and redeem the same invite again"
        );
    })
    .await
    .expect("collision test timed out");
}

/// #87 end to end: after a collision refusal, the SAME invite redeems successfully under a
/// different nickname — the recovery path the non-burning check exists for. Restoring the old
/// burn-before-check order fails this at the second redeem (`Unknown` → refused).
#[tokio::test]
async fn collision_refusal_preserves_the_invite_for_a_retry_under_a_new_name() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        let carol_id = [0xC0u8; 32];
        seed_peer(&store, carol_id, "carol", &[]);

        let secret = [25u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &[], FUTURE))
            .await
            .unwrap();

        // First attempt collides and is refused…
        let reply = drive_redeemer(
            &redeemer,
            addr.clone(),
            hello_frame(&secret, &redeemer_id, "carol"),
        )
        .await;
        assert_eq!(reply["result"], "refused", "{reply}");

        // …and the SAME secret then redeems under a unique name.
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "dave")).await;
        assert_eq!(
            reply["result"], "ok",
            "the same invite must redeem after a rename — the collision refusal must not have \
             burned it (#87): {reply}"
        );
        let entry = store
            .resolve(&redeemer_id)
            .unwrap()
            .expect("the retry writes the trust entry");
        assert_eq!(entry.nickname, "dave");
        assert_eq!(invites.count(), 0, "the successful redeem burns the invite");
    })
    .await
    .expect("collision-retry test timed out");
}

/// The no-oracle boundary of the distinguishable reason (#87): the collision check must not run
/// — and must not answer — for a caller that has NOT proven possession of a live secret. A
/// stranger probing a colliding nickname with a garbage secret gets exactly the generic
/// refusal, or the distinguishable reason becomes a store-contents oracle.
#[tokio::test]
async fn a_wrong_secret_with_a_colliding_nickname_gets_only_the_generic_refusal() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id) = setup().await;
        let redeemer_id = *redeemer.id().as_bytes();
        let carol_id = [0xC0u8; 32];
        seed_peer(&store, carol_id, "carol", &[]);

        // A live invite exists (the accept gate is open), but the dialer sends a WRONG secret
        // while claiming the colliding name.
        invites
            .mint(make_invite([26u8; 32], inviter_id, &[], FUTURE))
            .await
            .unwrap();
        let reply = drive_redeemer(
            &redeemer,
            addr,
            hello_frame(&[27u8; 32], &redeemer_id, "carol"),
        )
        .await;

        assert_eq!(reply["result"], "refused", "{reply}");
        assert_eq!(
            reply["reason"], "pairing refused",
            "an unproven caller must get the GENERIC reason — a nickname-specific answer here \
             is a store-contents oracle for anyone who can dial: {reply}"
        );
        // #147: and no CODE either. The refusal code exists so an embedder can branch instead of
        // reading prose, which means it carries exactly the information the reason does — so
        // stamping this path would rebuild the oracle the generic reason exists to prevent,
        // machine-readably. Asserted on the real SEND SITE: a unit test over a hand-built
        // PairReply pins the serializer, not the branch that chooses the code.
        assert!(
            reply.get("code").is_none(),
            "an unproven caller must get NO refusal code — one here is the same store-contents \
             oracle as a specific reason, just easier to script: {reply}"
        );
        assert_eq!(invites.count(), 1, "the real invite is untouched");
    })
    .await
    .expect("collision-oracle test timed out");
}

// ---------------------------------------------------------------------------------------------
// Second-pairing MERGE semantics (the "reverse pairing clobbers the dial directory" fix).
// `PeerStore::add` is a replace-on-endpoint_id upsert, so the rendezvous write sites must
// resolve-then-merge: the inviter PRESERVES its stored nickname + dial directory + proven
// user_id; the redeemer UNIONs a repeat grant and takes the new invite's suggested nickname.
// ---------------------------------------------------------------------------------------------

/// Reverse pairing preserves the inviter's dial directory, nickname, and proven user_id.
///
/// The user story: Alice invited Bob first (Bob redeemed → BOB's alice-entry carries
/// `services = ["notes"]`, his chosen name "alice", her proven user_id). Later BOB invites Alice
/// back (to grant her his "code" service). Bob is now the INVITER: his side's write must MERGE
/// into his existing alice-entry, not replace it with the fresh `{services: []}` dial-back row —
/// and the authorization grant lands as her STABLE principal (#38: the stored `b64u:` user_id,
/// since her earlier pairing proved a binding), never any nickname.
#[tokio::test]
async fn reverse_pairing_preserves_the_inviters_dial_directory_and_nickname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) =
            setup_full(&format!("[services.code]\nrun = ['{STUB}']\nallow = []\n")).await;
        let alice_id = *redeemer.id().as_bytes();
        // Bob's PRE-EXISTING alice-entry from the EARLIER Alice→Bob pairing (he redeemed her
        // invite): his name for her, the dial directory of what he may dial on her, her proven
        // user_id, the original pairing stamp.
        store
            .add(PeerEntry {
                endpoint_id: alice_id,
                nickname: "alice".into(),
                services: vec!["notes".into()],
                paired_at: Some("1000".into()),
                user_id: Some("b64u:ALICE".into()),
                last_addr: None,
            })
            .unwrap();

        // Alice redeems Bob's invite, self-suggesting a DIFFERENT name and presenting NO binding.
        let secret = [31u8; 32];
        invites
            .mint(make_invite(secret, inviter_id, &["code"], FUTURE))
            .await
            .unwrap();
        let reply = drive_redeemer(
            &redeemer,
            addr,
            hello_frame(&secret, &alice_id, "alice-laptop"),
        )
        .await;
        assert_eq!(
            reply["result"], "ok",
            "the reverse pairing must succeed: {reply}"
        );

        let entry = store
            .resolve(&alice_id)
            .unwrap()
            .expect("the alice entry survives the reverse pairing");
        assert_eq!(
            entry.nickname, "alice",
            "the inviter's chosen nickname must not be renamed by the redeemer's self-suggestion"
        );
        assert_eq!(
            entry.services,
            vec!["notes".to_string()],
            "the inviter's dial directory must be preserved, not wiped to []"
        );
        assert_eq!(
            entry.user_id.as_deref(),
            Some("b64u:ALICE"),
            "a verified user_id is never downgraded to None by a binding-less re-pair"
        );
        assert_eq!(
            entry.paired_at.as_deref(),
            Some("1000"),
            "the original pairing stamp is kept on the inviter side"
        );
        // The authorization grant lands as her stable principal: the binding-present branch
        // writes the stored b64u: user_id (#38) — resilient to any rename on either side.
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(
            cfg.services.get("code").unwrap().allow,
            vec!["b64u:ALICE".to_string()],
            "the grant must target the stable principal, never a nickname"
        );
    })
    .await
    .expect("reverse-pairing merge test timed out");
}

/// A REPEAT grant on the REDEEMER side UNIONs the dial directory (dedup, stable order: existing
/// first, new appended), applies the NEW invite's suggested nickname (rename-by-a-fresh-invite is
/// a deliberate feature), and never clobbers a verified user_id to None.
#[tokio::test]
async fn repeat_grant_unions_the_redeemers_dial_directory_and_applies_the_new_nickname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, _store, invites, inviter_id, _cfg) = setup_full("").await;
        // The redeemer ALREADY paired with this inviter once: notes granted, her user_id proven,
        // named "alice-old" by the earlier invite.
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        bob_store
            .add(PeerEntry {
                endpoint_id: inviter_id,
                nickname: "alice-old".into(),
                services: vec!["notes".into()],
                paired_at: Some("1000".into()),
                user_id: Some("b64u:ALICE".into()),
                last_addr: None,
            })
            .unwrap();

        // A SECOND invite from the SAME inviter: re-grants notes (dedup) plus kb, and suggests a
        // NEW nickname. The inviter presents no binding (no self_binding installed in setup_full).
        let secret = [32u8; 32];
        let invite = Invite {
            secret,
            inviter_id,
            inviter_addr_json: serde_json::to_string(&addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["kb".into(), "notes".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        invites.mint(invite.clone()).await.unwrap();

        let result = redeem_invite(
            redeemer,
            "bob".into(),
            invite.encode(),
            None,
            bob_store.clone(),
            None,
            None,
        )
        .await
        .expect("the second redeem succeeds");
        assert_eq!(result.peer_nickname, "alice");

        let entry = bob_store
            .resolve(&inviter_id)
            .unwrap()
            .expect("the alice entry survives the repeat grant");
        assert_eq!(
            entry.nickname, "alice",
            "the NEW invite's suggested nickname is applied (rename-by-fresh-invite)"
        );
        assert_eq!(
            entry.services,
            vec!["notes".to_string(), "kb".to_string()],
            "the dial directory UNIONs the repeat grant (dedup, existing order first)"
        );
        assert_eq!(
            entry.user_id.as_deref(),
            Some("b64u:ALICE"),
            "a verified user_id is never clobbered to None by a binding-less re-pair"
        );
        assert_ne!(
            entry.paired_at.as_deref(),
            Some("1000"),
            "the redeemer stamps each redeem as a fresh pairing event"
        );
        drop(bob_dir);
    })
    .await
    .expect("repeat-grant union test timed out");
}

/// **Redeemer-side nickname collision (name squatting).** The mirror of the inviter-side
/// impersonation guard. Bob already trusts "alice" (endpoint A). He then redeems an invite from a
/// DIFFERENT endpoint (Mallory) whose suggested nickname is also "alice". Applying that suggestion
/// would point the name Bob's gate resolves — and his `[services.*].allow` authorizes — at
/// Mallory's endpoint, silently handing her every grant Bob made to the real alice. That would
/// break the invariant that redeeming an invite grants the redeemed-from side NOTHING, so the
/// redeem must be REFUSED and Bob's existing alice-entry left untouched.
#[tokio::test]
async fn redeem_refuses_an_invite_squatting_an_existing_peers_nickname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, _store, invites, mallory_id, _cfg) = setup_full("").await;

        // Bob's store: the REAL alice, under a different endpoint id than the inviter he's about
        // to redeem from.
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let real_alice_id = [0xA1u8; 32];
        assert_ne!(real_alice_id, mallory_id);
        bob_store
            .add(PeerEntry {
                endpoint_id: real_alice_id,
                nickname: "alice".into(),
                services: vec!["notes".into()],
                paired_at: Some("1000".into()),
                user_id: Some("b64u:ALICE".into()),
                last_addr: None,
            })
            .unwrap();

        // Mallory's invite suggests the name Bob already uses for alice.
        let secret = [33u8; 32];
        let invite = Invite {
            secret,
            inviter_id: mallory_id,
            inviter_addr_json: serde_json::to_string(&addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["kb".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        invites.mint(invite.clone()).await.unwrap();

        let err = redeem_invite(
            redeemer,
            "bob".into(),
            invite.encode(),
            None,
            bob_store.clone(),
            None,
            None,
        )
        .await
        .expect_err("redeeming a nickname-squatting invite must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("alice"),
            "the error must name the colliding nickname so the user can rename: {msg}"
        );

        // Bob's real alice-entry is untouched, and NO entry exists under Mallory's id.
        let alice = bob_store
            .resolve(&real_alice_id)
            .unwrap()
            .expect("the real alice entry survives a squatting attempt");
        assert_eq!(alice.nickname, "alice");
        assert_eq!(alice.services, vec!["notes".to_string()]);
        assert!(
            bob_store.resolve(&mallory_id).unwrap().is_none(),
            "no entry may be written for the squatter"
        );
        drop(bob_dir);
    })
    .await
    .expect("redeemer-side squatting test timed out");
}

/// #87(b): a dial against an inviter with NO live invite must explain itself. The accept gate
/// fast-closes with `b"no pairing in progress"`, and the redeemer used to surface that as a bare
/// "no reply from the inviter" — indistinguishable from a network problem, when the actual
/// causes are: the invite expired, was already used, or the inviter's daemon restarted (invites
/// do not survive restarts). Dropping the close-reason match reverts to the bare error and
/// fails the message assertion.
#[tokio::test]
async fn a_dead_invite_dial_reports_the_cause_not_a_bare_connection_failure() {
    timeout(Duration::from_secs(60), async {
        // Accept loop up, NOTHING minted — the state every outstanding invite is in after the
        // inviter's daemon restarts, and what a redeemer holding yesterday's invite dials into.
        let (redeemer, addr, _store, _invites, inviter_id, _cfg) = setup_full("").await;

        let invite = Invite {
            secret: [28u8; 32],
            inviter_id,
            inviter_addr_json: serde_json::to_string(&addr).unwrap(),
            nickname: "alice".into(),
            services: vec![],
            expires_at_epoch: FUTURE, // the LINE still advertises a live TTL — that is the bug
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        let err = redeem_invite(
            redeemer,
            "bob".into(),
            invite.encode(),
            None,
            Arc::new(PeerStore::open(&tempfile::tempdir().unwrap().keep().join("b.redb")).unwrap()),
            None,
            None,
        )
        .await
        .expect_err("a dead invite must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no longer live") && msg.contains("expired"),
            "the error must name the dead-invite causes instead of presenting as a connection \
             failure (#87b): {msg}"
        );
        // #87b made invites SURVIVE restarts, so the old wording — which offered "the inviter's
        // daemon restarted (invites do not survive a restart)" as an explanation — became a false
        // one, handed to a user in the exact moment they are working out what went wrong.
        assert!(
            !msg.contains("restart"),
            "and must not blame a restart, which no longer voids an invite: {msg}"
        );
    })
    .await
    .expect("dead-invite dial test timed out");
}

/// **The load-bearing seam, end to end (M2b T6 Step 5).** A REAL redeemer (`redeem_invite`) pairs
/// with a REAL serving inviter over the daemon's own accept loop, and the payoff is proven: the
/// paired+granted peer is ACTUALLY ADMITTED to the granted service over a mesh (mcp/1) session.
/// This is the whole point of T6 — PeerEntry (identity) + config `allow` (authorization) together
/// admit the peer, and the inviter-side grant appends the redeemer to `[services.notes].allow` +
/// reloads so `select_service` says yes.
/// #87: BOTH local aliases, driven through the real two-sided ceremony.
///
/// A unit test of `effective_redeemer_nickname` would prove nothing about which name the inviter
/// actually WRITES, and a unit test of the redeemer's `local_name` nothing about what it stores.
/// The call sites are the whole claim, so this asserts on both stores after a real pairing.
#[tokio::test(flavor = "multi_thread")]
async fn both_sides_store_their_own_local_alias_after_a_real_pairing() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("alice.redb");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let invites = Arc::new(LiveInvites::new());
        let alice = inviter_endpoint().await;
        let alice_id = *alice.id().as_bytes();
        let alice_addr = alice.addr();
        let cfg = Config::load(&config_path).unwrap();
        let mesh = MeshState::new(
            alice,
            gate,
            store.clone(),
            invites.clone(),
            "alice".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
        mesh.set_accept_task(task).await;

        // Alice mints with HER local name for whoever redeems.
        let invite = Invite {
            secret: [21u8; 32],
            inviter_id: alice_id,
            inviter_addr_json: serde_json::to_string(&alice_addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: Some("bobs-laptop".into()),
        };
        invites.mint(invite.clone()).await.unwrap();

        // Bob redeems under HIS OWN local name for Alice.
        let bob = redeemer_endpoint().await;
        let bob_id = *bob.id().as_bytes();
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("b.redb")).unwrap());
        let result = redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            Some("alice-work".into()),
            bob_store.clone(),
            None,
            None,
        )
        .await
        .expect("the ceremony completes with aliases on both sides");

        // Bob's side: his alias, NOT the "alice" the invite suggested.
        assert_eq!(
            result.peer_nickname, "alice-work",
            "the pair RESULT must echo the redeemer's own alias — a UI renders this"
        );
        let bobs_entry = bob_store
            .resolve(&alice_id)
            .unwrap()
            .expect("bob stored the inviter");
        assert_eq!(
            bobs_entry.nickname, "alice-work",
            "the redeemer must STORE its alias, not the invite's suggestion"
        );

        // Alice's side: her alias, NOT the "bob" he claimed for himself.
        let alices_entry = store
            .resolve(&bob_id)
            .unwrap()
            .expect("alice stored the redeemer");
        assert_eq!(
            alices_entry.nickname, "bobs-laptop",
            "the inviter must STORE its peer_nickname, overriding the redeemer's self-claim"
        );

        drop(bob_dir);
        std::mem::forget(dir);
    })
    .await
    .expect("alias ceremony timed out");
}

#[tokio::test]
async fn paired_and_granted_peer_is_admitted_to_the_service_end_to_end() {
    timeout(Duration::from_secs(60), async {
        // ---- Alice: a serving inviter with a `notes` service, allow = [] (local-only) ----
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.redb");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let invites = Arc::new(LiveInvites::new());

        let alice = inviter_endpoint().await;
        let alice_id = *alice.id().as_bytes();
        let alice_addr = alice.addr();

        let cfg = Config::load(&config_path).unwrap();
        let mesh = MeshState::new(
            alice,
            gate,
            store.clone(),
            invites.clone(),
            "alice".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
        mesh.set_accept_task(task).await;

        // ---- Alice mints an invite for [notes], carrying her REAL dialable addr ----
        let secret = [11u8; 32];
        let invite = Invite {
            secret,
            inviter_id: alice_id,
            inviter_addr_json: serde_json::to_string(&alice_addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        invites.mint(invite.clone()).await.unwrap();

        // ---- Bob redeems it (real dial over the accept loop) ----
        let bob = redeemer_endpoint().await;
        let bob_id = *bob.id().as_bytes();
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        // #43: a recording grant-back hook captures the inviter principal the redeemer would
        // grant its OWN services to. Alice presented no binding here → the principal is her eid.
        let granted_back: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let rec = granted_back.clone();
        let grant_back: GrantBackFn = Box::new(move |principal, display| {
            let rec = rec.clone();
            Box::pin(async move {
                rec.lock().unwrap().push((principal, display));
                Ok(())
            })
        });
        let result = redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            None,
            bob_store.clone(),
            None,
            Some(grant_back),
        )
        .await
        .expect("redeem_invite dials, verifies the inviter id, sends the secret, succeeds");
        assert_eq!(result.peer_nickname, "alice");
        // #43: the mutual grant-back fired with the inviter's STABLE principal (its eid, since
        // it presented no binding) and the redeemer's display name for it.
        let back = granted_back.lock().unwrap().clone();
        assert_eq!(
            back,
            vec![(
                mcpmesh_net::EndpointId::from_bytes(alice_id).principal(),
                "alice".to_string()
            )],
            "the redeemer grants the inviter back by its stable principal (#43)"
        );
        // The PairResult carries the granted services (from the invite) so the porcelain can print
        // the "You can mount: alice/notes" line without re-decoding the invite (M2b T7).
        assert_eq!(result.services, vec!["notes".to_string()]);

        // ---- Mutual entries with the CORRECT asymmetric services (§4.2) ----
        // Bob's alice-entry: services == [notes] (what bob may dial), paired_at set.
        let bob_side = bob_store
            .resolve(&alice_id)
            .unwrap()
            .expect("bob's store has an alice entry");
        assert_eq!(bob_side.nickname, "alice");
        assert_eq!(bob_side.services, vec!["notes".to_string()]);
        assert!(bob_side.paired_at.is_some());
        // Alice's bob-entry: services == [] (dial-back identity only), paired_at set.
        let alice_side = store
            .resolve(&bob_id)
            .unwrap()
            .expect("alice's store has a bob entry");
        assert_eq!(alice_side.nickname, "bob");
        assert!(
            alice_side.services.is_empty(),
            "alice's dial-back entry carries no service grants (§4.2): {:?}",
            alice_side.services
        );
        assert!(alice_side.paired_at.is_some());

        // ---- The GRANT took effect on disk as bob's STABLE principal (#38) ----
        let after = Config::load(&config_path).unwrap();
        assert_eq!(
            after.services.get("notes").unwrap().allow,
            vec![format!("eid:{}", bob.id())],
            "the pairing grant must append bob's eid principal to [services.notes].allow"
        );

        // ---- BOTH sides computed the SAME sas_code (order-independent) ----
        let expected_sas = short_auth_code(&alice_id, &bob_id, &secret);
        assert_eq!(
            result.sas_code, expected_sas,
            "redeemer SAS must be correct"
        );
        assert_eq!(
            short_auth_code(&bob_id, &alice_id, &secret),
            expected_sas,
            "SAS must be endpoint-order-independent (both sides read the same words)"
        );

        // ---- THE PAYOFF: bob is now ACTUALLY admitted to alice/notes over the mesh ----
        // The gate RESOLVES bob's endpoint_id -> "bob" (his PeerEntry); select_service ADMITS
        // "bob" to notes (config allow now has bob, live after the grant's reload); the echo
        // stub answers and MCPMESH_PEER_NAME is injected as "bob".
        let mut transport = connect(&bob, alice_addr, "notes").await.unwrap().0;
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "_meta": {"mcpmesh/service": "notes"},
                    "capabilities": {}, "clientInfo": {"name": "bob", "version": "0"}
                }
            }))
            .await
            .unwrap();
        let init = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "the paired+granted peer must be ADMITTED to notes (not -32054'd): {init}"
        );
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "paired!"}}
            }))
            .await
            .unwrap();
        let call = transport.recv_value().await.unwrap().unwrap();
        assert_eq!(call["result"]["content"][0]["text"], "paired!");
        assert_eq!(
            call["result"]["peer_name"], "bob",
            "the gate-resolved identity 'bob' was injected into the served child"
        );

        drop(bob_dir);
        std::mem::forget(dir);
    })
    .await
    .expect("E2E admission test timed out");
}

/// THE #38 REGRESSION: a display rename can never desync a grant. Pre-0.8.0 this exact flow
/// refused with `-32054`: pairing granted by NICKNAME, `peer_rename` (first-class since the
/// 0.7.1 `set_nickname` era) rewrote the stored name, and the gate then resolved the peer to
/// a name the allow list no longer contained. Post-#38 the grant is the peer's `eid:`
/// principal, the rename touches only the display row, and admission is unchanged.
#[tokio::test]
async fn rename_after_pairing_keeps_the_peer_admitted() {
    timeout(Duration::from_secs(60), async {
        // ---- Alice serves notes; the REAL accept loop + gate + config (e2e harness) ----
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let db_path = dir.path().join("state.redb");
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();
        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let invites = Arc::new(LiveInvites::new());
        let alice = inviter_endpoint().await;
        let alice_id = *alice.id().as_bytes();
        let alice_addr = alice.addr();
        let cfg = Config::load(&config_path).unwrap();
        let mesh = MeshState::new(
            alice,
            gate,
            store.clone(),
            invites.clone(),
            "alice".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
        mesh.set_accept_task(task).await;

        // ---- Bob pairs (real invite, real dial) and is admitted ----
        let secret = [61u8; 32];
        let invite = Invite {
            secret,
            inviter_id: alice_id,
            inviter_addr_json: serde_json::to_string(&alice_addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        invites.mint(invite.clone()).await.unwrap();
        let bob = redeemer_endpoint().await;
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            None,
            bob_store,
            None,
            None,
        )
        .await
        .expect("pairing succeeds");
        let mut t = connect(&bob, alice_addr.clone(), "notes").await.unwrap().0;
        t.send_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25",
                       "_meta": {"mcpmesh/service": "notes"},
                       "capabilities": {}, "clientInfo": {"name": "bob", "version": "0"}}
        }))
        .await
        .unwrap();
        let init = t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "paired peer admitted before the rename: {init}"
        );
        drop(t);

        // ---- Alice renames bob → "robert" through the REAL rename handler ----
        let state = mcpmesh::control::DaemonState::with_mesh("test", mesh.clone());
        mcpmesh::daemon::rename_peer(
            &state,
            mcpmesh_local_api::PeerRenameParams {
                to: "robert".into(),
                user_id: None,
                nickname: Some("bob".into()),
            },
        )
        .await
        .expect("rename succeeds");
        assert_eq!(
            store
                .resolve(bob.id().as_bytes())
                .unwrap()
                .unwrap()
                .nickname,
            "robert",
            "the display rename landed"
        );
        // The grant is untouched — allow still holds bob's eid principal, byte-identical.
        let after = Config::load(&config_path).unwrap();
        assert_eq!(
            after.services.get("notes").unwrap().allow,
            vec![format!("eid:{}", bob.id())],
            "a rename must leave grants byte-identical (#38)"
        );

        // ---- THE PAYOFF: bob dials again and is STILL admitted (pre-#38: -32054) ----
        let mut t = connect(&bob, alice_addr, "notes").await.unwrap().0;
        t.send_value(json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25",
                       "_meta": {"mcpmesh/service": "notes"},
                       "capabilities": {}, "clientInfo": {"name": "bob", "version": "0"}}
        }))
        .await
        .unwrap();
        let init = t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "a renamed peer must STILL be admitted — the #38 regression: {init}"
        );
        // And the served child now sees the NEW display name — display followed the rename,
        // authorization didn't move.
        t.send_value(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "still-here"}}
        }))
        .await
        .unwrap();
        let call = t.recv_value().await.unwrap().unwrap();
        assert_eq!(call["result"]["content"][0]["text"], "still-here");
        assert_eq!(
            call["result"]["peer_name"], "robert",
            "display identity follows the rename while the grant stands"
        );
    })
    .await
    .expect("#38 regression test timed out");
}

/// **Self-sovereign identity adoption (device->user binding), end to end.** When BOTH sides present
/// a device->user binding at pairing, each stores the OTHER's PROVEN `user_id` on its `PeerEntry`,
/// verified against the TLS-authenticated endpoint (never a self-asserted id) — so kb audiences can
/// later key on the USER, not just the per-device nickname. Backward-compat (no binding → `user_id:
/// None`) is covered by the other redeem tests here, which all pass `None`.
#[tokio::test]
async fn pairing_exchanges_and_stores_each_sides_verified_user_id() {
    timeout(Duration::from_secs(60), async {
        // ---- Alice: a serving inviter carrying her self-sovereign binding ----
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.redb");
        let config_path = dir.path().join("config.toml");
        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let invites = Arc::new(LiveInvites::new());

        let alice = inviter_endpoint().await;
        let alice_id = *alice.id().as_bytes();
        let alice_addr = alice.addr();

        // Alice's self-sovereign user key + the binding she presents over her OWN endpoint.
        let (alice_uk, _) =
            mcpmesh_trust::UserKey::load_or_generate(&dir.path().join("alice-user.key")).unwrap();
        let alice_user_id = mcpmesh_trust::binding::user_id(&alice_uk);
        let (a_pk, a_sig) = mcpmesh_trust::binding::present(&alice_uk, &alice_id);

        let cfg = Config::load(&config_path).unwrap();
        let mesh = MeshState::new(
            alice,
            gate,
            store.clone(),
            invites.clone(),
            "alice".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        mesh.set_self_binding(Some(SelfBinding {
            user_pk: a_pk,
            sig: a_sig,
        }));
        let task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
        mesh.set_accept_task(task).await;

        // ---- Alice mints an invite carrying her real dialable addr (no services needed) ----
        let secret = [21u8; 32];
        let invite = Invite {
            secret,
            inviter_id: alice_id,
            inviter_addr_json: serde_json::to_string(&alice_addr).unwrap(),
            nickname: "alice".into(),
            services: vec![],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };
        invites.mint(invite.clone()).await.unwrap();

        // ---- Bob redeems, presenting HIS own binding over his endpoint ----
        let bob = redeemer_endpoint().await;
        let bob_id = *bob.id().as_bytes();
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let (bob_uk, _) =
            mcpmesh_trust::UserKey::load_or_generate(&bob_dir.path().join("bob-user.key")).unwrap();
        let bob_user_id = mcpmesh_trust::binding::user_id(&bob_uk);
        let (b_pk, b_sig) = mcpmesh_trust::binding::present(&bob_uk, &bob_id);

        let pair_result = redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            None,
            bob_store.clone(),
            Some(SelfBinding {
                user_pk: b_pk,
                sig: b_sig,
            }),
            None,
        )
        .await
        .expect("redeem succeeds and exchanges self-sovereign bindings");

        // #30: the redeemer LEARNS the inviter's stable user_id at pair time (PairResult), so it
        // can align its own identity and later dial by it — no scraping `status`.
        assert_eq!(
            pair_result.peer_user_id.as_deref(),
            Some(alice_user_id.as_str()),
            "pair result must return alice's proven user_id to the redeemer"
        );

        // ---- Each side stored the OTHER's VERIFIED user_id (invariant: bound to the TLS id) ----
        let bob_side = bob_store
            .resolve(&alice_id)
            .unwrap()
            .expect("bob has an alice entry");
        assert_eq!(
            bob_side.user_id.as_deref(),
            Some(alice_user_id.as_str()),
            "bob must store alice's proven self-sovereign user_id"
        );
        let alice_side = store
            .resolve(&bob_id)
            .unwrap()
            .expect("alice has a bob entry");
        assert_eq!(
            alice_side.user_id.as_deref(),
            Some(bob_user_id.as_str()),
            "alice must store bob's proven self-sovereign user_id"
        );

        drop(bob_dir);
        std::mem::forget(dir);
    })
    .await
    .expect("user_id exchange test timed out");
}

/// P3 negative (address-swap defense): the invite NAMES one inviter id, but its embedded ADDRESS
/// routes to a DIFFERENT endpoint. `redeem_invite` verifies the TLS-authenticated peer id against
/// the invite's `inviter_id` BEFORE sending the secret, so the mismatch bails — no entry written,
/// the bearer secret never leaves the redeemer.
#[tokio::test]
async fn redeem_refuses_an_address_swap_and_writes_no_entry_p3() {
    timeout(Duration::from_secs(60), async {
        // A real endpoint (mallory) that accepts the pair dial so bob's connect() completes and
        // learns mallory's TLS id — but the invite claims a DIFFERENT inviter id.
        let mallory = inviter_endpoint().await;
        let mallory_id = *mallory.id().as_bytes();
        let mallory_addr = mallory.addr();
        tokio::spawn(async move {
            while let Some(inc) = mallory.accept().await {
                tokio::spawn(async move {
                    if let Ok(conn) = inc.await {
                        // Accept the handshake; bob bails after the P3 check without opening a
                        // stream, so this accept_bi just errors when he drops the connection.
                        let _ = conn.accept_bi().await;
                    }
                });
            }
        });

        let named_inviter_id = [0xABu8; 32];
        assert_ne!(
            named_inviter_id, mallory_id,
            "the named inviter id must differ from the dialed endpoint's real id"
        );
        let invite = Invite {
            secret: [7u8; 32],
            inviter_id: named_inviter_id,
            inviter_addr_json: serde_json::to_string(&mallory_addr).unwrap(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
        };

        let bob = redeemer_endpoint().await;
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let err = redeem_invite(
            bob,
            "bob".into(),
            invite.encode(),
            None,
            bob_store.clone(),
            None,
            None,
        )
        .await
        .expect_err("a P3 id mismatch must fail the redeem");
        assert!(
            err.to_string().contains("address-swap") || err.to_string().contains("id mismatch"),
            "expected an address-swap / id-mismatch error, got: {err}"
        );
        // No dial-back entry under EITHER the named id or the dialed endpoint's real id.
        assert!(bob_store.resolve(&named_inviter_id).unwrap().is_none());
        assert!(bob_store.resolve(&mallory_id).unwrap().is_none());
        drop(bob_dir);
    })
    .await
    .expect("P3 negative test timed out");
}

/// Install (once) a process-global INFO fmt subscriber capturing every event into a shared
/// buffer, and return that buffer. Global (not thread-local) so the rendezvous handler's log is
/// captured no matter which iroh/tokio thread runs it. Idempotent via `OnceLock`; a
/// pre-existing global default (unexpected in this test binary) is tolerated.
fn global_log_buf() -> Arc<Mutex<Vec<u8>>> {
    static LOG_BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG_BUF
        .get_or_init(|| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let subscriber = tracing_subscriber::fmt()
                .with_writer(BufMakeWriter(buf.clone()))
                .with_max_level(tracing::Level::INFO)
                .with_ansi(false) // clean text for substring matching
                .with_target(true) // render the target so we can isolate OUR crate's lines
                .without_time()
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            buf
        })
        .clone()
}

/// A `MakeWriter` that appends every formatted log line into a shared buffer, so a test can
/// inspect exactly what the rendezvous logged.
#[derive(Clone)]
struct BufMakeWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufMakeWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufMakeWriter {
    type Writer = BufMakeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
