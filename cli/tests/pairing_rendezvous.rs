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
use mcpmesh::pairing::rendezvous::{SelfBinding, redeem_invite};
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
        petname: "alice".into(),
        services: services.iter().map(|s| s.to_string()).collect(),
        expires_at_epoch,
    }
}

fn hello_frame(secret: &[u8; 32], redeemer_id: &[u8; 32], petname: &str) -> Value {
    json!({
        "secret": secret.to_vec(),
        "redeemer_id": redeemer_id.to_vec(),
        "redeemer_petname": petname,
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
/// petname-collision orphan-allow check + the grant can read real `[services.*].allow` entries)
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
        invites.mint(make_invite(secret, inviter_id, &["notes", "kb"], FUTURE));
        assert_eq!(invites.count(), 1);

        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        // The reply is PairReply::Ok carrying the inviter's identity (from the redeemed invite).
        assert_eq!(reply["result"], "ok", "expected Ok reply, got {reply}");
        assert_eq!(reply["inviter_petname"], "alice");
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
        // stamped paired_at, named by the redeemer's petname. Per §4.2's ASYMMETRIC grant, the
        // INVITER's entry for the redeemer carries NO service grants (`services == []`) — it is a
        // dial-back identity row, not a client-side dial directory. (T6 corrected this from T5's
        // earlier `invite.services`; `PeerEntry.services` is never an admission input, so this is
        // semantic cleanliness matching the spec, and authorization lives in config `allow`.)
        let entry = store
            .resolve(&redeemer_id)
            .unwrap()
            .expect("a PeerEntry must be written for the redeemer");
        assert_eq!(entry.petname, "bob");
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
        invites.mint(make_invite([1u8; 32], inviter_id, &["notes"], FUTURE));
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
        invites.mint(make_invite(secret, inviter_id, &["notes"], PAST));

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
        invites.mint(make_invite(secret, inviter_id, &["notes"], FUTURE));

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
        // isolate this crate's lines by target (`mcpmesh::…`) so iroh's internal INFO logging —
        // which may print endpoint ids and is not our surface — can't pollute the assertion. The
        // id-mismatch refusal line is unique to THIS test (others log a different reason), so its
        // presence confirms our handler's refusal log was captured.
        let logs = String::from_utf8(log_buf.lock().unwrap().clone()).unwrap();
        let ours: String = logs
            .lines()
            .filter(|l| l.contains("mcpmesh::"))
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
        invites.mint(make_invite([4u8; 32], inviter_id, &["notes"], FUTURE));

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
// Identity-confusion / privilege-escalation guard (T6 security fold-in). The redeemer's
// self-asserted petname becomes BOTH its resolved identity and the string appended to config
// `allow`, so a name that matches an existing identity would let it assume that identity's
// access. `handle_inviter_side` refuses such names BEFORE writing the PeerEntry / granting.
// These five cases lock in the security property AND that legitimate re-pairing still works.
// ---------------------------------------------------------------------------------------------

/// A pre-seeded store peer (the `internal peer add` shape — no `paired_at`).
fn seed_peer(store: &PeerStore, endpoint_id: [u8; 32], petname: &str, services: &[&str]) {
    store
        .add(PeerEntry {
            endpoint_id,
            petname: petname.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();
}

/// Case 1 — a fresh, unique petname not present in any store peer or any config allow is ALLOWED
/// (the guard must not break the normal first-pair path).
#[tokio::test]
async fn collision_guard_allows_a_fresh_unique_petname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) =
            setup_full(&format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n")).await;
        let redeemer_id = *redeemer.id().as_bytes();
        let secret = [21u8; 32];
        invites.mint(make_invite(secret, inviter_id, &["notes"], FUTURE));

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
        assert_eq!(entry.petname, "bob");
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(
            cfg.services.get("notes").unwrap().allow,
            vec!["bob".to_string()]
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
        invites.mint(make_invite(secret, inviter_id, &["notes"], FUTURE));
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

/// Case 3 — the SAME peer re-pairing to an ADDITIONAL service is ALLOWED even though its name is
/// already in the FIRST service's allow: the orphan-allow check is skipped because a store peer
/// (same id) backs the name — that's the peer's own grant, not an orphan.
#[tokio::test]
async fn collision_guard_allows_same_peer_additional_service() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, config_path) = setup_full(&format!(
            "[services.notes]\nrun = ['{STUB}']\nallow = [\"bob\"]\n\
             [services.kb]\nrun = ['{STUB}']\nallow = []\n"
        ))
        .await;
        let redeemer_id = *redeemer.id().as_bytes();
        // Bob already paired to notes (SAME id), and "bob" is already in notes' allow.
        seed_peer(&store, redeemer_id, "bob", &["notes"]);

        let secret = [23u8; 32];
        invites.mint(make_invite(secret, inviter_id, &["kb"], FUTURE));
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "bob")).await;

        assert_eq!(
            reply["result"], "ok",
            "the same peer pairing to an additional service must be allowed: {reply}"
        );
        // The grant added bob to kb's allow (and left notes' as-is).
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(
            cfg.services.get("kb").unwrap().allow,
            vec!["bob".to_string()]
        );
        assert_eq!(
            cfg.services.get("notes").unwrap().allow,
            vec!["bob".to_string()]
        );
    })
    .await
    .expect("additional-service re-pair test timed out");
}

/// Case 4 — impersonation: a peer "carol" (a DIFFERENT endpoint_id) already exists; a redeemer
/// that names itself "carol" is REFUSED (blocks assuming another peer's identity/access). No
/// entry is written under the redeemer's id and no grant happens; the invite is consumed.
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
        invites.mint(make_invite(secret, inviter_id, &["notes"], FUTURE));
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "carol")).await;

        // Generic refusal reason (no oracle), no entry under the redeemer's id, no grant.
        assert_eq!(
            reply["result"], "refused",
            "impersonation must be refused: {reply}"
        );
        assert_eq!(reply["reason"], "pairing refused");
        assert!(
            store.resolve(&redeemer_id).unwrap().is_none(),
            "no entry may be written under the impersonator's id"
        );
        let cfg = Config::load(&config_path).unwrap();
        assert!(
            cfg.services.get("notes").unwrap().allow.is_empty(),
            "no grant may be applied for an impersonation attempt"
        );
        assert_eq!(invites.count(), 0, "the burned invite is not preserved");
    })
    .await
    .expect("impersonation test timed out");
}

/// Case 5 — orphan-allow: config pre-provisions "carol" in a service's allow but NO store peer
/// holds that name; a redeemer that names itself "carol" is REFUSED (blocks inheriting a
/// pre-provisioned grant not backed by a known peer).
#[tokio::test]
async fn collision_guard_refuses_an_orphan_allow_name() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, store, invites, inviter_id, _cfg) = setup_full(&format!(
            "[services.notes]\nrun = ['{STUB}']\nallow = [\"carol\"]\n"
        ))
        .await;
        let redeemer_id = *redeemer.id().as_bytes();
        // No store peer named "carol" — but the name sits in notes' allow.

        let secret = [25u8; 32];
        invites.mint(make_invite(secret, inviter_id, &["notes"], FUTURE));
        let reply =
            drive_redeemer(&redeemer, addr, hello_frame(&secret, &redeemer_id, "carol")).await;

        assert_eq!(
            reply["result"], "refused",
            "an orphan-allow name must be refused: {reply}"
        );
        assert_eq!(reply["reason"], "pairing refused");
        assert!(
            store.resolve(&redeemer_id).unwrap().is_none(),
            "no entry may be written for an orphan-allow claim"
        );
        assert_eq!(invites.count(), 0, "the burned invite is not preserved");
    })
    .await
    .expect("orphan-allow test timed out");
}

// ---------------------------------------------------------------------------------------------
// Second-pairing MERGE semantics (the "reverse pairing clobbers the dial directory" fix).
// `PeerStore::add` is a replace-on-endpoint_id upsert, so the rendezvous write sites must
// resolve-then-merge: the inviter PRESERVES its stored petname + dial directory + proven
// user_id; the redeemer UNIONs a repeat grant and takes the new invite's suggested petname.
// ---------------------------------------------------------------------------------------------

/// Reverse pairing preserves the inviter's dial directory, petname, and proven user_id.
///
/// The user story: Alice invited Bob first (Bob redeemed → BOB's alice-entry carries
/// `services = ["notes"]`, his chosen name "alice", her proven user_id). Later BOB invites Alice
/// back (to grant her his "code" service). Bob is now the INVITER: his side's write must MERGE
/// into his existing alice-entry, not replace it with the fresh `{services: []}` dial-back row —
/// and the authorization grant must admit her STORED petname (the name his gate resolves her
/// dials to), not her self-suggestion.
#[tokio::test]
async fn reverse_pairing_preserves_the_inviters_dial_directory_and_petname() {
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
                petname: "alice".into(),
                services: vec!["notes".into()],
                paired_at: Some("1000".into()),
                user_id: Some("b64u:ALICE".into()),
                last_addr: None,
            })
            .unwrap();

        // Alice redeems Bob's invite, self-suggesting a DIFFERENT name and presenting NO binding.
        let secret = [31u8; 32];
        invites.mint(make_invite(secret, inviter_id, &["code"], FUTURE));
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
            entry.petname, "alice",
            "the inviter's chosen petname must not be renamed by the redeemer's self-suggestion"
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
        // The authorization grant admits her STORED petname — the name the gate resolves her to.
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(
            cfg.services.get("code").unwrap().allow,
            vec!["alice".to_string()],
            "the grant must target the stored petname, not the self-suggestion"
        );
    })
    .await
    .expect("reverse-pairing merge test timed out");
}

/// A REPEAT grant on the REDEEMER side UNIONs the dial directory (dedup, stable order: existing
/// first, new appended), applies the NEW invite's suggested petname (rename-by-a-fresh-invite is
/// a deliberate feature), and never clobbers a verified user_id to None.
#[tokio::test]
async fn repeat_grant_unions_the_redeemers_dial_directory_and_applies_the_new_petname() {
    timeout(Duration::from_secs(60), async {
        let (redeemer, addr, _store, invites, inviter_id, _cfg) = setup_full("").await;
        // The redeemer ALREADY paired with this inviter once: notes granted, her user_id proven,
        // named "alice-old" by the earlier invite.
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        bob_store
            .add(PeerEntry {
                endpoint_id: inviter_id,
                petname: "alice-old".into(),
                services: vec!["notes".into()],
                paired_at: Some("1000".into()),
                user_id: Some("b64u:ALICE".into()),
                last_addr: None,
            })
            .unwrap();

        // A SECOND invite from the SAME inviter: re-grants notes (dedup) plus kb, and suggests a
        // NEW petname. The inviter presents no binding (no self_binding installed in setup_full).
        let secret = [32u8; 32];
        let invite = Invite {
            secret,
            inviter_id,
            inviter_addr_json: serde_json::to_string(&addr).unwrap(),
            petname: "alice".into(),
            services: vec!["kb".into(), "notes".into()],
            expires_at_epoch: FUTURE,
        };
        invites.mint(invite.clone());

        let result = redeem_invite(
            redeemer,
            "bob".into(),
            invite.encode(),
            bob_store.clone(),
            None,
        )
        .await
        .expect("the second redeem succeeds");
        assert_eq!(result.peer_petname, "alice");

        let entry = bob_store
            .resolve(&inviter_id)
            .unwrap()
            .expect("the alice entry survives the repeat grant");
        assert_eq!(
            entry.petname, "alice",
            "the NEW invite's suggested petname is applied (rename-by-fresh-invite)"
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

/// **The load-bearing seam, end to end (M2b T6 Step 5).** A REAL redeemer (`redeem_invite`) pairs
/// with a REAL serving inviter over the daemon's own accept loop, and the payoff is proven: the
/// paired+granted peer is ACTUALLY ADMITTED to the granted service over a mesh (mcp/1) session.
/// This is the whole point of T6 — PeerEntry (identity) + config `allow` (authorization) together
/// admit the peer, and the inviter-side grant appends the redeemer to `[services.notes].allow` +
/// reloads so `select_service` says yes.
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
            petname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
        };
        invites.mint(invite.clone());

        // ---- Bob redeems it (real dial over the accept loop) ----
        let bob = redeemer_endpoint().await;
        let bob_id = *bob.id().as_bytes();
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let result = redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            bob_store.clone(),
            None,
        )
        .await
        .expect("redeem_invite dials, verifies the inviter id, sends the secret, succeeds");
        assert_eq!(result.peer_petname, "alice");
        // The PairResult carries the granted services (from the invite) so the porcelain can print
        // the "You can mount: alice/notes" line without re-decoding the invite (M2b T7).
        assert_eq!(result.services, vec!["notes".to_string()]);

        // ---- Mutual entries with the CORRECT asymmetric services (§4.2) ----
        // Bob's alice-entry: services == [notes] (what bob may dial), paired_at set.
        let bob_side = bob_store
            .resolve(&alice_id)
            .unwrap()
            .expect("bob's store has an alice entry");
        assert_eq!(bob_side.petname, "alice");
        assert_eq!(bob_side.services, vec!["notes".to_string()]);
        assert!(bob_side.paired_at.is_some());
        // Alice's bob-entry: services == [] (dial-back identity only), paired_at set.
        let alice_side = store
            .resolve(&bob_id)
            .unwrap()
            .expect("alice's store has a bob entry");
        assert_eq!(alice_side.petname, "bob");
        assert!(
            alice_side.services.is_empty(),
            "alice's dial-back entry carries no service grants (§4.2): {:?}",
            alice_side.services
        );
        assert!(alice_side.paired_at.is_some());

        // ---- The GRANT took effect on disk: [services.notes].allow now lists bob ----
        let after = Config::load(&config_path).unwrap();
        assert_eq!(
            after.services.get("notes").unwrap().allow,
            vec!["bob".to_string()],
            "the pairing grant must append bob to [services.notes].allow"
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
        let mut transport = connect(&bob, alice_addr, "notes").await.unwrap();
        transport
            .send_value(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
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

/// **Self-sovereign identity adoption (device->user binding), end to end.** When BOTH sides present
/// a device->user binding at pairing, each stores the OTHER's PROVEN `user_id` on its `PeerEntry`,
/// verified against the TLS-authenticated endpoint (never a self-asserted id) — so kb audiences can
/// later key on the USER, not just the per-device petname. Backward-compat (no binding → `user_id:
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
            petname: "alice".into(),
            services: vec![],
            expires_at_epoch: FUTURE,
        };
        invites.mint(invite.clone());

        // ---- Bob redeems, presenting HIS own binding over his endpoint ----
        let bob = redeemer_endpoint().await;
        let bob_id = *bob.id().as_bytes();
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let (bob_uk, _) =
            mcpmesh_trust::UserKey::load_or_generate(&bob_dir.path().join("bob-user.key")).unwrap();
        let bob_user_id = mcpmesh_trust::binding::user_id(&bob_uk);
        let (b_pk, b_sig) = mcpmesh_trust::binding::present(&bob_uk, &bob_id);

        redeem_invite(
            bob.clone(),
            "bob".into(),
            invite.encode(),
            bob_store.clone(),
            Some(SelfBinding {
                user_pk: b_pk,
                sig: b_sig,
            }),
        )
        .await
        .expect("redeem succeeds and exchanges self-sovereign bindings");

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
            petname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch: FUTURE,
        };

        let bob = redeemer_endpoint().await;
        let bob_dir = tempfile::tempdir().unwrap();
        let bob_store = Arc::new(PeerStore::open(&bob_dir.path().join("state.redb")).unwrap());
        let err = redeem_invite(bob, "bob".into(), invite.encode(), bob_store.clone(), None)
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
