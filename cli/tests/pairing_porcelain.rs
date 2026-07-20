//! M2b Task 7 acceptance: the `invite` / `pair` / `pair --remove` porcelain.
//!
//! Two shapes, both hermetic (relay disabled → no network egress):
//!
//!  - **`invite` porcelain (subprocess).** The REAL `mcpmesh invite notes` binary auto-starts a
//!    detached daemon (the M2a auto-start harness) in an XDG-scoped tempdir, mints an invite, and
//!    prints the §1.5 surface-#2 block. We assert the exact output shape — the "One-time invite …"
//!    line, the copyable `mcpmesh-invite:` line, and the "can access" service list.
//!
//!  - **`pair --remove` functional truth (in-process).** We assemble a HERMETIC `MeshState`
//!    (temp config + temp store + a localhost endpoint) inside a `DaemonState`, seed a peer AND a
//!    service `allow` listing it, then call the REAL `daemon::remove_peer` handler and assert on
//!    the STORE + CONFIG (not `status` output — the T7 out-of-scope note): the PeerEntry is gone
//!    AND the nickname is stripped from every `[services.*].allow`. Re-removal + removal of an
//!    absent peer tear nothing down and are refused (no false success on a revocation surface).
//!
//! A full `pair <invite>` against a live inviter folds into Task 8's E2E; the `pair` OUTPUT shape
//! (SAS line + `<peer>/<service>` mounts) is covered by `main.rs`'s unit tests over `pair_lines`.
// Unix-only: the test process connects to the daemon's control endpoint at a hardcoded
// filesystem socket path (`connect_control(<tmp>/mcpmesh/mcpmesh.sock)`), the path the
// child computes on unix. On windows the endpoint is a hash-derived named pipe the test
// cannot reconstruct without a forbidden windows twin. Windows coverage for the control
// path lives at the transport layer (local-api transport::windows pipe tests) and the
// client protocol layer (local-api client.rs seam tests); a windows daemon-subprocess
// round-trip is deferred — see the plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh::control::DaemonState;
use mcpmesh::daemon::{self, MeshState, STACK_VERSION};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh_local_api::PeerRemoveParams;
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate};
use serde_json::json;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// The typed `peer_remove` params, as the control dispatcher hands them to `daemon::remove_peer`.
fn unpair(nickname: &str) -> PeerRemoveParams {
    PeerRemoveParams {
        nickname: nickname.into(),
    }
}

// ───────────────────────────── invite porcelain (subprocess) ─────────────────────────────

/// A hermetic launch env: the built `mcpmesh` binary + a tempdir runtime/config/data (mirrors
/// `daemon_autostart.rs::launch_in`). `relay_mode = "disabled"` keeps the daemon's endpoint
/// localhost-only (no relay egress in CI). `[services.notes]` is pre-registered (stub backend)
/// so `invite notes` passes the daemon's invite-time registration check the way a real serve'd
/// setup would. Returns (exe, socket, env-vars).
fn launch_in(
    dir: &Path,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    Vec<(OsString, OsString)>,
) {
    let runtime = dir.join("runtime");
    let config = dir.join("config");
    let data = dir.join("data");
    let config_mcpmesh = config.join("mcpmesh");
    std::fs::create_dir_all(&config_mcpmesh).unwrap();
    std::fs::write(
        config_mcpmesh.join("config.toml"),
        format!(
            "[network]\nrelay_mode = \"disabled\"\n\n[services.notes]\nrun = ['{STUB}']\nallow = []\n"
        ),
    )
    .unwrap();
    let socket = runtime.join("mcpmesh").join("mcpmesh.sock");
    let env = vec![
        (OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()),
        (OsString::from("XDG_CONFIG_HOME"), config.into_os_string()),
        (OsString::from("XDG_DATA_HOME"), data.into_os_string()),
    ];
    (cargo_bin("mcpmesh"), socket, env)
}

/// Run a porcelain subcommand as a subprocess with the hermetic env (the auto-started daemon
/// inherits it). Returns the captured output.
fn run_cmd(exe: &Path, env: &[(OsString, OsString)], args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mcpmesh subcommand")
}

async fn wait_until_down(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if connect_control(socket).await.is_err() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon still accepting connections after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    wait_until_down(socket).await;
}

/// `mcpmesh invite notes` prints the §1.5 surface-#2 block: the "One-time invite (expires …)"
/// header, the copyable `mcpmesh-invite:` line, and the "can access: notes" grant list. Drives the
/// REAL porcelain against an auto-started hermetic daemon.
#[tokio::test(flavor = "multi_thread")]
async fn invite_porcelain_prints_the_copyable_block() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, socket, env) = launch_in(tmp.path());

        let out = run_cmd(&exe, &env, &["invite", "notes"]);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "`mcpmesh invite notes` exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The header, with the friendly relative expiry.
        assert!(
            stdout.contains("One-time invite (expires in")
                && stdout.contains("Share it out-of-band"),
            "invite header missing:\n{stdout}"
        );
        // The copyable artifact (surface #2).
        assert!(
            stdout.contains("mcpmesh-invite:"),
            "invite line missing:\n{stdout}"
        );
        // The grant list is derived from the requested services arg.
        assert!(
            stdout.contains("Whoever redeems it can access: notes"),
            "grant list missing:\n{stdout}"
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("invite porcelain test timed out");
}

/// `mcpmesh invite` with NO services is an error (DECLARED: an invite granting nothing is useless).
/// The daemon is never even contacted — the porcelain rejects it up front. Non-zero exit, the
/// friendly message on stderr.
#[tokio::test(flavor = "multi_thread")]
async fn invite_with_no_services_is_an_error() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, _socket, env) = launch_in(tmp.path());

        let out = run_cmd(&exe, &env, &["invite"]);
        assert!(!out.status.success(), "empty invite must exit non-zero");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("specify at least one service to grant"),
            "expected the friendly empty-invite message, got: {stderr}"
        );
    })
    .await
    .expect("empty-invite test timed out");
}

/// `mcpmesh invite <unregistered>` is REFUSED by the daemon: an invite for a name with no
/// `[services.*]` registration would redeem fine and only fail at connect time on the FRIEND's
/// machine. Non-zero exit; the message names the missing service, lists what IS served (here:
/// the pre-registered `notes`), and points at `mcpmesh status` — no wire vocabulary.
#[tokio::test(flavor = "multi_thread")]
async fn invite_for_an_unregistered_service_is_refused() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, socket, env) = launch_in(tmp.path());

        let out = run_cmd(&exe, &env, &["invite", "nosuchsvc"]);
        assert!(
            !out.status.success(),
            "inviting an unregistered service must exit non-zero; stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no service named 'nosuchsvc'"),
            "the refusal names the missing service: {stderr}"
        );
        assert!(
            stderr.contains("you serve: notes") && stderr.contains("mcpmesh status"),
            "the refusal lists what IS served and points at status: {stderr}"
        );
        // Nothing was minted: no `mcpmesh-invite:` artifact anywhere in the output.
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("mcpmesh-invite:"),
            "no invite line may be printed on refusal"
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("unregistered-invite test timed out");
}

/// `mcpmesh pair --remove <unknown>` is an ERROR, not a false success: `pair --remove` is a
/// revocation surface, so a typo'd nickname must exit non-zero with a pointer at `mcpmesh status`
/// (the daemon reports that nothing was actually torn down). Drives the REAL porcelain + daemon.
#[tokio::test(flavor = "multi_thread")]
async fn pair_remove_of_an_unknown_nickname_is_refused() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, socket, env) = launch_in(tmp.path());

        let out = run_cmd(&exe, &env, &["pair", "--remove", "nobody"]);
        assert!(
            !out.status.success(),
            "removing an unknown peer must exit non-zero; stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("no paired peer named 'nobody'")
                && stderr.contains("'mcpmesh status' lists your peers"),
            "the refusal names the nickname and points at status: {stderr}"
        );
        // No false-success porcelain either.
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("Unpaired"),
            "no 'Unpaired …' success line may be printed on refusal"
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("unknown-nickname remove test timed out");
}

// ─────────────────────────── pair --remove functional (in-process) ───────────────────────────

/// A localhost-only endpoint advertising both ALPNs (matches the daemon's `build_endpoint` list),
/// so the `MeshState` we assemble behaves like production for the revoke's accept-loop reload.
async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind localhost endpoint")
}

fn seed_peer(store: &PeerStore, endpoint_id: [u8; 32], nickname: &str, services: &[&str]) {
    store
        .add(PeerEntry {
            endpoint_id,
            nickname: nickname.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            paired_at: Some("1751760000".into()),
            user_id: None,
            last_addr: None,
        })
        .unwrap();
}

/// `peer_remove` drops the peer's PeerEntry (identity) AND strips the nickname from EVERY
/// `[services.*].allow` (authorization) — asserted on the store + config directly (functional
/// truth, not `status`). A different peer (carol) sharing a service is left untouched.
/// Re-removal + removing an absent peer tear nothing down, so both are ERRORS (revocation must
/// never report false success) — and both leave the durable state untouched.
#[tokio::test(flavor = "multi_thread")]
async fn pair_remove_drops_the_peer_and_revokes_every_service_allow() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.redb");
        let config_path = dir.path().join("config.toml");
        // bob is allowed on BOTH notes and kb; carol shares kb (must survive bob's removal).
        std::fs::write(
            &config_path,
            format!(
                "[services.notes]\nrun = ['{STUB}']\nallow = [\"bob\"]\n\
                 [services.kb]\nrun = ['{STUB}']\nallow = [\"bob\", \"carol\"]\n"
            ),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let bob_id = [1u8; 32];
        let carol_id = [2u8; 32];
        seed_peer(&store, bob_id, "bob", &["notes", "kb"]);
        seed_peer(&store, carol_id, "carol", &["kb"]);

        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let endpoint = local_endpoint().await;
        let mesh = MeshState::new(
            endpoint,
            gate,
            store.clone(),
            Arc::new(LiveInvites::new()),
            "self".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let state = DaemonState::with_mesh(STACK_VERSION, mesh);

        // ── Unpair bob ──
        daemon::remove_peer(&state, unpair("bob"))
            .await
            .expect("peer_remove bob");

        // Identity: bob's PeerEntry is gone; carol's remains.
        assert!(
            store.resolve(&bob_id).unwrap().is_none(),
            "bob's PeerEntry must be removed"
        );
        assert!(
            store.resolve(&carol_id).unwrap().is_some(),
            "carol's PeerEntry must be untouched"
        );

        // Authorization: bob is stripped from EVERY service's allow on disk; carol survives in kb.
        let cfg = Config::load(&config_path).unwrap();
        assert!(
            cfg.services.get("notes").unwrap().allow.is_empty(),
            "bob must be revoked from notes.allow: {:?}",
            cfg.services.get("notes").unwrap().allow
        );
        assert_eq!(
            cfg.services.get("kb").unwrap().allow,
            vec!["carol".to_string()],
            "bob must be revoked from kb.allow, carol untouched"
        );

        // ── Re-removing bob tears nothing down (revoke changed=false, store no-op) → ERROR
        //    with the status pointer, so a repeated/typo'd revocation never reads as success ──
        let err = daemon::remove_peer(&state, unpair("bob"))
            .await
            .expect_err("re-removing an already-removed peer must error");
        assert!(
            err.to_string()
                .contains("no paired peer named 'bob' — 'mcpmesh status' lists your peers"),
            "the refusal names the nickname and points at status: {err}"
        );
        // ── Removing a never-present peer is the same refusal ──
        let err = daemon::remove_peer(&state, unpair("ghost"))
            .await
            .expect_err("removing an absent peer must error");
        assert!(
            err.to_string().contains("no paired peer named 'ghost'"),
            "the refusal names the nickname: {err}"
        );

        // State is stable after the refused removals.
        assert!(store.resolve(&bob_id).unwrap().is_none());
        assert!(store.resolve(&carol_id).unwrap().is_some());
        let cfg = Config::load(&config_path).unwrap();
        assert!(cfg.services.get("notes").unwrap().allow.is_empty());
        assert_eq!(
            cfg.services.get("kb").unwrap().allow,
            vec!["carol".to_string()]
        );

        std::mem::forget(dir); // keep the redb file alive for the store's lifetime
    })
    .await
    .expect("pair --remove test timed out");
}

/// Removing a peer that HAS a trust entry but is in NO service allow still drops the entry
/// cleanly (the revoke half is a no-op, the identity half does the work) — proves the two halves
/// are independent and the whole thing never errors on a peer with no authorization.
#[tokio::test(flavor = "multi_thread")]
async fn pair_remove_drops_a_peer_with_no_service_allow() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.redb");
        let config_path = dir.path().join("config.toml");
        // A service exists, but dave is NOT in its allow.
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = []\n"),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let dave_id = [3u8; 32];
        seed_peer(&store, dave_id, "dave", &[]);

        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let endpoint = local_endpoint().await;
        let mesh = MeshState::new(
            endpoint,
            gate,
            store.clone(),
            Arc::new(LiveInvites::new()),
            "self".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let state = DaemonState::with_mesh(STACK_VERSION, mesh);

        daemon::remove_peer(&state, unpair("dave"))
            .await
            .expect("peer_remove dave (no allow membership)");

        assert!(
            store.resolve(&dave_id).unwrap().is_none(),
            "dave's PeerEntry must be removed even with no allow membership"
        );
        // notes.allow stays empty; nothing corrupted.
        let cfg = Config::load(&config_path).unwrap();
        assert!(cfg.services.get("notes").unwrap().allow.is_empty());

        std::mem::forget(dir);
    })
    .await
    .expect("no-allow removal test timed out");
}

/// **M4b — `pair --remove` audits an unpair ONLY when something was actually torn down (§11.3).** The
/// `trust(event="unpair")` record must fire on a REAL unpair (a removed PeerEntry and/or a revoked
/// allow) but NOT on a remove of a never-paired nickname (both the revoke half — `changed=false` —
/// and the store remove tear nothing down, so the removal is REFUSED). Installs a real AuditLog,
/// removes a GHOST nickname (→ an error + ZERO unpair records) then removes bob (→ EXACTLY one
/// `trust(event="unpair", target="bob")`).
#[tokio::test(flavor = "multi_thread")]
async fn pair_remove_audits_a_real_unpair_but_not_a_no_op() {
    use mcpmesh::audit::{AuditLog, AuditSink, now_ts};
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("state.redb");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!("[services.notes]\nrun = ['{STUB}']\nallow = [\"bob\"]\n"),
        )
        .unwrap();

        let store = Arc::new(PeerStore::open(&db_path).unwrap());
        let bob_id = [1u8; 32];
        seed_peer(&store, bob_id, "bob", &["notes"]);

        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let endpoint = local_endpoint().await;
        let mesh = MeshState::new(
            endpoint,
            gate,
            store.clone(),
            Arc::new(LiveInvites::new()),
            "self".into(),
            config_path.clone(),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let audit_dir = dir.path().join("audit");
        mesh.set_audit(AuditSink::new(AuditLog::spawn(audit_dir.clone())));
        let state = DaemonState::with_mesh(STACK_VERSION, mesh);

        let month = &now_ts()[..7];
        let file = audit_dir.join(format!("{month}.jsonl"));

        // ── A remove of a never-paired nickname is REFUSED and must write NO unpair record ──
        daemon::remove_peer(&state, unpair("ghost"))
            .await
            .expect_err("removing an absent peer must error");
        // Give the async audit writer ample time to have flushed a record IF one were emitted.
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after_ghost = std::fs::read_to_string(&file).unwrap_or_default();
        assert_eq!(
            after_ghost.matches("\"event\":\"unpair\"").count(),
            0,
            "a refused remove of a never-paired nickname must NOT write a phantom unpair record: \
             {after_ghost}"
        );

        // ── A REAL unpair of bob writes EXACTLY one unpair record targeted at "bob" ──
        daemon::remove_peer(&state, unpair("bob"))
            .await
            .expect("peer_remove bob");
        let mut unpairs = 0;
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file) {
                unpairs = b.matches("\"event\":\"unpair\"").count();
                if unpairs >= 1 {
                    assert!(
                        b.contains("\"kind\":\"trust\"") && b.contains("\"target\":\"bob\""),
                        "the unpair record is a trust event targeted at bob: {b}"
                    );
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            unpairs, 1,
            "a real unpair writes exactly one trust(unpair) record"
        );

        std::mem::forget(dir);
    })
    .await
    .expect("unpair audit test timed out");
}
