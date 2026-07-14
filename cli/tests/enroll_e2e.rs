//! M3b Task 12 — the ENROLLMENT E2E (spec §16 M3 AC "full enrollment via porcelain only"), end to
//! end into real enforcement. A subprocess porcelain enrollment PRODUCES a signed roster; that same
//! roster + the joiner's REAL device key then drive real group admission + D8 revocation over a
//! localhost mesh (reusing M3a's `hero_flow_roster.rs` in-process harness). This is the porcelain
//! capstone: M3a proved the ENFORCEMENT core against a HAND-minted roster; M3b proves the PORCELAIN
//! (`org create`/`join`/`approve`/`revoke`) mints the roster that drives the exact same enforcement.
//!
//! ── sub-phase → AC-clause mapping (DECLARED; mirrors `hero_flow_roster.rs`) ──
//!   * **"full enrollment via porcelain only"** → Phase A (`org create` → `join` → `org approve`, all
//!     subprocess `mcpmesh …`): the resulting `roster.json` VERIFIES against the org root (`sign::verify`)
//!     and carries alice/team-eng/the joiner's device at serial 2 — no roster hand-editing anywhere.
//!   * **"group-based allow works"** → Phase B step 4: the porcelain-produced serial-2 roster admits
//!     alice via the `team-eng` GROUP arm (`allow = ["team-eng"]`, not a user_id/petname); the served
//!     child sees the §6.3 identity env (`MCPMESH_PEER_USER=alice` + `MCPMESH_PEER_GROUPS` ∋ `team-eng`).
//!   * **"revoked device cut from live sessions"** → Phase B step 5: the porcelain-produced serial-3
//!     roster (`org revoke alice/laptop`) installed into the in-process operator mesh SEVERS alice's
//!     live session (assert-on-close, then `ConnRegistry` len settles) and refuses her re-dial pre-MCP.
//!     The "stale pair entry" variant is already proven by `hero_flow_roster.rs`; M3b proves the
//!     porcelain produces the roster that drives it.
//!
//! ── revoke sequencing (DECLARED) ── `org revoke` is an operator-SUBPROCESS command that needs the
//! operator daemon, but Phase B.1 shuts that daemon down (so only the in-process endpoints are live).
//! So ALL porcelain (create/join/approve/revoke) runs in Phase A while the operator daemon is alive,
//! capturing BOTH `roster.json` states as file ARTIFACTS (serial 2 post-approve, serial 3 post-revoke).
//! Phase B then shuts the daemons down and installs each PORCELAIN-produced artifact into the
//! in-process operator mesh (serial 2 → group admit; serial 3 → D8 sever). The revoke roster is thus
//! porcelain-produced, never hand-mutated — the AC clause holds end to end.
//!
//! ── the artifact bridge (DECLARED) ── Phase B builds the joiner's in-process iroh endpoint from
//! Phase A's `device.key` FILE (`DeviceKey::load_or_generate` → `SecretKey::from_bytes(secret_bytes)`),
//! so its endpoint id == the join code's `device_endpoint_id` == the roster device record — the SAME
//! identity flows porcelain → roster → enforcement (asserted explicitly). Cross-node roster
//! DISTRIBUTION is M3c; here the operator installs the roster in-process (the manual convergence path).
//!
//! (Copy `launch_in`/`run_cmd`/`shutdown_daemon` + the stdout extractors from `roster_install.rs` /
//!  `org_enroll.rs`; copy `dual_alpn_endpoint` / `wait_for_len` / the `MeshState` assembly + the echo
//!  stub from `hero_flow_roster.rs`. The harness is not yet a shared module, so the helpers are copied
//!  as those tests do.)
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use ed25519_dalek::VerifyingKey;
use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::client::connect_control;
use mcpmesh::daemon::{
    MeshState, build_services, install_roster_view_and_sever, spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::RosterStore;
use mcpmesh::roster::enroll::{JoinCode, OrgInviteCode};
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, TrustGate, connect};
use mcpmesh_trust::DeviceKey;
use mcpmesh_trust::roster::{Roster, decode_endpoint_id, encode_b64u, sign};
use serde_json::json;
use tokio::time::timeout;

/// The hermetic echo MCP stub — echoes a `tools/call` payload plus the injected identity env
/// (`peer_name`/`peer_user`/`peer_groups`), so the E2E can assert the §6.3 injection at the child.
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

// ── Phase-A subprocess harness (copied verbatim from `roster_install.rs` / `org_enroll.rs`) ────────

/// A hermetic launch env: the built `mcpmesh` binary + a tempdir runtime/config/data. `relay_mode =
/// "disabled"` keeps the auto-started daemon's endpoint localhost-only (no relay egress in CI).
/// Returns (exe, socket, config-dir, env-vars).
fn launch_in(dir: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<(OsString, OsString)>) {
    let runtime = dir.join("runtime");
    let config = dir.join("config");
    let data = dir.join("data");
    let config_mcpmesh = config.join("mcpmesh");
    std::fs::create_dir_all(&config_mcpmesh).unwrap();
    std::fs::write(
        config_mcpmesh.join("config.toml"),
        "[network]\nrelay_mode = \"disabled\"\n",
    )
    .unwrap();
    let socket = runtime.join("mcpmesh").join("mcpmesh.sock");
    let env = vec![
        (OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()),
        (OsString::from("XDG_CONFIG_HOME"), config.into_os_string()),
        (OsString::from("XDG_DATA_HOME"), data.into_os_string()),
    ];
    (cargo_bin("mcpmesh"), socket, config_mcpmesh, env)
}

/// Run a porcelain subcommand as a subprocess with the hermetic env (the auto-started daemon inherits
/// it). Returns the captured output.
fn run_cmd(exe: &Path, env: &[(OsString, OsString)], args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mcpmesh subcommand")
}

/// Shut a subprocess daemon down over its control socket, then wait until it stops accepting.
async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while connect_control(socket).await.is_ok() {
        assert!(
            Instant::now() < deadline,
            "daemon still accepting connections after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The `word-word-word-word` fingerprint token on the (first) line CONTAINING `label` (splits on
/// whitespace, returns the first token with a '-'). Distinguishes the org-root-fingerprint line.
fn fingerprint_after(label: &str, out: &str) -> String {
    out.lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split_whitespace().find(|w| w.contains('-')))
        .unwrap_or("")
        .to_string()
}

/// The opaque `mcpmesh-org:…` invite token from `org create` stdout (a single whitespace-free word).
fn org_invite_from(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.split_whitespace().find(|w| w.starts_with("mcpmesh-org:")))
        .expect("an org invite code")
        .to_string()
}

/// The opaque `mcpmesh-join:…` code token from `join` stdout (a single whitespace-free word).
fn join_code_from(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            l.split_whitespace()
                .find(|w| w.starts_with("mcpmesh-join:"))
        })
        .expect("a join code")
        .to_string()
}

/// Wall-clock now as epoch seconds (i64) — the validity-window anchor for `install_from_file`.
fn now_epoch_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The installed roster body under a temp config dir.
fn read_roster(config_dir: &Path) -> Roster {
    serde_json::from_slice(&std::fs::read(config_dir.join("roster.json")).unwrap()).unwrap()
}

// ── Phase-B in-process mesh helpers (copied from `hero_flow_roster.rs`) ─────────────────────────────

/// A localhost-only endpoint seeded from a KNOWN secret key (the artifact bridge: the joiner's
/// endpoint is built from ITS `device.key`, so its id == the roster device record). `alpns` selects
/// mesh-only (client) vs. mesh+pair (server). Relay disabled → localhost, no egress (mirrors
/// `build_endpoint`).
async fn endpoint_from_secret(secret: iroh::SecretKey, alpns: Vec<Vec<u8>>) -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .expect("bind endpoint from a known device key")
}

/// A localhost-only server endpoint advertising BOTH mesh + pair ALPNs (a fresh random identity — the
/// operator's mesh identity is orthogonal to the roster), so we drive the daemon's real accept loop.
async fn dual_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec()])
        .bind()
        .await
        .expect("bind dual-ALPN endpoint")
}

/// The `initialize` frame naming `service` in the reserved `_meta` (spec §7.2, so `select_service`
/// routes it) — mirrors `hero_flow_roster.rs`.
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

/// Poll `registry.len()` to `target` (up to ~5s). A secondary check AFTER a connection-close
/// observation: `sever_matching` closes connections but defers map removal to the severed handler's
/// RAII Drop, so a synchronous `len()` right after sever can transiently overcount — assert on the
/// close first, then let `len()` settle here (the `hero_flow_roster.rs` discipline).
async fn wait_for_len(registry: &ConnRegistry, target: usize) {
    for _ in 0..50 {
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

/// **The §16 M3 AC "full enrollment via porcelain only", end to end.** Phase A drives the enrollment
/// porcelain as SUBPROCESSES to PRODUCE a signed roster (no hand-editing); Phase B feeds that produced
/// roster + the joiner's REAL device key into the in-process enforcement mesh — group admission, then
/// a porcelain-produced `org revoke` cuts the live session. See the module doc for the full sub-phase
/// → AC-clause mapping + the revoke sequencing.
#[tokio::test(flavor = "multi_thread")]
async fn full_enrollment_via_porcelain_admits_a_group_service_and_revocation_cuts_it() {
    timeout(Duration::from_secs(120), async {
        // ────────────────────────── Phase A: porcelain-only enrollment (subprocess) ──────────────────
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, opcfg, openv) = launch_in(opdir.path());
        let jdir = tempfile::tempdir().unwrap();
        let (jexe, jsock, jcfg, jenv) = launch_in(jdir.path());

        // ── `org create acme`: mint the org root, sign an empty roster, pin it; capture invite + fp_op.
        let create = run_cmd(&opexe, &openv, &["org", "create", "acme"]);
        assert!(
            create.status.success(),
            "org create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );
        let invite = org_invite_from(&create);
        let fp_op = fingerprint_after(
            "Org root fingerprint:",
            &String::from_utf8_lossy(&create.stdout),
        );
        assert!(!fp_op.is_empty(), "operator prints an org-root fingerprint");
        // The org root pubkey (from the invite) — the trust anchor Phase B verifies the roster against.
        let org_root_pub: VerifyingKey = {
            let ic = OrgInviteCode::decode(&invite).expect("decode org invite");
            let bytes = decode_endpoint_id(&ic.org_root_pk).expect("decode org_root_pk");
            VerifyingKey::from_bytes(&bytes).expect("org root pk is a valid key")
        };

        // ── `join <invite> --name Alice --user-id alice --label laptop`: the §4.4 ceremony.
        let join = run_cmd(
            &jexe,
            &jenv,
            &[
                "join", &invite, "--name", "Alice", "--user-id", "alice", "--label", "laptop",
            ],
        );
        assert!(
            join.status.success(),
            "join failed: {}",
            String::from_utf8_lossy(&join.stderr)
        );
        let join_code = join_code_from(&join);
        // Ceremony 1 (person→org-root): the joiner's org-root fingerprint EQUALS the operator's fp_op.
        assert_eq!(
            fingerprint_after("Org root fingerprint:", &String::from_utf8_lossy(&join.stdout)),
            fp_op,
            "the joiner's org-root fingerprint must match the operator's (the §4.4 ceremony)"
        );
        // The user key is minted 0600 (local; only its public half + the binding sig ride out).
        let ukey = jcfg.join("user.key");
        assert!(ukey.exists(), "the user key is minted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ukey).unwrap().permissions().mode() & 0o777,
                0o600,
                "the user key must be 0600"
            );
        }
        // Config pinned: org_id / org_root_pk / user_id / user_key.
        let jcfg_txt = std::fs::read_to_string(jcfg.join("config.toml")).unwrap();
        assert!(jcfg_txt.contains("org_id = \"acme\""), "config pins org_id");
        assert!(jcfg_txt.contains("org_root_pk"), "config pins org_root_pk");
        assert!(jcfg_txt.contains("user_id = \"alice\""), "config pins user_id");
        assert!(jcfg_txt.contains("user_key"), "config pins the user key path");
        // The joiner's device endpoint (verbatim from the join code) — the roster device + the bridge.
        let jc = JoinCode::decode(&join_code).expect("decode join code");
        let joiner_device_b64u = jc.device_endpoint_id.clone();

        // ── `org approve <join-code> --groups team-eng`: PRODUCE the signed serial-2 roster.
        let approve = run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &join_code, "--groups", "team-eng"],
        );
        assert!(
            approve.status.success(),
            "org approve failed: {}",
            String::from_utf8_lossy(&approve.stderr)
        );
        let roster2 = read_roster(&opcfg);
        assert_eq!(roster2.serial, 2, "approve bumps the roster to serial 2");
        let alice = roster2
            .users
            .iter()
            .find(|u| u.user_id == "alice")
            .expect("alice enrolled by the porcelain");
        assert!(
            alice.groups.contains(&"team-eng".to_string()),
            "alice is in the team-eng group: {:?}",
            alice.groups
        );
        assert_eq!(alice.devices.len(), 1, "alice has the one enrolled device");
        assert_eq!(
            alice.devices[0].endpoint_id, joiner_device_b64u,
            "the roster device record == the join code's device endpoint"
        );
        // The PORCELAIN produced a correctly SIGNED roster — no hand-editing anywhere (the AC).
        sign::verify(&roster2, &org_root_pub)
            .expect("the porcelain-produced serial-2 roster verifies against the org root");
        // Snapshot the serial-2 artifact BEFORE the revoke overwrites roster.json in place.
        let serial2_file = opdir.path().join("roster-serial2.json");
        std::fs::copy(opcfg.join("roster.json"), &serial2_file).unwrap();

        // ── `org revoke alice/laptop`: PRODUCE the signed serial-3 roster (revoking the device).
        // Sequenced here (Phase A, operator daemon alive) so Phase B can run purely in-process (B.1).
        let revoke = run_cmd(&opexe, &openv, &["org", "revoke", "alice/laptop"]);
        assert!(
            revoke.status.success(),
            "org revoke failed: {}",
            String::from_utf8_lossy(&revoke.stderr)
        );
        let roster3 = read_roster(&opcfg);
        assert_eq!(roster3.serial, 3, "revoke bumps the roster to serial 3");
        assert_eq!(
            roster3.revoked_endpoints,
            vec![joiner_device_b64u.clone()],
            "the joiner's device is the sole revoked endpoint"
        );
        assert!(
            roster3
                .users
                .iter()
                .find(|u| u.user_id == "alice")
                .map(|u| u.devices.is_empty())
                .unwrap_or(true),
            "alice's device list is emptied by the revoke"
        );
        sign::verify(&roster3, &org_root_pub)
            .expect("the porcelain-produced serial-3 roster verifies against the org root");
        let serial3_file = opdir.path().join("roster-serial3.json");
        std::fs::copy(opcfg.join("roster.json"), &serial3_file).unwrap();

        // ── B.1: shut the Phase-A subprocess daemons down — only the in-process endpoints stay live.
        shutdown_daemon(&opsock).await;
        shutdown_daemon(&jsock).await;

        // ────────────────────────── Phase B: the produced roster drives enforcement ──────────────────
        // ── B.2: build the joiner's in-process endpoint from ITS device.key (the artifact bridge).
        let (joiner_dk, _) =
            DeviceKey::load_or_generate(&jcfg.join("device.key")).expect("load joiner device key");
        assert_eq!(
            encode_b64u(&joiner_dk.public_bytes()),
            joiner_device_b64u,
            "the joiner's device.key pubkey == the join code's device endpoint == the roster record"
        );
        let joiner_secret = iroh::SecretKey::from_bytes(&joiner_dk.secret_bytes());
        let joiner_client = endpoint_from_secret(joiner_secret, vec![ALPN_MCP.to_vec()]).await;
        assert_eq!(
            encode_b64u(joiner_client.id().as_bytes()),
            joiner_device_b64u,
            "the in-process joiner endpoint id == the roster device record (the identity flows through)"
        );

        // ── B.3: build the in-process OPERATOR mesh serving `echo` with `allow = ["team-eng"]`.
        let bdir = tempfile::tempdir().unwrap();
        let cfg = mcpmesh::config::Config::from_toml_str(&format!(
            "[services.echo]\nrun = ['{STUB}']\nallow = [\"team-eng\"]\n"
        ))
        .expect("parse operator config");
        // Empty pairing store — alice is admitted PURELY by the roster group, nothing else.
        let store = Arc::new(PeerStore::open(&bdir.path().join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));
        let roster = Arc::new(RosterGate::empty());
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
        let conn_registry = Arc::new(ConnRegistry::new());

        let server = dual_alpn_endpoint().await;
        let addr = server.addr();
        let mesh = MeshState::new(
            server,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "operator".into(),
            bdir.path().join("config.toml"),
            roster.clone(),
            conn_registry.clone(),
            None,
            None,
            None,
            None,
        );
        let _task = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));

        // ── B.4: install the PORCELAIN-produced serial-2 roster → group admit + identity injection.
        // Install via the SAME persist→validate→swap→sever pipeline the daemon runs; no live sessions
        // yet, so it severs 0. One `RosterStore` tracks the installed serial (0 → 2 → 3, monotone).
        let rstore = RosterStore::new(bdir.path().join("installed-roster.json"));
        let now = now_epoch_i64();
        let view2 = rstore
            .install_from_file(&serial2_file, &org_root_pub, now)
            .expect("install the porcelain-produced serial-2 roster");
        assert_eq!(
            install_roster_view_and_sever(&mesh, view2),
            0,
            "installing the first roster severs nothing (no live sessions yet)"
        );

        // The joiner dials `echo`: the composed gate resolves her to {name:alice, user_id:Some(alice),
        // groups:[team-eng]}; select_service admits via the GROUP arm (allow=["team-eng"]).
        let mut joiner_t = connect(&joiner_client, addr.clone(), "echo")
            .await
            .expect("the rostered joiner dials echo");
        joiner_t.send_value(initialize_frame("echo")).await.unwrap();
        let init = joiner_t.recv_value().await.unwrap().unwrap();
        assert_eq!(
            init["result"]["serverInfo"]["name"], "echo-stub",
            "group-based allow must admit the porcelain-enrolled joiner to a live session: {init}"
        );

        // tools/call → the echo child answers AND reports the injected §6.3 identity env.
        joiner_t.send_value(tools_call_frame("group-admit")).await.unwrap();
        let reply = timeout(Duration::from_secs(5), joiner_t.recv_value())
            .await
            .expect("echo reply must arrive promptly")
            .expect("transport ok")
            .expect("reply frame");
        assert_eq!(reply["result"]["content"][0]["text"], "group-admit");
        assert_eq!(
            reply["result"]["peer_user"], "alice",
            "MCPMESH_PEER_USER = the roster user_id: {reply}"
        );
        let groups = reply["result"]["peer_groups"].as_str().unwrap_or_default();
        assert!(
            groups.split(',').any(|g| g == "team-eng"),
            "MCPMESH_PEER_GROUPS must contain the admitting group `team-eng`, got {groups:?}: {reply}"
        );
        // The live session is registered before we revoke.
        wait_for_len(&conn_registry, 1).await;

        // ── B.5: install the PORCELAIN-produced serial-3 roster → D8 severs the live session.
        let view3 = rstore
            .install_from_file(&serial3_file, &org_root_pub, now)
            .expect("install the porcelain-produced serial-3 (revoking) roster");
        let severed = install_roster_view_and_sever(&mesh, view3);
        assert_eq!(
            severed, 1,
            "exactly the revoked joiner's live session is severed"
        );

        // (a) alice's live session is SEVERED — its next recv observes the close (assert on the CLOSE,
        //     not a synchronous len()).
        let after = timeout(Duration::from_secs(5), joiner_t.recv_value())
            .await
            .expect("the severed session must close promptly, not hang");
        assert!(
            !matches!(after, Ok(Some(_))),
            "the revoked joiner's live session must be severed, got: {after:?}"
        );

        // (b) a FRESH dial from the (now-revoked) joiner endpoint is refused PRE-MCP (revocation wins).
        match connect(&joiner_client, addr.clone(), "echo").await {
            Err(_) => {} // refused at/near handshake — a valid "closed" outcome
            Ok(mut t) => {
                let _ = t.send_value(initialize_frame("echo")).await;
                let res = timeout(Duration::from_secs(5), t.recv_value())
                    .await
                    .expect("a revoked re-dial must close promptly, not hang");
                assert!(
                    !matches!(res, Ok(Some(_))),
                    "a revoked endpoint must be refused pre-MCP, got: {res:?}"
                );
            }
        }

        // Secondary: after the severed handler task unwinds, the registry settles to empty.
        wait_for_len(&conn_registry, 0).await;
    })
    .await
    .expect("enrollment E2E timed out");
}
