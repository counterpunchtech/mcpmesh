//! Task 3 auto-start integration test. Drives the REAL `mcpmesh` binary as a detached daemon
//! (via `assert_cmd::cargo::cargo_bin`) plus the library client, in a hermetic tempdir whose
//! runtime dir is passed to the daemon CHILD's env — the test never mutates its own env
//! (`set_var` is `unsafe` under `forbid(unsafe)`), so the socket path is derived explicitly
//! and handed to the daemon out of band.
// Unix-only: the launch fixture hardcodes the control endpoint as a filesystem socket path
// (`<tmp>/mcpmesh/mcpmesh.sock`) and the test asserts `launch.socket.exists()` + dials it
// via `connect_control`. On windows the endpoint is a hash-derived named pipe with no
// filesystem presence, unreconstructable without a forbidden windows twin. Windows coverage
// for the control path lives at the transport layer (local-api transport::windows pipe
// tests) and the client protocol layer (local-api client.rs seam tests); a windows
// daemon-subprocess autostart round-trip is deferred — see the plan's Task 6 "Windows
// coverage gap" note.
#![cfg(unix)]
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use mcpmesh::client::{ControlClient, DaemonLaunch, connect_control, ensure_daemon_with};
use mcpmesh::daemon::STACK_VERSION;
use mcpmesh::{Request, StatusResult};
use mcpmesh_local_api::{BackendSpec, RegisterServiceParams};
use serde_json::json;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// Scan `s` against the CANONICAL transport-vocabulary blocklist (spec §1.5/§17) — the ONE
/// shared fixture at `fixtures/transport-vocabulary.json`, also consumed by
/// the host/kb/loc surface-leak suites. Returns the first banned term found, or `None`.
///
/// Matching semantics (mirrors the fixture's note + the kb suite): case-insensitive;
/// `carve_outs` (spec-canonical identifiers that legitimately embed a banned substring) are
/// neutralized first; `substring_banned` terms match anywhere; `token_banned` terms match as
/// whole IDENTIFIER tokens (`_` is a word char, so a domain compound like `index_serial`
/// never false-trips).
fn transport_vocab_violation(s: &str) -> Option<String> {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../fixtures/transport-vocabulary.json"
    );
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fixture_path).expect("read the canonical fixture"),
    )
    .expect("fixture parses");
    let terms = |key: &str| -> Vec<String> {
        fixture[key]
            .as_array()
            .expect(key)
            .iter()
            .map(|v| v.as_str().expect("term is a string").to_string())
            .collect()
    };
    let mut lower = s.to_lowercase();
    for carve in terms("carve_outs") {
        lower = lower.replace(&carve.to_lowercase(), "carved_out");
    }
    for banned in terms("substring_banned") {
        if lower.contains(&banned) {
            return Some(banned);
        }
    }
    terms("token_banned").into_iter().find(|word| {
        lower
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|tok| tok == word)
    })
}

/// A hermetic launch spec: the built binary + a tempdir runtime/config/data passed to the
/// daemon child. The socket path mirrors what the daemon computes from `XDG_RUNTIME_DIR`
/// (`$XDG_RUNTIME_DIR/mcpmesh/mcpmesh.sock`). Since Task 9 the daemon also builds the Iroh
/// endpoint and opens `state.redb`, so the data dir must be hermetic too (`XDG_DATA_HOME`),
/// and a `relay_mode = "disabled"` config keeps the endpoint localhost-only (no relay egress
/// in CI). The config file is written under `XDG_CONFIG_HOME/mcpmesh/config.toml`.
fn launch_in(dir: &Path) -> DaemonLaunch {
    launch_with_config(dir, "[network]\nrelay_mode = \"disabled\"\n")
}

/// [`launch_in`] with explicit config contents — the seam for the autostart-failure tests,
/// which need a config the daemon REFUSES to start on.
fn launch_with_config(dir: &Path, config_toml: &str) -> DaemonLaunch {
    let runtime = dir.join("runtime");
    let config = dir.join("config");
    let data = dir.join("data");
    let config_mcpmesh = config.join("mcpmesh");
    std::fs::create_dir_all(&config_mcpmesh).unwrap();
    std::fs::write(config_mcpmesh.join("config.toml"), config_toml).unwrap();
    DaemonLaunch {
        exe: cargo_bin("mcpmesh"),
        socket: runtime.join("mcpmesh").join("mcpmesh.sock"),
        env: vec![
            (OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()),
            (OsString::from("XDG_CONFIG_HOME"), config.into_os_string()),
            (OsString::from("XDG_DATA_HOME"), data.into_os_string()),
        ],
    }
}

async fn status(client: &mut ControlClient) -> StatusResult {
    let result = client
        .request(Request::Status)
        .await
        .expect("status request");
    serde_json::from_value(result).expect("StatusResult deserializes")
}

/// Poll until the socket stops accepting connections (the daemon has exited).
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

#[tokio::test(flavor = "multi_thread")]
async fn ensure_daemon_autostarts_reuses_and_serves_status() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());

        // First call: socket dead → a detached daemon is auto-started and the hello read.
        let mut first = ensure_daemon_with(&launch)
            .await
            .expect("first ensure_daemon");
        assert_eq!(first.hello().api, "mcpmesh-local/1");
        assert_eq!(first.hello().api_version, "1.0");
        assert_eq!(first.hello().stack_version, STACK_VERSION);
        assert!(launch.socket.exists(), "daemon bound the control socket");

        // Second call: the daemon is live → reuse it (fast-path connect, no new spawn).
        let mut second = ensure_daemon_with(&launch)
            .await
            .expect("second ensure_daemon");
        assert_eq!(second.hello().api, "mcpmesh-local/1");

        // Single-daemon-per-uid: a directly-spawned extra daemon must LOSE the flock race
        // and exit 0 without binding. The original keeps serving.
        let extra = std::process::Command::new(cargo_bin("mcpmesh"))
            .args(["internal", "daemon"])
            .env("XDG_RUNTIME_DIR", tmp.path().join("runtime"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn extra daemon");
        let extra_status = tokio::task::spawn_blocking(move || {
            let mut extra = extra;
            extra.wait()
        })
        .await
        .expect("join extra-daemon wait")
        .expect("wait extra daemon");
        assert!(extra_status.success(), "the flock loser must exit 0");

        // Status: empty registry, correct stack version.
        let s = status(&mut first).await;
        assert_eq!(s.stack_version, STACK_VERSION);
        assert!(s.services.is_empty(), "no services registered in M2a");
        assert!(s.peers.is_empty(), "no peers known in M2a");

        // Third-party wire shape MUST be answered: {"method":"status","params":{}} — the
        // dispatcher resolves the method string, it does NOT `from_value::<Request>`.
        let raw = second
            .request_value(&json!({ "method": "status", "params": {} }))
            .await
            .expect("status with params:{} is answered");
        let s2: StatusResult = serde_json::from_value(raw).expect("StatusResult deserializes");
        assert_eq!(s2.stack_version, STACK_VERSION);

        // Shut the daemon down over the socket. The daemon raises its stop signal BEFORE
        // best-effort-acking (so an explicit stop always stops), so the ack is best-effort;
        // `wait_until_down` is the authoritative assertion that the daemon actually exited.
        let _ = first.request_value(&json!({ "method": "shutdown" })).await;
        wait_until_down(&launch.socket).await;
    })
    .await
    .expect("autostart test timed out");
}

#[tokio::test(flavor = "multi_thread")]
async fn racing_ensure_daemon_calls_converge_on_one_daemon() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());

        // Two callers race with no daemon up: both may spawn, but the flock singleton means
        // exactly one binds; both clients converge on it.
        let (a, b) = tokio::join!(ensure_daemon_with(&launch), ensure_daemon_with(&launch));
        let mut a = a.expect("racing caller A");
        let mut b = b.expect("racing caller B");
        assert_eq!(a.hello().api, "mcpmesh-local/1");
        assert_eq!(b.hello().api, "mcpmesh-local/1");
        assert_eq!(status(&mut a).await.stack_version, STACK_VERSION);
        assert_eq!(status(&mut b).await.stack_version, STACK_VERSION);

        a.request_value(&json!({ "method": "shutdown" })).await.ok();
        wait_until_down(&launch.socket).await;
    })
    .await
    .expect("racing test timed out");
}

/// Task 9 control-API path: `register_service` persists a `[services.*]` config entry and
/// hot-reloads the registry, and `peer_add` writes the allowlist store through the daemon —
/// both surface in `status`. This drives the real daemon subprocess over the control socket.
#[tokio::test(flavor = "multi_thread")]
async fn register_service_and_peer_add_reflect_in_status() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());
        let mut client = ensure_daemon_with(&launch).await.expect("ensure_daemon");

        // Register a `run` service (persisted + hot-reloaded into the live serve loop).
        client
            .request(Request::RegisterService(RegisterServiceParams {
                name: "echo".into(),
                backend: BackendSpec::Run {
                    cmd: vec![STUB.to_string()],
                },
                allow: vec!["tester".into()],
            }))
            .await
            .expect("register_service");

        // Add a peer through the daemon (redb is single-process; the daemon owns the store).
        // A valid base32 endpoint id from a fixed key so the round-trip is deterministic.
        let endpoint_id = iroh::SecretKey::from_bytes(&[9u8; 32]).public().to_string();
        client
            .request_value(&json!({
                "method": "peer_add",
                "params": {"petname": "tester", "endpoint_id": endpoint_id, "allow": ["echo"]}
            }))
            .await
            .expect("peer_add");

        // Status reflects both, on the SAME serialized connection.
        let s = status(&mut client).await;
        assert!(
            s.services
                .iter()
                .any(|svc| svc.name == "echo" && svc.allow == vec!["tester".to_string()]),
            "registered service must appear in status: {:?}",
            s.services
        );
        assert!(
            s.peers
                .iter()
                .any(|p| p.name == "tester" && p.services == vec!["echo".to_string()]),
            "added peer must appear in status: {:?}",
            s.peers
        );

        // The config entry was persisted atomically (survives a daemon restart).
        let cfg_file = tmp
            .path()
            .join("config")
            .join("mcpmesh")
            .join("config.toml");
        let content = std::fs::read_to_string(&cfg_file).expect("read config.toml");
        assert!(
            content.contains("[services.echo]"),
            "config.toml must carry the registered service:\n{content}"
        );

        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
        wait_until_down(&launch.socket).await;
    })
    .await
    .expect("control-API test timed out");
}

/// FIX 1 guard: two CONCURRENT `register_service` calls (distinct connections) must BOTH
/// persist — neither a lost update (second write clobbers the first's service) nor a torn
/// config.toml (interleaved temp writes) may occur. The daemon serializes the whole reload
/// section under `reload_lock` and uses per-call-unique temp names; this drives the real
/// control-API path under concurrency and asserts both services survive AND the config still
/// parses (Config::load via a fresh `status` after a would-be torn write).
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_register_service_calls_all_persist() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());
        let mut a = ensure_daemon_with(&launch).await.expect("client a");
        let mut b = ensure_daemon_with(&launch).await.expect("client b");

        // Fire both registrations concurrently on distinct connections.
        let reg_a = a.request(Request::RegisterService(RegisterServiceParams {
            name: "alpha".into(),
            backend: BackendSpec::Run {
                cmd: vec![STUB.to_string()],
            },
            allow: vec!["x".into()],
        }));
        let reg_b = b.request(Request::RegisterService(RegisterServiceParams {
            name: "beta".into(),
            backend: BackendSpec::Run {
                cmd: vec![STUB.to_string()],
            },
            allow: vec!["y".into()],
        }));
        let (ra, rb) = tokio::join!(reg_a, reg_b);
        ra.expect("register alpha");
        rb.expect("register beta");

        // Both survive in status (proves no lost update).
        let s = status(&mut a).await;
        assert!(
            s.services.iter().any(|v| v.name == "alpha"),
            "alpha lost: {:?}",
            s.services
        );
        assert!(
            s.services.iter().any(|v| v.name == "beta"),
            "beta lost: {:?}",
            s.services
        );

        // The persisted config is well-formed and carries BOTH (no torn write).
        let cfg_file = tmp
            .path()
            .join("config")
            .join("mcpmesh")
            .join("config.toml");
        let content = std::fs::read_to_string(&cfg_file).expect("read config.toml");
        assert!(
            content.contains("[services.alpha]") && content.contains("[services.beta]"),
            "config.toml must carry both services after concurrent registration:\n{content}"
        );

        let _ = a.request_value(&json!({ "method": "shutdown" })).await;
        wait_until_down(&launch.socket).await;
    })
    .await
    .expect("concurrent register test timed out");
}

/// Run the porcelain `mcpmesh status` subprocess with the hermetic launch env, capturing its
/// output. The spawned `mcpmesh internal daemon` (auto-start) inherits this env, so the whole
/// XDG-scoped tempdir carries through to the daemon child.
fn run_status_cmd(launch: &DaemonLaunch) -> std::process::Output {
    let mut cmd = std::process::Command::new(&launch.exe);
    cmd.arg("status");
    for (key, value) in &launch.env {
        cmd.env(key, value);
    }
    cmd.output().expect("run mcpmesh status")
}

/// Count the `*.sock` files in the runtime dir — the single-daemon-per-uid invariant means
/// exactly one control socket is ever bound.
fn socket_count(runtime_mcpmesh: &Path) -> usize {
    std::fs::read_dir(runtime_mcpmesh)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "sock"))
                .count()
        })
        .unwrap_or(0)
}

/// Shut the running daemon down over the control socket and wait for it to exit. Used by the
/// porcelain/AC tests, which drive `mcpmesh status` (a subprocess) rather than holding a client.
async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    wait_until_down(socket).await;
}

// Task 11: `mcpmesh status` (the porcelain, via assert_cmd) auto-starts the daemon and prints
// the api + stack version; a second invocation reuses the same daemon; exactly one socket is
// bound; both exit 0. This is the un-ignored + filled Task 3 skeleton.
#[tokio::test(flavor = "multi_thread")]
async fn porcelain_autostarts_daemon_and_second_call_reuses_it() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());
        let runtime_mcpmesh = tmp.path().join("runtime").join("mcpmesh");

        // First `mcpmesh status`: the socket is dead → a detached daemon is auto-started.
        let out1 = run_status_cmd(&launch);
        let stdout1 = String::from_utf8_lossy(&out1.stdout);
        assert!(
            out1.status.success(),
            "first status exit 0; stderr: {}",
            String::from_utf8_lossy(&out1.stderr)
        );
        assert!(
            stdout1.contains("mcpmesh-local/1"),
            "status prints the api name: {stdout1}"
        );
        assert!(
            stdout1.contains(STACK_VERSION),
            "status prints the stack version: {stdout1}"
        );
        assert!(
            launch.socket.exists(),
            "first status bound the control socket"
        );

        // Second `mcpmesh status`: the daemon is live → reuse it (no new spawn).
        let out2 = run_status_cmd(&launch);
        let stdout2 = String::from_utf8_lossy(&out2.stdout);
        assert!(out2.status.success(), "second status exit 0");
        assert!(stdout2.contains("mcpmesh-local/1"));
        assert!(stdout2.contains(STACK_VERSION));

        // Exactly one control socket ever bound (single-daemon-per-uid).
        assert_eq!(
            socket_count(&runtime_mcpmesh),
            1,
            "exactly one control socket bound"
        );

        shutdown_daemon(&launch.socket).await;
    })
    .await
    .expect("porcelain autostart test timed out");
}

/// Issue #7: a daemon that REFUSES to start (here: an invalid `[network]` config) must fail
/// autostart FAST — not wait out the 10s connect window — and the error must replay the
/// daemon's OWN reason plus the doctor next step (was previously a bare "Connection refused"
/// after the full window).
#[tokio::test(flavor = "multi_thread")]
async fn autostart_failure_replays_the_daemons_reason_fast() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        // `relay_mode = "custom"` with no relay_urls: the daemon refuses to run (operator.md's
        // refuse-rather-than-silently-fall-back policy).
        let launch = launch_with_config(tmp.path(), "[network]\nrelay_mode = \"custom\"\n");

        let start = Instant::now();
        let err = ensure_daemon_with(&launch)
            .await
            .expect_err("a refusing daemon must fail autostart");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("the daemon failed to start"),
            "the failure states what happened: {msg}"
        );
        assert!(
            msg.contains("relay_urls"),
            "the daemon's own reason is replayed: {msg}"
        );
        assert!(
            msg.contains("run 'mcpmesh doctor' to diagnose"),
            "the exact next command is named: {msg}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "a dead child must fail fast, not wait out the 10s window (took {:?})",
            start.elapsed()
        );
    })
    .await
    .expect("autostart-failure test timed out");
}

/// The same failure through the PORCELAIN (`mcpmesh status` as a subprocess): non-zero exit,
/// and stderr carries the daemon's reason + the doctor next step — the end-to-end shape a
/// config-editing user actually sees (issue #7).
#[tokio::test(flavor = "multi_thread")]
async fn porcelain_surfaces_the_daemons_startup_error() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_with_config(tmp.path(), "[network]\nrelay_mode = \"custom\"\n");

        let out = run_status_cmd(&launch);
        assert!(
            !out.status.success(),
            "status against a refusing daemon must exit non-zero"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("relay_urls") && stderr.contains("run 'mcpmesh doctor' to diagnose"),
            "stderr replays the daemon's reason and the next step: {stderr}"
        );
        // The raw io kernel-speak of the pre-fix message must not be the story the user gets.
        assert!(
            stderr.contains("the daemon failed to start"),
            "the failure is stated in plain language: {stderr}"
        );
    })
    .await
    .expect("porcelain startup-error test timed out");
}

/// Spec AC: "a non-porcelain client drives status over mcpmesh-local/1 and receives the API
/// version at connect." A RAW `connect_control` client (NOT the `mcpmesh status` porcelain)
/// reads the server's `Hello` FIRST frame, asserts the api + a non-empty api version, then
/// drives `Request::Status` and gets a `StatusResult` back.
#[tokio::test(flavor = "multi_thread")]
async fn non_porcelain_client_drives_status_over_local_api() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());
        // Bring the daemon up (the auto-start seam), then drop that connection.
        drop(ensure_daemon_with(&launch).await.expect("start daemon"));

        // A raw, non-porcelain client: `connect_control` reads the Hello at connect.
        let mut raw = connect_control(&launch.socket)
            .await
            .expect("raw connect_control");
        assert_eq!(
            raw.hello().api,
            "mcpmesh-local/1",
            "api identified at connect"
        );
        assert!(
            !raw.hello().api_version.is_empty(),
            "a non-empty api version is delivered at connect: {:?}",
            raw.hello()
        );

        // Drive status over the wire and parse the typed result.
        let result = raw.request(Request::Status).await.expect("status request");
        let s: StatusResult = serde_json::from_value(result).expect("StatusResult deserializes");
        assert_eq!(s.stack_version, STACK_VERSION);

        let _ = raw.request_value(&json!({ "method": "shutdown" })).await;
        wait_until_down(&launch.socket).await;
    })
    .await
    .expect("non-porcelain AC test timed out");
}

/// Surface-leak AC (§1.5/§17): with a `run` service AND a peer configured, `mcpmesh status`
/// stdout must contain NONE of the canonical transport-vocabulary blocklist terms — the raw
/// endpoint id (base32), the socket path, the backend command, "ticket", "ALPN",
/// "mcpmesh/mcp/1". The status view carries only plain names + the backend KIND.
#[tokio::test(flavor = "multi_thread")]
async fn status_output_leaks_no_transport_vocabulary() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let tmp = tempfile::tempdir().unwrap();
        let launch = launch_in(tmp.path());
        let mut client = ensure_daemon_with(&launch).await.expect("ensure_daemon");

        // A `run` service whose backend command is the stub binary path — must NOT leak.
        client
            .request(Request::RegisterService(RegisterServiceParams {
                name: "files".into(),
                backend: BackendSpec::Run {
                    cmd: vec![STUB.to_string()],
                },
                allow: vec!["bob".into()],
            }))
            .await
            .expect("register_service");

        // A peer added by its raw endpoint id (base32) — the id must NOT leak into status.
        let endpoint_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string();
        client
            .request_value(&json!({
                "method": "peer_add",
                "params": {"petname": "bob", "endpoint_id": endpoint_id, "allow": ["files"]}
            }))
            .await
            .expect("peer_add");

        // Run the porcelain `mcpmesh status` and capture stdout.
        let out = run_status_cmd(&launch);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(out.status.success(), "status exit 0");

        // Sanity: the service + peer DID render (by plain name), so the absences below are
        // meaningful — status actually produced content.
        assert!(stdout.contains("files"), "service name renders: {stdout}");
        assert!(stdout.contains("bob"), "peer petname renders: {stdout}");

        // The canonical §1.5/§17 transport-vocabulary blocklist — the SHARED fixture at
        // fixtures/transport-vocabulary.json (its canonical copy; the host/kb/loc
        // surface-leak suites load the same file). None of its terms may appear.
        if let Some(term) = transport_vocab_violation(&stdout) {
            panic!("status leaked transport vocabulary '{term}':\n{stdout}");
        }
        // Plus the RUNTIME values a fixture cannot carry: the actual endpoint id, socket path,
        // and backend command must not leak either.
        let socket_path = launch.socket.to_string_lossy().into_owned();
        for term in [
            endpoint_id.as_str(), // the raw base32 endpoint id
            socket_path.as_str(), // the control socket path
            STUB,                 // the backend command (full path)
            "echo_mcp_stub",      // the backend command basename
            "mcpmesh/mcp/1",      // the mesh ALPN string itself
        ] {
            assert!(
                !stdout.contains(term),
                "status leaked transport vocabulary '{term}':\n{stdout}"
            );
        }

        shutdown_daemon(&launch.socket).await;
    })
    .await
    .expect("surface-leak test timed out");
}
