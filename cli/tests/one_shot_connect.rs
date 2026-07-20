//! Issue #25 regression: the ONE-SHOT piped connect —
//! `printf '<frame>\n' | mcpmesh connect <peer>/<service>` — must yield the backend's
//! response, not a silent empty exit 0.
//!
//! The bug this pins: both session pumps (`daemon::dial::pipe_session` on the dialing
//! side, `backends::pump` on the serving side) let the REQUEST direction's completion
//! cancel the response drain via `tokio::select!`. An interactive MCP client keeps stdin
//! open, so real sessions never hit it — but a one-shot pipe closes stdin right after the
//! request, the request direction "wins", and the drain is cancelled before the reply
//! (sometimes before the request itself ever flushed). Every e2e kept its client side
//! open until the reply landed, which is why this shape silently failed for months
//! (including step 4 of the shipped loopback demo). The fix: end-of-input HALF-CLOSES
//! toward the consumer and parks; only the drain direction may end a session.
//!
//! Harness: TWO REAL `mcpmesh` daemon subprocesses in isolated HOME/XDG worlds (the
//! `pairing_porcelain.rs` hermetic-env pattern; `relay_mode = "disabled"` in both configs,
//! so no relay and no discovery — the post-pair id-only dial resolves from iroh's
//! in-process address cache left by the pairing dial). Alice serves `echo` backed by the
//! `echo_mcp_stub` binary (its path is baked into her config's `run` — the
//! `CARGO_BIN_EXE_*` env exists only for THIS test binary, never for the daemon). Then
//! the literal user flow: `invite` → `pair` → a one-shot `connect` that writes exactly one
//! `initialize` frame, closes stdin IMMEDIATELY, and reads stdout.
//!
//! This is also the first e2e that reaches the serving daemon's OWN accept loop
//! (`spawn_accept_loop`, ALPN dispatch and all) through a fully-booted daemon
//! subprocess: the existing suites drive `net::serve` directly or assemble a `MeshState`
//! in-process (`hero_flow_pairing.rs`), so the daemon's production boot-to-session path
//! had no end-to-end coverage.
// Unix-only: the test shuts the daemons down via their control endpoints at hardcoded
// filesystem socket paths (`connect_control(<tmp>/mcpmesh/mcpmesh.sock)`), the path the
// child computes on unix. On windows the endpoint is a hash-derived named pipe the test
// cannot reconstruct without a forbidden windows twin — same posture as
// `pairing_porcelain.rs`.
#![cfg(unix)]
use std::ffi::OsString;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use mcpmesh::client::connect_control;
use mcpmesh_net::framing::write_frame;
use serde_json::{Value, json};
use tokio::time::timeout;

/// The hermetic echo MCP stub serving Alice's `echo` (replies to `initialize` and
/// `tools/call`, loops until stdin EOF — so only the fixed teardown discipline ends it).
const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");
/// The real `mcpmesh` binary — every step below is the actual shipped porcelain.
const MCPMESH: &str = env!("CARGO_BIN_EXE_mcpmesh");

/// One hermetic daemon world: a tempdir-scoped HOME + XDG triple (runtime/config/data)
/// and a config written from `config_body`. Mirrors `pairing_porcelain.rs::launch_in`;
/// the porcelain subcommands auto-start the daemon inside this world. Returns
/// (control socket path, env vars).
fn world(dir: &Path, config_body: &str) -> (std::path::PathBuf, Vec<(OsString, OsString)>) {
    let runtime = dir.join("runtime");
    let config = dir.join("config");
    let data = dir.join("data");
    let config_mcpmesh = config.join("mcpmesh");
    std::fs::create_dir_all(&config_mcpmesh).unwrap();
    std::fs::write(config_mcpmesh.join("config.toml"), config_body).unwrap();
    let socket = runtime.join("mcpmesh").join("mcpmesh.sock");
    let env = vec![
        (OsString::from("HOME"), dir.as_os_str().to_os_string()),
        (OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()),
        (OsString::from("XDG_CONFIG_HOME"), config.into_os_string()),
        (OsString::from("XDG_DATA_HOME"), data.into_os_string()),
    ];
    (socket, env)
}

/// Run one porcelain subcommand to completion inside a world (the auto-started daemon
/// inherits the env and OUTLIVES the subcommand).
fn run_cmd(env: &[(OsString, OsString)], args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(MCPMESH);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mcpmesh subcommand")
}

async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
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

/// The full four-command flow with a ONE-SHOT client: serve (via config) → `invite` →
/// `pair` → `printf <initialize> | mcpmesh connect alice/echo`. The one-shot connect must
/// print the backend's response frame (matching id) and exit 0 within the timeout — the
/// exact shape issue #25 reports as silently printing nothing.
#[tokio::test(flavor = "multi_thread")]
async fn one_shot_piped_connect_yields_the_response() {
    timeout(Duration::from_secs(120), async {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        // Alice: serves `echo` (stub backend, allow=[] until the pairing grant). The stub
        // path uses a TOML literal string (single quotes) so it survives verbatim.
        let (alice_socket, alice_env) = world(
            alice_dir.path(),
            &format!(
                "[identity]\npetname = \"alice\"\n\n[network]\nrelay_mode = \"disabled\"\n\n\
                 [services.echo]\nrun = ['{STUB}']\nallow = []\n"
            ),
        );
        // Bob: dials only — no services, just the hermetic network posture.
        let (bob_socket, bob_env) = world(
            bob_dir.path(),
            "[identity]\npetname = \"bob\"\n\n[network]\nrelay_mode = \"disabled\"\n",
        );

        // ── invite (Alice) ── auto-starts her daemon; capture the copyable invite line.
        let out = run_cmd(&alice_env, &["invite", "echo"]);
        assert!(
            out.status.success(),
            "`mcpmesh invite echo` exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let invite_line = stdout
            .split_whitespace()
            .find(|t| t.starts_with("mcpmesh-invite:"))
            .unwrap_or_else(|| panic!("no invite line in:\n{stdout}"))
            .to_string();

        // ── pair (Bob) ── auto-starts his daemon; redeems over pair/1 at the invite's
        // embedded addr and writes the mutual trust + Alice's `allow` grant.
        let out = run_cmd(&bob_env, &["pair", &invite_line]);
        assert!(
            out.status.success(),
            "`mcpmesh pair <invite>` exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // ── the ONE-SHOT connect (Bob) ── exactly one initialize frame, then stdin closes
        // IMMEDIATELY (before any response can have arrived). The session must still drain:
        // proxy half-closes toward the daemon, `pipe_session` half-closes toward Alice,
        // Alice's pump closes the stub's stdin, the stub replies and exits, and the reply
        // flows all the way back to this pipe's stdout.
        let mut child = tokio::process::Command::new(MCPMESH)
            .arg("connect")
            .arg("alice/echo")
            .envs(bob_env.iter().map(|(k, v)| (k.clone(), v.clone())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn one-shot mcpmesh connect");
        let mut child_in = child.stdin.take().expect("piped stdin");
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "one-shot", "version": "0"}}
            }),
        )
        .await
        .unwrap();
        drop(child_in); // the one-shot shape: stdin EOF right behind the request

        // A bounded wait is load-bearing: pre-fix the failure was empty stdout + exit 0,
        // but a drain that never ends would instead hang here — both are regressions.
        let out = timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .expect("one-shot connect did not finish within 30s")
            .expect("collect one-shot connect output");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "one-shot connect exit 0; stdout: {stdout}; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Exactly ONE response frame on stdout, and it is the backend's answer to OUR id.
        let frames: Vec<Value> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON line {l:?}: {e}")))
            .collect();
        assert_eq!(
            frames.len(),
            1,
            "the one-shot pipe carries exactly the one response frame:\n{stdout}"
        );
        assert_eq!(
            frames[0]["id"], 1,
            "the response answers our request id: {}",
            frames[0]
        );
        assert_eq!(
            frames[0]["result"]["serverInfo"]["name"], "echo-stub",
            "the response is the served backend's InitializeResult (not a synthesized \
             refusal): {}",
            frames[0]
        );

        shutdown_daemon(&alice_socket).await;
        shutdown_daemon(&bob_socket).await;
    })
    .await
    .expect("one-shot connect e2e timed out");
}
