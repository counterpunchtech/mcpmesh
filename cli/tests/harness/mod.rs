//! Shared hermetic-world helpers for the daemon-subprocess e2e suites
//! (`one_shot_connect.rs`, `cold_dial.rs`) — the `tests/harness/mod.rs` pattern: integration
//! tests are separate crates, so each consumes this via `mod harness;` and the items compile
//! into that crate. Unix-only by inheritance: every consumer is `#![cfg(unix)]` because
//! `shutdown_daemon` dials the control endpoint at its hardcoded filesystem socket path
//! (`<runtime>/mcpmesh/mcpmesh.sock`) — on windows the endpoint is a hash-derived named pipe
//! the test cannot reconstruct without a forbidden windows twin.
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use mcpmesh::client::connect_control;
use serde_json::json;

/// The hermetic echo MCP stub serving a world's `echo` (replies to `initialize` and
/// `tools/call`, loops until stdin EOF — so only the session teardown discipline ends it).
pub const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");
/// The real `mcpmesh` binary — every harness step is the actual shipped porcelain.
pub const MCPMESH: &str = env!("CARGO_BIN_EXE_mcpmesh");

/// One hermetic daemon world: a tempdir-scoped HOME + XDG triple (runtime/config/data)
/// and a config written from `config_body`. Mirrors `pairing_porcelain.rs::launch_in`;
/// the porcelain subcommands auto-start the daemon inside this world. Returns
/// (control socket path, env vars).
pub fn world(dir: &Path, config_body: &str) -> (std::path::PathBuf, Vec<(OsString, OsString)>) {
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
pub fn run_cmd(env: &[(OsString, OsString)], args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(MCPMESH);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mcpmesh subcommand")
}

/// Shut a world's daemon down via its control socket and wait (bounded) until BOTH the
/// socket stops accepting AND the per-uid singleton flock (`mcpmesh.lock`, the socket's
/// sibling) is released — i.e. the daemon PROCESS is fully gone, with its iroh endpoint
/// and IN-PROCESS address cache. The flock wait matters for restart flows: the socket
/// refuses before the process exits, and a daemon auto-started in that window loses the
/// still-held flock and exits 0 as a redundant singleton — the fresh start would then
/// never come up. A later porcelain command in the same world auto-starts a FRESH daemon.
pub async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if connect_control(socket).await.is_err() && singleton_lock_is_free(socket) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "daemon still accepting connections (or holding the singleton flock) after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Probe the daemon's per-uid singleton flock (`<runtime>/mcpmesh/mcpmesh.lock`): take the
/// exclusive non-blocking lock and immediately release it (drop). `true` = no daemon holds
/// it (a missing lock file means no daemon ever started — also free). Mirrors the daemon's
/// own `acquire_singleton_lock`; rustix is a package dependency, visible to the test crate.
fn singleton_lock_is_free(socket: &Path) -> bool {
    use rustix::fs::{FlockOperation, flock};
    let lock_path = socket.with_file_name("mcpmesh.lock");
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(&lock_path) else {
        return !lock_path.exists();
    };
    flock(&file, FlockOperation::NonBlockingLockExclusive).is_ok()
}
