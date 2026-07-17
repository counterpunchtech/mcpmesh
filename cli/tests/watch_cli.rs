//! Task 8 acceptance: `mcpmesh internal watch` — a thin, human-runnable reference consumer of the
//! `subscribe` stream. It subscribes and pretty-prints the live stream (snapshot summary + event
//! lines + lagged notices), running until interrupted.
//!
//! Test strategy (see the task's guidance): the reliably-observable, non-flaky part of a
//! run-until-interrupted subprocess is the SNAPSHOT — the auto-started hermetic daemon pushes it
//! the instant `watch` subscribes. So this file drives the REAL `mcpmesh internal watch` binary as
//! a subprocess against an auto-started hermetic daemon and asserts it connects and prints the
//! snapshot summary line + its startup banner, then kills it. The per-frame RENDERING of
//! event/lagged/snapshot frames is unit-tested directly against the pure `render_frame` in
//! `main.rs` (DRYer + deterministic than racing a subprocess for a live event).
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use mcpmesh::client::connect_control;
use serde_json::json;

/// A hermetic launch env: the built `mcpmesh` binary + a tempdir runtime/config/data (mirrors
/// `pairing_porcelain.rs::launch_in`). `relay_mode = "disabled"` keeps the auto-started daemon's
/// endpoint localhost-only (no relay egress in CI). Returns (exe, socket, env-vars).
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
        "[network]\nrelay_mode = \"disabled\"\n",
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

/// Ask the auto-started daemon to shut down (hygiene: it is detached, so it outlives the porcelain).
async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if connect_control(socket).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `mcpmesh internal watch` auto-starts a hermetic daemon, subscribes, and immediately prints its
/// startup banner + the snapshot summary line the daemon pushes first. It runs until interrupted,
/// so we spawn it, wait for the snapshot line on its captured stdout, then kill it.
#[test]
fn watch_prints_the_snapshot_summary_from_the_live_stream() {
    let tmp = tempfile::tempdir().unwrap();
    let (exe, socket, env) = launch_in(tmp.path());

    let mut child = std::process::Command::new(&exe)
        .args(["internal", "watch"])
        .envs(env.iter().cloned())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn `mcpmesh internal watch`");

    // Drain the child's stdout on a thread (Rust's stdout is line-buffered, so each `println!`
    // flushes at the newline and is readable while the process is still running).
    let stdout = child.stdout.take().expect("child stdout piped");
    let captured = Arc::new(Mutex::new(String::new()));
    let sink = captured.clone();
    let reader = std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(Ok(line)) = lines.next() {
            let mut buf = sink.lock().unwrap();
            buf.push_str(&line);
            buf.push('\n');
        }
    });

    // Poll until the snapshot line appears (bounded; auto-start + subscribe is sub-second normally,
    // but a cold daemon start under CI load has generous headroom here).
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut saw_snapshot = false;
    while Instant::now() < deadline {
        if captured.lock().unwrap().contains("snapshot:") {
            saw_snapshot = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // `watch` runs until interrupted → kill it; closing its stdout ends the reader thread.
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();

    let out = captured.lock().unwrap().clone();
    assert!(
        saw_snapshot,
        "`mcpmesh internal watch` must print a snapshot summary line; captured:\n{out}"
    );
    assert!(
        out.contains("watching the mesh"),
        "`mcpmesh internal watch` prints its startup banner; captured:\n{out}"
    );

    // Clean up the detached, auto-started daemon.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(shutdown_daemon(&socket));
}
