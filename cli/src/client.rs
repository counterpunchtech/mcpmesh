//! Porcelain-side client of mcpmesh-local/1 (spec §6.1). The WIRE client — connect the UDS,
//! read the server's `Hello` first frame, issue request/response frames, `open_session`'s
//! raw-pipe transition — is THE shared no-iroh implementation in
//! [`mcpmesh_local_api::client`] (D5: one mcpmesh-local/1 client, re-exported here); this module
//! layers on top of it only what the PORCELAIN adds: `ensure_daemon` auto-starts a detached
//! daemon when the socket is dead and converges on the single flock winner.
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mcpmesh_trust::paths;

pub use mcpmesh_local_api::client::{ClientError, ControlClient, connect_control};

/// How to (re)launch the daemon for auto-start. Production uses [`DaemonLaunch::ambient`]
/// (the running executable, the ambient control socket, inherited env). Tests inject the
/// built binary path + a hermetic tempdir env so the whole auto-start path runs against a
/// real detached process — without the test mutating its own environment (`set_var` is
/// `unsafe` under `forbid(unsafe)`, so the runtime dir is passed to the CHILD instead).
#[derive(Clone, Debug)]
pub struct DaemonLaunch {
    pub exe: PathBuf,
    pub socket: PathBuf,
    pub env: Vec<(OsString, OsString)>,
}

impl DaemonLaunch {
    pub fn ambient() -> Result<Self> {
        Ok(Self {
            exe: std::env::current_exe().context("resolve current executable")?,
            socket: paths::default_socket_path()?,
            env: Vec::new(),
        })
    }
}

/// Return a connected client to the running daemon, auto-starting it if the socket is dead
/// (spec §6.1). Idempotent: a second caller connects to the already-running daemon; racing
/// callers converge on the single flock winner.
pub async fn ensure_daemon() -> Result<ControlClient> {
    ensure_daemon_with(&DaemonLaunch::ambient()?).await
}

/// [`ensure_daemon`] with an explicit launch spec (the testable seam).
pub async fn ensure_daemon_with(launch: &DaemonLaunch) -> Result<ControlClient> {
    // Fast path: a live daemon already owns the socket — do NOT spawn (the connect-probe
    // half of the single-daemon guarantee).
    if let Ok(client) = connect_control(&launch.socket).await {
        return Ok(client);
    }
    spawn_detached(launch)?;
    // Poll-connect with capped backoff up to ~10s. The daemon's flock singleton means that
    // even if a racing caller also spawned, exactly one daemon binds; every client here
    // converges on it. The bound is generous (a cold start under machine load binds in
    // ~3-4s; 10s leaves comfortable headroom on loaded/CI hosts) — the happy path returns
    // sub-second via the fast-path probe above, so only a genuinely stuck start waits it out.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut backoff = Duration::from_millis(20);
    loop {
        match connect_control(&launch.socket).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(anyhow::Error::from(e)
                        .context("daemon did not accept connections within 10s"));
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(200));
            }
        }
    }
}

/// Spawn `mcpmesh internal daemon` DETACHED: stdio null, and the `std::process::Child` is
/// dropped WITHOUT waiting or killing — std `Child::drop` neither reaps nor signals, so the
/// daemon OUTLIVES us (no `kill_on_drop`). A redundant spawn is harmless: the flock loser
/// exits 0. (Delta from the plan's `tokio::process` suggestion — declared: spawning is a
/// synchronous syscall that needs no async runtime or tokio `process` feature.)
fn spawn_detached(launch: &DaemonLaunch) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new(&launch.exe);
    cmd.arg("internal")
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // Own process group (stable since 1.64, no `unsafe`): a terminal Ctrl-C sends SIGINT
        // to the spawner's foreground group only, so it must NOT reach this shared daemon —
        // otherwise one client's Ctrl-C would kill every session the daemon serves. The
        // remaining leak — terminal SIGHUP on hangup — needs a fresh session (`setsid` via
        // `pre_exec`, which is `unsafe` and barred by forbid(unsafe)); deferred, and the
        // flock singleton makes an accidental re-spawn after such a kill harmless anyway.
        .process_group(0);
    for (key, value) in &launch.env {
        cmd.env(key, value);
    }
    let _child = cmd
        .spawn()
        .with_context(|| format!("spawn {} internal daemon", launch.exe.display()))?;
    // `_child` is intentionally dropped here: we must NOT wait on or kill the daemon.
    Ok(())
}
