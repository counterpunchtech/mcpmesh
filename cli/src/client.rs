//! Porcelain-side client of mcpmesh-local/1. The WIRE client — connect the UDS,
//! read the server's `Hello` first frame, issue request/response frames, `open_session`'s
//! raw-pipe transition — is THE shared no-iroh implementation in
//! [`mcpmesh_local_api::client`] (one mcpmesh-local/1 client, re-exported here); this module
//! layers on top of it only what the PORCELAIN adds: `ensure_daemon` auto-starts a detached
//! daemon when the socket is dead and converges on the single flock winner.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
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
            socket: paths::default_endpoint()?,
            env: Vec::new(),
        })
    }
}

/// Return a connected client to the running daemon, auto-starting it if the socket is dead.
/// Idempotent: a second caller connects to the already-running daemon; racing
/// callers converge on the single flock winner.
pub async fn ensure_daemon() -> Result<ControlClient> {
    ensure_daemon_with(&DaemonLaunch::ambient()?).await
}

/// [`ensure_daemon`] with an explicit launch spec (the testable seam).
pub async fn ensure_daemon_with(launch: &DaemonLaunch) -> Result<ControlClient> {
    // Pre-flight (unix): a control-socket path longer than `sockaddr_un.sun_path` can NEVER
    // bind, so spawning a daemon and polling the connect window would only bury the cause in
    // kernel-speak ("path must be shorter than SUN_LEN", per issue #10). Refuse now, naming
    // the exact fix.
    #[cfg(unix)]
    check_socket_path_len(&launch.socket)?;
    // Fast path: a live daemon already owns the socket — do NOT spawn (the connect-probe
    // half of the single-daemon guarantee).
    if let Ok(client) = connect_control(&launch.socket).await {
        return Ok(client);
    }
    let mut spawned = spawn_detached(launch)?;
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
                // Fail FAST when OUR child died refusing to start (issue #7): a nonzero exit
                // means the daemon printed its own reason to the captured stderr — waiting
                // out the window would only bury it. A ZERO exit is the singleton loser
                // (flock on unix; pipe-bind on windows) converging on another racer's
                // winner: keep polling for the winner's socket.
                if let Ok(Some(status)) = spawned.child.try_wait()
                    && !status.success()
                {
                    anyhow::bail!("{}", autostart_failure_message(&spawned.read_stderr()));
                }
                if Instant::now() >= deadline {
                    // A stuck (not dead) start: replay whatever the child said so far; with
                    // nothing captured, keep the io cause but always name the next command.
                    let stderr = spawned.read_stderr();
                    if !stderr.is_empty() {
                        anyhow::bail!("{}", autostart_failure_message(&stderr));
                    }
                    return Err(anyhow::Error::from(e).context(
                        "the daemon did not accept connections within 10s — run \
                         'mcpmesh doctor' to diagnose",
                    ));
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_millis(200));
            }
        }
    }
}

/// The longest socket path `bind` accepts: `sockaddr_un.sun_path` is a fixed array (108 bytes
/// on linux, 104 on the BSDs/macOS) that must also hold a trailing NUL.
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAX_SOCKET_PATH: usize = 107;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
const MAX_SOCKET_PATH: usize = 103;

/// Refuse a control-socket path the kernel could never bind — BEFORE spawning a daemon and
/// waiting out the connect window (issue #10). User language only: name the cause (the
/// runtime dir) and the exact fix, never the sockaddr internals.
#[cfg(unix)]
fn check_socket_path_len(socket: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    if socket.as_os_str().as_bytes().len() > MAX_SOCKET_PATH {
        anyhow::bail!(
            "runtime dir path too long for a unix socket — set XDG_RUNTIME_DIR to a shorter path"
        );
    }
    Ok(())
}

/// Render the autostart-failure message from the spawned daemon's captured startup stderr
/// (issue #7): what happened, the daemon's OWN reason, and the exact next command. Pure so it
/// is unit-testable. The child prints through the same error path as every verb, so its first
/// line carries an `Error: ` prefix — strip it rather than stuttering "Error: Error:".
fn autostart_failure_message(stderr: &str) -> String {
    let reason = stderr.trim();
    let reason = reason.strip_prefix("Error: ").unwrap_or(reason);
    if reason.is_empty() {
        "the daemon failed to start — run 'mcpmesh doctor' to diagnose".to_string()
    } else {
        format!("the daemon failed to start: {reason}\nrun 'mcpmesh doctor' to diagnose")
    }
}

/// The detached daemon child plus its captured startup stderr. Holding the `Child` does NOT
/// tie the daemon's lifetime to ours (std `Child::drop` neither reaps nor signals — the same
/// invariant [`spawn_detached`] documents); it exists so [`ensure_daemon_with`] can fail fast
/// on a nonzero exit and replay the daemon's own startup error (issue #7). Dropping removes
/// the capture file: a healthy daemon writes nothing to stderr (no tracing subscriber is
/// installed), so nothing of value is discarded on the happy path.
struct SpawnedDaemon {
    child: std::process::Child,
    stderr_path: Option<PathBuf>,
}

impl SpawnedDaemon {
    /// The child's captured stderr so far (trimmed); empty when nothing was captured.
    fn read_stderr(&self) -> String {
        self.stderr_path
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}

impl Drop for SpawnedDaemon {
    fn drop(&mut self) {
        // Best-effort: on unix the unlink is clean even under the daemon's open fd; on
        // windows a still-open handle can refuse the delete — a stray empty capture file in
        // the per-user temp dir beats keeping the handle around.
        if let Some(p) = &self.stderr_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// A per-spawn-unique file to capture the daemon child's startup stderr into (issue #7), plus
/// its open handle. `None` when no file could be created — the spawn then degrades to a null
/// stderr (the pre-capture behavior) rather than failing autostart over diagnostics.
fn stderr_capture(socket: &Path) -> Option<(std::fs::File, PathBuf)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "daemon-start-{}-{}.stderr",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = capture_dir(socket).join(name);
    let file = std::fs::File::create(&path).ok()?;
    Some((file, path))
}

/// Where the capture file lives: beside the control socket (the 0700 same-uid runtime dir —
/// startup errors can carry config paths, so they stay private). Hardened through the SAME
/// rule the daemon's own bind applies ([`crate::ipc::ensure_runtime_dir`] — idempotent, so
/// pre-creating here is safe); an unhardenable dir degrades to the temp dir.
#[cfg(unix)]
fn capture_dir(socket: &Path) -> PathBuf {
    match socket.parent() {
        Some(parent) if crate::ipc::ensure_runtime_dir(parent).is_ok() => parent.to_path_buf(),
        _ => std::env::temp_dir(),
    }
}

/// Windows: the control endpoint is a named pipe with no filesystem parent; `%TEMP%` is
/// per-user, which keeps the capture private.
#[cfg(windows)]
fn capture_dir(_socket: &Path) -> PathBuf {
    std::env::temp_dir()
}

/// Spawn `mcpmesh internal daemon` DETACHED: stdin/stdout null, stderr captured to a private
/// file (issue #7 — the parent replays it when the start fails), and the child is NEVER
/// waited on or killed — std `Child::drop` neither reaps nor signals, so the daemon OUTLIVES
/// us (no `kill_on_drop`; the returned handle is only `try_wait`-probed). A redundant spawn
/// is harmless: the singleton loser (flock on unix; pipe-bind on windows) exits 0. (Delta
/// from the plan's `tokio::process` suggestion — declared: spawning is a synchronous syscall
/// that needs no async runtime or tokio `process` feature.)
fn spawn_detached(launch: &DaemonLaunch) -> Result<SpawnedDaemon> {
    let (stderr_stdio, stderr_path) = match stderr_capture(&launch.socket) {
        Some((file, path)) => (std::process::Stdio::from(file), Some(path)),
        None => (std::process::Stdio::null(), None),
    };
    let mut cmd = std::process::Command::new(&launch.exe);
    cmd.arg("internal")
        .arg("daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr_stdio);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group (stable since 1.64, no `unsafe`): a terminal Ctrl-C sends SIGINT
        // to the spawner's foreground group only, so it must NOT reach this shared daemon —
        // otherwise one client's Ctrl-C would kill every session the daemon serves. The
        // remaining leak — terminal SIGHUP on hangup — needs a fresh session (`setsid` via
        // `pre_exec`, which is `unsafe` and barred by forbid(unsafe)); deferred, and the
        // flock singleton makes an accidental re-spawn after such a kill harmless anyway.
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // DETACHED_PROCESS (0x0000_0008: no inherited console) + CREATE_NEW_PROCESS_GROUP
        // (0x0000_0200): the Ctrl-C / console-close of the spawning shell must NOT reach the
        // shared daemon — the same session isolation `process_group(0)` buys on unix. Both are
        // safe std APIs (`creation_flags`); no `unsafe` involved.
        cmd.creation_flags(0x0000_0008 | 0x0000_0200);
    }
    for (key, value) in &launch.env {
        cmd.env(key, value);
    }
    match cmd.spawn() {
        Ok(child) => Ok(SpawnedDaemon { child, stderr_path }),
        Err(e) => {
            // The capture file has no writer if the spawn itself failed — don't leak it.
            if let Some(p) = &stderr_path {
                let _ = std::fs::remove_file(p);
            }
            Err(anyhow::Error::from(e)
                .context(format!("spawn {} internal daemon", launch.exe.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_failure_message_replays_the_daemons_reason_and_names_doctor() {
        // The child prints through the shared error path, so its stderr starts "Error: " —
        // the replay must strip it (no "Error: Error:" stutter) and end with the next step.
        let msg = autostart_failure_message(
            "Error: config error in /home/x/config.toml: [network] relay_mode = \"custom\" \
             requires at least one relay_urls entry\n",
        );
        assert!(
            msg.starts_with("the daemon failed to start: config error"),
            "the daemon's own reason leads: {msg}"
        );
        assert!(
            !msg.contains("Error:"),
            "no stuttered Error: prefix inside the message: {msg}"
        );
        assert!(
            msg.contains("run 'mcpmesh doctor' to diagnose"),
            "the exact next command is named: {msg}"
        );
    }

    #[test]
    fn autostart_failure_message_degrades_cleanly_with_nothing_captured() {
        let msg = autostart_failure_message("");
        assert_eq!(
            msg,
            "the daemon failed to start — run 'mcpmesh doctor' to diagnose"
        );
    }

    /// The SUN_LEN pre-check (issue #10): an overlong socket path fails IMMEDIATELY with the
    /// exact fix — no daemon spawn, no 10s wait, no kernel vocabulary.
    #[cfg(unix)]
    #[tokio::test]
    async fn overlong_socket_path_is_refused_immediately_in_user_language() {
        let long_dir = std::env::temp_dir().join("x".repeat(200));
        let launch = DaemonLaunch {
            exe: PathBuf::from("/nonexistent-mcpmesh"),
            socket: long_dir.join("mcpmesh").join("mcpmesh.sock"),
            env: Vec::new(),
        };
        let start = Instant::now();
        let err = ensure_daemon_with(&launch).await.expect_err("must refuse");
        let msg = err.to_string();
        assert!(
            msg.contains("runtime dir path too long for a unix socket")
                && msg.contains("set XDG_RUNTIME_DIR to a shorter path"),
            "the refusal names the cause and the fix: {msg}"
        );
        assert!(
            !msg.contains("SUN_LEN"),
            "no kernel vocabulary reaches the user: {msg}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the refusal must not wait out the connect window"
        );
    }

    /// A path that fits binds normally — the pre-check must never false-positive on the
    /// common short runtime dirs.
    #[cfg(unix)]
    #[test]
    fn short_socket_path_passes_the_len_check() {
        assert!(check_socket_path_len(Path::new("/run/user/501/mcpmesh/mcpmesh.sock")).is_ok());
    }
}
