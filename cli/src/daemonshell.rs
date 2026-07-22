//! The daemon PROCESS shell: per-uid singleton flock (unix), env-derived paths, and the
//! tokio runtime — everything that makes the embeddable node core (`mcpmesh_node::daemon`)
//! a system daemon. Kept out of `mcpmesh-node` on purpose: an embedded node is its own
//! isolated identity under its own root and must never contend for the per-uid singleton.
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::path::Path;

use anyhow::{Context, Result};
use mcpmesh_trust::paths;

use crate::ipc;

/// Run the daemon. On unix, acquires the per-uid flock singleton (another holder → exit 0);
/// on Windows the control-endpoint bind in `serve_forever` is the singleton. Then binds the
/// control endpoint FIRST, builds the endpoint + store + gate + service registry, starts the
/// mesh serve loop, and serves the control API until a `shutdown` request stops it.
pub fn run() -> Result<()> {
    // Unix singleton: the per-uid flock, taken BEFORE anything else so the stale-socket unlink
    // and the state.redb open are single-daemon-safe. We hold the exclusive lock, so no other
    // daemon is live: the stale-socket unlink cannot orphan anyone AND we are the sole opener of
    // state.redb. `_lock` lives until this function returns (process lifetime for a serving
    // daemon). Windows singleton: there is no advisory-lock/filesystem equivalent here — the
    // control-pipe bind ITSELF is the singleton (a FILE_FLAG_FIRST_PIPE_INSTANCE create fails with
    // AddrInUse once a peer daemon owns the pipe), which is why `serve_forever` binds the listener
    // FIRST, before opening state.redb.
    #[cfg(unix)]
    let _lock = {
        let runtime = paths::runtime_dir()?;
        ipc::ensure_runtime_dir(&runtime)?;
        let lock_path = runtime.join("mcpmesh.lock");
        match acquire_singleton_lock(&lock_path)? {
            Some(lock) => lock,
            None => {
                tracing::info!("another mcpmesh daemon already holds the singleton lock; exiting");
                return Ok(());
            }
        }
    };
    let socket = paths::default_endpoint()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build daemon tokio runtime")?;
    rt.block_on(async move {
        mcpmesh_node::daemon::serve_forever(&socket, mcpmesh_node::NodePaths::from_env()?).await
    })
}

/// Acquire the per-uid singleton lock. Returns `Some(file)` when we
/// win the exclusive advisory lock (hold it for the process lifetime; dropping it releases
/// the lock), or `None` when another daemon already holds it (`EWOULDBLOCK`). Unix-only: on
/// Windows the control-pipe bind is the singleton (see `run`), so there is no flock path.
#[cfg(unix)]
fn acquire_singleton_lock(lock_path: &Path) -> Result<Option<File>> {
    use rustix::fs::{FlockOperation, flock};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| format!("open singleton lock {}", lock_path.display()))?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context("flock singleton lock")),
    }
}
