//! Small crate-wide utilities: the wall-clock epoch pair and the atomic file replace. One home
//! for helpers that were previously copy-pasted per module (the daemon, the roster store, the
//! gate, doctor, and the porcelain all need "now as epoch seconds"; the daemon's config writers
//! and the roster store share one atomic-replace discipline).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

/// Wall-clock now as epoch seconds — the invite/`paired_at`/roster time source (no date crate).
/// A clock before the Unix epoch (impossible on a sane host) collapses to 0 rather than
/// panicking. `pub` (not `pub(crate)`) so the `main.rs` bin crate shares the same clock.
pub fn epoch_now_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// [`epoch_now_u64`] as `i64` — the roster/freshness arithmetic works in signed seconds
/// (staleness windows subtract). Same pre-epoch-collapses-to-0 discipline.
pub fn epoch_now_i64() -> i64 {
    epoch_now_u64() as i64
}

/// Atomically replace `path`: write a same-dir temp file, fsync, rename over the target
/// (spec §13 torn-state-never). The rename is atomic on the same filesystem.
///
/// The temp name is per-call-unique — pid + a process-global counter — so two writes (even
/// concurrent ones within ONE daemon process) can NEVER collide on the same temp file. A
/// pid-only name would let two in-process writers interleave `create(O_TRUNC)` + `write_all`
/// on the same temp → byte-mixed content → the rename publishes a torn file that fails to
/// parse. This mirrors the M0 device-key mint fix.
///
/// Best-effort temp cleanup on any failure, so a failed write/sync/rename never orphans a
/// `*.tmp.*` next to the target. (mcpmesh writes only its OWN files this way — it never edits a
/// third-party AI client's config; `proxy::client_instruction_lines` PRINTS what to paste
/// instead.) `kb-core/src/fsutil.rs` mirrors this discipline on the plugin side (layering forbids
/// sharing the code) — keep the two in step.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);

    let parent = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create dir {}", parent.display()))?;
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), seq));
    let write = || -> Result<()> {
        {
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("create temp {}", tmp.display()))?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("f.toml");
        atomic_write(&path, b"one").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        atomic_write(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        // No orphaned temp files next to the target.
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temp orphans: {leftovers:?}");
    }

    #[test]
    fn epoch_pair_agrees() {
        let u = epoch_now_u64();
        let i = epoch_now_i64();
        assert!(
            i >= u as i64 && i - u as i64 <= 1,
            "same clock, same second"
        );
    }
}
