//! Local, append-only JSONL audit log (spec §11.3). One record per session open/close, per
//! proxied MCP request line (method + tool NAME + a blake3 hash of the arguments — NEVER the raw
//! arguments), per blob fetch, and per trust event. Best-effort: an audit-write failure is a
//! logged warning, never a blocked or failed session. Local-only: nothing here is ever transmitted;
//! `internal audit` reads these files directly with no daemon and no network.
pub mod log;
pub mod record;

// The writer types (`AuditLog`, `AuditSink`) plus the per-session proxied-line correlator
// (`RequestAuditor`, Task 3/4) are re-exported from `log.rs`.
pub use log::{AuditLog, AuditSink, RequestAuditor};
pub use record::{AuditKind, AuditRecord, args_hash, now_ts};

use mcpmesh_local_api::AuditSummaryResult;
use std::path::{Path, PathBuf};

/// Is `name` a monthly audit file (`YYYY-MM.jsonl`)? Returns the `YYYY-MM` month key if so. The
/// rotation unit is the calendar month, so a file name IS its month.
fn month_of_filename(name: &str) -> Option<String> {
    let stem = name.strip_suffix(".jsonl")?;
    let bytes = stem.as_bytes();
    // Shape: DDDD-DD (4 digits, dash, 2 digits).
    if stem.len() == 7
        && bytes[4] == b'-'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..].iter().all(u8::is_ascii_digit)
    {
        Some(stem.to_string())
    } else {
        None
    }
}

/// Enumerate the monthly files in `dir` as `(month, path, size_bytes)`, sorted ascending by month
/// (oldest first). A missing dir yields an empty list (no audit written yet), not an error.
pub fn list_month_files(dir: &Path) -> std::io::Result<Vec<(String, PathBuf, u64)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(month) = month_of_filename(&name) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((month, entry.path(), size));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Parse one monthly file into records. An unparseable line is SKIPPED with a warning (a torn final
/// line from a crash, or a forward-compatible unknown field) rather than failing the whole read —
/// the log is diagnostic, not transactional.
pub fn read_records(path: &Path) -> std::io::Result<Vec<AuditRecord>> {
    let body = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in body.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(line) {
            Ok(rec) => out.push(rec),
            Err(e) => tracing::warn!(%e, "skipping unparseable audit line"),
        }
    }
    Ok(out)
}

/// Read every record across all monthly files in chronological order (oldest month first, in-file
/// order within a month).
pub fn read_all_records(dir: &Path) -> std::io::Result<Vec<AuditRecord>> {
    let mut out = Vec::new();
    for (_, path, _) in list_month_files(dir)? {
        out.extend(read_records(&path)?);
    }
    Ok(out)
}

/// Filter records by optional kind and optional peer (both AND-combined; `None` matches all).
pub fn filter_records<'a>(
    records: &'a [AuditRecord],
    kind: Option<AuditKind>,
    peer: Option<&str>,
) -> Vec<&'a AuditRecord> {
    records
        .iter()
        .filter(|r| kind.is_none_or(|k| r.kind == k))
        .filter(|r| peer.is_none_or(|p| r.peer.as_deref() == Some(p)))
        .collect()
}

/// Aggregate audit records into per-peer / per-service SESSION counts (spec §11.3). A "session" is a
/// `SessionOpen` record; every other kind (proxied requests, blob fetches, trust events) is ignored.
/// Deterministic: `per_peer` / `per_service` are sorted ascending by name (BTreeMap iteration). PURE
/// over an injected record slice — the §9 reconciliation gate asserts this equals a direct count over
/// `read_all_records` (the same JSONL `internal audit` reads). LOCAL-only: the caller reads the
/// daemon's own `default_audit_dir()`; this fn never touches the network. Surface-clean (§1.5): the
/// keys are the record's petnames / service names, never endpoints/transport vocabulary.
pub fn summarize_sessions(records: &[AuditRecord]) -> AuditSummaryResult {
    use std::collections::BTreeMap;
    let mut per_peer: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_service: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_sessions: u64 = 0;
    for rec in records {
        if rec.kind != AuditKind::SessionOpen {
            continue;
        }
        total_sessions += 1;
        if let Some(peer) = &rec.peer {
            *per_peer.entry(peer.clone()).or_default() += 1;
        }
        if let Some(service) = &rec.service {
            *per_service.entry(service.clone()).or_default() += 1;
        }
    }
    AuditSummaryResult {
        per_peer: per_peer.into_iter().collect(),
        per_service: per_service.into_iter().collect(),
        total_sessions,
    }
}

/// Delete every monthly file STRICTLY older than `before` (a `YYYY-MM` string), returning the
/// deleted months. String comparison is correct for zero-padded `YYYY-MM`. The `before` month itself
/// is KEPT (delete-before-this, not delete-including). This is the rotation/prune of the monthly log.
pub fn prune_before(dir: &Path, before: &str) -> std::io::Result<Vec<String>> {
    let mut deleted = Vec::new();
    for (month, path, _) in list_month_files(dir)? {
        if month.as_str() < before {
            std::fs::remove_file(&path)?;
            deleted.push(month);
        }
    }
    Ok(deleted)
}

/// Parse a kind filter string from the porcelain (`--kind request`) into an [`AuditKind`].
pub fn parse_kind(s: &str) -> Option<AuditKind> {
    match s {
        "session_open" => Some(AuditKind::SessionOpen),
        "session_close" => Some(AuditKind::SessionClose),
        "request" => Some(AuditKind::Request),
        "blob_fetch" => Some(AuditKind::BlobFetch),
        "trust" => Some(AuditKind::Trust),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::AuditRecord;

    fn seed(dir: &std::path::Path) {
        // Two monthly files: 2026-06 (one trust record) and 2026-07 (two request records + one
        // session_open), so list/filter/prune have something to bite on.
        crate::audit::log::append_record(
            dir,
            &AuditRecord::trust(
                "2026-06-30T23:59:59.000Z".into(),
                "pair".into(),
                Some("bob".into()),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir,
            &AuditRecord::session_open(
                "2026-07-01T00:00:00.000Z".into(),
                Some("bob".into()),
                "notes".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir,
            &AuditRecord::proxied_notification(
                "2026-07-01T00:00:01.000Z".into(),
                Some("bob".into()),
                "notes".into(),
                "tools/list".into(),
                None,
                "blake3:deadbeef".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir,
            &AuditRecord::proxied_notification(
                "2026-07-01T00:00:02.000Z".into(),
                Some("alice".into()),
                "notes".into(),
                "tools/call".into(),
                Some("read_file".into()),
                "blake3:cafe".into(),
            ),
        )
        .unwrap();
    }

    #[test]
    fn lists_monthly_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let months: Vec<String> = list_month_files(dir.path())
            .unwrap()
            .into_iter()
            .map(|(m, _, _)| m)
            .collect();
        assert_eq!(months, vec!["2026-06".to_string(), "2026-07".to_string()]);
    }

    #[test]
    fn reads_and_filters_by_kind_and_peer() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let all = read_all_records(dir.path()).unwrap();
        assert_eq!(all.len(), 4);
        // Filter to request records only.
        let reqs = filter_records(&all, Some(AuditKind::Request), None);
        assert_eq!(reqs.len(), 2);
        // Filter to peer "alice".
        let alice = filter_records(&all, None, Some("alice"));
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].tool.as_deref(), Some("read_file"));
    }

    #[test]
    fn prune_deletes_months_strictly_before_the_boundary() {
        let dir = tempfile::tempdir().unwrap();
        seed(dir.path());
        let deleted = prune_before(dir.path(), "2026-07").unwrap();
        assert_eq!(deleted, vec!["2026-06".to_string()]);
        assert!(!dir.path().join("2026-06.jsonl").exists());
        assert!(
            dir.path().join("2026-07.jsonl").exists(),
            "the boundary month is kept"
        );
    }

    #[test]
    fn session_summary_reconciles_with_the_raw_audit_log() {
        // Seed a FIXED record set spanning two months: SessionOpen for bob/notes (x2), alice/notes
        // (x1), a peer-less SessionOpen for kb (x1), plus non-session records (a proxied request, a
        // trust event) that MUST NOT be counted as sessions.
        let dir = tempfile::tempdir().unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::session_open(
                "2026-06-30T10:00:00.000Z".into(),
                Some("bob".into()),
                "notes".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::session_open(
                "2026-07-01T10:00:00.000Z".into(),
                Some("bob".into()),
                "notes".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::session_open(
                "2026-07-01T11:00:00.000Z".into(),
                Some("alice".into()),
                "notes".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::session_open("2026-07-01T12:00:00.000Z".into(), None, "kb".into()),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::proxied_notification(
                "2026-07-01T13:00:00.000Z".into(),
                Some("bob".into()),
                "notes".into(),
                "tools/list".into(),
                None,
                "blake3:x".into(),
            ),
        )
        .unwrap();
        crate::audit::log::append_record(
            dir.path(),
            &AuditRecord::trust(
                "2026-07-01T14:00:00.000Z".into(),
                "pair".into(),
                Some("carol".into()),
            ),
        )
        .unwrap();

        let all = read_all_records(dir.path()).unwrap();
        let summary = summarize_sessions(&all);

        // total = 4 SessionOpen records (the proxied request + the trust event are excluded).
        assert_eq!(summary.total_sessions, 4);

        // RECONCILIATION (§10 AC): each per-peer session count equals an INDEPENDENT direct count via
        // filter_records — the SAME read path `internal audit --kind session_open --peer <p>` uses.
        for (peer, count) in &summary.per_peer {
            let direct =
                filter_records(&all, Some(AuditKind::SessionOpen), Some(peer)).len() as u64;
            assert_eq!(
                *count, direct,
                "per-peer session count must reconcile with the raw log for {peer}"
            );
        }

        // Concrete numbers (sorted ascending by name): bob=2, alice=1 (the peer-less kb session is not
        // attributed to a peer, so it is absent from per_peer but present in total_sessions).
        assert_eq!(
            summary.per_peer,
            vec![("alice".to_string(), 1), ("bob".to_string(), 2)]
        );
        // per_service: notes=3 (bob x2 + alice x1), kb=1 — sorted ascending by name.
        assert_eq!(
            summary.per_service,
            vec![("kb".to_string(), 1), ("notes".to_string(), 3)]
        );
    }
}
