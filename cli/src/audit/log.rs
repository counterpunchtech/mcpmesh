//! The append-only JSONL writer (spec §11.3): a bounded-channel single-writer task whose `record()`
//! never blocks the caller, plus the sync append core. Best-effort by construction — an audit-write
//! failure is a logged warning, never a blocked or failed session (spec §11.3 "must not block or
//! fail the hot path"). Local-only: nothing here is transmitted; the file is written and read only
//! on this machine.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::audit::record::AuditRecord;

/// Bounded queue depth between the hot path and the single writer task. Deep enough that a bursty
/// session never drops under normal load; bounded so a stuck disk cannot grow memory without limit
/// (spec §11.3 robustness). On overflow, `record()` DROPS the record with a warning rather than
/// awaiting — the hot path never blocks on the audit channel.
const AUDIT_CHANNEL_DEPTH: usize = 1024;

/// Append one record as a single JSONL line to `<dir>/<YYYY-MM>.jsonl` (the monthly file — the
/// rotation boundary is the calendar month, derived from the record's own `ts`). The directory is
/// created lazily. `O_APPEND` + a single `write_all` of `line + "\n"` is atomic-enough for JSONL:
/// concurrent appenders never interleave a partial line. This is the SYNC core the writer task runs
/// on the blocking pool; it is also unit-tested directly.
pub(crate) fn append_record(dir: &Path, rec: &AuditRecord) -> std::io::Result<()> {
    use std::io::Write as _;
    // The month key is the `YYYY-MM` prefix of the RFC3339 timestamp (always ≥ 7 chars from
    // `now_ts`); guard a malformed short ts by falling back to a fixed bucket rather than panicking.
    let month = rec.ts.get(0..7).unwrap_or("0000-00");
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{month}.jsonl"));
    let mut line = serde_json::to_vec(rec)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push(b'\n');
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    f.write_all(&line)
}

/// A running audit log: a handle over the sender half of the writer channel. Cheap to clone (an
/// `Arc` over the sender). The writer task drains the channel and appends each record on the
/// blocking pool for the daemon's lifetime.
pub struct AuditLog {
    tx: mpsc::Sender<AuditRecord>,
}

impl AuditLog {
    /// Spawn the single writer task over `dir` and return the handle. The task drains a bounded
    /// channel and appends each record via [`append_record`] on `spawn_blocking` (keeping fs off the
    /// runtime workers, the repo's fs house rule). An append error is logged and the record dropped —
    /// the task never exits on an IO error, so a transient full disk does not disable auditing.
    pub fn spawn(dir: PathBuf) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<AuditRecord>(AUDIT_CHANNEL_DEPTH);
        tokio::spawn(async move {
            while let Some(rec) = rx.recv().await {
                let dir = dir.clone();
                let res = tokio::task::spawn_blocking(move || append_record(&dir, &rec)).await;
                match res {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::warn!(%e, "audit append failed (record dropped)"),
                    Err(e) => tracing::warn!(%e, "audit writer join failed (record dropped)"),
                }
            }
        });
        Arc::new(Self { tx })
    }

    /// Record one event — NON-BLOCKING and infallible from the caller's view (spec §11.3). Uses
    /// `try_send`: a full channel (writer wedged on a slow disk) or a closed channel (writer gone)
    /// DROPS the record with a debug log and returns immediately. The hot path NEVER awaits the disk
    /// and an audit failure NEVER propagates into a session.
    pub fn record(&self, rec: AuditRecord) {
        if let Err(e) = self.tx.try_send(rec) {
            tracing::debug!(%e, "audit channel full or closed; dropping record (best-effort)");
        }
    }
}

/// A cheap, cloneable audit handle threaded into the backends / provider / trust hooks. `None` means
/// auditing is DISABLED (unit tests, or a daemon that failed to spawn the log) — `record` is a
/// no-op, so every hook is written unconditionally and the disabled path is zero-cost.
#[derive(Clone, Default)]
pub struct AuditSink(Option<Arc<AuditLog>>);

impl AuditSink {
    pub fn new(log: Arc<AuditLog>) -> Self {
        Self(Some(log))
    }
    /// The no-op sink (auditing disabled).
    pub fn disabled() -> Self {
        Self(None)
    }
    /// Record an event if enabled; a no-op otherwise. Never blocks, never errors (spec §11.3).
    pub fn record(&self, rec: AuditRecord) {
        if let Some(log) = &self.0 {
            log.record(rec);
        }
    }
}

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use serde_json::Value;

use crate::audit::record::{args_hash, now_ts};

/// One pending request awaiting its response (keyed by JSON-RPC id). Holds only the DIGEST of the
/// args (never the raw args) plus the metadata the completed record needs.
struct Pending {
    method: String,
    tool: Option<String>,
    args_hash: String,
    started: Instant,
}

/// Per-session correlation for the proxied-request-line hook (spec §11.3). The pump drives it from
/// its two directions: `on_request` (caller → server) hashes the args and remembers the request by
/// id; `on_response` (server → caller) matches the id, computes latency + status, and emits ONE
/// completed record with the response's `bytes_out` COUNT. A NOTIFICATION (no id) is recorded at
/// request time (no response correlates). PRIVACY — the raw arguments are hashed and then dropped;
/// they are never stored in `Pending` or written to the log.
///
/// The two directions run as concurrent async blocks in one pump future, so the pending map lives
/// behind a `Mutex` with only non-await critical sections (`Send`-safe, no lock held across `.await`).
/// The disabled path (a `RequestAuditor` built over `AuditSink::disabled()`) records nothing.
#[derive(Clone)]
pub struct RequestAuditor {
    inner: Option<Arc<RequestAuditorInner>>,
}

struct RequestAuditorInner {
    sink: AuditSink,
    peer: Option<String>,
    service: String,
    pending: Mutex<HashMap<String, Pending>>,
}

impl RequestAuditor {
    pub fn new(sink: AuditSink, peer: Option<String>, service: String) -> Self {
        Self {
            inner: Some(Arc::new(RequestAuditorInner {
                sink,
                peer,
                service,
                pending: Mutex::new(HashMap::new()),
            })),
        }
    }

    /// Direction A (caller → local server): a request line is about to be forwarded. Hash its args
    /// (NEVER stored raw), extract method + tool NAME, and either remember it by id (a request, to be
    /// completed by its response) or — for a notification (no id) — record it immediately.
    pub fn on_request(&self, frame: &Value) {
        let Some(inner) = &self.inner else { return };
        let Some(method) = frame.get("method").and_then(Value::as_str) else {
            return; // not a request/notification line (e.g. a client-side response); nothing to log
        };
        // Tool NAME only for tools/call (spec §11.3) — never the tool arguments or output.
        let tool = if method == "tools/call" {
            frame
                .pointer("/params/name")
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        // PRIVACY: hash the params; the raw args are never retained past this line.
        let ah = args_hash(frame.get("params").unwrap_or(&Value::Null));

        match frame.get("id") {
            Some(id) if !id.is_null() => {
                // A request: remember it until its response correlates (bytes_out/latency/status).
                let key = id.to_string();
                let mut pending = inner
                    .pending
                    .lock()
                    .expect("audit pending map not poisoned");
                pending.insert(
                    key,
                    Pending {
                        method: method.to_string(),
                        tool,
                        args_hash: ah,
                        started: Instant::now(),
                    },
                );
            }
            _ => {
                // A notification (no id / null id): record now — no response will correlate.
                inner.sink.record(AuditRecord::proxied_notification(
                    now_ts(),
                    inner.peer.clone(),
                    inner.service.clone(),
                    method.to_string(),
                    tool,
                    ah,
                ));
            }
        }
    }

    /// Direction B (local server → caller): a response line is about to go back. If it correlates to
    /// a pending request (by id), emit ONE completed record with the response's `bytes_out` COUNT,
    /// `status` (ok/error), and `latency_ms`. A response with no matching request (server-initiated)
    /// is ignored.
    ///
    /// SERVER-INITIATED REQUESTS (correctness, not just tidiness): MCP servers send REQUESTS to the
    /// client too (sampling/`createMessage`, `roots/list`, elicitation), and those flow through pump
    /// Direction B into here. Both peers number JSON-RPC ids from 1, so a server request id=1 would
    /// otherwise EVICT the client's still-pending id=1 and emit a bogus record (wrong bytes/latency),
    /// leaving the client's real response uncorrelated. A JSON-RPC *response* never carries `method`,
    /// so the `method`-present guard below cleanly excludes every server-initiated request/notification
    /// from response correlation (symmetric with Direction A's `on_request`, which REQUIRES `method`).
    pub fn on_response(&self, frame: &Value, bytes_out: u64) {
        let Some(inner) = &self.inner else { return };
        // Only a real response correlates: a frame carrying `method` is a server-initiated request or
        // notification (see the doc above), NOT a response to a client request — skip it.
        if frame.get("method").is_some() {
            return;
        }
        let Some(id) = frame.get("id").filter(|v| !v.is_null()) else {
            return; // a server notification, not a response — no correlation
        };
        let key = id.to_string();
        let pending = {
            let mut map = inner
                .pending
                .lock()
                .expect("audit pending map not poisoned");
            map.remove(&key)
        };
        let Some(p) = pending else { return };
        let status = if frame.get("error").is_some() {
            "error"
        } else {
            "ok"
        };
        let latency_ms = p.started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        inner.sink.record(AuditRecord::proxied_request(
            now_ts(),
            inner.peer.clone(),
            inner.service.clone(),
            p.method,
            p.tool,
            p.args_hash,
            bytes_out,
            status.to_string(),
            latency_ms,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::{AuditRecord, args_hash};
    use serde_json::json;

    #[test]
    fn append_writes_jsonl_to_the_month_file_and_hides_raw_args() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "top-secret-argument-value";
        let params = json!({"arguments": {"q": secret}});
        let rec = AuditRecord::proxied_request(
            "2026-07-03T14:02:11.480Z".into(),
            Some("bob".into()),
            "notes".into(),
            "tools/call".into(),
            Some("read_file".into()),
            args_hash(&params),
            42,
            "ok".into(),
            7,
        );
        append_record(dir.path(), &rec).unwrap();

        // The month is derived from the ts prefix → 2026-07.jsonl (the rotation boundary).
        let file = dir.path().join("2026-07.jsonl");
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(body.ends_with('\n'), "one JSONL line, newline-terminated");
        assert_eq!(body.lines().count(), 1);
        // PRIVACY: the raw argument NEVER lands in the file — only the blake3 digest.
        assert!(
            !body.contains(secret),
            "raw argument leaked to disk: {body}"
        );
        assert!(body.contains("blake3:"));

        // A second record in a DIFFERENT month lands in its own file (monthly rotation).
        let rec2 =
            AuditRecord::session_open("2026-08-01T00:00:00.000Z".into(), None, "notes".into());
        append_record(dir.path(), &rec2).unwrap();
        assert!(dir.path().join("2026-08.jsonl").exists());
        // The July file still has exactly one line (append, not overwrite).
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    }

    #[tokio::test]
    async fn record_is_non_blocking_and_writer_persists() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::spawn(dir.path().to_path_buf());
        let sink = AuditSink::new(log);
        // A burst of records — none of these calls awaits or blocks the caller.
        for i in 0..5 {
            sink.record(AuditRecord::session_open(
                format!("2026-07-03T14:02:1{i}.000Z"),
                Some("bob".into()),
                "notes".into(),
            ));
        }
        // The writer task drains asynchronously; poll the file until the records land.
        let file = dir.path().join("2026-07.jsonl");
        let mut lines = 0;
        for _ in 0..50 {
            if let Ok(body) = std::fs::read_to_string(&file) {
                lines = body.lines().count();
                if lines >= 5 {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(lines, 5, "all five records persisted");
    }

    #[test]
    fn disabled_sink_is_a_silent_no_op() {
        // The disabled sink never touches disk and never errors — the zero-cost test path.
        let sink = AuditSink::disabled();
        sink.record(AuditRecord::trust(
            "2026-07-03T14:02:11.480Z".into(),
            "pair".into(),
            None,
        ));
        // Nothing observable to assert beyond "did not panic / no file created"; the call returns.
    }

    #[tokio::test]
    async fn request_auditor_records_correlated_line_without_raw_args() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().to_path_buf();
        let sink = AuditSink::new(AuditLog::spawn(audit_dir.clone()));
        let auditor = RequestAuditor::new(sink, Some("bob".into()), "notes".into());

        let secret = "sensitive-search-query-xyzzy";
        // Direction A: a tools/call request with a sensitive argument. The auditor sees the raw args
        // (to hash them) but must NEVER write them.
        let req = json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"query": secret}}
        });
        auditor.on_request(&req);
        // A notification (no id) is recorded immediately at request time.
        auditor.on_request(&json!({
            "jsonrpc": "2.0", "method": "notifications/progress",
            "params": {"token": "t1"}
        }));
        // Direction B: the correlated response (matched by id 7) with 6210 bytes out, status ok.
        let resp = json!({"jsonrpc": "2.0", "id": 7, "result": {"content": []}});
        auditor.on_response(&resp, 6210);

        let month = &crate::audit::now_ts()[..7];
        let file = audit_dir.join(format!("{month}.jsonl"));
        let mut body = String::new();
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file)
                && b.matches("\"kind\":\"request\"").count() >= 2
            {
                body = b;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // PRIVACY: the raw argument value never reaches disk — only its blake3 digest.
        assert!(!body.contains(secret), "raw args leaked: {body}");
        // The correlated request record carries method + tool NAME + args_hash + bytes_out + status.
        assert!(body.contains("\"method\":\"tools/call\""));
        assert!(body.contains("\"tool\":\"read_file\""));
        assert!(body.contains("blake3:"));
        assert!(body.contains("\"bytes_out\":6210"));
        assert!(body.contains("\"status\":\"ok\""));
        assert!(body.contains("\"peer\":\"bob\""));
        // The notification recorded its method + a nil-tool (not a tools/call) with no bytes_out.
        assert!(body.contains("\"method\":\"notifications/progress\""));
    }

    /// A SERVER-INITIATED request (MCP sampling/roots/elicitation) flows through Direction B into
    /// `on_response`. It carries `method` AND an id that COLLIDES with the client's id numbering
    /// (both start at 1), so without the `method`-present guard it would evict the client's pending
    /// id=1 and emit a bogus record. Assert: the client's real id=1 response still correlates to a
    /// tools/call record, and the server request (method="sampling/createMessage") is NOT recorded.
    #[tokio::test]
    async fn server_initiated_request_does_not_corrupt_client_correlation() {
        let dir = tempfile::tempdir().unwrap();
        let sink = AuditSink::new(AuditLog::spawn(dir.path().to_path_buf()));
        let auditor = RequestAuditor::new(sink, Some("bob".into()), "notes".into());
        // Client sends request id=1 (tools/call).
        auditor.on_request(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/x"}}
        }));
        // Server sends its OWN request, ALSO id=1 (a collision) — flows through Direction B.
        auditor.on_response(
            &json!({"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}}),
            50,
        );
        // Client's real response to id=1 arrives — must still correlate to the tools/call.
        auditor.on_response(&json!({"jsonrpc": "2.0", "id": 1, "result": {}}), 300);

        let month = &crate::audit::now_ts()[..7];
        let file = dir.path().join(format!("{month}.jsonl"));
        let mut body = String::new();
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file)
                && b.contains("\"tool\":\"read_file\"")
            {
                body = b;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // The client's tools/call correlated (bytes_out from its REAL 300-byte response, not 50).
        assert!(body.contains("\"tool\":\"read_file\""));
        assert!(
            body.contains("\"bytes_out\":300"),
            "correlated to the client's response, not the server request"
        );
        // The server-initiated request was NOT recorded (the method-present guard skipped it).
        assert!(
            !body.contains("sampling/createMessage"),
            "server-initiated request must not be logged"
        );
    }

    #[tokio::test]
    async fn request_auditor_marks_error_responses() {
        let dir = tempfile::tempdir().unwrap();
        let sink = AuditSink::new(AuditLog::spawn(dir.path().to_path_buf()));
        let auditor = RequestAuditor::new(sink, Some("bob".into()), "notes".into());
        auditor
            .on_request(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}));
        auditor.on_response(
            &json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}),
            120,
        );
        let month = &crate::audit::now_ts()[..7];
        let file = dir.path().join(format!("{month}.jsonl"));
        let mut ok = false;
        for _ in 0..50 {
            if let Ok(b) = std::fs::read_to_string(&file)
                && b.contains("\"status\":\"error\"")
            {
                ok = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(ok, "an error response records status=error");
    }
}
