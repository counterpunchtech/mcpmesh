//! The typed audit record (spec §11.3) + the two pure helpers it needs: the blake3 args hash
//! (the PRIVACY core — arguments are hashed, never stored) and a zero-dependency RFC3339-millis
//! timestamp formatter (matching the codebase's "no date crate" idiom at `daemon::epoch_now`).
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The event class of an [`AuditRecord`] (spec §11.3's four classes). An additive discriminant on
/// top of the §11.3 example schema: it removes no spec field and makes the JSONL self-describing so
/// `internal audit` can filter by class without guessing from which optional fields are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A mesh session opened (a backend was selected for an authenticated peer).
    /// (A `session_open` with `status:"error"` is a synthesized FAILED-dial marker — no backend
    /// was reached; it records an attempted-and-failed reach for the telemetry stream.)
    SessionOpen,
    /// A mesh session closed (the backend returned / the session tore down).
    SessionClose,
    /// One proxied MCP request line (method + tool NAME + args_hash). NEVER carries raw arguments.
    Request,
    /// A peer fetched a blob from this node's gated provider (peer + hash + allow/deny).
    BlobFetch,
    /// A trust mutation (pair, unpair, roster install/swap, revoke).
    Trust,
}

/// One audit record — the union of the §11.3 event classes. Every field beyond `ts`/`kind` is
/// optional and elided when absent (`skip_serializing_if`), so each class serializes to just its
/// relevant keys (a session record has no `method`; a trust record has no `bytes_out`).
///
/// PRIVACY (spec §11.3): the proxied-request record carries `method` + `tool` (NAME only) +
/// `args_hash` (`"blake3:<hex>"`), and NEVER the raw arguments, the request/response content, or
/// any tool-output bytes — only a `bytes_out` COUNT and a `status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC3339 UTC with millisecond precision, e.g. `"2026-07-03T14:02:11.480Z"`. The `YYYY-MM`
    /// prefix also selects the monthly file (the rotation boundary), so it is always present.
    pub ts: String,
    pub kind: AuditKind,
    /// The gate-resolved authenticated peer (spec §11.3 attribution; endpoint_id-keyed). Absent on
    /// local-only events with no remote peer (a manual roster install).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The tool NAME only (never its arguments or output) — e.g. `"read_file"` for a `tools/call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// `"blake3:<hex>"` of the request arguments. The raw arguments are NEVER stored (spec §11.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    /// Byte COUNT of the response sent back to the peer — a count, never the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// `"ok"` / `"error"` (proxied request) or `"ok"` / `"denied"` (blob fetch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Trust-event verb: `"pair"` / `"unpair"` / `"roster_install"` / `"revoke"` (kind == Trust).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// A reference, NEVER content: a blob hash (`BlobFetch`) or a trust-event target such as a
    /// petname or `org/serial` (`Trust`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

impl AuditRecord {
    fn base(ts: String, kind: AuditKind) -> Self {
        Self {
            ts,
            kind,
            peer: None,
            service: None,
            method: None,
            tool: None,
            args_hash: None,
            bytes_out: None,
            status: None,
            latency_ms: None,
            event: None,
            target: None,
        }
    }

    pub fn session_open(ts: String, peer: Option<String>, service: String) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionOpen);
        r.peer = peer;
        r.service = Some(service);
        r
    }

    /// Set the record's `status` (`"ok"`/`"error"`/`"denied"`), returning `self` for chaining.
    /// Marks a synthesized failure record — e.g. the `session_open` for a FAILED dial, which
    /// reaches no backend and so is never audited by the far side's session guard — without a
    /// dedicated constructor. DRY: reuses the existing optional `status` field.
    pub fn with_status(mut self, status: &str) -> Self {
        self.status = Some(status.into());
        self
    }

    pub fn session_close(ts: String, peer: Option<String>, service: String) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionClose);
        r.peer = peer;
        r.service = Some(service);
        r
    }

    /// A completed (request→response correlated) proxied line: method + tool NAME + args_hash, plus
    /// the response's `bytes_out` COUNT, `status`, and `latency_ms`. PRIVACY: `args_hash` is a digest;
    /// no raw arguments, request/response content, or tool-output bytes are ever passed in.
    #[allow(clippy::too_many_arguments)]
    pub fn proxied_request(
        ts: String,
        peer: Option<String>,
        service: String,
        method: String,
        tool: Option<String>,
        args_hash: String,
        bytes_out: u64,
        status: String,
        latency_ms: u64,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Request);
        r.peer = peer;
        r.service = Some(service);
        r.method = Some(method);
        r.tool = tool;
        r.args_hash = Some(args_hash);
        r.bytes_out = Some(bytes_out);
        r.status = Some(status);
        r.latency_ms = Some(latency_ms);
        r
    }

    /// A proxied NOTIFICATION line (no `id`, so no response correlates): method + tool + args_hash,
    /// no `bytes_out`/`status`/`latency_ms`. Still records the line per spec §11.3.
    pub fn proxied_notification(
        ts: String,
        peer: Option<String>,
        service: String,
        method: String,
        tool: Option<String>,
        args_hash: String,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Request);
        r.peer = peer;
        r.service = Some(service);
        r.method = Some(method);
        r.tool = tool;
        r.args_hash = Some(args_hash);
        r
    }

    pub fn blob_fetch(ts: String, peer: Option<String>, hash: String, status: String) -> Self {
        let mut r = Self::base(ts, AuditKind::BlobFetch);
        r.peer = peer;
        r.target = Some(hash);
        r.status = Some(status);
        r
    }

    pub fn trust(ts: String, event: String, target: Option<String>) -> Self {
        let mut r = Self::base(ts, AuditKind::Trust);
        r.event = Some(event);
        r.target = target;
        r
    }
}

/// Hash a request's arguments to `"blake3:<hex>"` (spec §11.3). The raw argument bytes are NEVER
/// stored — only this digest — because callers' inputs can be sensitive. Deterministic within a
/// process for a given `params` value (serde_json serialization). `params` may be `Value::Null`
/// (a parameterless method) — that hashes the four bytes `null`, a stable non-empty digest.
pub fn args_hash(params: &Value) -> String {
    let bytes = serde_json::to_vec(params).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

/// The current wall-clock instant as an RFC3339 UTC millisecond string (spec §11.3 `ts`). Uses
/// `SystemTime` + a hand-rolled civil-date conversion — NO date crate — matching the codebase's
/// stated preference at `daemon::epoch_now` ("no date crate"). A pre-epoch clock (impossible on a
/// sane host) collapses to the epoch rather than panicking.
pub fn now_ts() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    fmt_rfc3339_millis(millis)
}

/// Format Unix-epoch milliseconds as `"YYYY-MM-DDTHH:MM:SS.mmmZ"`. Pure + unit-testable.
pub fn fmt_rfc3339_millis(unix_millis: u128) -> String {
    let secs = (unix_millis / 1000) as i64;
    let millis = (unix_millis % 1000) as u64;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (year, month [1..=12], day [1..=31]).
/// Proleptic Gregorian, exact for the whole i64 range — the standard branch-free algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamp_formats_epoch_and_millis() {
        // The Unix epoch and a sub-second instant — the boundary the writer derives the month from.
        assert_eq!(fmt_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(fmt_rfc3339_millis(1500), "1970-01-01T00:00:01.500Z");
        // A known modern instant: 1_700_000_000_000 ms == 2023-11-14T22:13:20.000Z.
        assert_eq!(
            fmt_rfc3339_millis(1_700_000_000_000),
            "2023-11-14T22:13:20.000Z"
        );
        // The month prefix (the rotation key) is the first 7 chars.
        assert_eq!(&fmt_rfc3339_millis(1_700_000_000_000)[..7], "2023-11");
    }

    #[test]
    fn args_hash_is_blake3_prefixed_and_deterministic() {
        let p = json!({"path": "/secret/passwords.txt"});
        let h = args_hash(&p);
        assert!(h.starts_with("blake3:"));
        assert_eq!(h, args_hash(&p), "same params → same hash");
        assert_ne!(h, args_hash(&json!({"path": "/other"})), "differs by input");
        // The hex is a 64-char blake3 digest.
        assert_eq!(h.len(), "blake3:".len() + 64);
    }

    /// PRIVACY (spec §11.3): a proxied-request record NEVER carries the raw arguments — only their
    /// blake3 digest — and it carries the method + tool NAME. Serialize a record built from a
    /// sensitive argument and assert the raw secret is ABSENT from the JSON while the digest is
    /// present. This is the unit-level guard on the hard privacy invariant.
    #[test]
    fn proxied_request_serialization_never_leaks_raw_arguments() {
        let secret = "hunter2-super-secret-token";
        let params = json!({"name": "read_file", "arguments": {"token": secret}});
        let rec = AuditRecord::proxied_request(
            "2026-07-03T14:02:11.480Z".into(),
            Some("bob".into()),
            "notes".into(),
            "tools/call".into(),
            Some("read_file".into()),
            args_hash(&params),
            6210,
            "ok".into(),
            41,
        );
        let line = serde_json::to_string(&rec).unwrap();
        assert!(
            !line.contains(secret),
            "raw argument leaked into the record: {line}"
        );
        assert!(line.contains("blake3:"), "args_hash digest must be present");
        assert!(
            line.contains("\"tool\":\"read_file\""),
            "tool NAME is recorded"
        );
        assert!(line.contains("\"method\":\"tools/call\""));
        // The kind serializes snake_case; a session record elides request-only fields.
        let s = AuditRecord::session_open(
            "2026-07-03T14:02:11.480Z".into(),
            Some("bob".into()),
            "notes".into(),
        );
        let sline = serde_json::to_string(&s).unwrap();
        assert!(sline.contains("\"kind\":\"session_open\""));
        assert!(
            !sline.contains("method"),
            "session record elides request fields"
        );
    }

    #[test]
    fn record_round_trips_through_jsonl() {
        // internal audit reads records back; a round-trip proves Deserialize matches Serialize.
        let rec = AuditRecord::trust(
            "2026-07-03T14:02:11.480Z".into(),
            "pair".into(),
            Some("bob".into()),
        );
        let line = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.kind, AuditKind::Trust);
    }
}
