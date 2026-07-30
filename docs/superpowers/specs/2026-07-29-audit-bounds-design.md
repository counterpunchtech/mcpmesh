# Bound, read, and observe the audit log (#88)

Date: 2026-07-29. Scope: all three asks — the prune verb, the list verb, storage bytes on
`status` — plus opt-in retention. The retention DEFAULT stays "keep forever" (see Decisions).

## Problem

`<root>/state/audit/<YYYY-MM>.jsonl` grows forever, driven by inbound peer traffic. The
primitives exist (`prune_before` is pub + tested; `list_month_files`, `read_records`,
`filter_records`, `parse_kind` all exist) but no control verb reaches them, so an embedder can
neither bound the log, read it, observe its size, nor honor a deletion request.

## Design

Control-API surface change → `API_MINOR 26 → 27`, `API_VERSION "1.27"`. All additive → PATCH
release (`0.23.4 → 0.23.5`). Follows `audit_summary`'s dispatch shape: resolve the node's own
audit dir off `mesh.audit().dir()` (env default in control-only mode), fs work on
`spawn_blocking`.

1. **`audit_prune { before: "YYYY-MM" }` → `{ deleted_months: [String] }`.** Validates the
   month shape up front (a malformed `before` errors rather than silently string-comparing to
   nothing), then wraps the existing `prune_before` (strictly-older-than; the named month is
   kept). Idempotent; pruning an empty/absent dir returns `[]`. Destructive but owner-only (the
   local control socket is the daemon owner's).
2. **`audit_list { since?, until?, kind?, peer?, limit?, offset? }` →
   `{ records: [AuditRecord], total }`.** `since`/`until` are inclusive `YYYY-MM` month keys —
   month-file granularity, matching the rotation unit, so filtering skips whole files without
   parsing them. `kind` uses the existing `parse_kind` strings (invalid → error, not
   silently-all). `peer` matches the record's stored nickname. `total` counts all matches;
   `records` pages by `offset` + `limit` (default 500, hard cap 1000 — a month file can be
   arbitrarily large and the response is one JSON frame, so the cap is load-bearing).
   `AuditRecord` is already published wire vocabulary (it rides `subscribe`), so no new types.
3. **`status.storage`** — additive `{ audit_bytes, redb_bytes, blobs_bytes }`
   (`#[serde(default)]`, skip-if-default): summed month-file sizes, `state.redb` metadata, and a
   bounded walk of the blobs dir. Computed on `spawn_blocking` in the status path.
4. **`[limits].audit_retain_months`** (u32, default 0 = keep forever). When > 0, boot runs
   `prune_before(cutoff)` where cutoff = current month minus N months (pure (year,month)
   arithmetic — no date crate, per the repo idiom). Boot-time only: a long-running daemon prunes
   on next start; the verb covers live needs.

## Decisions

- **Retention default stays 0 (keep forever).** The issue suggests a real default (3–6 months),
  but flipping today's keep-everything behavior to auto-deletion is destructive-by-default and
  is the repo owner's product call — noted on #88; the config makes it a one-line change.
- No CLI porcelain additions: `mcpmesh internal audit <tail|list|prune>` already covers the
  human file-direct path; these verbs are the embedder/daemon path.

## Tests (mutation-verified)

- `audit_prune` deletes strictly-older months and keeps `before` itself; malformed `before`
  errors; verb reaches the REAL dir the daemon's writer uses (write records through the sink,
  prune, re-read).
- `audit_list` filters by month range/kind/peer; `total` vs pagination pinned both sides
  (mutating the cap or dropping offset fails); invalid kind errors.
- `status.storage.audit_bytes` reflects bytes actually on disk (write, measure, compare); redb
  and blobs bytes present.
- Retention: boot over a dir seeded with old months + `audit_retain_months = N` deletes exactly
  the out-of-window months; default 0 deletes nothing (pinned — the keep-forever default is the
  decision above).

## Non-goals

Live size warnings/events (an embedder can poll `status.storage`), mid-flight rotation, record
redaction (#57's stable principal is separate), and any change to what is recorded.
