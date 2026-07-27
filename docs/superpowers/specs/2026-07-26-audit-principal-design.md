# `AuditRecord.principal` — a stable identity on the event stream (#57)

**Status:** accepted · **Issue:** #57 · **Target:** 0.12.1 (additive → PATCH)

## Problem

#41 and #42 established that every per-peer decision must key on a STABLE principal
(`eid:` device / `b64u:` user) rather than a display nickname, and added `principal` to `PeerInfo`
and `PeerReachability`. `AuditRecord` — the payload of every `StreamFrame::Event`, and the whole
of the on-disk log — was missed. It carries only `peer`, a rendered name.

So two devices under one nickname, or two contacts sharing a display name, are indistinguishable in
the only *pushed* surface the control API has. Every consumer of `subscribe` — presence, per-peer
activity, routing, "who is using my service right now" — is making exactly the caller-keyed
decision #41 argued must not key on a nickname.

It is also internally inconsistent in a way that costs embedders real work: a `Snapshot` frame
carries `PeerReachability` (which has `principal`) beside `AuditRecord` (which does not), so joining
the two halves of one frame falls back to nickname matching.

## Approach

Add `principal: Option<String>` to `AuditRecord`, carrying the **device `eid:` principal** — the
same value `PeerInfo.principal` (#41) and `PeerReachability.principal` (#42) carry, so the three
join directly. `peer` is retained unchanged as the display rendering.

### Where it comes from

The backends already derive `peer` from the gate-resolved `PeerIdentity`:

```rust
let peer = identity.as_ref().map(|id| id.user_id.clone().unwrap_or_else(|| id.name.clone()));
```

`principal` comes from the same resolution, one line over: `id.endpoint.principal()`. That is the
authenticated endpoint id rendered `eid:<hex>` — it cannot be spoofed or renamed, which is the
whole point.

Note `peer` is *sometimes* already stable (it prefers `user_id` when a device→user binding exists),
but it is not *guaranteed* stable and it never distinguishes two devices of one person. `principal`
is both.

### Threading it

Every constructor that takes `peer` takes `principal` **explicitly**, rather than a
`.with_principal()` builder. A builder makes the field opt-in, and a call site that forgets it
reintroduces the bug silently for that event type — the compiler should force the decision at each
site instead.

- `AuditRecord::{session_open, session_close, proxied_request, proxied_notification, blob_fetch}`
  gain a `principal: Option<String>` parameter beside `peer`.
- `AuditRecord::trust` gains one too. Trust events have no `peer`, but the pairing grant and the
  revoke both know the principal they acted on — that is precisely the identity an auditor wants,
  and leaving it `None` there would be a gap of the same kind.
- `AuditSink::session(peer, principal, service)` and `RequestAuditor::new(sink, peer, principal,
  service)` thread it through.

### The live-session table

`close_tracked` emits `session_close` from the stored row, so the principal must survive there. The
live table is keyed by the public `ActiveSession`, which this change deliberately **does not**
widen: the issue asks for the event stream, and `status`'s live-session view is a separate surface
with its own (real, but unfiled) version of this problem. The principal rides alongside the row
internally instead.

## Surface + versioning

- `AuditRecord.principal: Option<String>`, `#[serde(skip_serializing_if = "Option::is_none")]` —
  additive, absent on records with no resolved peer, so existing consumers are unaffected.
- `API_MINOR` 11 → 12, `API_VERSION` "1.11" → "1.12".
- `docs/local-protocol.md`: the `AuditRecord` field table and the versioning list.
- Workspace version → **0.12.1** (additive → PATCH per the pre-1.0 policy).

## Testing (TDD, RED first)

1. **Unit (serde)** — `principal` round-trips when `Some` and is OMITTED from the JSON when `None`,
   alongside the existing additive-serde tests.
2. **Integration** — a real gated session over the mesh emits `session_open` whose `principal` is
   the caller's `eid:` device principal, and equals the `principal` on that peer's `status` row
   (the join the issue says is currently impossible). Fails today: the field does not exist.
3. **Regression** — a record with no resolved peer (a manual roster install trust event) still
   serializes with neither `peer` nor `principal`, and the existing audit-log/rotation tests are
   unaffected.

## Out of scope

`ActiveSession.principal` (the `status` live-session view) — the same argument applies and it is
worth its own issue, but it is not what #57 asks for and widening two surfaces at once makes the
additive claim harder to verify.
