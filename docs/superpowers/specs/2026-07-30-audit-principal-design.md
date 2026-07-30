# AuditRecord.principal — stable identity on the event stream (#57, Option A)

Date: 2026-07-30. Supersedes PR #72 (drafted at 0.12.0, now 72 commits and 23 conflict regions
behind a since-rewritten audit module; its design decisions are adopted, its code is not).

## The maintainer decision this issue was parked on

#72 was held because `docs/local-protocol.md` states the audit record carries "never … endpoint-
ids", and `principal` is one, in a file that persists for months. **Decision: adopt (Option A),
and update the sentence.** Rationale:

- The rule predates #41/#42/#73, which put `eid:` principals on `status`, reachability rows, and
  the live-session view across the SAME trust boundary (same-uid, `0600` socket). The sentence
  was never re-affirmed against that work; every argument those issues made about collidable
  display names applies verbatim to the record of who-did-what.
- A stable principal is a public *identifier*, not a secret: it is literally how peers dial you,
  and the same values already sit in every `allow` list on the same disk. What the ban actually
  protects — raw arguments, response content, keys — is untouched.
- The counter-case (audit files get pasted into support channels; a months-long file is a
  different exposure than a live response) was weighed: #88's `audit_list` already makes the log
  a machine-readable API surface that will be pasted just as readily, and the primary embedder
  explicitly wants the join ("an audit log keyed on a display string is the one remaining place
  where our own records cannot be joined to our own policy").

## Changes (`API_MINOR 28 → 29`; MINOR `0.23.6 → 0.24.0` — pub constructor arity changed in published crates)

1. `AuditRecord.principal: Option<String>` — serde default + skip-if-none (the record is
   published wire vocabulary riding `StreamFrame::Event` AND the on-disk JSONL).
2. **Explicit constructor parameter** on all six record constructors — #72's shape, kept: a
   builder would let a call site silently omit it and reintroduce this bug per event class.
3. Producers:
   - session open/close: the #73 principal already threaded into `open_tracked` for
     `ActiveSession`; the close record reads the stored row's principal, so open and close
     always agree.
   - proxied request/notification: `RequestAuditor` gains the principal (from the same
     `session_principal` the guard uses).
   - blob fetch (the second surface from the issue thread): from `conn_eid`, already in scope —
     the record of who fetched which bytes is the one where two-devices-one-nickname is most
     likely the actual question.
   - trust `pair`: the redeemer's `eid:`. Deliberate `None`s, kept from #72: `unpair` (may tear
     down several devices — no single subject), `roster_install` (purely local), the
     failed-outbound-dial session record (our dial, not a gate-resolved caller).
4. Docs: the surface sentence now bans raw arguments, response content, keys, and RAW hex
   endpoint ids — the `eid:`/`b64u:` principal rendering is the one sanctioned identity form,
   consistent with the rest of the API since #41.
5. The old rule's test (asserting no principal in trust records) updates to the new rule: `pair`
   records CARRY the principal; raw un-prefixed hex still never appears anywhere.

## Tests (mutation-verified)

- `audit_e2e`: the real-session flow asserts `principal` on session_open / request /
  session_close lines (same `eid:` as the caller endpoint), and that open/close agree.
- Blob-fetch: the served-GET audit test asserts the fetcher's principal.
- Trust: a real pairing's `pair` record carries the allow-list principal (`b64u:` when bound,
  else `eid:`); unpair stays `None`.
- Mutations: drop the principal from any single producer → its named assertion fails (the
  explicit-parameter shape makes each producer independently breakable).

## Non-goals

Backfilling principal into existing on-disk records (they predate the field; `audit_list`
consumers must treat absent principal as "recorded before 0.24.0"), and any change to what is
hashed or counted.
