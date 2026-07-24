# Stable-principal authorization (issue #38) — design

**Date:** 2026-07-24 · **Status:** Approved · **Ships in:** 0.8.0 (breaking, pre-1.0 rule)

## Problem

`[services.*].allow` entries store self-asserted display nicknames, and admission
(`caller_admits`) compares the gate-resolved stored nickname against them. Nicknames are
rewritten by design (redeemer-side rename-by-fresh-invite; the 0.7.1 `set_nickname` verb
makes self-rename first-class), so grants silently desync: a rename + re-pair severs every
dial with a generic `-32054` and no diagnostic (#38, observed live on a bolo fleet).

## Design: nicknames become display-only EVERYWHERE

Pre-1.0: no compatibility layer, no dual namespace, no rename-walk. The bug class becomes
unrepresentable.

1. **Principal vocabulary for `allow` (and every authz surface):**
   - `b64u:<user_pk>` — person-level, the existing user-id principal (verified binding).
   - `eid:<endpoint-id>` — NEW device-level principal: the base32 endpoint id, i.e. the
     identity TLS actually authenticated. Always available (unlike `user_id`).
   - bare strings — roster GROUP names only.
   - Nicknames: **never matched**. The nickname arm is REMOVED from `principal_set`
     (signature drops the name param, gains the endpoint id).
2. **Grant paths write stable principals.** The inviter-side pairing grant writes
   `b64u:<user_pk>` when the redeemer presented a binding, else `eid:<endpoint-id>`.
   Operator-typed `allow` inputs (`serve --allow`, `register_service`) accept
   `b64u:`/`eid:` verbatim; a bare name is resolved through the PeerStore to that peer's
   stable principal at write time; an unresolvable bare name is kept verbatim (assumed
   roster group).
3. **Admission diagnostics:** `caller_admits` logs at debug the caller's principal set and
   the allow list compared, so a refusal is diagnosable without source-diving.
4. **Downstream reconciliation (the sweep decides the full list; known already):**
   - The rendezvous nickname-squat/collision guards that key on allow-membership lose
     their meaning (allow no longer holds nicknames) — rework to the PeerStore-only checks
     that still make sense, delete what doesn't.
   - Porcelain that renders `allow` (status/render/json) annotates principals with the
     store-resolved display name where known; raw principal remains the machine truth.
   - `doctor`: new lint flagging `allow` entries that are neither `b64u:`/`eid:` nor a
     plausible group — "nickname-keyed grants no longer admit (0.8.0); re-pair or replace".
   - Docs/examples using `allow = ["bob"]` (config.md, local-protocol.md, embedding.md,
     README, AGENTS.md) update to the principal story; `api_minor` → 3 (semantic change to
     the `allow` strings crossing the control API).
5. **Unchanged:** outbound naming (`open_session` by nickname / `<peer>/<service>`
   mounts), the identity env injection (`MCPMESH_PEER_NAME` stays display), PeerStore
   schema (nickname remains the display handle), roster-mode group semantics.

## Migration

None (pre-1.0). Release notes: nickname-keyed `allow` entries stop admitting — re-pair
(grants now written stably) or hand-edit config to `eid:`/`b64u:` principals; `doctor`
flags stragglers.

## Testing

Regression test reproducing #38 (rename + re-pair no longer severs); grant-path tests
(binding → `b64u:`, no binding → `eid:`; operator input resolution rules); admission-log
test; doctor lint test; the full existing suite reworked where it asserts nicknames in
`allow`. Release gate: this touches `mcpmesh-net`'s admission path — the two-machine
smoke (RELEASING.md) is genuinely indicated for this one.
