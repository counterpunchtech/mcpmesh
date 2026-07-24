# Stable-Principal Authorization Implementation Plan (#38)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Nicknames become display-only everywhere; `allow` and every authz surface speak stable principals (`eid:`/`b64u:`/roster bare names). Ships as 0.8.0. Spec: `docs/superpowers/specs/2026-07-24-stable-principal-authz-design.md`. The exhaustive file:line touchpoint map is the ultracode sweep result (workflow `wf_e3460d2c-966` journal); this plan sequences it.

**Architecture:** One renderer (`EndpointId::principal()` in net), one expansion (`principal_set`, name arm removed), three admission sites updated together; grant/revoke/rename paths rekeyed; porcelain annotates; doctor lints; the full test suite reworked per the map. TDD where a behavior changes; mechanical rewrites verified by the suite.

### Task 1: Admission speaks stable principals (net + local-api + the three enforcement sites)
- [ ] `net/src/identity.rs`: `EndpointId::principal() -> String` (`"eid:" + iroh base32`), doc'd as THE sanctioned rendering (not Display); zeroed-endpoint caveat noted.
- [ ] `local-api/src/principals.rs`: signature → `(eid: Option<&str>, user_id: Option<&str>, groups: &[String])`; module doc + tests inverted (nickname test becomes eid-only test).
- [ ] `net/src/endpoint.rs:255` `caller_admits`: render eid from `identity.endpoint`, drop name arm, add the refusal debug log (principal set vs allow); comments at 287-290; test at 522 reworked.
- [ ] `node/src/blobs/provider.rs:263`: same swap; superseded-comment rewrite.
- [ ] `node/src/backends/socket.rs:107`: inject `"eid"` into `_meta["mcpmesh/peer"]`; `local-api/src/service.rs:87` `peer_audiences` reads it, drops name; test at 265.
- [ ] Gate: workspace green except the mapped test fallout (tracked to Task 6). Commit.

### Task 2: Grant paths write stable principals
- [ ] `rendezvous.rs:125` `GrantFn` + `daemon.rs:447` closure widen to (principal, display_nickname, services); `handle_inviter_side:362` computes principal = entry user_id (already `b64u:`-prefixed) else `eid:` from `tls_id` — captured BEFORE the entry moves into the store (:350).
- [ ] `handlers.rs:657` `grant_service_access` takes the principal (nickname kept for audit/log only); `config_write.rs:197` param rename.
- [ ] Shared write-time resolver (one fn in handlers.rs): `b64u:`/`eid:` verbatim; bare name → PeerStore lookup (user_id else eid); unresolvable bare → verbatim (roster vocabulary). Used by `register_service:174` (both persistent + ephemeral branches) and `blob_grant:67`.
- [ ] TDD: grant-rule unit tests (binding→b64u, none→eid); resolution-rule tests. Commit.

### Task 3: Revoke / remove / rename rekeyed
- [ ] `handlers.rs:707` `revoke_service_access` + `:317` `remove_peer`: resolve entries FIRST; strip `eid:` per device always, `b64u:` iff last device of that user_id; `config_write.rs:256` takes a slice (one atomic RMW).
- [ ] `handlers.rs:463` rename allow-rewrite loop + reload DELETED; `config_write.rs:290` `rename_allow_in_config` DELETED; `rename_plan:399` guard (b) deleted, guard (a) re-rationalized (outbound-dial ambiguity).
- [ ] `rendezvous.rs` collision guards: orphan-allow arms (643/681) + `nickname_in_any_service_allow:695` DELETED; impersonation arms become store-only display checks with honest new message text.
- [ ] TDD: revoke-strips-principals test; last-device b64u rule test; rename-leaves-allow-untouched test. Commit.

### Task 4: Porcelain + protocol + doctor
- [ ] `status.rs`/`protocol.rs` docs: allow = principals; `API_MINOR` → 3, `API_VERSION` → "1.3"; verb docs (PeerRemove/PeerRename/BlobGrant/RegisterService) rewritten.
- [ ] `render.rs:234`: human status renders store-resolved display names for `eid:`/`b64u:` principals (never raw ids — the `status_output_leaks_no_transport_vocabulary` test is the constraint); unresolvable → `unpaired-device`. JSON stays raw.
- [ ] `main.rs` help/next-step text (:64/:546, blob grant :304).
- [ ] `doctor.rs`: `check_allow_principals` pure check + gather reads allow; pure-pairing bare entry → warn "nickname-keyed grants no longer admit (0.8.0); re-pair or replace". Tests. Commit.

### Task 5: The #38 regression test
- [ ] Model: `cli/tests/pairing_rendezvous.rs:842`. New test: pair (grant lands as principal) → self-rename + re-pair via fresh invite with a NEW suggested nickname (mechanics of :687) → dial again → session STILL admitted. Pre-fix this refused `-32054`. Commit.

### Task 6: Test sweep (the 58-item map)
- [ ] Rewrite every mapped fixture/assertion: `allow=["<name>"]` → `eid:`/`b64u:`/group per the map (session.rs, hero flows, daemon_serve/dispatch, proxy/subscribe/audit/presence/staleness/sever/three-node, pairing_porcelain, blob tests…); deletions per Task 3. Bare roster user_ids/groups KEEP. `MCPMESH_PEER_NAME` display assertions KEEP everywhere. `hot_reload...` test extends to cover the resolver rules. Full workspace gates green. Commit.

### Task 7: Docs sweep
- [ ] `docs/local-protocol.md` (allow vocabulary, api_minor 3 note, register_service row), `docs/config.md`, `docs/embedding.md` quickstart, `README.md`, `AGENTS.md`, `SECURITY.md` (principal-rendering carve-out), rendezvous/module docs already in code tasks. Commit.

### Task 8: Adversarial review + ship 0.8.0
- [ ] Ultracode review workflow over the full diff (security/correctness/completeness lenses, adversarial verify); fix confirmed findings.
- [ ] Merge to main, CI green. Bump 0.8.0 (workspace + five pins), locked tests, release commit, CI, tag, `cargo xtask publish` + index verify, GitHub release (with migration notes), formula, close #38, re-create the issue-check cron.
- [ ] Flag at tag time: this touches `mcpmesh-net` admission — the RELEASING.md two-machine smoke is genuinely indicated (user call, per standing precedent).
