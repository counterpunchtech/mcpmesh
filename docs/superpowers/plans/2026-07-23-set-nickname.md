# `set_nickname` Implementation Plan (issue #37)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Live self-rename via a `set_nickname` control verb + effective name in `status` (spec: `docs/superpowers/specs/2026-07-23-set-nickname-design.md`), shipped as 0.7.1.

**Architecture:** Additive mcpmesh-local/1 change (API_MINOR 2) in `local-api`; handler + live `RwLock<String>` nickname in `mcpmesh-node`; both sidecar and embedded consumers get it for free.

**Tech Stack:** Existing patterns only — `upsert_config_strings`, `with_params` dispatch, protocol serde-test conventions.

### Task 1: Protocol vocabulary (local-api)

**Files:** Modify `local-api/src/protocol.rs`, `local-api/src/client.rs`, `local-api/src/lib.rs`

- [ ] TDD: serde tests first (`set_nickname` frame shape via `method_of`; `SetNicknameParams` rejects unknown fields; `StatusResult` without `self_nickname` still deserializes) → FAIL → implement `SetNicknameParams`/`Request::SetNickname`/`StatusResult.self_nickname` (default + skip-if-empty) → bump `API_VERSION` to "1.2", `API_MINOR` to 2 with a doc line → `ControlClient::set_nickname` ack helper → tests PASS. Fix `StatusResult` literal constructions the compiler flags (client tests, cli stubs).
- [ ] `cargo test --workspace` green; commit.

### Task 2: Live nickname + handler (node)

**Files:** Modify `node/src/daemon.rs`, `node/src/daemon/handlers.rs`, `node/src/daemon/config_write.rs`, `node/src/daemon/status.rs`, `node/src/control.rs`

- [ ] `MeshState.self_nickname: std::sync::RwLock<String>` + `self_nickname() -> String` accessor (constructor still takes `String`); update the two readers (`mint_invite`, `redeem`) and status assembly.
- [ ] `write_identity_nickname(path, nickname)` = `upsert_config_strings(path, "identity", &[("nickname", nickname)])`.
- [ ] `pub(crate) async fn set_nickname(state, params)`: `mesh_required` → validate (trim non-empty, no `/`) → `reload_lock` → `blocking` config write → update RwLock. Dispatch arm `"set_nickname"` via `with_params` next to `set_roster_url`. `status_result` fills `self_nickname` (empty when mesh-less).
- [ ] `cargo test --workspace` green; commit.

### Task 3: Integration test + docs

**Files:** Modify `cli/tests/daemon_dispatch.rs`, `docs/local-protocol.md`

- [ ] Hermetic-mesh test: `set_nickname` → `status.self_nickname` updated → `config.toml` contains `nickname = "…"` → freshly minted invite's nickname is the new name → empty/`/` names answer JSON-RPC errors and change nothing.
- [ ] `docs/local-protocol.md`: method section + minor-history note. Full gates (test/clippy/fmt/doc); commit.

### Task 4: Release 0.7.1

- [ ] Merge to main, CI green. Bump workspace + five pins to 0.7.1, `cargo update -w`, locked tests, `release: 0.7.1` commit, push, CI green, tag `v0.7.1`, `cargo xtask publish` (index-verify), GitHub release, formula bump. Close #37 with a comment linking the release.
