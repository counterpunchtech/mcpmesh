# Agent-Friendly CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every porcelain verb an opt-in `--json` machine face (mirroring the mcpmesh-local/1 result types), JSON error output carrying the control-API error code, shell completions + man-page generation, an `AGENTS.md` automation contract, and an automated SAS assertion in the loopback harness — then release 0.6.1.

**Architecture:** A new pure module `cli/src/json.rs` owns every machine-face value (the JSON mirror of `render.rs`, which owns every human string). A global `--json` clap flag threads a `bool` into each verb; verbs print either the render lines or one `serde_json` line. Errors flow through `json::error_json` (stderr, single line, carries the JSON-RPC `code` when the failure came from the control API). No wire/daemon changes at all — this is purely the CLI output layer, hence a PATCH release per RELEASING.md's pre-1.0 rule (breaking → minor; everything else → patch).

**Tech Stack:** Rust (edition 2024, workspace v0.6.0 → 0.6.1), clap 4 derive, `clap_complete` + `clap_mangen` (new deps), serde_json, existing `mcpmesh-local-api` serde types.

**Output-shape principle:** `--json` output serializes the *existing* `mcpmesh-local-api` result structs wherever one exists (`StatusResult`, `InviteResult`, `PairResult`, `RosterInstallResult`, `BlobListResult`, `StreamFrame`, audit records), plus small hand-built objects for verbs with no API result (serve, up, use, enroll verbs). Fields with `skip_serializing_if` stay omitted-when-empty — same additive discipline as the wire protocol; AGENTS.md documents "absent = empty/none". Never invent parallel field names.

**Not in scope (deliberate):** `invite --quiet` (mooted by `--json`); per-class process exit codes (the JSON error `code` field solves machine branching without inventing an exit-code taxonomy); `--json` on `connect` / `internal daemon` (byte pump / daemon — the flag is accepted globally but has no output to shape; document as no-op).

---

### Task 1: Global `--json` flag, `json.rs` module, JSON error path

**Files:**
- Create: `cli/src/json.rs`
- Modify: `cli/src/lib.rs` (add `pub mod json;` next to `pub mod render;`)
- Modify: `cli/src/main.rs:21-32` (flag), `cli/src/main.rs:357-381` (error path), `run(cli)` signature threading

- [ ] **Step 1: Write failing unit tests in `cli/src/json.rs`** (module skeleton + tests only):

```rust
//! Every value the porcelain prints under `--json` — the machine face, as pure
//! unit-tested builders. `render.rs` owns the human strings; this module owns the
//! JSON mirror. Shapes serialize the mcpmesh-local/1 result types verbatim wherever
//! one exists (additive discipline: absent field = empty/none), plus small objects
//! for verbs with no API result. One JSON value per invocation, printed as a single
//! line; errors go to stderr as `{"error":{"code":…,"message":…}}`.

use crate::{client, render};

/// The `--json` error object: the SAME human message `render::error_lines` produces
/// (joined, without the leading "Error: "), plus the control-API JSON-RPC `code`
/// when the failure came from the daemon — the machine-branchable field the human
/// path deliberately hides.
pub fn error_json(err: &anyhow::Error) -> serde_json::Value {
    let code = err.chain().find_map(|cause| {
        match cause.downcast_ref::<client::ClientError>() {
            Some(client::ClientError::Api(v)) => v.get("code").and_then(|c| c.as_i64()),
            _ => None,
        }
    });
    let joined = render::error_lines(err).join("\n");
    let message = joined.strip_prefix("Error: ").unwrap_or(&joined).to_string();
    serde_json::json!({"error": {"code": code, "message": message}})
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn api_error(value: serde_json::Value) -> anyhow::Error {
        anyhow::Error::from(client::ClientError::Api(value))
    }

    #[test]
    fn error_json_carries_the_control_api_code_and_clean_message() {
        let err = api_error(json!({"code": -32055, "message": "invite failed: invite expired"}));
        let v = error_json(&err);
        assert_eq!(v["error"]["code"], json!(-32055));
        // The wire's "{method} failed: " framing is stripped, same as the human path.
        assert_eq!(v["error"]["message"], json!("invite expired"));
    }

    #[test]
    fn error_json_on_a_plain_error_has_null_code_and_the_chain() {
        let err = anyhow::Error::from(std::io::Error::other("disk full")).context("write roster");
        let v = error_json(&err);
        assert_eq!(v["error"]["code"], serde_json::Value::Null);
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(msg.contains("write roster") && msg.contains("disk full"), "{msg}");
    }
}
```

- [ ] **Step 2:** `cargo test -p mcpmesh --lib json::` — expect FAIL (module not registered). Add `pub mod json;` to `cli/src/lib.rs`; re-run — expect PASS (the impl above ships with the tests; this module is small enough that test+impl land together, TDD applies per-function from Task 2 on).

- [ ] **Step 3: Thread the flag.** In `cli/src/main.rs` `struct Cli` add after `profile`:

```rust
    /// Print machine-readable JSON instead of prose (one JSON value on stdout;
    /// errors become a single {"error":{code,message}} line on stderr). Shapes
    /// mirror the mcpmesh-local/1 result types — see AGENTS.md.
    #[arg(long, global = true)]
    json: bool,
```

In `main()`, capture `let json = cli.json;` before `run(cli)`, and change the error arm:

```rust
        Err(err) => {
            if json {
                eprintln!("{}", mcpmesh::json::error_json(&err));
            } else {
                for line in render::error_lines(&err) {
                    eprintln!("{line}");
                }
            }
            std::process::ExitCode::FAILURE
        }
```

`run(cli)` destructures `cli.json` and passes it to the run_* fns changed in Tasks 2-5 (leave untouched verbs as-is until their task).

- [ ] **Step 4:** `cargo build -p mcpmesh && cargo test -p mcpmesh --lib` — PASS.
- [ ] **Step 5:** Commit: `git commit -m "cli: global --json flag + json.rs machine face; JSON error path with control-API code"`

### Task 2: `--json` for status, up, serve, invite, pair, use

**Files:**
- Modify: `cli/src/json.rs` (builders + tests), `cli/src/main.rs` (`run_status`, `run_up`, `run_serve`, `run_invite`, `run_pair`, `run_use` take `json: bool`)

- [ ] **Step 1: Failing tests + builders in `json.rs`:**

```rust
use mcpmesh_local_api::{Hello, InviteResult, PairResult, StatusResult};

/// `status --json`: the StatusResult verbatim, plus the Hello fields and the device
/// fingerprint the human header carries (api, api_version, api_minor, stack_version
/// from Hello win over StatusResult's copy).
pub fn status_json(fingerprint: &str, hello: &Hello, status: &StatusResult) -> serde_json::Value {
    let mut v = serde_json::to_value(status).expect("StatusResult serializes");
    let o = v.as_object_mut().expect("StatusResult is an object");
    o.insert("api".into(), hello.api.clone().into());
    o.insert("api_version".into(), hello.api_version.clone().into());
    o.insert("api_minor".into(), hello.api_minor.into());
    o.insert("stack_version".into(), hello.stack_version.clone().into());
    o.insert("device_fingerprint".into(), fingerprint.into());
    v
}

/// `invite --json`: the InviteResult verbatim plus the requested services (what the
/// operator asked to grant — same provenance as the human line).
pub fn invite_json(invite: &InviteResult, services: &[String]) -> serde_json::Value {
    let mut v = serde_json::to_value(invite).expect("InviteResult serializes");
    v.as_object_mut()
        .expect("InviteResult is an object")
        .insert("services".into(), serde_json::json!(services));
    v
}

/// `pair --json`: the PairResult verbatim plus the ready-to-use `<peer>/<service>`
/// mount targets (the machine mirror of "You can now use: …").
pub fn pair_json(result: &PairResult) -> serde_json::Value {
    let mounts: Vec<String> = result
        .services
        .iter()
        .map(|s| format!("{}/{s}", result.peer_nickname))
        .collect();
    let mut v = serde_json::to_value(result).expect("PairResult serializes");
    v.as_object_mut()
        .expect("PairResult is an object")
        .insert("mounts".into(), serde_json::json!(mounts));
    v
}

/// `pair --remove --json`.
pub fn unpair_json(nickname: &str) -> serde_json::Value {
    serde_json::json!({"removed": nickname})
}

/// `serve --json`.
pub fn serve_json(name: &str) -> serde_json::Value {
    serde_json::json!({"service": name, "serving": true})
}

/// `up --json`.
pub fn up_json(socket: &std::path::Path) -> serde_json::Value {
    serde_json::json!({"socket": socket.display().to_string()})
}

/// `use --json`: per service, the mount target, the exact Claude Code command, and
/// the generic MCP stdio server entry (name/command/args) any client can consume.
pub fn use_json(peer: &str, services: &[String]) -> serde_json::Value {
    let mounts: Vec<serde_json::Value> = services
        .iter()
        .map(|s| {
            serde_json::json!({
                "target": format!("{peer}/{s}"),
                "claude_code_command": format!("claude mcp add {peer}-{s} -- mcpmesh connect {peer}/{s}"),
                "mcp_server": {
                    "name": format!("{peer}-{s}"),
                    "command": "mcpmesh",
                    "args": ["connect", format!("{peer}/{s}")],
                },
            })
        })
        .collect();
    serde_json::json!({"peer": peer, "mounts": mounts})
}
```

Tests (same `mod tests`): build the same fixtures `render.rs` tests use and assert e.g.

```rust
    #[test]
    fn pair_json_serializes_the_result_and_mount_targets() {
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into(), "kb".into()],
            app_label: None,
            peer_user_id: None,
        };
        let v = pair_json(&result);
        assert_eq!(v["peer_nickname"], "alice");
        assert_eq!(v["sas_code"], "tango-fig-42");
        assert_eq!(v["mounts"], serde_json::json!(["alice/notes", "alice/kb"]));
    }

    #[test]
    fn status_json_merges_hello_and_fingerprint_over_the_status_result() {
        let hello = Hello {
            api: "mcpmesh-local/1".into(),
            api_version: "1.1".into(),
            api_minor: 1,
            stack_version: "0.6.1".into(),
        };
        let status = StatusResult {
            stack_version: "0.6.1".into(),
            services: vec![],
            peers: vec![],
            roster: None,
            presence: vec![],
            self_user_id: None,
            recent_pairings: vec![],
            reachability: vec![],
        };
        let v = status_json("fp-words", &hello, &status);
        assert_eq!(v["api_minor"], 1);
        assert_eq!(v["device_fingerprint"], "fp-words");
        // Empty vecs with skip_serializing_if stay ABSENT (additive discipline).
        assert!(v.get("recent_pairings").is_none());
    }
```

Plus one test each for `invite_json` (invite_line + expires_at_epoch + services present), `use_json` (mcp_server args exactly `["connect","alice/notes"]`), `up_json`, `serve_json`, `unpair_json`.

- [ ] **Step 2:** `cargo test -p mcpmesh --lib json::` — PASS after implementation.
- [ ] **Step 3: Wire into main.rs.** Each verb takes `json: bool`; pattern (invite shown, others identical in shape):

```rust
        let invite = client.invite_with(services.clone(), label).await?;
        if json {
            println!("{}", crate::… ) // binary crate: use mcpmesh::json
            // println!("{}", mcpmesh::json::invite_json(&invite, &services));
        } else {
            for line in render::invite_lines(&invite, &services, util::epoch_now_u64()) {
                println!("{line}");
            }
        }
```

`run_up`: replace the bare `println!("{}", socket.display())` with the branch (`up_json` when json). `run_status`: `if json { println!("{}", mcpmesh::json::status_json(&fingerprint, &hello, &status)); } else { render::render_status(...) }`. `run_use`: validation unchanged; success branch prints `use_json(&peer, &[service])`. `run_pair`: redeem branch → `pair_json`; remove branch → `unpair_json`.

- [ ] **Step 4:** `cargo test -p mcpmesh` (lib + bins compile, existing integration suite untouched) — PASS.
- [ ] **Step 5:** Commit: `git commit -m "cli: --json for status/up/serve/invite/pair/use"`

### Task 3: `--json` for doctor

**Files:**
- Modify: `cli/src/doctor.rs` (`Level::as_str`, `run_doctor(json: bool)`), `cli/src/json.rs` (`doctor_json`), `cli/src/main.rs` dispatch

- [ ] **Step 1:** Add to `doctor.rs` `impl Level`:

```rust
    /// The machine word for this level (`doctor --json`).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
```

`json.rs`:

```rust
use crate::doctor::{Level, Verdict};

/// `doctor --json`: every finding, plus the warn/error tallies the human summary
/// line carries and an overall `ok` (false iff any ERROR — mirrors the exit code).
pub fn doctor_json(findings: &[(&str, Verdict)]) -> serde_json::Value {
    let list: Vec<serde_json::Value> = findings
        .iter()
        .map(|(check, v)| {
            serde_json::json!({"check": check, "level": v.level.as_str(), "message": v.message})
        })
        .collect();
    let count = |l: Level| findings.iter().filter(|(_, v)| v.level == l).count();
    serde_json::json!({
        "findings": list,
        "warnings": count(Level::Warn),
        "errors": count(Level::Error),
        "ok": count(Level::Error) == 0,
    })
}
```

Test: two findings (one ok, one error) → `errors == 1`, `ok == false`, `findings[1]["level"] == "error"`.

- [ ] **Step 2:** `run_doctor(json: bool)`: same gather/findings; `if json { println!("{}", crate::json::doctor_json(&findings)); } else { for line in render_report(...) … }`; the `worst_level == Error → exit(1)` stays for both. Update `main.rs`: `Some(Cmd::Doctor) => doctor::run_doctor(cli_json)`.
- [ ] **Step 3:** `cargo test -p mcpmesh` (unit + `cli/tests/doctor.rs`) — PASS; fix any test calling `run_doctor()` directly.
- [ ] **Step 4:** Commit: `git commit -m "cli: doctor --json (findings + tallies + ok flag, same exit contract)"`

### Task 4: `--json` for the enrollment verbs (join, org create/approve/revoke, devices code/add)

**Files:**
- Modify: `cli/src/enrollcmd.rs` (six fn signatures + output branches), `cli/src/main.rs` (dispatch), existing tests `enrollcmd.rs:502,513` (add `false` arg)

- [ ] **Step 1:** Each fn takes a trailing `json: bool`. JSON shapes (built inline with `serde_json::json!`, printed as one line; ALL prose printlns skipped when json):
  - `run_join` → `{"org_id", "user_id", "join_code", "join_code_fingerprint", "org_root_fingerprint"}` (values: `invite.org_id`, `requested_user_id`, `join`, `code_fp`, `fingerprint`)
  - `run_org_create` → `{"org_id": result.org_id, "serial": result.serial, "org_invite": invite, "org_root_fingerprint": fingerprint}`
  - `run_org_approve` → `{"user_id": uid, "groups": groups, "org_id": result.org_id, "serial": result.serial, "join_code_fingerprint": code_fp}` (the pre-install ceremony println pair is prose-only; in json mode the fingerprint rides in the result object — emit AFTER install like the human summary)
  - `run_org_revoke` → `{"target", "mode": "user-key-rotation"|"device"|"person", "org_id", "serial", "severed"}` (derive `mode` where `action` is derived today)
  - `run_devices_code` → `{"device_code": code}`
  - `run_devices_add` → `{"join_code": join, "join_code_fingerprint": code_fp}`
- [ ] **Step 2:** Update the two existing tests (`run_org_approve(code, "team-eng".into(), None, false)`, `run_devices_add("garbage".into(), false)`) and the six `main.rs` dispatch arms to pass `cli.json`.
- [ ] **Step 3:** `cargo test -p mcpmesh` — PASS (including `cli/tests/enroll_e2e.rs` / `org_enroll.rs`, which drive the binary; they use prose mode and must be untouched).
- [ ] **Step 4:** Commit: `git commit -m "cli: --json for join/org/devices enrollment verbs"`

### Task 5: `--json` for the internal verbs (peer add, roster install, blob, audit list/prune, watch)

**Files:**
- Modify: `cli/src/main.rs` (`run_peer_add`, `run_roster_install`, `run_internal_blob`, `run_internal_audit`, `run_watch` take `json: bool`)

- [ ] **Step 1:** Shapes (inline `serde_json::json!` in main.rs is fine here — these have no render.rs twin; keep `json.rs` for shapes with logic):
  - `peer add` → `{"peer": nickname, "added": true}`
  - `roster install` → `serde_json::to_value(&installed)?` (RosterInstallResult: org_id/serial/severed)
  - `blob publish` → `{"hash": r.hash, "ticket": r.ticket}`; `grant` → `{"scope", "principal", "granted": true}`; `list` → `serde_json::to_value(&r)?`; `fetch` → `{"bytes_len", "hash", "dest"}`
  - `audit tail` → unchanged (already JSONL, both modes); `list` → `[{"month", "bytes"}]`; `prune` → `{"pruned": [months]}`
  - `watch` → when json, print `serde_json::to_string(&frame)?` per frame (JSONL of the typed StreamFrame wire shape) and SKIP the "watching the mesh" banner (stdout stays pure JSONL)
- [ ] **Step 2:** `cargo test -p mcpmesh` — PASS (`cli/tests/watch_cli.rs` drives prose mode; untouched).
- [ ] **Step 3:** Commit: `git commit -m "cli: --json for internal peer/roster/blob/audit/watch"`

### Task 6: Shell completions + man pages

**Files:**
- Modify: `Cargo.toml` (workspace deps: `clap_complete = "4"`, `clap_mangen = "0.2"`), `cli/Cargo.toml` (both `.workspace = true`), `cli/src/main.rs` (new `Completions` top-level command, `Internal::Man`)

- [ ] **Step 1:** New top-level command (porcelain, visible — humans use it too):

```rust
    /// Print a shell completion script (bash, zsh, fish, elvish, powershell) to stdout.
    ///
    /// Install e.g. `mcpmesh completions zsh > "${fpath[1]}/_mcpmesh"` or
    /// `mcpmesh completions bash > /etc/bash_completion.d/mcpmesh`.
    Completions {
        /// The shell to emit a script for.
        shell: clap_complete::Shell,
    },
```

Dispatch (needs `use clap::CommandFactory;`):

```rust
        Some(Cmd::Completions { shell }) => {
            clap_complete::generate(shell, &mut Cli::command(), "mcpmesh", &mut std::io::stdout());
            Ok(())
        }
```

- [ ] **Step 2:** `Internal::Man { dir: PathBuf }` ("Generate roff man pages for every command into DIR."):

```rust
fn run_internal_man(dir: PathBuf) -> anyhow::Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(&dir)?;
    let mut count = 0usize;
    write_man_tree(&dir, &Cli::command(), "mcpmesh", &mut count)?;
    println!("wrote {count} man pages to {}", dir.display());
    Ok(())
}

fn write_man_tree(
    dir: &std::path::Path,
    cmd: &clap::Command,
    stem: &str,
    count: &mut usize,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone().name(stem.to_string())).render(&mut buf)?;
    std::fs::write(dir.join(format!("{stem}.1")), buf)?;
    *count += 1;
    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set() && s.get_name() != "help") {
        write_man_tree(dir, sub, &format!("{stem}-{}", sub.get_name()), count)?;
    }
    Ok(())
}
```

- [ ] **Step 3: Integration test** `cli/tests/completions.rs` (assert_cmd, no daemon):

```rust
use assert_cmd::Command;

#[test]
fn completions_emit_a_script_naming_the_binary() {
    let out = Command::cargo_bin("mcpmesh").unwrap().args(["completions", "bash"]).output().unwrap();
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(script.contains("mcpmesh"), "bash completions name the binary");
}

#[test]
fn man_pages_generate_for_the_command_tree() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("mcpmesh").unwrap()
        .args(["internal", "man"]).arg(dir.path()).output().unwrap();
    assert!(out.status.success());
    assert!(dir.path().join("mcpmesh.1").exists());
    assert!(dir.path().join("mcpmesh-pair.1").exists());
}
```

- [ ] **Step 4:** `cargo test -p mcpmesh --test completions` — PASS. Run `cargo deny check` if configured (new deps: clap_complete/clap_mangen are MIT/Apache, should pass `deny.toml`).
- [ ] **Step 5:** Commit: `git commit -m "cli: shell completions + internal man page generation"`

### Task 7: AGENTS.md + README link

**Files:**
- Create: `AGENTS.md`
- Modify: `README.md` (one pointer line in an appropriate section)

- [ ] **Step 1:** Write `AGENTS.md` covering, with exact commands (final wording at execution time, structure fixed here):
  1. **TL;DR recipe** — readiness (`SOCK=$(mcpmesh up --timeout 15)`), isolated identities (`--profile <dir>` / `MCPMESH_HOME`), `--json` on every verb, artifacts' grep-stable prefixes (`mcpmesh-invite:` / `mcpmesh-join:` / `mcpmesh-org:` / `mcpmesh-device:`).
  2. **No prompts, ever** — no TTY interaction anywhere; destructive verbs (`pair --remove`, `org revoke`, `roster install`) act immediately; no `--yes` exists because nothing asks.
  3. **`--json` contract** — one JSON value per invocation on stdout; shapes mirror mcpmesh-local/1 result types (link `docs/local-protocol.md`); additive-only evolution, absent field = empty/none; errors under `--json` are one `{"error":{"code","message"}}` line on stderr; exit codes stay 0/1 — branch on `error.code`.
  4. **Blocking commands** — `connect` (stdio MCP bridge — point your MCP client at it, don't run it in a script and wait), `internal daemon`, `internal watch` (JSONL stream under `--json`).
  5. **Pairing end-to-end, scripted** — invite → pair via `--json`, and the SAS: redeemer reads `sas_code` from `pair --json`, inviter from `status --json` `.recent_pairings[0].sas_code`; a harness string-compares them (automated MITM assertion). Humans compare aloud; automation compares strings.
  6. **The local API** — for long-lived embedders prefer the `mcpmesh-local/1` socket (`local-api` crate) over shelling out; `mcpmesh up` prints the socket path.
  7. **Testing sandbox** — the scratch-HOME/`--profile` loopback pattern, pointing at `docs/loopback.sh`.
- [ ] **Step 2:** README: after the Quick start section add one line: `> 🤖 Driving mcpmesh from a script or an AI agent? See [AGENTS.md](AGENTS.md) — every verb takes \`--json\`.`
- [ ] **Step 3:** Commit: `git commit -m "docs: AGENTS.md — the automation/agent driving contract"`

### Task 8: SAS assertion in the loopback harness + e2e docs paragraph

**Files:**
- Modify: `docs/loopback.sh` (add SAS cross-check using `--json`), `docs/loopback.md` (mention it), `docs/e2e-real.md` (paragraph on asserting the SAS in automated runs)

- [ ] **Step 1:** In `docs/loopback.sh`, capture the pair output and cross-check (POSIX, no jq — read the script first and match its existing helper/style):

```sh
# Redeemer's SAS from `pair --json`; inviter's from the friend's `status --json`
# recent_pairings. Matching strings = the same authenticity check the humans do aloud.
PAIR_JSON=$(mcpmesh --json pair "$INVITE")
MY_SAS=$(printf '%s' "$PAIR_JSON" | sed -n 's/.*"sas_code":"\([^"]*\)".*/\1/p')
FRIEND_SAS=$(friend mcpmesh --json status | sed -n 's/.*"sas_code":"\([^"]*\)".*/\1/p' | head -n1)
[ -n "$MY_SAS" ] && [ "$MY_SAS" = "$FRIEND_SAS" ] || {
  echo "SAS mismatch: '$MY_SAS' vs '$FRIEND_SAS'" >&2; exit 1; }
echo "SAS verified: $MY_SAS"
```

(Adapt variable names/mount extraction to the script's actual current content — it previously grepped the prose `pair` output for mounts; keep that working or switch it to the JSON.)
- [ ] **Step 2:** `docs/e2e-real.md`: add a short "Asserting the safety code" subsection: same two reads, string-compare, note that matching SAS is a real MITM assertion (stronger than skipping), and that the human read-aloud ceremony remains the norm outside tests.
- [ ] **Step 3:** Run `sh docs/loopback.sh` end-to-end locally — expect the new `SAS verified:` line and the existing final proof to pass.
- [ ] **Step 4:** Commit: `git commit -m "e2e: assert the SAS programmatically in loopback; document the pattern for real-network runs"`

### Task 9: Full verification

- [ ] `cargo fmt --all -- --check` (fix if needed)
- [ ] `cargo clippy --workspace --all-targets` — no new warnings
- [ ] `cargo test --workspace` — all green
- [ ] `sh docs/loopback.sh` — green (real end-to-end: serve, invite, pair, SAS assert, tools/call through connect)
- [ ] Commit anything outstanding.

### Task 10: Release 0.6.1

Per RELEASING.md (pre-1.0: non-breaking → PATCH):

- [ ] Bump `[workspace.package] version` and the four `mcpmesh-*` pins in `Cargo.toml` to `0.6.1`; `cargo update -w`; `cargo test --workspace --locked`
- [ ] Pre-tag smoke: RELEASING.md mandates the two-machine smoke (`docs/dev-two-machine-smoke.md`). Attempt `docs/e2e-real.sh` `PEER_MODE=remote` if the remote peer is reachable; otherwise run `PEER_MODE=local` + loopback and REPORT the gap to the user in the final summary (the release touches only the CLI output layer — no wire/daemon/NAT changes — but the deviation must be stated, not hidden).
- [ ] `git commit -am "release: 0.6.1 — agent-friendly CLI: --json everywhere, completions/man, AGENTS.md"`; `git push`; wait for CI green (`gh run watch` / `gh run list`)
- [ ] `git tag v0.6.1 && git push origin v0.6.1`
- [ ] `cargo xtask publish --dry-run` (review) then `cargo xtask publish`
- [ ] `gh release create v0.6.1 --title "mcpmesh 0.6.1" --notes "<summary of the agent-friendly surface>"`
- [ ] Homebrew: `curl -sL https://github.com/counterpunchtech/mcpmesh/archive/refs/tags/v0.6.1.tar.gz | shasum -a 256`; update `Formula/mcpmesh.rb` url+sha256; commit + push.

---

## Self-review notes

- **Spec coverage:** rec 1 (`--json` + JSON errors w/ code) → Tasks 1-5; rec 2 (AGENTS.md) → Task 7; rec 3 (SAS assertion + docs) → Task 8; rec 4 (invite symmetry) → satisfied by `--json` (documented as out-of-scope rationale); rec 5 (completions/man) → Task 6. Release → Tasks 9-10.
- **Types:** `json.rs` uses `Verdict`/`Level` from doctor (needs `pub` — they already are), `client::ClientError` (pub), `render::error_lines` (pub). `Cli::command()` needs `clap::CommandFactory` imported where used.
- **Binary vs lib:** main.rs refers to the lib as `mcpmesh::json`; inside `cli/src/json.rs` it's `crate::`.
- **Known risk:** existing integration tests that snapshot stdout of verbs gaining a `json` parameter — signatures change only for `run_doctor` + six enrollcmd fns (lib-public); grep for callers when executing.
