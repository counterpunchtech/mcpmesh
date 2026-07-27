---
name: mcpmesh-maintainer
description: This skill should be used when the user wants to put the agent into autonomous "mcpmesh maintainer mode" — continuously watching the mcpmesh GitHub issue queue and upstream iroh releases, taking on the most logical next unblocked issue, implementing and testing it fully, shipping it via a PR, and releasing new versions to crates.io + GitHub + Homebrew, then resuming the watch loop. Invoke when the user says things like "enter mcpmesh maintainer mode", "run the maintainer loop", "start maintaining mcpmesh", "watch for mcpmesh issues and work them", "check whether iroh released a new version", or "/mcpmesh-maintainer". Also re-invoke it when a scheduled maintainer check fires (a prompt like "mcpmesh-maintainer: check the issue queue and upstream iroh releases").
---

# mcpmesh maintainer mode

Turn the agent into an autonomous maintainer of the mcpmesh project (`/Users/john/mcpmesh`, a
peer-to-peer MCP transport in Rust). It runs a loop: **watch the issue queue → take the next
unblocked issue → implement + test it fully → ship it (PR + full release) → resume the watch.**

**Announce at start:** "Entering mcpmesh maintainer mode — I'll watch the issue queue and work
the next unblocked issue end-to-end."

## Operator decisions baked into this skill

These were chosen by the repo owner; follow them unless the user overrides in the moment:

- **Deploy autonomy: FULL AUTO for every release** (PATCH *and* MINOR). After implementing +
  testing an issue, go all the way through the release train without a human gate. crates.io is
  irreversible (yank-only) — this is a deliberate opt-in. Never publish on a red gate (see below).
- **Merge flow: a real PR.** Push a branch → open a PR → wait for CI green → merge the PR. One PR
  per issue, a reviewable trail.
- **Issue scope: any open, unblocked issue.** Pick the most logical next one; skip anything
  blocked or gated (see Triage).
- **Upstream watch: iroh, checked on EVERY triage tick (so, far more often than daily).** A new
  stable `iroh` release becomes a GitHub issue **immediately and autonomously** — filing is not
  gated on the owner. Filing only enqueues work; whether to *do* it is normal triage priority.

## The loop (state machine)

```
enter → ensure watch cron → TRIAGE ─(no work)→ idle (cron re-fires TRIAGE later)
                               │      (every TRIAGE runs the iroh watch first)
                          (work found)
                               ▼
              pause watch cron → WORK → SHIP → recreate watch cron → TRIAGE (immediately)
```

### 0. Enter maintainer mode

1. Announce (above) and state the goal.
2. **Ensure exactly ONE watch cron exists.** `CronList` first. Create the maintainer cron only if
   absent, with `CronCreate` `cron: "*/10 * * * *"`, `recurring: true`, and
   `prompt: "mcpmesh-maintainer: check the issue queue and upstream iroh releases, and take the next unblocked issue."`
   — that prompt re-invokes THIS skill on each fire (its description matches). **`CronDelete` any
   prior generic issue-check cron** (e.g. one whose prompt is just "check for any new issues…") so
   the two loops don't both fire. Tell the user the session-only + 7-day-expiry caveats once.
   **Do NOT add a second cron for the iroh watch** — it rides this one (TRIAGE step 1). A separate
   cron would keep firing during WORK, exactly what the pause in step 5 exists to prevent.
3. Go straight to **TRIAGE** now — don't wait for the first fire.

### 1. TRIAGE — is there actionable work?

1. **Upstream watch — iroh. Run this FIRST, on EVERY tick, before anything else.** The watch cron
   fires every 10 minutes, so running it here satisfies "at least daily" with no timestamp
   bookkeeping and no second cron. Run it even when mid-issue (see step 2): filing an issue is
   **queue-only** — no branch, no build, no release — so it cannot corrupt an in-flight issue.

   ```bash
   UA='User-Agent: mcpmesh-maintainer (knotanotsea@protonmail.com)'   # crates.io 403s a bare curl
   curl -s -H "$UA" https://crates.io/api/v1/crates/iroh \
     | python3 -c "import json,sys; c=json.load(sys.stdin)['crate']; print(c['max_stable_version'], c['newest_version'])"
   grep -E '^iroh = ' Cargo.toml     # our pin, e.g. iroh = "=1.0.3"
   ```

   - **`max_stable_version` > our pin** → **file an issue immediately** (below), then continue triage.
   - **Only a new prerelease** (`newest_version` is a `-beta`/`-rc` above `max_stable_version`) →
     do **not** file; we pin stable only. Note it in the tick report so the owner sees it coming.
   - **Nothing new** → one line saying so, move on.

   **Dedup before filing — MANDATORY.** The cron re-fires every 10 minutes; skip this and you file
   the same issue ~144×/day:
   ```bash
   gh issue list --state all --search "iroh <VERSION> in:title" --json number,title,state
   ```
   Any hit, **open or closed**, means it is already tracked — do NOT file again.

   **File it:**
   ```bash
   gh issue create --title "chore: bump iroh to <VERSION>" --body "<body>"
   ```
   The body must carry: the new version + release date, a link to the notes
   (`https://github.com/n0-computer/iroh/releases/tag/v<VERSION>`), our current pin, and a
   **sibling-compat checklist** — `iroh-gossip` and `iroh-blobs` are pinned separately and must
   still resolve against the new `iroh` (`cargo update -w`, then the full suite) — plus a note that
   an iroh bump touches `mcpmesh-net` and therefore carries the two-machine smoke-test caveat (see
   SHIP). Do not pre-judge whether the bump is worth taking; that is triage's call later.

   The filed issue then competes for attention through normal triage ordering, like any other issue.
2. **If already mid-issue** (a maintainer working branch exists, or a WORK step is in progress):
   having done step 1, do NOT start another issue and do NOT go further into triage — continue the
   in-flight issue. (Finishing one issue at a time is the rule; interleaving corrupts the release
   train.)
3. List open issues: `gh issue list --state open --limit 50 --json number,title,labels`.
4. For each, decide **unblocked**:
   - `gh issue view <n> --json body,labels` — read it. An issue is **blocked** if it has an open
     `blocked_by` dependency, a "blocked by" / "gated on" banner in the body, or it waits on an
     external gate (an upstream release, a spec finalizing, ecosystem adoption). **Skip blocked
     issues.** (As of this writing #45/#46/#48/#49 are the gated vNext roadmap — all blocked.)
   - Re-verify a claimed gate before trusting it — e.g. if it waits on "stable rmcp 3.0.0", check
     crates.io (`curl -s -H "$UA" https://crates.io/api/v1/crates/rmcp`) to see if the gate lifted.
5. **No unblocked issue** → report "no actionable issues — <gated items> remain" (plus the step-1
   iroh line) and stop for this tick. The watch cron re-fires TRIAGE later. Do NOT invent work.
6. **Unblocked issue(s) exist** → pick the **most logical next** one (state your reasoning: user
   impact, unblocks other work, smallest safe increment). Then:
   - **Pause the watch cron** (`CronDelete` its id) so checks don't interleave with implementation.
   - Proceed to **WORK**.

### 2. WORK — implement the issue fully

Follow the superpowers process skills in order (invoke each via the Skill tool — do not shortcut):

1. **`brainstorming`** → a short design. Write the spec to
   `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` and commit it. For an issue with a clear,
   small shape you may keep the design terse, but still write + commit the spec.
2. **`writing-plans`** → an implementation plan under `docs/superpowers/plans/` for anything
   non-trivial (skip for a one-file mechanical change).
3. **Implement TDD** on a fresh branch off `main` (`feat/<slug>` or `fix/<slug>`). Match the
   surrounding code's idiom, comment density, and naming. Keep files focused.
4. **Honor the project policy:**
   - **Backwards compatibility: WE DO NOT CARE until post-v1.0.** Greenfield freely; do not add
     compat shims or deprecation layers.
   - **Versioning (pre-1.0):** additive change (new field/verb, new optional behavior) → **PATCH**;
     behavior change or breaking change → **MINOR**. Bump `[workspace.package] version` + the five
     `mcpmesh-*` pins in `Cargo.toml` in lockstep.
   - **Control-API surface:** every surface change bumps `API_MINOR` (and `API_VERSION` string) in
     `local-api/src/protocol.rs`, in the SAME change. Keep `docs/local-protocol.md` +
     `docs/config.md` in sync.
   - **Config writes** go through the surgical RMW writers in `node/src/daemon/config_write.rs`
     under `mesh.reload_lock`; identity injection stays authoritative (never spoofable).
5. **Verify** (`verification-before-completion`): run the FULL suite, clippy, fmt — all green,
   with fresh evidence, before claiming done:
   ```
   cargo fmt --all
   cargo clippy --workspace --all-targets      # zero warnings (CI runs -D warnings)
   cargo test --workspace --locked             # zero failures
   ```
6. **Adversarial review of the diff** (a subagent): stage the diff, dispatch a `general-purpose`
   agent to hunt correctness + security defects against the spec. Fix every real finding and add a
   **regression test per finding**. Re-run the suite. This step is mandatory for anything touching
   trust/authz, config writes, the network/iroh layer, or identity.

### 3. SHIP — PR + full release train

Follow `RELEASING.md`. Full auto (no human gate):

1. **Version bump** (if not already done in WORK): `Cargo.toml` version + 5 pins → `X.Y.Z`, then
   `cargo update -w` and `cargo test --workspace --locked`.
2. **Land via PR:**
   ```
   git push -u origin <branch>
   gh pr create --title "<type>: <summary> (#<issue>)" --body "<what + why, closes #<issue>>"
   ```
   Wait for CI green (`gh run watch <id> --exit-status`), then:
   ```
   gh pr merge --squash --delete-branch     # or --merge; keep main linear
   git checkout main && git pull
   ```
   **Never merge on red CI.** If CI fails, fix on the branch and re-push.
3. **Tag:** `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. **Publish crates:** `cargo xtask publish --dry-run` then `cargo xtask publish` (order:
   codec → local-api → trust → net → node → cli; resumable). Verify each crate shows `X.Y.Z` on
   crates.io.
5. **GitHub release:** `gh release create vX.Y.Z --title "mcpmesh X.Y.Z" --notes "<summary>"`.
6. **Homebrew formula:** compute the tag tarball sha256
   (`curl -sL …/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256`), set `url` + `sha256` in
   `Formula/mcpmesh.rb`, commit `formula: X.Y.Z`, push `main`.
7. **Close the issue** with a consumer-facing summary (what shipped, the verb/field names, the
   `api_minor`, how the consumer swaps to it).

**Smoke-test caveat (state it, don't silently skip):** `RELEASING.md` marks the two-machine smoke
test pre-release-mandatory for the real-NAT path, but it needs two real machines and can't run
headless here. When a release touches `mcpmesh-net`/iroh or relay/discovery behavior, **note in the
PR + release notes that the smoke test was not run** and recommend the downstream (bolo) validate
on a real network. The loopback e2e suite gates CI in the meantime.

### 4. RESUME

1. **Recreate the watch cron** (step 0.2) — it was deleted during WORK.
2. Go straight back to **TRIAGE** (a just-finished issue may unblock the next one). Its step 1
   re-runs the iroh watch, which is what keeps the daily guarantee intact across a long WORK — no
   ticks fire while the cron is paused. Keep going until TRIAGE finds no actionable work, then idle
   on the cron.

## Stop / escalate

- **User says stop** ("exit maintainer mode", "stop the loop"): `CronDelete` the watch cron,
  report the last state, and stop.
- **Genuine blocker** the code/spec can't resolve (ambiguous requirements only the owner can
  settle, a design fork with real product tradeoffs, a red gate you can't fix): pause, report
  concretely (what you tried, what's blocking), and ask — do NOT guess on irreversible steps.
- **Never**: publish on red tests/clippy/fmt; force-push; start implementation on `main`; take on a
  blocked/gated issue; run two issues at once; file an iroh-bump issue without the dedup search
  first; start an iroh bump just because you filed it (filing ≠ working — it goes through triage).

## Memory

This project keeps file-based memory at
`/Users/john/.claude/projects/-Users-john-mcpmesh/memory/`. Relevant standing notes:
`always-pick-up-waiting-work` (act on open issues autonomously), `issue-loop-pause-while-working`
(delete the watch cron during WORK, recreate after SHIP). After a materially new decision or
recurring gotcha, write a memory (one fact per file) and add its one-line pointer to `MEMORY.md`.

## Quick reference

| Phase | Key commands |
|-------|--------------|
| iroh watch | `curl -s -H "$UA" https://crates.io/api/v1/crates/iroh` · `grep '^iroh = ' Cargo.toml` · dedup `gh issue list --state all --search "iroh <V> in:title"` · `gh issue create` |
| Triage | `gh issue list --state open`, `gh issue view <n>` |
| Verify | `cargo fmt --all` · `cargo clippy --workspace --all-targets` · `cargo test --workspace --locked` |
| PR | `gh pr create` · `gh run watch <id> --exit-status` · `gh pr merge --squash` |
| Release | `git tag vX.Y.Z` · `cargo xtask publish` · `gh release create` · bump `Formula/mcpmesh.rb` |
| Loop | `CronCreate "*/10 * * * *"` / `CronDelete` / `CronList` |
