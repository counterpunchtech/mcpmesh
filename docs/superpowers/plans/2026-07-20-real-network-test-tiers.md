# Real-Network Test Tiers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give mcpmesh automated coverage of the porcelain across a real network, so a bug like the cold-probe defect (`049877b`) is caught by CI rather than by a human on a phone hotspot.

**Architecture:** One parameterized POSIX shell script (`docs/e2e-real.sh`) drives the real `mcpmesh` porcelain between two identities and asserts on observable CLI output. The same script serves three callers: a human running it by hand, a self-hosted GitHub Actions job on the Jetson (tier 2, LAN), and a nightly cross-NAT job (tier 3). No new Rust code and no new dependencies — the script shells out to the shipped binary exactly as a user would.

**Tech Stack:** POSIX `sh` (must run under Ubuntu's `dash` on the Jetson, not just `bash`), GitHub Actions, the `mcpmesh` CLI, `npx @modelcontextprotocol/server-filesystem` as the demo MCP server.

**Scope:** Covers items 1–4 of the spec's implementation order. Item 5 (fuzzing, Windows, cross-version, chaos, perf) is a separate project and needs its own spec and plan — do not start it here.

**Reference spec:** `docs/superpowers/specs/2026-07-20-real-network-test-tiers-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `docs/e2e-real.sh` (create) | The whole tier-2/tier-3 test. Sets up two identities, runs the porcelain, asserts, cleans up. Parameterized by env var so one file serves all callers. |
| `docs/e2e-real.md` (create) | How to run it by hand, what each assertion proves, and what it deliberately does not prove. |
| `.github/workflows/real-network.yml` (create) | The tier-2 (and later tier-3) jobs. Kept separate from `ci.yml` so a self-hosted runner outage can never affect the hermetic matrix. |
| `docs/dev-two-machine-smoke.md` (modify) | Add a pointer to the new script clarifying which layer each covers. |

### `set -e` discipline (found during Task 1 execution — applies to Tasks 3–7)

The skeleton uses `set -eu`. The working prototype this is derived from used only
`set -u`. That difference is load-bearing and was nearly missed:

```sh
$ sh -c 'set -eu; X=$(false); echo "reached: $X"'; echo "exit=$?"
exit=1          # no output, no summary, script just stops
```

`set -e` is *wanted* during setup — if `mkdir` or the peer daemon fails to start,
aborting is correct. It is *dangerous* around assertions, where a non-zero exit
is a normal outcome we want to record as `FAIL`, not a reason to vanish.

Every assertion in Tasks 3–7 must therefore be phrased so it cannot abort:

```sh
OUT=$(some-command 2>&1) || true          # capture, never abort
if printf '%s' "$OUT" | grep -q expected; then ok "…"; else bad "…"; fi
```

`cmd && ok "…" || bad "…"` is also safe (the `||` arm always runs and returns 0),
but the `if` form is clearer and is preferred.

Additionally, Task 2's cleanup trap must print the summary, so that even an
unexpected abort reports what had passed before it died rather than exiting
silently.

### Signal traps must exit themselves (found during Task 2 execution)

Two more shell facts surfaced implementing the cleanup trap, both verified under
dash, both load-bearing for every later task:

1. **A trap that does not `exit` resumes the script body.** `trap cleanup EXIT
   INT TERM` runs `cleanup` on SIGTERM and then *continues the script* from where
   the signal landed — which, after cleanup has deleted the scratch world,
   re-auto-starts a daemon into it (a leak) and can still exit 0 (a false pass).
   Each signal trap must end in `exit`:
   ```sh
   trap cleanup EXIT
   trap 'cleanup; exit 129' HUP     # HUP is NOT in the default set — SSH drop / CI cancel
   trap 'cleanup; exit 130' INT
   trap 'cleanup; exit 143' TERM
   ```
   The idempotence guard (`cleaned_up`) makes the double call (signal trap → EXIT
   trap) a safe no-op.

2. **A function's output redirection applies to the shell during the call.**
   `peer() { ... "$MM" "$@"; }` invoked as `peer serve ... >/dev/null` sends the
   trap's own summary to `/dev/null` if a signal lands during that call. Save the
   real stdout once at startup (`exec 3>&1`) and write the summary to `>&3`.

`cleanup` must also run under `set +e` (best-effort teardown), or a failed `echo`
to a dead terminal aborts it before it kills the daemon.

### A note on TDD for a test harness

The Iron Law still applies, but "write the failing test first" maps differently here: the artifact *is* a test. The equivalent discipline is **prove each assertion can fail before trusting it.** Every task that adds an assertion has a step that deliberately breaks the condition, runs the script, and confirms it reports FAIL. An assertion never observed failing is not an assertion — it is a comment.

---

## Task 1: Script skeleton with a pass/fail harness

**Files:**
- Create: `docs/e2e-real.sh`

- [x] **Step 1: Write the skeleton with its counters and no real assertions yet**

```sh
#!/bin/sh
# Real-network end-to-end test for the mcpmesh PORCELAIN.
#
# Unlike the hermetic suite (localhost, relay disabled, discovery seeded) and
# unlike docs/dev-two-machine-smoke.md (which drives mcpmesh-net directly with a
# StaticGate), this runs the commands a USER runs — serve, invite, pair, status,
# connect — between two identities over real network interfaces.
#
# Two callers, selected by PEER_MODE:
#   local  — a scratch HOME on this machine is the second identity (tier 2).
#            Real NICs and real discovery, but ONE host: this does NOT prove
#            NAT traversal.
#   remote — pair with an invite minted elsewhere via INVITE_FILE (tier 3).
#
# POSIX sh: must run under dash. No bashisms.
set -eu

MM="${MM:-mcpmesh}"
PEER_MODE="${PEER_MODE:-local}"
PEER="${PEER:-e2e-peer}"
WORK="${WORK:-$HOME/.mcpmesh-e2e}"
SENTINEL='e2e sentinel: this note crossed the mesh'
# Bound for assertion 2. Derived, not invented: REACH_TTL_SECS is 20s and
# PROBE_TIMEOUT is 3s (cli/src/daemon/reach.rs), so 30s allows a full TTL cycle
# plus a probe. The pre-049877b bug left the redeemer at "offline" indefinitely,
# so this fails loudly on a regression without being flaky.
REACH_BOUND_SECS="${REACH_BOUND_SECS:-30}"

pass=0
fail=0
ok()  { pass=$((pass+1)); echo "  PASS  $1"; }
bad() { fail=$((fail+1)); echo "  FAIL  $1"; }

echo "=== mcpmesh real-network e2e ($PEER_MODE) ==="
"$MM" --version

echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
```

- [x] **Step 2: Verify the harness reports success and exits 0**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: prints the version, `=== 0 passed, 0 failed ===`, `exit=0`.

- [x] **Step 3: Verify the harness can actually fail**

Temporarily add the line `bad "deliberate"` immediately before the final `echo`, then run:

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: prints `  FAIL  deliberate`, `=== 0 passed, 1 failed ===`, `exit=1`.

**Remove the temporary `bad "deliberate"` line before continuing.** If exit was 0, the harness is broken — fix it before adding any assertion, because every later assertion depends on this.

- [x] **Step 4: Verify it runs under dash, not just bash**

Run: `dash docs/e2e-real.sh; echo "exit=$?"`
(On macOS, skip — dash is absent. The Jetson runner uses `sh` = dash, so this must be checked at least once on Linux before Task 8.)
Expected: same output as Step 2. A syntax error here means a bashism slipped in.

- [x] **Step 5: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: skeleton for the real-network e2e harness"
```

---

## Task 2: Stand up the second identity and clean up after it

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Add identity setup and a trap-based cleanup**

Insert after the `ok`/`bad` definitions, before the `echo "=== mcpmesh real-network e2e"` line:

```sh
PEER_HOME="$WORK/peer"
PEER_RUN="$PEER_HOME/runtime"

# Everything this script created, removed on ANY exit path (success, failure,
# or Ctrl-C). A leaked daemon would hold a stale identity that breaks the NEXT
# run's nickname-collision guard, so cleanup is not optional.
cleanup() {
    [ -n "${PEER_PID:-}" ] && kill "$PEER_PID" 2>/dev/null || true
    "$MM" pair --remove "$PEER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

peer() { HOME="$PEER_HOME" XDG_RUNTIME_DIR="$PEER_RUN" "$MM" "$@"; }

setup_local_peer() {
    mkdir -p "$PEER_HOME/notes" "$PEER_RUN" "$PEER_HOME/.config/mcpmesh"
    # Under $HOME, never /tmp or $TMPDIR: on macOS both resolve through a symlink
    # and the filesystem MCP server rejects every path (see docs/loopback.sh).
    echo "$SENTINEL" > "$PEER_HOME/notes/hello.md"
    printf '[identity]\nnickname = "%s"\n' "$PEER" \
        > "$PEER_HOME/.config/mcpmesh/config.toml"
    HOME="$PEER_HOME" XDG_RUNTIME_DIR="$PEER_RUN" "$MM" internal daemon &
    PEER_PID=$!
    i=0
    until [ -S "$PEER_RUN/mcpmesh/mcpmesh.sock" ]; do
        i=$((i+1))
        [ "$i" -gt 100 ] && { echo "peer daemon did not start" >&2; exit 1; }
        sleep 0.2
    done
    peer serve notes -- npx -y @modelcontextprotocol/server-filesystem \
        "$PEER_HOME/notes" >/dev/null
}
```

- [x] **Step 2: Call it and print the peer's identity**

Insert after the `"$MM" --version` line:

```sh
rm -rf "$WORK"
if [ "$PEER_MODE" = "local" ]; then
    echo "--- standing up the local peer identity ---"
    setup_local_peer
    peer status | sed -n '1,4p'
fi
```

- [x] **Step 3: Run it**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: prints the peer's `mcpmesh-local/1` banner with a `device` and `identity` line distinct from your own, then `0 passed, 0 failed`, `exit=0`.

- [x] **Step 4: Verify cleanup actually removed everything**

Run: `ls -d "$HOME/.mcpmesh-e2e" 2>/dev/null || echo "work dir gone"`
Expected: `work dir gone`.

Run: `pgrep -f "mcpmesh internal daemon" | wc -l`
Expected: at most 1 (your own daemon). If 2+, the trap is not killing the peer — fix before continuing, or every later run inherits a stale identity.

- [x] **Step 5: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: stand up and tear down the e2e peer identity"
```

---

## Task 3: Assertion 1 — pairing completes and the SAS matches both sides

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Add the pairing assertion**

Insert before the final `echo "=== $pass passed"` line:

```sh
echo "--- 1. pair ---"
if [ "$PEER_MODE" = "local" ]; then
    INVITE=$(peer invite notes | grep -o 'mcpmesh-invite:[A-Za-z0-9]*')
else
    INVITE=$(cat "${INVITE_FILE:?INVITE_FILE required when PEER_MODE=remote}")
fi

PAIROUT=$("$MM" pair "$INVITE" 2>&1) || true
echo "$PAIROUT" | sed -n '1,2p'
case "$PAIROUT" in
    *"Paired with"*) ok "pairing completed" ;;
    *) bad "pairing failed: $PAIROUT" ;;
esac

# The SAS is the security ceremony: both sides must print the SAME words, or a
# tampered invite would go unnoticed. Comparing them is the point of the code.
OUR_SAS=$(printf '%s' "$PAIROUT" | sed -n 's/.*code: \([a-z-]*\).*/\1/p')
if [ "$PEER_MODE" = "local" ]; then
    THEIR_SAS=$(peer status | sed -n 's/.*code: \([a-z-]*\).*/\1/p' | head -1)
    if [ -n "$OUR_SAS" ] && [ "$OUR_SAS" = "$THEIR_SAS" ]; then
        ok "safety code matches on both sides ($OUR_SAS)"
    else
        bad "safety code mismatch: ours='$OUR_SAS' theirs='$THEIR_SAS'"
    fi
fi
```

- [x] **Step 2: Run it and watch it pass**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `PASS  pairing completed`, `PASS  safety code matches on both sides (…)`, `2 passed, 0 failed`, `exit=0`.

- [x] **Step 3: Prove the SAS assertion can fail**

Temporarily change `THEIR_SAS=$(peer status ...)` to `THEIR_SAS="wrong-words-here"`, then run:

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `FAIL  safety code mismatch: ours='…' theirs='wrong-words-here'`, `exit=1`.

**Revert the temporary change.** An assertion never seen failing proves nothing.

- [x] **Step 4: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: assert pairing completes and the SAS matches both sides"
```

---

## Task 4: Assertion 2 — status reports the peer online within the bound

This is the regression guard for `049877b`. It is the reason this whole plan exists.

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Add the bounded reachability assertion**

Insert after the Task 3 block:

```sh
echo "--- 2. reachability within ${REACH_BOUND_SECS}s of pairing ---"
# Regression guard for 049877b. Before that fix the REDEEMER's first probe began
# a cold id-only dial needing full discovery resolution, blew the 3s
# PROBE_TIMEOUT, and status reported a freshly-paired peer as offline — while
# sessions to that same peer worked. Poll rather than sleep-then-check so the
# reported latency is the real one.
REACH_START=$(date +%s)
REACH_SEEN=""
while [ $(( $(date +%s) - REACH_START )) -lt "$REACH_BOUND_SECS" ]; do
    LINE=$("$MM" status 2>/dev/null | grep "$PEER" | grep -E 'online|offline' || true)
    case "$LINE" in
        *online*) REACH_SEEN="$LINE"; break ;;
    esac
    sleep 2
done
REACH_TOOK=$(( $(date +%s) - REACH_START ))
if [ -n "$REACH_SEEN" ]; then
    ok "peer online after ${REACH_TOOK}s:$(printf '%s' "$REACH_SEEN" | sed 's/^ *//')"
else
    bad "peer never reported online within ${REACH_BOUND_SECS}s (cold-probe regression?)"
fi
```

- [x] **Step 2: Run it and watch it pass**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `PASS  peer online after Ns: …` where N is small (single digits on a LAN), `3 passed, 0 failed`.

- [x] **Step 3: Prove this assertion catches the actual bug it guards**

This is the highest-value verification in the plan: confirm the assertion goes red against the pre-fix code.

```bash
git stash list                      # note current state
git log --oneline -1 049877b        # the fix commit
git revert --no-commit 049877b
cargo build --release
MM=./target/release/mcpmesh sh docs/e2e-real.sh; echo "exit=$?"
```

Expected: `FAIL  peer never reported online within 30s (cold-probe regression?)`, `exit=1`.

If it PASSES against the reverted fix, the assertion is worthless — the bound is too loose, or the local tier resolves discovery too fast to reproduce it. In that case record that finding in `docs/e2e-real.md` under "what this does not prove" and rely on tier 3 for this specific guard. Do not silently keep an assertion that cannot fail.

Then restore:

```bash
git revert --abort 2>/dev/null || git checkout -- .
cargo build --release
```

- [x] **Step 4: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: assert status reports a freshly-paired peer online within 30s"
```

---

## Task 5: Assertions 3 and 4 — a real tool call, and session reuse

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Add the tool-call and reuse assertions**

Insert after the Task 4 block:

```sh
echo "--- 3. end-to-end tools/call ---"
# initialize alone only proves the session opened. The tool call proves a real
# request reached the peer's MCP server and its data came back — the omission
# that let the /tmp symlink bug hide in docs/loopback.sh.
REPLIES=$(
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}'
    sleep 25
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"'"$PEER_HOME"'/notes/hello.md"}}}'
    sleep 15
  } | "$MM" connect "$PEER/notes" 2>&1
)
printf '%s' "$REPLIES" | grep -q '"id":1.*result' \
    && ok "initialize round-tripped" || bad "initialize did not round-trip"
printf '%s' "$REPLIES" | grep -q "$SENTINEL" \
    && ok "tool call returned the peer's file" \
    || bad "tool call did not return the peer's file: $(printf '%s' "$REPLIES" | tail -2)"

echo "--- 4. session reuse ---"
R2=$(
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e2","version":"0"}}}'
    sleep 20
  } | "$MM" connect "$PEER/notes" 2>&1
)
printf '%s' "$R2" | grep -q '"id":1.*result' \
    && ok "second session established" || bad "second session failed"
```

Note: `PEER_HOME` is only meaningful when `PEER_MODE=local`. For `remote`, the caller must export `NOTE_PATH` and this block needs `"$NOTE_PATH"` instead — handled in Task 7.

- [x] **Step 2: Run it and watch both pass**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `PASS  tool call returned the peer's file`, `PASS  second session established`, `6 passed, 0 failed`. Takes ~90s.

- [x] **Step 3: Prove the sentinel assertion can fail**

Temporarily change the `read_file` path to `/nonexistent/nope.md`, then run:

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `FAIL  tool call did not return the peer's file: …`, `exit=1`.

**Revert the temporary change.**

- [x] **Step 4: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: assert a real tool call round-trips and sessions are reusable"
```

---

## Task 6: Assertions 5 and 6 — severance and the nickname-squatting guard

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Add the squatting assertion**

Insert after the Task 5 block. This runs BEFORE severance, because it needs the peer still paired:

```sh
echo "--- 5. nickname squatting is refused ---"
# Guard from d525c06: an invite from a DIFFERENT endpoint claiming a nickname we
# already trust must be refused, or it would inherit that peer's access.
if [ "$PEER_MODE" = "local" ]; then
    SQUAT_HOME="$WORK/squatter"
    SQUAT_RUN="$SQUAT_HOME/runtime"
    mkdir -p "$SQUAT_HOME/notes" "$SQUAT_RUN" "$SQUAT_HOME/.config/mcpmesh"
    echo "squatted" > "$SQUAT_HOME/notes/hello.md"
    printf '[identity]\nnickname = "%s"\n' "$PEER" \
        > "$SQUAT_HOME/.config/mcpmesh/config.toml"
    HOME="$SQUAT_HOME" XDG_RUNTIME_DIR="$SQUAT_RUN" "$MM" serve notes -- \
        npx -y @modelcontextprotocol/server-filesystem "$SQUAT_HOME/notes" >/dev/null 2>&1
    SQUAT_INVITE=$(HOME="$SQUAT_HOME" XDG_RUNTIME_DIR="$SQUAT_RUN" "$MM" invite notes \
        2>/dev/null | grep -o 'mcpmesh-invite:[A-Za-z0-9]*')
    SQUAT_OUT=$("$MM" pair "$SQUAT_INVITE" 2>&1) || true
    case "$SQUAT_OUT" in
        *"already use that name"*) ok "squatting invite refused" ;;
        *) bad "squatting invite was NOT refused: $SQUAT_OUT" ;;
    esac
    # There is no `mcpmesh internal shutdown` subcommand (verified against the
    # shipped CLI: internal exposes daemon/id/peer/roster/blob/audit/watch only).
    # The squatter daemon auto-started under its own HOME, so match on that path.
    pkill -f "$SQUAT_HOME" 2>/dev/null || true
fi
```

Add the squatter daemon to `cleanup()` so a failure mid-assertion cannot leak it — change the `cleanup` function's first line to:

```sh
    [ -n "${PEER_PID:-}" ] && kill "$PEER_PID" 2>/dev/null || true
    pkill -f "$WORK/squatter" 2>/dev/null || true
```

> **`pkill -f` self-match warning.** `pkill -f` matches against full command
> lines, including the shell running this script and any SSH command that
> mentions the pattern. During the 2026-07-20 session a `pkill -f "mcpmesh
> internal daemon"` issued over SSH killed its own connection twice, because the
> remote `bash -c` command line contained the pattern. Here the pattern is a
> filesystem path that does not appear in this script's own argv, so it is safe —
> but if you ever widen it, verify with `pgrep -af <pattern>` first and confirm
> the only matches are the processes you intend to kill.

- [x] **Step 2: Add the severance assertion**

Insert after the squatting block. This must be LAST, since it unpairs:

```sh
echo "--- 6. pair --remove severs access ---"
"$MM" pair --remove "$PEER" >/dev/null 2>&1 || true
SEVERED=$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
    | "$MM" connect "$PEER/notes" 2>&1 || true)
# An unknown/removed peer surfaces as -32055 "peer unreachable" (verified
# against the shipped binary). A SUCCESSFUL dial here would mean unpairing did
# not actually revoke access.
case "$SEVERED" in
    *-32055*|*"unreachable"*|*"not in the allowlist"*) ok "unpaired peer can no longer be dialed" ;;
    *result*) bad "SECURITY: dial succeeded after unpair: $SEVERED" ;;
    *) ok "unpaired peer dial failed (as expected): $(printf '%s' "$SEVERED" | head -1)" ;;
esac
```

- [x] **Step 3: Run the full script**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `8 passed, 0 failed`, `exit=0`. Takes ~2 minutes.

- [x] **Step 4: Prove the squatting assertion can fail**

Temporarily change its `case` pattern from `*"already use that name"*` to `*"this text never appears"*`, then run:

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `FAIL  squatting invite was NOT refused: …`, `exit=1`.

**Revert the temporary change.**

- [x] **Step 5: Verify cleanup after a full run**

Run: `ls -d "$HOME/.mcpmesh-e2e" 2>/dev/null || echo "gone"; pgrep -f "mcpmesh internal daemon" | wc -l`
Expected: `gone`, and at most 1 daemon.

Run: `mcpmesh status | grep -c "$PEER" || echo "no leftover peer"`
Expected: `no leftover peer`.

- [x] **Step 6: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: assert squatting is refused and unpair severs access"
```

---

## Task 7: Support `PEER_MODE=remote` for tier 3

**Files:**
- Modify: `docs/e2e-real.sh`

- [x] **Step 1: Parameterize the note path and skip local-only assertions**

Replace the hardcoded `"$PEER_HOME"/notes/hello.md` in the Task 5 tool-call block with `"$NOTE_PATH"`, and add this near the other defaults at the top:

```sh
# Where the peer's sentinel note lives. Local mode knows; remote mode must be told.
if [ "$PEER_MODE" = "local" ]; then
    NOTE_PATH="${NOTE_PATH:-$WORK/peer/notes/hello.md}"
else
    : "${NOTE_PATH:?NOTE_PATH required when PEER_MODE=remote}"
    : "${INVITE_FILE:?INVITE_FILE required when PEER_MODE=remote}"
fi
```

The SAS-comparison, squatting, and peer-setup blocks are already guarded by `[ "$PEER_MODE" = "local" ]`, so they skip correctly in remote mode. Assertions 1, 2, 3, 4 and 6 all run in both modes.

- [x] **Step 2: Verify local mode still passes unchanged**

Run: `sh docs/e2e-real.sh; echo "exit=$?"`
Expected: `8 passed, 0 failed`, `exit=0` — identical to Task 6.

- [x] **Step 3: Verify remote mode fails fast without its required inputs**

Run: `PEER_MODE=remote sh docs/e2e-real.sh; echo "exit=$?"`
Expected: exits non-zero with `NOTE_PATH required when PEER_MODE=remote`. A missing input must be a loud error, never a silently skipped assertion.

- [x] **Step 4: Commit**

```bash
git add docs/e2e-real.sh
git commit -m "test: support PEER_MODE=remote for the cross-NAT tier"
```

---

## Task 8: Register the Jetson as a self-hosted runner

No code — infrastructure. The Jetson is `aarch64`, has `npx`, 57G free, and user lingering already enabled (verified 2026-07-20), so a user-scoped runner service will survive logout.

- [x] **Step 1: Create the runner registration token**

In the GitHub UI: repository → Settings → Actions → Runners → New self-hosted runner → Linux / ARM64. Copy the token from the `config.sh` line it displays.

- [x] **Step 2: Install the runner on the Jetson**

```bash
ssh jetson-001
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -o actions-runner-linux-arm64.tar.gz -L \
  https://github.com/actions/runner/releases/latest/download/actions-runner-linux-arm64-2.328.0.tar.gz
tar xzf actions-runner-linux-arm64.tar.gz
./config.sh --url https://github.com/counterpunchtech/mcpmesh \
            --token <TOKEN> --labels jetson --unattended
```

Check the release page for the current version if that filename 404s.

- [x] **Step 3: Install it as a service so it survives reboot**

```bash
sudo ./svc.sh install bolo
sudo ./svc.sh start
sudo ./svc.sh status
```

Expected: `active (running)`.

- [x] **Step 4: Confirm GitHub sees it**

Run: `gh api repos/counterpunchtech/mcpmesh/actions/runners --jq '.runners[] | "\(.name) \(.status) \(.labels[].name)"'`
Expected: a line containing `online` and `jetson`.

- [x] **Step 5: Verify the runner can build the project**

```bash
ssh jetson-001 'cd ~/mcpmesh-src && ~/.cargo/bin/cargo build --release 2>&1 | tail -2'
```

Expected: `Finished \`release\` profile`. If Rust is missing in the runner's environment (its PATH differs from your login shell), the workflow must set it explicitly — note that for Task 9.

---

## Task 9: The tier-2 CI job

**Files:**
- Create: `.github/workflows/real-network.yml`

- [x] **Step 1: Write the workflow**

```yaml
name: real-network
on:
  pull_request:
  workflow_dispatch:
permissions: { contents: read }
concurrency:
  # The Jetson is ONE machine with one mcpmesh identity — two concurrent runs
  # would fight over the same daemon, peer store, and nickname namespace.
  group: real-network-jetson
  cancel-in-progress: false
jobs:
  lan-porcelain:
    runs-on: [self-hosted, jetson]
    timeout-minutes: 20
    # Non-blocking until its real flake rate is known (spec: promote later).
    continue-on-error: true
    steps:
      - uses: actions/checkout@v5
      - name: Build
        run: cargo build --release --locked
      - name: Real-network porcelain e2e (tier 2, LAN)
        run: |
          echo "::notice::Tier 2 runs two identities on ONE host: it proves the"
          echo "::notice::porcelain works over real interfaces and discovery."
          echo "::notice::It does NOT prove NAT traversal — that is tier 3."
          MM=./target/release/mcpmesh sh docs/e2e-real.sh
```

- [x] **Step 2: Push and trigger it**

```bash
git add .github/workflows/real-network.yml
git commit -m "ci: tier-2 real-network porcelain job on the self-hosted jetson"
git push
gh workflow run real-network --ref "$(git rev-parse --abbrev-ref HEAD)"
```

- [x] **Step 3: Watch the run and confirm it passes**

Run: `gh run watch "$(gh run list --workflow=real-network --limit 1 --json databaseId --jq '.[0].databaseId')"`
Expected: the job succeeds and its log shows `8 passed, 0 failed` plus the three `::notice::` limitation lines.

- [x] **Step 4: Confirm the runner left nothing behind**

```bash
ssh jetson-001 'ls -d ~/.mcpmesh-e2e 2>/dev/null || echo "gone"; pgrep -fc "mcpmesh internal daemon"'
```

Expected: `gone`, and `1` (the Jetson's own daemon). A leaked identity here breaks the next run.

- [x] **Step 5: Commit any fixes**

If the job needed environment adjustments (a `PATH` for cargo, a `HOME` override), commit them:

```bash
git add .github/workflows/real-network.yml
git commit -m "ci: fix the jetson runner environment for the tier-2 job"
```

---

## Task 10: Documentation

**Files:**
- Create: `docs/e2e-real.md`
- Modify: `docs/dev-two-machine-smoke.md`

- [x] **Step 1: Write `docs/e2e-real.md`**

```markdown
# Real-network porcelain e2e

Runs the commands a USER runs — `serve`, `invite`, `pair`, `status`, `connect`,
`pair --remove` — between two identities over real network interfaces, and
asserts on the observable CLI output.

## How this differs from the other suites

| Suite | Layer | Network |
|---|---|---|
| `cargo test` (hermetic) | in-process `MeshState` | localhost, relay disabled, discovery seeded |
| `docs/dev-two-machine-smoke.md` | `mcpmesh-net` + `StaticGate` | two real machines, real NATs |
| **this** | **the CLI porcelain** | real interfaces (tier 2) or real NATs (tier 3) |

The middle row proves the transport crosses NATs but never touches pairing,
`status`, or reachability. This one covers exactly that gap — which is where the
cold-probe bug (`049877b`) lived.

## Run it

Tier 2 — a scratch `HOME` on this machine is the second identity:

```sh
MM=./target/release/mcpmesh sh docs/e2e-real.sh
```

Tier 3 — pair with an invite minted on a machine on a different network:

```sh
PEER_MODE=remote PEER=their-nickname \
INVITE_FILE=./invite.txt NOTE_PATH=/home/them/notes/hello.md \
MM=./target/release/mcpmesh sh docs/e2e-real.sh
```

## What it asserts

1. Pairing completes.
2. The safety code matches on both sides (local mode only — remote has no way to read the peer's screen).
3. `status` reports the peer online within 30s of pairing. **This is the `049877b` regression guard**: before that fix the redeemer's cold probe blew the 3s `PROBE_TIMEOUT` and reported a freshly-paired peer offline.
4. A real `tools/call` returns the peer's file — not merely `initialize`.
5. A second session establishes.
6. A nickname-squatting invite is refused (local mode only).
7. `pair --remove` severs access.

## What it does NOT prove

- **Tier 2 does not prove NAT traversal.** Two identities on one host share a
  NIC. Relay bootstrap and hole-punching are tier 3's job.
- Nothing here covers Windows: the porcelain is driven through a POSIX shell
  script.
- A green run says nothing about throughput or memory — see `docs/load-soak.md`.
```

- [x] **Step 2: Cross-reference from the existing runbook**

Add to the top of `docs/dev-two-machine-smoke.md`, right after its title line:

```markdown
> **Layer note:** this runbook drives `mcpmesh-net` directly (a `StaticGate`,
> hand-passed addresses, an echo backend) — it does not exercise pairing,
> `status`, or reachability. For the CLI porcelain across a real network, see
> [`e2e-real.md`](e2e-real.md).
```

- [x] **Step 3: Verify every command in the doc actually runs**

Run each `sh` invocation from "Run it" verbatim. The tier-3 one should fail fast with a clear missing-input error, not a confusing one.
Expected: tier 2 passes; tier 3 without its env vars exits non-zero naming the missing variable.

- [x] **Step 4: Commit**

```bash
git add docs/e2e-real.md docs/dev-two-machine-smoke.md
git commit -m "docs: how to run the real-network porcelain e2e, and what it does not prove"
```

---

## Task 11: Observe, then promote tier 2 to blocking

Do NOT do this in the same sitting as Task 9. The spec is explicit that a tier
only becomes blocking after its real flake rate is known.

- [ ] **Step 1: Let it run for a week**

After ~7 days (or ~10 PR runs), collect the outcomes:

Run: `gh run list --workflow=real-network --limit 20 --json conclusion,createdAt --jq '.[] | "\(.createdAt) \(.conclusion)"'`

- [ ] **Step 2: Decide with the human**

If every run passed, or the only failures were real regressions, remove
`continue-on-error: true` from `.github/workflows/real-network.yml`.

If there were flakes, do NOT promote. Diagnose them first — a flaky blocking
check trains people to ignore red, which is worse than no check.

- [ ] **Step 3: Commit the promotion (only if warranted)**

```bash
git add .github/workflows/real-network.yml
git commit -m "ci: make the tier-2 real-network job blocking"
```

---

## Task 12: Tier 3 nightly (cross-NAT)

Only start this after tier 2 is stable. Tier 3 pairs the Jetson (home NAT) with
a GitHub-hosted runner (Azure) — two genuinely different networks.

**Files:**
- Modify: `.github/workflows/real-network.yml`

- [ ] **Step 1: Add the nightly trigger**

Change the `on:` block to:

```yaml
on:
  pull_request:
  schedule:
    - cron: '17 8 * * *'   # 08:17 UTC daily
  workflow_dispatch:
```

- [ ] **Step 2: Add the cross-NAT job**

```yaml
  cross-nat:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    runs-on: [self-hosted, jetson]
    timeout-minutes: 25
    # Depends on iroh's PUBLIC relay infrastructure and on carrier NAT behaviour,
    # so it can go red for reasons unrelated to this codebase. Never blocking.
    continue-on-error: true
    steps:
      - uses: actions/checkout@v5
      - run: cargo build --release --locked
      - name: Mint an invite for the hosted peer
        run: |
          ./target/release/mcpmesh serve nightly -- \
            npx -y @modelcontextprotocol/server-filesystem "$HOME/nightly-notes"
          ./target/release/mcpmesh invite nightly | \
            grep -o 'mcpmesh-invite:[A-Za-z0-9]*' > invite.txt
      - uses: actions/upload-artifact@v4
        with: { name: invite, path: invite.txt }
```

The hosted half (a second job on `ubuntu-latest` that downloads the artifact and
runs the script with `PEER_MODE=remote`) requires the invite to be available
before that job starts. Implement it as a dependent job with
`needs: cross-nat`, and have it install the binary with
`cargo install --path cli --locked`.

- [ ] **Step 3: Trigger it manually and inspect**

Run: `gh workflow run real-network --ref main`
Then: `gh run watch "$(gh run list --workflow=real-network --limit 1 --json databaseId --jq '.[0].databaseId')"`

Expected: the cross-NAT job either passes, or fails with a diagnosable relay or
discovery error. Record the observed pair latency and cold-probe time in
`docs/e2e-real.md` — those numbers are the baseline for spotting future
regressions.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/real-network.yml
git commit -m "ci: nightly cross-NAT tier-3 job"
```

---

## Out of scope (needs its own spec and plan)

From the spec's deferred list, ranked. Do not start these here:

1. Fuzzing the untrusted parsers (`RedeemerHello`, `Invite::decode`, the NDJSON codec) — highest risk-per-effort, since the pair ALPN accepts strangers by design.
2. Windows control-plane coverage (the named-pipe DACL path).
3. Cross-version compatibility (old client ↔ new daemon; orphaned redb rows).
4. Chaos (peer vanishes mid-session, relay outage, daemon restart with live sessions).
5. Performance baselines.
