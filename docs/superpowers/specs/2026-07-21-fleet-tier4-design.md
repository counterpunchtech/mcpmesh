# Tier 4: the volunteer fleet

**Status:** design, awaiting implementation
**Date:** 2026-07-21
**Builds on:** `2026-07-20-real-network-test-tiers-design.md` (tiers 1–3)

## The problem, stated precisely

Tiers 1–3 end at "the Jetson paired with a GitHub-hosted runner." That proves
relay bootstrap and one NAT pair — Azure ↔ one home network. It cannot prove
what mcpmesh actually claims: that two *friends*, on networks neither of us
controls (Comcast ↔ garr's ISP, CGNAT ↔ home NAT), can pair and call tools,
release after release, without either of them debugging anything.

The missing piece is a small fleet of real, independently-owned machines that
test **pairwise** against each other on a schedule, with no human coordination.
The constraint that shapes everything: some machines belong to friends. Whatever
we ask garr to run must be safe for him, boring to maintain, and must never
execute unreviewed code on his hardware.

## Decisions already made (with John, 2026-07-21)

1. **Purpose: automated functional test rounds.** Not continuous monitoring —
   scheduled runs of the tier-3 scenario suite across machine pairs.
2. **Trust model: tagged releases only.** Fleet machines run only published
   releases (Homebrew or `cargo install`), never branch or PR builds. Nothing
   merged-but-unreleased can reach a friend's machine.
3. **Coordination: GitHub as the bus, outbound-only pull agents.** No VPN (an
   overlay network would mask the NAT behavior under test), no SSH into
   friends' machines, no new servers.

## What tier 4 uniquely proves

- NAT traversal between network *pairs* no CI reaches, recorded per pair over
  time.
- The porcelain works between machines with different owners, uptimes, OS
  versions, and — because machines update at different moments — sometimes
  different mcpmesh releases. (Deliberate cross-version testing is deferred;
  incidental skew that occurs anyway must fail loudly, not weirdly.)
- The SAS ceremony survives a real out-of-band channel: both sides publish the
  code they saw, and a machine — not politeness — asserts they match.

Always non-blocking. A red round is a signal to investigate, never a gate:
it depends on residential ISPs, sleeping Macs, and iroh's public relays.

## Architecture

Three parts. Each exists because removing it breaks the system; nothing here
is speculative.

### 1. The bus: a `mcpmesh-fleet` repository

A separate repo (private is fine) is the entire coordination layer. Plain git
— every fleet machine already has git, the history is the audit log, and there
is no server to run. Layout:

```
machines/<name>.json          # one per machine: os, arch, owner; agent
                              # rewrites it each tick with a heartbeat timestamp
                              # and the installed mcpmesh version
rounds/<round-id>/            # round-id: UTC date + run number, e.g. 2026-08-01.1
  manifest.json               # written once by the orchestrator: the ordered
                              # pair list, roles, and deadline
  current                     # the index of the pair being tested NOW;
                              # orchestrator-owned, advanced as results land
  <pair>/                     # pair dir: <inviter>--<redeemer>
  <pair>/invite.txt           # inviter posts the bare mcpmesh-invite: token
  <pair>/note-path.txt        # inviter posts the sentinel note's absolute path
                              # on ITS machine (scratch HOMEs differ per host,
                              # so the redeemer cannot derive NOTE_PATH)
  <pair>/inviter-sas.txt      # inviter posts the safety code it saw
  <pair>/result.json          # redeemer posts pass/fail counts, its SAS, and
                              # the harness summary line
  <pair>/log.txt              # redeemer posts the full harness output
  summary.md                  # orchestrator's verdict for the round
```

Write races are avoided by ownership, not locking: the orchestrator alone
writes `manifest.json`, `current`, and `summary.md`; each machine writes only
under its own name. Agents `pull --rebase` and retry once on a rejected push —
with single-writer files that is sufficient.

### 2. The agent: `fleet/agent.sh` in the main repo

One POSIX shell script (same dialect and discipline as `docs/e2e-real.sh`),
run by launchd/systemd-timer every 5 minutes. Per tick:

1. **Pin to the latest release.** `git -C <mcpmesh checkout> fetch --tags &&
   git checkout <latest release tag>` for the scripts, and upgrade the binary
   via brew or `cargo install --locked` when the tag is newer than
   `mcpmesh --version`. The agent itself does not self-modify: it *is* part of
   the tagged checkout it just updated. Everything executable on the machine
   traces to a published tag — this is the whole trust model, mechanized.
2. **Heartbeat.** Rewrite `machines/<self>.json` with a timestamp and version.
3. **Play its role, if any.** If an open round's `current` pair names this
   machine, enter an inner loop (poll the repo every 30s until the round
   closes) and act:
   - **Inviter:** stand up a *scratch* identity (the `loopback.md` mechanism:
     scratch `HOME` + `XDG_RUNTIME_DIR`, nickname `fleet-<self>`), write the
     sentinel note, `serve notes`, `invite notes`, post `invite.txt` +
     `note-path.txt` and — after the redeemer pairs — its safety code as
     `inviter-sas.txt`. Keep the
     scratch daemon alive until the pair has a result or the deadline passes,
     then tear it down (kill by held PID — the pkill lesson from Task 6) and
     delete the scratch world.
   - **Redeemer:** wait for `invite.txt`, then run the existing harness
     unchanged:
     `PEER_MODE=remote PEER=fleet-<inviter> INVITE_FILE=… NOTE_PATH=… sh docs/e2e-real.sh`
     Post `result.json` (pass/fail counts, the SAS grepped from the pair
     output, the summary line) and `log.txt`. The harness already guarantees
     the safe properties: fail-fast on missing inputs, refusal if the nickname
     is somehow already paired, unpair-on-exit, trap-based cleanup.

The redeemer runs as the machine's real identity — exactly what
`PEER_MODE=remote` was built and reviewed for. The `fleet-` nickname prefix
plus the harness's already-paired refusal keep real pairings untouchable.

### 3. The orchestrator: one workflow in the fleet repo

`on: schedule` (nightly) + `workflow_dispatch`. It:

1. Reads `machines/`, keeps machines with a heartbeat fresher than 15 minutes.
   Fewer than two fresh → write a "skipped: <who was stale>" summary and exit
   green. **A sleeping mac mini is expected, not a failure.**
2. Writes `manifest.json`: every unordered pair of fresh machines, one
   pair-test per pair, roles alternating by round parity so both directions
   get exercised over time. Pairs run **one at a time, globally** — the
   orchestrator advances `current` only when the active pair posts a result
   or times out (10 minutes per pair). Global serialization costs wall-clock
   (~6 pairs × ~5 min for a 4-machine fleet, well inside a workflow's limits)
   and buys the same thing the Jetson job's concurrency group buys: no
   machine ever plays two roles at once, no daemon/nickname contention,
   no distributed locking to build or debug.
3. When all pairs have resolved (result, or timeout → SKIPPED with whoever
   went silent named), writes `summary.md`: per pair — PASS/FAIL/SKIPPED, the
   harness summary line, and **SAS match: yes/no** (comparing
   `inviter-sas.txt` against the SAS in `result.json`; a mismatch is a FAIL
   even if every assertion passed — that is the tamper check working).
   The workflow's own conclusion is red only when a pair genuinely FAILED,
   so the Actions history is the pass/fail record. No dashboard: `git log`
   over `rounds/` and the Actions list are the durability evidence.

## Security

- **Per-machine fine-grained PAT, scoped to `mcpmesh-fleet` only** (contents
  read/write). Owners are collaborators on the fleet repo and mint their own
  tokens. A leaked token can vandalize test coordination — it cannot touch
  the main repo, releases, or anything else.
- **The bus carries data, never code.** `manifest.json` selects machines,
  roles, and ordering; every executable line an agent runs comes from the
  tagged release checkout. An attacker with fleet-repo write access can
  disrupt rounds, not execute code.
- **Invites in the repo are acceptable by design:** one-time, expiring,
  scratch-identity-backed, and the SAS cross-check turns a tampered invite
  into a red round rather than a silent compromise.
- The agent runs as an unprivileged user and touches only its scratch worlds,
  the pinned checkout, and the fleet clone.

## Failure semantics (worth stating once, plainly)

| Situation | Outcome |
|---|---|
| Machine asleep/offline at round start | Excluded from manifest; noted in summary |
| Machine goes silent mid-pair | Pair SKIPPED after 10 min, round continues |
| Harness assertion fails | Pair FAIL, log posted, workflow red |
| SAS mismatch | Pair FAIL (tamper check) |
| Invite expires before redeemer polls it | Pair FAIL with the harness's own error in the log — visible, diagnosable |
| Agent crashes | Heartbeat goes stale; machine drops out of future rounds until fixed |
| mcpmesh release is broken | Every pair fails identically — which is the fleet doing its job |

## Enrollment (the garr test: two commands and a token)

`docs/fleet.md` will document: install mcpmesh (brew or cargo), clone the main
repo and check out the latest tag, accept the fleet-repo invitation and mint a
scoped PAT, write `~/.mcpmesh-fleet.conf` (machine name + token + paths), and
install the launchd/systemd timer from a template in `fleet/`. Removal is the
reverse; nothing runs as root.

## Deliberately not built (deferred until a round of real use demands it)

1. **Laggard role / deliberate cross-version testing** — incidental version
   skew already surfaces in heartbeats and logs; a dedicated role waits until
   we've watched real rounds.
2. **Relay-forced variants, path (DIRECT/RELAY) reporting** — needs harness
   changes; the RTT already lands in the log via the reachability PASS line.
3. **Dashboards, badges, pass-rate tables** — Actions history + git history
   suffice for a 3–4 machine fleet.
4. **mcpmesh as its own control plane** — becomes just another scenario later,
   never a foundation.
5. **Parallel pair execution** — revisit only if the fleet grows past ~6
   machines and rounds stop fitting in a night.
6. **Chaos, soak, Windows fleet members.**

## Prerequisite and implementation order

The harness features tier 4 depends on (`PEER_MODE=remote`, refusal guard,
unpair-on-exit) exist on `main` but in no tagged release yet. **Step 0 is
shipping the next release** containing the harness and `fleet/`.

1. Create `mcpmesh-fleet`, write `fleet/agent.sh` + timer templates +
   `docs/fleet.md` in the main repo.
2. Enroll John's Mac and the Jetson; run rounds for a week (two machines whose
   failures we can debug hands-on).
3. Tag the release; enroll garr's mac mini.
4. After a few weeks of rounds, revisit the deferred list against observed
   reality.

## Success criteria

- A full round (manifest → pairs → summary) completes with zero human action.
- garr's machine joins with nothing beyond the enrollment doc, and its being
  offline never turns a round red.
- A deliberately broken invite (tamper test) produces a SAS-mismatch FAIL.
- Months of Actions history across ≥3 independently-owned NATs — the
  durability proof the project can point at.
