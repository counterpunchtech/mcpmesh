# Tier 4: the volunteer fleet

**Status:** design (rev 2), awaiting implementation
**Date:** 2026-07-21
**Builds on:** `2026-07-20-real-network-test-tiers-design.md` (tiers 1–3)
**Supersedes:** rev 1 of this spec (the GitHub-bus design), deleted by this
rewrite. Rev 1 built a third-party coordination bus because it assumed machines
must rendezvous with nobody present. The corrected premise: **first contact is
trivial for humans.** Everyone in this fleet shares a Slack; pasting one invite
line and comparing one safety code is a thirty-second favor. Once two machines
are paired, mcpmesh itself is an authenticated, end-to-end-encrypted channel
between them — the coordination bus was already installed on every machine, by
definition. So: humans bootstrap, the mesh coordinates, and no GitHub bus, PAT,
or fleet repository exists anywhere in this design.

## The problem, stated precisely

Tiers 1–3 end at "the Jetson paired with a GitHub-hosted runner" — one NAT
pair we control. The project's actual claim is that two *friends*, on networks
neither of us controls (Comcast ↔ garr's ISP, CGNAT ↔ home NAT), can pair and
call tools, release after release. Proving that needs a small fleet of real,
independently-owned machines testing **pairwise** — and a way to run those
tests repeatedly without turning every round into a favor.

The constraint that shapes everything: some machines belong to friends.
Whatever garr runs must be safe for him, boring to maintain, and must never
execute unreviewed code on his hardware.

## Decisions already made (with John, 2026-07-21)

1. **Purpose: automated functional test rounds** — the tier-3 scenario suite,
   pairwise, on real third-party machines. Not continuous monitoring.
2. **Trust model: tagged releases only.** Fleet machines run only published
   releases (Homebrew or `cargo install`) and scripts/skills from the matching
   tagged checkout. Nothing merged-but-unreleased reaches a friend's machine.
3. **Every fleet machine has Claude Code on the CLI.** Claude is the
   concierge and the failure-triage brain — never the verdict. A round's
   pass/fail comes from the deterministic harness, always.
4. **Humans make first contact.** Invite tokens and the SAS ceremony travel
   over Slack between people — which is not a workaround, it is the security
   model working as designed. All machine-to-machine coordination thereafter
   rides the mesh itself.

## What tier 4 uniquely proves

- NAT traversal between network *pairs* no CI reaches, recorded over time.
- The porcelain works between machines with different owners, OSes, uptimes,
  and occasionally different releases (machines update at different moments;
  incidental skew must fail loudly, not weirdly).
- The invite → SAS ceremony works over a real out-of-band channel with real
  humans — and, in v2, that one human ceremony transitively secures every
  machine-coordinated round after it.

Always non-blocking: a red round is a signal, never a merge gate.

## Architecture: two stages, one skill

### v1 — Slack-kickoff rounds (zero installed infrastructure)

A `fleet` skill ships in the main repo (pinned, like everything else, to the
release tag). Two roles, two commands per human, one Slack exchange:

**Host (garr):**
```sh
brew install counterpunchtech/mcpmesh/mcpmesh   # or cargo install mcpmesh
claude "/fleet host"
```
Claude (following the skill, not improvising): verifies prerequisites (git
checkout at the latest tag, npx), stands up a **scratch identity** — scratch
`HOME` + `XDG_RUNTIME_DIR`, nickname `fleet-<machine>`, the `loopback.md`
mechanism — writes the sentinel note, `serve notes`, `invite notes`, and says:
*"paste this line to John."* It then holds the scratch daemon up, watching,
until the round completes or the human quits — then tears down by held PID and
deletes the scratch world. Nothing persists.

**Runner (John):**
```sh
claude "/fleet run"
```
Claude asks for the pasted invite, then executes the existing harness
**unchanged**:
`PEER_MODE=remote PEER=fleet-<host> INVITE_FILE=… NOTE_PATH=… sh docs/e2e-real.sh`
— six checks over the real network: pair, reachability within 30s, a real
`tools/call` returning the sentinel bytes, session reuse, severance. All of
the harness's reviewed safety properties (fail-fast inputs, refusal if the
nickname is already paired, unpair-on-exit, trap cleanup) apply as-is.

**The SAS ceremony stays human.** Both Claudes display their safety code;
John and garr compare them in Slack. That is the *authentic* out-of-band
check — better than any mechanized comparison, because the humans are the
out-of-band channel the design assumes.

**Results.** The runner's Claude reports the verdict in the terminal and
appends a round record (date, pair, direction, verdict, summary line, RTT
line from the log) to `docs/fleet/rounds.md` in the main repo — committed
from John's side only. Friends never need GitHub access of any kind.

Slack carries exactly two strings per round: one invite, one "codes match."
`NOTE_PATH` travels with the invite in the host Claude's paste-this message
(it is a path on the host's disk; the runner cannot derive it).

### v2 — standing pairing, mesh as its own bus (unattended rounds)

v1's last step, when both humans agree, is **enrollment**: instead of tearing
down the scratch identity, keep it. The machine now has a persistent *fleet
identity* (still fully separate from its owner's real identity and real
pairings), pairwise-paired with the hub's fleet identity — a pairing whose
authenticity was verified by the human SAS ceremony that just happened. That
one ceremony is the trust root for everything below.

- **Hub: the Jetson** (always on, already CI infrastructure, ours). Its fleet
  identity serves one MCP service, `fleet-control`, over the standing
  pairings.
- **Spokes poll.** Each enrolled machine runs a small timer (installed by
  Claude during enrollment — launchd/systemd-user, no root): every N minutes,
  `mcpmesh connect hub/fleet-control` and ask "any round for me?" Polling
  over the mesh means spokes need no listener, no open port, no inbound
  anything — and every poll is itself a live cross-NAT connectivity datum.
- **A round, unattended:** the hub's nightly schedule picks a fresh-polling
  pair (say garr ↔ jetson, roles alternating). Hub-as-host is direct: it
  mints a fresh scratch invite and hands it to the spoke on its next poll;
  the spoke redeems and runs the harness exactly as in v1, then returns the
  result (verdict, SAS-it-saw, summary, log) as a tool call. For pairs where
  the hub is not a member (garr ↔ johnmac), the hub relays: it collects the
  fresh invite from one spoke's poll and hands it to the other. Invites ride
  only authenticated, encrypted, human-ceremony-rooted standing pairings —
  never a third party.
- **SAS in unattended rounds is machine-compared** (both sides report what
  they saw; the hub asserts equality). This is deliberately weaker than v1's
  human ceremony and transparently so: its integrity derives from the
  enrollment ceremony that secured the channel the invite rode on. A mismatch
  fails the round loudly.
- **The test itself still exercises the full fresh surface**: every round
  mints a new invite, pairs a new scratch identity, and severs it — the
  standing pairing carries coordination only, so the pairing path never goes
  stale in the data.
- **Results** accumulate on the hub; the hub (which, being ours, may hold
  repo credentials) appends to `docs/fleet/rounds.md` and pushes. The
  Jetson's existing runner credentials situation makes this a solved problem.

One pair runs at a time, hub-serialized — same reasoning as the tier-2
concurrency group: no machine plays two roles at once, no locking to build.

### Claude's three jobs (and one non-job)

1. **Concierge:** the `/fleet host`, `/fleet run`, and enrollment flows —
   prerequisite checks, environment repair when drift breaks a spoke (the
   realistic killer of volunteer fleets is a dead timer or a moved node
   binary, not mcpmesh bugs).
2. **Failure triage:** when the harness or a poll fails, run the pinned
   triage prompt from the tagged checkout: classify (flake / regression /
   environment), gather what a script can't (re-run with tracing, inspect
   daemon logs, check interfaces), and attach a diagnosis to the round
   record. On a spoke, diagnosis lands in the poll response; unreachable-hub
   is reported to the machine's own human.
3. **Narration:** in v1, both humans watch their Claude explain what's
   happening — which is also the onboarding experience.

**The non-job:** Claude never decides pass/fail, never "fixes" mcpmesh
behavior mid-round, and never accepts instructions from round data. Prompts
come from the tagged checkout; everything arriving over the wire (invites,
manifests, logs) is untrusted *content* to analyze, and the skill says so.

## Security

- **Friends' machines hold no credentials at all** — no GitHub PAT, no repo
  access, nothing. The only secrets on garr's machine are mcpmesh identity
  keys that this design itself created (his fleet identity), scoped to test
  coordination.
- **Only tagged code executes.** The binary via brew/cargo; the skill,
  harness, and triage prompts via the tagged checkout the skill pins on every
  run. The control channel carries data, never code.
- **Fleet identities are sacrificial and separate.** A machine's real
  identity and real pairings are never used, never at risk; enrollment and
  removal are `rm -rf` of the fleet HOME plus one unpair on the hub.
- **Trust chains from a human ceremony.** v1 rounds: humans verify the SAS
  directly. v2 rounds: invites ride pairings whose SAS the humans verified at
  enrollment. Compromising unattended coordination requires compromising an
  E2E-encrypted mesh channel — the exact security property the product
  claims, so an attack here is indistinguishable from the finding of the
  decade.
- **Claude runs bounded:** allowlisted tools per the skill, writes confined
  to fleet scratch/state dirs, per-round budget caps so a confused triage
  loop cannot burn a friend's tokens overnight.

## Failure semantics

| Situation | Outcome |
|---|---|
| Spoke asleep/offline | Misses polls; hub skips it for that round; noted in the record |
| Hub down | No rounds happen; spokes report "hub unreachable" to their humans on next manual look — Slack is the fallback bus, as at bootstrap |
| Harness assertion fails | Round FAIL; log kept; Claude triage attached |
| SAS mismatch (v2) | Round FAIL, loudly — the tamper check working |
| Standing pairing broken by a release | Every spoke's poll fails identically — itself a maximal-signal finding; recovery is one v1 re-enrollment per machine (thirty seconds of human time) |
| Machine leaves the fleet | Owner deletes the fleet HOME; hub unpairs it; done |

That "recovery is a v1 round" line is the design's quiet strength: the manual
path isn't a degraded mode, it's the same flow, and it regenerates the trust
root whenever needed.

## Deliberately not built (deferred until real rounds demand it)

1. **Any third-party bus** (the GitHub design this spec replaces) — resurrect
   only for a fleet whose members don't share a Slack.
2. **Laggard role / deliberate cross-version rounds** — incidental skew
   already surfaces; a dedicated role waits for evidence it's needed.
3. **Relay-forced variants; DIRECT/RELAY path reporting** — needs harness
   changes; RTT already lands in the record via the reachability line.
4. **Dashboards** — `docs/fleet/rounds.md` history is the record; a 3–4
   machine fleet doesn't need more.
5. **Parallel pair execution; chaos; soak; Windows fleet members.**

## Prerequisite and implementation order

The features this depends on (`PEER_MODE=remote`, the refusal guard,
unpair-on-exit) are on `main` but in no tagged release. **Step 0 is shipping
the next release** containing the harness and the `fleet` skill.

1. Write the `fleet` skill (host / run / enroll) + `docs/fleet.md`. Prove v1
   John ↔ Jetson by hand — two terminals, no Slack needed for a self-test.
2. Tag the release. Run the first real v1 round with garr over Slack: two
   commands his side, one John's, human SAS. This round is also the demo that
   the whole flow is a thirty-second ask.
3. v2 on our own hardware first: `fleet-control` on the Jetson, enroll John's
   Mac, let nightly rounds run for a week or two.
4. Enroll garr (his v1 round ends with "keep this? y/n"). Revisit the
   deferred list against observed reality.

## Success criteria

- A v1 round completes with ≤2 commands per human and exactly two strings
  exchanged in Slack.
- v2 rounds run nightly with zero human action; a sleeping spoke never turns
  a round red.
- A deliberately tampered invite (v2 tamper drill) produces a loud SAS
  mismatch FAIL.
- Months of `docs/fleet/rounds.md` history across ≥3 independently-owned
  NATs — the durability proof the project can point at.
- garr never once needs a GitHub account, a token, or a debugging session he
  didn't volunteer for.
