# Real-network test tiers

**Status:** design, awaiting implementation
**Date:** 2026-07-20

## The problem, stated precisely

The suite is strong where it looks: 436 tests, a three-OS CI matrix, `fmt` +
`clippy -D warnings` + `cargo-deny` as gates, and integration suites that spawn
the real shipped binary in tempdir-scoped `HOME`/`XDG` worlds
(`cli/tests/harness/mod.rs`) over genuine iroh meshes.

Every one of those networked tests binds localhost with
`relay_mode: Disabled`, and every reachability test seeds discovery through a
`MemoryLookup`. That is correct for hermetic CI. It also means the production
network path — relay bootstrap, NAT hole-punching, pkarr discovery, real
latency — has no automated coverage at all.

Two manual runbooks exist and are genuinely useful, but neither closes this:

- `docs/dev-two-machine-smoke.md` drives two `#[ignore]`d helpers in
  `net/tests/session.rs` across real NATs. It tests **`mcpmesh-net` directly**:
  a `StaticGate`, hand-passed `EndpointAddr` JSON, an echo backend. It contains
  zero references to pairing, `status`, reachability, or probing — it never runs
  the porcelain a user runs.
- `docs/load-soak.md` is a 10-minute limiter soak, also `#[ignore]`d and manual.

So the gap is not "no two-machine testing exists." It is: **no test exercises
the porcelain across a real network, and nothing runs automatically.**

## Why this is worth building: a worked example

On 2026-07-20 we paired a Mac (Comcast, `24.15.73.245`) with a Jetson Orin Nano
(Verizon hotspot, `174.192.74.124`) — two carrier NAT domains. Pairing succeeded
in ~1s and a real `tools/call` returned the peer's file. But `status` on the Mac
reported the peer **offline** while sessions to that same peer worked.

Root cause: `probe_peer` dialed the bare endpoint-id, so its answer depended on
discovery having already resolved the peer. The redeemer's first probe began a
cold id-only dial needing full discovery resolution, which blew the 3s
`PROBE_TIMEOUT`. The inviter, already holding a live path back, probed the other
direction in **11ms**. The side that just redeemed an invite — exactly the
person most likely to run `status` — was told their brand-new peer was offline.

The fix (`049877b`) reused `stored_dial_addr`, which `dial_service` already used
for precisely this reason (issue #27). Measured after: cold probe **816ms → 24ms**.

Three properties of this bug define the tiers below:

1. **435 hermetic tests could not see it.** Every reachability test seeds
   discovery, so the id-only dial resolves instantly and the defect is
   structurally invisible.
2. **The existing two-machine runbook could not see it.** It tests the net layer,
   never `status`.
3. **Once understood, it reduced to a fast deterministic test.** Store the
   `last_addr` hint, omit `seed_lookup`, and the id-only dial cannot resolve —
   red before the fix, green after, in 0.87s with no network.

Point 3 is the whole strategy: **real-network runs are for discovery; every bug
they find gets pulled down into the hermetic tier as a fast regression test.**

## Architecture: three tiers

| Tier | Peers | Uniquely proves | Runs | Blocking |
|---|---|---|---|---|
| 1. Hermetic (exists) | localhost, relay disabled | Protocol, gate, authz, wire logic | Every PR, 3 OSes | yes |
| 2. LAN two-machine | Jetson ↔ second identity on the LAN | Real NICs, IPv6, mDNS, direct dial, **porcelain end-to-end** | Every PR (self-hosted) | yes |
| 3. Cross-NAT | Jetson ↔ peer on a different carrier | Relay bootstrap, hole-punching, WAN latency, cold-probe timing | Nightly | **no** |

Each tier is labelled for what it covers so a green check is never mistaken for
coverage it does not have.

### Why tier 3 is non-blocking

It depends on iroh's public relay infrastructure and on carrier NAT behaviour.
It can fail for reasons unrelated to this codebase. A red tier 3 must be a
signal to investigate, never a merge blocker — otherwise someone else's relay
outage stops your work. Promote to blocking only after observing its real flake
rate over weeks.

### Why tier 2 can block

The Jetson is on the same LAN as the runner and needs no external
infrastructure. Its failure modes are local and diagnosable.

## Tier 2 design (the new automated tier)

**Venue.** The Jetson registers as a GitHub Actions self-hosted runner, labelled
`[self-hosted, jetson]`. The existing hermetic matrix is untouched; tier 2 is a
separate job.

**The second identity.** Rather than depend on the Mac being online, the Jetson
pairs against a *second identity on itself* using a scratch `HOME` +
`XDG_RUNTIME_DIR` — the mechanism `docs/loopback.md` already documents and
`docs/loopback.sh` already automates. Both daemons bind real interfaces and dial
over the real stack, so this is meaningfully different from in-process localhost
tests. It removes the Mac as a dependency and makes the job self-contained.

> **Honest limitation, stated in the job output:** same-host identities share a
> NIC. This tier proves the porcelain works over real interfaces and real
> discovery; it does **not** prove NAT traversal. That is tier 3's job, and the
> job log must say so, so a green tier 2 is never read as NAT coverage.

**What it asserts** (the porcelain path, not the transport):

1. `serve` + `invite` + `pair` complete; the SAS matches on both sides.
2. `status` reports the peer **online with an RTT within 30s of pairing** — the
   assertion that would have caught the cold-probe bug. The bound is derived,
   not invented: `REACH_TTL_SECS` is 20s, so a stale entry is refreshed on the
   next read, and `PROBE_TIMEOUT` is 3s; 30s allows one full TTL cycle plus a
   probe and still fails loudly on the pre-fix behaviour, where the peer stayed
   `offline` indefinitely on the redeemer side.
3. A real `tools/call` returns the peer's file (not just `initialize`).
4. A second session establishes (path is reusable, not a one-shot).
5. `pair --remove` severs access: a subsequent dial fails cleanly.
6. Nickname-squatting is refused (the `d525c06` guard, over a real network).
7. Cleanup leaves no daemons, identities, or config behind.

**Entry point.** One script, parameterized by env var so the same code serves
manual runs and CI:

```sh
MM=… PEER=… INVITE_FILE=… NOTE_PATH=… sh docs/e2e-real.sh
```

`/Users/john/xnat-test.sh` from the 2026-07-20 session is the working prototype
and should be moved into the repo as the basis for this.

## Tier 3 design (cross-NAT, nightly)

Same script, different peer. Two viable peers, in preference order:

1. **GitHub-hosted runner** (`ubuntu-latest`, Azure) paired with the self-hosted
   Jetson — two genuinely different networks, no extra cost or hardware. Requires
   passing an invite line between jobs (job output or artifact) and tolerating
   startup skew.
2. **Manual hotspot run** — a human switches a machine to a phone hotspot. This
   is what found the bug and remains the *best* probe, because carrier-grade NAT
   is the case where hole-punching most often fails and relay fallback must
   carry the session. It cannot be automated; keep it as a documented
   pre-release step.

Tier 3 additionally asserts **cold-probe timing**: after pairing, `status` must
report the peer online within a bounded window. That is the specific regression
the 2026-07-20 bug would have tripped.

## What this does not cover (deliberate, ranked)

These remain open after this work. Listed so their absence is a decision, not an
oversight:

1. **Windows control plane.** `cli/tests/harness/mod.rs` and the daemon e2e
   suites are `#![cfg(unix)]` — they reconstruct a filesystem socket path a named
   pipe cannot provide. CI runs `windows-latest`, but these compile out there, so
   the platform whose security mechanism is entirely different (owner-only DACL)
   gets only unit-level coverage. Already acknowledged in-repo as the "Task 6
   Windows coverage gap".
2. **Fuzzing the untrusted parsers.** The pair ALPN is documented gate-exempt and
   parses `RedeemerHello` from unauthenticated strangers; the codec parses
   untrusted frames under a 16 MiB cap. No fuzz targets, no proptest. Highest
   risk-per-effort remaining, because it is adversarial input on the trust
   boundary.
3. **Cross-version compatibility.** `b973b79` shipped a breaking wire and config
   change. Nothing verifies an old client meets a new daemon and fails *cleanly*
   rather than hanging, nor that orphaned redb rows are "skipped and logged" as
   claimed.
4. **Chaos.** Peer vanishing mid-session, relay outage, daemon restart with live
   sessions.
5. **Performance baselines.** No benches; a throughput or latency regression is
   invisible until a user notices.

## Implementation order

1. Move the prototype script into the repo as `docs/e2e-real.sh`, parameterized,
   with the tier-2 assertions above. Runnable by hand immediately.
2. Register the Jetson as a self-hosted runner; add the non-blocking tier-2 job.
3. Observe for a week; make tier 2 blocking once stable.
4. Add tier 3 nightly against a GitHub-hosted peer, non-blocking.
5. Revisit the deferred list, starting with fuzzing.

## Success criteria

- A bug of the 2026-07-20 class (porcelain-visible, real-network-only) is caught
  automatically rather than by a human on a hotspot.
- Every real-network bug gets a hermetic regression test, so tier 1 grows and the
  slow tiers stay discovery-only.
- No tier's green check is mistaken for coverage it does not have — each job
  states its limitation in its own output.
