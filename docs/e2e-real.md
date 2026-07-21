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

Tier 2 also runs automatically: `.github/workflows/real-network.yml` fires this
script on every same-repo pull request on the self-hosted Jetson runner,
non-blocking until its flake rate is known.

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

Remote mode hard-requires `PEER`, `NOTE_PATH`, and `INVITE_FILE` — a missing one
fails fast, before any state is touched, naming which one you forgot. Two
details the peer side must get right or the run false-FAILs:

- The file at `NOTE_PATH`, on the **peer's** machine, must contain exactly
  `e2e sentinel: this note crossed the mesh` — that literal line is what
  assertion 4 greps for. Easiest: `echo 'e2e sentinel: this note crossed the
  mesh' > ~/notes/hello.md` on the peer side.
- `NOTE_PATH` is spliced raw into a JSON `tools/call` payload, so no
  double-quotes or backslashes in the path.

Use a dedicated test nickname for `PEER`, not one you actually pair with day to
day: the run's last assertion unpairs `$PEER`, and — since that would destroy
real state — the harness refuses to start at all (exit 2) if a peer by that
name is already paired. In remote mode, the run therefore always ends
*unpaired*: the far side keeps serving, but your local pairing to it is gone
once the script finishes. Re-pair before using that peer again for real.

## What it asserts

1. Pairing completes.
2. The safety code matches on both sides (local mode only — remote has no way to read the peer's screen).
3. `status` reports the peer online within 30s of pairing. **This is the `049877b` regression guard**: before that fix the redeemer's cold probe blew the 3s `PROBE_TIMEOUT` and reported a freshly-paired peer offline.
4. A real `tools/call` returns the peer's file — not merely `initialize` (this is two checks: the `initialize` round-trip and the `tools/call` result, so a full run prints 8 `PASS` lines against this 7-item list).
5. A second session establishes.
6. A nickname-squatting invite is refused (local mode only).
7. `pair --remove` severs access.

## What it does NOT prove

- **Tier 2 does not prove NAT traversal.** Two identities on one host share a
  NIC. Relay bootstrap and hole-punching are tier 3's job.
- **Tier 2 cannot catch a cold-probe regression, even though it runs the
  assertion.** During implementation we reverted `049877b`, rebuilt, restarted
  the daemon from the reverted binary, and re-ran this script — assertion 3
  still passed, peer online in ~2s. Same-host discovery resolves the bare-id
  dial far inside the 3s `PROBE_TIMEOUT`, so the bug that motivated this whole
  suite is structurally invisible in local mode. The guard is only meaningful
  on tier 3 (or better, cross-NAT) runs — which is where the original bug was
  actually found, carrier NAT to carrier NAT.
- Nothing here covers Windows: the porcelain is driven through a POSIX shell
  script.
- A green run says nothing about throughput or memory — see `docs/load-soak.md`.
