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

Tier 2 — a scratch `HOME` on this machine is the second identity. You need a
release build (`cargo build --release`) and `npx` (Node) on `PATH` for the demo
filesystem server first — the script fails fast on either being missing, but
building up front saves the round trip:

```sh
MM=./target/release/mcpmesh sh docs/e2e-real.sh
```

Tier 3 — pair with an invite minted on a machine on a different network.

### On the peer's machine, first

This side never sees the peer's machine, so it can't set this up for you — do
it there before touching the redeemer commands below:

```sh
mkdir -p ~/notes
echo 'e2e sentinel: this note crossed the mesh' > ~/notes/hello.md
mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
mcpmesh invite notes | grep -o 'mcpmesh-invite:[A-Za-z0-9]*' > invite.txt
```

- **The service must be named exactly `notes`** — the script hardcodes
  `connect "$PEER/notes"`.
- **The sentinel line must be exact, byte for byte**: `e2e sentinel: this note
  crossed the mesh`. That's what assertion 3's `tools/call` greps for.
- **`invite.txt` must hold only the bare token**, nothing else. The redeemer
  side reads it with `INVITE=$(cat "$INVITE_FILE")`, which strips trailing
  blank lines but not a leading one or any surrounding prose — a file holding
  `invite`'s full human-readable output (the `Share it out-of-band:` framing,
  etc.) breaks decoding. Piping through `grep -o` as above, rather than pasting the
  command's output, is what keeps the file to just the token.
- **Keep this `serve` process (and its daemon) running** for the whole run —
  the redeemer dials it live from `pair` itself (assertion 1) through
  assertion 4.
- Note this identity's nickname (`~/.config/mcpmesh/config.toml`'s
  `[identity] nickname`, or whatever it already resolves to without one) —
  that exact name is what the redeemer must pass as `PEER` below. Copy
  `invite.txt` over to the redeemer's machine.

Then, on the redeemer's machine:

```sh
PEER_MODE=remote PEER=their-nickname \
INVITE_FILE=./invite.txt NOTE_PATH=/home/them/notes/hello.md \
MM=./target/release/mcpmesh sh docs/e2e-real.sh
```

Remote mode hard-requires `PEER`, `NOTE_PATH`, and `INVITE_FILE` — a missing
one fails fast, before any state is touched, naming which one you forgot.

- `PEER` must equal the peer's real nickname exactly: `pair` redeems the
  invite under the name the invite itself carries, not whatever you happen to
  pass. Get this wrong and pairing still succeeds under their real name, but
  every later step that references `$PEER` — the reachability check, both
  `connect` calls, and cleanup — is looking for a name that was never paired.
  Assertion 2 fails after the full 30s wait, and cleanup's
  `pair --remove "$PEER"` removes nothing, leaving a real (mis-tracked)
  pairing behind.
- `NOTE_PATH` is the sentinel file's path as the **peer's own** filesystem
  server sees it — here, `/home/them/notes/hello.md` on their disk, not yours
  — and it's spliced raw into a JSON `tools/call` payload, so no
  double-quotes or backslashes in it.

Use a dedicated test nickname for `PEER`, not one you actually pair with day to
day: the run's last assertion unpairs `$PEER`, and — since that would destroy
real state — the harness refuses to start at all (exit 2) if a peer by that
name is already paired. In remote mode, the run therefore always ends
*unpaired*: the far side keeps serving, but your local pairing to it is gone
once the script finishes. Re-pair before using that peer again for real.

## What it asserts

The script prints six numbered banners but eight `PASS` lines in local mode —
banners 1 and 3 each cover two checks. (Remote mode prints six: the two
local-only checks are skipped.)

1. `pair` completes, **and** the safety code matches on both sides (local
   mode only — remote has no way to read the peer's screen).
2. `status` reports the peer online within 30s of pairing. **This is the
   `049877b` regression guard**: before that fix the redeemer's cold probe
   blew the 3s `PROBE_TIMEOUT` (`cli/src/daemon/reach.rs`) and reported a
   freshly-paired peer offline.
3. A real `tools/call` returns the peer's file, **and** the `initialize`
   round-trip that precedes it succeeds — not merely `initialize` alone.
4. A second session establishes (session reuse).
5. A nickname-squatting invite is refused (local mode only).
6. `pair --remove` severs access.

### Asserting the safety code

Since 0.6.1 every verb takes `--json`, so the SAS assertion needs no prose scraping:
the redeemer reads `.sas_code` from `mcpmesh --json pair …`, the inviter reads the
newest `.recent_pairings[].sas_code` from `mcpmesh --json status`, and the harness
string-compares the two. A match is a real man-in-the-middle assertion — strictly
stronger than skipping the ceremony (pairing completes either way; the check is
advisory authenticity). Outside automated runs the human read-aloud ceremony remains
the norm. In remote mode the runner cannot read the peer's screen; if the peer end is
scriptable (ssh), fetch its `--json status` and make the same comparison — otherwise
the check stays local-mode-only, as today.

## What it does NOT prove

- **Tier 2 does not prove NAT traversal.** Two identities on one host share a
  NIC. Relay bootstrap and hole-punching are tier 3's job.
- **Tier 2 cannot catch a cold-probe regression, even though it runs the
  assertion.** During implementation we reverted `049877b`, rebuilt, restarted
  the daemon from the reverted binary, and re-ran this script — assertion 2
  still passed, peer online in ~2s. Same-host discovery resolves the bare-id
  dial far inside the 3s `PROBE_TIMEOUT`, so the bug that motivated this whole
  suite is structurally invisible in local mode. The guard is only meaningful
  on tier 3 (or better, cross-NAT) runs — which is where the original bug was
  actually found, carrier NAT to carrier NAT.
- **In CI, the redeemer-side daemon is not the build under test.** The tier-2
  job rendezvouses with the Jetson's already-running daemon (one machine, one
  lockable `state.redb` — a second daemon under the same `HOME` cannot start).
  Only the CLI front-end and the scratch peer/squatter daemons run the PR's
  binary; redeemer-side daemon behavior (probing, gate decisions, dialing) is
  whatever the Jetson's installed daemon was built from. A PR that regresses
  only that side can still go green here.
- Nothing here covers Windows: the porcelain is driven through a POSIX shell
  script.
- A green run says nothing about throughput or memory — see `docs/load-soak.md`.
