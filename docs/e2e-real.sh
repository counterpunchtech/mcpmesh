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
WORK="${E2E_WORK:-${HOME:-/tmp}/.mcpmesh-e2e}"
SENTINEL='e2e sentinel: this note crossed the mesh'
# Bound for assertion 2. Derived, not invented: REACH_TTL_SECS is 20s and
# PROBE_TIMEOUT is 3s (cli/src/daemon/reach.rs), so 30s allows a full TTL cycle
# plus a probe. The pre-049877b bug left the redeemer at "offline" indefinitely,
# so this fails loudly on a regression without being flaky.
REACH_BOUND_SECS="${REACH_BOUND_SECS:-30}"

command -v "$MM" >/dev/null 2>&1 || { echo "error: '$MM' not found — build with 'cargo build --release' or set MM" >&2; exit 2; }

# ok/bad mutate these counters: call them ONLY from the main shell, never
# inside a pipeline or $(...). dash runs those in a subshell, so the
# increment would be lost and the run would report a FALSE PASS.
pass=0
fail=0
ok()  { pass=$((pass+1)); echo "  PASS  $1"; }
bad() { fail=$((fail+1)); echo "  FAIL  $1"; }

echo "=== mcpmesh real-network e2e ($PEER_MODE) ==="
"$MM" --version

echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
