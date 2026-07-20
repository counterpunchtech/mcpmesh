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

PEER_HOME="$WORK/peer"
PEER_RUN="$PEER_HOME/runtime"

# fd 3 = the real stdout, captured before anything runs. A signal can land
# while a `cmd >/dev/null` is in flight, and dash then runs the trap UNDER
# that redirection (a function call's redirect applies to the parent shell),
# silently swallowing the summary. Writing it to >&3 survives that.
exec 3>&1

# Everything this script created, removed on ANY exit path (success, failure,
# or Ctrl-C). A leaked daemon would hold a stale identity that breaks the NEXT
# run's nickname-collision guard, so cleanup is not optional.
#
# The summary prints from HERE, not the bottom of the script: under set -e an
# unexpected failure aborts mid-script and the trap is the only code guaranteed
# to still run, so even a silent abort reports the score so far. The cleaned_up
# guard keeps it single-shot when a signal trap fires and the EXIT trap then
# fires again for the same termination.
cleaned_up=0
cleanup() {
    # Teardown is best-effort: without set +e, a failed summary echo (e.g.
    # stdout gone after a hangup) would abort before kill/pair-remove/rm.
    set +e
    [ "$cleaned_up" -eq 1 ] && return 0
    cleaned_up=1
    echo "=== $pass passed, $fail failed ===" >&3
    if [ -n "${PEER_PID:-}" ]; then
        kill "$PEER_PID" 2>/dev/null || true
        # Reap it before rm -rf so the daemon is gone, not merely signalled,
        # when its world is deleted out from under it.
        wait "$PEER_PID" 2>/dev/null || true
    fi
    # Targets ONLY the scratch peer's nickname ($PEER, default e2e-peer);
    # real peers paired under other names are untouched.
    "$MM" pair --remove "$PEER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
# Signal traps must exit THEMSELVES: in dash a trap that merely returns hands
# control back to the script body, which would then rebuild the world cleanup
# just tore down (and the guarded EXIT-trap cleanup would no-op, leaking a
# daemon and reporting a false pass). 128+signum keeps conventional codes; the
# cleaned_up guard makes the follow-on EXIT-trap invocation a safe no-op.
trap cleanup EXIT
trap 'cleanup; exit 129' HUP
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

peer() { HOME="$PEER_HOME" XDG_RUNTIME_DIR="$PEER_RUN" "$MM" "$@"; }

# Task 6 will generalize this into a start_scratch_daemon <subdir> <nickname>
# helper for the squatter identity; note cleanup currently kills only PEER_PID.
setup_local_peer() {
    command -v npx >/dev/null 2>&1 || { echo "error: npx not found — needed for the demo notes server" >&2; exit 2; }
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
        [ "$i" -gt 150 ] && { echo "peer daemon did not start" >&2; exit 1; }
        sleep 0.2
    done
    peer serve notes -- npx -y @modelcontextprotocol/server-filesystem \
        "$PEER_HOME/notes" >/dev/null
}

echo "=== mcpmesh real-network e2e ($PEER_MODE) ==="
"$MM" --version

rm -rf "$WORK"
# A prior run that died without its traps (kill -9) can leave the $PEER
# pairing in the REAL store, tripping the nickname-collision guard on this
# run. Removes ONLY $PEER (e2e-peer) — never the user's real peers.
"$MM" pair --remove "$PEER" >/dev/null 2>&1 || true
if [ "$PEER_MODE" = "local" ]; then
    echo "--- standing up the local peer identity ---"
    setup_local_peer
    peer status | sed -n '1,4p'
fi

# Sets the script's exit status; the EXIT trap prints the summary and cleans
# up, and dash preserves this status through the trap.
[ "$fail" -eq 0 ]
