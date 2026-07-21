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
    if [ -n "${SQUAT_PID:-}" ]; then
        kill "$SQUAT_PID" 2>/dev/null || true
        wait "$SQUAT_PID" 2>/dev/null || true
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

echo "--- 1. pair ---"
if [ "$PEER_MODE" = "local" ]; then
    # || true: grep exits 1 when it finds no match (and `peer invite` itself
    # can fail); under set -e either would silently abort the whole script
    # instead of counting as a failed assertion.
    INVITE=$(peer invite notes | grep -o 'mcpmesh-invite:[A-Za-z0-9]*') || true
else
    # An UNSET INVITE_FILE is a usage error: the :? runs in the MAIN shell so
    # it really aborts (inside the $(...) below, || true would rescue it). A
    # set-but-unreadable file falls through to the empty-INVITE check instead.
    : "${INVITE_FILE:?INVITE_FILE required when PEER_MODE=remote}"
    INVITE=$(cat "$INVITE_FILE") || true
fi

if [ -z "${INVITE:-}" ]; then
    # Pairing with an empty string would only produce a confusing usage error;
    # surface the real problem (minting failed) as the failed assertion.
    bad "could not mint an invite"
else
    PAIROUT=$("$MM" pair "$INVITE" 2>&1) || true
    echo "$PAIROUT" | sed -n '1,2p'
    case "$PAIROUT" in
        *"Paired with"*) ok "pairing completed" ;;
        *) bad "pairing failed: $PAIROUT" ;;
    esac

    # The SAS is the security ceremony: both sides must print the SAME words, or a
    # tampered invite would go unnoticed. Comparing them is the point of the code.
    # Format on our side: "Paired with <peer> — code: <words>" (render::pair_lines);
    # on theirs: "  <nick> · code: <words> · <age>" (render::recent_pairing_lines).
    OUR_SAS=$(printf '%s' "$PAIROUT" | sed -n 's/.*code: \([a-z-]*\).*/\1/p')
    if [ "$PEER_MODE" = "local" ]; then
        THEIR_SAS=$(peer status | sed -n 's/.*code: \([a-z-]*\).*/\1/p' | head -1)
        if [ -n "$OUR_SAS" ] && [ "$OUR_SAS" = "$THEIR_SAS" ]; then
            ok "safety code matches on both sides ($OUR_SAS)"
        else
            bad "safety code mismatch: ours='$OUR_SAS' theirs='$THEIR_SAS'"
        fi
    fi
fi

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
) || true
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
) || true
printf '%s' "$R2" | grep -q '"id":1.*result' \
    && ok "second session established" || bad "second session failed"

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
    # Started explicitly (not via serve's auto-start) so we hold its PID:
    # the auto-started daemon's argv is just "internal daemon" — no path —
    # so pkill -f can never find it and it would leak on every run.
    HOME="$SQUAT_HOME" XDG_RUNTIME_DIR="$SQUAT_RUN" "$MM" internal daemon &
    SQUAT_PID=$!
    i=0
    until [ -S "$SQUAT_RUN/mcpmesh/mcpmesh.sock" ]; do
        i=$((i+1))
        [ "$i" -gt 150 ] && { echo "squatter daemon did not start" >&2; exit 1; }
        sleep 0.2
    done
    HOME="$SQUAT_HOME" XDG_RUNTIME_DIR="$SQUAT_RUN" "$MM" serve notes -- \
        npx -y @modelcontextprotocol/server-filesystem "$SQUAT_HOME/notes" >/dev/null 2>&1 || true
    SQUAT_INVITE=$(HOME="$SQUAT_HOME" XDG_RUNTIME_DIR="$SQUAT_RUN" "$MM" invite notes \
        2>/dev/null | grep -o 'mcpmesh-invite:[A-Za-z0-9]*') || true
    if [ -z "${SQUAT_INVITE:-}" ]; then
        bad "could not mint a squatting invite"
    else
        SQUAT_OUT=$("$MM" pair "$SQUAT_INVITE" 2>&1) || true
        case "$SQUAT_OUT" in
            *"already use that name"*) ok "squatting invite refused" ;;
            *) bad "squatting invite was NOT refused: $SQUAT_OUT" ;;
        esac
    fi
    kill "$SQUAT_PID" 2>/dev/null || true
    wait "$SQUAT_PID" 2>/dev/null || true
fi

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

# Sets the script's exit status; the EXIT trap prints the summary and cleans
# up, and dash preserves this status through the trap.
[ "$fail" -eq 0 ]
