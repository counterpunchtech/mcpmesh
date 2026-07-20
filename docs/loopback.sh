#!/bin/sh
# Try mcpmesh alone, on one machine — no second machine, no friend required.
#
# The trick: a daemon's whole world (keys, config, control endpoint) lives under
# HOME + XDG_RUNTIME_DIR, so a scratch HOME is a complete second identity. This
# script stands up that "pretend friend", has them serve a folder of notes and
# mint a real invite, then redeems it as YOU — the same flow two machines run,
# end to end: real keys, a real one-time invite, a real encrypted session.
#
# The guided walkthrough of exactly these steps is docs/loopback.md.
# macOS/Linux. Requires: mcpmesh on PATH, and npx (for the demo notes server).
set -eu

command -v mcpmesh >/dev/null || { echo "mcpmesh is not on PATH — install it first (see README)" >&2; exit 1; }
command -v npx >/dev/null || { echo "npx is not on PATH — the demo shares a Node-based notes server" >&2; exit 1; }

# Deliberately under $HOME, not /tmp or $TMPDIR: on macOS both resolve through a
# symlink (/tmp → /private/tmp, $TMPDIR → /private/var/...), and the filesystem MCP
# server compares its allowed directory against a realpath-resolved argument — so
# every path in step 5 would come back "outside allowed directories".
FRIEND_HOME="${FRIEND_HOME:-$HOME/.mcpmesh-demo-friend}"
FRIEND_RUN="$FRIEND_HOME/runtime"

# Run any command as the pretend friend: same binary, different world.
friend() { HOME="$FRIEND_HOME" XDG_RUNTIME_DIR="$FRIEND_RUN" "$@"; }

# The friend's world: a folder of notes to share, and a name they go by
# (without a nickname the friend would introduce themselves by this machine's
# hostname — same as yours, which makes a confusing demo).
mkdir -p "$FRIEND_HOME/notes" "$FRIEND_RUN" "$FRIEND_HOME/.config/mcpmesh"
echo "It worked: this note reached you through the mesh." > "$FRIEND_HOME/notes/hello.md"
printf '[identity]\nnickname = "demo-friend"\n' > "$FRIEND_HOME/.config/mcpmesh/config.toml"

# 1. The friend's daemon, in the background. (Yours auto-starts when you pair.)
echo "==> starting the demo friend's daemon"
friend mcpmesh internal daemon &
FRIEND_PID=$!
i=0
until [ -S "$FRIEND_RUN/mcpmesh/mcpmesh.sock" ]; do
    i=$((i + 1))
    [ "$i" -gt 50 ] && { echo "the friend's daemon did not start" >&2; exit 1; }
    sleep 0.2
done

# 2. The friend shares their notes folder and mints a one-time invite.
echo "==> the friend serves their notes and mints an invite"
friend mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem "$FRIEND_HOME/notes"
INVITE=$(friend mcpmesh invite notes | grep -o 'mcpmesh-invite:[^ ]*')

# 3. YOUR identity (your normal environment) redeems it — the same command a
#    real friend would run with an invite you sent them.
echo "==> you redeem it"
mcpmesh pair "$INVITE"

# 4. Prove a live MCP exchange end to end: initialize the friend's server through
#    the mesh, then actually CALL a tool and read the note back. Initialize alone
#    only proves the session opened; the tools/call is what proves a real request
#    reached the friend's server and returned their data over the encrypted link.
#    (The first dial can take a moment while npx fetches the server, hence the waits.)
echo "==> proving a live end-to-end MCP exchange (initialize + a real tool call)"
mcp_exchange() {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"loopback-demo","version":"0.0.0"}}}'
    sleep 20
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"'"$FRIEND_HOME"'/notes/hello.md"}}}'
    sleep 12
}
REPLIES=$(mcp_exchange | mcpmesh connect demo-friend/notes)
echo "$REPLIES" | grep '"id":1' || true

# The note the friend wrote in step 0 — if this text came back, a tool call
# travelled the mesh to their server and their file content came back to us.
if echo "$REPLIES" | grep -q 'this note reached you through the mesh'; then
    echo "==> tool call returned the friend's note — the mesh works end to end"
else
    echo "the tool call did not return the friend's note. Full replies:" >&2
    echo "$REPLIES" >&2
    exit 1
fi

echo
echo "Paired with demo-friend. Explore from here:"
echo "  mcpmesh status                   # see demo-friend + the safety code"
echo "  mcpmesh use demo-friend/notes    # the steps to mount it in your AI client"
echo
echo "Clean up when done:"
echo "  mcpmesh pair --remove demo-friend"
echo "  kill $FRIEND_PID && rm -rf '$FRIEND_HOME'"
