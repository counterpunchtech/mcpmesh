# Try it alone: the loopback walkthrough

The [README quick start](../README.md#-quick-start) assumes two machines. You don't need two to
evaluate mcpmesh — you need two *identities*, and a daemon's whole world (keys, config, control
endpoint) lives under `HOME` + `XDG_RUNTIME_DIR`. Point those somewhere fresh and you have a
complete second identity — a pretend friend — on the machine you're sitting at.

Nothing in this walkthrough is mocked: the friend mints real keys, hands you a real one-time
invite, and your session to their notes server is the same end-to-end-encrypted session two
machines would run. The only pretend part is that both ends are you.

**Requirements:** macOS or Linux, `mcpmesh` on `PATH`, and `npx` (the demo shares the standard
filesystem MCP server; substitute any MCP server you like). On Windows the same idea works by
overriding the `XDG_*` variables instead of `HOME` — but the script below is a Unix shell script,
so on Windows follow the two-machine flow or use WSL.

## The one-command version

From a checkout:

```sh
sh docs/loopback.sh
```

The script does everything below, prints the safety code and a live proof frame, and ends by
telling you how to clean up. The rest of this page is the same flow step by step, so you can see
there is no magic in it.

## Step by step

### 0. Give the friend a world

```sh
FRIEND_HOME=$HOME/.mcpmesh-demo-friend
mkdir -p $FRIEND_HOME/notes $FRIEND_HOME/runtime $FRIEND_HOME/.config/mcpmesh
echo "It worked: this note reached you through the mesh." > $FRIEND_HOME/notes/hello.md
printf '[identity]\nnickname = "demo-friend"\n' > $FRIEND_HOME/.config/mcpmesh/config.toml
```

Keep this under `$HOME`, not `/tmp` or `$TMPDIR`. On macOS both resolve through a symlink
(`/tmp` → `/private/tmp`), and the filesystem MCP server compares its allowed directory against a
realpath-resolved argument — so every path in step 4 would come back "outside allowed directories".

The `nickname` line names the friend. Without it they would introduce themselves by this machine's
hostname — the same name *your* daemon uses, which makes for a confusing demo. (That key, and every
other config key, is documented in the [configuration reference](config.md).)

A shell helper keeps the rest readable — `friend <cmd>` runs any command in the friend's world:

```sh
friend() { HOME=$FRIEND_HOME XDG_RUNTIME_DIR=$FRIEND_HOME/runtime "$@"; }
```

### 1. The friend serves and invites

```sh
friend mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem $FRIEND_HOME/notes
friend mcpmesh invite notes
```

Exactly the two commands from the quick start, just prefixed with `friend`. The first porcelain
verb auto-starts the friend's own daemon (independent of yours — different keys, different
everything). `invite` prints a one-time `mcpmesh-invite:…` line.

> The script instead starts the friend's daemon explicitly (`friend mcpmesh internal daemon &`) so
> it holds a PID to hand you for cleanup. Either way works.

### 2. You redeem it

In your **normal** environment — no `friend` prefix, this is your real identity:

```sh
mcpmesh pair mcpmesh-invite:…        # paste the whole line the friend printed
```

`pair` prints the safety code and the exact commands to mount `demo-friend/notes` in Claude Code or
Claude Desktop. From here you are in the standard two-machine flow.

### 3. Both sides confirm the code

Normally you'd read the code to your friend out loud. Here you can play both parts: your `pair`
output showed the code, and the friend — as the inviter — sees the same words under **recent
pairings**:

```sh
friend mcpmesh status      # "recent pairings: … code: tango-fig-cabbage"
```

Matching words are what a real pairing ceremony checks.

### 4. Prove a live exchange end to end

Mount it in your AI client (`mcpmesh use demo-friend/notes` prints the steps), or prove the pipe
with raw MCP frames — an `initialize`, then an actual tool call that reads the friend's note:

```sh
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"loopback-demo","version":"0.0.0"}}}'
  sleep 20
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"'"$FRIEND_HOME"'/notes/hello.md"}}}'
  sleep 12
} | mcpmesh connect demo-friend/notes
```

The reply to `id:2` carries the text of `hello.md`. That is the part worth watching: `initialize`
alone only proves the session opened, whereas the tool call proves a real request travelled to the
friend's server and their file content came back over the encrypted link — the same path a request
from another machine would take. (The `sleep`s cover the first dial, which can take a moment while
`npx` fetches the server.)

## Cleaning up

```sh
mcpmesh pair --remove demo-friend      # your side forgets the friend
kill <friend-daemon-pid>               # the script printed this line for you
rm -rf $FRIEND_HOME                    # the friend's world, keys and all
```

If you followed the manual steps (where the friend's daemon was auto-started rather than started
with a recorded PID), find it with `pgrep -fl "mcpmesh internal daemon"` — you'll see yours too;
the friend's is the one whose start time matches this walkthrough.

## Why the naive attempt fails

The tempting one-daemon shortcut — `mcpmesh invite` followed by `mcpmesh pair` in the same
environment — fails: a daemon cannot pair with itself (there is only one identity in play, and
self-granting would be meaningless). The second `HOME`/`XDG_RUNTIME_DIR` is what makes it two
identities, and everything downstream ordinary.
