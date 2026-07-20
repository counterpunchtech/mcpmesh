<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" width="440" alt="mcpmesh">
  </picture>
</p>

<p align="center"><b>🔗 Share MCP servers with people you trust — peer to peer. No accounts, no cloud.</b></p>

## 🤝 What is this?

**mcpmesh lets your AI use your friends' tools.**

Got an [MCP](https://modelcontextprotocol.io) server running on your machine — your notes, your code
search, your scripts? Share it with a specific person, and their AI client (Claude Desktop, Claude
Code, or anything that speaks MCP) mounts it as if it were local. 🪄

- 🚫 **No hosting.** The server runs on *your* machine. Nothing is uploaded anywhere.
- 🔒 **No middleman.** An end-to-end-encrypted connection straight between your two machines.
- 🙅 **No accounts, no OAuth, nothing to sign up for.**

> 🎬 New here? The [**tech presentation**](https://counterpunchtech.github.io/mcpmesh/presentation.html)
> is a two-minute visual tour of what mcpmesh is and how it works.

## 🚀 Quick start

One minute, two machines — call them `you` and `friend`:

```sh
cargo install mcpmesh    # on both machines (macOS, Linux, or Windows)

# 🖥️  you — share a folder of notes as an MCP server, under a name you pick:
mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
mcpmesh invite notes     # prints a one-time mcpmesh-invite:… line — send it to your friend

# 📩 friend — redeem the invite:
mcpmesh pair mcpmesh-invite:…
```

That's it. ✅ `pair` prints the exact next steps — the safety code to confirm, and the one command
that wires the share into Claude Code (`claude mcp add you-notes -- mcpmesh connect you/notes`) or
the entry to paste into Claude Desktop. (Run `mcpmesh use you/notes` any time to see them again.)

Both of you also see the same short code, like `tango-fig-cabbage`. 🗣️ Read it to each other —
**matching words mean the pairing is authentic.** Now your friend's AI can search your notes over an
encrypted peer-to-peer link, and it works both ways whenever they want to share back.

## 🧪 Try it alone

Only one machine? Fake the friend. A daemon's whole world lives under `HOME` +
`XDG_RUNTIME_DIR`, so a scratch `HOME` is a complete second identity — and the two pair on one
machine exactly as two machines would (macOS/Linux):

```sh
# A real (symlink-free) path — NOT /tmp or $TMPDIR: on macOS both resolve through a symlink
# (/tmp → /private/tmp), and the filesystem MCP server then rejects every path you give it.
FH=$HOME/.mcpmesh-demo-friend; mkdir -p $FH/notes $FH/run && echo hi > $FH/notes/hello.md

# the "friend" serves a folder and mints a real invite under the scratch identity…
HOME=$FH XDG_RUNTIME_DIR=$FH/run mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem $FH/notes
HOME=$FH XDG_RUNTIME_DIR=$FH/run mcpmesh invite notes

# …and YOUR identity redeems it, exactly as a real friend would:
mcpmesh pair mcpmesh-invite:…
```

From `pair` onward you're in the two-machine flow — safety code, mount, connect. Nothing is
mocked: real keys, a real one-time invite, a real encrypted session. The guided version with a
live end-to-end proof and cleanup is [`docs/loopback.md`](docs/loopback.md), or just run
[`docs/loopback.sh`](docs/loopback.sh).

## 🛡️ Why it's safe to try

- **🔐 Default-deny.** Nothing is shared until *you* run `serve` + `invite`. Every grant names
  exactly who gets access, and `mcpmesh pair --remove` cuts a peer off instantly.
- **🕵️ No middleman.** Traffic is end-to-end encrypted, machine to machine
  ([iroh](https://iroh.computer)/QUIC with NAT hole-punching). No account to create, no server of
  ours in the trust path.
- **✋ Tamper-evident invites.** Invites are one-time and expiring, and the spoken safety code
  catches a tampered invite *before* anything is shared.

## 👥 The full walkthrough: Alice and Bob

Two people, two machines. Alice shares an MCP server with Bob; then Bob shares one back. Install on
both machines first — `cargo install mcpmesh`, or via Homebrew on macOS/Linux:

```sh
brew tap counterpunchtech/mcpmesh https://github.com/counterpunchtech/mcpmesh
brew install counterpunchtech/mcpmesh/mcpmesh
```

### 1️⃣ Alice serves a server and invites Bob

mcpmesh doesn't know or care what a server *does* — you register any MCP server under a name you
pick, and that name is how peers refer to it:

```sh
# Everything after `--` is just the command that runs the server;
# "notes" is Alice's alias for it (any name works):
alice$ mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes

alice$ mcpmesh invite notes
One-time invite (expires in 24h). Share it out-of-band:
  mcpmesh-invite:…
Whoever redeems it can access: notes

Next: send them that line over any channel. They redeem it with `mcpmesh pair <line>`,
which prints a short safety code — run `mcpmesh status` to see yours and confirm the two
match, out loud. Same words = the pairing is authentic.
```

💡 Every command tells you what to do next, so you can follow the whole flow without the docs open.

Alice sends that `mcpmesh-invite:…` line to Bob over **any** channel he can paste from — chat,
email, a shared doc. (It's a long line, a couple of KB of text — not one to copy by hand.) The
channel doesn't need to be secure: tampering with the invite makes the next step's code mismatch,
and the invite is one-time and expiring.

### 2️⃣ Bob redeems the invite

```sh
bob$ mcpmesh pair mcpmesh-invite:…
Paired with alice — code: tango-fig-cabbage
Next: confirm this code matches what alice sees, out loud (they see it under `mcpmesh status`).
Same words = the pairing is authentic.

You can now use: alice/notes

Tools from alice run on alice's machine. Treat their output as you would anything else alice sends you.

To use in Claude Code, run:
  claude mcp add alice-notes -- mcpmesh connect alice/notes

To use in Claude Desktop, add this under "mcpServers" in
  ~/Library/Application Support/Claude/claude_desktop_config.json
then quit and restart Claude Desktop:
  "alice-notes": {"command": "mcpmesh", "args": ["connect", "alice/notes"]}

Any other MCP client: add a stdio server with the command `mcpmesh connect alice/notes`.
```

One redemption pairs the two machines **both ways** 🔄 — each side now knows and trusts the other's
device. Access stays one-way until granted: right now Bob can reach `alice/notes`, and Alice can
reach nothing of Bob's.

> ℹ️ "alice" here is *Bob's* nickname for Alice — suggested by the invite, local to Bob. Names in
> mcpmesh are always **your** names for **your** peers, never global identities.

### 3️⃣ Both sides confirm the code 🗣️

Alice checks her side:

```sh
alice$ mcpmesh status
…
recent pairings (confirm the code with the other side):
  bob · code: tango-fig-cabbage · just now
```

Alice and Bob compare codes out loud (or over any channel they already trust). **Same words on both
screens = the pairing is authentic.** ✅ A mismatch means someone tampered with the invite in transit
— unpair and start over. ⚠️ Do this before using the service; it's the whole ceremony.

### 4️⃣ Bob mounts the service in his AI client

Bob follows the instruction `pair` already printed — one command for Claude Code:

```sh
bob$ claude mcp add alice-notes -- mcpmesh connect alice/notes
```

…or the pasted entry for Claude Desktop. (Lost the block? `mcpmesh use alice/notes` prints it
again.) Alice's notes server now appears as a normal local MCP server, and Bob's AI can search it —
every request travels the encrypted P2P session straight to Alice's machine. 🎉

> 📝 Run that command **as printed, with no `--scope`**: it lands in Claude Code's default *local*
> scope and connects right away. Adding `--scope project` instead writes a checked-in `.mcp.json`,
> which Claude Code holds at **pending approval** until someone approves it interactively — a
> sensible guard against servers arriving through a shared repo, but it looks like the mount silently
> failed if you weren't expecting it.

mcpmesh prints these steps rather than editing your AI client's config for you: it's *your* config,
and a line you pasted yourself is one you can find and remove later.

### 5️⃣ Bob shares something back

The same three verbs in the other direction — pairing is already mutual, so Bob just serves,
invites, and Alice redeems:

```sh
bob$   mcpmesh serve code -- npx -y @modelcontextprotocol/server-filesystem ~/projects
bob$   mcpmesh invite code

alice$ mcpmesh pair mcpmesh-invite:…       # Bob's invite this time
Paired with bob — code: quartz-melon-drift
Next: confirm this code matches what bob sees, out loud …

You can now use: bob/code
…
alice$ claude mcp add bob-code -- mcpmesh connect bob/code   # the command `pair` just printed
```

➕ Grants accumulate — this second pairing adds `bob/code` to what Alice may dial without touching
what Bob already had, and nobody's chosen names for their peers change. Repeat with more people and
more services; every grant is explicit and per-service.

### 6️⃣ See and undo everything

```sh
mcpmesh status               # what you serve, to whom; which peers are online (+ RTT); recent pairings; next steps
mcpmesh use alice/notes      # the exact steps to mount a peer's service in your AI client
mcpmesh doctor               # local, read-only health check of this machine's setup
mcpmesh pair --remove alice  # unpair: alice loses access to YOUR services from now on
```

📡 `status` shows a **reachability** line per paired peer — online or offline, with a round-trip time
— so you can see who's actually up before you dial. It's advisory and on-demand (a peer that's off
just reads offline; it never blocks a dial), and it works both ways once you're paired.

🧭 `status` also closes with a **next steps** block — the exact command for whatever this machine can
do from where it is (share something, invite someone to a service nobody can reach yet, redeem an
invite, or mount a peer's service). It's silent when there's nothing to nudge.

## 🏢 For teams: roster mode

Pairing is person-to-person. Roster mode layers team management on the same machinery: an operator
creates an org (`mcpmesh org create`), members join with `mcpmesh join`, and membership lives in a
**signed roster file** you can host on any static web host — the signature is the trust boundary, so
the host, the network, and the gossip layer are all untrusted transport. Revoking a member updates
the roster and severs their live sessions everywhere. The full ceremony (including the fingerprint
confirmations that make it safe) is in the 📘 [operator runbook](docs/operator.md).

## 🧩 What's underneath

| Piece | What it is |
|---|---|
| `mcpmesh` (CLI + daemon) | The binary: porcelain verbs above, plus a per-user daemon it auto-starts |
| `mcpmesh-net` | The transport kernel: iroh/QUIC sessions, accept-time trust gating |
| `mcpmesh-trust` | Keys, signed rosters, device→user bindings — no network code |
| `mcpmesh-codec` | The one NDJSON frame codec both ends of every wire share |
| `mcpmesh-local-api` | The local control API (`mcpmesh-local/1`) clients and plugins build on |

🪪 **Identity is self-sovereign:** devices hold keys that never leave the machine, people are verified
device→user bindings, and the names you see are nicknames *you* chose. By default connections
bootstrap via iroh's public relays; `relay_mode = "custom"` / `discovery_mode = "custom"` in the
[config](docs/config.md) let you self-host both, and `"disabled"` runs fully hermetic
(LAN/localhost only). `mcpmesh doctor` validates whatever combination you configure.

> **⚖️ The trust boundary, in one line:** mcpmesh authenticates *who* you're talking to and encrypts
> the pipe — it does **not** vet *what* a peer's MCP server says. Treat tool output from a peer like
> any content from that person.

## 🛠️ Building on mcpmesh

To **share a tool**, you write an ordinary [MCP](https://modelcontextprotocol.io) server — the same
artifact you'd hand to Claude Desktop — and `serve` it. That works in any language with an MCP SDK,
with no mcpmesh code: the mesh hands your server the **cryptographically verified caller identity**
per call (an env var for a spawned server, an `initialize` `_meta` field for a warm one), so you can
scope what you disclose to *who* is asking.

To **drive the mesh** — a GUI, a launcher, a plugin daemon — talk to the per-user daemon over
`mcpmesh-local/1`: newline-delimited JSON over a same-user local endpoint (a Unix socket on
macOS/Linux, a named pipe on Windows), simple enough to implement in any language. The
[**`mcpmesh-local/1` protocol spec**](docs/local-protocol.md) documents the
framing, the handshake, every method, and the identity contract. Rust clients can depend on the
[`mcpmesh-local-api`](https://crates.io/crates/mcpmesh-local-api) crate directly instead. Runnable
samples of both — the typed Rust client and a dependency-free ~60-line Python client proving the
any-language claim — live in [`local-api/examples/`](local-api/examples).

📺 For a **live view of the mesh**, the daemon exposes an event stream (`subscribe`): an initial
snapshot of active sessions and peer reachability, then per-event telemetry — sessions opening and
closing, per-request latency and byte counts, trust changes — as it happens, enough to render the
mesh in real time. `mcpmesh internal watch` is a thin reference consumer you can run to watch the
stream in a terminal; the [protocol spec](docs/local-protocol.md#live-event-stream) has the frame
shapes.

## 💻 Platform support

macOS, Linux, and Windows 10+ (x86_64 / aarch64). Rust ≥ 1.95 to build from source. On Windows, the
local control plane uses a per-user named pipe with an owner-only DACL instead of a Unix socket —
same-user-only access, enforced by the kernel either way.

## 🚦 Status

**Pre-release.** The wire protocol and config format can still change without migration paths.
🔐 Security reports: knotanotsea@protonmail.com.

📄 License: MIT OR Apache-2.0.
