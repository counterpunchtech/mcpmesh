<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" width="440" alt="mcpmesh">
  </picture>
</p>

<p align="center"><b>Share MCP servers with people you trust — peer to peer, no accounts, no cloud.</b></p>

mcpmesh lets your AI use your friends' tools. Take any
[MCP](https://modelcontextprotocol.io) server running on your machine — your notes, your code
search, your scripts — and share it with a specific person; their AI client (Claude Desktop, or
anything that speaks MCP) mounts it as if it were local. No hosting, no OAuth, nothing published
to the internet: an end-to-end-encrypted connection straight between your two machines.

Check out the [tech presentation](https://counterpunchtech.github.io/mcpmesh/presentation.html)
for a quick tour of what mcpmesh is and how it works.

## Quick start

One minute, two machines — call them `you` and `friend`:

```sh
cargo install mcpmesh    # on both machines (macOS/Linux)

# you — share a folder of notes as an MCP server, under a name you pick:
mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
mcpmesh invite notes     # prints a one-time mcpmesh-invite:… line — send it to your friend

# friend — redeem the invite, then plug the share into Claude Desktop:
mcpmesh pair mcpmesh-invite:…
mcpmesh setup claude you/notes
```

Both sides now see the same short code (like `tango-fig-cabbage`). Read it to each other —
matching words mean the pairing is authentic. That's it: your friend's AI can search your notes
over an encrypted peer-to-peer link, and the pairing works both ways when they want to share back.

## Why it's safe to try

- **Default-deny.** Nothing is shared until you run `serve` + `invite`, every grant names exactly
  who gets access, and `mcpmesh pair --remove` cuts a peer off instantly.
- **No middleman.** Traffic is end-to-end encrypted, machine to machine
  ([iroh](https://iroh.computer)/QUIC with NAT hole-punching). No account to create, no server of
  ours in the trust path.
- **Tamper-evident invites.** Invites are one-time and expiring, and the spoken safety code
  catches a tampered invite before anything is shared.

## The full walkthrough: Alice and Bob

Two people, two machines. Alice will share an MCP server with Bob; then Bob will share one back.
Install on both machines first (`cargo install mcpmesh` as above, or via Homebrew:
`brew tap counterpunchtech/mcpmesh https://github.com/counterpunchtech/mcpmesh && brew install --HEAD counterpunchtech/mcpmesh/mcpmesh`).

### 1. Alice serves an MCP server and invites Bob

mcpmesh doesn't know or care what a server does — you register any MCP server under a name you
pick, and that name is how peers refer to it:

```sh
# Everything after `--` is just the command that runs the server;
# "notes" is Alice's alias for it (any name works):
alice$ mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes

alice$ mcpmesh invite notes
One-time invite (expires in 24h). Share it out-of-band:
  mcpmesh-invite:…
Whoever redeems it can access: notes
```

Alice sends that `mcpmesh-invite:…` line to Bob over any channel — chat, email, a sticky note.
The channel doesn't need to be secure: tampering with the invite makes the next step's code
mismatch, and the invite is one-time and expiring.

### 2. Bob redeems the invite

```sh
bob$ mcpmesh pair mcpmesh-invite:…
Paired with alice — code: tango-fig-cabbage
Confirm this code matches what alice sees. You can mount: alice/notes
```

One redemption pairs the two machines **both ways** — each side now knows and trusts the other's
device. Access stays one-way until granted: right now Bob can reach `alice/notes`, and Alice can
reach nothing of Bob's.

("alice" here is Bob's petname for Alice — suggested by the invite, local to Bob. Names in
mcpmesh are always *your* names for *your* peers, never global identities.)

### 3. Both sides confirm the code

Alice checks her side:

```sh
alice$ mcpmesh status
…
recent pairings (confirm the code with the other side):
  bob · code: tango-fig-cabbage · just now
```

Alice and Bob compare codes out loud (or over any channel they already trust). **Same words on
both screens = the pairing is authentic.** A mismatch means someone tampered with the invite in
transit — unpair and start over. Do this before using the service; it's the whole ceremony.

### 4. Bob mounts the service in his AI client

```sh
bob$ mcpmesh setup claude alice/notes
```

That writes Claude Desktop's config so Alice's notes server appears as a normal local MCP server
(for any other MCP client, add `--print` and paste the entry into that client's config). Bob's AI
can now search Alice's notes — every request travels the encrypted P2P session straight to
Alice's machine.

### 5. Bob shares something back

The same three verbs in the other direction — pairing is already mutual, so Bob just serves,
invites, and Alice redeems:

```sh
bob$   mcpmesh serve code -- npx -y @modelcontextprotocol/server-filesystem ~/projects
bob$   mcpmesh invite code

alice$ mcpmesh pair mcpmesh-invite:…       # Bob's invite this time
Paired with bob — code: quartz-melon-drift
Confirm this code matches what bob sees. You can mount: bob/code
alice$ mcpmesh setup claude bob/code
```

Grants accumulate — this second pairing adds `bob/code` to what Alice may dial without touching
what Bob already had, and nobody's chosen names for their peers change. Repeat with more people
and more services; every grant is explicit and per-service.

### 6. See and undo everything

```sh
mcpmesh status               # what you serve, to whom; what you can reach; recent pairings
mcpmesh doctor               # local, read-only health check of this machine's setup
mcpmesh pair --remove alice  # unpair: alice loses access to YOUR services from now on
```

## For teams: roster mode

Pairing is person-to-person. Roster mode layers team management on the same machinery: an operator
creates an org (`mcpmesh org create`), members join with `mcpmesh join`, and membership lives in a
**signed roster file** you can host on any static web host — the signature is the trust boundary,
so the host, the network, and the gossip layer are all untrusted transport. Revoking a member
updates the roster and severs their live sessions everywhere. The full ceremony (including the
fingerprint confirmations that make it safe) is in the
[operator runbook](docs/operator.md).

## What's underneath

| Piece | What it is |
|---|---|
| `mcpmesh` (CLI + daemon) | The binary: porcelain verbs above, plus a per-user daemon it auto-starts |
| `mcpmesh-net` | The transport kernel: iroh/QUIC sessions, accept-time trust gating |
| `mcpmesh-trust` | Keys, signed rosters, device→user bindings — no network code |
| `mcpmesh-codec` | The one NDJSON frame codec both ends of every wire share |
| `mcpmesh-local-api` | The local control API (`mcpmesh-local/1`) clients and plugins build on |

Identity is self-sovereign:
devices hold keys that never leave the machine, people are verified device→user bindings, and
names you see are petnames *you* chose. By default connections bootstrap via iroh's public relays;
`relay_mode = "custom"` / `discovery_mode = "custom"` in the config let you self-host both, and
`"disabled"` runs fully hermetic (LAN/localhost only). `mcpmesh doctor` validates whatever
combination you configure.

**The trust boundary, in one line:** mcpmesh authenticates *who* you're talking to and encrypts
the pipe — it does not vet *what* a peer's MCP server says. Treat tool output from a peer like
any content from that person.

## Platform support

macOS and Linux (x86_64 / aarch64). Rust ≥ 1.95 to build from source. Windows is not supported
(the local-socket security model is built on Unix peer credentials) and is not planned for v1.

## Status

Pre-release. The wire protocol and config format can still change without migration paths.
Security reports: security@runbolo.com.

License: MIT OR Apache-2.0.
