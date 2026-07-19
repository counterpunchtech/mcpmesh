# mcpmesh configuration reference

Every table and key the daemon reads from `config.toml`, with its default. The file lives at:

- **macOS/Linux:** `~/.config/mcpmesh/config.toml` (`$XDG_CONFIG_HOME/mcpmesh/config.toml` when that
  var is set, non-empty, and absolute)
- **Windows:** `%APPDATA%\mcpmesh\config.toml` (an absolute `XDG_CONFIG_HOME` override still wins)

> **You rarely hand-edit this file.** The porcelain writes it: `serve` writes `[services.<name>]`,
> each pairing appends the new peer to the granted `allow` lists, and `org create` / `join` pin the
> `[identity]` and `[roster]` anchors. Hand-editing is for the tunables — `[network]` self-hosting,
> `[limits]`, the `[roster]` timing knobs, and `[identity].petname`. Restart the daemon after
> editing (`mcpmesh status` auto-starts it), and run `mcpmesh doctor` to lint what you changed.

**Loading rules.** A missing file means all defaults (a fresh machine needs no config). A malformed
file is an **error** — the daemon never silently reverts your choices to defaults. Unknown keys are
ignored, so a config written by a newer version still loads.

**Durations** (`grace_period`, `poll_interval`, `max_staleness`) are a number with a
`d`/`h`/`m`/`s` suffix, or bare seconds: `"72h"`, `"30m"`, `"1d"`, `"3600"`. An unparseable value
falls back to that key's default — a typo never disables a freshness bound.

---

## `[identity]`

| Key | Default | Meaning |
|---|---|---|
| `petname` | this machine's short hostname (else a short fingerprint of the device identity) | The name this device suggests for itself in the invites it mints — what your peers will call you unless they rename you. Set it when your hostname isn't the name you want to go by. |
| `device_key` | `<config-dir>/device.key` | Path to this device's private key. Minted on first run, `0600`, never leaves the machine. |
| `org_id` | *(unset)* | Roster mode: the org this node joined. Pinned by `org create` / `join` — do not hand-edit. |
| `org_root_pk` | *(unset)* | Roster mode: the pinned org-root public key (`b64u:…`) — the single trust anchor roster signatures verify against. Pinned on first install / `join` — do not hand-edit. |
| `user_id` | *(unset)* | Roster mode: this person's stable id in the org, spanning all their devices. Pinned at `join` — do not hand-edit. |
| `user_key` | `<config-dir>/user.key` | Path to this person's user key (binds their devices together; per machine, never moves). |

`<config-dir>` is the directory the config itself lives in (above).

## `[network]`

The self-hosting knobs (spec §10.3) — the full procedure and the "self-host both or neither" rule
are in the [operator runbook §5](operator.md#5-self-hosting-relay--discovery-103).

| Key | Default | Meaning |
|---|---|---|
| `relay_mode` | `"default"` | `"default"` (public infrastructure) \| `"custom"` (your own relays — requires `relay_urls`) \| `"disabled"` (**hermetic**: no relay AND no discovery; localhost/LAN only). |
| `relay_urls` | `[]` | Your self-hosted relay URLs. Required when `relay_mode = "custom"`. |
| `discovery_mode` | `"default"` | `"default"` \| `"custom"` (your own discovery service — requires `discovery_urls`). Ignored when `relay_mode = "disabled"`. |
| `discovery_urls` | `[]` | Your self-hosted discovery URLs, used for both publishing and resolving peer addresses. Required when `discovery_mode = "custom"`. |

An unknown mode, or a `"custom"` mode without its URL list, is a **startup error** — the daemon
refuses to run rather than silently falling back to public infrastructure.

## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_per_min` | `120` | Per-peer request rate (token bucket; this value is also the burst allowance). An over-limit request is refused with a retry hint — never served. |
| `max_sessions` | `4` | Per-service cap on concurrently spawned sessions for a `run` service (a `socket` service is one warm process that manages its own concurrency). `0` is floored to `1`. |
| `max_inflight` | `16` | Reserved: parsed and accepted, not yet enforced at this release. |

The 16 MiB per-frame cap is deliberately **not** configurable — it is a fixed constant at every
wire.

## `[roster]`

Roster-mode (team) tunables — see the [operator runbook](operator.md) for the ceremonies these
serve. All four are safe to hand-edit; the durations use the format above.

| Key | Default | Meaning |
|---|---|---|
| `grace_period` | `"72h"` | How long a roster past its `expires_at` keeps serving (degraded, with warnings) before the node stops granting roster identity. Advisory — revocation is enforced regardless of degraded state. |
| `url` | *(unset)* | The pinned HTTPS roster URL — the joiner's first-roster bootstrap and the ongoing currency beacon. Set by `org create --roster-url` and carried in the org invite; `mcpmesh doctor` warns when roster mode has none. |
| `poll_interval` | `"1h"` | How often the daemon re-polls `url` to confirm the installed roster is current. |
| `max_staleness` | `"24h"` | How long the node may go without confirming the roster current before it degrades (same warning-then-stop ladder as expiry). Under an adversary withholding updates, staleness is bounded by `max_staleness + grace_period`. |

## `[services.<name>]`

One table per served MCP server — written by `mcpmesh serve`, grown by pairings. The table name is
the service's public name (`mcpmesh serve notes …` writes `[services.notes]`).

| Key | Default | Meaning |
|---|---|---|
| `run` | *(unset)* | The command to spawn per session — an ordinary stdio MCP server, e.g. `["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/alice/notes"]`. |
| `socket` | *(unset)* | The local endpoint of an **already-running** MCP server the daemon dials instead of spawning (how plugin daemons register themselves). |
| `allow` | `[]` | The petnames/groups admitted to this service. Pairing appends to it; `mcpmesh pair --remove` prunes it. |

Exactly **one** of `run` / `socket` per service — both or neither makes that one service error
(surfaced when it is dialed; the rest of the config still loads). Peers themselves are *not* in the
config: who you trust lives in the daemon's state store, and only the *names* granted access appear
here.

---

## A complete example

```toml
[identity]
petname = "alice-laptop"

[network]                  # self-hosted infrastructure (omit for the public defaults)
relay_mode     = "custom"
relay_urls     = ["https://relay.acme.com"]
discovery_mode = "custom"
discovery_urls = ["https://dns.acme.com/pkarr"]

[limits]
rate_limit_per_min = 120

[roster]                   # roster mode only — pinned by `join`, tunables hand-editable
url = "https://intranet.acme.com/mcpmesh-roster.json"
poll_interval = "30m"

[services.notes]           # written by `mcpmesh serve notes -- npx …`
run = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/alice/notes"]
allow = ["bob", "team-eng"]
```

Source of truth: [`cli/src/config.rs`](../cli/src/config.rs) — where this document and the code
disagree, the code wins; please file an issue.
