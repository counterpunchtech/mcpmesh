# mcpmesh configuration reference

Every table and key the daemon reads from `config.toml`, with its default. The file lives at:

- **macOS/Linux:** `~/.config/mcpmesh/config.toml` (`$XDG_CONFIG_HOME/mcpmesh/config.toml` when that
  var is set, non-empty, and absolute)
- **Windows:** `%APPDATA%\mcpmesh\config.toml` (an absolute `XDG_CONFIG_HOME` override still wins)

### Profiles: isolating an instance

To run an isolated second identity on one machine — a sandbox for local testing, or a per-tenant
instance in an embedder — pass **`mcpmesh --profile <dir>`** (alias `--home <dir>`). It roots
*everything* under that one directory: keys, config, data, state, and the control socket. This
replaces the old dance of overriding five separate `XDG_*` variables (overriding only `HOME` leaks
the real identity's state, because the XDG vars take precedence). A deep profile directory still
gets a bindable control socket — when `<dir>/run/mcpmesh.sock` would exceed the OS socket-path
limit, the socket is placed at a short `$TMPDIR/mcpmesh-<hash>/mcpmesh.sock` derived from the root.

The equivalent env var is **`MCPMESH_HOME`** (absolute path); the `--profile` flag takes precedence.
The spawned daemon inherits the profile, so every verb you run with the same `--profile` rendezvous
on the same instance. Omit it for the standard per-user locations above.

> **You rarely hand-edit this file.** The porcelain writes it: `serve` writes `[services.<name>]`,
> each pairing appends the new peer to the granted `allow` lists, and `org create` / `join` pin the
> `[identity]` and `[roster]` anchors. Hand-editing is for the tunables — `[network]` self-hosting,
> `[limits]`, the `[roster]` timing knobs, and `[identity].nickname`. Restart the daemon after
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
| `nickname` | this machine's short hostname (else a short fingerprint of the device identity) | The name this device suggests for itself in the invites it mints — what your peers will call you unless they rename you. Set it when your hostname isn't the name you want to go by. |
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
| `relay_urls` | `[]` | Your self-hosted relay URLs. Required when `relay_mode = "custom"`. **Live-editable** at runtime via the `set_relays` control verb (#53) — when already in `custom` mode, adding/removing relays is applied to the running endpoint with no restart and no dropped peer sessions; see [local-protocol.md](local-protocol.md). |
| `discovery_mode` | `"default"` | `"default"` \| `"custom"` (your own discovery service — requires `discovery_urls`). Ignored when `relay_mode = "disabled"`. |
| `discovery_urls` | `[]` | Your self-hosted discovery URLs, used for both publishing and resolving peer addresses. Required when `discovery_mode = "custom"`. |
| `relay_only` | `false` | **TESTING ONLY (#116).** Force application data over the **relay** even when a direct path exists. Requires building with the `unstable-relay-only` cargo feature — without it the field still parses (configs stay portable) but is **ignored with a warning**, never a startup error. See the caveats below. |

An unknown mode, or a `"custom"` mode without its URL list, is a **startup error** — the daemon
refuses to run rather than silently falling back to public infrastructure.

### `relay_only` — CURRENTLY NON-FUNCTIONAL (#116)

> **Do not rely on this flag.** Measured end to end (`relay_only_keeps_data_on_the_relay_while_a_direct_path_exists`,
> `#[ignore]`d in `node/src/daemon/boot.rs`): on loopback with a real relay, the client's connection
> has exactly **one** path — direct IP — from the first sample onward. **No relay path is ever
> present**, so the selector has nothing to select and traffic goes direct.

The mechanism is the problem, not the wiring. A `PathSelector` chooses among paths iroh has
**already opened**. When a direct path wins, there is no relay path open to choose — so precisely in
the situation the flag exists for (a direct path is available, force the relay anyway) it does
nothing. iroh's own `RelayOnly` works at the socket layer and also suppresses hole-punching; that is
not reachable through the public `path_selector` API.

`mcpmesh doctor` warns when the flag is set on a binary without the `unstable-relay-only` feature,
and when it is set alongside a hermetic `relay_mode`. It cannot warn about the case above, because
nothing is detectably wrong at config time.

**To actually verify relayed behaviour today, break direct connectivity** — which is the situation
#116 was filed to escape. The issue remains open.


## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_per_min` | `120` | Per-peer request rate (token bucket; this value is also the burst allowance). An over-limit **request** is refused with a `-32053` retry hint — never served. An over-limit **notification** is dropped **silently**, since JSON-RPC gives it no reply channel: notification delivery is not guaranteed under load and the loss is undetectable by the sender (see `docs/local-protocol.md`). |
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
| `env` | `{}` | (`run` only, #51) Per-service environment variables for the spawned child, overlaid on the daemon's inherited env. The injected `MCPMESH_PEER_*` identity vars always win; a service `env` cannot set them. Literal values (owner-only config file, same posture as every MCP client). |
| `cwd` | — | (`run` only, #51) Working directory to spawn the child in. Default: inherit the daemon's cwd. |
| `allow` | `[]` | The STABLE principals admitted to this service (#38): `b64u:<user_id>`, `eid:<device id>`, or roster group/user_id names — never display nicknames (they cannot admit). Pairing appends the peer's principal; `mcpmesh pair --remove` prunes it; a bare nickname typed at `serve --allow`/`register_service` time is resolved to the peer's principal on write. Removing a principal here (via `service_allow_revoke` / `peer_remove`) takes effect IMMEDIATELY on peers that are already connected — their next session is refused and their live connections are severed (#54, 0.11.0). |

Exactly **one** of `run` / `socket` per service — both or neither makes that one service error
(surfaced when it is dialed; the rest of the config still loads). Peers themselves are *not* in the
config: who you trust lives in the daemon's state store, and only the *names* granted access appear
here.

---

## A complete example

```toml
[identity]
nickname = "alice-laptop"

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
allow = ["b64u:9f2k…", "team-eng"]   # stable principals + roster names — never nicknames (#38)
```

Source of truth: [`cli/src/config.rs`](../cli/src/config.rs) — where this document and the code
disagree, the code wins; please file an issue.
