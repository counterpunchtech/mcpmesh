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
| `idle_timeout_secs` | iroh's (**30 s**) | QUIC idle timeout. **Negotiated** — the connection uses the minimum of both peers' values, so raising it needs every node configured. See [Idle timeout and keepalive](#idle-timeout-and-keepalive-56). |
| `keep_alive_secs` | iroh's (**5 s**) | QUIC keepalive interval. **Legal range is `1`–`5`** — iroh caps the per-path keepalive at 5 s, so a larger value is a **startup error**, not a slower ping. `0` is refused too (a PING storm, not "disabled"). Must additionally be less than the effective idle timeout. See [Idle timeout and keepalive](#idle-timeout-and-keepalive-56). |
| `presence_mode` | `"paired"` | **Who gets a reachability pong** on `mcpmesh/ping/1` (#89). `"paired"` = any paired peer (today's behaviour) \| `"granted"` = only a peer currently holding at least one service grant \| `"off"` = never pong. See [Presence](#presence-who-can-see-that-you-are-online-89). |
| `relay_only` | `false` | **TESTING ONLY (#116).** Force application data over the **relay** even when a direct path exists. Requires building with the `unstable-relay-only` cargo feature — without it the field still parses (configs stay portable) but is **ignored with a warning**, never a startup error. See the caveats below. |

### `[services.<name>].rate_limit_per_min` — isolating a noisy service (#63)

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_per_min` | `[limits].rate_limit_per_min` | Proxied-request rate for THIS service, per peer. |

Before this, every service a peer could reach drew from **one shared bucket**: an agent hammering a
browser or filesystem service exhausted it, and your own low-rate control traffic to a *different*
service on the same node started failing. Buckets are now per `(service, peer)`.

> **It can only LOWER the rate.** `[limits].rate_limit_per_min` is a hard ceiling — a larger value
> here is clamped, not honoured, and neither a config edit nor a `register_service` call can raise
> it. `0` is rejected rather than silently blocking every request.

**What this changes about the old guarantee.** `[limits].rate_limit_per_min` used to bound a peer's
*aggregate* rate across every mount. It now bounds a peer's rate **per service**, so the aggregate is
bounded by (services that peer is granted) × (their limits) — both operator-chosen, neither
peer-influenced. That is a real weakening, and it is the minimum one that delivers the isolation:
also consulting a shared bucket would restore the old ceiling and restore the starvation with it.

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



### Presence: who can see that you are online (#89)

The reachability probe (`mcpmesh/ping/1`) is gated by **pairing alone**, so `service_allow_revoke`
never reached it. Before this knob, a peer from whom you had revoked *every* service still received,
on demand: **that you are online right now**, your RTT (a coarse geography signal), your
`stack_version`, and whatever you set via `set_app_metadata`. The only way to stop it was a full
unpair — a relationship-destroying action to express a privacy preference.

| Value | Who gets a pong |
|---|---|
| `"paired"` *(default)* | Any paired peer. Unchanged behaviour. |
| `"granted"` | Only a peer currently holding **at least one service grant**. |
| `"off"` | Nobody. |

**`"granted"` is the useful one for a product with a per-peer sharing switch.** It makes that
existing switch control presence too: revoking a peer's last service takes their view of your
presence with it, **live** — grants are already applied without a restart.

> ### This is not "appear offline". Read this before you build a UI on it.
>
> **What it does:** withholds the pong *payload* — your `stack_version`, your `set_app_metadata`
> value, the services that peer may use, and the probe's RTT measurement — and makes mcpmesh's own
> reachability probe report you as unreachable, so you vanish from that peer's `status` list.
>
> **What it does NOT do: hide that your node is running.** A determined peer still learns you are up:
>
> - A QUIC **application** close only happens *after* the handshake completes, so a bare
>   `connect(you, "mcpmesh/ping/1")` returning success already proves you are online — and times.
> - **`mcpmesh/pair/1` answers anyone**, by design (it must, to receive an invite redemption). A
>   total stranger with only your endpoint id gets a distinguishable close from it.
> - A **paired** peer, even with every service revoked, still gets a served `mcpmesh/mcp/1` session
>   and an application-layer refusal frame back — proof of life within one RTT.
>
> So `"off"` is **not** an invisibility cloak, and a product must not describe it as one. It stops
> the *presence feature* from reporting you, which is a real and useful thing; it does not defeat an
> adversary who dials you directly.
>
> **A refusal does not say which reason applied.** Within this arm, `"off"` and
> `"granted"`-without-a-grant close identically to the trust gate's refusal of a stranger, so the
> probe itself does not distinguish "not paired" from "hidden" from "no grants".

**Changing the mode needs a restart** — it is read at boot. The *per-peer* effect under `"granted"`
does not, because grants are live. An unknown value is a **startup error**, never a silent fall back
to `"paired"`: a privacy knob that fails open is worse than no knob, and `presence_mode = "of"` must
not quietly leave you visible.

**Other presence surfaces this knob does not govern.** Roster-mode presence gossip (#39) is a
separate mechanism with its own surface, and app-blob **scope grants** (#62) are not service grants —
under `"granted"`, a peer you are actively sharing blobs with is hidden from the probe while still
being able to fetch those blobs, which proves you are online. If your per-peer switch is about file
sharing rather than services, `"granted"` will not track it.

### Idle timeout and keepalive (#56)

| Key | Default | Meaning |
|---|---|---|
| `idle_timeout_secs` | iroh's (**30 s** on iroh 1.0.3) | How long a connection survives with no traffic **and no keepalive** before QUIC closes it. `0` = no timeout at all. |
| `keep_alive_secs` | iroh's (**5 s** on iroh 1.0.3) | How often the transport PINGs an otherwise idle connection. **Can only be LOWERED — legal range `1`–`5`**; see the ceiling note below. Must be **less than** the effective idle timeout (`idle_timeout_secs` if set, else iroh's 30 s), or boot fails. |

**A held session does not die when idle.** iroh already keepalives every 5 s, so `open_session` and
`subscribe` survive indefinitely while the process runs and the network is up. The idle timeout is
what detects a peer that *vanished* — not one that is merely quiet. **You do not need an
application-level heartbeat for liveness**, and one costs you `[limits].rate_limit_per_min` budget
that a transport keepalive does not: the limiter only counts method-bearing JSON-RPC frames, and a
QUIC PING never becomes one.

> **`keep_alive_secs` cannot make pings LESS frequent; values above 5 s — and `0` — are refused.** iroh
> keepalives per *path* as well as per connection, and it **caps the per-path interval at 5 s** —
> `default_path_keep_alive_interval` discards anything larger with only a log warning. So a node set
> to `keep_alive_secs = 60` would still ping every 5 s on every path. Rather than accept a setting
> that silently does nothing, **the daemon refuses to start** and says so. Lower it (e.g. `3`) to ping
> more often on a lossy link; there is **no supported way to reduce keepalive traffic on a metered
> connection** with iroh 1.0.3. `keep_alive_secs = 0` does **not** disable keepalives either — it
> arms a zero-length timer, so every packet emits a PING; no value disables them, and the daemon
> refuses `0` rather than let it saturate the link it was meant to quiet. If a future iroh lifts the
> cap, `iroh_transport_defaults_are_what_the_docs_claim` fails and this note gets revisited.

The first three rows of the table above are pinned by that test and cannot drift silently. The
**relay-path idle timeout is not** — it comes from `RELAY_PATH_MAX_IDLE_TIMEOUT` and is applied
per-path at runtime, never through `QuicTransportConfig`, so no test can observe it. Re-measure that
one by hand on an iroh bump.

> **The idle timeout is NEGOTIATED, not imposed.** QUIC uses the **minimum** of the two peers'
> advertised values (RFC 9000 §10.1). Raising `idle_timeout_secs` on one node achieves nothing
> against a peer still on the default — the connection still times out at 30 s. Raise it only if
> you are configuring every node in the mesh; *lowering* it works one-sidedly. Likewise `0` means
> "no timeout from this side", which yields the peer's value: against a default peer, still 30 s.
>
> This is the sentence to read twice if you are scoping around session lifetime.

**These defaults are iroh's, not ours.** As measured on the pinned iroh 1.0.3:

| setting | value | source |
|---|---|---|
| `keep_alive_interval` | 5 s | iroh overrides the QUIC default |
| `max_idle_timeout` | 30 s | QUIC default, not overridden |
| `default_path_max_idle_timeout` | 15 s | iroh override |
| relay path max idle | 30 s | iroh override |

An iroh bump can move them. Treat a change here as release-note-worthy; that is why they are written
down rather than left to be measured on real hardware.

Setting either key starts from iroh's *overridden* defaults, so changing one does not silently reset
the others. The per-path knobs are deliberately **not** exposed: their interaction with hole-punching
is uncharacterised, and a knob we cannot explain is worse than no knob.

## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_per_min` | `120` | Per-peer, **per-service** request rate (token bucket; this value is also the burst allowance). Since #63 each service has its own `(service, peer)` bucket, so a noisy service cannot starve a quiet one — see `[services.<name>].rate_limit_per_min` below. This value is the **ceiling**: a per-service entry may only lower it. An over-limit **request** is refused with a `-32053` retry hint — never served. An over-limit **notification** is dropped without a reply, since JSON-RPC gives it no reply channel — but **not silently**: it is recorded with `status: "rate_limited"` in the audit log and on the `subscribe` stream (#76), so the loss is visible to the node operator even though the *sender* cannot detect it. That record is **latched** — one per throttle episode, not one per dropped notification (deliberately, so a flood cannot turn the audit log into a DoS): you learn that throttling happened, not how many notifications it ate. Notification delivery is not guaranteed under load (see `docs/local-protocol.md`). |
| `blob_bytes_per_min` | `0` | Per-peer **app-blob byte budget**, bytes per minute. `0` = unlimited (the default), so upgrading changes nothing. The other blob limiter counts *connections*, which cannot see one granted peer re-pulling a 4 GB blob on each of 60 connections a minute; this bounds the bytes. A peer that exceeds it has its transfer **aborted** (retryable — `RateLimited`, not a permission failure), not paced: pacing holds the request open and turns a bandwidth problem into an unbounded-concurrency one. **The consequence is a partial transfer**, so size the budget above the largest blob you expect a peer to fetch in a minute. Setting it non-zero also arms a per-chunk intercept (~16 KiB granularity), which costs an in-process round trip per chunk — that cost is not paid at the default. **Requires a daemon restart** (the mask and the limiter are built once at boot), and **use 0 or at least 32768** (two chunks) — a value in `1..32768` is **floored to 32768**. Admission reserves one chunk before any bytes, so a sub-floor budget would not fail closed: it would silently cap every servable blob at about `budget - 16384` bytes and truncate anything larger (measured: 20480 serves a 4 KiB blob and nothing bigger). Note the budget also caps GETs at roughly `blob_bytes_per_min / 16384` per minute regardless of blob size. |
| `audit_retain_months` | `0` | Audit-log retention window in calendar months (#88). **`0` = keep forever (the default)** — upgrading changes nothing. `N > 0` deletes monthly audit files older than the last `N` months **at daemon boot** (the current month counts as month 1); a long-running daemon prunes on its next start, and the `audit_prune` control verb covers live needs. The audit log grows with **inbound peer traffic** and shares a filesystem with `state.redb` and the device key — watch it via `status.storage.audit_bytes`. |
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
blob_bytes_per_min = 0   # 0 = unlimited; see the table above before raising
audit_retain_months = 0  # 0 = keep the audit log forever; N > 0 prunes older months at boot

[roster]                   # roster mode only — pinned by `join`, tunables hand-editable
url = "https://intranet.acme.com/mcpmesh-roster.json"
poll_interval = "30m"

[services.notes]           # written by `mcpmesh serve notes -- npx …`
run = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/alice/notes"]
allow = ["b64u:9f2k…", "team-eng"]   # stable principals + roster names — never nicknames (#38)
```

Source of truth: [`cli/src/config.rs`](../cli/src/config.rs) — where this document and the code
disagree, the code wins; please file an issue.
