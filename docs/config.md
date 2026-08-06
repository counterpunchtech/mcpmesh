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
| `local_discovery` | `"off"` | **Find peers on the LAN with no internet at all** (#68). `"off"` \| `"on"` (resolve *and* announce) \| `"resolve"` (listen only, never announce). See [Local discovery](#local-discovery-finding-peers-with-no-internet-68). |
| `presence_mode` | `"paired"` | **Who gets a reachability pong** on `mcpmesh/ping/1` (#89). `"paired"` = any paired peer (today's behaviour) \| `"granted"` = only a peer currently holding at least one service grant \| `"off"` = never pong. See [Presence](#presence-who-can-see-that-you-are-online-89). |
| `relay_only` | `false` | **TESTING ONLY (#116).** Force application data over the **relay** even when a direct path exists. Requires building with the `unstable-relay-only` cargo feature — without it the field still parses (configs stay portable) but is **ignored with a warning**, never a startup error. See the caveats below. |

An unknown mode, or a `"custom"` mode without its URL list, is a **startup error** — the daemon
refuses to run rather than silently falling back to public infrastructure.

### Per-session idle timeout (#166)

`[network].idle_timeout_secs` is node-wide, so a chat session, a bulk blob transfer and a media flow
all share one compromise. `open_session` can override it for **one** session:

```
open_session { peer, service, idle_timeout_secs: 120 }
```

Three things decide what this can do, and all three follow from how QUIC works:

- **Only lowering is unilateral.** `max_idle_timeout` is negotiated to the **minimum** of the two
  peers' values (RFC 9000 §10.1), so this can always make a session die sooner when it goes quiet,
  and can never make it outlive what the peer allows. Raising needs both peers configured — which
  was already true of the node-wide knob.
- **Outbound only, and that is not half a feature.** An accepted session uses the node-wide value,
  because iroh gives the server config no per-connection seam. But the direction that *can* work
  one-sidedly is available here, and the direction that cannot never worked anywhere. A node wanting
  a shorter timeout on a session it did not initiate can dial instead.
- **It must exceed this node's keepalive.** A keepalive arriving after the idle timer has fired
  severs a session whose peer is alive and answering, so a value at or below `keep_alive_secs`
  (default 5s) is **refused** — the same rule the node-wide pair is validated against at boot.

**Ignored on a racing dial**, because that opens connections it then abandons. Precisely: a **roster
person** races whenever the roster lists them with any device — including exactly one — so a
`user_id` naming a rostered person never gets it; a pairing-mode **`b64u:`** races only with two or
more stored devices, and with exactly one it does get it. The node logs at `warn!` when it drops the
value, because a caller cannot know how many devices a peer has. Name one device with `eid:` to be
certain.

The value is still **validated** on a racing dial even though it is then dropped — a bad value is an
error whichever path a peer happens to resolve to, so the same call does not succeed or fail
depending on how many machines someone owns.

There is no per-session **keepalive**: iroh caps the per-path interval at 5s and discards larger
values, so one could only make pings more frequent.

### Local discovery — finding peers with no internet (#68)

Peer resolution normally needs external infrastructure: the pkarr publisher a relay provides, or an
address someone already handed you in an invite. So two machines on the same LAN with **no uplink**
cannot find each other, though the network path between them is fine — a boat, a workshop, a failed
uplink, a deliberately air-gapped network. There is a commoner weak version too: a LAN where the
internet is merely *flaky*, so peers that could talk directly fail to resolve because resolution
goes out first.

```toml
[network]
local_discovery = "on"        # resolve peers on this link, and announce this node to it
```

| Value | Resolves peers | Announces **your identity** | Emits mDNS queries |
|---|---|---|---|
| `"off"` *(default)* | no | no | **no** |
| `"on"` | yes | yes | yes |
| `"resolve"` | yes | **no** | **yes — see below** |

**`"resolve"` is not silent.** Resolving over mDNS means *asking*, and the underlying library asks
on a fixed cadence: a node in this mode multicasts a query for `_mcpmesh._udp.local` roughly **once
a second, continuously**, from the moment it boots. It never publishes your endpoint id or your
addresses — that part of the promise holds, and is pinned by a test that reads the multicast group
directly — but every device on the link can see that *something at this IP is running mcpmesh and is
up right now*.

If that matters where you are, the mode you want is `"off"`.

An unknown value is a **startup error**, like `relay_mode` and `presence_mode`, and it is refused
*before* the endpoint binds. `local_discovery = "resolv"` quietly meaning `"on"` would put a node on
the air whose operator asked it only to listen.

#### Read this before turning it on

**`"on"` multicasts this node's endpoint id and its addresses to every device on the link**,
unprompted and repeatedly, including machines that had no idea it existed.

"Its addresses" is broader than it sounds, and worth stating exactly: the announcement carries the
**LAN address, the public WAN IPv4, and global IPv6 addresses**. So a café LAN learns your home or
ISP address, not just your presence on that café's network.

That is not the same disclosure as the default relay setup, and the difference is why this ships
off:

- **pkarr** publishes a *signed record* that someone must already know your endpoint id to look up.
  It is a lookup table.
- **mDNS** is an announcement to strangers. Your endpoint id is the identity peers *pin*, so
  broadcasting it on each network you join correlates you across them.

On a home or office LAN that is exactly what you want. On a café, hotel, conference or coworking
network, decide deliberately. A node cannot un-send a multicast packet — which is why `"resolve"`
exists, for the benefit without the announcement.

**#68 asked for this on by default. It is not**, for the reason above. Turning it on is one line.

One honest tension: naming the service `mcpmesh` rather than iroh's shared `irohv1` (below) makes
the query in `"resolve"` mode *more* identifying, not less — it says "mcpmesh" rather than "some
iroh app". That trade is taken deliberately: cross-advertising with unrelated iroh applications is a
disclosure on the `"on"` path, which is the one that carries your identity, and blending into other
traffic is not a privacy property anyone should rely on.

#### What actually goes on the wire

Records take the form `<endpoint-id>._mcpmesh._udp.local`, carrying this node's direct addresses and
its relay URL if it has one. The service name is `mcpmesh`, deliberately **not** iroh's shared
`irohv1` default — otherwise every unrelated iroh application on the link would advertise into the
same namespace and be resolved out of it.

**`relay_only` does NOT restrain this on a stock build.** `AddrFilter::relay_only()` is installed
only when the binary is built with the `unstable-relay-only` cargo feature; without it,
`relay_only = true` is inert (it says so in its own section below) and mDNS announces the **full**
direct address set. With the feature, the filter strips direct addresses before mDNS sees them and
the announcement carries only a relay URL — useless on a LAN with no uplink, but quiet. Boot warns
either way, naming which of the two you actually got.

An earlier version of this section claimed the filter always applied. It does not; that was caught
on the wire.

`presence_mode = "off"` and `local_discovery = "on"` also work against each other — the first
withholds reachability from paired peers, the second broadcasts it to the whole link. Boot warns.

**Discovery is not authorization.** A peer found this way faces the trust gate exactly as one found
any other way; resolution answers *where*, never *who may*. That is what makes it safe to switch on
at all — it cannot widen who this node admits.

`status.self_network.local_discovery` reports the effective mode (`api_minor >= 50`), so a product
backing a privacy switch can show its real state and "why can't these two machines see each other"
has an answer from the control API.

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

### `admit_attested_devices` — letting a replacement machine back in (#85 ask 3)

```toml
[identity]
admit_attested_devices = true      # default false
```

Admits **another device of a person you already pair with** when it presents a binding signed by
that person's user key — no fresh SAS ceremony. This is what makes `mcpmesh identity import` useful:
without it, a machine restored from a recovery phrase presents the right `b64u:` and is still a
stranger to everyone.

**Off by default**, and #85 asked for it to be seamless. It changes what a pairing *means*: today it
admits a device, and with this on it admits a person and their future devices. #38 arguably made
that true of grants already — they are keyed on stable principals — but "arguably implied" is not a
reason to widen admission on somebody's node during an upgrade.

Two consequences worth knowing before you turn it on:

- **It does not resurrect a device you removed.** `pair --remove` deletes the row; it does not stop
  the *person* from attesting a device afterwards, because you still pair with them. If you removed
  a device because it was compromised, use `mcpmesh revoke peer <b64u:>` — revoking the PERSON.
  Revoking the endpoint id alone is not enough here: whoever holds that machine holds the user key,
  and can sign a binding over a fresh endpoint id at will.
- **The pair ALPN stays reachable.** It normally fast-closes when no invite is live; an attestation
  carries no invite, so this keeps that door open to a rate-limited, binding-verified ceremony that
  can only ever admit a device of someone you already pair with.

## `[blobs]`

Reclaiming disk from the app-blob store (#80).

| Key | Default | Meaning |
|---|---|---|
| `gc_interval` | *(unset — no collection)* | How often to sweep `<data_dir>/blobs/`, e.g. `"1h"`. Minimum `60s`. Absent means the store grows monotonically, which is the behaviour of every release up to 0.42.0. |

`blob_unpublish` and `blob_revoke` withdraw *access*; neither reclaims a byte. This is the knob that
does, so an embedder that has told a user "this file is deleted" can deliver that.

**What a sweep deletes: every blob no scope names.** That is the reclaim you asked for, and it also
covers a case worth knowing before you turn this on:

> A blob this node **fetched** and never republished is in no scope, so it is reclaimed. The fetch
> already wrote the caller's `dest_path` and the store copy is a cache — but it means
> **`blob_republish` of a hash fetched more than one interval ago fails**, and this node stops being
> an alternate source for it (`blob_fetch --from`).

Pick the interval against how long you want to stay a source for things you fetched, not just
against disk.

**A bad value leaves collection OFF.** Unlike `[roster]`'s durations — where a typo falls back to
the default, because a typo must never disable a safety property — an unparseable `gc_interval`, or
one below `60s`, turns collection off and logs a warning. A knob that deletes bytes must not start
deleting them because a fallback guessed an interval. A below-minimum value is refused rather than
raised to the minimum, so `status` can never report an interval the node is not on.

**Watch `status.storage.blobs_gc.runs`.** Two properties come from iroh-blobs and cannot be worked
around here:

- The collector **sleeps a full interval before its first run**. A node with `gc_interval = "24h"`
  reclaims nothing for its first 24 hours, and there is no way to request a sweep on demand.
- It **stops collecting for the life of the process after its first sweep error** — a log line, and
  otherwise silent. `runs` failing to advance across several intervals is the only signal. Restart
  the daemon to resume.

`status.storage.blobs_gc` is absent entirely when collection is not configured, and present with
`runs: 0` when it is configured and has not swept yet.

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


### `rate_limit_per_min` — isolating a noisy service (#63)

| Key | Default | Meaning |
|---|---|---|
| `rate_limit_per_min` | `[limits].rate_limit_per_min` | Proxied-request rate for THIS service, per peer. |

Before this, every service a peer could reach drew from **one shared bucket**: an agent hammering a
browser or filesystem service exhausted it, and your own low-rate control traffic to a *different*
service on the same node started failing. Buckets are now per `(service, peer)`.

> **It can only LOWER the rate.** `[limits].rate_limit_per_min` is a hard ceiling — a larger value
> here is clamped, not honoured, and neither a config edit nor a `register_service` call can raise
> it.
>
> **`0` is a startup error, and does NOT mean unlimited here.** Note the asymmetry with
> `[limits].blob_bytes_per_min`, where `0` *does* mean unlimited: a `0` rate would floor to
> 1 request/minute — the most restrictive setting there is — so it is refused rather than silently
> giving an operator the opposite of what they asked for.

**Changing it needs a daemon restart to affect an OPEN session.** A backend captures its limiter
when the registry is built, so a session already in flight keeps the old rate until it ends — and
MCP sessions are long-lived by design. New sessions pick up the change on the next reload.

**Observing your remaining budget is not implemented.** #63's second ask is still open: a caller
learns the limit by receiving `-32053`, not by querying it.

**What this changes about the old guarantee.** `[limits].rate_limit_per_min` used to bound a peer's
*aggregate* rate across every mount. It now bounds a peer's rate **per service**, so the aggregate is
bounded by (services that peer is granted) × (their limits) — both operator-chosen, neither
peer-influenced. That is a real weakening, and it is the minimum one that delivers the isolation:
also consulting a shared bucket would restore the old ceiling and restore the starvation with it.

#### Sizing it against MCP 2026-07-28 (#188)

**One logical tool call can now cost several requests, and each is charged.**
[SEP-2322 Multi Round-Trip Requests][mrtr] replaces the server-initiated `elicitation/create`,
`sampling/createMessage` and `roots/list` — which previously held a stream open — with: the server
returns `resultType: "input_required"`, and the client **retries the original call** with its
answers in `inputResponses`.

That retry is metered as a **fresh request**. So a tool that needs one round of user input costs
**two** requests against this bucket, and two rounds cost three.

This is a decision, not an accident, and it is worth stating why: there is no correlation id at the
mesh layer, and inventing one would mean parsing MCP request/response semantics inside the
transport — which mcpmesh deliberately does not do (it pumps; it does not interpret). A
continuation is also still a round trip, still a backend invocation, and still the unit this limit
exists to bound.

**The practical consequence:** a budget tuned against 2025-11-25 traffic is effectively **2–3×
tighter** for exactly the interactive tools MRTR exists to enable, and the failure surfaces
*mid-interaction* — after the user has already been asked a question. If you serve tools that
elicit input, size for the round trips, not the tool calls.

[mrtr]: https://blog.modelcontextprotocol.io/posts/2026-07-28/

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
