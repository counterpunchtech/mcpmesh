# The `mcpmesh-local/1` protocol

This is the wire contract between the mcpmesh daemon and the programs on the **same machine** that
drive it — the CLI, the desktop host, and plugin daemons like `kb` and `loc`. It is a small,
line-delimited JSON protocol over a same-user local endpoint: a Unix domain socket on macOS/Linux, a
named pipe on Windows. Anything that can open the endpoint and parse JSON can speak it, in any
language — [`local-api/examples/status.py`](../local-api/examples/status.py) is a complete client
in ~60 lines of dependency-free Python.

> **Status: pre-release.** The API is versioned `mcpmesh-local/1` (`api_version` `1.16`, `api_minor` `16`) and evolves
> **additively** (see [Versioning](#versioning)), but until a stable release this document — like the
> wire format itself — may change without a migration path. Pin the mcpmesh version you build
> against. Source of truth is the Rust in [`local-api/`](../local-api/src/protocol.rs); where this
> document and the code disagree, the code wins — please file an issue.

## Three ways to build against mcpmesh

Most people who want to "build against mcpmesh" do **not** need this protocol at all. Pick your row:

| You want to… | You build | You need |
|---|---|---|
| **Share a tool** with a peer | a normal [MCP](https://modelcontextprotocol.io) server | nothing mcpmesh-specific — just read the [identity contract](#the-identity-contract) if you want to know *who* is calling |
| **Drive or embed the mesh** (a GUI, a TUI, another launcher) | a `mcpmesh-local/1` client | this document |
| **Reimplement the peer transport** (iroh/QUIC, pairing crypto) | — | out of scope; that layer is Rust-first and exposed only through the CLI/daemon today |

The first row is the common one and it is the point of MCP: you write an ordinary stdio MCP server —
the same artifact you would hand to Claude Desktop — and share it with `mcpmesh serve <name> -- <your
command>`. mcpmesh spawns it per session. It never speaks `mcpmesh-local/1`; the mesh speaks to *it*
in ordinary MCP, and tells it who is calling through the [identity contract](#the-identity-contract).

The rest of this document is the second row.

## Transport and framing

- **Endpoint type:** a same-user local endpoint — a Unix-domain stream socket on macOS/Linux, a named
  pipe on Windows. There is no TCP surface.
- **Framing:** [newline-delimited JSON](https://jsonlines.org/). One JSON value per frame, terminated
  by a single `\n` (`0x0A`). The value is compact (no embedded newlines) and UTF-8.
- **Frame cap:** 16 MiB per frame (`MAX_FRAME_BYTES`). A frame that exceeds the cap, or that is not
  valid JSON, is a framing violation and the peer may close the connection.

This is the whole codec. It is deliberately trivial so that both ends — and any third-party client —
share one implementation that cannot drift. Reference: [`codec/src/lib.rs`](../codec/src/lib.rs).

## Finding the local endpoint

The daemon binds its control endpoint at:

- **macOS/Linux:** `<runtime-dir>/mcpmesh/mcpmesh.sock`
- **Windows:** `\\.\pipe\mcpmesh-<domain>-<user>`

`<runtime-dir>` resolves the same way the daemon and CLI resolve it, so a client lands on the same
path:

1. `$XDG_RUNTIME_DIR` when set, non-empty, and absolute (Linux) → `$XDG_RUNTIME_DIR/mcpmesh/`.
2. Otherwise `$TMPDIR/mcpmesh/`, or the platform temp dir when `TMPDIR` is unset (macOS, whose
   per-user `$TMPDIR` is already private).

Windows has no per-user runtime dir with the right ACL semantics, so the pipe name itself carries the
identity instead: `<domain>` and `<user>` come from the owning account, sanitized and lowercased, so a
client resolves the same name the daemon bound.

On macOS/Linux the socket is `0600` inside a `0700` directory the daemon owns, and the daemon verifies
the **connecting process's uid matches its own** before serving. On Windows the pipe carries an
**owner-only DACL** that grants access only to the current user's SID, so the kernel refuses a
cross-user connect before the daemon ever sees it. Either way, only the same user can connect (see
[Security model](#security-model)). Reference: [`local-api/src/paths.rs`](../local-api/src/paths.rs).

Rust consumers never need to reimplement this rule: `mcpmesh_local_api::paths::default_endpoint()`
returns the resolved endpoint on either platform, and (behind the `client` feature)
`connect_control_default()` dials it and completes the handshake in one call.

If no daemon is running, the endpoint will not exist (no socket file on macOS/Linux; no bound pipe
name on Windows). The CLI auto-starts one on demand; an embedding client either spawns `mcpmesh` (any
porcelain verb starts the daemon) or runs `mcpmesh internal daemon` itself.

## Handshake

**The server speaks first.** Immediately on accept, the daemon writes one `Hello` frame:

```json
{"api":"mcpmesh-local/1","api_version":"1.3","api_minor":3,"stack_version":"…"}
```

A client MUST read this frame first and check `api == "mcpmesh-local/1"` before sending anything. A
different `api` means you have connected to a sibling `*-local/N` socket (plugins bind their own),
not the mcpmesh daemon — hang up. `stack_version` is the daemon's build version, informational.

After the `Hello`, the client sends request frames and reads response frames.

## Message envelope

Requests and responses are JSON-RPC 2.0-*shaped*. Two deliberate leniencies make the surface easy to
target from any language — see the notes below.

### Request

```json
{"method":"invite","params":{"services":["notes"]}}
```

- `method` — the method name (snake_case; see the [table](#methods)).
- `params` — a per-method object. **Omit it, send `null`, or send `{}`** for parameterless methods
  (`status`, `blob_list`, `audit_summary`, `subscribe`); all three are accepted.
- `id` / `jsonrpc` — **optional on the request.** The daemon echoes whatever `id` you send (defaulting
  to `null`) back on the response, so include one if you pipeline concurrent requests and need to
  correlate them. One request/response per turn on a single connection needs no `id`.

The daemon dispatches on the `method` string and parses `params` per-method — it does **not**
deserialize the whole message into a fixed schema. Unknown top-level fields are ignored. This is what
keeps the surface tolerant for third-party clients.

### Response

Success:

```json
{"jsonrpc":"2.0","id":null,"result":{ ... }}
```

Error:

```json
{"jsonrpc":"2.0","id":null,"error":{"code":-32602,"message":"…"}}
```

`result` is the per-method payload (see the table; an acknowledgement-only method returns `{}`).
Presence of `error` instead of `result` means the call failed; read `error.code` and
`error.message`. See [Error codes](#error-codes).

## Methods

Every method is one frame in, one frame out — **except `open_session` and `subscribe`**, which
upgrade the connection (see [Sessions](#sessions) and [Live event stream](#live-event-stream)).

Methods split into two groups by audience:

- **Plugin-facing** — what a service daemon realistically uses: `register_service`, `status`,
  `audit_summary`.
- **Porcelain / host-privileged** — the pairing, roster, and blob operations that drive the mesh.
  An embedding GUI (like the desktop host) uses these; a shared-tool plugin does not.

| `method` | `params` | `result` |
|---|---|---|
| `register_service` | `{name, backend, allow, ephemeral?}` — `backend` is `{"run":{"cmd":[…], "env"?:{…}, "cwd"?:"…"}}` (#51 — per-service env + working dir; `MCPMESH_PEER_*` identity vars always win over `env`, and a service `env` cannot set them) or `{"socket":{"path":"…"}}`; `allow` is a list of STABLE principals — `b64u:<user_id>`, `eid:<device id>`, or roster group/user_id names; a bare input naming a paired peer's nickname is RESOLVED to that peer's stable principal at write time (#38); `ephemeral:true` (#36) keeps the registration in memory only and unregisters it when THIS connection closes (see [Ephemeral registration](#ephemeral-registration)) | `{}` (ack) |
| `status` | *(none)* | [`StatusResult`](#statusresult) |
| `audit_summary` | *(none)* | `{per_peer:[[name,count],…], per_service:[[name,count],…], total_sessions}` — this node's **local** session tallies; nothing is transmitted |
| `invite` | `{services:[…]}` | `{invite_line:"mcpmesh-invite:…", expires_at_epoch}` |
| `pair` | `{invite_line}` | `{peer_nickname, sas_code, services:[…], app_label?, peer_user_id?}` — `app_label` echoes any opaque label the inviter attached (#31); `peer_user_id` is the inviter's stable `b64u:` identity when it presented a binding (#30). **Grants MUTUALLY (#43):** redemption grants the inviter access to ALL services THIS (redeemer) node serves — under the same stable-principal rule as the inviter-side grant — so one ceremony admits both directions. Fails (no dial attempted) if the invite's suggested nickname is already yours for a *different* peer; see [Nickname collisions](#nickname-collisions) |
| `peer_remove` | `{nickname}` | `{}` (ack) |
| `peer_rename` | `{to, user_id?, nickname?}` — rename a person by `user_id`, else a provisional contact by `nickname` | `{}` (ack) |
| `set_nickname` | `{nickname}` — rename **this node** live (#37, `api_minor >= 2`): validated (trimmed non-empty, no `/`), persisted to `[identity].nickname` under the daemon's own config lock (no lost-update window against a concurrent grant/registration), and effective for FUTURE invites/presentations immediately — no restart. Display-only: peers keep the nickname they stored at pairing time until a re-invite | `{}` (ack) |
| `service_allow_grant` | `{service, principal}` — grant a stable principal (`b64u:`/`eid:`) access to ONE service's allow WITHOUT (re)pairing (#44), under the daemon's config lock + hot-reload. The per-peer "sharing on" toggle. Works on EPHEMERAL registrations too, mutating their in-memory allow (#55, `api_minor >= 11`). Idempotent; a name in neither the config nor the ephemeral registry → `-32040`. | `{}` (ack) |
| `service_allow_revoke` | `{service, principal}` — remove a stable principal from ONE service's allow WITHOUT unpairing (#44): the peer's `PeerEntry` identity is untouched. **Immediate at `api_minor >= 10`** — see "Revocation is immediate" below. Works on EPHEMERAL registrations too (#69, `api_minor >= 11`). Idempotent; an absent principal is a clean no-op, a name in neither the config nor the ephemeral registry → `-32040`. | `{}` (ack) |
| `unregister_service` | `{name}` — remove a service registration (#50), the mirror of `register_service`: drops the whole `[services.<name>]` entry (allow included) + any ephemeral registration, then hot-reloads. Idempotent; unknown name → clean no-op. In-flight sessions finish; no new ones admitted. | `{}` (ack) |
| `peer_services` | `{peer}` — discover which services a paired `peer` (nickname / `eid:` / `b64u:`) CURRENTLY grants you (#52): dials the peer over `mcpmesh/ping/1` and returns `{services:[…]}` — the names whose allow admits YOUR principal (only yours, never the peer's full registry). Authoritative + current. | `{services:[…]}` |
| `set_relays` | `{relay_urls}` — set this node's CUSTOM relay set LIVE (#53, `api_minor >= 9`): each URL must parse as an iroh relay URL (empty list → error; disable relays via a `relay_mode="disabled"` restart). When the node is already `relay_mode="custom"`, the daemon diffs against the running endpoint and applies the delta with iroh's live `insert_relay`/`remove_relay` — **no restart, no dropped peer sessions** — then persists `[network] relay_mode="custom" relay_urls=[…]` under the config lock. Idempotent (an unchanged set → `changed:false`, no writes). When the node is currently `default`/`disabled`, iroh cannot live-transition the relay MODE: the config is persisted but `restart_required:true` is returned (apply on next start). | `{changed, restart_required}` |
| `set_app_metadata` | `{metadata}` — attach this node's opaque app metadata (#39, `api_minor >= 4`, roster mode): a ≤256-byte blob the daemon never interprets, folded **signed** into each presence heartbeat so paired roster peers see it in their `status` presence (`PresencePeer.meta`) — no per-peer session. `""` clears it. In-memory (lost on restart; re-set on startup). Over-cap → error. In pairing mode it is carried on the `mcpmesh/ping/1` reachability probe pong instead (#40), surfacing as `PeerReachability.meta` (near-real-time when a peer reads `status` — the probe cache has a ~20s TTL). | `{}` (ack) |
| `open_session` | `{peer, service}` — `peer` is a **nickname, a stable `b64u:` user_id** (#30, racing a person's devices), **or an `eid:<hex>` device principal** (#41, targeting that EXACT authenticated endpoint — no nickname ambiguity) | *no response frame — see [Sessions](#sessions)* |
| `subscribe` | *(none)* | *no response frame — a one-way live stream; see [Live event stream](#live-event-stream)* |
| `roster_install` | `{path, org_root_pk?}` — `path` is a local file the daemon reads; `org_root_pk` pins the root on first install | `{org_id, serial, severed}` |
| `org_join` | `{org_id, org_root_pk, user_id, user_key}` — `user_key` is a local path; the key never crosses the socket | `{org_id}` |
| `set_roster_url` | `{url}` | `{}` (ack) |
| `blob_publish` | `{scope, path}` | `{ticket:"mcpmesh/blob/1…", hash}` |
| `blob_grant` | `{scope, principal}` | `{}` (ack) |
| `blob_revoke` | `{scope, principals}` — withdraw principals from ONE scope's grants (#62, `api_minor >= 15`). The blob analogue of `service_allow_revoke`: un-shares a file without unpairing the person. **Scoped** — grants on other scopes are untouched. A principal that held no grant is a clean no-op; an unknown **scope** is `-32040`, not a silent ack. | `{}` (ack) |
| `blob_unpublish` | `{scope, hash}` — remove a blake3 hash from ONE scope (#62, `api_minor >= 15`). Refuses **subsequent** GETs from that scope; does **not** delete bytes and does **not** interrupt a transfer in flight — see the note below. `hash` must parse as blake3 (case-insensitive); garbage is an error, not a silent no-op. An already-absent hash is a clean no-op; an unknown **scope** is `-32040`. | `{}` (ack) |
| `blob_list` | *(none)* | `{scopes:[{name, hashes:[…], grants:[…]}]}` |
| `blob_fetch` | `{ticket, dest_path}` | `{hash, bytes_len}` |

> **`blob_fetch` blocks the control connection, and cannot be cancelled.**
>
> The fetch streams to disk, so peak memory does not scale with blob size (#82). Two limits remain:
>
> - **It is awaited inline on the control connection.** A multi-GB transfer stalls every other verb
>   on *that* connection — status, reachability, grants. Use a separate control connection for a
>   large fetch if you need the daemon responsive meanwhile.
> - **There is no cancellation.** Dropping the client does not abort an in-flight transfer; the
>   reader only errors at the next frame. A Cancel button cannot currently stop the work.
>
> Neither end reports progress, so a stalled transfer is indistinguishable from a slow one. Tracked
> in [#82](https://github.com/counterpunchtech/mcpmesh/issues/82).

> **`blob_unpublish` withdraws access, it does not delete data.** The bytes stay in the provider's
> local store. The authorization effect applies to **new requests from that scope**: a subsequent
> GET is refused at the request hook, even for a caller holding the ticket — a hash is not a
> capability. Two limits to be precise about:
>
> - **A transfer already streaming is not interrupted.** Unlike `service_allow_revoke` (#54), these
>   verbs do not sever live connections; a large blob mid-flight completes.
> - **Other scopes still serve it.** If the same hash is published into another scope that grants
>   the caller, it remains fetchable there — unpublish is per-scope, never a global delete.
>
> So if you have promised a user that a file is *deleted*, this verb does not deliver that promise.
>
> There is currently **no reclaim**: `<data_dir>/blobs/` grows monotonically. `iroh-blobs` exposes
> no on-demand sweep (its `delete` is crate-private and it directs users to garbage collection,
> which it only supports as a periodic background policy configured at store construction), so a
> reclaim path needs its own design. Tracked in
> [#80](https://github.com/counterpunchtech/mcpmesh/issues/80).

Paths and files (`roster_install.path`, `org_join.user_key`, `blob_publish.path`,
`blob_fetch.dest_path`) are passed **as local paths, not bytes** — the same-uid daemon reads/writes
them directly, which is within the trust boundary.

### Revocation is immediate (#54, 0.11.0, `api_minor >= 10`)

`service_allow_revoke` and `peer_remove` take effect **now**, on peers that are already connected:

- **New sessions are refused.** The daemon resolves every session against the live service
  registry, so a peer that holds an open connection is re-evaluated on its very next session.
- **In-flight sessions are cut.** The revoke closes the principal's live mesh connections.

Before 0.11.0 both waited for the peer to disconnect on its own. The verb returned success
immediately but a connected peer kept opening admitted sessions for the entire lifetime of its
connection — unbounded for a client holding a warm session, which is what this document recommends.
A consumer can guard on `api_minor >= 10` before telling a user that access has been withdrawn.

**Severing is connection-granular, not session-granular.** Revoking a principal from ONE service
closes its whole QUIC connection, so its in-flight sessions to services it *still* holds are cut
too; it redials and is re-evaluated against the current allow. Expect a revoke to cost a
well-behaved peer one reconnect.

**Two limits worth knowing:**

- **Severing reaches the peer's other connections.** The daemon tracks mesh, gossip, and blob
  connections by endpoint id with no protocol discriminator, so a revoke closes that peer's live
  gossip and blob connections too. Each of those carries its own gate, so this costs availability
  (a presence blip, an aborted blob transfer), never authorization; the peer reconnects.
- **Ephemeral services are covered as of `api_minor >= 11`** (#55/#69). Both verbs resolve the
  service ephemeral-first, then config, so a grant or revoke against an ephemeral registration
  mutates its in-memory allow and takes effect immediately, like any other service. Before that
  they edited only `config.toml` and silently changed nothing.

Roster principals ARE covered: a bare roster `user_id` or a GROUP name in an `allow` resolves
through the installed roster view to that user's or group's devices. Roster-mode revocation by
roster INSTALL is unchanged and independent (`roster_install` reports `severed`).

### Nicknames are display-only; principals authorize (#38, 0.8.0)

Authorization keys on STABLE principals — the `eid:` device principal (the TLS-authenticated
endpoint id) and the `b64u:` user_id (a verified device→user binding), plus roster group/user_id
names. A display nickname NEVER admits: names are self-asserted and rewritable (`set_nickname`,
rename-by-fresh-invite), so no rename can change what a peer is granted — the 0.7.x class of
silent grant desync is unrepresentable. `status` reports both the raw `allow` principals and an
`allow_display` annotation (each principal resolved to its peer's display name by the daemon);
porcelain shows the display form and never prints raw ids.

Nickname UNIQUENESS is still enforced, for display/routing clarity only (outbound
`<peer>/<service>` routing is first-match by name):

- **`pair` (redeemer side)** — the redeem fails, **before any dial**, if a stored peer already
  holds the invite's suggested nickname under a different endpoint (your own dials to that name
  would become ambiguous).
- **Inviter side** — symmetrically, a redeemer self-asserting a name already belonging to a
  different endpoint is refused with the generic `pairing refused` (no detail about which names
  exist).
- **`peer_rename`** — refuses a target name another contact already holds; it is a pure display
  mutation (no grant is touched, no serving reload happens).

Re-pairing with a peer you already know always passes: renaming a peer by redeeming a fresh
invite from them keeps working — and is fully safe, since no grant keys on the name.

### Ephemeral registration

By default `register_service` **persists** the service into the daemon's on-disk config, so it
survives restarts. That is the right model for a daemonized service, but awkward for an embedder
that serves a `socket` backend from a fresh path each run: a persisted entry outlives the process
and points at a dead socket, and there is no unregister, so stale entries accumulate.

Pass `ephemeral: true` for a registration that instead:

- lives **in daemon memory only** — never written to config, gone on daemon restart;
- is **unregistered automatically when the control connection that registered it closes** (clean
  close, error, or the client process exiting);
- appears in `status` with `"ephemeral": true` so its transience is legible.

The lifetime is the **connection's**, so an embedder must hold its control connection open for as
long as it wants the service offered — register over a `ControlClient` and keep it alive, rather
than the connect-register-disconnect pattern (which would tear the registration down immediately).
An ephemeral name that collides with an existing persistent (config) service is refused. Everything
else — the `allow` list, dialing, invites granting it — works identically to a persistent service.

### Reserved / internal methods

The daemon answers two further methods that are **not** part of the stable surface; they are listed
here only so a third-party implementer is not surprised to see them on the wire:

- `shutdown` — asks the daemon to exit cleanly; used by the CLI's own lifecycle management.
- `peer_add` — installs a peer directly from a raw `endpoint_id`, an internal stand-in for
  populating trust without the pairing ceremony. This is a deliberate, documented exception to the
  surface discipline described under [`StatusResult`](#statusresult): everywhere else, raw endpoint
  identifiers never cross this socket.

Do not build on either — they may change or disappear without an `api_version` bump.

### `StatusResult`

```json
{
  "stack_version": "…",
  "services": [{"name": "notes", "allow": ["eid:9f2k…"], "allow_display": ["bob"], "backend": "run"}],
  "peers":    [{"name": "bob", "services": ["notes"], "user_id": "b64u:…", "principal": "eid:…"}],
  "self_user_id": "b64u:…",
  "roster":   {"org_id":"…","serial":42,"state":"approved","org_root_fingerprint":"tango-fig-cabbage"},
  "presence": [{"user_id":"b64u:…","device_label":"laptop","role":"primary","online":true,"meta":"v=1.2.3"}],
  "recent_pairings": [{"peer_nickname":"bob","sas_code":"tango-fig-cabbage","paired_at_epoch":1751760000}],
  "reachability": [{"name":"bob","reachable":true,"rtt_ms":42,"age_secs":3,"meta":"v=1.2.3","principal":"eid:…"}],
  "self_nickname": "workbench"
}
```

`roster`, `presence`, `self_user_id`, and `recent_pairings` are optional — absent on a pure-pairing
daemon with no roster and no user key. `backend` reports the *kind* (`"run"` \| `"socket"`) only,
never the command or path.

`reachability` is **advisory** — an on-demand liveness read of your paired peers, populated by a
probe cache the daemon refreshes lazily. It is empty until the first probe completes. A `status`
call kicks off a background refresh for any peer whose entry is stale or missing, but **never blocks
on a probe**. Each entry is a **nickname** (`name`, never an endpoint-id), a `reachable` bool (the
last probe result), `rtt_ms` (the last measured round-trip, present only when reachable), and
`age_secs` (how long ago the entry was measured). `age_secs` is **absent** for a peer that has never
been probed — render that as "checking…", not "offline".

Under the hood the daemon measures reachability with a trust-gated, peer-facing probe over the
`mcpmesh/ping/1` ALPN: it dials the peer, and a **paired** peer answers one pong carrying its
`stack_version`. Only paired peers pong — an unpaired scanner's probe is closed with no answer, so
the probe leaks no presence to strangers. (This ALPN is a peer-transport detail; you never speak it
over this local socket — you read its result in `reachability`.)

Note the surface discipline that runs through every response: names are **nicknames and self-sovereign
`user_id`s** (opaque `b64u:` identifiers spanning a person's devices), never raw endpoint
identifiers, keys, or transport addresses. If you are keying authorization, key on `user_id`.

### Embedding the pairing ceremony (both sides of the SAS)

The safety code (SAS) — the words the two humans read aloud to confirm the pairing is authentic —
is surfaced to **both** ends of a pairing through this protocol, so an embedder can render the whole
ceremony without ever shelling out to `mcpmesh status`:

- **Redeemer** (the side calling `pair`): the SAS is the `sas_code` in the [`pair`
  result](#methods), returned the moment redemption completes.
- **Inviter** (the side that called `invite`): `invite` returns *before* anyone redeems, and the
  SAS is derived from the redeemer's identity, so it cannot appear in the `invite` result. Instead
  it lands in **`status.recent_pairings`** — a structured, newest-first list of
  `{peer_nickname, sas_code, paired_at_epoch}` — as soon as the redemption completes. Poll `status`,
  or (cheaper) hold a [`subscribe`](#live-event-stream) stream open and wait for the `trust` event
  with `event: "pair"` naming the peer, then read that peer's `sas_code` from `recent_pairings`.

Both sides then display the same words for the out-of-band human check. `recent_pairings` is an
in-memory ring (the last few completions), cleared on daemon restart — it is a display aid for the
ceremony, never trust state, and the SAS is deliberately kept out of the durable audit log.

## Sessions

`open_session` is special: it is the one method that turns the control connection into a **raw MCP
pipe**. The client sends:

```json
{"method":"open_session","params":{"peer":"alice","service":"notes"}}
```

…and then does **not** read a JSON-RPC response. Instead, the daemon dials the peer's service across
the mesh and, from that point, every byte in each direction is the remote MCP session verbatim —
`initialize`, `tools/list`, `tools/call`, and so on, in the same newline-framed JSON. The client
pumps its consumer's stdin/stdout against this connection until either side closes.

`peer` may be a **local nickname** or the peer's **stable `b64u:` user_id** — the same
self-sovereign identity attested *inbound* on `_meta["mcpmesh/peer"].user_id` (see [the identity
contract](#the-identity-contract)). Addressing by `user_id` makes outbound symmetric with inbound:
an embedder that keys its own contacts by a portable identity can dial `open_session(<user_id>,
service)` directly, without maintaining a `URN → nickname` map. A `user_id` that spans several of a
person's devices races them, exactly like a roster person→device dial; a nickname resolves the one
peer it names. Either way the dial is still pinned to the peer's endpoint key and TLS-authenticated —
the identity string is a lookup handle, never the trust decision.

Two failure frames can arrive *in place of* a live session, as ordinary MCP error frames, so a
consumer always gets a well-formed answer rather than a hang:

- `-32055` — peer unreachable.
- `-32054` — session refused (e.g. not authorized).

- `-32053` — rate-limited, carrying `retry_after_ms`. See the warning below.

All carry `"data":{"source":"mcpmesh"}` to distinguish a mesh-synthesized error from one the remote
server produced. A session severed mid-stream instead surfaces as a clean EOF.

> **Rate-limited notifications are dropped silently — design for it.**
>
> The per-peer rate limiter is consulted before forwarding any method-bearing frame. Over the limit:
>
> - a **request** (an `id` present and non-null) is answered `-32053` with `retry_after_ms`, so the
>   caller learns it was throttled and can back off;
> - a **notification** (no `id`) is dropped with **no signal at all**.
>
> JSON-RPC gives a notification no reply channel, so there is nowhere to put the refusal. The
> consequence is that notification delivery is **not guaranteed under load**, and the loss is
> *undetectable from the sending side* — a dropped notification is indistinguishable from a
> delivered one.
>
> If you rely on server-initiated pushes, a reconciliation path is **mandatory, not an
> optimization**: reconcile periodically, or carry a sequence number your peer can notice a gap in.
> Do not treat notifications as an at-least-once channel.
>
> Whether the daemon should surface dropped-notification counts (a `status` counter, an audit
> record, or a `subscribe` frame) is tracked in
> [#76](https://github.com/counterpunchtech/mcpmesh/issues/76).

This is exactly what `mcpmesh connect <peer>/<service>` does; an embedding client that wants to mount
a remote service itself reproduces this upgrade. Reference:
[`cli/src/proxy.rs`](../cli/src/proxy.rs).

## Live event stream

`subscribe` is the other method that upgrades the connection. Like [`open_session`](#sessions), the
socket **stops being request/response** after this call. The client sends:

```json
{"method":"subscribe"}
```

…and then does **not** read a JSON-RPC response. Instead the daemon pushes a **one-way** stream of
newline-delimited frames — a live view of the mesh for an embedding UI to render — until the client
disconnects. There is no request channel back; to stop, close the connection.

Every frame is a JSON object tagged by a `"type"` field, in one of three shapes.

**`snapshot`** — always the **first** frame: a point-in-time picture, so a fresh subscriber renders
immediately without replaying history. It carries the currently-open sessions and the paired-peer
`reachability` (the same list [`status`](#statusresult) reports).

```json
{
  "type": "snapshot",
  "active_sessions": [{"peer": "bob", "service": "notes", "opened_at": 1751760000}],
  "reachability": [{"name": "bob", "reachable": true, "rtt_ms": 42, "age_secs": 3}]
}
```

Each `active_sessions` entry is one live session: the caller's nickname/`user_id` (`peer`), the
mounted `service`, and `opened_at` (epoch seconds). This list is the starting state — a client keeps
its session view current by applying subsequent `session_open`/`session_close` events to it. Only a
`session_open` **without** an error status opens a real session: a `session_open` carrying
`status: "error"` is a terminal *attempted-and-failed* marker (a failed dial — see below)
that never pairs with a `session_close`, so a client must **not** add it to the active view — doing so
strands a phantom session. The snapshot's `active_sessions` already excludes failed dials.

**`event`** — one audit record, emitted live as it happens. `record` is the daemon's audit record
**verbatim** — the same schema written to the local audit log, so the stream and the log carry one
shape.

```json
{
  "type": "event",
  "record": {
    "ts": "2026-07-03T14:02:11.480Z",
    "kind": "request",
    "peer": "bob",
    "service": "notes",
    "method": "tools/call",
    "tool": "read_file",
    "args_hash": "blake3:…",
    "bytes_out": 6210,
    "status": "ok",
    "latency_ms": 41
  }
}
```

`record.kind` is one of `session_open`, `session_close`, `request`, `blob_fetch`, `trust`. `ts` is
an RFC3339-millis UTC timestamp. Every field beyond `ts` and `kind` is optional and present only
when it applies:

- `peer` — the caller's nickname/`user_id` (absent on a local-only event with no remote peer).
- `service` — the mounted service name.
- On a `request` (one proxied MCP line): `method` (the MCP method, e.g. `tools/call`), `tool` (the
  tool **name** only, for a `tools/call`), `args_hash` (a `"blake3:…"` digest of the arguments —
  **never** the raw arguments), `bytes_out` (a byte **count** of the response, never its content),
  `status` (`"ok"` \| `"error"`), and `latency_ms`.
- On a `blob_fetch` or `trust`: `target` — the blob's `"blake3:…"` hash, or the trust operation's
  target (a nickname or `org/serial`) — and, on a `trust`, `event` (the trust verb: `pair`, `unpair`,
  `roster_install`, `revoke`).

A **failed dial** surfaces as a `session_open` with `status: "error"` — it reached no backend, so it
is otherwise never session-audited; this frame records the attempted-and-failed reach.

Upholding the surface discipline: a record carries names, counts, and a status — a nickname/`user_id`,
a service name, a method/tool name, an argument **digest**, and byte/latency **numbers** — never raw
arguments, response content, endpoint-ids, or keys.

**`reachability`** — a peer went online or offline (`api_minor >= 12`, #58). Pushed so you do not
have to poll `status` for a liveness indicator, and so work queued for an unreachable peer can flush
the instant it returns rather than on the next poll tick.

```json
{
  "type": "reachability",
  "peer": {
    "name": "bob",
    "reachable": true,
    "rtt_ms": 12,
    "age_secs": 0,
    "meta": "",
    "principal": "eid:9f2k…"
  }
}
```

`peer` is a whole `PeerReachability` row — the same shape the opening `snapshot`'s `reachability`
list carries, so both project through one code path.

### `path` — direct or relayed (`api_minor >= 13`, #64)

Every `PeerReachability` row carries how the peer is reached:

```json
"path": {"kind": "direct"}
"path": {"kind": "relay", "url": "https://relay.example/"}
"path": {"kind": "unknown"}
```

- `direct` — a direct or hole-punched QUIC path. The bytes did not transit a relay.
- `relay` — through a relay server, so the path depends on third-party infrastructure. `url` is the
  relay when known.
- `unknown` — never probed, no active transport address, or a transport mcpmesh does not model.

**Only `direct` supports a locality claim.** `unknown` means "we do not know" — rendering it as
"private" is the one misuse that turns this field into a false privacy statement, and a row from a
pre-`api_minor`-13 daemon defaults to `unknown` precisely so it cannot be mistaken for a guarantee
that daemon never made.

The daemon errs the same way: while hole-punching, a relay and a direct path can BOTH be active, and
it reports `relay` in that case. Overstating privacy is worse than understating it.

`path` is captured by the same probe that sets `reachable`/`rtt_ms`, so it shares their freshness —
one TTL, one `age_secs`. `rtt_ms` is not a proxy for it: a fast relay beats a slow direct path.

**A first probe may report `unknown`.** A fresh connection starts on the relay and hole-punches in
the background; the daemon waits briefly for the path to settle, but under load that can time out.
The next probe reports the settled answer. So treat `unknown` as "not yet known" and re-read, rather
than as a stable property of the peer — and never as "private".

A path change alone does **not** emit a `reachability` frame — only the `reachable` verdict flipping
does. Hole-punching flaps by nature, and the stream stays quiet through it; read `status` if you
need the current path.

Emitted on a **transition** only: the `reachable` verdict changed, or this is the first probe of
that peer. A refreshed probe that re-confirms the same verdict emits nothing, so a peer that stays
up does not produce a frame per cache refresh; `rtt_ms`/`meta` drift is advisory detail, not a
transition. `age_secs` is `0` — the probe just completed.

This is the **pairing-mode probe**. Roster-mode presence travels on the gossip topic and surfaces
through `status`; it is not (yet) an event here.

**`lagged`** — the subscriber fell behind one of the daemon's bounded rings and `dropped` messages
were skipped. The stream is **not** dropped and continues; **reconnect** to get a fresh `snapshot`
and resume in sync.

A `lagged` frame may account for skipped **audit events or reachability transitions** — it does not
say which. That matters for liveness: a missed `reachability` transition is **never re-asserted**
(the next frame comes only on the next flip), so a consumer that shrugs off `lagged` can hold a
stale online/offline indicator indefinitely. If you render liveness, treat `lagged` as "resync":
reconnect, or fall back to a `status` read.

```json
{"type": "lagged", "dropped": 12}
```

Typed Rust bindings for these frames (`StreamFrame`, `ActiveSession`, and the audit record) ship in
[`mcpmesh-local-api`](../local-api/src/protocol.rs), and `ControlClient::subscribe` yields them
directly, so a Rust consumer deserializes the stream instead of hand-parsing it. `mcpmesh internal
watch` is a thin reference consumer of this stream.
Reference: [`local-api/src/client.rs`](../local-api/src/client.rs).

## The identity contract

This is the part that matters even if you never speak `mcpmesh-local/1`: **how a shared MCP server
learns who is calling it.** mcpmesh authenticates the caller cryptographically and hands your server
a verified identity — *per call*, never forgeable by the caller. There are two mechanisms, one per
backend kind.

### `run` backend — environment variables

A `run` service is spawned fresh per session, so identity arrives as environment variables the
process reads at startup:

| Variable | Meaning |
|---|---|
| `MCPMESH_PEER_EID` | the caller's **stable device principal**, `eid:<hex>` — the authenticated endpoint id (#60, `api_minor >= 14`). **Always present** for a resolved caller. Scope per-caller state on this. |
| `MCPMESH_PEER_NAME` | the caller's nickname (your local name for them) — **display only**; it collides and changes under a rename |
| `MCPMESH_PEER_USER` | the caller's verified `user_id`, spanning all their devices — a **bare handle** in roster mode (`alice`), a `b64u:…` principal in pairing mode. **Absent** when a pairing peer presented no device→user binding, and see the warning below: it is *not* stable for a fixed device |
| `MCPMESH_PEER_GROUPS` | comma-joined roster groups (may be empty) |

```python
import os
# KEY PERSISTENT STATE ON THE DEVICE PRINCIPAL. It is the only identifier that is always
# present and never changes for a given caller. `[...]` not `.get(...)`: failing loudly beats
# silently sharing one bucket between callers.
storage_key = os.environ["MCPMESH_PEER_EID"]

# Use the user_id for cross-device POLICY ("is this the same person?"), not as a storage key.
person = os.environ.get("MCPMESH_PEER_USER")  # may be absent, and may change — see below
```

> **`MCPMESH_PEER_USER` is not stable for a fixed device.** It can appear, disappear, or change for
> the same physical caller, so keying stored state on it loses that state:
>
> - An unbound pairing peer that later proves a device→user binding flips `eid:…` → `b64u:…`.
> - If the org roster goes stale or expires past its grace window, a rostered peer falls back to its
>   pairing identity and the value flips `alice` → `eid:…` — with no operator action, and back again
>   when a fresh roster installs.
> - One person on two unbound devices has no shared value at all.
>
> It also spans three namespaces (a bare roster handle, `b64u:…`, `eid:…`), so a bare handle can
> collide with a group name or an attacker-chosen literal in a `caller`-keyed store. Key on
> `MCPMESH_PEER_EID`; consult `MCPMESH_PEER_USER` for policy.


### `socket` backend — MCP `initialize` `_meta`

A `socket` service is a warm, shared process (like the `kb` daemon), so identity cannot ride in
per-process env. Instead the daemon injects it into the MCP `initialize` request it forwards, under
`params._meta["mcpmesh/peer"]`:

```json
{"name": "alice", "user_id": "b64u:…", "groups": ["team-eng"]}
```

This value is **authoritative**: the daemon strips any caller-supplied `mcpmesh/*` `_meta` keys and
overwrites this object, so a caller cannot forge who they are. `user_id` is `null` when a pairing peer
presented no binding.

### Using it well

- **Authorize on `user_id`, not the nickname.** The nickname is *your* local label; the `user_id` is
  the cryptographically verified identity, and it is the same across all of that person's devices.
- **The tool surface is the disclosure policy.** `search_notes(query)` grants something categorically
  narrower than `read_file(path)` over the same data. Design the tools you expose as the permission
  you are granting.
- mcpmesh authenticates *who* is calling and encrypts the pipe. It does **not** vet *what* your
  server returns, nor what a peer's server returns to you — treat a peer's tool output like any
  content from that person.

Reference: [`cli/src/backends/spawn.rs`](../cli/src/backends/spawn.rs) (`run`),
[`cli/src/backends/socket.rs`](../cli/src/backends/socket.rs) (`socket`).

## Error codes

| Code | Meaning |
|---|---|
| `-32600` | invalid request (the frame has no `method` field) |
| `-32601` | unknown method |
| `-32602` | invalid params (a required field missing or the wrong type) |
| `-32603` | internal error |
| `-32040` | no such service — the name is in neither `config.toml` nor the ephemeral registry (`service_allow_grant` / `service_allow_revoke`, `api_minor >= 11`) |
| `-32000` | operation failed — `message` carries the detail. One common instance: the daemon is in control-only mode with no mesh (e.g. `invite`/`pair` before a mesh exists) |
| `-32055` | *(session only)* peer unreachable |
| `-32054` | *(session only)* session refused |
| `-32053` | *(session only)* rate-limited; carries `retry_after_ms`. **Requests only** — a rate-limited *notification* is dropped silently, see below |

`-32600` through `-32603` follow their JSON-RPC 2.0 meanings. Session errors (`-3205x`) appear
inside a [session](#sessions), not as control-method responses, and carry `data.source = "mcpmesh"`.

## Versioning

The API is `mcpmesh-local/1`. Two version numbers travel on the `Hello`, and they mean different
things:

- **`api` / the `/N` major** — bumped only on a breaking wire change (`mcpmesh-local/2`). The
  transport already rejects a mismatched `api`, so a client needs no explicit equality check.
- **`api_version` = `"MAJOR.MINOR"`, and `api_minor` = the integer MINOR** — the
  protocol-compatibility version, **distinct from `stack_version`** (the crate release train, which
  moves for reasons unrelated to the wire). MINOR increments on **every** surface change within a
  major: an added field, a new method, or a strictness change. It is bumped in the same change that
  makes it, and never resets except on a MAJOR bump. A client guards a feature it needs with
  `api_minor >= N` — e.g. strict params validation is `api_minor >= 1`; the `set_app_metadata`
  verb + `PresencePeer.meta` are `api_minor >= 4` (#39); `PeerReachability.meta` — the same
  app metadata on the pairing-mode probe pong — is `api_minor >= 5` (#40); `PeerInfo.principal`
  (a peer's eid: device principal) is `api_minor >= 6` (#41); `PeerReachability.principal` —
  the same on reachability rows — is `api_minor >= 7` (#42); the `service_allow_grant`/
  `service_allow_revoke` per-peer access verbs are `api_minor >= 8` (#44); `unregister_service` (#50), the `run`-backend `env`/`cwd` (#51), `peer_services` (#52), and the `set_relays` live relay-set verb (#53) are `api_minor >= 9`; IMMEDIATE revocation
  (`service_allow_revoke`/`peer_remove` refuse new sessions on already-open connections AND sever
  live ones, #54) is `api_minor >= 10`; `AuditRecord`-adjacent surfaces aside, the pushed
  `reachability` frame (#58) is `api_minor >= 12`, `PeerReachability.path` (#64) is
  `api_minor >= 13`, and the `run`-backend `MCPMESH_PEER_EID` identity var (#60) is
  `api_minor >= 14`; ephemeral-service grant/revoke plus the `-32040`
  no-such-service error (#55, #69) are `api_minor >= 11`; app blobs in PAIRING mode (#61) are
  `api_minor >= 16`; the `blob_revoke` / `blob_unpublish` verbs
  (#62) are `api_minor >= 15`; the pushed `reachability` stream frame (#58)
  is `api_minor >= 12`; the `set_nickname` verb
  and `StatusResult.self_nickname` are `api_minor >= 2` (#37); STABLE-principal `allow`
  strings + `ServiceInfo.allow_display` are `api_minor >= 3` (#38). `api_minor` is itself
  additive: a pre-1.1 daemon omits it and it reads as `0`.

Changes remain **additive within a major**: new response fields are optional (absent-tolerant), so a
newer daemon's payload still parses in an older client and vice versa. Build defensively — ignore
fields you do not recognize, and do not assume an optional field is present.

### Params are strict; the envelope is tolerant

The two are deliberately different. The **envelope** (the keys beside `method`/`params`/`id`) is
tolerant — unknown top-level fields are ignored, so a conforming client can send extra envelope
metadata. **Params are strict**: every method's `params` object rejects unknown fields
(`-32602 invalid params`), so a typo like `{service: "kb"}` for `invite` (singular — the field is
`services`) fails loudly instead of silently minting a wrongly-scoped invite. One consequence for
forward-compat: a *newer* client that sends a *new* optional param field to an *older* daemon is
rejected rather than having the field ignored — gate such a send on `api_minor`.

## Security model

- **Same-user only.** On macOS/Linux the socket lives in a `0700` directory the daemon owns, is
  itself `0600`, and the daemon checks the connecting process's uid against its own before serving.
  On Windows the pipe carries an owner-only DACL, so the kernel enforces the same restriction before
  the daemon ever sees the connection. Either way there is no network listener and no authentication
  token because there is no cross-user or cross-machine access to this endpoint — the boundary is the
  OS user account.
- **Local paths are trusted.** Methods that take a `path`/`dest_path` have the daemon read or write
  that file directly. That is safe precisely because only the same user can issue the call.
- **Keys never cross the socket.** `org_join` passes a *path* to the user key, not the key bytes; the
  private key stays `0600` on disk.

## Where the truth lives

This document describes the surface; the code defines it.

- Protocol types & method table — [`local-api/src/protocol.rs`](../local-api/src/protocol.rs)
- Client (connect, handshake, request/response, session upgrade) —
  [`local-api/src/client.rs`](../local-api/src/client.rs)
- Frame codec — [`codec/src/lib.rs`](../codec/src/lib.rs)
- Endpoint/path resolution — [`local-api/src/paths.rs`](../local-api/src/paths.rs)
- Identity injection — [`cli/src/backends/`](../cli/src/backends/)
- Live event-stream frames — [`local-api/src/protocol.rs`](../local-api/src/protocol.rs)
  (`mcpmesh internal watch` in [`cli/src/stream.rs`](../cli/src/stream.rs) is the reference consumer)

The `mcpmesh-local-api` crate is [published to crates.io](https://crates.io/crates/mcpmesh-local-api):
Rust clients can depend on it directly (`client` feature) rather than reimplementing the wire format.
