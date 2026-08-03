# The `mcpmesh-local/1` protocol

This is the wire contract between the mcpmesh daemon and the programs on the **same machine** that
drive it — the CLI, the desktop host, and plugin daemons like `kb` and `loc`. It is a small,
line-delimited JSON protocol over a same-user local endpoint: a Unix domain socket on macOS/Linux, a
named pipe on Windows. Anything that can open the endpoint and parse JSON can speak it, in any
language — [`local-api/examples/status.py`](../local-api/examples/status.py) is a complete client
in ~60 lines of dependency-free Python.

> **Status: pre-release.** The API is versioned `mcpmesh-local/1` (`api_version` `1.41`, `api_minor` `41`) and evolves
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
| `audit_prune` | `{before:"YYYY-MM"}` — delete audit months **strictly older** than `before` (that month itself is kept), `api_minor >= 27` (#88). The month shape is validated up front: a malformed key is an error, never a silent no-op. Idempotent; local-only; owner-only (the control socket). | `{deleted_months:[…]}` ascending |
| `audit_list` | `{since?, until?, kind?, peer?, limit?, offset?}` — read this node's **local** audit records, filtered (AND-combined) and paged, `api_minor >= 27` (#88): the "show me everything you hold about me" verb. `since`/`until` are inclusive `YYYY-MM` month keys (the rotation unit). `kind` is one of `session_open` / `session_close` / `request` / `blob_fetch` / `trust` — an unknown kind **errors** rather than silently matching all. `limit` defaults to 500 and is **clamped to 1000** (the response is one JSON frame; `blob_list`'s minor-20 lesson). `total` counts ALL matches, so a caller pages without a second counting call. | `{records:[AuditRecord…], total}` chronological (oldest month first) |
| `invite` | `{services:[…], max_uses?, peer_nickname?}` — mint a pairing invite. **`peer_nickname`** (#87, `api_minor >= 39`) is YOUR local name for whoever redeems, overriding the nickname they claim for themselves — for two same-model laptops, the fix that does not require the other person to rename their machine. Never sent to them (it is stripped from the invite line) and it does **not** bypass the collision check: an alias that itself collides is refused identically. Rejected with `max_uses > 1`, since one alias applied to every redeemer would collide on the second redemption. **Outstanding invites survive a daemon restart** (`api_minor >= 34`, #87b): they are persisted, so `expires_at_epoch` is the real lifetime rather than an upper bound on process lifetime, and a mint that cannot be persisted is an ERROR rather than an invite that will quietly not survive. **`max_uses`** (#87, `api_minor >= 35`) makes it redeemable that many times, each redemption running its OWN SAS ceremony and writing its own peer rows — N independent pairings sharing one secret, never a group identity. Absent = 1. `0` is rejected (`-32602`); above `MAX_INVITE_USES` (64) is clamped, and `uses_remaining` in the result is the value ACTUALLY applied — read it rather than assuming your request was honoured. Sending `max_uses` to an `api_minor < 35` daemon FAILS with `-32602 unknown field` rather than degrading to single-use (params are strict), so omit it unless you have checked. | `{invite_line, expires_at_epoch, uses_remaining}` |
| `pair` | `{invite_line, as_nickname?}` — **`as_nickname`** (#87, `api_minor >= 39`) is YOUR local name for the inviter, overriding the one its invite suggests. This is how you resolve a name collision yourself instead of asking them to re-mint; `set_nickname` is not the answer, it rewrites your own GLOBAL self-name. Never sent to the inviter, and it does not bypass the collision check. | `{peer_nickname, sas_code, services:[…], app_label?, peer_user_id?}` — `app_label` echoes any opaque label the inviter attached (#31); `peer_user_id` is the inviter's stable `b64u:` identity when it presented a binding (#30). **Grants MUTUALLY (#43):** redemption grants the inviter access to ALL services THIS (redeemer) node serves — under the same stable-principal rule as the inviter-side grant — so one ceremony admits both directions. Fails (no dial attempted) if the invite's suggested nickname is already yours for a *different* peer; see [Nickname collisions](#nickname-collisions) |
| `peer_remove` | `{nickname}` | `{}` (ack) |
| `peer_rename` | `{to, user_id?, nickname?}` — rename a person by `user_id`, else a provisional contact by `nickname` | `{}` (ack) |
| `set_nickname` | `{nickname}` — rename **this node** live (#37, `api_minor >= 2`): validated (trimmed non-empty, no `/`), persisted to `[identity].nickname` under the daemon's own config lock (no lost-update window against a concurrent grant/registration), and effective for FUTURE invites/presentations immediately — no restart. Display-only: peers keep the nickname they stored at pairing time until a re-invite | `{}` (ack) |
| `service_allow_grant` | `{service, principal}` — grant a stable principal (`b64u:`/`eid:`) access to ONE service's allow WITHOUT (re)pairing (#44), under the daemon's config lock + hot-reload. The per-peer "sharing on" toggle. Works on EPHEMERAL registrations too, mutating their in-memory allow (#55, `api_minor >= 11`). Idempotent; a name in neither the config nor the ephemeral registry → `-32040`. **When the edit lands only in the ephemeral overlay (nothing changes on disk), the registry is updated in place rather than rebuilt from `config.toml` — so the verb no longer picks up unrelated hand-edits to the config file as a side effect (#94). Use `register_service` or a daemon restart to apply config edits.** | `{}` (ack) |
| `service_allow_revoke` | `{service, principal}` — remove ONE allow entry from ONE service WITHOUT unpairing (#44): the peer's `PeerEntry` identity is untouched. **`principal` is matched as an EXACT STRING, never resolved — so any literal in the list is a valid target, including a BARE entry** (a legacy nickname from a pre-#38 config, a roster group name). See the note below (#149). **Immediate at `api_minor >= 10`** — see "Revocation is immediate" below. Works on EPHEMERAL registrations too (#69, `api_minor >= 11`). Idempotent; an absent principal is a clean no-op, a name in neither the config nor the ephemeral registry → `-32040`. **Same overlay-only fast path as `service_allow_grant`: when nothing changes on disk the registry is updated in place rather than rebuilt, so unrelated `config.toml` hand-edits are not applied as a side effect (#94).** | `{}` (ack) |
| `unregister_service` | `{name}` — remove a service registration (#50), the mirror of `register_service`: drops the whole `[services.<name>]` entry (allow included) + any ephemeral registration, then hot-reloads. Idempotent; unknown name → clean no-op. In-flight sessions finish; no new ones admitted. | `{}` (ack) |
| `peer_diagnostics` | `{peer}` — dump the DURABLE state this node stores for one peer (#140, `api_minor >= 33`): the persisted dial hint verbatim, whether it is actually usable (an unparseable or id-mismatched hint is silently discarded at every dial), the addresses inside it, the pairing stamp, and the live reachability row. **The one verb that deliberately carries transport vocabulary** — see the note below. Read-only: probes nothing, dials nothing, writes nothing. | `PeerDiagnosticsResult` |
| `peer_services` | `{peer}` — discover which services a paired `peer` (nickname / `eid:` / `b64u:`) CURRENTLY grants you (#52): dials the peer over `mcpmesh/ping/1` and returns `{services:[…]}` — the names whose allow admits YOUR principal (only yours, never the peer's full registry). **Reuses a reachability-cache entry younger than ~20s rather than always dialing (#89)** — an unconditional probe collided with the `mcpmesh/ping/1` rate limiter, and a refused probe is reported as unreachable, so polling this verb faster than ~1/s made a healthy peer appear offline. Freshness is now the same contract `status` gives. **Answered from the LIVE service registry — the same one the accept path authorizes from (#100, `api_minor >= 17`). A service present in `config.toml` but not yet loaded is NOT reported: it would be refused on connect, which a caller cannot distinguish from a network failure. `status` likewise lists only live services.** | `{services:[…]}` |
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
| `blob_republish` | `{scope, hash}` — make a blob this daemon ALREADY holds servable **from here**, in a scope it controls (#83, `api_minor >= 18`). No filesystem round-trip and no third copy: `blob_publish {scope, path}` was the only route back in and re-imported bytes the store already held. The blob must be held **COMPLETE** — an absent hash, or partial bytes from an interrupted fetch, answer `-32041`. A hash deliberately WITHDRAWN by `blob_unpublish` answers **`-32042`** and is NOT restored — see the warning below (#107, `api_minor >= 19`). **Grants nobody NEW** — but see the warning below: it re-exposes the hash to every principal the target scope already grants. The returned ticket names THIS node. Idempotent. | `{ticket, hash}` |

> **As of `api_minor >= 19` (#107), `blob_republish` can no longer undo a `blob_unpublish` for that
> hash IN THAT SCOPE.**
>
> The withdrawal is per-`(scope, hash)`. Republishing the same hash into a **different** scope on
> this node is still allowed and will expose it to whatever that scope grants — and `blob_grant`
> creates a scope implicitly, so two cheap calls can re-expose withdrawn content under a new name.
> That is by design (a scope is the unit of sharing), but do not read "unpublish" as "this content
> can no longer be served from here". `blob_unpublish` records a durable withdrawal, persisted with the scope table, and a later
> `blob_republish` of that hash into that scope is refused with `-32042`. The withdrawal is cleared
> only by a deliberate `blob_publish {scope, path}` — naming the FILE — because that is an operator
> re-sharing specific content on purpose. `blob_grant` never clears it: it names a principal, not a
> hash.
>
> Still true, and unchangeable: a recipient's re-advertisement from a DIFFERENT node is outside your
> control. Content addressing means these verbs bind only where they run. Treat them as "stop
> serving from here", never as "unshare from everyone".
>
> *(Before `api_minor` 19 the following applied, and is why #107 existed:)*
> **`blob_republish` can undo a `blob_unpublish`.** Unpublish removes reachability, not bytes
> (there is no reclaim — #80), so the blob stays complete in the local store indefinitely and
> `blob_republish` will happily re-add it to the same scope, whose grants unpublish never touched.
> Every principal that scope grants regains access immediately, with no grant call and no warning.
>
> Do **not** call `blob_republish` unconditionally after each fetch as hygiene — call it when a user
> asks to re-share. Note also that a recipient's re-advertisement is outside the original
> publisher's control entirely: content addressing means `blob_revoke`/`blob_unpublish` bind only
> the node they run on. Treat them as "stop serving from here", never as "unshare from everyone".

| `blob_list` | `{scope?, hash?, limit?, offset?, counts_only?}` — the daemon's scopes (name → hashes + grants + withdrawn + counts). **All params optional; `blob_list {}` still works.** `scope` is an EXACT match, never a prefix. `hash` is normalized before comparing. **A DEFAULT LIMIT of 256 scopes applies when `limit` is absent (#84b, `api_minor >= 20`)** — unpaged, this verb rendered every scope into one frame against the 16 MiB cap; past it the CLIENT rejects the frame as malformed. The control surface carries **no** strike bound, so the connection survives — but you get an opaque error and no way to page, which is an unusable answer rather than a large one. **Note the cap counts SCOPES, not bytes:** one legacy scope holding very many hashes can still exceed the frame at `limit: 1` (see #84a). Check `truncated` and page with `offset`; `total` is the match count BEFORE limit/offset. `counts_only` omits the three vectors and keeps `hash_count`/`grant_count`/`withdrawn_count`. | `{scopes:[…], total, truncated}` |
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
> - **A partially fetched blob's chunks stay in the store.** They are not listed by `blob_list`
>   (which lists published scopes, not raw store contents) and there is no reclaim path yet (#80),
>   so an abandoned fetch leaves bytes on disk that nothing surfaces or frees.
>
> Both remaining limits are tracked in
> [#172](https://github.com/counterpunchtech/mcpmesh/issues/172).
>
> **Progress IS reported, from `api_minor >= 41`** (#82): subscribe on a *separate* control
> connection and read `StreamFrame::BlobTransfer` — it arrives on both the serving and the fetching
> side, so a stalled transfer is now distinguishable from a slow one even while the fetching
> connection is blocked. `Progress` frames are **coalesced** (at most ~102 per transfer whatever its
> size), and the last one before `Completed` is usually skipped by the stride — read the final byte
> count off `Completed`, never off the last `Progress`.
>
> On the fetching side `bytes_total` is `None`: the size is learned as bytes arrive, so render an
> indeterminate bar until `Completed`. The serving side knows it from `Started`.

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

### Removing an allow entry no other path will strip (#149)

`service_allow_revoke` matches `principal` as an **exact string** — it is never resolved — so any
literal already in the list is a valid target, **including a bare entry**: a nickname left behind by
a pre-#38 config, a roster group name, anything. That is the remedy for an entry that has outlived
its meaning.

Two neighbouring paths deliberately will not do it, and reading them together suggests such an entry
is permanent. It is not:

- **`peer_remove` (unpair)** strips the peer's stable principals but never bare strings, on purpose:
  post-#38 a bare entry is roster vocabulary, and a nickname-keyed strip could collide with a group
  name and revoke a whole roster group.
- **`register_service`** unions the incoming allow with what is on disk, so re-registering cannot
  drop an entry either.

Naming a literal has no group-vs-nickname hazard *for the strip*, which is why it is allowed where
resolving a name is not: exactly one line goes, and it is the one you named.

**The sever is a different matter, and is the one thing to be careful about.** After the strip,
revocation is immediate (above) — live connections for the revoked principal are cut, and THAT
lookup does resolve, through roster `user_id`s and group membership. So revoking a bare literal that
happens to match a live roster group severs every device in that group, including their sessions to
*other* services. Access elsewhere is unchanged and clients reconnect, so this is bluntness rather
than a security problem — but if you are pruning dead vocabulary on a roster node, check the string
is not also a live group name first.

The other corollary: an exact match is exactly as literal as it sounds. Revoking `b64u:<user>`
removes that entry outright, **without** the multi-device protection unpairing applies (which keeps
a shared `b64u:` while another paired device still carries it). You named the string, so the string
goes.

**Reading which entries are stale.** `status`'s `services[].allow_display` is index-aligned with
`allow`: an `eid:` with no matching peer entry renders `unpaired-device`, a `b64u:` with none
renders `unpaired-peer`, and a bare entry renders verbatim.

Two limits on reading it as "this entry is dead":

- The daemon cannot classify a bare entry at all — it cannot tell a live roster group from dead
  legacy vocabulary, because in **pairing** mode there is no roster to check against.
- `allow_display` resolves against **paired-peer entries only, never the roster**. On a roster node
  an `eid:` can render `unpaired-device` and still be admitted, because the roster gate authorizes
  from the authenticated endpoint id without needing a `PeerEntry`. So `unpaired-*` means "no
  display name available", NOT "admits nobody". In a pure-pairing daemon the two coincide; do not
  carry that assumption onto a roster node.

There is currently no CLI subcommand for this verb — it is control-API only, so an operator without
an embedder still has no remedy but a config edit.

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
  different endpoint is refused. Since #87 the collision is checked **before** the invite is
  burned, so the refusal names the collision, states the invite was NOT consumed, and the
  redeemer can `set_nickname` and redeem the **same** invite again. This is not an oracle: the
  distinguishable reason is only ever sent to a caller that proved possession of a live invite
  secret — an unproven dialer (wrong/expired secret) still gets the generic `pairing refused`
  with no detail about which names exist. Known trade: because the refusal no longer burns, a
  live-invite HOLDER can retry names and enumerate which display names exist on the inviter —
  someone the inviter deliberately invited, learning names only (never ids or grants; grants
  are principal-keyed), bounded by the pair limiter, and each attempt is warn-logged on the
  inviter.
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
  "self_nickname": "workbench",
  "storage": {"audit_bytes": 18234, "redb_bytes": 1069056, "blobs_bytes": 0},
  "self_network": {"online": true, "home_relay": "https://relay.example:443",
                   "relays": [{"url": "https://relay.example:443", "connected": true}],
                   "direct_addrs": ["192.168.1.20:53420"], "last_change_epoch": 1753842000}
}
```

`roster`, `presence`, `self_user_id`, and `recent_pairings` are optional — absent on a pure-pairing
daemon with no roster and no user key. `backend` reports the *kind* (`"run"` \| `"socket"`) only,
never the command or path.

`self_network` (`api_minor >= 28`, #90) is THIS node's own reachability posture — the first
question in every "my message never arrived" investigation. `online` uses **iroh's semantics**: a
home-relay connection is established. In `relay_mode = "disabled"` it is always `false` with an
empty `relays` list — that is a *configuration* (LAN-only), not an outage; do not render it as a
health warning. `home_relay` is the connected relay, sanitized to scheme+host+port (operator relay
URLs can carry credentials). `direct_addrs` are the node's own dialable coordinates (the same ones
its invites embed). `last_change_epoch` is when the daemon's watcher last saw the block change —
`null` until the first change after boot. No per-relay latency: iroh's `net_report` is
unstable-feature-gated as of 1.0.3; `connected` is the stable truth. `identity_conflict_epoch`
(`api_minor >= 32`, #134) is when another endpoint was last seen presenting THIS node's identity,
absent if never — see its own section below, including why absence does not mean "unique". A change
of `online`, the home relay, any relay's connection state, **or a new identity-conflict
observation** also pushes a `self_network` frame on `subscribe` (and the subscribe snapshot carries
the block), so an embedder learns "you just went unreachable" without polling — the signal
`set_relays` (#53) never had.

`storage` (`api_minor >= 27`, #88) is this node's own on-disk footprint — counts, never content:
the summed monthly audit files, the `state.redb` trust store, and the app-blob store directory
(0 when none exists). Computed **live** per call, so an embedder can warn a user before ENOSPC —
the audit log's write rate is driven by inbound peer traffic and it shares a filesystem with the
trust store and device key. Bound the audit half with `audit_prune` or
`[limits].audit_retain_months` (see `docs/config.md`). Absent in mesh-less control-only mode.

`reachability` is **advisory** — an on-demand liveness read of your paired peers, populated by a
probe cache the daemon refreshes lazily. It is empty until the first probe completes. A `status`
call kicks off a background refresh for any peer whose entry is stale or missing, but **never blocks
on a probe**. Each entry is a **nickname** (`name`, never an endpoint-id), a `reachable` bool (the
last probe result), `rtt_ms` (the last measured round-trip — dial + ping/pong, stamped at the
pong; it EXCLUDES the window the daemon spends determining the path, so a relayed peer can report
under 600ms, #123 — present only when reachable), and
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

### Server-initiated frames (push), and what is metered

A served backend — `run` or `socket` — **may** write unsolicited notifications and requests to the
connected peer, not only responses. This is a contract, not an accident (#91): it is what lets an
agent *react* to an incoming message instead of polling for one.

**Outbound frames are NOT metered.** `[limits].rate_limit_per_min` applies only to what the REMOTE
peer sends inbound. The limiter is keyed on `(service, authenticated endpoint)` since #63 — before that one bucket was shared across every service a peer could reach, so a noisy service starved a quiet one, and
an outbound frame originates from YOUR local server — charging it against the peer's budget would
let a chatty local server exhaust the allowance of the peer it is talking to. So push is free and
polling is not; budget accordingly.

*(Contrast the inbound direction, which consults the limiter before forwarding a method-bearing
frame, answers `-32053` with `retry_after_ms` for a request, and **drops** an over-limit
notification with no reply — none is possible — but records it (#76).)*

**Ordering is FIFO in the server's own output order.** Both directions write through the same
mutex-guarded transport writer, and the outbound direction reads the server's stdout sequentially,
so a notification emitted between two responses arrives between them. There is no reordering and no
separate priority channel.

**Backpressure reaches the local server.** A blocked send stops the outbound direction draining the
server's stdout, so the OS pipe buffer fills and the server blocks on write. There is **no bounded
queue and no buffering** — a slow or gone peer applies backpressure rather than accumulating frames
in the daemon. That is deliberate: the alternative is unbounded memory growth keyed on a peer that
may never read again.

**Session lifetime is unchanged by pushing.** The session ends on the server's output EOF or the
peer going away; an unsolicited frame neither extends nor shortens it.

> ⚠️ **This contract is written against the CURRENT wire.** MCP vNext (#45) removes the `initialize`
> handshake this session shape is built around. The push property must be re-established explicitly
> under that rework — it is exactly the kind of property that disappears unnoticed when the
> surrounding shape changes, which is why it is written down here first.

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

> **Rate-limited notifications are dropped without a reply — but the drop is recorded.**
>
> The per-peer rate limiter is consulted before forwarding any method-bearing frame. Over the limit:
>
> - a **request** (an `id` present and non-null) is answered `-32053` with `retry_after_ms`, so the
>   caller learns it was throttled and can back off;
> - a **notification** (no `id`) is dropped with **no reply to the sender** (there is no reply channel for a notification), and recorded in the audit stream instead.
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

Every frame is a JSON object tagged by a `"type"` field, in one of four shapes.

**`snapshot`** — always the **first** frame: a point-in-time picture, so a fresh subscriber renders
immediately without replaying history. It carries the currently-open sessions and the paired-peer
`reachability` (the same list [`status`](#statusresult) reports).

```json
{
  "type": "snapshot",
  "active_sessions": [{"peer": "bob", "service": "notes", "opened_at": 1751760000, "principal": "eid:1f0a…"}],
  "reachability": [{"name": "bob", "reachable": true, "rtt_ms": 42, "age_secs": 3}],
  "self_network": {"online": true, "home_relay": "https://relay.example:443", "relays": [{"url": "https://relay.example:443", "connected": true}], "direct_addrs": ["192.168.1.20:53420"]}
}
```

Each `active_sessions` entry is one live session: the caller's nickname/`user_id` (`peer`), the
mounted `service`, `opened_at` (epoch seconds), and — from `api_minor` **25** — `principal`, the
caller's stable `eid:<hex>` device principal (#73).

**Key on `principal`, not `peer`.** Two devices under one nickname, or two contacts sharing a
display name, produce identical `peer` values, so per-peer session counts and any UI that acts on a
session (revoke, disconnect, inspect) need the principal. Nicknames never authorize.

This list is the starting state — a client keeps its session view current by applying subsequent
`session_open`/`session_close` events to it. Since `api_minor >= 29` (#57) those events carry the
same `principal` the snapshot rows do, so the delta path distinguishes two same-nickname sessions
without re-subscribing — key the projection on `principal`, fall back to `peer` only for records
from an older daemon. Only a
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
- `principal` — the subject's stable principal (`api_minor >= 29`, #57): `eid:<hex>` on
  session/request/blob records (the exact authenticated device, like `ActiveSession`), the
  allow-list value (`b64u:` when bound, else `eid:`) on a trust `pair`. Deliberately absent on
  `unpair`/`roster_install`/the failed-dial record, and on records written before 0.24.0.
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

Upholding the surface discipline: a record carries identities, counts, and a status — a
nickname/`user_id` (`peer`, the display rendering), the subject's **stable principal**
(`principal`, `eid:<hex>`/`b64u:<pk>`, `api_minor >= 29`, #57), a service name, a method/tool
name, an argument **digest**, and byte/latency **numbers** — never raw arguments, response
content, keys, or **raw un-prefixed hex endpoint ids**. The prefixed principal rendering is the
one sanctioned identity form, the same value the rest of the API has keyed on since #41/#42/#73:
it is a public *identifier* (it is how peers dial you, and it already sits in every `allow` list
on the same disk), not a secret. `principal` is deliberately absent on `unpair` (may tear down
several devices — no single subject), `roster_install` (purely local), the failed-dial record
(our own dial), and every record written before 0.24.0 — treat an absent `principal` as
"unattributable or pre-0.24.0", never as an error.

**`reachability`** — a peer's reachability OR its network path changed (`api_minor >= 12`, #58;
`path` joined the rule at 21, #92). Not an up/down toggle — see below. Pushed so work queued for an
unreachable peer can flush the instant it returns rather than on the next poll tick. It reduces
polling; it does not replace it — for a peer with no open session, `status` is what drives the
probe that produces these frames (see below).

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
  },
  "source": "session"
}
```

`peer` is a whole `PeerReachability` row — the same shape the opening `snapshot`'s `reachability`
list carries, so both project through one code path.

`source` (`api_minor >= 30`, #150) names WHICH of the two producers observed the transition —
`"probe"`, `"session"`, or `"unknown"`. See "Two producers" below. It sits on the frame rather than
on the row because it describes the *event*, not the peer — `status` and the snapshot report cached
rows with no producer to name.

**`self_network`** — THIS node's own posture changed (`api_minor >= 28`, #90): `online` flipped,
the home relay moved, or a relay's connection state changed. `direct_addrs` drift alone does not
emit (address churn is chatty and not a decision point; it rides the next frame). The payload is
the same `SelfNetwork` block `status` and the snapshot carry — see
[`StatusResult`](#statusresult). One frame is also pushed shortly after boot when the endpoint
first connects to a relay ("came online" is genuinely news — the moment invites and WAN dials
become viable).

```json
{
  "type": "self_network",
  "self_network": {"online": false, "relays": [{"url": "https://relay.example:443", "connected": false}],
                   "direct_addrs": ["192.168.1.20:53420"], "last_change_epoch": 1753842000,
                   "identity_conflict_epoch": 1753841880}
}
```

### `peer_diagnostics` — the durable state behind one pairing (`api_minor >= 33`, #140)

**This verb prints another endpoint's addresses.** The rendered porcelain is address-free
everywhere — nicknames and path *kinds* — so a peer's coordinates cannot leak through a screenshot.
(`status` already returns *this* node's own `direct_addrs`; what is new here is a peer's.) Relay
URLs are sanitized to scheme+host+port, as everywhere else, because an operator's can carry a
userinfo token. Here it is the whole question: "what is this node about to dial, and
where did that come from" has no answer without the address. It is your own store's record of your
own paired peers; read the output before pasting it anywhere public.

It exists because of a specific shape of failure: a long-lived pairing that cannot hole-punch while
a **fresh identity on the same hardware punches direct in milliseconds**. Everything else having
been eliminated, the question becomes what durable state a long-lived pairing carries that a fresh
one does not — and from this node's side there is exactly one such thing, the persisted dial hint.
Everything else a fresh identity lacks is derived at runtime.

```json
{"nickname": "jetson", "principal": "eid:9f2k…", "paired_at": "1753600000",
 "last_addr": "{\"id\":\"…\",\"addrs\":[…]}", "hint_addrs": ["192.168.1.50:4433"],
 "hint_usable": true,
 "reachability": {"name": "jetson", "reachable": true, "path": {"kind": "relay"}, …}}
```

`hint_usable` is the field to read first. A stored hint that does not parse, or whose embedded
endpoint id is a *different* peer, is silently discarded on every dial — the node behaves as though
it had no hint at all while the store insists it has one. That discrepancy is invisible from every
other surface, and it is computed here by running the hint through the same function the dial uses,
so the two cannot disagree.

**The hint is merged with discovery, not substituted for it — but that merge has a condition worth
knowing.** iroh inserts these addresses as additional candidate paths and then triggers address
lookup, *except* that the lookup is skipped while a path is already selected, and a selected path is
cleared only when the last connection to that peer closes. On a pair holding an open **relayed**
connection, discovery does not re-run and this hint is the only addressing the dial contributes. So
"a stale hint is harmless because discovery still runs" is least true on a pair that is already
stuck.

It is the first thing to compare because it is the only durable per-peer state **on this node's
disk that the dial path reads** — not the only durable difference. A discovery record published
under the same long-lived key, and `identity_conflict_epoch`, are others; they just do not feed the
dial.

Intended as a **paired capture**: run it on both ends of a stuck pairing and read the two side by
side. `mcpmesh internal peer state <peer> [--json]`.

### `identity_conflict_epoch` — someone else is using this identity (`api_minor >= 32`, #134)

Two nodes booted from **copies** of one mesh root present the same endpoint id. A relay can serve
only one of them, so the displaced node's peers simply go unreachable — with nothing, anywhere,
saying why. That is the failure this field exists to name.

`self_network.identity_conflict_epoch` is the epoch second at which the relay last reported that
another endpoint is presenting this node's identity, and is **absent** if it never has. A new
observation is a posture change, so it also pushes a `self_network` frame — you learn it when it
happens rather than on a poll.

**Sticky, and a timestamp rather than a flag.** The relay announces the condition once, as the
displaced connection is dropped; it is not a state that keeps being reported. A flag that cleared
itself would read `false` by the time anyone called `status`, so judge staleness from the epoch the
way you would `last_change_epoch`.

**Absence is not proof of uniqueness.** iroh exposes this condition only as a log line, so detection
requires an `IdentityConflictLayer` in the process's `tracing` subscriber. The standalone `mcpmesh`
daemon installs one at boot. An **embedded** node cannot — a subscriber is global and your
application owns it — so it reports `null` until you compose the layer into yours:

```rust
use tracing_subscriber::prelude::*;
let conflict = std::sync::Arc::new(mcpmesh_node::diag::IdentityConflict::default());
tracing_subscriber::registry()
    .with(your_fmt_layer)
    .with(mcpmesh_node::diag::IdentityConflictLayer::new(conflict.clone()))
    .init();
```

Never render an absent value as "identity verified unique" — it means "not observed", and on an
embedded node with no layer installed it means "not observable".

The remedy is always the same: stop the duplicate, or give it its own identity. mcpmesh does not
refuse either node, deliberately — with two live endpoints there is no principled way to tell the
impostor from the original, and a wrong refusal takes down the legitimate node.

**Advisory, and relay-attested rather than authenticated.** The claim originates at a relay, and
iroh's older health frame carries arbitrary text through the same channel, so any relay in your set
can synthesize this condition. Treat it as a diagnostic: show it, act on it manually, never gate
authorization on it. The worst a hostile relay achieves is a misleading status field — the same
trust you already extend to a relay for reachability.

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

`rtt_ms` is not a proxy for `path`: a fast relay beats a slow direct path.

**`path` and `reachable` no longer share one freshness.** Through `api_minor` 21 they did — one
probe set both, under one TTL and one `age_secs`. Since **22** a live session updates `path` alone
and deliberately leaves `probed_at`/`rtt_ms`/`meta` untouched (re-stamping them would forge the
freshness of a measurement nobody took). So a `status` row can carry a path observed seconds ago
beside an `age_secs` and `rtt_ms` many times older, and a pushed frame reports `age_secs: 0` for the
PATH while its `rtt_ms` may be stale. Treat `age_secs` as the age of the *probe*, not of `path`.

Through `api_minor` 22, `rtt_ms` also contained the daemon's own path-settle window, so a relayed
peer could never report under 600ms and "relayed **and** fast" was unreachable by construction. From
`api_minor` **23** the figure is stamped at the pong and excludes that window, so a health check may
treat a relayed peer with a low `rtt_ms` as evidence that a direct path *should* have been available
(#123). Guard on `api_minor >= 23` before building on it — an older daemon reports the inflated
number with no way to tell from the value alone.

Through `api_minor` 23, `reachable` shared its deadline with that same classification window: a
relayed peer whose pong arrived after roughly 2.4s timed out *while the route was being determined*
and was reported **offline despite answering**. From `api_minor` **24** the exchange alone decides
`reachable`, and a classification failure degrades `path` to `unknown` rather than flipping the
verdict (#128). Guard on `api_minor >= 24` before trusting a `false` for a high-latency relayed
peer.

**A first probe may report `unknown`.** A fresh connection starts on the relay and hole-punches in
the background; the daemon waits briefly for the path to settle, but under load that can time out.
The next probe reports the settled answer. So treat `unknown` as "not yet known" and re-read, rather
than as a stable property of the peer — and never as "private".

Emitted on a **transition**: the `reachable` verdict changed, **or `path` changed**, or this is the
first probe of that peer. A refresh that re-confirms the same verdict *and* the same path emits
nothing, so a peer that stays up does not produce a frame per cache refresh; `rtt_ms`/`meta` drift
is advisory detail, not a transition. `age_secs` is `0` — the observation just completed.

**Do not treat this as an up/down toggle.** It carried that meaning through `api_minor` **20**
(0.18.0), and this document wrongly said so — "a path change alone does not emit a frame" — until
**0.20.3** corrected it. It stopped being true at `api_minor` **21** (0.19.0), when `path` joined
the transition rule; same-verdict frames have been possible ever since. `api_minor` cannot date
this correction, because it describes behaviour that already shipped — the release can.

**Two producers, since `api_minor` 22 — and since 30, `source` says which one (#150):**

| `source` | producer | when | what it licenses |
|---|---|---|---|
| `"probe"` | a completing **probe** | `status`, `subscribe`'s snapshot, or `peer_services` refreshes a stale entry | "a fresh throwaway dial toward this peer went via a relay." Says nothing about the connection anyone is using. |
| `"session"` | a **live session** | its selected path changed under it (0.20.0) | "the connection this peer's traffic is actually on just changed." A real statement about a live link. |
| `"unknown"` | — | the daemon predates `api_minor` 30, or named a producer you predate | Neither. Hedge to the weaker (probe-level) claim. |

That distinction is the difference between warning a user that their call has silently degraded and
saying nothing useful at all, so read `source` rather than inferring it.

**`rtt_ms` does not tell you which one sent a frame, and never did.** A probe reporting a peer
*unreachable* carries `null`, and a live-session update on a peer a probe already measured carries
that earlier — possibly stale — number. Only a session-sourced frame for a peer **never probed**
carries `null` for the reason people assume. Through `api_minor` 29 this document said there was no
discriminator and invited the ask; #150 was that ask, and `source` is the answer.

**Absent `source` means `unknown`, not `probe`.** An older daemon's frame omits the key, and any
daemon from `api_minor` 22 on already has *both* producers — so an absent key genuinely does not say
which one ran. Defaulting it to `probe` would assert the wrong producer for every session-sourced
frame such a daemon emits.

An **unreadable** value also reads as `unknown` — an unrecognized producer name, but also `null`, a
number, or any other shape. So neither a future third producer nor a proxy that rewrites absent
optional fields to `null` can break your parse of the frame; the worst case is a degraded
attribution, which is what `unknown` already means.

The live producer is why `path` is trustworthy for a long-lived session: a call that degrades
`direct` → `relay` says so **when it happens**, rather than staying silently mislabelled until
something probes.

**Subscribing is not sufficient on its own.** The live producer only watches peers with an OPEN
session — a paired peer you are not talking to has no watcher. And there is no periodic probe loop:
probes are demand-driven, and `subscribe` triggers them exactly once, at snapshot time. For
session-less peers, polling `status` is what *drives* the probe producer, not a legacy alternative
to it. Subscribe for live sessions; keep polling if you need liveness for idle peers.

Hole-punching flaps by nature, and the stream stays mostly quiet through it — but **not
symmetrically**. Both the probe and the live watcher wait up to ~600ms for a change to hold, and
that wait short-circuits the moment a path becomes `direct`. So a `direct → relay → direct` flap is
damped and emits nothing, while a `relay → direct → relay` flap emits the `direct` immediately and
the return to `relay` after the window: two frames for a blip. Do not treat a single `direct` frame
as durable evidence of locality — it may be a hole-punch that did not survive.

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

This value is **authoritative**: the daemon strips any caller-supplied `mcpmesh/*` `_meta` key from
**every** frame it proxies — not only the session's first — and overwrites this object on whichever
frame is really the `initialize`, so a caller cannot forge who they are. `user_id` is `null` when a
pairing peer presented no binding.

> **`api_minor >= 37` is what guarantees this.** Below 37 the rule was enforced on the first frame
> only, and `run_session` treats frame 1 as the `initialize` whatever its method is — so a caller
> could send any other method first and put its real `initialize`, with a forged `mcpmesh/peer`, in
> frame 2 (#164). A consumer that keys authorization on this value should require `>= 37`.

The strip covers `params._meta`, including inside a JSON-RPC batch. It does not touch a top-level
`_meta` sibling of `params`, nor `result._meta` on a client→server response — neither is a seam a
backend reads identity from.

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
| `-32041` | `blob_republish` — the blob is not held COMPLETE by this daemon (#83). Remedy: fetch it first. |
| `-32042` | `blob_republish` — the blob was deliberately WITHDRAWN from that scope (#107). Remedy: `blob_publish {scope, path}` from the file if the re-share is intended. |
| `-32043` | `pair` — the INVITER refused: the nickname is already held by a different peer it has paired, **and the invite survived** (#87, `api_minor >= 31`). The one refusal with a self-service remedy: **rename this node and redeem the same invite again**. Branch on this and write your own copy; see the note below (#147). |
| `-32044` | `pair` — the invite line's own expiry has passed, checked before dialing (#159, `api_minor >= 36`). Ask for a fresh invite. |
| `-32045` | `pair` — the inviter has **no outstanding invite at all**; its accept gate closed the dial (#159). The safe union of "expired, already used, or cancelled" — see the note below on why it is not split further. Ask for a fresh invite. |
| `-32046` | `pair` — the inviter's machine could not be dialed (#159). The invite is untouched: check they are online and retry the SAME line. |
| `-32047` | `pair` — **the address-swap defense fired**: the machine that answered is not the endpoint the invite names (#159). **Do not render this as "try again"** — get the invite again through a channel you trust. |
| `-32048` | `pair` — the invite asks to be called a name this node already uses for a different peer (#159). The redeemer-side mirror of `-32043`. Ask for an invite suggesting a different name. |
| `-32049` | `pair` — the inviter refused and the cause is **deliberately withheld** (#159). Ask for a fresh invite. |
| `-32000` | operation failed — `message` carries the detail. One common instance: the daemon is in control-only mode with no mesh (e.g. `invite`/`pair` before a mesh exists) |
| `-32055` | *(session only)* peer unreachable |
| `-32054` | *(session only)* session refused |
| `-32053` | *(session only)* rate-limited; carries `retry_after_ms`. **Requests only** — a rate-limited *notification* gets no reply (none is possible), but is recorded as `status: "rate_limited"` from `api_minor` 26, see below |

**Why "expired" and "already used" are not separate codes (#159).** The inviter answers ONE refusal
for unknown, expired, and wrong secret on purpose: telling them apart is a **redemption oracle** — a
prober presenting guessed secrets would learn which ones were ever real. So `-32049` says "that
invite did not work" and nothing more, which is exactly what the prose already said.

`-32045` gets as close as is safe by answering a different question: it reports that *the inviter has
nothing outstanding*, which is a fact about the inviter rather than about the secret presented. In
practice that is the everyday shape of "expired or already used", and it is the one to branch on.

Be precise about what that discloses, though. It comes from the accept gate, **before** any secret is
presented, so anyone who can dial the node learns whether it currently has an invite outstanding —
and for a node with exactly one (the single-use default) that is effectively "is this invite still
live". The bit was already observable: #87b gave that path its own distinct sentence, and an invite
line is unsigned, so anyone could fabricate one to reach it. `api_minor >= 36` makes it a documented
contract rather than incidental prose.

**And SAS mismatch is not a refusal.** The short authentication code is compared by two humans out of
band; the daemon never learns the other side's reading, so there is nothing to signal. A mismatch
means the humans stop and `peer_remove`.

**A refusal's prose is ours; its remedy is yours (#147, `api_minor >= 31`).** The nickname-collision
message is built on the **inviter** and travels to the redeemer, so the embedder that displays it is
not the one that could rewrite it into its own vocabulary — the only downstream fix was
substring-matching our copy. Through `api_minor` 30 that message also named `set_nickname`, a
control verb a GUI user cannot type, see, or find. It now states the action ("rename this node"), and
more usefully the refusal carries `-32043`, so branch on the code and write the sentence naming
*your* rename affordance.

**The surviving invite is part of what `-32043` means**, not a detail of the prose. Two other
`pair` failures are also nickname collisions, and the remedy `-32043` implies would be wrong for
both:

- the inviter's post-redeem **race guard** — two redeemers claiming the same new name, where the
  loser's invite was already burned winning the race. Its reason says "ask the inviter for a fresh
  invite", which is the correct advice; retrying the same invite would fail. On a **multi-use**
  invite the loser's invite survives, so that one *does* carry `-32043` and the rename-and-retry
  advice is right. The uncoded burned case surfaces as `-32049` `ERR_INVITE_REFUSED`.
- the **redeemer-side** squat check, which refuses adopting an invite's suggested nickname when you
  already use that name for a different peer. That is a condition on *your* node, not the
  inviter's. It carries **`-32048` `ERR_INVITE_NAME_CONFLICT`** (#159) — the paragraph above said
  `-32000` through `api_minor` 38 and was stale.

  **From `api_minor >= 39` this one is self-service:** retry the same `pair` with
  `as_nickname` set (#87). Its message still says "ask them for an invite suggesting a different
  name", which was the only remedy before; branch on `-32048` and offer the rename instead.

So: branch on `-32043` for the rename-and-retry case, `-32048` to offer `as_nickname`, and render
the message for everything else.

> **A collision on the inviter's own `peer_nickname` (#87) is deliberately opaque.** When the
> inviter aliased you and *its* alias collides, the refusal is the generic `pairing refused` with no
> code — byte-identical to every other opaque refusal. Naming it would send you the inviter's
> private name for you (and, when the clash is with a third party, disclose that name's existence),
> and coding it `-32043` would have you rename and retry forever over a name you cannot influence.
> The inviter's operator gets the detail in their own log.

Every remaining `pair` refusal stays `-32000`. The one guarding the invite secret is also
deliberately **opaque** — it does not distinguish unknown-vs-expired-vs-wrong-secret, because a
specific reason there would be a redemption oracle an attacker could probe, and a machine-readable
code would rebuild that oracle in a form that is easier to script. `-32043` is safe to distinguish
precisely because it is sent only to a caller that already proved possession of a live invite
secret. (The malformed-frame and id-mismatch refusals name themselves; neither is a secret oracle.)

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
  `api_minor >= 16`; `blob_republish` (#83) is `api_minor >= 18`; durable withdrawals + `-32042` (#107) are `api_minor >= 19`; `blob_list` filters/paging and its DEFAULT LIMIT (#84b) are `api_minor >= 20`; a PATH change emitting a reachability transition (#92) is `api_minor >= 21`; `status` + `peer_services` — and the `mcpmesh/ping/1` probe's `services` field, which shares the same resolver — answering from the live registry rather than `config.toml` (#100) is `api_minor >= 17`; the `blob_revoke` / `blob_unpublish` verbs
  (#62) are `api_minor >= 15`; the pushed `reachability` stream frame (#58)
  is `api_minor >= 12`; the `set_nickname` verb
  and `StatusResult.self_nickname` are `api_minor >= 2` (#37); STABLE-principal `allow`
  strings + `ServiceInfo.allow_display` are `api_minor >= 3` (#38); the `reachability` frame's
  `source` — which of the two producers observed the transition (#150) — is `api_minor >= 30`;
  the branchable nickname-collision refusal `-32043` (#147) is `api_minor >= 31`;
  `SelfNetwork.identity_conflict_epoch` (#134) is `api_minor >= 32`; the `peer_diagnostics` verb
  (#140) is `api_minor >= 33`; durable outstanding invites — `expires_at_epoch` became the real
  lifetime rather than an upper bound on process lifetime (#87b) — are `api_minor >= 34`;
  `InviteParams.max_uses` + `InviteResult.uses_remaining` (#87) are `api_minor >= 35`; the
  onboarding refusal codes `-32044`..`-32049` (#159) are `api_minor >= 36`; the reserved
  `mcpmesh/*` `_meta` namespace is enforced on every proxied frame, not just the session's first,
  at `api_minor >= 37` (#164) — guard on that before keying authorization on
  `_meta["mcpmesh/peer"]`; `SelfNetwork.presence_mode` and the `reachable: false` meaning change it
  brings (#89) are `api_minor >= 38`; `PairParams.as_nickname` + `InviteParams.peer_nickname`
  (#87) are `api_minor >= 39`; `RegisterServiceParams.rate_limit_per_min` and the per-service
  meaning of `-32053` (#63) are `api_minor >= 40`; `StreamFrame::BlobTransfer` (#82) is
  `api_minor >= 41` — below that `deny_unknown_fields` rejects the whole request, so
  guard before offering an alias field in a UI.
  `api_minor` is itself additive: a pre-1.1 daemon omits it and it reads as `0`.

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
