# The `mcpmesh-local/1` protocol

This is the wire contract between the mcpmesh daemon and the programs on the **same machine** that
drive it — the CLI, the desktop host, and plugin daemons like `kb` and `loc`. It is a small,
line-delimited JSON protocol over a same-user local endpoint: a Unix domain socket on macOS/Linux, a
named pipe on Windows. Anything that can open the endpoint and parse JSON can speak it, in any
language.

> **Status: pre-release.** The API is versioned `mcpmesh-local/1` (`api_version` `1.0`) and evolves
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
[Security model](#security-model)). Reference: [`trust/src/paths.rs`](../trust/src/paths.rs).

If no daemon is running, the endpoint will not exist (no socket file on macOS/Linux; no bound pipe
name on Windows). The CLI auto-starts one on demand; an embedding client either spawns `mcpmesh` (any
porcelain verb starts the daemon) or runs `mcpmesh internal daemon` itself.

## Handshake

**The server speaks first.** Immediately on accept, the daemon writes one `Hello` frame:

```json
{"api":"mcpmesh-local/1","api_version":"1.0","stack_version":"0.2.0"}
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
| `register_service` | `{name, backend, allow}` — `backend` is `{"run":{"cmd":[…]}}` or `{"socket":{"path":"…"}}`; `allow` is a list of petnames/groups | `{}` (ack) |
| `status` | *(none)* | [`StatusResult`](#statusresult) |
| `audit_summary` | *(none)* | `{per_peer:[[name,count],…], per_service:[[name,count],…], total_sessions}` — this node's **local** session tallies; nothing is transmitted |
| `invite` | `{services:[…]}` | `{invite_line:"mcpmesh-invite:…", expires_at_epoch}` |
| `pair` | `{invite_line}` | `{peer_petname, sas_code, services:[…]}` |
| `peer_remove` | `{petname}` | `{}` (ack) |
| `peer_rename` | `{to, user_id?, petname?}` — rename a person by `user_id`, else a provisional contact by `petname` | `{}` (ack) |
| `open_session` | `{peer, service}` | *no response frame — see [Sessions](#sessions)* |
| `subscribe` | *(none)* | *no response frame — a one-way live stream; see [Live event stream](#live-event-stream)* |
| `roster_install` | `{path, org_root_pk?}` — `path` is a local file the daemon reads; `org_root_pk` pins the root on first install | `{org_id, serial, severed}` |
| `org_join` | `{org_id, org_root_pk, user_id, user_key}` — `user_key` is a local path; the key never crosses the socket | `{org_id}` |
| `set_roster_url` | `{url}` | `{}` (ack) |
| `blob_publish` | `{scope, path}` | `{ticket:"mcpmesh/blob/1…", hash}` |
| `blob_grant` | `{scope, principal}` | `{}` (ack) |
| `blob_list` | *(none)* | `{scopes:[{name, hashes:[…], grants:[…]}]}` |
| `blob_fetch` | `{ticket, dest_path}` | `{hash, bytes_len}` |

Paths and files (`roster_install.path`, `org_join.user_key`, `blob_publish.path`,
`blob_fetch.dest_path`) are passed **as local paths, not bytes** — the same-uid daemon reads/writes
them directly, which is within the trust boundary.

### `StatusResult`

```json
{
  "stack_version": "0.2.0",
  "services": [{"name": "notes", "allow": ["bob"], "backend": "run"}],
  "peers":    [{"name": "bob", "services": ["notes"], "user_id": "b64u:…"}],
  "self_user_id": "b64u:…",
  "roster":   {"org_id":"…","serial":42,"state":"approved","org_root_fingerprint":"tango-fig-cabbage"},
  "presence": [{"user_id":"b64u:…","device_label":"laptop","role":"primary","online":true}],
  "recent_pairings": [{"peer_petname":"bob","sas_code":"tango-fig-cabbage","paired_at_epoch":1751760000}],
  "reachability": [{"name":"bob","reachable":true,"rtt_ms":42,"age_secs":3}]
}
```

`roster`, `presence`, `self_user_id`, and `recent_pairings` are optional — absent on a pure-pairing
daemon with no roster and no user key. `backend` reports the *kind* (`"run"` \| `"socket"`) only,
never the command or path.

`reachability` is **advisory** — an on-demand liveness read of your paired peers, populated by a
probe cache the daemon refreshes lazily. It is empty until the first probe completes. A `status`
call kicks off a background refresh for any peer whose entry is stale or missing, but **never blocks
on a probe**. Each entry is a **petname** (`name`, never an endpoint-id), a `reachable` bool (the
last probe result), `rtt_ms` (the last measured round-trip, present only when reachable), and
`age_secs` (how long ago the entry was measured). `age_secs` is **absent** for a peer that has never
been probed — render that as "checking…", not "offline".

Under the hood the daemon measures reachability with a trust-gated, peer-facing probe over the
`mcpmesh/ping/1` ALPN: it dials the peer, and a **paired** peer answers one pong carrying its
`stack_version`. Only paired peers pong — an unpaired scanner's probe is closed with no answer, so
the probe leaks no presence to strangers. (This ALPN is a peer-transport detail; you never speak it
over this local socket — you read its result in `reachability`.)

Note the surface discipline that runs through every response: names are **petnames and self-sovereign
`user_id`s** (opaque `b64u:` identifiers spanning a person's devices), never raw endpoint
identifiers, keys, or transport addresses. If you are keying authorization, key on `user_id`.

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

Two failure frames can arrive *in place of* a live session, as ordinary MCP error frames, so a
consumer always gets a well-formed answer rather than a hang:

- `-32055` — peer unreachable.
- `-32054` — session refused (e.g. not authorized).

Both carry `"data":{"source":"mcpmesh"}` to distinguish a mesh-synthesized error from one the remote
server produced. A session severed mid-stream instead surfaces as a clean EOF.

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

Each `active_sessions` entry is one live session: the caller's petname/`user_id` (`peer`), the
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

- `peer` — the caller's petname/`user_id` (absent on a local-only event with no remote peer).
- `service` — the mounted service name.
- On a `request` (one proxied MCP line): `method` (the MCP method, e.g. `tools/call`), `tool` (the
  tool **name** only, for a `tools/call`), `args_hash` (a `"blake3:…"` digest of the arguments —
  **never** the raw arguments), `bytes_out` (a byte **count** of the response, never its content),
  `status` (`"ok"` \| `"error"`), and `latency_ms`.
- On a `blob_fetch` or `trust`: `target` — the blob's `"blake3:…"` hash, or the trust operation's
  target (a petname or `org/serial`) — and, on a `trust`, `event` (the trust verb: `pair`, `unpair`,
  `roster_install`, `revoke`).

A **failed dial** surfaces as a `session_open` with `status: "error"` — it reached no backend, so it
is otherwise never session-audited; this frame records the attempted-and-failed reach.

Upholding the surface discipline: a record carries names, counts, and a status — a petname/`user_id`,
a service name, a method/tool name, an argument **digest**, and byte/latency **numbers** — never raw
arguments, response content, endpoint-ids, or keys.

**`lagged`** — the subscriber fell behind the daemon's bounded event ring and `dropped` records were
skipped. The stream is **not** dropped and continues; **reconnect** to get a fresh `snapshot` and
resume in sync.

```json
{"type": "lagged", "dropped": 12}
```

`mcpmesh internal watch` is a thin reference consumer of this stream. Reference:
[`cli/src/stream.rs`](../cli/src/stream.rs).

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
| `MCPMESH_PEER_NAME` | the caller's petname (your local name for them) |
| `MCPMESH_PEER_USER` | the caller's verified self-sovereign `user_id` (`b64u:…`), spanning all their devices. **Absent** when a pairing peer presented no device→user binding |
| `MCPMESH_PEER_GROUPS` | comma-joined roster groups (may be empty) |

```python
import os
caller = os.environ.get("MCPMESH_PEER_USER") or os.environ["MCPMESH_PEER_NAME"]
# authorize / scope your answer to `caller`
```

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

- **Authorize on `user_id`, not the petname.** The petname is *your* local label; the `user_id` is
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
| `-32602` | invalid params (a required field missing or the wrong type) |
| `-32603` | internal error |
| `-32000` | daemon is in control-only mode with no mesh (e.g. `invite`/`pair` before a mesh exists) |
| `-32055` | *(session only)* peer unreachable |
| `-32054` | *(session only)* session refused |

`-32602` and `-32603` follow their JSON-RPC 2.0 meanings. Session errors (`-3205x`) appear inside a
[session](#sessions), not as control-method responses, and carry `data.source = "mcpmesh"`.

## Versioning

The API is `mcpmesh-local/1` at `api_version` `1.0` and changes **additively within a major
version**: new response fields are added as optional (absent-tolerant) fields, so a payload from a
newer daemon still parses in an older client and vice versa. Build defensively — ignore fields you do
not recognize, and do not assume an optional field is present. A breaking change would bump the major
(`mcpmesh-local/2`), which a client detects at the `Hello`.

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
- Socket path resolution — [`trust/src/paths.rs`](../trust/src/paths.rs)
- Identity injection — [`cli/src/backends/`](../cli/src/backends/)
- Live event-stream frames — [`cli/src/stream.rs`](../cli/src/stream.rs)

The `mcpmesh-local-api` crate is [published to crates.io](https://crates.io/crates/mcpmesh-local-api):
Rust clients can depend on it directly (`client` feature) rather than reimplementing the wire format.
