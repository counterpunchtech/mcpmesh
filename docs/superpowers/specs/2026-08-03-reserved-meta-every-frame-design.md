# The reserved `mcpmesh/*` namespace holds on every frame, not just the first (#164)

**Status:** accepted · **Target:** 0.29.0 (MINOR) · **`api_minor`:** unchanged

## The defect, reproduced

`select_service` strips caller-supplied `mcpmesh/*` `_meta` keys, and `socket.rs` injects the
authoritative `mcpmesh/peer`. Both run on **one frame** — the first one the session reads, which
`run_session` treats as `initialize` **whatever its method actually is** (`net/src/endpoint.rs:381`;
`select_service` never inspects `method`, and with a single admitted service the key-absent arm
defaults to `Selected`).

Every later frame goes rate gate → audit hook → `write_frame` (`node/src/backends/mod.rs`,
direction A). **No strip, no injection.** So a caller spends frame 1 on a `ping` — which the MCP
lifecycle permits before `initialize`, and which rmcp answers — and sends its real `initialize` as
frame 2, where nothing touches it.

The module doc says a forged value "never survives a MESH session". On this path it does.

## Two harms, and each fix shape only closes one

The issue offers two fixes and treats them as alternatives. They are not — each leaves the other
harm standing:

- **Strip on every frame** makes the reserved-namespace sentence true, but the backend's real
  `initialize` then arrives with **no** `mcpmesh/peer` at all. The reporter names this second harm
  explicitly: *"a session that arrives with no `_meta` at all is unattributable"*. A shared server
  keying per-principal state cannot tell an unattributable session from a legitimate one.
- **Resolve the real `initialize`** attributes the handshake correctly, but leaves reserved keys
  flowing on every non-`initialize` frame — and `mcpmesh/service` is authorization-relevant.

So we ship both, at one seam.

## Design

`pump`'s direction A, for **every** caller→backend frame, in this order:

1. **Strip** all `mcpmesh/*` keys from `params._meta` — before the rate gate, the audit hook, or
   the forward, matching `select_service`'s "before anything acts on the frame" discipline.
2. **Inject** the authoritative `mcpmesh/peer` when the frame's `method` is `"initialize"`.

Step 1 is unconditional and applies to both backends. Step 2 is socket-only: the `run` backend
conveys identity through `MCPMESH_PEER_*` env vars, set once per spawned process, and injecting
`_meta` there would invent a seam that backend does not have. `pump` therefore takes
`Option<Value>` — `Some` from `socket.rs`, `None` from `spawn.rs`.

**One definition of "reserved".** The strip moves into a shared
`mcpmesh_net::service::strip_reserved_meta`, called by both `select_service` and `pump`, so frame 1
and frame 2 cannot drift apart. That drift is the bug.

**Scope boundary, stated rather than implied.** The strip covers `params._meta` — the seam MCP
defines and the only one a backend reads. A top-level `_meta` sibling of `params` is *not* stripped,
here or in `select_service` before this change. Named so the next reader does not infer total
coverage from the word "never".

## Versioning

**MINOR → 0.29.0.** Behavior change: frames a backend previously received verbatim are now modified.
`pump` is `pub(crate)`; `strip_reserved_meta` is additive `pub` in `mcpmesh-net`. No wire or
Control-API change, so `api_minor` is unchanged.

## Testing

1. **The reported repro, end to end**: frame 1 is a `ping`, frame 2 is an `initialize` carrying a
   forged `mcpmesh/peer` naming another principal. The backend must observe frame 2 with the
   **authoritative** identity, not the forged one.
2. A forged `mcpmesh/service` on a later frame is stripped (authorization-relevant, and the key
   `select_service` acts on).
3. Non-reserved `_meta` keys **survive** on every frame — the strip must not become a general
   `_meta` eraser.
4. A `run` backend gets the strip but **no** injection, so its frames do not sprout a `_meta` seam
   the backend does not use.
5. Frames with no `params`, a non-object `params`, or a non-object `_meta` pass through without
   panicking — `Value`'s `IndexMut` panics on a non-object base, and `select_service` already
   documents this shape as reachable.

Mutation: reverting the strip to first-frame-only fails 1 and 2; dropping the later-`initialize`
injection fails 1; stripping all of `_meta` rather than the reserved prefix fails 3; injecting for
the `run` backend fails 4.
