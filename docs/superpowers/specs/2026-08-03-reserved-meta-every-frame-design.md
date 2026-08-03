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
`pump` is `pub(crate)`; `strip_reserved_meta` is additive `pub` in `mcpmesh-net`.

**`api_minor` 36 → 37.** The first draft said "no wire change, so `api_minor` is unchanged" — wrong
by this file's own precedent. Minor 10, 17, 21, 22, 23 and 24 all shipped with no type change; they
moved *meaning*, and 10's entry says exactly why: "A consumer can guard on `api_minor >= 10`." Here
what changed is whether `_meta["mcpmesh/peer"]` can be trusted, which is the entire reason a backend
reads it. Leaving it at 36 would give bolo no programmatic feature-detect for a **security** fix and
force them to parse `stack_version`.

## The batch bypass the gate found

The first implementation was still evadable. `strip_reserved_meta` resolves `params/_meta` through a
JSON pointer and the injection reads `frame.get("method")` — **both return `None` on an array
root**. So wrapping the forged frame in `[ ... ]` carried it through untouched, reproduced end to end
against the real socket backend.

Whether it reaches a handler depends on the server: rmcp 3.1.0 does not unwrap batches (MCP removed
them in 2025-06-18), but an older SDK or a custom NDJSON server does. **The invariant cannot depend
on which server is behind it** — this daemon pumps rather than interprets, and the reporter is
explicit that enforcing the reserved namespace is ours. Both halves now descend a batch, depth-bounded
at 8 (a valid batch is one level; `serde_json` already caps parse depth).

Worse, the first draft's own test *asserted the bypass was fine*: `odd_shapes_survive_sanitize_without_panicking`
checked that `json!([1,2,3])` passed through unchanged. A test can encode the defect as intended
behavior.

## The trait contract, and what an embedder must do

`SessionBackend` is `pub` in `mcpmesh-net`, and its doc said the transport "carries the rest of the
session verbatim" — describing the defect as the contract. Enforcement lives in `mcpmesh-node`'s
private `pump`, so an embedder implementing the trait itself gets raw frames 2+. The doc now says so
and points at `strip_reserved_meta`. Moving enforcement into `mcpmesh-net` would mean wrapping the
transport the backend consumes; not done here, and named rather than left implied.

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

Mutation, eight run and eight caught: reverting the strip to first-frame-only (deleting the call site,
not the helper) fails 1, 2 and 5; dropping the later-`initialize` injection fails 1; stripping all of
`_meta` rather than the reserved prefix fails 3; making `spawn.rs` pass a peer instead of `None`
fails 4.

Four more from the gate round: strip skipping a batch fails 6; injection skipping a batch fails 6;
widening the injection gate to every frame fails 2 (it previously escaped every integration test and
was caught only by a helper unit test — the same call-site blindness as case 4); removing the
`params` object guard fails 5.

6. A JSON-RPC **batch** cannot smuggle a forged key past either half, and a non-`initialize` element
   inside one is stripped without being attributed.

**Case 4 needed a call-site test, and the first attempt was a helper test that proved nothing.**
`sanitize_caller_frame(&mut f, None)` is not evidence that `spawn.rs` passes `None` — the argument is
the whole decision. The `run` case is now pinned end to end through the child process, which reports
whether the `initialize` it received carried a `mcpmesh/peer` at all.

## Implementation note

The strip and the injection live in one `sanitize_caller_frame` helper rather than inline in the
pump loop, so the property is testable directly for odd frame shapes a duplex harness makes awkward
to drive. The `!frame.is_object()` guard the socket backend needs is **absent** here on purpose:
only an object can carry `method == "initialize"`, so a non-object frame returns before any indexing
and passes through unchanged rather than being coerced into an invented `initialize`.
