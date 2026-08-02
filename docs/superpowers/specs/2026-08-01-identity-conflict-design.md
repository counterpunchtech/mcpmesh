# Surfacing the duplicate-identity condition (#134)

**Status:** accepted · **Target:** 0.26.0 (MINOR) · **`api_minor`:** 32

## Problem

Two nodes booted from **copies** of one mesh root present the same endpoint id. A relay serves only
one; the displaced node's peers go unreachable with nothing, anywhere, saying why. Diagnosing the
reported incident cost the downstream real time.

Not preventable locally, and not by the embedder: a second node on the SAME root is stopped by the
redb lock, but a node on a COPY is a different file, at a different path, possibly on another
machine. Only the network layer observes it.

## What the signal actually is (investigated, not assumed)

- The relay **does** tell the displaced client: `Status::SameEndpointIdConnected` arrives on the
  wire (`iroh-relay-1.0.3/src/protos/relay.rs`).
- iroh 1.0.3 handles it in `socket/transports/relay/actor.rs` with
  `warn!("Relay server reports problem: {status}")` and **nothing else** — no event, no `Endpoint`
  state, no watcher.

So a `tracing` event is the only channel that exists. Everything below follows from that.

## Design

### A Layer, never a subscriber

A `tracing` subscriber is process-global and set-once. An **embedded** `mcpmesh-node` does not own
it — the host does — and the reported incident is the embedded case.

`IdentityConflictLayer` composes into whatever subscriber the host already runs.
`diag::install_for_daemon` is called **only from `serve_forever`**, the standalone daemon that owns
its process.

**This must not move into `boot_node`.** That path is shared with `NodeBuilder::start`, and the
first implementation did exactly that: an embedded node seized the global, so a host calling
`fmt::init()` afterwards panicked, and one using `try_init()` lost its logs for the process
lifetime. A patch-range upgrade would have bricked the reporter's logging.

The daemon's layer is filtered to `WARN`. Not tidiness: `tracing`'s max-level hint comes from the
installed subscriber, and a bare registry sets it to `TRACE` — turning every `trace_span!` in iroh,
quinn and tokio from a compiled-out no-op into an allocation on the datagram hot path, for a daemon
that prints nothing.

### The shared cell

`MeshState.identity_conflict` is a **set-once** `Arc<IdentityConflict>` (the `audit`/`limits`
discipline), not an owned value: the layer must be constructed with the Arc *before* the host
installs its subscriber, which happens before any node exists.

`NodeBuilder::identity_conflict(Arc)` is what makes the embedded path work at all. Without it the
host's layer records into one cell while `status` reads another, and the field stays null forever —
which is what the first implementation shipped.

### Matching a log message

Brittle by nature, so the needle is **derived** from `Status::SameEndpointIdConnected`'s own
`Display` — the same value iroh formats — rather than transcribed. A rewording moves both sides
together. The test pins that the derivation still yields something *specific*: if iroh made `Status`
display generically, the layer would match unrelated warnings, and a detector that fires on any
warning is worse than none.

### Surfacing

`status.self_network.identity_conflict_epoch`, plus a `SelfNetwork` frame — a new observation joins
the change signature, so it is learned when it happens rather than on a poll. And a `doctor` rung,
for the reason #125 added one: the daemon's own `error!` reaches nobody in the shipped binary.

## Three properties stated rather than implied

- **Sticky, a timestamp not a flag.** The relay announces it once, as the displaced connection
  drops. A self-clearing flag would read false by the time anyone called `status`.
- **Absence is not proof of uniqueness.** On an embedded node with no layer it means *not
  observable*. `doctor` therefore emits nothing when unobserved rather than a green line.
- **Advisory, relay-attested, not authenticated.** iroh's deprecated `Health { problem }` frame
  carries arbitrary wire text through the same log line, so any relay in the set can synthesize
  this. It is a diagnostic: never gate authorization on it. Authenticating a log line is not
  available; saying so is.

## Not refusing either node

Deliberate, and the reporter's own reasoning: with two live endpoints there is no principled way to
tell the impostor from the original, and a wrong refusal takes down the legitimate node.

## Versioning

**MINOR → 0.26.0.** The new `SelfNetwork` field breaks exhaustive construction — the compiler
proved it on our own fixture. JSON consumers are unaffected. `API_MINOR` 32.

New runtime deps on `mcpmesh-node`: `tracing-subscriber` (registry+std only) and `iroh-relay`
(already in the lock via iroh; needed for the `Status` type the needle derives from).

## Testing

1. The needle is derived from iroh and is specific enough to be a safe substring.
2. The layer records the real event and **not** unrelated warnings.
3. The stamp is the most recent observation.
4. A new observation is a transition (emits); an unchanged one is not (does not emit per tick).
5. **End to end through a real `MeshState`:** an observation on the host's cell reaches `status`.
6. `doctor` speaks only when it has seen something, names the age, and says the claim is
   unauthenticated.

Mutation: firing on any event fails 2; a generic needle fails 1; dropping the stamp from the
signature fails 4; severing the cell read fails 5 (and passed everything before 5 existed).
