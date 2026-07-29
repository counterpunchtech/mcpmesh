# App-blob byte budget (#84a)

**Status:** accepted · **Issue:** #84 item (a) · **Target:** 0.21.0 (config surface → MINOR)

## Problem

The only app-blob limiter counts **connections** — `BLOB_CONN_PER_MIN = 60` per endpoint
(`node/src/limits.rs:169`) — and `throttle: ThrottleMode::None` explicitly declines bandwidth
control (`node/src/blobs/provider.rs:52`).

So one granted peer can open 60 connections a minute and re-pull the same 4 GB blob on each,
saturating a home uplink. mcpmesh neither refuses it nor reports that it happened. The connection
limiter cannot help: the abuse is a small number of *legitimate* connections moving an unbounded
number of bytes.

Distinct from #63, which meters proxied MCP **requests** — different limiter, different unit.

## Approach

iroh-blobs 0.103 emits a `Throttle` event per chunk when `throttle: ThrottleMode::Intercept`
(verified against `provider/events.rs:611`):

```rust
pub struct Throttle {
    pub connection_id: u64,   // NOT the endpoint id
    pub request_id: u64,
    pub size: u64,            // chunk size, "usually 16 KiB"
}
```

**The load-bearing detail: `Throttle` carries a `connection_id`, not an endpoint id.** Metering
per-endpoint therefore requires a `connection_id → EndpointId` map, populated on the `connected`
event — which is already `ConnectMode::Intercept` and already "records the authenticated endpoint
id" per its own doc comment. Building the budget without that map would meter per *connection*,
which is exactly the bypass the issue describes (60 connections, each with a fresh budget).

### Metering

- `[limits].blob_bytes_per_min: u64`, per authenticated endpoint, default **0 = unlimited** so this
  is opt-in and no existing deployment changes behaviour on upgrade.
- Reuse the existing `TokenBucket`/`RateLimiter` shape in `node/src/limits.rs` rather than inventing
  a second metering primitive — same per-endpoint map, same bounded-map discipline, capacity in
  bytes instead of requests.
- Over budget → return `AbortReason::RateLimited`, which iroh-blobs already models as "OK to try
  again later" (`events.rs:83`). **Not** `Permission`: the peer is authorized, it is pacing that
  failed, and conflating the two would make a bandwidth event look like an authz denial in the
  audit trail.

### Throttle vs refuse

`Throttle` is called *per chunk mid-transfer*, so the handler can either delay (pace) or abort.
**Abort**, deliberately: delaying holds the request open and converts a bandwidth problem into a
concurrency problem, with no bound on how many paced transfers accumulate. Aborting is legible to
the peer, bounded for us, and retryable by contract.

The consequence to state plainly: a peer that exceeds the budget mid-blob gets a **partial
transfer**, not a slow one. For a 4 GB blob against a small budget that means it can never complete
until the budget allows it — which is the intended answer to "one peer saturating the uplink", but
it is a behaviour change and belongs in the release notes, not a footnote.

### Observability, because silence is half the bug

The issue's complaint is two-part: mcpmesh "neither refuses it nor reports it happened". A budget
that refuses silently fixes one half. Emit an audit record on the first refusal per endpoint per
window — first only, or a peer hammering the budget writes an unbounded audit log, which is #88.

## Surface + versioning

- `[limits].blob_bytes_per_min` (default 0 = unlimited), documented in `docs/config.md`.
- No control-API change; `API_MINOR` unchanged — no verb, field, or frame shape changes.
- Workspace → **0.21.0** (new config surface → MINOR).

## Explicitly NOT here

Per-scope or per-blob budgets (the unit is the peer). A global uplink cap (the ask is per-endpoint).
Throttling the *fetch* side — this bounds what we serve, not what we pull; #82 owns fetch-side
resource behaviour. Retro-fitting bandwidth accounting into `status` (a reporting surface question,
worth its own issue if wanted).

## Testing (TDD, RED first)

1. **Unit — the bucket meters BYTES, not calls.** Two 16 KiB chunks against a 20 KiB budget: the
   first passes, the second is refused. Fails if the limiter counts events.
2. **Unit — the budget is PER ENDPOINT, via the connection map.** Two connection ids mapped to the
   SAME endpoint share one budget; mapped to different endpoints they do not. This is the test that
   catches the `connection_id`-vs-endpoint bypass, and it is the whole point of the design.
3. **Unit — an unmapped `connection_id` is refused, not allowed.** A `Throttle` for a connection we
   have no `connected` record for must fail CLOSED. Fails open → an attacker who can elicit that
   state bypasses the budget entirely.
4. **Unit — `0` means unlimited**, and is the default: no bucket is consulted, no allocation per
   endpoint. Pins the opt-in guarantee.
5. **Unit — refusal is `RateLimited`, never `Permission`.** Mutating the reason must fail: an
   authorized peer that overran a budget is not an authz denial, and the audit trail must not say
   it was.
6. **Integration — a peer over budget gets a partial transfer and the connection survives.** The
   abort is per-request; it must not sever a session or poison the scope gate.
7. **Regression — an under-budget fetch is byte-identical to today.** With the feature on and the
   budget generous, `blob_fetch` returns the same bytes; with it at default 0, the throttle handler
   is never invoked at all.
8. **Regression — the audit record is emitted ONCE per endpoint per window**, not per chunk. Fails
   if a refused 4 GB transfer writes a record per 16 KiB chunk (~262k records).
