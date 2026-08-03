# Blob transfer progress (#82 ask 2)

**Status:** accepted · **Target:** 0.33.0 (MINOR) · **`api_minor`:** 40 → 41

## Scope: ask 1 already shipped; asks 3 and the blocking consequence do not

Re-verified against `main` before starting — #82 lists four asks and four consequences:

- **Ask 1 (stream to disk instead of `read_bytes` + `fs::write`) — DONE.** `provider.export_to`
  writes incrementally and `blob_fetch` uses it, with a `#82` comment. Peak RSS is size-independent,
  so **consequence 1 (the OOM kill) is fixed.**
- **Ask 2 (transfer events + a `BlobTransfer` stream frame) — NOT DONE.** This change.
- **Ask 3 (`mode: "copy" | "reference"`) — deliberately NOT done.** `provider.rs` already documents
  why: `ExportMode::TryReference` ties the destination file's lifetime to the store, and there is no
  reclaim path yet (#80). Shipping a flag that silently makes a user's exported file disappear on a
  future GC is worse than the second copy. Revisit with #80.
- **Consequence 2 (the control connection is blocked for the transfer's duration) — NOT fixed**, and
  it is not in the ask list. `handle_request` is awaited inline in the per-connection loop
  (`control.rs`), so a multi-GB fetch stalls every other verb *on that connection*. Fixing it means
  concurrent dispatch, which collides with the two upgrade paths (`open_session`, `subscribe`) that
  MOVE `write_half` out of the loop. That is a control-plane redesign with its own ordering and
  bounding questions — filed separately rather than bolted on here.
- **Consequence 3 (no cancellation) — NOT fixed**, for the same reason. Ask 4 asks for the contract
  to be *documented*; that is done here, truthfully.

**Progress is still worth shipping alone**, because it arrives on the `subscribe` connection — a
*different* connection from the one running the fetch. So an embedder gets a real progress bar today
even though the fetching connection is still blocked.

## Design

### Serving side: `RequestMode::InterceptLog`

`get` moves from `Intercept` to `InterceptLog`. That is strictly additive: `InterceptLog` is
"Intercept **plus** detailed transfer events", so the scope check that authorizes every single-blob
GET is unchanged. The drain loop's `_ => {}` currently discards everything else; it gains arms for
`TransferStarted` / `TransferProgress` / `TransferCompleted` / `TransferAborted`.

### Fetching side: `GetProgress::stream`

`provider.fetch` currently drops the returned `GetProgress` on the floor. It becomes a stream we
consume, emitting the same frame with `direction: "fetch"`.

### The frame

```rust
StreamFrame::BlobTransfer {
    direction: BlobDirection,   // Serve | Fetch
    hash: String,
    bytes_done: u64,
    bytes_total: Option<u64>,   // None until known
    state: BlobTransferState,   // Started | Progress | Completed | Aborted
    peer: Option<String>,       // serving side only: the principal we are serving
}
```

`peer` is the **stable principal**, never a display nickname (#38) — and it is present only on the
serving side, because the fetching side's counterparty is named by the ticket, not by a resolved
identity.

### Coalescing is mandatory, not an optimisation

`transfer_progress` fires **per chunk (~16 KiB)**. Broadcasting a frame each time would push ~262k
frames for a 4 GiB transfer through a ring of depth `STREAM_BROADCAST_DEPTH`, so every subscriber
would see `Lagged` and lose the audit events sharing that ring. Frames are emitted on:

- `Started` and `Completed`/`Aborted` — always, and
- `Progress` only when `bytes_done` has advanced by at least `PROGRESS_STRIDE` since the last frame
  for that transfer, where the stride is `max(1 MiB, total / 100)`.

So a transfer emits at most ~102 frames whatever its size. **The last `Progress` before completion
may be skipped** — `Completed` carries the final byte count, so a consumer must not treat the last
`Progress` as the total.

The broadcast is non-blocking (`send` on a `broadcast::Sender` never awaits), preserving
iroh-blobs' own `try_send` property: a slow subscriber must never stall a transfer.

## Ask 4: the cancellation contract, documented truthfully

Determined by reading the code, not assumed:

- **Dropping the control connection does NOT abort an in-flight fetch.** The handler is awaited
  inline, so the transfer runs to completion (or error) and only then does the write fail. An
  embedder's Cancel button cannot stop the bytes today.
- **A partially fetched blob's chunks stay in the store.** They are not exposed by `blob_list`
  (which lists published scopes, not raw store contents) and there is no reclaim path (#80), so they
  are orphaned until the store is deleted.

Both go in `docs/local-protocol.md` under `blob_fetch`. Stating this is the point of ask 4 — the
reporter is shipping a Cancel button that lies, and needs to know it will keep lying until
consequence 2 is fixed.

## Versioning

**MINOR → 0.33.0.** New `StreamFrame` variant — a `#[non_exhaustive]`-less enum, so matching
downstreams break. `api_minor` **40 → 41**: a consumer must guard on `>= 41` before expecting
`BlobTransfer` frames.

## Testing

1. A served transfer emits `Started` → … → `Completed`, in order, with a non-decreasing
   `bytes_done`.
2. **Coalescing holds:** a transfer large enough to produce many chunks emits a bounded number of
   frames, not one per chunk. This is the property that keeps the ring usable.
3. `bytes_total` is reported once known, and `Completed` carries the final count.
4. A fetch emits `direction: "fetch"` frames on the fetching node.
5. The scope check still refuses an unauthorized GET under `InterceptLog` — the mode change must not
   weaken authorization.
6. An aborted transfer emits `Aborted`, not a silent stop.

Mutation, ten run and ten caught: dropping the coalescing gate fails 2; downgrading
`InterceptLog` to `NotifyLog` fails 5; dropping the `Aborted` emit fails 6; dropping the
final-count clamp fails 3.

**Test 3 was vacuous in its first form** — the fixture's chunk loop landed exactly on the size, so
`done` already equalled the total when `Completed` arrived and the clamp was a no-op. It now uses a
deliberately LAGGING last progress (400 of 1000), which is the case the clamp exists for: the stride
skips the tail, so a consumer rendering the last `Progress` as the total stops at 40% on a fully
successful transfer.

## The gate round: the bound was false in the direction that matters, and the wiring was untested

**The fetch side never learns `total`** — `GetProgressItem` carries no size — so `stride()` fell to
the fixed 1 MiB floor forever. A 4 GiB fetch emitted **~4098 frames into a 256-deep ring**, and three
places (this spec, the rustdoc, `docs/local-protocol.md`) stated "~102 whatever its size"
unconditionally. The serve side was correctly bounded; the FETCH direction — the one #82 is about —
was the one still flooding. The stride now doubles every 16 frames when the total is unknown, so the
count grows with the log of the size (~128 frames for 4 GiB).

**Five mutations escaped the whole workspace**, because every new test drove `apply_transfer_update`
as a pure function and nothing drove the wiring:

| mutation | now caught by |
|---|---|
| `emit_fetch`'s body deleted — all fetch-side frames gone | `a_real_transfer_emits_progress_on_both_sides` |
| the serve side reports `direction: Fetch` | same |
| the drain task never calls `apply_transfer_update` | same |
| `blob_frame` drops every value — frames produced, never delivered | `blob_transfer_frames_reach_a_subscriber` |
| the synthesized end-of-stream `Aborted` deleted | covered by the unit case |

The spec's own **test 4** ("a fetch emits `direction: "fetch"` frames") was listed as required and
never written — and the mutation that would have exposed it was deleted from the mutation list
rather than run. Both tests now exist, and one drives a real publish → grant → fetch.

Also corrected from the gate: `internal watch` — the documented reference consumer — rendered every
frame as `[unknown frame]`; the two new enums were spliced into the middle of `StreamFrame`'s doc
comment; `docs/local-protocol.md` had no entry for the frame, still said "four shapes", and
mis-attached #63's `deny_unknown_fields` caveat to a server-pushed frame; the fetch rewrite defaulted
`outcome` to `Ok`, a fail-OPEN where `complete()` failed closed; and the claim that `StreamFrame` is
not `#[non_exhaustive]` was simply wrong (it is — the real break is `AppBlobs::load`'s signature).

**Two semantics documented rather than papered over:** on the serve side `bytes_done` is an absolute
offset and `bytes_total` the whole blob, so a legitimate sub-range GET still completes at the full
size; on the fetch side it counts bytes downloaded *by this call*, so a re-fetch of a blob you
already hold completes with `bytes_done: 0`.

## A regression the existing AC tests caught

Under `InterceptLog` the per-request update receiver **must be drained**. The first version spawned
the drainer only when a broadcast existed, so every fixture built with `transfers: None` dropped
`rx` — which makes the provider's own `transfer_started` send fail and **aborts the transfer**. An
authorized fetch failed with "fetch app blob". `granted_caller_fetches_but_ungranted_and_uncontained_are_denied`
failed immediately, which is the value of having an authorization test that drives real bytes.

The receiver is now drained unconditionally; only the FRAMES are optional.
