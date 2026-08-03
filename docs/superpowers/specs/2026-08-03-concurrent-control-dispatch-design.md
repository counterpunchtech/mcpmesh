# Concurrent control dispatch + a Cancel that stops the bytes (#172)

**Status:** accepted · **Target:** 0.36.0 (MINOR) · **`api_minor`:** 43 → 44

## The two defects, and why they are one change

`serve_control_io`'s request loop awaits `handle_request` **inline**. Two consequences, both named
in #172:

1. **Head-of-line blocking.** While a `blob_fetch` runs, every other verb on that connection is
   stalled behind it. At media scale, minutes.
2. **No cancellation.** Dropping the client does not abort the transfer — the loop is *inside*
   `handle_request`, so nothing observes the reader until the fetch finishes and the write fails.

They share a root (the inline await) but they do **not** share a fix. Concurrency alone gives a
crude cancel — *close the connection* — and closing a connection is indistinguishable from a crash
and carries no ack. So this ships both halves: concurrent dispatch, and a verb that cancels a
named transfer from any connection.

## Part A — concurrent dispatch

Each ordinary request is spawned into a per-connection `JoinSet`; the read loop returns immediately
to `reader.next()`. Responses are written from the spawned tasks.

### The shared writer, and the upgrade paths

`open_session` and `subscribe` MOVE the write half and consume the connection for their lifetime.
That is why this was not fixed alongside the rest of #82.

The resolution is **`Arc<tokio::sync::Mutex<W>>` plus a quiesce**, not a response channel:

- Ordinary responses take the mutex for **one whole frame** and release it. Frame atomicity is the
  property that matters — a `std::sync::Mutex` taken per `poll_write` would let two tasks interleave
  fragments of two frames, which is worse than the bug being fixed.
- An upgrade verb **drains the `JoinSet` first** (every in-flight response lands, in whatever order
  it finished), then takes an `OwnedMutexGuard` and holds it for the connection's remaining life.
  A thin `OwnedWriter<W>` wrapper implements `AsyncWrite` by delegating to the guard, so
  `open_session` and `run_subscription` keep their existing `impl AsyncWrite + Unpin + Send`
  signatures.

Draining before the upgrade is what makes the guard exclusive. Taking the guard *without* draining
would also be safe on the wire, but leaves in-flight tasks blocked forever on a mutex nobody
releases — a leak until abort, and a response the client is still waiting for.

### Ordering is now unspecified — this is the behaviour change

Responses arrive in **completion order**, not request order. JSON-RPC ids make that legal and the
in-tree `ControlClient` cannot observe it (`request_value` takes `&mut self` — it is strictly one
request at a time, by construction). A hand-rolled client that pipelines and matches responses
positionally would break.

That is an observable change to a shipped surface, so: **`api_minor` 43 → 44**, and
`docs/local-protocol.md` states the guarantee in the negative.

Note the corollary for a client that pipelines two *mutating* verbs without awaiting the first:
they may now execute concurrently. `register_service` followed immediately by `status` no longer
implies the status reflects it. Nothing in-tree does this; it is documented, not defended against.

### Bounding

A per-connection `Semaphore(MAX_INFLIGHT = 32)`. The loop uses **`try_acquire_owned`**, never
`acquire().await`: awaiting a permit inside the read loop would reintroduce the exact head-of-line
blocking this change exists to remove. At the cap the request is refused **immediately** with
`ERR_TOO_MANY_INFLIGHT` (`-32051`), documented as retryable.

Refuse rather than queue, deliberately: a queue is invisible backpressure that shows up as latency,
and the client cannot tell a slow daemon from a saturated connection. A coded refusal can be
retried or spread over a second connection.

### What stays inline

- **`shutdown`** — it must always stop, ordering-independent, and it aborts every other connection.
- **The upgrade verbs**, which by definition end the loop.
- **The `register_service` ephemeral peek (#36)** moves *into* the spawned task, recorded before the
  response is written, so a connection that closes immediately after still tears the name down.

### Connection close now aborts in-flight work

Dropping the `JoinSet` aborts every spawned task. So closing the control connection genuinely stops
a `blob_fetch` — which is defect 2's crude fix, and true for every verb, not just blobs.

## Part B — `blob_fetch_cancel`

```rust
pub struct BlobFetchCancelParams { pub hash: String }
pub struct BlobFetchCancelResult { pub cancelled: bool }
```

Keyed by **blob hash**, not by JSON-RPC id. Two reasons, and the first is decisive:

- **A JSON-RPC id is not reachable.** `ControlClient` holds `&mut self` for the duration of a
  request, so a client cannot send `cancel(id)` down the same connection while the fetch it names is
  still running. An id-keyed cancel would be unusable from the only client we ship.
- A hash is what the consumer's UI already has — it is the key in every `BlobTransfer` stream frame
  (#82 ask 2), so a Cancel button next to a progress bar already holds it.

So cancel is addressable from **any** control connection, including a fresh one.

### Mechanism

`blob_fetch` parses the ticket for its hash *before* dialing, registers a `CancelToken` in
`MeshState.fetches: Mutex<HashMap<String, CancelToken>>`, and runs fetch-then-export under a
`select!` against it. `blob_fetch_cancel` looks the hash up and trips the token.

Cancellation is **cooperative**, not `abort()`. An aborted task would deliver no response at all
and the caller would wait forever on a request that has already stopped; the select arm returns
`ERR_CANCELLED` (`-32050`), so the fetch answers.

`CancelToken` is a closed-`Semaphore` (`acquire()` errors once `close()` is called) — a few lines,
and avoids taking a `tokio-util` dependency for one type.

Concurrent fetches of the **same** hash share one token: cancelling a hash cancels every fetch of
it. That is the semantic a UI wants, and the registry entry is refcounted so the last fetch to
finish removes it.

### What cancellation does NOT do

Partial chunks already written into the store stay there, orphaned and unlisted, exactly as they do
when a fetch fails today. There is no reclaim path — that is **#80**, and inventing a
cancel-only cleanup here would leave the failure path still leaking. Stated in the docs rather than
half-solved.

## Surface

- `Request::BlobFetchCancel` + params/result structs.
- `ERR_CANCELLED = -32050`, `ERR_TOO_MANY_INFLIGHT = -32051`.
- `ControlClient::blob_fetch_cancel`.
- `mcpmesh blob cancel <hash>`.
- **`api_minor` 43 → 44** — a consumer must guard on `>= 44` for both the verb and the
  ordering change.

## Versioning

**MINOR → 0.36.0.** Response ordering on a shipped surface changes; new verb.

## Testing

1. A slow request does **not** stall the connection: a verb that blocks answers *after* a `status`
   issued behind it. This is the whole point of Part A.
2. Responses carry the right ids when they complete out of order.
3. Over the cap, the 33rd concurrent request answers `ERR_TOO_MANY_INFLIGHT` **immediately**, and
   the connection stays usable once a permit frees.
4. An upgrade (`subscribe`) after an in-flight request writes the pending response **before** the
   snapshot — the drain, and the frame-interleaving guard.
5. `open_session` still pipes bytes through the shared writer.
6. Closing the connection aborts an in-flight request (a sentinel the task would set on completion
   stays unset).
7. `blob_fetch_cancel` on an in-flight fetch answers `cancelled: true`, and the fetch answers
   `ERR_CANCELLED`.
8. `blob_fetch_cancel` for an unknown hash answers `cancelled: false` — not an error.
9. The ephemeral `register_service` teardown (#36) still fires when the register ran in a spawned
   task.

Mutation: `acquire().await` in place of `try_acquire_owned` fails 1 and 3; taking the guard without
draining fails 4; a `std::sync::Mutex` per `poll_write` fails 4's interleaving assertion; `abort()`
in place of the cooperative token fails 7 (no response); not removing the registry entry fails 8.
