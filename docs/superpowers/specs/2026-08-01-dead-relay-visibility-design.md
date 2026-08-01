# A dead relay in a custom list: measure it, then make it visible (#125)

**Status:** accepted · **Target:** 0.25.4 (PATCH) · **`api_minor`:** unchanged (31)

## What was reported

One unreachable relay in a `relay_mode = "custom"` list adds **40–200 s** to mesh boot, with four
healthy relays behind it. Measured on 0.19.3, macOS 15 aarch64. The reporter infers the list is
**walked rather than raced**, because "the cost scales with where the dead relay sits", and asks for
either racing or a bounded per-relay connect deadline.

## What we measured

0.19.3 and 0.25.3 pin the **same** `iroh = "=1.0.3"`, so the relay stack is unchanged between their
measurement and now. Built a real reproduction: an in-process healthy relay
(`iroh::test_utils::run_relay_server`) plus a **true blackhole** — a TCP listener that accepts and
then never writes a byte, so the handshake hangs rather than failing fast, which is strictly worse
than an unroutable address. Five samples per case, one process, `Endpoint::online()` as the clock.

| case | n | min | median | max | came online |
|---|---|---|---|---|---|
| healthy only | 5 | 216 ms | **226 ms** | 232 ms | yes |
| blackhole FIRST | 5 | 3013 ms | **3017 ms** | 3021 ms | yes |
| blackhole LAST | 5 | 3016 ms | **3017 ms** | 3020 ms | yes |
| 4× blackhole FIRST | 5 | 3008 ms | **3017 ms** | 3019 ms | yes |
| unroutable FIRST | 5 | 3012 ms | **3013 ms** | 3018 ms | yes |

Three conclusions, each directly supported:

1. **The relays are raced, not walked.** The cost is identical whether the dead entry is first or
   last. The reporter's central inference does not hold on this pin.
2. **The cost does not scale with the number of dead relays.** Four blackholes cost the same as one.
3. **The residual is a flat ~2.8 s**, and the node still comes online every time.

So requested fix (1) is already the upstream behaviour, and fix (2) — a bounded per-relay deadline —
already exists in effect: the observed penalty is bounded and position-independent.

## What this does NOT explain

~2.8 s is not 40–200 s. Their dead host is remote and real; ours is loopback. Untested differences
that could account for the gap: DNS resolution of the dead host hanging (ours needs none), and their
"mesh boot" clock being a loopback pairing test reaching mesh-up — which includes pkarr publish and
discovery over the real internet, not just `online()`.

**We are not claiming their measurement was wrong.** We are reporting that the mechanism they
inferred is not the one in this code, that the part we can measure is bounded and raced, and asking
for a re-measure on 0.25.4 with the new diagnostic below.

## What we ship

No relay-selection change: it is iroh's, and it already does the requested thing.

### 1. `doctor` reports live relay health (the actual gap)

`status.self_network.relays[]` has carried `{url, connected}` since #90, and nothing surfaces it. A
node whose pinned relay is dead pays the penalty silently and the operator has no way to see why —
which is the part of this report that IS ours.

`check_relays(configured, live) -> Verdict`, pure and table-tested like every other doctor check:

- no relays configured (`default` / `disabled` mode) → not emitted.
- daemon unreachable → `Info` ("live relay state needs a running daemon").
- every configured relay connected → `Ok`.
- some connected, some not → **`Warn`** naming the dead URLs, and saying what it costs: the node
  still works via the healthy relays, and boot pays a bounded penalty.
- none connected → **`Warn`** — this node has no relay path right now.

Wired through `probe_daemon`, which already opens a control connection and reads `status`; it gains
the `self_network.relays` list alongside the roster state it already extracts.

### 2. A regression test pinning the raced behaviour

The measurement above becomes a permanent test asserting a dead relay's cost is **position- and
count-independent**, with generous absolute bounds (it asserts the *shape*, not a latency budget —
a tight bound here is what made #110 flaky).

This is the durable value: it guards the property on every future `iroh` bump, which the maintainer
loop files automatically. If a future iroh regresses to a sequential walk, this fails instead of a
downstream re-discovering it in production.

## Versioning

**PATCH → 0.25.4.** A new doctor finding, no wire change, no verb change. `api_minor` unchanged —
`doctor` is porcelain, not protocol.

## Testing

1. `check_relays` table: unconfigured, daemon-down, all-connected, partial, none-connected.
2. The partial case NAMES the dead URL — an operator must be able to act on it.
3. The raced-behaviour regression test (position and count independence).

Mutation: making the partial case return `Ok` must fail 1; dropping the URL from the message must
fail 2; a sequential walk would fail 3.

## Out of scope

Relay selection itself, and any change to `RELAY_READY_TIMEOUT` (already 3 s and already bounded).
