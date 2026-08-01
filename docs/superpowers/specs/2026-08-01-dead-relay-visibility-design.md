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

**Correction to the 4× row (gate finding).** It was not four relays. `RelayMap` is a `BTreeMap`
keyed by URL, so four clones of one blackhole collapsed to a single entry and silently re-measured
the 1× case. Re-run with four *distinct* listeners: one dead 3007 ms, four dead 3008 ms. The
conclusion holds; the original evidence for it did not.

That same fact retires the position question outright, and far more strongly than any timing could:
configured ORDER is **structurally discarded** before iroh sees it, because `net_plan` hands
`RelayMode::Custom` that same URL-keyed `BTreeMap`. "Where the dead relay sits" is not a property
this system has — so the positional walk the report infers is impossible by construction, and a
timing test of it can never fail. The first version of the regression test was exactly that test.

Conclusions:

1. **A positional walk is not representable.** Config order does not survive into iroh.
2. **Cost does not scale with the number of dead relays** — measured with distinct entries.
3. **The residual is a flat ~3.0 s**, and the node still comes online every time. That figure is
   iroh's `PROBES_TIMEOUT`: the net-report waits for its slowest probe before a home relay can be
   picked.

So requested fix (1) is already the upstream behaviour, and fix (2) already holds in effect: the
penalty is bounded and independent of both position and count.

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

### 1. `doctor` reports live relay health

`status --json` has carried `self_network.relays[].connected` since #90, but no HUMAN surface did —
not the `status` line, not `doctor` — so it was available only to an embedder that already knew to
look. A node whose pinned relay is dead pays the penalty with nothing pointing at the cause.

Emitted for `relay_mode = "custom"` ONLY. `relay_urls` is ignored in every other mode and nothing
rejects leftovers, so gating on the list alone told a healthy node on the default relays that it
had "no relay path right now" (gate finding).

URL matching is EXACT, over the daemon's own `sanitize_relay_url` — shared, not reimplemented, so
the two renderings cannot drift. The first version prefix-matched and reported a dead relay as
connected whenever it was a strict prefix of a healthy one (`https://relay.acme.com` masked by
`https://relay.acme.com:8443`), which is precisely the failure the check exists to prevent.

`check_relays(configured, live) -> Verdict`, pure and table-tested like every other doctor check:

- no relays configured (`default` / `disabled` mode) → not emitted.
- daemon unreachable → `Info` ("live relay state needs a running daemon").
- every configured relay connected → `Ok`.
- some connected, some not → **`Warn`** naming the dead URLs, and saying what it costs: the node
  still works via the healthy relays, and boot pays a bounded penalty.
- none connected → **`Warn`** — this node has no relay path right now.

Wired through `probe_daemon`, which already opens a control connection and reads `status`; it gains
the `self_network.relays` list alongside the roster state it already extracts.

### 2. Regression tests with actual teeth

Three, none asserting a latency budget — a tight wall-clock bound is what made #110 flaky, and the
absolute figure is iroh's to change:

- config order is discarded before iroh sees it (a property, not a timing);
- a dead relay's cost does not grow with their NUMBER, using distinct listeners, with an assertion
  that the map did not collapse them;
- `RELAY_READY_TIMEOUT` outlasts a measured `online()` under a dead relay — see below.

The durable value is the iroh-bump path: the maintainer loop files a bump on every new stable
release, and relay selection is exactly the internal behaviour a minor bump can change with no type
diff.

## Versioning

**PATCH → 0.25.4.** A new doctor finding, no wire change, no verb change. `api_minor` unchanged —
`doctor` is porcelain, not protocol.

## Testing

1. `check_relays` table: daemon-down, all-connected, partial, none-connected.
2. The partial case NAMES the dead URL — an operator must be able to act on it.
3. A dead relay is not masked by a healthy one it prefixes; a re-spelling of one relay is not read
   as a second, dead one.
4. The finding is emitted for `custom` mode only.
5. Cost independent of the number of dead relays (distinct listeners, collapse guarded).
6. `RELAY_READY_TIMEOUT` exceeds a measured `online()` by real margin.

Mutation: the partial case returning `Ok` fails 1; counting instead of naming fails 2; restoring
the 3 s deadline fails 6.

## The finding the first draft missed

`RELAY_READY_TIMEOUT` was **3 s** — the same value as iroh's `net_report::defaults::PROBES_TIMEOUT`,
which is what `online()` is waiting on. Every dead-relay sample above lands at 3007–3021 ms, i.e.
*just past* a 3000 ms deadline. So `mint_invite` and `BlobProvider::ticket_for` lost that race
essentially always and produced an address with **no relay URL** — on a node that was perfectly
online via the healthy relays behind the dead one. A WAN redeemer bootstraps from that URL.

That is a candidate mechanism for the multi-minute mesh-up actually reported, and unlike relay
selection it is entirely ours. Raised to **5 s**, which clears iroh's window with margin. The extra
wait is paid only when no relay answers at all — where the mint was already going to be relay-less;
a healthy node returns in ~200 ms either way.

Pinned by asserting the ORDERING against a *measured* `online()`, not a hardcoded number, so it
stays honest when iroh changes its constant — which is exactly what the iroh-bump path needs.

The first draft declared this out of scope on the premise that 3 s was "already bounded". It was
bounded and wrong: the bound sat exactly on the value it needed to exceed.

## Out of scope

Relay selection itself — it is iroh's, and it already does the requested thing.
