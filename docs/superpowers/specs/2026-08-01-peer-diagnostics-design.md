# `peer_diagnostics` — the durable state behind one pairing (#140)

**Status:** accepted · **Target:** 0.26.1 (PATCH) · **`api_minor`:** 33

## What was reported

Two paired endpoints on one LAN cannot hole-punch in either direction, across 0.19.3 → 0.23.0. The
same two machines **punch direct in ~23 ms with fresh mesh identities**, and raw UDP works both ways
— so the network and the hardware are eliminated. #124's dial-hint refresh fixed a WAN peer at the
same moment and did not clear this pair. It survives live sessions in both directions, dial-backs in
both directions, and multiple daemon restarts.

The ask is precise and answerable: *"What state does a long-lived pairing carry that a fresh
identity does not? … If there is a way to dump per-peer path/hint state for a pair, we can capture
it on both ends of a live reproduction."*

## What we can and cannot do here

**Cannot:** reproduce it. It needs two real machines on a real LAN with a specific history. Any
"cause" asserted from here would be a guess dressed as a finding.

**Can:** answer the state question from our own code, correct a wrong claim in our own docs while
doing so, and build the capture they asked for. That is what ships.

## The state question, answered

From this node's side exactly one thing is durable, per-peer, and different between a long-lived
pairing and a fresh identity: **`PeerEntry.last_addr`**, the persisted dial hint. Everything else a
fresh identity lacks — path state, the reachability cache, iroh's per-remote actor — is derived at
runtime and does not survive a restart, and the report notes restarts do not clear the failure.

### A correction found on the way

Two of our own docs disagreed about what a hint does. `dial.rs` said iroh *merges* it with
discovery; `dial_hint.rs` said a hint is *"replacing the bare-id dial"*.

`dial.rs` is right. In iroh 1.0.3, `handle_msg_resolve_remote` inserts the provided addresses as
candidate paths with `Source::App` and then calls `trigger_address_lookup` — discovery still runs.
What a new hint replaces is the previously **stored** hint, which is why #124's real finding (never
persist a relay URL over a direct one) holds while its wording did not.

This matters for reading #140: a stale hint does **not** by itself hide a live discovered address.
It stays the first thing to compare because it is the only durable per-peer difference — not because
it is proven to be the cause.

## What ships

`peer_diagnostics {peer}` → the durable state plus this node's live view, in one capture:
the hint verbatim, its parsed addresses, `hint_usable`, the pairing stamp, the reachability row.
`mcpmesh internal peer state <peer> [--json]`.

### `hint_usable` is the field that earns the verb

A stored hint that does not parse, or whose embedded endpoint id is a **different** peer, is
silently discarded by `stored_dial_addr` on every dial: the node behaves as if it had no hint while
the store insists it has one. That discrepancy is invisible from every other surface.

It is computed by running the hint through **`stored_dial_addr` itself** — the function the dial
uses — not by re-reading the JSON, so the report and the behaviour cannot disagree.

### Transport vocabulary, deliberately

Every other surface is address-free on purpose. This one is not, because the question is "what
address is this node about to dial". Marked loudly on the type, the verb, the CLI help, and the
protocol doc. Read-only — it probes nothing, dials nothing, writes nothing — so running it cannot
perturb the state under study, which matters when the reproduction *is* the experiment.

## Versioning

**PATCH → 0.26.1.** A new verb and new types are additive; no existing shape changes. `API_MINOR`
33.

## Testing

1. No hint → `hint_usable: false`, no addresses — the fresh-identity baseline.
2. A well-formed hint for this peer → reported verbatim, addresses extracted, usable.
3. **A hint whose embedded id is a different peer** → reported verbatim, `hint_usable: false`,
   no addresses. The invisible case.
4. Garbage → degrades identically rather than erroring the verb.

Mutation: computing `hint_usable` from "a hint is present" instead of from `stored_dial_addr` fails
3 — which is the whole point of the field.

## Out of scope

Any change to hole-punching, dialing, or hint lifetime. This is a diagnostic; the next move belongs
to the paired capture it produces.
