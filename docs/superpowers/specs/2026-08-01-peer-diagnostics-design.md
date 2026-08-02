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

Scoped carefully, because the reporter will act on it: **the only durable per-peer state on this
node's disk that the DIAL PATH reads is `PeerEntry.last_addr`.**

That is narrower than "the only durable difference", and the first draft overstated it. Other
durable state a long-lived identity carries that a fresh one does not: a discovery record published
under the same key (the `presets::N0` pkarr publisher), accumulated `services` from repeated
pairings, legacy bare-nickname allow entries, blob-scope grants, and #134's
`identity_conflict_epoch`. None of it feeds the dial — but "exactly one thing" would have sent
someone looking in one place when several exist.

### A correction found on the way

Two of our own docs disagreed about what a hint does. `dial.rs` said iroh *merges* it with
discovery; `dial_hint.rs` said a hint is *"replacing the bare-id dial"*.

`dial.rs` is right about the merge: `handle_msg_resolve_remote` inserts the provided addresses as
candidate paths with `Source::App`, then calls `trigger_address_lookup`. What a new hint replaces is
the previously **stored** hint, which is why #124's real finding (never persist a relay URL over a
direct one) holds while its wording did not.

**But that lookup is conditional, and the condition is the interesting part.**
`trigger_address_lookup` returns early when `selected_path.is_some()`, and a selected path is
cleared only when the last connection to that peer closes. So on a pair that already holds an open
**relayed** connection — live sessions and dial-backs in both directions, which is precisely the
reported steady state — discovery does **not** re-run, and the stored hint is the only addressing
the dial contributes.

The first draft stated the merge unconditionally and told the reporter a stale hint "does not by
itself hide a live address". That reassurance is least true in exactly the state a stuck pairing is
in, which makes the condition a lead rather than a footnote.

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

The rendered porcelain is address-free on purpose. This surface is not, because the question is
"what address is this node about to dial". (`status` already returns this node's OWN `direct_addrs`;
what is new is a peer's.) Relay URLs are sanitized to scheme+host+port, as everywhere else, because
an operator's can carry a userinfo token and this output is meant to be pasted into an issue.

Read-only, and getting that right took a correction: the first version read the live row through
`status`'s projection, which **spawns a background probe for every stale peer** — so a verb
documented as "dials nothing" dialed every paired peer, wrote both caches, pushed `Reachability`
frames at subscribers, and spent the peer's #89 ping budget. It now reads the cache directly. A
diagnostic used ON a live reproduction must observe it, not join it.

## Versioning

**PATCH → 0.26.1.** A new verb and new types are additive; no existing shape changes. `API_MINOR`
33.

## Testing

1. No hint → `hint_usable: false`, no addresses — the fresh-identity baseline.
2. A well-formed hint for this peer → reported verbatim, addresses extracted, usable.
3. **A hint whose embedded id is a different peer** → reported verbatim, `hint_usable: false`,
   no addresses. The invisible case.
4. Garbage → degrades identically rather than erroring the verb.
5. A **relay-only** hint is reported, not filtered into an empty line, and its userinfo is
   sanitized. That shape can never punch and is reachable in production.
6. The verb **takes no probe ticket** — it does not dial.
7. The live row is joined by **endpoint id**, not nickname: two peers may share a name.

Mutation: computing `hint_usable` from "a hint is present" instead of from `stored_dial_addr` fails
3; restoring the `reachability_of` call fails 6 and 7.

## Out of scope

Any change to hole-punching, dialing, or hint lifetime. This is a diagnostic; the next move belongs
to the paired capture it produces.
