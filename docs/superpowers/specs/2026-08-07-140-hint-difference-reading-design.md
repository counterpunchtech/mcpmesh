# #140: make `iroh_addrs_not_in_hint` readable — design

Date: 2026-08-07
Issue: #140 (`A long-lived pairing cannot hole-punch on its own LAN`)
Release: 0.52.5 (PATCH — documentation and test only, no surface change)

## Why this, and why nothing else

#140's reported symptom is **resolved**. The fleet in the issue now punches `direct` in both
directions at 10 ms, below its own pre-regression figure of ~12 ms, with both ends on `=0.52.4` and
both restarted. The issue's diagnostic question — *what durable state does a long-lived pairing
carry that a fresh identity does not* — was answered across 0.49.2 / 0.52.0 / 0.52.2.

What remains in the thread is one observation the reporter flagged as unexplained, and explicitly
declined to interpret:

> the Mac's hint did **not** refresh the same way (`hint_addrs` stayed 1, `iroh_addrs_not_in_hint`
> went 5 → 8), and the thinner-hint side is the one reporting higher rtt.

They read the growing difference as the hint drifting. **It is not.** The two lists are built from
different things and are expected to diverge:

- `hint_addrs` comes from `dial_hint::observed_for` — the open **IP** paths of one live connection.
  On a healthy session that is typically one to three addresses.
- `known_addrs` comes from `Endpoint::remote_info` — every `TransportAddr` iroh's remote map holds
  for the peer, accumulated from discovery and from paths, active or not, **including relay URLs**.

Two structural consequences follow, and neither is currently written down:

1. A hint **whose addresses came from `observed_for`** is IP-only by construction — that function
   filters to `is_ip`. So every relay URL iroh holds is in `iroh_addrs_not_in_hint` for as long as
   such a hint stands. It is never evidence of anything. (Scoped by SOURCE, not by release: a
   legacy row, a legacy value carried forward by a later write, or a direct `PeerStore::add` by an
   embedder can each still name a relay, and `peer_diagnostics` reports that shape rather than
   hiding it.)
2. A growing `iroh_addrs_not_in_hint` means **iroh learned more candidates** — the normal result of
   discovery running. It does not mean the stored hint went stale.

`hint_addrs_unknown_to_iroh` — the converse field — already carries three paragraphs of
interpretation guidance warning against exactly this class of misreading ("is not accumulated
cruft"). `iroh_addrs_not_in_hint` carries one sentence: "the converse: what iroh holds that our
stored hint does not name". The asymmetry in the docs produced the asymmetry in the reading.

This file's own code comments set the standard being applied here: *"A diagnostic that confidently
mislabels the common case is worse than no diagnostic."* The field does not mislabel — but it
leaves its most natural misreading unguarded, and that misreading has now happened in the field, in
the issue the field was built for.

## What is deliberately NOT in scope

Recorded so it is not re-attempted from scratch a fourth time.

**The relay-only refresh gap is not being closed.** On a pairing whose every connection is relayed,
this node has no mechanism to learn the peer's current direct addresses: `observed_for` returns
`None` (correctly — persisting a relay URL over a direct candidate was #124's own measured bug) and
`merge_hint` reads `None` as *leave alone* (also correctly — clearing on a transient relayed session
would discard a good hint).

Closing that gap **requires** storing addresses the peer claims but this node has never validated.
There is no safe source for them:

- The pong-carries-`direct_addrs` design was implemented, tested, and refused at review: it hands a
  paired-but-hostile peer a standing UDP reflection primitive, refreshed every 20 s by the probe
  cycle and surviving both the attacker going offline and a daemon restart.
- `remote_info`'s `Active` addresses cannot substitute. On a relay-only pair, by definition, no IP
  address is active — that is the condition being diagnosed. It would fix nothing.

So the gap is a **known limitation with a stated reason**, not an open TODO. Filed as its own issue
so it stops being rediscovered inside a 20-comment thread.

**The hint is not being widened to a union.** `set_last_addr` replaces wholesale, so a node whose
sessions open one path at a time keeps a one-address hint and discards addresses it had itself
validated earlier — which is what the Mac's `hint_addrs: 1 (unchanged)` shows. Unioning would be a
dial-path change with no measurement demanding it, against a pair that is currently healthy, and it
needs a class-aware cap — the exact mechanism that sank the previous attempt, whose `BTreeSet`
ascending truncation dropped public IPv4 and all IPv6 first. Noted in the follow-up issue as a
candidate with its tradeoff, not shipped.

## The change

**`local-api/src/protocol.rs`** — give `iroh_addrs_not_in_hint` the interpretation guidance its
counterpart has: growth means iroh learned candidates, not that the hint drifted; the two lists have
different cardinality by design; a hint sourced from `observed_for` is IP-only, so relay URLs iroh
holds sit in this list — with the three routes by which a stored hint can still name one.

**`docs/local-protocol.md`** — the same two points as a bullet beside the existing
`hint_addrs_unknown_to_iroh` bullet, keeping the prose doc and the rustdoc in sync.

**No `API_MINOR` bump.** No field is added, removed, or changed shape; no verb changes. This is
documentation over an existing `api_minor 59` surface.

## Testing

A rustdoc change is not itself testable, so what gets pinned is the behaviour the guidance
describes. There is a real coverage gap to close here, and it is the one the doc gap mirrors.

`known_addrs_reports_irohs_own_view_once_a_connection_exists` asserts
`hint_addrs_unknown_to_iroh.is_empty()` against a live view and asserts **nothing** about
`iroh_addrs_not_in_hint`. So the direction the reporter actually read is computed by code no test
observes with a real view present — the same "pin the call site, not the helper" shape that test's
own docstring was written to close, left open in the other direction.

New test, alongside it rather than replacing it, so both directions stay pinned:

- two hermetic endpoints, one real loopback connection, exactly as the existing test;
- seed `last_addr` with a well-formed `EndpointAddr` for the **right peer id** carrying only
  `192.0.2.7:4433` — TEST-NET-1, dialable under `is_dialable_addr`, and never equal to a real local
  address;
- connect with `peer_addr` explicitly, so iroh's remote map holds the peer's real addresses and
  never the hint's (`peer_diagnostics` does not dial, so nothing else can insert it);
- assert `hint_addrs_unknown_to_iroh == ["192.0.2.7:4433"]` **and** `iroh_addrs_not_in_hint`
  non-empty and containing none of the hint's addresses.

Deterministic by construction: the two address sets cannot intersect, so neither assertion depends
on which interfaces the host happens to have.

**Mutations to verify it is not vacuous:** hardcode `iroh_addrs_not_in_hint` to `Vec::new()`, and
separately compute `addr_differences` in one direction only. Each must fail the new test.

This also demonstrates the doc's point directly: a peer that is connected **right now**, whose view
is live and whose hint is well-formed, reports a non-empty `iroh_addrs_not_in_hint`.

### Relay exclusion IS tested — an earlier draft of this spec claimed otherwise, and was wrong

This section originally asserted that no test in this repo could put a relay address into iroh's
remote map, because hermetic endpoints run `relay_mode = "disabled"`, and therefore that
`observed_for`'s relay filtering was unverifiable. **Both statements are false**, and the gate
caught them.

`cli/tests/dial_hint_refresh.rs::a_live_session_refreshes_the_dial_hint_and_never_stores_a_relay`
stands up a real relay with `iroh::test_utils::run_relay_server()`, binds both endpoints with
`RelayMode::Custom`, seeds a relay-only `last_addr` so the session starts relayed, drives
`dial_service` → path watcher → `observed_for` → the stored hint, and asserts the healed hint
contains an `Ip` and no `Relay`. Four other suites also run non-disabled relays
(`live_path_events`, `peer_path`, `self_network`, `relay_race`).

So the docs cite that test rather than excusing the absence of one.

### The claim's axis is sourced-from, not written-when

A second correction from the gate. `merge_hint(None, existing)` preserves a stored value, and the
attestation admit path (`rendezvous.rs:680`) re-persists `prior.last_addr` — so a **write performed
today** can carry a relay whose value is legacy. `allowlist` is also a public module, so an embedder
can `PeerStore::add` anything.

The accurate claim is therefore about a hint **whose addresses came from `observed_for`**, not one
written after a particular release. The docs say it that way, and name all three routes by which a
stored hint can still carry a relay.

## Consumer impact

None. Documentation and one test. The reply on #140 carries the reading guidance to the person who
needs it today; the doc change is what stops the next reader making the same inference.
