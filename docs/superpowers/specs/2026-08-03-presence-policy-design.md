# `[network].presence_mode` — presence becomes revocable (#89)

**Status:** accepted · **Target:** 0.30.0 (MINOR) · **`api_minor`:** unchanged

## Scope: ask 1 already shipped, ask 3 is separable

The issue is stale against `main`. Re-verified before starting:

- **Ask 1 (per-endpoint ping bucket) is DONE.** `PING_PER_MIN = 60` and `admit_ping` exist
  (`node/src/limits.rs:225,344`), consulted in the ping arm after gate-resolve, with
  `pings_refused` for the count and a distinguishable `PING_THROTTLE_CLOSE` so a throttled probe is
  not written down as "peer offline". It landed with #142's work.
- **Ask 3 (publish the responder's rate-limit budget on the pong)** the issue itself marks separable
  and invites on #63. Not in this change.

So this change is **ask 2 only**: `[network].presence_mode`.

## The problem, in the reporter's terms

The ping arm is gated by **pairing alone**. `service_allow_revoke` has no effect on it. So a peer
from whom every service has been revoked still gets, on demand: that you are online right now, your
RTT (a coarse geography signal), your `stack_version`, and your `set_app_metadata` value. The only
lever that stops it is a full unpair — a relationship-destroying action used to express a privacy
preference.

Their product has a per-peer sharing switch. Turning it **off** leaves that peer holding a real-time
attendance log of the user's working day. They cannot describe the switch honestly.

## Design

```toml
[network]
presence_mode = "paired"   # default — today's behaviour
# presence_mode = "granted"
# presence_mode = "off"
```

- **`paired`** — pong to any resolvable (paired) peer. Unchanged; the default, so nothing moves for
  anyone who does not set it.
- **`granted`** — pong only to a caller currently holding **at least one service grant**. The data
  is already computed in that arm: `caller_admitted_services` runs there to fill the pong's
  `services` field, so this reads a value the arm already has.
- **`off`** — never pong.

**`granted` is the load-bearing mode**, and it is why this is a config knob rather than a new verb:
it makes the embedder's *existing* per-peer sharing switch control presence, with no new API and no
restart. Grants are already live (`service_allow_revoke` reloads under `reload_lock`), so revoking
the last service takes presence away in the same action. That is the thing the reporter cannot
express today.

### A refusal must not distinguish why

`off`, and `granted`-without-a-grant, close **exactly like the trust gate's refusal** —
`CLOSE_UNAUTHORIZED` with `b"unauthorized"`, byte-identical. A prober therefore cannot tell "not
paired" from "presence off" from "no grants": all three read as offline, which is what
`probe_peer` already records (`reach.rs`: "a gate refusal (no pong) or any dial/IO failure is a
clean `reachable:false`").

This is the same discipline as the pairing redemption oracle — the refusal wording never
distinguishes the cause. If a hidden node answered with its own distinguishable close, a prober
would learn "this peer is online and deliberately hiding", which is precisely the fact the mode
exists to withhold.

**The policy check runs BEFORE the rate limiter**, deliberately. `PING_THROTTLE_CLOSE` is
distinguishable on purpose (#142: a throttled probe must not be written down as "offline"), so
metering a hidden node first would leak presence through the throttle close. Cost of that ordering:
a hidden node still pays one `gate.resolve` per dial — identical to the unpaired-scanner path that
already exists and is accepted under "strangers stay cheap".

### Not exposed on the control API

No verb reports the mode, so `api_minor` does not move. An embedder sets it through
`NodeBuilder::config` and already knows its own value; a human sets it in `config.toml`. Adding a
read-back verb is a separate, additive change if anyone asks.

**It is read at boot**, not live-editable. The per-peer effect that a product needs *is* live, via
grants under `granted`. Changing the mode itself needs a restart, and the docs say so rather than
leaving it to be discovered.

## Versioning

**MINOR → 0.30.0.** `NetworkCfg` is `pub` in a published crate and gains a field, breaking
exhaustive construction for embedders. Behaviour is unchanged at the default.

An unknown mode is a **startup error**, matching `relay_mode`/`discovery_mode` — a privacy knob must
never silently fall back to the permissive value. That is the whole reason the validation exists:
`presence_mode = "of"` failing loudly is the difference between a user who is hidden and a user who
believes they are.

## Testing

1. `paired` (and absent) pongs to a paired caller with no grants — today's behaviour preserved.
2. `granted` pongs to a caller holding a grant, and **refuses one holding none**.
3. `off` refuses a paired caller holding grants — the mode overrides everything below it.
4. **The refusal is byte-identical to the trust gate's**, asserted across the unpaired, `off`, and
   `granted`-without-grant cases. This is the anti-oracle property.
5. An unknown mode is a startup error naming the key and the legal values.
6. The policy is consulted **before** the limiter: a hidden node's refusal is never
   `PING_THROTTLE_CLOSE`.

Mutation: defaulting an unknown mode to `paired` fails 5; moving the policy check after the limiter
fails 6; making `off` close with its own reason fails 4; making `granted` read the full registry
rather than the caller's admitted services fails 2.
