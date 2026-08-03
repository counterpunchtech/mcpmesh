# The idle/keepalive contract, documented and configurable (#56)

**Status:** accepted · **Target:** 0.28.0 (MINOR) · **`api_minor`:** unchanged

## The issue's premise is wrong, and that is the most useful finding

#56 assumes a held session's survival is "whatever iroh's defaults happen to be", and the reporter
ships an **application-level heartbeat** as a workaround — which they note costs
`rate_limit_per_min` budget from the same bucket their real traffic draws on.

Measured against iroh 1.0.3's source, not its release notes:

| setting | value | where from |
|---|---|---|
| `keep_alive_interval` | **5 s** | iroh overrides the QUIC default (`HEARTBEAT_INTERVAL`) |
| `default_path_keep_alive_interval` | **5 s** | iroh override |
| `max_idle_timeout` | **30 s** | noq-proto default, not overridden |
| `default_path_max_idle_timeout` | **15 s** | iroh override (`PATH_MAX_IDLE_TIMEOUT`) |
| relay path max idle | **30 s** | `RELAY_PATH_MAX_IDLE_TIMEOUT` |

**iroh already sends a transport keepalive every 5 s.** A held session does not die after 30 s idle;
it survives indefinitely while the process runs and the network is up. The 30 s idle timeout is what
closes a connection whose keepalives stop arriving — a peer that vanished — not one that is merely
quiet.

So the app-level heartbeat is unnecessary and is spending rate-limit budget for nothing. Telling
them that is worth more than the config knobs.

### Ask 3, confirmed with the mechanism

A transport keepalive does **not** consume a rate-limit token. `node/src/backends/mod.rs` gates the
limiter on `frame.get("method").is_some()` — a method-bearing JSON-RPC frame read off the session
stream. A QUIC PING never becomes a JSON value and never reaches that loop. This is structural, not
incidental.

## What we ship

### 1. Document it, and treat it as release-note-worthy

The table above, in `docs/config.md`, with the values named as *iroh 1.0.3's* rather than as
mcpmesh's promises — they are upstream constants and a bump can move them. That is exactly why the
issue asks for it.

### 2. `[network].idle_timeout_secs` and `[network].keep_alive_secs`

Applied via `Endpoint::builder().transport_config(...)`. Both optional; absent means "iroh's
default", so nothing changes for anyone who does not set them.

**Validation matters more than usual here**, because both knobs can bricks a node quietly:

- `keep_alive_secs` **must be less than** `idle_timeout_secs`, or the peer times the connection out
  before the next keepalive arrives — a config that severs every session on a timer. Rejected at
  boot with the reason, not accepted and mysterious.
- `keep_alive_secs` **must be at most 5s**, iroh's per-path cap. Above it the setting is silently
  discarded upstream, so accepting it would mean reporting success for a no-op.
- `idle_timeout_secs = 0` means "no timeout" in QUIC. Accepted, but it is a real choice: a dead peer
  is then never detected at the transport layer. Documented rather than silently allowed.
- The QUIC wire caps `max_idle_timeout` at a varint; absurd values are rejected rather than
  saturating.

### 3. Not exposed: the per-path knobs

`default_path_*` and the relay-path idle timeout are multipath internals whose interaction with
hole-punching we have not characterised. Exposing a knob we cannot explain is worse than not having
it — an operator who sets it has no way to tell what they broke.

## Versioning

**MINOR → 0.28.0.** `NetworkCfg` is a `pub` struct in a published crate and an embedder constructs
it (`NodeBuilder::config`), so new fields break exhaustive construction. No wire change, so
`api_minor` is unchanged.

## Corrections the gate forced

Three claims in the first draft were wrong, and two of them were in user-facing docs:

- **The idle timeout is NEGOTIATED** — QUIC uses the minimum of both peers' values (RFC 9000
  §10.1). "Raise it for a flaky link" was wrong: raising one node's value achieves nothing against
  a peer on the default. `0` likewise yields the peer's value rather than no timeout. This is the
  one that would have driven an embedder's architecture decision wrong.
- **`keep_alive_secs` cannot do what the issue wanted, and now says so.** The first fix set the
  per-path keepalive too, believing that let the knob reduce ping frequency. It does not: iroh
  **caps** the per-path interval at 5s and discards anything larger with only a `warn!`. So a value
  above 5 changes nothing observable — every path keeps pinging at 5s. Boot now **refuses** it and
  names the cap, because the alternative is a knob whose headline use case silently no-ops. The
  metered-link saving #56 was filed for is **not available on iroh 1.0.3**; that is the honest
  answer and it is worth more to the reporter than the knob.

  This one survived a round of review because the test asserted `Some(5s)` while iroh's own default
  is 5s — deleting the per-path assignment left the assertion true. The fixture value collided with
  the default it existed to distinguish from. Values are now 3s, below both the default and the cap.
- **A bare `keep_alive_secs` skipped validation entirely.** `keep_alive_secs = 3600` with no
  `idle_timeout_secs` was accepted, producing exactly the keepalive-outlives-timeout pairing the
  check exists to reject, because iroh's 30s still applied. It now validates against the effective
  timeout — though the cap above makes that path unreachable for a bare keepalive today, since
  anything the cap admits (≤ 5s) is under iroh's 30s default. The check stays because it is what
  bites if a bump moves either number.

## Testing

1. Absent config → nothing is applied at all.
2. Configured values reach the **built `QuicTransportConfig`**, asserted on its `Debug` — including
   that `keep_alive_secs` sets the per-path keepalive too, and that `idle_timeout_secs = 0` really
   sets no-timeout rather than leaving iroh's 30s. Fixtures use 3s, which differs from every iroh
   default in the struct.
3. `keep_alive_secs` above iroh's **per-path cap** → boot **fails**, naming their value, the cap,
   and the fact that raising it cannot reduce traffic.
4. `keep_alive_secs >= effective idle timeout` → boot **fails**, naming both values.
5. **iroh's documented defaults are pinned, and so is the cap** — the cap is probed
   *behaviourally* (build with cap+1, assert it came back clamped), not asserted against our own
   constant, so a bump that lifts it fails the test and tells us the metered-link case just became
   possible. This is ask 1's "treat a change as release-note-worthy" made mechanical.

Not tested, and stated rather than implied: that a live session survives an idle period longer than
the timeout. It needs two endpoints and a wall-clock wait longer than any unit test should take, and
the property it would demonstrate is iroh's, not ours — pinning iroh's keepalive default (4) is the
proxy. The rate-limit claim is confirmed structurally (the limiter's single call site is gated on
`frame.get("method").is_some()`), not by a test.

Mutation, all five run and all five caught: dropping the per-path keepalive fails 2; dropping the
`0`-means-no-timeout branch fails 2; dropping the cap refusal fails 3; dropping the ordering
refusal fails 4; changing the cap constant to a value iroh does not enforce fails 5.
