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

## Testing

1. Absent config → the endpoint is built with iroh's default transport config (no override).
2. Both set → applied, and readable back off the built endpoint's config.
3. `keep_alive_secs >= idle_timeout_secs` → boot **fails** with a message naming both values.
4. A session stays alive across an idle period longer than `idle_timeout_secs` when keepalives are
   on — the property the issue is actually about.
5. The rate limiter does not count a transport keepalive.

Mutation: dropping the ordering validation fails 3; applying the values in the wrong order (idle as
keepalive) fails 2.
