# Force the relay path, behind a test-only feature (#116)

**Status:** accepted · **Issue:** #116 · **Target:** 0.20.0 (config surface → MINOR)

## Problem

There is no way to make a node use the relay while a direct path exists. `relay_mode` offers
`default | custom | disabled`, and `disabled` is the *hermetic* posture — no relay **and** no
discovery. So the choices are "prefer direct, fall back to relay" or "no network at all".

The cost is concrete: proving that a revoke severs a **live relayed** connection required physically
moving a machine onto a phone hotspot, twice. Anything an embedder wants to verify about relayed
behaviour — relay-path severing, relay RTT budgets, a relay dropping mid-session, media-over-relay
limits — has the same problem.

The trap that makes it non-obvious: **two machines on a LAN with IPv6 hole-punch direct**, so a
"WAN" test on different subnets can silently still be direct.

0.19.1 shipped the observability half (`status` shows `direct`/`relay`/`path unknown`). This is the
forcing half.

## Approach

iroh 1.0.3 exposes `Endpoint::builder().path_selector(Arc<dyn PathSelector>)`. A selector chooses
among the **open** paths, so a `RelayOnly` selector picks the relay path whenever one exists.

**Owner decision: behind a test-only cargo feature**, so production never depends on it.

`path_selector` is gated behind iroh's `unstable-custom-transports`, and iroh states that API is
*"not covered by semantic versioning guarantees and may change in any release without a major
version bump."* mcpmesh exact-pins iroh precisely to control that risk. A default-off feature means a
normal `cargo build` never compiles against the unstable API, so a breaking iroh change cannot break
a production build — only a test build that opted in.

```toml
# node/Cargo.toml
[features]
unstable-relay-only = ["iroh/unstable-custom-transports"]
```

The `unstable-` prefix mirrors iroh's own convention and states the semver posture in the name.

### What the selector does, and what it does NOT do

`select()` returns the relay path when one is open. It does **not** prevent hole-punching — that is
socket-level behaviour a selector cannot reach, unlike iroh's internal `RelayOnly`. So a direct path
may still form; we simply never select it.

**That is sufficient, and honest.** Application data rides the relay, which is what a relay test
needs. And because #64 derives `PeerPath` from `Path::is_selected()`, `status` reports `relay` —
the observable agrees with the reality.

Documented explicitly so nobody reads "relay only" as "no direct path was ever attempted".

### Config surface

`[network] relay_only = true`. The field **always parses** — `NetworkCfg` is `#[serde(default)]`
with no `deny_unknown_fields` — and only its *effect* is gated:

- feature ON, `relay_only = true` → install the selector.
- feature OFF, `relay_only = true` → **`warn!` and continue**, not a startup error.

A config that names a knob the binary cannot honour must say so loudly, but it must not brick a node
over a testing switch, and a config file should stay portable between a test build and a production
one. A silent ignore is the unacceptable option — that is how someone believes they tested the relay
and did not, which is the exact failure #116 reports.

No `NodeBuilder` method: an embedder already passes a whole `Config` via `NodeBuilder::config`, so
the field is reachable in-process with no new surface.

## Surface + versioning

- `NetworkCfg.relay_only: bool` (default `false`), documented in `docs/config.md` as **testing
  only**, with the semver caveat and the hole-punching caveat.
- New cargo feature `unstable-relay-only` on `mcpmesh-node`, default off.
- No control-API change; `API_MINOR` unchanged.
- Workspace → **0.20.0** (new config surface → MINOR).

## Testing (TDD, RED first)

1. **Unit — the selector picks the relay path** when both a relay and an IP path are candidates.
   Fails if it returns `none()` or picks the IP path. This is the property; everything else is
   plumbing.
2. **Unit — with no relay candidate it selects nothing** (`PathSelection::none()`), leaving iroh's
   current selection rather than inventing one.
3. **Unit — `relay_only = true` parses on a build WITHOUT the feature** and does not error. Guards
   config portability.
4. **Unit — the ignored-knob path warns.** Assert the warning is emitted when the feature is off and
   the flag is set; a silent ignore is the failure mode this exists to prevent.
5. **Integration (feature-gated) — two hermetic nodes with a relay reach each other, and
   `PeerPath` reports `Relay`.** The end-to-end proof that traffic actually took the relay, using
   the observable 0.19.1 added.
6. **Regression — the default build is unchanged.** With the feature off and `relay_only` unset,
   `build_endpoint` produces the same configuration as before.

## Explicitly NOT here

Preventing hole-punching outright (needs iroh's internal `RelayOnly`, not reachable through the
public selector API). A CLI flag — the knob is for embedders and test harnesses, and `mcpmesh serve`
reading a config file already reaches it.
