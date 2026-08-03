# Per-service request rate limits (#63) — resolving the parked design

**Status:** accepted · **Target:** 0.32.0 (MINOR) · **`api_minor`:** 39 → 40

## This issue was parked, and why it is not blocked any more

`feat/per-service-rate-limit` carries a WIP marked *"BLOCKED on a maintainer decision, do not
merge"*. Its adversarial review found six problems, and the first is the real one:

> `daemon.rs` documents **SECURITY invariant 1**: the limiter is ONE `Arc` so a peer's rate spans
> every mount. Per-service buckets necessarily break it.

That is true and unavoidable — **the invariant is the bug the issue reports.** A shared bucket is
precisely what lets a noisy service starve a quiet one, which is what #63 is about. So the invariant
has to change. The decision that was actually blocking is *how far*, and this is the answer:

**A per-service value may only LOWER the rate, never raise it.** `[limits].rate_limit_per_min` stays
a hard ceiling that no config entry and no control call can exceed. The invariant is restated
honestly rather than deleted:

- **Before:** a peer's aggregate rate across all mounts ≤ `rate_limit_per_min`.
- **After:** a peer's rate *per service* ≤ `rate_limit_per_min`, and per-service overrides can only
  reduce it. Aggregate is bounded by (services that peer is granted) × (their limits) — both
  operator-chosen, neither peer-influenced.

That is a real weakening, stated in the code and the docs. It buys the isolation the issue asks for,
and it is the minimum weakening that does: consulting the old global bucket *as well* would restore
the ceiling but re-introduce starvation, which is the whole complaint.

Only-lower also deletes the second finding outright: `RegisterServiceParams.rate_limit_per_min` was
attacker-supplied on the control socket with no clamp, so one call uncapped a service. Clamped to
the global, an unclamped request can no longer raise anything.

## The remaining four findings, each with its fix

3. **Toggling a service's rate minted a fresh limiter, resetting buckets** — a cheaper version of
   the reset hole the design set out to close. `for_service` now returns the EXISTING limiter when
   the effective rate is unchanged, and only replaces it when the rate actually moves. A reload
   (grant, revoke, register, roster install) therefore preserves every bucket.
4. **`write_service_to_config` rebuilt the entry table and dropped the new field**, so a
   re-registration erased a persisted rate — and every shipped client sends `None`, making that the
   default path. The surgical writer now preserves it.
5. **The 256-service cap handed an overridden service the GLOBAL (higher) limiter.** With
   only-lower that is an inflation, so it must not fall back. The map LRU-evicts instead, like the
   endpoint map already does. Eviction resets that service's buckets — reachable only by
   registering more than `MAX_TRACKED_SERVICES` distinct names, which is a **local, owner-only**
   control-socket operation (the socket is 0600). A caller who can do that already owns the node.
   Stated rather than left implicit.
6. **`MeshLimiters::unlimited()` stopped being unlimited** because `build_services` enforced
   120/min. The global rate is now `Option<u32>` with `None` meaning unlimited, and `for_service`
   propagates that: an unlimited bundle yields unlimited per-service limiters whatever the config
   says.

## Design

`MeshLimiters` gains a service-keyed map; `session_backend_spawn`/`session_backend_socket` already
receive both the service `name` and `limiters`, so the seam is one call:

```rust
limiter: limiters.for_service(name, cfg_rate_for(name)),
```

Each entry is still a `RateLimiter` keyed by endpoint internally, so the effective bucket is
**(service, endpoint)**.

**The map lives on `MeshLimiters`, not in `build_services`.** `MeshLimiters` is built once and
survives hot-reloads; `build_services` runs on *every* reload. Creating limiters there would reset
every peer's bucket on each reload, so a local caller could spam grants to clear its own rate limit.

## Surface

- `ServiceCfg.rate_limit_per_min: Option<u32>` — config, additive.
- `RegisterServiceParams.rate_limit_per_min: Option<u32>` — control, additive, **clamped**.
  Included deliberately: #55 was filed because a per-service feature (the allow list) silently did
  nothing for ephemeral registrations, and repeating that shape would earn the same report.

`0` is rejected rather than meaning "block everything silently" — the same call `max_uses` made.

## Versioning

**MINOR → 0.32.0.** Behaviour change (buckets are now per-service) plus a new `pub` field on
`ServiceCfg`, which breaks exhaustive construction. **`api_minor` 39 → 40**: a new request field,
and the meaning of `-32053` changes — it is now per-service, so a consumer backing off globally on
one is now backing off further than it needs to.

## Testing

1. Two services, one peer: exhausting service A's bucket leaves service B admitting. This is the
   issue.
2. A per-service override **lowers** the rate, and one above the global is **clamped**, not honoured
   — asserted through the effective limiter, not the parsed config.
3. A reload with an unchanged rate **preserves** bucket state (the reset hole).
4. A reload that CHANGES the rate applies the new one.
5. `RegisterServiceParams.rate_limit_per_min` is clamped identically to the config path.
6. Re-registering a service **preserves** a persisted `rate_limit_per_min`.
7. `MeshLimiters::unlimited()` stays unlimited per-service.
8. `0` is refused.

Mutation, eleven run and eleven caught: dropping the clamp fails 2 and 5; re-creating the limiter on
every reload fails 3; the config-writer dropping the field fails 6; `unlimited()` carrying a real
rate fails 7; the map falling back to the global past the cap fails the bounded-ness test.

### The gate round: three more escaped, and one of them was the whole feature

**`tracked_rpm` was not the call-site assertion it claimed to be.** It reads the limiter *map*, so
it proves `for_service` was CALLED with the right arguments — and nothing about the returned `Arc`
being installed. `{ let _ = limiters.for_service(name, rate); limiters.requests.clone() }` passed
the entire workspace with every backend back on one shared bucket, i.e. with the bug fully restored.
A side-effect assertion is not a call-site assertion. The backend constructors now return the
concrete type so a test can `Arc::ptr_eq` the limiter the backend actually holds.

**The PERSISTENT register path dropped the rate**, and `ephemeral` defaults to `false`, so that is
the default path. The new tests used `ephemeral: true` exclusively and the config-writer test called
the writer directly, so nothing crossed the handler. One step over from the #55 shape again.

**`rate_limit_per_min = 0` silently became 1/min.** `RateLimiter::per_minute` floors at 1, so the
most restrictive setting possible — while `docs/config.md` claimed `0` was rejected AND while
`blob_bytes_per_min = 0` in the same file means UNLIMITED. Now a startup error that corrects the
reading. The eviction test also only asserted `len() <= cap`, so wiping the whole map passed; it now
pins that the map sits AT the cap.

Also corrected: three doc sites still asserting the old invariant verbatim; a rustdoc claiming
`effective_rpm` is "reported on the reachability pong", which is a surface that does not exist
(**#63's second ask is NOT implemented** — a consumer still learns the limit only by receiving
`-32053`); the 256× aggregate memory bound; that a rate change does not reach an already-open
session; and that map entries are never removed on unregister, so the cap counts names *ever seen*.

**Two escaped on the first pass before that, both the same trap:**

- **Sharing one limiter across services.** The starvation test called `for_service` directly, so
  reverting `build_services` to the shared `requests` limiter — the entire bug — passed it.
  `MeshLimiters::tracked_rpm` now lets a test assert that `build_services` actually routed each
  backend through it.
- **The ephemeral path ignoring its rate.** The register test asserted `effective_rpm`, which is
  arithmetic, not wiring — so dropping `eph.rate_limit_per_min` at the call site passed. That is
  precisely the #55 shape this design set out not to repeat, and it took a call-site assertion to
  catch. It now asserts through the real bucket, with a below-ceiling rate so a dropped value is
  distinguishable from a clamped one.
