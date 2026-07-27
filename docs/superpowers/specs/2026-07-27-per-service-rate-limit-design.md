# Per-service request rate limits (#63)

**Status:** accepted · **Issue:** #63 · **Target:** 0.14.0 (behavior change → MINOR)

## Problem

The proxied-request bucket is keyed on the authenticated endpoint alone. Every service a peer can
reach draws from **one shared bucket**, and there is no per-service override.

That becomes a problem the moment a node serves more than one service — which #36/#50/#51 actively
encourage:

- **A noisy service starves a quiet one.** An agent hammering a browser or filesystem service
  exhausts the shared bucket, and the embedder's own low-rate control traffic to a *different*
  service on the same node starts failing.
- **Bulk competes with interactive.** A backfill against one service throttles interactive calls
  against another.

The embedder cannot schedule around it either: bucket state is not observable, so it is pacing blind
against a limit it cannot query.

## Approach

Two changes, both needed — the override alone would not fix starvation, and isolation alone would
not let an operator tune a known-noisy service.

### 1. One bucket set per service

`MeshLimiters` gains a service-keyed map of `RateLimiter`s, handed to the backend at build time in
place of the single shared `requests` limiter. Each `RateLimiter` remains keyed by endpoint
internally, so the effective bucket is **(service, endpoint)** and one service can no longer starve
another.

**The map lives on `MeshLimiters`, not in `build_services`.** `MeshLimiters` is built once and
survives hot-reloads; `build_services` runs on *every* reload (grant, revoke, register, roster
install). Creating the limiters there would reset every peer's bucket on each reload — a local
caller could spam grants to clear its own rate limit. Persisting them across reloads closes that.

Entries are re-created only when the configured rate for that name changes, so a reload with an
unchanged rate preserves bucket state.

**Bounded, like every other map here.** Capped at `MAX_TRACKED_SERVICES`; beyond the cap a service
falls back to the shared global limiter rather than growing the map without limit. Ephemeral
registrations can churn names, so this is not hypothetical.

### 2. `rate_limit_per_min` per service

- Config: `[services.<name>].rate_limit_per_min`, `Option<u32>`, falling back to
  `[limits].rate_limit_per_min`.
- Control API: the same optional field on `RegisterServiceParams`, so an **ephemeral** registration
  (#36) can set it too.

Including the ephemeral path is deliberate. #55 was filed precisely because a per-service feature
(the allow list) skipped ephemeral registrations and silently did nothing for them; repeating that
shape here would earn the same bug report. `EphemeralService` carries the value alongside its allow.

## Surface + versioning

- `ServiceCfg.rate_limit_per_min: Option<u32>` (config, additive).
- `RegisterServiceParams.rate_limit_per_min: Option<u32>` (`#[serde(default)]`, additive).
- `API_MINOR` 13 → 14, `API_VERSION` "1.13" → "1.14".
- `docs/config.md` + `docs/local-protocol.md`.
- Workspace version → **0.14.0**. This is a **behavior change**, not merely additive: a peer that
  could previously make `N` requests per minute across all services can now make `N` per service.
  Operators relying on the aggregate cap must set explicit per-service values. Per the pre-1.0
  policy that is a MINOR.

## Explicitly NOT in scope

**Observable remaining budget.** The issue floats it as "optionally"; it is a new surface with its
own design questions (per-service? per-peer? pushed or polled? does exposing it leak another peer's
activity?) and does not belong bolted onto this change. Worth its own issue.

**Silent notification loss.** The issue raises, separately, that a rate-limited *notification* may
produce no signal at all, unlike a request's `-32053`. That is a real and distinct concern about a
different code path. It will be **investigated and filed on its own** rather than folded in — if it
is true, it deserves a titled issue an embedder can find, not a paragraph inside a rate-limit PR.

## Testing (TDD, RED first)

1. **Unit — isolation.** Exhausting service A's bucket for an endpoint leaves service B's bucket for
   that same endpoint intact. Fails today (one shared bucket).
2. **Unit — override.** A service configured with a lower rate refuses at its own limit while
   another service on the same node still admits at the global rate.
3. **Unit — reload stability.** Requesting the limiter for an unchanged `(name, rate)` twice returns
   the SAME limiter (bucket state survives a hot-reload); a changed rate returns a fresh one.
4. **Unit — cap.** Past `MAX_TRACKED_SERVICES`, a further service gets the shared global limiter
   rather than growing the map.
5. **Integration.** A peer rate-limited on one service still gets served on another, end to end.
6. **Regression.** With no per-service value set anywhere, behavior matches today's global limit.
