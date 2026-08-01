# `Default` on the status-read surface (#148)

**Status:** accepted · **Target:** 0.25.2 (PATCH) · **`api_minor`:** unchanged (31)

## Problem

`StatusResult` and friends derive no `Default` and are not `#[non_exhaustive]`. Every field we add
is additive on the wire — but it is a **breaking change for any downstream that constructs one in a
test**.

Adopting `=0.23.2` → `=0.23.6` broke five literal constructions across two bolo modules, all
fixtures for a pure mapping function, none of which cared about the new fields. The fix is always
"add `field: None`". It is the single most reliable source of compile breakage when they track our
releases, and this session alone shipped three more additive bumps (0.24.0, 0.25.0, 0.25.1).

## Design

Derive `Default` across the status-read surface, so a downstream fixture is
`StatusResult { peers, ..Default::default() }` and additive growth costs nobody anything:

`StatusResult`, `ServiceInfo`, `PeerInfo`, `PeerReachability`, `SelfNetwork`, `RelayInfo`,
`StorageInfo`, `RosterStatus`, `PresencePeer`, `RecentPairing`.

`PeerPath` already has `#[default] Unknown`. Nothing becomes `#[non_exhaustive]` — the issue
explicitly does not want that, and exhaustive construction stays available.

Note `StatusResult` needs only its own derive: its element types sit inside `Vec`/`Option`, which
default to empty/`None` regardless. The element derives are for fixtures that build a *row*.

### `BackendKind` — the one real decision

`ServiceInfo::default()` needs one, and `BackendKind` is `Run | Socket` with no natural default.
Neither value is "no backend"; both are real claims.

Take `#[default] Run` and **document it as a construction convenience, not a semantic claim**. It is
defensible (a `run` backend is the common config shape) and, unlike the trap in #150, it cannot
mislead a consumer reading live data: the daemon sets `backend` explicitly on every `ServiceInfo` it
builds, so a defaulted value only ever exists in a fixture its author wrote.

The rustdoc says so plainly, because a reader who finds `Default` on a two-valued enum will
otherwise assume it means something.

## Versioning

**PATCH → 0.25.2.** Adding a trait impl breaks no existing caller.

**`api_minor` does NOT move, and that is deliberate.** It is the *protocol*-compatibility version:
it increments on an added field, a new method, or a strictness change. A Rust trait impl adds none
of those and is invisible on the wire — a non-Rust consumer sees zero difference. Bumping it would
tell every consumer to re-read the surface for a change that does not exist there.

## Testing

1. **`Default::default()` produces an empty, honest status** — no phantom peers/services, `None`
   for the optional blocks, empty strings.
2. **A default round-trips through JSON** and comes back equal, so the elided-vs-null discipline
   (`skip_serializing_if`) holds for a defaulted value.
3. **The struct-update fixture pattern works** — `StatusResult { peers, ..Default::default() }`,
   which is the ergonomic the issue asks for.
4. **`PeerReachability::default()` is not reachable and has no path claim** — `reachable: false`,
   `path: Unknown`. A default that said "reachable" or "direct" would be a fixture asserting a
   privacy/liveness guarantee nobody made.

Mutation: changing `PeerPath`'s `#[default]` to `Direct` must fail 4.

## Out of scope

No field, no verb, no behavior changes. `#[non_exhaustive]` is explicitly not added.
