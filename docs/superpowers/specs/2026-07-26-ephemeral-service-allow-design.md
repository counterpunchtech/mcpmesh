# Ephemeral services get a live allow (#55, #69)

**Status:** accepted · **Issues:** #55 (grant), #69 (revoke) · **Target:** 0.12.0 (behavior change → MINOR)

## Problem

`service_allow_grant` and `service_allow_revoke` mutate `config.toml` and nothing else. An
ephemeral registration (#36) is in-memory only (`MeshState.ephemeral_services`), so for those
services **both verbs return `{}` (success) and change nothing**:

- **Grant (#55).** `append_allow_to_config` finds no `[services.<name>]` entry, logs a
  `tracing::warn!`, returns `Ok(false)`. The caller sees success and nobody is admitted. An
  embedder building a member list on top shows people added who cannot connect.
- **Revoke (#69).** `remove_principal_from_service` likewise strips nothing, and
  `reload_services_from_disk` re-overlays the ephemeral registration's untouched `allow` on the
  very next swap. Since #54 this is at least an honest no-op (the sever is gated on `changed`, so
  there is no false "revocation took effect" signal) — but it still cannot revoke.

Ephemeral registration and per-peer grants are each individually useful, and combining them is the
natural way to express a short-lived, selectively-shared service — a per-room or per-document
service whose lifetime is a control connection. That combination is exactly what silently fails.

## Approach

Take the *second* shape #55 offers (an in-memory allow the verbs mutate) rather than the minimum
(error on unknown service). The minimum leaves the useful case unbuildable; this makes it work, and
still yields a clean error for a genuinely unknown service.

### 1. The ephemeral allow becomes mutable

Two helpers on `MeshState`, mirroring the config writers' idempotent-and-report-`changed` contract:

```rust
pub(crate) fn grant_ephemeral(&self, service: &str, principal: &str) -> Option<bool>
pub(crate) fn revoke_ephemeral(&self, service: &str, principal: &str) -> Option<bool>
```

`None` = no ephemeral registration by that name (so the caller falls through to config).
`Some(changed)` = the registration exists; `changed` reports whether the allow actually moved.
Both take the `ephemeral_services` std `Mutex` for the mutation only — never across an await —
under the caller's `reload_lock`, exactly like every other registry change.

### 2. Routing: ephemeral first, then config, then error

Both single-service verbs resolve the target in this order:

1. an ephemeral registration by that name → mutate its in-memory allow;
2. else a `[services.<name>]` config entry → the existing surgical RMW writer;
3. else → **error** `NoSuchService`.

A name cannot be both: `register_service` writes config, `register_service {ephemeral: true}` writes
the map, and the overlay means an ephemeral name shadows a config name of the same name anyway —
so "ephemeral first" matches what the running registry actually serves.

Either path that reports `changed` triggers the same `reload_services_from_disk` swap, so the
ephemeral mutation reaches already-open connections through the #54 live registry. Revoke then
feeds the #54 sever on the same `changed` gate, which is what makes ephemeral revocation immediate
rather than merely eventual.

### 3. The pairing grant stays lenient

`grant_service_access(mesh, principal, display, services)` is the **pairing** path and takes a
LIST. It keeps today's behavior for an unknown name — warn and skip, never fail — because a stale
service name in an invite must not abort a pairing ceremony. It gains the ephemeral routing, so
pairing into an ephemeral service now actually grants.

Only the single-service `service_allow_grant` / `service_allow_revoke` verbs are strict. That split
is deliberate: the verb is a direct operator/embedder request about one named service, where a
silent miss is the bug being fixed; the ceremony is a bulk best-effort.

### 4. Surface

- New control-API error code **`-32040` `ERR_NO_SUCH_SERVICE`** in `local-api/src/protocol.rs`,
  returned when neither verb can find the named service. Plumbed through `respond`'s existing
  `downcast_ref` idiom — the same mechanism `InvalidParams` → `-32602` already uses — via a
  `NoSuchService` error type. Nothing else changes shape.
- `API_MINOR` 10 → 11, `API_VERSION` "1.10" → "1.11".
- `docs/local-protocol.md`: drop the "Ephemeral services are excluded" caveat added by #54,
  document the new code and the strict/lenient split. `docs/config.md` unchanged (this is not a
  config surface).
- Workspace version → **0.12.0** (behavior change → MINOR: a previously-silent success is now an
  error, and ephemeral allows now really change).

## Testing (TDD, RED first)

Each test must fail against the current code for the right reason.

1. **Unit** — `grant_ephemeral` / `revoke_ephemeral`: `None` for an unknown name; `Some(true)` on a
   real change; `Some(false)` when idempotent (re-grant / re-revoke).
2. **Integration, grant (#55)** — register an ephemeral service, `service_allow_grant` a peer, and
   the peer's session is **served**. Fails today (allow untouched → refused).
3. **Integration, revoke (#69)** — the same peer, then `service_allow_revoke`, and its live
   connection is **severed** and a new session refused. Fails today (allow re-overlaid → still
   served).
4. **Integration, live on an open connection** — the grant in (2) is visible to a NEW session on an
   ALREADY-OPEN connection, tying the ephemeral path to the #54 live registry.
5. **Error** — both verbs against a name that is neither config nor ephemeral → `NoSuchService`
   (`-32040`), not silent success.
6. **Regression** — the pairing `grant_service_access` with one unknown service in its list still
   succeeds and still grants the known ones (leniency preserved).
7. **Regression** — an ephemeral registration still survives an unrelated grant/revoke swap (the
   overlay path the #54 review flagged as untested).

## Out of scope

Persisting ephemeral allows across a restart — they are in-memory *by design* (#36); an embedder
re-registers per boot. Unregistering an ephemeral service is already `unregister_service`.
