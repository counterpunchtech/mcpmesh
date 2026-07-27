# Live allow-revocation: sever on revoke + live `Services` evaluation (#54)

**Status:** accepted · **Issue:** #54 · **Target:** 0.11.0 (behavior change → MINOR)

## Problem

In pairing mode, `service_allow_revoke` and `peer_remove` return success but have **no effect on
an already-connected peer for the whole lifetime of that QUIC connection**. Two independent holes:

- **H1 — stale snapshot.** `spawn_accept_loop` hands each accepted connection an `Arc<Services>`
  captured when the *loop* was spawned (`node/src/daemon/accept.rs:84`). `run_mesh_connection`
  then loops `accept_bi()` forever, resolving every **new** session against that captured snapshot
  (`net/src/endpoint.rs:237`). `reload_accept_loop` aborts the loop and respawns it with rebuilt
  `Services`, but the per-connection tasks are independent `tokio::spawn`s — aborting the loop
  never touches them. A revoked peer keeps opening new sessions.
- **H2 — no sever.** `ConnRegistry::sever_matching` is called only from `roster_install.rs`.
  Neither revoke handler calls it, and the predicate (`gate.rs:236` `should_sever_now`) is
  structurally `false` for a pairing-only peer (`roster_user == None`, not roster-revoked), so
  in-flight sessions run on regardless.

For an access-control surface, a success response meaning "effective at an unbounded future time"
is the dangerous default. The window grows with connection lifetime — worst for embedders holding
warm sessions, which is what our own docs encourage.

## Approach

Fix **both** halves. H1 alone closes the new-session hole; H2 closes the in-flight one. Neither
subsumes the other.

### Part A — live `Services` handle (closes H1)

Replace the per-connection snapshot with a shared, swappable handle read at session-admit time.

- New `net::service::LiveServices` — a `std::sync::RwLock<Arc<Services>>` with `get()` / `store()`.
  Chosen over `arc-swap` (present only as a transitive dep) and over `tokio::sync::watch` to match
  the surrounding idiom (`MeshState::self_nickname`, `app_metadata`). The lock is never held across
  an await: `get()` clones the `Arc` and drops the guard.
- `MeshState` gains `services: Arc<LiveServices>`. `spawn_accept_loop(mesh)` no longer takes a
  separate `services` argument — it reads `mesh.services`.
- `run_mesh_connection` takes `Arc<LiveServices>` and calls `get()` **per accepted bi-stream**, so
  each new session resolves against the current allow.
- `reload_accept_loop` (abort + respawn) is **replaced** by `swap_services(mesh, services)`, a
  plain `store()`. This also removes the abort/respawn serving blip and the window in which the
  loop is down. Pre-1.0: no compat shim, callers migrate.

In-flight sessions deliberately keep the `Arc<Services>` they started with — a session's service
resolution is fixed at admit. Cutting those is Part B's job.

### Part B — sever on revoke (closes H2)

Reuse `ConnRegistry::sever_matching`, whose predicate is already
`Fn(&EndpointId, Option<&str>) -> bool`; no new registry API. The revoke paths resolve their target
to an endpoint set and pass `|eid, _| targets.contains(eid)`.

Principal → endpoint resolution (`node/src/daemon/sever.rs`, new):

| Principal form | Resolution |
|---|---|
| `eid:<b32>` | decode directly to one `EndpointId` |
| `b64u:<…>` / bare | every `PeerStore` entry whose `user_id` matches, plus the roster view's devices for that user |

Call sites:
- `service_allow_revoke(service, principal)` — sever the principal's endpoints.
- `revoke_service_access(nickname)` (the authorization half of `peer_remove`) — it already resolves
  the target devices; sever those endpoints.

**Ordering: swap-before-sever**, mirroring `roster_install.rs:60-67`. Swap `Services` first so no
new session admits the peer, then sever. A connection check-registering across the swap is caught
by the registry's lock-serialized recheck.

**Granularity — connection, not session (accepted trade-off).** `sever_matching` closes the whole
QUIC connection, so revoking one service also drops that peer's in-flight sessions to services it
*still* holds. Per-session cancellation would need the registry to track sessions by service —
materially larger, and it still would not protect the revoked service's in-flight stream, which is
the actual hazard. The peer redials and is re-evaluated live against the new allow. Revocation is
an explicit operator action; disruption is the expected cost. Documented in `local-protocol.md`.

Only `should_sever_now` (the roster/register-time recheck) stays untouched — widening it would
over-reach into roster semantics. Pairing-mode severing is driven by the explicit target set.

## Surface + versioning

- `API_MINOR` 9 → 10, `API_VERSION` "1.9" → "1.10", same change. The verbs' shapes are unchanged,
  but their observable contract is: at `api_minor >= 10` revocation is immediate and severs live
  connections. Consumers gate on it — bolo can drop its "takes effect on next connection" UI copy.
- `docs/local-protocol.md` + `docs/config.md` updated in the same change.
- Workspace version → **0.11.0** (behavior change → MINOR per the pre-1.0 policy).

## Testing (TDD, RED first)

1. **Unit** — `LiveServices` get/store returns the stored registry; store is visible to a prior
   `get()`-holder only on its next `get()`.
2. **Integration, H1** — peer connects, completes a session, `service_allow_revoke`, then opens a
   **new** bi-stream on the **same** connection → refused. Fails before Part A.
3. **Integration, H2** — peer connected with a live session; revoke → connection closed. Fails
   before Part B.
4. **Regression** — revoking principal X does **not** sever an unrelated connected principal Y.
5. **Regression** — `peer_remove` severs the removed peer's endpoints.
6. **Regression** — a roster install still severs exactly what `roster_sever.rs` asserts today
   (Part A must not disturb the roster path), and an ephemeral registration still survives a
   swap (`reload_services_from_disk`'s ephemeral overlay).

## Out of scope

Per-session (rather than per-connection) revocation granularity. The blob/gossip ALPN arms — they
carry their own gates and are untouched. #55 (ephemeral-service grant silently no-ops) is a
separate issue.
