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
| `eid:<hexlower>` | the stored/roster device whose rendered principal matches (rendered, not parsed — `EndpointId::principal()` is HEXLOWER) |
| `b64u:<…>` | every `PeerStore` entry whose `user_id` matches |
| bare (roster vocabulary) | every roster-view device whose `user_id` OR whose GROUP list matches |

An unrecognized principal resolves to the empty set and severs nothing — failing to "sever
nothing" is the safe direction, since over-severing cuts peers the operator never revoked.

Call sites:
- `service_allow_revoke(service, principal)` — sever the principal's endpoints, but **only when the
  strip actually changed the config**. A strip that removed nothing means this principal was not in
  that allow; severing anyway would show the operator a disconnect that looks like the revoke
  landed while access is unchanged (e.g. `allow = ["b64u:alice"]` and a caller revoking alice's
  `eid:` — she is still admitted via the user_id and is served again the moment she redials). A
  false "revocation took effect" signal is worse here than a missed sever.
- `revoke_service_access(nickname)` (the authorization half of `peer_remove`) — it already resolves
  the target devices; sever those endpoints, **unconditionally**. `remove_peer` deletes the
  `PeerEntry` immediately after, so the peer loses gate resolve entirely and cannot be re-admitted —
  there is no false-signal risk, and the unpair genuinely took effect.

**Ordering: swap-before-sever**, mirroring `roster_install.rs:60-67`. Swap `Services` first so no
new session admits the peer, then sever.

Note what does *not* protect this path: the registry's check-register recheck runs
`gate.should_sever_now`, which is structurally `false` for a pairing-only peer — that is H2's own
premise. So a connection registering across the swap is NOT caught by that recheck. It is safe for
a different reason: because the swap lands first, any connection that registers afterwards resolves
its sessions against the already-updated registry.

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
2. **Integration, Part A in ISOLATION** — peer connects; a service that admits nobody refuses its
   session; the peer is then GRANTED that service; a **new** bi-stream on the **same** connection is
   served, with the connection still up. Built on the grant path deliberately: a grant never severs,
   so this can only pass if the connection re-read the registry. Fails with Part A reverted alone.
   (The revoke-side "new session refused" test is a contract test, not a Part-A regression test —
   the sever also closes the connection, so it passes with either half present. Adversarial review
   caught that the original version of this plan had NO isolating coverage of Part A.)
3. **Integration, H2** — peer connected with a live session; revoke → connection closed. Fails
   before Part B.
4. **Regression** — revoking principal X does **not** sever an unrelated connected principal Y.
5. **Regression** — `peer_remove` severs the removed peer's endpoints.
6. **Regression** — a roster install still severs exactly what `roster_sever.rs` asserts today
   (Part A must not disturb the roster path), and an ephemeral registration still survives a
   swap (`reload_services_from_disk`'s ephemeral overlay).

## Out of scope

Per-session (rather than per-connection) revocation granularity.

Two consequences are accepted rather than fixed, and are documented in `local-protocol.md` instead:

- **The sever is not ALPN-scoped.** `ConnRegistry` tracks gossip and blob connections under the same
  endpoint id with no protocol discriminator, so a revoke closes those too. Availability only —
  each of those arms keeps its own gate — and the peer reconnects. Scoping it would mean threading
  an ALPN through the registry, which is a larger change than this fix warrants.
- **Ephemeral services cannot be revoked by this verb**, because their `allow` is in-memory and the
  strip edits `config.toml`. The `changed` gate means this is now an honest no-op (no sever, no
  false signal) rather than a silent contradiction. The mirror of #55; worth its own issue.
