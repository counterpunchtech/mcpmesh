# #229 Endpoint hooks — outbound revocation veto + outbound sever — Implementation Plan

> **For agentic workers:** executed inline with superpowers:test-driven-development. Steps use checkbox syntax.

**Goal:** no connection of this node — gossip learned-peer dials, `connect_protocol`, `open_session`, probes, blobs — reaches or survives on a device `dial_refused` refuses.

**Architecture:** one `iroh::endpoint::EndpointHooks` impl (`MeshHooks`) installed in `build_endpoint`. `before_connect` vetoes refused ids on every ALPN except `ALPN_PAIR`; `after_handshake` registers a `WeakConnectionHandle` per remote id (both directions, non-pair) and re-checks outbound dials. Every revoke path runs one close pass over that registry. Based on #223 (`dial::refused_by`).

**Tech:** iroh 1.2.0 `endpoint/hooks.rs`, iroh-gossip 0.101 `net.rs` Dialer.

---

## Decisions (researched)

- **Hooks are async** (`hooks.rs:81-108` return `impl Future`). The `refused_by` redb reads run on the blocking pool (`util::blocking`) inside the hook. No snapshot cache.
- **Gossip actor stall (iroh-gossip#155):** gossip dials run in the Dialer's `JoinSet` (`net.rs:1016-1030`), not on the actor loop, so a hook await cannot stall the actor. Inbound `after_handshake` runs in the accept loop's per-connection task (`accept.rs`).
- **Cell = `Arc<OnceLock<DialGate>>`, `DialGate { store: Arc<PeerStore>, roster: Arc<RosterGate> }`.** Neither holds the `Endpoint` (`hooks.rs:60-64`). The cell is set in `boot_node` right after store + roster gate exist (step 3), BEFORE `compose_roster_transport` subscribes gossip with its bootstrap set — the first gated dial at boot. Between bind and that point nothing dials, so fail-closed costs startup nothing. Unset cell ⇒ `Reject` for every non-pair ALPN.
- **Gated ALPNs: all except `ALPN_PAIR`** (deny-by-default: gossip, roster blob, `ALPN_MCP`, `ALPN_PING`, app blob, and every embedder app protocol — these are peer connections to the same device). Pairing stays exempt; the pairing dials keep their own `PeerStore::is_refused` check.
- **Registry `PeerConns`:** `Mutex<HashMap<[u8;32], HashMap<u64, WeakConnectionHandle>>>`; one watcher task per registered connection awaits `weak.closed()` and removes its entry (bounded by live connections; never holds a strong `Connection`).
- **TOCTOU:** outbound `after_handshake` INSERTS first, then re-checks `refused_by`, removing + rejecting (`CLOSE_UNAUTHORIZED`, `b"revoked"`) on refusal. A revoke write before the recheck ⇒ rejected; after ⇒ its close pass sees the entry.
- **Close pass** `close_refused(conns, store, roster)`: snapshot ids, compute refused set on the blocking pool, close every handle of those ids. Wired into `sever_principals` (covers `peer_revoke`, `device_revoke`, `device_revocation_import`, `service_allow_revoke`, `revoke_service_access`) and `install_roster_view_and_sever` (spawned — sync fn; covers manual install, gossip and URL convergence, org revoke). Unpair / roster DROP (not revoked) do not refuse dials, so they close nothing outbound — consistent with the predicate.
- **#215:** its MCP connection-cache `close_to` is superseded by this registry; not imported.
- **Inbound recheck:** not in the hook — the gate already refuses inbound with its own close codes, which existing tests pin.

## Tasks

- [ ] **1. Fail-closed hook + install** — `node/src/daemon/hooks.rs` (new), `boot.rs::build_endpoint` gains `hooks: Option<MeshHooks>`. Test (unit): unset cell ⇒ `connect(.., ALPN_MCP)` is `LocallyRejected`; `ALPN_PAIR` dial connects. Mutation: `before_connect` → `Accept`.
- [ ] **2. Refusal via cell** — set cell in `boot_node`; unit test with a revoked id refused, unrevoked accepted.
- [ ] **3. Gossip learned-peer test** — A from `build_endpoint(roster, Some(hooks))` + gossip; B, Y, X raw gossip endpoints; X revoked in A's store. Y (control) and X join via B (ForwardJoin) and via `join_peers`; assert Y dialed/neighbour, X zero accepts from A per ALPN and never in `neighbors()`. Mutation: remove `.hooks(..)` in `build_endpoint`.
- [ ] **4. Registry + prune** — `after_handshake` registers; test N open/close ⇒ registry empty (bounded wait).
- [ ] **5. Close on revoke** — `MeshState::peer_conns` (OnceLock, set at boot); close pass in `sever_principals` + `install_roster_view_and_sever`. Tests (embedded, `cli/tests/embedded_loopback.rs`): held `connect_protocol` conn closes after `peer_revoke`; `open_session` pipe EOFs after `peer_revoke`; roster install revoking closes too. Mutation: drop the close-pass call.
- [ ] **6. Docs + API_MINOR 64 → 65** (new outbound refusals on embedder app protocols; open outbound connections now severed), history entry, `dial_refused` doc "Not covered" list updated.
- [ ] **7. Verify** fmt, clippy, full suite; adversarial pass over `git diff cf78376..HEAD`.
