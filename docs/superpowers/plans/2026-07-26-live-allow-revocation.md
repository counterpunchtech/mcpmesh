# Live allow-revocation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this
> plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `service_allow_revoke` / `peer_remove` take effect immediately on an
already-connected pairing-mode peer — both for new sessions and for in-flight ones (#54).

**Architecture:** Two independent halves. (A) `Services` moves from a per-connection `Arc` snapshot
to a shared `LiveServices` handle read per bi-stream, so a reload is visible to the next session on
an existing connection. (B) The revoke handlers resolve the target principal to its stored endpoint
ids and call `ConnRegistry::sever_matching`, closing live connections. Ordering is
swap-before-sever, mirroring `roster_install.rs`.

**Tech Stack:** Rust workspace (`net`, `node`, `local-api`), tokio, iroh/QUIC, `std::sync::RwLock`.

**Spec:** `docs/superpowers/specs/2026-07-26-live-allow-revocation-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `net/src/endpoint.rs` | new `LiveServices`; `run_mesh_connection` reads it per bi-stream; `serve` wraps |
| `node/src/daemon.rs` | `MeshState.services: Arc<LiveServices>` field + init |
| `node/src/daemon/accept.rs` | `spawn_accept_loop` stores into `mesh.services`; `reload_accept_loop` → `swap_services` |
| `node/src/daemon/handlers.rs` | `reload_services_from_disk` swaps; revoke handlers sever |
| `node/src/daemon/sever.rs` (new) | `endpoints_for_principal` — principal → stored endpoint ids |
| `cli/tests/allow_revoke_sever.rs` (new) | H1 + H2 + regression integration tests |
| `local-api/src/protocol.rs` | `API_VERSION` "1.10", `API_MINOR` 10 |
| `docs/local-protocol.md`, `docs/config.md` | document immediate revocation + sever granularity |
| `Cargo.toml` | version 0.11.0 + 5 `mcpmesh-*` pins |

---

## Task 1: `LiveServices` handle

**Files:**
- Modify: `net/src/endpoint.rs` (after the `Services` impl, ~line 132)

- [ ] **Step 1: Write the failing test**

Append to `net/src/endpoint.rs`'s `#[cfg(test)] mod tests` (create the module if absent):

```rust
#[test]
fn live_services_swap_is_visible_to_next_get() {
    use std::collections::HashMap;
    let live = LiveServices::new(Arc::new(Services::new(HashMap::new())));
    let before = live.get();
    assert!(before.get("kb").is_none());

    let mut map = HashMap::new();
    map.insert(
        "kb".to_string(),
        ServiceEntry { backend: Arc::new(NullBackend), allow: vec!["eid:beef".into()] },
    );
    live.store(Arc::new(Services::new(map)));

    // The previously-taken handle is unchanged (a session keeps its snapshot)...
    assert!(before.get("kb").is_none());
    // ...but the next read sees the swap.
    assert_eq!(live.get().get("kb").map(|e| e.allow.clone()), Some(vec!["eid:beef".to_string()]));
}
```

`NullBackend` is the existing test backend in this module; if it is absent, add:

```rust
struct NullBackend;
#[async_trait::async_trait]
impl SessionBackend for NullBackend {
    async fn run(
        &self,
        _identity: PeerIdentity,
        _initialize: serde_json::Value,
        _transport: Box<dyn crate::Framed>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
```
(Match the real `SessionBackend` signature at `net/src/endpoint.rs:95-101`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcpmesh-net live_services_swap`
Expected: FAIL — `cannot find type LiveServices in this scope`

- [ ] **Step 3: Implement `LiveServices`**

```rust
/// A hot-swappable handle to the live [`Services`] registry.
///
/// The accept path reads this ONCE PER accepted bi-stream, so a config reload (a grant, a
/// revoke, a roster install) is visible to the very next session on an ALREADY-OPEN connection.
/// The previous design handed each connection an `Arc<Services>` captured when the accept loop was
/// spawned, which meant a revoked peer kept opening admitted sessions for the whole lifetime of
/// its connection (#54).
///
/// In-flight sessions deliberately keep the snapshot they started with — a session's service
/// resolution is fixed at admit; cutting those is the revoke path's `sever_matching` job.
///
/// `std::sync::RwLock` (not `arc-swap`) matches the surrounding idiom and is never held across an
/// await: [`get`](Self::get) clones the `Arc` and drops the guard.
pub struct LiveServices(std::sync::RwLock<Arc<Services>>);

impl LiveServices {
    /// Wrap an initial registry.
    pub fn new(services: Arc<Services>) -> Self {
        Self(std::sync::RwLock::new(services))
    }

    /// The registry as of now. Cheap: one `Arc` clone under a read lock.
    pub fn get(&self) -> Arc<Services> {
        self.0.read().expect("live services lock not poisoned").clone()
    }

    /// Hot-swap the registry. Visible to every subsequent [`get`](Self::get).
    pub fn store(&self, services: Arc<Services>) {
        *self.0.write().expect("live services lock not poisoned") = services;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mcpmesh-net live_services_swap`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add net/src/endpoint.rs
git commit -m "feat(net): LiveServices — hot-swappable service registry handle (#54)"
```

---

## Task 2: `run_mesh_connection` reads the live handle

**Files:**
- Modify: `net/src/endpoint.rs:199-247` (`run_mesh_connection`, `serve`)

- [ ] **Step 1: Change the signature and the read site**

In `run_mesh_connection`, change the parameter:

```rust
pub async fn run_mesh_connection(
    conn: iroh::endpoint::Connection,
    gate: Arc<dyn TrustGate>,
    services: Arc<LiveServices>,
    registry: Arc<crate::registry::ConnRegistry>,
) {
```

and the accept_bi loop body (was `let services = services.clone();`):

```rust
    while let Ok((send, recv)) = conn.accept_bi().await {
        // Read the LIVE registry per session (#54): a revoke that lands between two sessions on
        // this same connection is honored by the second one. In-flight sessions keep the snapshot
        // they were admitted under.
        let services = services.get();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = run_session(recv, send, &identity, &services).await {
                tracing::warn!(peer = %identity.name, %e, "session ended with error");
            }
        });
    }
```

In `serve`, replace `let services = Arc::new(services);` with:

```rust
    let services = Arc::new(LiveServices::new(Arc::new(services)));
```

- [ ] **Step 2: Build**

Run: `cargo build -p mcpmesh-net`
Expected: PASS (node still fails to build — fixed in Task 3)

- [ ] **Step 3: Commit**

```bash
git add net/src/endpoint.rs
git commit -m "feat(net): resolve each session against the live registry (#54)"
```

---

## Task 3: `MeshState` holds the live handle; reload swaps instead of respawning

**Files:**
- Modify: `node/src/daemon.rs` (`MeshState` struct + `new`)
- Modify: `node/src/daemon/accept.rs:81` (`spawn_accept_loop`), `:269` (`reload_accept_loop`)
- Modify: `node/src/daemon/handlers.rs:136` (`reload_services_from_disk`)

- [ ] **Step 1: Add the field**

In `node/src/daemon.rs`, next to `conn_registry`:

```rust
    /// The LIVE service registry every accepted connection resolves sessions against
    /// ([`LiveServices`](mcpmesh_net::LiveServices)). Installed by [`spawn_accept_loop`] and
    /// hot-swapped by [`swap_services`](crate::daemon::accept::swap_services) on every reload
    /// (grant, revoke, register, roster install) — so a reload reaches connections that are
    /// ALREADY open, which the old abort-and-respawn never did (#54).
    pub(crate) services: Arc<mcpmesh_net::LiveServices>,
```

In `MeshState::new`, initialize alongside `conn_registry`:

```rust
            services: Arc::new(mcpmesh_net::LiveServices::new(Arc::new(
                mcpmesh_net::Services::new(std::collections::HashMap::new()),
            ))),
```

- [ ] **Step 2: `spawn_accept_loop` installs, does not capture**

In `node/src/daemon/accept.rs`, keep the signature (12 test call sites depend on it) and install:

```rust
pub fn spawn_accept_loop(mesh: Arc<MeshState>, services: Arc<Services>) -> JoinHandle<()> {
    // INSTALL the registry as the live handle, then serve from that handle forever. The loop
    // captures `mesh` only: a reload swaps `mesh.services` in place, so connections this loop has
    // ALREADY accepted see the new registry on their next session (#54).
    mesh.services.store(services);
    tokio::spawn(async move {
        while let Some(incoming) = mesh.endpoint.accept().await {
            let mesh = mesh.clone();
            tokio::spawn(async move {
```

and in the `ALPN_MCP` arm:

```rust
                        run_mesh_connection(
                            conn,
                            mesh.gate.clone(),
                            mesh.services.clone(),
                            mesh.conn_registry.clone(),
                        )
```

Delete the now-unused `let (mesh, services) = (mesh.clone(), services.clone());` binding.

- [ ] **Step 3: Replace `reload_accept_loop` with `swap_services`**

```rust
/// Hot-swap the live service registry. Replaces the old abort-and-respawn of the accept loop:
/// the loop reads `mesh.services` per connection and `run_mesh_connection` reads it per session,
/// so a swap reaches connections that are already open (#54) — and there is no longer a window in
/// which the accept loop is down. The CALLER holds `mesh.reload_lock` for the whole
/// config→reload→swap section.
pub(crate) fn swap_services(mesh: &Arc<MeshState>, services: Services) {
    mesh.services.store(Arc::new(services));
}
```

- [ ] **Step 4: Update `reload_services_from_disk`**

In `node/src/daemon/handlers.rs:147`, replace the `reload_accept_loop(...).await;` call with:

```rust
    swap_services(
        mesh,
        crate::daemon::build_services_with_ephemeral(&cfg, &mesh.audit(), &mesh.limits(), &ephemeral),
    );
```

Fix the import (`reload_accept_loop` → `swap_services`) and any other call site the compiler flags.

- [ ] **Step 5: Build + full suite**

Run: `cargo build --workspace && cargo test --workspace --locked`
Expected: PASS — in particular `roster_sever`, `pairing_rendezvous`, `hero_flow_pairing`,
`roster_distribute` (they drive `spawn_accept_loop` unchanged).

- [ ] **Step 6: Commit**

```bash
git add node/src Cargo.lock
git commit -m "feat(node): swap the live registry on reload instead of respawning the accept loop (#54)"
```

---

## Task 4: H1 regression test — a new session on an open connection honors a revoke

**Files:**
- Create: `cli/tests/allow_revoke_sever.rs`

Model the harness on `cli/tests/roster_sever.rs:38-60` (`dual_alpn_endpoint`, `client_endpoint`)
and its `MeshState` construction; reuse `const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");`.

- [ ] **Step 1: Write the failing test**

```rust
//! #54: a revoke reaches a peer that is ALREADY connected — its next session on the SAME
//! connection is refused (live registry), and its live connection is severed (sever-on-revoke).

/// Alice is paired and allowed on `kb`. She connects, completes a session, THEN her grant is
/// revoked. A NEW bi-stream on the SAME connection must be refused — before #54 it was admitted
/// for the whole lifetime of the connection.
#[tokio::test]
async fn a_new_session_on_an_open_connection_is_refused_after_revoke() {
    let (mesh, cfg, _tmp) = paired_mesh_with_kb_allowing("eid:alice").await;
    let _accept = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));

    let conn = dial_mesh(&alice_endpoint, mesh.endpoint.node_addr()).await;
    assert!(open_kb_session(&conn).await.is_ok(), "granted peer admitted before revoke");

    service_allow_revoke(&state, "kb".into(), "eid:alice".into()).await.unwrap();

    // SAME connection, NEW bi-stream.
    let second = open_kb_session(&conn).await;
    assert!(second.is_err(), "revoked peer must not open a new session on its existing connection");
}
```

Fill `paired_mesh_with_kb_allowing`, `dial_mesh`, `open_kb_session` from the `roster_sever.rs`
patterns (write a real `initialize` frame with `_meta["mcpmesh/service"] = "kb"` and read the
response; an error/EOF is the refusal).

- [ ] **Step 2: Run test to verify it fails on the PRE-Task-3 code**

Run: `git stash && cargo test -p mcpmesh-cli --test allow_revoke_sever && git stash pop`
Expected: FAIL (second session admitted). If it passes on stashed code, the test is not
exercising the hole — fix the test before proceeding.

- [ ] **Step 3: Run against the implemented code**

Run: `cargo test -p mcpmesh-cli --test allow_revoke_sever`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cli/tests/allow_revoke_sever.rs
git commit -m "test: a revoke is honored by the next session on an open connection (#54)"
```

---

## Task 5: `endpoints_for_principal` — principal → stored endpoint ids

**Files:**
- Create: `node/src/daemon/sever.rs`
- Modify: `node/src/daemon.rs` (add `mod sever;`)

Scope: PAIRING mode (the `PeerStore`). Roster-mode revocation already severs through
`install_roster_view_and_sever`; this path deliberately does not duplicate it.

- [ ] **Step 1: Write the failing test**

In `node/src/daemon/sever.rs`'s `#[cfg(test)] mod tests`:

```rust
#[test]
fn resolves_both_eid_and_user_id_principals_and_nothing_else() {
    let (store, _tmp) = store_with(&[
        (/* endpoint */ [1u8; 32], Some("b64u:ann"), "ann-laptop"),
        (/* endpoint */ [2u8; 32], Some("b64u:ann"), "ann-phone"),
        (/* endpoint */ [3u8; 32], None, "bob"),
    ]);
    let eid = |b: u8| EndpointId::from_bytes([b; 32]);

    // An `eid:` principal resolves to exactly that one device.
    assert_eq!(
        endpoints_for_principal(&store, &eid(1).principal()).unwrap(),
        [eid(1)].into_iter().collect::<HashSet<_>>()
    );
    // A shared user_id resolves to EVERY device of that person.
    assert_eq!(
        endpoints_for_principal(&store, "b64u:ann").unwrap(),
        [eid(1), eid(2)].into_iter().collect::<HashSet<_>>()
    );
    // An unknown principal resolves to nothing (and must never sever).
    assert!(endpoints_for_principal(&store, "b64u:nobody").unwrap().is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mcpmesh endpoints_for_principal`
Expected: FAIL — unresolved import

- [ ] **Step 3: Implement**

```rust
//! Principal → live-connection resolution for the pairing-mode revoke paths (#54).

use std::collections::HashSet;

use mcpmesh_net::EndpointId;

use crate::allowlist::PeerStore;

/// Every STORED endpoint that the stable `principal` names: the device whose `eid:` rendering
/// matches, or every device carrying that `user_id` (a person principal covers all their
/// devices). Matching renders each stored endpoint rather than PARSING the principal, so both
/// forms are handled with no new parser and an unknown principal resolves to the empty set —
/// which severs nothing.
///
/// Pairing-mode only: roster-driven revocation severs through `install_roster_view_and_sever`.
pub(crate) fn endpoints_for_principal(
    store: &PeerStore,
    principal: &str,
) -> anyhow::Result<HashSet<EndpointId>> {
    let mut out = HashSet::new();
    for entry in store.list()? {
        let eid = EndpointId::from_bytes(entry.endpoint_id);
        if eid.principal() == principal || entry.user_id.as_deref() == Some(principal) {
            out.insert(eid);
        }
    }
    Ok(out)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mcpmesh endpoints_for_principal`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add node/src/daemon/sever.rs node/src/daemon.rs
git commit -m "feat(node): resolve a stable principal to its stored endpoints (#54)"
```

---

## Task 6: Sever on `service_allow_revoke` and on `peer_remove`

**Files:**
- Modify: `node/src/daemon/handlers.rs:963` (`service_allow_revoke`), `:1008`
  (`revoke_service_access`)

- [ ] **Step 1: Write the failing tests**

Add to `cli/tests/allow_revoke_sever.rs`:

```rust
/// The in-flight half: a revoke CLOSES the peer's live connection, not just its next session.
#[tokio::test]
async fn revoke_severs_the_live_connection() {
    let (mesh, cfg, _tmp) = paired_mesh_with_kb_allowing("eid:alice").await;
    let _accept = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&cfg)));
    let conn = dial_mesh(&alice_endpoint, mesh.endpoint.node_addr()).await;
    assert!(open_kb_session(&conn).await.is_ok());
    assert_eq!(mesh.conn_registry.len(), 1, "connection tracked before revoke");

    service_allow_revoke(&state, "kb".into(), "eid:alice".into()).await.unwrap();

    // The QUIC connection is closed from the server side.
    let closed = timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(closed.is_ok(), "revoke must sever the live connection");
}

/// Revoking one principal must NOT disturb an unrelated connected principal.
#[tokio::test]
async fn revoke_does_not_sever_an_unrelated_peer() {
    // kb allows BOTH alice and bob; both connect; revoke alice only.
    // Assert bob's connection is still open AND bob can still open a new session.
}

/// `peer_remove` severs the removed peer's devices.
#[tokio::test]
async fn peer_remove_severs_the_removed_peer() { /* mirrors the revoke test via remove_peer */ }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p mcpmesh-cli --test allow_revoke_sever`
Expected: the two sever tests FAIL (connection stays open); the "unrelated" test PASSES already.

- [ ] **Step 3: Implement — `service_allow_revoke`**

In `handlers.rs`, after the existing `if changed { reload_services_from_disk(...) }`:

```rust
    // SWAP-BEFORE-SEVER (the same ordering `install_roster_view_and_sever` uses): the registry
    // swap above means no NEW session admits the principal; severing now also cuts the sessions
    // already in flight. Connection-granular by construction — `sever_matching` closes the whole
    // QUIC connection, so a peer revoked from ONE service also loses its in-flight sessions to
    // services it still holds, and redials into a live re-evaluation. That bluntness is the
    // accepted cost of making an access-control verb take effect NOW (#54).
    let severed = sever_principal(mesh, &principal).await?;
    tracing::info!(%service, %principal, changed, severed, "service allow revoked");
```

Add the shared helper next to the handlers:

```rust
/// Close every live mesh connection held by `principal`'s stored devices. Returns the number
/// severed. A principal with no stored device (or no live connection) severs nothing.
async fn sever_principal(mesh: &Arc<MeshState>, principal: &str) -> Result<usize> {
    let store = mesh.store.clone();
    let principal_w = principal.to_string();
    let targets = blocking("join sever principal resolution", move || {
        crate::daemon::sever::endpoints_for_principal(&store, &principal_w)
    })
    .await??;
    if targets.is_empty() {
        return Ok(0);
    }
    Ok(mesh.conn_registry.sever_matching(
        mcpmesh_net::CLOSE_UNAUTHORIZED,
        b"access revoked",
        |eid, _| targets.contains(eid),
    ))
}
```

(Confirm the close-code constant's name/path against `roster_install.rs`'s `sever_matching` call
and reuse exactly that one.)

- [ ] **Step 4: Implement — `revoke_service_access` (the `peer_remove` half)**

`revoke_service_access` already resolves the target devices' principals into `principals`. After
its reload, sever every resolved principal:

```rust
    let mut severed = 0;
    for principal in &principals {
        severed += sever_principal(mesh, principal).await?;
    }
    tracing::info!(peer = %nickname, changed, severed, "revoked service access");
```

Place this AFTER the reload so the swap-before-sever ordering holds.

- [ ] **Step 5: Run tests**

Run: `cargo test -p mcpmesh-cli --test allow_revoke_sever`
Expected: PASS (all four)

- [ ] **Step 6: Commit**

```bash
git add node/src/daemon/handlers.rs cli/tests/allow_revoke_sever.rs
git commit -m "feat(node): sever live connections on service_allow_revoke and peer_remove (#54)"
```

---

## Task 7: Surface bump + docs

**Files:**
- Modify: `local-api/src/protocol.rs:917,928`
- Modify: `docs/local-protocol.md`, `docs/config.md`

- [ ] **Step 1: Bump the surface constants**

```rust
pub const API_VERSION: &str = "1.10";
pub const API_MINOR: u32 = 10;
```

Extend the `API_MINOR` doc comment with the reason: *"10: `service_allow_revoke`/`peer_remove`
take effect immediately — the live registry refuses the next session on an already-open
connection and the peer's live connections are severed (#54)."*

- [ ] **Step 2: Document the contract**

In `docs/local-protocol.md`, under `service_allow_revoke` and `peer_remove`, state: revocation is
immediate at `api_minor >= 10`; it refuses new sessions on already-open connections AND closes the
principal's live connections; severing is connection-granular, so a peer revoked from one service
loses in-flight sessions to services it still holds and must redial. Mirror a one-line note in
`docs/config.md` where `[services.*].allow` is described.

- [ ] **Step 3: Run the suite (protocol tests assert the constants)**

Run: `cargo test --workspace --locked`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add local-api/src/protocol.rs docs/
git commit -m "docs: api_minor 10 — revocation is immediate (#54)"
```

---

## Task 8: Verify + version bump

- [ ] **Step 1: Full green gate**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets     # zero warnings
cargo test --workspace --locked            # zero failures
```

- [ ] **Step 2: Version → 0.11.0** (behavior change → MINOR)

Bump `[workspace.package] version` and the five `mcpmesh-*` pins in `Cargo.toml` in lockstep, then:

```bash
cargo update -w && cargo test --workspace --locked
```

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "release: 0.11.0"
```

---

## Self-review notes

- Spec coverage: Part A → Tasks 1-3; Part B → Tasks 5-6; surface/versioning → Tasks 7-8; the six
  spec test cases → Tasks 1 (unit), 4 (H1), 6 (H2 + both regressions), 3 Step 5 (roster + ephemeral
  regressions via the existing suite).
- Task 4 Step 2 stashes to prove RED against the pre-fix code — the one place the fix could
  otherwise be tested by a test that never failed.
- `sever_principal` is defined once (Task 6 Step 3) and reused by Task 6 Step 4 — no duplication.
