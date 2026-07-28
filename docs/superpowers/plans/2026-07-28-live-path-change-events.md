# Live path-change events (#92 item 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or
> superpowers:executing-plans to implement this task-by-task. Steps use `- [ ]` for tracking.

**Goal:** A session whose selected path changes mid-flight pushes a `Reachability` frame when it
happens, instead of staying silent until something probes.

**Architecture:** One `path_events()` watcher task per user session (inbound *and* outbound),
ending with its connection. On a settled `Selected` change it joins the existing `probe_seq` ticket
discipline to write `MeshState::reachability`, then emits on `reach_bcast`.

**Tech Stack:** Rust, tokio, iroh 1.0.3 (`Connection::path_events`, `PathEvent`), existing
`mcpmesh-local-api` `StreamFrame::Reachability`.

**Spec:** `docs/superpowers/specs/2026-07-28-live-path-change-events-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `node/src/daemon/path_watch.rs` | **NEW.** The watcher: event loop, settle/debounce, ticket-disciplined cache commit, emit. |
| `node/src/daemon/reach.rs` | Expose what the watcher reuses: `selected_path`, `settle`, `supersedes`, `reachability_row`, `ReachEntry`. Keep ONE constructor for the wire row. |
| `node/src/daemon/accept.rs` | Inbound seam — spawn the watcher in `gate_and_register`. |
| `node/src/daemon/dial.rs` | Outbound seam — spawn the watcher in `connect_with_timeout`. |
| `node/src/daemon.rs` | Nothing structural; `reach_bcast` + `probe_seq` already exist on `MeshState`. |
| `local-api/src/protocol.rs` | Correct the FALSE `Reachability` doc; bump `API_VERSION`/`API_MINOR` to 1.22. |
| `cli/tests/live_path_events.rs` | **NEW.** Integration: inbound + outbound transitions, `status` coherence, probe silence. |
| `docs/local-protocol.md` | Document the new producer + cadence change. |

**Ordering note:** Task 1 is the RED integration test. It must fail for the RIGHT reason (no frame
arrives), not a compile error, before any watcher code exists — so it is written against the
existing public surface only.

---

### Task 1: RED — a live transition emits nothing today

**Files:** Create `cli/tests/live_path_events.rs`

- [ ] **Step 1: Write the failing integration test.**

Reuse #110's proven harness shape: `iroh::test_utils::run_relay_server()`, relay-only `last_addr`
so the dial starts relayed, and **hold ONE connection** across the transition. Sampling fresh
probes cannot observe a live change by construction — that is the whole point of this issue.

```rust
//! #92 item 2: a live session whose selected path changes pushes a frame WHEN IT HAPPENS.
//!
//! Ordering follows cli/tests/peer_path.rs (#110): hold one connection across the relay->direct
//! transition. A fresh probe per sample cannot see a live change.

#[tokio::test(flavor = "multi_thread")]
async fn a_live_relay_to_direct_transition_pushes_a_frame() {
    // 1. relay + two endpoints, peer store seeded with a RELAY-ONLY last_addr (see peer_path.rs)
    // 2. subscribe to mesh.reach_bcast BEFORE opening the session
    // 3. open ONE mesh session (outbound) and hold it
    // 4. await a frame with path == Direct, with a generous timeout (network wait, not a budget)
    // 5. assert NO probe ran: probe_seq unchanged from before the session opened
    let frame = tokio::time::timeout(Duration::from_secs(30), rx.recv())
        .await
        .expect("a live path change must push a frame — this is #92 item 2");
    assert_eq!(frame.unwrap().path, PeerPath::Direct);
}
```

- [ ] **Step 2: Run it; confirm it fails because no frame arrives.**

`cargo test -p mcpmesh --test live_path_events`
Expected: timeout at step 4 ("a live path change must push a frame"). If it fails on a compile
error or at an earlier assert, fix the harness first — a test that fails for the wrong reason
proves nothing.

- [ ] **Step 3: Commit.** `test: a live path change pushes no frame today (#92 RED)`

---

### Task 2: The watcher core, over a seam (no network)

**Files:** Create `node/src/daemon/path_watch.rs`; modify `node/src/daemon/reach.rs`

- [ ] **Step 1: Widen reach.rs visibility.** Make `selected_path`, `settle`, `supersedes`,
      `reachability_row` and `ReachEntry`'s fields reachable as `pub(crate)`/`pub(super)`. No
      behaviour change; `settle` already exists from #110.

- [ ] **Step 2: Write failing unit tests** in `path_watch.rs` for the pure logic, driven over a
      closure (the `settle` seam) with `#[tokio::test(start_paused = true)]` so they are instant
      and deterministic:
  - a flap inside the window (Direct→Relay→Direct) emits **nothing**
  - a settled change emits **once**
  - `Lagged` triggers a re-read rather than a skip
  - an unchanged path emits nothing

- [ ] **Step 3: Implement the decision function.** Keep it pure: given the observed path, the
      cached path and the settle window, return `Option<PeerPath>` (the value to commit+emit).
      The network loop stays a thin shell around it — this is what makes the mutations above
      catchable without a relay.

- [ ] **Step 4: Run the unit tests; all pass.**

- [ ] **Step 5: MUTATION-TEST each claim.** For every property above, break it and watch the named
      test fail: zero the settle window; make `Lagged` a `continue`; drop the "differs from cache"
      check. Record which mutation each test catches. A test that passes both ways is vacuous —
      #110 shipped exactly that and it was caught only by mutation.

- [ ] **Step 6: Commit.** `feat: path-change watcher core, with the flap and Lagged rules (#92)`

---

### Task 3: Cache commit under the ticket discipline

**Files:** `node/src/daemon/path_watch.rs`, `node/src/daemon/reach.rs`

- [ ] **Step 1: Write the failing unit test** — an older probe must not overwrite a newer watcher
      observation, and vice versa. This is `supersedes` with the watcher as the second writer.
      Also: a watcher update with **no** existing entry seeds `reachable: true`, `rtt_ms: None`.

- [ ] **Step 2: Implement the commit**: take a `probe_seq` ticket BEFORE observing, commit under
      one lock acquisition with the `supersedes` check, emit via `reach_bcast` only if committed.
      Reuse `reachability_row` so the wire row has ONE constructor.

- [ ] **Step 3: Run; passes.**

- [ ] **Step 4: MUTATION-TEST:** take the ticket *after* observing → the ordering test must fail.
      Fabricate an `rtt_ms` → the seed test must fail.

- [ ] **Step 5: Commit.** `feat: watcher joins the probe_seq ticket discipline (#92)`

---

### Task 4: Wire the INBOUND seam

**Files:** `node/src/daemon/accept.rs`

- [ ] **Step 1:** In `gate_and_register`, after a successful `register_checked`, spawn the watcher
      for that connection. It ends when `path_events()` ends (connection close).
- [ ] **Step 2:** Run the Task 1 test — expect it still FAILS if that test uses an outbound
      session. That is correct and is the point of Task 5.
- [ ] **Step 3: Commit.** `feat: watch inbound sessions for path changes (#92)`

---

### Task 5: Wire the OUTBOUND seam — the motivating case

**Files:** `node/src/daemon/dial.rs`

- [ ] **Step 1:** In `connect_with_timeout`, spawn the same watcher on the established connection.
      Do **not** attach it in `reach.rs`'s probe dial, `rendezvous.rs`, or `provider.rs` — see the
      spec's exclusion list.
- [ ] **Step 2:** Run the Task 1 test — it must now PASS.
- [ ] **Step 3: Add the regression:** a `probe_peer` against a peer with no user session pushes no
      watcher frame. Fails if the watcher was attached to every `connect`.
- [ ] **Step 4: Commit.** `feat: watch outbound sessions — the reported use case (#92)`

---

### Task 6: Coherence, lifetime, and the false doc

**Files:** `cli/tests/live_path_events.rs`, `local-api/src/protocol.rs`, `docs/local-protocol.md`

- [ ] **Step 1: Integration — `status` agrees** with the frame just pushed. Fails if the watcher
      emits without writing the cache (the #58 defect class).
- [ ] **Step 2: Regression — the watcher dies with its connection.** Close it; assert no further
      cache writes. #61 cost a release to a detached task; prove this one is bounded.
- [ ] **Step 3: Correct the FALSE doc** at `local-api/src/protocol.rs:1020` — it still says
      "Emitted on a CHANGE of `reachable` only", untrue since 0.19.0 (#92 item 1). State the real
      rule: emitted on a change of `reachable` **or** `path`, from a probe **or** a live session.
- [ ] **Step 4: Bump** `API_VERSION` "1.21" → "1.22", `API_MINOR` 21 → 22.
- [ ] **Step 5: Update `docs/local-protocol.md`** with the new producer and the cadence change.
- [ ] **Step 6: Commit.** `feat: API 1.22 — live path events, and correct a false frame doc (#92)`

---

### Task 7: Verify, gate, ship

- [ ] **Step 1: Full suite, UNTRUNCATED.** Never pipe through `head`/`tail`; report counts and
      EVERY failure. `cargo test` stops at the first failing binary, so "N suites ok" is not a
      whole-workspace pass when anything failed.
- [ ] **Step 2:** `cargo fmt --all`, `cargo clippy --workspace --all-targets --locked` (zero
      warnings).
- [ ] **Step 3: Version bump** to **0.20.0** (behaviour change → MINOR) across `Cargo.toml` +
      the five pins; `cargo update -w`.
- [ ] **Step 4: COMMIT, then run the adversarial GATE** (skill step 2b) before `git push`. Never
      `git add -A` while a reviewer is running. Point it at: test vacuity, the ticket-ordering
      window, watcher task leaks, and every factual claim in the commit messages.
- [ ] **Step 5: PR, CI green, merge, full release train.** Note in the PR that the two-machine
      smoke test was not run (this touches the network layer).
