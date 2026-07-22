# Embeddable Full Node (`mcpmesh-node`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the daemon core from `cli` into a new `mcpmesh-node` library crate so Rust consumers embed a full-parity mesh node in-process (no sidecar), while the CLI daemon becomes a thin shell over the same code.

**Architecture:** New workspace member `node/` between the infra crates and the shell (`codec`/`net`/`trust` → `local-api` → `node` → `cli`). The embed API is the existing `mcpmesh-local/1` protocol served over an in-memory duplex: `Node::control()` returns the same `ControlClient` from `mcpmesh-local-api`. Modules move mechanically (`git mv`) with `pub use mcpmesh_node::x;` re-exports in `cli/src/lib.rs` so all remaining cli code and every integration test compiles without import rewrites.

**Tech Stack:** Rust workspace (edition 2024, `forbid(unsafe_code)`), tokio, iroh (exact-pinned), redb, figment/toml, `mcpmesh-local-api` client+service features.

**Spec:** `docs/superpowers/specs/2026-07-22-embeddable-node-design.md`

**Declared deviations from spec (improvements, keep documented):**
1. Builder takes ONE `root` dir using the existing profile-root layout (`<root>/config`, `<root>/data`, `<root>/state`) instead of a bare `data_dir` — one knob, and an embedded node's root is layout-identical to a `mcpmesh --profile <dir>` profile.
2. `Node::wait()` resolves when shutdown is requested (the control `shutdown` verb or another handle calling `Node::shutdown`), not on "fatal background-task death" — the daemon has no fatal-task machinery today (tasks log and serving continues), and inventing one is YAGNI.
3. The two-node loopback e2e lives in `cli/tests/` (not `node/tests/`) so it reuses the existing `echo_mcp_stub` test binary via `CARGO_BIN_EXE_` instead of duplicating the stub — and it exercises the real consumer path (cli is itself a `mcpmesh-node` consumer).

**Ground rules for every task:**
- Verification gate = `cargo test --workspace` green (plus `cargo clippy --workspace --all-targets` at each commit; workspace lints are strict).
- Moves are `git mv` + minimal edits. Never rewrite module internals while moving them.
- Inside moved modules, `crate::x` paths keep resolving because the modules move together with their dependency closure (order below is topological).
- In `cli/src/lib.rs`, replace each moved `pub mod x;` with `#[doc(hidden)] pub use mcpmesh_node::x;` — this keeps `crate::x::...` working in remaining cli modules AND `mcpmesh::x::...` working in `cli/tests/*`.

---

### Task 1: Scaffold the `node` crate

**Files:**
- Create: `node/Cargo.toml`, `node/src/lib.rs`
- Modify: `Cargo.toml` (workspace root), `cli/Cargo.toml`

- [ ] **Step 1: Create `node/Cargo.toml`**

Copy the dependency set from `cli/Cargo.toml` minus the CLI-only deps (`clap`, `clap_complete`, `clap_mangen`, `assert_cmd`). Keep the inline comments with each dep you carry over (they document pin rationale).

```toml
[package]
name = "mcpmesh-node"
version.workspace = true
edition.workspace = true
license.workspace = true
rust-version.workspace = true
repository.workspace = true
description = "Embed a full mcpmesh node in-process — the daemon core as a library"

[lints]
workspace = true

[dependencies]
anyhow.workspace = true
async-trait.workspace = true
figment.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio = { workspace = true, features = ["process"] }
tracing.workspace = true
mcpmesh-trust.workspace = true
mcpmesh-net.workspace = true
mcpmesh-local-api = { workspace = true, features = ["service"] }
ed25519-dalek.workspace = true
rustix = { version = "1", features = ["process", "fs"] }
redb = "2"
toml = "0.8"
data-encoding = "2"
blake3 = "1"
rand.workspace = true
iroh.workspace = true
iroh-gossip = { workspace = true }
iroh-blobs = { workspace = true }
reqwest = { workspace = true }
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
bytes = { workspace = true }
n0-future = { workspace = true }
url = { workspace = true }

[dev-dependencies]
tempfile.workspace = true
tracing-subscriber = "0.3"
serde_json.workspace = true
```

- [ ] **Step 2: Create `node/src/lib.rs`** (banner only for now)

```rust
//! Embed a full [mcpmesh](https://github.com/counterpunchtech/mcpmesh) node in-process.
//!
//! The supported surface is [`NodeBuilder`]/[`Node`] plus the `mcpmesh-local/1` control
//! protocol [`Node::control`] speaks (see `docs/local-protocol.md`). Every other module in
//! this crate is `#[doc(hidden)]` internals of the mcpmesh daemon — no stability promise is
//! made for them; they may change or vanish in any release without a major version bump.
//!
//! Only driving a RUNNING daemon (the sidecar model)? Depend on
//! [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api) instead — it links no
//! networking stack at all.

/// This crate's version — the mcpmesh release-train version the daemon binary ships on.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
```

- [ ] **Step 3: Wire the workspace.** In root `Cargo.toml`: add `"node"` to `members` (between `"local-api"` and `"cli"`), and under `[workspace.dependencies]` add:

```toml
mcpmesh-node = { path = "node", version = "0.6.1" }
```

In `cli/Cargo.toml` `[dependencies]` add `mcpmesh-node.workspace = true`.

- [ ] **Step 4: Verify** — Run: `cargo test --workspace` → all existing tests pass; `cargo clippy --workspace --all-targets` → clean.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "node: scaffold the mcpmesh-node crate (empty supported surface)"`

---

### Task 2: Move the foundation modules — `util`, `ipc`, `config`

These three have no `crate::` dependencies (verified by grep).

**Files:**
- Move: `cli/src/util.rs` → `node/src/util.rs`; `cli/src/ipc.rs` → `node/src/ipc.rs`; `cli/src/config.rs` → `node/src/config.rs`
- Modify: `node/src/lib.rs`, `cli/src/lib.rs`

- [ ] **Step 1: Move** — `git mv cli/src/util.rs node/src/util.rs && git mv cli/src/ipc.rs node/src/ipc.rs && git mv cli/src/config.rs node/src/config.rs`

- [ ] **Step 2: Declare in `node/src/lib.rs`:**

```rust
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod ipc;
#[doc(hidden)]
pub mod util;
```

- [ ] **Step 3: Re-export in `cli/src/lib.rs`** — delete the three `pub mod` lines (`util`, `ipc`, `config`) and add in their place:

```rust
#[doc(hidden)]
pub use mcpmesh_node::{config, ipc, util};
```

- [ ] **Step 4: Fix stragglers.** `cargo check --workspace` will flag any `crate::`-path or visibility breakage (e.g. `pub(crate)` items in moved modules referenced from cli — promote those to `#[doc(hidden)] pub` if hit; unit tests inside moved files travel with them and need no edits). Iterate until clean.

- [ ] **Step 5: Verify** — `cargo test --workspace` green; clippy clean.

- [ ] **Step 6: Commit** — `git commit -am "node: move util, ipc, config out of cli (re-exported for the shell + tests)"`

---

### Task 3: Move `limits`, `audit`, `stream`, `allowlist`

Deps (all already in node after Task 2): `limits`→config; `audit`→util; `stream`→audit; `allowlist`→(none).

- [ ] **Step 1: Move** — `git mv cli/src/limits.rs node/src/limits.rs && git mv cli/src/audit node/src/audit && git mv cli/src/stream.rs node/src/stream.rs && git mv cli/src/allowlist.rs node/src/allowlist.rs`

- [ ] **Step 2: Declare in `node/src/lib.rs`** (each as `#[doc(hidden)] pub mod`) and swap the four `cli/src/lib.rs` declarations for:

```rust
#[doc(hidden)]
pub use mcpmesh_node::{allowlist, audit, limits, stream};
```

(merge with the Task 2 `pub use` line into one).

- [ ] **Step 3: Fix stragglers, verify** — `cargo test --workspace` green; clippy clean.

- [ ] **Step 4: Commit** — `git commit -am "node: move limits, audit, stream, allowlist out of cli"`

---

### Task 4: Move `roster`, `backends`, `pairing`, `blobs`

Deps: `roster`→allowlist,limits,util; `backends`→audit,limits; `pairing`→allowlist,config,util (its `crate::daemon` mentions are doc-links only); `blobs`→audit,roster. All satisfied.

- [ ] **Step 1: Move** — `git mv cli/src/roster node/src/roster && git mv cli/src/backends node/src/backends && git mv cli/src/pairing node/src/pairing && git mv cli/src/blobs node/src/blobs`

- [ ] **Step 2: Declare/re-export** as in Task 3 (`backends, blobs, pairing, roster`).

- [ ] **Step 3: Fix stragglers, verify** — `cargo test --workspace` green (this batch carries unit tests using `tempfile`/`tracing-subscriber` — both already in node dev-deps); clippy clean.

- [ ] **Step 4: Commit** — `git commit -am "node: move roster, backends, pairing, blobs out of cli"`

---

### Task 5: Move `daemon` + `control` together; leave a shell `run()` in cli

`daemon` and `control` are mutually recursive — they move as one. The env/flock/runtime part of `boot::run` STAYS in cli.

**Files:**
- Move: `cli/src/daemon.rs` → `node/src/daemon.rs`; `cli/src/daemon/` → `node/src/daemon/`; `cli/src/control.rs` → `node/src/control.rs`
- Create: `cli/src/daemonshell.rs`
- Modify: `node/src/lib.rs`, `cli/src/lib.rs`, `cli/src/main.rs`, `node/src/daemon/boot.rs`

- [ ] **Step 1: Move** — `git mv cli/src/daemon.rs node/src/daemon.rs && git mv cli/src/daemon node/src/daemon && git mv cli/src/control.rs node/src/control.rs`

- [ ] **Step 2: Split `run()` out of `node/src/daemon/boot.rs`.** Delete `pub fn run()` and the unix-only `acquire_singleton_lock` from `boot.rs`; make `serve_forever` `pub` (still `#[doc(hidden)]`-tier via the module). Update `node/src/daemon.rs`'s `pub use boot::run;` to `pub use boot::serve_forever;`.

- [ ] **Step 3: Create `cli/src/daemonshell.rs`** with the extracted shell, verbatim from the old `run()`/`acquire_singleton_lock` bodies (env paths, flock, runtime build), now calling `mcpmesh_node::daemon::serve_forever`:

```rust
//! The daemon PROCESS shell: per-uid singleton flock (unix), env-derived paths, and the
//! tokio runtime — everything that makes the embeddable node (`mcpmesh-node`) a system
//! daemon. The node core itself lives in `mcpmesh_node::daemon`.
use anyhow::{Context, Result};
use mcpmesh_trust::paths;

use crate::ipc;

pub fn run() -> Result<()> {
    #[cfg(unix)]
    let _lock = {
        let runtime = paths::runtime_dir()?;
        ipc::ensure_runtime_dir(&runtime)?;
        let lock_path = runtime.join("mcpmesh.lock");
        match acquire_singleton_lock(&lock_path)? {
            Some(lock) => lock,
            None => {
                tracing::info!("another mcpmesh daemon already holds the singleton lock; exiting");
                return Ok(());
            }
        }
    };
    let socket = paths::default_endpoint()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build daemon tokio runtime")?;
    rt.block_on(async move { mcpmesh_node::daemon::serve_forever(&socket).await })
}

#[cfg(unix)]
fn acquire_singleton_lock(/* signature + body verbatim from old boot.rs */) { /* moved code */ }
```

Carry the original doc comments for both functions over verbatim.

- [ ] **Step 4: Rewire.** `node/src/lib.rs`: declare `#[doc(hidden)] pub mod control;` and `#[doc(hidden)] pub mod daemon;`. `cli/src/lib.rs`: drop the `daemon`/`control` mods, add them to the `pub use mcpmesh_node::{...}` line, and declare `#[doc(hidden)] pub mod daemonshell;`. `cli/src/main.rs`: the daemon subcommand arm changes from `daemon::run()` to `crate::daemonshell::run()`. Any cli-side references to `daemon::STACK_VERSION` etc. keep resolving via the re-export (`STACK_VERSION` is `env!("CARGO_PKG_VERSION")` — node and cli share the workspace version, so the reported value is unchanged).

- [ ] **Step 5: Fix stragglers** — expect a handful of visibility promotions (`pub(crate)` → `#[doc(hidden)] pub`) where cli porcelain (`doctor.rs`, `enrollcmd.rs`, `pairing` porcelain callers in `main.rs`) reaches into daemon items. `cargo check --workspace` drives the list. cli's `rustls`/`redb`-class deps now sit unused — leave them; Task 11 prunes.

- [ ] **Step 6: Verify** — `cargo test --workspace` green (the full daemon integration suite now exercises shell + node crate); clippy clean.

- [ ] **Step 7: Commit** — `git commit -am "node: move daemon core + control dispatch; cli daemon becomes the process shell"`

---

### Task 6: `NodePaths` — inject paths, stop reading env inside node

**Files:**
- Create: `node/src/paths.rs`
- Modify: `node/src/lib.rs`, `node/src/daemon/boot.rs`, `node/src/daemon.rs` (MeshState), `node/src/daemon/roster_install.rs`, `node/src/control.rs`

- [ ] **Step 1: Write the failing test** (in `node/src/paths.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The one-root layout MUST equal the `--profile <root>` layout (local-api paths.rs
    /// profile-root arms): config under <root>/config, data under <root>/data, state
    /// under <root>/state. An embedded node's root dir is a valid CLI profile dir.
    #[test]
    fn under_root_matches_the_profile_layout() {
        let p = NodePaths::under_root(Path::new("/r"));
        assert_eq!(p.config_path, Path::new("/r/config/config.toml"));
        assert_eq!(p.device_key_path, Path::new("/r/config/device.key"));
        assert_eq!(p.user_key_path, Path::new("/r/config/user.key"));
        assert_eq!(p.roster_path, Path::new("/r/config/roster.json"));
        assert_eq!(p.state_db_path, Path::new("/r/data/state.redb"));
        assert_eq!(p.blobs_dir, Path::new("/r/data/blobs"));
        assert_eq!(p.blob_scopes_path, Path::new("/r/data/blob-scopes.json"));
        assert_eq!(p.audit_dir, Path::new("/r/state/audit"));
    }
}
```

- [ ] **Step 2: Run it** — `cargo test -p mcpmesh-node under_root` → FAIL (NodePaths undefined).

- [ ] **Step 3: Implement `node/src/paths.rs`:**

```rust
//! Every filesystem location a node reads or writes, resolved ONCE at construction.
//! The node itself never consults the environment: the embedder picks a root
//! ([`NodePaths::under_root`] — layout-identical to a `mcpmesh --profile <root>` dir),
//! and the daemon shell resolves the standard per-user layout ([`NodePaths::from_env`]).
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct NodePaths {
    pub config_path: PathBuf,
    pub device_key_path: PathBuf,
    pub user_key_path: PathBuf,
    pub roster_path: PathBuf,
    pub state_db_path: PathBuf,
    pub blobs_dir: PathBuf,
    pub blob_scopes_path: PathBuf,
    pub audit_dir: PathBuf,
}

impl NodePaths {
    /// The profile-root layout under one directory (see module doc).
    pub fn under_root(root: &Path) -> Self {
        let config = root.join("config");
        let data = root.join("data");
        NodePaths {
            config_path: config.join("config.toml"),
            device_key_path: config.join("device.key"),
            user_key_path: config.join("user.key"),
            roster_path: config.join("roster.json"),
            state_db_path: data.join("state.redb"),
            blobs_dir: data.join("blobs"),
            blob_scopes_path: data.join("blob-scopes.json"),
            audit_dir: root.join("state").join("audit"),
        }
    }

    /// The standard per-user layout, from the same `mcpmesh_trust::paths` rules the
    /// porcelain uses (XDG/APPDATA, honoring a profile root). Daemon-shell only.
    pub fn from_env() -> std::io::Result<Self> {
        use mcpmesh_trust::paths as p;
        Ok(NodePaths {
            config_path: p::default_config_path()?,
            device_key_path: p::default_device_key_path()?,
            user_key_path: p::default_user_key_path()?,
            roster_path: p::default_roster_path()?,
            state_db_path: p::default_state_db_path()?,
            blobs_dir: p::default_blobs_dir()?,
            blob_scopes_path: p::default_blob_scopes_path()?,
            audit_dir: p::default_audit_dir()?,
        })
    }
}
```

Declare `pub mod paths;` (NOT doc-hidden — it's supported surface) and `pub use paths::NodePaths;` in `node/src/lib.rs`.

- [ ] **Step 4: Run it** — `cargo test -p mcpmesh-node under_root` → PASS.

- [ ] **Step 5: Thread `NodePaths` through boot.** Change `serve_forever(socket: &Path)` to `serve_forever(socket: &Path, paths: NodePaths)`; inside it, replace every `paths::default_*()?` call with the matching `paths.field` (audit dir, config path, device key default, state db, roster path, blob scopes, blobs dir, user key default — the config-file overrides for `device_key`/`user_key` keep winning exactly as today). `cli/src/daemonshell.rs` passes `NodePaths::from_env()?`. Note `roster_confirmed_path(&config_path)` is already derived from the config path — leave it.

- [ ] **Step 6: Carry paths on `MeshState`.** In `node/src/daemon.rs`, replace the `config_path: PathBuf` field with `paths: NodePaths`, add accessors to keep churn mechanical:

```rust
pub(crate) fn config_path(&self) -> &Path { &self.paths.config_path }
```

Update `MeshState::new` (takes `NodePaths` where it took `config_path`) and every `mesh.config_path` use to `mesh.config_path()`. The dial-only test seam at the old `daemon.rs:701` builds with `NodePaths::from_env().unwrap_or_else(|_| NodePaths::under_root(Path::new("")))` (same HOME-less degradation as before).

- [ ] **Step 7: Fix the two runtime env-path callsites.** `node/src/daemon/roster_install.rs` (`paths::default_roster_path()` → `mesh.paths.roster_path.clone()`); `node/src/control.rs` `audit_summary` (resolve the dir from the mesh's `paths.audit_dir` when a mesh is present; keep the `mcpmesh_trust::paths::default_audit_dir()` fallback for the mesh-less `DaemonState::new` control-only mode the cli test stubs use). After this, `grep -rn "paths::default_\|paths::runtime_dir" node/src` must return NOTHING outside `paths.rs::from_env`.

- [ ] **Step 8: Verify** — grep clean per Step 7; `cargo test --workspace` green; clippy clean.

- [ ] **Step 9: Commit** — `git commit -am "node: NodePaths — all filesystem locations injected, env resolution stays in the shell"`

---

### Task 7: `connect_control_io` — the `ControlClient` handshake over any stream

**Files:**
- Modify: `local-api/src/client.rs`, `local-api/src/lib.rs`, plus whatever `cargo check` flags in `cli/src/proxy.rs` / `cli/src/stream.rs` / `cli/src/client.rs` (return-type adaptation).

- [ ] **Step 1: Write the failing test** (in `local-api/src/client.rs` tests module):

```rust
#[tokio::test]
async fn connect_control_io_handshakes_over_a_duplex() {
    let (client_io, mut server_io) = tokio::io::duplex(4096);
    tokio::spawn(async move {
        let hello = serde_json::json!({
            "api": API_NAME, "api_version": API_VERSION,
            "api_minor": crate::API_MINOR, "stack_version": "test",
        });
        // write_frame is already imported by the existing stub-daemon tests
        crate::codec::write_frame(&mut server_io, &hello).await.unwrap();
    });
    let (r, w) = tokio::io::split(client_io);
    let client = connect_control_io(r, w).await.expect("handshake");
    assert_eq!(client.hello().stack_version, "test");
}
```

(Adapt the `write_frame` path to wherever the existing client tests import it from.)

- [ ] **Step 2: Run it** — `cargo test -p mcpmesh-local-api connect_control_io` → FAIL (not defined).

- [ ] **Step 3: Implement.** In `local-api/src/client.rs`:

```rust
/// The client's read half — boxed so one `ControlClient` serves every transport
/// (the platform socket/pipe, or an embedder's in-memory duplex).
pub type ControlRead = Box<dyn tokio::io::AsyncRead + Send + Unpin>;
/// The client's write half — see [`ControlRead`].
pub type ControlWrite = Box<dyn tokio::io::AsyncWrite + Send + Unpin>;
```

Change `ControlClient` fields to `reader: FrameReader<ControlRead>, writer: ControlWrite`, and `open_session`/`open_stream` return types to `(FrameReader<ControlRead>, ControlWrite)` (bodies unchanged). Factor the handshake out of `connect_control` into:

```rust
/// Complete the mcpmesh-local/1 hello handshake over an ALREADY-CONNECTED byte stream —
/// the transport-agnostic core of [`connect_control`], and the front door for in-process
/// embedding (`mcpmesh-node`'s `Node::control` dials a tokio duplex through here).
pub async fn connect_control_io(
    reader: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    writer: impl tokio::io::AsyncWrite + Send + Unpin + 'static,
) -> Result<ControlClient, ClientError> {
    let mut reader = FrameReader::new(Box::new(reader) as ControlRead, MAX_FRAME_BYTES);
    // ... hello read + api assert, moved verbatim from connect_control ...
    Ok(ControlClient { hello, reader, writer: Box::new(writer) as ControlWrite })
}

pub async fn connect_control(path: &Path) -> Result<ControlClient, ClientError> {
    let stream = connect_local(path).await?;
    let (read_half, write_half) = split_local(stream);
    connect_control_io(read_half, write_half).await
}
```

Export `connect_control_io`, `ControlRead`, `ControlWrite` from `local-api/src/lib.rs` alongside the existing client exports.

- [ ] **Step 4: Run it** — new test PASS; then `cargo check --workspace` and adapt the callers the return-type change flags (cli `proxy.rs`/`stream.rs` pump generically — expect type-annotation-only edits or none).

- [ ] **Step 5: Verify** — `cargo test --workspace` green (the seam-ported stub-daemon tests in local-api prove socket behavior is unchanged); clippy clean.

- [ ] **Step 6: Commit** — `git commit -am "local-api: connect_control_io — ControlClient over any byte stream (boxed halves)"`

---

### Task 8: `serve_control_io` — the control server over any stream

**Files:**
- Modify: `node/src/control.rs`

- [ ] **Step 1: Write the failing test** (in `node/src/control.rs` tests):

```rust
#[tokio::test]
async fn serve_control_io_speaks_the_protocol_over_a_duplex() {
    let state = std::sync::Arc::new(DaemonState::new("in-proc-test"));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (sr, sw) = tokio::io::split(server_io);
    tokio::spawn(serve_control_io(sr, sw, state));
    let (cr, cw) = tokio::io::split(client_io);
    let mut client = mcpmesh_local_api::connect_control_io(cr, cw).await.expect("hello");
    assert_eq!(client.hello().stack_version, "in-proc-test");
    let status = client.status().await.expect("status");
    assert_eq!(status.stack_version, "in-proc-test");
}
```

- [ ] **Step 2: Run it** — `cargo test -p mcpmesh-node serve_control_io` → FAIL.

- [ ] **Step 3: Implement.** Split `handle_conn` in two: it keeps ONLY the `ipc::check_peer` same-user gate + `split_local`, then delegates. Everything from the `Hello` write down moves verbatim into:

```rust
/// Serve one mcpmesh-local/1 connection over ALREADY-AUTHORIZED byte halves — the
/// transport-agnostic body of [`handle_conn`], and what an embedded node's in-memory
/// control connection runs (the duplex needs no peer gate: it never leaves the process).
pub async fn serve_control_io(
    read_half: impl tokio::io::AsyncRead + Send + Unpin + 'static,
    mut write_half: impl tokio::io::AsyncWrite + Send + Unpin + 'static,
    state: Arc<DaemonState>,
) -> Result<()> { /* moved body */ }
```

- [ ] **Step 4: Run it** — PASS. Then `cargo test --workspace` (the daemon-dispatch and subscribe integration tests prove the socket path through `handle_conn` is unchanged); clippy clean.

- [ ] **Step 5: Commit** — `git commit -am "node: serve_control_io — control dispatch over any byte stream"`

---

### Task 9: The supported surface — `NodeBuilder` / `Node` / `StartError`

**Files:**
- Create: `node/src/node.rs`, `node/tests/start.rs`
- Modify: `node/src/lib.rs`, `node/src/daemon/boot.rs`, `cli/src/daemonshell.rs`

- [ ] **Step 1: Write the failing tests** (`node/tests/start.rs`):

```rust
use mcpmesh_node::{Node, NodeBuilder, StartError};

/// A fresh root dir + default config boots to a serving node whose control API answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_starts_in_an_empty_root_and_answers_status() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let mut control = node.control().await.expect("control");
    let status = control.status().await.expect("status");
    assert_eq!(status.stack_version, mcpmesh_node::VERSION);
    assert!(status.services.is_empty());
    node.shutdown().await;
}

/// Two nodes on ONE root must refuse: redb's exclusive lock is the guard, surfaced typed.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_node_on_the_same_root_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let _first = NodeBuilder::new(root.path()).start().await.expect("first");
    let err = NodeBuilder::new(root.path()).start().await.expect_err("second must refuse");
    assert!(matches!(err, StartError::DataDirInUse { .. }), "got: {err:?}");
}
```

- [ ] **Step 2: Run them** — `cargo test -p mcpmesh-node --test start` → FAIL (types undefined).

- [ ] **Step 3: Restructure boot for reuse.** In `boot.rs`, split `serve_forever(socket, paths)` at its step-6 seam into:
  - `pub(crate) async fn start_node(paths: NodePaths, config: Option<Config>) -> Result<Arc<DaemonState>, StartError>` — everything serve_forever does EXCEPT the listener bind and `serve_control` (crypto-provider install, audit sink, config load — skipped when `config` is `Some`, key load, endpoint, store/gates, limiters, services, MeshState, task spawns, `DaemonState::with_mesh`). Map errors while splitting: config load failure → `StartError::Config`, `PeerStore::open` database-lock errors → `StartError::DataDirInUse` (match redb's already-open/locked error variants; every other store error → `StartError::Store`), endpoint build → `StartError::Endpoint`, the rest → `StartError::Io`. Create the root's `config/`/`data/` parent dirs exactly where the old code created them (no extra mkdirs).
  - `serve_forever(socket, paths)` becomes: bind listener (AddrInUse → exit-0 log, as today) → `start_node(paths, None)` → the startup `tracing::info!` → `serve_control(listener, state)`. The daemon shell is behaviorally identical, including Windows bind-first singleton ordering.

- [ ] **Step 4: Implement `node/src/node.rs`:**

```rust
//! The supported embedding surface: build ([`NodeBuilder`]) and drive ([`Node`]) a full
//! in-process mesh node. The node is its OWN mesh identity under its OWN root directory —
//! it never touches the per-user daemon's state, socket, or singleton lock.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcpmesh_local_api::{ClientError, ControlClient, connect_control_io};

use crate::config::Config;
use crate::control::{DaemonState, serve_control_io};
use crate::paths::NodePaths;

/// Everything that can refuse a [`NodeBuilder::start`].
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("config error in {path}: {source}")]
    Config { path: PathBuf, #[source] source: anyhow::Error },
    #[error("data dir already in use by another node: {path}")]
    DataDirInUse { path: PathBuf },
    #[error("peer store error: {0}")]
    Store(#[source] anyhow::Error),
    #[error("endpoint error: {0}")]
    Endpoint(#[source] anyhow::Error),
    #[error(transparent)]
    Io(anyhow::Error),
}

pub struct NodeBuilder {
    root: PathBuf,
    config: Option<Config>,
}

impl NodeBuilder {
    /// A node rooted at `root` — the ONE directory holding its whole world
    /// (`config/`, `data/`, `state/`; layout-identical to `mcpmesh --profile <root>`).
    /// Missing pieces are created on start: first start mints the device key.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), config: None }
    }

    /// Use this configuration instead of reading `<root>/config/config.toml`. The type
    /// IS the config-file vocabulary (`docs/config.md`) — one schema, two front doors.
    /// Config-persisting control verbs (a non-ephemeral `register_service`, pairing
    /// grants) still write `<root>/config/config.toml`.
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Boot the node: identity, stores, gates, the iroh endpoint, and every serving
    /// loop the daemon runs. Requires a multi-thread tokio runtime.
    pub async fn start(self) -> Result<Node, StartError> {
        let paths = NodePaths::under_root(&self.root);
        let state = crate::daemon::boot::start_node(paths, self.config).await?;
        Ok(Node { state })
    }
}

/// A running in-process node. Dropping it does NOT stop serving — call
/// [`shutdown`](Node::shutdown).
pub struct Node {
    state: Arc<DaemonState>,
}

impl Node {
    /// A control connection to THIS node: the same typed `mcpmesh-local/1` client a
    /// sidecar consumer gets from `connect_control_default`, over an in-memory pipe.
    /// Cheap; open one per concurrent conversation (a session upgrade consumes its
    /// connection, exactly as on the socket).
    pub async fn control(&self) -> Result<ControlClient, ClientError> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server_io);
        let state = self.state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_control_io(sr, sw, state).await {
                tracing::debug!(%e, "in-process control connection ended");
            }
        });
        let (cr, cw) = tokio::io::split(client_io);
        connect_control_io(cr, cw).await
    }

    /// This node's mesh identity — what a peer's invite/pair flow binds to.
    pub fn endpoint_id(&self) -> iroh::EndpointId { /* via state.mesh endpoint */ }

    /// Resolves once shutdown has been requested — by [`shutdown`](Node::shutdown) or by
    /// the control protocol's `shutdown` verb (e.g. an operator driving this node's
    /// control connection).
    pub async fn wait(&self) { self.state.shutdown_requested().await }

    /// Stop serving: sever live sessions, stop background loops, close the endpoint.
    pub async fn shutdown(self) { /* notify + abort accept/poll tasks + endpoint.close() */ }
}
```

Fill the two `/* */` bodies from `DaemonState`/`MeshState` internals (same crate — direct field access; add a small `DaemonState::shutdown_requested()` alias for the existing `shutdown: Notify` and reuse the notify + task-abort + `Endpoint::close` sequence; check `control.rs`'s `shutdown` verb handler for the exact existing teardown steps and mirror them). Export from `lib.rs`: `pub mod node;` + `pub use node::{Node, NodeBuilder, StartError};` and `pub use config::Config;` (plus `config`'s public sub-structs stay reachable as `mcpmesh_node::config::*`).

- [ ] **Step 5: Run the tests** — `cargo test -p mcpmesh-node --test start` → both PASS.

- [ ] **Step 6: Full verify** — `cargo test --workspace` green; clippy clean; `cargo doc -p mcpmesh-node --no-deps` renders only `NodeBuilder`/`Node`/`StartError`/`Config`/`NodePaths`/`VERSION` as visible items.

- [ ] **Step 7: Commit** — `git commit -am "node: NodeBuilder/Node — the supported in-process embedding surface"`

---

### Task 10: The embedded two-node loopback e2e

**Files:**
- Create: `cli/tests/embedded_loopback.rs`

- [ ] **Step 1: Write the test.** Mirror `cli/tests/hero_flow_pairing.rs` mechanics (read it first for the exact invite/pair/session sequencing and any wait/retry helpers), but with two in-process `Node`s instead of two daemon processes:

```rust
//! The loopback hero flow, EMBEDDED: two in-process nodes in one test binary — the
//! full product loop (serve → invite → pair → SAS → session) with no daemon process,
//! proving `mcpmesh-node` full parity over the same control vocabulary.
use mcpmesh_local_api::BackendSpec;
use mcpmesh_node::NodeBuilder;

#[tokio::test(flavor = "multi_thread")]
async fn two_embedded_nodes_pair_and_run_an_mcp_session() {
    let (a_root, b_root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = NodeBuilder::new(a_root.path()).start().await.expect("node a");
    let b = NodeBuilder::new(b_root.path()).start().await.expect("node b");

    // a serves the hermetic stdio MCP stub (same binary the process-level tests spawn).
    let mut a_ctl = a.control().await.unwrap();
    a_ctl.register_service(
        "notes",
        BackendSpec::Run { cmd: vec![env!("CARGO_BIN_EXE_echo_mcp_stub").into()] },
        vec![],
    ).await.expect("register");

    // invite → pair, then assert the SAS programmatically on BOTH sides (the e2e
    // pattern from the process-level loopback): redeemer's PairResult vs inviter's
    // recent_pairings.
    let invite = a_ctl.invite(vec!["notes".into()]).await.expect("invite");
    let mut b_ctl = b.control().await.unwrap();
    let paired = b_ctl.pair(&invite.invite_line).await.expect("pair");
    assert!(!paired.sas_code.is_empty());
    let a_status = a_ctl.status().await.expect("status");
    assert_eq!(
        a_status.recent_pairings.last().expect("a recorded the pairing").sas_code,
        paired.sas_code,
        "both sides display the same safety code"
    );

    // b opens a live MCP session to a/notes over real iroh and round-trips the stub.
    let session_ctl = b.control().await.unwrap();
    let (reader, writer) = session_ctl
        .open_session(paired.peer_nickname.clone(), "notes".into())
        .await.expect("open_session");
    // initialize + tools/call echo — reuse the exact frames + pump helpers the
    // process-level proxy/session tests use against the stub.
    exercise_stub_session(reader, writer).await;

    b.shutdown().await;
    a.shutdown().await;
}
```

Implement `exercise_stub_session` by lifting the newline-delimited initialize/tools-call exchange from the existing stub-driving test (`cli/tests/spawn_backend.rs` or `proxy_roundtrip.rs` — whichever pumps raw session bytes) — same request lines, same response assertions (echoed `text` plus the injected `MCPMESH_PEER_NAME`). Adapt exact field/arg names (`open_session` peer naming, `recent_pairings` element type) to what the compiler tells you — the shapes above are from `local-api/src/protocol.rs` as of this writing.

- [ ] **Step 2: Run it** — `cargo test -p mcpmesh --test embedded_loopback` → PASS (first run may legitimately take seconds: two real iroh endpoints hole-punching over loopback).

- [ ] **Step 3: Full verify** — `cargo test --workspace` green; clippy clean.

- [ ] **Step 4: Commit** — `git commit -am "e2e: two embedded nodes pair + run an MCP session in one process"`

---

### Task 11: Parity guard + cli dependency prune

**Files:**
- Create: `cli/tests/embed_parity.rs`
- Modify: `cli/Cargo.toml`

- [ ] **Step 1: Write the parity test:**

```rust
//! The lockstep guard: the daemon binary and the embeddable crate are the SAME stack
//! version — an embedder pinning mcpmesh-node N embeds exactly what `mcpmesh` N ships.
#[test]
fn the_binary_and_the_embeddable_crate_are_one_release() {
    let out = assert_cmd::Command::cargo_bin("mcpmesh").unwrap()
        .arg("--version").assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains(mcpmesh_node::VERSION),
        "binary `{stdout}` != mcpmesh-node {}", mcpmesh_node::VERSION
    );
}
```

- [ ] **Step 2: Run it** — PASS (both are the workspace version; this guards future drift).

- [ ] **Step 3: Prune `cli/Cargo.toml`.** Remove each dependency the shell no longer uses — candidates: `redb`, `blake3`, `data-encoding`, `iroh-gossip`, `iroh-blobs`, `reqwest`, `rustls`, `bytes`, `n0-future`, `url`, `rand`, `ed25519-dalek`, `toml`, `figment`, `async-trait` — by deleting ALL candidates at once, running `cargo check -p mcpmesh --all-targets`, and re-adding only what errors demand (porcelain like `doctor`/`enrollcmd`/`main` may still need a few, e.g. `iroh`; keep `rustix` — the shell's flock needs it). Keep each survivor's rationale comment.

- [ ] **Step 4: Verify** — `cargo test --workspace` green; clippy clean; `cargo tree -p mcpmesh -e no-dev | grep -c clap` still ≥1 while `cargo tree -p mcpmesh-node -e no-dev | grep clap` is EMPTY (embedders don't inherit the CLI stack).

- [ ] **Step 5: Commit** — `git commit -am "cli: prune to shell deps; guard binary/embed version lockstep"`

---

### Task 12: Docs + release-train wiring

**Files:**
- Create: `docs/embedding.md`
- Modify: `README.md`, `AGENTS.md`, `RELEASING.md`, `local-api/src/lib.rs` (doc pointer), `node/src/lib.rs` (quickstart doc)

- [ ] **Step 1: Write `docs/embedding.md`** — audience: a Rust developer embedding a node. Contents, in order: (1) sidecar vs embedded — one paragraph + when to pick which (embedded = your app IS a node with its own identity; sidecar = drive the user's existing daemon; point to `mcpmesh-local-api` for the latter); (2) the quickstart below; (3) the root-dir layout + "a node root is a valid `--profile` dir"; (4) the contract notes: `mcpmesh-local/1` is the API (link `docs/local-protocol.md`), multi-thread runtime required, the iroh exact-pin rule (use `mcpmesh_net::iroh`, never your own iroh dep), tracing/crypto-provider notes from the spec's hygiene section, `StartError::DataDirInUse` semantics (one node per root; a CLI daemon is unaffected — different root). Quickstart (also goes in `node/src/lib.rs` as a `no_run` doctest):

```rust
let node = mcpmesh_node::NodeBuilder::new("/var/lib/myapp/mesh").start().await?;
let mut control = node.control().await?;
control.register_service(
    "notes",
    mcpmesh_local_api::BackendSpec::Run { cmd: vec!["my-mcp-server".into()] },
    vec![],
).await?;
let invite = control.invite(vec!["notes".into()]).await?;
println!("send this to a friend: {}", invite.invite_line);
```

- [ ] **Step 2: Pointers.** README: one short "🦀 Embedding in Rust" section after the AGENTS.md callout, linking `docs/embedding.md`. AGENTS.md: one line noting in-process embedding exists for Rust consumers (link). `local-api/src/lib.rs` crate doc: one sentence — "to RUN a node in-process instead of driving a daemon, see `mcpmesh-node`". RELEASING.md: the five-crate lockstep becomes six (`mcpmesh-node` publishes after `local-api`, before `mcpmesh`); update Formula/publish ordering text accordingly. `node/src/lib.rs`: fold the quickstart into the crate docs as `no_run`.

- [ ] **Step 3: Verify** — `cargo test --workspace` (doctests included) green; clippy clean; `cargo doc --workspace --no-deps` warning-free.

- [ ] **Step 4: Commit** — `git commit -am "docs: embedding guide — mcpmesh-node joins the release train"`

---

## Self-Review (performed at write time)

- **Spec coverage:** extraction (T2–T5) ✓; injected paths/no-env (T6) ✓; in-memory control both halves (T7–T8) ✓; builder/handle/typed errors incl. `DataDirInUse` (T9) ✓; library hygiene (flock/exit stay in shell T5, crypto note T9/T12, tracing/runtime docs T12) ✓; loopback e2e with SAS (T10) ✓; CLI tests as regression net (every task's gate) ✓; parity guard (T11) ✓; release-train + docs (T12) ✓. Spec's `wait()`-on-fatal-death and `data_dir`-named builder input are consciously narrowed — see Declared Deviations.
- **Placeholders:** the `/* */` bodies in T9 Step 4 are deliberate same-crate field wiring with the source location named (control.rs `shutdown` verb handler); T10 names the exact donor tests for the session frames. No TBDs.
- **Type consistency:** `NodePaths` fields match between T6 and T9; `serve_control_io`/`connect_control_io` signatures match between T7, T8, and T9's `control()`; `StartError::DataDirInUse` matches T9's test; `BackendSpec::Run { cmd }` verified against `protocol.rs:736`.
