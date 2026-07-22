# Embeddable full node: `mcpmesh-node` — design

**Date:** 2026-07-22
**Status:** Approved (design); implementation plan to follow

## Problem

Rust consumers who want mcpmesh functionality inside their own application currently must run
the `mcpmesh` daemon as a sidecar process and drive it over the local control socket via
`mcpmesh-local-api`. There is no supported way to link the node itself into a Rust binary.
Everything that makes a process a mesh node lives in the `cli` crate, whose `lib.rs` explicitly
disclaims SDK support.

## Goal

A supported, in-process ("static library" — an ordinary Rust crate/rlib; no FFI) embedding of a
**full-parity** mesh node, alongside the existing CLI/daemon/sidecar approaches, which must keep
working unchanged.

## Decisions (settled during design)

1. **Scope: full node.** The embedding app IS a mesh node — identity, serving MCP backends,
   invite/pair, allowlist, dialing peers — with **full feature parity** with the daemon
   (roster/org install, gossip presence, blobs, audit, staleness severing).
2. **State model: isolated identity.** The embedded node takes an explicit data/config
   directory and is its own mesh identity (own device key, own pairings). It never touches the
   uid-default state dir, never takes the per-uid flock, and coexists freely with a CLI daemon
   on the same machine. Peers pair with the app itself.
3. **Approach: extract a node crate whose embed API is the existing control protocol.**
   Full parity is achieved by construction, not by maintaining a parallel API: the embedded
   node serves the already-supported, already-versioned `mcpmesh-local/1` vocabulary over an
   in-memory transport, using the same handler code the daemon uses. (A typed object API was
   considered and rejected for v1 — it doubles the supported surface; it can be layered later
   as thin sugar. Blessing the `cli` crate as a library was rejected — embedders would inherit
   the binary's dependency tree, and bin+lib feature-gating ages badly.)

## Architecture

New workspace member `node/` → crate **`mcpmesh-node`**, between the infrastructure crates and
the shell:

```
codec ─┐
net  ──┼→ local-api → node → cli
trust ─┘
```

**Moves from `cli` into `node`:** `daemon/*` (accept loop, boot core, dial, handlers, reach,
roster_install, status, config_write), `allowlist`, `backends`, `pairing`, `roster`, `audit`,
`blobs`, `limits`, the daemon config model (`config`), and the control dispatch
(`control::DaemonState`).

**Stays in `cli`:** the clap tree, porcelain/render/json output, `doctor`, the `connect` stdio
proxy, `client.rs` (`ensure_daemon`), `enrollcmd`, completions/man. The daemon subcommand
becomes a thin shell — per-uid flock + uid-default path resolution + unix-socket/named-pipe
bind — wrapped around the same `Node` the embedder gets. One implementation; parity cannot
drift.

## Public API surface (the semver commitment)

Deliberately tiny:

- **`NodeBuilder`** — everything injected, nothing read from the environment: `data_dir`
  (device key, `state.redb`, config), services/backends, limits, optional roster URL. A
  `from_config_dir()` loader accepts the same TOML the daemon reads.
- **`Node`** — `start()`, `shutdown()` (graceful sever + task teardown), `endpoint_id()`,
  `wait()` (surfaces fatal background-task death), and the centerpiece:
- **`Node::control() -> ControlClient`** — the same typed client from `mcpmesh-local-api`,
  speaking `mcpmesh-local/1` over an in-memory duplex instead of a socket. Every control verb
  works, including `open_session`, which upgrades the pipe to a raw MCP session exactly as the
  unix-socket path does; the embedder hands the reader/writer pair straight to an rmcp client.

Everything else in the crate is `#[doc(hidden)]` behind the same "not a supported SDK" banner
`cli/src/lib.rs` carries today. The supported contract remains `mcpmesh-local/1` (per
`docs/local-protocol.md`) plus the builder/handle above. Sidecar consumers of
`mcpmesh-local-api` switch to in-process by changing one constructor.

## Library hygiene (what the extraction must scrub)

- **No env reads** in `node` — `HOME`/`XDG_RUNTIME_DIR` resolution stays in `cli`.
- **No flock, no `std::process::exit`** in library paths. `redb`'s own exclusive file lock is
  the two-nodes-one-dir guard, surfaced as a typed `DataDirInUse` error.
- **Crypto provider:** keep the idempotent `rustls::crypto::ring::default_provider()
  .install_default()` (tolerates a host that installed a provider first); document it.
- **No signal handlers, no tracing subscriber** — the node emits `tracing` events; the host
  owns the subscriber. Runs on the ambient tokio runtime (multi-thread runtime documented as
  required, matching the daemon today).
- The **iroh exact-pin** is documented as an embedder-facing fact (it already is, via
  `mcpmesh-net`): embedders use `mcpmesh_net::iroh` re-exports, never their own iroh dep.

## Error handling

- `Node::start` returns typed construction errors: invalid config, `DataDirInUse`, endpoint
  bind failure.
- Runtime errors keep flowing through the control protocol's existing coded JSON errors — the
  agent-friendly error contract shipped in 0.6.1 is unchanged and becomes the embedder contract
  too.
- Fatal background-task death surfaces via `Node::wait()` rather than a silent zombie.

## Testing

- **Library loopback e2e:** two `Node`s in one process, two temp data dirs, real invite → pair
  → SAS asserted programmatically (the established loopback pattern) → `open_session` over real
  iroh.
- **Existing CLI integration tests run unchanged** — they regression-test both the shell and
  the extraction.
- **Parity guard:** a test asserting the daemon binary and an embedded node report identical
  `stack_version` / `API_VERSION`.

## Versioning & rollout

`mcpmesh-node` joins the lockstep release train (workspace version; publishes with the other
crates — `cargo publish` requires the path deps carry versions, as the workspace already does).

Staged, each stage green and behavior-preserving for existing users:

1. Create the crate; move leaf modules (`allowlist`, `backends`, `audit`, `pairing`, `roster`,
   `blobs`, `limits`, `config`).
2. Move the daemon core + control dispatch; `cli` daemon becomes the shell.
3. Add `NodeBuilder`/`Node` + the in-memory control transport.
4. Library loopback e2e + docs: `docs/embedding.md`, README pointer, AGENTS.md note.

## Out of scope

- A typed object API over the node (possible later as sugar over `control()`).
- Sharing the uid-default identity/state with the CLI daemon, or serving the porcelain control
  socket from an embedded node.
- FFI (`staticlib`/`cdylib`) bindings for non-Rust consumers.
