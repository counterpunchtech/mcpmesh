# Embedding mcpmesh in a Rust application

Two supported ways to build on mcpmesh from Rust:

- **Sidecar** — your app drives the user's *running* `mcpmesh` daemon over its local
  control endpoint. Depend on [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api):
  it links no networking stack at all, and you share the user's existing identity and
  pairings. Right when mcpmesh is *the user's* tool and yours is one client of it.
- **Embedded** — your app IS a mesh node, in-process, with no `mcpmesh` binary anywhere.
  Depend on [`mcpmesh-node`](https://docs.rs/mcpmesh-node). Right when the mesh is an
  implementation detail of *your* product: your app owns its own identity, serves its own
  MCP backends, and pairs with peers itself.

Both speak the same protocol: the embedded node's `control()` returns the **same
`ControlClient`** the sidecar model uses — the [`mcpmesh-local/1`](local-protocol.md)
vocabulary — so code written against one moves to the other by swapping a constructor.

## Quickstart

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

The friend redeems with any mcpmesh — `mcpmesh pair …`, or their own embedded node's
`pair` verb — and from there every control verb works exactly as documented in
[`docs/local-protocol.md`](local-protocol.md): `status`, `open_session` (a live MCP byte
pipe you can hand to an MCP client library), `subscribe` (live telemetry), roster/org
verbs, blob grants, the audit summary. Full parity is structural: the embedded node runs
the daemon's own handlers.

## The root directory

`NodeBuilder::new(root)` takes ONE directory that holds the node's whole world:

    <root>/config/   config.toml, device.key, user.key, roster.json
    <root>/data/     state.redb (the peer allowlist), blobs
    <root>/state/    audit/   (the append-only audit log)

- The layout is identical to a `mcpmesh --profile <root>` profile dir — handy for
  debugging: point the CLI at your app's root (while your app is stopped) and inspect it.
- **One node per root.** A second `start()` on a live root returns
  `StartError::DataDirInUse` (enforced by redb's exclusive database lock).
- The embedded node is an **isolated identity**: its own device key, its own pairings.
  It never touches the per-user daemon's state, socket, or singleton lock — your app and
  a running `mcpmesh` daemon coexist freely.
- `NodeBuilder::config(Config)` injects configuration programmatically instead of reading
  `<root>/config/config.toml`; the type is the same schema as the file
  ([`docs/config.md`](config.md)). Config-persisting verbs (a non-ephemeral
  `register_service`, pairing grants) still write the file.

## Host-application contract

- **Runtime:** a multi-thread tokio runtime; the node spawns its serving loops onto it.
  `Node::shutdown()` stops them and closes the endpoint gracefully; dropping the `Node`
  does not.
- **iroh version:** `mcpmesh-node` exact-pins iroh (via `mcpmesh-net`). Never add your
  own `iroh` dependency — use the `mcpmesh_net::iroh` re-export; a floating requirement
  is a different crate to the type system and breaks the build.
- **Crypto provider:** `start()` installs a process-default rustls `CryptoProvider`
  (ring) only if none is installed — idempotent; a host that installed its own first wins.
- **Tracing:** the node emits `tracing` events and never installs a subscriber — the
  host owns telemetry.
- **Versioning:** `mcpmesh-node` rides the release train (all crates version-lockstep);
  `mcpmesh_node::VERSION` is the stack version peers see in `status`.
