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
    <root>/data/     state.redb (the peer allowlist), blobs, invites.json
    <root>/state/    audit/   (the append-only audit log)

`data/invites.json` holds pairing invites you have minted that nobody has redeemed yet, so they
survive a restart and honour the expiry the invite line advertises (#87b). It contains **bearer
secrets** and is written `0600` — the same protection the device key gets. Deleting it invalidates
every outstanding invite and nothing else.

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
- **rmcp version — currently a PRERELEASE:** `mcpmesh-net` exact-pins
  `rmcp = "=3.0.0-beta.3"` and implements `rmcp::transport::Transport` on its public
  `NdjsonTransport`, so rmcp is in the public API just as iroh is. Use the
  `mcpmesh_net::rmcp` re-export and never add your own `rmcp` dependency.
  This matters more than the iroh case: Cargo does **not** match a caret requirement
  against a prerelease, so `rmcp = "3"` (or `rmcp = "2"`, which worked before 0.16.0)
  resolves a SECOND rmcp crate. The build then fails at your use site with
  `expected Transport, found Transport` and no version in the message.
  The prerelease is deliberate — it tracks the SDK ahead of the coming MCP spec change,
  and already knows `ProtocolVersion::V_2026_07_28` while still defaulting to the
  `V_2025_11_25` mcpmesh speaks today.
- **Crypto provider:** `start()` installs a process-default rustls `CryptoProvider`
  (ring) only if none is installed — idempotent; a host that installed its own first wins.
- **Tracing:** the node emits `tracing` events and never installs a subscriber — the
  host owns telemetry.
- **Versioning:** `mcpmesh-node` rides the release train (all crates version-lockstep);
  `mcpmesh_node::VERSION` is the stack version peers see in `status`.

## Attributing a payload that outlives its connection (`sign_app`, #59)

mcpmesh authenticates the **transport**. Inside a session, `_meta["mcpmesh/peer"]` tells your
service who is calling — exactly right for request/response, and no help at all for a payload that
outlives the connection it arrived on.

Anything store-and-forward hits this: offline delivery, an always-on relay, a mailbox, an app-level
gossip overlay. The bytes reach you from someone other than their author, so the transport
authenticated the **forwarder**, not the **origin**.

`Node::sign_app` signs with the node's own device key — the same identity `endpoint_id()` reports
and the transport already proves — so attribution needs no second keypair, no second
backup/revocation story, and no binding protocol tying the two identities together.

```rust
const DOMAIN: &[u8] = b"myapp/chat-message/1";

// Author's node, once, when the message is created:
let sig = node.sign_app(DOMAIN, payload);

// Any recipient, however the bytes got there — needs only the author's endpoint id:
if mcpmesh_node::Node::verify_app(&author_eid, DOMAIN, payload, &sig) {
    // these bytes were produced by that device
}
```

Three things worth knowing:

- **Pick one `domain` per statement KIND**, not per app. A signature is only as narrow as its
  domain, so sharing one between "a message" and "a delivery receipt" lets either be read as the
  other. The domain is covered by the signature, and the boundary between it and the message is
  length-prefixed, so no choice of one can be made to look like a different split of the two.
- **mcpmesh's own signing domains are out of reach**, whatever you pass. The preimage carries a
  fixed `mcpmesh/app-sig/1` prefix your `domain` sits inside, so a caller — including a peer that
  influences the bytes you sign — cannot steer `sign_app` into emitting a device binding or an
  endorsement. This is a property of the preimage, not of your discipline.
- **It answers "which device", not "was that device allowed to say this".** Authorization stays
  yours, answered from your own state. `verify_app` returns `false` for anything malformed and
  never panics — every input is attacker-supplied by construction.

`verify_app` is an associated function: verification needs no running node, so a consumer can check
a stored payload without one.

Signatures survive restarts and process exits — the device key lives under the node's root
directory, so a mailbox full of payloads signed by long-gone processes stays attributable.
