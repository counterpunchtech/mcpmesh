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

## Roster mode from an embedded node (`api_minor >= 46`, #66/#93)

Roster mode gives you managed group membership signed by an org root, instead of per-peer pairing.
Both halves of it are now on the control API, so an app can run the whole thing — including an
"approve this person" button — without shipping the `mcpmesh` binary alongside itself.

**Authoring** (the operator's node):

```rust
let mut ctl = node.control().await?;

// One-time per node. Show org_root_fingerprint to your operator — it is what every joiner
// reads back out-of-band, and the only thing anchoring their trust in the org.
let org = ctl.org_create("acme", Some(365 * 86_400), None).await?;

// A joiner sends you their join code. INSPECT it first — this verifies the binding and
// returns the fingerprint, without approving anything.
let seen = ctl.org_join_code(&join_code).await?;
show(&seen.display_name, &seen.requested_user_id, &seen.join_code_fingerprint);

// Nothing in a join code binds it to a person, so a substituted one is caught by the two
// humans comparing that fingerprint out-of-band — before this call, not after.
let approved = ctl.org_approve(&join_code, vec!["eng".into()], None).await?;

// Three readings; `mode` tells you which one you got.
ctl.org_revoke("alice", false).await?;          // person departs — devices revoked
ctl.org_revoke("alice/laptop", false).await?;   // one device
ctl.org_revoke("alice", true).await?;           // key ROTATION — devices stay usable
```

**Reading** (any member's node):

```rust
let members = ctl.roster_members().await?;
for user in &members.users {
    println!("{} ({}) in [{}]", user.display_name, user.user_id, user.groups.join(", "));
}
```

Three things worth knowing:

- **Inspect before you approve.** `org_join_code` exists so an approve button can show who is
  asking and, crucially, the fingerprint to confirm — *before* the member lands in the signed
  roster. The same words come back on the approval result, but by then declining means revoking.
  The claims (`display_name`, `requested_user_id`, `device_label`) are chosen by the sender: render
  them, do not trust them. The binding is verified either way, so a forged code is refused.
- **A `user_id` may not contain `/`.** It would collide with the `<user_id>/<device>` revoke
  grammar, and the id defaults to one the person being approved chose — so `org_approve` refuses
  it. Pass an explicit `user_id` to override.
- **`roster_members` is not `status.presence`.** That one lists reachable *devices* and omits a
  person entirely when none of theirs is up. This is the member list — everyone the roster carries,
  with `online` per device, so one read draws both. It reads the same validated view the trust gate
  resolves against, so a **revoked device is absent**, not shown as merely offline.
- **`org_join` may need a restart.** Roster mode is decided at boot: it fixes the ALPNs bound on the
  endpoint and whether gossip, presence and app-blobs are constructed at all. A node that started in
  pairing mode and then joins an org reaches a state where sessions to org members work while
  presence stays permanently empty. `OrgJoinResult::restart_required` says so — surface it, don't
  treat it as a failure. The pin is durable; the restart is all that is missing.
- **The 90-day roster expiry is an operator default, and a sharp edge for a small group.** Past it
  the roster degrades and the group stops working — which for a handful of laptops can arrive days
  after one was closed for a long weekend. Pass a long `expires_secs` to `org_create` deliberately.

Not yet available: **org root rotation** (#93c). An operator machine that dies takes the org with it
once the roster expires, so back up `<root>/config/org-root.key` alongside `roster.json` — copying
both to a second operator machine works today.

## Your own protocol on the node's endpoint (`accept_protocol`, #67)

mcpmesh has already built the hard parts of a P2P application platform — identity, pairing, a trust
gate, relay fallback, discovery, rate limiting, a connection registry — and exposes one protocol
shape on top: request/response MCP over bi-streams. Anything that does not fit (realtime media
wanting datagrams, efficient bulk transfer, an app-level overlay) used to be out of reach however
well the identity layer suited it.

The alternative was a second iroh endpoint with a second identity, which discards the gate, the
pairing relationship and the relay config — and makes your users pair twice.

```rust
use mcpmesh_node::iroh;                      // ← always this re-export, never your own dep

#[derive(Debug)]
struct MyProto;

impl iroh::protocol::ProtocolHandler for MyProto {
    async fn accept(&self, conn: iroh::endpoint::Connection)
        -> Result<(), iroh::protocol::AcceptError>
    {
        // conn.remote_id() is the AUTHENTICATED peer — the same identity the MCP path injects.
        let (send, recv) = conn.accept_bi().await?;
        // …your protocol…
        Ok(())
    }
}

node.accept_protocol(b"app/myproto/1", std::sync::Arc::new(MyProto))?;

// The client half. `peer` resolves exactly as `open_session` resolves it — a paired nickname,
// a `b64u:` user_id, or an `eid:` principal.
let conn = node.connect_protocol("alice", b"app/myproto/1").await?;
```

Four things worth knowing:

- **Your handler runs behind the same gate as every built-in protocol.** An unauthorized or revoked
  peer is closed *before* `accept` is called, and the connection is entered in the registry — so
  revoking that peer **severs it mid-protocol** rather than waiting for it to end. That inheritance
  is the whole reason to use this rather than your own endpoint.
- **mcpmesh's own ALPNs are refused**, and that is more than the `mcpmesh/` prefix: two built-ins
  are named by their upstream crates (`/iroh-gossip/1`, `/iroh-bytes/4`). The accept loop dispatches
  all of them by exact ALPN *before* consulting your registry, so a handler on one would be silently
  dead. The whole `mcpmesh/` namespace is reserved on top, so a protocol mcpmesh adds *later* cannot
  turn a working registration into a dead one on upgrade. `app/…` is the suggested convention.
- **You do not inherit a rate limit.** The pair, ping and blob arms each meter admission; this one
  does not, so an *authorized* peer can churn connections as fast as it likes (the same shape the
  MCP arm has, where metering is per request). Impose a bound in your handler if you need one.
- **Registration takes effect for connections negotiated from now on.** ALPN is chosen at handshake,
  so a peer already connected cannot use the new protocol. Register during startup, before you
  announce the node as ready.
- `connect_protocol` **dials; it does not authorize**. The remote side's gate decides whether to
  admit you, and closes the connection if you are not paired with them.

`Node::endpoint_addr()` gives this node's currently-dialable address if your application has its own
out-of-band channel and does not want a pairing invite. It authorizes nothing — a peer dialling it
still faces the gate.

## Holding the device key yourself (`device_key`, #85)

By default the device key is 32 raw ed25519 secret bytes at 0600, in a directory the node owns — no
passphrase, no keychain, no hardware seam. You could not change that from outside: the file lives
inside the mesh root you are told not to hand-write, and nothing accepted a decrypted key at boot.

```rust
use mcpmesh_node::mcpmesh_trust::ed25519_dalek::SigningKey;   // ← the re-export, not your own dep

let signing = SigningKey::from_bytes(&secret_from_your_keychain);
let node = NodeBuilder::new(root).device_key(signing).start().await?;
```

**When set, no DEVICE key file is read, minted, or written** — so that secret never lands on disk,
and the node cannot silently fall back to a file key (which would boot happily under a *different*
identity, leaving every paired peer unable to reach it).

It covers the device key only. The node still mints `<root>/config/user.key`, the pairing-identity
key — #85 asks 2–3 are about that one and are not shipped.

**Custody moves to you.** mcpmesh cannot recover this identity if you lose the key — there is no
escrow and no recovery path today (#85 asks 2–3). It is also the identity every peer pinned at
pairing, so replacing it makes this node a stranger to all of them. Pass the **same** key on every
restart of the same node; a fresh one mints a new identity each boot.

## Supplying your own peer resolver (`add_address_lookup`, #68)

Peer resolution otherwise depends on external infrastructure — the pkarr publisher/resolver a relay
provides, or an address someone already handed you in an invite. **Two machines on the same LAN with
no internet cannot find each other**, even though the network path between them is fine. That is the
scenario where "peer to peer" earns its keep: a boat, a workshop, a failed uplink, a deliberately
air-gapped network. It is also the common weaker case — a home or office LAN where the internet is
merely flaky, and peers that could talk directly fail to resolve because resolution goes out first.

iroh 1.0.3 ships **no** mDNS or local-swarm lookup (that existed in 0.x and is not present here), so
mcpmesh cannot simply switch one on. What it can do is stop the resolver set being closed:
`iroh::address_lookup::AddressLookup` is a public, pluggable trait, so an implementation can live
outside this crate.

```rust
use mcpmesh_node::iroh::address_lookup::{AddressLookup, EndpointData};

#[derive(Debug)]
struct MyMdns;

impl AddressLookup for MyMdns {
    fn publish(&self, _data: &EndpointData) { /* announce on the LAN */ }
    // `resolve` defaults to None; implement it to answer queries.
}

node.add_address_lookup(MyMdns)?;
```

**It publishes, not only resolves.** iroh hands your service this node's own `EndpointData` — its
direct IP addresses, LAN *and* public — synchronously inside `add_address_lookup`, and again on
every address change. That happens whether or not you implement `publish`: the default is a no-op
*you* own, so a lookup that grows one later, or a dependency's lookup you pass through, starts
announcing them. This is outside `[network].discovery_urls`' scope — an operator who pinned that so
publication never leaves their infrastructure has no say over what you add here. The node's address
filter still applies, so a relay-only posture hands over relay-only data.

**Its answers are attacker-controlled input.** A resolver on an untrusted LAN is fed by whoever is on
that LAN. They cannot impersonate a peer, but they can steer a dial — make your node handshake at an
address of their choosing, revealing that it is looking for peer X, or return a relay URL that routes
metadata through them. Validate what your implementation accepts.

- **Additive, never authoritative.** Your lookup is consulted alongside whatever the node already
  has; `add` appends and every service is queried, so adding one cannot remove relay-based
  resolution.
- **Resolution authorizes nothing.** A misdirected dial cannot complete against the wrong peer —
  iroh's TLS verifier rejects any server whose key is not the `EndpointId` the dial named. A peer
  found this way then faces the trust gate exactly as one found any other way: resolution answers
  *where*, never *who may*.
- **Takes effect for dials from now on.** A dial already in flight is not re-resolved.
- **A panic in your `publish` propagates out of `add_address_lookup`** — it is called synchronously.

**An in-tree mDNS implementation behind `[network].local_discovery` is still open** (#68). This is
the seam that unblocks writing one outside; it is not the discovery itself.

## Recovering a person's identity on new hardware (#85 ask 2)

A person's `b64u:` user id is what peers pin, kb audiences key on, and a roster names. It lives in
one file on one machine. Before this, replacing a laptop destroyed it — the new machine mints a
fresh user key, presents a new `b64u:`, and is a stranger even to peers that had pinned the old one.

```rust
let out = ctl.user_key_export().await?;      // 33 words + the user_id they restore
show_once(&out.recovery_phrase);

// …on the new machine:
let restored = ctl.user_key_import(&phrase, /* replace */ false).await?;
assert_eq!(restored.user_id, expected);       // check it — see below
```

CLI: `mcpmesh identity export`, and `… | mcpmesh identity import` (pipe it; an argument is visible
in `ps` and lands in shell history).

- **The phrase IS the private key**, not a password over one. Show it once, to its owner. It is
  deliberately absent from the audit log, from `status`, and from every other surface — the export
  response is the only place it exists. The *event* is audited; the phrase is not.
- **Check the returned `user_id`.** The phrase carries a checksum, so a mistyped word is refused
  rather than silently restoring a *different* identity — but that failure is invisible if it ever
  happens, because it looks exactly like every peer having forgotten you. The `user_id` is the
  definitive check.
- **`replace` is only needed for a key the node loaded from disk.** A key its own boot minted
  seconds earlier is not an identity anyone has seen, so a genuine new-machine recovery does not
  need the destructive flag. `replaced: true` in the result means a *real* identity was discarded.
- **It does not get this device admitted by anyone.** Peers authorize per **device**, and a restored
  user key puts this endpoint in nobody's allowlist. You still pair — or enroll this device from
  another one you still hold (`invite --as-self`), which a recovered machine can also *initiate*.
- **In roster mode it desyncs you from the roster**, which pins the device→user binding against the
  key that was current when the operator approved this device. Nothing re-signs; an operator must
  re-approve.

Not shipped: a device attestation so a peer admits a replacement device without a fresh SAS, and
pairing-mode revocation (#85 asks 3 and 4). Restoring the identity is not the same as restoring
access, and this is only the first half.
