# mcpmesh: MCP over P2P — serve and consume MCP servers across authenticated peer-to-peer connections

**Technical Design Specification**

| | |
|---|---|
| **Version** | 0.5 |
| **Date** | 2026-07-03 |
| **Status** | M0–M4 implemented — the platform MVP is complete: M1 MCP echo over iroh, M2 the serve · invite · pair · connect hero flow, M3 roster mode, M4 blobs/audit/hardening/doctor/packaging. §16 tracks per-milestone scope and acceptance criteria. |
| **Audience** | Implementing engineer(s) |
| **Supersedes** | 0.4/0.3/0.2 (this file's git history) and an earlier draft 0.1 — see Appendix C |
| **Companions** | Separate specs (not part of this repository) cover the platform's first consumers — a desktop host shell and a knowledge-base plugin daemon. This spec stands alone; those references are context, not dependencies. |
| **Name** | `mcpmesh` (binary: `mcpmesh`; crates: `mcpmesh-codec`, `mcpmesh-net`, `mcpmesh-trust`, `mcpmesh-local-api`) |
| **Renamed** | 2026-07-13: the platform was renamed `mcp2p` → `mcpmesh` everywhere — ALPNs, signed-document domains/formats, invite prefix, local-API id, filesystem paths, env vars, crates, binary. Breaking by design (no compatibility shims); existing meshes must re-pair. |

---

## 1. Overview

### 1.1 Purpose

The Model Context Protocol has a locality problem: an MCP server runs either on your own machine (stdio) or behind someone's HTTPS deployment. There is no good story for *"my AI client uses an MCP server running on your laptop"* — the machine is behind NAT, has no domain, no TLS certificate, and no auth stack, and standing up cloud infrastructure to bridge two laptops defeats the point of local-first tools.

mcpmesh solves exactly that: **serve any MCP server over an authenticated, end-to-end-encrypted peer-to-peer connection, and mount any peer's served MCP server as if it were local.** Iroh provides transport, NAT traversal, encryption, and cryptographic peer identity ("dial a public key"). MCP passes through verbatim — any MCP-speaking client or server works unmodified.

mcpmesh is **domain-agnostic by charter**. It knows nothing about what the MCP servers it carries actually do. Domain solutions — federated search, shared knowledge bases, team tool hubs — are separate projects built on top. The first such consumer is the knowledge-base application specified in the companion document; it validates every extension point this spec defines, and nothing in this spec exists that it (or the §1.5 hero flow) does not exercise. That extraction discipline is the guard against designing a platform for imaginary consumers.

### 1.2 Goals

- **G1**: A user can expose any local MCP server (stdio command or long-running local endpoint) to named peers over a direct, E2EE p2p connection, with no server infrastructure on the data path.
- **G2**: A peer's AI client can mount that served MCP server with one config entry, tools passing through byte-faithfully.
- **G3**: All access is authenticated (cryptographic device identity), authorized (default-deny, per-service), and audited (local append-only log).
- **G4**: Two people can connect **ad-hoc** with a one-time pairing code — no administrator, no shared infrastructure (pairing mode).
- **G5**: Teams can manage identity centrally — people, devices, groups, revocation — via a signed org roster (roster mode).
- **G6**: Works across NATs, home networks, office networks, and laptop sleep/wake.
- **G7**: Applications with domain semantics (identity-aware serving, fan-out, large-content transfer) can build on a small, stable Rust library API without forking the platform. *Scoped to what ships:* the reusable libraries are `mcpmesh-codec`/`-net`/`-trust`/`-local-api` — echo-level serving over one's own endpoint (`serve`/`connect` + `TrustGate`), roster/key/binding primitives, and the local-API client. Pairing, the production gates, roster distribution, and the gated blob provider live in the `mcpmesh` binary crate; a daemon-library split is deferred until a real standalone embedder exists (co-resident apps — the only consumers to date — use `mcpmesh-local/1` instead, per §3.1).

### 1.3 Non-goals (v1)

- **NG1**: Domain semantics of any kind — search, indexing, content models, result aggregation, provenance rewriting. These belong to applications (see companion spec).
- **NG2**: Modifying, filtering, or "sanitizing" proxied MCP payloads. The platform guarantees *who* you are talking to, never *what* they say (§11.1).
- **NG3**: Cross-org federation in roster mode. One roster, one org root key.
- **NG4**: Mobile clients. Desktop/server (Linux, macOS) only in v1; Windows is Q5.
- **NG5**: Preventing exfiltration of already-served content. A peer that legitimately called your tools has the results; revocation is forward-looking only.
- **NG6**: A remote-write or push channel. The served surface is whatever the underlying MCP server exposes; the platform adds no server-initiated messages of its own.

### 1.4 Summary of the design

One Rust daemon (`mcpmesh`) per machine owns a single Iroh endpoint (one device identity) and performs two roles:

1. **Serving** — a registry of named **services**, each backed by a local MCP server (spawned per-session stdio child, or a long-running local socket). Inbound Iroh connections on ALPN `mcpmesh/mcp/1` pass an accept-time **trust gate**; a session then selects a service at `initialize`, is checked against that service's allowlist, and is piped to the backend. Caller identity is injected for backends that want it (§6.3).
2. **Connecting** — `mcpmesh connect <peer>/<service>` is a stdio MCP proxy (what AI clients invoke) that dials the peer, opens a session to the named service, and passes MCP through transparently. One proxy per mounted service; the platform adds no tools of its own.

Trust comes in two modes sharing one enforcement path: **pairing** (local allowlist built from one-time invite codes; identities are device-level petnames) and **roster** (org-signed document mapping people → user keys → device keys → groups). Large-payload transfer for platform-aware applications is provided by an optional **blob sidecar library** (iroh-blobs behind the same trust gate). Presence and roster distribution use iroh-gossip in roster mode only.

### 1.5 Design tenet: a small, human surface

The complete exposed surface is **five items**. If a concept is not on this list, no user, operator, AI model, or developer should need to know it exists:

| # | Surface | Audience | Contents |
|---|---|---|---|
| 1 | CLI porcelain (§1.6) | Users & operators | 11 verbs (6 in pairing-only use). Everything else hides under `mcpmesh internal …`. |
| 2 | Invite / pair / join codes | Humans, out-of-band | Opaque one-line strings exchanged over chat or QR. The only artifacts a human copies. |
| 3 | Service definitions | The person serving | A name, a command (or socket), and who's allowed. Three keys in a TOML table, or one `serve` flag. |
| 4 | Library API (§3.1) | Rust developers (standalone embedders) | `serve`/`connect` + a `TrustGate` trait + blob helpers. |
| 5 | Local control API `mcpmesh-local/1` (§6.1) | Local integrators (host shell, plugin daemons, tooling) | Versioned UDS API: trust ops, service management, sessions/blobs on behalf of co-resident apps, status/events — anything the porcelain can do. |

**The AI-facing surface is deliberately empty**: a mounted peer service presents the remote server's own tools, unchanged. mcpmesh introduces zero tool vocabulary.

**Deliberately hidden** (present in this spec, absent from every user-facing surface): EndpointIds, device/user/org keys, roster JSON and serials, ALPNs, QUIC streams, framing limits, blob hashes and tickets, gossip topics, relays and discovery. They appear only in `--verbose` diagnostics and `mcpmesh doctor`. This list is the **canonical transport-vocabulary blocklist** for the whole family, materialized as ONE shared test fixture — `local-api/fixtures/transport-vocabulary.json` — that the surface-leak suites load; additions land there first. One deliberate carve-out: key material rendered as short trust-ceremony fingerprints (wordlist form, never raw key bytes) appears in pairing/join/status surfaces (§4.2, §4.4).

**What day one looks like — pairing mode (the hero flow).** Alice shares her notes server; Bob mounts it:

```
alice$ mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes
Serving "notes". Invite someone: mcpmesh invite notes

alice$ mcpmesh invite notes
One-time invite (expires 24h):  mcpmesh-invite:7-tangerine-castle-…

bob$   mcpmesh pair mcpmesh-invite:7-tangerine-castle-…
Paired with alice — code: tango-fig-42 (Alice sees the same code). You can mount: alice/notes

bob$   mcpmesh setup claude alice/notes
Claude Desktop configured: tools from alice/notes will appear as "alice-notes".
```

Four commands total across two people, and none of them mention keys, NATs, or certificates. **Roster mode** layers team management on the same machinery: `mcpmesh org create` → `mcpmesh join <invite> ` → `mcpmesh org approve <join-code> --groups team-eng`, after which service allowlists can name groups (`allow = ["team-eng"]`) instead of individuals.

### 1.6 CLI surface

Porcelain (stable, documented, tab-completed):

| Command | Does | Mode |
|---|---|---|
| `mcpmesh serve <name> -- <cmd…>` | Register + start serving a service (persisted to config; `--allow` to scope) | both |
| `mcpmesh invite [service…]` | Mint a one-time pairing code granting the named services | pairing |
| `mcpmesh pair <invite>` | Redeem an invite; mutual allowlist entries are exchanged in-band | pairing |
| `mcpmesh setup <client> <peer>/<service>` | Write the AI-client config entry (`--print` to just show it) | both |
| `mcpmesh status` | Serving what, to whom; reachable peers; trust freshness. Plain language. | both |
| `mcpmesh doctor` | Lints: unreachable backends, stale roster, key permissions, relay reachability | both |
| `mcpmesh org create <name>` | Mint org root key + empty roster; print org invite code | roster |
| `mcpmesh org approve <join-code> --groups …` | Verify + add member, bump serial, sign, publish | roster |
| `mcpmesh org revoke <person\|device>` | Revocation (§4.6), incl. user-key rotation flow | roster |
| `mcpmesh join <org-invite>` | Generate keys, pin org root, print join code | roster |
| `mcpmesh devices add <device-code>` | Bind another machine to your identity; keys never move between machines | roster |

`mcpmesh connect <peer>/<service>` is what `setup` writes into AI-client configs — invoked by clients, rarely typed by humans. Plumbing lives under `mcpmesh internal …`: `daemon`, `audit`, `roster install`, `org backup`/`restore`. The daemon needs no lifecycle management: `connect`, `serve`, and every porcelain verb auto-start it via the socket (§6.1); `setup` offers an optional launchd/systemd-user unit so serving survives logout.

There is deliberately **no** generic `mcpmesh call`/`mcpmesh search` CLI in v1 — invoking tools is the AI client's job; a second client surface doubles the testing matrix for no new capability.

---

## 2. Glossary

| Term | Definition |
|---|---|
| **Service** | A named MCP server exposed by an endpoint, e.g. `alice/notes`. The unit of serving and authorization. |
| **Backend** | What answers a service's sessions: a spawned stdio child process (`run`) or a long-running local MCP server on a Unix socket (`socket`). |
| **EndpointId** | Iroh's stable cryptographic identity for one device: the public half of an Ed25519 keypair. What peers dial. |
| **Peer name** | The human handle for a remote identity: the locally-stored petname (pairing mode) or a roster `user_id` (roster mode). In both modes a verified person-level `user_id` may ALSO be present (device→user bindings, D4) — the petname names a device, the `user_id` names the person. |
| **Trust gate** | The accept-time check resolving an inbound EndpointId to a peer identity, or refusing the connection. One trait, two built-in implementations (§4). |
| **Pairing** | Ad-hoc trust: a one-time invite code redeemed by one peer, producing mutual allowlist entries. |
| **Roster** | Roster mode's signed JSON document listing users, devices, groups, and revocations. The org's single source of trust. |
| **User key** | Roster mode: an Ed25519 keypair representing a *person*, binding their devices together. |
| **Org root key** | Roster mode: the operator's Ed25519 keypair that signs rosters. Pinned at join. |
| **Connect proxy** | The stdio process AI clients invoke (`mcpmesh connect …`); a transparent pipe to one remote service. |
| **Blob sidecar** | Optional library mechanism for platform-aware apps to move large content out-of-band via iroh-blobs, behind the trust gate. |
| **MCP** | Model Context Protocol: JSON-RPC 2.0-based protocol for exposing tools/resources to AI applications. |
| **ALPN** | Application-Layer Protocol Negotiation string identifying a protocol on an Iroh/QUIC connection. |

---

## 3. Architecture

### 3.1 Crate layout

```
mcpmesh-codec   The family NDJSON codec (§7.3): FrameReader/write_frame + the
              fixed 16 MiB cap (MAX_FRAME_BYTES). ONE implementation both
              wire ends link — re-exported by mcpmesh-net (framing) and
              mcpmesh-local-api (codec). No iroh. Wire-codec only, by charter.
              (Post-dates 0.5: extracted when the local-api client landed.
              The gated blob provider planned as `mcpmesh-blobs` shipped inside
              the binary — `cli/src/blobs` over iroh-blobs — instead; the
              placeholder crate was removed.)

mcpmesh-net     The kernel: Iroh endpoint management, ALPN constants, session
              establishment incl. service selection, framing strikes, and
              rmcp Transport adapters for both ends of a QUIC bi-stream.
              Public API is deliberately small:
                serve(endpoint, gate, services) -> ServeHandle
                connect(endpoint, peer, service) -> impl rmcp Transport
                trait TrustGate { resolve(EndpointId) -> Option<PeerIdentity> }
                struct PeerIdentity { name, user_id?, groups: Vec<String> }
              Ships one gate: StaticGate (a fixed map, for embedders/tests).
              No knowledge of pairing, rosters, or any domain. (G7)

mcpmesh-trust   Trust PRIMITIVES, no gates and no internal deps: key generation
              and 0600 storage (device/user/org-root), the roster document
              (schema, JCS sign/verify, validation rules, mutations), the
              device→user binding (§4.2), and the shared paths rule (§13).

mcpmesh-local-api  The mcpmesh-local/1 seam (§6.1): protocol types + the ONE §5
              principal-set expansion (both feature-free), a no-iroh UDS
              client (`client` feature), and the plugin-daemon service seam
              (`service` feature: hardened UDS bind, audience expansion,
              self-registration). Re-exports the blob-reference type (§9) so
              co-resident apps never touch iroh-blobs. Consumed by the
              porcelain, the connect proxy, the host shell, and co-resident
              plugin daemons.

mcpmesh (bin)   The daemon + CLI: service registry, backend spawner/dialer,
              the production gates (AllowlistGate over the peer store,
              RosterGate, and the ComposedGate precedence — §4), pairing
              rendezvous, roster distribution, gated blob provider (§9),
              connect proxy, presence (roster mode), audit log, porcelain.
```

Dependency direction (the real crate DAG): `mcpmesh` (bin) → `mcpmesh-trust` + `mcpmesh-net` + `mcpmesh-local-api`; `mcpmesh-net` → `mcpmesh-codec` + `mcpmesh-local-api` (default features — types-only, for the shared §5 principal set); `mcpmesh-local-api` → `mcpmesh-codec` (client feature); `mcpmesh-trust` and `mcpmesh-codec` have no internal deps. Two consumption styles, deliberately distinct: **co-resident applications** (plugin daemons on a machine that runs the mcpmesh daemon, per D3) use only the `mcpmesh-local-api` client — all their networking rides the shared daemon's single endpoint over the UDS; **standalone embedders** (a product that *is* its own endpoint) use `mcpmesh-net`/`-trust` directly (G7, scoped honestly there). The binary has no privileged APIs — everything it does flows through the same crates.

### 3.2 Component diagram

```
┌────────────────────────── Alice's laptop ──────────────────────────┐
│                                                                    │
│   [notes backend]      [kb backend]          Alice's AI client     │
│   (spawned child,      (long-running app,         │ stdio          │
│    per session)         unix socket)              ▼                │
│        ▲                    ▲              [connect proxy] ────┐   │
│        │ stdio              │ UDS (MCP +        (per mounted   │   │
│  ┌─────┴────────────────────┴───────────┐       service)       │   │
│  │            mcpmesh daemon              │                      │   │
│  │  [Service registry]                  │◀──── UDS ────────────┘   │
│  │  [Trust gate: pairs ∪ roster]        │                          │
│  │  [Audit log]  [Presence (roster)]    │                          │
│  │  [Iroh Endpoint — device key, QUIC,  │                          │
│  │   ALPN router, blob provider (gated)]│                          │
│  └──────────────────┬───────────────────┘                          │
└─────────────────────┼──────────────────────────────────────────────┘
                      │ QUIC (hole-punched direct, or via
                      │ relay — always E2EE, mutually authed)
             ┌────────┴────────┬──────────────────┐
             ▼                 ▼                  ▼
        Bob's daemon      Carol's daemon     (any mcpmesh endpoint)
```

### 3.3 Data flows

**F1 — Serving (Bob's AI uses Alice's `notes`):** Bob's AI client runs `mcpmesh connect alice/notes` (stdio) → proxy asks Bob's daemon over UDS → daemon dials Alice's EndpointId, ALPN `mcpmesh/mcp/1` → TLS mutually authenticates device keys → Alice's trust gate resolves Bob → session opens, `initialize` names service `notes` → allowlist check → Alice's daemon spawns the `notes` child (or attaches to the socket backend) and pipes the session → MCP flows verbatim → every request line is appended to Alice's audit log.

**F2 — Pairing:** Alice `mcpmesh invite notes` → daemon mints a single-use secret + a short-lived rendezvous listener on ALPN `mcpmesh/pair/1` → Bob `mcpmesh pair <code>` dials it → both sides verify the invite secret, exchange `{EndpointId, suggested name}`, and write mutual allowlist entries (Bob gains `notes`; Alice gains a dial-back entry with no services unless she grants some). Invite is burned on first redemption or expiry.

**F3 — Roster update (roster mode):** operator publishes serial N+1 (gossip topic + HTTPS fallback) → nodes validate org signature, `serial > current`, atomically swap → revoked identities are disconnected across **all** ALPNs and future dials refused.

**F4 — Blob fetch (platform-aware apps):** app's tool result carries a blob reference (§9) → caller's app asks its daemon to fetch → blob connection passes the same trust gate → provider checks the hash is in a scope granted to that caller → BLAKE3-verified streaming transfer.

### 3.4 Key design decisions (with rationale)

- **D1: MCP verbatim over a custom transport, not a custom RPC.** MCP is JSON-RPC 2.0 and transport-agnostic; carrying it byte-faithfully means every existing MCP client and server works unmodified, and the platform never chases MCP feature releases. The wire protocol (§7) is byte-compatible with MCP's stdio framing.
- **D2: Transparent per-service proxy; no platform aggregation.** Mounting `alice/notes` presents Alice's tools unchanged. Fan-out, merging, reranking, and provenance labeling are domain decisions that belong to applications (the KB app's bridge does all four — see companion spec). The platform adding its own tool vocabulary is how "few primitives" dies.
- **D3: One daemon, one device identity, many services.** Per-machine identity amortizes pairing/enrollment across every service and app on that machine. Applications register as backends rather than owning endpoints, so a user pairs once, not once per app.
- **D4: Transport identity = device identity; person identity layered above.** Iroh's TLS identity *is* the Ed25519 endpoint key — device authentication is free and unforgeable. Person identity comes from a **device→user binding** (a user-key signature over the device's endpoint id, `trust/src/binding.rs`): in ROSTER mode the roster carries it; in PAIRING mode the two daemons exchange and verify bindings during the rendezvous (each daemon auto-mints a self-sovereign user key at boot), so a paired peer ALSO resolves with a verified `user_id` — content shared to a person reaches all their devices without an org. Roster mode's remaining uniqueness is central management: groups, operator-controlled membership, and revocation at scale. Both modes produce the same `PeerIdentity { name, user_id?, groups }` so serving code has exactly one authorization path.
- **D5: Default deny everywhere.** Unknown EndpointId → connection refused before any MCP traffic. Service not in the caller's grants → indistinguishable from nonexistent. Empty allowlist → service is local-only.
- **D6: The platform authenticates peers, never content.** Proxied payloads are not parsed beyond framing, not filtered, not rewritten (NG2): rewriting arbitrary tool results (images, structured JSON) would corrupt them, and a "sanitizing" proxy invites false confidence. Mounting a peer's service is trusting that peer's server, exactly like installing any MCP server — the platform makes the *who* cryptographically certain and keeps the *what* out of scope (§11.1). Content-level containment (provenance wrapping of text it composes) lives in apps. The single enumerated exception to verbatim pass-through is the `initialize` frame's platform-reserved `_meta["mcpmesh/*"]` keys (§6.3) — tested as such (§17).
- **D7: Large content out-of-band, opt-in.** Frames are capped (default 16 MiB) to bound memory, which accommodates ordinary MCP servers inlining screenshots or files. Platform-aware apps that move genuinely large content use the blob sidecar library — behind the same trust gate, with hashes treated as integrity proofs, never as authorization capabilities.
- **D8: Every network-reachable surface sits behind an accept-time gate.** MCP sessions, blob transfers, gossip: one identity trust gate, all ALPNs — revocation severs everything at once. The sole exception is the pairing rendezvous (`mcpmesh/pair/1`), whose gate is by construction possession of a valid unburned invite secret rather than identity: it exists only while an invite is outstanding, precisely so trust can be established with a not-yet-known peer (§4.2).
- **D9: Relay and discovery infrastructure are both configurable.** Iroh's defaults use n0's public relays and DNS/pkarr discovery. Content is always E2EE; what these see is metadata. Orgs with metadata-privacy requirements self-host both: `relay_mode = "custom"` + `relay_urls` (self-hosted iroh relays) and `discovery_mode = "custom"` + `discovery_urls` (self-hosted pkarr relays, used for both publish and resolve). Configuring only one is an incomplete mitigation (§10.3); `relay_mode = "disabled"` is the hermetic mode (no relay, no discovery).

---

## 4. Identity & Trust

Two trust modes, one enforcement path. Both implement `TrustGate` and resolve an inbound EndpointId to `PeerIdentity { name, user_id?, groups }` or refuse the connection. A daemon can run both simultaneously (pairs ∪ roster), with explicit precedence: (1) the composed gate consults the installed roster's `revoked_endpoints` first — a revoked endpoint is refused even if a pair entry exists (revocation wins over pairing, across all ALPNs); (2) an endpoint present in the roster resolves to its roster identity (user_id + groups) even if a pair entry exists — equivalently, pair entries for rostered endpoints are masked while the roster lists them.

### 4.1 Device identity (both modes)

Every machine gets an Ed25519 device key at first run, stored at `~/.config/mcpmesh/device.key` (mode 0600). Its public half is the EndpointId — the machine's dialable, unforgeable address. This is the only mandatory identity artifact.

### 4.2 Pairing mode

State: a local, daemon-owned allowlist — `{ endpoint_id, petname, services: [names], paired_at }` per peer, persisted in `state.redb`.

- `mcpmesh invite [services…]` mints `{ one-time secret, this endpoint's dialable address **and EndpointId**, suggested petname, granted services, expiry ≤ 24h }`, encoded as one `mcpmesh-invite:` line. The secret is a bearer credential: single-use, short-lived, exchanged out-of-band (chat, QR) — interception risk is bounded by those properties, the bindings below, and the human noticing an unexpected "paired" notification (§11, P3).
- `mcpmesh pair <invite>` dials the inviter on ALPN `mcpmesh/pair/1`. The redeemer MUST verify that the TLS-authenticated peer EndpointId equals the invite's (closing address-swap substitution), then proves possession of the secret; the two daemons exchange identities and both display a **short authentication code** (a few words derived from a transcript hash over both EndpointIds + the secret) in the completion notice — "Paired with alice — code: tango-fig-42" — so a whole-invite forgery is catchable by a second-channel human check. Mutual entries are written; the invite is burned. Failed secret verification never burns the invite; attempts are capped (small fixed budget per invite, e.g. 10, after which the invite is invalidated), each attempt logged as a trust event (§11.3), and the rendezvous listener is torn down at burn or expiry.
- Grants are asymmetric and editable: `mcpmesh invite notes` gives the redeemer access to `notes` and gives the inviter a dial-back entry with no service grants (grant later via `mcpmesh serve --allow`).
- Unpair: `mcpmesh org revoke` is roster-mode; pairing mode uses `mcpmesh pair --remove <petname>` (drops the entry, disconnects live sessions).
- **Person identity in pairing mode (D4):** every daemon auto-mints a self-sovereign user key at boot; the rendezvous exchanges each side's **device→user binding** (a user-key signature over the device endpoint id, `trust/src/binding.rs`) and verifies it before storing. A paired peer therefore resolves with a VERIFIED `user_id` alongside its petname — the same `PeerIdentity` shape as roster mode — so person-level grants (§5) and multi-device reach work without an org. An unbound legacy peer simply has `user_id: None`.

No gossip, no presence, no third document: pairing-mode reachability is established by dialing.

### 4.3 Roster mode

For teams. Adds two key layers above device identity:

```
Org root key (Ed25519)               — held by operator; signs rosters
 └── User key (Ed25519, per person)  — binds a person's devices; proves device additions
      └── Device key (Ed25519)       — as §4.1; the TLS identity
```

User keys are generated by `mcpmesh join` on a person's first device. Additional devices: the new machine's `join` prints a device code; `mcpmesh devices add <code>` on an enrolled device signs the binding with the user key (keys never move between machines) and emits the join code for the operator.

**Roster schema (`mcpmesh-roster/1`)** — canonical JSON per RFC 8785 (JCS); `sig` is Ed25519 by the org root over the canonical form with `sig` removed:

```json
{
  "format": "mcpmesh-roster/1",
  "org_id": "acme",
  "serial": 42,
  "issued_at": "2026-07-03T12:00:00Z",
  "expires_at": "2026-10-01T00:00:00Z",
  "groups": ["team-eng", "team-research", "all"],
  "users": [
    { "user_id": "alice", "display_name": "Alice Nguyen", "user_pk": "b64u:…",
      "groups": ["team-eng", "all"],
      "devices": [ { "endpoint_id": "b64u:…", "label": "laptop", "role": "primary" } ] }
  ],
  "revoked_endpoints": ["b64u:…"],
  "sig": "b64u:…"
}
```

Validation rules (all MUST):

1. `sig` verifies against the pinned org root public key.
2. `serial` strictly greater than the installed serial (prevents rollback).
3. `issued_at ≤ now ≤ expires_at` (clock skew tolerance ±10 min).
4. Every `endpoint_id` appears at most once across users, and never both under a user and in `revoked_endpoints` (revocation wins; warn).
5. Group names and `user_id`s draw from a **single flat namespace** and MUST be disjoint — this is what lets service allowlists say `allow = ["team-eng", "bob"]` with no type prefixes.
6. On acceptance: atomically persist; drop live connections (all ALPNs, D8) from endpoints revoked or — among endpoints previously resolved via the roster — absent from the new roster (roster installs never sever pairing-only peers); refresh cached identities.

The device `role` field (`primary` | `mirror`, default `primary`) is an **advisory dial-ordering hint** (§10.1), never a security property — authorization still derives solely from endpoint_id/user_id/groups.

Expiry without replacement → **degraded mode**: existing behavior continues for a grace period (default 72 h) with warnings, then inbound serving stops. A stale roster must not authorize forever.

**Distribution:** gossip topic `blake3("mcpmesh/roster/" + org_id)` carrying `{serial, roster_hash, blob_ticket}` with fetch via iroh-blobs; HTTPS fallback URL polled hourly; manual `mcpmesh internal roster install`. All three converge on the same validation code.

**Publication:** `org approve`/`org revoke` (any serial bump) atomically install the new roster on the operator's node, add it to the operator daemon's blob store, and announce `{serial, roster_hash, blob_ticket}` on the roster topic. Every node that validates and accepts a roster re-seeds its blob and re-announces, so propagation does not depend on the operator staying online. The `[roster] url` is optional operator-managed static hosting; keeping it current after each serial bump is the operator's responsibility — a step in the M4 operator runbook.

**Freshness (normative):** each node tracks `last_confirmed` — the last instant it validated the installed roster as current via an authenticated channel (a successful TLS poll of the pinned roster URL returning serial ≥ installed, a gossip-delivered roster passing full validation, or manual install). If `now − last_confirmed > max_staleness` (`[roster] max_staleness`, default `"24h"`), the node enters the same degraded mode as expiry — warnings, then inbound serving stops after `grace_period`. This bounds adversarial staleness at `max_staleness + grace` (~4 days by default) independent of `expires_at`. Residual: a compromised roster-distribution server can withhold like a network attacker — the remaining reason to keep `expires_at` modest. (Poll-based freshness rather than a signed liveness beacon: a beacon needs frequent org-root signatures, contradicting P4/P5's offline-root requirement; the TLS poll is unforgeable-but-blockable, and blocked fails toward degraded mode, matching D5's default deny.)

### 4.4 Enrollment flow (roster mode)

Two opaque strings and three porcelain commands; keys and signatures never surface.

1. `mcpmesh org create` → org root key + **org invite code** (org_id, root public key, roster URL).
2. `mcpmesh join <org-invite>` → keys generated, root pinned → **join code**. `join` prints the pinned org-root fingerprint in short-word form and instructs the person to confirm it against a value obtained out-of-band (a phished org invite otherwise pins an attacker's root); `mcpmesh status` — and the host Sharing surface, via `mcpmesh-local/1` — display the pinned fingerprint thereafter.
3. Operator verifies the person out-of-band (the human trust ceremony — now bidirectional at zero extra process cost: the operator reads the root fingerprint back while verifying the joiner), then `mcpmesh org approve <join-code> --groups …` → roster serial+1, signed, published.
4. The new node obtains its first roster via the roster URL from the org invite (hourly poll), or `mcpmesh internal roster install` out-of-band when no URL is configured — gossip cannot serve it yet, since it knows no peer EndpointIds before its first roster and peers' gates refuse it until they hold serial N+1 (D5). Once installed, it joins the roster/presence topics via roster-listed peers, and `mcpmesh status` flips to "approved".

### 4.5 Revocation

**Device** (lost/stolen): `mcpmesh org revoke alice/laptop` moves its endpoint to `revoked_endpoints`, serial+1, publish. Connected conformant nodes enforce within 60 s (gossip); one poll interval via HTTPS; under adversarial withholding of both channels, bounded by `max_staleness + grace` (§4.3 freshness rule), never by roster expiry alone. **Person departing:** remove the user entry. **Pairing mode:** `mcpmesh pair --remove`. Honest limitation: revocation stops *future* access only (NG5).

### 4.6 User-key rotation (compromise runbook)

A compromised *user key* lets an attacker bind new devices as that person. Recovery: operator removes the user entirely (severs all devices at once), user regenerates a user key and re-enrolls per §4.4, operator re-approves with the same `user_id` and groups. No new mechanism — the roster already expresses it; `mcpmesh org revoke --user-key alice` wraps the sequence.

---

## 5. Authorization

Authentication answers "which device — and in roster mode, which person — is this?" (§4). Authorization answers "may they open this service?" and happens at exactly two points:

1. **Accept-time (gate):** unresolvable EndpointId → connection closed with QUIC application error `401` before any MCP traffic.
2. **Initialize-time (service check):** the session names a service (§7.2); the daemon checks the resolved identity against that service's `allow` list (petnames, user_ids, group names — one flat namespace). Failure → JSON-RPC error `-32054`, worded identically to "no such service" (existence of unshared services is not disclosed).

**The principal set (normative, one implementation).** A resolved caller's flat authorization identity is `groups ∪ {petname} ∪ {user_id}` (empty components skipped; no identity ⇒ empty set ⇒ default deny). This expansion has exactly ONE implementation — `mcpmesh_local_api::principal_set` (feature-free, dependency-free) — consumed by all three enforcement sites: the mesh service `allow` check (`mcpmesh-net`), the plugin seam's audience expansion (`peer_audiences`), and the blob-scope gate (§9). The petname is a first-class principal at EVERY site, including blob scopes: a pairing-mode peer with no user binding can be granted — and must be admitted — by its petname alone.

There is no per-tool authorization in the platform (a service is the grant unit — split servers into two services if you need two tiers). Rate limits: token bucket per peer identity (default 120 req/min, burst 20, both configurable per service); in-flight cap per session (default 16). Exceeding either → `-32053` with `retry_after_ms`.

Applications needing finer-grained decisions (the KB app's per-group indexes) receive the resolved identity via backend injection (§6.3) and enforce internally — the platform hands them *who*, they decide *what*.

---

## 6. Services

### 6.1 Registry & daemon

Services are declared in config (or via `mcpmesh serve`, which writes config and hot-reloads the daemon):

```toml
[services.notes]
run   = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "~/notes"]
allow = ["bob"]                    # petnames, user_ids, and/or groups

[services.kb]
socket = "<runtime_dir>/kb.sock"   # written by the kb daemon at startup via
allow  = ["team-eng"]              #   mcpmesh-local/1; allow entries are user
                                   #   grants — see kb-mesh §1.4
```

The daemon (`mcpmesh internal daemon`) is auto-started by any porcelain verb or connect proxy via its own UDS (`<runtime_dir>/mcpmesh.sock`, path rule §13) and owns all Iroh state. `mcpmesh setup` offers a launchd/systemd-user unit for serve-while-logged-out.

The daemon's UDS control API (**`mcpmesh-local/1`**) is a **versioned product surface**, not internal plumbing: the porcelain, the connect proxy, the desktop host shell, and co-resident plugin daemons are all ordinary clients of it. Protocol types and the client live in `mcpmesh-local-api` (§3.1); the wire is the same NDJSON JSON-RPC framing as §7.3 — one codec everywhere. Contract:

- **Hello convention (shared by every `*-local/N` API in the family):** the first exchange on the socket identifies `{api name, api semver, stack version}` and the server's capabilities — additive-only changes within a major.
- **Trust & services:** trust operations (invite/pair/join/status), service management — including an application idempotently registering/updating its own `[services.*]` entry — and a status/event stream. Anything the porcelain can do, an API client can do, and vice versa. The person-centric contact ops live here too: `peer_remove` (drop a pairing + its `allow` grants) and `peer_rename` (authoritatively rename a contact — every device sharing a `user_id`, or a single provisional petname — rewriting `[services.*].allow` so grants follow the rename; refuses a collision with a different identity). The host Contacts surface is a pure projection over `status` plus these ops.
- **On-behalf networking (for co-resident apps, D3):** `connect(peer[, device], service)` → session stream (the same operation the connect proxy performs); blob operations — publish/register hashes under a named scope, scope management, fetch-by-reference (§9).
- **Advisory reads:** roster membership (names, groups, device labels/roles only — flat-namespace vocabulary, never keys, serials, or EndpointIds) and per-device reachability/presence, sufficient for an app's primary-vs-mirror fallback; typed audit summaries (session and request counts per peer and per service over a time window, inbound and outbound — the reach-around-compliant source for the host Mesh surface; `mcpmesh internal audit` remains the raw view).

It never exposes raw key material, and the surface-leak suite (§17) applies to its outputs. Its trust model is the P12/P14 boundary: any same-uid client is fully privileged; there is no intra-user privilege separation in v1 (§11.2).

### 6.2 Backends & session lifecycle

- **`run` (spawn):** one child process per inbound session — spawned on session open, stdio piped to the QUIC stream, killed on session close (mirrors how stdio MCP servers are used locally: one process per client). Concurrency cap per service (default 4 concurrent sessions) → excess sessions get `-32053`.
- **`socket`:** the daemon connects to a long-running local MCP server per session (the backend multiplexes its own sessions). For applications that hold warm state — indexes, caches, models.

Crash/exit of a backend mid-session → the QUIC stream is closed; the caller's proxy surfaces a clean transport EOF (AI clients treat it as server exit and can reconnect, which spawns/redials fresh).

### 6.3 Caller-identity injection

Most generic servers neither know nor care who is calling — they get nothing. Backends that opt in receive the resolved identity:

- **`run` backends:** env vars on the spawned child — `MCPMESH_PEER_NAME`, `MCPMESH_PEER_USER` (roster mode), `MCPMESH_PEER_GROUPS` (comma-separated). Zero-code-change friendly.
- **`socket` backends:** the daemon injects `_meta["mcpmesh/peer"] = { "name", "user_id"?, "groups" }` into the `initialize` request it forwards. The local UDS hop is trusted; the backend treats this as authoritative.

**Reserved namespace (normative):** `_meta` keys under `mcpmesh/*` are platform-reserved on the wire. The serving daemon MUST delete all caller-supplied `mcpmesh/*` keys from the inbound `initialize` before acting on it, MUST strip `mcpmesh/service` before forwarding `initialize` to any backend (run or socket), and for opted-in socket backends MUST then set `mcpmesh/peer` itself — a backend only ever sees a daemon-authored value or nothing. This is the single enumerated exception to verbatim pass-through (D6), asserted as exactly-this-and-nothing-else by the transparency suite (§17). Same-uid local processes are inside the trust boundary per P12/P14.

This is the entire identity-awareness contract, and it is what the KB app builds per-group authorization on (companion spec §4).

---

## 7. Wire Protocol: MCP over Iroh

### 7.1 ALPNs & versioning

- MCP sessions: **`mcpmesh/mcp/1`**. Pairing rendezvous: **`mcpmesh/pair/1`**. Blob transfer: iroh-blobs' ALPN wrapped by the gate (§9). All registered on one Iroh `Router`; every accept handler runs the identity trust gate first (D8) — except `mcpmesh/pair/1`, which is registered only while an invite is live and verifies the invite secret before anything else.
- Breaking wire changes bump the trailing integer; nodes MAY register multiple versions during migration. Additive MCP-level changes never bump it — MCP's own capability negotiation covers them.

### 7.2 Connection & session lifecycle

1. Caller dials the EndpointId with ALPN `mcpmesh/mcp/1` (Iroh picks direct hole-punched path or relay; E2EE and mutually authenticated either way).
2. Callee's gate resolves the caller (§4) or closes with app error `401`.
3. Caller opens **one bidirectional stream per session**; a connection may carry several sessions (streams), e.g. two AI clients mounting different services of the same peer over one pooled connection.
4. First frame on the stream is the standard MCP `initialize` request, with `params._meta["mcpmesh/service"] = "<name>"`. Missing `_meta` — or `_meta` without a `mcpmesh/service` key — + exactly one service allowed for this caller → that service (the common case stays zero-config; unrelated `_meta` members don't forfeit it). A present-but-non-string `mcpmesh/service` is a malformed request and refuses; it never falls through to the default. Unknown/unauthorized → `-32054`, session closed. The daemon strips platform-reserved `_meta["mcpmesh/*"]` keys before forwarding (§6.3).
5. Service check passes → backend attached (§6.2) → all subsequent frames pass through verbatim, both directions, until either side closes the stream. Reconnect ⇒ fresh `initialize`. Callers pool connections (idle close 300 s); proxies dial lazily.

The platform does not inspect, buffer, or reorder MCP messages beyond framing; pipelining, notifications, and out-of-order responses are between client and server per JSON-RPC.

### 7.3 Framing

Byte-compatible with MCP stdio transport: each message is one compact JSON object, UTF-8, `\n`-terminated, no literal newlines. Limits (each side enforces on receive):

| Violation | Handling |
|---|---|
| Frame exceeds the frame cap (16 MiB — a FIXED protocol constant, `mcpmesh-codec::MAX_FRAME_BYTES`; not configurable) | Discard remainder; JSON-RPC error `id: null`, code `-32051` (the id is unrecoverable from an unframeable line); 3 strikes → close |
| Not valid JSON | `-32700`, `id: null`; 3 strikes → close |
| In-flight cap / token bucket exceeded | `-32053` with `retry_after_ms` |

The 16 MiB cap exists for ordinary MCP servers that inline images or file contents; platform-aware applications SHOULD keep frames small and use the blob sidecar (§9) — the KB app caps its own frames at 1 MiB by policy. (A configurable `max_frame` existed in early drafts but was never wired to any reader — it was removed as dead surface rather than threaded through; the cap is one constant at every wire end.)

### 7.4 Error codes

The platform reserves JSON-RPC server-error codes **-32050…-32069** — a band with no known MCP or SDK assignment (`-32000`/`-32001` are SDK ConnectionClosed/RequestTimeout, `-32002` is MCP resource-not-found). Applications SHOULD allocate from **-32020…-32049**.

| Code | Meaning |
|---|---|
| `-32051` | Framing violation (inbound frame too large) |
| `-32052` | Session not initialized / gate raced a revocation |
| `-32053` | Rate limited or concurrency-capped (data: `retry_after_ms`) |
| `-32054` | Unknown or unauthorized service (deliberately indistinguishable) |
| `-32055` | Peer unreachable / session severed pre-response (synthesized caller-side by the proxy, §8) |

Every platform- or proxy-synthesized JSON-RPC error MUST carry `error.data.source = "mcpmesh"`; an error without that member originates from the proxied server. Code values alone are never the discriminator — JSON-RPC gives the whole -32000…-32099 band to the (proxied) server implementation, so the platform guarantees only its own band plus the marker. Errors originating in the proxied MCP server pass through untouched.

---

## 8. The Connect Proxy

`mcpmesh connect <peer>/<service>` — the only thing AI clients ever run:

```json
{ "mcpServers": { "alice-notes": { "command": "mcpmesh", "args": ["connect", "alice/notes"] } } }
```

Written by `mcpmesh setup <client> alice/notes`. The proxy is a thin stdio pipe to the daemon's UDS; the daemon owns dialing, pooling, and the session. Transparency contract: frames pass unmodified in both directions (D6); the proxy's only interventions are transport-level — clean EOF on remote close, and a synthesized JSON-RPC error (`-32055`, or `-32054` pass-through) when the peer is unreachable, the service is refused, or the session is severed mid-request, so clients get a well-formed answer rather than a hang. Reconnection is the AI client's choice (they already handle stdio server restarts); the proxy does not silently re-dial mid-session, because the remote server's session state died with the session.

---

## 9. Blob Sidecar (library, for platform-aware apps)

An optional blob sidecar (shipped inside the `mcpmesh` binary, `cli/src/blobs`) for content too large to inline sensibly. An app's tool result carries a reference instead of bytes:

```json
{ "kind": "blob", "name": "diagram.png", "mime": "image/png",
  "size": 4194304, "hash": "blake3:…", "ticket": "blob…" }
```

The caller-side app fetches via its daemon (iroh-blobs: BLAKE3-verified, resumable). Access control (normative, D7/D8):

1. **Accept-time:** blob connections pass the same trust gate as MCP connections. A revoked or unknown endpoint gets nothing regardless of what tickets or hashes it holds.
2. **Request-time:** the serving app registers blobs under named **scopes** (e.g. the KB app: one scope per audience); the provider serves a hash only to callers whose identity is granted a scope containing it. Grants draw from the SAME §5 flat principal namespace — `groups ∪ {petname} ∪ {user_id}`, via the one shared `principal_set` — so a scope granted to a pairing-mode petname admits that peer exactly as a service `allow` would (the KB app's attachment scopes rely on this: its audiences include petnames). Hashes are integrity proofs, never capabilities.
3. The provider's store contains only deliberately published blobs; it is not a general filesystem surface.

Engineering note: implement request-time checks via iroh-blobs' provider hooks if the pinned release exposes them; otherwise serve over a thin `mcpmesh/blob/1` protocol doing BLAKE3-verified streaming from the same store — identical store and checks, ticket format unchanged from the caller's perspective.

The generic proxy path never mints or interprets blob references — a vanilla MCP server's oversized-but-under-16MiB payloads simply flow inline (§7.3).

---

## 10. Presence, Discovery & Infrastructure

### 10.1 Presence (roster mode only)

Gossip topic `blake3("mcpmesh/presence/" + org_id)`; heartbeat every 60 s ± jitter, signed by the device key:

```json
{ "t": "presence", "endpoint_id": "…", "user_id": "alice",
  "ts": 1751500000, "roster_serial": 42, "sig": "b64u:…" }
```

Receivers verify signature against the roster-listed device key, `endpoint_id ∈ roster`, `|now − ts| < 120 s`; entries expire after 180 s. `roster_serial` doubles as roster-update discovery (higher serial → fetch, §4.3). Presence is **advisory**: it feeds `mcpmesh status` and dial ordering; absence of a heartbeat never blocks a dial (gossip is best-effort), and no security decision derives from presence. Pairing mode has no gossip at all — reachability is discovered by dialing (3 s timeout).

**Person → device resolution:** when a dial target is a user_id with multiple roster devices, the daemon dials candidates in order — `role=primary` devices first, then mirrors, most-recent presence first within a role — starting the next candidate 500 ms after the previous one if no connection is established (a staggered race, which keeps interactive fan-out budgets viable against the cold-dial p95); the first established session wins, and absence of presence never removes a candidate.

Deliberately not gossiped: service names, tool lists, any content metadata. Broadcasting them org-wide would bypass service allowlists.

### 10.2 Address discovery

Dialing an EndpointId uses Iroh's discovery layer to resolve current addresses — no DHT of our own, no port forwarding, no user-visible configuration in the default case.

### 10.3 Metadata exposure & self-hosting

Defaults use n0's public relays and DNS/pkarr discovery. Traffic is always E2EE; what infrastructure sees is metadata: which EndpointIds exist, their addresses, and (for relayed sessions) the connection graph. Config, parallel knobs (§12 — this is the exact shipped surface):

- `relay_mode = default | custom | disabled` — `custom` requires `relay_urls` (self-hosted iroh relay URLs, e.g. `https://relay.acme.com`); `disabled` is the HERMETIC mode: no relay AND no discovery (localhost/tests).
- `discovery_mode = default | custom` — `custom` requires `discovery_urls`: self-hosted **pkarr relay** URLs (an iroh-dns-server exposes one). Custom discovery publishes AND resolves through those URLs only — nothing goes to n0. Ignored (off) when `relay_mode = "disabled"`. (mDNS/"local" discovery did not ship in v1 — §18 Q7.)

An unknown mode, or `custom` without its URL list, refuses to start — the knobs never silently fall back to public infrastructure. Self-hosting only one of the two is an incomplete mitigation; `mcpmesh doctor` warns on that combination (and errors on any `[network]` the daemon would refuse). Direct connections are preferred automatically whenever hole-punching succeeds.

---

## 11. Security Considerations

### 11.1 The trust boundary, stated plainly

Mounting `alice/notes` means running Alice's MCP server's outputs through your AI client — **exactly** the trust decision you make installing any MCP server, plus one improvement: cryptographic certainty about who Alice is and an unforgeable off-switch (revocation/unpair). The platform does not and cannot make a malicious peer's *content* safe (D6, NG2); it makes the peer *identifiable, authorized, and severable*. Client-side content hygiene (untrusted-data labeling, tool-output wrapping) belongs to applications that compose text — the KB app's bridge is the reference implementation (companion spec §6) — and to AI-client-level defenses.

`mcpmesh setup` prints this boundary at mount time: *"Tools from alice/notes run on alice's machine. Treat their output as you would any third-party MCP server."*

### 11.2 Threat model

| # | Threat | Vector | Mitigations |
|---|---|---|---|
| P1 | Unauthorized access | Unknown device dials; peer probes unshared services | Gate refuses pre-MCP (`401`); per-service allowlists; `-32054` indistinguishability; default deny (D5) |
| P2 | Stolen/compromised device | Device key exfiltrated | Revocation ≤ 60 s to connected nodes (roster), staleness under withholding bounded by the §4.3 freshness rule / immediate local unpair (pairing); keys 0600; OS keychain integration (Q3); forward-only limitation documented (NG5) |
| P3 | Invite-code interception / substitution | Attacker redeems — or swaps — a pairing invite in transit | Single-use, ≤ 24 h expiry, out-of-band channel choice; invite binds the inviter's EndpointId, verified against the TLS identity at redemption; short authentication code shown on both sides (§4.2); completion announced on the inviter's side; a hijacked invite grants only its listed services, unpairable on sight |
| P4 | Roster forgery / rollback / substituted org invite | Fake or replayed roster; phished invite pins attacker's root | Org-root signature; strictly-increasing serial; expiry + degraded mode; root key offline; joiner-side root-fingerprint confirmation in the enrollment ceremony (§4.4) |
| P5 | Org root key compromise | Attacker signs own roster | Catastrophic by design — documented ops requirement: offline/HSM storage, key ceremony, fingerprint cross-check at approval. v2: threshold signing (Q4) |
| P6 | Metadata exposure to infrastructure | Relays/discovery see EndpointIds, addresses, connection graph | Self-hostable relays **and** discovery (§10.3); doctor warns on half-configured setups; direct paths preferred |
| P7 | DoS / resource exhaustion | Session floods, giant frames, spawn bombs | Gate rejects strangers before any spawn; per-identity token buckets; per-service concurrency caps; frame caps + strikes; QUIC flow control. Pairing ALPN accepts strangers by design — bounded instead by invite-gated listener lifetime and per-invite attempt caps (§4.2) |
| P8 | Malicious served content | Peer's server emits prompt-injection payloads | Out of platform scope by design — see §11.1. Identity/audit make attribution certain; apps add content containment |
| P9 | Gossip abuse (roster mode) | Forged presence, topic spam | Signed heartbeats verified against roster; non-roster senders dropped; fixed schema, 512 B cap |
| P10 | Blob authorization bypass | Replayed ticket post-revocation; hash probing across scopes | Gate on blob ALPN + scope membership checks (§9); hashes ≠ capabilities |
| P11 | Supply chain | Malicious dependency | `cargo-deny` + lockfile in CI; minimal features; reproducible release builds |
| P12 | Local privilege boundary | Another local user reaches the daemon UDS | Socket in the runtime dir (§13) — a per-user directory the daemon creates 0700 and verifies ownership of where the OS provides none — mode 0600; peer-uid check on accept |
| P13 | Roster withholding / freeze | Network-position attacker drops gossip and roster-poll traffic so a node never sees the serial revoking a device | Freshness rule (§4.3): unconfirmed roster currency > `max_staleness` → degraded mode → serving stops; the TLS poll is blockable but unforgeable; staleness surfaced in `status`/`doctor` |
| P14 | Same-user local code | Malicious code running as the user (npm postinstall, `npx -y` payloads, compromised app) reaches the UDS, key files, or config directly | Out of the v1 defensive boundary by declaration: same-uid code can read `device.key` and write config/state — full device compromise regardless of any API gating; the P12 uid check bounds *other* users only. Detection, not prevention: trust mutations and new service registrations announced in-UI/status and audited (§11.3). Hardening path: keychain key storage with code-signing ACLs (Q3), after which privileged local-API ops MAY require an authenticated client — not before, since any v1 token would be same-uid-readable, pure theater |

### 11.3 Audit log

Append-only JSONL at `~/.local/state/mcpmesh/audit/YYYY-MM.jsonl`: one record per session open/close, per proxied request line (method + tool name only), per blob fetch, per trust event (pair, unpair, roster swap):

```json
{ "ts": "2026-07-03T14:02:11.480Z", "peer": "bob", "service": "notes",
  "method": "tools/call", "tool": "read_file",
  "args_hash": "blake3:…", "bytes_out": 6210, "status": "ok", "latency_ms": 41 }
```

Arguments are hashed, never stored (callers' inputs can be sensitive). `mcpmesh internal audit` views/rotates; nothing is transmitted anywhere.

---

## 12. Configuration (`~/.config/mcpmesh/config.toml`)

Written by `mcpmesh serve` / `join` / `pair`; users normally never open it. Everything outside `[services]` is optional with the defaults shown.

```toml
[identity]
device_key = "~/.config/mcpmesh/device.key"
# roster mode only (absent in pure pairing use):
# org_id      = "acme"
# org_root_pk = "b64u:…"
# user_id     = "alice"
# user_key    = "~/.config/mcpmesh/user.key"

[roster]                          # roster mode only
# url           = "https://intranet.acme.com/mcpmesh-roster.json"
# poll_interval = "1h"
# grace_period  = "72h"
# max_staleness = "24h"           # freshness bound, §4.3

[network]
relay_mode     = "default"        # default | custom | disabled ("disabled" = hermetic:
                                  #   no relay AND no discovery — localhost/tests)
discovery_mode = "default"        # default | custom (ignored when relay_mode = "disabled")
# relay_urls     = ["https://relay.acme.com"]        # required when relay_mode = "custom"
# discovery_urls = ["https://dns.acme.com/pkarr"]    # required when discovery_mode = "custom":
                                  #   self-hosted pkarr relay URLs (e.g. an iroh-dns-server),
                                  #   used for BOTH publish and resolve in place of n0
# An unknown mode, or "custom" without its URL list, is a startup ERROR — the knobs never
# silently fall back to public infrastructure.

[limits]
# NOTE: the 16 MiB frame cap is a FIXED protocol constant (§7.3), not a config key.
rate_limit_per_min = 120          # per peer identity
max_inflight       = 16           # per session
max_sessions       = 4            # per spawn-backend service

[services.notes]
run   = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "~/notes"]
allow = ["bob"]
```

---

## 13. Persistence & Filesystem Layout

```
~/.config/mcpmesh/                 config.toml, device.key, [user.key, roster.json]
~/.local/share/mcpmesh/
    state.redb                   pair allowlist, presence cache, invite nonces
    blobs/                       gated iroh-blobs store (published scopes only)
~/.local/state/mcpmesh/audit/      audit JSONL
<runtime_dir>/mcpmesh.sock         daemon ⇄ proxy/porcelain IPC (0600, uid-checked)
```

Paths are shown in Linux XDG form; each daemon resolves them through one shared paths rule. **`<runtime_dir>`:** `$XDG_RUNTIME_DIR` if set (Linux); otherwise a daemon-created directory, mode 0700, ownership verified before binding (macOS: under the per-user `$TMPDIR`, e.g. `$TMPDIR/mcpmesh/`). `mcpmesh status`/`doctor` print the resolved paths. Roster and state writes use write-new + atomic-rename; a crash never leaves a torn trust state.

---

## 14. Performance Targets

Assumptions: commodity laptops, 20-peer roster, direct path where noted.

| Metric | Target |
|---|---|
| Session establishment, warm connection (stream open → initialize response) | p50 < 50 ms + backend cost |
| Session establishment, cold (dial + hole-punch + spawn) | p95 < 1.5 s |
| Proxy overhead per request (vs. same server local stdio) | p50 < 5 ms, p95 < 20 ms |
| Sustained throughput, one stream (large inline frames) | ≥ 50 MB/s direct path |
| Blob fetch, 100 MB attachment, direct path | ≤ 5 s at LAN speeds; resumable |
| Daemon RSS steady state (5 services, 10 pooled peers) | < 100 MiB (excl. spawned backends) |
| Revocation propagation to connected nodes (roster mode) | ≤ 60 s (delivered); staleness bound under withholding: `max_staleness + grace` (§4.3) |

---

## 15. Technology Stack

| Concern | Choice | Notes |
|---|---|---|
| Language / runtime | Rust (edition 2024), tokio | single static binary |
| P2P transport | `iroh` **1.x** | pin exact minor; Endpoint/Router/ALPN APIs |
| Blob transfer | `iroh-blobs` | tickets, BLAKE3 verified streaming; gated per §9 |
| Gossip | `iroh-gossip` | roster + presence topics, roster mode only |
| MCP | `rmcp` (official Rust SDK) | types + stdio server; custom `Transport` over the QUIC stream |
| State | `redb` | pure-Rust embedded KV |
| Crypto | `ed25519-dalek`, `blake3`, `serde_jcs` | JCS canonicalization for signed documents |
| CLI / config / logs | `clap`, `figment`, `tracing` | |
| CI hygiene | `cargo-deny`, `cargo-audit` | P11 |

Engineer note: iroh 1.0 stabilized recently with identifier renames in the run-up (Node→Endpoint terminology). Code fragments here are illustrative — resolve exact method and hook names (including iroh-blobs provider hooks, §9) against the pinned docs at implementation time.

---

## 16. Milestones & Acceptance Criteria

Milestones define scope and sequencing only; each one's acceptance criteria (AC) are demoable requirements.

**M0 — Scaffolding.** Workspace (`mcpmesh` bin; `mcpmesh-net`, `mcpmesh-trust`, `mcpmesh-local-api`; `mcpmesh-blobs` was scaffolded then removed once the real blob code shipped in the binary; `mcpmesh-codec` extracted later), CI (fmt, clippy, test, deny), config loading, device keygen. *AC: first run mints a device key; CI green.*

**M1 — MCP echo over Iroh.** Endpoint + Router + `TrustGate` (static allowlist); NDJSON framing with caps + strikes; rmcp transport adapters; session establishment with service selection; one stub service. *AC: two machines on different NATs complete an MCP session over `mcpmesh/mcp/1`; oversized/malformed frames rejected per §7.3 (unit-tested).*

**M2 — Services + proxy + pairing: the hero flow.** *(Status: IMPLEMENTED — M2a (daemon + serving spine) + M2b (pairing); the four-command hero flow works end to end.)* Service registry, spawn + socket backends, per-session child lifecycle, identity injection; connect proxy with daemon auto-start; the pairing-mode `TrustGate` (`AllowlistGate` over the peer store) populated by the invite/pair rendezvous (EndpointId binding + short authentication code); porcelain: `serve`, `invite`, `pair`, `setup`, `status`. The daemon UDS control API is delivered as the versioned **`mcpmesh-local/1`** surface (§6.1): hello convention at connect, trust operations, service management incl. app self-registration, status/event stream, and `connect()` sessions — the porcelain and connect proxy are its first clients; the API grows in place as later milestones add features (M3 roster reads, M4 blob ops + audit summaries). *AC: the §1.5 transcript works verbatim on a clean machine — Alice serves a filesystem server, Bob pairs and uses it from Claude Desktop, four commands total; a third unpaired machine is refused pre-MCP; a non-porcelain client drives invite/pair/status over `mcpmesh-local/1` and receives the API version at connect.* **All three AC clauses are proven end to end by the M2b Task 8 E2E (`cli/tests/hero_flow_pairing.rs`): a real two-daemon localhost mesh does serve → invite → pair → `connect alice/notes` (identity `MCPMESH_PEER_NAME=bob` threaded through the paired trust), a third unpaired endpoint is refused pre-MCP, and a raw `connect_control` client drives invite/pair/status over `mcpmesh-local/1`. Production dial-by-id AFTER pairing resolves EndpointId → address via iroh discovery (the `build_endpoint` N0 preset = pkarr publish + DNS address lookup + n0 relays); the E2E seeds a `MemoryLookup` only because relay-disabled localhost has no discovery — the id-only `dial_service` path itself is identical to production. (Robustness follow-up, noted in the M2b plan: the invite carries the inviter's dialable address, but pairing does not persist it into the dial-back `PeerEntry`, so the first post-pair mesh dial re-resolves via discovery rather than reusing that address.) M2b keeps the pair ALPN permanently advertised and realizes the §7.1/§4.2 "windowed listener" via a live-invite accept-gate (a pair dial with no outstanding invite is closed immediately) plus the per-secret refusal in the rendezvous, in lieu of dynamically registering/unregistering the ALPN; per-connection rate-limiting of the pair ALPN is deferred to M4.**

**M3 — Roster mode.** *(Status: COMPLETE — M3a (ENFORCEMENT CORE) + M3b (ENROLLMENT PORCELAIN) + M3c (DISTRIBUTION/GOSSIP/HTTPS + re-seeding, the `last_confirmed`/`max_staleness` freshness rule, presence + person→device dial, the 3-node 60 s cross-node propagation AC) all IMPLEMENTED.)* Roster validation/install/rollback protection; gossip + HTTPS distribution + publication/re-seeding; freshness rule (§4.3); presence + person→device dial resolution (§10.1); `org create/approve/revoke`, `join` (root-fingerprint ceremony), `devices add` (roster never hand-edited, even by us); revocation propagation incl. pairing-precedence rules (§4); degraded mode; user-key rotation runbook. *AC: full enrollment via porcelain only; revoked device cut from live sessions within 60 s in a 3-node test — including one holding a stale pair entry; group-based `allow` works.* **M3a delivers the enforcement core end to end (`trust/src/roster/*` — schema + `b64u` codec + JCS sign/verify + the six §4.3 validation rules + the resolvable `RosterView`/`RosterState`; `cli/src/roster/*` — `RosterStore` install/rollback/persist with a pinned org root, the hot-swappable `RosterGate`, and the `ComposedGate` §4.1 precedence revocation→roster→pairing): `select_service`'s group/user_id `allow` arms (a group name in `allow` admits every group member — the AC's "group-based `allow` works"), live-session severing on revocation (D8 — `mcpmesh_net::ConnRegistry` + swap-before-sever with a lock-serialized TOCTOU recheck, revocation winning across all ALPNs even over a stale pair entry), the §6.3 roster identity injection (`MCPMESH_PEER_USER` + `MCPMESH_PEER_GROUPS` added alongside `MCPMESH_PEER_NAME`, a superset that leaves pairing callers unchanged), the EXPIRY-driven degraded core (`RosterState` machine over `expires_at` + `[roster].grace_period`, with a degraded-grace serving warning; fail-closed — revocation is enforced regardless of degraded state), and roster `status` (org_id / serial / state / org-root fingerprint words). The minted-roster capstone E2E (`cli/tests/hero_flow_roster.rs`) proves the "group-based `allow` works" and "revoked device cut from live sessions — including one holding a stale pair entry" AC clauses over a REAL localhost mesh; M3a used the manual mint + `internal roster install` path — the SAME `sign`/`mint_signed` production path M3b's `org approve` drives. NOT in M3a (honest scope): the full-enrollment-VIA-PORCELAIN AC (`org create/approve/revoke`, `join` root-fingerprint ceremony, `devices add`) is M3b; the 3-node 60 s CROSS-NODE propagation timing, gossip + HTTPS distribution + re-seeding, the §4.3 freshness rule (`last_confirmed`/`max_staleness`) on the same `RosterState`, and presence + person→device dial resolution are M3c.** **M3b delivers the enrollment porcelain end to end (`trust/src/{keys,roster}/*` — `OrgRootKey`/`UserKey` over a shared 0600 Ed25519-file core (`keys.rs`), the `sign_device_binding`/`verify_device_binding` join-code proof, and the `empty_roster`/`upsert_member`/`revoke_device`/`remove_user` mutations that form a complete pre-image of M3a's `validate_for_install`; `cli/src/roster/*` — the `OrgInviteCode`/`JoinCode`/`DeviceCode` base32-JSON codec and the porcelain commands): `mcpmesh org create` (mint org root → sign + install empty roster → org invite code + fingerprint), `mcpmesh join` (mint user key → pin org root → emit join code), `mcpmesh org approve --groups` (verify device binding → upsert member → serial+1 → sign → install), `mcpmesh org revoke <person>` / `<person>/<device>` / `--user-key <person>` (the §4.5/§4.6 revocation + rotation grammar), and `mcpmesh devices add` (user-key-signed second-device binding — keys never move between machines). The roster is NEVER hand-edited: every serial bump is a signed mutation through the porcelain feeding M3a's single-writer `RosterInstall`. Enrollment MITM hardening: `join` and `org approve` print a **DUAL fingerprint ceremony** — the pinned org-root fingerprint (P4, closing the phished-invite substitution) AND a join-code fingerprint (`b64u(user_pk‖device_endpoint)` under a dedicated domain, the enrollment analog of the pairing SAS) confirmed on both sides, closing the join-code-substitution MITM on the operator↔joiner channel that "verify the person out-of-band" (§4.4) alone underspecifies. The `org-root.key` is strictly offline-signed-in-porcelain — never an online control-API oracle. The full-enrollment-VIA-PORCELAIN AC is proven end to end by `cli/tests/enroll_e2e.rs`: subprocess `org create → join → org approve` produces a roster that verifies against the org root and carries the joiner's device under a group (no hand-editing), that porcelain-produced roster admits the joiner via the group `allow` arm, and a subsequent `org revoke` cuts the joiner from the live session. Completed in M3c (below): gossip + iroh-blobs + HTTPS roster distribution / re-seeding (M3b installs on the operator node only — `OrgInviteCode.roster_url` is reserved, set `None`), the §4.3 `last_confirmed`/`max_staleness` freshness rule, presence + person→device dial resolution, and the 3-node 60 s CROSS-NODE propagation timing.** **M3c delivers roster distribution end to end (`cli/src/roster/*` — `transport` (the gossip + blob layer), `distribute` (the three-channel convergence), `freshness` (the `last_confirmed` sidecar), `presence`; `trust/src/roster/validate.rs` — `RosterView::{effective_state,devices_for_user}`): gossip (`blake3("mcpmesh/roster/"+org_id)` carrying `{serial, roster_hash, blob_ticket}`) + iroh-blobs roster-blob fetch + the `[roster].url` HTTPS poll ALL converge on M3a's SINGLE validator (`RosterStore::install_from_file` → `install_roster_view_and_sever`, under `mesh.reload_lock`; grep-verified NO second validator in `distribute.rs`), and every accepting node re-seeds its blob + re-announces (operator-offline-safe propagation, §4.3). The joiner's FIRST roster arrives via the URL poll (D5, gossip cannot serve it first); `set_roster_url` (re)starts the poll loop at RUNTIME so a runtime join bootstraps without a daemon restart, and `serve_forever` installs a process-default rustls `ring` `CryptoProvider` once before the first reqwest client (iroh 1.0.1 installs none). The §4.3 freshness rule folds `last_confirmed`/`max_staleness` onto the SAME `RosterState` machine (worse-of expiry/staleness); a stale/expired roster (`effective_state == DegradedStopped`) authorizes NO new inbound (`RosterGate::resolve → None → 401`), bounding NEW-connection adversarial staleness at `max_staleness + grace` — currency is CONFIRMED on install/gossip/URL-poll (the URL poll also confirms on an EQUAL serial, the liveness signal gossip/manual cannot give). Presence is a device-key-signed `{t, endpoint_id, user_id, ts, roster_serial, sig}` heartbeat (domain `mcpmesh/presence/1`, ±120 s skew, 180 s TTL, ≤512 B, verified against the endpoint-as-pubkey), strictly ADVISORY (no reference in the net crate / trust gate / `select_service`); person→device dial = `devices_for_user` (revoked devices never a candidate; primary→mirror) re-ordered within a role by presence recency, then a 500 ms-staggered concurrent race (tokio `JoinSet`). The 3-node 60 s CROSS-NODE propagation AC (revoked device — incl. one holding a stale pair entry — cut from live sessions within 60 s across nodes, D8 severing the gossip + blob ALPNs too) is proven by `cli/tests/three_node_propagation.rs` over a REAL localhost mesh; `config user_id` reconciles to the authoritative roster on every install (`reconcile_user_id_from_roster`). DEFERRED to M4 (honest scope, no new AC gap): cutting an EXISTING roster-authorized session on staleness needs a time-triggered periodic sweep (the register-time `should_sever_now` cannot re-evaluate an established session as the clock crosses the bound — the resolve-time NEW-inbound gate is the M3c freshness bound); the gossip-fetch DoS timeout/concurrency/rate-limit, the HTTPS-poll timeout + response-size cap, and a symmetric dial timeout on the person→device race are recorded in the M4 hardening backlog.**

> **M3b spec follow-ups — flagged for the design owner (candidate rows, NOT yet normative; do not treat as settled wording):**
> - **Candidate threat row mirroring P3, for enrollment.** §4.4 step 3's "operator verifies the person out-of-band" underspecifies the person→`user_pk` binding: a join-code *substitution* MITM on the operator↔joiner channel (attacker swaps the joiner's join code for its own device's) is not caught by the org-root fingerprint (P4) alone. M3b closes it with the DUAL ceremony's second leg — a join-code fingerprint confirmed on both sides, the enrollment analog of P3's pairing authentication code. Candidate: a P-row (or P4 extension) for enrollment-code interception/substitution, mirroring P3's "short authentication code shown on both sides".
> - **Candidate Q-row cross-ref for the org root.** `org-root.key` is the catastrophic-compromise anchor (P4/P5). Note that Q4 (threshold/quorum org-root signing) is the v2 hardening path for it, and that M3b keeps the org root **strictly offline-signed-in-porcelain** — the signing key is only ever loaded by the local `org create/approve/revoke` porcelain, never exposed as an online control-API signing oracle. Candidate: cross-reference Q4 from P5's "v2: threshold signing" and record the M3b offline-porcelain property as the interim mitigation.

**M4 — Blobs, audit, hardening.** *(Status: COMPLETE — M4a (GATED BLOB PROVIDER) + M4b (AUDIT LOG) + M4c (RATE-LIMITS + CONCURRENCY-CAPS + the M3c hardening backlog) + M4d (`doctor` + packaging (brew/deb) + operator runbook) all IMPLEMENTED. With M4 done, the mcpmesh PLATFORM (M1 echo + M2 hero flow + M3 roster mode + M4 blobs/audit/hardening/doctor/packaging/runbook) is COMPLETE — the platform MVP.)* Gated blob provider with scopes; blob operations + typed audit summaries on `mcpmesh-local/1`; audit log covering sessions/requests/blobs/trust events; rate limits + concurrency caps under load; `doctor`; packaging (brew/deb) + operator runbook (incl. roster publication). *AC: 100 MB blob fetched with verification; same fetch refused after revocation mid-test and for an ungranted scope; 20 peers × 120 rpm for 10 min — limiter engages, no unbounded memory; runbook executed by a non-author.* **M3c reused iroh-blobs `0.103.0` (the §18 Q2 version) for the ROSTER blob ONLY — a `MemStore`-backed `BlobsProtocol::new(store, None)` (no scope events). M4 adds the GATED per-scope blob provider: `BlobsProtocol::new(store, Some(events))` + the `Intercept` scope hooks (spec §9/Q2) over an `FsStore` at `<data_dir>/blobs/`. M3c→M4 hardening backlog carried forward: a periodic staleness SWEEP that cuts EXISTING roster-authorized sessions when a node's roster crosses `last_confirmed + max_staleness + grace` (M3c enforces the freshness bound at register/resolve time only); a gossip-fetch DoS timeout + bounded concurrency + rate-limit; the HTTPS-poll timeout + response-size cap; and a symmetric dial timeout on the person→device race. `doctor` M4 candidate: WARN when a roster node has no `[roster].url` (it will degrade to stale after `max_staleness` with no way to re-confirm currency — the freshness URL-less hint `status` already surfaces).**

**Post-v1 backlog:** capability tokens for peer-issued delegation, Windows (named-pipe IPC + platform-appropriate data dirs — the only Windows blockers, kept that way), keychain key storage (unlocks authenticated local-API clients, P14), threshold org signing, connection-level QoS.

The KB application's milestones live in the companion spec and begin after platform M3; K-M2 onward additionally requires M4's gated blob provider.

---

## 17. Testing Strategy

- **Unit:** framing codec (fuzz: truncation, huge frames, invalid UTF-8, interleaved ids); roster validation (bad sig, replayed serial, expiry, dup/conflicting endpoints, namespace collisions); gate precedence (endpoint in both pair allowlist and `revoked_endpoints` → refused; in both pair allowlist and a roster user entry → resolves to roster identity, group `allow` grants); invite lifecycle (reuse, expiry, wrong secret, attempt-cap invalidation); JCS + signature round-trips.
- **Transparency suite (release-blocking):** golden-transcript tests running real MCP servers (filesystem, everything-server) both locally and through the proxy — byte-identical frames both directions, modulo transport-level errors and the enumerated `initialize` `_meta["mcpmesh/*"]` transformation (§6.3/§7.2), asserted to be exactly that transformation and nothing else, including that a caller-forged `mcpmesh/peer` never reaches a backend. Every synthesized error carries the `data.source` marker (§7.4).
- **Surface-leak suite (release-blocking):** porcelain output and proxy-synthesized errors scanned for every term in the canonical transport-vocabulary blocklist (§1.5) — loaded from the ONE shared fixture, `local-api/fixtures/transport-vocabulary.json` (mcpmesh's suite: `cli/tests/daemon_autostart.rs`), plus the runtime values a fixture cannot carry (the actual endpoint id, socket path, backend command). The abstraction boundary is a tested contract.
- **Integration:** multi-node localhost harness; full session lifecycle over both backend kinds; pairing rendezvous; revocation timing across MCP *and* blob ALPNs — including a node holding a stale pair entry for the revoked endpoint; relay-only path (direct candidates disabled).
- **Load:** session floods from unauthorized endpoints (cheap rejection), authorized request floods (limiter), spawn-bomb attempts (concurrency caps).
- **Chaos:** kill daemon mid-session/mid-roster-swap → restart serves consistent trust state (old or new, never torn); backend crash mid-session → clean EOF at the caller.

---

## 18. Open Questions

| # | Question | Current lean |
|---|---|---|
| Q1 | Should a connection carry sessions to *multiple* services concurrently, or is one-service-per-connection simpler to reason about for revocation? | Multiple (streams are cheap); revocation closes the connection, which closes all sessions — actually simpler |
| Q2 | iroh-blobs provider hooks sufficient for scope checks, or custom `mcpmesh/blob/1`? | **Resolved: use the hooks.** `iroh-blobs 0.103.0` (compatible with `iroh =1.0.1`) exposes an `Intercept`-mode provider event (`GetRequestReceived` → `Result<(), AbortReason>`, blocked-on before bytes) that denies a specific hash to a specific caller at request time — §9.2 as-is; caller identity comes from `ClientConnected.endpoint_id`, joined by `connection_id`. The thin `mcpmesh/blob/1` path (§9 note) stays the recorded fallback. |
| Q3 | OS keychain for keys vs. 0600 files? | Files v1; keychain fast-follow |
| Q4 | Threshold/quorum org root signing | v2; single offline key + runbook acceptable ≤ 50 users |
| Q5 | Windows support | Nothing blocks it except UDS (named pipe swap); untested in v1 |
| Q6 | Should `setup` support mounting several services in one client entry (a multiplexing proxy)? | No for v1 — one entry per service keeps the transparency contract trivial; revisit on demand |
| Q7 | `discovery_mode = "local"` (mDNS + static address hints in roster device records)? | Cut from v1 (was specced but never implemented; the knob was removed rather than shipped dead). Self-hosted pkarr URLs (`discovery_mode = "custom"`) cover the metadata-privacy need; revisit mDNS for offline-LAN use in v1.1 |

---

## Appendix A — Example wire trace (Bob mounts alice/notes, condensed)

```
# Bob's proxy → daemon (UDS) → dials Alice, ALPN mcpmesh/mcp/1; TLS mutual auth;
# Alice's gate: pair entry found (bob). Stream opened.
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",
    "_meta":{"mcpmesh/service":"notes"},"capabilities":{},"clientInfo":{…}}}
# Alice's daemon: "notes" allowed for bob → spawns child, forwards initialize
# (mcpmesh/* _meta stripped, §6.3; env: MCPMESH_PEER_NAME=bob), returns the
# child's response verbatim:
← {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{…},
    "serverInfo":{"name":"filesystem-server","version":"…"}}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file",…}}
← {"jsonrpc":"2.0","id":2,"result":{…}}          # untouched by the platform
# Alice's audit: {peer:"bob", service:"notes", tool:"read_file", …}
```

## Appendix B — Alternatives considered

- **Ship the KB product with an embedded transport (the 0.1/0.2 shape).** Rejected as the headline: it buries the general-purpose value inside one application, and every future domain app would re-solve identity/serving. See Appendix C for the rebalance rationale.
- **libp2p as transport.** Larger surface, lower hole-punch success in practice, no need for its DHT/pubsub breadth. Iroh's dial-by-key + relay fallback is a tighter fit.
- **HTTP/MCP Streamable over Tailscale/VPN.** Workable inside one tailnet, but pushes identity/ACL into network config and requires org-wide VPN adoption. Iroh keeps identity in-protocol and infra-free.
- **Platform-level aggregation bridge (0.2's D2).** Rejected: fan-out/merge/rerank are domain semantics (NG1); a transparent per-service proxy keeps the platform's AI-facing vocabulary at zero. Applications aggregate (companion spec §6).
- **Per-request QUIC streams.** Cleaner cancellation, but breaks MCP's session model; JSON-RPC ids already multiplex. One stream per *session*, many sessions per connection.
- **Content sanitization in the proxy.** Rejected (D6): can't rewrite arbitrary payloads without corrupting them, and partial sanitization invites misplaced trust. Who-not-what is the honest guarantee.
- **UCAN / capability-token delegation in v1.** Deferred: pairing + roster cover v1's need; a flat signed-token design remains upgrade-compatible (backlog).

## Appendix C — Change log

### 0.4 → 0.5: the family review — the platform closes the gaps its consumers exposed

A four-spec cross-review (host, kb-mesh, ecosystem vision) confirmed 40 findings; the platform's share: **(1) `mcpmesh-local/1` finished what 0.4 started** — the surface table says five items, the `mcpmesh-local-api` crate exists in the layout and M0, and the API now carries what co-resident apps actually need (hello convention shared by every `*-local/N`, self-registration, `connect()` sessions, blob scope ops, advisory roster/presence reads, typed audit summaries) so a plugin daemon never owns an Iroh endpoint (D3 held). **(2) Trust hardening from the review's adversarial pass:** invite EndpointId-binding + short authentication codes (P3), joiner-side org-root fingerprint ceremony (P4), roster freshness bound `max_staleness` (new P13), revocation-over-pairing precedence, pairing-rendezvous exception stated honestly in D8, `_meta["mcpmesh/*"]` reserved-namespace stripping as the single tested pass-through exception, same-uid boundary declared (new P14), roster publication/bootstrap specified. **(3) Error codes renumbered** to -32050…-32069 with a `data.source: "mcpmesh"` marker (the old band collided with MCP/SDK-assigned codes). **(4) Portability:** `<runtime_dir>` path rule replaces raw `$XDG_RUNTIME_DIR` (absent on macOS); the canonical transport-vocabulary blocklist became a single shared fixture. Windows stays post-v1 (product decision), with its blockers named and fenced.

### 0.3 → 0.4: local API promoted; three-project structure settled

The product family is now three projects in one monorepo — **mcpmesh** (this spec), **kb-mesh** (the knowledge daemon, renamed from working name `mcpmesh-kb`; spec file renamed accordingly), and **kb-app** (desktop application; later retitled to the **host** spec when the ecosystem's host+plugins frame landed). Driven by the desktop-app decision: the daemon's UDS control API is promoted from plumbing to a versioned surface (`mcpmesh-local/1`, §6.1) so GUI and CLI are two skins over one contract; the earlier "separate repos" lean is replaced by a monorepo with lockstep versioning to make cross-component version skew structurally impossible.

### 0.2 → 0.3: the rebalance (general-purpose platform becomes the headline)

0.2 was a knowledge-base product with a reusable transport buried inside (its G7). 0.3 inverts that: **mcpmesh is the domain-agnostic platform; the KB is its first application, moved wholesale to the companion spec** (then named `kb-app-design`, since split into the kb-mesh and host specs) and — at the time — destined for its own repository (superseded by the monorepo decision, 0.4 above). This is a simplifying move, verified rather than assumed — making generic the headline flushed out three KB assumptions that had been passing as "generic":

1. **The 1 MiB frame cap was KB policy, not a transport property.** Ordinary MCP servers legitimately inline multi-MiB images/files. Now: 16 MiB configurable default (§7.3); the blob sidecar becomes an opt-in library (§9); the KB app keeps 1 MiB as *its* policy.
2. **The aggregator bridge (0.2 D2) was KB-shaped.** Fan-out, merging, reranking, and provenance wrapping are domain semantics. Now: the platform mounts one remote service per transparent proxy and adds zero AI-facing vocabulary (new D2, §8); the KB bridge owns aggregation (companion §6).
3. **Provenance-wrapping all remote content is impossible generically** — rewriting arbitrary payloads corrupts them. Now stated as a principle (D6, §11.1): the platform authenticates *who*, never sanitizes *what*; content containment belongs to apps composing text.

New scope that "general-purpose" genuinely requires: **pairing mode** (§4.2) — one-time invite codes for ad-hoc two-person use, no org ceremony; it is the new hero flow. New extension points, each exercised by the KB app: **service registry with spawn/socket backends** (§6.2), **caller-identity injection** (§6.3), **blob scopes** (§9). Moved out to the companion spec: vault/indexing/search/embeddings, share frontmatter, the 5-tool bridge, mirrors/sync, KB threat rows, KB error codes (allocated from the application range, §7.4), KB milestones. Roster **audiences** generalized to **groups** (opaque labels; the KB app interprets them as audiences). The modest scope added over 0.2 buys pairing mode and the clean seam.

Guard against the classic single-consumer platform trap: the extraction rule in §1.1 — nothing ships in the platform that the KB app or the §1.5 hero flow doesn't exercise.

### 0.1 → 0.2 (retained; see git history for the full text)

Kept 0.1's architecture wholesale; hardened blob access control (gate + scopes), added discovery-layer metadata treatment (`discovery_mode`), made `answers-only` construction-time safe, cleaned up framing/error-code ambiguities, added user-key rotation, pinned the embedding query-prefix convention, made presence advisory, documented `ask` threat surface, and defined the exposed surface explicitly (porcelain, flat namespace, ticket-hiding, surface-leak tests).

— end of specification —
