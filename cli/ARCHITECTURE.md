# cli architecture

The `mcpmesh` crate is one binary with three layers:

1. **Porcelain** (`main.rs`) — clap parsing and human-facing rendering. Every command talks to
   the daemon through the typed `mcpmesh-local-api` client; output is built by pure,
   unit-tested `*_lines` render functions (`render.rs`), never ad-hoc `println!`s.
2. **Daemon** (`daemon/`, `control.rs`) — the long-lived process. It owns the single Iroh
   endpoint and serves two roles at once: the mesh accept loop (dispatching inbound
   connections by ALPN) and the `mcpmesh-local/1` control API on the local socket/pipe.
3. **Wire contract** (`mcpmesh-local-api`, a separate crate) — the one typed truth for the
   control protocol. The daemon dispatches on it, the porcelain calls through it, and it is
   the only supported surface for third-party integrations. Everything in this crate is
   internal and unstable by design.

The porcelain auto-starts the daemon when the socket is dead, so there is no separate install
step — `mcpmesh` is a single self-hosting binary.

## Module map

| Module | One line |
| --- | --- |
| `main.rs` | clap tree + command dispatch; porcelain only, no daemon logic |
| `render.rs` | pure `*_lines` render functions for every human-facing output |
| `client.rs` | local-socket client helpers (connect, auto-start, typed calls) |
| `proxy.rs` | `mcpmesh connect`: stdio ⇄ control-socket MCP byte pipe for AI clients |
| `control.rs` | control-API server: `DaemonState`, per-method dispatch, the subscribe stream |
| `daemon.rs` | `MeshState` (the composition root) + service-registry build; hands out contexts |
| `daemon/boot.rs` | process bring-up: singleton, config, endpoint, gate, loop spawns |
| `daemon/accept.rs` | the ALPN-dispatch accept loop + the shared gate-and-register discipline |
| `daemon/handlers.rs` | control verbs: register/peer add/remove/rename, invite/pair, blobs, open_session |
| `daemon/roster_install.rs` | the single roster install pipeline (validate → persist → swap → sever) |
| `daemon/dial.rs` | outbound: nickname/person resolution, staggered race dial, the session pipe |
| `daemon/reach.rs` | trust-gated reachability probe + its advisory cache |
| `daemon/status.rs` | live `status` projections (services, peers, roster, presence) |
| `daemon/config_write.rs` | surgical, atomic `config.toml` read-modify-write helpers |
| `allowlist.rs` | the redb peer store + `AllowlistGate` (pairing trust) |
| `pairing/` | invites, the rendezvous (both sides), SAS words; daemon-free via `InviterCtx` |
| `roster/` | roster persistence, the composed/roster gates, distribution, presence, transport |
| `blobs/` | the gated per-scope app-blob provider |
| `backends/` | per-session service backends: spawn (subprocess) and socket |
| `audit/` | the append-only audit log + broadcast sink |
| `limits.rs` | process-wide rate/concurrency limiters |
| `config.rs` / `ipc.rs` / `util.rs` | config schema; socket/pipe platform seam; small shared helpers |

## The state picture

`DaemonState` (control.rs) is thin: the stack version, a shutdown signal, and an optional
`Arc<MeshState>`. Control-only tests build it without a mesh; every mesh-requiring verb
answers a clean error there.

`MeshState` (daemon.rs) is the composition root: endpoint, composed trust gate, peer store,
invites, the accept-loop/poll-loop handles, the roster gate + connection registry, the
roster-mode gossip/blob handles, and the audit/limits/identity set-once slots. It is always
shared as `Arc<MeshState>`.

The subsystem modules never see `MeshState`. It composes narrow seams and hands them out:

- `pairing::rendezvous` gets an `InviterCtx` per pair connection — store + invite ring +
  a `grant` hook into the config-append/reload machinery.
- `roster::presence` gets a `PresenceCtx` — presence table + topic handle + roster gate.
- `roster::distribute` runs against the `DistributionHost` trait `MeshState` implements —
  endpoint, roster gate, blob transport, topic handles, and `install_roster_bytes`, the
  handle into the single install pipeline in `daemon/roster_install.rs`.

Control flow for a request: porcelain → local-api client → control socket → `control.rs`
dispatch → a `daemon/handlers.rs` (or `roster_install.rs`) verb → `MeshState`.
Inbound mesh traffic: `daemon/accept.rs` dispatches by ALPN → mesh sessions run through
`mcpmesh_net::run_mesh_connection`; pairing, gossip, and blobs go to their own arms.

## Where the invariants live

- **`reload_lock`** (`MeshState`) serializes every config-mutating critical section — service
  registration, the pairing grant/revoke, rename, org join/pin, and all three roster install
  channels. Read → mutate → atomic write → rebuild → accept-loop swap happens under one hold;
  helpers called under it (`config_write.rs`, `reconcile_user_id_from_roster`) are lock-free
  so nothing re-enters the non-reentrant mutex.
- **Lock ordering** (`daemon/roster_install.rs`, `install_roster`): `reload_lock` is only ever
  a *source* — nothing acquires it while holding another lock. Under it the code touches the
  gate `RwLock` and the connection-registry mutex, but never the reverse, so the graph is
  acyclic.
- **Swap-before-sever** (`install_roster_view_and_sever`): sever sets are computed from the
  new view directly (never by locking the gate), the gate view is hot-swapped *first*, then
  live connections are severed; the registry's lock-serialized check-register closes the
  race for connections landing mid-swap.
- **Revoke-before-remove** (`daemon/handlers.rs`, `remove_peer`): removal is the grant's LIFO
  inverse — strip the config `allow` (authorization) before deleting the `PeerEntry`
  (identity), so every partial-failure point leaves the peer *more* restricted, never less.
- **Fail-closed trust**: the org-root signature is the sole roster trust input
  (`roster::distribute` + `roster_install.rs`); a corrupt store row resolves to deny
  (`allowlist.rs`); an unauthenticated poll body never refreshes freshness.
- **Blocking discipline**: every redb/fs operation runs on a blocking worker
  (`util::blocking`); std mutexes in hot paths are never held across an await.
