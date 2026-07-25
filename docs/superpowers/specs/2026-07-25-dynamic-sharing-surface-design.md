# Dynamic-sharing surface: unregister + Run env/cwd + peer service discovery (#50, #51, #52) — design

**Date:** 2026-07-25 · **Status:** Approved · **Ships in:** 0.10.1 (all additive; api_minor bump)

Three complementary gaps in bolo's per-server MCP sharing (a user shares an installed MCP
server with named peers; each shared server is its own mcpmesh service with #44 grants). All
additive, none blocking.

## #50 — `unregister_service` verb (deregistration)

Registration is add-only: `register_service` upserts; the only removal is
`unregister_ephemeral` (fires on the registering connection's close, #36). An embedder that
registers dynamically accumulates dead `[services.*]` entries forever.

- `Request::UnregisterService { name }` + `ControlClient::unregister_service(name)`.
- Removes the WHOLE `[services.<name>]` entry (allow list included — grants are meaningless
  once the service is gone; a re-register starts from an explicit allow). Also drops an
  in-memory ephemeral registration of that name.
- Idempotent (unknown name → clean no-op), under the SAME `reload_lock` as
  `register_service`/#44, then hot-reload. In-flight sessions finish (the reload rebuilds the
  registry without the service; no NEW sessions admitted) — matching `service_allow_revoke`.
- New `config_write::remove_service_from_config(path, name) -> bool`.

## #51 — `Run` backend `env` + `cwd`

`BackendSpec::Run { cmd }` inherits the daemon env and adds identity vars only — so most real
MCP servers (a token, a cwd, an `npx` inside a repo) can't be a `Run` backend, forcing
embedders to reimplement process supervision behind a `Socket`.

- Additive fields: `BackendSpec::Run { cmd, env: BTreeMap<String,String> (default {}), cwd:
  Option<String> }`. Config: `[services.x] run=[…] cwd="…"` + `[services.x.env]` table.
- `ServiceCfg` gains `env`/`cwd`; `backend_result` carries them; `SpawnBackend` gains them and
  applies: **`command.envs(service_env)` then `command.current_dir(cwd)`, and the
  `MCPMESH_PEER_*` injection stays LAST** so identity can never be spoofed by a service's env
  (a service-defined `MCPMESH_PEER_*` is overwritten). `config_write::write_service_to_config`
  persists env/cwd for a Run backend.
- **Secrets:** literal env values in `config.toml` — the same posture as every MCP client's
  config; the file is already owner-only (0600). Surface-clean: backend *definition*
  vocabulary, never in `status` (which shows `BackendKind` only).

## #52 — discover a peer's currently-granted services

`PeerInfo.services` is frozen at pairing — a peer registering + granting a new service later is
invisible to the grantee. (`dial_service` doesn't validate the name against the stored record,
so *knowing* the name still dials — only discovery is missing.)

- **Mechanism (bolo's preferred option 1, via the existing probe):** extend the trust-gated
  `mcpmesh/ping/1` pong to carry the **caller-admitted** service names — the responder already
  resolves the caller's identity, so it computes "which of my services' allow admits this
  principal" (`mcpmesh_local_api::principal_set` over each service's allow) and returns them.
  The caller learns ONLY services granted to its own principal — never the full registry.
- `Request::PeerServices { peer }` → `PeerServicesResult { services }` +
  `ControlClient::peer_services(peer)`: resolve `peer` (nickname → stored `PeerEntry`, or
  `eid:`/`b64u:` principal) to its endpoint, probe `ping/1`, return the pong's service list.
  Authoritative, always current, on-demand, no gossip.
- `ReachEntry` gains `services`; the probe caches them (a bonus for reachability consumers),
  and `peer_services` runs a fresh probe so the answer is current.

`API_MINOR` → 9. Bump 0.10.1 (all additive; existing configs/pairings unaffected).

## Non-goals

Secret references/vaulting for #51 (literal values, owner-only file); refreshing the frozen
`PeerInfo.services` (kept as the pairing dial-directory; #52 adds a separate current view);
severing in-flight sessions on unregister (they finish, per #50).

## Testing

- **#50:** register → unregister removes the config entry + reloads; idempotent unknown-name
  no-op; ephemeral unregister via the verb; a dial after unregister is refused a NEW session.
- **#51:** a Run service with `env`+`cwd` spawns the child with them; `MCPMESH_PEER_*` wins
  over a service-defined collision (identity not spoofable); config round-trips env/cwd.
- **#52:** two nodes, A grants B a service after pairing → B's `peer_services("A")` returns it;
  a service NOT granted to B is absent (only caller-admitted); caller-admitted computation
  matches `caller_admits`.
- Adversarial review of the diff (the env-precedence security property + the new peer RPC).
