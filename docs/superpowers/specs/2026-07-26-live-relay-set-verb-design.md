# Live relay-set control verb (issue #53) — design

**Date:** 2026-07-26 · **Status:** Approved · **Ships in:** 0.10.2 (additive verb — PATCH; carries an `iroh` 1.0.1→1.0.3 patch bump)

## Problem

bolo pins the mesh relay set via a managed `[network]` block (`relay_mode="custom"` +
`relay_urls=[…]`) written before `NodeBuilder::start()` — the only safe window, since a live
hand-write of the node config races the reload lock. bolo#10 adds a UI to let a user add their
own relay to the mix, but there is **no runtime control verb for relays** (the 0.10.1 surface
has `set_nickname`, `set_roster_url`, `set_app_metadata`, service verbs — nothing for
`[network]`). So applying a relay edit today means bolo must **restart the embedded node**
(stop → rewrite config → start) — a multi-second mesh blip on every edit.

## Feasibility finding (drives the design)

The issue assumed `iroh::Endpoint` has a live `set_relay_mode`/relay-map reconfigure. Our
pinned **iroh 1.0.1 has no such API** (the only live `Endpoint` setters are `set_alpns` and
`set_user_data_for_address_lookup`; `relay_mode()` is a consuming *builder* method). But
**iroh 1.0.3** (a patch bump, within our `^1.0` range) adds live, incremental mutation of the
running endpoint's `RelayMap`:

```rust
pub async fn insert_relay(&self, relay: RelayUrl, config: Arc<RelayConfig>) -> Option<Arc<RelayConfig>>
pub async fn remove_relay(&self, relay: &RelayUrl) -> Option<Arc<RelayConfig>>
```

`RelayConfig` is `{ url, quic: Option<…>, auth_token: Option<…> }` with `From<RelayUrl>`, so a
plain relay is `Arc::new(RelayConfig::from(url))`. The API is **incremental (insert/remove a
delta), not declarative set-mode** — that shapes the verb below. Returns `None` only if the
endpoint is closed; there is no failure path to reconcile beyond that.

## Design

### Verb: `set_relays { relay_urls: Vec<String> }`

Declarative from the caller's view — "make the custom relay set exactly this" — implemented as
a live diff. **Custom mode is implied** (see Scope). No `relay_mode` param: `custom` is the only
mode iroh 1.0.3 can live-reconfigure, and it is exactly bolo's mode. Result:

```rust
pub struct SetRelaysResult { pub changed: bool, pub restart_required: bool }
```

- **`changed`** — the persisted `relay_urls` differed from the prior config (a no-op edit →
  `false`, no writes, no endpoint calls).
- **`restart_required`** — `true` iff the node's current `relay_mode` is not `custom` (see
  Non-custom below); `false` for the live custom→custom path.

`ControlClient::set_relays(relay_urls) -> Result<SetRelaysResult>` typed helper.

### Handler (`node/src/daemon/handlers.rs`, mirrors `set_roster_url`)

Under `mesh.reload_lock` (held across the whole critical section — the lock is non-reentrant,
call `config_write` directly):

1. **Validate atomically.** Parse every entry as `iroh::RelayUrl` (same as `net_plan`,
   `boot.rs`). Any malformed URL → return an error, apply **nothing** (no half-applied set).
   Reject an **empty** list (custom mode requires ≥1 relay, matching the `net_plan` startup
   rule — fully disabling relays is a `relay_mode="disabled"` restart, out of scope here).
2. **Load current config** (`Config::load(&mesh.config_path)`) to read the current
   `network.relay_mode` and `network.relay_urls` (the last-applied set).
3. **Compute `changed`** = desired set (order-normalized) ≠ current `relay_urls`. If unchanged,
   return `{ changed: false, restart_required: <mode != custom> }` — no writes, no endpoint
   calls.
4. **Live apply — only when current `relay_mode == "custom"`.** Diff by URL:
   - insert `(desired − current)`: `mesh.endpoint.insert_relay(url.clone(), Arc::new(RelayConfig::from(url)))`
   - remove `(current − desired)`: `mesh.endpoint.remove_relay(&url)`
5. **Persist** `[network].relay_mode = "custom"` and `[network].relay_urls = […desired]` via a
   new `config_write::write_relays(path, &urls)` (array RMW; see below).
6. **Return** `{ changed, restart_required: current_mode != "custom" }`.

### Non-custom current mode (`default` / `disabled`)

iroh 1.0.3 cannot cleanly live-transition these: a `default` endpoint's `RelayMap` is n0's
built-in set (inserting customs yields n0 **plus** customs, and removing n0's entries needs
their URLs we don't hold); a `disabled` endpoint was bound with `RelayMode::Disabled`. So for a
non-custom current mode we **persist** the new `relay_mode="custom"` + `relay_urls` (so the next
restart's `build_endpoint` reproduces exactly this set) and return `restart_required: true` —
honest, not a pretend live-apply. bolo already runs `custom`, so its steady-state path is the
live custom→custom branch; `restart_required` is the correct answer only for a first-time
switch onto custom.

### Config writer (`node/src/daemon/config_write.rs`)

`relay_urls` is a TOML **array**, so `upsert_config_strings` (string-keys only) does not apply.
New `write_relays(path: &Path, urls: &[String]) -> Result<()>` modeled on
`write_service_to_config` / `append_allow_to_config` (which already do `toml::Value::Array`
RMW): read-modify-write `doc["network"]["relay_mode"] = "custom"` and
`doc["network"]["relay_urls"] = Array`, preserving every other key (`discovery_mode`,
`discovery_urls`, all other tables). `[network]` round-trips are already covered by existing
config_write tests.

`API_MINOR` → 10. Bump **0.10.2** (additive verb; existing configs/pairings unaffected).

## Non-goals

- A `relay_mode` param / live mode transitions (`default`↔`custom`↔`disabled`) — iroh 1.0.3
  can't back them live; a mode change stays a config-edit + restart. YAGNI: bolo edits the
  custom set only.
- Per-relay `auth_token` / QUIC config on the verb (plain `From<RelayUrl>`; add later if a
  consumer needs it — the `RelayConfig` slot is there).
- Discovery URLs (`[network].discovery_urls`) — separate concern, no live iroh path, unchanged.
- Reconciling a failed live insert/remove: the calls only no-op on a closed endpoint, and
  config is the durable truth a restart reconciles.

## Testing

- **Config writer:** `write_relays` writes `relay_mode="custom"` + the array and preserves
  other `[network]` keys (`discovery_*`) and other tables; round-trips via `Config::load`;
  overwrites a prior `relay_urls`.
- **Handler (unit/loopback):** current mode `custom` → `set_relays` with a changed set persists
  it and returns `{ changed: true, restart_required: false }`; same set again → `{ changed:
  false, … }` (idempotent, no writes); a malformed URL → error, config untouched; empty list →
  error; current mode `default` → persists custom + returns `restart_required: true`.
- **Live effect (loopback):** on a running custom-mode node, `set_relays` adding then removing
  a relay URL leaves the endpoint reachable (probe/dial still succeeds) — the reconfigure does
  not tear down the endpoint. (Asserting iroh's internal RelayMap is out of scope; we assert
  the node keeps serving across the edit + the config reflects the new set.)
- **iroh bump smoke:** full `cargo test` + clippy/fmt on the 1.0.3 bump (our `RelayMode::custom`
  / preset build paths in `boot.rs` are unchanged API across 1.0.x — verify by building).
- Real-network relay validation (two-machine, a real relay swap) is **recommended** before the
  release since this touches transport posture; the loopback suite gates CI, consistent with
  prior net-touching releases.
- Adversarial review of the diff (URL validation atomicity + the persist/live-apply ordering
  under the reload lock) before shipping.
