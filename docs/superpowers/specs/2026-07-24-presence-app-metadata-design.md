# Signed app-metadata on presence (issue #39) — design

**Date:** 2026-07-24 · **Status:** Approved · **Ships in:** 0.9.0 (MINOR — signed presence-beat wire change)

## Problem

Embedders (bolo) want each peer's small app-metadata (motivating case: app version)
visible fleet-wide in near-real-time. Today the only way is to dial every peer's MCP
service and ask — a session per peer per poll, which also perturbs app-level idle
detection.

## Design

An optional, size-capped, **device-key-signed** metadata blob riding the existing roster
presence heartbeat. The daemon never interprets it; the embedder puts whatever it wants
inside (a version string, small JSON, …).

### Decisions (settled in brainstorming)

- **Roster-mode only.** Metadata rides the signed presence gossip beat, which exists only
  in roster mode. Pairing mode has no always-on channel and gets nothing (out of scope).
- **Signed.** The blob is inside the device-key signature peers already verify — a
  displayed app-version is authentic, not spoofable by any gossip participant.
- **Opaque ≤256-byte string.** Not a typed map; the embedder structures its own bytes.
- **`set_app_metadata` control verb.** In-memory on the daemon, folded into each outgoing
  beat; lost on restart (embedder re-sets on startup, like ephemeral services).

### 1. The beat (`node/src/roster/presence.rs`)

- Add `meta: String` to `Presence` (`#[serde(default, skip_serializing_if = "String::is_empty")]`).
- Include `meta` in `preimage()` **only when non-empty**. Consequence — the rollout story:
  a node that sets NO metadata produces signed bytes byte-identical to a pre-feature node,
  so old and new nodes keep verifying each other fully. Only a node that SETS metadata
  produces beats an old node cannot verify (it drops them, exactly as it drops any
  unverifiable beat) — acceptable, since enabling the feature means the new build is
  deployed. `verify()` reconstructs the preimage from the beat's own fields, staying
  symmetric with `signed()`.
- Raise the beat-size sanity assertion from 512B to 768B to fit ≤256B of metadata.

### 2. Set path (`set_app_metadata`)

- `MeshState` gains `app_metadata: std::sync::RwLock<String>` (the live-value pattern the
  `self_nickname` field uses since #37) with `app_metadata()` read-clone + `set_app_metadata()`.
- New `Request::SetAppMetadata { metadata }` (mcpmesh-local/1, additive) → handler validates
  `metadata.len() <= 256` (reject over-cap with a coded control error) and stores it. `""`
  clears. `ControlClient::set_app_metadata` typed helper.
- The publish loop reads the value FRESH each beat (as it already reads `roster_serial`).

### 3. Track + surface

- `PresenceEntry` and `PresenceTable::record` carry `meta` alongside `ts` (freshest beat wins,
  as today).
- `PresencePeer` gains `meta: String` (additive, skip-if-empty); `presence_peers()` joins the
  table's meta in. `API_MINOR` → 4, `API_VERSION` → "1.4".
- The node's OWN metadata in its OWN status is best-effort from the stored value (a node does
  not receive its own gossip).

## Non-goals

Pairing-mode metadata; a typed key-value schema; persistence across restart; any
authorization or gating role for metadata (it is advisory display data, exactly like the
rest of presence — it never feeds a gate or sever decision).

## Testing

- `signed`/`verify` round-trip WITH and WITHOUT meta, and the compat guarantee: an
  empty-meta beat's signed bytes equal a pre-feature beat's (old nodes still verify).
- ≤256B cap rejection at `set_app_metadata`.
- `PresenceTable` records + surfaces meta; a reordered older beat never regresses it.
- Protocol serde: `SetAppMetadata` frame + `deny_unknown_fields`; `PresencePeer.meta`
  additive round-trip.
- Integration: two roster nodes; A `set_app_metadata` → the value appears in B's `status`
  presence for A's device.
- Ultracode adversarial review of the diff before shipping.
