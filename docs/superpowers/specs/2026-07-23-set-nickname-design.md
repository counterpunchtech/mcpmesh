# `set_nickname` control verb (issue #37) — design

**Date:** 2026-07-23 · **Status:** Approved · **Ships in:** 0.7.1 (additive, patch)

## Problem

Renaming a node today means an out-of-band `config.toml` write plus a full restart. The
external write is not serialized with the daemon's own config writers (lost-update window
against a concurrent pairing grant / `register_service`), and for an embedded `Node` the
restart means `shutdown()` + re-`start()` + re-registering services.

## Design

1. **Protocol (mcpmesh-local/1, additive; `API_MINOR` 1 → 2):**
   - `Request::SetNickname(SetNicknameParams { nickname })`, method `"set_nickname"`,
     `deny_unknown_fields` like every params struct. Ack result (`{}`).
   - `StatusResult.self_nickname: String`, additive
     (`#[serde(default, skip_serializing_if = "String::is_empty")]`) — the *effective*
     name (config override, else hostname, else fingerprint), closing the issue's
     write-only gap. Empty in mesh-less control-only mode.
   - `ControlClient::set_nickname(&mut self, nickname)` typed helper.
2. **Daemon:** `MeshState.self_nickname` becomes `std::sync::RwLock<String>` (read-clone
   accessor; never held across await). `MeshState::new` keeps taking `String` — no caller
   churn. The handler takes `reload_lock` (the SAME serialization as `register_service`),
   upserts `[identity].nickname` via a new `write_identity_nickname` (the
   `upsert_config_strings` one-liner pattern), and only on write success updates the
   in-memory name. Future invites/presentations pick it up immediately; no restart.
3. **Validation:** trimmed non-empty, and no `/` (the nickname becomes the peer-side
   `<peer>/<service>` mount prefix). Same empty-rejection posture as `peer_rename`.
4. **Semantics unchanged elsewhere:** display-only; peers keep their stored pairing-time
   nickname until re-invite (per the issue).

## Testing

Protocol serde tests (round-trip, unknown-field rejection, `StatusResult` additivity);
a dispatch-level integration test on a hermetic mesh (set → `status` reflects it →
`config.toml` contains it → a freshly minted invite carries it → empty and `/` are
refused); the embedded surface inherits the verb for free (same handlers).

## Out of scope

CLI porcelain for self-rename (no issue asks for it); any change to peer-side stored
nicknames.
