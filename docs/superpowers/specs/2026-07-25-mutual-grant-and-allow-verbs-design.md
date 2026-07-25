# Mutual pairing grant (#43) + per-peer allow verbs (#44) — design

**Date:** 2026-07-25 · **Status:** Approved · **Ships in:** 0.10.0 (MINOR — #43 changes grant semantics; #44 is additive, rides along)

## Problem

- **#43:** redemption grants ONE way — the inviter's `[services.*].allow` gains the redeemer's
  principal, but the redeemer's allow gains nothing. So the redeemer can call the inviter,
  not vice-versa. Humans do one ceremony and expect a two-way relationship.
- **#44:** an embedder's "Sharing" toggle needs to revoke/grant a peer's access WITHOUT
  unpairing. `peer_remove` is too destructive (drops the `PeerEntry`); a full-set
  `register_service_with` write races the reload lock. No safe per-principal verb exists.

Both are greenfield for bolo — breaking change / api_minor bump fine.

## Design

### #43 — mutual grant (redeemer grants the inviter back, all served services)

At redemption completion the redeemer's daemon appends the **inviter's stable principal** to
the allow of **every service the redeemer currently serves** (scope decision: full mutual
trust — pairing is one-time + SAS-confirmed, so the inviter is already trusted; #44's revoke
narrows per-peer). The inviter's principal follows the SAME stable-principal rule as the
inviter side: the verified `b64u:` user_id when the inviter presented a binding
(`peer_user_id`, already computed in `redeem_invite`), else `eid:<inviter_id>`.

- **Mechanism:** `redeem_invite` gains an optional `grant_back: Option<GrantBackFn>` hook
  (symmetric with the inviter side's `GrantFn`) — the daemon wires it to
  `grant_service_access(mesh, principal, display, &all_served_service_names)`; tests pass
  `None`. Keeps `redeem_invite`'s return type (and its existing test callers) unchanged.
- The redeemer computes `inviter_principal` from data it already has; display name = the
  invite's suggested nickname (the redeemer's name for the inviter). Empty served set → no-op.
- The grant runs under the SAME `reload_lock` `grant_service_access` already takes, so it is
  serialized against concurrent config writes (no lost-update).

### #44 — per-peer allow verbs

Two idempotent control verbs, each under `reload_lock`, peer identity (`PeerEntry`) untouched:

- `Request::ServiceAllowGrant { service, principal }` → append `principal` to
  `[services.<service>].allow` + hot-reload. Reuses `grant_service_access(mesh, principal,
  principal, &[service])` (already idempotent; unknown service logs + no-ops).
- `Request::ServiceAllowRevoke { service, principal }` → remove `principal` from that ONE
  service's allow + hot-reload. New `config_write::remove_principal_from_service(path,
  service, principal) -> bool` (single-service, vs. the existing all-services
  `remove_allow_from_config`), wrapped in a `revoke_service_allow(mesh, service, principal)`
  handler mirroring `grant_service_access`'s lock/reload discipline.
- `ControlClient::service_allow_grant` / `service_allow_revoke` typed ack helpers.
- Idempotent by construction: granting a present principal → `changed=false`, no reload;
  revoking an absent principal / unknown service → `changed=false`, no reload. Clean no-op.

`API_MINOR` → 8.

## Non-goals

Signing/re-verifying the inviter at grant-back (already verified in the ceremony); changing
the inviter-side grant or the dial-back `PeerEntry` merge; a UI-level toggle (embedder owns
that, reading state from `status`).

## Testing

- **#43:** two-node redeem where the redeemer serves a service → after the ceremony, the
  redeemer's config allow contains the inviter's principal (b64u when the inviter is bound,
  else eid); an unbound inviter → eid; a redeemer serving nothing → clean no-op. The existing
  one-way grant assertions (inviter side) stay.
- **#44:** `service_allow_grant` then a dial admits; `service_allow_revoke` then the peer is
  refused a NEW session (identity row still present — not an unpair); both idempotent; unknown
  service/principal → clean no-op. Driven over the real control API.
- Adversarial review of the diff (grant semantics + the new write verbs) before shipping.
