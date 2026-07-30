# A nickname collision must not burn the invite, and a dead invite must say so (#87)

Date: 2026-07-29. Scope: asks (a) and the refusal half of (b). Persistence, TTL policy, the
local-alias slot, and multi-use invites are explicitly out (see Non-goals).

## Problem

(a) The nickname-collision check runs inside `Redeem::Ok` — after `try_redeem` has burned the
secret — and answers the generic `REASON_REFUSED`. Two hosts with the same hostname fail their
first pairing, the invite is spent, and neither side learns why.

(b) `LiveInvites` is in-memory, so a restart drops every invite while the invite advertises a
24h TTL; the `ALPN_PAIR` accept gate then fast-closes (`b"no pairing in progress"`) and the
redeemer reports a bare connection failure — "expired" presents as "unreachable".

## Design

### (a) Peek before burn; the collision refusal is distinguishable and non-destructive

Order is the whole design. A naive "check collision first" leaks store contents: a stranger with
a garbage secret and a guessed nickname would learn whether that nickname exists. So:

1. `LiveInvites::peek(secret, now)` — a NON-MUTATING validity check (Unknown / Expired / Live;
   never removes, never burns).
2. In `handle_inviter_side`, after the hello: `peek`. Not live → the existing generic path,
   unchanged (no oracle: unknown/expired stay indistinguishable).
3. Live → run the collision check (same `nickname_collision` scan, `spawn_blocking`). Collides →
   reply `Refused` with the new distinguishable reason and return WITHOUT calling `try_redeem`:
   the invite survives, and the redeemer is told to pick another name and redeem the SAME invite
   again. Telling the truth here is safe — the caller just proved possession of a live secret.
4. No collision → `try_redeem` (authoritative burn) exactly as today, and the EXISTING post-burn
   collision check STAYS as the race guard: two different redeemers claiming the same new
   nickname can both pass step 3 (neither stored yet); the loser must still be refused after the
   first one's store write. Burning in that race is acceptable and rare; the post-check's reason
   becomes distinguishable too (possession proven), with "ask for a fresh invite" guidance since
   that path did burn. The pre-check and post-check call ONE shared helper so neither can drift.

The race-guard post-check has no direct test: pinning it requires a store mutation interleaved
between peek and redeem inside one handler call, which no seam exposes. Stated gap, documented
at the call site — the shared helper's logic is pinned by the pre-check tests.

### (b) The dead-invite close becomes a readable error on the redeemer

The accept gate already closes with `b"no pairing in progress"`. The redeemer's dial/read path
surfaces it the same way #89's throttle detection reads the probe close: on failure, check
`Connection::close_reason()` for that application close and map it to a distinguishable error —
the invite is no longer live on the inviter: expired, already used, or the inviter's daemon
restarted (invites do not survive restarts). Any other failure keeps today's error.

## Wire / version

New `PairReply::Refused` reason strings on the pair ALPN (node-to-node, pre-1.0, no compat
shims). No control-API surface change → no `API_MINOR` bump. PATCH: `0.23.3 → 0.23.4`.

## Tests (mutation-verified)

1. **Collision does not burn**: inviter stores peer "x"; a redeemer self-named "x" is refused
   with the collision reason, then the SAME invite redeemed as "y" succeeds. Mutations: restore
   burn-before-check → second redeem fails; genericize the reason → message assertion fails.
2. **No oracle**: a garbage-secret dial with a colliding nickname gets the GENERIC reason —
   pins that the collision check never runs (and never answers) for an unproven caller.
3. **Dead-invite close is readable**: redeemer dials an inviter with no live invite → the error
   names the expired/restarted cause, not a bare connection failure. Mutation: drop the
   close-reason match → assertion on the message fails.

## Non-goals (noted on #87 for the owner)

- Persisting invites across restarts writes a bearer credential to disk — a policy call the
  issue itself defers to the repo owner.
- Shortening the advertised TTL is a product statement about process lifetime; same.
- `PairParams` local-alias slot and bounded multi-use invites are control-API surface changes —
  separable, and worth doing together if the owner wants them.
