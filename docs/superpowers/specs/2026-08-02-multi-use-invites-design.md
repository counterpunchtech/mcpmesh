# Bounded multi-use invites (#87, separable ask)

**Status:** accepted · **Target:** 0.27.0 (MINOR) · **`api_minor`:** 35

## Problem

Every invite is single-use, so onboarding a team is N ceremonies: mint, send, wait, repeat. The
reporter framed it as *"the difference between 'add your colleagues' being a five-minute task and an
afternoon."*

## Design

`invite { max_uses }` — an invite redeemable up to `max_uses` times, each redemption performing its
own SAS ceremony and writing its own mutual `PeerEntry` rows exactly as today.

### The wire

- `InviteParams.max_uses: Option<u32>` — absent means **1**, so nothing changes for any existing
  caller. Note `InviteParams` is `deny_unknown_fields`, so **sending it to an `api_minor < 35`
  daemon fails with `-32602 unknown field` rather than degrading to single-use.** Loud is the right
  behaviour, but an embedder must omit the field rather than rely on it being ignored — an earlier
  draft of this spec claimed the opposite.
- `Invite.uses_remaining: u32` — `#[serde(default = "one")]`, so an invite line minted by an older
  daemon decodes to a single-use invite rather than an unusable one.
- `InviteResult.uses_remaining` so the minting embedder can show "3 of 5 left" without re-parsing
  the line it just received.

### Redemption

`try_redeem` decrements instead of unconditionally removing. It burns — removes — when the count
reaches zero, so the terminal state is byte-identical to today's single-use behaviour and the
accept-gate's `count() == 0` check keeps working unchanged.

Every existing guard applies per redemption and is untouched: the nickname-collision pre-check, the
post-redeem race guard, expiry, and the SAS. Two people redeeming the same invite are two
independent ceremonies that happen to share a secret.

### Bounds

`max_uses` is clamped to **`MAX_INVITE_USES = 64`**, and `0` is rejected as invalid params rather
than silently meaning "unusable". A bearer credential's blast radius is `max_uses × TTL`; an
unbounded count would let one leaked line enroll arbitrarily many devices for 24h. 64 is comfortably
above "a team" and far below "a fleet".

### Persistence

The remaining count rides the existing `invites.json` (#87b) with no new mechanism — a decrement is
a mutation, so it persists through the same write-through path, under the same async write lock.

**A decrement that cannot persist FAILS the redemption**, rolling the count back and answering
`Redeem::Unavailable`. An earlier draft warned-and-continued on the reasoning that "the pairing has
already succeeded" — it has not: the decrement happens before any peer rows are written, so refusing
denies a pairing that has not happened yet. And the cost of continuing is not the "one higher" that
draft claimed; it is up to `max_uses` extra redemptions per restart within the TTL.

## Security notes, stated rather than implied

- A multi-use invite is a bearer credential that admits **up to `max_uses` distinct devices**. That
  is strictly more exposure than single-use, which is why it is opt-in, capped, and reported back in
  `InviteResult`.
- It does **not** weaken any authentication: each redemption still proves possession, still runs its
  own SAS for the humans to compare, and still writes an independently authenticated `PeerEntry`
  keyed on the redeemer's TLS identity.
- It does **not** become a group credential — there is no shared identity. N redemptions produce N
  separate paired peers.
- **It widens the pair-ALPN window** (gate finding). The accept gate fast-closes when no invite is
  outstanding; a single-use invite made that door shut seconds after minting, while a multi-use one
  holds it open for the whole TTL. Strangers reach the rate-limited rendezvous for up to 24h rather
  than seconds. No code changed there — the property did — and it is the one genuinely new exposure
  to a caller without the secret.
- **A redemption that cannot be RECORDED is refused** (`Redeem::Unavailable`), not warned through.
  An unrecorded use is a credential we have lost count of: with `max_uses` up to 64, a warn-and-
  continue policy risks up to `max_uses` extra redemptions per restart inside the TTL, not the
  "one higher" an earlier draft of this spec claimed. It fails closed in the same direction `mint`
  does, and it runs before any peer rows are written, so it denies a pairing that has not happened
  rather than undoing one that has.

## Testing

1. Default is 1: an `invite` with no `max_uses` behaves exactly as before, including burning.
2. `max_uses: 3` admits three redemptions and refuses the fourth as `Unknown` (the same answer a
   spent invite gives — no new oracle).
3. The count is **durable**: redeem once, restart, the remaining count is what it was.
4. `max_uses: 0` is rejected; above the cap is clamped, and the clamped value is what
   `InviteResult` reports (so the caller is never told it got more than it did).
5. An invite line from an older daemon (no `uses_remaining`) decodes as single-use.
6. Expiry still terminates a multi-use invite with uses left.

Mutation: removing instead of decrementing fails 2; not persisting the decrement fails 3; dropping
the clamp fails 4; a `default = 0` on the field fails 5.

**One thing is fixed but NOT pinned, and saying so is the point.** The post-redeem race guard passed
a hardcoded `invite_survived = false`, which with `max_uses > 1` told the loser of a nickname race to
fetch a fresh invite while it held one with uses left, and dropped `ERR_NICKNAME_TAKEN` exactly where
renaming would have worked — #147's defect, reintroduced. It now derives survival from the redeemed
invite. Reaching that arm needs a store write interleaved between `peek_live` and `try_redeem`, and
no seam exists for that; the rendezvous test added here covers the PRE-check path instead, and
flipping the fix back leaves it green. Same gap #87/#147 already recorded for this arm.

## Out of scope

The `as_nickname` / `peer_nickname` local aliases — the other optional half of #87(a).
