# Outstanding invites survive a restart (#87b)

**Status:** accepted · **Target:** 0.26.2 (PATCH) · **`api_minor`:** unchanged (33)

## Problem

`LiveInvites` is an in-memory `Mutex<HashMap>`, so **every daemon restart drops every outstanding
invite** — while the invite advertises a **24h TTL**. The reporter's product force-applies unattended
updates roughly every two hours, so an invite emailed to a colleague is reliably dead long before
its stated TTL, through no action by either person.

The redeemer's side of this already shipped: `pair` against an inviter with no live invite reports
*expired / already redeemed / inviter daemon restarted* rather than a bare connection failure (#87a,
0.23.4). What remains is that the failure happens at all.

## Decision

**Persist outstanding invites, at 0600.** The issue explicitly left this to us — "acknowledging that
this writes a bearer credential to disk, which is your call and not ours" — and the alternative
(shorten the advertised TTL) does not help someone emailing an invite to a colleague; it only makes
the failure predictable.

Persisting is **consistent with the existing posture, not a new risk class.** The device key already
lives on disk at 0600 and grants strictly more: it *is* the node's identity, permanently. An invite
secret is single-use, TTL-bounded, and grants only the right to pair. Declining to persist the lesser
credential while persisting the greater one protects nothing.

## Design

### Storage

`<data_dir>/invites.json` — a JSON array of `Invite`, rewritten whole on every mutation.

- **0600**, set at create time on the temp file (`OpenOptions::mode`), the same way `device.key` is
  written. Not chmod-after-write: that leaves a window where the secret is world-readable.
- **Atomic replace** — write a per-call-unique temp in the same directory, `sync_all`, then
  `rename` over the target. A torn invite file would be worse than no file: it fails the whole load
  and silently drops every outstanding invite, which is the bug being fixed.
- Deliberately **not** the redb trust store. That file is not 0600 today, and quietly changing the
  permissions of the trust store as a side effect of an invite feature is the wrong way to make that
  decision. Invites are also TTL-bounded ephemeral state, not trust data; a separate file is
  trivially inspectable and trivially deletable.

### Lifecycle

- **Load at boot**, dropping anything already expired, and persist the reaped set so the file does
  not accumulate.
- **Persist on every mutation**: mint, redeem (burn), reap.
- **A mint that cannot persist FAILS.** The advertised TTL is part of the invite's contract; handing
  someone an invite we already know will not survive is exactly what #87 filed. A write failure in
  the data dir is also a real problem the operator needs to see — the trust store lives there too.

### Not in scope

`max_uses` (multi-use invites) and the `as_nickname` / `peer_nickname` local aliases, both listed as
optional and separable in the issue. This is the durability half only.

## Security notes, stated rather than implied

- The file holds **bearer secrets**. Anyone who can read it can redeem those invites until they
  expire or are burned. 0600 plus the data directory's own permissions are the whole protection —
  the same protection the device key gets.
- Deleting the file is a safe operation that invalidates every outstanding invite. That is a
  legitimate operator action and worth documenting as one.
- Expiry is enforced on **load and on redemption**, not only by the reaper, so an attacker who
  preserves a stale file gains nothing.

## Testing

1. Mint → drop the registry → reload from the same path → the invite is still redeemable.
2. An **expired** invite does not survive a reload, and the file is rewritten without it.
3. Redemption is durable: burn → reload → the secret is `Unknown`, not redeemable twice.
4. The file is **0600** on unix.
5. A mint that cannot persist **errors** rather than returning an invite that will not survive.
6. A **corrupt/truncated** file does not panic and does not take the daemon down.

Mutation: making `mint` persist nothing fails 1; skipping the expiry filter on load fails 2; leaving
the burn unpersisted fails 3; dropping the `mode(0o600)` fails 4.
