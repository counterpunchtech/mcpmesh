# `peer_introduce` — O(N) onboarding without weakening first contact (#65)

**Status:** accepted · **Target:** 0.34.0 (MINOR) · **`api_minor`:** 41 → 42

## Question 1, answered: there is no supported path today

The issue asks whether an out-of-band endorsement can install a peer now. **No**, and the three
candidates each fail for a different reason:

- **`pair`** requires a live redemption — a dial to the inviter over `mcpmesh/pair/1`, proof of a
  32-byte secret, and a SAS both humans read aloud. It cannot be driven from a payload.
- **#31's `app_label`** is carried through invite → pair, but it is **opaque by construction**:
  "mcpmesh never interprets it — not a nickname, never resolved or authorized". Making it install
  trust would turn the one field documented as inert into the most powerful one on the wire.
- **`peer_add`** is reserved/internal and stays that way.

Roster mode is the only supported non-ceremony path, and it needs the org apparatus the issue is
explicitly trying to avoid.

## Question 2, answered: `peer_introduce`, and for a stronger reason than surface discipline

The issue prefers a purpose-built verb over promoting `peer_add` with a trust tier, reasoning from
surface discipline ("raw endpoint ids should not be a casual input"). That is right, and there is a
load-bearing reason underneath it:

**`peer_add` + a tier would be unverifiable.** The local caller simply asserts "trust this id at
tier N", and the daemon has nothing to check it against. An endorsement can be **cryptographically
verified**: C signs it with the user key A already holds from pairing with C, so A checks the
provenance rather than taking its own caller's word.

That distinction is the whole feature. An introduction is not "peer_add with a label"; it is a
statement A can independently validate.

### The trust model, stated plainly

Pairing's SAS defends first contact against a man-in-the-middle. An introduction replaces that
defence with a **different** one: C's signature. A is trusting

1. that C's key is C's (established when A paired with C, with a SAS), and
2. **C's judgment and key hygiene** — a compromised C can introduce anyone.

That is a real reduction and it is the point of the feature; the design's job is to bound what it
buys an attacker.

### What bounds it: an introduction installs IDENTITY, never AUTHORIZATION

This is the decision that makes the reduced check safe enough to ship, and it means **no new trust
tier is needed**:

- `peer_introduce` writes a `PeerEntry` — endpoint id → nickname, plus the subject's `user_id` when
  the endorsement carries one. The peer becomes *resolvable*.
- It grants **nothing**. Service access is principal-keyed in config (#38) and stays an explicit,
  separate act.

So a compromised C can make A *know about* an attacker; it cannot make A *serve* one. The existing
separation between `PeerEntry` and `[services.*].allow` already does the work a tier would have had
to invent.

## Wire format

A new domain, alongside `mcpmesh/join/device-binding/1`, so a signature can never be replayed across
purposes:

```
mcpmesh/introduce/1 ∥ endorser_user_pk ∥ subject_endpoint_id ∥ subject_user_pk?
```

```rust
pub struct PeerIntroduceParams {
    /// The subject's endpoint id, `eid:<hex>`.
    pub subject: String,
    /// The endorser's user public key, `b64u:` — MUST already be a paired peer's `user_id`.
    pub endorsed_by: String,
    /// The endorser's signature over the domain-separated preimage, `b64u:`.
    pub evidence: String,
    /// The subject's own user key when the endorser vouches for it, `b64u:`. Optional.
    pub subject_user_id: Option<String>,
    /// OUR local name for the subject. Same rules as every other nickname (#87).
    pub nickname: String,
}
```

### Verification, in order, all mandatory

1. `endorsed_by` resolves to a **currently paired** peer whose stored `user_id` equals it. An
   endorsement from a stranger, or from a peer we have since unpaired, is refused — the trust chain
   must terminate at someone we paired with *ourselves*.
2. The signature verifies over the exact preimage, `verify_strict`, matching the roster path.
3. `subject` is not already stored under a different nickname, and `nickname` does not collide —
   the same guard pairing runs, for the same routing reason (#87).
4. `subject` is not our own endpoint id.

## Versioning

**MINOR → 0.34.0.** New verb + new `pub` params struct. **`api_minor` 41 → 42**: a consumer must
guard on `>= 42`.

## Testing

1. A valid endorsement from a paired endorser installs the peer, resolvable by nickname.
2. **It grants nothing** — the subject is refused by a service it was not explicitly granted. This
   is the property that bounds the whole feature.
3. An endorsement signed by a **non-paired** key is refused, even with a valid signature.
4. An endorsement from a peer we have **unpaired** is refused (the chain must be live).
5. A signature over a *different* subject does not verify — no transplanting.
6. A signature from the **device-binding** domain does not verify as an introduction, and vice
   versa. Domain separation is the property that stops replay.
7. Introducing our own endpoint id is refused.
8. A colliding nickname is refused, exactly as pairing refuses it.

Mutation: skipping the paired-endorser check fails 3 and 4; dropping the domain prefix fails 6;
verifying against the subject's key rather than the endorser's fails 5; granting on install fails 2.
