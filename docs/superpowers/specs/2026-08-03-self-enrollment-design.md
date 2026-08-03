# Self-enrollment: one person, several devices (#86 ask 1)

**Status:** accepted · **Target:** 0.35.0 (MINOR) · **`api_minor`:** 42 → 43

## The design decision: enrollment moves a BINDING, never a key

The issue frames this as needing to "derive or transfer the UserKey", and calls the embedder-side
workaround — copying `user.key` between roots — tempting but wrong. It is worse than wrong: it moves
raw private key bytes, and every copy is another place the person's whole identity can leak.

**It is also unnecessary.** `binding::present(user_key, device_endpoint_id)` signs an *arbitrary*
endpoint id, and `verify_presented(user_pk, sig, authenticated_endpoint)` checks it against whatever
endpoint actually authenticated. So the device that holds the key can sign a binding **for the new
device's endpoint**, hand over just that signature, and the new device presents it forever after.

```
A (holds user_key)          B (new device)
        │   ── SAS-authenticated pairing rendezvous ──   │
        │  <──────────  B's authenticated endpoint id     │
        │  sign_device_binding(user_key, B_endpoint)      │
        │  ──────────>  (user_pk, sig)                    │
                                       B stores it as its OWN SelfBinding
```

Both devices now present the same `user_pk`, so both resolve to the same `user_id` on every peer
they pair with. **The private key never leaves A.**

### What that costs, stated up front

- **An enrolled device cannot enroll a third.** B holds no private key, so it cannot sign a binding
  for C. Every device is enrolled from the one that holds the key. That is a limitation *and* the
  security property — one copy of the key, in one place.
- **There is no revocation.** A binding, once issued, verifies forever; nothing in mcpmesh can
  withdraw it. Losing an enrolled device means rotating the user key, which changes the `user_id`
  and requires re-pairing with everyone. #85 is where identity lifecycle belongs.

## Ceremony

`invite { as_self: true }`, redeemed with the ordinary `pair`. The SAS comparison is unchanged and
is **more** load-bearing than usual: the inviter signs a binding for whichever endpoint redeemed, so
a redemption by an impostor mints *that impostor* a binding for the person's identity. The invite
secret plus the SAS is what prevents it — the same protection pairing already relies on, applied to
a higher-value payload.

Consequently:

- **`as_self` requires `max_uses = 1`.** A multi-use identity invite is a standing offer to become
  this person; refused at mint. (The same call `peer_nickname` made in #87.)
- **No peer row is written on either side, and nothing is granted.** The two devices are the same
  person, not peers of each other. Writing a row would put a person in their own contact list and —
  worse — make their own second device an authorizable principal.

## Ask 2: refreshing a stored binding

The issue offers "re-pair" as an acceptable answer and that is the answer. A peer stores a
`user_id` at pairing; re-pairing rewrites it. There is no push-refresh, and inventing one would mean
an unsolicited identity update from a peer, which is a strictly worse trust story than a fresh
ceremony. Documented rather than built.

## Surface

- `InviteParams.as_self: bool` — additive, `#[serde(default)]`.
- `Invite.as_self: bool` — on the invite line, so the redeemer knows to adopt rather than pair.
- `PairResult.enrolled_as_self: bool` — so a caller can tell the two outcomes apart without
  inspecting its own store.
- The adopted binding is persisted next to the user key, and boot prefers it over the
  locally-derived one.

## Versioning

**MINOR → 0.35.0.** New `pub` fields on structs an embedder constructs. **`api_minor` 42 → 43.**

## Testing

1. End to end: A mints `as_self`, B redeems, and B thereafter presents A's `user_pk`.
2. **Neither side writes a peer row**, and nothing is granted. This is what keeps a person out of
   their own contact list and out of their own allow lists.
3. The binding B adopts verifies against **B's own endpoint**, not A's — it is B's to present.
4. The adopted binding **survives a restart** (it is the only copy; B cannot re-derive it).
5. `as_self` + `max_uses > 1` is refused at mint.
6. An ordinary invite still pairs normally — the flag must not change the default path.
7. A peer pairing with both devices resolves both to the SAME `user_id`.

Mutation: writing a peer row on either side fails 2; signing A's endpoint instead of B's fails 3;
not persisting fails 4; allowing multi-use fails 5; defaulting `as_self` to true fails 6.
