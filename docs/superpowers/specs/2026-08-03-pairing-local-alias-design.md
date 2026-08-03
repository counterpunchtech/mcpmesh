# Local aliases so a nickname collision is self-resolvable (#87, the optional half)

**Status:** accepted · **Target:** 0.31.0 (MINOR) · **`api_minor`:** 38 → 39

## Scope: everything else in #87 already shipped

Re-verified against `main` before starting:

- **(a) collision check before `try_redeem`, with a distinguishable reason** — shipped.
  `resolve_and_check_collision` runs at `rendezvous.rs:497`, ahead of `try_redeem` at `:514`, and
  `ERR_NICKNAME_TAKEN` (-32043) exists with `RefusalCode::NicknameTaken` (#147).
- **(b) durable invites + a distinguishable `ALPN_PAIR` refusal** — shipped.
  `node/src/pairing/persist.rs` (0600, atomic) and `NO_LIVE_INVITE_CLOSE` (#87b, `api_minor` 34).
- **Optional multi-use invite** — shipped. `InviteParams.max_uses` / `InviteResult.uses_remaining`,
  capped at `MAX_INVITE_USES = 64` (`api_minor` 35).

What remains is the one clause never built: *"Optionally, `PairParams.as_nickname` /
`InviteParams.peer_nickname` local aliases, so the redeeming side can disambiguate without renaming
itself globally."*

## Why it still matters after #147

#147 made the collision **diagnosable**. It did not make it **resolvable by the person hitting it**.
Both refusals currently tell the user to go ask the other human for something:

- Inviter side: *"nickname 'X' is already taken by another paired peer; …"*
- Redeemer side: *"this invite asks to be called 'X', but … **Ask them for an invite suggesting a
  different name.**"*

For two same-model Macs — the issue's exact case, and the default self-name is the hostname — the
only levers are `set_nickname` (rewrites your *global* self-name, which nobody wants in order to add
one colleague) or a re-mint by the other party. A local alias is the obvious fix and the issue asked
for it.

## Design

Two optional fields, one per direction. Each is **the caller's own local name for the other party**,
and neither is ever sent to or accepted from the peer.

| field | set by | replaces |
|---|---|---|
| `PairParams.as_nickname` | the redeemer, at `pair` | `invite.nickname` — the inviter's suggestion for what to call them |
| `InviteParams.peer_nickname` | the inviter, at `invite` | `hello.redeemer_nickname` — the redeemer's self-claim |

`InviteParams.peer_nickname` is stored **on the invite** and applied when that invite is redeemed,
so a multi-use invite carrying one deliberately names every redeemer the same — which is a
collision on the second redemption. **Refused at mint** rather than discovered on redemption number
two, because the alternative is an invite that works once and then cannot.

### The alias does not bypass the collision check

The chosen name — alias if present, else the peer's suggestion — is what the existing collision
check runs against, unchanged. An alias that itself collides is refused with the same code and the
same prose. This is the property that keeps the fix from becoming a hole: the check exists because a
duplicate display name makes `<peer>/<service>` routing ambiguous (first-match by name), and that is
just as true of a name the local user chose.

Grants are principal-keyed (#38), so no authorization follows a nickname either way.

### Validation

An alias goes through the same nickname rules as any stored name, at the control-API boundary, so a
bad one is a clean `-32602` rather than a pairing failure halfway through a ceremony. Empty is
rejected rather than treated as absent — `as_nickname: ""` almost certainly means a UI passed
through a blank field, and silently falling back to the peer's suggestion is how a user ends up with
the name they were trying to avoid.

## Versioning

**MINOR → 0.31.0.** `PairParams` and `InviteParams` are `pub` structs in a published crate and an
embedder constructs them, so a new field breaks exhaustive construction — the same call the
transport knobs got in #56. Wire-additive (`#[serde(default)]`), so an old caller is unaffected.

**`api_minor` 38 → 39.** New optional request fields; a consumer must guard on `>= 39` before
offering an alias in its UI, since below it the field is rejected outright by
`deny_unknown_fields` — loudly, which is the right failure, but it is still a failure to guard on.

## Testing

1. `as_nickname` names the inviter locally: the stored `PeerEntry` carries the alias, not
   `invite.nickname`.
2. `as_nickname` **resolves** the redeemer-side collision the issue is about — a `pair` that fails
   with `ERR_INVITE_NAME_CONFLICT` succeeds with an alias, same invite.
3. `peer_nickname` names the redeemer locally on the inviter side, overriding the self-claim.
4. **An alias that itself collides is still refused**, with the same code as without one — the check
   is not bypassed.
5. `peer_nickname` on a `max_uses > 1` invite is refused **at mint**, naming both.
6. An empty or invalid alias is a `-32602`, not a silent fallback.

Mutation: applying the alias *after* the collision check fails 4; using the peer's suggestion when
an alias is present fails 1 and 3; accepting `peer_nickname` with `max_uses > 1` fails 5; treating
`Some("")` as absent fails 6.
