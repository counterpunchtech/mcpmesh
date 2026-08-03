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

Mutation, eleven run and eleven caught: the redeemer ignoring `as_nickname` fails 1 and 2; the squat
check reading `invite.nickname` instead of the chosen name fails 4; `encode()` not stripping
`peer_nickname` fails the line test; accepting `peer_nickname` with `max_uses > 1` fails 5; treating
a blank alias as absent fails 6; `effective_redeemer_nickname` returning the self-claim fails 3; and
the inviter applying its alias to the STORE but checking the self-claim also fails 3.

Four more from the gate round: leaking the alias into the refusal, and checking the self-claim
while storing the alias — the latter **survived the entire workspace** before, because no test drove
an inviter-side collision with an alias present; removing `as_nickname`'s validation from `redeem`
(its branch had no test at all, only `peer_nickname`'s); and dropping the trim.

**Tests 1 and 3 are deliberately end-to-end**, through the real two-sided ceremony, asserting on both
peer stores. A unit test of `effective_redeemer_nickname` proves nothing about which name the inviter
writes, and one of the redeemer's `local_name` nothing about what it stores — the call sites are the
entire claim. That is the failure mode this repo keeps hitting.

## What the gate found: "never sent" was false

The commit, the rustdoc and `docs/local-protocol.md` all said neither alias is ever sent. **The
inviter's was.** `encode()` strips it from the invite line, but the collision refusal interpolates
the colliding name into `PairReply::Refused.reason`, and this change had pointed that at the
*chosen* name — which is the alias. Reproduced: the redeemer received

```
nickname 'MY-PRIVATE-NAME-FOR-BOB' is already taken by another paired peer; …
```

Two harms, not one. It disclosed the inviter's private name for that peer, and when the clash was
with a **third party** it disclosed that peer's nickname too. It also carried `ERR_NICKNAME_TAKEN`
— the documented rename-and-retry code — over a name the redeemer cannot influence, so an embedder
following the contract would rename and retry forever.

An aliased collision now answers the **generic** refusal, byte-identical to every other opaque one,
so it discloses not even that a collision occurred. The operator gets the detail server-side. And
`mint_invite` now checks the alias against the peer store at MINT, where the error reaches the
person who chose the name and can still act on it.

**A guessed-at scope error, corrected:** the gate also reported that a same-id re-pair checks a name
it will never store. It does not — `resolve_and_check_collision` computes
`existing.is_none() && nickname_collision(...)`, so an existing entry short-circuits the check
entirely. Verified before acting.

## Aliases were unvalidated where `set_nickname` is strict

They took anything. `"alice/notes"` made the peer permanently unmountable (`split_target` cuts at
the first `/`), and `" alice "` slipped past a collision check that compares exact bytes while
rendering identically to `alice`. Both aliases now go through one `validated_alias` applying the
same rules as `set_nickname`: trim, reject `/`, reject control characters, cap at 64 characters.

## The CLI could not reach any of it

`mcpmesh invite` had no `--peer-name` and `mcpmesh pair` no `--as`, so a fix for "two same-model
laptops" was reachable only from a hand-rolled JSON-RPC client — while the CLI kept printing the
refusal that says to go ask the other person. Both flags now exist, plus `ControlClient::invite_named`
and `pair_as`. `--as` with `--remove` is refused rather than silently ignored.

## Also fixed while here

`docs/local-protocol.md` claimed the redeemer-side squat check answers `-32000`. It has carried
`-32048 ERR_INVITE_NAME_CONFLICT` since #159; the paragraph was never updated. It also named
"unpair the existing peer first" as the remedy, which is now the *worse* of two — `as_nickname` is
self-service.
