# Branchable codes for the onboarding refusals (#159)

**Status:** accepted · **Target:** 0.27.1 (PATCH) · **`api_minor`:** 36

## Problem

`ERR_NICKNAME_TAKEN` (#147) is the *only* pairing failure with a code. Everything else in the flow
arrives as `-32000` plus prose, so an embedder either forwards our sentence verbatim to end users or
substring-matches it. bolo does the former — which means our wording silently became their onboarding
copy, and a reword on our side changes what a stranger reads in their first five minutes.

They explicitly asked us to draw the boundary: *"you know which of these are genuinely
distinguishable inside the daemon better than we do."*

## Where the boundary is

### Codeable — every one of these is decided locally or reveals nothing new

| code | condition | recovery it licenses |
|---|---|---|
| `-32044` `ERR_INVITE_EXPIRED` | the invite line's own `expires_at_epoch` has passed. Checked **before dialing**, from the line in hand. | ask for a fresh invite |
| `-32045` `ERR_INVITE_NOT_LIVE` | the inviter has **no outstanding invite at all** — its accept gate fast-closed us. | ask for a fresh invite |
| `-32046` `ERR_INVITER_UNREACHABLE` | could not dial the inviter's address at all. | check they are online, retry |
| `-32047` `ERR_INVITER_MISMATCH` | the TLS-authenticated peer is **not** the id the invite names — the address-swap defense fired. | **do not retry**; the invite or the route is substituted |
| `-32048` `ERR_INVITE_NAME_CONFLICT` | the invite asks to be called a name this node already uses for a different peer. | ask for an invite suggesting a different name |
| `-32049` `ERR_INVITE_REFUSED` | the inviter refused, cause **deliberately withheld**. | ask for a fresh invite |

`-32047` deserves emphasis: bolo did not ask for it, and it is the one refusal here that should
*not* be rendered as a friendly retry. It means the endpoint that answered is not the one the invite
names. An embedder that treats every pairing failure as "try again" is papering over exactly the
attack the check exists to catch.

### NOT codeable, and this is the answer to their first ask

**"Invite expired" vs "already consumed" cannot be distinguished on the wire**, and we should not
make them so. The inviter answers a deliberately generic refusal for unknown-vs-expired-vs-wrong
secret because distinguishing them is a **redemption oracle**: a prober presenting guessed secrets
would learn which ones were ever real. That property is load-bearing and predates this issue.

`ERR_INVITE_NOT_LIVE` gets as close as is safe: it says *the inviter has nothing outstanding*, which
is a fact about the inviter, not about the probed secret. When it fires, "expired, already used, or
cancelled" is the honest union — and it is the everyday shape of the failure bolo is describing.

`ERR_INVITE_REFUSED` covers the rest without splitting it.

### Not applicable

**SAS mismatch is not a refusal and cannot be one.** The short authentication code is compared by two
humans out of band; the daemon never learns the other side's reading. There is nothing to signal. A
mismatch means the humans stop and unpair — which is `peer_remove`, not a pairing error.

## Design

One typed error carrying its code, rather than six marker structs:

```rust
pub struct PairRefusal { code: i64, message: String }
```

`respond` downcasts it once and uses `.code`. Adding the seventh condition later is then a constant
plus a call site, not another arm.

**No prose changes.** The issue is explicit that the wording is wanted for the diagnostic tail; the
code is what lets a consumer decide *per case* which to show and which to replace.

## Versioning

**PATCH → 0.27.1.** New `pub const`s and a path that answered `-32000` answering something specific.
No shape changes. `API_MINOR` 36 — an embedder must guard on `>= 36`, since below that every one of
these is `-32000`.

## Testing

1. Each condition produces its own code, end to end through `respond`.
2. `-32047` (id mismatch) is distinct from every "retry me" code — the one that must not be
   rendered as a friendly retry.
3. The **opaque** refusal keeps its generic prose while gaining `-32049`: the code must not
   distinguish unknown-vs-expired-vs-wrong-secret. Assert the reason is byte-identical across those
   three inputs.
4. An unrelated failure still answers `-32000`, so the codes stay meaningful.

Mutation: mapping any two of these to one code fails 1; splitting the opaque refusal by cause fails 3.
