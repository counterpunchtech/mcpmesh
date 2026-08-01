# The nickname-collision refusal leaks a control verb across the embedder seam (#147)

**Status:** accepted · **Target:** 0.25.1 (PATCH) · **`api_minor`:** 31

## Problem

`reason_nickname_taken` (`node/src/pairing/rendezvous.rs:78`) builds the invite-redemption refusal a
GUI embedder shows a human, and its recovery clause names a control verb:

> nickname 'studio-mac' is already taken by another paired peer; the invite was NOT consumed —
> **pick a different nickname (set_nickname)** and redeem the same invite again

`set_nickname` is *our* control-API verb. A bolo user cannot type it, see it, or find it — bolo's
affordance is a "Your name" field in a People panel, and every embedder has its own. Worse, the
embedder that *displays* the string is not the one that could rewrite it: the string is generated on
the **inviter's** side, travels to the redeemer as a `PairReply::Refused` reason, and surfaces
verbatim through the `pair` verb's JSON-RPC error. The only downstream fix is substring-matching our
prose.

The sibling clause `ask the inviter for a fresh invite` is the model: it names an action.

## Design

The issue offers "reword it, **or** split the machine-readable part from the human-readable part".
Do both — the reword alone leaves every embedder guessing from substrings, which is the more
durable half of the complaint.

### 1. The prose names the action

```
nickname 'X' is already taken by another paired peer; the invite was NOT consumed —
rename this node and redeem the same invite again
```

No verb, no API vocabulary. The burned-invite variant already reads correctly and is untouched.

### 2. A stable error code, so an embedder need not read the prose at all

This repo already has the pattern (`NoSuchService` → `ERR_NO_SUCH_SERVICE`): a typed error, a
downcast in `respond`, a stable JSON-RPC code. Follow it exactly.

- `ERR_NICKNAME_TAKEN: i64 = -32043` in `local-api/src/protocol.rs`.
- `NicknameTaken { nickname, invite_survived }` in `node/src/pairing/rendezvous.rs`, an
  `std::error::Error` whose `Display` is the reworded prose — ONE source for the string, so the
  wire reason and the local error cannot drift.
- `respond` (`node/src/control.rs:880`) downcasts it alongside the existing arms.

### 3. The redeemer must not substring-match either

The redeemer learns of the collision only through `PairReply::Refused { reason }` — a bare string.
Producing a typed error from it would mean parsing our own prose, i.e. shipping the exact anti-pattern
we are asking bolo to stop doing.

So `PairReply::Refused` gains a machine-readable discriminant:

```rust
Refused {
    reason: String,
    /// Additive (`#[serde(default)]`): an older inviter sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<RefusalCode>,
}
```

`RefusalCode` is `NicknameTaken` plus an `Unknown` catch-all reached by a hand-written
`Deserialize`, for the reason `ReachabilitySource` has one (#150): a future refusal kind must not
fail the whole reply on a pinned redeemer.

**This is a daemon-to-daemon wire change, not a control-API one.** `PairReply` is private to the
node crate. An inviter older than 0.25.1 sends no `code`, and the redeemer falls back to today's
generic `bail!` — same behavior as now, so a mixed-version pairing still works and still refuses
correctly, just without the branchable code.

**No oracle risk.** The code rides only the two refusals that already carry the distinguishable
collision reason — both sent exclusively to a caller that proved possession of a live secret (the
peek pre-check) or spent one (the post-redeem race guard). The generic `REASON_REFUSED` path, which
deliberately does not distinguish unknown-vs-expired-vs-wrong-secret, gains no code and stays
opaque. This spec does not widen what a refusal reveals; it only labels what it already said.

## Versioning

**PATCH → 0.25.1.** Purely additive: a new `pub const`, a new error code on a path that previously
answered `-32000`. No `pub` signature in a published crate changes shape — `PairReply` and
`RefusalCode` are private to `mcpmesh-node`.

`API_MINOR` 30 → **31**, `API_VERSION` "1.31", history line added. `docs/local-protocol.md` gains
the code in its error table and the `api_minor` index.

A consumer branching on `ERR_NICKNAME_TAKEN` must guard on `api_minor >= 31`; below that the same
condition arrives as `-32000` with the same prose.

## Testing

1. **The prose names no verb** — assert the refusal contains "rename this node" and, specifically,
   does NOT contain `set_nickname` or `(` — a regression here is a one-word edit away and reads
   fine to a reviewer.
2. **The collision refusal answers `ERR_NICKNAME_TAKEN`**, not `-32000`, end to end through
   `respond`.
3. **The generic refusal still answers the generic code and the opaque reason** — pins that the new
   code did not leak onto the oracle path.
4. **Wire additivity** — a `Refused` payload with no `code` key deserializes (older inviter); one
   with an unrecognized code deserializes to `Unknown` rather than failing the reply.
5. **`Display` and the wire reason are the same string** — pins the single-source claim.

Mutation-tested: restoring the verb name fails 1; mapping the collision to `-32000` fails 2; adding
the code to the generic path fails 3; deleting the hand-written `Deserialize` fails 4.

## Out of scope

The collision *policy* (#87) is unchanged: which redemptions are refused, and whether the invite
survives, are exactly as they are today. Only the wording and the branchability change.
