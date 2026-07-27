# Blob revoke and unpublish (#62)

**Status:** accepted · **Issue:** #62 · **Target:** 0.13.3 (additive verbs → PATCH)

## Problem

The blob control surface is `blob_publish` / `blob_grant` / `blob_list` / `blob_fetch`. There is no
way to withdraw access, remove a hash, or reclaim disk. Three things are unimplementable:

1. **Un-sharing a file** without unpairing the person — the blob analogue of #44.
2. **Retention and redaction.** An embedder promising "this file is deleted" cannot deliver it.
3. **Disk reclaim.** `<data_dir>/blobs/` grows monotonically for the life of the node.

The issue notes the revoke capability already exists internally (`ScopeStore::revoke_principals`,
with a passing test) and is simply unreachable from the control API.

## Approach

Three verbs. The unifying idea: **the scope table is the liveness root.** A blob is reachable iff
some scope lists its hash, and authorized iff that scope grants a caller principal. Everything
follows from that.

### 1. `blob_revoke { scope, principals }`

Removes principals from ONE scope's grant set. Note this is *not* the existing
`revoke_principals`, which strips a principal from **every** scope — that is unpair hygiene, and
using it here would silently withdraw access the caller never asked to touch. New
`BlobScopes::revoke_from_scope`, alongside the global one.

### 2. `blob_unpublish { scope, hash }`

Removes a hash from a scope. This is the **authorization** boundary: `BlobScopes::allows` requires
the hash to be in some scope, so an unpublished hash is immediately unfetchable — no GC needed for
the security property.

**It does not delete bytes**, and the docs must say so plainly. Shipping "unpublish" while implying
deletion would be the exact false promise the issue says it refuses to make to users.

### 3. GC — descoped mid-implementation, and why

The plan was a `blob_gc` verb calling `gc_run_once(store, live)`. **That function is not reachable:**
`iroh_blobs::store::gc` is a private module, and only `GcConfig` / `ProtectCb` / `ProtectOutcome`
are re-exported. `Blobs::delete` is likewise `pub(crate)`, with the crate's own docs directing users
to GC. So iroh-blobs 0.103.0 supports **only periodic background GC**, configured on the store at
load time — not an on-demand sweep.

That is a materially different design from the one specced: automatic rather than explicit, with a
config surface (interval, enable/disable) and a destructive failure mode if the liveness callback is
wrong. It is implementable and safe — `ProtectOutcome::Abort` exists precisely so a callback whose
hash source errored can skip the run rather than delete on a guess — but it deserves its own design
pass rather than being redesigned inside this change.

Split out to its own issue with the research attached. Shipping revoke + unpublish now is not a
punt: together they answer ask 1 in full and the *authorization* half of ask 2, which is the half
that is a security property. Ask 2's byte-deletion half and ask 3 need the GC design.

## Surface + versioning

- `Request::{BlobRevoke, BlobUnpublish}` + params structs.
- `API_MINOR` 14 → 15, `API_VERSION` "1.14" → "1.15".
- `docs/local-protocol.md`: the three verbs, and explicitly that **unpublish removes reachability,
  not bytes** — bytes remain in the store, and there is no reclaim yet.
- Workspace version → **0.13.3** (additive verbs → PATCH).

## Explicitly NOT in scope

`blob_publish_bytes` / `blob_fetch_bytes`. The issue marks them "optional", and they are a separate
concern (an in-memory transfer path) from access withdrawal and retention. Worth their own issue —
the argument that publishing sensitive content should not require a plaintext temp file is a good
one and deserves its own design rather than a tail-end addition here.

## Testing (TDD, RED first)

1. **Unit — `revoke_from_scope` is scoped.** Revoking a principal from scope A leaves its grant on
   scope B intact. Distinguishes the new method from the existing global `revoke_principals`;
   fails if wired to the wrong one.
2. **Unit — unpublish removes reachability.** `allows(hash, principals)` is true before and false
   after, with the grant untouched — the authz property, independent of GC.
3. **Unit — unpublish is scoped.** A hash published into two scopes stays reachable via the other.
4. **Integration — an unpublished blob is refused over the wire.** The gate denies a fetch for a
   hash removed from its scope, while a peer's other granted blob still fetches.
5. **Regression** — unpair hygiene (`revoke_principals` across all scopes) still works.
