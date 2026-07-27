# Blob revoke, unpublish, and GC (#62)

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

### 3. `blob_gc {}` — the reclaim

`iroh_blobs::store::gc::gc_run_once(store, live)` is public; `Blobs::delete` is `pub(crate)` and the
crate's own docs say *"Users should rely only on garbage collection for blob deletion."* So GC is
the supported path, not a workaround.

`live` = every hash in every scope. mcpmesh creates no persistent tags (`add_path`'s `TempTag` is
dropped at the end of `publish_path`), so the scope table is the **only** root — which is why "GC
deletes what no scope references" is exact rather than approximate.

**Fail-safe:** if the scope snapshot cannot be read, the verb **errors** rather than running with an
empty live set. An empty `live` would delete every blob on the node. This is the one destructive
verb on the surface and it must never run on a guess.

**Explicit only, never automatic.** No background GC, no GC-on-unpublish. An embedder that wants
retention runs it; nobody gets surprise deletion. Returns `{ retained }` so the caller can sanity-
check the root set before trusting the outcome.

## Surface + versioning

- `Request::{BlobRevoke, BlobUnpublish, BlobGc}` + params structs; `BlobGcResult { retained }`.
- `API_MINOR` 14 → 15, `API_VERSION` "1.14" → "1.15".
- `docs/local-protocol.md`: the three verbs, and explicitly that **unpublish removes reachability,
  not bytes** — bytes go on `blob_gc`.
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
4. **Integration — GC reclaims exactly the unreferenced.** Publish two blobs, unpublish one, GC:
   the unpublished hash is gone from the store and the retained one is still fetchable.
5. **Integration — GC is fail-safe.** With an unreadable scope store the verb errors and deletes
   nothing.
6. **Regression** — unpair hygiene (`revoke_principals` across all scopes) still works.
