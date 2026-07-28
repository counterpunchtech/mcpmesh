# Durable blob revocation (#107)

**Status:** accepted · **Issue:** #107 · **Target:** 0.17.0 (surface change → MINOR)

## Problem

`blob_unpublish` removes a hash's reachability but not its bytes (#80: no reclaim), so the blob
stays complete in the local store forever and `blob_republish` re-adds it to the same scope — whose
grants unpublish never touched. Every principal that scope grants regains access, with no grant call
and no warning.

0.15.0 (#104) fixed the **atomicity** half: a republish decision made before an unpublish can no
longer land after it. It did not fix the semantic half, and a mutex cannot: exclusion is in
*lock-acquisition* order, not request-arrival order, so an unpublish that acquires first is still
erased by a republish acquiring second, both returning success.

Closing the class needs **state**, not exclusion.

## Approach — a per-scope withdrawal set

`Scope` gains `withdrawn: BTreeSet<String>` alongside `hashes` and `grants`.

- **`blob_unpublish { scope, hash }`** removes from `hashes` AND records in `withdrawn`.
- **`blob_republish { scope, hash }`** refuses if the hash is in that scope's `withdrawn` →
  new `BlobWithdrawn` / **`-32042`**.
- **`blob_publish { scope, path }`** clears the hash from `withdrawn` as it publishes.

Persisted in the existing scope sidecar, so it survives restart. That is not incidental: a tombstone
that evaporates on restart is the worst of both worlds — it reads as durable, then silently reverts.

### Why `blob_publish` is the un-withdraw and `blob_grant` is not

The rule is **deliberate acts clear a withdrawal; cheap ones do not.**

`blob_republish` takes a *hash* — content the node happens to still hold, typically fetched from
someone else. It is the cheap path, and the one an embedder is tempted to call as fetch hygiene. It
must not resurrect withdrawn content.

`blob_publish` takes a *path* — the operator names an actual file on disk. That is a deliberate
re-share of specific content into a specific scope, and treating it as "I mean it, un-withdraw this"
matches what the operator just expressed.

`blob_grant` is not the un-withdraw either: it grants a *principal*, says nothing about a hash, and
using it to clear a withdrawal would resurrect content as a side effect of an unrelated act — the
exact silent-widening this issue exists to stop.

### Scope boundary, restated because it will be misread

This makes an unpublish durable **on the node that ran it**. A recipient's re-advertisement from a
*different* node is outside the publisher's control and always will be — content addressing means
`blob_revoke`/`blob_unpublish` bind only where they run (documented in 0.14.1). This issue does not
change that and cannot.

## Surface + versioning

- `Scope.withdrawn: BTreeSet<String>`, `#[serde(default)]` so existing sidecars load unchanged and
  an old daemon ignores the field.
- New `ERR_BLOB_WITHDRAWN` = **-32042**, distinct from `-32041` (`NoSuchBlob`): the remedies differ
  entirely — "fetch it first" versus "this was deliberately withdrawn; re-publish from the file if
  you mean it".
- `blob_list` reports withdrawn hashes per scope, so an operator can see what is tombstoned rather
  than inferring it from a refusal.
- `API_MINOR` 18 → 19, `API_VERSION` "1.18" → "1.19".
- Workspace → **0.17.0** (surface change → MINOR).

## Testing (TDD, RED first)

1. **Unit — unpublish records the withdrawal**, and `republish` of that hash into that scope fails
   with `BlobWithdrawn` while the hash stays absent from `hashes`.
2. **Unit — the withdrawal is per-(scope, hash).** Withdrawing H from scope A does not block
   republishing H into scope B, nor a different hash into A. Fails if the set is global.
3. **Unit — `blob_publish` clears it.** After unpublish → publish from a path, a later republish
   succeeds. Pins the deliberate-act rule.
4. **Unit — `blob_grant` does NOT clear it.** Granting a principal on the scope leaves the
   withdrawal in force. Fails if un-withdraw leaks into the grant path.
5. **Unit — it survives a reload.** Write, drop, re-`load` the `ScopeStore`, and the withdrawal is
   still enforced. This is the whole point; a non-persisted tombstone is worse than none.
6. **Integration — the race from #107 is now closed.** Drive unpublish-then-republish concurrently
   via the existing delay seam and assert the hash is NOT served afterwards, whichever order the
   lock is acquired in.
7. **Regression — an un-withdrawn hash still republishes** (0.14.1's #83 behaviour is intact).
