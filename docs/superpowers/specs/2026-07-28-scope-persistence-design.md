# O(1) blob-scope persistence (#84c)

**Status:** accepted · **Issue:** #84 item (c) · **Target:** 0.19.0 (on-disk format change → MINOR)

## Problem

`ScopeStore` holds the whole scope table in memory and, on **every** mutation, clones it and
re-serializes the entire thing to one JSON sidecar (`ScopeStore::persist`). Publishing file N+1
costs O(N); the cumulative cost of publishing N files is O(N²).

That was tolerable when a scope was a room. It is not now: #84(d) settled that the intended
granularity is **one scope per file** (`file:<hash>`), so scope count grows with every file ever
shared. 0.17.0 (#107) made it worse by adding a per-scope `withdrawn` set — every row is bigger, and
the withdrawn set is never pruned.

## Approach — redb, not per-scope files

**Per-scope files are the obvious idea and they are wrong here.** Scope names are `file:<hash>`, and
`:` is an invalid filename character on Windows, which CI builds and tests. Encoding names into safe
filenames (hex, base32, hashing) buys a directory of thousands of tiny files, a name→file mapping to
maintain, and no transaction across a multi-scope mutation. It trades an O(N) write for a pile of
new failure modes.

**redb 2 is already a workspace dependency** (the peer allowlist store uses it). It gives keyed
O(log N) writes, real transactions, and no filename problem:

```
table "scopes":  scope_name (&str) -> serde_json::to_vec(&Scope)
```

- **Reads are unchanged.** `BlobScopes` stays in memory behind the existing `RwLock`, so `allows`,
  `list_page` and the request-time gate keep their current cost and their current lock discipline.
  This change is about the WRITE path only.
- **A single-scope mutation writes one key.** `publish_hash`, `unpublish_hash`, `grant`,
  `revoke_from_scope` become O(log N) instead of O(N).
- **Multi-scope mutations stay O(N) but become one transaction.** `revoke_principals` (unpair
  hygiene) touches every scope; that is inherent, it is rare, and today it is *also* O(N) with no
  atomicity. One write txn is strictly better.

### The lock hazard this introduces, and how it is handled

#61 cost a release to diagnose: a detached task held the trust gate → `PeerStore` → the redb
data-dir lock, so a restart hit `DataDirInUse`. A second redb file means a second such lock.

Mitigations, both required:

1. The `Database` handle lives on `ScopeStore`, which is owned by `AppBlobs`, which
   `Node::shutdown` already takes and drops via `boot::shutdown_booted` (#105). No detached task
   may hold it.
2. `shutdown_frees_the_root_even_with_a_live_subscription_attached` is extended to assert a second
   node can open the same root after shutdown — it is the existing regression test for exactly this
   failure and it must cover the new lock.

**Rejected:** sharing the peer store's `state.redb`. It couples blob availability to the trust
store's lifetime, and the peer store is opened before the blob provider exists.

### Migration

On `ScopeStore::open`:

- redb file exists → use it.
- redb absent, JSON sidecar present → **import the sidecar in one transaction**, then rename it to
  `blob-scopes.json.migrated` rather than deleting it. A destructive migration of authorization
  state on first boot of a new version is not something to do silently.
- Neither → empty store.

A downgrade after migration finds no sidecar and starts empty — **every grant and withdrawal
invisible**. That is worse than 0.17.0's downgrade hazard (which lost only withdrawals), so the
renamed file is the recovery path and the release notes must say so plainly.

## Surface + versioning

No control-API change; `API_MINOR` unchanged. The **on-disk format** changes, which is a
behaviour change for an operator (backup/restore, downgrade) → **0.19.0**, MINOR.

`ScopeStore::open` replaces `load`; `new` (memory-only, used by tests and the ungated fetcher) keeps
its signature but no longer implies a path that will be written.

## Testing (TDD, RED first)

1. **Unit — a single-scope mutation writes only that key.** Instrument or assert via a second store
   opened on the same file that other scopes' rows are byte-identical after the mutation. Fails if
   the whole table is rewritten.
2. **Unit — round-trip.** Publish, grant, unpublish, reopen: hashes, grants and `withdrawn` all
   survive. Extends 0.17.0's persistence test to the new backend.
3. **Unit — migration imports a 0.18 sidecar**, preserves grants + withdrawals, and RENAMES the
   sidecar rather than deleting it. Assert the `.migrated` file exists and parses.
4. **Unit — migration does not run twice.** With both a redb file and a stale sidecar, the redb
   content wins and the sidecar is untouched.
5. **Unit — `revoke_principals` across many scopes is one transaction**: interrupting is not
   testable directly, so assert the post-state is all-or-nothing by checking every scope changed.
6. **Regression — shutdown frees the lock.** Extend
   `shutdown_frees_the_root_even_with_a_live_subscription_attached` so a second node opens the same
   root after shutdown, with a blob provider built. Fails if any task retains the `Database`.
7. **Bench-ish sanity — publishing 1000 scopes is not quadratic.** Not a strict timing assertion
   (this repo has learned that timing assertions on a loaded machine lie); instead assert the write
   count, which is the property that actually matters.
