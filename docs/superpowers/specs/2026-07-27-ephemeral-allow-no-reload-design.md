# Ephemeral allow changes skip the registry rebuild (#94)

**Status:** accepted · **Issue:** #94 · **Target:** 0.13.6 (behaviour-preserving perf → PATCH)

## Problem

`service_allow_grant` / `service_allow_revoke` against an **ephemeral** service (#36/#55/#69) do a
full `Config::load` and a whole-registry rebuild, then log a warning describing a condition that is
correct and expected. The issue reports adding one person to a 20-member room as 20 serialized
round trips, 20 full config parses, and 20 misleading warning lines.

## What the issue gets right, and what it gets wrong

The **ask** is "skip the config read-modify-write *and* the disk reload entirely." Only the second
half is safe, and the first half is not where the cost is.

**The config write is not the cost.** `append_allow_to_config` returns `Ok(false)` **without
writing** when nothing changed (`config_write.rs:293`); `remove_principal_from_service` is the
same. For an ephemeral-only name the disk cost is a read + TOML parse, not a write, and not an
fsync.

**The config read cannot be skipped, and this is load-bearing.** The #55 adversarial review
established — and `handlers.rs:1175-1181` records — that a name can be held by **both** an ephemeral
registration and a hand-edited `config.toml`. Stripping only the shadowing ephemeral copy leaves the
config copy holding the principal: invisible while the overlay shadows it, then **live with the
stale allow the moment the registering control connection drops**, re-admitting a principal the
operator was told was revoked. Revocation must be fail-closed across every allow the name owns.

`is_ephemeral` being already computed does not make the config pass redundant — *ephemeral* and *in
config* are not mutually exclusive, which is exactly the bug that comment exists to prevent. Grant
keeps the config pass for the same reason, symmetrically: if the name is also a config service, a
grant that skipped config would silently expire when the ephemeral registration dropped.

**The reload IS redundant, and it is the expensive half.** When the config file did not change,
`reload_services_from_disk` re-reads and re-parses the config only to rebuild a registry whose
config half is byte-identical, reconstructing **every** service's backend object. That is the
per-grant cost that scales with total services, not with the one being changed.

## Approach

Split the two cases on **what actually changed on disk**, not on `is_ephemeral`:

```rust
if config_moved {
    reload_services_from_disk(mesh, why).await?;   // config changed → rebuild from disk
} else if ephemeral_changed {
    apply_ephemeral_allow(mesh, &service)?;        // only the overlay → targeted swap
}
```

`Services::with_allow_replaced(name, allow) -> Option<Services>` clones the registry with one
entry's `allow` replaced. `ServiceEntry.backend` is an `Arc`, so this is N `Arc` clones and N `Vec`
clones — no backend reconstruction, no config I/O. Swapped in through the existing
`LiveServices::store`, so it inherits #54's per-bi-stream visibility exactly: the next session on an
already-open connection sees it.

Both branches remain under `mesh.reload_lock`, and revoke's SWAP-BEFORE-SEVER ordering (#54) is
unchanged — the swap still happens before `sever_principal`.

### The misleading warning

`append_allow_to_config` warns `"grant: service not in config; skipping allow-append"` per absent
service. When the caller already knows the name is ephemeral, that is not a warning, it is the
expected path. Thread a `known_ephemeral: &HashSet<String>` (empty for the pairing-grant caller) and
log those at `debug!` instead. Names in neither config nor the set still warn — that case is a
genuine mistake and must stay visible.

## Behaviour change, stated plainly

A grant/revoke that changes only the ephemeral overlay **no longer picks up unrelated hand-edits to
`config.toml`** as a side effect. Today it does, incidentally, because it reloads from disk.

Scoped to `service_allow_grant` / `service_allow_revoke`, the two verbs #94 names. The
multi-service PAIRING grant (`grant_service_access`) still rebuilds from disk — it grants into
several services at once, so the single-entry swap does not fit it, and extending it is a separate
change. A regression test pins that it was not altered by accident.

This is a deliberate improvement: applying an operator's unrelated, possibly half-finished config
edit as a side effect of granting one principal is surprising, and `register_service` / the explicit
reload path remain the documented ways to pick config changes up. It is called out in
`docs/local-protocol.md` because someone is relying on the accident.

### Two incidental effects, recorded rather than left to be found

- **The per-service spawn semaphore is no longer reset on every grant.** `session_backend_run`
  builds a fresh `Semaphore::new(spawn_concurrency(cfg))` per rebuild, so every reload previously
  reset each run-service's concurrency cap and dropped accounting for in-flight spawns. Reusing the
  backend `Arc` keeps one semaphore for the service's life — strictly safer, and adjacent to
  #63/#77.
- **A corrupt `config.toml` no longer aborts an overlay-only revoke.** It used to strip the
  in-memory allow, then fail `Config::load` and return `Err` without swapping or severing. The fast
  path now completes the revoke. Fail-closed improvement.

## Surface + versioning

No control-API surface change — same verbs, same params, same results. **No `API_MINOR` bump.**
`Services::with_allow_replaced` is new public API on `mcpmesh-net`, purely additive.

Workspace version → **0.13.6** (behaviour-preserving performance fix → PATCH).

## Testing (TDD, RED first)

1. **Unit — `with_allow_replaced` replaces one entry and leaves the rest identical**, returning
   `None` for an unknown name. Backend `Arc`s must be *the same allocations* (`Arc::ptr_eq`), which
   is the actual claim: no backend was reconstructed.
2. **Integration — an ephemeral grant takes effect without a config reload.** Grant a principal on
   an ephemeral service, then assert the peer is admitted. This is the anti-regression test: it
   fails if the targeted swap does not reach the live registry.
3. **Integration — the both-holder invariant survives.** A name held by BOTH an ephemeral
   registration and `config.toml`: revoke, drop the ephemeral registration, and assert the config
   copy no longer admits the principal. This is #55's exact defect and the reason the fast path is
   NOT taken on `is_ephemeral`. **It must fail if the config pass is skipped.**
4. **Integration — an ephemeral grant does not apply an unrelated config edit.** Write a new
   `[services.*]` into `config.toml` after boot, grant on an unrelated ephemeral service, and assert
   the new service is NOT live — pinning the behaviour change above rather than leaving it implicit.
5. **Regression — config-service grant/revoke still reloads from disk** and still returns
   `NoSuchService` for a name in neither source.
