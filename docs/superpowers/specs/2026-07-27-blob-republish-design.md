# `blob_republish` + relay-ready ticket minting (#83, asks 1 and 3)

**Status:** accepted · **Issue:** #83 · **Target:** 0.14.1 (additive verb → PATCH)

## Problem

Content addressing makes every recipient a potential source. The control API does not:

1. **A fetched blob joins no scope.** `blob_fetch` lands verified bytes in the local store but adds
   the hash to no scope, and `BlobScopes::allows` requires scope membership — so a peer holding a
   complete, byte-identical blob cannot serve it. The only route back in is `blob_publish { scope,
   path }`, re-importing from the filesystem and creating a **third** copy of bytes the store
   already holds (with no reclaim, #80).
2. **A ticket minted before the relay handshake is NAT-dead.** `publish_path` mints from
   `endpoint.addr()` immediately. Published shortly after boot or after a network change, the
   ticket can carry direct addresses only: LAN-dialable, dead across NAT. `mint_invite` already
   solves this with a bounded `online()` wait; the blob path never got it.

The reported failure is ordinary: someone shares a file with eight people and closes their laptop.
Three have the complete blob. The other five fail, because the only address anyone holds points at
the sleeping publisher.

## Scope of THIS change

Asks 1 and 3. **Ask 2 — `blob_fetch { hash, from: [principals] }` with fallback — is NOT here.** It
needs principal→endpoint resolution and a try-in-turn loop over a `Vec`, which is a materially
bigger change than a scope insert, and it wants its own design pass and its own tests. #83 stays
open for it.

Ask 1 is the structural half regardless: once a recipient can re-serve, an embedder can hand out a
ticket from any holder. Ask 2 automates choosing among them.

## 1. `blob_republish { scope, hash }`

Adds a hash **already complete in the local store** to a scope, and returns a ticket addressed to
**this** node. No filesystem round-trip, no third copy.

```rust
pub async fn republish(&self, scope: &str, hash_hex: &str) -> Result<String>
```

**The completeness check is the load-bearing part.** Putting a hash in a scope *advertises* it: the
scope gate will authorize GETs for it, and the returned ticket names us as the source. If the store
holds only partial bytes — an interrupted fetch leaves them — we would advertise a blob we cannot
serve, converting the sender's outage into a hang at every fetcher. `Blobs::has` is exactly the
right predicate: it is `true` only for `BlobStatus::Complete { .. }`, not for `Partial`.

Absent or partial → `NoSuchBlob` (`-32041`), a new error type alongside #62's `NoSuchBlobScope`
(`-32040`). An unknown scope keeps returning `NoSuchBlobScope`, checked FIRST so a typo'd scope
does not report as a missing blob.

Republishing is **idempotent** — `publish_hash` is a set insert — so a client may call it
unconditionally after a fetch.

### What republish does NOT do

It does not grant anyone access. Scope grants are `blob_grant`'s job, and a republisher inheriting
the original's grant list would be a silent authorization transfer. The republisher chooses a scope
they already control; the bytes become servable, not automatically shared.

## 2. Relay-ready ticket minting

`publish_path` waits, bounded by the same 3s `RELAY_READY_TIMEOUT` `mint_invite` uses, for
`endpoint.online()` before constructing the `BlobTicket`. A cap, not a fixed delay: production
returns the instant the relay handshake completes; the relay-disabled test preset never completes,
so it fires and mints a direct-address ticket, which is what those tests need anyway.

The constant moves to a shared location so the two paths cannot drift.

## Surface + versioning

- `Request::BlobRepublish { scope, hash }` → `{ticket, hash}` (same shape as `blob_publish`, so a
  client can treat the two interchangeably after a fetch).
- New `NoSuchBlob` → `-32041`.
- `API_MINOR` 17 → 18, `API_VERSION` "1.17" → "1.18".
- `docs/local-protocol.md`: the verb, that it requires the blob to be COMPLETE locally, that it
  grants nobody, and that the ticket names this node.
- Workspace → **0.14.1** (additive verb → PATCH).

## Testing (TDD, RED first)

1. **Unit — republish requires completeness.** A hash never fetched → `NoSuchBlob`; the scope is
   left untouched (assert `allows()` is still false, so a failed republish cannot half-advertise).
2. **Unit — an unknown scope reports `NoSuchBlobScope`, not `NoSuchBlob`**, even when the hash is
   also absent. Pins the check order.
3. **Integration — a fetched blob becomes servable from the fetcher.** Three nodes: A publishes and
   grants B; B fetches; B republishes into its own scope and grants C; **C fetches from B while A's
   endpoint is closed.** This is the issue's exact scenario and fails if republish is a no-op.
4. **Integration — republish does not transfer A's grants.** After B republishes, a principal
   granted by A but not by B is REFUSED by B. Guards the silent-authorization-transfer trap.
5. **Unit — idempotent.** Republishing twice is not an error and leaves one scope entry.
6. **Regression — the ticket still round-trips** under the relay-disabled preset, proving the
   `online()` wait is a cap rather than a stall.
