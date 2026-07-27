# `status` and `peer_services` report from the live registry (#100)

**Status:** accepted · **Issue:** #100 · **Target:** 0.14.0 (behaviour change → MINOR)

## Problem

`status` and `peer_services` compute their answers from `config.toml` + the in-memory ephemeral map,
read live. The accept path authorizes from the **live service registry** (`LiveServices`). When the
two disagree, the control API reports a service that a connection attempt then refuses.

`peer_services` is the "what can I actually use" answer an embedder builds UI on. A service listed
there that then refuses the session is, from the caller's side, indistinguishable from a transient
failure — and it points debugging at the network layer instead of at a stale registry.

Reachable any time `config.toml` changes without a reload. #94 made the window durable rather than
incidental: an overlay-only grant no longer reloads, so a hand-added `[services.late]` is reported
indefinitely while never being servable.
`cli/tests/ephemeral_allow.rs::an_overlay_only_grant_does_not_apply_an_unrelated_config_edit`
constructs exactly this state today.

## Approach

**The live registry decides the answer**, because it is what authorizes.

- `caller_admitted_services` (the `peer_services` answer) iterates `mesh.services.get()` and keeps
  the names whose `allow` admits the caller. This is strictly simpler than the current
  config-then-overlay merge, and it deletes the `!out.contains(name)` dedup — the registry is
  already keyed by name, with the overlay having won at build time.
- `service_infos` (the `status` answer) takes the live registry and derives **everything** from it.

### The registry is self-describing (revised after adversarial review)

The first implementation kept `ServiceEntry` as `{backend, allow}` and looked the `backend` kind and
`ephemeral` flag up from config as metadata, dropping any entry found in neither source. **That was
a real defect, and the inverse of the one being fixed:** if `[services.x]` was removed from
`config.toml`, renamed, or made malformed after boot, `status` dropped `x` **while the accept path
went on serving it** — so a live grant became invisible and unrevokable ("it isn't in status, so
there is nothing to revoke"), and `status` disagreed with `peer_services` and with the accept path.

`ServiceEntry` therefore carries `kind: ServiceKind` and `ephemeral: bool`, set once at build time.
`service_infos` consults config for nothing. The failure mode is structurally impossible rather than
guarded against, and the `status` path no longer clones the ephemeral map on every call.

### `mint_invite` deliberately keeps the config view

`mint_invite` also calls `service_infos`, but its question is "is this a known service name", not
"what is live right now". An invite is redeemed later, after reloads, so validating a config service
that is pending a reload is correct there — switching it to the live registry would reject an invite
for a service the operator has just added to `config.toml`.

It moves to a dedicated `known_service_names(cfg, ephemeral)` helper. Two functions for two genuinely
different questions is better than one function whose answer is right for only one caller.

## Behaviour change

1. **A config service that is not yet in the live registry is no longer reported** by `status` or
   `peer_services`. This is the fix.
2. **A malformed config service is no longer reported** by `peer_services`. It already wasn't
   servable — `build_services_with_ephemeral` skips it with a warning — and `service_infos` already
   filtered it, so `peer_services` was the odd one out.

Both directions are "stop reporting something that does not work", so nothing that previously
succeeded starts failing.

`API_MINOR` 16 → 17, `API_VERSION` "1.16" → "1.17". No field changes, but the *meaning* of two
responses changed, and `api_minor` is what consumers key that off.

Workspace version → **0.14.0** (behaviour change → MINOR).

## Testing (TDD, RED first)

1. **Integration — `peer_services` does not report a config service pending a reload.** Boot, add
   `[services.late]` to `config.toml` by hand, take an overlay-only grant so nothing reloads, then
   assert `late` is absent from the caller's admitted set while the ephemeral service is present.
   Must FAIL before the change.
2. **Integration — `status` does not list it either**, same setup. Distinct from (1) because they
   are separate code paths that were separately wrong.
3. **Integration — after a real reload, the service IS reported.** Pins that the change withholds
   only what is genuinely not live, rather than dropping config services generally.
4. **Unit — `service_infos` keeps `backend` and `ephemeral` correct** when derived from the live
   registry: an ephemeral name reports `ephemeral: true` and its own backend kind, and a
   both-held name reports the ephemeral one (overlay wins).
5. **Regression — `mint_invite` still accepts a config service pending a reload**, pinning the
   deliberate split above. Must fail if `mint_invite` is switched to the live view.
6. **Regression — the existing `caller_admitted_services` unit test** still passes.
