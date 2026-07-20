//! Control-verb handlers for the local `mcpmesh-local/1` API: service registration, peer
//! add/remove/rename, invite minting and redemption, the pairing grant/revoke pair, the
//! app-blob verbs, and the `open_session` dial-and-pipe — each one serialized against the
//! others through `MeshState::reload_lock` wherever it mutates config.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcpmesh_local_api::{
    BlobFetchResult, BlobPublishResult, BlobScopeList, InviteResult, PairResult, PeerAddParams,
    PeerRemoveParams, PeerRenameParams, RegisterServiceParams, ScopeInfo,
};
use mcpmesh_net::errors::{ERR_UNREACHABLE, synthesized};
use mcpmesh_net::framing::{FrameReader, write_frame};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::allowlist::{PeerEntry, PeerStore};
use crate::audit::{AuditRecord, now_ts};
use crate::config::Config;
use crate::control::DaemonState;
use crate::pairing::Invite;
use crate::util::{blocking, epoch_now_u64};

use super::accept::reload_accept_loop;
use super::config_write::{
    append_allow_to_config, remove_allow_from_config, rename_allow_in_config,
    write_service_to_config,
};
use super::status::service_infos;
use super::{MeshState, build_services_audited, dial_service, pipe_session};

/// A minted pairing invite lives at most 24h.
const INVITE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on how long `mint_invite` waits for the endpoint to come "online" (a home-relay
/// handshake) before minting, so the invite's address carries the relay URL the redeemer
/// bootstraps from across NAT. It is a CAP, not a
/// fixed wait: production returns the instant the relay handshake completes (~1s). On the
/// relay-disabled localhost preset `online()` never completes, so this fires and we mint
/// with the direct-address-only addr (dialable on localhost/LAN — sufficient for tests).
const RELAY_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// Handle a `blob_publish` control request: add a LOCAL file into a scope on the gated
/// app-blob store, returning the ticket + hash. Requires roster mode (the provider is built only
/// there); a pure-pairing daemon answers a clean error.
pub(crate) async fn blob_publish(
    state: &DaemonState,
    scope: String,
    path: String,
) -> Result<BlobPublishResult> {
    let mesh = state.mesh_required()?;
    let provider = mesh
        .app_blobs()
        .await
        .context("app-blob provider not enabled (roster mode only)")?;
    let (ticket, hash) = provider
        .publish_scope(&scope, Path::new(&path))
        .await
        .context("publish blob into scope")?;
    Ok(BlobPublishResult { ticket, hash })
}

/// Handle a `blob_grant` control request: grant a scope to a principal (single-writer).
pub(crate) async fn blob_grant(
    state: &DaemonState,
    scope: String,
    principal: String,
) -> Result<()> {
    let mesh = state.mesh_required()?;
    let provider = mesh
        .app_blobs()
        .await
        .context("app-blob provider not enabled (roster mode only)")?;
    provider.grant(&scope, &principal)
}

/// Handle a `blob_list` control request: the daemon's scopes (name → hashes + grants).
pub(crate) async fn blob_list(state: &DaemonState) -> Result<BlobScopeList> {
    let mesh = state.mesh_required()?;
    let scopes = match mesh.app_blobs().await {
        Some(provider) => provider
            .list()
            .into_iter()
            .map(|(name, hashes, grants)| ScopeInfo {
                name,
                hashes,
                grants,
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(BlobScopeList { scopes })
}

/// Handle a `blob_fetch` control request: fetch a `mcpmesh/blob/1` ticket THROUGH the daemon
/// (BLAKE3-verified streaming into the gated store) and export the verified blob to `dest_path` (a
/// local file the same-uid daemon writes — within the trust boundary). Returns the verified hash + byte length.
pub(crate) async fn blob_fetch(
    state: &DaemonState,
    ticket: String,
    dest_path: String,
) -> Result<BlobFetchResult> {
    let mesh = state.mesh_required()?;
    let provider = mesh
        .app_blobs()
        .await
        .context("app-blob provider not enabled (roster mode only)")?;
    let hash = provider.fetch(&ticket).await.context("fetch blob")?;
    let bytes = provider
        .read_bytes(hash)
        .await
        .context("read fetched blob")?;
    let bytes_len = bytes.len() as u64;
    let dest = PathBuf::from(dest_path);
    tokio::fs::write(&dest, &bytes)
        .await
        .with_context(|| format!("write fetched blob to {}", dest.display()))?;
    Ok(BlobFetchResult {
        hash: hash.to_hex().to_string(),
        bytes_len,
    })
}

/// Reload the config from disk and hot-swap the accept loop with services rebuilt from it — the
/// shared read→rebuild→swap tail of every config-mutating control verb ([`register_service`],
/// [`rename_peer`], [`grant_service_access`], [`revoke_service_access`]). `why` names the mutation
/// for the reload error (`"reload config after {why}: …"`). The CALLER holds `mesh.reload_lock`
/// around its whole critical section; this helper takes no lock beyond [`reload_accept_loop`]'s
/// short-lived `accept_task` swap.
async fn reload_services_from_disk(mesh: &Arc<MeshState>, why: &str) -> Result<()> {
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("reload config after {why}: {e}"))?;
    reload_accept_loop(
        mesh,
        build_services_audited(&cfg, &mesh.audit(), &mesh.limits()),
    )
    .await;
    Ok(())
}

/// Handle a `register_service` control request: write/update the `[services.*]` config entry
/// (atomic), reload the registry, and hot-reload the mesh serve loop. Config writes block, so
/// they run on `spawn_blocking` (the fs house rule).
pub(crate) async fn register_service(
    state: &DaemonState,
    params: RegisterServiceParams,
) -> Result<()> {
    let mesh = state.mesh_required()?;

    // Serialize the ENTIRE critical section (read → upsert → write → reload → rebuild → serve
    // swap → status). Two concurrent registrations must not read the same base config and
    // clobber each other's new service. Held until this function returns.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Atomic config write on a blocking thread.
    let config_path = mesh.config_path.clone();
    let RegisterServiceParams {
        name,
        backend,
        allow,
    } = params;
    let (name_w, backend_w, allow_w) = (name.clone(), backend.clone(), allow.clone());
    blocking("join config write", move || {
        write_service_to_config(&config_path, &name_w, &backend_w, &allow_w)
    })
    .await??;

    // 2/3. Reload config, rebuild the registry from the persisted truth, and hot-reload: abort the
    //      old accept loop, spawn a fresh one on the same endpoint carrying the rebuilt registry
    //      (a brief serving blip is acceptable). Shared with the pairing grant / revoke /
    //      rename via [`reload_services_from_disk`] (DRY). `status` reads the config live, so the
    //      new service is visible on the very next call.
    reload_services_from_disk(mesh, "register").await?;

    tracing::info!(service = %name, "registered/updated service");
    Ok(())
}

/// Handle a `peer_add` control request: write
/// a [`PeerEntry`] to the daemon's OPEN store (redb is single-process, so this must route
/// through the daemon). The live [`AllowlistGate`](crate::allowlist::AllowlistGate) reads the
/// same database, so the new peer is resolvable on the very next accept — no gate rebuild
/// needed — and `status` reads the store live, so it shows the peer immediately.
pub(crate) async fn add_peer(state: &DaemonState, params: PeerAddParams) -> Result<()> {
    let mesh = state.mesh_required()?;
    let PeerAddParams {
        nickname,
        endpoint_id,
        allow,
    } = params;
    // endpoint_id encoding = iroh's native base32 (`EndpointId`/`PublicKey` Display/FromStr,
    // `decode_base32_hex`); round-trips the 32 bytes and matches what pairing/status show.
    let endpoint_id = endpoint_id
        .parse::<iroh::EndpointId>()
        .map_err(|e| anyhow::anyhow!("peer_add: endpoint_id is not a valid EndpointId: {e}"))?;
    let entry = PeerEntry {
        endpoint_id: *endpoint_id.as_bytes(),
        nickname: nickname.clone(),
        services: allow,
        // `internal peer add` is not a pairing write — leave the audit stamp unset
        // (only the pair rendezvous records `paired_at`) and no pairing-proven dial hint
        // (`last_addr` — discovery resolves this peer).
        paired_at: None,
        user_id: None,
        last_addr: None,
    };

    // redb writes block + fsync — run on a blocking thread (the fs house rule).
    let store = mesh.store.clone();
    blocking("join peer add", move || store.add(entry)).await??;

    tracing::info!(peer = %nickname, "added peer to allowlist");
    Ok(())
}

/// Handle a `peer_remove` control request: drop a paired
/// peer's authorization AND identity — the strict INVERSE of the pairing grant.
///
/// **Fail-safe teardown order (DECLARED).** The pairing grant writes, in order, (1) the
/// [`PeerEntry`] (identity — who the peer is) then (2) the config `allow` append (authorization —
/// what it may open). Removal is that grant's LIFO inverse: undo (2) FIRST via
/// `revoke_service_access` (strip the nickname from every `[services.*].allow`, the
/// security-relevant half), THEN undo (1) via [`PeerStore::remove`] (drop the identity row). This
/// leaves the peer MORE restricted, never less, at every partial-failure point:
///  - revoke fails → we abort BEFORE touching the store: the peer is unchanged (still fully
///    paired) — a clean, retriable failure, no half-state, and no orphaned config entry;
///  - revoke succeeds, store remove fails → the peer is known-but-forbidden (identity still
///    resolvable, but stripped from every allow → `select_service` denies it). Safe. Retriable:
///    both steps are idempotent, so re-running finishes the teardown.
///
/// (The alternative order — remove identity first — would, on a mid-failure, leave an ORPHAN
/// allow name that also trips the pairing collision guard on a later re-pair; revoke-first avoids
/// that.)
///
/// **Unknown nickname is an error (DECLARED).** When NEITHER half tears anything down (no allow
/// stripped, no PeerEntry deleted) the nickname matches no paired peer, and the removal FAILS with
/// a pointer at `mcpmesh status` — false success on a revocation surface would make a typo read
/// as a completed cut-off. Each half stays individually idempotent, so retrying a
/// partially-failed removal (allow stripped, identity row still present) still finishes clean.
///
/// **Live sessions.** This severs only the ability to establish NEW authorized sessions;
/// an in-flight mesh session runs to completion (an unpair does not cut live sessions —
/// roster revocation is the surface that does).
///
/// **Status snapshot.** Not refreshed here — and it no longer needs to be: `status` reads the
/// config + store LIVE (control.rs `status_result`), so a revoke is reflected immediately even
/// though this detached handler holds no `DaemonState`. The functional truth is the store +
/// config (which the `pair --remove` tests assert on), and `status` now reads exactly that.
pub async fn remove_peer(state: &DaemonState, params: PeerRemoveParams) -> Result<()> {
    let mesh = state.mesh_required()?;
    let nickname = params.nickname;

    // (2)⁻¹ AUTHORIZATION: revoke first (the security-relevant half). Propagate its error so a
    // failure aborts before we touch the identity row (see the fail-safe reasoning above). Capture
    // whether an allow was actually stripped — one half of the actual-removal signal.
    let revoked = revoke_service_access(mesh, &nickname).await?;

    // (1)⁻¹ IDENTITY: drop the PeerEntry (removes ALL entries sharing this nickname — nicknames are
    // not unique). redb writes block + fsync — run on a blocking thread. Capture
    // whether a PeerEntry was actually deleted — the other half of the actual-removal signal.
    let store = mesh.store.clone();
    let nickname_w = nickname.clone();
    let removed = blocking("join peer remove", move || store.remove(&nickname_w)).await??;

    // Actual-removal signal: neither an allow stripped NOR a PeerEntry deleted means the nickname
    // matches no paired peer. `pair --remove` is a REVOCATION surface — reporting success here
    // would let a typo ("alice" vs "Alice") read as a completed cut-off — so an all-no-op removal
    // is an ERROR, not a silent success. Retry-after-partial-failure still completes: with the
    // allow already stripped but the identity row still present, `removed` comes back true.
    if !revoked && !removed {
        anyhow::bail!("no paired peer named '{nickname}' — 'mcpmesh status' lists your peers");
    }

    tracing::info!(peer = %nickname, "unpaired peer");
    // Trust event: an unpair — reached only when something was ACTUALLY torn down (a
    // stripped allow OR a deleted PeerEntry; the all-no-op case errored above), so a refused
    // remove of a never-paired nickname writes NO phantom `unpair` record. Nickname only.
    mesh.audit().record(AuditRecord::trust(
        now_ts(),
        "unpair".into(),
        Some(nickname.clone()),
    ));
    Ok(())
}

/// The vetted plan for a rename: the target [`PeerEntry`]s (the person) and their current nicknames.
struct RenamePlan {
    targets: Vec<PeerEntry>,
    old_nicknames: std::collections::BTreeSet<String>,
}

/// Identify the person's entries and run the rename COLLISION GUARD (privilege-escalation defense,
/// mirroring pairing's `nickname_collision`). The person is every entry sharing `user_id` (renames all
/// their devices in one op), else the single entry named `nickname` (a provisional contact). Returns
/// `Ok(None)` when every target is already named `to` (a no-op), `Ok(Some(plan))` when the rename is
/// safe, or `Err` when no contact matches or `to` would inherit a DIFFERENT identity's access.
/// Blocking (redb + config read) — call on a blocking thread.
fn rename_plan(
    store: &PeerStore,
    config_path: &Path,
    user_id: Option<&str>,
    nickname: Option<&str>,
    to: &str,
) -> Result<Option<RenamePlan>> {
    let all = store.list()?;
    let targets: Vec<PeerEntry> = all
        .iter()
        .filter(|e| match user_id {
            Some(u) => e.user_id.as_deref() == Some(u),
            None => Some(e.nickname.as_str()) == nickname,
        })
        .cloned()
        .collect();
    if targets.is_empty() {
        anyhow::bail!("peer_rename: no matching contact");
    }
    if targets.iter().all(|e| e.nickname == to) {
        return Ok(None); // already named `to` — a no-op
    }

    let target_ids: std::collections::BTreeSet<[u8; 32]> =
        targets.iter().map(|e| e.endpoint_id).collect();
    // (a) impersonation: a peer named `to` at an endpoint that is NOT one of the targets is a
    // DIFFERENT contact — renaming onto it would let this person assume that identity's grants.
    if all
        .iter()
        .any(|e| e.nickname == to && !target_ids.contains(&e.endpoint_id))
    {
        anyhow::bail!("the nickname \"{to}\" is already used by another contact");
    }
    // (b) orphan-allow: `to` sits in some service allow but backs NO peer — a pre-provisioned grant
    // the renamed peer would inherit. (If a target is already named `to`, a backing peer exists.)
    let backed_by_peer = all.iter().any(|e| e.nickname == to);
    if !backed_by_peer
        && crate::pairing::rendezvous::nickname_in_any_service_allow(config_path, to)?
    {
        anyhow::bail!("the nickname \"{to}\" is already granted access — pick another");
    }

    let old_nicknames = targets.iter().map(|e| e.nickname.clone()).collect();
    Ok(Some(RenamePlan {
        targets,
        old_nicknames,
    }))
}

/// Handle a `peer_rename` control request (the Contacts rename). Renames a contact's
/// nickname (nickname) authoritatively — all the person's `PeerEntry`s to `to`, and rewrites the old
/// nickname → `to` in every `[services.*].allow` so grants follow — then reloads so the new name
/// admits. Guarded against renaming onto another identity's name/grant. Held entirely under
/// `reload_lock` (like grant/revoke/register) so guard→mutate→reload is one atomic critical section.
pub async fn rename_peer(state: &DaemonState, params: PeerRenameParams) -> Result<()> {
    let mesh = state.mesh_required()?;
    let to = params.to.trim().to_string();
    if to.is_empty() {
        anyhow::bail!("peer_rename: the new nickname is empty");
    }
    let PeerRenameParams {
        user_id, nickname, ..
    } = params;
    if user_id.is_none() && nickname.is_none() {
        anyhow::bail!("peer_rename: no contact identified");
    }

    // Hold the whole guard→mutate→reload section under the SAME lock as grant/revoke/register, so a
    // concurrent config edit can neither race the collision guard nor clobber the allow rewrite.
    let _reload = mesh.reload_lock.lock().await;

    let store = mesh.store.clone();
    let config_path = mesh.config_path.clone();
    let (uid_c, pn_c, to_c) = (user_id.clone(), nickname.clone(), to.clone());
    let plan = blocking("join rename plan", move || {
        rename_plan(
            &store,
            &config_path,
            uid_c.as_deref(),
            pn_c.as_deref(),
            &to_c,
        )
    })
    .await??;
    let RenamePlan {
        targets,
        old_nicknames,
    } = match plan {
        Some(p) => p,
        None => return Ok(()), // no-op: already named `to`
    };

    // Mutate on a blocking thread: rewrite each old nickname → `to` in the config allow lists, then
    // upsert each target `PeerEntry` (same endpoint_id, new nickname).
    let store = mesh.store.clone();
    let config_path = mesh.config_path.clone();
    let to_c = to.clone();
    blocking("join rename mutate", move || {
        for old in &old_nicknames {
            if old != &to_c {
                rename_allow_in_config(&config_path, old, &to_c)?;
            }
        }
        for mut e in targets {
            e.nickname = to_c.clone();
            store.add(e)?;
        }
        anyhow::Ok(())
    })
    .await??;

    // Reload so the rebuilt `Services` admit under the new nickname (select_service reads the allow
    // baked in at build time).
    reload_services_from_disk(mesh, "rename").await?;
    tracing::info!(to = %to, "renamed contact");
    Ok(())
}

/// The invite-time registration check: the refusal message when any requested service name has
/// no well-formed `[services.<name>]` entry, or `None` when every name is registered. Pure over
/// (requested, served) so the message shapes are unit-testable. The message states what IS
/// served (or that nothing is yet) and names the exact next command — never wire vocabulary.
fn unregistered_service_error(requested: &[String], served: &[String]) -> Option<String> {
    let unknown: Vec<&String> = requested.iter().filter(|r| !served.contains(r)).collect();
    let quoted: Vec<String> = unknown.iter().map(|n| format!("'{n}'")).collect();
    let named = match quoted.as_slice() {
        [] => return None,
        [one] => format!("no service named {one}"),
        many => format!("no services named {}", many.join(", ")),
    };
    Some(if served.is_empty() {
        format!(
            "{named} — nothing is served yet; register one with \
             'mcpmesh serve <name> -- <command>'"
        )
    } else {
        format!(
            "{named} — you serve: {} (see 'mcpmesh status')",
            served.join(", ")
        )
    })
}

/// Mint a one-time pairing invite granting `services`.
///
/// Builds an [`Invite`] { 32 CSPRNG-byte secret, our endpoint id + dialable address, our
/// suggested nickname, the granted services, a `≤ now + 24h` expiry }, registers it in the
/// live registry so the accept loop's `mcpmesh/pair/1` branch will redeem it, and returns the
/// copyable `mcpmesh-invite:` line. Logs a trust event carrying NO secret and NO peer
/// id — an invite has no peer yet; the redeemer is only known once it dials the rendezvous.
///
/// The secret uses the OS CSPRNG via `rand::rngs::OsRng` — the SAME source the device-key
/// mint uses (mcpmesh-trust), no new crate. The address comes from `endpoint.addr()`; we first
/// wait (bounded by [`RELAY_READY_TIMEOUT`]) for the endpoint to come online so the addr
/// carries the home-relay URL the redeemer bootstraps from across NAT.
///
/// **Registration check (DECLARED).** Every requested name must have a well-formed
/// `[services.<name>]` entry, or the mint is REFUSED: an invite for an unregistered name would
/// redeem fine, pass the safety-code ceremony, and only fail at connect time on the REDEEMER's
/// machine — the worst place to discover the inviter's typo. Validated against the SAME view
/// `status` renders ([`service_infos`], read live from disk like `status_result`), so the
/// refusal's "you serve:" list always matches what `mcpmesh status` shows.
pub(crate) async fn mint_invite(services: Vec<String>, mesh: &MeshState) -> Result<InviteResult> {
    use rand::RngCore;

    // Registration check FIRST — before the CSPRNG mint and the online()-wait, so a typo'd
    // name fails fast and never touches the invite registry.
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("config error in {}: {e}", mesh.config_path.display()))?;
    let served: Vec<String> = service_infos(&cfg).into_iter().map(|s| s.name).collect();
    if let Some(msg) = unregistered_service_error(&services, &served) {
        anyhow::bail!(msg);
    }

    // 32 CSPRNG bytes — the single-use bearer credential.
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let inviter_id = *mesh.endpoint.id().as_bytes();

    // Our own dialable address, WITH the relay URL when we can get it: `online()` completes on
    // a home-relay handshake, after which `addr()` carries that relay. Bounded so a relay-less
    // (localhost/test) endpoint still mints promptly with its direct addrs.
    let _ = tokio::time::timeout(RELAY_READY_TIMEOUT, mesh.endpoint.online()).await;
    let inviter_addr_json = serde_json::to_string(&mesh.endpoint.addr())
        .context("serialize our own endpoint address for the invite")?;

    let now = epoch_now_u64();
    let expires_at_epoch = now + INVITE_TTL.as_secs();
    let invite = Invite {
        secret,
        inviter_id,
        inviter_addr_json,
        nickname: mesh.self_nickname.clone(),
        services: services.clone(),
        expires_at_epoch,
    };
    let invite_line = invite.encode();
    // Reap expired invites before minting so a long-lived daemon's registry can't grow
    // unboundedly with never-redeemed invites (bounds map growth; the invite lifetime cap,
    // the invite-lifetime cap). Cheap: one lock + retain over a small map.
    mesh.invites.remove_expired(now);
    mesh.invites.mint(invite);

    // Trust event: record the mint. NO secret, NO peer id (there is no peer yet).
    tracing::info!(?services, "invite minted");
    Ok(InviteResult {
        invite_line,
        expires_at_epoch,
    })
}

/// Handle a `pair` control request: dial the inviter named by
/// `invite_line` on `mcpmesh/pair/1`, verify its TLS identity binds the invite's `inviter_id`
/// (the address-swap defense), prove the secret, write OUR dial-back [`PeerEntry`], and return
/// the inviter's nickname + the display-only SAS. Delegates to
/// [`crate::pairing::rendezvous::redeem_invite`], threading our own endpoint + self-nickname +
/// store. The inviter-side authorization (adding US to its service `allow`) happens on ITS
/// daemon inside its rendezvous handler — see [`grant_service_access`].
pub(crate) async fn redeem(state: &DaemonState, invite_line: String) -> Result<PairResult> {
    let mesh = state.mesh_required()?;
    crate::pairing::rendezvous::redeem_invite(
        mesh.endpoint.clone(),
        mesh.self_nickname.clone(),
        invite_line,
        mesh.store.clone(),
        mesh.self_binding(),
        &mesh.config_path,
    )
    .await
}

/// Grant a freshly-paired peer AUTHORIZATION to the services its invite named: append
/// `redeemer_nickname` to each service's config `[services.<svc>].allow` (idempotently) and
/// hot-reload so the running registry admits it. This is the load-bearing half of pairing.
///
/// Why it is separate from (and necessary alongside) the [`PeerEntry`] the rendezvous writes:
/// the [`AllowlistGate`](crate::allowlist::AllowlistGate) only RESOLVES an inbound endpoint to
/// a nickname (identity); `select_service` then ADMITS that nickname only if the
/// service's config `allow` names it — and that allow is baked into the [`Services`](mcpmesh_net::Services) snapshot
/// at [`build_services`](crate::daemon::build_services) time. So a PeerEntry makes the peer KNOWN; only appending to `allow`
/// + reloading makes it AUTHORIZED. Without this the peer is known-but-forbidden.
///
/// Serialized against `register_service` via `mesh.reload_lock` (SAME lock — a concurrent
/// register and a pairing-grant must not read the same base config and clobber each other's
/// write). Reuses `append_allow_to_config`'s atomic write and `reload_accept_loop`'s
/// abort/respawn (DRY). A service not present in config is logged + skipped (a pairing grant
/// never CREATES a service). Reloads ONLY when the append actually changed the config — an
/// idempotent re-pair or an all-missing grant is a no-op with no serving blip. (The cached
/// `status` snapshot is not refreshed here — this runs inside the accept loop's detached pair
/// handler, which holds no `DaemonState` — but it need not be: `status` reads the config + store
/// LIVE (control.rs `status_result`), so this grant shows up immediately. The durable allow-append
/// + the live rebuilt `Services` are the functional truth.)
pub async fn grant_service_access(
    mesh: &Arc<MeshState>,
    redeemer_nickname: &str,
    services: &[String],
) -> Result<()> {
    // SAME serialization as register_service: hold the whole append→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Idempotent allow-append on a blocking thread (config IO blocks).
    let config_path = mesh.config_path.clone();
    let nickname = redeemer_nickname.to_string();
    let services_w = services.to_vec();
    let changed = blocking("join grant config write", move || {
        append_allow_to_config(&config_path, &nickname, &services_w)
    })
    .await??;

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already admits the peer). The reload MUST happen for a real append to take effect,
    //      since `select_service` reads the allow baked into `Services` at build time.
    if changed {
        reload_services_from_disk(mesh, "grant").await?;
    }

    // Trust event: NO secret, NO endpoint id (nickname only).
    tracing::info!(peer = %redeemer_nickname, ?services, changed, "granted service access");
    // Trust event: a pairing grant. Nickname only — NO secret, NO endpoint id.
    mesh.audit().record(AuditRecord::trust(
        now_ts(),
        "pair".into(),
        Some(redeemer_nickname.to_string()),
    ));
    Ok(())
}

/// Revoke a peer's AUTHORIZATION: remove `nickname` from EVERY service's config
/// `[services.<svc>].allow` and hot-reload so the running registry stops admitting it. The exact
/// INVERSE of [`grant_service_access`] (which appends the nickname to the named services' allow),
/// and the authorization half of [`remove_peer`].
///
/// Serialized against [`register_service`] / [`grant_service_access`] via `mesh.reload_lock` (the
/// SAME lock — a concurrent config mutation must not read the same base config and clobber this
/// removal). Reuses [`remove_allow_from_config`]'s atomic write and [`reload_accept_loop`]'s
/// abort/respawn (DRY — the same helper the grant uses). Reloads ONLY when the removal actually
/// changed the config (an absent nickname is a no-op with no serving blip). Idempotent: revoking a
/// nickname not present in any allow returns `Ok(())` with `changed == false` and no reload.
///
/// (Like [`grant_service_access`], the cached `status` snapshot is not refreshed here — but
/// `status` reads the config + store LIVE (control.rs `status_result`), so the removal shows up
/// immediately. The durable allow-removal + the live rebuilt `Services` are the functional truth.)
pub(crate) async fn revoke_service_access(mesh: &Arc<MeshState>, nickname: &str) -> Result<bool> {
    // SAME serialization as register_service / grant: hold the whole remove→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Idempotent allow-removal on a blocking thread (config IO blocks).
    let config_path = mesh.config_path.clone();
    let nickname_w = nickname.to_string();
    let changed = blocking("join revoke config write", move || {
        remove_allow_from_config(&config_path, &nickname_w)
    })
    .await??;

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already excludes the peer). A real removal MUST reload for `select_service` — which
    //      reads the allow baked into `Services` at build time — to stop admitting the nickname.
    if changed {
        reload_services_from_disk(mesh, "revoke").await?;
    }

    // Return whether an allow was actually stripped so `remove_peer` audits an `unpair` only
    // on a real tear-down (nickname only — NO secret, NO endpoint id).
    tracing::info!(peer = %nickname, changed, "revoked service access");
    Ok(changed)
}

/// Handle an `open_session` control request: resolve the nickname, dial the named
/// service over the mesh, and pipe that session to/from the control connection — which, after
/// this request, STOPS being JSON-RPC and becomes a raw MCP byte pipe (protocol.rs
/// `OpenSession`). On any dial-ESTABLISHMENT failure (peer not allowlisted, malformed stored
/// id, unreachable) the caller is handed a synthesized `-32055` (ERR_UNREACHABLE) frame, so
/// the AI client gets a well-formed answer instead of a hang; the remote's own `-32054`
/// refusal, and every session frame, flow back verbatim through the pipe. There is no
/// mid-session re-dial — the remote session state died with the session, so a severed session
/// simply ends the pipe (the AI client re-invokes if it wants a fresh one).
pub(crate) async fn open_session<CR, CW>(
    state: &DaemonState,
    peer: &str,
    service: &str,
    control_reader: FrameReader<CR>,
    mut control_writer: CW,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send,
    CW: AsyncWrite + Unpin + Send,
{
    let Some(mesh) = state.mesh() else {
        // Control-only construction (no endpoint) can never dial — answer unreachable.
        let _ = write_frame(
            &mut control_writer,
            &synthesized(Value::Null, ERR_UNREACHABLE, "daemon has no mesh"),
        )
        .await;
        return Ok(());
    };
    let transport = match dial_service(mesh, peer, service).await {
        Ok(t) => t,
        Err(e) => {
            // A failed dial reaches no backend, so the far side's session guard never audits
            // it (no session_open/close). Emit an error record HERE — exactly once, ONLY on
            // this failure branch (the Ok arm pipes the session instead) — so the telemetry
            // stream shows the attempted-and-failed reach. `peer` is the caller's
            // nickname/user_id, never an endpoint-id.
            mesh.audit().record(
                AuditRecord::session_open(now_ts(), Some(peer.to_string()), service.to_string())
                    .with_status("error"),
            );
            // Dial establishment failed: hand the proxy a well-formed -32055 (not a hang),
            // which it relays to the AI client. The error id is null — the AI
            // client's request id is not known daemon-side (the dial precedes the client's
            // first frame); this matches the null-id synthesis discipline in net::endpoint.
            tracing::warn!(peer, service, %e, "open_session dial failed; answering -32055");
            let _ = write_frame(
                &mut control_writer,
                &synthesized(Value::Null, ERR_UNREACHABLE, "peer unreachable"),
            )
            .await;
            return Ok(());
        }
    };
    pipe_session(transport, service, control_reader, control_writer).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::testutil::hermetic_mesh;

    /// The invite registration-check message shapes: silent on all-registered, names the missing
    /// service(s), lists what IS served (matching `status`) or says nothing is served yet, and
    /// always states the exact next command — never wire vocabulary.
    #[test]
    fn unregistered_service_error_message_shapes() {
        let s = |names: &[&str]| -> Vec<String> { names.iter().map(|n| n.to_string()).collect() };

        // Every requested name registered → no error.
        assert_eq!(
            unregistered_service_error(&s(&["notes"]), &s(&["notes", "kb"])),
            None
        );
        // One unknown name, with a served list → name it, list what IS served, point at status.
        assert_eq!(
            unregistered_service_error(&s(&["nosuchsvc"]), &s(&["notes", "code"])).unwrap(),
            "no service named 'nosuchsvc' — you serve: notes, code (see 'mcpmesh status')"
        );
        // Several unknown names → all of them named (the mixed known name is not).
        assert_eq!(
            unregistered_service_error(&s(&["a", "notes", "b"]), &s(&["notes"])).unwrap(),
            "no services named 'a', 'b' — you serve: notes (see 'mcpmesh status')"
        );
        // Nothing served at all → say so, and name the serve command as the next step.
        assert_eq!(
            unregistered_service_error(&s(&["nosuchsvc"]), &[]).unwrap(),
            "no service named 'nosuchsvc' — nothing is served yet; register one with \
             'mcpmesh serve <name> -- <command>'"
        );
    }

    /// The blob control operations fail gracefully (Err, never a panic) in control-only mode — the
    /// `state.mesh()` guard every one shares before touching the app-blob provider.
    #[tokio::test]
    async fn blob_ops_error_without_a_mesh() {
        let st = DaemonState::new("test");
        assert!(blob_list(&st).await.is_err());
        assert!(
            blob_publish(&st, "scope".into(), "/tmp/x".into())
                .await
                .is_err()
        );
        assert!(blob_grant(&st, "scope".into(), "bob".into()).await.is_err());
        assert!(
            blob_fetch(&st, "ticket".into(), "/tmp/dst".into())
                .await
                .is_err()
        );
    }

    /// `rename_peer` renames ALL of a person's devices (matched by user_id) to the new nickname AND
    /// rewrites the old nickname → new in every service allow, so grants FOLLOW the rename. The happy
    /// path also drives `build_services_audited` + `reload_accept_loop` under `reload_lock`.
    /// The typed `peer_rename` params, as the control dispatcher hands them to `rename_peer`.
    fn rename_params(user_id: Option<&str>, to: &str) -> PeerRenameParams {
        PeerRenameParams {
            user_id: user_id.map(str::to_string),
            nickname: None,
            to: to.into(),
        }
    }

    #[tokio::test]
    async fn rename_peer_renames_all_devices_and_carries_grants() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = [\"alice-old\"]\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        // Two devices of ONE person (same user_id), both under the old nickname.
        mesh.store
            .add(rename_entry(1, "alice-old", Some("b64u:ALICE")))
            .unwrap();
        mesh.store
            .add(rename_entry(2, "alice-old", Some("b64u:ALICE")))
            .unwrap();
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());

        rename_peer(&state, rename_params(Some("b64u:ALICE"), "Alice"))
            .await
            .unwrap();

        // Both PeerEntries now carry the new nickname.
        let names: Vec<String> = mesh
            .store
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.nickname)
            .collect();
        assert!(
            names.iter().all(|n| n == "Alice"),
            "all devices renamed, got {names:?}"
        );
        // The grant followed: allow now names "Alice", not "alice-old".
        let doc: toml::Table =
            toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let allow = doc["services"]["kb"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|v| v.as_str() == Some("Alice")));
        assert!(!allow.iter().any(|v| v.as_str() == Some("alice-old")));
    }

    /// `rename_peer` rejects an empty nickname, a request that names no contact, a no-such-contact
    /// target, and a collision onto ANOTHER contact's nickname (the impersonation guard) — and on a
    /// rejected rename nothing changes.
    #[tokio::test]
    async fn rename_peer_guards_bad_requests_and_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path).await;
        mesh.store
            .add(rename_entry(1, "alice", Some("b64u:ALICE")))
            .unwrap();
        mesh.store
            .add(rename_entry(2, "bob", Some("b64u:BOB")))
            .unwrap();
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());

        // Empty `to` (whitespace trims to empty).
        assert!(
            rename_peer(&state, rename_params(Some("b64u:ALICE"), "  "))
                .await
                .is_err()
        );
        // Neither user_id nor nickname identifies a contact.
        assert!(rename_peer(&state, rename_params(None, "X")).await.is_err());
        // No matching contact.
        assert!(
            rename_peer(&state, rename_params(Some("b64u:NOBODY"), "X"))
                .await
                .is_err()
        );
        // Collision: renaming alice onto bob's nickname would steal bob's identity/grants.
        assert!(
            rename_peer(&state, rename_params(Some("b64u:ALICE"), "bob"))
                .await
                .is_err()
        );
        // The guard held: nothing changed — alice is still "alice", bob still "bob".
        let names: std::collections::BTreeSet<String> = mesh
            .store
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.nickname)
            .collect();
        assert!(
            names.contains("alice") && names.contains("bob"),
            "no rename should have occurred: {names:?}"
        );
    }

    fn rename_entry(id: u8, nickname: &str, user_id: Option<&str>) -> PeerEntry {
        PeerEntry {
            endpoint_id: [id; 32],
            nickname: nickname.into(),
            services: Vec::new(),
            paired_at: None,
            user_id: user_id.map(str::to_string),
            last_addr: None,
        }
    }

    #[test]
    fn rename_plan_groups_by_user_id_and_guards_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "[services.kb]\nallow = [\"orphan\"]\n").unwrap();
        let store = PeerStore::open(&dir.path().join("s.redb")).unwrap();
        store
            .add(rename_entry(1, "bob-phone", Some("b64u:BOB")))
            .unwrap();
        store
            .add(rename_entry(2, "bob-laptop", Some("b64u:BOB")))
            .unwrap();
        store
            .add(rename_entry(3, "carol", Some("b64u:CAROL")))
            .unwrap();

        // Renaming the PERSON by user_id targets BOTH of Bob's devices in one op.
        let plan = rename_plan(&store, &cfg, Some("b64u:BOB"), None, "Bobby")
            .unwrap()
            .unwrap();
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(
            plan.old_nicknames,
            ["bob-laptop".to_string(), "bob-phone".to_string()]
                .into_iter()
                .collect()
        );

        // GUARD (a) impersonation: renaming Bob → "carol" (a DIFFERENT contact) is refused.
        assert!(rename_plan(&store, &cfg, Some("b64u:BOB"), None, "carol").is_err());
        // GUARD (b) orphan-allow: "orphan" sits in kb.allow but backs no peer → refused.
        assert!(rename_plan(&store, &cfg, Some("b64u:BOB"), None, "orphan").is_err());
        // A provisional contact (no user_id) renames by nickname to a fresh name.
        store.add(rename_entry(4, "dave", None)).unwrap();
        assert_eq!(
            rename_plan(&store, &cfg, None, Some("dave"), "Dave")
                .unwrap()
                .unwrap()
                .targets
                .len(),
            1
        );
        // Renaming to the current name is a no-op (Ok(None)).
        assert!(
            rename_plan(&store, &cfg, Some("b64u:CAROL"), None, "carol")
                .unwrap()
                .is_none()
        );
        // No matching contact → error.
        assert!(rename_plan(&store, &cfg, Some("b64u:NOBODY"), None, "x").is_err());
    }
}
