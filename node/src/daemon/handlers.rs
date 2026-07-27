//! Control-verb handlers for the local `mcpmesh-local/1` API: service registration, peer
//! add/remove/rename, invite minting and redemption, the pairing grant/revoke pair, the
//! app-blob verbs, and the `open_session` dial-and-pipe — each one serialized against the
//! others through `MeshState::reload_lock` wherever it mutates config.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcpmesh_local_api::{
    BlobFetchResult, BlobPublishResult, BlobScopeList, InviteResult, PairResult, PeerAddParams,
    PeerRemoveParams, PeerRenameParams, RegisterServiceParams, ScopeInfo, SetRelaysResult,
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

use super::accept::swap_services;
use super::config_write::{
    append_allow_to_config, remove_allow_from_config, remove_principal_from_service,
    remove_service_from_config, write_relays, write_service_to_config,
};
use super::status::service_infos;
use super::{MeshState, dial_service, pipe_session};

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
    // Stored VERBATIM (#38), like service `allow`: a `b64u:`/`eid:` principal or a roster
    // group/user_id name grants; a bare display nickname does not authorize anyone.
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

/// Reload the config from disk and hot-swap the LIVE service registry with services rebuilt from
/// it — the shared read→rebuild→swap tail of every config-mutating control verb
/// ([`register_service`], [`rename_peer`], [`grant_service_access`], [`revoke_service_access`]).
/// `why` names the mutation for the reload error (`"reload config after {why}: …"`). The CALLER
/// holds `mesh.reload_lock` around its whole critical section; [`swap_services`] itself takes only
/// the live handle's short write lock.
///
/// Post-#54: the swap is visible to connections that are ALREADY open (their next session
/// reads the new registry), not merely to connections accepted afterwards.
async fn reload_services_from_disk(mesh: &Arc<MeshState>, why: &str) -> Result<()> {
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("reload config after {why}: {e}"))?;
    // Overlay the in-memory ephemeral registrations (#36) so they survive every hot-reload —
    // grants, renames, roster installs all funnel through here, so none of them drop an
    // ephemeral service. The lock is held only for the tiny clone.
    let ephemeral = mesh
        .ephemeral_services
        .lock()
        .expect("ephemeral_services lock not poisoned")
        .clone();
    swap_services(
        mesh,
        crate::daemon::build_services_with_ephemeral(
            &cfg,
            &mesh.audit(),
            &mesh.limits(),
            &ephemeral,
        ),
    );
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

    let RegisterServiceParams {
        name,
        backend,
        allow,
        ephemeral,
        rate_limit_per_min,
    } = params;
    // `allow` entries are stored VERBATIM (#38): a `b64u:`/`eid:` principal or a roster
    // group/user_id name admits; a bare display nickname does NOT (nicknames never authorize
    // — the daemon deliberately does no nickname→principal resolution here, since a
    // self-asserted nickname could shadow roster vocabulary and misdirect the grant, and a
    // non-unique nickname is ambiguous). Pairing GRANTS write the peer's principal directly
    // from its verified identity; a manual grant names a principal or a roster group. The
    // doctor lint flags a stray nickname on a pure-pairing node.

    if ephemeral {
        // #36: in-memory only. Refuse a name that already exists on disk — an ephemeral entry
        // must not silently shadow (or be shadowed by) a persistent one, and unregistering it
        // later must never touch config. A repeat ephemeral register of the same name updates it.
        let cfg = Config::load(&mesh.config_path)
            .map_err(|e| anyhow::anyhow!("config error in {}: {e}", mesh.config_path.display()))?;
        if cfg.services.contains_key(&name) {
            anyhow::bail!(
                "service '{name}' is already registered persistently in config; \
                 use a different name for an ephemeral registration"
            );
        }
        mesh.ephemeral_services
            .lock()
            .expect("ephemeral_services lock not poisoned")
            .insert(
                name.clone(),
                crate::daemon::EphemeralService {
                    backend,
                    allow: allow.clone(),
                    rate_limit_per_min,
                },
            );
        reload_services_from_disk(mesh, "register-ephemeral").await?;
        tracing::info!(service = %name, "registered ephemeral service");
        return Ok(());
    }

    // Persistent: refuse a name an EPHEMERAL registration already holds — the symmetric half of
    // the guard above (#55 review). Without it a config entry could be created UNDER a live
    // ephemeral one; the overlay would shadow it, so the allow verbs would mutate the ephemeral
    // copy while the config copy sat unreachable — and then went live, with a stale allow, the
    // moment the registering control connection dropped the ephemeral entry.
    {
        let map = mesh
            .ephemeral_services
            .lock()
            .expect("ephemeral_services lock not poisoned");
        if map.contains_key(&name) {
            anyhow::bail!(
                "service '{name}' is currently registered ephemerally; \
                 unregister it first, or use a different name for the persistent registration"
            );
        }
    }

    // Persistent: atomic config write on a blocking thread, then hot-reload.
    let config_path = mesh.config_path.clone();
    let (name_w, backend_w, allow_w) = (name.clone(), backend.clone(), allow.clone());
    blocking("join config write", move || {
        write_service_to_config(
            &config_path,
            &name_w,
            &backend_w,
            &allow_w,
            rate_limit_per_min,
        )
    })
    .await??;

    // Reload config, rebuild the registry from the persisted truth, and hot-reload: abort the
    // old accept loop, spawn a fresh one on the same endpoint carrying the rebuilt registry
    // (a brief serving blip is acceptable). Shared with the pairing grant / revoke / rename via
    // [`reload_services_from_disk`] (DRY). `status` reads the config live, so the new service is
    // visible on the very next call.
    reload_services_from_disk(mesh, "register").await?;

    tracing::info!(service = %name, "registered/updated service");
    Ok(())
}

/// Unregister the named EPHEMERAL services (#36) and hot-reload so the accept loop stops offering
/// them. Called when a control connection that registered ephemeral services closes. Persistent
/// (config) services are never touched. A no-op if nothing was ephemerally registered by the
/// connection. Takes `reload_lock`, like every registry mutation.
pub(crate) async fn unregister_ephemeral(mesh: &Arc<MeshState>, names: &[String]) {
    if names.is_empty() {
        return;
    }
    let _reload = mesh.reload_lock.lock().await;
    {
        let mut map = mesh
            .ephemeral_services
            .lock()
            .expect("ephemeral_services lock not poisoned");
        for name in names {
            map.remove(name);
        }
    }
    if let Err(e) = reload_services_from_disk(mesh, "unregister-ephemeral").await {
        tracing::warn!(%e, "reload after ephemeral unregister failed");
    }
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
/// `revoke_service_access` (strip the peer's stable principals from every `[services.*].allow`, the
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
/// **Live sessions.** Cut immediately, as of #54. The authorization half
/// ([`revoke_service_access`]) resolves the peer's devices and closes their live connections, so
/// an unpair no longer leaves in-flight mesh sessions running until the peer happens to
/// disconnect. Severing is connection-granular (see [`sever_principals`]).
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

    // BLOB hygiene (#38): strip the peer's stable principals from every blob scope too, BEFORE
    // dropping the identity row (we need the entries to compute the principals). Roster mode
    // only (the provider exists only there); a pure-pairing node is a no-op. The
    // last-device b64u rule mirrors the service-allow revoke.
    if let Some(provider) = mesh.app_blobs().await {
        let store = mesh.store.clone();
        let nick_r = nickname.clone();
        let principals: Vec<String> = blocking("join blob-revoke principals", move || {
            let (targets, others): (Vec<_>, Vec<_>) = store
                .list()?
                .into_iter()
                .partition(|e| e.nickname == nick_r);
            let mut principals = Vec::new();
            for t in &targets {
                principals.push(mcpmesh_net::EndpointId::from_bytes(t.endpoint_id).principal());
                if let Some(uid) = &t.user_id
                    && !others.iter().any(|o| o.user_id.as_deref() == Some(uid))
                    && !principals.contains(uid)
                {
                    principals.push(uid.clone());
                }
            }
            anyhow::Ok(principals)
        })
        .await??;
        if !principals.is_empty()
            && let Err(e) = provider.revoke_principals(&principals)
        {
            tracing::warn!(%e, "blob-scope revoke on unpair failed");
        }
    }

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

/// The vetted plan for a rename: the target [`PeerEntry`]s (the person). Post-#38 a rename is
/// a pure display mutation — the old nicknames are no longer needed (nothing authz-bearing
/// keyed on them), so the plan carries only the entries to re-nickname.
struct RenamePlan {
    targets: Vec<PeerEntry>,
}

/// Identify the person's entries and run the rename COLLISION GUARD (privilege-escalation defense,
/// mirroring pairing's `nickname_collision`). The person is every entry sharing `user_id` (renames all
/// their devices in one op), else the single entry named `nickname` (a provisional contact). Returns
/// `Ok(None)` when every target is already named `to` (a no-op), `Ok(Some(plan))` when the rename is
/// safe, or `Err` when no contact matches or `to` would inherit a DIFFERENT identity's access.
/// Blocking (redb + config read) — call on a blocking thread.
fn rename_plan(
    store: &PeerStore,
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
    // (a) display-uniqueness: a peer named `to` at an endpoint that is NOT one of the targets is
    // a DIFFERENT contact — a duplicate name would misdirect YOUR outbound dials
    // (`PeerStore::entry_for` is first-match by nickname) and make status ambiguous. Grants are
    // principal-keyed (#38) and unaffected by names; this guard protects routing/display only.
    if all
        .iter()
        .any(|e| e.nickname == to && !target_ids.contains(&e.endpoint_id))
    {
        anyhow::bail!("the nickname \"{to}\" is already used by another contact");
    }
    Ok(Some(RenamePlan { targets }))
}

/// Handle a `peer_rename` control request (the Contacts rename). Renames a contact's
/// display nickname — all the person's `PeerEntry`s to `to`. DISPLAY-ONLY (#38): grants are
/// principal-keyed, so no `allow` rewrite and no serving reload happen (and none are needed —
/// a rename can never change what a peer is granted). Guarded against duplicating another
/// contact's display name (outbound-dial routing is first-match by nickname). Held under
/// `reload_lock` so the guard and the store mutation stay one atomic critical section against
/// concurrent config/store writers.
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
    let (uid_c, pn_c, to_c) = (user_id.clone(), nickname.clone(), to.clone());
    let plan = blocking("join rename plan", move || {
        rename_plan(&store, uid_c.as_deref(), pn_c.as_deref(), &to_c)
    })
    .await??;
    let RenamePlan { targets } = match plan {
        Some(p) => p,
        None => return Ok(()), // no-op: already named `to`
    };

    // Mutate on a blocking thread: upsert each target `PeerEntry` (same endpoint_id, new
    // nickname). That is the WHOLE rename now (#38): grants are principal-keyed, so no config
    // rewrite and no serving reload — a rename is a pure display mutation with no serving blip
    // (the #38 fix: a rename can never desync a grant, because no grant names a nickname).
    let store = mesh.store.clone();
    let to_c = to.clone();
    blocking("join rename mutate", move || {
        for mut e in targets {
            e.nickname = to_c.clone();
            store.add(e)?;
        }
        anyhow::Ok(())
    })
    .await??;
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
pub(crate) async fn mint_invite(
    services: Vec<String>,
    app_label: Option<String>,
    mesh: &MeshState,
) -> Result<InviteResult> {
    use rand::RngCore;

    // The opaque app label (#31) is capped: the invite line is a human-copied base32 artifact,
    // so a caller cannot bloat it. mcpmesh never interprets the label — this bounds size only.
    if let Some(label) = &app_label
        && label.len() > crate::pairing::MAX_APP_LABEL_LEN
    {
        anyhow::bail!(
            "app_label is {} bytes; the maximum is {}",
            label.len(),
            crate::pairing::MAX_APP_LABEL_LEN
        );
    }

    // An invite that grants nothing is useless, and a silently-empty list is exactly the
    // symptom of a param typo like `{service: "kb"}` (singular) slipping past validation
    // (#34). Reject it before minting, matching the CLI porcelain which already makes the
    // service arg required. `deny_unknown_fields` on `InviteParams` catches the typo at parse
    // time; this is the belt-and-braces guard on the value itself.
    if services.is_empty() {
        anyhow::bail!(
            "invite must name at least one registered service (an invite granting nothing is useless)"
        );
    }

    // Registration check FIRST — before the CSPRNG mint and the online()-wait, so a typo'd
    // name fails fast and never touches the invite registry.
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("config error in {}: {e}", mesh.config_path.display()))?;
    // Served names include EPHEMERAL registrations (#36) — an invite may grant an ephemeral
    // service just like a persistent one.
    let ephemeral = mesh
        .ephemeral_services
        .lock()
        .expect("ephemeral_services lock not poisoned")
        .clone();
    let served: Vec<String> = service_infos(&cfg, &ephemeral, &[])
        .into_iter()
        .map(|s| s.name)
        .collect();
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
        nickname: mesh.self_nickname(),
        services: services.clone(),
        expires_at_epoch,
        app_label,
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
    // #43: the redeemer-side MUTUAL grant hook — grant the inviter access to ALL services this
    // node serves (the same stable-principal + reload discipline as the inviter-side grant).
    let grant_mesh = mesh.clone();
    let grant_back: crate::pairing::rendezvous::GrantBackFn =
        Box::new(move |principal, display| {
            let mesh = grant_mesh.clone();
            Box::pin(async move {
                let served: Vec<String> = match Config::load(&mesh.config_path) {
                    Ok(cfg) => cfg.services.keys().cloned().collect(),
                    Err(e) => {
                        // A config we can't read means we can't know what we serve; the mutual
                        // grant is best-effort (the pairing itself already succeeded), so log
                        // and skip rather than fail the ceremony.
                        tracing::warn!(%e, "mutual grant-back skipped: config unreadable");
                        return Ok(());
                    }
                };
                if served.is_empty() {
                    return Ok(()); // we serve nothing → nothing to grant back
                }
                // BEST-EFFORT (#43): the pairing (store write + inviter-side grant) already
                // succeeded and the one-time invite is burned, so a grant-back failure must NOT
                // fail the ceremony (which would strand the user in a paired-but-errored state
                // with no invite to retry). Log it; the operator can re-grant via
                // `service_allow_grant`. The reload_lock inside serializes it safely.
                if let Err(e) = grant_service_access(&mesh, &principal, &display, &served).await {
                    tracing::warn!(%e, "mutual grant-back failed (pairing still succeeded)");
                }
                Ok(())
            })
        });
    crate::pairing::rendezvous::redeem_invite(
        mesh.endpoint.clone(),
        mesh.self_nickname(),
        invite_line,
        mesh.store.clone(),
        mesh.self_binding(),
        Some(grant_back),
    )
    .await
}

/// Handle a `peer_services` control request (#52): resolve `peer` to its endpoint, probe it
/// over `mcpmesh/ping/1`, and return the services its pong reports the caller is admitted to.
/// Authoritative + current (a fresh probe), only the caller's own admitted services.
pub(crate) async fn peer_services(
    state: &DaemonState,
    peer: String,
) -> Result<mcpmesh_local_api::PeerServicesResult> {
    let mesh = state.mesh_required()?;
    let endpoint_id = resolve_peer_endpoint(mesh, &peer).await?;
    let entry = crate::daemon::probe_peer(mesh, endpoint_id).await;
    anyhow::ensure!(
        entry.reachable,
        "peer '{peer}' is unreachable — cannot fetch its shared services"
    );
    Ok(mcpmesh_local_api::PeerServicesResult {
        services: entry.services,
    })
}

/// Resolve a `peer` selector to a stored endpoint id (#52): an `eid:<hex>` decodes directly;
/// else a stored `PeerEntry` by nickname; else the first device under a `b64u:` user_id.
async fn resolve_peer_endpoint(mesh: &Arc<MeshState>, peer: &str) -> Result<[u8; 32]> {
    if let Some(hex) = peer.strip_prefix("eid:") {
        let bytes = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid eid principal: not lowercase hex"))?;
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid eid principal: expected 32 bytes"));
    }
    let store = mesh.store.clone();
    let peer_owned = peer.to_string();
    let eid = tokio::task::spawn_blocking(move || -> Result<Option<[u8; 32]>> {
        if let Some(e) = store.entry_for(&peer_owned)? {
            return Ok(Some(e.endpoint_id));
        }
        Ok(store
            .entries_for_user(&peer_owned)?
            .first()
            .map(|e| e.endpoint_id))
    })
    .await
    .context("join peer resolve for peer_services")??;
    eid.with_context(|| format!("no paired peer '{peer}' — 'mcpmesh status' lists your peers"))
}

/// Handle an `unregister_service` control request/// Handle an `unregister_service` control request (#50): remove the whole `[services.<name>]`
/// entry (allow list included) AND drop any in-memory ephemeral registration of that name,
/// then hot-reload so the running registry stops serving it. Idempotent (unknown name → clean
/// no-op), serialized under the SAME `reload_lock` as `register_service`/#44. In-flight
/// sessions finish (the reload rebuilds the registry without it; no NEW sessions admitted).
pub(crate) async fn unregister_service(state: &DaemonState, name: String) -> Result<()> {
    let mesh = state.mesh_required()?;
    let _reload = mesh.reload_lock.lock().await;

    // Drop an in-memory ephemeral registration of this name (if any).
    let dropped_ephemeral = mesh
        .ephemeral_services
        .lock()
        .expect("ephemeral_services lock not poisoned")
        .remove(&name)
        .is_some();

    // Remove the persistent config entry (if any).
    let config_path = mesh.config_path.clone();
    let name_w = name.clone();
    let removed_config = blocking("join unregister config write", move || {
        remove_service_from_config(&config_path, &name_w)
    })
    .await??;

    // Reload only if something actually changed (else the running registry already excludes it).
    if dropped_ephemeral || removed_config {
        reload_services_from_disk(mesh, "unregister").await?;
    }
    tracing::info!(service = %name, dropped_ephemeral, removed_config, "unregistered service");
    Ok(())
}

/// Set this node's CUSTOM relay set LIVE (#53, the `set_relays` verb). `relay_urls` is the
/// DESIRED custom set; the daemon computes a diff against the currently-persisted set and, when
/// the node is already in `relay_mode = "custom"`, applies the delta to the RUNNING endpoint via
/// iroh 1.0.3 `Endpoint::insert_relay`/`remove_relay` — no endpoint rebuild, no dropped sessions
/// — then persists `[network] relay_mode="custom" relay_urls=[…]`. Serialized under the SAME
/// `reload_lock` as every other config mutator.
///
/// - **Validation is atomic and up front:** an empty list is rejected (custom mode requires ≥1
///   relay; fully disabling relays is a `relay_mode="disabled"` restart, not this verb), and every
///   URL must parse as an iroh `RelayUrl` — a single bad entry aborts with NOTHING applied.
/// - **Idempotent:** if the desired set (order-independent) equals the persisted set, no writes
///   and no endpoint calls happen (`changed = false`).
/// - **Mode transitions are NOT live:** iroh cannot swap a running endpoint's relay MODE
///   (`default`'s built-in map / a `disabled` no-relay endpoint). So when the node's current mode
///   is not `custom`, the new set is PERSISTED but not applied live and `restart_required = true`
///   is returned. On the custom→custom path `restart_required = false` (already live).
pub(crate) async fn set_relays(
    state: &DaemonState,
    relay_urls: Vec<String>,
) -> Result<SetRelaysResult> {
    let mesh = state.mesh_required()?;

    // Validate atomically, BEFORE the lock and before any mutation: non-empty + every URL a
    // well-formed iroh RelayUrl. A malformed entry must abort with nothing half-applied.
    anyhow::ensure!(
        !relay_urls.is_empty(),
        "set_relays: relay_urls is empty (custom mode requires at least one relay; \
         disable relays via a relay_mode=\"disabled\" restart)"
    );
    let parsed: Vec<iroh::RelayUrl> = relay_urls
        .iter()
        .map(|u| {
            u.parse::<iroh::RelayUrl>()
                .map_err(|e| anyhow::anyhow!("set_relays: relay url {u:?}: {e}"))
        })
        .collect::<Result<_>>()?;

    let _reload = mesh.reload_lock.lock().await;

    // The LIVE relay posture (seeded at boot, updated on each edit) is the runtime truth we diff
    // against — NOT the on-disk config, which the `.config()` embedder front door may never have
    // written. Only `custom` mode can be live-reconfigured; any other current mode means the
    // switch onto custom is a MODE transition iroh can't do live → persist + `restart_required`.
    let posture = mesh.applied_relays();
    let restart_required = posture.mode != "custom";

    // Diff on the NORMALIZED relay URL (iroh's canonical `RelayUrl` form — trailing slash, lowercased
    // host, default port dropped), NOT the raw strings: the running endpoint's relay map keys on the
    // normalized value, so a re-spelling of the same relay (a trailing slash, host case) must count
    // as unchanged. Diffing raw strings would `remove_relay` a relay the caller meant to KEEP.
    let desired_norm: Vec<String> = parsed.iter().map(|r| r.to_string()).collect();
    let current_norm: Vec<String> = posture
        .urls
        .iter()
        .filter_map(|u| u.parse::<iroh::RelayUrl>().ok().map(|r| r.to_string()))
        .collect();
    let desired_set: BTreeSet<&str> = desired_norm.iter().map(String::as_str).collect();
    let current_set: BTreeSet<&str> = current_norm.iter().map(String::as_str).collect();

    // Idempotent on BOTH paths: an unchanged set → no writes, no endpoint calls. (On the
    // restart-required path `current_norm` is the last-persisted set we tracked, so a repeat call
    // with the same set before a restart is a clean no-op too.)
    if current_set == desired_set {
        return Ok(SetRelaysResult {
            changed: false,
            restart_required,
        });
    }

    // Persist FIRST — it is the ONLY fallible step (iroh's insert/remove can't fail on an open
    // endpoint). Persisting before the live mutation keeps the critical section atomic: a write
    // error leaves the endpoint, the posture, AND the config all untouched (nothing applied). We
    // persist the NORMALIZED forms so config/posture always match the live map's keys.
    let config_path = mesh.config_path.clone();
    let persisted = desired_norm.clone();
    blocking("set_relays config write", move || {
        write_relays(&config_path, &persisted)
    })
    .await??;

    // Apply the delta to the running endpoint ONLY on the custom→custom path (iroh can't live-
    // transition the relay MODE). These calls are infallible on an open endpoint.
    if !restart_required {
        // Insert the newly-added relays (desired − current).
        for (ru, norm) in parsed.iter().zip(desired_norm.iter()) {
            if !current_set.contains(norm.as_str()) {
                mesh.endpoint
                    .insert_relay(ru.clone(), Arc::new(iroh::RelayConfig::from(ru.clone())))
                    .await;
            }
        }
        // Remove the dropped relays (current − desired). `current_norm` came from parsing, so each
        // re-parses to the same `RelayUrl` the live map holds.
        for norm in &current_norm {
            if !desired_set.contains(norm.as_str())
                && let Ok(ru) = norm.parse::<iroh::RelayUrl>()
            {
                mesh.endpoint.remove_relay(&ru).await;
            }
        }
    }

    // Track the persisted set as the new posture. On the custom path the live endpoint now matches;
    // on the restart-required path the endpoint is UNCHANGED, so keep the (non-custom) mode — that
    // makes a repeat call idempotent yet still `restart_required` until an actual restart.
    let new_mode = if restart_required {
        &posture.mode
    } else {
        "custom"
    };
    mesh.set_applied_relays(new_mode, &desired_norm);

    tracing::info!(
        count = desired_norm.len(),
        restart_required,
        "set custom relay set"
    );
    Ok(SetRelaysResult {
        changed: true,
        restart_required,
    })
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
/// write). Reuses `append_allow_to_config`'s atomic write and `swap_services`'s
/// in-place registry swap (DRY). A service not present in config is logged + skipped (a pairing grant
/// never CREATES a service). Reloads ONLY when the append actually changed the config — an
/// idempotent re-pair or an all-missing grant is a no-op with no serving blip. (The cached
/// `status` snapshot is not refreshed here — this runs inside the accept loop's detached pair
/// handler, which holds no `DaemonState` — but it need not be: `status` reads the config + store
/// LIVE (control.rs `status_result`), so this grant shows up immediately. The durable allow-append
/// + the live rebuilt `Services` are the functional truth.)
pub async fn grant_service_access(
    mesh: &Arc<MeshState>,
    principal: &str,
    display_nickname: &str,
    services: &[String],
) -> Result<()> {
    // SAME serialization as register_service: hold the whole append→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Idempotent allow-append on a blocking thread (config IO blocks). `principal` is the
    //    redeemer's STABLE identity (#38: `b64u:` when bound, else `eid:`) — the display
    //    nickname below is audit/log color only and never lands in `allow`.
    //    This path stays LENIENT about a name matching neither source (warn + skip, as before):
    //    it is the pairing ceremony, and a stale service name in an invite must never abort a
    //    pairing. The strict, single-service [`grant_service_allow`] is where an unknown name
    //    errors.
    //
    //    ORDER MATTERS: the CONFIG write runs FIRST, and the in-memory ephemeral allow is only
    //    mutated once it has succeeded (#55 review). The reverse order left a failed grant
    //    half-applied — the verb returned `Err`, but the in-memory grant stood and was installed
    //    by the next unrelated reload, admitting a principal the caller was told was not granted.
    let config_path = mesh.config_path.clone();
    let principal_w = principal.to_string();
    let config_services = services.to_vec();
    let changed = blocking("join grant config write", move || {
        append_allow_to_config(&config_path, &principal_w, &config_services)
    })
    .await??;

    //    EPHEMERAL registrations carry their allow in memory only (#55), so the config append
    //    above cannot reach them. Apply to BOTH sources rather than ephemeral-first: a name can be
    //    held by both (a hand-edited config under a live ephemeral registration), and granting only
    //    the shadowing copy would leave the config copy stale — then live, with the wrong allow,
    //    the moment the ephemeral entry is dropped.
    let mut changed = changed;
    for svc in services {
        if let Some(moved) = mesh.grant_ephemeral(svc, principal) {
            changed |= moved;
        }
    }

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already admits the peer). The reload MUST happen for a real append to take effect,
    //      since `select_service` reads the allow baked into `Services` at build time.
    if changed {
        reload_services_from_disk(mesh, "grant").await?;
    }

    // Trust event: NO secret (the display nickname is the surface-clean handle).
    tracing::info!(peer = %display_nickname, ?services, changed, "granted service access");
    // Trust event: a pairing grant. Display nickname only — NO secret.
    mesh.audit().record(AuditRecord::trust(
        now_ts(),
        "pair".into(),
        Some(display_nickname.to_string()),
    ));
    Ok(())
}

/// Does `config.toml` carry a `[services.<name>]` entry the daemon can actually SERVE? Read fresh
/// (not from the live registry) so a service added out-of-band since boot counts. Used only to
/// distinguish "nothing to change" from "no such service" (#55) — the surgical RMW writers report
/// `false` for both.
///
/// A config-load failure PROPAGATES rather than answering `false` (#55 review): a corrupt or
/// unreadable config is not the same condition as a missing service, and reporting
/// [`NoSuchService`] for it would tell the operator to register a service that already exists.
///
/// The entry must also have a well-formed backend. `build_services_with_ephemeral` skips a
/// malformed `[services.*]` (neither/both of `run` and `socket`) with a warning, so treating it as
/// present would let a grant report success and write an allow that admits nobody — the exact
/// silent-success class this strictness exists to remove.
async fn service_servable_in_config(mesh: &Arc<MeshState>, service: &str) -> Result<bool> {
    let config_path = mesh.config_path.clone();
    let service = service.to_string();
    blocking("join service-exists config read", move || {
        let cfg = Config::load(&config_path)
            .map_err(|e| anyhow::anyhow!("config error in {}: {e}", config_path.display()))?;
        Ok(cfg
            .services
            .get(&service)
            .is_some_and(|svc| svc.backend_result().is_ok()))
    })
    .await?
}

/// The named service exists in neither the config nor the ephemeral registry (#55). A distinct
/// error type so `respond` can map it to [`ERR_NO_SUCH_SERVICE`](mcpmesh_local_api::ERR_NO_SUCH_SERVICE)
/// and a caller can branch — the same `downcast_ref` idiom `InvalidParams` uses for `-32602`.
#[derive(Debug)]
pub struct NoSuchService(pub String);

impl std::fmt::Display for NoSuchService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no service named '{}' that this daemon can serve — register it first \
             ('mcpmesh serve', or register_service), or check the config entry names exactly one \
             of `run` / `socket`",
            self.0
        )
    }
}
impl std::error::Error for NoSuchService {}

/// Grant a SINGLE stable `principal` access to a SINGLE `service` (#44, the
/// `service_allow_grant` verb) — the per-peer "sharing on" toggle primitive. Idempotent +
/// serialized under `reload_lock`, exactly like a pairing grant.
///
/// Unlike the pairing [`grant_service_access`] it wraps, this is STRICT (#55): a name that is
/// neither an ephemeral registration nor a `[services.*]` config entry is a [`NoSuchService`]
/// error, not a silent success. It used to answer `{}` for every unknown name — including EVERY
/// ephemeral service, whose allow is in memory and so was never touched by the config append.
pub(crate) async fn service_allow_grant(
    state: &DaemonState,
    service: String,
    principal: String,
) -> Result<()> {
    grant_service_allow(state.mesh_required()?, service, principal).await
}

/// The mesh-level half of `service_allow_grant`, and the exact mirror of [`revoke_service_allow`]:
/// resolve the service, append `principal` to its allow, hot-swap the live registry.
///
/// Resolution and mutation BOTH happen under `reload_lock` (#55 review). Resolving outside the
/// lock left a race: an ephemeral registration whose control connection dropped between the check
/// and the mutation fell through to the config append, which warn-and-skipped, and the verb
/// reported success having granted nobody — the #55 symptom restored as a race.
///
/// STRICT, unlike the pairing [`grant_service_access`]: a name that is neither an ephemeral
/// registration nor a servable `[services.*]` entry is a [`NoSuchService`] error rather than a
/// silent success. It used to answer `{}` for every unknown name — silently including EVERY
/// ephemeral service, whose allow the config append never touched.
///
/// `pub` (like [`revoke_service_allow`]) so integration tests drive the SAME pipeline the verb does.
pub async fn grant_service_allow(
    mesh: &Arc<MeshState>,
    service: String,
    principal: String,
) -> Result<()> {
    let _reload = mesh.reload_lock.lock().await;
    let is_ephemeral = {
        let map = mesh
            .ephemeral_services
            .lock()
            .expect("ephemeral_services lock not poisoned");
        map.contains_key(&service)
    };
    if !is_ephemeral && !service_servable_in_config(mesh, &service).await? {
        anyhow::bail!(NoSuchService(service));
    }

    // CONFIG FIRST, then the in-memory allow — a failed config write must not leave an ephemeral
    // grant half-applied (see `grant_service_access`).
    let config_path = mesh.config_path.clone();
    let (principal_w, services_w) = (principal.clone(), vec![service.clone()]);
    let mut changed = blocking("join service-allow grant config write", move || {
        append_allow_to_config(&config_path, &principal_w, &services_w)
    })
    .await??;
    if let Some(moved) = mesh.grant_ephemeral(&service, &principal) {
        changed |= moved;
    }
    if changed {
        reload_services_from_disk(mesh, "service-allow-grant").await?;
    }
    tracing::info!(%service, %principal, changed, "service allow granted");
    Ok(())
}

/// Revoke a SINGLE stable `principal` from a SINGLE `service`'s allow (#44, the
/// `service_allow_revoke` verb) — the per-peer "sharing off" toggle, WITHOUT unpairing (the
/// peer's `PeerEntry` identity is untouched). A thin `DaemonState` wrapper over
/// [`revoke_service_allow`], mirroring how [`service_allow_grant`] wraps
/// [`grant_service_access`].
pub(crate) async fn service_allow_revoke(
    state: &DaemonState,
    service: String,
    principal: String,
) -> Result<()> {
    revoke_service_allow(state.mesh_required()?, service, principal).await
}

/// The mesh-level half of `service_allow_revoke`: strip `principal` from `service`'s allow,
/// hot-swap the live registry, then SEVER the principal's live connections. Idempotent +
/// serialized under `reload_lock`, mirroring [`grant_service_access`].
///
/// **Resolves the service EPHEMERAL-first, then config, then errors** (#69). An ephemeral
/// registration's allow lives in memory only, so before this the strip edited `config.toml`, found
/// nothing, and the next hot-reload re-overlaid the untouched in-memory allow — the peer stayed
/// admitted while the verb reported success. A name that is neither is now a
/// [`NoSuchService`] error rather than a silent no-op.
///
/// Post-#54: revocation is IMMEDIATE. New sessions are refused (the live registry, read per
/// bi-stream) and in-flight ones are cut (the sever). Previously both waited for the peer to
/// disconnect on its own.
///
/// `pub` (like [`grant_service_access`]) so the integration tests drive the SAME
/// strip→swap→sever pipeline the control verb drives.
pub async fn revoke_service_allow(
    mesh: &Arc<MeshState>,
    service: String,
    principal: String,
) -> Result<()> {
    let _reload = mesh.reload_lock.lock().await;

    // Strip from BOTH sources, not ephemeral-first (#55 review). A name can be held by both — a
    // hand-edited `config.toml` under a live ephemeral registration — and stripping only the
    // shadowing ephemeral copy left the config copy holding the principal. That copy is invisible
    // while the overlay shadows it, then goes LIVE with the stale allow the moment the registering
    // control connection drops the ephemeral entry, re-admitting a principal the operator was told
    // was revoked. Revocation must be fail-closed across every allow the name owns.
    let ephemeral_moved = mesh.revoke_ephemeral(&service, &principal);
    let config_path = mesh.config_path.clone();
    let (svc_w, principal_w) = (service.clone(), principal.clone());
    let config_moved = blocking("join service-allow revoke config write", move || {
        remove_principal_from_service(&config_path, &svc_w, &principal_w)
    })
    .await??;

    // `remove_principal_from_service` reports `false` both for "service absent" and for "principal
    // was not in this service's allow", so re-read the config to tell them apart: only the former
    // is an error, and only when no ephemeral registration claims the name either.
    if ephemeral_moved.is_none()
        && !config_moved
        && !service_servable_in_config(mesh, &service).await?
    {
        anyhow::bail!(NoSuchService(service));
    }
    let changed = config_moved || ephemeral_moved.unwrap_or(false);
    // SWAP-BEFORE-SEVER (#54): swap first so no NEW session admits the principal, THEN cut the
    // sessions already in flight.
    //
    // Gated on `changed` DELIBERATELY. A strip that removed nothing means this principal was not
    // in that allow, so nothing was revoked — and severing anyway would hand the operator a
    // visible disconnect that LOOKS like the revoke landed while access is unchanged. Concretely:
    // `allow = ["b64u:alice"]` and a caller revoking `eid:<alice's device>` strips nothing, but
    // that device is still admitted via the user_id and would be served again the instant it
    // redialed. A false "revocation took effect" signal is worse on this surface than a missed
    // sever, and `api_minor >= 10` is what consumers key that signal off.
    let severed = if changed {
        reload_services_from_disk(mesh, "service-allow-revoke").await?;
        sever_principal(mesh, &principal).await?
    } else {
        0
    };
    tracing::info!(%service, %principal, changed, severed, "service allow revoked");
    Ok(())
}

/// Close every live mesh connection held by one `principal`'s devices. Thin wrapper over
/// [`sever_principals`] for the single-principal call sites.
async fn sever_principal(mesh: &Arc<MeshState>, principal: &str) -> Result<usize> {
    sever_principals(mesh, std::slice::from_ref(&principal.to_string())).await
}

/// Close every live connection held by ANY of `principals`' devices, returning the number severed.
///
/// The liveness half of a revoke (#54): stripping the config `allow` and swapping the live
/// registry stop NEW sessions, but an in-flight session on an already-open connection keeps running
/// until the peer disconnects — unbounded for an embedder holding a warm session.
///
/// Resolves the WHOLE set in ONE pass (one `store.list()` + one roster-view walk) rather than once
/// per principal, since `revoke_service_access` routinely passes a device `eid:` and its owner's
/// `b64u:` together.
///
/// **Granularity is the CONNECTION, not the session.** `sever_matching` closes the whole QUIC
/// connection, so a peer revoked from ONE service also loses in-flight sessions to services it
/// still holds; it redials and is re-evaluated against the live registry. Per-session cancellation
/// would need the registry to track sessions by service, and would still not protect the revoked
/// service's own in-flight stream — the actual hazard. Revocation is an explicit operator action,
/// so the bluntness is the accepted cost of the verb taking effect NOW.
///
/// **It also reaches non-mesh ALPNs.** The registry tracks gossip and blob connections on the same
/// endpoint id with no ALPN discriminator, so a revoke cuts those too. Availability only (each of
/// those arms keeps its own gate), and the peer reconnects; documented in `docs/local-protocol.md`
/// so it is not a surprise.
///
/// A principal naming no device (or no live connection) severs nothing.
async fn sever_principals(mesh: &Arc<MeshState>, principals: &[String]) -> Result<usize> {
    let store = mesh.store.clone();
    let roster = mesh.roster.view();
    let principals_w = principals.to_vec();
    let targets = blocking("join sever principal resolution", move || {
        let mut all = std::collections::HashSet::new();
        for principal in &principals_w {
            all.extend(crate::daemon::sever::endpoints_for_principal(
                &store,
                roster.as_deref(),
                principal,
            )?);
        }
        anyhow::Ok(all)
    })
    .await??;
    if targets.is_empty() {
        return Ok(0);
    }
    Ok(mesh.conn_registry.sever_matching(
        mcpmesh_net::CLOSE_UNAUTHORIZED, // 401 — "no longer authorized"
        b"access revoked",
        |eid, _| targets.contains(eid),
    ))
}

/// Revoke a peer's AUTHORIZATION: resolve the nickname to its devices' STABLE principals
/// (#38) and strip them from EVERY service's config `[services.<svc>].allow`, then hot-reload
/// so the running registry stops admitting them. The exact INVERSE of
/// [`grant_service_access`] (which appends the stable principal), and the authorization half
/// of [`remove_peer`].
///
/// **The principal-strip rule (spec-settled):** each target device's `eid:` is stripped
/// ALWAYS; the shared `b64u:` user_id is stripped ONLY when no OTHER stored peer entry
/// carries it — unpairing one device of a multi-device person must never revoke the person.
/// Bare strings in `allow` are NEVER stripped here: post-#38 a bare entry is roster
/// vocabulary (a group or roster user_id), and a nickname-keyed strip could collide with a
/// group name and revoke a whole roster group. (Note the boundary: admission requires gate
/// RESOLVE first, so deleting the PeerEntry already denies the device outright — this strip
/// is grant hygiene, not the security boundary.)
///
/// Serialized against [`register_service`] / [`grant_service_access`] via `mesh.reload_lock` (the
/// SAME lock — a concurrent config mutation must not read the same base config and clobber this
/// removal). Reuses [`remove_allow_from_config`]'s atomic write and [`swap_services`]'s
/// in-place registry swap (DRY — the same helper the grant uses). Reloads ONLY when the removal actually
/// changed the config (an absent nickname is a no-op with no serving blip). Idempotent: revoking a
/// nickname not present in any allow returns `Ok(())` with `changed == false` and no reload.
///
/// (Like [`grant_service_access`], the cached `status` snapshot is not refreshed here — but
/// `status` reads the config + store LIVE (control.rs `status_result`), so the removal shows up
/// immediately. The durable allow-removal + the live rebuilt `Services` are the functional truth.)
pub async fn revoke_service_access(mesh: &Arc<MeshState>, nickname: &str) -> Result<bool> {
    // SAME serialization as register_service / grant: hold the whole remove→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 0. Resolve the target devices' stable principals BEFORE any teardown (the caller
    //    `remove_peer` deletes the rows after this returns — ordering already safe).
    let store = mesh.store.clone();
    let nick_r = nickname.to_string();
    let principals: Vec<String> = blocking("join revoke principal resolution", move || {
        let (targets, others): (Vec<_>, Vec<_>) = store
            .list()?
            .into_iter()
            .partition(|e| e.nickname == nick_r);
        let mut principals = Vec::new();
        for target in &targets {
            principals.push(mcpmesh_net::EndpointId::from_bytes(target.endpoint_id).principal());
            if let Some(user_id) = &target.user_id {
                let shared_elsewhere = others.iter().any(|o| o.user_id.as_deref() == Some(user_id));
                if !shared_elsewhere && !principals.contains(user_id) {
                    principals.push(user_id.clone());
                }
            }
        }
        anyhow::Ok(principals)
    })
    .await??;
    if principals.is_empty() {
        // No stored device under this nickname → nothing resolvable to strip. (Legacy
        // bare-nickname allow entries are deliberately untouched — doctor lints them.)
        tracing::info!(peer = %nickname, changed = false, "revoked service access");
        return Ok(false);
    }

    // 1. Idempotent allow-removal on a blocking thread (config IO blocks) — ONE atomic RMW
    //    over all of the peer's principals.
    let config_path = mesh.config_path.clone();
    let principals_w = principals.clone(); // the sever below needs them after the write consumes its copy
    let changed = blocking("join revoke config write", move || {
        remove_allow_from_config(&config_path, &principals_w)
    })
    .await??;

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already excludes the peer). A real removal MUST reload for `select_service` — which
    //      reads the allow baked into `Services` at build time — to stop admitting the nickname.
    if changed {
        reload_services_from_disk(mesh, "revoke").await?;
    }

    // 4. SEVER the peer's live connections (#54). The strip + swap above stop NEW sessions;
    //    without this, sessions already in flight run to completion on a connection whose peer we
    //    just de-authorized. Runs AFTER the swap (swap-before-sever, the ordering
    //    `install_roster_view_and_sever` uses) so a peer racing a redial across the sever meets
    //    the NEW registry.
    //
    //    UNCONDITIONAL of `changed` here — unlike `revoke_service_allow`, which gates on it. The
    //    caller (`remove_peer`) DELETES the `PeerEntry` right after this returns, so the peer
    //    loses gate resolve entirely and cannot be re-admitted on redial. There is therefore no
    //    false "it took effect" signal to worry about: the unpair really did take effect, whether
    //    or not any allow line happened to name it.
    let severed = sever_principals(mesh, &principals).await?;

    // Return whether an allow was actually stripped so `remove_peer` audits an `unpair` only
    // on a real tear-down (nickname only — NO secret, NO endpoint id).
    tracing::info!(peer = %nickname, changed, severed, "revoked service access");
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

    /// #50: `unregister_service` removes the whole config entry (allow included), idempotently,
    /// without touching peer identity.
    #[tokio::test(flavor = "multi_thread")]
    async fn unregister_service_removes_the_entry_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = [\"eid:beef\"]\n             [services.notes]\nsocket = \"/run/notes.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());
        let has = |name: &str| {
            crate::config::Config::load(&config_path)
                .unwrap()
                .services
                .contains_key(name)
        };

        assert!(has("kb") && has("notes"));
        unregister_service(&state, "kb".into()).await.unwrap();
        assert!(!has("kb"), "kb removed");
        assert!(has("notes"), "other services untouched");
        // Idempotent: unregistering an unknown / already-gone name is a clean no-op.
        unregister_service(&state, "kb".into()).await.unwrap();
        unregister_service(&state, "ghost".into()).await.unwrap();
        assert!(has("notes"));
    }

    /// #44: `service_allow_grant`/`service_allow_revoke` toggle
    /// service's allow, idempotently, WITHOUT touching peer identity. The "sharing switch".
    #[tokio::test(flavor = "multi_thread")]
    async fn service_allow_grant_and_revoke_toggle_one_principal() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());
        let allow = || {
            crate::config::Config::load(&config_path)
                .unwrap()
                .services
                .get("kb")
                .unwrap()
                .allow
                .clone()
        };

        // Grant → the principal lands in the service allow.
        service_allow_grant(&state, "kb".into(), "eid:beef".into())
            .await
            .unwrap();
        assert_eq!(allow(), vec!["eid:beef".to_string()]);
        // Idempotent grant → still exactly one entry.
        service_allow_grant(&state, "kb".into(), "eid:beef".into())
            .await
            .unwrap();
        assert_eq!(allow(), vec!["eid:beef".to_string()]);

        // Revoke → removed. Peer identity is not involved here at all (no PeerEntry touched).
        service_allow_revoke(&state, "kb".into(), "eid:beef".into())
            .await
            .unwrap();
        assert!(allow().is_empty());
        // Idempotent revoke of an absent principal → clean no-op.
        service_allow_revoke(&state, "kb".into(), "eid:beef".into())
            .await
            .unwrap();
        assert!(allow().is_empty());

        // #55: an unknown service is now an ERROR on both verbs, not a silent success. It used to
        // answer `{}` — which silently included every ephemeral service, whose allow the config
        // writers never touch.
        let grant_err = service_allow_grant(&state, "ghost".into(), "eid:beef".into())
            .await
            .expect_err("an unknown service must not report success");
        assert!(
            grant_err.downcast_ref::<NoSuchService>().is_some(),
            "the grant error must be branchable as NoSuchService, got: {grant_err}"
        );
        let revoke_err = service_allow_revoke(&state, "ghost".into(), "eid:beef".into())
            .await
            .expect_err("an unknown service must not report success");
        assert!(
            revoke_err.downcast_ref::<NoSuchService>().is_some(),
            "the revoke error must be branchable as NoSuchService, got: {revoke_err}"
        );
    }

    /// #55: the no-such-service condition reaches the WIRE as the branchable `-32040`, not the
    /// generic `-32000`. The unit assertions above only prove the Rust-level downcast; a
    /// misordered `respond` arm or a stray `.context()` would silently downgrade the code with
    /// every other test still green.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_service_answers_the_no_such_service_code_on_the_wire() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path).await;
        let state = crate::control::DaemonState::with_mesh("test", mesh);
        let req = |method: &str| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": method,
                "params": {"service": "ghost", "principal": "eid:beef"}
            })
        };

        for method in ["service_allow_grant", "service_allow_revoke"] {
            let r = crate::control::handle_request(&req(method), &state).await;
            assert_eq!(
                r["error"]["code"],
                mcpmesh_local_api::ERR_NO_SUCH_SERVICE,
                "{method} must answer -32040 for an unknown service, got: {r}"
            );
        }
    }

    /// #55 review: a name held BOTH ephemerally and in config must be revoked from BOTH. The
    /// ephemeral entry shadows the config one in the registry, so stripping only the shadow left
    /// the config allow holding the principal — invisible until the ephemeral registration was
    /// dropped, at which point it went live and re-admitted them.
    #[tokio::test(flavor = "multi_thread")]
    async fn revoking_a_shadowed_name_strips_the_config_allow_too() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.room]\nsocket = \"/run/room.sock\"\nallow = [\"eid:beef\"]\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        // A hand-edited config under a live ephemeral registration of the same name.
        mesh.register_ephemeral(
            "room".to_string(),
            crate::daemon::EphemeralService {
                backend: mcpmesh_local_api::BackendSpec::Socket {
                    path: "/run/room.sock".into(),
                },
                allow: vec!["eid:beef".to_string()],
                rate_limit_per_min: None,
            },
        );

        revoke_service_allow(&mesh, "room".into(), "eid:beef".into())
            .await
            .unwrap();

        assert!(
            mesh.ephemeral_services
                .lock()
                .unwrap()
                .get("room")
                .unwrap()
                .allow
                .is_empty(),
            "the ephemeral allow is stripped"
        );
        assert!(
            crate::config::Config::load(&config_path)
                .unwrap()
                .services
                .get("room")
                .unwrap()
                .allow
                .is_empty(),
            "the SHADOWED config allow must be stripped too — otherwise it goes live with a \
             revoked principal the moment the ephemeral registration is dropped"
        );
    }

    /// #55 review: a FAILED grant must not leave the in-memory ephemeral allow mutated. The config
    /// write runs first; if it fails the whole grant fails, and a later unrelated reload must not
    /// install a principal the caller was told was not granted.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_config_write_leaves_the_ephemeral_allow_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // `allow` as a scalar makes `append_allow_to_config` bail.
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = \"not-an-array\"\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path).await;
        mesh.register_ephemeral(
            "room".to_string(),
            crate::daemon::EphemeralService {
                backend: mcpmesh_local_api::BackendSpec::Socket {
                    path: "/run/room.sock".into(),
                },
                allow: vec![],
                rate_limit_per_min: None,
            },
        );

        let r = grant_service_access(
            &mesh,
            "eid:beef",
            "eid:beef",
            &["room".to_string(), "kb".to_string()],
        )
        .await;
        assert!(r.is_err(), "the malformed config must fail the grant");
        assert!(
            mesh.ephemeral_services
                .lock()
                .unwrap()
                .get("room")
                .unwrap()
                .allow
                .is_empty(),
            "a FAILED grant must not have applied the in-memory half"
        );
    }

    /// #55/#69: both verbs route to an EPHEMERAL registration's in-memory allow, which the config
    /// writers cannot reach. The unit-level complement to `cli/tests/ephemeral_allow.rs` (which
    /// proves a real peer is admitted/refused end to end).
    #[tokio::test(flavor = "multi_thread")]
    async fn allow_verbs_mutate_an_ephemeral_registration() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path).await;
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());

        mesh.register_ephemeral(
            "room".to_string(),
            crate::daemon::EphemeralService {
                backend: mcpmesh_local_api::BackendSpec::Socket {
                    path: "/run/room.sock".into(),
                },
                allow: vec![],
                rate_limit_per_min: None,
            },
        );
        let allow = || {
            mesh.ephemeral_services
                .lock()
                .unwrap()
                .get("room")
                .unwrap()
                .allow
                .clone()
        };

        service_allow_grant(&state, "room".into(), "eid:beef".into())
            .await
            .unwrap();
        assert_eq!(allow(), vec!["eid:beef".to_string()], "granted in memory");
        service_allow_grant(&state, "room".into(), "eid:beef".into())
            .await
            .unwrap();
        assert_eq!(allow(), vec!["eid:beef".to_string()], "grant is idempotent");

        service_allow_revoke(&state, "room".into(), "eid:beef".into())
            .await
            .unwrap();
        assert!(allow().is_empty(), "revoked in memory");
        service_allow_revoke(&state, "room".into(), "eid:beef".into())
            .await
            .unwrap();
        assert!(allow().is_empty(), "revoke is idempotent");

        // The config service is untouched by the ephemeral routing.
        assert!(
            crate::config::Config::load(&mesh.config_path)
                .unwrap()
                .services
                .get("kb")
                .unwrap()
                .allow
                .is_empty(),
            "an ephemeral grant must not write the config"
        );
    }

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

    /// The typed `peer_rename` params, as the control dispatcher hands them to `rename_peer`.
    fn rename_params(user_id: Option<&str>, to: &str) -> PeerRenameParams {
        PeerRenameParams {
            user_id: user_id.map(str::to_string),
            nickname: None,
            to: to.into(),
        }
    }

    /// `rename_peer` renames ALL of a person's devices (matched by user_id) to the new nickname —
    /// and touches NOTHING else (#38): `allow` holds stable principals (here the renamed person's
    /// own `b64u:` user_id), so the config is byte-identical after the rename. Grants survive a
    /// rename by construction — no allow rewrite happens because no grant names a nickname.
    #[tokio::test]
    async fn rename_peer_renames_all_devices_and_leaves_grants_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // The grant names the renamed person's PRINCIPAL — the strongest case: even the
        // renamed person's own grant must not be rewritten.
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = [\"b64u:BOB\"]\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        // Two devices of ONE person (same user_id), both under the old nickname.
        mesh.store
            .add(rename_entry(1, "bob-old", Some("b64u:BOB")))
            .unwrap();
        mesh.store
            .add(rename_entry(2, "bob-old", Some("b64u:BOB")))
            .unwrap();
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());
        let config_before = std::fs::read_to_string(&config_path).unwrap();

        rename_peer(&state, rename_params(Some("b64u:BOB"), "Bobby"))
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
            names.iter().all(|n| n == "Bobby"),
            "all devices renamed, got {names:?}"
        );
        // #38: the rename touched ONLY nicknames — the config (and its principal-keyed allow)
        // is byte-identical, so the grant survived without any rewrite.
        let config_after = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            config_before, config_after,
            "rename must not rewrite the config"
        );
        let doc: toml::Table = toml::from_str(&config_after).unwrap();
        let allow = doc["services"]["kb"]["allow"].as_array().unwrap();
        assert_eq!(allow.len(), 1);
        assert_eq!(allow[0].as_str(), Some("b64u:BOB"));
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
        let plan = rename_plan(&store, Some("b64u:BOB"), None, "Bobby")
            .unwrap()
            .unwrap();
        assert_eq!(plan.targets.len(), 2);

        // GUARD (a) display-uniqueness: renaming Bob → "carol" (a DIFFERENT contact) is
        // refused — a duplicate display name misdirects outbound dials. (The old orphan-allow
        // guard (b) is GONE, #38: allow holds principals, so no name can inherit a grant.)
        assert!(rename_plan(&store, Some("b64u:BOB"), None, "carol").is_err());
        // A provisional contact (no user_id) renames by nickname to a fresh name.
        store.add(rename_entry(4, "dave", None)).unwrap();
        assert_eq!(
            rename_plan(&store, None, Some("dave"), "Dave")
                .unwrap()
                .unwrap()
                .targets
                .len(),
            1
        );
        // Renaming to the current name is a no-op (Ok(None)).
        assert!(
            rename_plan(&store, Some("b64u:CAROL"), None, "carol")
                .unwrap()
                .is_none()
        );
        // No matching contact → error.
        assert!(rename_plan(&store, Some("b64u:NOBODY"), None, "x").is_err());
    }
}
