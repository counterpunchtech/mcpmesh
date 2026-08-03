//! Daemon process bring-up: the per-uid singleton, `[network]`-posture validation
//! ([`net_plan`]), Iroh endpoint construction, roster-mode transport composition, and the
//! `serve_forever` assembly that wires the whole daemon together and serves until shutdown.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, ALPN_PING, TrustGate};
use mcpmesh_trust::DeviceKey;

use crate::allowlist::{AllowlistGate, PeerStore};
use crate::audit::{AuditLog, AuditSink};
use crate::config::Config;
use crate::control::{DaemonState, serve_control};
use crate::ipc;
use crate::node::StartError;
use std::time::Duration;

use crate::pairing::LiveInvites;
use crate::paths::NodePaths;
use crate::roster::RosterStore;
use crate::roster::freshness::FreshnessStore;
use crate::roster::gate::{ComposedGate, RosterGate};
use crate::util::{blocking, epoch_now_i64};

use super::accept::spawn_accept_loop;
use super::roster_install::{
    respawn_poll_loop, roster_confirmed_path, spawn_staleness_sweep, warn_if_degraded_grace,
};
use super::{MeshState, STACK_VERSION, build_services_audited, default_self_nickname};

/// The daemon shell's async body: bind the control endpoint, boot the node core
/// (`start_node`), and serve the control API until a `shutdown` request stops it.
/// `paths` is the node's resolved on-disk world — the shell passes [`NodePaths::from_env`];
/// nothing below consults the environment for a location.
pub async fn serve_forever(socket: &Path, paths: NodePaths) -> Result<()> {
    // 0a. Bind the control listener FIRST — before state.redb, the endpoint, or the audit log. On
    //     Windows the pipe bind IS the singleton lock (there is no flock; the shell skips it there):
    //     a FILE_FLAG_FIRST_PIPE_INSTANCE create returns AddrInUse once a peer daemon owns the pipe,
    //     so binding early is what serializes daemons. On unix this AddrInUse arm is dead — the
    //     shell's flock already serialized us before we ever reached here — but the shape is uniform.
    //     The socket/pipe creation has no side effects the later construction depends on.
    let listener = match ipc::bind_control_socket(socket).await {
        Ok(l) => l,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse) =>
        {
            tracing::info!("another mcpmesh daemon already owns the control endpoint; exiting");
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let booted = start_node(paths, None).await?;
    let state = booted.state;
    // #134: the duplicate-identity detector, installed ONLY here.
    //
    // `serve_forever` is the STANDALONE daemon — it owns its process and installs no subscriber of
    // its own, so taking the global default is ours to take. This must never move into
    // `boot_node`: that path is shared with `NodeBuilder::start`, and an embedded node seizing the
    // process-global subscriber would panic a host that calls `fmt::init()` afterwards, or
    // silently swallow its logs for the process lifetime if it uses `try_init()`. An embedder
    // wires the same detection through `NodeBuilder::identity_conflict` instead.
    if let Some(mesh) = state.mesh() {
        let conflict = std::sync::Arc::new(crate::diag::IdentityConflict::default());
        mesh.adopt_identity_conflict(conflict.clone());
        crate::diag::install_for_daemon(conflict);
    }
    // The daemon serves for the process lifetime — the background handles need no owner
    // (the embedding `Node` keeps them to abort on `shutdown`; the process just exits).
    drop(booted.background);
    // Our own endpoint id is operator-shareable (it is how a peer pairs us) — not a
    // surface leak (that discipline forbids leaking OTHER peers' ids/paths in porcelain).
    tracing::info!(
        endpoint_id = %state.mesh_required()?.endpoint.id(),
        socket = %socket.display(),
        "mcpmesh daemon serving mesh + control"
    );
    serve_control(listener, state).await
}

/// A booted node core: the control-dispatch state plus the detached background loops the
/// boot spawned (presence, roster converge, staleness sweep). The daemon shell drops the
/// handles (process lifetime); the embedding `Node` aborts them on `shutdown`.
pub(crate) struct BootedNode {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) background: Vec<tokio::task::JoinHandle<()>>,
}

/// Tear a booted node down: stop accepting, end the background loops, END THE APP-BLOB GATE LOOP
/// (and wait for it), then close the endpoint.
///
/// Shared by `Node::shutdown` and by tests that boot a real node (#105). Factored out rather than
/// duplicated because a test teardown that drifts from the production one silently stops testing
/// the thing it models — and because `BootedNode::background` is EMPTY in pairing mode, so the
/// obvious `for h in booted.background { h.abort() }` is a no-op that LOOKS like cleanup while the
/// accept loop, the gate loop (holding the redb data-dir lock) and the endpoint all leak.
pub(crate) async fn shutdown_booted(booted: BootedNode) {
    let state = &booted.state;
    state.request_shutdown();
    state.abort_control_tasks();
    let Some(mesh) = state.mesh().cloned() else {
        return;
    };
    if let Some(task) = mesh.accept_task.lock().await.take() {
        task.abort();
    }
    if let Some(task) = mesh.poll_loop.lock().await.take() {
        task.abort();
    }
    for task in booted.background {
        task.abort();
    }
    // Wait for the gate loop: it owns the `Arc<dyn TrustGate>` -> `PeerStore` -> redb lock, and
    // aborting without awaiting only SCHEDULES the drop (#61).
    if let Some(blobs) = mesh.app_blobs.lock().await.take() {
        blobs.shutdown().await;
    }
    mesh.endpoint.close().await;
}

/// Boot the node core — everything `serve_forever` does EXCEPT the control endpoint:
/// crypto-provider install, audit sink, config + device key, the iroh endpoint, stores,
/// gates, limiters, service registry, the mesh accept loop, and roster mode's loops.
/// `config` overrides the on-disk `paths.config_path` when `Some` (the embedder's
/// programmatic config); config-persisting verbs still write that path.
pub(crate) async fn start_node(
    paths: NodePaths,
    config: Option<Config>,
) -> Result<BootedNode, StartError> {
    let config_path = paths.config_path.clone();
    let db_path = paths.state_db_path.clone();
    boot_node(paths, config)
        .await
        .map_err(|e| StartError::classify(e, &config_path, &db_path))
}

/// The anyhow-typed boot body — [`start_node`] classifies its error at the boundary
/// (classification inspects the error CHAIN, so inner `?` sites stay untouched).
async fn boot_node(paths: NodePaths, config: Option<Config>) -> Result<BootedNode> {
    // 0. CRITICAL: install a process-default rustls `CryptoProvider` (ring) BEFORE any
    //    reqwest client is built. reqwest 0.13.4 (`rustls-no-provider`) resolves the provider via
    //    `CryptoProvider::get_default()` at CLIENT-BUILD time and PANICS ("No rustls crypto provider
    //    is configured") if none is installed. iroh 1.0.1 passes ring per-endpoint and installs NO
    //    process-default, so nothing else does this for us. Idempotent: `install_default` returns Err
    //    if a provider is already installed, which `let _ =` swallows — a HOST APPLICATION that
    //    installed its own provider first wins. This MUST precede the URL poll loop spawned below.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut background: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // 0b. The audit log: one bounded-channel writer over <state_dir>/audit. Best-effort
    //     — record() never blocks or fails a session. Threaded into the backends (build_services_
    //     audited) and stored on the mesh for the reload sites + trust-event hooks.
    let audit = AuditSink::new(AuditLog::spawn(paths.audit_dir.clone()));

    // 1. Config + device key.
    let config_path = paths.config_path.clone();
    let cfg = match config {
        Some(c) => c,
        // `.with_context` (not a formatted `anyhow!`) keeps the `figment::Error` in the
        // chain — `StartError::classify` keys on it.
        None => Config::load(&config_path)
            .with_context(|| format!("config error in {}", config_path.display()))?,
    };

    // 1a. Audit retention (#88): with `[limits].audit_retain_months = N > 0`, delete monthly
    //     audit files older than the last N months. Boot-time only (a long-running daemon prunes
    //     on next start; the `audit_prune` verb covers live needs), BEFORE serving so a caller
    //     never reads a month the config says is out of window. Best-effort like the writer: a
    //     prune failure is a warning, never a failed boot — refusing to start over an
    //     undeletable old log file would be worse than keeping it. Default 0 deletes nothing.
    if let Some(cutoff) =
        crate::audit::retention_cutoff(&crate::audit::now_ts()[..7], cfg.limits.audit_retain_months)
    {
        let dir = paths.audit_dir.clone();
        match blocking("join audit retention prune", move || {
            crate::audit::prune_before(&dir, &cutoff)
        })
        .await
        {
            Ok(Ok(deleted)) if !deleted.is_empty() => {
                tracing::info!(?deleted, "audit retention pruned old months");
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::warn!(%e, "audit retention prune failed"),
            Err(e) => tracing::warn!(%e, "audit retention prune failed"),
        }
    };
    let key_path = match cfg.identity.device_key.clone() {
        Some(p) => p,
        None => paths.device_key_path.clone(),
    };
    let (key, _created) = DeviceKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("device key error at {}: {e}", key_path.display()))?;

    // 2. The single Iroh endpoint, seeded from the device key. Roster mode (an org root
    //    pinned in config) additionally advertises the gossip + blob ALPNs on this same endpoint;
    //    a pure-pairing daemon advertises exactly mcp/1 + pair/1 (no roster ALPNs to probe).
    let secret = iroh::SecretKey::from_bytes(&key.secret_bytes());
    let roster_mode = cfg.identity.org_root_pk.is_some();
    // #89: resolve the presence policy BEFORE binding a socket, so `presence_mode = "of"` is a
    // startup error rather than a node that silently pongs to everyone while its operator believes
    // they are hidden. A privacy knob that fails open is worse than no knob.
    let presence = presence_mode(&cfg.network)?;
    let endpoint = build_endpoint(secret, &cfg.network, roster_mode).await?;
    let our_id = endpoint.id();

    // 3. The peer allowlist store + gate. redb open + reads are blocking; open on a blocking
    //    thread so a slow trust-file fsync never stalls a runtime worker.
    let db_path = paths.state_db_path.clone();
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create data dir {}", parent.display()))?;
    }
    let store = blocking("join peer-store open", move || PeerStore::open(&db_path)).await??;
    let store = Arc::new(store);
    // The composed trust gate: pairing ∪ roster with explicit precedence
    // (revocation → roster → pairing). `pairs` is the `AllowlistGate` over the redb peer
    // allowlist; `roster` is the hot-swappable roster gate, empty until a signed roster is
    // installed/loaded. With NO roster installed, `ComposedGate` falls through to `pairs` for
    // everything — every pairing flow preserved.
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    // The degraded-expiry grace window (default 72h; total parse — see
    // `RosterCfg::grace_seconds`, which also carries the degraded-split design note).
    let grace = cfg.roster.grace_seconds();
    // The roster-daemon gate: expiry grace AND the freshness bound. A stale roster
    // (not re-confirmed within `max_staleness`) degrades on the SAME `RosterState` machine as expiry.
    let roster = Arc::new(RosterGate::with_freshness(
        grace,
        cfg.roster.max_staleness_seconds(),
    ));
    // Load the pinned roster at startup, if an org root is pinned in config. FAIL-CLOSED: any load
    // error (a corrupt/tampered roster.json, a signature mismatch) leaves the roster EMPTY — roster
    // peers are refused (the gate resolves nothing), while pairing is entirely unaffected. An
    // invalid pinned pk disables roster mode with a warning (pairing still works).
    if let Some(pk_str) = cfg.identity.org_root_pk.clone() {
        match crate::roster::parse_org_root_pk(&pk_str) {
            Ok(pk) => {
                let rstore = RosterStore::new(paths.roster_path.clone());
                match blocking("join roster load", move || rstore.load(&pk)).await {
                    Ok(Ok(Some(view))) => {
                        roster.install(view);
                        tracing::info!("installed roster loaded");
                        // If the loaded roster is already past expiry but within grace, warn on load
                        // — an expired-but-valid installed roster loads into degraded mode.
                        warn_if_degraded_grace(&roster);
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) | Err(e) => {
                        tracing::warn!(%e, "installed roster failed to load; refusing roster peers")
                    }
                }
            }
            Err(e) => tracing::warn!(%e, "pinned org_root_pk is invalid; roster mode disabled"),
        }
    }
    // Freshness bootstrap: arm the gate's `last_confirmed` from the sidecar.
    //  - present sidecar  → restore the persisted confirmation instant.
    //  - ABSENT sidecar + a roster IS installed → the ONE-TIME UPGRADE GRACE: a node upgrading
    //    from a build without freshness tracking has no sidecar yet; treat `now` as the
    //    confirmation instant and persist it, so it does NOT instantly degrade to stale on its
    //    first boot with this build (it re-confirms on its next poll).
    //  - absent sidecar + NO roster → leave `None` (a fresh node arms freshness on its first confirm).
    // Best-effort persist: a write failure leaves the in-RAM arm intact.
    {
        let fpath = roster_confirmed_path(&config_path);
        let fstore = FreshnessStore::new(fpath.clone());
        match blocking("join roster freshness load", move || fstore.load()).await {
            Ok(Ok(Some(lc))) => roster.set_last_confirmed(lc),
            Ok(Ok(None)) if roster.view().is_some() => {
                let now = epoch_now_i64();
                roster.set_last_confirmed(now);
                let fstore = FreshnessStore::new(fpath);
                match blocking("join roster freshness upgrade-grace persist", move || {
                    fstore.store(now)
                })
                .await
                {
                    Ok(Ok(())) => tracing::info!("roster freshness upgrade grace applied"),
                    Ok(Err(e)) | Err(e) => {
                        tracing::warn!(%e, "persist roster freshness upgrade grace")
                    }
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(%e, "read roster freshness sidecar; treating as unconfirmed")
            }
        }
    }
    let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

    // 4. Rate/concurrency limiters, built once from config and shared across every
    //    backend + the accept loop. Installed on the mesh AFTER it is built (below).
    let limiters = crate::limits::MeshLimiters::from_config(&cfg.limits);
    // 4b. Service registry from config. `run_mesh_connection` shares one registry across every
    //    connection, so wrap it once in `Arc` here. (The `status` service/peer lists are read
    //    LIVE from config + store per call — nothing to snapshot here.)
    let services = Arc::new(build_services_audited(&cfg, &audit, &limiters));

    // 5. Assemble the mesh half, start the daemon's OWN ALPN-dispatch accept loop, and install
    //    its handle for hot-reload. Chicken-egg (the loop needs `mesh`, `mesh.accept_task` needs
    //    the loop's handle): build `mesh` with an empty accept_task, spawn the loop with
    //    `mesh.clone()`, then set the handle. The invite registry starts empty (`invite`
    //    mints into it).
    // #87b: restore outstanding invites rather than starting empty. Without this every restart
    // silently voided every invite while the invite line advertised a 24h TTL — an invite mailed
    // to a colleague was reliably dead within a couple of hours on a node that auto-updates.
    // Expired ones are dropped on load, so the file cannot accumulate.
    let invites = Arc::new(LiveInvites::load(
        paths.invites_path.clone(),
        crate::util::epoch_now_u64(),
    ));
    // The nickname we suggest for ourselves in invites + advertise to peers: config override, else the
    // machine hostname (friendly: peers see `jetson`, not `96246d3f`), else the endpoint fingerprint.
    let self_nickname = cfg
        .identity
        .nickname
        .clone()
        .unwrap_or_else(|| default_self_nickname(&our_id));
    // The live-connection registry: threaded into the accept loop's mesh handler
    // (CHECK-register on accept) so a roster install can sever its live sessions. `roster`
    // (the hot-swappable roster gate) + `gate` (the composed gate over it) were built above.
    let conn_registry = Arc::new(ConnRegistry::new());
    // Roster-mode gossip/blob composition: spawn iroh-gossip +
    // the roster-blob transport on THIS SAME endpoint, and subscribe the roster topic bootstrapping
    // from the installed roster's device endpoints (the swarm forms as peers arrive — an empty
    // bootstrap is fine). The accept loop's gossip/blob arms dispatch to these handles. A pure-pairing
    // daemon spawns NEITHER (`None`) — no gossip at all.
    let (gossip, blobs, roster_topic, presence_topic) =
        compose_roster_transport(&endpoint, &roster, &cfg, roster_mode, &our_id).await;
    let mesh = MeshState::new(
        endpoint,
        gate,
        store,
        invites,
        self_nickname,
        config_path,
        roster,
        conn_registry,
        gossip,
        blobs,
        roster_topic,
        presence_topic,
    );
    // Install the process audit sink on the mesh BEFORE serving, so the reload sites +
    // trust-event hooks can re-thread/read it.
    mesh.set_audit(audit.clone());
    mesh.set_limits(limiters.clone());
    // Seed the live relay posture from the boot `[network]` so the `set_relays` verb (#53) diffs
    // against runtime truth, not the on-disk config (the `.config()` embedder front door may
    // never persist the boot config to disk).
    mesh.set_applied_relays(&cfg.network.relay_mode, &cfg.network.relay_urls);
    // #89: who gets a reachability pong. Parsed BEFORE this point (see the `presence_mode` call in
    // the config-validation block) so an unknown value is a startup error, never a silent fall back
    // to the permissive default — a privacy knob that fails open is worse than no knob.
    mesh.set_presence_mode(presence);
    // Self-sovereign pairing identity: load
    // (or mint) this person's UserKey and precompute this daemon's binding over `our_id`, so the
    // pairing handlers PRESENT it and paired peers store a VERIFIED `user_id`. The key path mirrors
    // roster mode's (`[identity].user_key`, else the default), so a roster `join` and pairing share
    // ONE self-sovereign user key/id (DRY). Best-effort: a key error logs + presents nothing (pairing
    // still works, peers store `user_id: None`) rather than failing the daemon.
    let user_key_path = match cfg.identity.user_key.clone() {
        Some(p) => p,
        None => paths.user_key_path.clone(),
    };
    let self_binding = match mcpmesh_trust::UserKey::load_or_generate(&user_key_path) {
        Ok((user_key, _created)) => {
            let (user_pk, sig) = mcpmesh_trust::binding::present(&user_key, our_id.as_bytes());
            Some(crate::pairing::rendezvous::SelfBinding { user_pk, sig })
        }
        Err(e) => {
            tracing::warn!(
                %e,
                path = %user_key_path.display(),
                "no user key for pairing identity; paired peers will store this daemon without a user_id"
            );
            None
        }
    };
    mesh.set_self_binding(self_binding);
    // Build the gated per-scope app-blob provider in roster mode and install it on the
    // mesh BEFORE the accept loop starts. Uses the SAME trust gate the mesh resolves inbound MCP
    // with, so the request-time scope check keys on the exact authenticated identity. A build
    // failure disables app blobs with a warning (pairing + mesh keep working).
    //
    // Built in BOTH modes (#61). The scope gate is identity-generic — a grant is a flat principal
    // (`eid:` device, `b64u:` user, or a roster group/user name), and the `eid:` arm is exercised
    // against a non-roster gate by `pairing_mode_eid_grant_admits_and_nickname_grant_stays_denied`.
    // Gating construction on an org root key kept content-addressed transfer out of the mode the
    // quickstart teaches, for no authorization reason.
    {
        let scopes_path = paths.blob_scopes_path.clone();
        match blocking("join app-blob scopes load", move || {
            crate::blobs::scope::ScopeStore::open(scopes_path)
        })
        .await
        {
            Ok(Ok(scopes)) => {
                match crate::blobs::provider::AppBlobs::load(
                    paths.blobs_dir.clone(),
                    Arc::new(scopes),
                    mesh.gate.clone(),
                    mesh.endpoint.clone(),
                    audit.clone(),
                    // The limiter built at boot, NOT `mesh.limits()` — that falls back to
                    // `unlimited()` on a OnceCell miss, so a wiring mistake would silently disable
                    // a security control. Fail closed, like everything else here (#84a review).
                    limiters.clone(),
                )
                .await
                {
                    Ok(provider) => {
                        // #83 ask 3: production tickets must carry the home-relay URL, so wait
                        // (bounded) for the relay handshake before minting. Only here — see
                        // `enable_relay_wait`.
                        provider.enable_relay_wait();
                        // #88: record the on-disk store dir alongside the provider, so
                        // `status.storage.blobs_bytes` walks the dir that actually holds bytes.
                        mesh.set_blobs_dir(paths.blobs_dir.clone());
                        mesh.set_app_blobs(provider).await
                    }
                    Err(e) => tracing::warn!(%e, "app-blob provider disabled (build failed)"),
                }
            }
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(%e, "app-blob scopes failed to load; provider disabled")
            }
        }
    }
    // #90: the self-network posture watcher — pushes a StreamFrame::SelfNetwork when this
    // node's own reachability changes (relay connected/lost, home relay moved) and stamps
    // `last_change_epoch` for `status`. Every mode, including relay-disabled (where it simply
    // never observes a relay and never emits): the projection is what `status` reads either way.
    background.push(crate::daemon::spawn_self_net_watch(mesh.clone()));

    let accept_task = spawn_accept_loop(mesh.clone(), services);
    mesh.set_accept_task(accept_task).await;

    // 5b. Roster mode: spawn the distribution converge loop — it pulls `RosterAnnounce`s
    //     off the roster topic and, on a higher serial, fetches + single-validates + installs the new
    //     roster, then re-seeds/re-announces (propagation is operator-offline-safe). Self-guards on a
    //     `None` receiver (pure-pairing daemon), so an unconditional call is a no-op there; the
    //     detached handle runs for the daemon lifetime (the loop ends when the topic stream closes).
    if roster_mode {
        let book = std::sync::Arc::new(crate::roster::transport::RosterAddrBook::register(
            &mesh.endpoint,
            256,
        ));
        let _ = mesh.roster_addr_book.set(book);
        background.push(crate::roster::distribute::spawn_receive_loop(mesh.clone()));
    }

    // 5b'. Roster mode: spawn presence. ADVISORY-ONLY — presence feeds `status` + the
    //      person→device dial ORDERING; it NEVER touches a gate, an authz check, or a sever
    //      decision (absence of a presence entry never blocks a dial). Both loops run against the
    //      narrow presence context the mesh composes (table + topic + roster gate). The TRACK loop
    //      records verified heartbeats (each bound to the roster's authoritative user_id); the
    //      PUBLISH loop beats this node's own device-key-signed heartbeat every ~60s. A pure-pairing
    //      daemon (not roster mode) spawns NEITHER loop. The device SigningKey is the SAME ed25519 key
    //      the endpoint id derives from (`key.secret_bytes()`), so the beat's endpoint_id == our_id and
    //      peers resolve us in their roster. Publish only when this node's own user_id is known (config
    //      `[identity].user_id`, else its roster resolution) — a beat under an unknown user_id would be
    //      self-rejected by every peer's user_id binding, so it is skipped rather than sent as noise.
    if roster_mode {
        background.push(crate::roster::presence::track_loop(mesh.presence_ctx()));
        let self_user_id = cfg.identity.user_id.clone().or_else(|| {
            mesh.roster
                .view()
                .and_then(|v| v.resolve(our_id.as_bytes()).map(|d| d.user_id.clone()))
        });
        match self_user_id {
            Some(user_id) => {
                let device_key = ed25519_dalek::SigningKey::from_bytes(&key.secret_bytes());
                background.push(crate::roster::presence::publish_loop(
                    mesh.presence_ctx(),
                    device_key,
                    user_id,
                ));
            }
            None => tracing::debug!(
                "presence publish skipped: no user_id for this node (track loop still runs)"
            ),
        }
    }

    // Periodic staleness sweep. The freshness bound denies NEW inbound at
    // `resolve`; this cuts EXISTING roster-authorized sessions once the node crosses
    // `last_confirmed + max_staleness + grace`. Roster mode only; never severs pairing-only sessions.
    if roster_mode {
        background.push(spawn_staleness_sweep(mesh.clone()));
    }

    // 5c. Roster mode with a pinned `[roster].url`: spawn the HTTPS fallback poll loop.
    //     It GETs the URL every `poll_interval` AND once at startup, so a joiner gets its FIRST roster
    //     (a joiner cannot gossip before it holds a roster). A newer served roster converges
    //     through the SAME `install_from_file` path (no second validator); an equal serial CONFIRMS
    //     currency (freshness). Guarded on `roster_mode` (an org root pinned) — a stray url with no
    //     anchor has nothing to converge to. The rustls provider is installed (step 0) before this runs.
    if roster_mode && let Some(url) = cfg.roster.url.clone() {
        // Route through the tracked helper (NOT a bare spawn) so the startup handle lands in
        // `mesh.poll_loop` — a later runtime `set_roster_url` then aborts+replaces it rather than
        // stacking a second loop.
        respawn_poll_loop(&mesh, url).await;
    }

    // 6. The control-dispatch state over the mesh half; the caller decides how it is
    //    served — the daemon shell binds a socket, an embedded `Node` opens in-memory pipes.
    let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh));
    Ok(BootedNode { state, background })
}

/// How this daemon's endpoint resolves peer addresses: the n0 defaults
/// (pkarr publish + DNS lookup against n0's servers — what `presets::N0` wires), or
/// self-hosted pkarr relay URLs used for BOTH publish and resolve (`discovery_mode =
/// "custom"` + `discovery_urls`).
#[derive(Debug)]
pub enum DiscoveryPlan {
    N0,
    Custom(Vec<url::Url>),
}

/// The validated `[network]` posture — the SINGLE truth `build_endpoint`
/// binds and `doctor` reports on. `Hermetic` (`relay_mode = "disabled"`) is no relay AND no
/// discovery — the localhost/tests mode.
#[derive(Debug)]
pub enum NetPlan {
    Hermetic,
    Mesh {
        relay: iroh::RelayMode,
        discovery: DiscoveryPlan,
    },
}

/// Validate `[network]` into a [`NetPlan`]. Pure (parses, never binds) so config tests and
/// `doctor` share it. Unknown modes and a `"custom"` without URLs are ERRORS, never a silent
/// fallback to public infrastructure — a metadata-privacy knob that quietly reverts to n0
/// defaults would be worse than none.
/// Who gets a reachability pong on `mcpmesh/ping/1` (#89).
///
/// The ping arm is gated by PAIRING alone, so `service_allow_revoke` never reached it: a peer whose
/// every service was revoked still learned you were online, on demand and forever. The only lever
/// was a full unpair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PresenceMode {
    /// Any paired peer. Today's behaviour, and the default.
    #[default]
    Paired,
    /// Only a caller currently holding at least one service grant — so an embedder's existing
    /// per-peer sharing switch controls presence too, live, with no new verb.
    Granted,
    /// Never pong.
    Off,
}

impl PresenceMode {
    /// The config/wire spelling. One function, so `SelfNetwork.presence_mode` can never disagree
    /// with the value an operator wrote in `config.toml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Paired => "paired",
            Self::Granted => "granted",
            Self::Off => "off",
        }
    }
}

/// Parse `[network].presence_mode`. An unknown value is a STARTUP ERROR, matching
/// `relay_mode`/`discovery_mode`: a privacy knob must never silently fall back to the permissive
/// value. `presence_mode = "of"` failing loudly is the difference between a user who is hidden and
/// a user who believes they are.
pub fn presence_mode(net: &crate::config::NetworkCfg) -> Result<PresenceMode> {
    match net.presence_mode.as_str() {
        "paired" => Ok(PresenceMode::Paired),
        "granted" => Ok(PresenceMode::Granted),
        "off" => Ok(PresenceMode::Off),
        other => anyhow::bail!(
            "[network] unknown presence_mode {other:?} (expected \"paired\" | \"granted\" | \"off\")"
        ),
    }
}

pub fn net_plan(net: &crate::config::NetworkCfg) -> Result<NetPlan> {
    let relay = match net.relay_mode.as_str() {
        // Hermetic: no relay, no discovery (discovery_mode is ignored — doctor warns if set).
        "disabled" => return Ok(NetPlan::Hermetic),
        "default" => iroh::RelayMode::Default,
        "custom" => {
            anyhow::ensure!(
                !net.relay_urls.is_empty(),
                "[network] relay_mode = \"custom\" requires at least one relay_urls entry"
            );
            let urls = net
                .relay_urls
                .iter()
                .map(|u| {
                    u.parse::<iroh::RelayUrl>()
                        .map_err(|e| anyhow::anyhow!("[network] relay_urls entry {u:?}: {e}"))
                })
                .collect::<Result<Vec<_>>>()?;
            iroh::RelayMode::custom(urls)
        }
        other => anyhow::bail!(
            "[network] unknown relay_mode {other:?} (expected \"default\" | \"custom\" | \"disabled\")"
        ),
    };
    let discovery = match net.discovery_mode.as_str() {
        "default" => DiscoveryPlan::N0,
        "custom" => {
            anyhow::ensure!(
                !net.discovery_urls.is_empty(),
                "[network] discovery_mode = \"custom\" requires at least one discovery_urls entry \
                 (a self-hosted pkarr relay, e.g. an iroh-dns-server)"
            );
            let urls = net
                .discovery_urls
                .iter()
                .map(|u| {
                    u.parse::<url::Url>()
                        .map_err(|e| anyhow::anyhow!("[network] discovery_urls entry {u:?}: {e}"))
                })
                .collect::<Result<Vec<_>>>()?;
            DiscoveryPlan::Custom(urls)
        }
        other => anyhow::bail!(
            "[network] unknown discovery_mode {other:?} (expected \"default\" | \"custom\")"
        ),
    };
    Ok(NetPlan::Mesh { relay, discovery })
}

/// Build the Iroh endpoint advertising the mcpmesh/mcp/1 (mesh) + mcpmesh/pair/1 (pairing)
/// ALPNs — the accept loop dispatches each inbound connection by whichever one negotiated. In
/// ROSTER mode (`roster_mode == true`, an org root pinned) it ALSO advertises the gossip + blob
/// ALPNs so the roster/presence distribution + roster-blob transport share this ONE endpoint.
/// A pure-pairing daemon (`roster_mode == false`) advertises EXACTLY mcp/1 + pair/1.
///
/// The `[network]` posture comes from [`net_plan`]:
/// - Hermetic (`relay_mode = "disabled"`): `presets::Minimal` + `RelayMode::Disabled` — a
///   localhost-only endpoint, no relay, no discovery (hermetic tests).
/// - n0-default discovery: `presets::N0` (pkarr publish + DNS lookup + n0 relays), with the
///   relay map overridden to the operator's `relay_urls` when `relay_mode = "custom"`.
/// - Custom discovery (`discovery_urls`): `presets::Minimal` plus a `PkarrPublisher` AND a
///   `PkarrResolver` per URL — publish and resolve BOTH go to the self-hosted pkarr relay(s),
///   never to n0 (a half-private discovery setup would defeat the metadata-privacy point).
///
/// Verified against iroh 1.0.1: `Builder::alpns(Vec<Vec<u8>>)` advertises MULTIPLE
/// ALPNs on one endpoint; `Endpoint::builder(preset)`, `.secret_key()`, `.relay_mode()`,
/// `.address_lookup()`, `.bind()` per the pinned crate; `RelayMode::custom(urls)` builds the
/// custom `RelayMap`; all preset paths yield the same `Builder` type.
pub(crate) async fn build_endpoint(
    secret: iroh::SecretKey,
    net: &crate::config::NetworkCfg,
    roster_mode: bool,
) -> Result<iroh::Endpoint> {
    let builder = match net_plan(net)? {
        NetPlan::Hermetic => iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled),
        NetPlan::Mesh {
            relay,
            discovery: DiscoveryPlan::N0,
        } => iroh::Endpoint::builder(iroh::endpoint::presets::N0).relay_mode(relay),
        NetPlan::Mesh {
            relay,
            discovery: DiscoveryPlan::Custom(urls),
        } => {
            let mut b = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal).relay_mode(relay);
            for u in urls {
                b = b
                    .address_lookup(iroh::address_lookup::PkarrPublisher::builder(u.clone()))
                    .address_lookup(iroh::address_lookup::PkarrResolver::builder(u));
            }
            b
        }
    };
    let alpns = alpns_for(roster_mode);
    let builder = apply_relay_only(builder, net);
    let builder = apply_transport_config(builder, net)?;
    builder
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context("bind iroh endpoint")
}

/// iroh 1.0.3's effective QUIC idle timeout, in seconds — the value we validate a bare
/// `keep_alive_secs` against when no `idle_timeout_secs` is set (#56).
///
/// Pinned by `iroh_transport_defaults_are_what_the_docs_claim`, which is the drift detection the
/// issue actually asked for: an iroh bump that moves this fails a test instead of quietly making a
/// documented number wrong.
pub(crate) const IROH_DEFAULT_IDLE_SECS: u64 = 30;

/// iroh's hard ceiling on the per-path keepalive (`HEARTBEAT_INTERVAL`), in seconds.
///
/// Not a default — a **cap**. `default_path_keep_alive_interval` drops any larger value with a
/// `warn!` and no error, so above this the knob cannot lower ping frequency at all. Pinned by
/// `iroh_transport_defaults_are_what_the_docs_claim`; if a bump raises or removes the cap, the
/// metered-link case #56 was filed for becomes possible and this refusal should be revisited.
pub(crate) const IROH_MAX_PATH_KEEP_ALIVE_SECS: u64 = 5;

/// Build the QUIC transport config `[network]` asks for (#56), or `None` to leave iroh's alone.
///
/// Returns the CONFIG rather than a mutated builder so a test can assert what was actually set —
/// `QuicTransportConfig` has a useful `Debug`. A test that only checks "did bind succeed" cannot
/// see a knob that was never applied, and did not: two mutations escaped that way (#56 gate).
fn build_transport_config(
    net: &crate::config::NetworkCfg,
) -> Result<Option<iroh::endpoint::QuicTransportConfig>> {
    let (idle, keep) = (net.idle_timeout_secs, net.keep_alive_secs);
    if idle.is_none() && keep.is_none() {
        return Ok(None);
    }

    if let Some(k) = keep {
        // iroh CAPS the per-path keepalive at 5s: `default_path_keep_alive_interval` discards any
        // larger value with only a `warn!` and returns the builder unchanged (iroh 1.0.3
        // `endpoint/quic.rs`). So a keepalive above 5s cannot reduce ping frequency — every path
        // keeps pinging at 5s and the operator's metered-link saving never happens. Refuse it
        // rather than accept a knob that silently does the opposite of what it says (#56 gate).
        // `0` is NOT "disable keepalives" — it is a zero-length timer. noq-proto arms it already
        // expired, so every authed packet emits a PING whose ACK re-arms it expired: a self-
        // sustaining PING/ACK loop at RTT cadence on every path. An operator reading `0` the way
        // `idle_timeout_secs = 0` reads three lines up in the same table would saturate the link
        // they meant to quiet. iroh's builder takes a `Duration`, so there is no value that
        // disables keepalives at all — say that rather than accept the one that inverts it.
        anyhow::ensure!(
            k > 0,
            "[network] keep_alive_secs = 0 is not \"disable keepalives\" — it is a zero-length \
             timer that makes every packet emit a PING, saturating the link. There is no way to \
             disable the transport keepalive; omit the key to get iroh's default of \
             {IROH_MAX_PATH_KEEP_ALIVE_SECS}s"
        );
        anyhow::ensure!(
            k <= IROH_MAX_PATH_KEEP_ALIVE_SECS,
            "[network] keep_alive_secs ({k}) is above iroh's per-path keepalive cap of \
             {IROH_MAX_PATH_KEEP_ALIVE_SECS}s, which it silently ignores — every path would keep \
             pinging every {IROH_MAX_PATH_KEEP_ALIVE_SECS}s regardless, so this cannot reduce \
             keepalive traffic. Lower it to make pings MORE frequent on a lossy link; there is no \
             supported way to make them less frequent"
        );
        // Validate against the EFFECTIVE idle timeout, not just an explicitly configured one.
        // Unreachable for a BARE keepalive while the cap above (5s) sits under iroh's default idle
        // timeout (30s) — kept because it is what bites if a bump moves either number, and
        // `iroh_transport_defaults_are_what_the_docs_claim` is what tells us one moved.
        let effective = idle.unwrap_or(IROH_DEFAULT_IDLE_SECS);
        anyhow::ensure!(
            effective == 0 || k < effective,
            "[network] keep_alive_secs ({k}) must be less than the idle timeout ({effective}s{}): \
             a keepalive arriving after the peer's idle timer has fired severs sessions on a clock \
             rather than keeping them open",
            // Always "" in practice: the cap above admits only <= 5s, which is under iroh's 30s
            // default, so a BARE keepalive cannot reach this check. Kept with the `unwrap_or`
            // because it is what bites if a bump moves either number.
            if idle.is_some() {
                ""
            } else {
                ", iroh's default — set idle_timeout_secs to raise it"
            }
        );
    }

    let mut cfg = iroh::endpoint::QuicTransportConfig::builder();
    if let Some(i) = idle {
        // `0` is QUIC's "no idle timeout" — a real (if sharp) choice, so it maps to `None` AND is
        // still set, which is what distinguishes it from "not configured".
        let timeout = if i == 0 {
            None
        } else {
            Some(
                iroh::endpoint::IdleTimeout::try_from(Duration::from_secs(i)).map_err(|e| {
                    anyhow::anyhow!(
                        "[network] idle_timeout_secs {i} is out of the range QUIC can encode: {e}"
                    )
                })?,
            )
        };
        cfg = cfg.max_idle_timeout(timeout);
    }
    if let Some(k) = keep {
        // BOTH keepalives, deliberately. iroh sets a connection-level one AND a per-path one, and
        // every path (including PathId::ZERO) pings on the path value. Setting only the connection
        // one leaves a 5s path ping running, so the knob could make pings MORE frequent but never
        // fewer — an operator raising it to save battery on a metered link would get nothing and
        // have no way to tell (#56 gate).
        let d = Duration::from_secs(k);
        cfg = cfg
            .keep_alive_interval(d)
            .default_path_keep_alive_interval(d);
    }
    Ok(Some(cfg.build()))
}

/// Pre-flight the `[network]` transport knobs WITHOUT binding an endpoint (#56).
///
/// `doctor` exists so an operator learns about a fatal config error before a restart, not after.
/// These knobs are validated inside `build_endpoint`, which doctor must never call — it is
/// read-only and binding a socket is not. This is the same validation with the endpoint left out,
/// so the two cannot drift: both go through `build_transport_config`.
pub fn validate_transport_config(net: &crate::config::NetworkCfg) -> Result<()> {
    // #89: presence_mode rides the same pre-flight — doctor must not bless a config whose privacy
    // knob the daemon will reject, and a typo there is exactly the case where the operator most
    // needs to hear about it before the restart rather than after.
    presence_mode(net)?;
    build_transport_config(net).map(|_| ())
}

/// Apply `[network].idle_timeout_secs` / `keep_alive_secs` (#56), if set.
///
/// Untouched when both are absent — the endpoint gets iroh's defaults verbatim, so a config that
/// says nothing about this behaves exactly as it did before the knobs existed. The builder starts
/// from iroh's OVERRIDDEN defaults, so setting one knob does not silently reset the others.
fn apply_transport_config(
    builder: iroh::endpoint::Builder,
    net: &crate::config::NetworkCfg,
) -> Result<iroh::endpoint::Builder> {
    Ok(match build_transport_config(net)? {
        None => builder,
        Some(cfg) => builder.transport_config(cfg),
    })
}

/// TEST-ONLY (#116): an iroh `PathSelector` that carries application data over the RELAY whenever a
/// relay path is open, even if a direct path exists.
///
/// Why this is behind `unstable-relay-only`: `Endpoint::builder().path_selector` is gated behind
/// iroh's `unstable-custom-transports` and documented as "not covered by semantic versioning
/// guarantees and may change in any release without a major version bump". mcpmesh exact-pins iroh
/// to control exactly that, so a production build must never compile against it.
///
/// **It does not stop hole-punching.** A selector chooses among the paths iroh has already opened;
/// preventing direct paths from forming is socket-level behaviour it cannot reach. A direct path
/// may still exist — it simply never carries data. `status` reports `relay` regardless, because #64
/// derives `PeerPath` from `Path::is_selected()`, so the observable agrees with reality.
///
/// Returning `none()` when no relay path is open leaves iroh's current selection alone rather than
/// inventing one — the trait documents an empty selection as "keep the current one".
#[cfg(feature = "unstable-relay-only")]
#[derive(Debug)]
pub(crate) struct RelayOnlySelector;

#[cfg(feature = "unstable-relay-only")]
impl iroh::endpoint::transports::PathSelector for RelayOnlySelector {
    fn select(
        &self,
        ctx: &iroh::endpoint::transports::PathSelectionContext<'_>,
    ) -> iroh::endpoint::transports::PathSelection {
        let mut selection = iroh::endpoint::transports::PathSelection::none();
        if let Some(p) = ctx.paths().find(|p| {
            matches!(
                p.network_path().remote(),
                iroh::endpoint::transports::Addr::Relay(..)
            )
        }) {
            selection.set(&p);
        }
        selection
    }
}

/// Install the relay-only path selector when the config asks for it AND the build supports it
/// (#116).
///
/// The two arms are the whole point of the feature gate: with it OFF, `relay_only = true` still
/// PARSES (so a config file is portable between a test build and a production one) but is ignored
/// — loudly. A startup error would brick a node over a testing switch; a SILENT ignore would let
/// someone believe they tested the relay when they did not, which is the exact failure #116
/// reports.
#[cfg(feature = "unstable-relay-only")]
fn apply_relay_only(
    builder: iroh::endpoint::Builder,
    net: &crate::config::NetworkCfg,
) -> iroh::endpoint::Builder {
    if net.relay_only {
        tracing::warn!(
            "[network] relay_only = true — TESTING POSTURE: no direct addresses are published or \
             resolved, so peers can only reach this node through the relay. Not for production."
        );
        // BOTH halves are needed, and the address filter is the one that actually works.
        //
        // `path_selector` alone did NOT: a selector chooses among paths iroh has ALREADY opened,
        // and when hole-punching succeeds there is simply no relay path left to choose. Measured:
        // the connection had one path, direct, never selected.
        //
        // `AddrFilter::relay_only()` works a layer earlier — it strips IP addresses before they are
        // published or resolved, so a direct path never forms and the relay path is all there is.
        return builder
            .addr_filter(iroh::address_lookup::AddrFilter::relay_only())
            .path_selector(std::sync::Arc::new(RelayOnlySelector));
    }
    builder
}

#[cfg(not(feature = "unstable-relay-only"))]
fn apply_relay_only(
    builder: iroh::endpoint::Builder,
    net: &crate::config::NetworkCfg,
) -> iroh::endpoint::Builder {
    if net.relay_only {
        tracing::warn!(
            "[network] relay_only = true is IGNORED — this binary was built without the \
             `unstable-relay-only` cargo feature. Traffic will take whatever path iroh selects, \
             which on a LAN with IPv6 is usually DIRECT. Rebuild with the feature, or do not rely \
             on this test having exercised the relay."
        );
    }
    builder
}

/// The ALPNs a daemon advertises, by trust mode (#61).
///
/// Every daemon advertises mcp/1 + pair/1 + ping/1 (the trust-gated reachability probe) AND
/// `mcpmesh/blob/1`, the gated app-blob provider.
///
/// **The app-blob ALPN is deliberately NOT roster-gated.** Its authorization is per-scope grants
/// over the flat principal namespace, which an `eid:` device principal satisfies exactly as a roster
/// group name does; the accept arm resolves through `Arc<dyn TrustGate>`, so a pairing
/// `AllowlistGate` gates it identically. Advertising it leaks nothing to a stranger — the arm
/// refuses an unresolved peer with a 401 before any request, then rate-limits per endpoint.
/// Gating it on an org root key kept content-addressed transfer out of the mode the quickstart
/// teaches, for no authorization reason.
///
/// `GOSSIP_ALPN` and the roster `BLOB_ALPN` stay roster-only: both key on `org_id`, which a
/// pairing-mode node does not have.
pub(crate) fn alpns_for(roster_mode: bool) -> Vec<Vec<u8>> {
    let mut alpns = vec![
        ALPN_MCP.to_vec(),
        ALPN_PAIR.to_vec(),
        ALPN_PING.to_vec(),
        crate::blobs::APP_BLOB_ALPN.to_vec(),
    ];
    if roster_mode {
        alpns.push(crate::roster::transport::GOSSIP_ALPN.to_vec());
        alpns.push(crate::roster::transport::BLOB_ALPN.to_vec());
    }
    alpns
}

/// Compose the roster-mode gossip/blob transport on the daemon's ONE endpoint.
/// In roster mode, spawns iroh-gossip + the roster-blob transport and
/// subscribes the roster topic (derived from the org_id — config's pinned value, else the loaded
/// roster view's), bootstrapping from the installed roster's OTHER device endpoints (the swarm forms
/// as peers arrive — an empty bootstrap is fine, [`subscribe`] does not block). Returns
/// `(None, None, None)` for a pure-pairing daemon (no gossip spawned), or —
/// fail-safe — when no org_id is resolvable / the subscribe fails (pairing + mesh keep working;
/// distribution is simply disabled with a warning).
///
/// [`subscribe`]: crate::roster::transport::subscribe
async fn compose_roster_transport(
    endpoint: &iroh::Endpoint,
    roster: &Arc<RosterGate>,
    cfg: &Config,
    roster_mode: bool,
    our_id: &iroh::EndpointId,
) -> (
    Option<iroh_gossip::net::Gossip>,
    Option<crate::roster::transport::RosterBlobs>,
    Option<crate::roster::transport::RosterGossip>,
    Option<crate::roster::transport::RosterGossip>,
) {
    use crate::roster::transport;
    if !roster_mode {
        return (None, None, None, None);
    }
    // The org_id anchors the topic derivation: config's pinned org_id, else the loaded roster view's.
    let Some(org_id) = cfg
        .identity
        .org_id
        .clone()
        .or_else(|| roster.view().map(|v| v.org_id().to_string()))
    else {
        tracing::warn!("roster mode but no org_id known; gossip distribution disabled");
        return (None, None, None, None);
    };
    let gossip = transport::spawn_gossip(endpoint);
    let blobs = transport::RosterBlobs::new(endpoint);
    // Bootstrap from the installed roster's device endpoints (excluding ourselves). BOTH the roster
    // and presence topics bootstrap from the SAME peer set — the swarm forms as peers
    // arrive, so an empty bootstrap is fine (subscribe does not block on a neighbor).
    let bootstrap: Vec<iroh::EndpointId> = roster
        .view()
        .map(|v| {
            v.device_endpoints()
                .filter(|d| *d != our_id.as_bytes())
                .filter_map(|d| iroh::EndpointId::from_bytes(d).ok())
                .collect()
        })
        .unwrap_or_default();
    let roster_topic = match transport::subscribe(
        &gossip,
        transport::roster_topic_bytes(&org_id),
        bootstrap.clone(),
    )
    .await
    {
        Ok(rg) => Some(rg),
        Err(e) => {
            tracing::warn!(%e, "roster-topic subscribe failed; distribution disabled");
            None
        }
    };
    // The presence topic — reuse `transport::presence_topic_bytes`; same org_id +
    // bootstrap. A subscribe failure disables presence ONLY (roster distribution is independent).
    let presence_topic =
        match transport::subscribe(&gossip, transport::presence_topic_bytes(&org_id), bootstrap)
            .await
        {
            Ok(rg) => Some(rg),
            Err(e) => {
                tracing::warn!(%e, "presence-topic subscribe failed; presence disabled");
                None
            }
        };
    (Some(gossip), Some(blobs), roster_topic, presence_topic)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #116: `relay_only = true` PARSES on a build without the feature, and does not error.
    ///
    /// A config file must stay portable between a test build and a production one. Making the
    /// field feature-gated would turn a shared config into a parse error on the wrong binary; a
    /// startup error would brick a node over a testing switch. The ignore is loud (a `warn!` in
    /// `apply_relay_only`) — a SILENT ignore is the failure #116 reports, where you believe you
    /// tested the relay and did not.
    #[test]
    fn relay_only_parses_regardless_of_the_feature() {
        let cfg: crate::config::NetworkCfg =
            toml::from_str("relay_only = true\n").expect("the field parses on ANY build");
        assert!(cfg.relay_only);
        // And the default posture is off, so an ordinary config is unaffected.
        let plain: crate::config::NetworkCfg = toml::from_str("").unwrap();
        assert!(!plain.relay_only, "default must be off");
    }

    // #116: `select()` itself cannot be UNIT-tested — iroh's `PathSelectionContext` has no public
    // constructor (`for_test` is `pub(crate)`), so there is no way to hand the selector a candidate
    // set from outside the crate. But the property that matters is end-to-end, and THAT is
    // testable: `iroh::test_utils::run_relay_server()` gives a hermetic harness with a real relay.
    //
    // An earlier version of this comment claimed a hermetic harness could not cover it "because
    // relays are disabled there". That was wrong — `cli/tests/peer_path.rs` had been using
    // `run_relay_server()` since #64. The test below is what that claim should have been.

    /// #116: with the relay-only selector installed, application data takes the RELAY even though
    /// a direct path is available and iroh would otherwise select it.
    ///
    /// Both endpoints are on loopback with a real in-process relay, so a direct path IS reachable
    /// and hole-punching succeeds — `peer_path.rs` asserts exactly that for the default selector.
    /// Here the selected path must be the relay regardless, which is the whole feature.
    /// **THIS TEST CURRENTLY FAILS, AND THAT IS THE POINT.** It documents that `relay_only` does
    /// NOT deliver what it claims, measured rather than argued.
    ///
    /// Observed on loopback with a real in-process relay: the client's connection has exactly ONE
    /// path — direct IP, never `is_selected()` — at every sample from the first. **No relay path
    /// is ever present**, so `RelayOnlySelector` has no relay candidate, returns
    /// `PathSelection::none()`, and iroh keeps whatever it was already doing.
    ///
    /// So a `PathSelector` cannot implement relay-only: it chooses among paths iroh has ALREADY
    /// opened, and when a direct path wins there is no relay path open to choose. iroh's own
    /// `RelayOnly` works at the socket layer (it also suppresses hole-punching) and is not
    /// reachable through the public `path_selector` API.
    ///
    /// `#[ignore]` so it does not fail the suite while the feature is known-broken; run it with
    /// `--ignored` to re-measure. Un-ignore when the mechanism is fixed — do not delete it.
    #[cfg(feature = "unstable-relay-only")]
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_only_keeps_data_on_the_relay_while_a_direct_path_exists() {
        use std::time::Duration;
        tokio::time::timeout(Duration::from_secs(90), async {
            let (relay_map, _relay_url, _guard) = iroh::test_utils::run_relay_server()
                .await
                .expect("in-process relay");

            // The SERVER accepts; only the client forces relay-only, so this proves the selector
            // and not merely "both ends refused to hole-punch".
            let server = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Custom(relay_map.clone()))
                .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
                .alpns(vec![b"mcpmesh/relayonly/test".to_vec()])
                .bind()
                .await
                .expect("bind server");
            let server_addr = server.addr();
            tokio::spawn(async move {
                while let Some(incoming) = server.accept().await {
                    if let Ok(conn) = incoming.await
                        && let Ok((mut send, _recv)) = conn.accept_bi().await
                    {
                        let _ = send.write_all(b"ok").await;
                        let _ = send.finish();
                    }
                }
            });

            let client = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Custom(relay_map))
                .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
                .addr_filter(iroh::address_lookup::AddrFilter::relay_only())
                .path_selector(std::sync::Arc::new(super::RelayOnlySelector))
                .bind()
                .await
                .expect("bind client");

            // Dial with a RELAY-ONLY address: strip the server's direct addrs, as an address
            // filter would if the address had arrived through lookup rather than by hand.
            let relay_only_addr = iroh::EndpointAddr::from_parts(
                server_addr.id,
                server_addr
                    .addrs
                    .iter()
                    .filter(|a| matches!(a, iroh::TransportAddr::Relay(_)))
                    .cloned(),
            );
            let conn = client
                .connect(relay_only_addr, b"mcpmesh/relayonly/test")
                .await
                .expect("connect over the relay");
            let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
            send.write_all(b"hi").await.unwrap();
            send.finish().unwrap();
            let _ = recv.read_to_end(64).await;

            // Give hole-punching every chance to succeed and be selected. The default selector
            // WOULD switch to direct here — that is what `peer_path.rs` asserts — so if we still
            // read a relay path as selected, the selector is doing the work.
            let mut direct_available = false;
            let mut selected_relay = false;
            for _ in 0..40 {
                for p in &conn.paths() {
                    if p.is_ip() {
                        direct_available = true;
                    }
                    if p.is_relay() && p.is_selected() {
                        selected_relay = true;
                    }
                }
                if direct_available && selected_relay {
                    break;
                }
            }

            assert!(
                direct_available,
                "SETUP: loopback must offer a direct path, or this proves nothing — the selector \
                 would trivially pick the only path there is"
            );
            assert!(
                selected_relay,
                "relay_only must keep DATA on the relay while a direct path is available; the \
                 default selector switches to direct here (peer_path.rs asserts that)"
            );
        })
        .await
        .expect("relay-only e2e timed out");
    }

    /// #105: a BOOTED daemon must have the relay-ready ticket wait ON.
    ///
    /// The wait is opt-in and `boot_node` is the ONLY caller of `enable_relay_wait`, so deleting
    /// that one line silently reverts #83 ask 3 — and the symptom is invisible on any developer
    /// machine: it appears only across a real NAT, shortly after boot, and the SENDER sees nothing
    /// wrong because the file looks fine to them. Nothing else in the suite touches the production
    /// path, since every other fixture builds `AppBlobs` by hand (where the flag defaults off, on
    /// purpose — a relay-disabled endpoint would otherwise pay a guaranteed 3s per mint).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_booted_daemon_waits_for_the_relay_before_minting_tickets() {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::NodePaths::under_root(dir.path());
        std::fs::create_dir_all(paths.config_path.parent().unwrap()).unwrap();
        // Relay-disabled so the test never reaches the network; the FLAG is what is under test.
        std::fs::write(&paths.config_path, "[network]\nrelay_mode = \"disabled\"\n").unwrap();

        let booted = super::boot_node(paths, None)
            .await
            .expect("the node boots in pairing mode");
        let provider = booted
            .state
            .mesh_required()
            .expect("mesh is up")
            .app_blobs()
            .await
            .expect("the app-blob provider must build in pairing mode (#61) — if THIS fails it is a provider-build regression, not a relay-wait one");

        assert!(
            provider.relay_wait_enabled(),
            "boot must enable the relay-ready wait — without it a ticket minted before the relay \
             handshake carries direct addresses only: LAN-dialable and NAT-dead, and the sender \
             cannot tell (#83 ask 3)"
        );

        // Real teardown — `booted.background` is EMPTY in pairing mode, so aborting it cleans up
        // NOTHING: the accept loop, the app-blob gate loop (holding the redb data-dir lock) and
        // the endpoint would all outlive this test for the life of the binary.
        super::shutdown_booted(booted).await;
    }

    /// #89 gate: pin the two BOOT lines, not just the parser.
    ///
    /// `boot_node` is the only production caller of `set_presence_mode`, and the only place the
    /// parse is reached on the daemon path. Both survived the whole suite when deleted: with the
    /// install gone, `presence_mode = "off"` parses, doctor says OK, the daemon boots — and pongs
    /// everybody. Nothing reports the live mode, so the operator cannot notice. That is the
    /// "pin the call site, not the helper" failure exactly.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_booted_daemon_installs_the_configured_presence_mode() {
        let boot_with = async |cfg: &str| {
            let dir = tempfile::tempdir().unwrap();
            let paths = crate::paths::NodePaths::under_root(dir.path());
            std::fs::create_dir_all(paths.config_path.parent().unwrap()).unwrap();
            std::fs::write(&paths.config_path, cfg).unwrap();
            let out = super::boot_node(paths, None).await;
            (dir, out)
        };

        // The configured mode must reach the LIVE mesh, not just parse.
        let (_d, booted) =
            boot_with("[network]\nrelay_mode = \"disabled\"\npresence_mode = \"off\"\n").await;
        let booted = booted.expect("the node boots with presence_mode = off");
        assert_eq!(
            booted
                .state
                .mesh_required()
                .expect("mesh is up")
                .presence_mode(),
            PresenceMode::Off,
            "boot must INSTALL the configured presence_mode — parsing it and dropping it on the \
             floor leaves an operator who asked to be hidden pongging everyone, with nothing to see"
        );
        // …and the READ-BACK must report the live mesh, through the real projection. Asserting on
        // `project(.., Some("off"))` directly proves only that a parameter survives a struct
        // literal; the call site is what decides whether an operator can confirm their setting
        // (#89 gate — the helper-vs-call-site trap again).
        let reported = crate::daemon::self_net::read_current(
            booted.state.mesh_required().expect("mesh is up"),
            None,
        );
        assert_eq!(
            reported.presence_mode.as_deref(),
            Some("off"),
            "status must report the LIVE presence mode, not a constant and not the on-disk config"
        );
        super::shutdown_booted(booted).await;

        // The default is still today's behaviour.
        let (_d2, booted2) = boot_with("[network]\nrelay_mode = \"disabled\"\n").await;
        let booted2 = booted2.expect("the node boots with no presence_mode set");
        assert_eq!(
            booted2
                .state
                .mesh_required()
                .expect("mesh is up")
                .presence_mode(),
            PresenceMode::Paired,
            "an unset presence_mode must leave today's behaviour untouched"
        );
        super::shutdown_booted(booted2).await;

        // And an unknown mode must REFUSE TO BOOT — not fall back to the permissive default.
        let (_d3, refused) =
            boot_with("[network]\nrelay_mode = \"disabled\"\npresence_mode = \"of\"\n").await;
        let e = format!(
            "{:#}",
            refused
                .err()
                .expect("an unknown presence_mode must refuse to boot, never fall open")
        );
        assert!(
            e.contains("presence_mode") && e.contains("of"),
            "and the startup error must name the key and the typo: {e}"
        );
    }

    /// #61: a PAIRING-mode daemon must advertise the app-blob ALPN. This is the load-bearing half
    /// of the change — the provider is useless if the endpoint never negotiates the protocol, and
    /// the existing blob AC tests build the provider by hand, so they pass either way and cannot
    /// catch a regression here.
    ///
    /// Gossip and the ROSTER blob ALPN must stay roster-only: both key on `org_id`.
    #[test]
    fn pairing_mode_advertises_app_blobs_but_not_gossip_or_roster_blobs() {
        let pairing = super::alpns_for(false);
        let roster = super::alpns_for(true);
        let has = |v: &[Vec<u8>], a: &[u8]| v.iter().any(|x| x.as_slice() == a);

        for alpn in [ALPN_MCP, ALPN_PAIR, ALPN_PING] {
            assert!(
                has(&pairing, alpn),
                "every daemon advertises the base ALPNs"
            );
        }
        assert!(
            has(&pairing, crate::blobs::APP_BLOB_ALPN),
            "a pairing-mode daemon MUST advertise mcpmesh/blob/1 — its scope gate is \
             identity-generic and an eid: grant authorizes it (#61)"
        );

        // The two that legitimately need an org.
        assert!(
            !has(&pairing, crate::roster::transport::GOSSIP_ALPN),
            "gossip keys on org_id — never advertised without a roster"
        );
        assert!(
            !has(&pairing, crate::roster::transport::BLOB_ALPN),
            "the ROSTER blob transport is distinct from app blobs and stays roster-only"
        );
        assert!(has(&roster, crate::roster::transport::GOSSIP_ALPN));
        assert!(has(&roster, crate::roster::transport::BLOB_ALPN));
        assert!(has(&roster, crate::blobs::APP_BLOB_ALPN));
    }
    /// `net_plan` implements EXACTLY the shipped `[network]` surface — the privacy knobs are
    /// real, validated, and never silently fall back to public infrastructure.
    #[test]
    fn net_plan_validates_the_shipped_network_surface() {
        use crate::config::NetworkCfg;
        let cfg = |relay: &str, relay_urls: &[&str], disc: &str, disc_urls: &[&str]| NetworkCfg {
            relay_mode: relay.into(),
            relay_urls: relay_urls.iter().map(|s| s.to_string()).collect(),
            discovery_mode: disc.into(),
            discovery_urls: disc_urls.iter().map(|s| s.to_string()).collect(),
            relay_only: false,
            ..Default::default()
        };

        // Defaults → the n0 mesh.
        assert!(matches!(
            net_plan(&NetworkCfg::default()).unwrap(),
            NetPlan::Mesh {
                relay: iroh::RelayMode::Default,
                discovery: DiscoveryPlan::N0
            }
        ));
        // Disabled → hermetic, regardless of the discovery knobs (they are off).
        assert!(matches!(
            net_plan(&cfg("disabled", &[], "default", &[])).unwrap(),
            NetPlan::Hermetic
        ));

        // Custom relay: the builder receives a RelayMap holding EXACTLY the configured URLs.
        let plan = net_plan(&cfg(
            "custom",
            &["https://relay.acme.com", "https://relay2.acme.com"],
            "default",
            &[],
        ))
        .unwrap();
        match plan {
            NetPlan::Mesh {
                relay: iroh::RelayMode::Custom(map),
                discovery: DiscoveryPlan::N0,
            } => {
                assert_eq!(map.len(), 2, "both relay_urls land in the RelayMap");
            }
            other => panic!("expected a custom relay plan, got {other:?}"),
        }

        // Custom discovery: the pkarr relay URLs parse and are carried verbatim.
        let plan = net_plan(&cfg(
            "default",
            &[],
            "custom",
            &["https://dns.acme.com/pkarr"],
        ))
        .unwrap();
        match plan {
            NetPlan::Mesh {
                relay: iroh::RelayMode::Default,
                discovery: DiscoveryPlan::Custom(urls),
            } => {
                assert_eq!(urls.len(), 1);
                assert_eq!(urls[0].as_str(), "https://dns.acme.com/pkarr");
            }
            other => panic!("expected a custom discovery plan, got {other:?}"),
        }

        // ERRORS, never silent fallbacks: custom without URLs, garbage URLs, unknown modes.
        assert!(net_plan(&cfg("custom", &[], "default", &[])).is_err());
        assert!(net_plan(&cfg("custom", &["not a url"], "default", &[])).is_err());
        assert!(net_plan(&cfg("default", &[], "custom", &[])).is_err());
        assert!(net_plan(&cfg("default", &[], "custom", &["not a url"])).is_err());
        assert!(net_plan(&cfg("relayless", &[], "default", &[])).is_err());
        assert!(
            net_plan(&cfg("default", &[], "local", &[])).is_err(),
            "the never-implemented \"local\" mode is refused honestly"
        );
    }

    /// #56 gate: what actually reaches the endpoint, not just what was decided.
    ///
    /// The first version asserted only that `bind()` succeeded, which cannot see a knob that was
    /// never applied — two mutations escaped that way, including the one that makes
    /// `idle_timeout_secs = 0` mean "no timeout" rather than silently leaving iroh's 30s.
    /// `QuicTransportConfig` has a `Debug`, so assert on it.
    #[test]
    fn the_configured_values_reach_the_transport_config() {
        let net = |idle: Option<u64>, keep: Option<u64>| crate::config::NetworkCfg {
            idle_timeout_secs: idle,
            keep_alive_secs: keep,
            ..Default::default()
        };
        let dbg = |idle, keep| {
            format!(
                "{:?}",
                build_transport_config(&net(idle, keep))
                    .expect("valid config")
                    .expect("configured")
            )
        };

        assert!(
            build_transport_config(&net(None, None)).unwrap().is_none(),
            "an unconfigured node must touch NOTHING — iroh's defaults verbatim"
        );

        // 3, NOT 5: iroh's own default for BOTH keepalives is 5s, so asserting `Some(5s)` passed
        // with the per-path assignment deleted — the fixture value collided with the default it
        // existed to distinguish from. It must also be BELOW 5, which is iroh's per-path cap.
        let d = dbg(Some(60), Some(3));
        assert!(d.contains("60000"), "idle must reach max_idle_timeout: {d}");
        assert!(
            d.contains("keep_alive_interval: Some(3s)"),
            "keepalive must reach keep_alive_interval: {d}"
        );
        assert!(
            d.contains("default_path_keep_alive_interval: Some(3s)"),
            "and the PER-PATH keepalive too — every path pings on that value, so setting only the \
             connection one makes the knob unable to REDUCE ping frequency: {d}"
        );

        // `0` = no timeout must actually be SET, not left as iroh's 30s.
        let z = dbg(Some(0), None);
        assert!(
            z.contains("max_idle_timeout: None"),
            "idle_timeout_secs = 0 must set no-timeout, not leave iroh's 30s: {z}"
        );

        // A keepalive alone must not invent an idle timeout.
        let k = dbg(None, Some(3));
        assert!(
            k.contains("max_idle_timeout: Some(30000)"),
            "a keepalive alone leaves iroh's idle timeout in place: {k}"
        );
    }

    /// #56 ask 1: the documented iroh numbers are PINNED, so a bump that moves them fails here
    /// rather than silently making four documented values wrong.
    ///
    /// This is the drift detection the issue asked for — "treat a change to them as
    /// release-note-worthy" needs something that notices the change.
    #[test]
    fn iroh_transport_defaults_are_what_the_docs_claim() {
        let d = format!("{:?}", iroh::endpoint::QuicTransportConfig::default());
        for (needle, doc) in [
            ("max_idle_timeout: Some(30000)", "30s idle timeout"),
            ("keep_alive_interval: Some(5s)", "5s keepalive"),
            (
                "default_path_keep_alive_interval: Some(5s)",
                "5s path keepalive",
            ),
            (
                "default_path_max_idle_timeout: Some(15s)",
                "15s path idle timeout",
            ),
        ] {
            assert!(
                d.contains(needle),
                "iroh's default changed: docs/config.md and node/src/config.rs claim {doc} for \
                 iroh 1.0.3. Re-measure and update BOTH, and note it in the release. NOTE: the \
                 relay-path idle timeout in that table is NOT pinned here — it never reaches \
                 QuicTransportConfig — so check it by hand too. Got: {d}"
            );
        }
        assert_eq!(
            IROH_DEFAULT_IDLE_SECS, 30,
            "the constant a bare keep_alive_secs is validated against must track the real default"
        );

        // The per-path CAP, not a default: iroh drops a larger value with only a `warn!`. Probe it
        // behaviourally rather than trusting the constant — if a bump raises or removes the cap,
        // the metered-link case #56 was filed for becomes possible and the refusal in
        // `build_transport_config` should be revisited rather than left denying something that now
        // works.
        let over = format!(
            "{:?}",
            iroh::endpoint::QuicTransportConfig::builder()
                .default_path_keep_alive_interval(Duration::from_secs(
                    IROH_MAX_PATH_KEEP_ALIVE_SECS + 1
                ))
                .build()
        );
        assert!(
            over.contains(&format!(
                "default_path_keep_alive_interval: Some({IROH_MAX_PATH_KEEP_ALIVE_SECS}s)"
            )),
            "iroh no longer caps the per-path keepalive at {IROH_MAX_PATH_KEEP_ALIVE_SECS}s. \
             Raising keep_alive_secs may now genuinely reduce ping traffic — revisit the refusal \
             in build_transport_config and the metered-link note in docs/config.md. Got: {over}"
        );
    }

    /// #89: an unknown `presence_mode` must be a STARTUP ERROR, never a silent fall back to the
    /// permissive default. `presence_mode = "of"` quietly meaning "paired" is the difference
    /// between a user who is hidden and a user who believes they are.
    #[test]
    fn an_unknown_presence_mode_is_a_startup_error() {
        let with = |m: &str| crate::config::NetworkCfg {
            presence_mode: m.into(),
            ..Default::default()
        };
        for good in ["paired", "granted", "off"] {
            presence_mode(&with(good)).unwrap_or_else(|e| panic!("{good:?} must parse: {e:#}"));
        }
        assert_eq!(
            presence_mode(&crate::config::NetworkCfg::default()).unwrap(),
            PresenceMode::Paired,
            "the DEFAULT must stay today's behaviour — this knob must not change anyone silently"
        );

        // A typo, and the near-miss that matters most: a value that looks like it disables.
        for bad in ["of", "OFF", "none", "disabled", "true", ""] {
            let e = presence_mode(&with(bad)).unwrap_err().to_string();
            assert!(
                e.contains(bad) && e.contains("presence_mode"),
                "the error must name the key AND the bad value: {e}"
            );
            assert!(
                e.contains("paired") && e.contains("granted") && e.contains("off"),
                "and list every legal value, or the operator guesses again: {e}"
            );
        }
    }

    /// #56: the ordering check. A keepalive at or above the idle timeout means the peer's timer
    /// fires before the next PING arrives — every session dies on a clock, from a config that
    /// reads as reasonable. Boot must refuse it and name both values.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_keepalive_at_or_above_the_idle_timeout_is_refused() {
        let net = |idle: u64, keep: u64| crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            idle_timeout_secs: Some(idle),
            keep_alive_secs: Some(keep),
            ..Default::default()
        };
        let key = || iroh::SecretKey::from_bytes(&[19u8; 32]);

        // Above iroh's per-path CAP the knob cannot do what its name promises: iroh discards the
        // per-path value with a `warn!`, every path keeps pinging at 5s, and the operator's metered
        // link saves nothing. Refuse it instead of accepting a lie (#56 gate).
        let cfg = |idle: Option<u64>, keep: Option<u64>| crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            idle_timeout_secs: idle,
            keep_alive_secs: keep,
            ..Default::default()
        };

        // 64, and an idle timeout of 1200 rather than 3600: "3600" CONTAINS "60", so the previous
        // fixture let an error that named only the idle timeout satisfy "must name their value".
        // Neither number here is a substring of the other.
        let e = build_transport_config(&cfg(Some(1200), Some(64)))
            .expect_err("a keepalive above iroh's per-path cap must be refused, not silently sunk");
        let msg = format!("{e:#}");
        assert!(
            msg.contains("64"),
            "the error must name THEIR value, not just the cap: {msg}"
        );
        assert!(
            msg.contains("cap of 5s"),
            "and the cap itself, as a number they can act on: {msg}"
        );
        assert!(
            msg.contains("cannot reduce"),
            "and say plainly that raising it does NOT reduce keepalive traffic — that is the whole \
             reason someone sets it: {msg}"
        );

        // THE BOUNDARY. 6 is the smallest value iroh actually discards; 5 is the largest it keeps.
        // Without both, an off-by-one in the predicate this whole change exists to add ships green.
        build_transport_config(&cfg(Some(1200), Some(6)))
            .expect_err("6s is above iroh's cap — iroh would drop it, so boot must refuse it");
        build_transport_config(&cfg(Some(1200), Some(IROH_MAX_PATH_KEEP_ALIVE_SECS)))
            .expect("5s is exactly the cap — iroh keeps it, so refusing it would be wrong");

        // `0` is a PING storm, not "disabled" (#56 gate). The error must not merely refuse; it must
        // correct the reading, or the operator retries with `1` and still has no way to turn it off.
        let z = format!(
            "{:#}",
            build_transport_config(&cfg(Some(1200), Some(0)))
                .expect_err("keep_alive_secs = 0 arms a zero-length timer and must be refused")
        );
        assert!(
            z.contains("not \"disable keepalives\"") && z.contains("omit the key"),
            "and must say what 0 really does AND how to actually get the default: {z}"
        );

        // `idle_timeout_secs = 0` (no timeout) with a keepalive: the `effective == 0` escape hatch.
        // Untested before, and deleting it turned a valid config into a boot failure whose error
        // said the keepalive must be less than `0s`.
        build_transport_config(&cfg(Some(0), Some(3)))
            .expect("no idle timeout means no keepalive can outlive it — this must be allowed");

        // The ordering check needs an idle timeout BELOW the cap; a bare keepalive can no longer
        // reach it, since anything the cap admits (<= 5s) is under iroh's 30s default. The check
        // stays because it is what would bite if a bump moved either number, and
        // `iroh_transport_defaults_are_what_the_docs_claim` is what would tell us it had.
        for (idle, keep) in [(5, 5), (4, 5)] {
            let e = build_endpoint(key(), &net(idle, keep), false)
                .await
                .expect_err("a keepalive that cannot arrive in time must be refused at boot");
            let msg = format!("{e:#}");
            assert!(
                msg.contains(&keep.to_string()) && msg.contains(&idle.to_string()),
                "the error must name BOTH values — an operator cannot fix what it does not \
                 identify: {msg}"
            );
        }

        // The valid ordering binds.
        let ep = build_endpoint(key(), &net(30, 5), false)
            .await
            .expect("keepalive below the timeout is the working configuration");
        ep.close().await;
    }

    /// #56: an absent config changes NOTHING — the endpoint gets iroh's defaults verbatim, so a
    /// config that says nothing about this behaves exactly as it did before the knobs existed.
    #[tokio::test(flavor = "multi_thread")]
    async fn absent_transport_config_leaves_iroh_defaults_alone() {
        let net = crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            ..Default::default()
        };
        assert_eq!(net.idle_timeout_secs, None);
        assert_eq!(net.keep_alive_secs, None);
        let ep = build_endpoint(iroh::SecretKey::from_bytes(&[20u8; 32]), &net, false)
            .await
            .expect("an unconfigured node still binds");
        ep.close().await;
    }

    /// #56: `idle_timeout_secs = 0` is QUIC's "no timeout", and is ACCEPTED rather than rejected —
    /// it is a real (if sharp) choice. Pinned so it is not turned into an error by accident.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_zero_idle_timeout_means_no_timeout_and_is_allowed() {
        let net = crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            idle_timeout_secs: Some(0),
            ..Default::default()
        };
        let ep = build_endpoint(iroh::SecretKey::from_bytes(&[21u8; 32]), &net, false)
            .await
            .expect("0 = no idle timeout is a valid QUIC configuration");
        ep.close().await;
    }

    /// A custom-relay endpoint BINDS without any live relay (the RelayMap is config, not a
    /// connection) — proving the builder wiring end to end with no network dependency.
    #[tokio::test(flavor = "multi_thread")]
    async fn build_endpoint_binds_with_a_custom_relay_map() {
        let net = crate::config::NetworkCfg {
            relay_mode: "custom".into(),
            relay_urls: vec!["https://relay.acme.com".into()],
            discovery_mode: "custom".into(),
            discovery_urls: vec!["https://dns.acme.com/pkarr".into()],
            relay_only: false,
            ..Default::default()
        };
        let ep = build_endpoint(iroh::SecretKey::from_bytes(&[9u8; 32]), &net, false)
            .await
            .expect("custom relay+discovery endpoint binds offline");
        ep.close().await;
    }
}
