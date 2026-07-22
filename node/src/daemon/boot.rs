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
use crate::pairing::LiveInvites;
use crate::node::StartError;
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
    let invites = Arc::new(LiveInvites::new());
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
    // mesh BEFORE the accept loop starts. Uses the SAME composed trust gate the mesh resolves inbound
    // MCP with, so the request-time scope check keys on the exact authenticated identity. A build
    // failure disables app blobs with a warning (pairing + mesh keep working); a pure-pairing daemon
    // never builds it.
    if roster_mode {
        let scopes_path = paths.blob_scopes_path.clone();
        match blocking("join app-blob scopes load", move || {
            crate::blobs::scope::ScopeStore::load(scopes_path)
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
                )
                .await
                {
                    Ok(provider) => mesh.set_app_blobs(provider).await,
                    Err(e) => tracing::warn!(%e, "app-blob provider disabled (build failed)"),
                }
            }
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(%e, "app-blob scopes failed to load; provider disabled")
            }
        }
    }
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
    // Roster mode advertises the gossip + blob ALPNs; every daemon (pairing or roster) also
    // advertises ping/1, the trust-gated reachability probe (pairing-mode liveness) — it leaks
    // nothing to a stranger (the accept arm gate-refuses an unresolved peer with no pong).
    let mut alpns = vec![ALPN_MCP.to_vec(), ALPN_PAIR.to_vec(), ALPN_PING.to_vec()];
    if roster_mode {
        alpns.push(crate::roster::transport::GOSSIP_ALPN.to_vec());
        alpns.push(crate::roster::transport::BLOB_ALPN.to_vec());
        alpns.push(crate::blobs::APP_BLOB_ALPN.to_vec());
    }
    builder
        .secret_key(secret)
        .alpns(alpns)
        .bind()
        .await
        .context("bind iroh endpoint")
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

    /// A custom-relay endpoint BINDS without any live relay (the RelayMap is config, not a
    /// connection) — proving the builder wiring end to end with no network dependency.
    #[tokio::test(flavor = "multi_thread")]
    async fn build_endpoint_binds_with_a_custom_relay_map() {
        let net = crate::config::NetworkCfg {
            relay_mode: "custom".into(),
            relay_urls: vec!["https://relay.acme.com".into()],
            discovery_mode: "custom".into(),
            discovery_urls: vec!["https://dns.acme.com/pkarr".into()],
        };
        let ep = build_endpoint(iroh::SecretKey::from_bytes(&[9u8; 32]), &net, false)
            .await
            .expect("custom relay+discovery endpoint binds offline");
        ep.close().await;
    }
}
