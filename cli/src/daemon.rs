//! The long-lived mcpmesh daemon. It owns the single Iroh endpoint (seeded from the device
//! key) and runs two roles simultaneously on one tokio runtime: (1) it runs its
//! OWN accept loop ([`spawn_accept_loop`]) that dispatches each inbound connection by its
//! negotiated ALPN — `mcpmesh/mcp/1` flows through net's gated per-connection handler
//! [`mcpmesh_net::run_mesh_connection`], where `gate` is an
//! [`AllowlistGate`] over the `state.redb` peer allowlist and
//! `services` are backends built from config, while `mcpmesh/pair/1` flows to the pairing
//! rendezvous, GATE-EXEMPT by design and authenticated by the invite secret rather than
//! the trust gate; and (2) it serves the `mcpmesh-local/1` control API on
//! `<runtime_dir>/mcpmesh.sock` (hello + status + service registration + peer add), consumed by
//! the porcelain.
//!
//! The daemon deliberately does not call `mcpmesh_net::serve`: routing by ALPN is the whole
//! point (the gate exemption only applies to the pair ALPN), which the mesh-only `serve`
//! cannot do. `serve`/`ServeHandle` REMAIN in net for its own tests + standalone use; the
//! daemon just composes the same [`mcpmesh_net::run_mesh_connection`] under its own loop.
//!
//! Single-daemon-per-uid: an exclusive non-blocking `flock` on
//! `<runtime_dir>/mcpmesh.lock` is acquired BEFORE any endpoint/store/socket work and held for
//! the process lifetime. This makes `ipc::bind_control_socket`'s stale-socket unlink safe —
//! no LIVE daemon can exist while we hold the lock — and (critically for redb, which takes
//! an exclusive file lock) guarantees exactly one process opens `state.redb`. A redundant
//! daemon loses the lock and exits 0 before touching the device key, store, or endpoint.
mod accept;
mod boot;
pub(crate) mod config_write;
mod dial;
mod handlers;
mod reach;
mod roster_install;
mod status;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ServiceEntry, Services, SessionBackend, TrustGate};
use mcpmesh_trust::paths;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use crate::allowlist::{AllowlistGate, PeerStore};
use crate::audit::AuditSink;
use crate::backends::socket::SocketBackend;
use crate::backends::spawn::SpawnBackend;
use crate::config::{Backend, Config};
use crate::control::DaemonState;
use crate::pairing::LiveInvites;
use crate::roster::freshness::FreshnessStore;
use crate::roster::gate::RosterGate;
use crate::util::blocking;

use roster_install::roster_confirmed_path;

pub use accept::spawn_accept_loop;
pub use boot::run;
pub use dial::{dial_service, pipe_session, race_dial};
pub use handlers::{grant_service_access, remove_peer, rename_peer};
pub use reach::{REACH_TTL_SECS, ReachEntry, probe_peer, reachability_of};
pub use roster_install::{
    install_roster_view_and_sever, should_staleness_sever, staleness_sweep_once,
};

pub(crate) use boot::{NetPlan, net_plan};
pub(crate) use handlers::{
    add_peer, blob_fetch, blob_grant, blob_list, blob_publish, mint_invite, open_session, redeem,
    register_service,
};
pub(crate) use roster_install::{install_roster, org_join, set_roster_url};
pub(crate) use status::{peer_infos, presence_peers, roster_status, service_infos};

/// The lockstep stack version (workspace version) reported in `Hello`/`status`.
pub const STACK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default per-service spawn concurrency cap. Each `run` service gets its own
/// semaphore of this size; a socket service has no per-session cap (deliberate). The runtime cap is
/// now config-driven via [`spawn_concurrency`] (`[limits].max_sessions`); this const remains the
/// DOCUMENTED default, pinned to the config default by `spawn_concurrency_reads_max_sessions_*`.
#[allow(dead_code)] // documented default; asserted (test-only) to equal LimitsCfg::default().max_sessions
const SPAWN_CONCURRENCY: usize = 4;

/// The per-service spawn concurrency. Floors to
/// 1 so a `max_sessions = 0` misconfig bounds to one session rather than refusing every session.
pub(crate) fn spawn_concurrency(cfg: &Config) -> usize {
    (cfg.limits.max_sessions.max(1)) as usize
}

/// The mesh half of the daemon: the endpoint, the trust gate + its backing store, the live
/// invite registry, and the running accept-loop task. Held (behind an `Arc`) inside
/// [`DaemonState`] so the control API's `register_service` / `peer_add` / `pair` methods can
/// hot-reload the registry and populate the store on the SAME open database the gate reads
/// (redb is single-process; routing writes through the daemon is the only correct design).
///
/// It is `Arc<MeshState>` (not owned) because the accept loop and every long-lived roster loop
/// share it. The subsystem modules deliberately never see this struct: the pair rendezvous runs
/// against the narrow [`InviterCtx`] (`inviter_ctx`), the presence loops
/// against [`PresenceCtx`] (`presence_ctx`), and the roster distribution
/// channels against the [`DistributionHost`] seam this struct implements — `MeshState` is the
/// COMPOSER that hands out those contexts, not a parameter the modules take.
///
/// `pub` (fields `pub(crate)`) only so integration tests can assemble one via [`MeshState::new`]
/// + [`MeshState::set_accept_task`] and drive the SAME accept loop the daemon runs.
///
/// [`InviterCtx`]: crate::pairing::rendezvous::InviterCtx
/// [`PresenceCtx`]: crate::roster::presence::PresenceCtx
/// [`DistributionHost`]: crate::roster::distribute::DistributionHost
pub struct MeshState {
    pub(crate) endpoint: iroh::Endpoint,
    pub(crate) gate: Arc<dyn TrustGate>,
    pub(crate) store: Arc<PeerStore>,
    /// The in-RAM registry of outstanding pairing invites. The accept loop's
    /// `mcpmesh/pair/1` branch redeems against it; shared with every spawned pair handler.
    pub(crate) invites: Arc<LiveInvites>,
    /// This device's suggested name for itself, carried in a minted invite.
    /// Resolved once at startup: config `identity.nickname`, else a short base32 fingerprint
    /// of the endpoint id. The redeemer stores it as its local name for us.
    pub(crate) self_nickname: String,
    /// The daemon's own ALPN-dispatch accept loop (see [`spawn_accept_loop`]). Hot-reload
    /// takes it, `.abort()`s it, and installs a fresh loop with the rebuilt registry — a brief
    /// serving blip is acceptable.
    pub(crate) accept_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// The running HTTPS roster-poll loop, if `[roster].url` is set. `None` until a URL is
    /// pinned. Held so [`respawn_poll_loop`] can ABORT+REPLACE it — a runtime `set_roster_url`
    /// (a joiner's first-roster bootstrap, or a URL change) (re)starts polling WITHOUT a daemon
    /// restart, and repeated calls never STACK duplicate loops (the idempotency guard). Initialized
    /// `None` inside [`new`](Self::new) (like `accept_task`), so no call site changes.
    ///
    /// [`respawn_poll_loop`]: roster_install::respawn_poll_loop
    pub(crate) poll_loop: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Serializes the WHOLE config-mutating critical section — `register_service` (config read →
    /// upsert → atomic write → reload → rebuild → accept-loop swap → status refresh) AND the
    /// pairing `grant_service_access` (allow-append → reload → swap). Without it, a concurrent
    /// registration and a pairing-grant each read the same base config and the second write
    /// clobbers the first's change (lost update). The redb `peer_add` path is already serialized
    /// by redb's write lock; this gives the config path an equivalent.
    pub(crate) reload_lock: tokio::sync::Mutex<()>,
    pub(crate) config_path: PathBuf,
    /// The roster-mode gate handle (hot-swapped on install; consulted for the sever set + status).
    /// `RosterGate::empty()` in a pure-pairing daemon — where [`ComposedGate`] then falls through to
    /// pairing for everything, exactly as a pairing-only build behaved. In a roster daemon this is the SAME
    /// `Arc<RosterGate>` [`ComposedGate`] holds, so [`install_roster_view_and_sever`] hot-swaps the
    /// live gate's view with a single `install` (no gate rebuild).
    ///
    /// [`ComposedGate`]: crate::roster::gate::ComposedGate
    pub(crate) roster: Arc<RosterGate>,
    /// Live mesh connections, for revocation-severing on roster install.
    /// [`spawn_accept_loop`] threads it into [`run_mesh_connection`] (CHECK-register on accept); the
    /// install path calls [`ConnRegistry::sever_matching`] against it.
    pub(crate) conn_registry: Arc<ConnRegistry>,
    /// The roster/presence gossip handle + roster-blob transport, spawned on the
    /// daemon's ONE endpoint (). `None` in a pure-pairing daemon (no org root
    /// pinned) — no gossip is spawned, exactly the pairing-only behavior. [`spawn_accept_loop`]'s gossip/blob
    /// arms dispatch inbound connections to these; a `None` arm closes the connection cleanly.
    pub(crate) gossip: Option<iroh_gossip::net::Gossip>,
    pub(crate) blobs: Option<crate::roster::transport::RosterBlobs>,
    /// The roster-topic subscription: the sender announces (cloned per call), the receiver is
    /// moved out ONCE by the converge loop. `None`/empty in a pure-pairing daemon.
    pub(crate) roster_topic: tokio::sync::Mutex<Option<crate::roster::transport::RosterGossip>>,
    /// The presence-topic subscription: the publish loop clones the sender to broadcast
    /// heartbeats; the track loop moves the receiver out ONCE. `None`/empty in a pure-pairing
    /// daemon. Behind an `Arc` because `presence_ctx` shares the SAME
    /// handle with the presence loops (which own the sender/receiver access).
    pub(crate) presence_topic:
        Arc<tokio::sync::Mutex<Option<crate::roster::transport::RosterGossip>>>,
    /// The advisory presence table: the track loop records verified heartbeats here;
    /// `status` + the person→device dial read it for recency ORDERING. ADVISORY-ONLY — no gate,
    /// authz check, or sever decision ever consults it (absence never blocks a dial). Always present
    /// (constructed in [`new`](Self::new)); a pure-pairing daemon simply never records into it.
    pub(crate) presence_table: Arc<crate::roster::presence::PresenceTable>,
    /// The gated per-scope app-blob provider. `None` in a pure-pairing daemon and
    /// until [`set_app_blobs`](Self::set_app_blobs) installs it (roster mode only — grants use roster
    /// vocabulary). Behind a `tokio::sync::Mutex<Option<..>>` set post-construction (like
    /// `accept_task`/`poll_loop`), so `MeshState::new`'s signature is unchanged and no existing caller
    /// breaks. The accept loop's `APP_BLOB_ALPN` arm reads it per-connection.
    pub(crate) app_blobs: tokio::sync::Mutex<Option<Arc<crate::blobs::provider::AppBlobs>>>,
    /// The process-wide audit sink. Set ONCE by [`serve_forever`] before serving via
    /// [`set_audit`](Self::set_audit); read by the reload sites (to re-thread it into rebuilt
    /// backends) and the trust-event hooks. `OnceLock` — set-once, lock-free reads, no async.
    /// Empty (→ `AuditSink::disabled()`) in a control-only test daemon.
    pub(crate) audit: std::sync::OnceLock<AuditSink>,
    /// The process rate/concurrency limiters. Set ONCE by `serve_forever` before
    /// serving (like `audit`); read by the reload sites (rebuilt backends re-thread it) and the
    /// accept loop. Empty (→ an unlimited default) in a control-only test daemon.
    pub(crate) limits: std::sync::OnceLock<Arc<crate::limits::MeshLimiters>>,
    /// The bounded provider address book for roster-blob fetches. Registered once in
    /// roster mode; a per-announce address add goes through it (bounded). `None` (unset) → tests use
    /// the per-fetch fallback. Kept in a OnceLock (like `audit`/`limits`) so `MeshState::new` is
    /// unchanged.
    pub(crate) roster_addr_book:
        std::sync::OnceLock<std::sync::Arc<crate::roster::transport::RosterAddrBook>>,
    /// This daemon's precomputed self-sovereign identity presentation for pairing (the device->user
    /// binding, identity). Loaded ONCE by [`serve_forever`] from the config
    /// `[identity].user_key` (auto-generated if absent) and signed over THIS endpoint via
    /// [`set_self_binding`](Self::set_self_binding) — same set-once discipline as `audit`/`limits`.
    /// `None` (unset) in a control-only/test daemon or when no user key exists → the pairing handlers
    /// present nothing and paired peers store `user_id: None` (the pre-identity behavior).
    pub(crate) self_binding: std::sync::OnceLock<Option<crate::pairing::rendezvous::SelfBinding>>,
    /// Recent INVITER-side pairing completions — a tiny in-memory ring (cap
    /// [`RECENT_PAIRINGS_CAP`]) `status` surfaces so the inviter's HUMAN can read the SAS and
    /// compare it with the redeemer's out-of-band ("both humans compare the code"; the
    /// redeemer gets the code in its `PairResult`, this is the inviter's porcelain path to the
    /// same words). DISPLAY-ONLY ceremony state, NOT trust data: never persisted, lost on daemon
    /// restart (acceptable — the ceremony happens right after the pair), never an authorization
    /// input. std `Mutex` (never held across an await; push/snapshot are sync + tiny).
    pub(crate) recent_pairings:
        std::sync::Mutex<std::collections::VecDeque<mcpmesh_local_api::RecentPairing>>,
    /// On-demand reachability probe cache (pairing-mode liveness). Keyed by endpoint-id INTERNALLY;
    /// [`probe_peer`] writes it and [`reachability_of`] reads it (projecting to the NICKNAME —
    /// never the id). In-memory + ephemeral: never persisted, lost on restart, never an
    /// authorization input (advisory presence only). std `Mutex` — held only for the tiny
    /// insert/clone, never across an await.
    pub(crate) reachability: std::sync::Mutex<std::collections::HashMap<[u8; 32], ReachEntry>>,
}

/// Cap on the [`MeshState::recent_pairings`] ring: enough for a burst of ceremonies (a person
/// pairing several devices back-to-back) while keeping `status` output and memory tiny.
const RECENT_PAIRINGS_CAP: usize = 8;

impl MeshState {
    /// Assemble the mesh half from its parts, wrapped in an `Arc` (it is always shared —
    /// held by [`DaemonState`] AND by the running accept loop). `accept_task` starts empty;
    /// the caller spawns the loop with the returned `Arc` and installs the handle via
    /// [`set_accept_task`](Self::set_accept_task) (the construction chicken-egg: the loop
    /// needs `mesh`, and `mesh.accept_task` needs the loop's handle).
    ///
    /// `pub` so integration tests can build one; the fields stay `pub(crate)`.
    // The mesh half genuinely has 12 collaborators to assemble (endpoint, gate, store, invites,
    // nickname, config, roster, registry — plus roster mode's gossip/blobs handles + the two topic
    // subscriptions); a params-struct would only rename the same fields, and this signature is
    // pinned by the integration tests that assemble hermetic meshes. The four roster-transport
    // params are `None`/empty in a pure-pairing daemon.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: iroh::Endpoint,
        gate: Arc<dyn TrustGate>,
        store: Arc<PeerStore>,
        invites: Arc<LiveInvites>,
        self_nickname: String,
        config_path: PathBuf,
        roster: Arc<RosterGate>,
        conn_registry: Arc<ConnRegistry>,
        gossip: Option<iroh_gossip::net::Gossip>,
        blobs: Option<crate::roster::transport::RosterBlobs>,
        roster_topic: Option<crate::roster::transport::RosterGossip>,
        presence_topic: Option<crate::roster::transport::RosterGossip>,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint,
            gate,
            store,
            invites,
            self_nickname,
            accept_task: tokio::sync::Mutex::new(None),
            poll_loop: tokio::sync::Mutex::new(None),
            reload_lock: tokio::sync::Mutex::new(()),
            config_path,
            roster,
            conn_registry,
            gossip,
            blobs,
            roster_topic: tokio::sync::Mutex::new(roster_topic),
            presence_topic: Arc::new(tokio::sync::Mutex::new(presence_topic)),
            presence_table: Arc::new(crate::roster::presence::PresenceTable::new()),
            app_blobs: tokio::sync::Mutex::new(None),
            audit: std::sync::OnceLock::new(),
            limits: std::sync::OnceLock::new(),
            roster_addr_book: std::sync::OnceLock::new(),
            self_binding: std::sync::OnceLock::new(),
            recent_pairings: std::sync::Mutex::new(std::collections::VecDeque::new()),
            reachability: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Record a completed inviter-side pairing for the `status` ceremony surface (display-only —
    /// see the [`recent_pairings`](Self::recent_pairings) field doc). Bounded: the OLDEST entry
    /// is dropped once the ring holds [`RECENT_PAIRINGS_CAP`].
    pub(crate) fn record_pairing(
        &self,
        peer_nickname: String,
        sas_code: String,
        paired_at_epoch: u64,
    ) {
        let mut ring = self
            .recent_pairings
            .lock()
            .expect("recent_pairings lock not poisoned");
        if ring.len() >= RECENT_PAIRINGS_CAP {
            ring.pop_front();
        }
        ring.push_back(mcpmesh_local_api::RecentPairing {
            peer_nickname,
            sas_code,
            paired_at_epoch,
        });
    }

    /// Snapshot of the recent inviter-side pairings, NEWEST FIRST (the order `status` renders —
    /// the code the human is looking for is almost always the latest one).
    pub(crate) fn recent_pairings(&self) -> Vec<mcpmesh_local_api::RecentPairing> {
        self.recent_pairings
            .lock()
            .expect("recent_pairings lock not poisoned")
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    /// Install the gated app-blob provider post-construction (roster mode only).
    /// Called by `serve_forever` BEFORE `spawn_accept_loop`, so the `APP_BLOB_ALPN` arm always sees
    /// it once serving begins.
    pub async fn set_app_blobs(&self, provider: Arc<crate::blobs::provider::AppBlobs>) {
        *self.app_blobs.lock().await = Some(provider);
    }

    /// A clone of the installed app-blob provider handle, or `None` (pure-pairing / not yet set).
    pub async fn app_blobs(&self) -> Option<Arc<crate::blobs::provider::AppBlobs>> {
        self.app_blobs.lock().await.clone()
    }

    /// Install the process audit sink, once, before serving. A second call is ignored
    /// (`OnceLock::set` returns `Err`), keeping the invariant self-healing.
    pub fn set_audit(&self, sink: AuditSink) {
        let _ = self.audit.set(sink);
    }

    /// The audit sink, or the disabled no-op sink if none was installed (control-only test daemon).
    pub(crate) fn audit(&self) -> AuditSink {
        self.audit.get().cloned().unwrap_or_default()
    }

    /// Install this daemon's self-sovereign pairing identity, once, before serving (like
    /// [`set_audit`](Self::set_audit)). `None` records "this daemon has no user key" explicitly.
    pub fn set_self_binding(&self, binding: Option<crate::pairing::rendezvous::SelfBinding>) {
        let _ = self.self_binding.set(binding);
    }

    /// A clone of this daemon's self-sovereign pairing identity, or `None` when unset (control-only /
    /// test daemon) or when this daemon has no user key. The pairing handlers present it to peers.
    pub(crate) fn self_binding(&self) -> Option<crate::pairing::rendezvous::SelfBinding> {
        self.self_binding.get().cloned().flatten()
    }

    pub fn set_limits(&self, limits: Arc<crate::limits::MeshLimiters>) {
        let _ = self.limits.set(limits);
    }

    pub(crate) fn limits(&self) -> Arc<crate::limits::MeshLimiters> {
        self.limits
            .get()
            .cloned()
            .unwrap_or_else(crate::limits::MeshLimiters::unlimited)
    }

    pub(crate) fn roster_addr_book(
        &self,
    ) -> Option<std::sync::Arc<crate::roster::transport::RosterAddrBook>> {
        self.roster_addr_book.get().cloned()
    }

    /// A clone of the roster-topic gossip SENDER, or `None` in a pure-pairing daemon. Cloned
    /// under the mutex so `announce_roster` can broadcast from any site while the receiver has
    /// been moved out by the converge loop — the sender stays live in `roster_topic`.
    pub async fn roster_topic_sender(&self) -> Option<iroh_gossip::api::GossipSender> {
        self.roster_topic
            .lock()
            .await
            .as_ref()
            .map(|g| g.sender.clone())
    }

    /// Move the roster-topic gossip RECEIVER out — EXACTLY ONCE, for the distribution receive
    /// loop (a `GossipReceiver` is a single-consumer stream). Leaves the sender in place so
    /// `roster_topic_sender` still announces. `None` if pure-pairing or already taken.
    pub async fn take_roster_topic_receiver(&self) -> Option<iroh_gossip::api::GossipReceiver> {
        self.roster_topic
            .lock()
            .await
            .as_mut()
            .and_then(|g| g.receiver.take())
    }

    /// The narrow context the presence loops run against (`roster::presence::publish_loop` /
    /// `track_loop`): the presence table, the presence-topic handle, and the roster gate — the
    /// SAME `Arc`s this struct holds, so the loops observe live roster hot-swaps without ever
    /// seeing the rest of the daemon.
    pub(crate) fn presence_ctx(&self) -> crate::roster::presence::PresenceCtx {
        crate::roster::presence::PresenceCtx {
            roster: self.roster.clone(),
            table: self.presence_table.clone(),
            topic: self.presence_topic.clone(),
        }
    }

    /// The narrow context the inviter-side pair rendezvous runs against: the peer store + invite
    /// ring + this daemon's identity presentation, plus two hooks that reach back into the mesh —
    /// `grant` (the config-append + reload machinery behind [`grant_service_access`], which may
    /// abort/respawn the very accept loop that spawned the handler; safe because the handler is a
    /// detached child task — see the `InviterCtx` doc) and `record_pairing` (the `status`
    /// ceremony ring). Assembled per accepted pair connection by the accept loop.
    pub(crate) fn inviter_ctx(self: &Arc<Self>) -> crate::pairing::rendezvous::InviterCtx {
        let grant_mesh = self.clone();
        let record_mesh = self.clone();
        crate::pairing::rendezvous::InviterCtx {
            store: self.store.clone(),
            invites: self.invites.clone(),
            config_path: self.config_path.clone(),
            self_binding: self.self_binding(),
            grant: Box::new(move |nickname, services| {
                let mesh = grant_mesh.clone();
                Box::pin(async move { grant_service_access(&mesh, &nickname, &services).await })
            }),
            record_pairing: Box::new(move |nickname, sas, paired_at| {
                record_mesh.record_pairing(nickname, sas, paired_at);
            }),
        }
    }

    /// Record that the installed roster was CONFIRMED current at `now` — the freshness `last_confirmed`
    /// bump. Bumps the LIVE gate (the resolve/sever paths see it on the very next call)
    /// AND persists the instant to the per-node sidecar (`<config_dir>/roster.confirmed`) so a restart
    /// re-arms freshness at the confirmed time rather than instantly degrading. Called from ALL the
    /// confirmation events: a URL poll whose served serial is `>= installed` (even EQUAL — proof of
    /// currency without a serial bump, the only channel that gives it), a gossip-delivered roster
    /// passing validation, and a manual install. The persist is best-effort — a write failure leaves
    /// the in-RAM arm intact (the live decision is correct; only a restart would lose the instant).
    /// Async so the sidecar write runs on a blocking worker (the fs house rule).
    pub(crate) async fn confirm_roster_current(&self, now: i64) {
        // Live gate first — the security-bearing update (resolve/sever consult this immediately).
        self.roster.set_last_confirmed(now);
        // Then persist (best-effort). Derived per-node from `config_path` so two daemons in one process
        // (the multi-node integration tests) keep separate sidecars — mirrors `installed_roster_path`.
        let store = FreshnessStore::new(roster_confirmed_path(&self.config_path));
        match blocking("join roster freshness persist", move || store.store(now)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) | Err(e) => {
                tracing::warn!(%e, "persist roster freshness (in-memory freshness still applied)")
            }
        }
    }

    /// Install the accept-loop handle after [`new`](Self::new) + [`spawn_accept_loop`]
    /// (completes the construction chicken-egg). Also used to seed the handle a later
    /// hot-reload aborts.
    ///
    /// Take-and-abort any prior handle first (mirroring `reload_accept_loop`): a stray second
    /// call would otherwise DROP the previous `JoinHandle` — detaching, not stopping, its loop —
    /// leaving two loops accepting on one endpoint. Latent today (each caller invokes once), but
    /// this keeps the invariant self-healing rather than silently doubling the accept loop.
    pub async fn set_accept_task(&self, handle: JoinHandle<()>) {
        let mut guard = self.accept_task.lock().await;
        if let Some(old) = guard.take() {
            old.abort();
        }
        *guard = Some(handle);
    }
}

/// The mesh state IS the roster-distribution channels' host: the narrow seam
/// `roster::distribute` runs against (endpoint + roster gate + blob transport + topic handles +
/// the install pipeline), implemented here so that module never sees this struct. The install
/// pipeline itself lives in [`roster_install`] (`converge_roster_bytes` — the single-writer
/// converge shared with the manual install).
impl crate::roster::distribute::DistributionHost for MeshState {
    fn endpoint(&self) -> &iroh::Endpoint {
        &self.endpoint
    }

    fn roster(&self) -> &RosterGate {
        &self.roster
    }

    fn blobs(&self) -> Option<&crate::roster::transport::RosterBlobs> {
        self.blobs.as_ref()
    }

    fn gossip_active(&self) -> bool {
        self.gossip.is_some()
    }

    fn installed_roster_path(&self) -> PathBuf {
        roster_install::installed_roster_path(self)
    }

    fn pinned_org_root_pk(&self) -> anyhow::Result<Option<String>> {
        roster_install::mesh_config_org_root_pk(self)
    }

    fn addr_book(&self) -> Option<Arc<crate::roster::transport::RosterAddrBook>> {
        self.roster_addr_book()
    }

    fn roster_topic_sender(
        &self,
    ) -> impl std::future::Future<Output = Option<iroh_gossip::api::GossipSender>> + Send {
        MeshState::roster_topic_sender(self)
    }

    fn take_roster_topic_receiver(
        &self,
    ) -> impl std::future::Future<Output = Option<iroh_gossip::api::GossipReceiver>> + Send {
        MeshState::take_roster_topic_receiver(self)
    }

    fn confirm_roster_current(&self, now: i64) -> impl std::future::Future<Output = ()> + Send {
        MeshState::confirm_roster_current(self, now)
    }

    fn install_roster_bytes(
        &self,
        bytes: &[u8],
        serial: u64,
        channel: &'static str,
    ) -> impl std::future::Future<Output = anyhow::Result<bool>> + Send {
        roster_install::converge_roster_bytes(self, bytes, serial, channel)
    }
}

/// Build the `Services` registry from config `[services.*]`: a `run` service becomes a
/// [`SpawnBackend`] (its own concurrency semaphore), a `socket` service a [`SocketBackend`].
/// Backends carry NO identity — that is threaded per-caller through `SessionBackend::run`
/// (the injected identity is per-session, the backend is shared). A malformed service (both
/// or neither backend kind) is logged and skipped rather than failing the whole daemon.
///
/// `pub` so the integration tests can compose the SAME registry wiring the daemon uses
/// against an in-process endpoint (the daemon's own `run()` is a subprocess; the test drives
/// the composition directly to prove config → services → gate → backend → env injection).
pub fn build_services(cfg: &Config) -> Services {
    build_services_audited(
        cfg,
        &AuditSink::disabled(),
        &crate::limits::MeshLimiters::unlimited(),
    )
}

/// Build the service registry, giving every backend its service NAME, the audit sink,
/// and the shared per-identity request limiter. The limiter is ONE `Arc` shared
/// across ALL backends so a peer's rate spans every mount (SECURITY invariant 1, keyed on endpoint).
pub fn build_services_audited(
    cfg: &Config,
    audit: &AuditSink,
    limiters: &Arc<crate::limits::MeshLimiters>,
) -> Services {
    let mut map: HashMap<String, ServiceEntry> = HashMap::new();
    for (name, svc) in &cfg.services {
        let backend: Arc<dyn SessionBackend> = match svc.backend_result() {
            Ok(Backend::Run(cmd)) => Arc::new(SpawnBackend {
                cmd: cmd.to_vec(),
                concurrency: Arc::new(Semaphore::new(spawn_concurrency(cfg))),
                service: name.clone(),
                audit: audit.clone(),
                limiter: limiters.requests.clone(),
            }),
            Ok(Backend::Socket(path)) => Arc::new(SocketBackend {
                path: path.to_string(),
                service: name.clone(),
                audit: audit.clone(),
                limiter: limiters.requests.clone(),
            }),
            Err(e) => {
                tracing::warn!(service = %name, %e, "skipping malformed service");
                continue;
            }
        };
        map.insert(
            name.clone(),
            ServiceEntry {
                backend,
                allow: svc.allow.clone(),
            },
        );
    }
    Services::new(map)
}

/// A short, human-glanceable fingerprint of an endpoint id: the first 8 chars of its base32
/// (`EndpointId`'s `Display`) form. The default self-nickname when config sets none (
/// "suggested nickname"). Not security-bearing — the id itself is the routing key.
fn short_fingerprint(id: &iroh::EndpointId) -> String {
    id.to_string().chars().take(8).collect()
}

/// A friendly default display name for this node when the config sets no `nickname`: the machine's
/// short hostname, else the endpoint fingerprint. So a freshly-started daemon advertises `jetson`
/// instead of `96246d3f` out of the box (a config `nickname` still wins; a peer's stored nickname is
/// captured at pairing time from whatever the peer suggests here).
fn default_self_nickname(id: &iroh::EndpointId) -> String {
    hostname_nickname().unwrap_or_else(|| short_fingerprint(id))
}

/// This machine's `hostname`, sanitized into a nickname, or `None` if the command fails or is empty.
fn hostname_nickname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    sanitize_hostname(&String::from_utf8_lossy(&out.stdout))
}

/// Sanitize a raw hostname into a nickname: the short name (before the first `.`), lowercased, keeping
/// only `[a-z0-9-]`; `None` if the result is empty. Pure — the fallible `hostname` call is separate.
fn sanitize_hostname(raw: &str) -> Option<String> {
    let short = raw
        .trim()
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let cleaned: String = short
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Assemble a serving [`DaemonState`] around an already-bound endpoint and peer store, for
/// in-process integration tests that must drive the REAL control server (`serve_control`) —
/// the proxy round-trip test binds a control socket over this and runs `mcpmesh connect` as
/// a subprocess against it, so the actual `open_session` dial-by-id + pipe are exercised. The
/// mesh's serve loop is inert here (`open_session` reads only the endpoint + store to DIAL
/// outbound); production assembles its own `MeshState` inline in `serve_forever`.
pub fn serving_state(endpoint: iroh::Endpoint, store: Arc<PeerStore>) -> Arc<DaemonState> {
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    let self_nickname = short_fingerprint(&endpoint.id());
    // No accept loop is spawned here (this seam only dials OUTBOUND via `open_session`), so the
    // mesh's `accept_task` stays empty.
    let mesh = MeshState::new(
        endpoint,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        self_nickname,
        // Test-only dial seam (no roster install runs through it): a HOME-less env
        // degrades to an empty config path rather than failing the seam.
        paths::default_config_path().unwrap_or_default(),
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    );
    Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh))
}

/// Test-only assembly shared by the daemon submodules' unit tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::path::PathBuf;
    use std::sync::Arc;

    use mcpmesh_net::TrustGate;
    use mcpmesh_net::registry::ConnRegistry;

    use crate::allowlist::{AllowlistGate, PeerStore};
    use crate::pairing::LiveInvites;
    use crate::roster::gate::{ComposedGate, RosterGate};

    use super::MeshState;
    use super::boot::build_endpoint;

    /// Build a HERMETIC mesh (relay-disabled endpoint, temp config/store, EMPTY roster) so we can
    /// drive `org_join` + `roster_status` in-process against the real config-write + status paths.
    pub(crate) async fn hermetic_mesh(config_path: PathBuf) -> Arc<MeshState> {
        let dir = config_path.parent().unwrap();
        let store = Arc::new(PeerStore::open(&dir.join("state.redb")).unwrap());
        let pairs = Arc::new(AllowlistGate::new(store.clone()));
        let roster = Arc::new(RosterGate::empty());
        let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
        let hermetic = crate::config::NetworkCfg {
            relay_mode: "disabled".into(),
            ..Default::default()
        };
        let endpoint = build_endpoint(iroh::SecretKey::from_bytes(&[7u8; 32]), &hermetic, false)
            .await
            .unwrap();
        MeshState::new(
            endpoint,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "test".into(),
            config_path,
            roster,
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recent_pairings_surfaces_the_inviter_side_sas() {
        // #35: the inviter learns its side of the SAS from status.recent_pairings — the
        // `record_pairing` sink the accept-loop calls on a completed redemption. Newest-first,
        // carrying the SAS words for the out-of-band human check, so an embedder renders the
        // whole ceremony without shelling out to `mcpmesh status`.
        let dir = tempfile::tempdir().unwrap();
        let mesh = super::testutil::hermetic_mesh(dir.path().join("config.toml")).await;
        assert!(mesh.recent_pairings().is_empty(), "no pairings yet");

        mesh.record_pairing("bob".into(), "tango-fig-cabbage".into(), 1000);
        mesh.record_pairing("carol".into(), "delta-hop-iron".into(), 2000);

        let recent = mesh.recent_pairings();
        assert_eq!(recent.len(), 2);
        // Newest first, each carrying the SAS the inviter reads aloud.
        assert_eq!(recent[0].peer_nickname, "carol");
        assert_eq!(recent[0].sas_code, "delta-hop-iron");
        assert_eq!(recent[1].peer_nickname, "bob");
        assert_eq!(recent[1].sas_code, "tango-fig-cabbage");
    }

    #[test]
    fn sanitize_hostname_makes_a_friendly_nickname() {
        assert_eq!(sanitize_hostname("jetson\n").as_deref(), Some("jetson"));
        assert_eq!(
            sanitize_hostname("Johns-MacBook-Pro.local").as_deref(),
            Some("johns-macbook-pro"),
            "strip the domain, lowercase, keep dashes"
        );
        assert_eq!(
            sanitize_hostname("nvidia jetson!").as_deref(),
            Some("nvidiajetson"),
            "drop spaces + punctuation"
        );
        assert_eq!(sanitize_hostname("   ").as_deref(), None);
        assert_eq!(sanitize_hostname("").as_deref(), None);
        assert_eq!(sanitize_hostname(".local").as_deref(), None);
    }

    #[test]
    fn spawn_concurrency_reads_max_sessions_with_a_safe_floor() {
        let c = Config::from_toml_str("[limits]\nmax_sessions = 2\n").unwrap();
        assert_eq!(super::spawn_concurrency(&c), 2);
        let dflt = Config::from_toml_str("").unwrap();
        assert_eq!(super::spawn_concurrency(&dflt), 4, "default max_sessions");
        let zero = Config::from_toml_str("[limits]\nmax_sessions = 0\n").unwrap();
        assert_eq!(
            super::spawn_concurrency(&zero),
            1,
            "a 0 misconfig floors to 1, never no-permits"
        );
        // Keep the documented default constant PINNED to the config default (and referenced, so it is
        // not dead code once `build_services_audited` switches to `spawn_concurrency(cfg)`).
        assert_eq!(
            super::SPAWN_CONCURRENCY as u32,
            crate::config::LimitsCfg::default().max_sessions,
            "the documented default matches the config default"
        );
    }
}
