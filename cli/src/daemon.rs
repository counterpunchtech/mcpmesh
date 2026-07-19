//! The long-lived mcpmesh daemon. It owns the single Iroh endpoint (seeded from the M0 device
//! key) and runs two UDS-facing roles simultaneously on one tokio runtime: (1) it runs its
//! OWN accept loop ([`spawn_accept_loop`]) that dispatches each inbound connection by its
//! negotiated ALPN (spec §7.1) — `mcpmesh/mcp/1` flows through M1's gated per-connection handler
//! [`mcpmesh_net::run_mesh_connection`], where `gate` is an
//! [`AllowlistGate`](crate::allowlist::AllowlistGate) over the `state.redb` peer allowlist and
//! `services` are backends built from config, while `mcpmesh/pair/1` flows to the pairing
//! rendezvous, GATE-EXEMPT (D8 exception) and authenticated by the invite secret rather than
//! the trust gate; and (2) it serves the `mcpmesh-local/1` control API on
//! `<runtime_dir>/mcpmesh.sock` (hello + status + service registration + peer add), consumed by
//! the porcelain.
//!
//! The daemon deliberately no longer calls `mcpmesh_net::serve`: routing by ALPN is the whole
//! point (D8's gate exemption only applies to the pair ALPN), which the mesh-only `serve`
//! cannot do. `serve`/`ServeHandle` REMAIN in net for its own tests + standalone use; the
//! daemon just composes the same [`mcpmesh_net::run_mesh_connection`] under its own loop.
//!
//! Single-daemon-per-uid (Task 2 BINDING hand-off): an exclusive non-blocking `flock` on
//! `<runtime_dir>/mcpmesh.lock` is acquired BEFORE any endpoint/store/socket work and held for
//! the process lifetime. This makes `ipc::bind_control_socket`'s stale-socket unlink safe —
//! no LIVE daemon can exist while we hold the lock — and (critically for redb, which takes
//! an exclusive file lock) guarantees exactly one process opens `state.redb`. A redundant
//! daemon loses the lock and exits 0 before touching the device key, store, or endpoint.
pub(crate) mod config_write;
mod dial;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcpmesh_local_api::{
    BackendKind, BlobFetchResult, BlobPublishResult, BlobScopeList, InviteResult, OrgJoinResult,
    PairResult, PeerAddParams, PeerInfo, PeerRemoveParams, PeerRenameParams, PresencePeer,
    RegisterServiceParams, RosterInstallResult, RosterStatus, ScopeInfo, ServiceInfo,
};
use mcpmesh_net::errors::{ERR_UNREACHABLE, synthesized};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{
    ALPN_MCP, ALPN_PAIR, ALPN_PING, ServiceEntry, Services, SessionBackend, TrustGate,
    run_mesh_connection,
};
use mcpmesh_trust::roster::validate::RosterState;
use mcpmesh_trust::{DeviceKey, paths};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub use dial::{dial_service, pipe_session, race_dial};

use self::config_write::{
    append_allow_to_config, remove_allow_from_config, rename_allow_in_config, write_identity_pin,
    write_identity_user_id, write_join_pin, write_roster_url, write_service_to_config,
};
use crate::util::{epoch_now_i64, epoch_now_u64};

use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use crate::audit::{AuditLog, AuditRecord, AuditSink, now_ts};
use crate::backends::socket::SocketBackend;
use crate::backends::spawn::SpawnBackend;
use crate::config::{Backend, Config};
use crate::control::{DaemonState, serve_control};
use crate::ipc;
use crate::pairing::{self, Invite, LiveInvites};
use crate::roster::RosterStore;
use crate::roster::freshness::FreshnessStore;
use crate::roster::gate::{ComposedGate, RosterGate};

/// The lockstep stack version (workspace version) reported in `Hello`/`status`.
pub const STACK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default per-service spawn concurrency cap (spec §6.2). Each `run` service gets its own
/// semaphore of this size; a socket service has no per-session cap (T8 decision). The runtime cap is
/// now config-driven via [`spawn_concurrency`] (`[limits].max_sessions`); this const remains the
/// DOCUMENTED default, pinned to the config default by `spawn_concurrency_reads_max_sessions_*`.
#[allow(dead_code)] // documented default; asserted (test-only) to equal LimitsCfg::default().max_sessions
const SPAWN_CONCURRENCY: usize = 4;

/// The per-service spawn concurrency (spec §6.2 / §12 `[limits].max_sessions`, default 4). Floors to
/// 1 so a `max_sessions = 0` misconfig bounds to one session rather than refusing every session.
pub(crate) fn spawn_concurrency(cfg: &Config) -> usize {
    (cfg.limits.max_sessions.max(1)) as usize
}

/// A minted pairing invite lives at most 24h (spec §4.2 "expiry ≤ 24h").
const INVITE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Cap on how long `mint_invite` waits for the endpoint to come "online" (a home-relay
/// handshake) before minting, so the invite's address carries the relay URL the redeemer
/// bootstraps from across NAT (spec §4.2; bolo runs relay.runbolo.com). It is a CAP, not a
/// fixed wait: production returns the instant the relay handshake completes (~1s). On the
/// relay-disabled localhost preset `online()` never completes, so this fires and we mint
/// with the direct-address-only addr (dialable on localhost/LAN — sufficient for tests).
const RELAY_READY_TIMEOUT: Duration = Duration::from_secs(3);

/// The mesh half of the daemon: the endpoint, the trust gate + its backing store, the live
/// invite registry, and the running accept-loop task. Held (behind an `Arc`) inside
/// [`DaemonState`] so the control API's `register_service` / `peer_add` / `pair` methods can
/// hot-reload the registry and populate the store on the SAME open database the gate reads
/// (redb is single-process; routing writes through the daemon is the only correct design).
///
/// It is `Arc<MeshState>` (not owned) because the accept loop's `mcpmesh/pair/1` branch hands
/// the WHOLE mesh to [`pairing::rendezvous::handle_inviter_side`], which on a successful pair
/// calls [`grant_service_access`] — the config-append + reload machinery that also lives on
/// this struct (M2b T6). Threading `Arc<MeshState>` through [`spawn_accept_loop`] lets the
/// pair grant reload the very loop that spawned it (the handler is a detached child task, so
/// the reload's abort does not touch it — see [`handle_inviter_side`] for that reasoning).
///
/// `pub` (fields `pub(crate)`) only so integration tests can assemble one via [`MeshState::new`]
/// + [`MeshState::set_accept_task`] and drive the SAME accept loop the daemon runs.
///
/// [`handle_inviter_side`]: crate::pairing::rendezvous::handle_inviter_side
/// [`pairing::rendezvous::handle_inviter_side`]: crate::pairing::rendezvous::handle_inviter_side
pub struct MeshState {
    pub(crate) endpoint: iroh::Endpoint,
    pub(crate) gate: Arc<dyn TrustGate>,
    pub(crate) store: Arc<PeerStore>,
    /// The in-RAM registry of outstanding pairing invites (spec §4.2). The accept loop's
    /// `mcpmesh/pair/1` branch redeems against it (T5); shared with every spawned pair handler.
    pub(crate) invites: Arc<LiveInvites>,
    /// This device's suggested name for itself, carried in a minted invite (spec §4.2).
    /// Resolved once at startup: config `identity.petname`, else a short base32 fingerprint
    /// of the endpoint id (T5). The redeemer stores it as its local name for us.
    pub(crate) self_petname: String,
    /// The daemon's own ALPN-dispatch accept loop (see [`spawn_accept_loop`]). Hot-reload
    /// takes it, `.abort()`s it, and installs a fresh loop with the rebuilt registry — a brief
    /// serving blip is acceptable (spec §6.1 "hot-reloads").
    pub(crate) accept_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// The running HTTPS roster-poll loop (spec §4.3 M3c), if `[roster].url` is set. `None` until a
    /// URL is pinned. Held so [`respawn_poll_loop`] can ABORT+REPLACE it — a runtime `set_roster_url`
    /// (a joiner's D5 first-roster bootstrap, or a URL change) (re)starts polling WITHOUT a daemon
    /// restart, and repeated calls never STACK duplicate loops (the idempotency guard). Initialized
    /// `None` inside [`new`](Self::new) (like `accept_task`), so no call site changes.
    pub(crate) poll_loop: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    /// Serializes the WHOLE config-mutating critical section — `register_service` (config read →
    /// upsert → atomic write → reload → rebuild → accept-loop swap → status refresh) AND the
    /// pairing `grant_service_access` (allow-append → reload → swap). Without it, a concurrent
    /// registration and a pairing-grant each read the same base config and the second write
    /// clobbers the first's change (lost update). The redb `peer_add` path is already serialized
    /// by redb's write lock; this gives the config path an equivalent.
    pub(crate) reload_lock: tokio::sync::Mutex<()>,
    pub(crate) config_path: PathBuf,
    /// The roster-mode gate handle (hot-swapped on install; consulted for the D8 sever set + status).
    /// `RosterGate::empty()` in a pure-pairing daemon — where [`ComposedGate`] then falls through to
    /// pairing for everything, byte-identical to M2b. In a roster daemon this is the SAME
    /// `Arc<RosterGate>` [`ComposedGate`] holds, so [`install_roster_view_and_sever`] hot-swaps the
    /// live gate's view with a single `install` (no gate rebuild).
    ///
    /// [`ComposedGate`]: crate::roster::gate::ComposedGate
    pub(crate) roster: Arc<RosterGate>,
    /// Live mesh connections, for D8 revocation-severing on roster install (spec §4.3 rule 6, §4.5).
    /// [`spawn_accept_loop`] threads it into [`run_mesh_connection`] (CHECK-register on accept); the
    /// T9 install path calls [`ConnRegistry::sever_matching`] against it.
    pub(crate) conn_registry: Arc<ConnRegistry>,
    /// The roster/presence gossip handle + roster-blob transport (spec §4.3/§10.1), spawned on the
    /// daemon's ONE endpoint ([RECONCILE-COMPOSE]). `None` in a pure-pairing daemon (no org root
    /// pinned) — no gossip is spawned, byte-identical to M2b. [`spawn_accept_loop`]'s new gossip/blob
    /// arms dispatch inbound connections to these; a `None` arm closes the connection cleanly.
    pub(crate) gossip: Option<iroh_gossip::net::Gossip>,
    pub(crate) blobs: Option<crate::roster::transport::RosterBlobs>,
    /// The roster-topic subscription (spec §4.3): the sender announces (T6, cloned per call), the
    /// receiver is moved out ONCE by the converge loop (T6). `None`/empty in a pure-pairing daemon.
    pub(crate) roster_topic: tokio::sync::Mutex<Option<crate::roster::transport::RosterGossip>>,
    /// The presence-topic subscription (spec §10.1): the publish loop clones the sender to broadcast
    /// heartbeats; the track loop moves the receiver out ONCE. `None`/empty in a pure-pairing daemon.
    pub(crate) presence_topic: tokio::sync::Mutex<Option<crate::roster::transport::RosterGossip>>,
    /// The advisory presence table (spec §10.1): the track loop records verified heartbeats here;
    /// `status` + (T11) the person→device dial read it for recency ORDERING. ADVISORY-ONLY — no gate,
    /// authz check, or sever decision ever consults it (absence never blocks a dial). Always present
    /// (constructed in [`new`](Self::new)); a pure-pairing daemon simply never records into it.
    pub(crate) presence_table: Arc<crate::roster::presence::PresenceTable>,
    /// The gated per-scope app-blob provider (spec §9, M4a). `None` in a pure-pairing daemon and
    /// until [`set_app_blobs`](Self::set_app_blobs) installs it (roster mode only — grants use roster
    /// vocabulary). Behind a `tokio::sync::Mutex<Option<..>>` set post-construction (like
    /// `accept_task`/`poll_loop`), so `MeshState::new`'s signature is unchanged and no existing caller
    /// breaks. The accept loop's `APP_BLOB_ALPN` arm reads it per-connection.
    pub(crate) app_blobs: tokio::sync::Mutex<Option<Arc<crate::blobs::provider::AppBlobs>>>,
    /// The process-wide audit sink (spec §11.3). Set ONCE by [`serve_forever`] before serving via
    /// [`set_audit`](Self::set_audit); read by the reload sites (to re-thread it into rebuilt
    /// backends) and the trust-event hooks. `OnceLock` — set-once, lock-free reads, no async.
    /// Empty (→ `AuditSink::disabled()`) in a control-only test daemon.
    pub(crate) audit: std::sync::OnceLock<AuditSink>,
    /// The process rate/concurrency limiters (spec §11.2 P7). Set ONCE by `serve_forever` before
    /// serving (like `audit`); read by the reload sites (rebuilt backends re-thread it) and the
    /// accept loop (T9). Empty (→ an unlimited default) in a control-only test daemon.
    pub(crate) limits: std::sync::OnceLock<Arc<crate::limits::MeshLimiters>>,
    /// The bounded provider address book for roster-blob fetches (spec §11.2 P7). Registered once in
    /// roster mode; a per-announce address add goes through it (bounded). `None` (unset) → tests use
    /// the per-fetch fallback. Kept in a OnceLock (like `audit`/`limits`) so `MeshState::new` is
    /// unchanged.
    pub(crate) roster_addr_book:
        std::sync::OnceLock<std::sync::Arc<crate::roster::transport::RosterAddrBook>>,
    /// This daemon's precomputed self-sovereign identity presentation for pairing (the device->user
    /// binding, spec §4.2 identity). Loaded ONCE by [`serve_forever`] from the config
    /// `[identity].user_key` (auto-generated if absent) and signed over THIS endpoint via
    /// [`set_self_binding`](Self::set_self_binding) — same set-once discipline as `audit`/`limits`.
    /// `None` (unset) in a control-only/test daemon or when no user key exists → the pairing handlers
    /// present nothing and paired peers store `user_id: None` (M2b parity).
    pub(crate) self_binding: std::sync::OnceLock<Option<crate::pairing::rendezvous::SelfBinding>>,
    /// Recent INVITER-side pairing completions — a tiny in-memory ring (cap
    /// [`RECENT_PAIRINGS_CAP`]) `status` surfaces so the inviter's HUMAN can read the SAS and
    /// compare it with the redeemer's out-of-band (spec §4.2 "both humans compare the code"; the
    /// redeemer gets the code in its `PairResult`, this is the inviter's porcelain path to the
    /// same words). DISPLAY-ONLY ceremony state, NOT trust data: never persisted, lost on daemon
    /// restart (acceptable — the ceremony happens right after the pair), never an authorization
    /// input. std `Mutex` (never held across an await; push/snapshot are sync + tiny).
    pub(crate) recent_pairings:
        std::sync::Mutex<std::collections::VecDeque<mcpmesh_local_api::RecentPairing>>,
    /// On-demand reachability probe cache (pairing-mode liveness). Keyed by endpoint-id INTERNALLY;
    /// [`probe_peer`] writes it and [`reachability_of`] reads it (projecting to the §1.5 PETNAME —
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
    // petname, config, roster, registry — plus M3c's gossip/blobs handles + the roster/presence
    // topic subscriptions); a params-struct would only rename the same fields. The M3c bump (8 → 12)
    // extends the deliberate T8 allow; the four new params are `None`/empty in a pure-pairing daemon.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: iroh::Endpoint,
        gate: Arc<dyn TrustGate>,
        store: Arc<PeerStore>,
        invites: Arc<LiveInvites>,
        self_petname: String,
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
            self_petname,
            accept_task: tokio::sync::Mutex::new(None),
            poll_loop: tokio::sync::Mutex::new(None),
            reload_lock: tokio::sync::Mutex::new(()),
            config_path,
            roster,
            conn_registry,
            gossip,
            blobs,
            roster_topic: tokio::sync::Mutex::new(roster_topic),
            presence_topic: tokio::sync::Mutex::new(presence_topic),
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
        peer_petname: String,
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
            peer_petname,
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

    /// Install the gated app-blob provider (spec §9, M4a) post-construction (roster mode only).
    /// Called by `serve_forever` BEFORE `spawn_accept_loop`, so the `APP_BLOB_ALPN` arm always sees
    /// it once serving begins.
    pub async fn set_app_blobs(&self, provider: Arc<crate::blobs::provider::AppBlobs>) {
        *self.app_blobs.lock().await = Some(provider);
    }

    /// A clone of the installed app-blob provider handle, or `None` (pure-pairing / not yet set).
    pub async fn app_blobs(&self) -> Option<Arc<crate::blobs::provider::AppBlobs>> {
        self.app_blobs.lock().await.clone()
    }

    /// Install the process audit sink (spec §11.3), once, before serving. A second call is ignored
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

    /// A clone of the roster-topic gossip SENDER (spec §4.3 announce), or `None` in a pure-pairing
    /// daemon. Cloned under the mutex so `announce_roster` (T6) can broadcast from any site while the
    /// receiver has been moved out by the converge loop — the sender stays live in `roster_topic`.
    pub async fn roster_topic_sender(&self) -> Option<iroh_gossip::api::GossipSender> {
        self.roster_topic
            .lock()
            .await
            .as_ref()
            .map(|g| g.sender.clone())
    }

    /// Move the roster-topic gossip RECEIVER out (spec §4.3 converge) — EXACTLY ONCE, for the T6
    /// receive loop (a `GossipReceiver` is a single-consumer stream). Leaves the sender in place so
    /// `roster_topic_sender` still announces. `None` if pure-pairing or already taken.
    pub async fn take_roster_topic_receiver(&self) -> Option<iroh_gossip::api::GossipReceiver> {
        self.roster_topic
            .lock()
            .await
            .as_mut()
            .and_then(|g| g.receiver.take())
    }

    /// A clone of the presence-topic gossip SENDER (spec §10.1 heartbeat), or `None` in a pure-pairing
    /// daemon / when the subscribe failed. The publish loop clones it once and broadcasts every beat;
    /// the sender stays live in `presence_topic` after the track loop takes the receiver.
    pub async fn presence_topic_sender(&self) -> Option<iroh_gossip::api::GossipSender> {
        self.presence_topic
            .lock()
            .await
            .as_ref()
            .map(|g| g.sender.clone())
    }

    /// Move the presence-topic gossip RECEIVER out (spec §10.1 track) — EXACTLY ONCE, for the track
    /// loop (a `GossipReceiver` is a single-consumer stream). Leaves the sender in place so
    /// `presence_topic_sender` still publishes. `None` if pure-pairing / already taken.
    pub async fn take_presence_topic_receiver(&self) -> Option<iroh_gossip::api::GossipReceiver> {
        self.presence_topic
            .lock()
            .await
            .as_mut()
            .and_then(|g| g.receiver.take())
    }

    /// Record that the installed roster was CONFIRMED current at `now` — the freshness `last_confirmed`
    /// bump (spec §4.3 P13). Bumps the LIVE gate (the resolve/sever paths see it on the very next call)
    /// AND persists the instant to the per-node sidecar (`<config_dir>/roster.confirmed`) so a restart
    /// re-arms freshness at the confirmed time rather than instantly degrading. Called from ALL FOUR
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
        match tokio::task::spawn_blocking(move || store.store(now)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(%e, "persist roster freshness (in-memory freshness still applied)")
            }
            Err(e) => tracing::warn!(%e, "join roster freshness persist"),
        }
    }

    /// Install the accept-loop handle after [`new`](Self::new) + [`spawn_accept_loop`]
    /// (completes the construction chicken-egg). Also used to seed the handle a later
    /// hot-reload aborts.
    ///
    /// Take-and-abort any prior handle first (mirroring [`reload_accept_loop`]): a stray second
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

/// Run the daemon. On unix, acquires the per-uid flock singleton (another holder → exit 0);
/// on Windows the control-endpoint bind in `serve_forever` is the singleton. Then binds the
/// control endpoint FIRST, builds the endpoint + store + gate + service registry, starts the
/// mesh serve loop, and serves the control API until a `shutdown` request stops it.
pub fn run() -> Result<()> {
    // Unix singleton: the per-uid flock, taken BEFORE anything else so the stale-socket unlink
    // and the state.redb open are single-daemon-safe. We hold the exclusive lock, so no other
    // daemon is live: the stale-socket unlink cannot orphan anyone AND we are the sole opener of
    // state.redb. `_lock` lives until this function returns (process lifetime for a serving
    // daemon). Windows singleton: there is no advisory-lock/filesystem equivalent here — the
    // control-pipe bind ITSELF is the singleton (a FILE_FLAG_FIRST_PIPE_INSTANCE create fails with
    // AddrInUse once a peer daemon owns the pipe), which is why `serve_forever` binds the listener
    // FIRST, before opening state.redb.
    #[cfg(unix)]
    let _lock = {
        let runtime = paths::runtime_dir()?;
        ipc::ensure_runtime_dir(&runtime)?;
        let lock_path = runtime.join("mcpmesh.lock");
        match acquire_singleton_lock(&lock_path)? {
            Some(lock) => lock,
            None => {
                tracing::info!("another mcpmesh daemon already holds the singleton lock; exiting");
                return Ok(());
            }
        }
    };
    let socket = paths::default_endpoint()?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build daemon tokio runtime")?;
    rt.block_on(async move { serve_forever(&socket).await })
}

/// The async body: compose the mesh serve loop and the control server, then run until
/// shutdown. Split out from [`run`] so the runtime setup stays synchronous.
async fn serve_forever(socket: &Path) -> Result<()> {
    // 0. [CRITICAL — M3c T7] Install a process-default rustls `CryptoProvider` (ring) BEFORE any
    //    reqwest client is built. reqwest 0.13.4 (`rustls-no-provider`) resolves the provider via
    //    `CryptoProvider::get_default()` at CLIENT-BUILD time and PANICS ("No rustls crypto provider
    //    is configured") if none is installed. iroh 1.0.1 passes ring per-endpoint and installs NO
    //    process-default, so nothing else does this for us. Idempotent: `install_default` returns Err
    //    if a provider is already installed, which `let _ =` swallows (safe against a re-entry / a test
    //    that also installed one). This MUST precede the URL poll loop spawned below (§4.3 HTTPS poll).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 0a. Bind the control listener FIRST — before state.redb, the endpoint, or the audit log. On
    //     Windows the pipe bind IS the singleton lock (there is no flock; `run` skips it there): a
    //     FILE_FLAG_FIRST_PIPE_INSTANCE create returns AddrInUse once a peer daemon owns the pipe,
    //     so binding early is what serializes daemons. On unix this AddrInUse arm is dead — `run`'s
    //     flock already serialized us before we ever reached here — but the shape is uniform. The
    //     socket/pipe creation has no side effects the later construction depends on, so hoisting it
    //     only moves WHEN the endpoint appears (earlier), never WHAT gets built.
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

    // 0b. The audit log (spec §11.3): one bounded-channel writer over <state_dir>/audit. Best-effort
    //     — record() never blocks or fails a session. Threaded into the backends (build_services_
    //     audited) and stored on the mesh for the reload sites + trust-event hooks.
    let audit = AuditSink::new(AuditLog::spawn(paths::default_audit_dir()?));

    // 1. Config + device key.
    let config_path = paths::default_config_path()?;
    let cfg = Config::load(&config_path)
        .map_err(|e| anyhow::anyhow!("config error in {}: {e}", config_path.display()))?;
    let key_path = match cfg.identity.device_key.clone() {
        Some(p) => p,
        None => paths::default_device_key_path()?,
    };
    let (key, _created) = DeviceKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("device key error at {}: {e}", key_path.display()))?;

    // 2. The single Iroh endpoint, seeded from the device key (spec §7.1). Roster mode (an org root
    //    pinned in config) additionally advertises the gossip + blob ALPNs on this same endpoint;
    //    a pure-pairing daemon advertises exactly mcp/1 + pair/1 (M2b parity, [Important] 1).
    let secret = iroh::SecretKey::from_bytes(&key.secret_bytes());
    let roster_mode = cfg.identity.org_root_pk.is_some();
    let endpoint = build_endpoint(secret, &cfg.network, roster_mode).await?;
    let our_id = endpoint.id();

    // 3. The peer allowlist store + gate. redb open + reads are blocking; open on a blocking
    //    thread so a slow trust-file fsync never stalls a runtime worker (Task 4 seam note).
    let db_path = paths::default_state_db_path()?;
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create data dir {}", parent.display()))?;
    }
    let store = tokio::task::spawn_blocking(move || PeerStore::open(&db_path))
        .await
        .context("join peer-store open")??;
    let store = Arc::new(store);
    // The composed trust gate (spec §4.1): pairing ∪ roster with explicit precedence
    // (revocation → roster → pairing). `pairs` is the M2b `AllowlistGate` over the redb peer
    // allowlist; `roster` is the hot-swappable roster gate, empty until a signed roster is
    // installed/loaded. With NO roster installed, `ComposedGate` falls through to `pairs` for
    // everything — byte-identical to M2b (every pairing flow preserved).
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    // The degraded-expiry grace window (spec §4.3, default 72h; total parse — see
    // `RosterCfg::grace_seconds`, which also carries the M3a/M3c degraded-split design note).
    let grace = cfg.roster.grace_seconds();
    // The roster-daemon gate: expiry grace AND the freshness bound (spec §4.3 P13). A stale roster
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
                let rstore = RosterStore::new(paths::default_roster_path()?);
                match tokio::task::spawn_blocking(move || rstore.load(&pk)).await {
                    Ok(Ok(Some(view))) => {
                        roster.install(view);
                        tracing::info!("installed roster loaded");
                        // If the loaded roster is already past expiry but within grace, warn on load
                        // (spec §4.3) — an expired-but-valid installed roster loads into degraded mode.
                        warn_if_degraded_grace(&roster);
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(e)) => {
                        tracing::warn!(%e, "installed roster failed to load; refusing roster peers")
                    }
                    Err(e) => tracing::warn!(%e, "join roster load"),
                }
            }
            Err(e) => tracing::warn!(%e, "pinned org_root_pk is invalid; roster mode disabled"),
        }
    }
    // Freshness bootstrap (M3c, spec §4.3 P13): arm the gate's `last_confirmed` from the sidecar.
    //  - present sidecar  → restore the persisted confirmation instant.
    //  - ABSENT sidecar + a roster IS installed → the ONE-TIME UPGRADE GRACE: an M3a/M3b node
    //    upgrading to M3c has no sidecar yet; treat `now` as the confirmation instant and persist it,
    //    so it does NOT instantly degrade to stale on first M3c boot (it re-confirms on its next poll).
    //  - absent sidecar + NO roster → leave `None` (a fresh node arms freshness on its first confirm).
    // Best-effort persist: a write failure leaves the in-RAM arm intact.
    {
        let fpath = roster_confirmed_path(&config_path);
        let fstore = FreshnessStore::new(fpath.clone());
        match tokio::task::spawn_blocking(move || fstore.load()).await {
            Ok(Ok(Some(lc))) => roster.set_last_confirmed(lc),
            Ok(Ok(None)) if roster.view().is_some() => {
                let now = epoch_now_i64();
                roster.set_last_confirmed(now);
                let fstore = FreshnessStore::new(fpath);
                match tokio::task::spawn_blocking(move || fstore.store(now)).await {
                    Ok(Ok(())) => tracing::info!("roster freshness upgrade grace applied"),
                    Ok(Err(e)) => tracing::warn!(%e, "persist roster freshness upgrade grace"),
                    Err(e) => tracing::warn!(%e, "join roster freshness upgrade-grace persist"),
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                tracing::warn!(%e, "read roster freshness sidecar; treating as unconfirmed")
            }
            Err(e) => tracing::warn!(%e, "join roster freshness load"),
        }
    }
    let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));

    // 4. Rate/concurrency limiters (spec §11.2 P7), built once from config and shared across every
    //    backend + (T9) the accept loop. Installed on the mesh AFTER it is built (below).
    let limiters = crate::limits::MeshLimiters::from_config(&cfg.limits);
    // 4b. Service registry + status snapshots from config/store. `run_mesh_connection` shares
    //    one registry across every connection, so wrap it once in `Arc` here.
    let services = Arc::new(build_services_audited(&cfg, &audit, &limiters));
    let service_list = service_infos(&cfg);
    let store_for_list = store.clone();
    let peer_list = tokio::task::spawn_blocking(move || peer_infos(&store_for_list))
        .await
        .context("join peer list")?;

    // 5. Assemble the mesh half, start the daemon's OWN ALPN-dispatch accept loop, and install
    //    its handle for hot-reload. Chicken-egg (the loop needs `mesh`, `mesh.accept_task` needs
    //    the loop's handle): build `mesh` with an empty accept_task, spawn the loop with
    //    `mesh.clone()`, then set the handle. The invite registry starts empty (T5's `invite`
    //    mints into it).
    let invites = Arc::new(LiveInvites::new());
    // The petname we suggest for ourselves in invites + advertise to peers: config override, else the
    // machine hostname (friendly: peers see `jetson`, not `96246d3f`), else the endpoint fingerprint.
    let self_petname = cfg
        .identity
        .petname
        .clone()
        .unwrap_or_else(|| default_self_petname(&our_id));
    // The live-connection registry (M3a T8/T9): threaded into the accept loop's mesh handler
    // (CHECK-register on accept) so a roster install can sever its live sessions (D8). `roster`
    // (the hot-swappable roster gate) + `gate` (the composed gate over it) were built above.
    let conn_registry = Arc::new(ConnRegistry::new());
    // Roster-mode gossip/blob composition (spec §4.3/§10, [RECONCILE-COMPOSE]): spawn iroh-gossip +
    // the roster-blob transport on THIS SAME endpoint, and subscribe the roster topic bootstrapping
    // from the installed roster's device endpoints (the swarm forms as peers arrive — an empty
    // bootstrap is fine). The accept loop's gossip/blob arms dispatch to these handles. A pure-pairing
    // daemon spawns NEITHER (`None`) — no gossip, byte-identical to M2b.
    let (gossip, blobs, roster_topic, presence_topic) =
        compose_roster_transport(&endpoint, &roster, &cfg, roster_mode, &our_id).await;
    let mesh = MeshState::new(
        endpoint,
        gate,
        store,
        invites,
        self_petname,
        config_path,
        roster,
        conn_registry,
        gossip,
        blobs,
        roster_topic,
        presence_topic,
    );
    // Install the process audit sink on the mesh (spec §11.3) BEFORE serving, so the reload sites +
    // trust-event hooks can re-thread/read it.
    mesh.set_audit(audit.clone());
    mesh.set_limits(limiters.clone());
    // Self-sovereign pairing identity (spec §4.2 identity — the adopted device->user binding): load
    // (or mint) this person's UserKey and precompute this daemon's binding over `our_id`, so the
    // pairing handlers PRESENT it and paired peers store a VERIFIED `user_id`. The key path mirrors
    // roster mode's (`[identity].user_key`, else the default), so a roster `join` and pairing share
    // ONE self-sovereign user key/id (DRY). Best-effort: a key error logs + presents nothing (pairing
    // still works, peers store `user_id: None`) rather than failing the daemon.
    let user_key_path = match cfg.identity.user_key.clone() {
        Some(p) => p,
        None => paths::default_user_key_path()?,
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
    // M4a: build the gated per-scope app-blob provider (spec §9) in roster mode and install it on the
    // mesh BEFORE the accept loop starts. Uses the SAME composed trust gate the mesh resolves inbound
    // MCP with, so the request-time scope check keys on the exact authenticated identity. A build
    // failure disables app blobs with a warning (pairing + mesh keep working); a pure-pairing daemon
    // never builds it.
    if roster_mode {
        let scopes_path = paths::default_blob_scopes_path()?;
        match tokio::task::spawn_blocking(move || {
            crate::blobs::scope::ScopeStore::load(scopes_path)
        })
        .await
        {
            Ok(Ok(scopes)) => {
                match crate::blobs::provider::AppBlobs::load(
                    paths::default_blobs_dir()?,
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
            Ok(Err(e)) => tracing::warn!(%e, "app-blob scopes failed to load; provider disabled"),
            Err(e) => tracing::warn!(%e, "join app-blob scopes load"),
        }
    }
    let accept_task = spawn_accept_loop(mesh.clone(), services);
    mesh.set_accept_task(accept_task).await;

    // 5b. Roster mode: spawn the distribution converge loop (spec §4.3) — it pulls `RosterAnnounce`s
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
        let _converge = crate::roster::distribute::spawn_receive_loop(mesh.clone());
    }

    // 5b'. Roster mode: spawn presence (spec §10.1). ADVISORY-ONLY — presence feeds `status` + (T11)
    //      the person→device dial ORDERING; it NEVER touches a gate, an authz check, or a sever
    //      decision (absence of a presence entry never blocks a dial). The TRACK loop records verified
    //      heartbeats (each bound to the roster's authoritative user_id) into `mesh.presence_table`;
    //      the PUBLISH loop beats this node's own device-key-signed heartbeat every ~60s. A pure-pairing
    //      daemon (not roster mode) spawns NEITHER loop. The device SigningKey is the SAME ed25519 key
    //      the endpoint id derives from (`key.secret_bytes()`), so the beat's endpoint_id == our_id and
    //      peers resolve us in their roster. Publish only when this node's own user_id is known (config
    //      `[identity].user_id`, else its roster resolution) — a beat under an unknown user_id would be
    //      self-rejected by every peer's user_id binding, so it is skipped rather than sent as noise.
    if roster_mode {
        let _track = crate::roster::presence::track_loop(mesh.clone());
        let self_user_id = cfg.identity.user_id.clone().or_else(|| {
            mesh.roster
                .view()
                .and_then(|v| v.resolve(our_id.as_bytes()).map(|d| d.user_id.clone()))
        });
        match self_user_id {
            Some(user_id) => {
                let device_key = ed25519_dalek::SigningKey::from_bytes(&key.secret_bytes());
                let _publish =
                    crate::roster::presence::publish_loop(mesh.clone(), device_key, user_id);
            }
            None => tracing::debug!(
                "presence publish skipped: no user_id for this node (track loop still runs)"
            ),
        }
    }

    // M4c: periodic staleness sweep (spec §4.3 P13). The freshness bound denies NEW inbound at
    // `resolve`; this cuts EXISTING roster-authorized sessions once the node crosses
    // `last_confirmed + max_staleness + grace`. Roster mode only; never severs pairing-only sessions.
    if roster_mode {
        let _sweep = spawn_staleness_sweep(mesh.clone());
    }

    // 5c. Roster mode with a pinned `[roster].url`: spawn the HTTPS fallback poll loop (spec §4.3).
    //     It GETs the URL every `poll_interval` AND once at startup, so a joiner gets its FIRST roster
    //     (D5 — a joiner cannot gossip before it holds a roster). A newer served roster converges
    //     through the SAME `install_from_file` path (no second validator); an equal serial CONFIRMS
    //     currency (freshness, T9). Guarded on `roster_mode` (an org root pinned) — a stray url with no
    //     anchor has nothing to converge to. The rustls provider is installed (step 0) before this runs.
    if roster_mode && let Some(url) = cfg.roster.url.clone() {
        // Route through the tracked helper (NOT a bare spawn) so the startup handle lands in
        // `mesh.poll_loop` — a later runtime `set_roster_url` then aborts+replaces it rather than
        // stacking a second loop.
        respawn_poll_loop(&mesh, url).await;
    }

    // 6. The control server on the local endpoint (bound in step 0a), running on the same runtime
    //    as the mesh serve loop.
    let state = Arc::new(DaemonState::with_mesh(
        STACK_VERSION,
        mesh,
        service_list,
        peer_list,
    ));
    // Our own endpoint id is operator-shareable (it is how a peer pairs us) — not a §1.5
    // surface leak (that discipline forbids leaking OTHER peers' ids/paths in porcelain).
    tracing::info!(
        endpoint_id = %our_id,
        socket = %socket.display(),
        "mcpmesh daemon serving mesh + control"
    );
    serve_control(listener, state).await
}

/// Warn — once, at install/load time — when the just-installed roster is serving in DEGRADED-GRACE
/// (past `expires_at` but within the grace window), so serving continues with reduced confidence
/// (spec §4.3 "continues … with warnings"). Rate-limited to once per swap/load by construction: it
/// fires only from the two install/load sites ([`install_roster_view_and_sever`] + the startup load),
/// never per session. DegradedStopped is intentionally NOT warned here — the gate already refuses
/// roster identity outright (a hard stop the operator sees as refusals), whereas DegradedGrace is the
/// silent-degradation case this warning exists to surface. Reads the state against the gate's OWN
/// grace window so the warning and the `resolve` path agree on when a roster is degraded.
fn warn_if_degraded_grace(roster: &RosterGate) {
    // Route through the gate's EFFECTIVE state (expiry OR staleness, spec §4.3 P13) so a roster that is
    // degraded-grace because it is STALE (not just expired) is warned identically. DegradedStopped is
    // intentionally NOT warned here — the gate already refuses roster identity outright.
    if roster.effective_state(epoch_now_i64()) == Some(RosterState::DegradedGrace) {
        tracing::warn!(
            "roster degraded (expired or stale); serving continues for the grace period — \
             re-confirm currency or install a fresh roster"
        );
    }
}

/// Live roster-mode status for `status` (spec §4.4). **Computed LIVE from `mesh.roster.view()` on
/// each call — NOT a cached snapshot (DECLARED):** the roster view is already hot-swapped into the
/// gate on install, so a live read is cheap AND always-current, avoiding the display-only staleness
/// the pairing-grant snapshot path carries. Surface-clean (§1.5): only org_id, serial, a plain state
/// word, and the org-root FINGERPRINT in short words — never raw keys/EndpointIds/roster path.
///
/// Three cases (DECLARED): (1) a roster is installed → the live `state` word. (2) NO roster installed
/// but an org root is PINNED (post-`join`, pre-approval — D5) → `"pending"` with serial 0 + the
/// pinned org-root fingerprint, so `status` shows the anchor immediately after `join`. (3) a
/// pure-pairing daemon (no `org_root_pk` pin at all) → `None`, no roster block (byte-identical to M2b).
///
/// State mapping (DECLARED): `Approved → "approved"`, `DegradedGrace → "degraded"`,
/// `DegradedStopped → "stopped"`; no roster + pinned org → `"pending"`. The word is the gate's OWN
/// [`RosterGate::effective_state`] (expiry ∨ staleness, spec §4.3 P13) — the SAME computation `resolve`
/// decides on — so `status` reflects STALENESS, not just expiry.
///
/// Missing/unparseable pin (DECLARED): the org-root FINGERPRINT is derived from the pinned config
/// `org_root_pk`. If that pin is missing or unparseable (or the config read fails), the fingerprint
/// degrades GRACEFULLY to an empty string — NEVER a panic — and roster status still reports
/// org/serial/state (the render then omits the `org root:` line).
pub(crate) fn roster_status(mesh: &Arc<MeshState>, cfg: Option<&Config>) -> Option<RosterStatus> {
    // `cfg` is the caller's ALREADY-LOADED config (control.rs `status_result` loads it once for the
    // live service list and passes it through — the host polls status, so the double read mattered).
    // `None` models a transient read error, which must not fail `status`: fall back to an empty
    // fingerprint (and the "pending"/None cases below). Only the pinned org-root pk / org_id are
    // read from it — the state word comes from the gate's own `effective_state`.
    // The pinned org-root FINGERPRINT in short words (§4.4 carve-out). Decode the config b64u
    // `org_root_pk` → 32 bytes → fingerprint_words; a missing/unparseable pin → empty (no panic).
    let org_root_fingerprint = cfg
        .and_then(|c| c.identity.org_root_pk.as_deref())
        .and_then(|s| crate::roster::parse_org_root_pk(s).ok())
        .map(|vk| pairing::sas::fingerprint_words(&vk.to_bytes()))
        .unwrap_or_default();
    match mesh.roster.view() {
        Some(view) => {
            // The state word from the gate's OWN `effective_state` (expiry ∨ staleness, spec §4.3 P13)
            // — the SAME computation `resolve` decides on, so `status` reflects staleness, not just
            // expiry. `view` is Some here, so `effective_state` is Some (the `unwrap_or` never fires).
            let state = match mesh
                .roster
                .effective_state(epoch_now_i64())
                .unwrap_or(RosterState::Approved)
            {
                RosterState::Approved => "approved",
                RosterState::DegradedGrace => "degraded",
                RosterState::DegradedStopped => "stopped",
            };
            Some(RosterStatus {
                org_id: view.org_id().to_string(),
                serial: view.serial(),
                state: state.to_string(),
                org_root_fingerprint,
            })
        }
        None => {
            // Post-`join`, pre-approval: a pinned org root but no roster yet (D5) → "pending". A
            // pure-pairing daemon (no `org_root_pk` pin) has nothing to surface → None → no block.
            let cfg = cfg?;
            cfg.identity.org_root_pk.as_deref()?;
            Some(RosterStatus {
                org_id: cfg.identity.org_id.clone().unwrap_or_default(),
                serial: 0,
                state: "pending".to_string(),
                org_root_fingerprint,
            })
        }
    }
}

/// The advisory presence read for `status` (spec §10.1). Enumerates every ACTIVE roster device and
/// joins it with the presence table: display fields (user_id, device_label, role) come from the
/// installed roster; `online` is whether the table holds a LIVE (non-expired) heartbeat for that
/// endpoint (`PresenceTable::active`). ADVISORY-ONLY — a display convenience; NOTHING here authorizes
/// a dial. A device with no heartbeat reports `online: false` yet remains a full dial candidate
/// (absence never removes one). Empty in a pure-pairing daemon / before any roster is installed (the
/// field then serializes away). **Surface-clean (§1.5/§17):** the endpoint_id is used ONLY to join the
/// roster and presence tables — the output carries FLAT vocabulary alone (user_id/device_label/role/
/// online), never an EndpointId/pubkey/hash. Stable display order: by user, primary before mirror,
/// then label.
pub(crate) fn presence_peers(mesh: &Arc<MeshState>) -> Vec<PresencePeer> {
    let Some(view) = mesh.roster.view() else {
        return Vec::new();
    };
    let now = epoch_now_i64();
    let online: std::collections::HashSet<[u8; 32]> = mesh
        .presence_table
        .active(now)
        .into_iter()
        .map(|(eid, _)| eid)
        .collect();
    let mut peers: Vec<PresencePeer> = view
        .devices()
        .map(|(eid, d)| PresencePeer {
            user_id: d.user_id.clone(),
            device_label: d.label.clone(),
            role: d.role.clone(),
            online: online.contains(eid),
        })
        .collect();
    peers.sort_by(|a, b| {
        a.user_id
            .cmp(&b.user_id)
            .then_with(|| dial::dial_role_rank(&a.role).cmp(&dial::dial_role_rank(&b.role)))
            .then_with(|| a.device_label.cmp(&b.device_label))
    });
    peers
}

/// Hot-swap the installed roster view into the live gate AND sever the live mesh connections the
/// new roster invalidates (spec §4.3 rule 6, §4.5 D8). Delegates the per-connection decision to the
/// pure [`mcpmesh_net::should_sever`]: an endpoint is severed iff it is REVOKED (revocation wins, all
/// ALPNs — this cuts a device even when it also holds a stale pair entry, the §16 M3 AC clause), OR
/// it was ROSTER-resolved (`roster_user.is_some()`) and is ABSENT from the new roster's active
/// device set. A pairing-only peer (`roster_user == None`, not revoked) is NEVER severed by a roster
/// install.
///
/// **Ordering — swap-before-sever (the TOCTOU close, T8).** The sever sets are computed from the
/// NEW `view` handle DIRECTLY (never by locking the gate), then the gate view is hot-swapped FIRST,
/// THEN `sever_matching` runs. Swapping first means (a) no NEW session admits the revoked peer, and
/// (b) any connection CHECK-REGISTERING concurrently reads the new view and self-closes; a
/// registration that lands across the swap is caught by the registry's lock-serialized recheck (see
/// the `registry` module doc's three-case argument). Computing the sets from `view` — not the gate —
/// keeps the registry lock in `sever_matching` from ever nesting inside the gate's `RwLock`, so
/// there is no registry↔gate lock cycle. Returns the number of connections severed.
///
/// `pub` so the T9 integration test (`cli/tests/roster_sever.rs`) and the T10 install control both
/// drive the SAME persist→swap→sever pipeline.
pub fn install_roster_view_and_sever(
    mesh: &Arc<MeshState>,
    view: mcpmesh_trust::roster::validate::RosterView,
) -> usize {
    use std::collections::HashSet;
    // Capture the audit fields BEFORE the swap CONSUMES `view` (surface-clean §1.5 target: org/serial
    // only). This is the SINGLE choke point ALL three convergence channels funnel through (manual
    // install_roster + gossip on_announce + URL poll), and it is reached ONLY on a real serial-bumping
    // install — `install_from_file` (and the manual path) return a view ONLY when serial > installed;
    // a stale/equal serial errors BEFORE any swap — so the trust event below fires EXACTLY once per
    // real swap (incl. a joiner's first serial-1 install, a legit trust event).
    let (org_id, serial) = (view.org_id().to_string(), view.serial());
    // Compute the sever sets from the NEW view (no gate lock → no registry↔gate lock cycle).
    let revoked: HashSet<[u8; 32]> = view.revoked_endpoints().copied().collect();
    let active_devices: HashSet<[u8; 32]> = view.device_endpoints().copied().collect();
    // (a) SWAP FIRST: hot-swap the RosterGate view so the composed gate + any concurrent
    //     check-register immediately see the new roster (the other half of the TOCTOU invariant).
    mesh.roster.install(view);
    // Warn (once, on this swap) if the newly-installed roster is already in degraded-grace (spec
    // §4.3): serving continues within the grace window, but the operator should install a fresh one.
    warn_if_degraded_grace(&mesh.roster);
    // (b) THEN sever the already-registered live connections the new roster invalidates.
    let severed = mesh.conn_registry.sever_matching(
        mcpmesh_net::CLOSE_UNAUTHORIZED, // 401 — "no longer authorized"
        b"roster revoked",
        |eid, roster_user| mcpmesh_net::should_sever(eid, roster_user, &revoked, &active_devices),
    );
    // Trust event (spec §11.3 / P14): a roster install/swap — recorded HERE, the shared choke point,
    // so EVERY swap is audited, including the AUTOMATIC gossip/URL convergences a rostered node lives
    // on (which never touch the manual verb). The terminus of org approve/revoke funnels through here
    // too, so the manual path stays audited — once. Surface-clean: org/serial only, NO keys/EndpointIds.
    mesh.audit().record(AuditRecord::trust(
        now_ts(),
        "roster_install".into(),
        Some(format!("{org_id}/{serial}")),
    ));
    severed
}

/// How often the staleness sweep runs (spec §4.3 P13). 60 s mirrors the §14 revocation-propagation
/// target — an existing roster-authorized session is cut within a minute of the node crossing the
/// staleness bound.
const STALENESS_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// The sweep DECISION (pure): sweep iff the gate is effectively `DegradedStopped` (spec §4.3 P13 —
/// expiry OR staleness past grace). `None` (no roster) → never sweep. `Approved`/`DegradedGrace`
/// keep serving. [RECONCILE R3]: this is the time-triggered complement to the register-time gate.
/// `pub` (not `pub(crate)`) so the `staleness_sweep.rs` integration test — a separate crate — drives it.
pub fn should_staleness_sever(state: Option<mcpmesh_trust::roster::validate::RosterState>) -> bool {
    state == Some(mcpmesh_trust::roster::validate::RosterState::DegradedStopped)
}

/// One sweep tick (spec §4.3 P13): when the gate is `DegradedStopped`, sever EXISTING roster-
/// authorized live sessions (`roster_user.is_some()`) — the time-triggered cut the register-time
/// `should_sever_now` cannot make. NEVER severs pairing-only sessions (`roster_user == None`, whose
/// authorization is independent of the org roster) and never runs when the roster is fresh/absent.
/// Returns the number severed. `pub` so the `staleness_sweep.rs` integration test (a separate crate)
/// drives one tick directly.
pub fn staleness_sweep_once(mesh: &Arc<MeshState>, now: i64) -> usize {
    if !should_staleness_sever(mesh.roster.effective_state(now)) {
        return 0;
    }
    mesh.conn_registry.sever_matching(
        mcpmesh_net::CLOSE_UNAUTHORIZED, // 401 — the roster no longer authorizes this session
        b"roster stale",
        |_eid, roster_user| roster_user.is_some(),
    )
}

/// Spawn the periodic staleness sweep (roster mode). Runs for the daemon lifetime; each tick calls
/// [`staleness_sweep_once`] at the current clock.
fn spawn_staleness_sweep(mesh: Arc<MeshState>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(STALENESS_SWEEP_INTERVAL).await;
            let severed = staleness_sweep_once(&mesh, epoch_now_i64());
            if severed > 0 {
                tracing::warn!(
                    severed,
                    "staleness sweep cut roster-authorized sessions (degraded-stopped)"
                );
            }
        }
    })
}

/// Handle a `roster_install` control request (spec §4.3 manual path): resolve the org-root trust
/// anchor, read + FULLY validate the roster file (rules 1–6), persist it atomically, hot-swap the
/// gate, and sever the live sessions it invalidates (D8, via [`install_roster_view_and_sever`]).
///
/// **Pin flow (DECLARED — pin AFTER validation).** An explicit `org_root_pk` is the trust anchor for
/// a FIRST install (or an operator re-pin); once pinned it lives in config, so a subsequent install
/// OMITS it and reads the pinned value. The pin is persisted (`[identity] org_root_pk` + `org_id`)
/// only AFTER `install_from_file` accepts the roster — so a failed install (wrong pk, rollback, an
/// unparseable file) NEVER corrupts the pinned anchor or the on-disk roster. This is a deliberate
/// improvement over the plan's pin-before-validate sketch: the plan's `pin_org_root_pk(mesh, &s)`
/// had no `org_id` to write at pin time (org_id is only known after validation), and re-pinning
/// before a validation that then fails would leave the anchor pointing at a pk the installed roster
/// no longer verifies against. A mismatched pk simply fails validation (the sig won't verify) and
/// leaves everything untouched.
///
/// Path-not-bytes (P12/P14): the same-uid daemon reads the LOCAL file itself — passing a path, not
/// the bytes, is within the trust boundary (the operator obtains the roster + the pk out-of-band,
/// spec §4.4).
pub(crate) async fn install_roster(
    state: &DaemonState,
    path: String,
    org_root_pk: Option<String>,
) -> Result<RosterInstallResult> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    // Serialize the ENTIRE install critical section — installed-serial read → validate → persist →
    // pin → gate hot-swap → sever — under the SAME `reload_lock` that register_service /
    // grant_service_access / revoke_service_access hold around their whole read→write→swap sections
    // (M2b discipline). Without it, two concurrent same-uid `roster_install`s could BOTH read
    // installed_serial = N, BOTH validate N+1 / N+2, and race their writes+swaps → roster.json + the
    // live gate left at the LOWER serial (a non-monotonic lost update). Held until this fn returns.
    //
    // Lock ordering stays acyclic: `reload_lock` is only ever a SOURCE (nothing acquires it while
    // holding another lock). Under it we touch the config write (spawn_blocking), the RosterGate
    // RwLock (`gate.install`, released before the sever), and the ConnRegistry mutex
    // (`sever_matching`, whose sets come from the VIEW — not by reading the gate). `register_checked`
    // takes registry→gate but NEVER `reload_lock`, so there is no back-edge and no cycle. Holding it
    // across the spawn_blocking / sever awaits is fine (tokio Mutex, exactly as register_service).
    let _reload = mesh.reload_lock.lock().await;

    // Resolve the trust anchor: an explicit `org_root_pk` (first install / re-pin), else the pinned
    // config value; error if neither. The pin itself is written AFTER validation succeeds (below).
    let pk_str = match &org_root_pk {
        Some(s) => s.clone(),
        None => mesh_config_org_root_pk(mesh)?
            .context("no org root pinned; pass --org-root-pk on first install")?,
    };
    let pk = crate::roster::parse_org_root_pk(&pk_str)?;
    let rstore = RosterStore::new(paths::default_roster_path()?);
    let now = epoch_now_i64();
    let file = PathBuf::from(path);
    // Read + validate + persist on a blocking thread (fs + verify); returns the resolvable view.
    // A FAILED validation returns Err BEFORE the write, so the on-disk roster is left untouched.
    let view = tokio::task::spawn_blocking(move || rstore.install_from_file(&file, &pk, now))
        .await
        .context("join roster install")??;
    let (org_id, serial) = (view.org_id().to_string(), view.serial());
    // Pin the trust anchor + org_id to config now that the roster validated — only when an explicit
    // pk was provided (a first install or an operator re-pin). Call the lock-free `write_identity_pin`
    // DIRECTLY under the `reload_lock` we ALREADY hold — a nested `reload_lock.lock()` on the
    // non-reentrant tokio Mutex would deadlock. Same order as before: pin AFTER validation, using the
    // validated org_id; a subsequent install that reused the already-pinned value does not rewrite it.
    if org_root_pk.is_some() {
        let config_path = mesh.config_path.clone();
        let (pk_w, oid_w) = (pk_str.clone(), org_id.clone());
        tokio::task::spawn_blocking(move || write_identity_pin(&config_path, &pk_w, &oid_w))
            .await
            .context("join org-root pin config write")??;
        tracing::info!(org_id = %org_id, "pinned org root");
    }
    // Freshness (T9): a manual install is proof of currency — CONFIRM so the live gate's future
    // resolve/should_sever_now decisions treat this node as fresh (arms `last_confirmed` + persists).
    mesh.confirm_roster_current(now).await;
    // Hot-swap the live gate + sever (D8). Runs on the runtime (no blocking; close is non-blocking).
    let severed = install_roster_view_and_sever(mesh, view) as u32;
    // Reconcile config's proposed user_id against the roster's AUTHORITATIVE value ([RECONCILE-D],
    // §4.6) — the SAME shared post-install step the gossip/URL channels run. LOCK-FREE under the
    // `reload_lock` we ALREADY hold (no deadlock — see `reconcile_user_id_from_roster`).
    reconcile_user_id_from_roster(mesh).await;
    tracing::info!(org_id = %org_id, serial, severed, "roster installed");
    // NOTE: the `roster_install` trust event (spec §11.3) is recorded INSIDE
    // `install_roster_view_and_sever` (the shared choke point called above), so the manual path is
    // audited there — once — alongside the gossip/URL convergence paths. No record here.
    // Announce-on-publish (spec §4.3): the operator's serial bump (org approve/revoke terminate here)
    // seeds the new roster into the local blob store + broadcasts a `RosterAnnounce` on the roster
    // topic, so rostered peers converge without waiting for their URL poll. Best-effort — a gossip
    // failure must NOT fail the install (the roster is already persisted + hot-swapped); a
    // pure-pairing daemon (no gossip) no-ops. Runs under the held `reload_lock` (announce does not
    // take it, so no deadlock).
    if let Err(e) = crate::roster::distribute::announce_roster(mesh).await {
        tracing::warn!(%e, "roster announce-on-publish failed (install still applied)");
    }
    Ok(RosterInstallResult {
        org_id,
        serial,
        severed,
    })
}

/// Handle a `blob_publish` control request (spec §9, M4a): add a LOCAL file into a scope on the gated
/// app-blob store, returning the ticket + hash. Requires roster mode (the provider is built only
/// there); a pure-pairing daemon answers a clean error.
pub(crate) async fn blob_publish(
    state: &DaemonState,
    scope: String,
    path: String,
) -> Result<BlobPublishResult> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
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

/// Handle a `blob_grant` control request (spec §9): grant a scope to a principal (single-writer).
pub(crate) async fn blob_grant(
    state: &DaemonState,
    scope: String,
    principal: String,
) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let provider = mesh
        .app_blobs()
        .await
        .context("app-blob provider not enabled (roster mode only)")?;
    provider.grant(&scope, &principal)
}

/// Handle a `blob_list` control request (spec §9): the daemon's scopes (name → hashes + grants).
pub(crate) async fn blob_list(state: &DaemonState) -> Result<BlobScopeList> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
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

/// Handle a `blob_fetch` control request (spec §9): fetch a `mcpmesh/blob/1` ticket THROUGH the daemon
/// (BLAKE3-verified streaming into the gated store) and export the verified blob to `dest_path` (a
/// local file the same-uid daemon writes, P12/P14). Returns the verified hash + byte length.
pub(crate) async fn blob_fetch(
    state: &DaemonState,
    ticket: String,
    dest_path: String,
) -> Result<BlobFetchResult> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
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

/// Read the currently-pinned org-root pubkey (`[identity] org_root_pk`) from config, or `None` when
/// none is pinned. A plain read (no `reload_lock`): `atomic_write` publishes config by rename, so a
/// read can never observe a torn file. Used by [`install_roster`] to resolve the anchor on a
/// subsequent install that OMITS `--org-root-pk`.
pub(crate) fn mesh_config_org_root_pk(mesh: &Arc<MeshState>) -> Result<Option<String>> {
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("read config for org_root_pk: {e}"))?;
    Ok(cfg.identity.org_root_pk)
}

/// The installed-roster path for THIS daemon, derived from `mesh.config_path` (its parent + the
/// canonical `roster.json` name). Production-identical to [`paths::default_roster_path`] — the daemon
/// always runs with `config_path = config_dir()/config.toml`, so the parent is `config_dir()` and
/// this equals `config_dir()/roster.json`. Deriving it from `config_path` (rather than the global
/// path) keeps the gossip/URL install paths per-node in the in-process multi-node integration tests,
/// where two daemons in ONE process must NOT share a single global `roster.json` — and the config
/// read that resolves the trust anchor (`mesh_config_org_root_pk`) already uses the same per-node
/// `config_path`, so the anchor and the roster file always co-locate. **DECLARED** as the one
/// deviation from the plan's literal `paths::default_roster_path()` in `distribute.rs`.
pub(crate) fn installed_roster_path(mesh: &Arc<MeshState>) -> PathBuf {
    mesh.config_path
        .parent()
        .map(|dir| dir.join("roster.json"))
        .unwrap_or_else(|| PathBuf::from("roster.json")) // parentless config_path: never in practice
}

/// The per-node freshness sidecar path (spec §4.3 P13), derived from `config_path` (sibling
/// `roster.confirmed`) exactly as [`installed_roster_path`] derives `roster.json` — so the sidecar
/// co-locates with the installed roster and stays per-node in the in-process multi-daemon integration
/// tests. Production-identical to [`paths::default_roster_confirmed_path`] (the daemon runs with
/// `config_path = config_dir()/config.toml`). Takes `&Path` (not `&Arc<MeshState>`) so the `&self`
/// [`MeshState::confirm_roster_current`] and the startup bootstrap can both call it.
fn roster_confirmed_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(|dir| dir.join("roster.confirmed"))
        .unwrap_or_else(|| PathBuf::from("roster.confirmed")) // parentless: never in practice
}

/// Reconcile the daemon's config `[identity].user_id` against the just-installed roster
/// ([RECONCILE-D], spec §4.6). **The roster is AUTHORITATIVE for a device's user_id:** config's
/// `[identity].user_id` was a best-effort join-time PROPOSAL, and the roster's assignment for THIS
/// device's endpoint WINS. Resolve our own endpoint id in `mesh.roster.view()`; if the roster
/// assigns it a user_id that DIFFERS from config's, surgically rewrite config to the roster value —
/// NEVER the reverse (config never overwrites the roster). Two no-op cases: the roster resolves our
/// endpoint to the SAME user_id (nothing to change), OR this device is ABSENT from the roster (the
/// view is `None`, or `resolve` returns `None`) — config is left untouched (still pending), no write.
///
/// **Own endpoint id.** `mesh.endpoint.id()` is the ed25519 pubkey the endpoint is seeded from — the
/// SAME value a roster device record names (the daemon's own `our_id`; reused rather than recomputed
/// from the device key). We look it up directly in the installed view.
///
/// **Locking (DECLARED — LOCK-FREE under the held `reload_lock`).** Every caller runs this UNDER the
/// `mesh.reload_lock` it already holds — the manual [`install_roster`] and the gossip
/// [`on_announce`](crate::roster::distribute) / URL [`poll_roster_url_once`](crate::roster::distribute)
/// install paths — the SAME single-writer critical section the install itself uses. So it calls the
/// LOCK-FREE [`write_identity_user_id`] DIRECTLY (a nested `reload_lock.lock()` on the non-reentrant
/// tokio Mutex would DEADLOCK), EXACTLY as `install_roster` calls the lock-free `write_identity_pin`
/// under the same held lock. The config write runs on a blocking worker (the fs house rule).
///
/// Runs on EVERY roster install (all three channels share this post-install helper), so a roster
/// arriving by ANY channel reconciles + (via the live `roster_status`) flips pending → approved.
pub(crate) async fn reconcile_user_id_from_roster(mesh: &Arc<MeshState>) {
    // Resolve OUR own endpoint in the just-installed view. Absent (view None, or not in the roster) →
    // leave config untouched (still pending): no write.
    let our_id = mesh.endpoint.id();
    let Some(roster_user_id) = mesh
        .roster
        .view()
        .and_then(|v| v.resolve(our_id.as_bytes()).map(|d| d.user_id.clone()))
    else {
        return;
    };
    // The roster is authoritative: only WRITE when its value DIFFERS from config's proposal (a match
    // — or an unreadable config, treated as no proposal to overwrite — is a no-op).
    let config_path = mesh.config_path.clone();
    let proposed = Config::load(&config_path)
        .ok()
        .and_then(|c| c.identity.user_id);
    if proposed.as_deref() == Some(roster_user_id.as_str()) {
        return;
    }
    // Rewrite config to the ROSTER's authoritative value. LOCK-FREE writer under the caller's HELD
    // `reload_lock` (see the doc note — a nested lock would deadlock); on a blocking worker.
    let uid = roster_user_id.clone();
    match tokio::task::spawn_blocking(move || write_identity_user_id(&config_path, &uid)).await {
        Ok(Ok(())) => {
            tracing::info!(user_id = %roster_user_id, "reconciled config user_id from the authoritative roster")
        }
        Ok(Err(e)) => tracing::warn!(%e, "reconcile config user_id write failed"),
        Err(e) => tracing::warn!(%e, "join reconcile config user_id write"),
    }
}

/// Write roster BYTES to a unique temp file so [`RosterStore::install_from_file`] — the SINGLE
/// convergence path (validate rules 1–6 → persist) — can judge them. The gossip/URL channels fetch
/// bytes, but the install path takes a PATH (P12/P14: the same-uid daemon reads its own local file);
/// this bridges the two. The caller removes the temp file after the install. A per-call-unique name
/// (pid + seq — §13 "no fixed temp name"); the file is only ever READ by `install_from_file`.
pub(crate) fn write_temp_roster(bytes: &[u8]) -> Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "mcpmesh-roster-in.{}.{}.json",
        std::process::id(),
        seq
    ));
    let mut f =
        File::create(&path).with_context(|| format!("create temp roster {}", path.display()))?;
    f.write_all(bytes).context("write temp roster")?;
    f.sync_all().context("sync temp roster")?;
    Ok(path)
}

/// Handle an `org_join` control request (spec §4.4 step 2): pin the org root + user key in config so
/// `status` shows the pinned fingerprint and the eventual roster install (M3c) has its trust anchor.
/// No roster is installed (D5); the gate stays empty until serial N+1 arrives. Serialized under
/// `mesh.reload_lock` (the same config-write discipline as `register_service` / `install_roster`).
///
/// The pinned pk is parse-validated BEFORE the write (a garbage anchor must NOT land in config);
/// `user_key` is a LOCAL path (the key never crosses the API).
pub(crate) async fn org_join(
    state: &DaemonState,
    org_id: String,
    org_root_pk: String,
    user_id: String,
    user_key: String,
) -> Result<OrgJoinResult> {
    // Validate the pinned pk parses BEFORE writing (a garbage anchor must not land in config).
    crate::roster::parse_org_root_pk(&org_root_pk)?;
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let _reload = mesh.reload_lock.lock().await;
    let config_path = mesh.config_path.clone();
    let (oid, pk, uid, uk) = (org_id.clone(), org_root_pk, user_id, user_key);
    tokio::task::spawn_blocking(move || write_join_pin(&config_path, &oid, &pk, &uid, &uk))
        .await
        .context("join org-root pin config write")??;
    tracing::info!(org_id = %org_id, "pinned org root (join)");
    Ok(OrgJoinResult { org_id })
}

/// Handle a `set_roster_url` control request (spec §4.3 M3c): pin `[roster].url` in config AND, when
/// this node is in roster mode, (re)start the HTTPS poll loop AT RUNTIME so polling begins WITHOUT a
/// daemon restart. Written by `org create --roster-url` (the operator keeps the URL current) and by
/// `join` when the org invite carries one — the joiner's FIRST-roster bootstrap (D5).
///
/// **Runtime poll (re)start — the D5 fix (DECLARED).** `join` runs against an ALREADY-RUNNING daemon
/// that started pure-pairing (its step-5c poll spawn keyed on the STARTUP `roster_mode` snapshot).
/// The preceding `OrgJoin` pins `org_root_pk`, so once THIS write lands the LIVE config is in roster
/// mode. `poll_roster_url_once` reads the org anchor from config LIVE and is pure outbound HTTPS +
/// gate hot-swap (no endpoint/ALPN changes), so a runtime [`respawn_poll_loop`] genuinely starts
/// fetching — a fresh joiner installs its first roster autonomously (no human restart). The respawn
/// aborts+replaces any prior loop, so this is idempotent (repeated calls / a URL change never stack
/// loops). The operator's self-poll of its own URL is benign (equal-serial → confirm; a not-yet-hosted
/// URL → a logged Err retried next interval; a stale serial → `StaleSerial` skip — never a downgrade).
///
/// The config write is serialized under `mesh.reload_lock` (the SAME single-writer discipline as
/// `org_join` / `install_roster` / `register_service`); the respawn runs AFTER the write is durable and
/// takes only the short-lived `poll_loop` lock. The URL value is NOT logged (out of the trace surface).
pub(crate) async fn set_roster_url(state: &DaemonState, url: String) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let _reload = mesh.reload_lock.lock().await;
    let config_path = mesh.config_path.clone();
    let url_w = url.clone();
    tokio::task::spawn_blocking(move || write_roster_url(&config_path, &url_w))
        .await
        .context("roster-url config write")??;
    tracing::info!("pinned roster url");
    // Roster mode (an org root is pinned in the LIVE config — the `OrgJoin` before this write set it
    // on a joiner, or `org create` on an operator): (re)start the poll loop NOW so a runtime join
    // bootstraps its first roster without a restart (D5). Read live: a transient config-read error
    // just skips the runtime start (the next daemon start's step 5c picks it up), never fails the write.
    if Config::load(&mesh.config_path)
        .map(|c| c.identity.org_root_pk.is_some())
        .unwrap_or(false)
    {
        respawn_poll_loop(mesh, url).await;
        tracing::info!("roster URL poll loop (re)started");
    }
    Ok(())
}

/// How this daemon's endpoint resolves peer addresses (spec §10.3): the n0 defaults
/// (pkarr publish + DNS lookup against n0's servers — what `presets::N0` wires), or
/// self-hosted pkarr relay URLs used for BOTH publish and resolve (`discovery_mode =
/// "custom"` + `discovery_urls`).
#[derive(Debug)]
pub(crate) enum DiscoveryPlan {
    N0,
    Custom(Vec<url::Url>),
}

/// The validated `[network]` posture (spec §10.3/§12) — the SINGLE truth `build_endpoint`
/// binds and `doctor` reports on. `Hermetic` (`relay_mode = "disabled"`) is no relay AND no
/// discovery — the localhost/tests mode, byte-identical to the pre-D2 behavior.
#[derive(Debug)]
pub(crate) enum NetPlan {
    Hermetic,
    Mesh {
        relay: iroh::RelayMode,
        discovery: DiscoveryPlan,
    },
}

/// Validate `[network]` into a [`NetPlan`]. Pure (parses, never binds) so config tests and
/// `doctor` share it. Unknown modes and a `"custom"` without URLs are ERRORS, never a silent
/// fallback to public infrastructure — a metadata-privacy knob that quietly reverts to n0
/// defaults would be worse than none (§10.3).
pub(crate) fn net_plan(net: &crate::config::NetworkCfg) -> Result<NetPlan> {
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

/// Build the Iroh endpoint advertising the mcpmesh/mcp/1 (mesh) + mcpmesh/pair/1 (pairing) ALPNs (spec
/// §7.1) — the accept loop dispatches each inbound connection by whichever one negotiated. In ROSTER
/// mode (`roster_mode == true`, an org root pinned) it ALSO advertises the gossip + blob ALPNs (spec
/// §4.3/§10) so the roster/presence distribution + roster-blob transport share this ONE endpoint
/// ([RECONCILE-COMPOSE]). A pure-pairing daemon (`roster_mode == false`) advertises EXACTLY mcp/1 +
/// pair/1 — byte-identical to M2b ([Important] 1, the roster-None parity fix).
///
/// The `[network]` posture comes from [`net_plan`] (spec §10.3):
/// - Hermetic (`relay_mode = "disabled"`): `presets::Minimal` + `RelayMode::Disabled` — a
///   localhost-only endpoint, no relay, no discovery (hermetic tests).
/// - n0-default discovery: `presets::N0` (pkarr publish + DNS lookup + n0 relays), with the
///   relay map overridden to the operator's `relay_urls` when `relay_mode = "custom"`.
/// - Custom discovery (`discovery_urls`): `presets::Minimal` plus a `PkarrPublisher` AND a
///   `PkarrResolver` per URL — publish and resolve BOTH go to the self-hosted pkarr relay(s),
///   never to n0 (a half-private discovery setup would defeat §10.3's point).
///
/// [RECONCILE — SETTLED against iroh 1.0.1: `Builder::alpns(Vec<Vec<u8>>)` advertises MULTIPLE
/// ALPNs on one endpoint; `Endpoint::builder(preset)`, `.secret_key()`, `.relay_mode()`,
/// `.address_lookup()`, `.bind()` per the pinned crate; `RelayMode::custom(urls)` builds the
/// custom `RelayMap`; all preset paths yield the same `Builder` type.]
async fn build_endpoint(
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

/// Compose the roster-mode gossip/blob transport on the daemon's ONE endpoint (spec §4.3/§10,
/// [RECONCILE-COMPOSE]). In roster mode, spawns iroh-gossip + the roster-blob transport and
/// subscribes the roster topic (derived from the org_id — config's pinned value, else the loaded
/// roster view's), bootstrapping from the installed roster's OTHER device endpoints (the swarm forms
/// as peers arrive — an empty bootstrap is fine, [`subscribe`] does not block). Returns
/// `(None, None, None)` for a pure-pairing daemon (no gossip spawned, byte-identical to M2b), or —
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
    // and presence topics bootstrap from the SAME peer set (§4.3/§10.1) — the swarm forms as peers
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
    // The presence topic (spec §10.1) — reuse `transport::presence_topic_bytes` (T1); same org_id +
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

/// The shared D8 gate + CHECK-register for the roster-mode ALPN accept arms (gossip, roster-blob,
/// app-blob): resolve the remote against the composed trust gate — an unresolved peer is refused
/// 401 — then `register_checked` the connection so a revocation/roster-drop severs it live
/// (`should_sever_now`, T4). Returns the RAII registration the arm holds for the connection's
/// lifetime, or `None` AFTER closing the connection (the arm just returns). Extracting this keeps
/// the D8 discipline in exactly ONE place across ALL gated ALPNs.
///
/// The D8 sever discriminator is ROSTER membership (`gate.roster_user`, `None` for pairing),
/// captured at resolve time — NOT `identity.user_id`, which a paired peer also carries.
///
/// `blob_conn_limit` (the app-blob arm only): the per-endpoint app-blob connection rate-limit
/// (spec §9, the M4a-deferred DoS bound). Consulted AFTER resolve so ONLY AUTHENTICATED endpoints
/// allocate a bucket — a stranger was already refused above (SECURITY invariant 4: strangers stay
/// cheap, no allocation, no make_room work) — and BEFORE the registry insert. The real threat is a
/// valid roster member with no scope grant (a STABLE roster id) churning blob connections whose
/// GETs are denied. FAIL-SAFE: over-limit → close (the accept-time 401 + request-time Permission
/// gates are unchanged; this only bounds connection churn).
fn gate_and_register(
    mesh: &Arc<MeshState>,
    conn: &iroh::endpoint::Connection,
    blob_conn_limit: bool,
) -> Option<mcpmesh_net::registry::Registration> {
    let remote = *conn.remote_id().as_bytes();
    if mesh.gate.resolve(&remote).is_none() {
        conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
        return None;
    }
    if blob_conn_limit && !mesh.limits().admit_blob_conn(&remote) {
        conn.close(0u32.into(), b"blob rate limited");
        return None;
    }
    let roster_user = mesh.gate.roster_user(&remote);
    let registration = mesh
        .conn_registry
        .register_checked(conn, roster_user.clone(), |eid| {
            mesh.gate.should_sever_now(eid, roster_user.as_deref())
        });
    if registration.is_none() {
        conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
    }
    registration
}

/// Spawn the daemon's own ALPN-dispatch accept loop on `endpoint`, returning its task handle.
///
/// The daemon runs THIS instead of [`mcpmesh_net::serve`] so it can route each accepted
/// connection by its negotiated ALPN (spec §7.1): `mcpmesh/mcp/1` goes through net's gated
/// per-connection handler [`run_mesh_connection`]; `mcpmesh/pair/1` goes to the pairing
/// rendezvous — GATE-EXEMPT (D8 exception), authenticated by the invite secret, NOT the trust
/// gate (that is precisely why the mesh-only `serve` is not enough). An unknown ALPN is closed
/// cleanly.
///
/// Both the initial start ([`serve_forever`]) and the hot-reload swap ([`reload_accept_loop`],
/// shared by `register_service` and the pairing `grant_service_access`) call this ONE function,
/// so the loop is defined in exactly one place; the reload path aborts the returned handle and
/// spawns a fresh loop carrying the rebuilt `services`.
///
/// Takes `Arc<MeshState>` (not the individual parts): the `mcpmesh/mcp/1` branch reads
/// `mesh.gate`; the `mcpmesh/pair/1` branch hands the WHOLE `mesh` to the rendezvous, which needs
/// `mesh.invites` + `mesh.store` to redeem AND the grant/reload machinery on `mesh` to authorize
/// the paired peer (M2b T6). Only `services` is passed alongside because a hot-reload swaps the
/// registry without rebuilding the rest of the mesh.
///
/// `pub` (like [`build_services`]) so integration tests can drive the SAME accept loop the daemon
/// runs against in-process endpoints, proving mesh vs. pair ALPN routing.
pub fn spawn_accept_loop(mesh: Arc<MeshState>, services: Arc<Services>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = mesh.endpoint.accept().await {
            let (mesh, services) = (mesh.clone(), services.clone());
            tokio::spawn(async move {
                // M2a inbound-handshake discipline (preserved from net's `serve`): a failed
                // handshake drops the connection. The handshake ERROR is logged at debug (a
                // transport/TLS/ALPN-negotiation error — the handshake never completed, so it
                // carries NO peer identity; logging `%e` is thus no surface leak, spec §1.5)
                // and will help debug pairing dials in T5-T8.
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::debug!(%e, "inbound handshake failed");
                        return;
                    }
                };
                // iroh 1.0.1 [RECONCILE — verified]: on an accepted
                // `Connection<HandshakeCompleted>`, `alpn() -> &[u8]` returns the negotiated
                // ALPN (NOT `Option<Vec<u8>>` — that form exists only on the 0-RTT states).
                // Copy it out so `conn` is free to move into the selected handler.
                let alpn = conn.alpn().to_vec();
                match alpn.as_slice() {
                    a if a == ALPN_MCP => {
                        run_mesh_connection(
                            conn,
                            mesh.gate.clone(),
                            services,
                            mesh.conn_registry.clone(),
                        )
                        .await;
                    }
                    a if a == ALPN_PAIR => {
                        // Live-invite accept-gate (spec §7.1/§4.2/D8: the pair rendezvous is only
                        // "open" while an invite is live). iroh can't cheaply toggle an advertised
                        // ALPN on a live endpoint, so the pair ALPN stays advertised and we realize
                        // the windowed-listener semantics HERE — a dial with NO outstanding invite
                        // is closed immediately (no bi-stream, no hello, no handler task spawned to
                        // consume). `count()` is advisory (any-invite-live, coarse): if another
                        // conn burns the last invite first, this one still reaches `try_redeem` and
                        // gets `Unknown` → refused — so per-invite expiry/burn stays authoritative
                        // there, and this is a cheap front-door close, not the security boundary.
                        if mesh.invites.count() == 0 {
                            conn.close(0u32.into(), b"no pairing in progress");
                            return;
                        }
                        // Per-connection rate-limit of the by-design-open pair ALPN (spec §7.1/§4.2,
                        // the M2b-deferred bound). A SINGLE global bucket — the pair ALPN accepts
                        // strangers who pick fresh ids, so a per-endpoint map would be defeated by
                        // fresh ids. Placed AFTER the no-invite fast-close so it bounds only the
                        // attempts that would proceed to the (more expensive) rendezvous while an
                        // invite is live. FAIL-SAFE: over-rate → close (a client retries as tokens
                        // refill). NOT the removed per-invite attempt cap; the 32-byte secret is the
                        // security.
                        if !mesh.limits().admit_pair_accept() {
                            conn.close(0u32.into(), b"pair rate limited");
                            return;
                        }
                        // T5/T6: real inviter-side rendezvous. It gets the whole `mesh` so a
                        // successful pair can also GRANT service access (config-append + reload)
                        // via `grant_service_access`. The error is a transport/protocol error (a
                        // malformed hello, a dropped stream) or a grant failure — it carries NO
                        // peer identity, so `%e` is no surface leak (spec §1.5). Logged at debug.
                        if let Err(e) =
                            pairing::rendezvous::handle_inviter_side(conn, mesh.clone()).await
                        {
                            tracing::debug!(%e, "pair rendezvous error");
                        }
                    }
                    a if a == ALPN_PING => {
                        // Reachability pong (pairing-mode liveness) — TRUST-GATED: only pong to a
                        // resolvable (paired) peer, so an unpaired scanner's dial is closed with NO
                        // pong and learns nothing (no presence leak, spec §1.5). THIS gate is the
                        // security boundary of the probe (mirrors the `gate.resolve` refusal in
                        // `gate_and_register`). The EndpointId is not logged (surface-leak discipline).
                        let remote = *conn.remote_id().as_bytes();
                        if mesh.gate.resolve(&remote).is_none() {
                            conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
                            return;
                        }
                        // The dialer opens the bi-stream and sends one ping frame (which is what
                        // makes `accept_bi` resolve — a silent QUIC stream is invisible to the peer);
                        // we ignore its content and write the single pong. `finish()` + `stopped()`
                        // ensure the pong is ACKed before `conn` drops (the pairing `send_reply`
                        // discipline — a bare drop could preempt the un-acked reply).
                        if let Ok((mut send, _recv)) = conn.accept_bi().await {
                            let pong = serde_json::json!({ "stack_version": STACK_VERSION });
                            if write_frame(&mut send, &pong).await.is_ok() {
                                let _ = send.finish();
                                let _ = send.stopped().await;
                            }
                        }
                    }
                    a if a == crate::roster::transport::GOSSIP_ALPN => {
                        // Roster/presence gossip (spec §4.3/§10, roster mode only). Gate + register
                        // via [`gate_and_register`] (the shared D8 discipline: unresolved → 401,
                        // revocation/roster-drop severs live gossip connections too); only THEN is
                        // the connection handed to the gossip `ProtocolHandler`. A pure-pairing
                        // daemon never advertised this ALPN → `gossip` is `None` → close.
                        let Some(gossip) = mesh.gossip.clone() else {
                            conn.close(0u32.into(), b"gossip not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, false) else {
                            return;
                        };
                        if let Err(e) = iroh::protocol::ProtocolHandler::accept(&gossip, conn).await
                        {
                            tracing::debug!(%e, "gossip accept error");
                        }
                    }
                    a if a == crate::roster::transport::BLOB_ALPN => {
                        // Roster-blob provider (spec §4.3/§9 — the signed roster document only; ungated per
                        // scope, that is M4). The [`gate_and_register`] D8 gate on THIS arm is the access
                        // boundary — same gate + register + hand-off as the gossip arm, so a revocation
                        // severs blob connections too. `None` blobs (pure-pairing) → close.
                        let Some(blobs) = mesh.blobs.clone() else {
                            conn.close(0u32.into(), b"blobs not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, false) else {
                            return;
                        };
                        let blob_proto = blobs.protocol();
                        if let Err(e) =
                            iroh::protocol::ProtocolHandler::accept(&blob_proto, conn).await
                        {
                            tracing::debug!(%e, "blob accept error");
                        }
                    }
                    a if a == crate::blobs::APP_BLOB_ALPN => {
                        // The GATED per-scope app-blob provider (spec §9, M4a). TWO-LAYER D7/D8:
                        // (1) ACCEPT-TIME gate — the SAME [`gate_and_register`] resolve → 401 +
                        //     register_checked/should_sever_now as the roster BLOB_ALPN arm — PLUS
                        //     the per-endpoint connection rate-limit (`blob_conn_limit`, see the
                        //     helper doc): a revoked/unknown endpoint gets nothing regardless of the
                        //     ticket/hash it holds, and a revocation severs live app-blob
                        //     connections too.
                        // (2) REQUEST-TIME gate — inside the provider's Intercept drain loop (Task 3):
                        //     a valid-but-ungranted caller is refused with Permission before any bytes.
                        // `None` app_blobs (pure-pairing / build failed) → close cleanly.
                        let Some(app_blobs) = mesh.app_blobs().await else {
                            conn.close(0u32.into(), b"app blobs not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, true) else {
                            return;
                        };
                        let blob_proto = app_blobs.protocol();
                        if let Err(e) =
                            iroh::protocol::ProtocolHandler::accept(&blob_proto, conn).await
                        {
                            tracing::debug!(%e, "app-blob accept error");
                        }
                    }
                    // An endpoint we never advertised should be unreachable (ALPN negotiation
                    // rejects it at handshake), but close defensively rather than hang.
                    _ => conn.close(0u32.into(), b"unknown alpn"),
                }
            });
        }
    })
}

/// Abort the running accept loop and spawn a fresh one on the same endpoint carrying the
/// rebuilt `services`. Shared by [`register_service`] and [`grant_service_access`] so the
/// abort/respawn discipline lives in exactly ONE place (DRY). The CALLER holds
/// `mesh.reload_lock` for the whole config→reload→swap section; this helper only takes the
/// short-lived `accept_task` lock for the swap itself.
async fn reload_accept_loop(mesh: &Arc<MeshState>, services: Services) {
    let mut guard = mesh.accept_task.lock().await;
    if let Some(old) = guard.take() {
        old.abort();
    }
    *guard = Some(spawn_accept_loop(mesh.clone(), Arc::new(services)));
}

// ───────────────────────────── reachability probe (pairing-mode liveness) ─────────────────────

/// One cached reachability probe result (spec: pairing-mode liveness). Ephemeral, in-memory —
/// stored in [`MeshState::reachability`], keyed by endpoint-id. `probed_at` is epoch seconds.
#[derive(Clone)]
pub struct ReachEntry {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
    pub probed_at: i64,
}

/// Advisory reachability TTL: a cache entry older than this is refreshed by a NON-BLOCKING
/// background probe on the next [`reachability_of`] read.
pub const REACH_TTL_SECS: i64 = 20;

/// The reachability probe's hard deadline — a peer that has not ponged within this window is
/// reported unreachable. No retries/backoff/persistence (YAGNI); reachable ⇔ a pong in time.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe one peer over [`ALPN_PING`] and cache the result. Dials the peer BY ID (an id-only
/// [`iroh::EndpointAddr`], exactly like `dial::dial_service`'s §10.2 fallback — discovery resolves
/// the address from the id; hermetic localhost tests seed a `MemoryLookup`), sends one ping frame,
/// reads the pong, and measures RTT (dial + round-trip). Writes the outcome into the in-memory
/// [`MeshState::reachability`] cache and returns it. Reachable ⇔ a pong arrived within
/// [`PROBE_TIMEOUT`]; a gate refusal (no pong) or any dial/IO failure is a clean `reachable:false`.
pub async fn probe_peer(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> ReachEntry {
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(PROBE_TIMEOUT, probe_once(mesh, endpoint_id)).await;
    let reachable = matches!(outcome, Ok(Ok(())));
    let entry = ReachEntry {
        reachable,
        rtt_ms: reachable.then(|| started.elapsed().as_millis() as u64),
        probed_at: epoch_now_i64(),
    };
    mesh.reachability
        .lock()
        .expect("reachability lock not poisoned")
        .insert(endpoint_id, entry.clone());
    entry
}

/// The dial → ping → pong half of [`probe_peer`], separated so the whole exchange is one timeout
/// unit. Reuses the real iroh 1.0.1 call shapes from `dial.rs`/`pairing::rendezvous`
/// (`endpoint.connect`, `open_bi`, `write_frame`, `finish`, a framed read).
async fn probe_once(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> Result<()> {
    let id = iroh::EndpointId::from_bytes(&endpoint_id)
        .map_err(|e| anyhow::anyhow!("invalid endpoint id: {e}"))?;
    let addr = iroh::EndpointAddr::from(id);
    let conn = mesh.endpoint.connect(addr, ALPN_PING).await?;
    // We open the bi-stream and send one ping frame — the write is what makes the responder's
    // `accept_bi` resolve (a silent QUIC stream is invisible to the peer). We say nothing
    // meaningful; the responder speaks the pong. `finish()` closes our (empty) send direction.
    let (mut send, recv) = conn.open_bi().await?;
    write_frame(&mut send, &serde_json::json!({ "ping": true })).await?;
    let _ = send.finish();
    let mut reader = FrameReader::new(
        tokio::io::BufReader::new(recv),
        mcpmesh_net::framing::MAX_FRAME_BYTES,
    );
    match reader.next().await? {
        Some(Inbound::Frame(_)) => Ok(()), // any well-formed pong frame ⇒ reachable
        _ => anyhow::bail!("no pong from peer"),
    }
}

/// Build the `status` reachability list from the probe cache, and fire a NON-BLOCKING background
/// refresh for any paired peer whose cache entry is missing or older than [`REACH_TTL_SECS`].
/// NEVER blocks the caller on a probe: it returns the current cached view immediately and each
/// refresh runs as its own spawned task (parallel probes, no join helper / new dependency needed —
/// each `probe_peer` writes its own cache entry, read by the NEXT call).
///
/// §1.5 surface discipline: the cache is keyed by endpoint-id INTERNALLY, but every returned
/// [`mcpmesh_local_api::PeerReachability`] carries only the peer's PETNAME — never the endpoint-id.
pub fn reachability_of(mesh: &Arc<MeshState>) -> Vec<mcpmesh_local_api::PeerReachability> {
    let now = epoch_now_i64();
    // (petname, endpoint_id) for every paired peer — reuse the allowlist store's peer scan
    // (fail-open: a corrupt row is skipped, not fatal). The store IS the paired-peer set.
    let peers: Vec<(String, [u8; 32])> = mesh
        .store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.petname, e.endpoint_id))
        .collect();
    let cache = mesh
        .reachability
        .lock()
        .expect("reachability lock not poisoned")
        .clone();
    let mut stale: Vec<[u8; 32]> = Vec::new();
    let mut out = Vec::with_capacity(peers.len());
    for (petname, eid) in peers {
        match cache.get(&eid) {
            Some(e) => {
                let age = (now - e.probed_at).max(0);
                if age > REACH_TTL_SECS {
                    stale.push(eid);
                }
                out.push(mcpmesh_local_api::PeerReachability {
                    name: petname,
                    reachable: e.reachable,
                    rtt_ms: e.rtt_ms,
                    age_secs: Some(age as u64),
                });
            }
            None => {
                stale.push(eid);
                out.push(mcpmesh_local_api::PeerReachability {
                    name: petname,
                    reachable: false,
                    rtt_ms: None,
                    age_secs: None, // never probed → consumer shows "checking…"
                });
            }
        }
    }
    // KNOWN, BOUNDED v1 TRADEOFF: no in-flight dedup here. Rapid `status` polls against a DOWN
    // peer can spawn a few OVERLAPPING probes in the ~`PROBE_TIMEOUT` window before the first
    // result lands and writes `probed_at`. This is deliberately not guarded (no dedup set — YAGNI
    // for v1): each probe is cheap, self-limits once its result is cached, and the overlap is
    // bounded by `PROBE_TIMEOUT` (the probe's hard deadline) and `REACH_TTL_SECS` (which quiets
    // refreshes once a fresh entry exists). Revisit only if probe cost or poll rate ever makes the
    // transient overlap matter.
    for eid in stale {
        let mesh = mesh.clone();
        tokio::spawn(async move {
            probe_peer(&mesh, eid).await;
        });
    }
    out
}

/// Reload the config from disk and hot-swap the accept loop with services rebuilt from it — the
/// shared read→rebuild→swap tail of every config-mutating control verb ([`register_service`],
/// [`rename_peer`], [`grant_service_access`], [`revoke_service_access`]). `why` names the mutation
/// for the reload error (`"reload config after {why}: …"`). The CALLER holds `mesh.reload_lock`
/// around its whole critical section; this helper takes no lock beyond [`reload_accept_loop`]'s
/// short-lived `accept_task` swap. Returns the reloaded `Config` so a caller that also refreshes
/// its status snapshot ([`register_service`]) does not read the file twice.
async fn reload_services_from_disk(mesh: &Arc<MeshState>, why: &str) -> Result<Config> {
    let cfg = Config::load(&mesh.config_path)
        .map_err(|e| anyhow::anyhow!("reload config after {why}: {e}"))?;
    reload_accept_loop(
        mesh,
        build_services_audited(&cfg, &mesh.audit(), &mesh.limits()),
    )
    .await;
    Ok(cfg)
}

/// (Re)start the HTTPS roster-poll loop (spec §4.3 M3c), ABORTING any prior one first so repeated
/// calls never STACK duplicate loops (the idempotency guard) and a URL CHANGE cleanly replaces the
/// old loop. Called from TWO sites onto the SAME tracked `mesh.poll_loop` handle: (1) `serve_forever`
/// step 5c at startup (roster mode with a pinned URL), and (2) `set_roster_url` at RUNTIME — so a
/// joiner that pins `[roster].url` on an already-running daemon starts polling IMMEDIATELY (its D5
/// first-roster bootstrap) rather than waiting for a restart. Reads the poll interval from the LIVE
/// config (default hourly on any read/parse error). The freshly spawned loop does an immediate startup
/// poll (so the first roster arrives at once) then loops on the interval. Takes only the short-lived
/// `poll_loop` lock for the swap (never `reload_lock`, so no lock-order coupling with the config write
/// that precedes it in `set_roster_url`).
pub(crate) async fn respawn_poll_loop(mesh: &Arc<MeshState>, url: String) {
    let interval = Config::load(&mesh.config_path)
        .map(|c| c.roster.poll_interval_seconds())
        .unwrap_or(3600);
    let mut guard = mesh.poll_loop.lock().await;
    if let Some(old) = guard.take() {
        old.abort();
    }
    *guard = Some(crate::roster::distribute::spawn_poll_loop(
        mesh.clone(),
        url,
        interval,
    ));
}

/// Build the M1 `Services` registry from config `[services.*]`: a `run` service becomes a
/// [`SpawnBackend`] (its own concurrency semaphore), a `socket` service a [`SocketBackend`].
/// Backends carry NO identity — that is threaded per-caller through `SessionBackend::run`
/// (the injected identity is per-session, the backend is shared). A malformed service (both
/// or neither backend kind) is logged and skipped rather than failing the whole daemon.
///
/// `pub` so the Task 9 integration test can compose the SAME registry wiring the daemon uses
/// against an in-process endpoint (the daemon's own `run()` is a subprocess; the test drives
/// the composition directly to prove config → services → gate → backend → env injection).
pub fn build_services(cfg: &Config) -> Services {
    build_services_audited(
        cfg,
        &AuditSink::disabled(),
        &crate::limits::MeshLimiters::unlimited(),
    )
}

/// Build the service registry, giving every backend its service NAME, the audit sink (spec §11.3),
/// and the shared per-identity request limiter (spec §11.2 P7). The limiter is ONE `Arc` shared
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

/// The `status`-facing view of the configured services (name, allow, backend KIND only — no
/// command/path, §17). Malformed entries are omitted (they are not served either).
pub(crate) fn service_infos(cfg: &Config) -> Vec<ServiceInfo> {
    cfg.services
        .iter()
        .filter_map(|(name, svc)| {
            let backend = match svc.backend_result() {
                Ok(Backend::Run(_)) => BackendKind::Run,
                Ok(Backend::Socket(_)) => BackendKind::Socket,
                Err(_) => return None,
            };
            Some(ServiceInfo {
                name: name.clone(),
                allow: svc.allow.clone(),
                backend,
            })
        })
        .collect()
}

/// The `status`-facing view of known peers (petname + granted services — never the
/// EndpointId, §1.5). Fails open on a corrupt store row (see [`PeerStore::list`]).
pub(crate) fn peer_infos(store: &PeerStore) -> Vec<PeerInfo> {
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|e| PeerInfo {
            name: e.petname,
            services: e.services,
            // The peer's proven self-sovereign user_id (from a verified pairing binding), or `None`
            // for a petname-only / `internal peer add` peer. A §1.5-clean opaque id, not a key.
            user_id: e.user_id,
        })
        .collect()
}

/// Handle a `register_service` control request: write/update the `[services.*]` config entry
/// (atomic), reload the registry, and hot-reload the mesh serve loop. Config writes block, so
/// they run on `spawn_blocking` (Task 4 seam note).
pub(crate) async fn register_service(
    state: &DaemonState,
    params: RegisterServiceParams,
) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;

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
    tokio::task::spawn_blocking(move || {
        write_service_to_config(&config_path, &name_w, &backend_w, &allow_w)
    })
    .await
    .context("join config write")??;

    // 2/3. Reload config, rebuild the registry from the persisted truth, and hot-reload: abort the
    //      old accept loop, spawn a fresh one on the same endpoint carrying the rebuilt registry
    //      (a brief serving blip is acceptable, spec §6.1). Shared with the pairing grant / revoke /
    //      rename via [`reload_services_from_disk`] (DRY).
    let cfg = reload_services_from_disk(mesh, "register").await?;

    // 4. Refresh the status snapshot.
    *state.services.write().expect("services lock not poisoned") = service_infos(&cfg);
    tracing::info!(service = %name, "registered/updated service");
    Ok(())
}

/// Handle a `peer_add` control request (the M2a trust-population stand-in for pairing): write
/// a [`PeerEntry`] to the daemon's OPEN store (redb is single-process, so this must route
/// through the daemon), then refresh the `status` peer snapshot. The live
/// [`AllowlistGate`](crate::allowlist::AllowlistGate) reads the same database, so the new
/// peer is resolvable on the very next accept — no gate rebuild needed.
pub(crate) async fn add_peer(state: &DaemonState, params: PeerAddParams) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let PeerAddParams {
        petname,
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
        petname: petname.clone(),
        services: allow,
        // `internal peer add` is not a pairing write — leave the audit stamp unset (M2b:
        // only the pair rendezvous records `paired_at`, T5/T6).
        paired_at: None,
        user_id: None,
    };

    // redb writes block + fsync — run on a blocking thread (Task 4 BINDING seam note).
    let store = mesh.store.clone();
    tokio::task::spawn_blocking(move || store.add(entry))
        .await
        .context("join peer add")??;

    // Refresh the status peer snapshot from the store.
    let store = mesh.store.clone();
    let peers = tokio::task::spawn_blocking(move || peer_infos(&store))
        .await
        .context("join peer list")?;
    *state.peers.write().expect("peers lock not poisoned") = peers;
    tracing::info!(peer = %petname, "added peer to allowlist");
    Ok(())
}

/// Handle a `peer_remove` control request (spec §4.2, `mcpmesh pair --remove`): drop a paired
/// peer's authorization AND identity — the strict INVERSE of the pairing grant.
///
/// **Fail-safe teardown order (DECLARED).** The pairing grant writes, in order, (1) the
/// [`PeerEntry`] (identity — who the peer is) then (2) the config `allow` append (authorization —
/// what it may open). Removal is that grant's LIFO inverse: undo (2) FIRST via
/// [`revoke_service_access`] (strip the petname from every `[services.*].allow`, the
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
/// **Live sessions (M3/D8).** This severs only the ability to establish NEW authorized sessions;
/// an in-flight mesh session runs to completion (session severing is deferred to M3).
///
/// **Status snapshot.** Not refreshed here — and it no longer needs to be: `status` reads the
/// config + store LIVE (control.rs `status_result`), so a revoke is reflected immediately even
/// though this detached handler holds no `DaemonState`. The functional truth is the store +
/// config (which the `pair --remove` tests assert on), and `status` now reads exactly that.
pub async fn remove_peer(state: &DaemonState, params: PeerRemoveParams) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let petname = params.petname;

    // (2)⁻¹ AUTHORIZATION: revoke first (the security-relevant half). Propagate its error so a
    // failure aborts before we touch the identity row (see the fail-safe reasoning above). Capture
    // whether an allow was actually stripped — one half of the actual-removal signal.
    let revoked = revoke_service_access(mesh, &petname).await?;

    // (1)⁻¹ IDENTITY: drop the PeerEntry (removes ALL entries sharing this petname — petnames are
    // not unique). redb writes block + fsync — run on a blocking thread (M2a seam note). Capture
    // whether a PeerEntry was actually deleted — the other half of the actual-removal signal.
    let store = mesh.store.clone();
    let petname_w = petname.clone();
    let removed = tokio::task::spawn_blocking(move || store.remove(&petname_w))
        .await
        .context("join peer remove")??;

    tracing::info!(peer = %petname, "unpaired peer");
    // Trust event (spec §11.3): an unpair — recorded ONLY when something was ACTUALLY torn down (a
    // stripped allow OR a deleted PeerEntry). `pair --remove <never-paired>` is an idempotent no-op on
    // both halves, so it writes NO phantom `unpair` record. Petname only (§1.5).
    if revoked || removed {
        mesh.audit().record(AuditRecord::trust(
            now_ts(),
            "unpair".into(),
            Some(petname.clone()),
        ));
    }
    Ok(())
}

/// The vetted plan for a rename: the target [`PeerEntry`]s (the person) and their current petnames.
struct RenamePlan {
    targets: Vec<PeerEntry>,
    old_petnames: std::collections::BTreeSet<String>,
}

/// Identify the person's entries and run the rename COLLISION GUARD (privilege-escalation defense,
/// mirroring pairing's `petname_collision`). The person is every entry sharing `user_id` (renames all
/// their devices in one op), else the single entry named `petname` (a provisional contact). Returns
/// `Ok(None)` when every target is already named `to` (a no-op), `Ok(Some(plan))` when the rename is
/// safe, or `Err` when no contact matches or `to` would inherit a DIFFERENT identity's access.
/// Blocking (redb + config read) — call on a blocking thread.
fn rename_plan(
    store: &PeerStore,
    config_path: &Path,
    user_id: Option<&str>,
    petname: Option<&str>,
    to: &str,
) -> Result<Option<RenamePlan>> {
    let all = store.list()?;
    let targets: Vec<PeerEntry> = all
        .iter()
        .filter(|e| match user_id {
            Some(u) => e.user_id.as_deref() == Some(u),
            None => Some(e.petname.as_str()) == petname,
        })
        .cloned()
        .collect();
    if targets.is_empty() {
        anyhow::bail!("peer_rename: no matching contact");
    }
    if targets.iter().all(|e| e.petname == to) {
        return Ok(None); // already named `to` — a no-op
    }

    let target_ids: std::collections::BTreeSet<[u8; 32]> =
        targets.iter().map(|e| e.endpoint_id).collect();
    // (a) impersonation: a peer named `to` at an endpoint that is NOT one of the targets is a
    // DIFFERENT contact — renaming onto it would let this person assume that identity's grants.
    if all
        .iter()
        .any(|e| e.petname == to && !target_ids.contains(&e.endpoint_id))
    {
        anyhow::bail!("the nickname \"{to}\" is already used by another contact");
    }
    // (b) orphan-allow: `to` sits in some service allow but backs NO peer — a pre-provisioned grant
    // the renamed peer would inherit. (If a target is already named `to`, a backing peer exists.)
    let backed_by_peer = all.iter().any(|e| e.petname == to);
    if !backed_by_peer && crate::pairing::rendezvous::petname_in_any_service_allow(config_path, to)?
    {
        anyhow::bail!("the nickname \"{to}\" is already granted access — pick another");
    }

    let old_petnames = targets.iter().map(|e| e.petname.clone()).collect();
    Ok(Some(RenamePlan {
        targets,
        old_petnames,
    }))
}

/// Handle a `peer_rename` control request (Contacts rename, spec §mcpmesh). Renames a contact's
/// nickname (petname) authoritatively — all the person's `PeerEntry`s to `to`, and rewrites the old
/// petname → `to` in every `[services.*].allow` so grants follow — then reloads so the new name
/// admits. Guarded against renaming onto another identity's name/grant. Held entirely under
/// `reload_lock` (like grant/revoke/register) so guard→mutate→reload is one atomic critical section.
pub async fn rename_peer(state: &DaemonState, params: PeerRenameParams) -> Result<()> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    let to = params.to.trim().to_string();
    if to.is_empty() {
        anyhow::bail!("peer_rename: the new nickname is empty");
    }
    let PeerRenameParams {
        user_id, petname, ..
    } = params;
    if user_id.is_none() && petname.is_none() {
        anyhow::bail!("peer_rename: no contact identified");
    }

    // Hold the whole guard→mutate→reload section under the SAME lock as grant/revoke/register, so a
    // concurrent config edit can neither race the collision guard nor clobber the allow rewrite.
    let _reload = mesh.reload_lock.lock().await;

    let store = mesh.store.clone();
    let config_path = mesh.config_path.clone();
    let (uid_c, pn_c, to_c) = (user_id.clone(), petname.clone(), to.clone());
    let plan = tokio::task::spawn_blocking(move || {
        rename_plan(
            &store,
            &config_path,
            uid_c.as_deref(),
            pn_c.as_deref(),
            &to_c,
        )
    })
    .await
    .context("join rename plan")??;
    let RenamePlan {
        targets,
        old_petnames,
    } = match plan {
        Some(p) => p,
        None => return Ok(()), // no-op: already named `to`
    };

    // Mutate on a blocking thread: rewrite each old petname → `to` in the config allow lists, then
    // upsert each target `PeerEntry` (same endpoint_id, new petname).
    let store = mesh.store.clone();
    let config_path = mesh.config_path.clone();
    let to_c = to.clone();
    tokio::task::spawn_blocking(move || {
        for old in &old_petnames {
            if old != &to_c {
                rename_allow_in_config(&config_path, old, &to_c)?;
            }
        }
        for mut e in targets {
            e.petname = to_c.clone();
            store.add(e)?;
        }
        anyhow::Ok(())
    })
    .await
    .context("join rename mutate")??;

    // Reload so the rebuilt `Services` admit under the new petname (select_service reads the allow
    // baked in at build time).
    reload_services_from_disk(mesh, "rename").await?;
    tracing::info!(to = %to, "renamed contact");
    Ok(())
}

/// A short, human-glanceable fingerprint of an endpoint id: the first 8 chars of its base32
/// (`EndpointId`'s `Display`) form. The default self-petname when config sets none (spec §4.2
/// "suggested petname"). Not security-bearing — the id itself is the routing key.
fn short_fingerprint(id: &iroh::EndpointId) -> String {
    id.to_string().chars().take(8).collect()
}

/// A friendly default display name for this node when the config sets no `petname`: the machine's
/// short hostname, else the endpoint fingerprint. So a freshly-started daemon advertises `jetson`
/// instead of `96246d3f` out of the box (a config `petname` still wins; a peer's stored petname is
/// captured at pairing time from whatever the peer suggests here).
fn default_self_petname(id: &iroh::EndpointId) -> String {
    hostname_petname().unwrap_or_else(|| short_fingerprint(id))
}

/// This machine's `hostname`, sanitized into a petname, or `None` if the command fails or is empty.
fn hostname_petname() -> Option<String> {
    let out = std::process::Command::new("hostname").output().ok()?;
    sanitize_hostname(&String::from_utf8_lossy(&out.stdout))
}

/// Sanitize a raw hostname into a petname: the short name (before the first `.`), lowercased, keeping
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

/// Mint a one-time pairing invite granting `services` (spec §4.2, control method `"invite"`).
///
/// Builds an [`Invite`] { 32 CSPRNG-byte secret, our endpoint id + dialable address, our
/// suggested petname, the granted services, a `≤ now + 24h` expiry }, registers it in the
/// live registry so the accept loop's `mcpmesh/pair/1` branch will redeem it, and returns the
/// copyable `mcpmesh-invite:` line. Logs a trust event (§11.3) carrying NO secret and NO peer
/// id — an invite has no peer yet; the redeemer is only known once it dials (T5 rendezvous).
///
/// The secret uses the OS CSPRNG via `rand::rngs::OsRng` — the SAME source M0's device-key
/// mint uses (mcpmesh-trust), no new crate. The address comes from `endpoint.addr()`; we first
/// wait (bounded by [`RELAY_READY_TIMEOUT`]) for the endpoint to come online so the addr
/// carries the home-relay URL the redeemer bootstraps from across NAT (§4.2).
pub(crate) async fn mint_invite(services: Vec<String>, mesh: &MeshState) -> Result<InviteResult> {
    use rand::RngCore;

    // 32 CSPRNG bytes — the single-use bearer credential (spec §4.2).
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
        petname: mesh.self_petname.clone(),
        services: services.clone(),
        expires_at_epoch,
    };
    let invite_line = invite.encode();
    // Reap expired invites before minting so a long-lived daemon's registry can't grow
    // unboundedly with never-redeemed invites (bounds map growth; the invite lifetime cap,
    // spec §4.2). Cheap: one lock + retain over a small map.
    mesh.invites.remove_expired(now);
    mesh.invites.mint(invite);

    // Trust event (§11.3): record the mint. NO secret, NO peer id (there is no peer yet).
    tracing::info!(?services, "invite minted");
    Ok(InviteResult {
        invite_line,
        expires_at_epoch,
    })
}

/// Handle a `pair` control request (spec §4.2, the REDEEMER side): dial the inviter named by
/// `invite_line` on `mcpmesh/pair/1`, verify its TLS identity binds the invite's `inviter_id`
/// (P3 address-swap defense), prove the secret, write OUR dial-back [`PeerEntry`], and return
/// the inviter's petname + the display-only SAS. Delegates to
/// [`crate::pairing::rendezvous::redeem_invite`], threading our own endpoint + self-petname +
/// store. The inviter-side authorization (adding US to its service `allow`) happens on ITS
/// daemon inside its rendezvous handler — see [`grant_service_access`].
pub(crate) async fn redeem(state: &DaemonState, invite_line: String) -> Result<PairResult> {
    let mesh = state
        .mesh()
        .context("daemon has no mesh (control-only mode)")?;
    crate::pairing::rendezvous::redeem_invite(
        mesh.endpoint.clone(),
        mesh.self_petname.clone(),
        invite_line,
        mesh.store.clone(),
        mesh.self_binding(),
    )
    .await
}

/// Grant a freshly-paired peer AUTHORIZATION to the services its invite named: append
/// `redeemer_petname` to each service's config `[services.<svc>].allow` (idempotently) and
/// hot-reload so the running registry admits it. This is the load-bearing half of pairing.
///
/// Why it is separate from (and necessary alongside) the [`PeerEntry`] the rendezvous writes:
/// the [`AllowlistGate`](crate::allowlist::AllowlistGate) only RESOLVES an inbound endpoint to
/// a petname (identity); `select_service` (spec §5) then ADMITS that petname only if the
/// service's config `allow` names it — and that allow is baked into the [`Services`] snapshot
/// at [`build_services`] time. So a PeerEntry makes the peer KNOWN; only appending to `allow`
/// + reloading makes it AUTHORIZED. Without this the peer is known-but-forbidden.
///
/// Serialized against [`register_service`] via `mesh.reload_lock` (SAME lock — a concurrent
/// register and a pairing-grant must not read the same base config and clobber each other's
/// write). Reuses [`append_allow_to_config`]'s atomic write and [`reload_accept_loop`]'s
/// abort/respawn (DRY). A service not present in config is logged + skipped (a pairing grant
/// never CREATES a service). Reloads ONLY when the append actually changed the config — an
/// idempotent re-pair or an all-missing grant is a no-op with no serving blip. (The cached
/// `status` snapshot is not refreshed here — this runs inside the accept loop's detached pair
/// handler, which holds no `DaemonState` — but it need not be: `status` reads the config + store
/// LIVE (control.rs `status_result`), so this grant shows up immediately. The durable allow-append
/// + the live rebuilt `Services` are the functional truth.)
pub async fn grant_service_access(
    mesh: &Arc<MeshState>,
    redeemer_petname: &str,
    services: &[String],
) -> Result<()> {
    // SAME serialization as register_service: hold the whole append→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Idempotent allow-append on a blocking thread (config IO blocks, Task 4 seam note).
    let config_path = mesh.config_path.clone();
    let petname = redeemer_petname.to_string();
    let services_w = services.to_vec();
    let changed = tokio::task::spawn_blocking(move || {
        append_allow_to_config(&config_path, &petname, &services_w)
    })
    .await
    .context("join grant config write")??;

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already admits the peer). The reload MUST happen for a real append to take effect,
    //      since `select_service` reads the allow baked into `Services` at build time.
    if changed {
        reload_services_from_disk(mesh, "grant").await?;
    }

    // Trust event (§11.3): NO secret, NO endpoint id (petname only, §1.5).
    tracing::info!(peer = %redeemer_petname, ?services, changed, "granted service access");
    // Trust event (spec §11.3): a pairing grant. Petname only — NO secret, NO endpoint id (§1.5).
    mesh.audit().record(AuditRecord::trust(
        now_ts(),
        "pair".into(),
        Some(redeemer_petname.to_string()),
    ));
    Ok(())
}

/// Revoke a peer's AUTHORIZATION: remove `petname` from EVERY service's config
/// `[services.<svc>].allow` and hot-reload so the running registry stops admitting it. The exact
/// INVERSE of [`grant_service_access`] (which appends the petname to the named services' allow),
/// and the authorization half of [`remove_peer`].
///
/// Serialized against [`register_service`] / [`grant_service_access`] via `mesh.reload_lock` (the
/// SAME lock — a concurrent config mutation must not read the same base config and clobber this
/// removal). Reuses [`remove_allow_from_config`]'s atomic write and [`reload_accept_loop`]'s
/// abort/respawn (DRY — the same helper the grant uses). Reloads ONLY when the removal actually
/// changed the config (an absent petname is a no-op with no serving blip). Idempotent: revoking a
/// petname not present in any allow returns `Ok(())` with `changed == false` and no reload.
///
/// (Like [`grant_service_access`], the cached `status` snapshot is not refreshed here — but
/// `status` reads the config + store LIVE (control.rs `status_result`), so the removal shows up
/// immediately. The durable allow-removal + the live rebuilt `Services` are the functional truth.)
pub(crate) async fn revoke_service_access(mesh: &Arc<MeshState>, petname: &str) -> Result<bool> {
    // SAME serialization as register_service / grant: hold the whole remove→reload→swap section.
    let _reload = mesh.reload_lock.lock().await;

    // 1. Idempotent allow-removal on a blocking thread (config IO blocks, M2a seam note).
    let config_path = mesh.config_path.clone();
    let petname_w = petname.to_string();
    let changed =
        tokio::task::spawn_blocking(move || remove_allow_from_config(&config_path, &petname_w))
            .await
            .context("join revoke config write")??;

    // 2/3. Reload + hot-swap ONLY when the allow actually changed (else the running registry
    //      already excludes the peer). A real removal MUST reload for `select_service` — which
    //      reads the allow baked into `Services` at build time — to stop admitting the petname.
    if changed {
        reload_services_from_disk(mesh, "revoke").await?;
    }

    // Return whether an allow was actually stripped so `remove_peer` audits an `unpair` (§11.3) only
    // on a real tear-down (petname only — NO secret, NO endpoint id, §1.5).
    tracing::info!(peer = %petname, changed, "revoked service access");
    Ok(changed)
}

/// Handle an `open_session` control request (spec §8): resolve the petname, dial the named
/// service over the mesh, and pipe that session to/from the control connection — which, after
/// this request, STOPS being JSON-RPC and becomes a raw MCP byte pipe (protocol.rs
/// `OpenSession`). On any dial-ESTABLISHMENT failure (peer not allowlisted, malformed stored
/// id, unreachable) the caller is handed a synthesized `-32055` (ERR_UNREACHABLE) frame, so
/// the AI client gets a well-formed answer instead of a hang; the remote's own `-32054`
/// refusal, and every session frame, flow back verbatim through the pipe (§8). There is no
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
            // petname/user_id (§1.5), never an endpoint-id.
            mesh.audit().record(
                AuditRecord::session_open(now_ts(), Some(peer.to_string()), service.to_string())
                    .with_status("error"),
            );
            // Dial establishment failed: hand the proxy a well-formed -32055 (not a hang),
            // which it relays to the AI client (spec §8). The error id is null — the AI
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

/// Assemble a serving [`DaemonState`] around an already-bound endpoint and peer store, for
/// in-process integration tests that must drive the REAL control server (`serve_control`) —
/// the Task 10 proxy round-trip binds a control socket over this and runs `mcpmesh connect` as
/// a subprocess against it, so the actual `open_session` dial-by-id + pipe are exercised. The
/// mesh's serve loop is inert here (`open_session` reads only the endpoint + store to DIAL
/// outbound); production assembles its own `MeshState` inline in [`serve_forever`].
pub fn serving_state(endpoint: iroh::Endpoint, store: Arc<PeerStore>) -> Arc<DaemonState> {
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    let self_petname = short_fingerprint(&endpoint.id());
    // No accept loop is spawned here (this seam only dials OUTBOUND via `open_session`), so the
    // mesh's `accept_task` stays empty.
    let mesh = MeshState::new(
        endpoint,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        self_petname,
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
    Arc::new(DaemonState::with_mesh(
        STACK_VERSION,
        mesh,
        Vec::new(),
        Vec::new(),
    ))
}

/// Acquire the per-uid singleton lock (spec §13 single-daemon). Returns `Some(file)` when we
/// win the exclusive advisory lock (hold it for the process lifetime; dropping it releases
/// the lock), or `None` when another daemon already holds it (`EWOULDBLOCK`). Unix-only: on
/// Windows the control-pipe bind is the singleton (see `run`), so there is no flock path.
#[cfg(unix)]
fn acquire_singleton_lock(lock_path: &Path) -> Result<Option<File>> {
    use rustix::fs::{FlockOperation, flock};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .with_context(|| format!("open singleton lock {}", lock_path.display()))?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(Some(file)),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(None),
        Err(e) => Err(anyhow::Error::new(e).context("flock singleton lock")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mcpmesh_trust::roster::encode_b64u;

    #[test]
    fn sanitize_hostname_makes_a_friendly_petname() {
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

    /// `status` reflects the LIVE config + store, not a stale cached snapshot. A pairing grant
    /// (grant_service_access → allow-append) and a rendezvous PeerEntry write are durable but do
    /// NOT refresh the snapshot; `status` must still show the just-granted allow + the just-paired
    /// peer (the Jetson-proof "status says `allowed: no one yet` right after pairing" confusion).
    /// Models the bug faithfully by mutating the config + store directly (exactly what grant +
    /// rendezvous do to the durable state) behind the seeded snapshot's back.
    #[tokio::test(flavor = "multi_thread")]
    async fn status_reads_live_config_and_store_not_the_stale_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;

        // Seed the status snapshot with the PRE-grant truth (what startup/register would cache).
        let cfg0 = Config::load(&config_path).unwrap();
        let state = crate::control::DaemonState::with_mesh(
            "test",
            mesh.clone(),
            service_infos(&cfg0),
            peer_infos(&mesh.store),
        );

        // Durable mutations that BYPASS the snapshot (as grant + rendezvous do): append the grant
        // to the config, and write the peer's PeerEntry straight to the store.
        append_allow_to_config(&config_path, "alice", &["kb".to_string()]).unwrap();
        mesh.store
            .add(PeerEntry {
                endpoint_id: [9u8; 32],
                petname: "alice".into(),
                services: Vec::new(),
                paired_at: None,
                user_id: None,
            })
            .unwrap();

        // Status must reflect the LIVE truth, not the stale (empty) snapshot.
        let status = crate::control::status_result(&state);
        let kb = status
            .services
            .iter()
            .find(|s| s.name == "kb")
            .expect("kb service in status");
        assert!(
            kb.allow.contains(&"alice".to_string()),
            "status must show the live grant, got allow={:?}",
            kb.allow
        );
        assert!(
            status.peers.iter().any(|p| p.name == "alice"),
            "status must show the live peer, got peers={:?}",
            status.peers
        );
    }

    /// Status surfaces self-sovereign identity (the adopted device->user binding): the daemon's OWN
    /// `self_user_id` (from its self-binding) and each paired peer's PROVEN `user_id` (from its
    /// `PeerEntry`). A peer that presented no binding stays petname-only (`user_id: None`).
    #[tokio::test]
    async fn status_surfaces_self_and_peer_user_ids() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        mesh.set_self_binding(Some(crate::pairing::rendezvous::SelfBinding {
            user_pk: "b64u:selfpk".into(),
            sig: "b64u:selfsig".into(),
        }));
        // One peer that proved a self-sovereign user_id at pairing, one legacy petname-only peer.
        mesh.store
            .add(PeerEntry {
                endpoint_id: [1u8; 32],
                petname: "alice".into(),
                services: Vec::new(),
                paired_at: Some("1".into()),
                user_id: Some("b64u:alicepk".into()),
            })
            .unwrap();
        mesh.store
            .add(PeerEntry {
                endpoint_id: [2u8; 32],
                petname: "legacy".into(),
                services: Vec::new(),
                paired_at: None,
                user_id: None,
            })
            .unwrap();

        let cfg0 = Config::load(&config_path).unwrap();
        let state = crate::control::DaemonState::with_mesh(
            "test",
            mesh.clone(),
            service_infos(&cfg0),
            peer_infos(&mesh.store),
        );
        let status = crate::control::status_result(&state);

        assert_eq!(
            status.self_user_id.as_deref(),
            Some("b64u:selfpk"),
            "status must surface this daemon's own self-sovereign user_id"
        );
        let alice = status
            .peers
            .iter()
            .find(|p| p.name == "alice")
            .expect("alice in status");
        assert_eq!(
            alice.user_id.as_deref(),
            Some("b64u:alicepk"),
            "a paired peer's PROVEN user_id must be surfaced in status"
        );
        let legacy = status
            .peers
            .iter()
            .find(|p| p.name == "legacy")
            .expect("legacy in status");
        assert!(
            legacy.user_id.is_none(),
            "a petname-only peer stays user_id: None"
        );
    }

    /// The recent-pairings ring is BOUNDED (cap 8, oldest dropped), snapshots NEWEST FIRST, and
    /// `status_result` surfaces it (display-only §4.2 ceremony state; empty in a control-only
    /// daemon — covered by control.rs's snapshot tests, whose StatusResult omits the field).
    #[tokio::test]
    async fn recent_pairings_ring_is_bounded_newest_first_and_surfaced_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mesh = hermetic_mesh(config_path).await;
        for i in 0..10u64 {
            mesh.record_pairing(format!("peer{i}"), format!("code-{i}"), i);
        }
        let recent = mesh.recent_pairings();
        assert_eq!(recent.len(), 8, "the ring is capped at 8");
        assert_eq!(recent[0].peer_petname, "peer9", "newest first");
        assert_eq!(
            recent[7].peer_petname, "peer2",
            "the two oldest were dropped"
        );

        let state = crate::control::DaemonState::with_mesh("test", mesh, Vec::new(), Vec::new());
        let status = crate::control::status_result(&state);
        assert_eq!(status.recent_pairings.len(), 8);
        assert_eq!(status.recent_pairings[0].sas_code, "code-9");
        assert_eq!(status.recent_pairings[0].paired_at_epoch, 9);
    }

    /// `rename_peer` renames ALL of a person's devices (matched by user_id) to the new nickname AND
    /// rewrites the old petname → new in every service allow, so grants FOLLOW the rename. The happy
    /// path also drives `build_services_audited` + `reload_accept_loop` under `reload_lock`.
    /// The typed `peer_rename` params, as the control dispatcher hands them to `rename_peer`.
    fn rename_params(user_id: Option<&str>, to: &str) -> PeerRenameParams {
        PeerRenameParams {
            user_id: user_id.map(str::to_string),
            petname: None,
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
        let state =
            crate::control::DaemonState::with_mesh("test", mesh.clone(), Vec::new(), Vec::new());

        rename_peer(&state, rename_params(Some("b64u:ALICE"), "Alice"))
            .await
            .unwrap();

        // Both PeerEntries now carry the new nickname.
        let names: Vec<String> = mesh
            .store
            .list()
            .unwrap()
            .into_iter()
            .map(|e| e.petname)
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
        let state =
            crate::control::DaemonState::with_mesh("test", mesh.clone(), Vec::new(), Vec::new());

        // Empty `to` (whitespace trims to empty).
        assert!(
            rename_peer(&state, rename_params(Some("b64u:ALICE"), "  "))
                .await
                .is_err()
        );
        // Neither user_id nor petname identifies a contact.
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
            .map(|e| e.petname)
            .collect();
        assert!(
            names.contains("alice") && names.contains("bob"),
            "no rename should have occurred: {names:?}"
        );
    }

    fn rename_entry(id: u8, petname: &str, user_id: Option<&str>) -> PeerEntry {
        PeerEntry {
            endpoint_id: [id; 32],
            petname: petname.into(),
            services: Vec::new(),
            paired_at: None,
            user_id: user_id.map(str::to_string),
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
            plan.old_petnames,
            ["bob-laptop".to_string(), "bob-phone".to_string()]
                .into_iter()
                .collect()
        );

        // GUARD (a) impersonation: renaming Bob → "carol" (a DIFFERENT contact) is refused.
        assert!(rename_plan(&store, &cfg, Some("b64u:BOB"), None, "carol").is_err());
        // GUARD (b) orphan-allow: "orphan" sits in kb.allow but backs no peer → refused.
        assert!(rename_plan(&store, &cfg, Some("b64u:BOB"), None, "orphan").is_err());
        // A provisional contact (no user_id) renames by petname to a fresh name.
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

    /// D2: `net_plan` implements EXACTLY the shipped `[network]` surface — the §10.3 knobs are
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

    /// D2: a custom-relay endpoint BINDS without any live relay (the RelayMap is config, not a
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

    /// Build a HERMETIC mesh (relay-disabled endpoint, temp config/store, EMPTY roster) so we can
    /// drive `org_join` + `roster_status` in-process against the real config-write + status paths.
    async fn hermetic_mesh(config_path: PathBuf) -> Arc<MeshState> {
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

    /// `org_join` validates the pk BEFORE writing (garbage never lands), pins the four identity keys
    /// (preserving `petname`), and flips `roster_status` from `None` (pure-pairing) to `"pending"`
    /// with serial 0 + the pinned org-root fingerprint (spec §4.4 step 2, D5 — no roster installed).
    #[tokio::test(flavor = "multi_thread")]
    async fn org_join_pins_and_status_reports_pending() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[network]\nrelay_mode = \"disabled\"\n\n[identity]\npetname = \"mydev\"\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        let state = DaemonState::with_mesh("0.0.0", mesh.clone(), vec![], vec![]);
        // `roster_status` takes the caller's already-loaded config (L6: status loads it once);
        // the test mirrors control.rs `status_result` by loading fresh at each check.
        let live_status =
            |mesh: &Arc<MeshState>| roster_status(mesh, Config::load(&config_path).ok().as_ref());

        // Pure-pairing (no org pinned) → no roster block.
        assert!(
            live_status(&mesh).is_none(),
            "an unpinned daemon must surface no roster status"
        );

        // A GARBAGE anchor is rejected BEFORE the write — nothing lands in config.
        assert!(
            org_join(
                &state,
                "acme".into(),
                "not-a-real-key".into(),
                "alice".into(),
                "/home/alice/user.key".into(),
            )
            .await
            .is_err(),
            "a garbage org_root_pk must be rejected"
        );
        assert!(
            Config::load(&config_path)
                .unwrap()
                .identity
                .org_root_pk
                .is_none(),
            "a rejected join must NOT pin a garbage anchor"
        );
        assert!(
            live_status(&mesh).is_none(),
            "a rejected join leaves status unpinned"
        );

        // A VALID anchor pins the four keys + surfaces "pending".
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let pk_str = encode_b64u(root.verifying_key().as_bytes());
        let res = org_join(
            &state,
            "acme".into(),
            pk_str.clone(),
            "alice".into(),
            "/home/alice/user.key".into(),
        )
        .await
        .expect("valid join pins");
        assert_eq!(
            res,
            OrgJoinResult {
                org_id: "acme".into()
            }
        );

        // The four identity keys are pinned; the pre-existing petname is preserved.
        let cfg = Config::load(&config_path).unwrap();
        assert_eq!(cfg.identity.org_id.as_deref(), Some("acme"));
        assert_eq!(cfg.identity.org_root_pk.as_deref(), Some(pk_str.as_str()));
        assert_eq!(cfg.identity.user_id.as_deref(), Some("alice"));
        assert_eq!(
            cfg.identity.user_key.as_deref(),
            Some(Path::new("/home/alice/user.key"))
        );
        assert_eq!(cfg.identity.petname.as_deref(), Some("mydev"));

        // Status is now "pending": org pinned, NO roster installed (D5) → serial 0 + the fingerprint.
        let status = live_status(&mesh).expect("pinned org surfaces a pending status");
        assert_eq!(status.state, "pending");
        assert_eq!(status.serial, 0);
        assert_eq!(status.org_id, "acme");
        let expected_fp = pairing::sas::fingerprint_words(&root.verifying_key().to_bytes());
        assert!(!expected_fp.is_empty());
        assert_eq!(status.org_root_fingerprint, expected_fp);
    }

    /// [CRITICAL — M3c T7] The URL poll must NOT panic. reqwest 0.13.4 (`rustls-no-provider`) resolves
    /// the rustls `CryptoProvider` at client-build time and PANICS if none is installed; iroh installs
    /// no process-default. This test installs the ring provider EXACTLY as `serve_forever` does, then
    /// drives `poll_roster_url_once` against an unreachable URL: it must return an `Err` (the failed
    /// GET), NOT panic. A panic (a missing provider) would ABORT the test — so a clean `Err` PROVES the
    /// `install_default` call is what keeps the poll alive. (Also exercises the fail-toward-degraded
    /// path, D5: a blocked/unreachable poll is a plain error the loop logs + retries.)
    #[tokio::test(flavor = "multi_thread")]
    async fn url_poll_does_not_panic_when_the_ring_provider_is_installed() {
        // The SAME install `serve_forever` step 0 performs (idempotent — safe if another test ran it).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "[network]\nrelay_mode = \"disabled\"\n").unwrap();
        let mesh = hermetic_mesh(config_path).await;

        // An unreachable URL (loopback port 1 — nothing listens → immediate connection refused). The
        // reqwest client BUILDS (the panic point) before the connection fails, so reaching this `Err`
        // proves the provider is installed. `reqwest::get` panics here WITHOUT the install.
        let result = crate::roster::distribute::poll_roster_url_once(
            &mesh,
            "http://127.0.0.1:1/roster.json",
        )
        .await;
        assert!(
            result.is_err(),
            "an unreachable poll must return Err (not panic, not a silent Ok): {result:?}"
        );
    }

    /// A std-only localhost HTTP/1.1 server that serves `body` for EVERY request until stopped.
    /// Returns `(url, stop_flag, join_handle)` — set the flag + join to shut it down. Non-blocking
    /// accept + poll so a clean shutdown never wedges the thread.
    fn serve_roster_http(
        body: Vec<u8>,
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http server");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut buf = [0u8; 2048];
                        let _ = stream.read(&mut buf);
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(&body);
                        let _ = stream.flush();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        (format!("http://127.0.0.1:{port}/roster.json"), stop, handle)
    }

    /// **The D5 fix (M3c T7).** A `set_roster_url` on an ALREADY-RUNNING daemon whose config has the
    /// org anchor pinned but NO roster yet (the pending joiner, exactly the post-`OrgJoin` state) must
    /// (re)start the poll loop AT RUNTIME so the FIRST roster installs WITHOUT a daemon restart. Serve a
    /// valid signed serial-1 roster, call `set_roster_url`, and poll-assert (timeout + interval, NOT a
    /// fixed sleep) that the gate hot-swaps to serial 1 — proving the runtime respawn autonomously
    /// bootstraps the joiner (the no-human-restart directive). Idempotency: a SECOND `set_roster_url`
    /// aborts+replaces the loop (no stacking) and the roster stays installed.
    #[tokio::test(flavor = "multi_thread")]
    async fn runtime_set_roster_url_bootstraps_the_first_roster_without_a_restart() {
        use mcpmesh_trust::roster::mutate;
        use mcpmesh_trust::roster::sign::mint_signed;
        use std::sync::atomic::Ordering;
        // The SAME provider install `serve_forever` step 0 performs (idempotent).
        let _ = rustls::crypto::ring::default_provider().install_default();

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let pk_str = encode_b64u(&root.verifying_key().to_bytes());
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        // A pending joiner's config: the org anchor is pinned (as `OrgJoin` sets it) but no roster.
        std::fs::write(
            &config_path,
            format!(
                "[network]\nrelay_mode = \"disabled\"\n[identity]\norg_root_pk = \"{pk_str}\"\norg_id = \"acme\"\n"
            ),
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path).await;
        assert!(
            mesh.roster.view().is_none(),
            "pending joiner: no roster installed yet (D5)"
        );
        let state = DaemonState::with_mesh("0.0.0", mesh.clone(), vec![], vec![]);

        // A valid signed serial-1 roster hosted over HTTP (what the operator publishes to the URL).
        let now = epoch_now_i64();
        let roster = mint_signed(
            &root,
            mutate::empty_roster("acme", 1, now - 3600, now + 86_400),
        );
        let (url, stop, handle) = serve_roster_http(serde_json::to_vec(&roster).unwrap());

        // The RUNTIME trigger — no restart: pin the URL → `set_roster_url` respawns the poll loop →
        // the loop's immediate startup poll GETs + converges the first roster through install_from_file.
        set_roster_url(&state, url.clone())
            .await
            .expect("set_roster_url pins the URL and (re)starts polling");

        // Poll-assert the first roster installs autonomously (timeout + interval, never a fixed sleep).
        // Deadline widened for full-workspace parallelism: convergence is fast in isolation but CPU starvation under many concurrent test binaries can slow the real HTTP/mesh path; a wider bound tolerates that without masking a real hang (a genuine failure still hits the bound).
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            if mesh.roster.view().map(|v| v.serial()).unwrap_or(0) >= 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the first roster must install at RUNTIME (no daemon restart) after set_roster_url"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            mesh.roster.view().expect("roster installed").serial(),
            1,
            "the runtime poll bootstrapped the joiner's first roster (D5) — gate hot-swapped to serial 1"
        );

        // Idempotency: a SECOND set_roster_url aborts+replaces the loop (no stacking) — still serial 1.
        set_roster_url(&state, url)
            .await
            .expect("a repeat set_roster_url is idempotent (abort+replace, no stacking)");
        assert_eq!(
            mesh.roster.view().unwrap().serial(),
            1,
            "a repeat set_roster_url does not regress or double-install the roster"
        );

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
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

    #[test]
    fn staleness_sweep_fires_only_when_degraded_stopped() {
        use mcpmesh_trust::roster::validate::RosterState;
        assert!(super::should_staleness_sever(Some(
            RosterState::DegradedStopped
        )));
        assert!(!super::should_staleness_sever(Some(
            RosterState::DegradedGrace
        )));
        assert!(!super::should_staleness_sever(Some(RosterState::Approved)));
        assert!(
            !super::should_staleness_sever(None),
            "no roster → never sweep"
        );
    }
}
