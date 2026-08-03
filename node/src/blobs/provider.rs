use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::Endpoint;
use iroh_blobs::provider::events::{
    AbortReason, ConnectMode, EventMask, EventSender, ObserveMode, ProviderMessage, RequestMode,
    ThrottleMode,
};
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::ticket::BlobTicket;
use iroh_blobs::{BlobFormat, BlobsProtocol, Hash};
use mcpmesh_net::TrustGate;

use crate::audit::{AuditRecord, AuditSink, now_ts};
use crate::blobs::APP_BLOB_ALPN;
use crate::blobs::scope::ScopeStore;
use crate::daemon::RELAY_READY_TIMEOUT;

/// The request-time scope-gate `EventMask` for the serving app-blob provider.
///
/// SECURITY — deny-by-default on every non-GET request type, made EXPLICIT (not left to a vestigial
/// routing quirk). In the pinned iroh-blobs 0.103.0 the generic `EventSender::request()` reads ONLY
/// `mask.get` for EVERY request type (get/get_many/push/observe), so `get: Intercept` currently
/// routes all four to the drain loop, which denies the non-GET kinds explicitly.
/// To keep the deny-by-default INDEPENDENT of that single-field
/// routing, each non-GET request type is ALSO pinned to its most-refusing mask mode, so a FUTURE
/// iroh-blobs that honors the per-type fields still refuses them WITHOUT serving bytes:
///  - `get_many` / `push` = `RequestMode::Disabled`: the crate refuses this request type at the
///    protocol level with `Permission` and fires NO event — registry
///    `iroh-blobs-0.103.0/src/provider/events.rs:504-506` (`RequestMode::Disabled => return
///    Err(e!(ProgressError::Permission))`), doc at `events.rs:62-66`. Our legitimate clients only
///    ever do a single-blob `get`, so disabling these breaks nothing. (`push` is `Disabled` in
///    `EventMask::DEFAULT` already; pinning it makes the intent explicit.)
///  - `observe` = `ObserveMode::Intercept`: `ObserveMode` has NO `Disabled` variant
///    (`events.rs:34-44` — only `None`/`Notify`/`Intercept`), so the strongest available refusal is
///    `Intercept`, which fires an `ObserveRequestReceived` the drain loop denies with `Permission`.
///    `ObserveMode::None` (the default) would mean "no event, request served normally" → a silent
///    bypass, so it is explicitly the WRONG choice here.
///
/// `connected: Intercept` records the authenticated endpoint id; `get: Intercept` scope-checks every
/// single-blob GET (the AC fetch path — unchanged). `throttle` stays at its default
/// (`ThrottleMode::None`) — it is a transfer-throttling knob, not a request-serving gate.
const APP_BLOB_EVENT_MASK: EventMask = EventMask {
    connected: ConnectMode::Intercept,
    // `InterceptLog`, not `Intercept` (#82 ask 2): STRICTLY additive — it is Intercept plus the
    // per-request transfer-event stream. The scope check that authorizes every single-blob GET is
    // unchanged; what it adds is `msg.rx`, which the drain loop turns into `BlobTransfer` frames so
    // an embedder can draw a real progress bar instead of an indeterminate spinner.
    get: RequestMode::InterceptLog,
    get_many: RequestMode::Disabled,
    push: RequestMode::Disabled,
    observe: ObserveMode::Intercept,
    throttle: ThrottleMode::None,
};

/// [`APP_BLOB_EVENT_MASK`] with the #84a byte budget armed — identical except `throttle`.
///
/// Separate from the default because `ThrottleMode::Intercept` makes iroh-blobs round-trip an irpc
/// message PER CHUNK (~16 KiB), so a 4 GiB transfer is ~262k round-trips through the gate loop.
/// The cost is in-process and small, but a deployment that has not configured a budget should not
/// pay it at all. Chosen ONCE in `load`, so changing the config key needs a daemon restart.
const APP_BLOB_EVENT_MASK_METERED: EventMask = EventMask {
    throttle: ThrottleMode::Intercept,
    ..APP_BLOB_EVENT_MASK
};

/// Fold ONE transfer update into the coalescing state, emitting a frame when it warrants one (#82).
///
/// Returns `true` when the transfer is over (terminal event), so the caller stops draining.
///
/// A free function rather than inline in the drain task so the COALESCING RULE — the property that
/// keeps a 4 GiB transfer from pushing ~262k frames through a bounded ring — is directly testable
/// without a live provider and two endpoints.
fn apply_transfer_update(
    st: &mut Option<TransferProgressState>,
    update: &iroh_blobs::provider::events::RequestUpdate,
    bcast: &tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>,
    peer: &Option<String>,
) -> bool {
    use iroh_blobs::provider::events::RequestUpdate;
    use mcpmesh_local_api::BlobTransferState as S;

    match update {
        RequestUpdate::Started(started) => {
            let cur = TransferProgressState {
                hash: started.hash.to_hex().to_string(),
                peer: peer.clone(),
                total: Some(started.size),
                done: 0,
                last_emitted: 0,
            };
            emit_transfer(bcast, &cur, S::Started);
            *st = Some(cur);
            false
        }
        RequestUpdate::Progress(p) => {
            if let Some(cur) = st.as_mut() {
                cur.done = p.end_offset;
                // THE coalescing gate. Without it a 4 GiB transfer emits ~262k frames and every
                // subscriber lags out, losing the audit records that share their stream.
                if cur.done.saturating_sub(cur.last_emitted) >= cur.stride() {
                    cur.last_emitted = cur.done;
                    emit_transfer(bcast, cur, S::Progress);
                }
            }
            false
        }
        RequestUpdate::Completed(_) => {
            if let Some(cur) = st.as_mut() {
                // The final count, ALWAYS emitted — the last `Progress` before this is usually
                // skipped by the stride, so a consumer treating it as the total stops short.
                if let Some(total) = cur.total {
                    cur.done = cur.done.max(total);
                }
                emit_transfer(bcast, cur, S::Completed);
            }
            true
        }
        RequestUpdate::Aborted(_) => {
            if let Some(cur) = st.as_ref() {
                // Reported, not a silent stop: a stalled transfer must be distinguishable from a
                // slow one, which is the issue's fourth consequence.
                emit_transfer(bcast, cur, S::Aborted);
            }
            true
        }
    }
}

/// Minimum byte advance between two coalesced `Progress` frames (#82 ask 2).
///
/// iroh-blobs reports progress per ~16 KiB chunk. Broadcasting each one would push ~262k frames for
/// a 4 GiB transfer through a bounded ring, so every subscriber would see `Lagged` and lose the
/// reachability/audit signal sharing their stream. The stride is `max(this, total / 100)`, so a
/// transfer costs at most ~102 frames whatever its size — and a SMALL blob still gets its
/// `Started`/`Completed` pair, which is what a progress bar actually needs.
const PROGRESS_STRIDE_BYTES: u64 = 1024 * 1024;

/// Coalescing state for ONE in-flight served transfer (#82).
struct TransferProgressState {
    hash: String,
    peer: Option<String>,
    total: Option<u64>,
    done: u64,
    /// `done` as of the last frame emitted — the coalescing anchor.
    last_emitted: u64,
}

impl TransferProgressState {
    /// The byte advance required before another `Progress` frame is worth sending.
    fn stride(&self) -> u64 {
        self.total
            .map_or(PROGRESS_STRIDE_BYTES, |t| {
                (t / 100).max(PROGRESS_STRIDE_BYTES)
            })
            .max(1)
    }
}

/// [`emit_transfer`] for the FETCHING side (#82) — same frame, `direction: Fetch`, and no `peer`:
/// the counterparty is named by the ticket, not by an identity we resolved.
fn emit_fetch(
    bcast: &tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>,
    st: &TransferProgressState,
    state: mcpmesh_local_api::BlobTransferState,
) {
    let _ = bcast.send(crate::daemon::BlobTransfer {
        direction: mcpmesh_local_api::BlobDirection::Fetch,
        hash: st.hash.clone(),
        bytes_done: st.done,
        bytes_total: st.total,
        state,
        peer: None,
    });
}

/// Broadcast one transfer observation, never blocking (#82).
///
/// `send` on a `broadcast::Sender` does not await and errors only when there are no receivers, so a
/// slow or absent subscriber can never stall a transfer — preserving the `try_send` property
/// iroh-blobs itself relies on for progress.
fn emit_transfer(
    bcast: &tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>,
    st: &TransferProgressState,
    state: mcpmesh_local_api::BlobTransferState,
) {
    let _ = bcast.send(crate::daemon::BlobTransfer {
        direction: mcpmesh_local_api::BlobDirection::Serve,
        hash: st.hash.clone(),
        bytes_done: st.done,
        bytes_total: st.total,
        state,
        peer: st.peer.clone(),
    });
}

/// iroh-blobs' leaf/chunk size (`IROH_BLOCK_SIZE`, 16 KiB) — the unit a `Throttle` event reports,
/// and the amount reserved at request admission (#84a review).
const IROH_CHUNK_BYTES: u64 = 16 * 1024;

/// The gated app-blob provider. `events` is `Some` for a serving daemon (the request-time
/// scope Intercept gate is armed) and `None` for a caller-only fetcher. `scopes` is the persisted
/// scope table; a fetcher gets an empty one it never mutates.
///
/// The drain loop's `Receiver<ProviderMessage>` is moved into a task
/// spawned once in `load`. The loop lives as long as ANY `EventSender` clone lives; `AppBlobs` holds
/// one in `self.events` for the provider's lifetime (the daemon holds `AppBlobs` for its lifetime),
/// and every `protocol()` clones another into the `BlobsProtocol`. So the gate loop runs until the
/// daemon drops the provider — never terminating mid-serve.
pub struct AppBlobs {
    store: FsStore,
    endpoint: Endpoint,
    /// Where coalesced transfer progress goes (#82 ask 2). `None` on a fetcher-only or fixture
    /// provider, which then does no progress work at all.
    transfers: Option<tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>>,
    events: Option<EventSender>,
    scopes: Arc<ScopeStore>,
    /// The request-time gate loop's handle, so shutdown can END it deterministically (#61).
    ///
    /// That task owns an `Arc<dyn TrustGate>`, which on a pairing daemon holds the `PeerStore` and
    /// therefore the redb data-dir lock. It used to be a fire-and-forget `tokio::spawn` whose handle
    /// was discarded: the loop exits when the last `EventSender` drops, but only once the task is
    /// next polled, so nothing guaranteed the lock was released by the time `shutdown` returned.
    /// Unreachable while the provider was roster-only — an embedded `NodeBuilder` node never built
    /// one — and it broke `shutdown_frees_the_root_*` the moment app blobs reached pairing mode.
    gate_loop: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Wait (bounded) for the relay handshake before minting a ticket (#83 ask 3).
    ///
    /// OFF by default, switched ON by boot alone. The wait exists so a ticket carries the
    /// home-relay URL a fetcher needs across NAT; on a relay-disabled endpoint `online()` never
    /// completes, so it is a guaranteed [`RELAY_READY_TIMEOUT`] of dead time per mint. Defaulting
    /// off keeps that cost out of every test fixture (relay-disabled by construction) while
    /// production — the only place the relay URL matters — opts in explicitly.
    relay_wait: std::sync::atomic::AtomicBool,
    /// Serializes the HASH-MEMBERSHIP mutations (#104).
    ///
    /// `ScopeStore` makes each individual mutation atomic, but `republish` is a read-check-write:
    /// it verifies the blob is complete (an `.await` on the store) and only then inserts. A
    /// concurrent `blob_unpublish` landing in that gap is silently undone — both verbs return
    /// success and the operator's revocation disappears. An async lock is required because the
    /// completeness check awaits, so `ScopeStore`'s `std::sync::Mutex` cannot be held across it.
    ///
    /// Held by every verb that adds or removes a hash from a scope; grant/revoke of PRINCIPALS do
    /// not contend, since they cannot race a membership decision.
    hash_membership: tokio::sync::Mutex<()>,
    /// TEST-ONLY: pause between `republish`'s completeness check and its scope insert, so the
    /// interleaving #104 describes is deterministic rather than timing-dependent.
    #[cfg(test)]
    republish_delay: std::sync::Mutex<Option<std::time::Duration>>,
    /// TEST-ONLY: pause between `publish_scope`'s import and its scope insert (#104).
    #[cfg(test)]
    publish_delay: std::sync::Mutex<Option<std::time::Duration>>,
}

impl AppBlobs {
    /// End the request-time gate loop, releasing the `TrustGate` (and with it the redb handle).
    /// Idempotent; a fetcher has no loop and is a no-op.
    ///
    /// The `await` after `abort` is deliberate but NOT load-bearing for the current test: dropping
    /// the provider already closes the event channel, and abort-without-await passes today. It is
    /// here so the release is deterministic rather than dependent on when the runtime reaps the
    /// task — the racy version is the kind that fails under load, not in CI.
    pub async fn shutdown(&self) {
        let handle = self.gate_loop.lock().await.take();
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
    }
}

impl AppBlobs {
    /// A caller-only fetcher: an `FsStore` + endpoint, NO scope gate (`events: None`), an empty
    /// scopes table it never persists. Used caller-side (the fetch path) and by the ungated tests.
    pub async fn open_fetcher(blobs_dir: PathBuf, endpoint: Endpoint) -> Result<Arc<Self>> {
        tokio::fs::create_dir_all(&blobs_dir)
            .await
            .with_context(|| format!("create blobs dir {}", blobs_dir.display()))?;
        let store = FsStore::load(&blobs_dir)
            .await
            .with_context(|| format!("load blob store {}", blobs_dir.display()))?;
        Ok(Arc::new(Self {
            store,
            endpoint,
            // A fetcher-only provider (open_fetcher) has no mesh to broadcast into.
            transfers: None,
            events: None,
            relay_wait: std::sync::atomic::AtomicBool::new(false),
            hash_membership: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            republish_delay: std::sync::Mutex::new(None),
            #[cfg(test)]
            publish_delay: std::sync::Mutex::new(None),
            scopes: Arc::new(ScopeStore::new(blobs_dir.join("scopes.json"))),
            gate_loop: tokio::sync::Mutex::new(None),
        }))
    }

    /// The GATED provider: an `FsStore` + the request-time scope Intercept `EventSender`.
    /// Spawns the drain loop ONCE, wired to the trust `gate` (resolve endpoint → identity) and
    /// `scopes` (the authz table). `FsStore::load` is async/fallible;
    /// the dir is created first.
    pub async fn load(
        blobs_dir: PathBuf,
        scopes: Arc<ScopeStore>,
        gate: Arc<dyn TrustGate>,
        endpoint: Endpoint,
        audit: AuditSink,
        limits: Arc<crate::limits::MeshLimiters>,
        // #82 ask 2: the ring coalesced transfer progress rides. `None` for fixtures that build a
        // provider without a mesh — the gate loop then does no progress work at all.
        transfers: Option<tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>>,
    ) -> Result<Arc<Self>> {
        tokio::fs::create_dir_all(&blobs_dir)
            .await
            .with_context(|| format!("create blobs dir {}", blobs_dir.display()))?;
        let store = FsStore::load(&blobs_dir)
            .await
            .with_context(|| format!("load blob store {}", blobs_dir.display()))?;
        // The request-time scope gate: `APP_BLOB_EVENT_MASK` intercepts connect + single-blob GET,
        // and pins every non-GET request type to deny-by-default (Disabled/Intercept — see the
        // const's SECURITY note). Since `get: Intercept` also routes
        // get_many/observe/push to the drain loop today; the pinned fields keep them refused even if
        // a future iroh-blobs honors the per-type fields directly.
        // Only pay the per-chunk intercept when a budget is actually configured (#84a).
        let mask = if limits.blob_bytes_enabled() {
            APP_BLOB_EVENT_MASK_METERED
        } else {
            APP_BLOB_EVENT_MASK
        };
        let (events, rx) = EventSender::channel(64, mask);
        let gate_loop = spawn_gate_loop(rx, gate, scopes.clone(), audit, limits, transfers.clone());
        Ok(Arc::new(Self {
            store,
            endpoint,
            transfers,
            events: Some(events),
            scopes,
            gate_loop: tokio::sync::Mutex::new(Some(gate_loop)),
            relay_wait: std::sync::atomic::AtomicBool::new(false),
            hash_membership: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            republish_delay: std::sync::Mutex::new(None),
            #[cfg(test)]
            publish_delay: std::sync::Mutex::new(None),
        }))
    }

    /// The `BlobsProtocol` handler the accept loop dispatches `APP_BLOB_ALPN` to. Carries the scope
    /// gate when `events` is `Some` (a serving daemon); ungated for a fetcher. `&self.store`
    /// (a `&FsStore`) deref-coerces to `&Store`; `self.events.clone()` shares the ONE drain loop.
    pub fn protocol(&self) -> BlobsProtocol {
        BlobsProtocol::new(&self.store, self.events.clone())
    }

    /// TEST-ONLY: register an app-blob ALPN accept handler directly on `endpoint`, BYPASSING the
    /// accept-time trust gate (the request-time scope gate still runs via `protocol()`'s events).
    /// Production accept ALWAYS goes through the gated daemon loop (`spawn_accept_loop`'s
    /// `APP_BLOB_ALPN` arm: resolve → 401 + rate-limit + check-register); this exists only so
    /// same-file unit tests can serve blobs without assembling a daemon. `#[cfg(test)]` so it can
    /// never leak into a production accept path.
    #[cfg(test)]
    pub(crate) fn spawn_accept(&self, endpoint: &Endpoint) {
        let proto = self.protocol();
        let ep = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                if let Ok(conn) = incoming.await
                    && conn.alpn() == APP_BLOB_ALPN
                {
                    let _ = iroh::protocol::ProtocolHandler::accept(&proto, conn).await;
                }
            }
        });
    }

    /// Add a LOCAL file to the store (the large-blob idiom — `add_path`) and return
    /// `(ticket_string, blake3_hex)` WITHOUT touching any scope (used for the ungated round-trip).
    pub async fn publish_path(&self, path: &Path) -> Result<(String, String)> {
        let tag = self
            .store
            .blobs()
            .add_path(path)
            .await
            .with_context(|| format!("add blob from {}", path.display()))?;
        let ticket = self.ticket_for(tag.hash).await;
        Ok((ticket.to_string(), tag.hash.to_hex().to_string()))
    }

    /// Publish a LOCAL file INTO a scope: add it to the store AND record its hash in the
    /// named scope (single-writer via `ScopeStore`). Returns `(ticket_string, blake3_hex)`.
    pub async fn publish_scope(&self, scope: &str, path: &Path) -> Result<(String, String)> {
        let (ticket, hash_hex) = self.publish_path(path).await?;
        // #104: membership mutations are serialized as a family, so an import that finishes while
        // an unpublish is in flight cannot interleave with it either.
        let _membership = self.hash_membership.lock().await;
        #[cfg(test)]
        {
            let d = *self
                .publish_delay
                .lock()
                .expect("publish delay lock not poisoned");
            if let Some(d) = d {
                tokio::time::sleep(d).await;
            }
        }
        self.scopes.publish_hash(scope, &hash_hex)?;
        Ok((ticket, hash_hex))
    }

    /// Add a hash ALREADY COMPLETE in the local store to a scope (#83) — the "every recipient is a
    /// source" primitive. Returns a ticket addressed to THIS node.
    ///
    /// No filesystem round-trip: `blob_publish { scope, path }` was the only way back in, and it
    /// re-imported bytes the store already held, producing a third copy with nothing to reclaim it
    /// (#80).
    ///
    /// **Completeness is checked first, and it is load-bearing.** Recording a hash in a scope
    /// ADVERTISES it: the gate authorizes GETs for it and the returned ticket names us as the
    /// source. `Blobs::has` is true only for `BlobStatus::Complete`, so an interrupted fetch's
    /// partial bytes are refused exactly like absent ones — advertising what we cannot serve would
    /// convert the publisher going offline into a hang at every fetcher.
    ///
    /// Idempotent (the scope's hash set is a set).
    ///
    /// **Do NOT call this unconditionally after every fetch.** Republishing into a scope
    /// re-exposes the hash to every principal that scope ALREADY grants — including a hash an
    /// operator deliberately withdrew with `blob_unpublish`, which removes reachability but not
    /// the bytes, so `has()` stays true forever and a later republish silently restores access with
    /// no grant call and no warning. Republish when the user asks to share, not as fetch hygiene.
    ///
    /// **Grants nobody.** The republisher chooses a scope they already control; inheriting the
    /// original publisher's grant list would be a silent authorization transfer. Sharing is
    /// `blob_grant`'s job.
    pub async fn republish(&self, scope: &str, hash_hex: &str) -> Result<(String, String)> {
        // #104: hold the membership lock across the completeness CHECK and the scope INSERT. They
        // are a read-check-write with an `.await` between them, so a concurrent `blob_unpublish`
        // landing in the gap was silently undone — both verbs returned success and the operator's
        // revocation vanished.
        //
        // What this does NOT do: make a revocation unloseable. The mutex gives mutual exclusion in
        // LOCK-ACQUISITION order, not request-arrival order, so an unpublish that acquires FIRST
        // still has its effect erased by a republish acquiring second — both returning success.
        // That residue is the same semantic hazard the doc comment above describes (republish
        // re-adds to a scope whose grants unpublish never touched); the lock removes the
        // atomicity bug, where a decision made BEFORE the unpublish landed AFTER it. Eliminating
        // the class needs state (a per-(scope, hash) revocation generation re-validated before the
        // insert), not exclusion — tracked separately.
        let _membership = self.hash_membership.lock().await;
        // Scope first: a typo'd scope must not report as a missing blob.
        if !self.scopes.has_scope(scope) {
            anyhow::bail!(crate::daemon::NoSuchBlobScope(scope.to_string()));
        }
        // Parse (panic-safe) AND NORMALIZE before touching the scope. The gate compares against
        // the canonical lowercase hex (`msg.request.hash.to_hex()`), so inserting the caller's raw
        // string would record an entry that authorizes nothing: `blob_list` would show the file as
        // shared, every fetcher would be denied, and `blob_unpublish` — which normalizes — could
        // never remove it. That is #62's silent-no-op defect re-entered from the other side.
        // `blob_publish` is safe only because it stores `tag.hash.to_hex()`.
        let hash = crate::blobs::parse_blob_hash(hash_hex)?;
        let canonical = hash.to_hex().to_string();
        if !self.store.blobs().has(hash).await.unwrap_or(false) {
            anyhow::bail!(crate::daemon::NoSuchBlob(canonical));
        }
        // #107: a deliberate withdrawal outranks "we still hold the bytes". Checked INSIDE the
        // membership lock, so an unpublish that lands first cannot be overtaken — which is the
        // half a lock alone could never fix, since exclusion is in acquisition order, not
        // request-arrival order.
        if self.scopes.is_withdrawn(scope, &canonical) {
            anyhow::bail!(crate::daemon::BlobWithdrawn {
                scope: scope.to_string(),
                hash: canonical,
            });
        }
        #[cfg(test)]
        {
            let d = *self
                .republish_delay
                .lock()
                .expect("republish delay lock not poisoned");
            if let Some(d) = d {
                tokio::time::sleep(d).await;
            }
        }
        self.scopes.publish_hash(scope, &canonical)?;
        // Release BEFORE minting: `ticket_for` waits up to RELAY_READY_TIMEOUT (3s) for the relay
        // handshake, and production turns that wait on. Holding the membership lock across it
        // would block every concurrent `blob_unpublish` for the full 3s on a node whose handshake
        // has not completed — making the REVOCATION path pay for the publisher's latency, which is
        // backwards on a security surface. The insert above is the last thing the lock must cover.
        drop(_membership);
        Ok((self.ticket_for(hash).await.to_string(), canonical))
    }

    /// Mint a ticket for a hash this node holds, addressed to this node.
    ///
    /// Waits (bounded by [`RELAY_READY_TIMEOUT`]) for the endpoint to come online first, so the
    /// address carries the home-relay URL a fetcher needs across NAT (#83 ask 3). `mint_invite` has
    /// done this since #4; the blob path minted immediately, so a file published shortly after boot
    /// or after a network change could yield a direct-addresses-only ticket: LAN-dialable and
    /// NAT-dead. A CAP, not a fixed wait — production returns the instant the relay handshake
    /// completes, and the relay-disabled test preset simply falls through to direct addresses.
    async fn ticket_for(&self, hash: Hash) -> BlobTicket {
        if self.relay_wait.load(std::sync::atomic::Ordering::Relaxed) {
            let _ = tokio::time::timeout(RELAY_READY_TIMEOUT, self.endpoint.online()).await;
        }
        BlobTicket::new(self.endpoint.addr(), hash, BlobFormat::Raw)
    }

    /// Turn the relay-ready wait ON. Boot calls this; nothing else should.
    /// Is the relay-ready wait on? Test-only — production sets it and never asks (#105).
    #[cfg(test)]
    pub(crate) fn relay_wait_enabled(&self) -> bool {
        self.relay_wait.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Turn the relay-ready wait ON. Boot calls this; nothing else should.
    pub(crate) fn enable_relay_wait(&self) {
        self.relay_wait
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Grant a scope to a STABLE principal — a group name, a user_id, or an `eid:` device
    /// principal (never a display nickname, #38) — persisted single-writer.
    pub fn grant(&self, scope: &str, principal: &str) -> Result<()> {
        self.scopes.grant(scope, principal)
    }

    /// Revoke `principals` from every scope (unpair hygiene, #38) — persisted single-writer.
    /// Returns whether anything changed.
    pub fn revoke_principals(&self, principals: &[String]) -> Result<bool> {
        self.scopes.revoke_principals(principals)
    }

    /// Revoke `principals` from ONE scope (#62, `blob_revoke`) — the per-file un-share, the blob
    /// analogue of #44. Distinct from [`revoke_principals`](Self::revoke_principals), which is
    /// unpair hygiene across every scope.
    pub fn revoke_from_scope(&self, scope: &str, principals: &[String]) -> Result<bool> {
        self.scopes.revoke_from_scope(scope, principals)
    }

    /// Does this scope exist? The handlers use it to reject an unknown scope rather than acking it.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.has_scope(scope)
    }

    /// Remove a hash from ONE scope (#62, `blob_unpublish`).
    ///
    /// This is the AUTHORIZATION half and takes effect at once for NEW requests: the scope gate
    /// requires the hash to be listed in some scope, so a subsequent GET is refused at the request
    /// hook. The BYTES remain in the store — there is no reclaim (#80) — so do not describe this to
    /// a user as deletion. A transfer already streaming is not interrupted.
    pub async fn unpublish(&self, scope: &str, hash_hex: &str) -> Result<bool> {
        // NORMALIZE FIRST (#107 review). Since #107 this call WRITES a persistent key into the
        // withdrawn set, so a non-canonical rendering no longer merely fails to match — it records
        // a junk entry that no `republish` will ever compare equal to, in a set nothing prunes.
        // The control socket normalizes before calling, but `AppBlobs` is public API of a
        // published crate, so a library consumer passing uppercase hex must not poison the
        // sidecar. `republish` already normalizes one function away.
        let canonical = crate::blobs::parse_blob_hash(hash_hex)?
            .to_hex()
            .to_string();
        // #104: same lock as `republish`, so a revocation cannot land inside a republish's
        // check-then-insert window and be overwritten by it.
        let _membership = self.hash_membership.lock().await;
        self.scopes.unpublish_hash(scope, &canonical)
    }

    /// TEST-ONLY: pause between the import and the scope insert (#104).
    #[cfg(test)]
    pub(crate) fn set_publish_delay(&self, d: std::time::Duration) {
        *self
            .publish_delay
            .lock()
            .expect("publish delay lock not poisoned") = Some(d);
    }

    /// TEST-ONLY: pause between the completeness check and the scope insert (#104).
    #[cfg(test)]
    pub(crate) fn set_republish_delay(&self, d: std::time::Duration) {
        *self
            .republish_delay
            .lock()
            .expect("republish delay lock not poisoned") = Some(d);
    }

    /// The current scope table (name, hashes, grants) for `list`.
    /// One filtered, bounded page of the scope table (#84b).
    pub fn list_page(
        &self,
        q: &crate::blobs::scope::ListQuery,
    ) -> anyhow::Result<crate::blobs::scope::ScopePage> {
        self.scopes.list_page(q)
    }

    pub fn list(&self) -> Vec<crate::blobs::scope::ScopeRow> {
        self.scopes.list()
    }

    /// Fetch a ticket THROUGH this endpoint over `APP_BLOB_ALPN`, streaming BLAKE3-verified bytes
    /// into `self.store` (the Downloader cannot dial a custom ALPN — see [`APP_BLOB_ALPN`]).
    /// Returns the verified hash. A provider that refuses this
    /// caller (accept-time 401 or request-time Permission) surfaces here as an `Err`.
    pub async fn fetch(&self, ticket_str: &str) -> Result<Hash> {
        let ticket: BlobTicket = ticket_str.parse().context("parse blob ticket")?;
        let conn = self
            .endpoint
            .connect(ticket.addr().clone(), APP_BLOB_ALPN)
            .await
            .context("dial app-blob provider")?;
        // #82 ask 2: consume the progress stream instead of dropping it on the floor. Same
        // coalescing rule as the serving side — `GetProgressItem::Progress` arrives per chunk, so
        // an uncoalesced fetch would flood the ring exactly as an uncoalesced serve would.
        //
        // `bytes_total` is NOT known here: the fetch side learns the size only as bytes arrive, so
        // the frame carries `None` and a consumer renders an indeterminate bar until `Completed`.
        // Reporting the ticket's hash as a size, or guessing, would be worse than saying so.
        use n0_future::StreamExt as _;
        let hash_hex = ticket.hash().to_hex().to_string();
        let mut stream = std::pin::pin!(self.store.remote().fetch(conn, ticket.hash()).stream());
        let mut st = TransferProgressState {
            hash: hash_hex,
            peer: None,
            total: None,
            done: 0,
            last_emitted: 0,
        };
        if let Some(b) = &self.transfers {
            emit_fetch(b, &st, mcpmesh_local_api::BlobTransferState::Started);
        }
        let mut outcome: Result<()> = Ok(());
        while let Some(item) = stream.next().await {
            match item {
                iroh_blobs::api::remote::GetProgressItem::Progress(done) => {
                    st.done = done;
                    if let Some(b) = &self.transfers
                        && st.done.saturating_sub(st.last_emitted) >= st.stride()
                    {
                        st.last_emitted = st.done;
                        emit_fetch(b, &st, mcpmesh_local_api::BlobTransferState::Progress);
                    }
                }
                iroh_blobs::api::remote::GetProgressItem::Done(_) => {
                    if let Some(b) = &self.transfers {
                        emit_fetch(b, &st, mcpmesh_local_api::BlobTransferState::Completed);
                    }
                }
                iroh_blobs::api::remote::GetProgressItem::Error(e) => {
                    if let Some(b) = &self.transfers {
                        emit_fetch(b, &st, mcpmesh_local_api::BlobTransferState::Aborted);
                    }
                    outcome = Err(anyhow::anyhow!("{e}"));
                }
            }
        }
        outcome.context("fetch app blob")?;
        Ok(ticket.hash())
    }

    /// Read a fully-present blob's bytes out of the store (callers/tests consume the fetched content).
    pub async fn read_bytes(&self, hash: Hash) -> Result<Bytes> {
        self.store
            .get_bytes(hash)
            .await
            .context("read fetched app blob")
    }

    /// STREAM a blob from the store to `dest`, returning the bytes written (#82).
    ///
    /// Peak memory is independent of blob size. The `read_bytes` + `fs::write` path this replaces
    /// materialized the whole blob as one `Bytes` first — and `get_bytes`' own iroh doc warns it
    /// *"will run out of memory when called for very large blobs"*. On a small headless node a
    /// multi-GB fetch was an OOM kill rather than a slow transfer.
    ///
    /// `ExportMode::Copy` (via `export`) writes an independent file, so the destination survives a
    /// later store reclaim. `ExportMode::TryReference` would avoid the second copy but ties the
    /// exported file's lifetime to the store — a separate decision, see #82's item 3.
    pub async fn export_to(&self, hash: Hash, dest: &Path) -> Result<u64> {
        self.store
            .blobs()
            .export(hash, dest)
            .await
            .with_context(|| format!("export app blob to {}", dest.display()))
    }
}

/// Which `blob_fetch` status to record, and whether to record at all (#84a fourth review).
///
/// Derived from the DECISION, never from a flag that excludes one variant: an earlier version used
/// `!matches!(decision, Err(RateLimited))`, so a GET refused with `Permission` was audited as a
/// successful fetch. The wire answer was right and the audit trail — the surface an operator
/// investigates with — lied.
///
/// `None` means "say nothing": a budget refusal is reported ONCE per endpoint until it fetches
/// successfully again. Refusals are cheap now that they precede any bytes, so recording every one
/// trades an uplink DoS for an audit-log DoS (measured ~2250 records/s).
fn audit_status(
    decision: &Result<(), AbortReason>,
    endpoint: Option<mcpmesh_net::EndpointId>,
    reported: &mut HashSet<mcpmesh_net::EndpointId>,
) -> Option<&'static str> {
    match decision {
        Err(AbortReason::Permission) => Some("denied"),
        Err(AbortReason::RateLimited) => match endpoint {
            // Already told the operator about this peer; stay quiet until it recovers.
            Some(eid) if !reported.insert(eid) => None,
            _ => Some("rate_limited"),
        },
        Ok(()) => {
            if let Some(eid) = endpoint {
                reported.remove(&eid); // recovered: a future refusal is news again
            }
            Some("ok")
        }
    }
}

/// The full GET-admission decision: authz first, then budget (#84a review).
///
/// Exists because pinning `request_budget_ok` alone left the CRITICAL fix unpinned — deleting the
/// budget check from the GET arm passed every test while a probe measured the full 94x regression.
/// That is verbatim the critique this branch made of the event mask, and it applied to the fix
/// itself.
fn get_admission(
    allow: bool,
    endpoint: Option<&mcpmesh_net::EndpointId>,
    limits: &crate::limits::MeshLimiters,
) -> Result<(), AbortReason> {
    if !allow {
        return Err(AbortReason::Permission);
    }
    // An unattributable connection is an ATTRIBUTION failure, not a budget one — same rule and
    // same reason code as `throttle_decision`. Reporting RateLimited here would tell a peer
    // "try again later" about a condition that will never clear.
    let Some(eid) = endpoint else {
        return Err(AbortReason::Permission);
    };
    if !request_budget_ok(Some(eid), limits) {
        return Err(AbortReason::RateLimited);
    }
    Ok(())
}

/// Is there budget to ADMIT a new GET request (#84a review)?
///
/// Separate from [`throttle_decision`] because the per-chunk hook is not sufficient on its own:
/// iroh-blobs writes the chunk BEFORE the hook runs, and a refusal resets only the stream, so a
/// peer that ignores the abort collects one free chunk per request forever. This is the gate that
/// runs before any bytes.
///
/// Reserves [`IROH_CHUNK_BYTES`] rather than peeking: a zero-cost check always passes, and
/// reserving makes an opened-but-undrained request cost the peer something. The side effect worth
/// knowing: the budget therefore also caps GETs at about `blob_bytes_per_min / 16384` per minute
/// REGARDLESS of blob size — a 4 MiB/min budget is ~256 fetches/min even for 100-byte blobs.
///
/// **Fails CLOSED** on `None` (no `ClientConnected` record), matching [`throttle_decision`].
fn request_budget_ok(
    endpoint: Option<&mcpmesh_net::EndpointId>,
    limits: &crate::limits::MeshLimiters,
) -> bool {
    // FAIL CLOSED on an unattributable connection, matching `throttle_decision`. The first version
    // used `is_none_or`, i.e. the inverse of its sibling's documented rule — masked today because
    // the caller short-circuits on `!allow`, but a latent trap for the next edit (#84a review).
    endpoint.is_some_and(|eid| limits.admit_blob_bytes(eid, IROH_CHUNK_BYTES))
}

/// The app-blob byte-budget decision for one CHUNK, mid-transfer (#84a).
///
/// The top-up to [`request_budget_ok`], not the gate: iroh-blobs writes the chunk before this
/// runs, and a refusal resets only the stream. Pure, so both rules are testable without a live
/// transfer; the async arm is a thin shell over it.
fn throttle_decision(
    endpoint: Option<&mcpmesh_net::EndpointId>,
    size: u64,
    limits: &crate::limits::MeshLimiters,
) -> Result<(), AbortReason> {
    match endpoint {
        // FAIL CLOSED. A chunk for a connection we cannot attribute must not be metered against
        // nobody — that is the same bypass as metering per connection, by another route.
        // `ClientConnected` already refuses an endpoint-less connection, so reaching here means
        // something is wrong and the safe answer is to refuse.
        None => Err(AbortReason::Permission),
        // Over budget: RateLimited, never Permission. The peer IS authorized; pacing failed.
        // Conflating them would make a bandwidth event read as an authz denial in the audit trail,
        // and iroh-blobs documents RateLimited as "OK to try again later" — which is true here and
        // false for a permission failure.
        Some(eid) if !limits.admit_blob_bytes(eid, size) => Err(AbortReason::RateLimited),
        Some(_) => Ok(()),
    }
}

/// The request-time scope Intercept drain loop (the security core). Single-consumer: this
/// task owns `rx`, so the `connection_id → endpoint_id` map is loop-local with NO lock
/// — FIFO delivery guarantees `ClientConnected(conn)` precedes any
/// `GetRequestReceived(conn)` on that connection. SECURITY-CRITICAL:
///  - `ClientConnected`: record the AUTHENTICATED `endpoint_id` (QUIC/TLS) → reply `Ok(())` to admit
///    (the accept-time gate already vetted the endpoint; the GET hook is the per-hash boundary). A
///    missing endpoint id (never on an authenticated conn) is denied defensively.
///  - `GetRequestReceived`: resolve the endpoint via the trust gate to its identity and ALLOW iff a
///    scope contains the hash AND grants one of the caller's principals — `groups ∪ {eid} ∪
///    {user_id}`, the shared `principal_set` (nicknames excluded, #38) — else `Permission`,
///    BEFORE any bytes (the Intercept path blocks the transfer on the provider's `rx.await??`).
///  - get_many/observe/push (all routed through `mask.get`): DENY
///    explicitly — deny-by-default, the store is not a general filesystem surface. Belt-and-suspenders
///    with `APP_BLOB_EVENT_MASK`, which ALSO pins these types (get_many/push = `Disabled`, observe =
///    `Intercept`): if a future iroh-blobs delivers them as events instead of refusing at the mask,
///    they are still denied here.
fn spawn_gate_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    gate: Arc<dyn TrustGate>,
    scopes: Arc<ScopeStore>,
    audit: AuditSink,
    limits: Arc<crate::limits::MeshLimiters>,
    // #82 ask 2: where coalesced transfer progress goes. `None` in fixtures that do not care.
    transfers: Option<tokio::sync::broadcast::Sender<crate::daemon::BlobTransfer>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut conns: HashMap<u64, mcpmesh_net::EndpointId> = HashMap::new();
        // #84a review: endpoints already audited for a budget refusal. A refusal is CHEAP —
        // measured 2250 records/s — so recording every one trades an uplink DoS for an audit-log
        // DoS, which is strictly worse because the attacker no longer has to move bytes. The spec
        // said "first only, or a peer hammering the budget writes an unbounded audit log" (#88);
        // that had not shipped. Cleared when the endpoint next fetches successfully, so a peer
        // that recovers and re-offends is reported again.
        let mut budget_reported: HashSet<mcpmesh_net::EndpointId> = HashSet::new();
        while let Some(msg) = rx.recv().await {
            match msg {
                ProviderMessage::ClientConnected(msg) => {
                    let res = match msg.endpoint_id {
                        Some(eid) => {
                            conns.insert(msg.connection_id, (*eid.as_bytes()).into());
                            Ok(())
                        }
                        None => Err(AbortReason::Permission),
                    };
                    msg.tx.send(res).await.ok();
                }
                // #84a: meter BYTES per authenticated endpoint. The connection limiter counts
                // connections, which cannot see one granted peer re-pulling a 4 GB blob on each of
                // 60 connections a minute.
                //
                // `Throttle` names a CONNECTION, so the endpoint comes from the same loop-local
                // map `ClientConnected` populates — metering per connection would hand a peer a
                // fresh budget per connection, which IS the bypass.
                ProviderMessage::Throttle(msg) => {
                    let res =
                        throttle_decision(conns.get(&msg.connection_id), msg.size, limits.as_ref());
                    msg.tx.send(res).await.ok();
                }
                ProviderMessage::GetRequestReceived(msg) => {
                    // Resolve the authenticated caller for BOTH the authz decision and the audit
                    // attribution (peer is the gate-resolved identity, not self-asserted).
                    let identity = conns
                        .get(&msg.connection_id)
                        .and_then(|eid| gate.resolve(eid));
                    let hash_hex = msg.request.hash.to_hex().to_string();
                    let allow = msg.request.ranges.is_blob()
                        && identity.as_ref().is_some_and(|identity| {
                            // The grant namespace is THE flat principal set —
                            // groups ∪ {eid} ∪ {user_id} — via the ONE shared
                            // `principal_set` (same expansion as the mesh allow check and
                            // the plugin seam). Nicknames are deliberately EXCLUDED (#38):
                            // scope grants are written as stable principals at grant time,
                            // so a pairing-mode peer is granted (and fetches) by its
                            // `eid:` device principal; legacy nickname-audience grants
                            // stop matching BY DESIGN (the doctor lint + release notes
                            // cover the migration). Default-deny is untouched: an unlisted
                            // principal still gets `Permission` before any bytes.
                            let eid = identity.endpoint.principal();
                            let principals: HashSet<&str> = mcpmesh_local_api::principal_set(
                                Some(&eid),
                                identity.user_id.as_deref(),
                                &identity.groups,
                            )
                            .into_iter()
                            .collect();
                            scopes.snapshot().allows(&hash_hex, &principals)
                        });
                    // Audit the fetch: peer + hash + status (ok/denied). A COUNT/ref only —
                    // never blob content. Attributes to the resolved user_id/nickname, or "unknown".
                    let peer = identity
                        .as_ref()
                        .map(|i| i.user_id.clone().unwrap_or_else(|| i.name.clone()));
                    // #84a: enforce the byte budget HERE, before any bytes, as well as per chunk.
                    // The per-chunk `Throttle` hook fires AFTER iroh-blobs has written the chunk,
                    // and a refusal resets only the STREAM — the connection survives and nothing
                    // bounds requests per connection. So a peer ignoring the abort gets one free
                    // ~16 KiB chunk per request, indefinitely: measured at ~1800x the configured
                    // rate from a single connection. Refusing the REQUEST is what bounds that.
                    //
                    // Reserves one chunk rather than peeking: a zero-cost check would always pass
                    // (`tokens >= 0.0`), and reserving means a peer that opens many requests it
                    // never drains still pays for them. Evaluated ONCE — calling it twice would
                    // double-charge.
                    let decision =
                        get_admission(allow, conns.get(&msg.connection_id), limits.as_ref());
                    // #84a: a refusal is REPORTED, not silent — the issue's complaint was that
                    // mcpmesh "neither refuses it nor reports it happened". But only the FIRST per
                    // endpoint until it succeeds again: see `budget_reported`.
                    let conn_eid = conns.get(&msg.connection_id).copied();
                    // Derived from the DECISION, not by excluding one variant. The first version
                    // computed `budget_ok = !matches!(decision, Err(RateLimited))`, so a GET
                    // refused with `Permission` — an unattributable connection — was audited as a
                    // successful fetch. The wire answer was right; the audit trail lied, which is
                    // the surface an operator investigates with (#84a third review).
                    let status = audit_status(&decision, conn_eid, &mut budget_reported);
                    if let Some(status) = status {
                        audit.record(AuditRecord::blob_fetch(
                            now_ts(),
                            peer,
                            hash_hex,
                            status.into(),
                            // #57 second surface: the record of who fetched which BYTES is the
                            // one where two-devices-one-nickname is most likely the actual
                            // question — attribute the authenticated endpoint, not the display
                            // name alone.
                            conn_eid.map(|eid| eid.principal()),
                        ));
                    }
                    let admitted = decision.is_ok();
                    msg.tx.send(decision).await.ok();
                    // #82 ask 2: `InterceptLog` hands us this request's transfer-event stream.
                    // Drained in its OWN task — draining inline would block the gate loop for the
                    // whole transfer, and the gate loop is what authorizes every OTHER request.
                    // Only for an ADMITTED request: a refused one transfers nothing, so its stream
                    // yields nothing and a `Started` frame would be a lie.
                    // The update receiver MUST be consumed, whether or not anyone wants the
                    // frames. Dropping it makes the provider's own `transfer_started` send fail,
                    // which ABORTS the transfer — an admitted, authorized fetch then errors with
                    // "fetch app blob". Only spawning this when a broadcast existed is exactly that
                    // bug: every fixture built with `transfers: None` broke.
                    if admitted {
                        let bcast = transfers.clone();
                        let peer_principal = conn_eid.map(|eid| eid.principal());
                        // Drained in its OWN task: doing it inline would block the gate loop —
                        // which authorizes every OTHER request — for the whole transfer. The
                        // receiver's type is irpc-internal, so it is captured rather than named.
                        let mut updates = msg.rx;
                        tokio::spawn(async move {
                            let mut st = None;
                            while let Ok(Some(update)) = updates.recv().await {
                                // Drained unconditionally; only the FRAMES are optional.
                                let terminal = match &bcast {
                                    Some(b) => {
                                        apply_transfer_update(&mut st, &update, b, &peer_principal)
                                    }
                                    None => matches!(
                                        update,
                                        iroh_blobs::provider::events::RequestUpdate::Completed(_)
                                            | iroh_blobs::provider::events::RequestUpdate::Aborted(
                                                _
                                            )
                                    ),
                                };
                                if terminal {
                                    return;
                                }
                            }
                            // The stream ended with no terminal event (peer vanished, tracker
                            // dropped). A consumer waiting on Completed/Aborted would hang, so
                            // synthesize Aborted rather than leave a transfer open forever.
                            if let (Some(b), Some(cur)) = (&bcast, st.as_ref()) {
                                emit_transfer(
                                    b,
                                    cur,
                                    mcpmesh_local_api::BlobTransferState::Aborted,
                                );
                            }
                        });
                    }
                }
                // Deny-by-default for every non-GET request type.
                ProviderMessage::GetManyRequestReceived(msg) => {
                    msg.tx.send(Err(AbortReason::Permission)).await.ok();
                }
                ProviderMessage::PushRequestReceived(msg) => {
                    msg.tx.send(Err(AbortReason::Permission)).await.ok();
                }
                ProviderMessage::ObserveRequestReceived(msg) => {
                    msg.tx.send(Err(AbortReason::Permission)).await.ok();
                }
                ProviderMessage::ConnectionClosed(msg) => {
                    conns.remove(&msg.connection_id);
                }
                _ => {}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{PROGRESS_STRIDE_BYTES, TransferProgressState, apply_transfer_update};
    use iroh_blobs::provider::events::{RequestUpdate, TransferProgress, TransferStarted};
    use mcpmesh_local_api::BlobTransferState as S;

    fn started(size: u64) -> RequestUpdate {
        RequestUpdate::Started(TransferStarted {
            index: 0,
            hash: iroh_blobs::Hash::new(b"blob"),
            size,
        })
    }
    fn progress(end_offset: u64) -> RequestUpdate {
        RequestUpdate::Progress(TransferProgress { end_offset })
    }

    /// Drive a sequence of updates and return every frame that came out.
    fn frames_for(size: u64, chunk: u64) -> Vec<crate::daemon::BlobTransfer> {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4096);
        let mut st = None;
        let peer = Some("eid:abc".to_string());
        apply_transfer_update(&mut st, &started(size), &tx, &peer);
        let mut at = 0;
        while at < size {
            at = (at + chunk).min(size);
            apply_transfer_update(&mut st, &progress(at), &tx, &peer);
        }
        apply_transfer_update(
            &mut st,
            &RequestUpdate::Completed(iroh_blobs::provider::events::TransferCompleted {
                stats: Box::new(iroh_blobs::provider::TransferStats {
                    payload_bytes_sent: 0,
                    other_bytes_sent: 0,
                    other_bytes_read: 0,
                    duration: std::time::Duration::ZERO,
                }),
            }),
            &tx,
            &peer,
        );
        let mut out = Vec::new();
        while let Ok(f) = rx.try_recv() {
            out.push(f);
        }
        out
    }

    /// #82 ask 2: COALESCING is the property that keeps the ring usable.
    ///
    /// iroh-blobs reports progress per ~16 KiB chunk. A 4 GiB transfer is ~262k updates; emitting a
    /// frame for each would overrun a bounded ring many times over and every subscriber would see
    /// `Lagged`, losing the audit records that share their stream.
    #[test]
    fn progress_frames_are_coalesced_not_one_per_chunk() {
        const GIB: u64 = 1024 * 1024 * 1024;
        let chunks = 4 * GIB / (16 * 1024);
        let frames = frames_for(4 * GIB, 16 * 1024);

        assert!(
            frames.len() <= 110,
            "a 4 GiB transfer produced {} frames from {chunks} chunks — the stride must bound this \
             to ~102 (Started + ~100 Progress + Completed), or every subscriber lags out",
            frames.len()
        );
        assert!(
            frames.len() >= 3,
            "…but it must still report PROGRESS, not just start and end: {}",
            frames.len()
        );
        assert_eq!(frames.first().unwrap().state, S::Started);
        assert_eq!(frames.last().unwrap().state, S::Completed);
        assert!(
            frames
                .windows(2)
                .all(|w| w[0].bytes_done <= w[1].bytes_done),
            "bytes_done must never go backwards"
        );
        assert_eq!(
            frames.last().unwrap().bytes_done,
            4 * GIB,
            "Completed must carry the FINAL count — the last Progress is skipped by the stride, so \
             a consumer treating it as the total would stop short of 100%"
        );
    }

    /// #82: `Completed` reports the FINAL count even when the last `Progress` fell short.
    ///
    /// The stride skips the tail of a transfer, and a provider need not emit a progress event for
    /// the final chunk — so a consumer that renders the last `Progress` as the total stops short of
    /// 100% and the bar never fills. Asserted with a deliberately LAGGING last progress, because a
    /// fixture whose chunks land exactly on the size makes this a no-op: the first version of this
    /// test did that and the mutation escaped.
    #[test]
    fn completed_reports_the_total_even_when_the_last_progress_lagged() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let mut st = None;
        apply_transfer_update(&mut st, &started(1000), &tx, &None);
        apply_transfer_update(&mut st, &progress(400), &tx, &None);
        apply_transfer_update(
            &mut st,
            &RequestUpdate::Completed(iroh_blobs::provider::events::TransferCompleted {
                stats: Box::new(iroh_blobs::provider::TransferStats {
                    payload_bytes_sent: 0,
                    other_bytes_sent: 0,
                    other_bytes_read: 0,
                    duration: std::time::Duration::ZERO,
                }),
            }),
            &tx,
            &None,
        );
        let frames: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let last = frames.last().unwrap();
        assert_eq!(last.state, S::Completed);
        assert_eq!(
            last.bytes_done, 1000,
            "Completed must report the total, not the 400 the last Progress reached — otherwise \
             the consumer's bar stops at 40% on a fully successful transfer"
        );
    }

    /// A SMALL blob must still get its Started/Completed pair — a progress bar needs both ends even
    /// when no Progress frame ever clears the stride.
    #[test]
    fn a_small_transfer_still_reports_both_ends() {
        let frames = frames_for(1024, 512);
        assert_eq!(frames.first().unwrap().state, S::Started);
        assert_eq!(frames.last().unwrap().state, S::Completed);
        assert_eq!(frames.last().unwrap().bytes_done, 1024);
        assert_eq!(
            frames.first().unwrap().bytes_total,
            Some(1024),
            "bytes_total is known from Started onward"
        );
        assert_eq!(
            frames.first().unwrap().peer.as_deref(),
            Some("eid:abc"),
            "the SERVING side attributes the stable principal (#38), never a nickname"
        );
    }

    /// The stride scales with size, so a big transfer does not emit proportionally more frames.
    #[test]
    fn the_stride_scales_with_the_transfer_size() {
        let small = TransferProgressState {
            hash: "h".into(),
            peer: None,
            total: Some(1024),
            done: 0,
            last_emitted: 0,
        };
        assert_eq!(
            small.stride(),
            PROGRESS_STRIDE_BYTES,
            "a tiny transfer floors at the fixed stride rather than emitting per byte"
        );
        let big = TransferProgressState {
            total: Some(4 * 1024 * 1024 * 1024),
            ..small
        };
        assert_eq!(
            big.stride(),
            4 * 1024 * 1024 * 1024 / 100,
            "a big one uses 1% so the frame COUNT stays bounded instead of the byte gap"
        );
    }

    /// #82: a transfer that ends without a terminal event must still be reported ABORTED — a
    /// consumer waiting on Completed/Aborted would otherwise wait forever, which is the "stalled is
    /// indistinguishable from slow" complaint.
    #[test]
    fn an_aborted_transfer_is_reported_not_silently_dropped() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let mut st = None;
        apply_transfer_update(&mut st, &started(4096), &tx, &None);
        let terminal = apply_transfer_update(
            &mut st,
            &RequestUpdate::Aborted(iroh_blobs::provider::events::TransferAborted {
                stats: Box::new(iroh_blobs::provider::TransferStats {
                    payload_bytes_sent: 0,
                    other_bytes_sent: 0,
                    other_bytes_read: 0,
                    duration: std::time::Duration::ZERO,
                }),
            }),
            &tx,
            &None,
        );
        assert!(terminal, "Aborted must end the drain");
        let frames: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[1].state, S::Aborted);
    }

    /// #84a fourth review: the three audit statuses, and the dedup.
    ///
    /// All three of these survived a fully green 595-test suite as mutations: recording "ok" for a
    /// Permission refusal (a verbatim regression of the blocker the previous round fixed), and
    /// deleting the dedup entirely. Nothing asserted a "denied" or "rate_limited" blob_fetch
    /// record anywhere in the tree — not even the pre-existing "denied".
    #[test]
    fn the_audit_status_follows_the_decision_and_reports_a_refusal_once() {
        use mcpmesh_net::EndpointId;
        let eid = EndpointId::from_bytes([2u8; 32]);
        let mut seen = HashSet::new();

        // An authz refusal is "denied" — NOT "ok". This is the exact regression the third review
        // caught: status derived by excluding RateLimited recorded a Permission refusal as success.
        assert_eq!(
            super::audit_status(&Err(AbortReason::Permission), Some(eid), &mut seen),
            Some("denied"),
            "a refused GET must never be audited as a successful fetch"
        );
        // Unattributable connections take the same path.
        assert_eq!(
            super::audit_status(&Err(AbortReason::Permission), None, &mut seen),
            Some("denied")
        );

        // A budget refusal is distinct from an authz denial, and reported ONCE.
        assert_eq!(
            super::audit_status(&Err(AbortReason::RateLimited), Some(eid), &mut seen),
            Some("rate_limited"),
            "the first refusal is news — the issue's complaint was that nothing reported it"
        );
        for _ in 0..500 {
            assert_eq!(
                super::audit_status(&Err(AbortReason::RateLimited), Some(eid), &mut seen),
                None,
                "and every later one is silent — refusals are cheap, so recording each would \
                 trade an uplink DoS for an audit-log DoS (~2250 records/s measured)"
            );
        }

        // Recovering re-arms the report, so an ongoing attack is not invisible forever.
        assert_eq!(
            super::audit_status(&Ok(()), Some(eid), &mut seen),
            Some("ok")
        );
        assert_eq!(
            super::audit_status(&Err(AbortReason::RateLimited), Some(eid), &mut seen),
            Some("rate_limited"),
            "a peer that recovered and re-offended must be reported again"
        );

        // A second endpoint is tracked independently.
        let other = EndpointId::from_bytes([3u8; 32]);
        assert_eq!(
            super::audit_status(&Err(AbortReason::RateLimited), Some(other), &mut seen),
            Some("rate_limited")
        );
    }

    /// #84a fourth review: `request_budget_ok` must fail CLOSED on an unattributable connection.
    ///
    /// Reverting it to `is_none_or` — fail OPEN, the inverse of `throttle_decision`'s rule —
    /// survived the whole suite, because every other test passes `Some(..)` and the two forms
    /// differ only on `None`.
    #[test]
    fn request_budget_ok_fails_closed_on_an_unattributable_connection() {
        use crate::config::LimitsCfg;
        use crate::limits::MeshLimiters;

        // Even with NO budget configured, an unattributable connection is refused: fail-closed is
        // about attribution, not about the budget being on.
        let off = MeshLimiters::from_config(&LimitsCfg::default());
        assert!(
            !super::request_budget_ok(None, &off),
            "a connection with no ClientConnected record must be refused — metering it against \
             nobody is the per-connection bypass by another route"
        );

        let on = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: super::IROH_CHUNK_BYTES * 4,
            ..Default::default()
        });
        assert!(!super::request_budget_ok(None, &on));
    }

    /// #84a review: GET admission must consult the budget, not only authz.
    ///
    /// This is THE critical fix, and nothing pinned it: deleting the budget check from the GET arm
    /// passed every test while a probe measured 3 MB delivered against a 32 KiB/min budget (94x).
    /// Testing `request_budget_ok` in isolation proved the helper worked, not that anything called
    /// it — the same vacuity this branch called out in the event mask.
    #[test]
    fn get_admission_refuses_on_budget_as_well_as_authz() {
        use crate::config::LimitsCfg;
        use crate::limits::MeshLimiters;
        use mcpmesh_net::EndpointId;

        let eid = EndpointId::from_bytes([6u8; 32]);
        let lim = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: super::IROH_CHUNK_BYTES * 2,
            ..Default::default()
        });

        // Authz denial wins and reports Permission, whatever the budget says.
        assert!(matches!(
            super::get_admission(false, Some(&eid), &lim),
            Err(AbortReason::Permission)
        ));

        // An authorized caller is admitted until its budget is spent, then RateLimited — before
        // any bytes. Two chunks of budget = two admissions.
        assert!(super::get_admission(true, Some(&eid), &lim).is_ok());
        assert!(super::get_admission(true, Some(&eid), &lim).is_ok());
        assert!(
            matches!(
                super::get_admission(true, Some(&eid), &lim),
                Err(AbortReason::RateLimited)
            ),
            "an over-budget REQUEST must be refused before any bytes — metering only per chunk \
             let a peer take one free chunk per request forever"
        );

        // Unattributable: fail closed, and as an authz failure rather than a budget one.
        assert!(matches!(
            super::get_admission(true, None, &lim),
            Err(AbortReason::Permission)
        ));
    }

    /// #84a review: the documented floor must actually serve a blob.
    ///
    /// The first version of this doc told operators the minimum was 16384 — which admits a request
    /// (reserving one chunk) and then has nothing left for the transfer's own chunks, so it serves
    /// zero bytes. A doc that recommends the value it warns against is worse than no doc.
    #[test]
    fn the_documented_minimum_budget_admits_a_request_and_a_chunk() {
        use crate::config::LimitsCfg;
        use crate::limits::MeshLimiters;
        use mcpmesh_net::EndpointId;

        let eid = EndpointId::from_bytes([8u8; 32]);
        const DOCUMENTED_MIN: u64 = 32_768;

        let lim = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: DOCUMENTED_MIN,
            ..Default::default()
        });
        assert!(
            super::request_budget_ok(Some(&eid), &lim),
            "the documented minimum must admit a request"
        );
        assert!(
            super::throttle_decision(Some(&eid), super::IROH_CHUNK_BYTES, &lim).is_ok(),
            "and must still have budget for the first CHUNK — otherwise the value we tell \
             operators to use serves zero bytes, which is the state the doc warns against"
        );

        // A sub-floor value is FLOORED, not honoured (#84a fourth review). Documenting a floor
        // and not enforcing it left an operator with a daemon that silently capped every servable
        // blob at `budget - 16384` bytes; the repo idiom is `max_sessions.max(1)`.
        let floored = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: super::IROH_CHUNK_BYTES, // one chunk: below the floor
            ..Default::default()
        });
        assert!(super::request_budget_ok(Some(&eid), &floored));
        assert!(
            super::throttle_decision(Some(&eid), super::IROH_CHUNK_BYTES, &floored).is_ok(),
            "a sub-floor budget must be raised to a usable one, not honoured into a daemon that \
             admits a request and then truncates every blob"
        );
    }

    /// #84a review: the default mask must be UNCHANGED, and the metered one must differ in
    /// exactly one field.
    ///
    /// Nothing pinned this: mutating the code to always use the metered mask survived the whole
    /// suite, because the only tests that could notice are network suites that flake on this
    /// machine. A const assertion is deterministic and instant.
    #[test]
    fn the_metered_mask_differs_from_the_default_in_throttle_alone() {
        let d = super::APP_BLOB_EVENT_MASK;
        let m = super::APP_BLOB_EVENT_MASK_METERED;

        assert_eq!(
            d.throttle,
            ThrottleMode::None,
            "a deployment with no budget must not arm the per-chunk intercept"
        );
        assert_eq!(m.throttle, ThrottleMode::Intercept);

        // Every OTHER field identical — the metered mask must not relax an authz decision.
        assert_eq!(d.connected, m.connected, "connect gate");
        assert_eq!(d.get, m.get, "the GET scope gate");
        assert_eq!(d.get_many, m.get_many, "get_many stays denied");
        assert_eq!(d.push, m.push, "push stays denied");
        assert_eq!(d.observe, m.observe, "observe stays intercepted");
    }

    /// #84a review: the budget must refuse the REQUEST, not only the chunk.
    ///
    /// The per-chunk hook fires after iroh-blobs has written the chunk, and a `RateLimited` abort
    /// resets only the stream — the connection survives and nothing caps requests per connection.
    /// Measured before this gate existed: ~1800x the configured rate from ONE connection, because
    /// every new request collected a free ~16 KiB chunk. Metering only per chunk does not bound an
    /// adversarial peer, only a polite one.
    #[test]
    fn a_request_is_refused_once_the_endpoint_budget_is_spent() {
        use crate::config::LimitsCfg;
        use crate::limits::MeshLimiters;
        use mcpmesh_net::EndpointId;

        let eid = EndpointId::from_bytes([4u8; 32]);
        // Exactly two chunks of budget.
        let lim = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: super::IROH_CHUNK_BYTES * 2,
            ..Default::default()
        });

        assert!(super::request_budget_ok(Some(&eid), &lim), "first request");
        assert!(super::request_budget_ok(Some(&eid), &lim), "second request");
        assert!(
            !super::request_budget_ok(Some(&eid), &lim),
            "the THIRD request must be refused before any bytes — metering only per chunk lets a \
             peer take one free chunk per request forever, which is ~1800x the budget in practice"
        );

        // With no budget configured, admission is never blocked.
        let off = MeshLimiters::from_config(&LimitsCfg::default());
        for _ in 0..100 {
            assert!(super::request_budget_ok(Some(&eid), &off));
        }
    }

    /// #84a: the two rules that decide whether a chunk goes out.
    ///
    /// Extracted as a pure function because the live path is an async irpc arm firing per ~16 KiB
    /// chunk — pinning these through a real transfer is how a test ends up asserting nothing.
    #[test]
    fn a_chunk_is_refused_over_budget_and_when_it_cannot_be_attributed() {
        use crate::config::LimitsCfg;
        use crate::limits::MeshLimiters;
        use mcpmesh_net::EndpointId;

        let eid = EndpointId::from_bytes([1u8; 32]);
        let lim = MeshLimiters::from_config(&LimitsCfg {
            blob_bytes_per_min: 32_768, // == the enforced floor (two chunks)
            ..Default::default()
        });

        // 32768 == two chunks, so two fit and the third does not.
        assert!(
            super::throttle_decision(Some(&eid), 16_384, &lim).is_ok(),
            "the first chunk is inside the budget"
        );
        assert!(
            super::throttle_decision(Some(&eid), 16_384, &lim).is_ok(),
            "and the second"
        );
        assert!(
            matches!(
                super::throttle_decision(Some(&eid), 16_384, &lim),
                Err(AbortReason::RateLimited)
            ),
            "over budget must be RateLimited — the peer IS authorized and pacing failed, so \
             reporting Permission would put a bandwidth event in the audit trail as an authz denial"
        );

        // FAIL CLOSED: a chunk we cannot attribute is refused, not waved through.
        assert!(
            matches!(
                super::throttle_decision(None, 16_384, &lim),
                Err(AbortReason::Permission)
            ),
            "an unattributable chunk must be REFUSED — metering it against nobody is the same \
             bypass as metering per connection"
        );

        // With no budget configured nothing is metered, but an unattributable chunk is STILL
        // refused: fail-closed is about attribution, not about the budget being on.
        let off = MeshLimiters::from_config(&LimitsCfg::default());
        assert!(super::throttle_decision(Some(&eid), u64::MAX, &off).is_ok());
        assert!(
            super::throttle_decision(None, 1, &off).is_err(),
            "fail-closed does not depend on a budget being configured"
        );
    }

    use super::*;
    use crate::blobs::APP_BLOB_ALPN;
    use crate::blobs::scope::ScopeStore;
    use mcpmesh_net::{EndpointId, PeerIdentity, StaticGate};
    use std::sync::Arc;

    /// #83: republishing a hash the store does NOT hold COMPLETE must fail, and must leave the
    /// scope untouched.
    ///
    /// Putting a hash in a scope ADVERTISES it — the gate will authorize GETs for it and the
    /// returned ticket names us as the source. Advertising bytes we cannot serve converts the
    /// original sender going offline into a hang at every fetcher, which is strictly worse than the
    /// failure #83 reports. Partial bytes (an interrupted fetch leaves them) must fail the same way
    /// as absent ones, which is why the predicate is `Blobs::has` (true only for
    /// `BlobStatus::Complete`) rather than "do we know this hash".
    #[tokio::test]
    async fn republishing_a_blob_we_do_not_hold_fails_and_leaves_the_scope_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
            .await
            .unwrap();
        provider.grant("room", "b64u:alice").unwrap();

        // A well-formed hash the store has never seen.
        let absent = blake3::hash(b"never fetched").to_hex().to_string();
        let err = provider
            .republish("room", &absent)
            .await
            .expect_err("republishing a blob we do not hold must fail");
        assert!(
            err.downcast_ref::<crate::daemon::NoSuchBlob>().is_some(),
            "must be NoSuchBlob so the client can tell it apart from a bad scope, got: {err}"
        );
        let hashes: Vec<String> = provider
            .list()
            .into_iter()
            .flat_map(|(_, hashes, _, _)| hashes)
            .collect();
        assert!(
            !hashes.contains(&absent),
            "a FAILED republish must not half-advertise the hash, got {hashes:?}"
        );
    }

    /// The check ORDER: an unknown scope reports `NoSuchBlobScope`, even when the hash is also
    /// absent. A typo'd scope must not be reported as a missing blob — the client's remedy differs.
    #[tokio::test]
    async fn an_unknown_scope_outranks_a_missing_blob() {
        let dir = tempfile::tempdir().unwrap();
        let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
            .await
            .unwrap();
        let absent = blake3::hash(b"nope").to_hex().to_string();
        let err = provider
            .republish("no-such-scope", &absent)
            .await
            .expect_err("unknown scope must fail");
        assert!(
            err.downcast_ref::<crate::daemon::NoSuchBlobScope>()
                .is_some(),
            "an unknown scope outranks a missing blob, got: {err}"
        );
    }

    /// #83's exact scenario, end to end: a fetched blob becomes servable FROM THE FETCHER, and a
    /// third peer gets it while the ORIGINAL PUBLISHER IS OFFLINE.
    ///
    /// "Someone posts a file to a room of eight and closes their laptop." Before republish, the
    /// only address anyone held pointed at the sleeping publisher, so the remaining peers failed
    /// even though complete, byte-identical bytes sat on three machines.
    ///
    /// B is a GATED provider (`AppBlobs::load`), which is what makes this test mean anything. An
    /// ungated fetcher serves every hash it holds, so the scope insert republish performs is never
    /// exercised and the test passes with republish recording nothing — verified by mutation.
    #[tokio::test]
    async fn a_fetched_blob_is_servable_from_the_fetcher_after_the_publisher_goes_away() {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let c_ep = ep().await;
            let c_eid = EndpointId::from_bytes(*c_ep.id().as_bytes());
            let mut entries = HashMap::new();
            entries.insert(
                c_eid,
                PeerIdentity {
                    endpoint: c_eid,
                    name: "carol".into(),
                    user_id: Some("carol".into()),
                    groups: vec![],
                },
            );
            let b_gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(StaticGate::new(entries));

            // A publishes (ungated — A's gate is not what is under test).
            let adir = tempfile::tempdir().unwrap();
            let a_ep = ep().await;
            let a = AppBlobs::open_fetcher(adir.path().join("blobs"), a_ep.clone())
                .await
                .unwrap();
            a.spawn_accept(&a_ep);
            let src = adir.path().join("shared.bin");
            std::fs::write(&src, b"the file everyone wants").unwrap();
            let (a_ticket, hash_hex) = a.publish_path(&src).await.unwrap();

            // B fetches it, and is GATED when it serves.
            let bdir = tempfile::tempdir().unwrap();
            let b_ep = ep().await;
            let b = AppBlobs::load(
                bdir.path().join("blobs"),
                Arc::new(ScopeStore::new(bdir.path().join("scopes.json"))),
                b_gate,
                b_ep.clone(),
                crate::audit::AuditSink::disabled(),
                crate::limits::MeshLimiters::unlimited(),
                None,
            )
            .await
            .unwrap();
            b.spawn_accept(&b_ep);
            b.fetch(&a_ticket).await.unwrap();

            // B republishes into a scope IT controls and grants C.
            b.grant("b-room", "carol").unwrap();
            let (b_ticket, _canon) = b.republish("b-room", &hash_hex).await.unwrap();
            assert_ne!(b_ticket, a_ticket, "the ticket must name B, not A");

            // A goes away — the laptop closes.
            a_ep.close().await;

            // C fetches from B regardless.
            let cdir = tempfile::tempdir().unwrap();
            let c = AppBlobs::open_fetcher(cdir.path().join("blobs"), c_ep)
                .await
                .unwrap();
            let got = c
                .fetch(&b_ticket)
                .await
                .expect("C must fetch from B with A offline — the whole point of #83");
            assert_eq!(
                &c.read_bytes(got).await.unwrap()[..],
                b"the file everyone wants"
            );
        })
        .await
        .expect("republish round-trip timed out");
    }

    /// Republish must NOT inherit the original publisher's grants. A principal A shared with, but
    /// B did not, is refused by B — otherwise republishing would silently widen access to everyone
    /// the previous holder had shared with, which no one asked for and no one would see.
    #[tokio::test]
    async fn republish_does_not_inherit_the_publishers_grants() {
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            let m_ep = ep().await;
            let m_eid = EndpointId::from_bytes(*m_ep.id().as_bytes());
            let mut entries = HashMap::new();
            entries.insert(
                m_eid,
                PeerIdentity {
                    endpoint: m_eid,
                    name: "mallory".into(),
                    user_id: Some("mallory".into()),
                    groups: vec![],
                },
            );
            let b_gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(StaticGate::new(entries));

            // A publishes and grants mallory.
            let adir = tempfile::tempdir().unwrap();
            let a_ep = ep().await;
            let a = AppBlobs::open_fetcher(adir.path().join("blobs"), a_ep.clone())
                .await
                .unwrap();
            a.spawn_accept(&a_ep);
            let src = adir.path().join("f.bin");
            std::fs::write(&src, b"a's file").unwrap();
            let (a_ticket, hash_hex) = a.publish_path(&src).await.unwrap();
            a.grant("a-room", "mallory").unwrap();

            // B fetches and republishes into ITS scope, granting nobody.
            let bdir = tempfile::tempdir().unwrap();
            let b_ep = ep().await;
            let b = AppBlobs::load(
                bdir.path().join("blobs"),
                Arc::new(ScopeStore::new(bdir.path().join("scopes.json"))),
                b_gate,
                b_ep.clone(),
                crate::audit::AuditSink::disabled(),
                crate::limits::MeshLimiters::unlimited(),
                None,
            )
            .await
            .unwrap();
            b.spawn_accept(&b_ep);
            b.fetch(&a_ticket).await.unwrap();
            b.grant("b-room", "someone-else").unwrap();
            let (b_ticket, _canon) = b.republish("b-room", &hash_hex).await.unwrap();

            // mallory — granted by A, never by B — is refused by B.
            let mdir = tempfile::tempdir().unwrap();
            let mallory = AppBlobs::open_fetcher(mdir.path().join("blobs"), m_ep)
                .await
                .unwrap();
            // A DENIED fetch does not fail fast (the gate refuses at accept and the fetcher
            // retries), so bound it: both "errored" and "never completed" are denials — only
            // SUCCESS is a failure of this property.
            let res =
                tokio::time::timeout(std::time::Duration::from_secs(10), mallory.fetch(&b_ticket))
                    .await;
            assert!(
                !matches!(res, Ok(Ok(_))),
                "republishing must not transfer A's grants to B's copy — that would silently widen \
                 access to everyone the previous holder shared with (got {res:?})"
            );
        })
        .await
        .expect("grant-isolation test timed out");
    }

    /// #83 review: a NON-CANONICAL rendering of a hash must not create an entry that authorizes
    /// nothing. The gate compares against canonical lowercase hex, so recording the caller's raw
    /// string (a valid 52-char base32 form, or uppercase hex) would put a row in `blob_list` that
    /// looks shared, denies every fetcher, and cannot be removed — `blob_unpublish` normalizes and
    /// would find nothing to delete, acking a no-op. That is #62's defect from the other side.
    #[tokio::test]
    async fn a_non_canonical_hash_is_normalized_before_it_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
            .await
            .unwrap();
        provider.grant("room", "b64u:alice").unwrap();
        let src = dir.path().join("f.bin");
        std::fs::write(&src, b"canonical me").unwrap();
        let (_t, canonical) = provider.publish_path(&src).await.unwrap();

        // The SAME hash in its base32 rendering — what `Hash`'s Display produces, and a form a
        // client can legitimately hold. (Uppercase HEX is not an alternative spelling: iroh's
        // parser rejects it outright, which the review's own probe confirmed.)
        let parsed = crate::blobs::parse_blob_hash(&canonical).unwrap();
        let base32 = data_encoding::BASE32_NOPAD
            .encode(parsed.as_bytes())
            .to_ascii_lowercase();
        assert_ne!(base32, canonical, "the fixture must actually differ");
        let (_ticket, returned) = provider
            .republish("room", &base32)
            .await
            .expect("an alternative rendering of a held hash must republish");

        assert_eq!(
            returned, canonical,
            "the RESULT must carry canonical hex — blob_publish does, and the docs promise the two \
             are interchangeable"
        );
        let recorded: Vec<String> = provider
            .list()
            .into_iter()
            .filter(|(name, _, _, _)| name == "room")
            .flat_map(|(_, hashes, _, _)| hashes)
            .collect();
        assert_eq!(
            recorded,
            vec![canonical],
            "the SCOPE must record canonical hex — the gate compares against it, so a raw-string \
             entry would authorize nobody and be unremovable"
        );
    }

    /// #104: a `blob_unpublish` concurrent with a `blob_republish` must not be silently undone.
    ///
    /// `republish` is a read-check-write — it verifies completeness (an `.await`) and only then
    /// inserts. Without a lock spanning both, an unpublish landing in that gap removes the hash,
    /// republish then re-inserts it, and BOTH verbs report success: the operator was told the file
    /// was withdrawn while it is being served.
    ///
    /// Driven deterministically via the test-only delay seam rather than hoping for the
    /// interleaving. With the lock, unpublish blocks until republish finishes and therefore
    /// serializes AFTER it — the revocation is the last word, which is the outcome an operator
    /// expects. Without it, unpublish slips into the gap and is overwritten.
    #[tokio::test]
    async fn a_concurrent_unpublish_is_not_lost_to_a_republish() {
        // 120s: these fixtures bind real endpoints, which costs ~20s on a loaded machine, and the
        // guard exists to catch a HANG (a deadlock on the new membership lock), not slowness.
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let dir = tempfile::tempdir().unwrap();
            let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
                .await
                .unwrap();
            provider.grant("room", "b64u:alice").unwrap();
            let src = dir.path().join("f.bin");
            std::fs::write(&src, b"contested").unwrap();
            // Already published into the scope, so the unpublish below has something to remove.
            let (_t, hash_hex) = provider.publish_scope("room", &src).await.unwrap();

            provider.set_republish_delay(std::time::Duration::from_millis(600));
            let p2 = provider.clone();
            let h2 = hash_hex.clone();
            let republish =
                tokio::spawn(async move { p2.republish("room", &h2).await.map(|_| ()) });

            // Let republish get past its completeness check and into the gap.
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let removed = provider.unpublish("room", &hash_hex).await.unwrap();
            republish.await.unwrap().unwrap();

            assert!(removed, "the unpublish must actually have removed the hash");
            let hashes: Vec<String> = provider
                .list()
                .into_iter()
                .flat_map(|(_, hashes, _, _)| hashes)
                .collect();
            assert!(
                !hashes.contains(&hash_hex),
                "the revocation must survive — a republish that overwrites a concurrent unpublish \
                 tells the operator the file was withdrawn while it is still being served (scope \
                 now holds {hashes:?})"
            );
        })
        .await
        .expect("republish/unpublish race test timed out");
    }

    /// #104: `publish_scope` takes the same membership lock, and nothing tested it — removing that
    /// lock alone passed the whole suite, so a refactor could drop it silently.
    ///
    /// Same mechanism as the republish race: `add_path` is a slow async import, and the scope
    /// insert that follows is unconditional. A `blob_unpublish` of a hash the import is about to
    /// re-add loses its effect. Reachable whenever two clients hold the same bytes — which is
    /// ordinary, since the hash is the content.
    #[tokio::test]
    async fn a_concurrent_unpublish_is_not_lost_to_a_publish() {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let dir = tempfile::tempdir().unwrap();
            let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
                .await
                .unwrap();
            provider.grant("room", "b64u:alice").unwrap();
            let src = dir.path().join("f.bin");
            std::fs::write(&src, b"contested by publish").unwrap();
            let (_t, hash_hex) = provider.publish_scope("room", &src).await.unwrap();

            // Re-publishing the SAME bytes races an unpublish of the same hash.
            provider.set_publish_delay(std::time::Duration::from_millis(600));
            let p2 = provider.clone();
            let src2 = src.clone();
            let publish =
                tokio::spawn(async move { p2.publish_scope("room", &src2).await.map(|_| ()) });

            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            let removed = provider.unpublish("room", &hash_hex).await.unwrap();
            publish.await.unwrap().unwrap();

            assert!(removed, "the unpublish must actually have removed the hash");
            let hashes: Vec<String> = provider
                .list()
                .into_iter()
                .flat_map(|(_, hashes, _, _)| hashes)
                .collect();
            assert!(
                !hashes.contains(&hash_hex),
                "a re-publish of identical bytes must not overwrite a concurrent revocation \
                 (scope now holds {hashes:?})"
            );
        })
        .await
        .expect("publish/unpublish race test timed out");
    }

    /// #105: the relay-ready wait is a CAP, and it actually RUNS.
    ///
    /// The first version of this test asserted neither. On a relay-disabled endpoint the minted
    /// ticket is byte-identical with and without the wait — no relay URL appears either way — so
    /// the ONLY observable difference is elapsed time. Deleting the wait from `ticket_for`
    /// entirely left both #105 tests passing (in 0.65s instead of 9.3s). Guarding the flag is not
    /// guarding the behaviour the flag exists to produce.
    ///
    /// Because `online()` never completes with relays disabled, an enabled wait MUST consume the
    /// full cap. So the elapsed time is a two-sided assertion: the lower bound fails if the wait
    /// is removed or skipped, the upper bound fails if it becomes unbounded or is lengthened.
    #[tokio::test]
    async fn the_relay_wait_actually_runs_and_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        let provider_ep = ep().await;
        let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), provider_ep.clone())
            .await
            .unwrap();
        // F3: pin the DEFAULT too. Without this, flipping `relay_wait`'s initial value to `true`
        // would make the boot guard in `boot.rs` stop failing when its one call is deleted — the
        // whole point of #105 would evaporate silently.
        assert!(
            !provider.relay_wait_enabled(),
            "the wait must default OFF — every hand-built fixture would otherwise pay the full cap \
             per mint, and the boot guard would stop guarding anything"
        );
        provider.enable_relay_wait();
        provider.spawn_accept(&provider_ep);

        let src = dir.path().join("capped.bin");
        std::fs::write(&src, b"capped").unwrap();

        let started = std::time::Instant::now();
        let published = provider.publish_path(&src).await.unwrap();
        let elapsed = started.elapsed();

        assert!(
            elapsed >= crate::daemon::RELAY_READY_TIMEOUT,
            "the wait must actually RUN — `online()` never completes on a relay-disabled endpoint, \
             so an enabled wait consumes the full cap. Minting in {elapsed:?} means the wait was \
             skipped or removed"
        );
        assert!(
            elapsed < crate::daemon::RELAY_READY_TIMEOUT + std::time::Duration::from_secs(2),
            "and it must be CAPPED — minting took {elapsed:?}, so the bound is longer than \
             RELAY_READY_TIMEOUT or the wait is unbounded"
        );

        // F5: the fetch is bounded too — an unbounded one hangs the whole test binary with no
        // failing test name, since libtest has no per-test timeout.
        let cdir = tempfile::tempdir().unwrap();
        let caller = AppBlobs::open_fetcher(cdir.path().join("blobs"), ep().await)
            .await
            .unwrap();
        let hash = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            caller.fetch(&published.0),
        )
        .await
        .expect("fetch timed out")
        .expect("the fallback direct-address ticket must still round-trip");
        assert_eq!(&caller.read_bytes(hash).await.unwrap()[..], b"capped");
    }

    /// #107: the race #104's lock could NOT close. A mutex orders by ACQUISITION, not by request
    /// arrival, so an unpublish that acquires first is still erased by a republish acquiring
    /// second — both returning success, operator told the file was withdrawn while it is served.
    ///
    /// Closed with state rather than exclusion: unpublish records a withdrawal, and republish
    /// refuses it. Asserted in the ORDER THAT USED TO LOSE — unpublish completes first, then
    /// republish runs — which is exactly the interleaving a lock cannot help with.
    #[tokio::test]
    async fn a_completed_unpublish_is_not_undone_by_a_later_republish() {
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            let dir = tempfile::tempdir().unwrap();
            let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
                .await
                .unwrap();
            provider.grant("room", "b64u:alice").unwrap();
            let src = dir.path().join("f.bin");
            std::fs::write(&src, b"withdrawn content").unwrap();
            let (_t, hash_hex) = provider.publish_scope("room", &src).await.unwrap();

            assert!(provider.unpublish("room", &hash_hex).await.unwrap());

            // The bytes are still in the store (#80: no reclaim), so `has()` is true and the ONLY
            // thing standing between the operator's revocation and its silent undoing is #107.
            let err = provider
                .republish("room", &hash_hex)
                .await
                .expect_err("a withdrawn hash must not republish");
            assert!(
                err.downcast_ref::<crate::daemon::BlobWithdrawn>().is_some(),
                "must be BlobWithdrawn so a client can tell it from 'fetch it first', got: {err}"
            );

            let hashes: Vec<String> = provider
                .list()
                .into_iter()
                .flat_map(|(_, hashes, _, _)| hashes)
                .collect();
            assert!(
                !hashes.contains(&hash_hex),
                "and the scope must still not list it (got {hashes:?})"
            );
        })
        .await
        .expect("durable revocation test timed out");
    }

    /// The deliberate re-share still works: `blob_publish` from a FILE clears the withdrawal, and
    /// a republish afterwards is allowed again. Without this, a withdrawal would be permanent and
    /// an operator could never re-share the same content into that scope.
    #[tokio::test]
    async fn publishing_from_the_file_again_lifts_the_withdrawal() {
        tokio::time::timeout(std::time::Duration::from_secs(90), async {
            let dir = tempfile::tempdir().unwrap();
            let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
                .await
                .unwrap();
            provider.grant("room", "b64u:alice").unwrap();
            let src = dir.path().join("f.bin");
            std::fs::write(&src, b"re-shared on purpose").unwrap();
            let (_t, hash_hex) = provider.publish_scope("room", &src).await.unwrap();
            provider.unpublish("room", &hash_hex).await.unwrap();
            provider.republish("room", &hash_hex).await.unwrap_err();

            // The deliberate act: name the FILE again.
            provider.publish_scope("room", &src).await.unwrap();
            provider
                .republish("room", &hash_hex)
                .await
                .expect("after a deliberate re-publish, republish is allowed again");
        })
        .await
        .expect("un-withdraw test timed out");
    }

    /// Republish is idempotent (the scope hash set is a set), so a client may call it
    /// unconditionally after every fetch without special-casing the second time.
    #[tokio::test]
    async fn republishing_twice_is_not_an_error_and_records_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let provider = AppBlobs::open_fetcher(dir.path().join("blobs"), ep().await)
            .await
            .unwrap();
        provider.grant("room", "b64u:alice").unwrap();
        let src = dir.path().join("f.bin");
        std::fs::write(&src, b"dupe").unwrap();
        let (_t, hash_hex) = provider.publish_path(&src).await.unwrap();

        provider.republish("room", &hash_hex).await.unwrap();
        provider.republish("room", &hash_hex).await.unwrap();

        // Constrain the SCOPE NAME too: without it, a mutation inserting into a hardcoded scope,
        // or into every scope, passes.
        let rooms: Vec<(String, Vec<String>)> = provider
            .list()
            .into_iter()
            .map(|(name, hashes, _, _)| (name, hashes))
            .collect();
        assert_eq!(
            rooms,
            vec![("room".to_string(), vec![hash_hex.clone()])],
            "exactly one entry, in the NAMED scope, not two and not elsewhere"
        );
    }

    /// Lock the exact serving mask: single-blob GET is scope-checked (`Intercept`); every other
    /// request type is pinned to deny-by-default so the refusal does NOT rely on 0.103.0's
    /// `mask.get`-routes-all quirk. A regression that loosens any of these fails here.
    #[test]
    fn app_blob_event_mask_pins_non_get_request_types_to_deny_by_default() {
        assert_eq!(APP_BLOB_EVENT_MASK.connected, ConnectMode::Intercept);
        // #82 ask 2: `InterceptLog`, NOT `Intercept` — and the distinction is the security one
        // worth pinning. `InterceptLog` is Intercept PLUS transfer events, so the scope check that
        // authorizes every single-blob GET still runs. Anything that merely NOTIFIES
        // (`Notify`/`NotifyLog`) would give up the veto and serve bytes to an ungranted caller.
        assert_eq!(APP_BLOB_EVENT_MASK.get, RequestMode::InterceptLog);
        assert!(
            !matches!(
                APP_BLOB_EVENT_MASK.get,
                RequestMode::Notify | RequestMode::NotifyLog | RequestMode::None
            ),
            "the GET mode must retain its VETO — a notify-only mode serves the bytes and tells us \
             afterwards"
        );
        // get_many/push refuse at the protocol level with Permission (events.rs:504-506), no event.
        assert_eq!(APP_BLOB_EVENT_MASK.get_many, RequestMode::Disabled);
        assert_eq!(APP_BLOB_EVENT_MASK.push, RequestMode::Disabled);
        // observe has no `Disabled` variant; `Intercept` routes it to the drain loop's deny arm.
        assert_eq!(APP_BLOB_EVENT_MASK.observe, ObserveMode::Intercept);
        // throttle is a transfer knob, not a request gate — left at its default.
        assert_eq!(APP_BLOB_EVENT_MASK.throttle, ThrottleMode::None);
    }

    async fn ep() -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![APP_BLOB_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind endpoint")
    }

    #[tokio::test]
    async fn ungated_fetcher_still_round_trips() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let pdir = tempfile::tempdir().unwrap();
            let provider_ep = ep().await;
            let provider = AppBlobs::open_fetcher(pdir.path().join("blobs"), provider_ep.clone())
                .await
                .unwrap();
            provider.spawn_accept(&provider_ep);
            let src = pdir.path().join("p.bin");
            std::fs::write(&src, b"hello scopes").unwrap();
            let (ticket, _hash) = provider.publish_path(&src).await.unwrap();

            let cdir = tempfile::tempdir().unwrap();
            let caller_ep = ep().await;
            let caller = AppBlobs::open_fetcher(cdir.path().join("blobs"), caller_ep.clone())
                .await
                .unwrap();
            let hash = caller.fetch(&ticket).await.unwrap();
            assert_eq!(&caller.read_bytes(hash).await.unwrap()[..], b"hello scopes");
        })
        .await
        .expect("timed out");
    }

    #[tokio::test]
    async fn granted_caller_fetches_but_ungranted_and_uncontained_are_denied() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            // Two callers: alice (granted) and bob (rostered but ungranted for this scope).
            let alice_ep = ep().await;
            let bob_ep = ep().await;
            let alice_id: EndpointId = alice_ep.id().into();
            let bob_id: EndpointId = bob_ep.id().into();

            // Provider gate resolves BOTH (both pass the accept-time gate); scope grants only alice.
            let mut entries = std::collections::HashMap::new();
            entries.insert(
                alice_id,
                PeerIdentity {
                    endpoint: [0u8; 32].into(),
                    name: "alice".into(),
                    user_id: Some("alice".into()),
                    groups: vec!["team-eng".into()],
                },
            );
            entries.insert(
                bob_id,
                PeerIdentity {
                    endpoint: [0u8; 32].into(),
                    name: "bob".into(),
                    user_id: Some("bob".into()),
                    groups: vec!["team-eng".into()],
                },
            );
            let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(StaticGate::new(entries));

            let pdir = tempfile::tempdir().unwrap();
            let scopes = Arc::new(ScopeStore::new(pdir.path().join("scopes.json")));
            let provider_ep = ep().await;
            let provider = AppBlobs::load(
                pdir.path().join("blobs"),
                scopes,
                gate,
                provider_ep.clone(),
                crate::audit::AuditSink::disabled(),
                crate::limits::MeshLimiters::unlimited(),
                None,
            )
            .await
            .unwrap();
            provider.spawn_accept(&provider_ep);

            // Publish into scope "docs" and grant it to the user_id "alice" ONLY (not team-eng).
            let src = pdir.path().join("secret.bin");
            std::fs::write(&src, b"top secret bytes").unwrap();
            let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
            provider.grant("docs", "alice").unwrap();

            // GRANTED (alice) → fetch succeeds + verifies.
            let cdir = tempfile::tempdir().unwrap();
            let alice = AppBlobs::open_fetcher(cdir.path().join("a"), alice_ep.clone())
                .await
                .unwrap();
            let hash = alice.fetch(&ticket).await.expect("granted alice fetches");
            assert_eq!(
                &alice.read_bytes(hash).await.unwrap()[..],
                b"top secret bytes"
            );

            // UNGRANTED (bob — rostered, team-eng, but "docs" grants only alice) → the request hook
            // denies with Permission BEFORE any bytes; the fetch errors.
            let bob = AppBlobs::open_fetcher(cdir.path().join("b"), bob_ep.clone())
                .await
                .unwrap();
            let bob_res =
                tokio::time::timeout(std::time::Duration::from_secs(10), bob.fetch(&ticket)).await;
            assert!(
                matches!(bob_res, Ok(Err(_))),
                "ungranted bob is refused: {bob_res:?}"
            );
        })
        .await
        .expect("timed out");
    }

    /// The #38 inversion for the blob-scope gate — grants hold STABLE principals only:
    /// a PAIRING-MODE peer (unbound: `user_id: None`, no groups) granted by its `eid:`
    /// device principal CAN fetch; a peer whose only "grant" names its display NICKNAME
    /// is DENIED (nicknames are self-asserted/rewritable and never admit). Identities
    /// carry their REAL authenticated endpoint bytes so the eid arm is honest.
    #[tokio::test]
    async fn pairing_mode_eid_grant_admits_and_nickname_grant_stays_denied() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let carol_ep = ep().await; // pairing-mode: granted by her eid: device principal
            let mallory_ep = ep().await; // "granted" only by nickname — must stay denied
            let carol_id: EndpointId = carol_ep.id().into();
            let mallory_id: EndpointId = mallory_ep.id().into();

            let mut entries = std::collections::HashMap::new();
            entries.insert(
                carol_id,
                PeerIdentity {
                    endpoint: carol_id, // the REAL authenticated bytes — the eid arm is honest
                    name: "carol".into(),
                    user_id: None, // no device→user binding — eid: is the ONLY principal
                    groups: vec![],
                },
            );
            entries.insert(
                mallory_id,
                PeerIdentity {
                    endpoint: mallory_id,
                    name: "mallory".into(),
                    user_id: None,
                    groups: vec![],
                },
            );
            let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(StaticGate::new(entries));

            let pdir = tempfile::tempdir().unwrap();
            let scopes = Arc::new(ScopeStore::new(pdir.path().join("scopes.json")));
            let provider_ep = ep().await;
            let provider = AppBlobs::load(
                pdir.path().join("blobs"),
                scopes,
                gate,
                provider_ep.clone(),
                crate::audit::AuditSink::disabled(),
                crate::limits::MeshLimiters::unlimited(),
                None,
            )
            .await
            .unwrap();
            provider.spawn_accept(&provider_ep);

            let src = pdir.path().join("attach.bin");
            std::fs::write(&src, b"eid-scoped bytes").unwrap();
            let (ticket, _hash) = provider
                .publish_scope("kb-attach-carol", &src)
                .await
                .unwrap();
            // Grant by the STABLE eid: device principal (iroh EndpointId Display is the same
            // hex-lower encoding as `EndpointId::principal()`).
            provider
                .grant("kb-attach-carol", &format!("eid:{}", carol_ep.id()))
                .unwrap();
            // A NICKNAME entry on the same scope — display names must NEVER admit (#38), so
            // this grants mallory nothing even though her resolved identity is named "mallory".
            provider.grant("kb-attach-carol", "mallory").unwrap();

            let cdir = tempfile::tempdir().unwrap();
            let carol = AppBlobs::open_fetcher(cdir.path().join("c"), carol_ep.clone())
                .await
                .unwrap();
            let hash = carol
                .fetch(&ticket)
                .await
                .expect("a pairing-mode peer granted by its eid: principal fetches");
            assert_eq!(
                &carol.read_bytes(hash).await.unwrap()[..],
                b"eid-scoped bytes"
            );

            // NICKNAME NEVER ADMITS: mallory resolves at accept time and the scope lists the
            // bare string "mallory", but her nickname is not a principal → Permission.
            let mallory = AppBlobs::open_fetcher(cdir.path().join("m"), mallory_ep.clone())
                .await
                .unwrap();
            let res =
                tokio::time::timeout(std::time::Duration::from_secs(10), mallory.fetch(&ticket))
                    .await;
            assert!(
                matches!(res, Ok(Err(_))),
                "a nickname-only grant is refused: {res:?}"
            );
        })
        .await
        .expect("eid-grant test timed out");
    }

    /// A served GET records a `blob_fetch` audit line attributed to the authenticated peer, with the
    /// hash and status=ok ("each blob fetch — peer + hash + …"). Uses a real temp AuditLog.
    #[tokio::test]
    async fn served_get_records_blob_fetch_audit() {
        use crate::audit::{AuditLog, AuditSink};
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let alice_ep = ep().await;
            let alice_id: EndpointId = alice_ep.id().into();
            let mut entries = std::collections::HashMap::new();
            entries.insert(
                alice_id,
                PeerIdentity {
                    endpoint: [0u8; 32].into(),
                    name: "alice".into(),
                    user_id: Some("alice".into()),
                    groups: vec![],
                },
            );
            let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(StaticGate::new(entries));

            let pdir = tempfile::tempdir().unwrap();
            let audit_dir = pdir.path().join("audit");
            let sink = AuditSink::new(AuditLog::spawn(audit_dir.clone()));
            let scopes = Arc::new(ScopeStore::new(pdir.path().join("scopes.json")));
            let provider_ep = ep().await;
            let provider = AppBlobs::load(
                pdir.path().join("blobs"),
                scopes,
                gate,
                provider_ep.clone(),
                sink,
                crate::limits::MeshLimiters::unlimited(),
                None,
            )
            .await
            .unwrap();
            provider.spawn_accept(&provider_ep);

            let src = pdir.path().join("doc.bin");
            std::fs::write(&src, b"auditable bytes").unwrap();
            let (ticket, hash_hex) = provider.publish_scope("docs", &src).await.unwrap();
            provider.grant("docs", "alice").unwrap();

            let cdir = tempfile::tempdir().unwrap();
            let alice = AppBlobs::open_fetcher(cdir.path().join("a"), alice_ep.clone())
                .await
                .unwrap();
            let _ = alice.fetch(&ticket).await.expect("granted alice fetches");

            let month = &crate::audit::now_ts()[..7];
            let file = audit_dir.join(format!("{month}.jsonl"));
            let mut ok = false;
            for _ in 0..50 {
                let alice_eid = format!("eid:{}", alice_ep.id());
                if let Ok(b) = std::fs::read_to_string(&file)
                    && b.contains("\"kind\":\"blob_fetch\"")
                    && b.contains("\"peer\":\"alice\"")
                    // #57 second surface: who fetched which BYTES is the record where
                    // two-devices-one-nickname is most likely the actual question.
                    && b.contains(&format!("\"principal\":\"{alice_eid}\""))
                    && b.contains(&hash_hex)
                {
                    ok = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(
                ok,
                "a served GET records blob_fetch(peer=alice, hash, status)"
            );
        })
        .await
        .expect("blob_fetch audit test timed out");
    }
}
