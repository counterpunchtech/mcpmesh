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
    get: RequestMode::Intercept,
    get_many: RequestMode::Disabled,
    push: RequestMode::Disabled,
    observe: ObserveMode::Intercept,
    throttle: ThrottleMode::None,
};

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
            events: None,
            relay_wait: std::sync::atomic::AtomicBool::new(false),
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
        let (events, rx) = EventSender::channel(64, APP_BLOB_EVENT_MASK);
        let gate_loop = spawn_gate_loop(rx, gate, scopes.clone(), audit);
        Ok(Arc::new(Self {
            store,
            endpoint,
            events: Some(events),
            scopes,
            gate_loop: tokio::sync::Mutex::new(Some(gate_loop)),
            relay_wait: std::sync::atomic::AtomicBool::new(false),
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
        self.scopes.publish_hash(scope, &canonical)?;
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
    pub fn unpublish(&self, scope: &str, hash_hex: &str) -> Result<bool> {
        self.scopes.unpublish_hash(scope, hash_hex)
    }

    /// The current scope table (name, hashes, grants) for `list`.
    pub fn list(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
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
        self.store
            .remote()
            .fetch(conn, ticket.hash())
            .await
            .context("fetch app blob")?;
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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut conns: HashMap<u64, mcpmesh_net::EndpointId> = HashMap::new();
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
                    audit.record(AuditRecord::blob_fetch(
                        now_ts(),
                        peer,
                        hash_hex,
                        if allow { "ok".into() } else { "denied".into() },
                    ));
                    let res = if allow {
                        Ok(())
                    } else {
                        Err(AbortReason::Permission)
                    };
                    msg.tx.send(res).await.ok();
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
            .flat_map(|(_, hashes, _)| hashes)
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
            .filter(|(name, _, _)| name == "room")
            .flat_map(|(_, hashes, _)| hashes)
            .collect();
        assert_eq!(
            recorded,
            vec![canonical],
            "the SCOPE must record canonical hex — the gate compares against it, so a raw-string \
             entry would authorize nobody and be unremovable"
        );
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
            .map(|(name, hashes, _)| (name, hashes))
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
        assert_eq!(APP_BLOB_EVENT_MASK.get, RequestMode::Intercept);
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
                if let Ok(b) = std::fs::read_to_string(&file)
                    && b.contains("\"kind\":\"blob_fetch\"")
                    && b.contains("\"peer\":\"alice\"")
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
