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

/// The request-time scope-gate `EventMask` for the serving app-blob provider (spec §9).
///
/// SECURITY — deny-by-default on every non-GET request type, made EXPLICIT (not left to a vestigial
/// routing quirk). In the pinned iroh-blobs 0.103.0 the generic `EventSender::request()` reads ONLY
/// `mask.get` for EVERY request type (get/get_many/push/observe), so `get: Intercept` currently
/// routes all four to the drain loop, which denies the non-GET kinds explicitly
/// ([RECONCILE-MASK-GET-ROUTES-ALL]). To keep the deny-by-default INDEPENDENT of that single-field
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

/// The gated app-blob provider (spec §9). `events` is `Some` for a serving daemon (the request-time
/// scope Intercept gate is armed) and `None` for a caller-only fetcher. `scopes` is the persisted
/// scope table; a fetcher gets an empty one it never mutates.
///
/// [RECONCILE-EVENTSENDER-LIFETIME] The drain loop's `Receiver<ProviderMessage>` is moved into a task
/// spawned once in `load`. The loop lives as long as ANY `EventSender` clone lives; `AppBlobs` holds
/// one in `self.events` for the provider's lifetime (the daemon holds `AppBlobs` for its lifetime),
/// and every `protocol()` clones another into the `BlobsProtocol`. So the gate loop runs until the
/// daemon drops the provider — never terminating mid-serve.
pub struct AppBlobs {
    store: FsStore,
    endpoint: Endpoint,
    events: Option<EventSender>,
    scopes: Arc<ScopeStore>,
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
            scopes: Arc::new(ScopeStore::new(blobs_dir.join("scopes.json"))),
        }))
    }

    /// The GATED provider (spec §9): an `FsStore` + the request-time scope Intercept `EventSender`.
    /// Spawns the drain loop ONCE, wired to the trust `gate` (resolve endpoint → identity) and
    /// `scopes` (the authz table). `[RECONCILE-FSSTORE-CTOR-ASYNC]` `FsStore::load` is async/fallible;
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
        // const's SECURITY note). Per [RECONCILE-MASK-GET-ROUTES-ALL] `get: Intercept` also routes
        // get_many/observe/push to the drain loop today; the pinned fields keep them refused even if
        // a future iroh-blobs honors the per-type fields directly.
        let (events, rx) = EventSender::channel(64, APP_BLOB_EVENT_MASK);
        spawn_gate_loop(rx, gate, scopes.clone(), audit);
        Ok(Arc::new(Self {
            store,
            endpoint,
            events: Some(events),
            scopes,
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
    /// `APP_BLOB_ALPN` arm: D8 resolve → 401 + rate-limit + check-register); this exists only so
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
        let ticket = BlobTicket::new(self.endpoint.addr(), tag.hash, BlobFormat::Raw);
        Ok((ticket.to_string(), tag.hash.to_hex().to_string()))
    }

    /// Publish a LOCAL file INTO a scope (spec §9): add it to the store AND record its hash in the
    /// named scope (single-writer via `ScopeStore`). Returns `(ticket_string, blake3_hex)`.
    pub async fn publish_scope(&self, scope: &str, path: &Path) -> Result<(String, String)> {
        let (ticket, hash_hex) = self.publish_path(path).await?;
        self.scopes.publish_hash(scope, &hash_hex)?;
        Ok((ticket, hash_hex))
    }

    /// Grant a scope to a principal — any §5 flat-namespace entry: a group name, a user_id,
    /// or a petname (D1 ruling) — persisted single-writer.
    pub fn grant(&self, scope: &str, principal: &str) -> Result<()> {
        self.scopes.grant(scope, principal)
    }

    /// The current scope table (name, hashes, grants) for `list`.
    pub fn list(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
        self.scopes.list()
    }

    /// Fetch a ticket THROUGH this endpoint over `APP_BLOB_ALPN`, streaming BLAKE3-verified bytes
    /// into `self.store` ([RECONCILE-ALPN]). Returns the verified hash. A provider that refuses this
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
}

/// The request-time scope Intercept drain loop (spec §9 — the security core). Single-consumer: this
/// task owns `rx`, so the `connection_id → endpoint_id` map is loop-local with NO lock
/// ([RECONCILE-MAP-CONCURRENCY]) — FIFO delivery guarantees `ClientConnected(conn)` precedes any
/// `GetRequestReceived(conn)` on that connection. SECURITY-CRITICAL:
///  - `ClientConnected`: record the AUTHENTICATED `endpoint_id` (QUIC/TLS) → reply `Ok(())` to admit
///    (the accept-time gate already vetted the endpoint; the GET hook is the per-hash boundary). A
///    missing endpoint id (never on an authenticated conn) is denied defensively.
///  - `GetRequestReceived`: resolve the endpoint via the trust gate to its identity and ALLOW iff a
///    scope contains the hash AND grants one of the caller's §5 principals — `groups ∪ {petname} ∪
///    {user_id}`, the shared `principal_set` (D1) — else `Permission`, BEFORE any bytes (the
///    Intercept path blocks the transfer on the provider's `rx.await??`).
///  - get_many/observe/push (all routed through `mask.get`, [RECONCILE-MASK-GET-ROUTES-ALL]): DENY
///    explicitly — deny-by-default, the store is not a general filesystem surface. Belt-and-suspenders
///    with `APP_BLOB_EVENT_MASK`, which ALSO pins these types (get_many/push = `Disabled`, observe =
///    `Intercept`): if a future iroh-blobs delivers them as events instead of refusing at the mask,
///    they are still denied here.
fn spawn_gate_loop(
    mut rx: tokio::sync::mpsc::Receiver<ProviderMessage>,
    gate: Arc<dyn TrustGate>,
    scopes: Arc<ScopeStore>,
    audit: AuditSink,
) {
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
                    // attribution (spec §11.3 — peer is the gate-resolved identity, not self-asserted).
                    let identity = conns
                        .get(&msg.connection_id)
                        .and_then(|eid| gate.resolve(eid));
                    let hash_hex = msg.request.hash.to_hex().to_string();
                    let allow = msg.request.ranges.is_blob()
                        && identity.as_ref().is_some_and(|identity| {
                            // D1 RULING: the grant namespace is THE §5 flat principal set —
                            // groups ∪ {petname} ∪ {user_id} — via the ONE shared
                            // `principal_set` (same expansion as the mesh allow check and
                            // the plugin seam). The petname is deliberately INCLUDED: a
                            // pairing-mode peer (no user binding) granted a scope by its
                            // petname can fetch, matching service `allow` semantics; kb's
                            // attachment scopes grant by kb audience strings, which include
                            // petnames. Excluding it (the pre-D1 behavior) silently broke
                            // petname-audience attachments. Default-deny is untouched: an
                            // unlisted principal still gets `Permission` before any bytes.
                            let principals: HashSet<&str> = mcpmesh_local_api::principal_set(
                                Some(&identity.name),
                                identity.user_id.as_deref(),
                                &identity.groups,
                            )
                            .into_iter()
                            .collect();
                            scopes.snapshot().allows(&hash_hex, &principals)
                        });
                    // Audit the fetch (spec §11.3): peer + hash + status (ok/denied). A COUNT/ref only —
                    // never blob content. Attributes to the resolved user_id/petname, or "unknown".
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
                // Deny-by-default for every non-GET request type ([RECONCILE-MASK-GET-ROUTES-ALL]).
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
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::APP_BLOB_ALPN;
    use crate::blobs::scope::ScopeStore;
    use mcpmesh_net::{EndpointId, PeerIdentity, StaticGate};
    use std::sync::Arc;

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

    /// D1 regression — the blob-scope grant namespace is the FULL §5 flat principal set,
    /// petname included: a PAIRING-MODE peer (petname only, `user_id: None`, no groups)
    /// granted a scope by its petname CAN fetch; a resolved-but-unlisted peer is still
    /// denied (default-deny holds). Pins the ruling that aligned this gate with the mesh
    /// `allow` semantics (petnames were previously — wrongly — excluded here).
    #[tokio::test]
    async fn pairing_mode_petname_grant_admits_and_unlisted_peer_stays_denied() {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let carol_ep = ep().await; // pairing-mode: petname only
            let mallory_ep = ep().await; // resolved by the gate, but granted nothing
            let carol_id: EndpointId = carol_ep.id().into();
            let mallory_id: EndpointId = mallory_ep.id().into();

            let mut entries = std::collections::HashMap::new();
            entries.insert(
                carol_id,
                PeerIdentity {
                    endpoint: [0u8; 32].into(),
                    name: "carol".into(),
                    user_id: None, // no device→user binding — petname is the ONLY principal
                    groups: vec![],
                },
            );
            entries.insert(
                mallory_id,
                PeerIdentity {
                    endpoint: [0u8; 32].into(),
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
            std::fs::write(&src, b"petname-scoped bytes").unwrap();
            let (ticket, _hash) = provider
                .publish_scope("kb-attach-carol", &src)
                .await
                .unwrap();
            // Grant by PETNAME — the kb attachment-scope shape (audience strings include petnames).
            provider.grant("kb-attach-carol", "carol").unwrap();

            let cdir = tempfile::tempdir().unwrap();
            let carol = AppBlobs::open_fetcher(cdir.path().join("c"), carol_ep.clone())
                .await
                .unwrap();
            let hash = carol
                .fetch(&ticket)
                .await
                .expect("a pairing-mode peer granted by petname fetches");
            assert_eq!(
                &carol.read_bytes(hash).await.unwrap()[..],
                b"petname-scoped bytes"
            );

            // DEFAULT-DENY: mallory resolves at accept time but holds no grant → Permission.
            let mallory = AppBlobs::open_fetcher(cdir.path().join("m"), mallory_ep.clone())
                .await
                .unwrap();
            let res =
                tokio::time::timeout(std::time::Duration::from_secs(10), mallory.fetch(&ticket))
                    .await;
            assert!(
                matches!(res, Ok(Err(_))),
                "an unlisted peer is refused: {res:?}"
            );
        })
        .await
        .expect("petname-grant test timed out");
    }

    /// A served GET records a `blob_fetch` audit line attributed to the authenticated peer, with the
    /// hash and status=ok (spec §11.3 "each blob fetch — peer + hash + …"). Uses a real temp AuditLog.
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
