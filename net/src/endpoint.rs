//! serve/connect over Iroh: the composition site for the session kernel.
//!
//! One accepted connection flows: accept-time trust gate → the first frame read
//! as `initialize` → service selection with reserved-`_meta` stripping → attach
//! the selected backend, or refuse.
//!
//! It is also THE single site that synthesizes framing-violation errors and
//! registers strikes. `recv_frame` answers each oversized/malformed frame with a
//! synthesized error (-32051 for `TooLarge`, -32700 for `InvalidJson`, both
//! `id: null` with `data.source: "mcpmesh"`), registers a strike, and finishes
//! the stream on the third strike. It is a general frame-reading primitive — not
//! special-cased to the first frame — so the same discipline covers the
//! pre-initialize read and any read the session loop drives. Once a backend
//! consumes the transport, it owns its own reads (the raw path sees typed
//! `RecvError::Violation` from `recv_value`; the rmcp path skip-and-logs).
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::errors::{ERR_FRAMING, ERR_PARSE, ERR_SERVICE, MSG_SERVICE, synthesized};
use crate::framing::{MAX_FRAME_BYTES, StrikeOutcome, Strikes, Violation};
use crate::identity::{EndpointId, PeerIdentity, TrustGate};
use crate::service::{ServiceDecision, select_service};
use crate::transport::{NdjsonTransport, RecvError};

/// ALPN for the one MCP-over-mesh protocol.
pub const ALPN_MCP: &[u8] = b"mcpmesh/mcp/1";

/// ALPN for the pairing rendezvous. Registered on the same endpoint as
/// `ALPN_MCP`; accept handlers for it are GATE-EXEMPT by construction — they
/// authenticate via the invite secret, not the trust gate. The cli owns the
/// handler; net only owns the ALPN string (the wire vocabulary registry).
pub const ALPN_PAIR: &[u8] = b"mcpmesh/pair/1";

/// ALPN for the reachability probe (pairing-mode liveness). A dialer connects, opens one
/// bi-stream, and sends a ping frame; the responder — ONLY for a trust-gated (paired) peer —
/// writes one pong frame `{"stack_version": "..."}` and closes. An unpaired scanner's connection
/// is closed with NO pong (no presence leak). The cli owns the accept handler (trust-gated there);
/// net owns only the ALPN string (the wire vocabulary registry, like `ALPN_PAIR`).
pub const ALPN_PING: &[u8] = b"mcpmesh/ping/1";

/// QUIC application close code for gate refusal, sent BEFORE any MCP traffic.
/// Mirrors HTTP 401 for operator legibility.
pub const CLOSE_UNAUTHORIZED: u32 = 401;

// Per-session frame cap: `framing::MAX_FRAME_BYTES` (16 MiB — the ONE family
// constant, owned by mcpmesh-codec).

/// One MCP session's byte streams as delivered by iroh, framed by the family
/// codec.
pub type SessionTransport = NdjsonTransport<iroh::endpoint::RecvStream, iroh::endpoint::SendStream>;

/// Why a [`connect`] dial failed. Each variant names one of the two failure
/// points of the dial sequence, so callers can match on the phase without
/// parsing strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    /// The QUIC dial itself failed: no route was discovered, the handshake
    /// failed, or the peer refused the connection (e.g. an untrusting gate
    /// closes with code 401 before any stream opens).
    #[error("dialing the peer failed: {0}")]
    Dial(#[from] iroh::endpoint::ConnectError),
    /// The connection came up but opening the session bi-stream failed — the
    /// connection was closed or lost before the stream could open.
    #[error("opening the session stream failed: {0}")]
    OpenStream(#[from] iroh::endpoint::ConnectionError),
}

/// What answers a selected service's session. `run` OWNS the transport so an
/// rmcp backend can hand it to `rmcp::serve_server`, while a raw backend drives
/// `recv_value`/`send_value` directly — one signature serves both.
///
/// `run` returns `anyhow::Result` DELIBERATELY (unlike [`connect`]'s typed
/// [`ConnectError`]): implementors are arbitrary backends whose failures are
/// open-ended (child process exits, socket teardown, protocol errors), and the
/// caller only logs them — there is nothing to match on.
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync + 'static {
    /// Drive one session. The gate-resolved caller `identity` is handed in FIRST
    /// (`Some` for every admitted session — a resolved identity is a
    /// precondition of reaching a backend; `None` is reserved for future
    /// no-identity paths). It is a PER-CALLER value threaded through `run` rather
    /// than a per-backend construction field, because the serving side builds
    /// each backend ONCE per service and reuses it across all callers. The
    /// backend maps the identity to its injection: env vars (`run`) or
    /// `_meta["mcpmesh/peer"]` (`socket`); `None` injects nothing.
    ///
    /// The `initialize` frame — already reserved-`_meta` stripped — is handed in
    /// next. The backend owns orderly teardown of the transport it consumes (raw
    /// path: `transport.shutdown()`; rmcp path: `close()` → drop → finish).
    ///
    /// **A CUSTOM backend must enforce the reserved namespace itself.** The frames
    /// this trait hands over after `initialize` are raw caller input, and frame 1 is
    /// only *assumed* to be the handshake — `run_session` never checks its `method`.
    /// #164 was exactly that gap: a caller sent another method first and forged
    /// `mcpmesh/peer` in frame 2. The in-tree backends route every frame through
    /// their pump's sanitizer; an embedder implementing this trait must call
    /// [`crate::service::strip_reserved_meta`] on every frame it reads, and inject
    /// its own authoritative identity into whichever frame carries
    /// `method == "initialize"`. This doc previously said the transport "carries the
    /// rest of the session verbatim", which described the defect.
    async fn run(
        &self,
        identity: Option<PeerIdentity>,
        initialize: Value,
        transport: SessionTransport,
    ) -> anyhow::Result<()>;
}

/// One registered service: the backend that answers it plus the `allow` list of
/// callers admitted to it (nicknames/user_ids/groups — a flat namespace).
/// `run_session` matches the resolved peer identity against `allow` to compute
/// the caller's admitted service set.
pub struct ServiceEntry {
    pub backend: Arc<dyn SessionBackend>,
    pub allow: Vec<String>,
    /// Which backend shape answers this service. Carried HERE rather than looked up from
    /// `config.toml` at report time (#100): the registry is the authority on what is being
    /// served, and a config file that has since been edited, had the entry removed, or been made
    /// malformed must not be able to hide a service the accept path is still admitting peers to.
    pub kind: ServiceKind,
    /// True if this entry came from an ephemeral registration (#36) rather than config — in-memory
    /// only, tied to the registering control connection, gone on restart.
    pub ephemeral: bool,
}

/// The backend shape of a [`ServiceEntry`] — kind only, never the command or socket path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ServiceKind {
    Run,
    Socket,
}

/// The service registry, keyed by distinct service name. Each [`ServiceEntry`]
/// carries the per-service `allow` list `run_session` consults to authorize a
/// resolved peer.
pub struct Services(HashMap<String, ServiceEntry>);

impl Services {
    /// Wrap a fully-built registry (the daemon builds the map from config `[services.*]`).
    pub fn new(services: HashMap<String, ServiceEntry>) -> Self {
        Self(services)
    }

    /// Look up one service by its distinct name.
    pub fn get(&self, name: &str) -> Option<&ServiceEntry> {
        self.0.get(name)
    }

    /// Iterate `(name, entry)` over every registered service.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &ServiceEntry)> {
        self.0.iter()
    }

    /// A copy of this registry with ONE service's `allow` replaced, or `None` if the name is not
    /// registered.
    ///
    /// This is the cheap half of a hot-reload (#94). Rebuilding from disk re-reads and re-parses
    /// `config.toml` and reconstructs EVERY service's backend, which is per-grant work that scales
    /// with the number of services rather than with the one being changed. When the config file
    /// did not change — an allow edit that lives purely in the ephemeral overlay (#36/#69) — the
    /// rebuilt registry would be identical apart from this one list.
    ///
    /// Backends are `Arc`s and are cloned by handle, never reconstructed: no process is respawned
    /// and no socket path is re-resolved. The result is swapped in through
    /// [`LiveServices::store`], so it inherits #54's per-bi-stream visibility unchanged.
    pub fn with_allow_replaced(&self, name: &str, allow: Vec<String>) -> Option<Services> {
        if !self.0.contains_key(name) {
            return None;
        }
        Some(Services(
            self.0
                .iter()
                .map(|(svc, entry)| {
                    let allow = if svc == name {
                        allow.clone()
                    } else {
                        entry.allow.clone()
                    };
                    (
                        svc.clone(),
                        ServiceEntry {
                            backend: Arc::clone(&entry.backend),
                            allow,
                            kind: entry.kind,
                            ephemeral: entry.ephemeral,
                        },
                    )
                })
                .collect(),
        ))
    }
}

/// A hot-swappable handle to the live [`Services`] registry.
///
/// The accept path reads this ONCE PER accepted bi-stream, so a config reload (a grant, a revoke,
/// a roster install) is visible to the very next session on an ALREADY-OPEN connection. The
/// previous design handed each connection an `Arc<Services>` captured when the accept loop was
/// spawned, so a revoked peer kept opening admitted sessions for the whole lifetime of its
/// connection — the verb reported success and did nothing (#54).
///
/// In-flight sessions deliberately keep the snapshot they were admitted under: a session's service
/// resolution is fixed at admit. Cutting those is the revoke path's
/// [`sever_matching`](crate::registry::ConnRegistry::sever_matching) job.
///
/// `std::sync::RwLock` (not `arc-swap`) matches the surrounding idiom and is never held across an
/// await — [`get`](Self::get) clones the `Arc` and drops the guard before returning.
pub struct LiveServices(std::sync::RwLock<Arc<Services>>);

impl LiveServices {
    /// Wrap an initial registry.
    pub fn new(services: Arc<Services>) -> Self {
        Self(std::sync::RwLock::new(services))
    }

    /// The registry as of now. Cheap: one `Arc` clone under a read lock.
    pub fn get(&self) -> Arc<Services> {
        self.0
            .read()
            .expect("live services lock not poisoned")
            .clone()
    }

    /// Hot-swap the registry. Visible to every subsequent [`get`](Self::get); handles already
    /// taken are unaffected (that is what keeps an in-flight session on its admit-time snapshot).
    pub fn store(&self, services: Arc<Services>) {
        *self.0.write().expect("live services lock not poisoned") = services;
    }
}

/// Handle to a running [`serve`] accept loop.
///
/// Dropping this handle does NOT stop the accept loop: the spawned task keeps
/// running for the life of the process. This RAII inversion is deliberate for a
/// process-lifetime daemon — only [`ServeHandle::shutdown`] aborts the loop (so
/// there is intentionally no `Drop` impl).
pub struct ServeHandle {
    task: tokio::task::JoinHandle<()>,
}

impl ServeHandle {
    /// Stop accepting new connections. In-flight sessions run in their own tasks
    /// and are not aborted here.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// Accept connections on `endpoint`, trust-gate each one, and route each session
/// bi-stream to its named service. Returns immediately; the accept loop runs in
/// a spawned task (stop it via [`ServeHandle::shutdown`]).
///
/// Every accepted connection is tracked in the caller-supplied `registry`, so
/// [`ConnRegistry::sever_matching`](crate::registry::ConnRegistry::sever_matching)
/// on that same handle severs live connections this loop admitted — keep the
/// `Arc` if you need severing. (An earlier version built a private registry
/// internally, which made the registry module's severing guarantees silently
/// unavailable to `serve` users.)
pub fn serve(
    endpoint: iroh::Endpoint,
    gate: Arc<dyn TrustGate>,
    services: Services,
    registry: Arc<crate::registry::ConnRegistry>,
) -> ServeHandle {
    let services = Arc::new(LiveServices::new(Arc::new(services)));
    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let gate = gate.clone();
            let services = services.clone();
            let registry = registry.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::debug!(%e, "inbound handshake failed");
                        return;
                    }
                };
                run_mesh_connection(conn, gate, services, registry).await;
            });
        }
    });
    ServeHandle { task }
}

/// Handle one accepted mesh (`ALPN_MCP`) connection: trust-gate the peer, then
/// route each session bi-stream to its named service. The connection is already
/// handshake-complete (the caller has awaited `incoming`).
///
/// Extracted from [`serve`]'s per-connection body so a daemon can run ONE accept
/// loop that dispatches by ALPN (mesh here, pairing elsewhere) — net keeps NO
/// pairing knowledge. `Services` arrives `Arc`'d because callers share one
/// registry across every connection (`serve` wraps once; the daemon holds its
/// own `Arc`).
pub async fn run_mesh_connection(
    conn: iroh::endpoint::Connection,
    gate: Arc<dyn TrustGate>,
    services: Arc<LiveServices>,
    registry: Arc<crate::registry::ConnRegistry>,
) {
    // 1. Accept-time trust gate — before any MCP traffic. `remote_id()` on a
    //    handshake-complete connection returns the peer id directly.
    let remote: EndpointId = conn.remote_id().into();
    let Some(identity) = gate.resolve(&remote) else {
        // Default-deny: refuse the stranger with a QUIC application close code
        // BEFORE opening any stream. No MCP frame is ever exchanged. The
        // EndpointId is deliberately NOT logged (surface-leak discipline).
        conn.close(CLOSE_UNAUTHORIZED.into(), b"unauthorized");
        tracing::debug!("refused unresolved peer (QUIC 401)");
        return;
    };
    // CHECK-register the connection so a roster install that swapped the view between the
    // `resolve` above and here cannot leave a to-be-severed session live (the TOCTOU close — see the
    // registry module doc's three-case argument). The recheck runs UNDER the registry lock,
    // serialized against the installer's `sever_matching`; it evaluates the FULL sever predicate via
    // `should_sever_now(eid, roster_user)` — closing BOTH halves: a newly-revoked endpoint AND a
    // previously-roster-resolved endpoint now absent from the installed roster (the
    // dropped-from-roster half). `roster_user` is the ROSTER-resolved user_id captured at resolve
    // time (`None` for a pairing-only peer) — NOT `identity.user_id`, which since the self-sovereign
    // device→user binding is also `Some` for a paired peer and would wrongly sever it. A `true` means
    // the endpoint must be severed per the live gate → self-close (QUIC 401) with no session and no
    // registry entry. The returned RAII `_registration` is held for the whole accept_bi loop below
    // and DEREGISTERS the connection when this fn returns (deregister-on-close, no leak).
    let roster_user = gate.roster_user(&remote);
    let Some(_registration) = registry.register_checked(&conn, roster_user.clone(), |eid| {
        gate.should_sever_now(eid, roster_user.as_deref())
    }) else {
        conn.close(CLOSE_UNAUTHORIZED.into(), b"unauthorized");
        tracing::debug!("refused newly-severed peer at check-register (race close, QUIC 401)");
        return;
    };
    // 2. Sessions: one bi-stream each; a connection may carry several.
    //    `accept_bi()` yields `(send, recv)`.
    while let Ok((send, recv)) = conn.accept_bi().await {
        // Read the LIVE registry PER SESSION (#54): a revoke landing between two sessions on
        // this same connection is honored by the second one. Before this, each connection carried
        // an `Arc<Services>` captured when the accept loop was spawned, so a revoked peer kept
        // opening admitted sessions until it happened to disconnect.
        let services = services.get();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = run_session(recv, send, &identity, &services).await {
                tracing::warn!(peer = %identity.name, %e, "session ended with error");
            }
        });
    }
}

/// Does this service's `allow` list admit the resolved caller? The flat authorization namespace
/// is STABLE principals (#38): the device `eid:` (rendered from the AUTHENTICATED endpoint id),
/// a user_id (roster bare handle or pairing `b64u:`), or a roster group name. The display
/// nickname is NEVER matched — renames can never change what a peer is granted. Extracted so
/// the exact predicate `run_session` uses is unit-testable.
///
/// The expansion itself is THE shared `mcpmesh_local_api::principal_set` — the same implementation
/// the plugin seam's `peer_audiences` and the blob-scope gate use, so the enforcement sites cannot
/// drift.
fn caller_admits(identity: &PeerIdentity, allow: &[String]) -> bool {
    let eid = identity.endpoint.principal();
    let principals =
        mcpmesh_local_api::principal_set(Some(&eid), identity.user_id.as_deref(), &identity.groups);
    let admitted = allow.iter().any(|a| principals.contains(a.as_str()));
    if !admitted {
        // The #38 diagnostic: a refusal names BOTH sides of the comparison, so a
        // principal/allow mismatch is debuggable without source-diving. Debug-level —
        // principals are the machine namespace, not porcelain output.
        tracing::debug!(?principals, ?allow, "caller not admitted by allow list");
    }
    admitted
}

/// Drive one accepted session: enforce framing on the first frame, select a
/// service, then attach the backend or refuse.
async fn run_session(
    recv: iroh::endpoint::RecvStream,
    send: iroh::endpoint::SendStream,
    // Peer identity is resolved by the gate and threaded here: it is matched
    // against each service's `allow` to compute the caller's admitted set, and
    // the `_meta["mcpmesh/peer"]` injection reads it too.
    identity: &PeerIdentity,
    services: &Services,
) -> anyhow::Result<()> {
    let mut transport = SessionTransport::new(recv, send, MAX_FRAME_BYTES);
    let mut strikes = Strikes::default();

    // The first frame the session reads is treated as `initialize`.
    // Pre-initialize framing violations are synthesized + struck inside
    // `recv_frame` (the single site); an EOF, a transport teardown, or a
    // strike-out all end the session cleanly.
    let Some(mut init) = recv_frame(&mut transport, &mut strikes).await else {
        return Ok(());
    };

    // caller_allowed = services whose `allow` admits this resolved identity (the flat allow
    // namespace is STABLE principals: `eid:` device ids, user_ids, and group names — never
    // nicknames, #38). `caller_admits` checks all three arms: the authenticated device eid,
    // the user_id (`identity.user_id`, present for roster callers and bound pairing peers),
    // and group — so a roster caller named only by its user_id is admitted. The roster's
    // flat-namespace disjointness rule guarantees a group and a user_id never collide.
    let allowed: Vec<String> = services
        .iter()
        .filter(|(_, e)| caller_admits(identity, &e.allow))
        .map(|(name, _)| name.clone())
        .collect();
    match select_service(&mut init, &allowed) {
        ServiceDecision::Selected(name) => {
            let backend = services
                .get(&name)
                .expect("selected from registry")
                .backend
                .clone();
            // Hand off: the backend owns the transport and its teardown. The
            // gate-resolved identity is threaded through `run` (per-caller), not
            // baked into the shared backend — it drives the backend's
            // env/`_meta` injection. Every admitted session has a resolved
            // identity post-gate.
            backend.run(Some(identity.clone()), init, transport).await
        }
        ServiceDecision::Refuse => {
            // Unknown or unauthorized — identical wording either way.
            // Echo the initialize `id` when present.
            let id = init.get("id").cloned().unwrap_or(Value::Null);
            // Best-effort teardown: the refusal decision (-32054) is final, but a
            // peer that already vanished must not turn a NORMAL refusal into a
            // warn!("session ended with error"). Write + finish are advisory —
            // same treatment `recv_frame` gives its own teardown writes.
            let _ = transport
                .send_value(synthesized(id, ERR_SERVICE, MSG_SERVICE))
                .await;
            // Finish the stream so the refusal frame flushes to the peer before
            // the write half closes (a bare drop abandons buffered data).
            let _ = transport.shutdown().await;
            Ok(())
        }
    }
}

/// Read the next MCP frame, enforcing the framing-violation protocol.
///
/// THE single site that synthesizes framing-violation errors and registers
/// strikes. A violated frame carries no recoverable request id, so the error
/// `id` is `null`; the code is `-32051` for an oversized frame and `-32700` for
/// a non-JSON frame, both marked `data.source: "mcpmesh"`. A strike is
/// registered per violation; the third strike (`StrikeOutcome::Close`) finishes
/// the stream and ends the read.
///
/// Returns `Some(frame)` for the next valid frame, or `None` for a clean end:
/// EOF, a transport IO teardown (the peer is gone — nothing to synthesize back),
/// or a strike-out close.
async fn recv_frame<R, W>(
    transport: &mut NdjsonTransport<R, W>,
    strikes: &mut Strikes,
) -> Option<Value>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        match transport.recv_value().await {
            Ok(Some(v)) => return Some(v),
            Ok(None) => return None, // clean EOF
            // A transport IO error is a clean teardown: the peer is gone, so
            // there is nothing to synthesize back.
            Err(RecvError::Io(_)) => return None,
            Err(RecvError::Violation(v)) => {
                let (code, message) = match v {
                    Violation::TooLarge => (ERR_FRAMING, "frame exceeds max_frame_bytes"),
                    Violation::InvalidJson => (ERR_PARSE, "frame is not valid JSON"),
                    // `Violation` is non_exhaustive: any future violation kind is
                    // still a framing violation — answer with the generic code.
                    _ => (ERR_FRAMING, "framing violation"),
                };
                // Best-effort: a failed write means the peer is gone; the strike
                // decision below still runs.
                let _ = transport
                    .send_value(synthesized(Value::Null, code, message))
                    .await;
                if strikes.register() == StrikeOutcome::Close {
                    // Orderly close so the final error frame flushes first.
                    let _ = transport.shutdown().await;
                    return None;
                }
                // Strike registered, stream continues: read the next frame.
            }
        }
    }
}

/// Caller side: dial `peer`, open one session bi-stream, and return the framed
/// transport ALONGSIDE the connection it rides. The caller writes the
/// `initialize` frame naming the service in the params
/// `_meta["mcpmesh/service"]`; the server strips the reserved key before any
/// backend sees it. `service` is accepted here only to name the dial in
/// errors/traces — the caller already holds it. `open_bi()` yields
/// `(send, recv)`.
///
/// **The `Connection` is returned as of #92 item 2, and that is a BREAKING
/// change.** It previously returned `SessionTransport` alone — an alias for
/// `NdjsonTransport<RecvStream, SendStream>`, i.e. the QUIC *streams* — and
/// dropped the connection here. Sessions still worked, because quinn's streams
/// keep the connection alive internally, but nothing upstream could observe it:
/// no `path_events()`, no `paths()`, no per-session path signal of any kind.
///
/// A caller that only wants the transport can `.0` it. The connection is
/// returned rather than a watcher being spawned here on purpose: `net` has no
/// knowledge of the reachability cache, and pushing the watcher down would mean
/// plumbing a callback through a lower layer for one caller's benefit.
pub async fn connect(
    endpoint: &iroh::Endpoint,
    peer: iroh::EndpointAddr,
    service: &str,
) -> Result<(SessionTransport, iroh::endpoint::Connection), ConnectError> {
    tracing::debug!(service, "dialing mesh service");
    let conn = endpoint.connect(peer, ALPN_MCP).await?;
    let (send, recv) = conn.open_bi().await?;
    Ok((SessionTransport::new(recv, send, MAX_FRAME_BYTES), conn))
}

#[cfg(test)]
mod tests {
    //! Directly exercise the synthesis+strike path over an in-memory `duplex`
    //! (no iroh setup): a violation draws a synthesized error on the wire
    //! (right code, id: null, `data.source: "mcpmesh"`), each violation
    //! strikes, and the third strike shuts the write half down
    //! (StrikeOutcome::Close). This is the session-layer half that the
    //! framing/transport unit tests only cover as primitives.
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex, split};

    use super::*;
    use crate::framing::{FrameReader, Inbound};

    /// A backend that is never run — these tests only care about registry identity, and
    /// `Arc::ptr_eq` on this is how they prove nothing was reconstructed.
    struct InertBackend;

    #[async_trait::async_trait]
    impl SessionBackend for InertBackend {
        async fn run(
            &self,
            _identity: Option<PeerIdentity>,
            _initialize: Value,
            _transport: SessionTransport,
        ) -> anyhow::Result<()> {
            unreachable!("InertBackend is never run")
        }
    }

    fn registry(entries: &[(&str, &[&str])]) -> Services {
        Services::new(
            entries
                .iter()
                .map(|(name, allow)| {
                    (
                        (*name).to_string(),
                        ServiceEntry {
                            backend: Arc::new(InertBackend),
                            allow: allow.iter().map(|a| (*a).to_string()).collect(),
                            kind: ServiceKind::Run,
                            ephemeral: false,
                        },
                    )
                })
                .collect(),
        )
    }

    /// #94: replacing ONE service's allow leaves every other entry untouched — and reuses the
    /// same backend allocations. `Arc::ptr_eq` is the assertion that carries the point: the
    /// whole reason this exists instead of `reload_services_from_disk` is that no backend is
    /// reconstructed. A rewrite that rebuilt backends would still pass an allow-only assertion.
    #[test]
    fn with_allow_replaced_swaps_one_allow_and_reuses_every_backend() {
        let before = registry(&[("room", &["b64u:alice"]), ("notes", &["b64u:bob"])]);
        let after = before
            .with_allow_replaced("room", vec!["b64u:alice".into(), "b64u:carol".into()])
            .expect("room is present");

        assert_eq!(
            after.get("room").expect("room survives").allow,
            vec!["b64u:alice".to_string(), "b64u:carol".to_string()],
            "the named service takes the new allow"
        );
        assert_eq!(
            after.get("notes").expect("notes survives").allow,
            vec!["b64u:bob".to_string()],
            "an unrelated service's allow is untouched"
        );
        for name in ["room", "notes"] {
            assert!(
                Arc::ptr_eq(
                    &before.get(name).expect("present before").backend,
                    &after.get(name).expect("present after").backend,
                ),
                "{name}: the backend must be the SAME allocation — reconstructing backends is \
                 exactly the cost this method exists to avoid"
            );
        }
    }

    /// An unknown name yields `None` rather than inserting a backendless entry — the caller
    /// (an ephemeral grant) must fall back to a real rebuild rather than invent a service.
    #[test]
    fn with_allow_replaced_returns_none_for_an_unknown_service() {
        let before = registry(&[("room", &["b64u:alice"])]);
        assert!(before.with_allow_replaced("nope", vec![]).is_none());
    }

    /// #54: a swap is visible to the NEXT read, while a handle already taken keeps the
    /// snapshot it was given — the exact split the accept path relies on (next session honors a
    /// revoke; the in-flight session it was admitted under is not rewritten under it).
    #[test]
    fn live_services_swap_is_visible_to_the_next_get_only() {
        let (before, after) = (
            Arc::new(Services::new(HashMap::new())),
            Arc::new(Services::new(HashMap::new())),
        );
        let live = LiveServices::new(before.clone());
        let taken = live.get();
        assert!(Arc::ptr_eq(&taken, &before));

        live.store(after.clone());
        assert!(
            Arc::ptr_eq(&taken, &before),
            "an already-taken handle keeps its admit-time snapshot"
        );
        assert!(
            Arc::ptr_eq(&live.get(), &after),
            "the next read resolves against the swapped-in registry"
        );
    }

    /// One error frame off the probe side; panics if the stream is EOF or a
    /// (non-existent) violation instead of a frame.
    async fn read_error<R: AsyncRead + Unpin>(probe: &mut FrameReader<R>) -> Value {
        match probe.next().await.unwrap().unwrap() {
            Inbound::Frame(v) => v,
            other => panic!("expected a synthesized error frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_frame_answers_invalid_json_with_parse_error() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (server_io, probe_io) = duplex(4096);
            let (sr, sw) = split(server_io);
            let (pr, mut pw) = split(probe_io);
            let mut server = NdjsonTransport::new(sr, sw, 64);
            let mut probe = FrameReader::new(pr, 4096);

            pw.write_all(b"not json at all\n").await.unwrap();
            // A split WriteHalf drop does NOT signal EOF; shutdown() does — the
            // server's follow-up read then returns None and recv_frame ends.
            pw.shutdown().await.unwrap();

            let task = tokio::spawn(async move {
                let mut strikes = Strikes::default();
                recv_frame(&mut server, &mut strikes).await
            });

            let err = read_error(&mut probe).await;
            assert_eq!(err["error"]["code"], ERR_PARSE); // -32700
            assert_eq!(err["error"]["data"]["source"], "mcpmesh");
            assert!(err["id"].is_null(), "a violated frame has no request id");
            assert!(
                task.await.unwrap().is_none(),
                "EOF after the strike ends the read"
            );
        })
        .await
        .expect("invalid-json synthesis test timed out");
    }

    #[tokio::test]
    async fn recv_frame_answers_oversized_frame_with_framing_error() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (server_io, probe_io) = duplex(4096);
            let (sr, sw) = split(server_io);
            let (pr, mut pw) = split(probe_io);
            let mut server = NdjsonTransport::new(sr, sw, 64);
            let mut probe = FrameReader::new(pr, 4096);

            // A 102-byte bare string exceeds the 64-byte cap → TooLarge.
            let oversized = format!("\"{}\"\n", "x".repeat(100));
            pw.write_all(oversized.as_bytes()).await.unwrap();
            pw.shutdown().await.unwrap(); // signal EOF (a split-half drop would not)

            let task = tokio::spawn(async move {
                let mut strikes = Strikes::default();
                recv_frame(&mut server, &mut strikes).await
            });

            let err = read_error(&mut probe).await;
            assert_eq!(err["error"]["code"], ERR_FRAMING); // -32051
            assert_eq!(err["error"]["data"]["source"], "mcpmesh");
            assert!(err["id"].is_null());
            assert!(task.await.unwrap().is_none());
        })
        .await
        .expect("oversized synthesis test timed out");
    }

    #[tokio::test]
    async fn recv_frame_strikes_out_and_closes_after_third_violation() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (server_io, probe_io) = duplex(4096);
            let (sr, sw) = split(server_io);
            let (pr, mut pw) = split(probe_io);
            let mut server = NdjsonTransport::new(sr, sw, 64);
            let mut probe = FrameReader::new(pr, 4096);

            // Three consecutive malformed frames — no trailing EOF is needed: the
            // third strike (StrikeOutcome::Close) must shut the stream down itself.
            pw.write_all(b"garbage one\ngarbage two\ngarbage three\n")
                .await
                .unwrap();

            let task = tokio::spawn(async move {
                let mut strikes = Strikes::default();
                recv_frame(&mut server, &mut strikes).await
            });

            for _ in 0..3 {
                let err = read_error(&mut probe).await;
                assert_eq!(err["error"]["code"], ERR_PARSE);
                assert_eq!(err["error"]["data"]["source"], "mcpmesh");
            }
            // The strike-out shutdown() finishes the write half → the probe reads
            // EOF right after the third synthesized error.
            assert!(
                probe.next().await.unwrap().is_none(),
                "the third strike must shut the stream down"
            );
            assert!(task.await.unwrap().is_none());
        })
        .await
        .expect("strike-out test timed out");
    }

    /// `caller_admits` implements the flat STABLE-principal namespace (#38): the authenticated
    /// device `eid:` OR user_id OR group — the display nickname NEVER admits. This calls the
    /// PRODUCTION function so each arm (and the nickname refusal) is a real red→green change.
    #[test]
    fn caller_admits_by_eid_user_id_or_group() {
        let allow = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // A roster identity: user_id "alice", groups team-eng+all, on device [1u8; 32].
        let roster = PeerIdentity {
            endpoint: EndpointId::from_bytes([1u8; 32]),
            name: "alice".into(),
            user_id: Some("alice".into()),
            groups: vec!["team-eng".into(), "all".into()],
        };
        assert!(
            caller_admits(&roster, &allow(&["alice"])),
            "user_id arm (bare roster handle is a principal)"
        );
        assert!(
            caller_admits(&roster, &allow(&["team-eng"])),
            "group arm (the group allow)"
        );
        assert!(
            caller_admits(&roster, &allow(&[&roster.endpoint.principal()])),
            "eid arm (the authenticated device principal admits)"
        );
        assert!(
            !caller_admits(&roster, &allow(&["bob"])),
            "unrelated name refused"
        );
        assert!(
            !caller_admits(
                &roster,
                &allow(&[&EndpointId::from_bytes([9u8; 32]).principal()])
            ),
            "an UNRELATED eid principal is refused"
        );

        // The load-bearing case: name != user_id proves the user_id arm is REQUIRED, and the
        // nickname arm is GONE — an allow entry naming the display nickname must NOT admit.
        let by_uid_only = PeerIdentity {
            endpoint: EndpointId::from_bytes([2u8; 32]),
            name: "device-label".into(),
            user_id: Some("alice".into()),
            groups: vec![],
        };
        assert!(
            caller_admits(&by_uid_only, &allow(&["alice"])),
            "user_id arm admits independent of name"
        );
        assert!(
            !caller_admits(&by_uid_only, &allow(&["device-label"])),
            "the display nickname is NOT a principal (#38): it must never admit"
        );

        // A pairing identity (user_id None) is admitted ONLY by its stable eid — never by
        // its nickname, so no rename can ever change what it is granted.
        let pairing = PeerIdentity {
            endpoint: EndpointId::from_bytes([3u8; 32]),
            name: "bob".into(),
            user_id: None,
            groups: vec![],
        };
        assert!(
            caller_admits(&pairing, &allow(&[&pairing.endpoint.principal()])),
            "eid arm is the pairing peer's one principal"
        );
        assert!(
            !caller_admits(&pairing, &allow(&["bob"])),
            "pairing peer's nickname must not admit"
        );
        assert!(
            !caller_admits(&pairing, &allow(&["alice"])),
            "pairing peer has no user_id to match"
        );
    }
}
