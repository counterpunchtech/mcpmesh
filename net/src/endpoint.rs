//! serve/connect over Iroh (spec §3.1 public API, §7.1–7.2 lifecycle).
//!
//! This is the composition site for the M1 kernel. One accepted connection flows:
//! accept-time trust gate (D5/D8) → the first frame read as `initialize`
//! (§7.2 step 4) → service selection with reserved-`_meta` stripping (§6.3) →
//! attach the selected backend, or refuse.
//!
//! It is also THE single site that synthesizes framing-violation errors and
//! registers strikes (Task 8 seam note). [`recv_frame`] answers each
//! oversized/malformed frame with a synthesized error (-32051 for `TooLarge`,
//! -32700 for `InvalidJson`, both `id: null` with `data.source: "mcpmesh"`),
//! registers a strike, and finishes the stream on the third strike (spec §7.3).
//! It is a general frame-reading primitive — not special-cased to the first
//! frame — so the same discipline covers the pre-initialize read and any read
//! the session loop drives. Once a backend consumes the transport, it owns its
//! own reads (the M1 raw path sees typed `RecvError::Violation` from
//! `recv_value`; the M2 rmcp path skip-and-logs per the Task 10 seam note, where
//! mid-session strike policy is decided).
use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::errors::{ERR_FRAMING, ERR_PARSE, ERR_SERVICE, MSG_SERVICE, synthesized};
use crate::framing::{MAX_FRAME_BYTES, StrikeOutcome, Strikes, Violation};
use crate::identity::{EndpointId, PeerIdentity, TrustGate};
use crate::service::{ServiceDecision, select_service};
use crate::transport::{NdjsonTransport, RecvError};

/// ALPN for the one MCP-over-mesh protocol (spec §3.1).
pub const ALPN_MCP: &[u8] = b"mcpmesh/mcp/1";

/// ALPN for the pairing rendezvous (spec §7.1). Registered on the same endpoint as
/// `ALPN_MCP`; accept handlers for it are GATE-EXEMPT by construction (D8 exception) —
/// they authenticate via the invite secret, not the trust gate. The cli owns the
/// handler; net only owns the ALPN string (the wire vocabulary registry).
pub const ALPN_PAIR: &[u8] = b"mcpmesh/pair/1";

/// QUIC application close code for gate refusal, sent BEFORE any MCP traffic
/// (spec §5, D5/D8). Mirrors HTTP 401 for operator legibility.
pub const CLOSE_UNAUTHORIZED: u32 = 401;

// Per-session frame cap: `framing::MAX_FRAME_BYTES` (spec §12 default, 16 MiB — the ONE
// family constant, owned by mcpmesh-codec). Config wiring is M2.

/// One MCP session's byte streams as delivered by iroh, framed by the family
/// codec. `iroh::endpoint::{RecvStream, SendStream}` are the settled Task 6
/// names.
pub type SessionTransport = NdjsonTransport<iroh::endpoint::RecvStream, iroh::endpoint::SendStream>;

/// What answers a selected service's session. M1 ships in-process backends only;
/// spawn/socket backends are M2 (spec §6.2). `run` OWNS the transport so an M2
/// rmcp backend can hand it to `rmcp::serve_server`, while an M1 raw backend
/// drives `recv_value`/`send_value` directly — one signature serves both.
#[async_trait::async_trait]
pub trait SessionBackend: Send + Sync + 'static {
    /// Drive one session. The gate-resolved caller `identity` is handed in FIRST
    /// (M2a: `Some` for every admitted session — a resolved identity is a
    /// precondition of reaching a backend; `None` is reserved for future
    /// no-identity paths). It is a PER-CALLER value threaded through `run` rather
    /// than a per-backend construction field, because `serve` builds each backend
    /// ONCE per service and reuses it across all callers (spec §6.3). The backend
    /// maps the identity to its injection: env vars (`run`) or
    /// `_meta["mcpmesh/peer"]` (`socket`); `None` injects nothing.
    ///
    /// The `initialize` frame — already reserved-`_meta` stripped (§6.3) — is
    /// handed in next; the transport then carries the rest of the session
    /// verbatim. The backend owns orderly teardown of the transport it consumes
    /// (raw path: `transport.shutdown()`; rmcp path: `close()` → drop → finish).
    async fn run(
        &self,
        identity: Option<PeerIdentity>,
        initialize: Value,
        transport: SessionTransport,
    ) -> anyhow::Result<()>;
}

/// One registered service: the backend that answers it plus the `allow` list of
/// callers admitted to it (petnames/user_ids/groups — a flat namespace, spec §5).
/// `run_session` matches the resolved peer identity against `allow` to compute
/// `caller_allowed` (RESOLVED: this closes M1's per-service-allow seam note; the
/// daemon builds each entry's `allow` from config `[services.*]`, Task 9).
pub struct ServiceEntry {
    pub backend: Arc<dyn SessionBackend>,
    pub allow: Vec<String>,
}

/// The service registry, keyed by distinct service name. Each [`ServiceEntry`]
/// carries the per-service `allow` list `run_session` consults to authorize a
/// resolved peer (RESOLVED M1 seam note "per-service allow lists from config —
/// M2").
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

/// Accept connections on `endpoint`, trust-gate each one (D5/D8), and route each
/// session bi-stream to its named service. Returns immediately; the accept loop
/// runs in a spawned task (stop it via [`ServeHandle::shutdown`]).
pub fn serve(
    endpoint: iroh::Endpoint,
    gate: Arc<dyn TrustGate>,
    services: Services,
) -> ServeHandle {
    let services = Arc::new(services);
    // Standalone (net's own tests / library use): a LOCAL registry so `serve`'s PUBLIC signature is
    // unchanged. No external caller severs against it — the daemon builds + threads its OWN shared
    // registry through [`run_mesh_connection`] for the D8 install-path sever (cli).
    let registry = Arc::new(crate::registry::ConnRegistry::new());
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

/// Handle one accepted mesh (`ALPN_MCP`) connection: trust-gate the peer (D5/D8),
/// then route each session bi-stream to its named service. The connection is
/// already handshake-complete (the caller has awaited `incoming`).
///
/// Extracted from [`serve`]'s per-connection body so the M2b daemon can run ONE
/// accept loop that dispatches by ALPN (mesh here, pairing elsewhere) — net keeps
/// NO pairing knowledge. `Services` arrives `Arc`'d because callers share one
/// registry across every connection (`serve` wraps once; the daemon holds its own
/// `Arc`).
pub async fn run_mesh_connection(
    conn: iroh::endpoint::Connection,
    gate: Arc<dyn TrustGate>,
    services: Arc<Services>,
    registry: Arc<crate::registry::ConnRegistry>,
) {
    // 1. Accept-time trust gate — before any MCP traffic (D5/D8).
    //    `remote_id()` on a HandshakeCompleted connection returns the
    //    peer EndpointId directly (iroh 1.0.1); `.as_bytes()` is our
    //    wire-agnostic `[u8; 32]` alias.
    let remote: EndpointId = *conn.remote_id().as_bytes();
    let Some(identity) = gate.resolve(&remote) else {
        // Default-deny: refuse the stranger with a QUIC application
        // close code BEFORE opening any stream (spec §5, D5/D8). No
        // MCP frame is ever exchanged. The EndpointId is deliberately
        // NOT logged (surface-leak discipline, spec §1.5).
        conn.close(CLOSE_UNAUTHORIZED.into(), b"unauthorized");
        tracing::debug!("refused unresolved peer (QUIC 401)");
        return;
    };
    // M3 (D8): CHECK-register the connection so a roster install that swapped the view between the
    // `resolve` above and here cannot leave a to-be-severed session live (the TOCTOU close — see the
    // registry module doc's three-case argument). The recheck runs UNDER the registry lock,
    // serialized against the installer's `sever_matching`; it evaluates the FULL D8 predicate via
    // `should_sever_now(eid, roster_user)` — closing BOTH halves of rule 6: a newly-revoked endpoint
    // AND a previously-roster-resolved endpoint now absent from the installed roster (the
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
        tracing::debug!("refused newly-severed peer at check-register (D8 race close, QUIC 401)");
        return;
    };
    // 2. Sessions: one bi-stream each; a connection may carry several
    //    (§7.2). `accept_bi()` yields `(send, recv)`.
    // M2: per-service concurrency cap (semaphore, §6.2) + rate limit
    //     (-32053, §7.3) attach here.
    while let Ok((send, recv)) = conn.accept_bi().await {
        let services = services.clone();
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = run_session(recv, send, &identity, &services).await {
                tracing::warn!(peer = %identity.name, %e, "session ended with error");
            }
        });
    }
}

/// Does this service's `allow` list admit the resolved caller? The flat authorization namespace
/// (spec §5): a petname (`identity.name`), a roster user_id, or a group name. Extracted so the
/// exact predicate `run_session` uses is unit-testable (and its arms can be added test-first).
///
/// The expansion itself is THE shared `mcpmesh_local_api::principal_set` (D1 unification) — the
/// same implementation the plugin seam's `peer_audiences` and the blob-scope gate use, so the
/// three §5 enforcement sites cannot drift.
fn caller_admits(identity: &PeerIdentity, allow: &[String]) -> bool {
    let principals = mcpmesh_local_api::principal_set(
        Some(&identity.name),
        identity.user_id.as_deref(),
        &identity.groups,
    );
    allow.iter().any(|a| principals.contains(a.as_str()))
}

/// Drive one accepted session: enforce framing on the first frame, select a
/// service, then attach the backend or refuse.
async fn run_session(
    recv: iroh::endpoint::RecvStream,
    send: iroh::endpoint::SendStream,
    // Peer identity is resolved by the gate and threaded here: M2a matches it
    // against each service's `allow` to compute `caller_allowed` (below); M2's
    // `_meta["mcpmesh/peer"]` injection (spec §6.3) reads it too.
    identity: &PeerIdentity,
    services: &Services,
) -> anyhow::Result<()> {
    let mut transport = SessionTransport::new(recv, send, MAX_FRAME_BYTES);
    let mut strikes = Strikes::default();

    // The first frame the session reads is treated as `initialize` (§7.2 step 4).
    // Pre-initialize framing violations are synthesized + struck inside
    // `recv_frame` (the single site); an EOF, a transport teardown, or a
    // strike-out all end the session cleanly.
    let Some(mut init) = recv_frame(&mut transport, &mut strikes).await else {
        return Ok(());
    };

    // caller_allowed = services whose `allow` admits this resolved identity (spec §5:
    // the flat allow namespace is petnames, user_ids, and group names). `caller_admits`
    // checks all three arms: petname (`identity.name`), roster user_id (`identity.user_id`,
    // None in pairing mode), and group. The user_id arm is now ACTIVE (M3a T7) — a roster
    // caller named only by its user_id is admitted. The flat-namespace disjointness (roster
    // rule 5, T3) guarantees a group and a user_id never collide, so checking all three is safe.
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
            // baked into the shared backend — it drives the backend's env/`_meta`
            // injection (spec §6.3). M2a always has a resolved identity post-gate.
            backend.run(Some(identity.clone()), init, transport).await
        }
        ServiceDecision::Refuse => {
            // Unknown or unauthorized — identical wording either way (spec §5).
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
            // the write half closes (Task 10 seam note — a bare drop abandons
            // buffered data).
            let _ = transport.shutdown().await;
            Ok(())
        }
    }
}

/// Read the next MCP frame, enforcing the framing-violation protocol (spec §7.3).
///
/// THE single site (Task 8 seam note) that synthesizes framing-violation errors
/// and registers strikes. A violated frame carries no recoverable request id, so
/// the error `id` is `null`; the code is `-32051` for an oversized frame and
/// `-32700` for a non-JSON frame, both marked `data.source: "mcpmesh"`. A strike is
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
            // A transport IO error is a clean teardown (Task 10 seam note): the
            // peer is gone, so there is nothing to synthesize back.
            Err(RecvError::Io(_)) => return None,
            Err(RecvError::Violation(v)) => {
                let (code, message) = match v {
                    Violation::TooLarge => (ERR_FRAMING, "frame exceeds max_frame_bytes"),
                    Violation::InvalidJson => (ERR_PARSE, "frame is not valid JSON"),
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
/// transport. The caller writes the `initialize` frame naming the service in the
/// params `_meta["mcpmesh/service"]` (spec §7.2); the server strips the reserved key
/// before any backend sees it (§6.3). `service` is accepted here only to name the
/// dial in errors/traces — the caller already holds it. `open_bi()` yields
/// `(send, recv)`.
pub async fn connect(
    endpoint: &iroh::Endpoint,
    peer: iroh::EndpointAddr,
    service: &str,
) -> anyhow::Result<SessionTransport> {
    tracing::debug!(service, "dialing mesh service");
    let conn = endpoint.connect(peer, ALPN_MCP).await?;
    let (send, recv) = conn.open_bi().await?;
    Ok(SessionTransport::new(recv, send, MAX_FRAME_BYTES))
}

#[cfg(test)]
mod tests {
    //! Directly exercise the §7.3 synthesis+strike path over an in-memory
    //! `duplex` (no iroh setup): a violation draws a synthesized error on the
    //! wire (right code, id: null, `data.source: "mcpmesh"`), each violation
    //! strikes, and the third strike shuts the write half down (StrikeOutcome::
    //! Close). This is the session-layer half of the M1 AC that the framing/
    //! transport unit tests only cover as primitives.
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, duplex, split};

    use super::*;
    use crate::framing::{FrameReader, Inbound};

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

    /// `caller_admits` implements the §5 flat namespace: petname (name) OR user_id OR group. This
    /// calls the PRODUCTION function so activating the user_id arm is a real red→green change.
    #[test]
    fn caller_admits_by_petname_user_id_or_group() {
        let allow = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // A roster identity: name == user_id == "alice", groups team-eng+all.
        let roster = PeerIdentity {
            endpoint: [0u8; 32],
            name: "alice".into(),
            user_id: Some("alice".into()),
            groups: vec!["team-eng".into(), "all".into()],
        };
        assert!(
            caller_admits(&roster, &allow(&["alice"])),
            "user_id/name arm"
        );
        assert!(
            caller_admits(&roster, &allow(&["team-eng"])),
            "group arm (the AC's group allow)"
        );
        assert!(
            !caller_admits(&roster, &allow(&["bob"])),
            "unrelated name refused"
        );

        // The load-bearing case: name != user_id proves the user_id arm is REQUIRED (name alone
        // would not admit "alice"). Against the CURRENT (name-OR-groups) predicate this FAILS.
        let by_uid_only = PeerIdentity {
            endpoint: [0u8; 32],
            name: "device-label".into(),
            user_id: Some("alice".into()),
            groups: vec![],
        };
        assert!(
            caller_admits(&by_uid_only, &allow(&["alice"])),
            "user_id arm admits independent of name"
        );

        // A pairing identity (user_id None) is admitted only by its petname/groups.
        let pairing = PeerIdentity {
            endpoint: [0u8; 32],
            name: "bob".into(),
            user_id: None,
            groups: vec![],
        };
        assert!(caller_admits(&pairing, &allow(&["bob"])));
        assert!(
            !caller_admits(&pairing, &allow(&["alice"])),
            "pairing peer has no user_id to match"
        );
    }
}
