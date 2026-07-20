//! The daemon's OUTBOUND dial machinery plus the session pipe: petname/person →
//! endpoint resolution, the staggered person→device race, the explicit dial timeout, and the
//! control↔mesh byte pipe with its service-name injection. Split out of `daemon.rs`
//! mechanically — no API change; `daemon` re-exports the public entry points.
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::{SessionTransport, connect};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::MeshState;

/// Resolve `peer` to a session over the mesh, preferring the roster PERSON→DEVICE path
/// and falling back to the single-petname path.
///
/// **Person→device (roster mode).** When `peer` names a roster USER that has active devices
/// (`mesh.roster.view().devices_for_user(peer)` non-empty), its devices are dialed as a STAGGERED
/// RACE ([`race_dial`]) ordered primary→mirror, then re-ordered WITHIN each role by presence recency
/// — see `order_dial_candidates`. Three safety invariants hold here (DECLARED):
///  - **Presence is ADVISORY — absence NEVER removes a candidate.** Recency only RE-ORDERS candidates
///    within a role; a device with NO presence entry is still dialed (just later in its role group).
///    If the person publishes no presence at all, ALL its devices are dialed in primary→mirror order.
///    (Rationale: presence is suppressible by an attacker; if absence removed a candidate, suppressing
///    presence would deny service.)
///  - **Revoked devices are NEVER candidates.** `devices_for_user` returns only ACTIVE endpoints
///    (revoked ones were excluded at `build_view`), so a revoked device can never be raced to.
///  - **Each candidate is authenticated by endpoint_id = pubkey.** A candidate endpoint_id IS an
///    ed25519 public key; `net::connect` establishes a QUIC/TLS session to the holder of that key, so
///    a racing candidate cannot be MITM'd — we reach the actual device or the dial fails. The peer's
///    own gate still authorizes us on their side; racing adds NO new trust decision on our side beyond
///    "this endpoint is an active roster device of the named user."
///
/// **Single-petname fallback.** Otherwise resolve the petname to its endpoint_id via the
/// allowlist store, build an id-only [`iroh::EndpointAddr`], and dial — iroh's discovery (DNS/pkarr
/// under the N0 preset) resolves addresses FROM the id. On LOCALHOST tests the connecting endpoint is
/// seeded via a `MemoryLookup` on `endpoint.address_lookup()`, so the SAME id-only dial resolves
/// locally. The (blocking) redb read runs on `spawn_blocking` (never redb IO on a runtime worker).
pub async fn dial_service(
    mesh: &Arc<MeshState>,
    peer: &str,
    service: &str,
) -> Result<SessionTransport> {
    // Person→device: `peer` names a roster user with active devices → staggered race.
    if let Some(view) = mesh.roster.view() {
        let devices = view.devices_for_user(peer);
        if !devices.is_empty() {
            let candidates = order_dial_candidates(&devices, &mesh.presence_table, peer);
            return race_dial(&mesh.endpoint, candidates, service)
                .await
                .with_context(|| format!("dial {peer}/{service}"));
        }
    }
    // Single-petname fallback: resolve the allowlist petname → endpoint_id → dial-by-id.
    let peer_owned = peer.to_string();
    let store = mesh.store.clone();
    let id_bytes = tokio::task::spawn_blocking(move || store.endpoint_id_for(&peer_owned))
        .await
        .context("join peer resolve")??
        .with_context(|| format!("peer '{peer}' is not in the allowlist"))?;
    let endpoint_id = iroh::EndpointId::from_bytes(&id_bytes)
        .map_err(|e| anyhow::anyhow!("stored endpoint id for '{peer}' is invalid: {e}"))?;
    // Dial by id: an address-less EndpointAddr that discovery resolves.
    let addr = iroh::EndpointAddr::from(endpoint_id);
    connect_with_timeout(&mesh.endpoint, addr, service, DIAL_TIMEOUT)
        .await
        .with_context(|| format!("dial {peer}/{service}"))
}

/// The person→device dial STAGGER: a live candidate is not blocked waiting on a
/// dead/stalling one — the next candidate joins the race this long after the previous.
const DIAL_STAGGER: Duration = Duration::from_millis(500);

/// The explicit application-level dial timeout. Defense-in-depth over iroh's
/// transport idle timeouts — SYMMETRIC across both dial paths (the person→device race AND the
/// single-petname fallback) so a dead/stalling peer fails a dial in a bounded, asserted window.
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// `connect` with an explicit timeout. On elapse → a typed Err (the caller surfaces
/// `-32055 unreachable` upstream). Used by BOTH `dial_one` and the single-petname `dial_service`.
pub(crate) async fn connect_with_timeout(
    endpoint: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
    service: &str,
    timeout: Duration,
) -> Result<SessionTransport> {
    match tokio::time::timeout(timeout, connect(endpoint, addr, service)).await {
        // A typed ConnectError (dial vs open-stream) converts into the anyhow chain.
        Ok(r) => r.map_err(Into::into),
        Err(_) => anyhow::bail!("dial timed out after {timeout:?}"),
    }
}

/// Order a person's active devices into the dial-candidate sequence. `devices` is the
/// roster order from [`RosterView::devices_for_user`] (primary→mirror, deterministic within role);
/// this RE-ORDERS candidates WITHIN each role by presence recency (most-recent first). Presence is
/// ADVISORY: a device with NO presence entry keeps its roster position AFTER the present ones in its
/// role group — it is never dropped (absence never removes a candidate). The role grouping
/// (primary→mirror) is preserved regardless of presence, so a freshly-seen mirror never jumps ahead
/// of a primary.
///
/// [`RosterView::devices_for_user`]: mcpmesh_trust::roster::validate::RosterView::devices_for_user
fn order_dial_candidates(
    devices: &[([u8; 32], String)],
    presence: &crate::roster::presence::PresenceTable,
    user_id: &str,
) -> Vec<[u8; 32]> {
    // Recency rank: a device's position in the presence table's most-recent-first list. Devices with
    // NO entry get a rank AFTER every present one (`usize::MAX`), so they stay candidates but sort last
    // WITHIN their role — presence never removes a candidate, only reorders.
    let by_recency = presence.endpoints_for_user_by_recency(user_id);
    let recency_rank = |eid: &[u8; 32]| -> usize {
        by_recency
            .iter()
            .position(|e| e == eid)
            .unwrap_or(usize::MAX)
    };
    let mut ordered: Vec<([u8; 32], String)> = devices.to_vec();
    // Stable sort on (role rank, recency rank): role grouping wins (primary→mirror), recency orders
    // within a role, and equal keys (same role, both absent from presence) keep the deterministic
    // roster order `devices_for_user` already imposed.
    ordered.sort_by_key(|(eid, role)| (dial_role_rank(role), recency_rank(eid)));
    ordered.into_iter().map(|(eid, _)| eid).collect()
}

/// Dial-candidate role rank mirroring `trust`'s `role_rank` (primary→mirror→other). Duplicated across
/// the crate seam deliberately: `devices_for_user` already emits roster order, but the presence
/// re-order here must re-assert the primary→mirror grouping so recency cannot lift a mirror above a
/// primary. Kept tiny; `pub(crate)` only for the `presence_peers` display sort in `daemon`.
pub(crate) fn dial_role_rank(role: &str) -> u8 {
    match role {
        "primary" => 0,
        "mirror" => 1,
        _ => 2,
    }
}

/// Staggered-race dial. Dials `candidates` in order, launching the next one
/// `DIAL_STAGGER` (500 ms) after the previous if no session has won yet — OR immediately if the
/// in-flight dials have all already failed (a fast-failing candidate doesn't impose the full 500 ms
/// wait). The FIRST [`connect`] success WINS: its transport is returned and the in-flight losing
/// dials are CANCELLED — dropping the [`JoinSet`] aborts its remaining tasks (their `connect` futures
/// are dropped at the next await point — no lingering tasks or half-open connections). If EVERY
/// candidate fails, the last error is returned (the race never hangs). An empty candidate list is an
/// immediate Err.
///
/// The stagger is why a live candidate is not blocked on a dead/stalling one: a stalled primary keeps
/// its dial in flight while the mirror is launched at 500 ms and can win. Correctness rests on
/// `connect` being cancellation-safe on abort (iroh's `Endpoint::connect` future holds no external
/// state that must be torn down explicitly — aborting it abandons the in-progress handshake).
///
/// **DECLARED — `JoinSet`, not `FuturesUnordered`.** The plan sketched `FuturesUnordered`; this uses
/// tokio's native [`JoinSet`] instead — same concurrent-unordered-race semantics (first-wins, drop
/// cancels the losers) but with NO new crate dependency. Pulling `futures-util` in as a direct dep
/// measurably enlarged the daemon binary and added ~0.5 s to cold startup under the parallel-spawn
/// integration tests (a pre-existing 3 s-bound test flipped to failing). `JoinSet` is already in the
/// tree via tokio's `rt`, keeps startup unchanged, and spawns each racer as a real task (so a stalled
/// dial makes progress on a runtime worker rather than only when this future is polled).
///
/// [`JoinSet`]: tokio::task::JoinSet
pub async fn race_dial(
    endpoint: &iroh::Endpoint,
    candidates: Vec<[u8; 32]>,
    service: &str,
) -> Result<SessionTransport> {
    anyhow::ensure!(!candidates.is_empty(), "no dial candidates to race");

    // Each racer is a 'static task, so it owns a cloned endpoint + service (iroh::Endpoint is a cheap
    // Arc-backed clone). Dropping the set on return ABORTS every still-running racer — the loser cancel.
    let mut set: tokio::task::JoinSet<Result<SessionTransport>> = tokio::task::JoinSet::new();
    let spawn_dial = |set: &mut tokio::task::JoinSet<Result<SessionTransport>>, eid: [u8; 32]| {
        let ep = endpoint.clone();
        let svc = service.to_string();
        set.spawn(async move { dial_one(&ep, eid, &svc).await });
    };

    let mut next = 0usize; // index of the next candidate to launch
    spawn_dial(&mut set, candidates[next]); // candidate 0 immediately
    next += 1;
    let mut last_err: Option<anyhow::Error> = None;

    loop {
        if next < candidates.len() {
            // A candidate is still waiting: race the in-flight dials against the 500 ms stagger.
            // `biased` polls the join first so a ready success/failure is handled before the timer,
            // and an EMPTY set (all in-flight already failed) yields `None` immediately → launch next.
            tokio::select! {
                biased;
                joined = set.join_next() => match joined {
                    Some(Ok(Ok(t))) => return Ok(t), // first success wins; drop `set` → abort the rest
                    Some(Ok(Err(e))) => last_err = Some(e), // this candidate's dial failed; keep racing
                    Some(Err(e)) => last_err = Some(anyhow::anyhow!("dial task join error: {e}")),
                    None => {
                        // Every in-flight dial failed before the stagger: launch the next NOW.
                        spawn_dial(&mut set, candidates[next]);
                        next += 1;
                    }
                },
                () = tokio::time::sleep(DIAL_STAGGER) => {
                    // No winner within the stagger window → add the next candidate to the race.
                    spawn_dial(&mut set, candidates[next]);
                    next += 1;
                }
            }
        } else {
            // No more candidates to launch: await whatever dials remain in flight.
            match set.join_next().await {
                Some(Ok(Ok(t))) => return Ok(t),
                Some(Ok(Err(e))) => last_err = Some(e),
                Some(Err(e)) => last_err = Some(anyhow::anyhow!("dial task join error: {e}")),
                None => {
                    return Err(
                        last_err.unwrap_or_else(|| anyhow::anyhow!("all dial candidates failed"))
                    );
                }
            }
        }
    }
}

/// Dial ONE roster device endpoint over the mesh.
/// The endpoint_id IS the device's ed25519 pubkey, so `connect` reaches the holder of that key or
/// fails — no MITM among racers. An id-only [`iroh::EndpointAddr`] lets discovery (or the localhost
/// `MemoryLookup`) resolve the address.
async fn dial_one(
    endpoint: &iroh::Endpoint,
    eid: [u8; 32],
    service: &str,
) -> Result<SessionTransport> {
    let endpoint_id = iroh::EndpointId::from_bytes(&eid)
        .map_err(|e| anyhow::anyhow!("roster device endpoint id is invalid: {e}"))?;
    let addr = iroh::EndpointAddr::from(endpoint_id);
    connect_with_timeout(endpoint, addr, service, DIAL_TIMEOUT).await
}

/// Pipe an established mesh session to/from the control connection. The FIRST
/// control frame — the AI client's `initialize` — is augmented with the reserved
/// `_meta["mcpmesh/service"]` naming the service (the SINGLE enumerated exception to
/// verbatim pass-through) before it is forwarded to the peer, so the far side's
/// `select_service` can route it. Then frames flow both directions verbatim until either
/// side ends. The two directions run as independent concurrent loops (one codec) — the same
/// anti-deadlock discipline as `backends::pump`; this is a sibling
/// of that pump, not a reuse, because the mesh side here is an owned [`SessionTransport`]
/// (not raw streams) and the service-name injection has no analogue there.
pub async fn pipe_session<CR, CW>(
    mut transport: SessionTransport,
    service: &str,
    mut control_reader: FrameReader<CR>,
    mut control_writer: CW,
) -> Result<()>
where
    CR: AsyncRead + Unpin + Send,
    CW: AsyncWrite + Unpin + Send,
{
    // 1. First control frame = the AI client's initialize. A clean EOF or a framing violation
    //    before it means there is no session to carry — end cleanly.
    let init = match control_reader.next().await? {
        Some(Inbound::Frame(v)) => inject_service(v, service),
        Some(Inbound::Violation(_)) | None => return Ok(()),
    };
    transport
        .send_value(init)
        .await
        .context("forward initialize to peer")?;

    // The outbound direction sends through a cloned writer handle (Arc) so it does not need
    // `&mut transport`, which the inbound direction holds for `recv_value` — the disjoint
    // split that lets the two loops run concurrently without a shared mutable borrow.
    let transport_writer = transport.writer();

    // Direction A: control (AI client via the proxy) -> mesh peer.
    let to_mesh = async {
        loop {
            match control_reader.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    if transport_writer.send_value(frame).await.is_err() {
                        break; // peer is gone
                    }
                }
                Ok(Some(Inbound::Violation(_))) => break,
                Ok(None) | Err(_) => break, // proxy closed / IO error
            }
        }
        // The proxy half-closed (its AI client sent everything it will send) — that ends the
        // REQUEST direction, never the session. Half-close toward the peer so its backend sees
        // a clean end-of-input, then park: only the peer closing (`to_control` ending) may tear
        // the session down, mirroring the proxy pump's drain discipline. Winning the select!
        // here would cancel `to_control` and drop responses still in flight — the one-shot
        // pipe case (`printf ... | mcpmesh connect ...`) hits exactly that race.
        let _ = transport_writer.shutdown().await;
        std::future::pending::<()>().await
    };
    // Direction B: mesh peer -> control. Carries the peer's responses AND any synthesized
    // -32054 refusal, verbatim. The `while let` exits on peer EOF / a severed
    // session / a framing violation (all `recv_value` non-`Ok(Some)` outcomes).
    let to_control = async {
        while let Ok(Some(frame)) = transport.recv_value().await {
            if write_frame(&mut control_writer, &frame).await.is_err() {
                break; // proxy is gone
            }
        }
    };
    tokio::select! {
        () = to_mesh => {}
        () = to_control => {}
    }
    // Orderly teardown on BOTH halves (backends::pump discipline — "a bare drop abandons
    // data"): flush any final buffered frame before each write half closes. Benign in
    // practice (write_frame flushes each frame), but symmetric and future-proof.
    let _ = transport.shutdown().await;
    let _ = control_writer.shutdown().await;
    Ok(())
}

/// Set `params._meta["mcpmesh/service"] = service` on the `initialize` frame, creating `params`
/// and `_meta` as objects if absent and REPLACING a non-object `_meta` (never merging — the
/// rule for the reserved-key injector). This is the one edit the otherwise
/// verbatim proxy path makes to a frame. A non-object frame is forwarded untouched —
/// the platform does not interpret MCP semantics; the far side rejects it.
fn inject_service(mut frame: Value, service: &str) -> Value {
    let Some(obj) = frame.as_object_mut() else {
        return frame;
    };
    let params = obj
        .entry("params")
        .or_insert_with(|| Value::Object(Default::default()));
    if !params.is_object() {
        *params = Value::Object(Default::default());
    }
    let params = params.as_object_mut().expect("params set to object above");
    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(Default::default()));
    if !meta.is_object() {
        *meta = Value::Object(Default::default()); // REPLACE a non-object _meta (§6.3)
    }
    meta.as_object_mut()
        .expect("meta set to object above")
        .insert("mcpmesh/service".into(), Value::String(service.to_string()));
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `inject_service` sets `params._meta["mcpmesh/service"]`, creating/replacing a non-object
    /// `params`/`_meta` and leaving a non-object frame untouched.
    #[test]
    fn inject_service_sets_meta_across_shapes() {
        use serde_json::json;
        // Object frame with no params → params._meta.mcpmesh/service is created; other keys kept.
        let f = inject_service(json!({"method": "initialize"}), "kb");
        assert_eq!(f["params"]["_meta"]["mcpmesh/service"], "kb");
        assert_eq!(f["method"], "initialize");
        // Existing params object is preserved; _meta is added.
        let f = inject_service(json!({"params": {"x": 1}}), "loc");
        assert_eq!(f["params"]["x"], 1);
        assert_eq!(f["params"]["_meta"]["mcpmesh/service"], "loc");
        // A non-object `params` is REPLACED with an object.
        let f = inject_service(json!({"params": 7}), "kb");
        assert_eq!(f["params"]["_meta"]["mcpmesh/service"], "kb");
        // A non-object `_meta` is REPLACED (never merged into a scalar).
        let f = inject_service(json!({"params": {"_meta": "nope"}}), "kb");
        assert_eq!(f["params"]["_meta"]["mcpmesh/service"], "kb");
        // A non-object frame is returned unchanged.
        assert_eq!(inject_service(json!("scalar"), "kb"), json!("scalar"));
    }

    /// Pins `pipe_session`'s TEARDOWN DISCIPLINE (issue #25): control-side EOF ends only
    /// the REQUEST direction — it half-closes toward the peer (`TransportWriter::shutdown`)
    /// and PARKS, and the session ends solely when the peer closes. The pre-fix `select!`
    /// let the control direction's completion cancel the mesh→control drain, resetting the
    /// stream before the response (sometimes before the request itself) crossed the wire —
    /// the one-shot pipe shape. The control side is in-memory duplex; the mesh side is a
    /// REAL localhost iroh pair, because `SessionTransport` is concretely iroh-typed (an
    /// honest subset: the fake peer echoes raw frames — no gate, no backend; the full
    /// daemon-to-daemon path is `one_shot_connect.rs`). The peer deliberately withholds
    /// its echo until it sees the dialer's half-close, so a `pipe_session` that tears down
    /// on control EOF can never pass.
    #[tokio::test(flavor = "multi_thread")]
    async fn pipe_session_delivers_the_echo_after_control_eof() {
        use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
        use serde_json::json;
        use tokio::io::duplex;

        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            // The fake peer: a localhost accept side that collects frames until the
            // dialer's half-close (recv EOF), THEN echoes them back and closes.
            let server_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
                .bind()
                .await
                .unwrap();
            let server_addr = server_ep.addr();
            // Holds the peer's connection open until the dialer has DRAINED the echo:
            // `shutdown` only queues the FIN, and dropping the Connection/Endpoint right
            // behind it sends CONNECTION_CLOSE, which discards the buffered echo — the
            // test would then hang on transport loss instead of exercising the drain.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let peer = tokio::spawn(async move {
                let incoming = server_ep.accept().await.expect("one inbound connection");
                let conn = incoming.await.expect("handshake");
                // `accept_bi` fires only once the dialer's first frame flushes — pre-fix,
                // the cancelled drain could reset the stream before even that.
                let (send, recv) = conn.accept_bi().await.expect("session bi-stream");
                let mut t = mcpmesh_net::SessionTransport::new(recv, send, 1024 * 1024);
                let mut seen = Vec::new();
                // Ok(None) = the dialer's clean half-close (its write half finished
                // while its read half stays open — the shutdown() under test).
                while let Ok(Some(f)) = t.recv_value().await {
                    seen.push(f);
                }
                for f in &seen {
                    t.send_value(f.clone()).await.unwrap();
                }
                t.shutdown().await.unwrap(); // finish the stream: the drain's clean end
                let _ = done_rx.await; // keep conn + endpoint alive until the test is done
                seen
            });

            let client_ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .relay_mode(iroh::RelayMode::Disabled)
                .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
                .bind()
                .await
                .unwrap();
            let transport = connect(&client_ep, server_addr, "echo").await.unwrap();

            // Control side, one whole DuplexStream per direction (dropping `ctl_in_w`
            // is the control-side EOF; a split half would keep the stream alive).
            let (mut ctl_in_w, ctl_in_r) = duplex(64 * 1024);
            let (ctl_out_w, ctl_out_test_r) = duplex(64 * 1024);
            let init = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
            write_frame(&mut ctl_in_w, &init).await.unwrap();
            drop(ctl_in_w);

            let session = tokio::spawn(pipe_session(
                transport,
                "echo",
                FrameReader::new(ctl_in_r, 1024 * 1024),
                ctl_out_w,
            ));

            // The echo must reach the control writer BEFORE teardown: the peer only sent
            // it after our half-close, so a request-direction-wins teardown drops it.
            let mut ctl_out = FrameReader::new(ctl_out_test_r, 1024 * 1024);
            match ctl_out.next().await.unwrap() {
                Some(Inbound::Frame(f)) => {
                    assert_eq!(f["id"], 1, "the echoed initialize answers our id: {f}");
                    assert_eq!(
                        f["params"]["_meta"]["mcpmesh/service"], "echo",
                        "the peer saw the service-injected initialize (the one enumerated \
                         edit), echoed verbatim: {f}"
                    );
                }
                other => panic!("the echo must reach the control side, got {other:?}"),
            }
            assert!(
                ctl_out.next().await.unwrap().is_none(),
                "the peer closing ends the session cleanly (control-side EOF)"
            );
            session.await.unwrap().expect("pipe_session returns Ok");
            let _ = done_tx.send(()); // release the peer's hold-open
            assert_eq!(
                peer.await.unwrap(),
                vec![inject_service(init, "echo")],
                "the peer received exactly the injected initialize before the half-close"
            );
        })
        .await
        .expect("pipe_session drain test timed out");
    }

    #[tokio::test]
    async fn connect_with_timeout_fails_fast_on_an_unreachable_peer() {
        // A relay-disabled localhost endpoint dialing a random, unresolved id can never connect; the
        // explicit timeout must return Err WELL before iroh's own idle timeouts (defense-in-depth).
        let ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .alpns(vec![mcpmesh_net::ALPN_MCP.to_vec()])
            .bind()
            .await
            .unwrap();
        let dead = iroh::EndpointAddr::from(iroh::EndpointId::from_bytes(&[3u8; 32]).unwrap());
        let start = std::time::Instant::now();
        let r =
            super::connect_with_timeout(&ep, dead, "svc", std::time::Duration::from_millis(300))
                .await;
        assert!(r.is_err(), "an unreachable dial times out to Err");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "the explicit timeout fired fast"
        );
    }
}
