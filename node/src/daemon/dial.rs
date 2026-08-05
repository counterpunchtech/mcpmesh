//! The daemon's OUTBOUND dial machinery plus the session pipe: nickname/person →
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
use crate::allowlist::PeerEntry;

/// Resolve `peer` to a session over the mesh, preferring the roster PERSON→DEVICE path
/// and falling back to the single-nickname path.
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
/// **Single-nickname fallback.** Otherwise resolve the nickname to its stored [`PeerEntry`] via the
/// allowlist store and dial an [`iroh::EndpointAddr`] carrying the entry's pairing-persisted
/// `last_addr` hint when usable (`stored_dial_addr`) — else id-only. iroh merges provided direct
/// addrs with what discovery (DNS/pkarr under the N0 preset) resolves FROM the id, so the hint makes
/// a COLD daemon able to reach a paired peer even with discovery disabled (issue #27) without ever
/// narrowing the discovery path. On LOCALHOST tests the connecting endpoint is
/// seeded via a `MemoryLookup` on `endpoint.address_lookup()`, so the same dial resolves
/// locally. The (blocking) redb read runs on `spawn_blocking` (never redb IO on a runtime worker).
///
/// [`PeerEntry`]: crate::allowlist::PeerEntry
pub async fn dial_service(
    mesh: &Arc<MeshState>,
    peer: &str,
    service: &str,
) -> Result<SessionTransport> {
    // #41: an explicit `eid:<hex>` DEVICE principal dials that EXACT authenticated endpoint —
    // the one the socket backend injects into `_meta` and the allow lists use. No nickname
    // ambiguity (nicknames are not unique), no person→device race: it targets one device
    // precisely, which is the whole point of dialing the verified caller back. Resolved FIRST.
    if let Some(hex) = peer.strip_prefix("eid:") {
        return dial_by_eid(mesh, hex, service).await;
    }

    // Person→device: `peer` names a roster user with active devices → staggered race.
    if let Some(view) = mesh.roster.view() {
        let devices = view.devices_for_user(peer);
        if !devices.is_empty() {
            let candidates = order_dial_candidates(&devices, &mesh.presence_table, peer);
            // #186: a rostered device often ALSO has a paired row, and its hint is the only address
            // anyone has on a network with no discovery.
            let candidates = hinted_addrs(mesh, candidates).await?;
            let (transport, conn) = race_dial(&mesh.endpoint, candidates, service)
                .await
                .with_context(|| format!("dial {peer}/{service}"))?;
            return Ok(watch_session(mesh, transport, conn));
        }
    }
    // Pairing-mode fallback. `peer` is resolved to stored entries by, in order:
    //  1. a NICKNAME match (the redeemer's local name for the peer), then
    //  2. a stable `user_id` match (#30: dial by the peer's self-sovereign `b64u:` identity, so a
    //     caller can address it by an id it aligns with its own — symmetric with the `user_id`
    //     already attested INBOUND on `_meta`). A user_id can match several devices of one person;
    //     those are raced exactly like the roster person→device path.
    // A single resolved entry is dialed WITH its pairing-persisted `last_addr` hint (issue #27: a
    // cold daemon must not depend on external discovery to reach a paired peer).
    let peer_owned = peer.to_string();
    let store = mesh.store.clone();
    let (single, multi): (Option<PeerEntry>, Vec<[u8; 32]>) =
        tokio::task::spawn_blocking(move || -> Result<_> {
            if let Some(e) = store.entry_for(&peer_owned)? {
                return Ok((Some(e), Vec::new()));
            }
            let mut by_user = store.entries_for_user(&peer_owned)?;
            match by_user.len() {
                0 => Ok((None, Vec::new())),
                1 => Ok((by_user.pop(), Vec::new())),
                _ => Ok((None, by_user.iter().map(|e| e.endpoint_id).collect())),
            }
        })
        .await
        .context("join peer resolve")??;

    // Several devices share the resolved user_id → race them (bare-id, discovery-resolved),
    // mirroring the roster person→device path.
    if !multi.is_empty() {
        // #186: these came from `entries_for_user`, so the hints were literally in hand and the
        // old code kept only the ids — making a two-device person unreachable offline while a
        // one-device person was fine.
        let multi = hinted_addrs(mesh, multi).await?;
        let (transport, conn) = race_dial(&mesh.endpoint, multi, service)
            .await
            .with_context(|| format!("dial {peer}/{service}"))?;
        return Ok(watch_session(mesh, transport, conn));
    }
    let entry = single.with_context(|| format!("peer '{peer}' is not in the allowlist"))?;
    let endpoint_id = iroh::EndpointId::from_bytes(&entry.endpoint_id)
        .map_err(|e| anyhow::anyhow!("stored endpoint id for '{peer}' is invalid: {e}"))?;
    let addr = stored_dial_addr(entry.last_addr.as_deref(), endpoint_id);
    let (transport, conn) = connect_with_timeout(&mesh.endpoint, addr, service, DIAL_TIMEOUT)
        .await
        .with_context(|| format!("dial {peer}/{service}"))?;
    Ok(watch_session(mesh, transport, conn))
}

/// Attach the #92 item 2 path watcher to an OUTBOUND session and hand back the transport.
///
/// The peer id comes from the CONNECTION (`remote_id`), not from the caller's bookkeeping: the
/// racing dial does not tell its caller which candidate won, and the connection is the only thing
/// that knows for certain who is on the other end.
///
/// This is the seam that makes #92 item 2 real. Watching only the accept path would cover sessions
/// others open to us and miss every session WE open — and the reported use case is an embedder
/// rendering a privacy indicator for a call it initiated.
fn watch_session(
    mesh: &Arc<MeshState>,
    transport: SessionTransport,
    conn: iroh::endpoint::Connection,
) -> SessionTransport {
    drop(super::path_watch::spawn(
        mesh.clone(),
        *conn.remote_id().as_bytes(),
        &conn,
    ));
    transport
}

/// Dial an EXACT endpoint named by its `eid:<hex>` device principal (#41). Decodes the 64-hex
/// endpoint id, attaches the pairing-persisted `last_addr` hint when a stored [`PeerEntry`] is
/// present at that id (cold-dial reachability, issue #27), else a bare-id discovery dial. The
/// peer's own gate remains the security boundary — dialing is outbound and authorizes nothing
/// on our side. An invalid hex / wrong length is a clear resolution error, never a panic.
async fn dial_by_eid(mesh: &Arc<MeshState>, hex: &str, service: &str) -> Result<SessionTransport> {
    let bytes = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid eid principal: not lowercase hex"))?;
    let endpoint_id_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid eid principal: expected 32 bytes (64 hex chars)"))?;
    let endpoint_id = iroh::EndpointId::from_bytes(&endpoint_id_bytes)
        .map_err(|e| anyhow::anyhow!("invalid eid principal: {e}"))?;
    // Best-effort last_addr hint from a stored peer at this exact endpoint (blocking redb read
    // on the blocking pool). An unknown eid still dials bare-id via discovery.
    let store = mesh.store.clone();
    let last_addr = tokio::task::spawn_blocking(move || store.resolve(&endpoint_id_bytes))
        .await
        .context("join eid peer resolve")?
        .ok()
        .flatten()
        .and_then(|e| e.last_addr);
    let addr = stored_dial_addr(last_addr.as_deref(), endpoint_id);
    let (transport, conn) = connect_with_timeout(&mesh.endpoint, addr, service, DIAL_TIMEOUT)
        .await
        .with_context(|| format!("dial eid:{hex}/{service}"))?;
    Ok(watch_session(mesh, transport, conn))
}

/// Assemble the single-nickname dial [`iroh::EndpointAddr`]: the stored `endpoint_id` plus,
/// when it is usable, the pairing-persisted `last_addr` hint (iroh merges provided direct
/// addrs with whatever discovery resolves, so attaching the hint never narrows reachability).
///
/// Addresses are dial HINTS, never identity: the hint is attached only if it parses AND its
/// embedded id EQUALS the stored `endpoint_id` — a stored address claiming a DIFFERENT id is
/// ignored (identity stays pinned to the allowlist row; TLS still authenticates whoever
/// answers). An unparseable/absent hint degrades to the bare-id, discovery-only dial.
/// Every endpoint worth trying for `peer`, best first (#67) — the candidate list a custom-protocol
/// dial walks.
///
/// Resolution order mirrors what `dial_service` considers, so `connect_protocol` reaches the same
/// peers `open_session` does rather than a narrower set:
///
/// 1. An `eid:` principal names one device directly.
/// 2. ROSTER first for a bare name: `devices_for_user` already orders primary before mirror and is
///    the only path that reaches a rostered person with no pairing entry. Omitting it — the first
///    version of this function did — made `connect_protocol("alice")` fail on a roster-mode node
///    where `open_session("alice")` works.
/// 3. Then the pairing store: an exact nickname, else every device of that `user_id` (not just the
///    first, which stranded a person whose first-stored device happened to be offline).
///
/// Deduplicated, preserving order. Empty means "nobody by that name", which the caller reports.
pub(crate) async fn protocol_candidates(
    mesh: &Arc<MeshState>,
    peer: &str,
) -> anyhow::Result<Vec<[u8; 32]>> {
    if let Some(hex) = peer.strip_prefix("eid:") {
        let bytes = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .map_err(|_| anyhow::anyhow!("invalid eid principal: not lowercase hex"))?;
        let id: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid eid principal: expected 32 bytes"))?;
        return Ok(vec![id]);
    }
    let mut out: Vec<[u8; 32]> = Vec::new();
    if let Some(view) = mesh.roster.view() {
        out.extend(view.devices_for_user(peer).into_iter().map(|(eid, _)| eid));
    }
    let store = mesh.store.clone();
    let name = peer.to_string();
    let from_store = crate::util::blocking("join connect_protocol resolve", move || {
        let mut v: Vec<[u8; 32]> = Vec::new();
        if let Some(e) = store.entry_for(&name)? {
            v.push(e.endpoint_id);
        }
        v.extend(
            store
                .entries_for_user(&name)?
                .into_iter()
                .map(|e| e.endpoint_id),
        );
        Ok::<_, anyhow::Error>(v)
    })
    .await??;
    out.extend(from_store);
    let mut seen = std::collections::HashSet::new();
    out.retain(|e| seen.insert(*e));
    Ok(out)
}

/// Resolve alternate blob SOURCES to dialable addresses (#83).
///
/// Each entry is a stable principal or a paired nickname — the same vocabulary `open_session`
/// takes — expanded through [`protocol_candidates`], so naming a PERSON offers every device of
/// theirs rather than one. Each address carries the stored dial hint, exactly as a service dial
/// does, so an alternate this node has not contacted since boot is still reachable on a hermetic
/// LAN.
///
/// A name that resolves to NOBODY is an error rather than a silent skip: a caller that typed a
/// nickname wrong would otherwise watch the fetch fail on the offline publisher and never learn
/// that its fallback list was empty all along.
///
/// Order is preserved and duplicates are dropped — including a device that two named people share,
/// which would otherwise be dialled twice for one timeout each.
pub(crate) async fn blob_source_addrs(
    mesh: &Arc<MeshState>,
    from: &[String],
) -> anyhow::Result<Vec<iroh::EndpointAddr>> {
    // Bounded before any work: each name costs a store scan and each candidate a dial timeout, so
    // an unbounded list is an unbounded wait on a request holding one of the connection's in-flight
    // slots. Refused rather than truncated — silently dropping the tail would make a fetch fail
    // while the source that had the blob sat unused.
    anyhow::ensure!(
        from.len() <= mcpmesh_local_api::MAX_BLOB_SOURCES,
        "too many blob sources: {} (the cap is {})",
        from.len(),
        mcpmesh_local_api::MAX_BLOB_SOURCES
    );
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for name in from {
        let candidates = protocol_candidates(mesh, name).await?;
        anyhow::ensure!(
            !candidates.is_empty(),
            "no blob source '{name}' — it must be a paired peer, a roster member, or an \
             `eid:`/`b64u:` principal"
        );
        for eid in candidates {
            if !seen.insert(eid) {
                continue;
            }
            let Ok(id) = iroh::EndpointId::from_bytes(&eid) else {
                continue;
            };
            let store = mesh.store.clone();
            let entry =
                crate::util::blocking("join blob source resolve", move || store.resolve(&eid))
                    .await??;
            out.push(stored_dial_addr(
                entry.and_then(|e| e.last_addr).as_deref(),
                id,
            ));
        }
    }
    Ok(out)
}

pub(crate) fn stored_dial_addr(
    last_addr: Option<&str>,
    endpoint_id: iroh::EndpointId,
) -> iroh::EndpointAddr {
    if let Some(json) = last_addr
        && let Ok(addr) = serde_json::from_str::<iroh::EndpointAddr>(json)
        && addr.id == endpoint_id
    {
        return addr;
    }
    iroh::EndpointAddr::from(endpoint_id)
}

/// The person→device dial STAGGER: a live candidate is not blocked waiting on a
/// dead/stalling one — the next candidate joins the race this long after the previous.
const DIAL_STAGGER: Duration = Duration::from_millis(500);

/// The explicit application-level dial timeout. Defense-in-depth over iroh's
/// transport idle timeouts — SYMMETRIC across both dial paths (the person→device race AND the
/// single-nickname fallback) so a dead/stalling peer fails a dial in a bounded, asserted window.
pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

/// `connect` with an explicit timeout. On elapse → a typed Err (the caller surfaces
/// `-32055 unreachable` upstream). Used by BOTH `dial_one` and the single-nickname `dial_service`.
pub(crate) async fn connect_with_timeout(
    endpoint: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
    service: &str,
    timeout: Duration,
) -> Result<(SessionTransport, iroh::endpoint::Connection)> {
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
    candidates: Vec<iroh::EndpointAddr>,
    service: &str,
) -> Result<(SessionTransport, iroh::endpoint::Connection)> {
    anyhow::ensure!(!candidates.is_empty(), "no dial candidates to race");

    // Each racer is a 'static task, so it owns a cloned endpoint + service (iroh::Endpoint is a cheap
    // Arc-backed clone). Dropping the set on return ABORTS every still-running racer — the loser cancel.
    let mut set: tokio::task::JoinSet<Result<(SessionTransport, iroh::endpoint::Connection)>> =
        tokio::task::JoinSet::new();
    let spawn_dial =
        |set: &mut tokio::task::JoinSet<Result<(SessionTransport, iroh::endpoint::Connection)>>,
         addr: iroh::EndpointAddr| {
            let ep = endpoint.clone();
            let svc = service.to_string();
            set.spawn(async move { dial_one(&ep, addr, &svc).await });
        };

    let mut next = 0usize; // index of the next candidate to launch
    spawn_dial(&mut set, candidates[next].clone()); // candidate 0 immediately
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
                        spawn_dial(&mut set, candidates[next].clone());
                        next += 1;
                    }
                },
                () = tokio::time::sleep(DIAL_STAGGER) => {
                    // No winner within the stagger window → add the next candidate to the race.
                    spawn_dial(&mut set, candidates[next].clone());
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

/// Attach each candidate's stored dial hint, so a RACED dial is no more discovery-dependent than a
/// single-device one (#186).
///
/// `stored_dial_addr` validates: a hint recorded for a different id is discarded rather than
/// dialled, and a peer with no stored row degrades to a bare id — which is what every raced dial
/// used to be. So this can only ever add reachability.
///
/// One store read per candidate, on the blocking pool. A race has at most a handful of candidates
/// (one person's devices), and the read happens once per dial rather than per attempt.
async fn hinted_addrs(
    mesh: &Arc<MeshState>,
    candidates: Vec<[u8; 32]>,
) -> Result<Vec<iroh::EndpointAddr>> {
    let store = mesh.store.clone();
    crate::util::blocking("join dial-candidate hints", move || {
        let mut out = Vec::with_capacity(candidates.len());
        for eid in candidates {
            let Ok(id) = iroh::EndpointId::from_bytes(&eid) else {
                continue; // a corrupt id is skipped, not fatal — another device may work
            };
            let last = store.resolve(&eid).ok().flatten().and_then(|e| e.last_addr);
            out.push(stored_dial_addr(last.as_deref(), id));
        }
        Ok(out)
    })
    .await?
}

/// Dial ONE candidate over the mesh.
///
/// The endpoint_id inside `addr` IS the device's ed25519 pubkey, so `connect` reaches the holder of
/// that key or fails — no MITM among racers, whatever address it carries.
///
/// Takes a PREPARED address rather than a bare id (#186). It used to build
/// `EndpointAddr::from(endpoint_id)` itself, which made every raced dial discovery-only — so a
/// person's SECOND device silently made their first unreachable on a network with no discovery,
/// dropping the invariant #27 established for the single-device path three lines away. The caller
/// now attaches the stored hint, exactly as the single-device path does.
async fn dial_one(
    endpoint: &iroh::Endpoint,
    addr: iroh::EndpointAddr,
    service: &str,
) -> Result<(SessionTransport, iroh::endpoint::Connection)> {
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
mod source_tests {
    use super::blob_source_addrs;
    use crate::daemon::testutil::hermetic_mesh;

    async fn mesh_with_peers(
        dir: &std::path::Path,
        peers: &[(&str, [u8; 32], Option<&str>)],
    ) -> std::sync::Arc<crate::daemon::MeshState> {
        let cfg = dir.join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = hermetic_mesh(cfg).await;
        for (nick, eid, user) in peers {
            mesh.store
                .add(crate::allowlist::PeerEntry {
                    endpoint_id: *eid,
                    nickname: (*nick).into(),
                    services: vec![],
                    paired_at: None,
                    user_id: user.map(|u| u.to_string()),
                    last_addr: None,
                })
                .unwrap();
        }
        mesh
    }

    fn eid_of(seed: u8) -> [u8; 32] {
        *iroh::SecretKey::from_bytes(&[seed; 32]).public().as_bytes()
    }

    /// #83: every property `blob_source_addrs`' doc claims, pinned.
    ///
    /// It had NO coverage in the first cut — nothing called it outside the handler, and the
    /// acceptance test passed literal addresses, bypassing resolution entirely. Review found that
    /// `Ok(vec![])`, a deleted typo guard and a deleted dedup all survived.
    #[tokio::test(flavor = "multi_thread")]
    async fn blob_sources_resolve_dedupe_and_refuse_a_typo() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (eid_of(41), eid_of(42));
        let mesh = mesh_with_peers(
            dir.path(),
            &[("alice", a, Some("b64u:alice-key")), ("bob", b, None)],
        )
        .await;

        // A nickname resolves.
        let out = blob_source_addrs(&mesh, &["alice".into()]).await.unwrap();
        assert_eq!(out.len(), 1, "a paired nickname must resolve to its device");
        assert_eq!(*out[0].id.as_bytes(), a);

        // A `b64u:` user_id resolves to that person's device — the doc and the `--from` help both
        // promise this, and it goes through a different store lookup than the nickname.
        let out = blob_source_addrs(&mesh, &["b64u:alice-key".into()])
            .await
            .unwrap();
        assert_eq!(*out[0].id.as_bytes(), a, "a b64u: user_id must resolve");

        // An `eid:` principal resolves without any store entry at all.
        let stranger = eid_of(43);
        let out = blob_source_addrs(
            &mesh,
            &[format!("eid:{}", data_encoding::HEXLOWER.encode(&stranger))],
        )
        .await
        .unwrap();
        assert_eq!(*out[0].id.as_bytes(), stranger);

        // ORDER is preserved — sources are tried in it, so a reordering changes which one answers.
        let out = blob_source_addrs(&mesh, &["bob".into(), "alice".into()])
            .await
            .unwrap();
        assert_eq!(
            out.iter().map(|x| *x.id.as_bytes()).collect::<Vec<_>>(),
            vec![b, a],
            "the caller's order must survive resolution"
        );

        // DEDUPED across names: the same device reached two ways is dialled once, not twice for
        // one timeout each.
        let out = blob_source_addrs(&mesh, &["alice".into(), "b64u:alice-key".into()])
            .await
            .unwrap();
        assert_eq!(out.len(), 1, "one device named twice must be dialled once");

        // A name that resolves to NOBODY is an error, not an empty contribution. Otherwise the
        // caller watches the fetch fail on the offline publisher and never learns its fallback
        // list was empty all along.
        let err = blob_source_addrs(&mesh, &["nobody".into()])
            .await
            .expect_err("an unresolvable source must be refused");
        assert!(
            format!("{err:#}").contains("no blob source 'nobody'"),
            "{err:#}"
        );

        // …and the fan-out is CAPPED rather than truncated: dropping the tail would make a fetch
        // fail while the source that had the blob sat unused.
        let many: Vec<String> = (0..mcpmesh_local_api::MAX_BLOB_SOURCES + 1)
            .map(|_| "alice".to_string())
            .collect();
        let err = blob_source_addrs(&mesh, &many)
            .await
            .expect_err("over the cap must be refused");
        assert!(
            format!("{err:#}").contains("too many blob sources"),
            "{err:#}"
        );
    }
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
            let transport = connect(&client_ep, server_addr, "echo").await.unwrap().0;

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

    /// #186: a RACED dial must carry the same stored hints a single-device dial does.
    ///
    /// The single-entry path attached `last_addr` citing #27 — "a cold daemon must not depend on
    /// external discovery to reach a paired peer" — and the multi-device path three lines away
    /// kept only the endpoint ids, throwing away hints it had literally just read out of the store.
    /// So one person with one device worked offline and the same person with two did not, with
    /// nothing saying the second device had changed that.
    ///
    /// Asserted on the ADDRESSES the race would dial, which is where the information was lost.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_raced_dial_carries_the_stored_hints() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;

        let first = *iroh::SecretKey::from_bytes(&[61u8; 32]).public().as_bytes();
        let second = *iroh::SecretKey::from_bytes(&[62u8; 32]).public().as_bytes();
        let sock: std::net::SocketAddr = "127.0.0.1:4455".parse().unwrap();
        let hint = serde_json::to_string(&iroh::EndpointAddr::from_parts(
            iroh::EndpointId::from_bytes(&first).unwrap(),
            [iroh::TransportAddr::Ip(sock)],
        ))
        .unwrap();

        // One person, two devices: the first has a persisted hint, the second never dialled.
        for (eid, nick, last) in [
            (first, "alice-laptop", Some(hint.clone())),
            (second, "alice-phone", None),
        ] {
            mesh.store
                .add(crate::allowlist::PeerEntry {
                    endpoint_id: eid,
                    nickname: nick.into(),
                    services: vec![],
                    paired_at: None,
                    user_id: Some("b64u:alice".into()),
                    last_addr: last,
                })
                .unwrap();
        }

        let addrs = super::hinted_addrs(&mesh, vec![first, second])
            .await
            .expect("candidates resolve");
        assert_eq!(addrs.len(), 2, "every candidate stays a candidate");

        // The device WITH a hint must be dialable without discovery.
        assert!(
            !addrs[0].addrs.is_empty(),
            "a raced candidate must carry its stored hint — a bare id is discovery-only, which is \
             exactly what made a two-device person unreachable on a LAN with no discovery"
        );
        assert_eq!(
            *addrs[0].id.as_bytes(),
            first,
            "and it must be THAT device's address"
        );

        // The device WITHOUT one degrades to a bare id rather than being dropped: presence and
        // hints never remove a candidate, they only change how it is reached.
        assert!(addrs[1].addrs.is_empty());
        assert_eq!(*addrs[1].id.as_bytes(), second);
    }

    /// `stored_dial_addr` attaches the persisted hint only when it parses AND names the
    /// stored id; anything else degrades to the bare-id, discovery-only dial (addresses are
    /// hints, never identity).
    #[test]
    fn stored_dial_addr_attaches_validates_and_degrades() {
        // Real curve points (arbitrary raw bytes are not valid ed25519 public keys).
        let id = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[8u8; 32]).public();
        let sock: std::net::SocketAddr = "127.0.0.1:4444".parse().unwrap();
        let stored = iroh::EndpointAddr::from_parts(id, [iroh::TransportAddr::Ip(sock)]);
        let stored_json = serde_json::to_string(&stored).unwrap();

        // Stored addr with the MATCHING id → attached verbatim (id + direct addrs).
        let addr = stored_dial_addr(Some(&stored_json), id);
        assert_eq!(addr, stored, "a matching-id hint is dialed as stored");

        // No stored addr → bare id (discovery-only).
        assert_eq!(stored_dial_addr(None, id), iroh::EndpointAddr::from(id));

        // Unparseable stored addr → bare id (graceful degradation, never an error).
        assert_eq!(
            stored_dial_addr(Some("not json"), id),
            iroh::EndpointAddr::from(id)
        );

        // Stored addr claiming a DIFFERENT id → IGNORED (bare id): an addr is a dial hint,
        // never identity — a poisoned hint must not redirect the dial's identity pin.
        let mismatched = serde_json::to_string(&iroh::EndpointAddr::from_parts(
            other,
            [iroh::TransportAddr::Ip(sock)],
        ))
        .unwrap();
        assert_eq!(
            stored_dial_addr(Some(&mismatched), id),
            iroh::EndpointAddr::from(id)
        );
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
