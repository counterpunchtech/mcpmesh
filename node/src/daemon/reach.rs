//! On-demand reachability probing (pairing-mode liveness): the trust-gated `mcpmesh/ping/1`
//! probe, its in-memory result cache on `MeshState`, and the non-blocking `status` projection
//! that refreshes stale entries in the background.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use mcpmesh_net::ALPN_PING;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};

use crate::util::epoch_now_i64;

use super::MeshState;

/// One cached reachability probe result (spec: pairing-mode liveness). Ephemeral, in-memory —
/// stored in `MeshState::reachability`, keyed by endpoint-id. `probed_at` is epoch seconds.
#[derive(Clone)]
pub struct ReachEntry {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
    pub probed_at: i64,
    /// The peer's app metadata (#40), read from its pong — empty when it set none, or when a
    /// hostile/oversized value was dropped on receive. Advisory display data, never authz.
    pub meta: String,
    /// The services this peer currently grants US (#52), read from its pong — the discovery
    /// answer. Only services whose allow admits our principal; empty if it shares nothing.
    pub services: Vec<String>,
    /// Monotonic ticket taken when this probe STARTED (#58 review). Probes of one peer overlap
    /// routinely — `reachability_of` spawns a refresh per stale peer, and BOTH `status` and
    /// `subscribe` call it — and they complete out of order, so a slow probe that started earlier
    /// must not overwrite a fast one that started later. Without this the older (timed-out) result
    /// wins on arrival, poisoning the cache for a full TTL and, since #58, PUSHING a false "went
    /// offline" for a peer that is up.
    pub seq: u64,
    /// Monotonic ticket taken when this probe's result was COMMITTED (#176) — drawn from the same
    /// counter as [`seq`](Self::seq), so the two are directly comparable.
    ///
    /// `seq` orders probes by when they STARTED; this orders them by when their evidence actually
    /// landed. Both are needed, because #58 and #176 are the same bug facing opposite ways: a
    /// timeout must not overwrite a pong, whether that pong came from a probe that started earlier
    /// or one that started later. The question that separates them is not "which is newer" but
    /// "did the peer answer inside my window?" — and answering it needs the pong's arrival
    /// compared against the timeout's start, which is exactly `observed` vs `seq`.
    pub observed: u64,
    /// HOW the peer was reached on this probe (#64) — direct/hole-punched vs through a relay.
    /// Captured alongside `reachable`/`rtt_ms` so it shares ONE TTL and one `age_secs`, rather
    /// than inventing a second staleness rule; `Unknown` covers "never probed" for free.
    pub path: mcpmesh_local_api::PeerPath,
}

/// One reachability transition on the way to `subscribe`'s fan-out (#150): the row, plus WHICH
/// producer observed it.
///
/// The ring used to carry a bare `PeerReachability`, which left the two senders indistinguishable
/// by the time [`run_subscription`](crate::control) built the frame. Only the sender knows, so it
/// stamps the attribution — see [`ReachabilitySource`](mcpmesh_local_api::ReachabilitySource) for
/// why the difference matters to an embedder.
#[derive(Clone, Debug)]
pub struct ReachTransition {
    pub peer: mcpmesh_local_api::PeerReachability,
    pub source: mcpmesh_local_api::ReachabilitySource,
}

/// Advisory reachability TTL: a cache entry older than this is refreshed by a NON-BLOCKING
/// background probe on the next [`reachability_of`] read.
pub const REACH_TTL_SECS: i64 = 20;

/// The reachability probe's hard deadline — a peer that has not ponged within this window is
/// reported unreachable. No retries/backoff/persistence (YAGNI); reachable ⇔ a pong in time.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The ping arm's rate-limit close reason (#89 gate) — the sibling idiom of `b"pair rate
/// limited"` / `b"blob rate limited"`. ONE constant for both sides so responder and prober
/// cannot drift: the accept arm writes it, [`probe_once`] matches it, and the match is what lets
/// a throttled probe be treated as non-evidence instead of a false "peer offline".
pub(crate) const PING_THROTTLE_CLOSE: &[u8] = b"ping rate limited";

/// Marker error: the probe was REFUSED by the peer's ping rate limiter (#89 gate). A refusal is
/// not evidence of unreachability in either direction — [`probe_peer`] commits nothing for it.
#[derive(Debug)]
struct ProbeThrottled;

impl std::fmt::Display for ProbeThrottled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "probe refused: ping rate limited")
    }
}

impl std::error::Error for ProbeThrottled {}

/// Did the peer close this connection with the ping limiter's reason? Read off the CONNECTION
/// rather than parsed out of whichever stream error surfaced first — the refusal races our
/// `open_bi`/write/read, so any of them can be the failure site, and all of them leave the
/// application close on `close_reason()`.
fn throttle_closed(conn: &iroh::endpoint::Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(ac))
            if ac.reason.as_ref() == PING_THROTTLE_CLOSE
    )
}

/// Probe one peer over [`ALPN_PING`] and cache the result. Dials the peer by id WITH its stored
/// `last_addr` hint attached when usable, exactly like `dial::dial_service`'s single-nickname
/// fallback (discovery still resolves/merges addresses; hermetic localhost tests seed a
/// `MemoryLookup` or store a hint), sends one ping frame,
/// reads the pong, and measures RTT (dial + round-trip, stamped AT THE PONG — it deliberately
/// EXCLUDES the `PATH_SETTLE` window that `settled_path` spends afterwards deciding which path we
/// are on, #123). Writes the outcome into the in-memory
/// `MeshState::reachability` cache and returns it. Reachable ⇔ a pong arrived within
/// `PROBE_TIMEOUT`; a gate refusal (no pong) or any dial/IO failure is a clean `reachable:false`.
///
/// That equivalence holds for the entry this call CONSTRUCTS as of #128, and did not before —
/// with two caveats it does not cover: a malformed/oversized pong is not a pong (it bails), and a
/// newer overlapping probe can supersede ours, in which case THAT entry is returned. Before #128
/// the equivalence failed for a much more ordinary reason: `PROBE_TIMEOUT` used to wrap the
/// `PATH_SETTLE` classification too, so a relayed peer whose pong arrived at ~2.4s timed out while
/// we were deciding which route it took, and was reported offline despite answering. The two
/// questions now get separate deadlines, and a classification failure degrades `path` to
/// `Unknown` rather than flipping `reachable`.
pub async fn probe_peer(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> ReachEntry {
    // Ticket FIRST, before any await: ordering is by probe START, not completion.
    let seq = mesh
        .probe_seq
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(PROBE_TIMEOUT, probe_once(mesh, endpoint_id, started)).await;
    // #89 gate (HIGH): a probe REFUSED by the peer's rate limiter is not evidence the peer is
    // down — commit NOTHING for it. Writing `reachable: false` here gave a live, paired peer a
    // fresh false offline for a full TTL and broadcast the transition. The caller gets the
    // previous entry if one exists (the refusal proves the peer is up, but the entry stays
    // honest about when it was actually probed), else an UNCOMMITTED unreachable row — never
    // cached, so it cannot poison anything.
    //
    // Two accepted bounds (#142 second gate), stated rather than fixed:
    // - A hostile PAIRED peer that answers every probe with the throttle close keeps its entry
    //   permanently stale, so every `reachability_of` read re-spawns a refresh — no 20s
    //   quiescence, one dial per read, until it pongs or goes down. Bounded by our own poll
    //   rate, costs the peer a connection each time, and it can only pin ITS OWN row (whose
    //   meta/path/rtt it already controls); a probe backoff belongs with #89's follow-up work.
    // - The check below matches `Ok(Err(_))` only: a refusal whose CONNECTION_CLOSE arrives
    //   after PROBE_TIMEOUT surfaces as `Elapsed` and commits `reachable: false` normally — a
    //   lost close frame is indistinguishable from a dead peer, so that is the honest verdict.
    if let Ok(Err(e)) = &outcome
        && e.downcast_ref::<ProbeThrottled>().is_some()
    {
        let previous = mesh
            .reachability
            .lock()
            .expect("reachability lock not poisoned")
            .get(&endpoint_id)
            .cloned();
        return previous.unwrap_or(ReachEntry {
            reachable: false,
            rtt_ms: None,
            probed_at: epoch_now_i64(),
            meta: String::new(),
            services: Vec::new(),
            seq,
            // Never cached (that is the point of this arm), so no other probe ever compares
            // against it. It carries our own start ticket rather than a fresh one so the row is
            // self-consistent if a caller inspects it.
            observed: seq,
            path: mcpmesh_local_api::PeerPath::Unknown,
        });
    }
    // `probe_once` returns the peer's (already length-capped) metadata on a reachable pong.
    // `path` rides the probe OUTCOME, so it is exactly as fresh as `reachable`/`rtt_ms` and an
    // unreachable peer reports `Unknown` rather than a stale route (#64 review). Reading it from
    // the endpoint's address map after the fact reported `Direct` for a peer that had just gone
    // away, because iroh leaves those entries Active for up to a minute after the connection dies.
    let (reachable, meta, services, path, rtt_ms) =
        classify(outcome, |conn| async move { settled_path(&conn).await }).await;
    // The COMMIT ticket (#176). Taken before the lock so it is drawn exactly once per probe, and
    // from the same counter as `seq` so `observed` and `seq` are comparable across probes.
    let observed = mesh
        .probe_seq
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let entry = ReachEntry {
        reachable,
        rtt_ms,
        probed_at: epoch_now_i64(),
        meta,
        services,
        seq,
        observed,
        path,
    };
    // Commit under ONE lock acquisition, DISCARDING a result a newer probe has already superseded
    // (#58 review): probes of one peer overlap and complete out of order.
    let outcome = {
        let mut cache = mesh
            .reachability
            .lock()
            .expect("reachability lock not poisoned");
        match cache.get(&endpoint_id) {
            // A newer probe already landed. Drop ours and report THEIRS, so a caller never acts on
            // a value the cache disagrees with.
            Some(newer) if !supersedes(seq, newer) => Outcome::Superseded(newer.clone()),
            // #176: our probe started LATER, but it found nothing while a pong landed INSIDE our
            // window. Drop ours — see `contradicted_by`.
            Some(pong) if contradicted_by(&entry, seq, pong) => Outcome::Superseded(pong.clone()),
            other => {
                let previous = other.cloned();
                cache.insert(endpoint_id, entry.clone());
                Outcome::Committed(previous)
            }
        }
    };
    let previous = match outcome {
        Outcome::Superseded(newer) => return newer,
        Outcome::Committed(previous) => previous,
    };

    if is_transition(previous.as_ref(), &entry) {
        // Only for a peer the STORE knows: `probe_peer` is also reachable via `peer_services`,
        // which accepts a bare `eid:` with no stored row. Emitting for one of those would push a
        // NAMELESS frame for an endpoint the snapshot's store-driven list can never contain — the
        // stream asserting state `status` contradicts (#58 review).
        if let Some(peer) = stored_row(mesh, endpoint_id, &entry) {
            // Best-effort: `send` errors only when there are no subscribers, the common case.
            let _ = mesh.reach_bcast.send(ReachTransition {
                peer,
                // #150: a probe is a throwaway dial. It says nothing about any live connection,
                // and a consumer must be able to tell that without inferring it from `rtt_ms`.
                source: mcpmesh_local_api::ReachabilitySource::Probe,
            });
        }
    }
    entry
}

/// Should a probe holding ticket `seq` overwrite `existing` (#58 review)?
///
/// Tickets are taken at probe START, so a LOWER ticket is an OLDER probe: it may complete later
/// (a 3s timeout losing to a 50ms pong) but must not win. Equal is impossible — tickets are unique
/// — and is treated as "write" so the guard can never wedge.
pub(crate) fn supersedes(seq: u64, existing: &ReachEntry) -> bool {
    seq >= existing.seq
}

/// Is `ours` — a probe that started at `seq` — contradicted by the cached `existing` entry (#176)?
///
/// True when all three hold: our verdict is `reachable: false`, the cached verdict is
/// `reachable: true`, and that pong was OBSERVED after we started (`existing.observed > seq`).
///
/// **Why a timeout is weaker evidence than a pong.** A pong is a fact about the peer at a known
/// instant. A `PROBE_TIMEOUT` elapse is a fact about *our dial* over a window — "no pong reached
/// me". When a pong demonstrably arrived inside that same window, on someone else's connection,
/// our window contained a live peer and our "unreachable" is simply wrong about it. Committing it
/// anyway is what pinned `reachable: false` for a full `REACH_TTL_SECS` on a peer that never went
/// anywhere. Same reasoning as #89's throttle arm: not every failed probe is evidence of a down
/// peer.
///
/// **Why [`supersedes`] alone could not fix it.** That rule orders by probe START, so among N
/// overlapping probes the last-started always wins — and the last-started is the most contended,
/// so it is the one most likely to time out. #58 stopped an OLD probe's timeout landing on a NEW
/// probe's pong; this stops the mirror image. Neither ordering by start nor ordering by completion
/// gets both, because the real relation is between one probe's window and another's arrival.
///
/// **It does not wedge a genuinely down peer as reachable.** This only ever refuses probes that
/// were already in flight when the last pong landed. Any probe starting AFTER it has
/// `seq > existing.observed`, so once the peer really stops answering the next probe commits
/// `reachable: false` normally. The stale-positive window is one probe cycle, not the 20s TTL.
fn contradicted_by(ours: &ReachEntry, seq: u64, existing: &ReachEntry) -> bool {
    !ours.reachable && existing.reachable && existing.observed > seq
}

/// What [`probe_peer`]'s commit step decided.
enum Outcome {
    /// Our result was written; carries the entry it replaced, if any.
    Committed(Option<ReachEntry>),
    /// A newer probe had already landed; carries THAT result.
    Superseded(ReachEntry),
}

/// How long to let a fresh connection settle before classifying its path (#64).
///
/// A dial starts on the relay and hole-punches in the background; measured on loopback the direct
/// path is SELECTED about 300 ms in. Classifying immediately after the pong therefore reported
/// `Relay` for every peer on a relay-enabled node — useless for the locality claim, and wrong in
/// the same direction as the address-map version this replaced. It is only ever spent on a
/// connection that has NOT yet selected a direct path.
///
/// It is a SEPARATE budget from `PROBE_TIMEOUT`, not a slice of it (#128). It used to be nested
/// inside, which is precisely the bug: a relayed peer whose pong landed near the deadline timed
/// out mid-classification and was reported offline while answering. A probe's worst case is now
/// `PROBE_TIMEOUT + PATH_SETTLE`.
const PATH_SETTLE: Duration = Duration::from_millis(600);

/// [`selected_path`] with a bounded wait for hole-punching to finish (#64).
///
/// Returns as soon as a DIRECT path is selected; otherwise polls until [`PATH_SETTLE`] elapses and
/// reports whatever is selected then — a genuinely relayed peer costs the full window once per
/// probe, and reports `Relay`, which is the truthful answer for it.
///
/// **This one line is NOT covered by any test (#110 review).** [`settle`]'s logic is pinned below,
/// but nothing catches this call site passing `Duration::ZERO` instead of [`PATH_SETTLE`] — that
/// mutation reintroduces the exact #64 regression (every peer reports `Relay` on a relay-enabled
/// node) with the whole suite green. Verified by mutation, not assumed. Pinning it needs a probe
/// against a real connection whose punch has not yet landed, which is precisely the timing race
/// that made this suite flaky; a latency assertion is not an option either, since timing
/// assertions on a loaded machine have lied to this repo before. Kept as a deliberate, stated gap
/// rather than a claim of coverage.
async fn settled_path(conn: &iroh::endpoint::Connection) -> mcpmesh_local_api::PeerPath {
    settle(PATH_SETTLE, || selected_path(conn)).await
}

/// The polling half of [`settled_path`], over a closure rather than a live connection (#110).
///
/// Split out because the property "keep looking until Direct, then stop; give up at the deadline"
/// is pure timing logic, and pinning it through a real hole-punch made the integration suite
/// depend on CI network luck. The e2e test proves we read the SELECTED path; this proves we WAIT
/// for it. Neither test can cover both without one of them going vacuous — reordering the e2e test
/// to be non-flaky silently stopped it catching a zeroed `PATH_SETTLE`.
///
/// Note the seam covers the WINDOW's behaviour, not the window's USE — see [`settled_path`].
pub(crate) async fn settle<F>(window: Duration, mut probe: F) -> mcpmesh_local_api::PeerPath
where
    F: FnMut() -> mcpmesh_local_api::PeerPath,
{
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let path = probe();
        if path == mcpmesh_local_api::PeerPath::Direct || tokio::time::Instant::now() >= deadline {
            return path;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Which path is this connection actually using (#64)?
///
/// `Path::is_selected()` is iroh's own answer to "selected for application data transmission" —
/// the only signal that means traffic. Every other view (the endpoint's remote-address map,
/// `TransportAddrUsage::Active`) reports *open* paths, and iroh deliberately keeps a relay path
/// open as a standby for the life of the connection, so those views call a hole-punched connection
/// relayed forever.
///
/// No selected path (a snapshot taken as the connection tears down) → `Unknown`, never a guess.
pub(crate) fn selected_path(conn: &iroh::endpoint::Connection) -> mcpmesh_local_api::PeerPath {
    let paths = conn.paths();
    for path in &paths {
        if !path.is_selected() {
            continue;
        }
        return match path.remote_addr() {
            iroh::TransportAddr::Relay(url) => mcpmesh_local_api::PeerPath::Relay {
                url: Some(sanitize_relay_url(url)),
            },
            iroh::TransportAddr::Ip(_) => mcpmesh_local_api::PeerPath::Direct,
            // A transport mcpmesh does not model: say so rather than guess.
            _ => mcpmesh_local_api::PeerPath::Unknown,
        };
    }
    mcpmesh_local_api::PeerPath::Unknown
}

/// Render a relay URL for the wire WITHOUT its userinfo (#64 review).
///
/// Relay URLs are operator-supplied (`[network].relay_urls`, `set_relays`), so a
/// `https://user:token@relay.internal/` would otherwise ship that token to every local-API client.
/// Scheme + host + port only: enough to name which relay is in use, carrying no credential and no
/// path/query.
pub fn sanitize_relay_url(url: &iroh::RelayUrl) -> String {
    let u: &url::Url = url; // RelayUrl derefs to Url
    match (u.host_str(), u.port()) {
        (Some(host), Some(port)) => format!("{}://{host}:{port}", u.scheme()),
        (Some(host), None) => format!("{}://{host}", u.scheme()),
        (None, _) => u.scheme().to_string(),
    }
}

/// Normalize a relay URL STRING to the same rendering [`sanitize_relay_url`] produces, so a raw
/// operator-configured value can be compared with a live [`RelayInfo`](mcpmesh_local_api::RelayInfo)
/// URL. `None` when it does not parse as a relay URL at all.
///
/// Exists so the PORCELAIN can do that comparison (#125's `doctor` relay check) without taking a
/// runtime dependency on iroh — the shipped `mcpmesh` binary reaches iroh through this crate on
/// purpose. Sharing the one function is also what stops the two renderings drifting: a prefix-match
/// substitute reported a dead relay as connected whenever it was a strict prefix of a healthy one.
pub fn normalize_relay_url(raw: &str) -> Option<String> {
    raw.parse::<iroh::RelayUrl>()
        .ok()
        .map(|u| sanitize_relay_url(&u))
}

/// Did this probe CHANGE what a subscriber already believes (#58)?
///
/// The baseline is the SNAPSHOT, not the cache: a peer with no cache entry is reported
/// `reachable: false` there (see [`reachability_of`]'s `None` arm). So first knowledge is news only
/// when the peer turns out to be UP — a first probe confirming "down" merely restates the snapshot,
/// and emitting it produced a burst of spurious "is now offline" frames on every daemon restart,
/// immediately after a snapshot that had just said exactly that (#58 review).
///
/// Deliberately NOT sensitive to `rtt_ms`/`meta`/`services`: those drift on every refresh and are
/// advisory detail, so treating them as transitions would emit a frame per TTL refresh for a peer
/// that is simply staying up — chatty, and not a decision point for any consumer.
fn is_transition(previous: Option<&ReachEntry>, current: &ReachEntry) -> bool {
    match previous {
        None => current.reachable,
        // #92: `path` counts, `rtt_ms`/`meta` do not. #64 grouped path with the advisory drift
        // fields, which was wrong — and the same release's own docs are what prove it. `Direct` is
        // the only value that supports a locality claim, and rendering `Unknown` as private is
        // documented as "the one misuse that turns this field into a false privacy statement". A
        // field carrying a truth claim about WHERE USER DATA WENT cannot be advisory: without this,
        // a session that degrades Direct -> Relay stays silently mislabelled as private for its
        // whole duration, and the only fallback is polling a 20s-TTL cache.
        //
        // Flapping was #64's stated reason for excluding it. `settled_path` already applies the
        // 600ms PATH_SETTLE window, so the cached value is post-hole-punch, and probes are TTL-gated
        // — a peer cannot emit more than once per refresh regardless.
        Some(prev) => prev.reachable != current.reachable || prev.path != current.path,
    }
}

/// Build the wire row for ONE peer. THE single constructor of `PeerReachability` — both the
/// `status`/snapshot list and the #58 transition event go through it, so the two genuinely cannot
/// drift (an earlier version merely CLAIMED this while `reachability_of` built its rows inline).
///
/// `entry == None` is a peer never probed: `reachable: false` with no age, which a consumer renders
/// as "checking…". `age_secs` is the caller's, since the snapshot computes it from `probed_at`
/// while a transition event is fresh by construction.
pub(crate) fn reachability_row(
    nickname: String,
    endpoint_id: [u8; 32],
    entry: Option<&ReachEntry>,
    age_secs: Option<u64>,
) -> mcpmesh_local_api::PeerReachability {
    mcpmesh_local_api::PeerReachability {
        path: entry.map(|e| e.path.clone()).unwrap_or_default(),
        name: nickname,
        reachable: entry.is_some_and(|e| e.reachable),
        rtt_ms: entry.and_then(|e| e.rtt_ms),
        age_secs,
        meta: entry.map(|e| e.meta.clone()).unwrap_or_default(),
        // #42: the eid: device principal, so a row joins to the authenticated endpoint rather
        // than the non-unique nickname.
        principal: Some(mcpmesh_net::EndpointId::from_bytes(endpoint_id).principal()),
    }
}

/// The transition event's row, or `None` when the peer has no stored entry — see the call site.
/// A point read, not the O(n) scan an earlier version used.
fn stored_row(
    mesh: &Arc<MeshState>,
    endpoint_id: [u8; 32],
    entry: &ReachEntry,
) -> Option<mcpmesh_local_api::PeerReachability> {
    let nickname = mesh.store.resolve(&endpoint_id).ok().flatten()?.nickname;
    Some(reachability_row(
        nickname,
        endpoint_id,
        Some(entry),
        Some(0),
    ))
}

/// The dial → ping → pong half of [`probe_peer`], separated so the whole exchange is one timeout
/// unit. Reuses the real iroh 1.0.1 call shapes from `dial.rs`/`pairing::rendezvous`
/// (`endpoint.connect`, `open_bi`, `write_frame`, `finish`, a framed read).
async fn probe_once(
    mesh: &Arc<MeshState>,
    endpoint_id: [u8; 32],
    started: tokio::time::Instant,
) -> Result<(String, Vec<String>, iroh::endpoint::Connection, u64)> {
    let id = iroh::EndpointId::from_bytes(&endpoint_id)
        .map_err(|e| anyhow::anyhow!("invalid endpoint id: {e}"))?;
    // Attach the pairing-persisted `last_addr` hint, exactly as `dial::dial_service` does
    // (issue #27): a just-paired peer is reachable at the address the handshake PROVED, so the
    // probe must not sit waiting on discovery to resolve the bare id. Without this the redeemer's
    // first probe blows `PROBE_TIMEOUT` and `status` calls a freshly-paired peer offline. A
    // missing/unparseable/id-mismatched hint degrades to the bare-id dial (see `stored_dial_addr`).
    // The redb read blocks, so it runs on the blocking pool (the fs house rule).
    let store = mesh.store.clone();
    let last_addr = tokio::task::spawn_blocking(move || store.resolve(&endpoint_id))
        .await
        .map_err(|e| anyhow::anyhow!("join peer resolve for probe: {e}"))?
        .ok()
        .flatten()
        .and_then(|e| e.last_addr);
    let addr = super::dial::stored_dial_addr(last_addr.as_deref(), id);
    let conn = mesh.endpoint.connect(addr, ALPN_PING).await?;
    let exchanged = exchange(&conn, started).await;
    // A limiter refusal (#89 gate) surfaces as whichever stream error lost the race with the
    // peer's close; the close reason on the CONNECTION is the reliable signal. Rewrite it to the
    // marker so `probe_peer` can refuse to treat it as evidence. Checked only on failure: a
    // successful exchange got a pong, throttled or not.
    match exchanged {
        Ok((meta, services, rtt_ms)) => Ok((meta, services, conn, rtt_ms)),
        Err(e) if throttle_closed(&conn) => Err(e.context(ProbeThrottled)),
        Err(e) => Err(e),
    }
}

/// The stream half of [`probe_once`], over an established connection: open the bi-stream, send
/// one ping frame, read the pong. Split from the dial so its failure can be classified against
/// the connection's close reason ([`throttle_closed`]) at ONE site rather than per stream call.
/// `started` is the PROBE's start — before the dial — so `rtt_ms` keeps meaning dial + round
/// trip (#123), not just this stream half.
async fn exchange(
    conn: &iroh::endpoint::Connection,
    started: tokio::time::Instant,
) -> Result<(String, Vec<String>, u64)> {
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
        // Any well-formed pong frame ⇒ reachable. It MAY carry the peer's app metadata (#40);
        // extract it, but — defense in depth against a compromised paired peer — enforce the
        // SAME ≤256B cap the sender applies (an oversized/absent/non-string value ⇒ empty).
        // The channel is authenticated (this is a trust-gated paired peer), so no signature is
        // needed; the cap is the only receive-side hardening required.
        // Classify the path from THIS connection, while it is still open (#64). It must come
        // from `Connection::paths()` + `Path::is_selected()` — the path actually carrying
        // application data — and NOT from the endpoint's remote-address map: iroh deliberately
        // keeps a relay path OPEN as a standby after hole-punching succeeds ("Relay and custom
        // paths are kept open", `remote_state.rs`), so an address-usage view reports a relay for
        // a connection whose data provably flows direct. That version made `Direct` unreachable
        // on any relay-enabled node — i.e. every real deployment — which is the opposite of the
        // truthful-locality-claim this field exists to support.
        Some(Inbound::Frame(v)) => {
            // Stamp the RTT HERE, at the pong — before any classification work (#123). Measuring
            // afterwards meant a relayed peer could never report under 600ms, because most of the
            // number was our own deliberate wait. An embedder read ~820ms on two machines one LAN
            // hop apart and filed it as a 66x fleet latency degradation; ~73% of that figure was
            // the settle window. `rtt_ms` means what its name says: dial + round trip.
            //
            // The CONNECTION is returned rather than a classified path (#128): classifying it
            // spends up to `PATH_SETTLE`, and that must happen OUTSIDE `PROBE_TIMEOUT` — see
            // `probe_peer`.
            let rtt_ms = started.elapsed().as_millis() as u64;
            Ok((pong_meta(&v), pong_services(&v), rtt_ms))
        }
        _ => anyhow::bail!("no pong from peer"),
    }
}

/// What the timed exchange produced: the pong's metadata, admitted services, the live connection
/// and the pong-stamped RTT — or a timeout.
type ExchangeOutcome<C> =
    std::result::Result<Result<(String, Vec<String>, C, u64)>, tokio::time::error::Elapsed>;

/// Turn a probe exchange outcome into the reported facts, classifying the path OUTSIDE the
/// exchange deadline (#128) and WITHOUT touching `rtt_ms` (#123).
///
/// A seam, and it earns its keep twice over — both hazards it guards were shipped and caught:
///
/// - **#128:** `reachable` is decided by the EXCHANGE alone. Folding classification into
///   `PROBE_TIMEOUT` meant a relayed peer whose pong landed after ~2.4s timed out DURING
///   classification and was reported offline while it was answering. Failing to classify degrades
///   `path` to `Unknown`, never `reachable` to false.
/// - **#123:** `rtt_ms` arrives already stamped at the pong and is passed through UNTOUCHED. The
///   fix for #128 moved the settle window into the same scope as `started`, four lines away, so
///   re-deriving the RTT after classification is a one-line edit that silently restores #123. An
///   earlier version of this commit deleted #123's pin and called the ordering "structural"; it
///   was not, and the adversarial gate reproduced the bug with the whole suite green.
///
/// Generic over the settle future so both properties are testable on a paused clock, with no live
/// connection and no wall-clock assertion.
async fn classify<C, F, Fut>(
    outcome: ExchangeOutcome<C>,
    settle: F,
) -> (
    bool,
    String,
    Vec<String>,
    mcpmesh_local_api::PeerPath,
    Option<u64>,
)
where
    F: FnOnce(C) -> Fut,
    Fut: std::future::Future<Output = mcpmesh_local_api::PeerPath>,
{
    match outcome {
        Ok(Ok((meta, services, conn, rtt_ms))) => {
            // `rtt_ms` is threaded through, never recomputed — see #123 above.
            let path = settle(conn).await;
            (true, meta, services, path, Some(rtt_ms))
        }
        _ => (
            false,
            String::new(),
            Vec::new(),
            mcpmesh_local_api::PeerPath::Unknown,
            None,
        ),
    }
}

/// Extract the optional app metadata from a pong frame, applying the receive cap (#40): a
/// missing / non-string / over-`APP_METADATA_MAX_BYTES` value yields empty. Control-character
/// hygiene is applied at RENDER time (`--json` carries it raw, JSON-escaped).
/// Extract the caller-admitted service names from a pong (#52) — a JSON array of strings, or
/// empty for a peer that shares nothing / an older peer without the field. Never panics on
/// hostile shapes.
fn pong_services(pong: &serde_json::Value) -> Vec<String> {
    pong.get("services")
        .and_then(|s| s.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn pong_meta(pong: &serde_json::Value) -> String {
    pong.get("meta")
        .and_then(|m| m.as_str())
        .filter(|s| s.len() <= crate::roster::presence::APP_METADATA_MAX_BYTES)
        .unwrap_or_default()
        .to_string()
}

/// Build the `status` reachability list from the probe cache, and fire a NON-BLOCKING background
/// refresh for any paired peer whose cache entry is missing or older than [`REACH_TTL_SECS`].
/// NEVER blocks the caller on a probe: it returns the current cached view immediately and each
/// refresh runs as its own spawned task (parallel probes, no join helper / new dependency needed —
/// each `probe_peer` writes its own cache entry, read by the NEXT call).
///
/// Surface discipline: the cache is keyed by endpoint-id INTERNALLY, but every returned
/// [`mcpmesh_local_api::PeerReachability`] carries only the peer's NICKNAME — never the endpoint-id.
/// The services `identity` is currently admitted to on THIS node (#52) — the discovery answer
/// the ping pong carries. Computes the caller's flat principal set (the SAME
/// `mcpmesh_local_api::principal_set` admission uses) and returns every persistent OR ephemeral
/// service whose `allow` names one of those principals. ONLY the caller's own admitted services
/// — never the full registry. A best-effort config read (an unreadable config → empty).
pub(crate) fn caller_admitted_services(
    mesh: &Arc<MeshState>,
    identity: &mcpmesh_net::PeerIdentity,
) -> Vec<String> {
    use std::collections::HashSet;
    let eid = identity.endpoint.principal();
    let principals: HashSet<&str> =
        mcpmesh_local_api::principal_set(Some(&eid), identity.user_id.as_deref(), &identity.groups)
            .into_iter()
            .collect();
    let admits = |allow: &[String]| allow.iter().any(|a| principals.contains(a.as_str()));

    // #100: answer from the LIVE registry — the same `Services` the accept path authorizes from.
    // Reading `config.toml` + the ephemeral map instead meant a hand-added service that had not
    // been reloaded was reported as usable and then refused, which a caller cannot distinguish
    // from a network failure. The registry is already keyed by name with the overlay having won at
    // build time, so no merge and no dedup is needed here.
    let mut out: Vec<String> = mesh
        .services
        .get()
        .iter()
        .filter(|(_, entry)| admits(&entry.allow))
        .map(|(name, _)| name.clone())
        .collect();
    out.sort();
    out
}

/// Probe `endpoint_id` only if the cache has nothing fresher than [`REACH_TTL_SECS`] (#89).
///
/// `probe_peer` is unconditional, which made `peer_services` the one caller with no TTL: a client
/// polling it faster than the ping limiter's sustained refill would be REFUSED, and a refusal is
/// reported as `reachable: false` and written to the cache. That turns a rate limit into a fresh
/// false "peer is offline" for the next [`REACH_TTL_SECS`] — a healthy, paired peer reported down,
/// which is worse than the flood the limiter exists to stop. Reusing a fresh entry keeps the verb
/// off the limiter entirely under any realistic poll rate, so the two cannot fight.
///
/// This trades the docstring's "a fresh probe" for "no staler than `status` would report", which is
/// the same freshness contract every other consumer of this cache already gets.
pub(crate) async fn probe_peer_cached(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> ReachEntry {
    let fresh = {
        let cache = mesh
            .reachability
            .lock()
            .expect("reachability lock not poisoned");
        cache.get(&endpoint_id).and_then(|e| {
            let age = (epoch_now_i64() - e.probed_at).max(0);
            (age <= REACH_TTL_SECS).then(|| e.clone())
        })
    };
    match fresh {
        Some(e) => e,
        None => probe_peer(mesh, endpoint_id).await,
    }
}

pub fn reachability_of(mesh: &Arc<MeshState>) -> Vec<mcpmesh_local_api::PeerReachability> {
    let now = epoch_now_i64();
    // (nickname, endpoint_id) for every paired peer — reuse the allowlist store's peer scan
    // (fail-open: a corrupt row is skipped, not fatal). The store IS the paired-peer set.
    let peers: Vec<(String, [u8; 32])> = mesh
        .store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|e| (e.nickname, e.endpoint_id))
        .collect();
    let cache = mesh
        .reachability
        .lock()
        .expect("reachability lock not poisoned")
        .clone();
    let mut stale: Vec<[u8; 32]> = Vec::new();
    let mut out = Vec::with_capacity(peers.len());
    for (nickname, eid) in peers {
        match cache.get(&eid) {
            Some(e) => {
                let age = (now - e.probed_at).max(0);
                if age > REACH_TTL_SECS {
                    stale.push(eid);
                }
                out.push(reachability_row(nickname, eid, Some(e), Some(age as u64)));
            }
            None => {
                stale.push(eid);
                // Never probed → `age_secs: None`, which a consumer renders as "checking…".
                out.push(reachability_row(nickname, eid, None, None));
            }
        }
    }
    // #176: ONE background refresh per peer at a time. The v1 note here called the missing dedup a
    // bounded tradeoff because the overlap self-limits once a result is cached — true of the probe
    // COUNT, not of the damage. A caller polling `status` faster than `PROBE_TIMEOUT` spawned a
    // fresh dial every poll, and that contention is what made the last-started probe (whose verdict
    // the ordering rule used to prefer) the one most likely to time out. `contradicted_by` fixes
    // the verdict; this removes the storm that produced it.
    //
    // Reads are unaffected: a peer already being refreshed still gets its cached row in `out`, just
    // no second dial. `probe_peer` itself stays unconditional — `peer_services` and the tests call
    // it directly and mean it.
    for (eid, guard) in claim_refreshes(mesh, stale) {
        let mesh = mesh.clone();
        tokio::spawn(async move {
            let _guard = guard; // released on completion, panic, or cancellation
            probe_peer(&mesh, eid).await;
        });
    }
    out
}

/// Which of `stale` this call may refresh (#176), each paired with the claim that reserves it.
///
/// Split from the spawn loop so the dedup decision is testable without a runtime and without a
/// timing assertion: the second call over the same peer returns an empty list, deterministically,
/// for as long as the first call's guards are alive. The loop above then holds nothing but a
/// `spawn`.
fn claim_refreshes(mesh: &Arc<MeshState>, stale: Vec<[u8; 32]>) -> Vec<([u8; 32], InFlight)> {
    stale
        .into_iter()
        .filter_map(|eid| InFlight::claim(mesh, eid).map(|g| (eid, g)))
        .collect()
}

/// A claim on "this peer is being refreshed" (#176), released on drop.
///
/// A drop guard rather than a `remove` at the end of the spawned task: a probe that panics, or a
/// task dropped when the runtime shuts down, would otherwise leave the peer marked in-flight
/// forever and never refresh it again. That failure is silent and permanent, which is a strictly
/// worse bug than the duplicate dials this exists to prevent.
struct InFlight {
    mesh: Arc<MeshState>,
    endpoint_id: [u8; 32],
}

impl InFlight {
    /// `Some` if no refresh for `endpoint_id` was already running — the claim. `None` means one is.
    fn claim(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> Option<Self> {
        mesh.probes_inflight
            .lock()
            .expect("probes_inflight lock not poisoned")
            .insert(endpoint_id)
            .then(|| Self {
                mesh: mesh.clone(),
                endpoint_id,
            })
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.mesh
            .probes_inflight
            .lock()
            .expect("probes_inflight lock not poisoned")
            .remove(&self.endpoint_id);
    }
}

#[cfg(test)]
mod tests {
    use super::pong_meta;
    use super::{ReachEntry, contradicted_by, is_transition, sanitize_relay_url, supersedes};
    use crate::roster::presence::APP_METADATA_MAX_BYTES;

    fn entry(reachable: bool, rtt_ms: Option<u64>) -> ReachEntry {
        ReachEntry {
            reachable,
            rtt_ms,
            probed_at: 1_700_000_000,
            meta: String::new(),
            services: Vec::new(),
            seq: 0,
            observed: 0,
            path: mcpmesh_local_api::PeerPath::Unknown,
        }
    }

    /// #128 AND #123, in one test, because they are the same coupling from two sides.
    ///
    /// The previous version of this test was VACUOUS: it built its own timeout over its own sleep
    /// and never touched production control flow, so re-nesting the settle inside `PROBE_TIMEOUT`
    /// — restoring #128 verbatim — left the whole suite green. The adversarial gate proved it.
    ///
    /// This drives the real seam on a paused clock. It fails on BOTH mutations:
    ///   - re-nesting classification inside the exchange deadline (#128)
    ///   - re-deriving `rtt_ms` from `started` after classification (#123)
    #[tokio::test(start_paused = true)]
    async fn classification_costs_neither_the_verdict_nor_the_rtt() {
        use mcpmesh_local_api::PeerPath;
        use std::time::Duration;

        let started = tokio::time::Instant::now();
        // A pong landing LATE but inside the exchange budget: this is the #128 peer.
        let late = super::PROBE_TIMEOUT - Duration::from_millis(200);
        tokio::time::sleep(late).await;
        let rtt_at_pong = started.elapsed().as_millis() as u64;

        // Classification then spends the full window, as a genuinely relayed peer does. Together
        // these exceed super::PROBE_TIMEOUT — which is exactly what used to flip `reachable` to false.
        let outcome: super::ExchangeOutcome<()> = Ok(Ok((
            "meta".to_string(),
            vec!["echo".to_string()],
            (),
            rtt_at_pong,
        )));
        let (reachable, _meta, _services, path, rtt_ms) = super::classify(outcome, |()| async {
            tokio::time::sleep(super::PATH_SETTLE).await;
            PeerPath::Relay { url: None }
        })
        .await;

        assert!(
            late + super::PATH_SETTLE > super::PROBE_TIMEOUT,
            "the fixture must exceed the OLD combined budget, or it proves nothing"
        );
        assert!(
            reachable,
            "a pong inside super::PROBE_TIMEOUT must survive classification — reporting a peer offline \
             while it is answering is #128, and it is wrong in the dangerous direction"
        );
        assert_eq!(path, PeerPath::Relay { url: None });
        assert_eq!(
            rtt_ms,
            Some(2800),
            "rtt_ms must be the pong stamp, NOT restamped after the settle window — restamping \
             is a one-line edit away and silently restores #123"
        );

        // An exchange that timed out reports unreachable with no route and no measurement.
        let timed_out: super::ExchangeOutcome<()> =
            tokio::time::timeout(Duration::ZERO, std::future::pending()).await;
        let (reachable, _m, _s, path, rtt_ms) =
            super::classify(timed_out, |()| async { PeerPath::Direct }).await;
        assert!(!reachable);
        assert_eq!(path, PeerPath::Unknown, "never a guessed route");
        assert_eq!(rtt_ms, None, "never a fabricated measurement");
    }

    /// #64/#110: the probe WAITS for hole-punching rather than classifying the instant the pong
    /// lands. A fresh dial starts on the relay, so a zero settle window reports `Relay` for every
    /// peer on a relay-enabled node — the bug #64 shipped and then fixed.
    ///
    /// This lives here, not in the e2e suite, because the e2e version could only observe it by
    /// racing a real hole-punch: that made it flaky on Windows and Linux CI (#110), and the
    /// reordering that de-flaked it stopped catching this mutation entirely. Time is driven by
    /// tokio's test clock, so it is deterministic and instant.
    #[tokio::test(start_paused = true)]
    async fn the_probe_waits_for_the_direct_path_instead_of_classifying_immediately() {
        use mcpmesh_local_api::PeerPath;
        use std::time::Duration;

        // A connection that is relayed for the first three polls, then hole-punches.
        let mut polls = 0;
        let path = super::settle(super::PATH_SETTLE, || {
            polls += 1;
            if polls > 3 {
                PeerPath::Direct
            } else {
                PeerPath::Relay { url: None }
            }
        })
        .await;
        assert_eq!(
            path,
            PeerPath::Direct,
            "the settle window must outlast a punch that takes a few polls — classifying on the \
             first look is what made Direct unreachable on every relay-enabled node"
        );
        assert_eq!(polls, 4, "it must stop polling as soon as Direct appears");

        // A ZEROED window is the mutation the e2e suite used to catch: it returns whatever the
        // very first look says, which for a fresh dial is always the relay.
        let mut polls = 0;
        let path = super::settle(Duration::ZERO, || {
            polls += 1;
            if polls > 3 {
                PeerPath::Direct
            } else {
                PeerPath::Relay { url: None }
            }
        })
        .await;
        assert_eq!(
            path,
            PeerPath::Relay { url: None },
            "with no settle window the relay answer wins — this assertion is what fails if \
             PATH_SETTLE is ever zeroed or the wait is removed"
        );

        // A genuinely relayed peer pays the whole window and truthfully reports Relay.
        let path = super::settle(super::PATH_SETTLE, || PeerPath::Relay { url: None }).await;
        assert_eq!(
            path,
            PeerPath::Relay { url: None },
            "a peer with no direct path must report Relay, not Unknown or Direct"
        );
    }

    /// #64 review: a relay URL reaching the wire must carry NO credential. Relay URLs are
    /// operator-supplied (`[network].relay_urls`, `set_relays`), so a `https://user:token@host/`
    /// would otherwise ship that token to every local-API client on every reachability row.
    #[test]
    fn sanitize_relay_url_drops_credentials_and_path() {
        let u = |s: &str| -> iroh::RelayUrl { s.parse().expect("relay url") };

        assert_eq!(
            sanitize_relay_url(&u("https://user:token@relay.internal/")),
            "https://relay.internal",
            "userinfo must never reach the wire"
        );
        assert_eq!(
            sanitize_relay_url(&u("https://relay.example:4433/some/path?x=1")),
            "https://relay.example:4433",
            "port is kept (it names the relay); path/query are not"
        );
        assert_eq!(
            sanitize_relay_url(&u("https://relay.example/")),
            "https://relay.example"
        );
        // A self-hosted relay on a LAN address still renders — the field names WHICH relay is in
        // use, and an operator who points at an IP has already chosen to expose it.
        assert_eq!(
            sanitize_relay_url(&u("http://192.168.1.5:4433/")),
            "http://192.168.1.5:4433"
        );
    }

    /// #58 review: a SLOW probe that started earlier must not overwrite a FAST one that started
    /// later. Probes of one peer overlap routinely — `reachability_of` spawns a refresh per stale
    /// peer and both `status` and `subscribe` call it — and they complete out of order. Without
    /// this the timed-out older result wins on arrival, poisoning the cache for a full TTL AND
    /// pushing a false "went offline" for a peer that is up.
    #[test]
    fn a_probe_never_overwrites_a_newer_one() {
        let mut newer = entry(true, Some(50));
        newer.seq = 7;

        assert!(
            !supersedes(3, &newer),
            "an older probe (ticket 3) must not overwrite ticket 7's result"
        );
        assert!(
            supersedes(9, &newer),
            "a newer probe (ticket 9) must overwrite"
        );
        assert!(
            supersedes(7, &newer),
            "equal tickets cannot happen, but must not wedge the guard"
        );
    }

    /// #176: the mirror of the case above, which `supersedes` alone cannot express.
    ///
    /// `supersedes` orders by probe START, so the LAST-started probe always wins. Among
    /// overlapping probes that one is the most contended and therefore the likeliest to hit
    /// `PROBE_TIMEOUT` — so its `reachable: false` overwrote a pong that had already arrived, and
    /// the peer read offline for a full 20s TTL while demonstrably up.
    ///
    /// The rule is about EVIDENCE, not recency: a timeout says "no pong reached ME over my
    /// window"; a pong inside that same window says the peer was up. Every assertion below pins one
    /// conjunct, so dropping any of the three flips exactly one of them.
    #[test]
    fn a_timeout_never_overwrites_a_pong_that_landed_inside_its_window() {
        // Our probe started at ticket 5 and timed out.
        let ours = entry(false, None);

        // THE CASE. A pong committed at ticket 9 — after we started, so it landed inside our
        // window. Dropping `existing.observed > seq` (or comparing against `existing.seq`, which
        // is 0 here) makes this false and reinstates #176.
        let mut pong_inside = entry(true, Some(50));
        pong_inside.observed = 9;
        assert!(
            contradicted_by(&ours, 5, &pong_inside),
            "a pong observed at 9 is inside the window of a probe that started at 5 — our timeout \
             says nothing about a peer that answered someone else meanwhile"
        );

        // …and the peer is NOT wedged reachable. A probe that starts AFTER that pong carries a
        // higher ticket, so it commits normally — which is how a genuinely down peer is reported
        // down, one probe cycle later rather than never.
        assert!(
            !contradicted_by(&ours, 11, &pong_inside),
            "a probe that started after the last pong must be free to commit reachable: false"
        );

        // A REACHABLE result is never refused. Without the `!ours.reachable` conjunct this would
        // block a fresh pong from landing over an older one.
        let ours_ok = entry(true, Some(12));
        assert!(
            !contradicted_by(&ours_ok, 5, &pong_inside),
            "the guard is about timeouts; a pong must always be free to commit"
        );

        // Nor does an UNREACHABLE cached entry protect anything — there is no positive evidence to
        // contradict. Without the `existing.reachable` conjunct a down peer's row would freeze.
        let mut cached_down = entry(false, None);
        cached_down.observed = 9;
        assert!(
            !contradicted_by(&ours, 5, &cached_down),
            "an unreachable cached row is not evidence the peer answered; ours must commit"
        );
    }

    /// #176 at the CALL SITE, not the helper: `probe_peer` must actually consult `contradicted_by`
    /// before it writes.
    ///
    /// Deterministic, with no timing assertion. The peer id is unroutable on a hermetic mesh, so
    /// the probe is guaranteed to produce `reachable: false`; the cache is seeded with a reachable
    /// row whose `observed` is above every ticket the probe can draw, which is exactly "a pong
    /// landed after this probe started". `seq: 0` keeps the #58 rule satisfied, so this test can
    /// only fail on the #176 arm.
    ///
    /// Deleting that match arm makes `probe_peer` return `reachable: false` here and overwrite the
    /// cache — the reported bug, caught.
    #[tokio::test(flavor = "multi_thread")]
    async fn probe_peer_does_not_commit_a_timeout_over_a_pong_from_its_own_window() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let eid = [0x5Au8; 32];

        let mut pong = entry(true, Some(42));
        pong.seq = 0;
        pong.observed = u64::MAX; // observed after any ticket this probe can take
        mesh.reachability.lock().unwrap().insert(eid, pong);

        let got = super::probe_peer(&mesh, eid).await;
        assert!(
            got.reachable,
            "the unreachable probe must be DISCARDED and the surviving pong reported"
        );
        assert_eq!(
            got.rtt_ms,
            Some(42),
            "and it must be that pong's row, not a synthesised one"
        );
        assert!(
            mesh.reachability
                .lock()
                .unwrap()
                .get(&eid)
                .expect("row still cached")
                .reachable,
            "the CACHE must be left holding the pong — this is what pinned reachable:false for a \
             full TTL"
        );

        // The negative control, same call site: with the pong observed BEFORE this probe started,
        // the timeout is honest evidence and must commit. Without it the assertions above are also
        // satisfied by a `probe_peer` that never writes `reachable: false` at all.
        let mut stale_pong = entry(true, Some(42));
        stale_pong.seq = 0;
        stale_pong.observed = 0;
        mesh.reachability.lock().unwrap().insert(eid, stale_pong);
        let got = super::probe_peer(&mesh, eid).await;
        assert!(
            !got.reachable,
            "a peer that stopped answering must still be reported down — the guard only refuses \
             probes that were already in flight when the last pong landed"
        );
    }

    /// #176: `reachability_of` spawns ONE refresh per peer, not one per poll.
    ///
    /// The old v1 note called the missing dedup bounded because each probe self-limits once its
    /// result is cached. That bounds the probe COUNT and not the damage: a caller polling `status`
    /// faster than `PROBE_TIMEOUT` spawned a dial per poll, and the contention that produced is
    /// what made the last-started probe — the one the ordering rule preferred — the likeliest to
    /// time out.
    ///
    /// Asserted through `claim_refreshes`, the function the spawn loop calls, so this needs no
    /// runtime and no "wait and see if a probe started" timing assertion.
    #[tokio::test]
    async fn a_peer_already_being_refreshed_is_not_probed_again() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let (a, b) = ([1u8; 32], [2u8; 32]);

        let first = super::claim_refreshes(&mesh, vec![a, b]);
        assert_eq!(
            first.len(),
            2,
            "both peers are unclaimed, so both are refreshed"
        );

        // While those claims are alive, a second poll gets nothing.
        assert!(
            super::claim_refreshes(&mesh, vec![a, b]).is_empty(),
            "a peer with a refresh already in flight must not be dialled again"
        );
        // …and a peer that is NOT in flight still is — the dedup must be per peer, not a global
        // latch. Without this, dropping the whole claim set would also pass the assertion above.
        assert_eq!(
            super::claim_refreshes(&mesh, vec![[3u8; 32]]).len(),
            1,
            "an unclaimed peer must still be refreshed while others are in flight"
        );

        // Released on drop — including on a panicking or cancelled probe task, which is why the
        // claim is a guard rather than a `remove` at the end of the spawned future. A leaked claim
        // would silently stop refreshing that peer forever.
        drop(first);
        assert_eq!(
            super::claim_refreshes(&mesh, vec![a, b]).len(),
            2,
            "claims must be released when the refresh ends"
        );
    }

    /// #176 at the CALL SITE: `reachability_of` must HOLD the claim for the life of the probe, not
    /// merely take one.
    ///
    /// Found by mutation review, and this is why the helper test above is not enough: inserting
    /// `drop(guard);` before the `tokio::spawn` disables the dedup completely — one dial per poll,
    /// exactly the behaviour #176 removes — and leaves every other test in this module green.
    /// Nothing else in the tree names `probes_inflight`.
    ///
    /// **The claim must still be held when the call returns, and that needs the probe to still be
    /// RUNNING** — which is why this peer is given a routable-but-silent address.
    ///
    /// The first version claimed to be deterministic because "the claim is taken synchronously
    /// before the spawn". That reasoning is wrong, and CI proved it: the claim is taken
    /// synchronously, but on a multi-thread runtime the spawned task can RUN TO COMPLETION and drop
    /// the guard before the assertion executes. A peer with `last_addr: None` has no address to
    /// dial, so the probe fails instantly — the fastest possible loser of that race. It passed 5/5
    /// locally and failed on ubuntu.
    ///
    /// Pointing `last_addr` at a loopback port nothing listens on makes the dial hang until
    /// `PROBE_TIMEOUT` (3s), so the window the assertion reads is three seconds wide instead of
    /// nanoseconds. That is a bounded, sleeping wait in the code under test rather than a `sleep`
    /// in the test, and it keeps the mutation coverage the timing version was written for.
    #[tokio::test(flavor = "multi_thread")]
    async fn reachability_of_holds_its_refresh_claim_across_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        // A REAL endpoint id — `EndpointAddr` will not carry an arbitrary 32 bytes — pointed at a
        // port nothing is bound to.
        let peer_key = iroh::SecretKey::generate();
        let peer_id = peer_key.public();
        let eid = *peer_id.as_bytes();
        let black_hole: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let addr = iroh::EndpointAddr::from_parts(peer_id, [iroh::TransportAddr::Ip(black_hole)]);
        mesh.store
            .add(crate::allowlist::PeerEntry {
                endpoint_id: eid,
                nickname: "never-probed".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: Some(serde_json::to_string(&addr).unwrap()),
            })
            .unwrap();

        // Never probed → stale → a refresh is scheduled.
        let rows = super::reachability_of(&mesh);
        assert_eq!(rows.len(), 1, "the stored peer must be projected");
        assert!(
            mesh.probes_inflight.lock().unwrap().contains(&eid),
            "the refresh claim must still be HELD while the probe runs — a claim taken and \
             released before the spawn dedups nothing"
        );

        // …and while it is held, a second poll schedules nothing for that peer. This is the
        // property, read through the real entry point rather than the helper.
        assert!(
            super::claim_refreshes(&mesh, vec![eid]).is_empty(),
            "a second status poll inside the probe window must not spawn another dial"
        );
    }

    /// #58: the emit rule, exhaustively. A transition is a CHANGE in the `reachable` verdict (or
    /// first knowledge of the peer) — never a refresh that merely re-confirms it, which would emit
    /// a frame per TTL refresh for a peer that is simply staying up.
    #[test]
    fn only_a_change_in_the_reachable_verdict_is_a_transition() {
        // First knowledge is news ONLY when the peer is UP. The snapshot already reports an
        // unprobed peer as `reachable: false`, so a first probe confirming "down" restates it —
        // emitting that produced a spurious offline burst on every daemon restart (#58 review).
        assert!(
            is_transition(None, &entry(true, Some(9))),
            "first probe finds the peer UP — news"
        );
        assert!(
            !is_transition(None, &entry(false, None)),
            "first probe confirms DOWN — the snapshot already said so"
        );

        // The two real flips.
        assert!(
            is_transition(Some(&entry(false, None)), &entry(true, Some(9))),
            "came back online"
        );
        assert!(
            is_transition(Some(&entry(true, Some(9))), &entry(false, None)),
            "went offline"
        );

        // A refresh confirming the same verdict is NOT a transition, even when the advisory
        // detail moved — this is what keeps a healthy peer from emitting once per TTL.
        assert!(
            !is_transition(Some(&entry(true, Some(9))), &entry(true, Some(9))),
            "unchanged refresh"
        );
        assert!(
            !is_transition(Some(&entry(true, Some(9))), &entry(true, Some(120))),
            "rtt drift alone is not a transition"
        );
        assert!(
            !is_transition(Some(&entry(false, None)), &entry(false, None)),
            "still offline"
        );

        // #92: a PATH change IS a transition, even with the verdict unchanged — unlike rtt/meta
        // drift above. `Direct` is a truth claim about where the traffic went, so a silent
        // Direct -> Relay leaves an embedder rendering "private" about a relayed session.
        let mut relayed = entry(true, Some(9));
        relayed.path = mcpmesh_local_api::PeerPath::Relay { url: None };
        let mut direct = entry(true, Some(9));
        direct.path = mcpmesh_local_api::PeerPath::Direct;
        assert!(
            is_transition(Some(&direct), &relayed),
            "Direct -> Relay must emit: the privacy indicator just became wrong"
        );
        assert!(
            is_transition(Some(&relayed), &direct),
            "and Relay -> Direct, so a recovered session can be relabelled"
        );
        assert!(
            !is_transition(Some(&direct), &direct.clone()),
            "but an unchanged path still does not emit once per TTL"
        );

        // Metadata drift alone is likewise not a transition.
        let mut with_meta = entry(true, Some(9));
        with_meta.meta = "status: away".into();
        assert!(
            !is_transition(Some(&entry(true, Some(9))), &with_meta),
            "meta drift alone is not a transition"
        );
    }

    /// The probe RECEIVE cap (#40): a pong's `meta` is surfaced only when it is a string within
    /// the ≤256B cap — a missing, non-string, or OVERSIZED value (a compromised paired peer
    /// signing nothing, just sending bytes over the authenticated channel) yields empty, so the
    /// prober never caches or surfaces an unbounded/garbage blob.
    #[test]
    fn pong_services_parses_the_array_and_tolerates_hostile_shapes() {
        use super::pong_services;
        assert_eq!(
            pong_services(&serde_json::json!({"services": ["notes", "kb"]})),
            vec!["notes".to_string(), "kb".to_string()]
        );
        assert!(pong_services(&serde_json::json!({"stack_version": "1"})).is_empty());
        assert!(pong_services(&serde_json::json!({"services": 42})).is_empty());
        assert!(pong_services(&serde_json::json!({"services": [1, {"x": 2}]})).is_empty());
    }

    /// #52: `caller_admitted_services` returns exactly the services whose allow admits the
    /// caller's principal — its eid, user_id, or a group — never the full registry.
    #[tokio::test(flavor = "multi_thread")]
    async fn caller_admitted_services_returns_only_admitted() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let caller_eid = mcpmesh_net::EndpointId::from_bytes([7u8; 32]).principal();
        std::fs::write(
            &config_path,
            format!(
                "[services.shared]\nsocket = \"/run/a.sock\"\nallow = [\"{caller_eid}\"]\n                 [services.grouped]\nsocket = \"/run/b.sock\"\nallow = [\"team-eng\"]\n                 [services.private]\nsocket = \"/run/c.sock\"\nallow = [\"eid:other\"]\n"
            ),
        )
        .unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(config_path).await;

        // The caller: its eid admits `shared`; its group admits `grouped`; `private` is neither.
        let identity = mcpmesh_net::PeerIdentity {
            endpoint: mcpmesh_net::EndpointId::from_bytes([7u8; 32]),
            name: "bob".into(),
            user_id: None,
            groups: vec!["team-eng".into()],
        };
        let admitted = super::caller_admitted_services(&mesh, &identity);
        assert_eq!(admitted, vec!["grouped".to_string(), "shared".to_string()]);
        assert!(
            !admitted.contains(&"private".to_string()),
            "never a non-admitted service"
        );
    }

    #[test]
    fn pong_meta_extracts_within_cap_and_drops_the_rest() {
        assert_eq!(
            pong_meta(&serde_json::json!({"stack_version": "1", "meta": "v=1.2.3"})),
            "v=1.2.3"
        );
        // No meta field → empty.
        assert_eq!(pong_meta(&serde_json::json!({"stack_version": "1"})), "");
        // Non-string meta → empty (never panics on hostile shapes).
        assert_eq!(pong_meta(&serde_json::json!({"meta": 42})), "");
        assert_eq!(pong_meta(&serde_json::json!({"meta": {"x": 1}})), "");
        // Exactly at the cap is kept; one over is dropped.
        let at = "x".repeat(APP_METADATA_MAX_BYTES);
        assert_eq!(pong_meta(&serde_json::json!({"meta": at.clone()})), at);
        let over = "x".repeat(APP_METADATA_MAX_BYTES + 1);
        assert_eq!(
            pong_meta(&serde_json::json!({"meta": over})),
            "",
            "oversized meta dropped"
        );
    }
}
