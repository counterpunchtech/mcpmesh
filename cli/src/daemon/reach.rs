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
}

/// Advisory reachability TTL: a cache entry older than this is refreshed by a NON-BLOCKING
/// background probe on the next [`reachability_of`] read.
pub const REACH_TTL_SECS: i64 = 20;

/// The reachability probe's hard deadline — a peer that has not ponged within this window is
/// reported unreachable. No retries/backoff/persistence (YAGNI); reachable ⇔ a pong in time.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe one peer over [`ALPN_PING`] and cache the result. Dials the peer BY ID (an id-only
/// [`iroh::EndpointAddr`], exactly like `dial::dial_service`'s single-petname fallback — discovery resolves
/// the address from the id; hermetic localhost tests seed a `MemoryLookup`), sends one ping frame,
/// reads the pong, and measures RTT (dial + round-trip). Writes the outcome into the in-memory
/// `MeshState::reachability` cache and returns it. Reachable ⇔ a pong arrived within
/// `PROBE_TIMEOUT`; a gate refusal (no pong) or any dial/IO failure is a clean `reachable:false`.
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
/// Surface discipline: the cache is keyed by endpoint-id INTERNALLY, but every returned
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
