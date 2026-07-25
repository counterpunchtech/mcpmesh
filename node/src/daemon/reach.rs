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
}

/// Advisory reachability TTL: a cache entry older than this is refreshed by a NON-BLOCKING
/// background probe on the next [`reachability_of`] read.
pub const REACH_TTL_SECS: i64 = 20;

/// The reachability probe's hard deadline — a peer that has not ponged within this window is
/// reported unreachable. No retries/backoff/persistence (YAGNI); reachable ⇔ a pong in time.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe one peer over [`ALPN_PING`] and cache the result. Dials the peer by id WITH its stored
/// `last_addr` hint attached when usable, exactly like `dial::dial_service`'s single-nickname
/// fallback (discovery still resolves/merges addresses; hermetic localhost tests seed a
/// `MemoryLookup` or store a hint), sends one ping frame,
/// reads the pong, and measures RTT (dial + round-trip). Writes the outcome into the in-memory
/// `MeshState::reachability` cache and returns it. Reachable ⇔ a pong arrived within
/// `PROBE_TIMEOUT`; a gate refusal (no pong) or any dial/IO failure is a clean `reachable:false`.
pub async fn probe_peer(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> ReachEntry {
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(PROBE_TIMEOUT, probe_once(mesh, endpoint_id)).await;
    // `probe_once` returns the peer's (already length-capped) metadata on a reachable pong.
    let (reachable, meta, services) = match outcome {
        Ok(Ok((meta, services))) => (true, meta, services),
        _ => (false, String::new(), Vec::new()),
    };
    let entry = ReachEntry {
        reachable,
        rtt_ms: reachable.then(|| started.elapsed().as_millis() as u64),
        probed_at: epoch_now_i64(),
        meta,
        services,
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
async fn probe_once(mesh: &Arc<MeshState>, endpoint_id: [u8; 32]) -> Result<(String, Vec<String>)> {
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
        Some(Inbound::Frame(v)) => Ok((pong_meta(&v), pong_services(&v))),
        _ => anyhow::bail!("no pong from peer"),
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

    let mut out: Vec<String> = Vec::new();
    if let Ok(cfg) = crate::config::Config::load(&mesh.config_path) {
        for (name, svc) in &cfg.services {
            if admits(&svc.allow) {
                out.push(name.clone());
            }
        }
    }
    for (name, eph) in mesh
        .ephemeral_services
        .lock()
        .expect("ephemeral_services lock not poisoned")
        .iter()
    {
        if admits(&eph.allow) && !out.contains(name) {
            out.push(name.clone());
        }
    }
    out.sort();
    out
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
                out.push(mcpmesh_local_api::PeerReachability {
                    name: nickname,
                    reachable: e.reachable,
                    rtt_ms: e.rtt_ms,
                    age_secs: Some(age as u64),
                    meta: e.meta.clone(),
                    // #42: the eid: device principal, so a row joins to the authenticated
                    // endpoint rather than the non-unique nickname.
                    principal: Some(mcpmesh_net::EndpointId::from_bytes(eid).principal()),
                });
            }
            None => {
                stale.push(eid);
                out.push(mcpmesh_local_api::PeerReachability {
                    name: nickname,
                    reachable: false,
                    rtt_ms: None,
                    age_secs: None, // never probed → consumer shows "checking…"
                    meta: String::new(),
                    principal: Some(mcpmesh_net::EndpointId::from_bytes(eid).principal()),
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

#[cfg(test)]
mod tests {
    use super::pong_meta;
    use crate::roster::presence::APP_METADATA_MAX_BYTES;

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
