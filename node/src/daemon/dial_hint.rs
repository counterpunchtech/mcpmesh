//! Keeping the persisted dial hint honest (#124).
//!
//! `PeerEntry::last_addr` is the pairing-proven dial-back hint: the address we attach to a dial so
//! a just-paired peer is reachable without waiting on discovery (#27). Until now it was written in
//! exactly ONE place — the pairing rendezvous — and never updated again.
//!
//! That made it permanently wrong the moment a peer changed networks. `stored_dial_addr` REPLACES
//! the bare-id dial with the hint, so a stale entry means the direct-candidate set is exactly one
//! dead address: every dial and every probe offers iroh that address, fails, and falls back to the
//! relay. Forever, because nothing rewrote it. An embedder measured it as a whole fleet stuck on
//! relay at ~800ms while a freshly-paired identity on the same two machines punched direct at
//! 11-23ms, and it survived daemon restarts because the hint lives in redb (#124).
//!
//! The fix is to refresh the hint from a peer we are demonstrably talking to. A live authenticated
//! connection knows the remote's ACTUAL address; that is ground truth, and writing it back makes
//! the hint self-healing across network changes. A stale hint then costs one failed attempt rather
//! than being permanent.

use std::sync::Arc;

use super::MeshState;

/// Refresh `last_addr` for `endpoint_id` from a LIVE connection, if it has changed (#124).
///
/// Best-effort and deliberately quiet: this is cache maintenance on a path whose real job is
/// already done, so every failure — an unknown peer, an empty path snapshot, a serialize error, a
/// redb write error — leaves the stored hint exactly as it was. A stale hint is a slow dial; a
/// *wrong* write could be worse, so the bar for replacing one is a connection that is up.
///
/// **Only writes on a CHANGE.** A dial per session times a redb write per session would put a
/// blocking disk write on every connection for a value that changes approximately never.
///
/// **Never downgrades `Some` to `None`**, matching the pairing path's rule: an empty path snapshot
/// means we learned nothing, not that the peer has no address.
pub(crate) fn refresh(
    mesh: &Arc<MeshState>,
    endpoint_id: [u8; 32],
    conn: &iroh::endpoint::Connection,
) {
    let Some(observed) = observed_addr(conn) else {
        return; // learned nothing — keep what we have
    };
    let mesh = mesh.clone();
    // The redb read+write blocks; keep it off the runtime (the fs house rule).
    tokio::task::spawn_blocking(move || write_if_changed(&mesh, endpoint_id, observed));
}

/// The store half of [`refresh`], separated so the rules are testable without a live connection:
/// replace a changed hint, skip an unchanged one, and never CREATE a peer.
fn write_if_changed(mesh: &Arc<MeshState>, endpoint_id: [u8; 32], observed: String) {
    let Ok(Some(mut entry)) = mesh.store.resolve(&endpoint_id) else {
        return; // not a stored peer (a bare eid probe, say) — nothing to refresh
    };
    if entry.last_addr.as_deref() == Some(observed.as_str()) {
        return; // unchanged, and the common case: no write
    }
    tracing::debug!(
        peer = %entry.nickname,
        "refreshing dial hint from a live connection (#124)"
    );
    entry.last_addr = Some(observed);
    if let Err(e) = mesh.store.add(entry) {
        // Cache maintenance: the session is already up and unaffected.
        tracing::debug!(%e, "could not persist refreshed dial hint");
    }
}

/// The remote's addresses as this connection actually sees them, serialized the way
/// [`crate::allowlist::PeerEntry::last_addr`] stores them.
///
/// `None` when the snapshot is empty or serialization fails — both mean "learned nothing", which
/// the caller must treat as leave-alone rather than clear.
fn observed_addr(conn: &iroh::endpoint::Connection) -> Option<String> {
    let addrs: Vec<iroh::TransportAddr> = conn
        .paths()
        .iter()
        .map(|p| p.remote_addr().clone())
        .collect();
    if addrs.is_empty() {
        return None;
    }
    serde_json::to_string(&iroh::EndpointAddr::from_parts(conn.remote_id(), addrs)).ok()
}

#[cfg(test)]
mod tests {
    use crate::allowlist::PeerEntry;

    /// #124: a hint that has gone stale must be REPLACED by what a live connection observes.
    ///
    /// This is the bug the embedder measured: after a network change both roots held each other's
    /// pre-change address, `stored_dial_addr` handed iroh that one dead address as the entire
    /// direct-candidate set, and every session fell back to the relay — permanently, because
    /// nothing rewrote the hint. A freshly-paired identity on the same hardware punched direct.
    ///
    /// Driven through the same store the daemon uses, with the observed address supplied directly:
    /// pinning it through a real network change would need two machines and a hotspot.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stale_hint_is_replaced_and_an_unchanged_one_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let eid = [3u8; 32];

        let stale = r#"{"id":"stale","addrs":[]}"#.to_string();
        mesh.store
            .add(PeerEntry {
                endpoint_id: eid,
                nickname: "bob".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: Some(stale.clone()),
            })
            .unwrap();

        // What a live connection would observe now — a DIFFERENT address.
        let fresh = r#"{"id":"fresh","addrs":[]}"#.to_string();
        super::write_if_changed(&mesh, eid, fresh.clone());
        assert_eq!(
            mesh.store.resolve(&eid).unwrap().unwrap().last_addr,
            Some(fresh.clone()),
            "a live observation must overwrite a stale hint — leaving it is #124: the peer is \
             dialed at a dead address forever and every session falls back to the relay"
        );

        // Re-observing the SAME address must not rewrite the row: a redb write per session for a
        // value that changes approximately never.
        let before = mesh.store.resolve(&eid).unwrap().unwrap();
        super::write_if_changed(&mesh, eid, fresh.clone());
        let after = mesh.store.resolve(&eid).unwrap().unwrap();
        assert_eq!(after.last_addr, before.last_addr);

        // An unknown peer is not invented — refresh is maintenance on a stored row, not a source
        // of trust. A bare-eid probe must never create an allowlist entry.
        super::write_if_changed(&mesh, [9u8; 32], fresh);
        assert!(
            mesh.store.resolve(&[9u8; 32]).unwrap().is_none(),
            "refreshing must never CREATE a peer — that would be an authorization path"
        );

        // The identity fields the pairing path protects are untouched.
        let row = mesh.store.resolve(&eid).unwrap().unwrap();
        assert_eq!(row.nickname, "bob");
        assert_eq!(row.endpoint_id, eid);
    }
}
