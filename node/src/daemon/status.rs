//! The `status`-facing projections: live roster-mode status, the advisory presence read, and
//! the surface-clean service/peer views — all computed LIVE from the config, store,
//! and gate on each call, never from a cached snapshot.

use std::sync::Arc;

use mcpmesh_local_api::{BackendKind, PeerInfo, PresencePeer, RosterStatus, ServiceInfo};
use mcpmesh_trust::roster::validate::RosterState;

use crate::allowlist::PeerStore;
use crate::config::{Backend, Config};
use crate::pairing;
use crate::util::epoch_now_i64;

use super::{MeshState, dial};

/// Live roster-mode status for `status`. **Computed LIVE from `mesh.roster.view()` on
/// each call — NOT a cached snapshot (DECLARED):** the roster view is already hot-swapped into the
/// gate on install, so a live read is cheap AND always-current, avoiding the display-only staleness
/// the pairing-grant snapshot path carries. Surface-clean: only org_id, serial, a plain state
/// word, and the org-root FINGERPRINT in short words — never raw keys/EndpointIds/roster path.
///
/// Three cases (DECLARED): (1) a roster is installed → the live `state` word. (2) NO roster installed
/// but an org root is PINNED (post-`join`, pre-approval) → `"pending"` with serial 0 + the
/// pinned org-root fingerprint, so `status` shows the anchor immediately after `join`. (3) a
/// pure-pairing daemon (no `org_root_pk` pin at all) → `None`, no roster block.
///
/// State mapping (DECLARED): `Approved → "approved"`, `DegradedGrace → "degraded"`,
/// `DegradedStopped → "stopped"`; no roster + pinned org → `"pending"`. The word is the gate's OWN
/// [`RosterGate::effective_state`] (expiry ∨ staleness) — the SAME computation `resolve`
/// decides on — so `status` reflects STALENESS, not just expiry.
///
/// Missing/unparseable pin (DECLARED): the org-root FINGERPRINT is derived from the pinned config
/// `org_root_pk`. If that pin is missing or unparseable (or the config read fails), the fingerprint
/// degrades GRACEFULLY to an empty string — NEVER a panic — and roster status still reports
/// org/serial/state (the render then omits the `org root:` line).
pub(crate) fn roster_status(mesh: &Arc<MeshState>, cfg: Option<&Config>) -> Option<RosterStatus> {
    // `cfg` is the caller's ALREADY-LOADED config (control.rs `status_result` loads it once for the
    // live service list and passes it through — the host polls status, so the double read mattered).
    // `None` models a transient read error, which must not fail `status`: fall back to an empty
    // fingerprint (and the "pending"/None cases below). Only the pinned org-root pk / org_id are
    // read from it — the state word comes from the gate's own `effective_state`.
    // The pinned org-root FINGERPRINT in short words. Decode the config b64u
    // `org_root_pk` → 32 bytes → fingerprint_words; a missing/unparseable pin → empty (no panic).
    let org_root_fingerprint = cfg
        .and_then(|c| c.identity.org_root_pk.as_deref())
        .and_then(|s| crate::roster::parse_org_root_pk(s).ok())
        .map(|vk| pairing::sas::fingerprint_words(&vk.to_bytes()))
        .unwrap_or_default();
    match mesh.roster.view() {
        Some(view) => {
            // The state word from the gate's OWN `effective_state` (expiry ∨ staleness)
            // — the SAME computation `resolve` decides on, so `status` reflects staleness, not just
            // expiry. `view` is Some here, so `effective_state` is Some (the `unwrap_or` never fires).
            let state = match mesh
                .roster
                .effective_state(epoch_now_i64())
                .unwrap_or(RosterState::Approved)
            {
                RosterState::Approved => "approved",
                RosterState::DegradedGrace => "degraded",
                RosterState::DegradedStopped => "stopped",
            };
            Some(RosterStatus {
                org_id: view.org_id().to_string(),
                serial: view.serial(),
                state: state.to_string(),
                org_root_fingerprint,
            })
        }
        None => {
            // Post-`join`, pre-approval: a pinned org root but no roster yet → "pending". A
            // pure-pairing daemon (no `org_root_pk` pin) has nothing to surface → None → no block.
            let cfg = cfg?;
            cfg.identity.org_root_pk.as_deref()?;
            Some(RosterStatus {
                org_id: cfg.identity.org_id.clone().unwrap_or_default(),
                serial: 0,
                state: "pending".to_string(),
                org_root_fingerprint,
            })
        }
    }
}

/// The advisory presence read for `status`. Enumerates every ACTIVE roster device and
/// joins it with the presence table: display fields (user_id, device_label, role) come from the
/// installed roster; `online` is whether the table holds a LIVE (non-expired) heartbeat for that
/// endpoint (`PresenceTable::active`). ADVISORY-ONLY — a display convenience; NOTHING here authorizes
/// a dial. A device with no heartbeat reports `online: false` yet remains a full dial candidate
/// (absence never removes one). Empty in a pure-pairing daemon / before any roster is installed (the
/// field then serializes away). **Surface-clean:** the endpoint_id is used ONLY to join the
/// roster and presence tables — the output carries FLAT vocabulary alone (user_id/device_label/role/
/// online), never an EndpointId/pubkey/hash. Stable display order: by user, primary before mirror,
/// then label.
pub(crate) fn presence_peers(mesh: &Arc<MeshState>) -> Vec<PresencePeer> {
    let Some(view) = mesh.roster.view() else {
        return Vec::new();
    };
    let now = epoch_now_i64();
    let online: std::collections::HashSet<[u8; 32]> = mesh
        .presence_table
        .active(now)
        .into_iter()
        .map(|(eid, _)| eid)
        .collect();
    let mut peers: Vec<PresencePeer> = view
        .devices()
        .map(|(eid, d)| PresencePeer {
            user_id: d.user_id.clone(),
            device_label: d.label.clone(),
            role: d.role.clone(),
            online: online.contains(eid),
        })
        .collect();
    peers.sort_by(|a, b| {
        a.user_id
            .cmp(&b.user_id)
            .then_with(|| dial::dial_role_rank(&a.role).cmp(&dial::dial_role_rank(&b.role)))
            .then_with(|| a.device_label.cmp(&b.device_label))
    });
    peers
}

/// The `status`-facing view of the configured services (name, allow, backend KIND only — no
/// command/path). Malformed entries are omitted (they are not served either).
pub(crate) fn service_infos(
    cfg: &Config,
    ephemeral: &std::collections::HashMap<String, crate::daemon::EphemeralService>,
) -> Vec<ServiceInfo> {
    let mut out: Vec<ServiceInfo> = cfg
        .services
        .iter()
        .filter_map(|(name, svc)| {
            let backend = match svc.backend_result() {
                Ok(Backend::Run(_)) => BackendKind::Run,
                Ok(Backend::Socket(_)) => BackendKind::Socket,
                Err(_) => return None,
            };
            Some(ServiceInfo {
                name: name.clone(),
                allow: svc.allow.clone(),
                backend,
                ephemeral: false,
            })
        })
        .collect();
    // Ephemeral registrations (#36): in-memory only, flagged so a consumer knows they vanish on
    // disconnect/restart. Same surface discipline — kind only, never the command/path.
    for (name, eph) in ephemeral {
        let backend = match &eph.backend {
            mcpmesh_local_api::BackendSpec::Run { .. } => BackendKind::Run,
            mcpmesh_local_api::BackendSpec::Socket { .. } => BackendKind::Socket,
        };
        out.push(ServiceInfo {
            name: name.clone(),
            allow: eph.allow.clone(),
            backend,
            ephemeral: true,
        });
    }
    out
}

/// The `status`-facing view of known peers (nickname + granted services — never the
/// EndpointId). Fails open on a corrupt store row (see [`PeerStore::list`]).
pub(crate) fn peer_infos(store: &PeerStore) -> Vec<PeerInfo> {
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|e| PeerInfo {
            name: e.nickname,
            services: e.services,
            // The peer's proven self-sovereign user_id (from a verified pairing binding), or `None`
            // for a nickname-only / `internal peer add` peer. A surface-clean opaque id, not a key.
            user_id: e.user_id,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::allowlist::PeerEntry;
    use crate::daemon::config_write::append_allow_to_config;
    use crate::daemon::testutil::hermetic_mesh;

    /// `status` reflects the LIVE config + store on every call. A pairing grant
    /// (grant_service_access → allow-append) and a rendezvous PeerEntry write land durably
    /// WITHOUT touching `DaemonState`; `status` must still show the just-granted allow + the
    /// just-paired peer (the Jetson-proof "status says `allowed: no one yet` right after
    /// pairing" confusion). Models the flows faithfully by mutating the config + store directly
    /// (exactly what grant + rendezvous do to the durable state).
    #[tokio::test(flavor = "multi_thread")]
    async fn status_reads_the_live_config_and_store() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());

        // Durable mutations exactly as grant + rendezvous perform them: append the grant to the
        // config, and write the peer's PeerEntry straight to the store.
        append_allow_to_config(&config_path, "alice", &["kb".to_string()]).unwrap();
        mesh.store
            .add(PeerEntry {
                endpoint_id: [9u8; 32],
                nickname: "alice".into(),
                services: Vec::new(),
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        // Status must reflect the LIVE truth.
        let status = crate::control::status_result(&state).unwrap();
        let kb = status
            .services
            .iter()
            .find(|s| s.name == "kb")
            .expect("kb service in status");
        assert!(
            kb.allow.contains(&"alice".to_string()),
            "status must show the live grant, got allow={:?}",
            kb.allow
        );
        assert!(
            status.peers.iter().any(|p| p.name == "alice"),
            "status must show the live peer, got peers={:?}",
            status.peers
        );
    }

    /// Status surfaces self-sovereign identity (the adopted device->user binding): the daemon's OWN
    /// `self_user_id` (from its self-binding) and each paired peer's PROVEN `user_id` (from its
    /// `PeerEntry`). A peer that presented no binding stays nickname-only (`user_id: None`).
    #[tokio::test]
    async fn status_surfaces_self_and_peer_user_ids() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = []\n",
        )
        .unwrap();
        let mesh = hermetic_mesh(config_path.clone()).await;
        mesh.set_self_binding(Some(crate::pairing::rendezvous::SelfBinding {
            user_pk: "b64u:selfpk".into(),
            sig: "b64u:selfsig".into(),
        }));
        // One peer that proved a self-sovereign user_id at pairing, one legacy nickname-only peer.
        mesh.store
            .add(PeerEntry {
                endpoint_id: [1u8; 32],
                nickname: "alice".into(),
                services: Vec::new(),
                paired_at: Some("1".into()),
                user_id: Some("b64u:alicepk".into()),
                last_addr: None,
            })
            .unwrap();
        mesh.store
            .add(PeerEntry {
                endpoint_id: [2u8; 32],
                nickname: "legacy".into(),
                services: Vec::new(),
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        let state = crate::control::DaemonState::with_mesh("test", mesh.clone());
        let status = crate::control::status_result(&state).unwrap();

        assert_eq!(
            status.self_user_id.as_deref(),
            Some("b64u:selfpk"),
            "status must surface this daemon's own self-sovereign user_id"
        );
        let alice = status
            .peers
            .iter()
            .find(|p| p.name == "alice")
            .expect("alice in status");
        assert_eq!(
            alice.user_id.as_deref(),
            Some("b64u:alicepk"),
            "a paired peer's PROVEN user_id must be surfaced in status"
        );
        let legacy = status
            .peers
            .iter()
            .find(|p| p.name == "legacy")
            .expect("legacy in status");
        assert!(
            legacy.user_id.is_none(),
            "a nickname-only peer stays user_id: None"
        );
    }

    /// The recent-pairings ring is BOUNDED (cap 8, oldest dropped), snapshots NEWEST FIRST, and
    /// `status_result` surfaces it (display-only ceremony state; empty in a control-only
    /// daemon — covered by control.rs's snapshot tests, whose StatusResult omits the field).
    #[tokio::test]
    async fn recent_pairings_ring_is_bounded_newest_first_and_surfaced_by_status() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mesh = hermetic_mesh(config_path).await;
        for i in 0..10u64 {
            mesh.record_pairing(format!("peer{i}"), format!("code-{i}"), i);
        }
        let recent = mesh.recent_pairings();
        assert_eq!(recent.len(), 8, "the ring is capped at 8");
        assert_eq!(recent[0].peer_nickname, "peer9", "newest first");
        assert_eq!(
            recent[7].peer_nickname, "peer2",
            "the two oldest were dropped"
        );

        let state = crate::control::DaemonState::with_mesh("test", mesh);
        let status = crate::control::status_result(&state).unwrap();
        assert_eq!(status.recent_pairings.len(), 8);
        assert_eq!(status.recent_pairings[0].sas_code, "code-9");
        assert_eq!(status.recent_pairings[0].paired_at_epoch, 9);
    }
}
