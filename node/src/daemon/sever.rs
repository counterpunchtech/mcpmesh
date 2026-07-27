//! Principal → live-connection resolution for the pairing-mode revoke paths ().
//!
//! `service_allow_revoke` and `peer_remove` strip a principal from the config `allow` and reload,
//! which stops NEW sessions. Cutting the sessions already in flight needs the set of ENDPOINTS
//! that principal names, which is what this module computes — the input to
//! [`ConnRegistry::sever_matching`](mcpmesh_net::registry::ConnRegistry::sever_matching).
//!
//! Pairing mode only, deliberately: roster-driven revocation already severs through
//! [`install_roster_view_and_sever`](super::install_roster_view_and_sever), which computes its
//! sever set from the installed roster view. Duplicating that here would double-sever and could
//! disagree with the roster's own rules.

use std::collections::HashSet;

use mcpmesh_net::EndpointId;

use crate::allowlist::PeerStore;

/// Every STORED endpoint the stable `principal` names: the device whose `eid:` rendering matches,
/// or EVERY device carrying that `user_id` (a person principal covers all of their devices, the
/// same expansion the allow-list check uses).
///
/// Matching RENDERS each stored endpoint rather than PARSING the principal, so both forms are
/// handled without a new parser and an unrecognized principal resolves to the empty set — which
/// severs nothing. That fail-open-to-nothing default is the safe direction here: over-severing
/// would cut connections the operator never revoked.
///
/// Note the boundary: this is the *liveness* half of a revoke. The authorization half is the
/// config `allow` strip plus the live-registry swap; a peer whose entry is deleted outright is
/// already denied at gate resolve.
pub(crate) fn endpoints_for_principal(
    store: &PeerStore,
    principal: &str,
) -> anyhow::Result<HashSet<EndpointId>> {
    let mut out = HashSet::new();
    for entry in store.list()? {
        let eid = EndpointId::from_bytes(entry.endpoint_id);
        if eid.principal() == principal || entry.user_id.as_deref() == Some(principal) {
            out.insert(eid);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::PeerEntry;

    /// A store holding `(endpoint byte, user_id, nickname)` rows.
    fn store_with(rows: &[(u8, Option<&str>, &str)]) -> (PeerStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = PeerStore::open(&tmp.path().join("state.redb")).expect("open store");
        for (b, user_id, nickname) in rows {
            store
                .add(&PeerEntry {
                    endpoint_id: [*b; 32],
                    nickname: (*nickname).to_string(),
                    services: vec![],
                    paired_at: None,
                    user_id: user_id.map(|u| u.to_string()),
                    addr: None,
                })
                .expect("add peer");
        }
        (store, tmp)
    }

    /// The resolution rule, exhaustively: an `eid:` principal is ONE device, a `user_id` principal
    /// is EVERY device of that person, and an unknown principal is nothing (never over-severs).
    #[test]
    fn endpoints_for_principal_resolves_eid_and_user_id_and_nothing_else() {
        let (store, _tmp) = store_with(&[
            (1, Some("b64u:ann"), "ann-laptop"),
            (2, Some("b64u:ann"), "ann-phone"),
            (3, None, "bob"),
        ]);
        let eid = |b: u8| EndpointId::from_bytes([b; 32]);
        let set = |ids: &[u8]| ids.iter().map(|b| eid(*b)).collect::<HashSet<_>>();

        assert_eq!(
            endpoints_for_principal(&store, &eid(1).principal()).unwrap(),
            set(&[1]),
            "an eid: principal names exactly its own device"
        );
        assert_eq!(
            endpoints_for_principal(&store, "b64u:ann").unwrap(),
            set(&[1, 2]),
            "a user_id principal names every device of that person"
        );
        assert_eq!(
            endpoints_for_principal(&store, &eid(3).principal()).unwrap(),
            set(&[3]),
            "a device with no user_id still resolves by its eid:"
        );
        assert!(
            endpoints_for_principal(&store, "b64u:nobody")
                .unwrap()
                .is_empty(),
            "an unknown principal must sever nothing"
        );
    }
}
