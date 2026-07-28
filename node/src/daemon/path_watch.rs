//! Live path-change watching (#92 item 2): one watcher per USER session, so a session whose
//! selected path changes mid-flight pushes a `Reachability` frame when it happens.
//!
//! #92 item (1) shipped in 0.19.0 and made `is_transition` compare `path`, so a PROBE observing a
//! changed path emits. That removed "no event, ever"; it did not give live signal. Probes are
//! TTL-gated (20s) and only run when `status`/`subscribe` asks, so a session that degrades
//! Direct→Relay mid-call stays silently mislabelled until something probes — possibly never.
//!
//! That matters because `path` is documented as a TRUTH CLAIM, not drift: `Direct` is the only
//! value supporting a locality claim. An embedder can render the indicator correctly at dial time
//! and have it become wrong for the rest of a long-lived session.
//!
//! **The decision logic here is deliberately PURE.** The network loop is a thin shell over
//! [`decide`], because the alternative — pinning the flap/`Lagged`/unchanged rules through a real
//! hole-punch — is how #110's suite ended up passing whether or not the behaviour was present.
//! Timing-dependent tests over a real network are where vacuity hides.

use std::time::Duration;

use mcpmesh_local_api::PeerPath;

/// How long a changed path must HOLD before it is worth telling anyone (#92 item 2).
///
/// Hole-punching flaps by nature — that was #64's stated reason for excluding `path` from
/// transitions altogether. A `path_events()` watcher sees every change, including the ordinary
/// relay→direct transition of a healthy dial, so it needs its own damping. Same 600ms as
/// `reach::PATH_SETTLE` and for the same reason: it is the measured time for a loopback punch to
/// settle, and it is well inside any session's lifetime.
// Consumed by the watcher loop in the next commit (Task 3); CI runs clippy -D warnings, so the
// gap between the pure rule landing and its caller landing must not leave the branch red.
#[allow(dead_code)]
pub(crate) const PATH_CHANGE_SETTLE: Duration = Duration::from_millis(600);

/// Should an observation be committed and emitted?
///
/// Pure so the rules are testable without a relay. `observed` is the path the connection reports
/// now; `cached` is what the reachability cache already says (`None` when the peer has no entry).
///
/// Returns the value to commit, or `None` to stay quiet. The rule is deliberately narrow: emit
/// only when the observation DIFFERS from what a consumer already believes. A watcher that emits
/// on every event turns a flapping connection into a frame storm, which is the noise #64 avoided
/// by excluding `path` entirely.
#[allow(dead_code)]
pub(crate) fn decide(observed: &PeerPath, cached: Option<&PeerPath>) -> Option<PeerPath> {
    // `Unknown` is never worth emitting: it means "we do not know", and pushing it would replace a
    // consumer's correct belief with an absence of one. A connection tearing down reports Unknown
    // routinely, and its path is about to stop mattering anyway.
    if matches!(observed, PeerPath::Unknown) {
        return None;
    }
    match cached {
        Some(known) if known == observed => None,
        _ => Some(observed.clone()),
    }
}

/// Commit a settled observation for `endpoint_id` and emit if it changed anything.
///
/// **The watcher is a SECOND writer to the reachability cache**, alongside `probe_peer`. That is
/// the hazard here, not the emission. `seq` must be a ticket taken BEFORE observing, exactly as
/// `probe_peer` does, so an in-flight 3s probe that started earlier cannot land later and overwrite
/// a fresher live observation — which would re-poison the cache for a full TTL and, since #58, push
/// a stale path a consumer then renders as a privacy claim.
///
/// Only `path` is the watcher's to set. `reachable`/`rtt_ms`/`meta`/`services` come from a probe's
/// pong; a live connection carrying data IS reachability evidence, but inventing an `rtt_ms` from a
/// path event would be a fabricated measurement, so a seeded entry carries `rtt_ms: None`.
#[allow(dead_code)]
pub(crate) fn commit_observation(
    mesh: &std::sync::Arc<super::MeshState>,
    endpoint_id: [u8; 32],
    seq: u64,
    observed: &PeerPath,
) -> Option<mcpmesh_local_api::PeerReachability> {
    let committed = {
        let mut cache = mesh
            .reachability
            .lock()
            .expect("reachability lock not poisoned");
        // A NEWER writer already landed — drop ours rather than moving the cache backwards.
        if let Some(existing) = cache.get(&endpoint_id)
            && !super::reach::supersedes(seq, existing)
        {
            return None;
        }
        let cached = cache.get(&endpoint_id).map(|e| e.path.clone());
        let path = decide(observed, cached.as_ref())?;
        match cache.get_mut(&endpoint_id) {
            Some(entry) => {
                entry.path = path.clone();
                entry.seq = seq;
                entry.probed_at = crate::util::epoch_now_i64();
                entry.clone()
            }
            None => {
                // First knowledge, from a LIVE session: it is up by construction — we are talking
                // to it — but we have measured no RTT and hold none of its pong metadata.
                let entry = super::ReachEntry {
                    reachable: true,
                    rtt_ms: None,
                    probed_at: crate::util::epoch_now_i64(),
                    meta: String::new(),
                    services: Vec::new(),
                    seq,
                    path,
                };
                cache.insert(endpoint_id, entry.clone());
                entry
            }
        }
    };
    // Same single constructor the probe path and `status` use, so the three cannot drift.
    let nickname = mesh.store.resolve(&endpoint_id).ok().flatten()?.nickname;
    let row = super::reach::reachability_row(nickname, endpoint_id, Some(&committed), Some(0));
    // Best-effort: `send` errors only when there are no subscribers, the common case.
    let _ = mesh.reach_bcast.send(row.clone());
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core rule: a change is news, a repeat is not. Without the second half a healthy session
    /// emits a frame per path event for as long as it lives.
    #[test]
    fn only_a_differing_path_is_worth_emitting() {
        let relay = PeerPath::Relay { url: None };

        assert_eq!(
            decide(&PeerPath::Direct, Some(&relay)),
            Some(PeerPath::Direct),
            "relay -> direct is the recovery a consumer must hear about"
        );
        assert_eq!(
            decide(&relay, Some(&PeerPath::Direct)),
            Some(relay.clone()),
            "direct -> relay is the DEGRADATION — the privacy indicator just became wrong"
        );
        assert_eq!(
            decide(&PeerPath::Direct, Some(&PeerPath::Direct)),
            None,
            "an unchanged path must stay quiet, or a stable session emits forever"
        );
        assert_eq!(
            decide(&PeerPath::Direct, None),
            Some(PeerPath::Direct),
            "first knowledge of a live session's path is news"
        );
    }

    /// `Unknown` means "we do not know", and the docs call rendering it as private "the one misuse
    /// that turns this field into a false privacy statement". Emitting it would overwrite a
    /// consumer's correct belief with an absence of one.
    #[test]
    fn unknown_is_never_emitted() {
        assert_eq!(decide(&PeerPath::Unknown, None), None);
        assert_eq!(decide(&PeerPath::Unknown, Some(&PeerPath::Direct)), None);
        assert_eq!(
            decide(&PeerPath::Unknown, Some(&PeerPath::Relay { url: None })),
            None
        );
    }

    /// The hazard this whole module has to get right: the watcher is a SECOND writer to the
    /// reachability cache. An in-flight probe that STARTED earlier can complete later (a 3s timeout
    /// losing to a live path event), and must not move the cache backwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_older_writer_never_overwrites_a_newer_observation() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let eid = [9u8; 32];
        mesh.store
            .add(crate::allowlist::PeerEntry {
                endpoint_id: eid,
                nickname: "bob".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        // A NEWER writer (ticket 7) lands Direct.
        let row = commit_observation(&mesh, eid, 7, &PeerPath::Direct);
        assert!(row.is_some(), "first observation commits");

        // An OLDER writer (ticket 3) tries to report Relay — the stale value. It must be dropped.
        let row = commit_observation(&mesh, eid, 3, &PeerPath::Relay { url: None });
        assert!(
            row.is_none(),
            "an older writer must not overwrite a newer observation — this is the #58 defect \
             class, and here it would push a stale path a consumer renders as a privacy claim"
        );
        let cached = mesh
            .reachability
            .lock()
            .unwrap()
            .get(&eid)
            .map(|e| e.path.clone());
        assert_eq!(
            cached,
            Some(PeerPath::Direct),
            "the cache must still hold the NEWER value"
        );
    }

    /// First knowledge from a live session: reachable by construction (we are talking to it), but
    /// no RTT has been measured. Inventing one would be a fabricated measurement.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_seeded_entry_is_reachable_with_no_fabricated_rtt() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let eid = [11u8; 32];
        mesh.store
            .add(crate::allowlist::PeerEntry {
                endpoint_id: eid,
                nickname: "carol".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        let row = commit_observation(&mesh, eid, 1, &PeerPath::Direct).expect("seeds an entry");
        assert!(row.reachable, "a live session IS reachability evidence");
        assert_eq!(
            row.rtt_ms, None,
            "no RTT was measured — never fabricate one"
        );
        assert_eq!(row.path, PeerPath::Direct);
    }

    /// An unchanged path must not commit or emit, even with a fresh ticket — otherwise a stable
    /// session rewrites the cache and pushes a frame on every path event for its whole life.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unchanged_path_commits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(&cfg, "").unwrap();
        let mesh = crate::daemon::testutil::hermetic_mesh(cfg).await;
        let eid = [13u8; 32];
        mesh.store
            .add(crate::allowlist::PeerEntry {
                endpoint_id: eid,
                nickname: "dave".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: None,
            })
            .unwrap();

        assert!(commit_observation(&mesh, eid, 1, &PeerPath::Direct).is_some());
        assert!(
            commit_observation(&mesh, eid, 2, &PeerPath::Direct).is_none(),
            "a repeat observation is not news, however fresh its ticket"
        );
    }

    /// A relay URL change is a real change: it names WHICH relay carries the data, and moving
    /// between relays is a different operational fact than staying put.
    #[test]
    fn a_different_relay_url_is_a_change() {
        let a = PeerPath::Relay {
            url: Some("https://a.example".into()),
        };
        let b = PeerPath::Relay {
            url: Some("https://b.example".into()),
        };
        assert_eq!(decide(&b, Some(&a)), Some(b.clone()));
        assert_eq!(decide(&a, Some(&a)), None);
    }
}
