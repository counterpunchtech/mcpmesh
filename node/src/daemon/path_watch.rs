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
