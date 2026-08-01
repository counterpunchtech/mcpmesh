//! THIS node's own network posture (#90): the `status.self_network` projection and the boot
//! watcher that pushes a [`StreamFrame::SelfNetwork`] transition when it changes.
//!
//! Everything reads iroh's STABLE watcher surface (`home_relay_status`, `Endpoint::addr`) as
//! non-blocking point reads — no `unstable-net-report`, which is why there is no per-relay RTT.
//!
//! [`StreamFrame::SelfNetwork`]: mcpmesh_local_api::StreamFrame::SelfNetwork

use std::sync::Arc;

use iroh::Watcher;
use mcpmesh_local_api::{RelayInfo, SelfNetwork};

use crate::util::epoch_now_i64;

use super::MeshState;

/// Project the block from `(url, connected)` relay pairs + direct addresses — PURE, so the
/// sanitization and home-relay selection are unit-testable without constructing iroh's
/// `RelayStatus` (its constructor is crate-private).
///
/// `home_relay` is the FIRST connected relay, sanitized; `online` ⇔ any relay is connected
/// (iroh's own `online()` loops on exactly this predicate). `last_change_epoch` is the
/// caller's — the point-in-time `status` read merges the watcher's stamp, a watcher emission
/// stamps "now".
pub(crate) fn project(
    relays: impl IntoIterator<Item = (String, bool)>,
    direct_addrs: Vec<String>,
    last_change_epoch: Option<i64>,
    identity_conflict_epoch: Option<i64>,
) -> SelfNetwork {
    let relays: Vec<RelayInfo> = relays
        .into_iter()
        .map(|(url, connected)| RelayInfo { url, connected })
        .collect();
    let online = relays.iter().any(|r| r.connected);
    let home_relay = relays.iter().find(|r| r.connected).map(|r| r.url.clone());
    SelfNetwork {
        online,
        home_relay,
        relays,
        direct_addrs,
        last_change_epoch,
        identity_conflict_epoch,
    }
}

/// The live read off the endpoint: relay states from `home_relay_status().get()` (sanitized via
/// [`sanitize_relay_url`](super::reach::sanitize_relay_url) — operator relay URLs can carry
/// userinfo tokens), direct addresses from `Endpoint::addr()` (the same coordinates invites
/// embed). Both are non-blocking point reads.
pub(crate) fn read_current(mesh: &MeshState, last_change_epoch: Option<i64>) -> SelfNetwork {
    let relays = mesh
        .endpoint
        .home_relay_status()
        .get()
        .into_iter()
        .map(|s| (super::reach::sanitize_relay_url(s.url()), s.is_connected()));
    let direct_addrs = mesh
        .endpoint
        .addr()
        .addrs
        .iter()
        .filter_map(|a| match a {
            iroh::TransportAddr::Ip(sock) => Some(sock.to_string()),
            _ => None,
        })
        .collect();
    // #134: the last duplicate-identity observation, if any layer is installed to make one.
    project(
        relays,
        direct_addrs,
        last_change_epoch,
        mesh.identity_conflict.last_seen_epoch(),
    )
}

/// Spawn the posture watcher (#90): loop on `home_relay_status().updated()`, re-project, and on
/// a CHANGE of `online` / `home_relay` / the relay list — deliberately NOT `direct_addrs`,
/// whose churn is chatty and not a decision point — stamp `self_net_change` on the mesh and
/// broadcast the frame's payload on `self_net_bcast`.
///
/// The baseline is OFFLINE-EMPTY, not the current projection: the first observation of an
/// online endpoint is therefore always a change and always emits. That makes "came online"
/// after boot a real frame (it is genuinely news — the moment invites/dials become viable
/// beyond the LAN), and makes the transition deterministic for a subscriber attached before
/// the watcher, instead of racing the relay handshake.
///
/// `pub` (like `spawn_accept_loop`) so integration tests can spawn the REAL watcher against an
/// in-process mesh with a controlled subscribe-then-watch ordering.
pub fn spawn_self_net_watch(mesh: Arc<MeshState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut watcher = mesh.endpoint.home_relay_status();
        // The offline-empty baseline (see above). Compared WITHOUT `direct_addrs` or the
        // stamp — see `signature`.
        let mut previous = project(std::iter::empty(), Vec::new(), None, None);
        loop {
            let current = read_current(&mesh, None);
            if signature(&current) != signature(&previous) {
                let stamp = epoch_now_i64();
                *mesh
                    .self_net_change
                    .lock()
                    .expect("self_net_change lock not poisoned") = Some(stamp);
                let frame = SelfNetwork {
                    last_change_epoch: Some(stamp),
                    ..current.clone()
                };
                // Best-effort, like `reach_bcast`: `send` errors only with no subscribers.
                let _ = mesh.self_net_bcast.send(frame);
                previous = current;
            }
            if watcher.updated().await.is_err() {
                // Backstop only: iroh's watcher disconnects when the LAST endpoint clone drops,
                // and this task's own Arc<MeshState> holds one — so in practice the loop ends
                // via its JoinHandle (aborted in shutdown_booted for embedded nodes; dropped
                // with the process for the daemon shell), not through this arm.
                return;
            }
        }
    })
}

/// What counts as a transition (#90): `online`, the home relay, and the relay list — NOT
/// `direct_addrs` (chatty, advisory) and NOT the stamp itself (comparing it would make every
/// emission differ from its successor by construction).
/// What the watcher compares tick to tick — `online`, the home relay, every relay's state, and
/// (since #134) the duplicate-identity stamp. Named because it outgrew a readable tuple.
type Posture<'a> = (bool, Option<&'a str>, Vec<(&'a str, bool)>, Option<i64>);

fn signature(net: &SelfNetwork) -> Posture<'_> {
    (
        net.online,
        net.home_relay.as_deref(),
        net.relays
            .iter()
            .map(|r| (r.url.as_str(), r.connected))
            .collect(),
        // #134: a NEW duplicate-identity observation is a posture change worth pushing. The stamp
        // is sticky and only moves when the relay reports again, so this emits once per report
        // rather than once per tick. Including it here is what turns "peers went unreachable with
        // no explanation" into a frame that names the cause at the moment it happens.
        net.identity_conflict_epoch,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The projection's selection rules: `online` ⇔ any connected; `home_relay` is the FIRST
    /// connected relay, `None` when none is.
    #[test]
    fn projection_selects_the_first_connected_relay_as_home() {
        let net = project(
            [
                ("https://a.example:443".to_string(), false),
                ("https://b.example:443".to_string(), true),
                ("https://c.example:443".to_string(), true),
            ],
            vec!["192.168.1.2:4444".into()],
            None,
            None,
        );
        assert!(net.online);
        assert_eq!(net.home_relay.as_deref(), Some("https://b.example:443"));
        assert_eq!(net.relays.len(), 3);

        let net = project(
            [("https://a.example:443".to_string(), false)],
            Vec::new(),
            None,
            None,
        );
        assert!(!net.online, "a known-but-disconnected relay is not online");
        assert_eq!(net.home_relay, None);

        let net = project(std::iter::empty::<(String, bool)>(), Vec::new(), None, None);
        assert!(!net.online, "no relays configured (relay_mode=disabled)");
        assert!(net.relays.is_empty());
    }

    /// #134: a NEW duplicate-identity observation is a transition, so it PUSHES a frame rather
    /// than waiting to be polled.
    ///
    /// This is the difference between "peers went unreachable and nothing said why" — the reported
    /// experience — and learning the cause at the moment the relay reports it. A sticky stamp that
    /// was excluded from the signature would still show up in `status`, but only if someone
    /// thought to look, which is exactly what nobody knew to do.
    #[test]
    fn a_duplicate_identity_observation_is_a_transition() {
        let with = |conflict| {
            project(
                [("https://a.example:443".to_string(), true)],
                vec!["10.0.0.1:1".into()],
                None,
                conflict,
            )
        };
        let clean = with(None);
        assert_eq!(
            clean.identity_conflict_epoch, None,
            "a node with a unique identity reports nothing"
        );
        assert_ne!(
            signature(&clean),
            signature(&with(Some(1_753_000_000))),
            "the first observation must emit — otherwise the fact exists only for a poller"
        );
        assert_ne!(
            signature(&with(Some(1_753_000_000))),
            signature(&with(Some(1_753_000_900))),
            "a LATER report is news too: it says the duplicate is still out there"
        );
        assert_eq!(
            signature(&with(Some(1_753_000_000))),
            signature(&with(Some(1_753_000_000))),
            "an unchanged stamp must not emit on every tick — the stamp is sticky, so this is \
             what stops one observation becoming a frame per loop iteration forever"
        );
    }

    /// The transition rule: `direct_addrs` drift alone is NOT a change; each of `online` /
    /// home-relay / relay-state IS. Pins the differ the watcher loops on — inverting any arm
    /// either spams a frame per address churn or goes silent on a real outage.
    #[test]
    fn only_online_home_relay_or_relay_state_count_as_a_transition() {
        let base = project(
            [("https://a.example:443".to_string(), true)],
            vec!["10.0.0.1:1".into()],
            None,
            None,
        );
        let addr_churn = project(
            [("https://a.example:443".to_string(), true)],
            vec!["10.0.0.2:2".into()],
            None,
            None,
        );
        assert_eq!(
            signature(&base),
            signature(&addr_churn),
            "address churn alone must not emit"
        );
        let relay_down = project(
            [("https://a.example:443".to_string(), false)],
            vec!["10.0.0.1:1".into()],
            None,
            None,
        );
        assert_ne!(
            signature(&base),
            signature(&relay_down),
            "a relay losing its connection is a transition"
        );
        // Isolate the RELAYS arm: a SECONDARY relay flaps while the home relay stays up, so
        // `online` and `home_relay` are unchanged and only the relay-state comparison can see
        // it. Without this case, dropping that arm from the differ passed this whole test —
        // the relay-down case above also flips `online`, which masks the arm (found by
        // mutation, not assumed).
        let two_up = project(
            [
                ("https://a.example:443".to_string(), true),
                ("https://b.example:443".to_string(), true),
            ],
            vec!["10.0.0.1:1".into()],
            None,
            None,
        );
        let secondary_down = project(
            [
                ("https://a.example:443".to_string(), true),
                ("https://b.example:443".to_string(), false),
            ],
            vec!["10.0.0.1:1".into()],
            None,
            None,
        );
        assert_ne!(
            signature(&two_up),
            signature(&secondary_down),
            "a secondary relay's connection state is a transition even while the home stays up              — losing a fallback relay is exactly the pre-outage warning #90 exists to give"
        );
        let stamp_only = SelfNetwork {
            last_change_epoch: Some(42),
            ..base.clone()
        };
        assert_eq!(
            signature(&base),
            signature(&stamp_only),
            "the stamp itself must not count, or every emission differs from its successor"
        );
    }
}
