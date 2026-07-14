//! The roster-mode gate ([RECONCILE-D], spec §4.1). [`RosterGate`] resolves an endpoint via the
//! installed [`RosterView`] (hot-swappable on install), degraded-aware. [`ComposedGate`] layers it
//! over the pairing [`AllowlistGate`] with the §4.1 precedence (revocation → roster → pairing).
use std::sync::{Arc, RwLock};

use mcpmesh_net::{EndpointId, PeerIdentity, TrustGate};
use mcpmesh_trust::roster::validate::{RosterState, RosterView};

use crate::allowlist::AllowlistGate;
use crate::util::epoch_now_i64 as now_epoch;

/// Default degraded grace window (spec §4.3 `[roster].grace_period` default "72h"). Config
/// override is threaded in T12; the gate takes the effective seconds at construction.
pub const DEFAULT_GRACE_SECS: i64 = 72 * 3600;

/// Roster-mode [`TrustGate`]: resolves an inbound endpoint to its user/device/group identity via
/// the installed roster, refusing anything absent / revoked / degraded-stopped. The installed
/// view is behind an `RwLock<Option<Arc<..>>>` so [`install`](Self::install) HOT-SWAPS it live
/// (the resolve path takes a cheap read lock, dropped before returning and NEVER held across an
/// await — `TrustGate::resolve`/`is_revoked` are sync). An empty gate (no roster) resolves nothing
/// — a pure-pairing daemon composes exactly like M2b.
pub struct RosterGate {
    view: RwLock<Option<Arc<RosterView>>>,
    grace_secs: i64,
    /// The last instant this node validated the installed roster as current via an authenticated
    /// channel (spec §4.3 P13) — bumped by [`set_last_confirmed`](Self::set_last_confirmed) on every
    /// confirmation event. `None` imposes NO freshness constraint (M3a back-compat: `empty`/`with_grace`
    /// leave it `None`). Behind its own `RwLock` so a confirmation hot-updates it live, exactly like
    /// [`install`](Self::install) hot-swaps the view — the resolve/sever paths take a cheap read.
    last_confirmed: RwLock<Option<i64>>,
    /// The freshness bound in seconds (spec §4.3 P13 `[roster].max_staleness`). `i64::MAX` in the M3a
    /// constructors (`empty`/`with_grace`) → the staleness fold is never reached → expiry-governed only.
    max_staleness: i64,
}

impl RosterGate {
    /// A gate with no roster installed (pure-pairing default; also the startup state before load).
    /// M3a back-compat: `last_confirmed = None`, `max_staleness = i64::MAX` → NO freshness constraint
    /// (the effective state collapses to the expiry-only `state`).
    pub fn empty() -> Self {
        Self {
            view: RwLock::new(None),
            grace_secs: DEFAULT_GRACE_SECS,
            last_confirmed: RwLock::new(None),
            max_staleness: i64::MAX,
        }
    }

    /// A gate with a configured grace window but NO freshness constraint (M3a back-compat:
    /// `last_confirmed = None`, `max_staleness = i64::MAX`). Retained for callers that want the
    /// expiry-only degraded machine; the roster daemon uses [`with_freshness`](Self::with_freshness).
    pub fn with_grace(grace_secs: i64) -> Self {
        Self {
            view: RwLock::new(None),
            grace_secs,
            last_confirmed: RwLock::new(None),
            max_staleness: i64::MAX,
        }
    }

    /// The roster-daemon constructor (spec §4.3 P13): a configured grace window AND a freshness bound.
    /// `last_confirmed` starts `None` (no constraint until the daemon loads/bootstraps it — the one-time
    /// upgrade grace) and is armed by [`set_last_confirmed`](Self::set_last_confirmed) on every
    /// confirmation event (URL poll ≥ installed, gossip install, manual install).
    pub fn with_freshness(grace_secs: i64, max_staleness: i64) -> Self {
        Self {
            view: RwLock::new(None),
            grace_secs,
            last_confirmed: RwLock::new(None),
            max_staleness,
        }
    }

    /// Record that the installed roster was confirmed current at `epoch` (the freshness bump). Hot-
    /// updates the live gate — the very next `resolve`/`should_sever_now` sees it (no gate rebuild).
    pub fn set_last_confirmed(&self, epoch: i64) {
        *self.last_confirmed.write().expect("freshness lock") = Some(epoch);
    }

    /// The current `last_confirmed`, or `None` when never confirmed / no freshness constraint. The
    /// daemon's status/warn paths read it to compute the SAME `effective_state` the gate resolves on.
    pub fn last_confirmed(&self) -> Option<i64> {
        *self.last_confirmed.read().expect("freshness lock")
    }

    /// The gate's EFFECTIVE roster state at `now_epoch` — the MORE-degraded of expiry and staleness
    /// (spec §4.3, folding `last_confirmed`/`max_staleness` onto the expiry machine) — or `None` when
    /// no roster is installed. Consulted by `resolve`: a DegradedStopped gate denies NEW inbound
    /// (`resolve → None → 401`), bounding NEW-connection adversarial staleness at `max_staleness +
    /// grace`. It is NOT consulted by `should_sever_now` (register-time only; cutting EXISTING
    /// staleness-degraded sessions needs a periodic sweep — deferred to M4, see `serve_forever`).
    pub fn effective_state(&self, now_epoch: i64) -> Option<RosterState> {
        let view = self.view()?;
        Some(view.effective_state(
            now_epoch,
            self.grace_secs,
            self.last_confirmed(),
            self.max_staleness,
        ))
    }

    /// Hot-swap the installed roster view (install path / startup load). The very next `resolve`
    /// sees it — no gate rebuild. Called by the daemon after `RosterStore::install_from_file`
    /// (T9/T10).
    pub fn install(&self, view: RosterView) {
        *self.view.write().expect("roster gate lock not poisoned") = Some(Arc::new(view));
    }

    /// A snapshot of the installed view (for the D8 sever set + status), or `None`. The read lock
    /// is released as the `Arc` clone returns — never held across an await.
    pub fn view(&self) -> Option<Arc<RosterView>> {
        self.view
            .read()
            .expect("roster gate lock not poisoned")
            .clone()
    }
}

impl TrustGate for RosterGate {
    /// Resolve a rostered device to `PeerIdentity{ name: user_id, user_id: Some, groups }`, or
    /// `None` (absent / revoked / degraded-STOPPED). In degraded-GRACE the roster still resolves
    /// (existing behavior continues, spec §4.3) — the warning is surfaced daemon-side (T12).
    fn resolve(&self, endpoint: &EndpointId) -> Option<PeerIdentity> {
        let view = self.view()?;
        // Effective degraded-stopped (expiry OR staleness past grace, spec §4.3 P13) → roster
        // authorizes nothing: a stale/expired roster must not admit NEW connections. This is the
        // freshness bound for NEW inbound (existing sessions are re-evaluated only on install/restart;
        // a time-triggered staleness sweep is M4 — see `serve_forever`).
        if self.effective_state(now_epoch()) == Some(RosterState::DegradedStopped) {
            return None;
        }
        // Revocation wins over any active listing (also enforced in build_view, belt-and-suspenders).
        if view.is_revoked(endpoint) {
            return None;
        }
        let d = view.resolve(endpoint)?;
        Some(PeerIdentity {
            endpoint: *endpoint,
            name: d.user_id.clone(), // name == user_id (§6.3 / the select_service arm)
            user_id: Some(d.user_id.clone()), // Some(..) marks this a roster identity (D8 rule)
            groups: d.groups.clone(),
        })
    }

    /// Is this endpoint revoked by the installed roster? Honored regardless of degraded state
    /// (fail-closed) — even a degraded-STOPPED roster still enforces its last-known revocations.
    /// The composed gate consults this FIRST (spec §4.1 precedence 1); an empty gate → `false`.
    fn is_revoked(&self, endpoint: &EndpointId) -> bool {
        self.view().map(|v| v.is_revoked(endpoint)).unwrap_or(false)
    }

    /// The roster-resolved user_id for the D8 sever discriminator: `Some` IFF this endpoint would
    /// resolve via the ROSTER right now (absent/revoked/degraded-stopped → `None`), reusing the exact
    /// `resolve` precedence. A purely-paired endpoint (not in the roster) is `None`, so it is never
    /// severed by a roster install even though its `PeerEntry` may carry a verified binding user_id.
    fn roster_user(&self, endpoint: &EndpointId) -> Option<String> {
        self.resolve(endpoint).and_then(|id| id.user_id)
    }
}

/// The daemon's composed trust gate (spec §4.1): pairing ∪ roster with explicit precedence.
///  1. the installed roster's `revoked_endpoints` are consulted FIRST — a revoked endpoint is
///     refused even if a pair entry exists (revocation wins over pairing, across all ALPNs);
///  2. an endpoint present (active) in the roster resolves to its ROSTER identity even if a pair
///     entry exists (roster masks the pair petname);
///  3. otherwise fall through to the pair entry (pairing mode continues untouched).
///
/// With an empty roster this is exactly the M2b `AllowlistGate` behavior (falls through for
/// everything) — so every M2b pairing test/flow is preserved.
pub struct ComposedGate {
    roster: Arc<RosterGate>,
    pairs: Arc<AllowlistGate>,
}

impl ComposedGate {
    pub fn new(roster: Arc<RosterGate>, pairs: Arc<AllowlistGate>) -> Self {
        Self { roster, pairs }
    }
    /// The roster gate handle — the daemon keeps it to hot-swap on install + compute the D8 sever set.
    pub fn roster(&self) -> &Arc<RosterGate> {
        &self.roster
    }
}

impl TrustGate for ComposedGate {
    /// The D8 sever discriminator (§4.3 rule 6): roster-resolved IFF the endpoint is in the roster
    /// (delegates to `RosterGate::roster_user`). Deliberately NOT `resolve(endpoint).user_id`: a
    /// paired-only peer resolves to its PAIR identity which — since the self-sovereign-binding
    /// feature — carries a `user_id`, so keying the sever on `identity.user_id` would sever
    /// legitimately-paired peers on a roster install. Keying on roster membership keeps them.
    fn roster_user(&self, endpoint: &EndpointId) -> Option<String> {
        self.roster.roster_user(endpoint)
    }

    fn resolve(&self, endpoint: &EndpointId) -> Option<PeerIdentity> {
        // (1) revocation wins, all ALPNs (§4.1 precedence 1).
        if self.roster.is_revoked(endpoint) {
            return None;
        }
        // (2) roster masks the pair entry (§4.1 precedence 2).
        if let Some(id) = self.roster.resolve(endpoint) {
            return Some(id);
        }
        // (3) fall through to pairing (also the DegradedStopped path: RosterGate::resolve returns
        //     None when stopped, so a rostered-AND-paired peer falls through to its PAIR petname —
        //     see the DegradedStopped×paired test + DECLARE below).
        self.pairs.resolve(endpoint)
    }

    /// The D8 check-register recheck (T8) asks the LIVE gate whether an endpoint is currently
    /// revoked. Delegate to the installed roster's revoked set — honored regardless of degraded
    /// state (fail-closed). This is what closes the TOCTOU race: a connection registering after a
    /// revoking install sees `true` here and self-closes.
    fn is_revoked(&self, endpoint: &EndpointId) -> bool {
        self.roster.is_revoked(endpoint)
    }

    /// The register-time D8 recheck (T4): sever iff the endpoint is REVOKED (revocation wins, all
    /// ALPNs), OR it was roster-resolved (`roster_user.is_some()`) AND is now ABSENT from the
    /// installed roster (the dropped-from-roster half M3a left open). CRITICAL: the absence test
    /// consults the ROSTER gate's own `view().resolve` (NOT the composed resolve) — a dropped
    /// endpoint that ALSO holds a pair entry must still be caught (`roster.resolve → None` even when
    /// `pairs.resolve → Some`). Mirrors `mcpmesh_net::should_sever` for one endpoint against the
    /// roster's CURRENT view; honored regardless of degraded state (revocation is fail-closed).
    ///
    /// STALENESS is deliberately NOT checked here: this recheck runs ONLY at register time (a NEW
    /// connection), and staleness is time-triggered with no event, so it cannot re-evaluate an
    /// already-established session as the clock crosses `last_confirmed + max_staleness + grace`. The
    /// freshness bound is enforced at `resolve` (NEW inbound → `None` → 401); cutting EXISTING
    /// roster-authorized sessions on staleness needs a periodic sweep, deferred to M4 (see
    /// `serve_forever`). An `effective_state == DegradedStopped` arm here would also over-reach
    /// (severing purely-paired peers, `roster_user == None`, whose authorization is independent of the
    /// org roster) while delivering nothing for roster peers (already denied at `resolve`).
    fn should_sever_now(&self, endpoint: &EndpointId, roster_user: Option<&str>) -> bool {
        self.roster.is_revoked(endpoint)
            || (roster_user.is_some()
                && self
                    .roster
                    .view()
                    .is_some_and(|v| v.resolve(endpoint).is_none()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mcpmesh_net::TrustGate;
    use mcpmesh_trust::roster::sign::mint_signed;
    use mcpmesh_trust::roster::validate::load_installed;
    use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};

    // Build a RosterView for GATE tests via `load_installed` (verifies the sig + structural rules
    // but NOT expiry/serial) — so an intentionally-EXPIRED `expires` (the degraded tests) still
    // yields a view; degraded state is then computed at resolve-time from the real clock. (The
    // install-time rule-3 rejection is exercised in T3, not here.)
    fn view(
        serial: u64,
        expires: &str,
        revoke_laptop: bool,
    ) -> mcpmesh_trust::roster::validate::RosterView {
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let r = mint_signed(
            &root,
            Roster {
                format: "mcpmesh-roster/1".into(),
                org_id: "acme".into(),
                serial,
                issued_at: "2000-01-01T00:00:00Z".into(),
                expires_at: expires.into(),
                groups: vec!["team-eng".into(), "all".into()],
                users: vec![RosterUser {
                    user_id: "alice".into(),
                    display_name: "Alice".into(),
                    user_pk: encode_b64u(&[1u8; 32]),
                    groups: vec!["team-eng".into(), "all".into()],
                    devices: vec![RosterDevice {
                        endpoint_id: encode_b64u(&[2u8; 32]),
                        label: "laptop".into(),
                        role: "primary".into(),
                    }],
                }],
                revoked_endpoints: if revoke_laptop {
                    vec![encode_b64u(&[2u8; 32])]
                } else {
                    vec![]
                },
                sig: String::new(),
            },
        );
        load_installed(&r, &root.verifying_key()).unwrap()
    }

    #[test]
    fn resolves_rostered_device_to_user_identity() {
        let gate = RosterGate::empty();
        gate.install(view(5, "2999-01-01T00:00:00Z", false));
        let id = gate.resolve(&[2u8; 32]).expect("alice's laptop resolves");
        assert_eq!(id.name, "alice"); // name == user_id (§6.3)
        assert_eq!(id.user_id.as_deref(), Some("alice"));
        assert_eq!(id.groups, vec!["team-eng".to_string(), "all".to_string()]);
        // An unknown endpoint is refused.
        assert!(gate.resolve(&[42u8; 32]).is_none());
    }

    #[test]
    fn empty_gate_resolves_nothing_and_is_never_revoked() {
        let gate = RosterGate::empty(); // pure-pairing daemon (no roster installed)
        assert!(gate.resolve(&[2u8; 32]).is_none());
        assert!(!gate.is_revoked(&[2u8; 32]));
    }

    #[test]
    fn revoked_endpoint_does_not_resolve_and_is_flagged() {
        let gate = RosterGate::empty();
        gate.install(view(5, "2999-01-01T00:00:00Z", true)); // laptop revoked
        assert!(gate.resolve(&[2u8; 32]).is_none()); // revocation wins → no identity
        assert!(gate.is_revoked(&[2u8; 32])); // consulted first by the composed gate
    }

    #[test]
    fn is_revoked_and_resolve_honored_through_dyn_dispatch() {
        // Regression pin: production touches the gate ONLY through `Arc<dyn TrustGate>`
        // (ComposedGate T6, the accept loop). A concrete-receiver call would hit an inherent
        // `is_revoked` if one existed, masking a regression; the dyn path goes through the vtable,
        // so it FAILS loudly if `is_revoked` ever moves back off the trait impl (fail-OPEN).
        let gate = RosterGate::empty();
        gate.install(view(5, "2999-01-01T00:00:00Z", true)); // laptop revoked
        let g: &dyn TrustGate = &gate; // the PRODUCTION path (ComposedGate holds Arc<dyn>)
        assert!(g.is_revoked(&[2u8; 32])); // FAILS if is_revoked ever regresses to inherent
        assert!(g.resolve(&[2u8; 32]).is_none()); // revocation wins via dyn too
    }

    #[test]
    fn degraded_stopped_roster_resolves_nothing_but_still_honors_revocation() {
        // Expired long ago; with the default grace it is past-grace → DegradedStopped.
        let gate = RosterGate::empty();
        gate.install(view(5, "2001-01-01T00:00:00Z", true));
        // now is 2026 ≫ expires+grace → stopped: no roster identity is granted.
        assert!(gate.resolve(&[2u8; 32]).is_none());
        // But revocation is still enforced (fail-closed) even when stopped.
        assert!(gate.is_revoked(&[2u8; 32]));
    }

    #[test]
    fn stale_gate_stops_resolving_even_when_unexpired() {
        let gate = RosterGate::with_freshness(72 * 3600, 24 * 3600); // grace 72h, max_staleness 24h
        gate.install(view(5, "2999-01-01T00:00:00Z", false)); // never expiry-degraded
        gate.set_last_confirmed(now_epoch() - 24 * 3600 - 72 * 3600 - 10); // past max_staleness+grace
        assert!(
            gate.resolve(&[2u8; 32]).is_none(),
            "a stale roster stops granting identity"
        );
        gate.set_last_confirmed(now_epoch()); // fresh confirmation restores it
        assert!(
            gate.resolve(&[2u8; 32]).is_some(),
            "a freshly-confirmed roster resolves again"
        );
        assert!(!gate.is_revoked(&[2u8; 32])); // revocation honored regardless of freshness
    }

    #[test]
    fn composed_gate_precedence_is_exhaustive() {
        use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        // Pair entries for FOUR endpoints (petname == "p-<n>").
        for n in [2u8, 3, 4, 5] {
            store
                .add(PeerEntry {
                    endpoint_id: [n; 32],
                    petname: format!("p-{n}"),
                    services: vec![],
                    paired_at: None,
                    user_id: None,
                })
                .unwrap();
        }
        let pairs = Arc::new(AllowlistGate::new(store));

        // Roster: user "alice" owns [2;32] (also paired) and revokes [3;32] (also paired).
        let roster = Arc::new(RosterGate::empty());
        roster.install(view_with(&[(2u8, "alice")], &[3u8])); // helper below
        let composed = ComposedGate::new(roster, pairs);

        // (a) rostered + paired → the ROSTER identity (masks the pair petname).
        let id = composed.resolve(&[2u8; 32]).expect("resolves");
        assert_eq!(id.user_id.as_deref(), Some("alice"));
        assert_eq!(id.name, "alice"); // NOT "p-2"

        // (b) revoked + paired → REFUSED (revocation wins over the pair entry, spec §4.1(1)).
        assert!(composed.resolve(&[3u8; 32]).is_none());

        // (c) paired only (not in roster) → the PAIR identity.
        let id = composed.resolve(&[4u8; 32]).expect("resolves");
        assert_eq!(id.user_id, None);
        assert_eq!(id.name, "p-4");

        // (d) neither (unknown, no pair, no roster) → REFUSED.
        assert!(composed.resolve(&[9u8; 32]).is_none());
        // (e) paired-only [5;32] still resolves (control: roster did not disturb it).
        assert_eq!(composed.resolve(&[5u8; 32]).unwrap().name, "p-5");
    }

    #[test]
    fn a_paired_peer_with_a_verified_binding_is_not_severed_by_a_roster() {
        use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        // A PAIRING peer [7;32] that presented a verified device→user binding → `user_id: Some`,
        // NOT a member of the org roster. (The self-sovereign-binding feature made pairing peers
        // carry a user_id, so `identity.user_id.is_some()` no longer means "roster-resolved".)
        store
            .add(PeerEntry {
                endpoint_id: [7u8; 32],
                petname: "bob-laptop".into(),
                services: vec![],
                paired_at: None,
                user_id: Some("b64u:BOB".into()),
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store));
        // Roster mode: an installed roster that lists alice [2;32] only (NOT bob).
        let roster = Arc::new(RosterGate::empty());
        roster.install(view_with(&[(2u8, "alice")], &[]));
        let composed = ComposedGate::new(roster, pairs);

        // The paired peer resolves WITH its binding user_id (needed for authz/audiences)…
        let id = composed.resolve(&[7u8; 32]).expect("paired peer resolves");
        assert_eq!(id.user_id.as_deref(), Some("b64u:BOB"));
        // …but it is NOT roster-resolved, so the D8 sever discriminator is None.
        assert_eq!(
            composed.roster_user(&[7u8; 32]),
            None,
            "a pairing-only peer must not be treated as roster-resolved"
        );
        // Therefore the register-time recheck must NOT sever it (the regression: keyed on the
        // binding user_id it WAS severed — asserted on the last line to pin the contrast).
        assert!(
            !composed.should_sever_now(&[7u8; 32], composed.roster_user(&[7u8; 32]).as_deref()),
            "a legitimately-paired peer must survive in roster mode"
        );
        // A genuinely roster-resolved peer still carries the discriminator (alice, in the roster).
        assert_eq!(composed.roster_user(&[2u8; 32]).as_deref(), Some("alice"));
        // Contrast — the OLD (buggy) discriminator (`identity.user_id`) DID sever the paired peer:
        assert!(
            composed.should_sever_now(&[7u8; 32], Some("b64u:BOB")),
            "regression witness: keying the sever on identity.user_id severs a paired peer"
        );
    }

    #[test]
    fn degraded_stopped_rostered_and_paired_falls_through_to_pair_identity() {
        use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        // [2;32] is BOTH a pair peer ("p-2") AND a rostered device ("alice") — but the roster is
        // DegradedStopped (expired long ago, past grace) so it stops resolving.
        store
            .add(PeerEntry {
                endpoint_id: [2u8; 32],
                petname: "p-2".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store));
        let roster = Arc::new(RosterGate::empty());
        roster.install(view_with_expiry(
            &[(2u8, "alice")],
            &[],
            "2001-01-01T00:00:00Z",
        )); // stopped
        let composed = ComposedGate::new(roster, pairs);

        // DECLARE (intended behavior): a stale (DegradedStopped) org roster stops granting ROSTER
        // identity, but LOCAL pairing is independent of org-roster freshness — so the peer falls
        // through to its PAIR petname "p-2" (not refused). Revocation still wins over this (step 1,
        // is_revoked is honored even when stopped) — a revoked-and-paired peer is still refused.
        let id = composed
            .resolve(&[2u8; 32])
            .expect("falls through to pairing");
        assert_eq!(id.name, "p-2");
        assert_eq!(id.user_id, None);
    }

    #[test]
    fn composed_is_revoked_honored_through_dyn_dispatch() {
        use crate::allowlist::{AllowlistGate, PeerEntry, PeerStore};
        use std::sync::Arc;
        // [3;32] is revoked+paired (the exhaustive test's arm (b) setup). We consult the gate ONLY
        // through `&dyn TrustGate` — the PRODUCTION path: the daemon holds `Arc<dyn TrustGate>` and
        // T8's D8 check-register recheck calls `is_revoked` through the vtable to close the
        // register-after-revoke TOCTOU race. The other two ComposedGate tests only call `resolve()`,
        // so `ComposedGate::is_revoked` itself is otherwise untested; without this pin an inherent
        // regression would silently hit the trait default `false` = revocation fail-OPEN on the recheck.
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        store
            .add(PeerEntry {
                endpoint_id: [3u8; 32],
                petname: "p-3".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
            })
            .unwrap();
        let pairs = Arc::new(AllowlistGate::new(store));
        let roster = Arc::new(RosterGate::empty());
        roster.install(view_with(&[(2u8, "alice")], &[3u8])); // roster revokes [3;32]
        let composed = ComposedGate::new(roster, pairs);

        let g: &dyn TrustGate = &composed; // the PRODUCTION path (daemon holds Arc<dyn TrustGate>)
        assert!(g.is_revoked(&[3u8; 32])); // FAILS if ComposedGate::is_revoked regresses to inherent
        assert!(g.resolve(&[3u8; 32]).is_none()); // revocation wins via dyn too
    }

    #[test]
    fn should_sever_now_selects_revoked_and_dropped_through_dyn() {
        use std::sync::Arc;
        // A roster: alice owns [2;32] (active), revokes [3;32]. [4;32] is NOT in the roster.
        let roster = Arc::new(RosterGate::empty());
        roster.install(view_with(&[(2u8, "alice")], &[3u8]));
        let dir = tempfile::tempdir().unwrap();
        let store =
            Arc::new(crate::allowlist::PeerStore::open(&dir.path().join("s.redb")).unwrap());
        let composed = ComposedGate::new(
            roster,
            Arc::new(crate::allowlist::AllowlistGate::new(store)),
        );
        let g: &dyn TrustGate = &composed; // PRODUCTION path (daemon holds Arc<dyn TrustGate>)

        // Revoked → sever (regardless of source).
        assert!(g.should_sever_now(&[3u8; 32], Some("alice")));
        assert!(g.should_sever_now(&[3u8; 32], None));
        // Roster-resolved AND still active → KEEP.
        assert!(!g.should_sever_now(&[2u8; 32], Some("alice")));
        // Was roster-resolved (roster_user Some) but now ABSENT from the roster → SEVER (the dropped
        // half M3a left open; [4;32] is in NO user entry).
        assert!(g.should_sever_now(&[4u8; 32], Some("bob")));
        // Pairing-only (roster_user None), not revoked, not in roster → KEEP (never severed by roster).
        assert!(!g.should_sever_now(&[4u8; 32], None));
    }

    // Test helper: a RosterView with the given (endpoint_byte, user_id) active devices + revoked
    // bytes, valid far into the future. Built via `load_installed` (sig + structural rules only,
    // no rule-3 rejection) so `view_with_expiry` can also hand it an EXPIRED timestamp.
    fn view_with(
        active: &[(u8, &str)],
        revoked: &[u8],
    ) -> mcpmesh_trust::roster::validate::RosterView {
        view_with_expiry(active, revoked, "2999-01-01T00:00:00Z")
    }

    fn view_with_expiry(
        active: &[(u8, &str)],
        revoked: &[u8],
        expires: &str,
    ) -> mcpmesh_trust::roster::validate::RosterView {
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let users = active
            .iter()
            .map(|(b, uid)| RosterUser {
                user_id: (*uid).into(),
                display_name: (*uid).into(),
                user_pk: encode_b64u(&[1u8; 32]),
                groups: vec!["team-eng".into()],
                devices: vec![RosterDevice {
                    endpoint_id: encode_b64u(&[*b; 32]),
                    label: "d".into(),
                    role: "primary".into(),
                }],
            })
            .collect();
        let r = mint_signed(
            &root,
            Roster {
                format: "mcpmesh-roster/1".into(),
                org_id: "acme".into(),
                serial: 5,
                issued_at: "2000-01-01T00:00:00Z".into(),
                expires_at: expires.into(),
                groups: vec!["team-eng".into()],
                users,
                revoked_endpoints: revoked.iter().map(|b| encode_b64u(&[*b; 32])).collect(),
                sig: String::new(),
            },
        );
        load_installed(&r, &root.verifying_key()).unwrap()
    }
}
