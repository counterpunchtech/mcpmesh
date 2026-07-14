//! The six validation rules (spec §4.3, all MUST) + the resolvable [`RosterView`] a gate reads +
//! [`RosterState`] (degraded-mode computation). Rule 1 (signature) lives in
//! [`sign::verify`](crate::roster::sign::verify); this module runs it plus rules 2–6. Pure:
//! `now` and `installed_serial` are PARAMETERS (no clock, no I/O) so every rule is unit-testable.
use std::collections::{HashMap, HashSet};

use ed25519_dalek::VerifyingKey;

use super::sign::verify;
use super::{ROSTER_FORMAT, Roster, RosterError, SKEW_SECS, decode_endpoint_id};

/// A validated, resolvable roster — the lookup maps a `RosterGate` holds (built once at
/// install/load). Net-free: `resolve` returns `(user_id, groups)`; the cli maps that to a
/// `PeerIdentity`.
#[derive(Debug, Clone)]
pub struct RosterView {
    org_id: String,
    serial: u64,
    expires_at_epoch: i64,
    /// Active (NON-revoked) device endpoint → its owner's identity.
    devices: HashMap<[u8; 32], ResolvedDevice>,
    /// Every revoked endpoint (revocation wins over any active listing).
    revoked: HashSet<[u8; 32]>,
}

/// A rostered device's resolved identity (the roster-mode half of a `PeerIdentity`, spec §6.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDevice {
    pub user_id: String,
    pub groups: Vec<String>,
    /// The device's role in its user's device set (`"primary"` | `"mirror"`; free-form otherwise).
    /// Feeds the T11 person→device dial candidate ORDER (`devices_for_user`) — primary before mirror
    /// — never an authorization decision.
    pub role: String,
    /// The device's human label (spec §4.3 `RosterDevice.label`). Display-only — the T11 advisory
    /// presence read (`status`) renders it; never an authorization input.
    pub label: String,
}

/// Roster liveness (spec §4.3 degraded mode). Computed from `expires_at` + a grace window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterState {
    /// now ≤ expires_at: full authority.
    Approved,
    /// expires_at < now ≤ expires_at + grace: keep serving, warn (spec: "continues … with warnings").
    DegradedGrace,
    /// now > expires_at + grace: inbound serving stops (roster authorizes nothing).
    DegradedStopped,
}

impl RosterView {
    pub fn org_id(&self) -> &str {
        &self.org_id
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn expires_at_epoch(&self) -> i64 {
        self.expires_at_epoch
    }

    /// Resolve an ACTIVE (non-revoked) rostered device to its identity, else `None`.
    pub fn resolve(&self, endpoint: &[u8; 32]) -> Option<&ResolvedDevice> {
        self.devices.get(endpoint)
    }

    /// Is this endpoint revoked? Honored regardless of degraded state (fail-closed): a stale
    /// roster's last-known revocation list is strictly safer to keep than to drop.
    pub fn is_revoked(&self, endpoint: &[u8; 32]) -> bool {
        self.revoked.contains(endpoint)
    }

    /// All active device endpoints (the D8 sever rule's "still in the new roster" set).
    pub fn device_endpoints(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.devices.keys()
    }

    /// Every active (non-revoked) device with its resolved identity + display fields — the T11
    /// advisory presence read (`status`, spec §10.1) enumerates these and marks each `online` from
    /// the presence table. Revoked endpoints are absent (excluded at `build_view`). Iteration order
    /// is the underlying map's (unordered) — the caller sorts for a stable display.
    pub fn devices(&self) -> impl Iterator<Item = (&[u8; 32], &ResolvedDevice)> {
        self.devices.iter()
    }

    /// The ACTIVE (non-revoked) device endpoints + roles owned by `user_id`, ordered `"primary"`
    /// before `"mirror"` (any other role last), with endpoint bytes as a DETERMINISTIC within-role
    /// tiebreak (the `devices` map is unordered, so a total order is needed for a reproducible result).
    /// Empty for an unknown user.
    ///
    /// This is the T11 person→device dial's CANDIDATE ORDER (spec §10.1). Two invariants the dial
    /// leans on: (1) a REVOKED endpoint is NEVER returned — `build_view` already excludes revoked
    /// endpoints from `devices`, so a revoked device can never be a dial candidate; (2) EVERY active
    /// device of the user is returned regardless of presence — the dial then re-orders WITHIN a role
    /// by presence recency, but presence is ADVISORY (a device with no presence entry stays a
    /// candidate; absence never removes one). Net-free — the cli races these endpoints.
    pub fn devices_for_user(&self, user_id: &str) -> Vec<([u8; 32], String)> {
        let mut out: Vec<([u8; 32], String)> = self
            .devices
            .iter()
            .filter(|(_, d)| d.user_id == user_id)
            .map(|(eid, d)| (*eid, d.role.clone()))
            .collect();
        out.sort_by(|(a_eid, a_role), (b_eid, b_role)| {
            role_rank(a_role)
                .cmp(&role_rank(b_role))
                .then_with(|| a_eid.cmp(b_eid))
        });
        out
    }

    /// Every revoked endpoint (the D8 sever rule's revoked set).
    pub fn revoked_endpoints(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.revoked.iter()
    }

    /// Degraded-mode state machine (spec §4.3). M3a implements the EXPIRY-driven core here;
    /// M3c layers the `last_confirmed`/`max_staleness` staleness poll onto the SAME `RosterState`
    /// (a stale-but-unexpired roster degrades identically). Grace is a config window (T5), NOT the
    /// install-time ±skew — freshness vs. liveness are separate concerns ([RECONCILE-C]).
    pub fn state(&self, now_epoch: i64, grace_secs: i64) -> RosterState {
        if now_epoch <= self.expires_at_epoch {
            RosterState::Approved
        } else if now_epoch <= self.expires_at_epoch + grace_secs {
            RosterState::DegradedGrace
        } else {
            RosterState::DegradedStopped
        }
    }
}

impl RosterState {
    /// Degradation severity for the effective-state fold (Approved < DegradedGrace < DegradedStopped).
    fn severity(self) -> u8 {
        match self {
            RosterState::Approved => 0,
            RosterState::DegradedGrace => 1,
            RosterState::DegradedStopped => 2,
        }
    }
}

impl RosterView {
    /// The EFFECTIVE degraded state (spec §4.3): the MORE-degraded of the expiry state
    /// ([`state`](Self::state)) and the freshness/staleness state. Freshness: `last_confirmed` is the
    /// last instant this node validated the roster as current via an authenticated channel (a TLS URL
    /// poll ≥ installed, a gossip-delivered roster passing validation, or manual install). If
    /// `now - last_confirmed > max_staleness` the node degrades exactly like expiry — warnings within
    /// `grace`, then serving stops — bounding adversarial staleness at `max_staleness + grace`
    /// independent of `expires_at` (P13). `last_confirmed = None` imposes NO freshness constraint
    /// (a node with no freshness tracking configured is expiry-governed only — back-compat).
    pub fn effective_state(
        &self,
        now_epoch: i64,
        grace_secs: i64,
        last_confirmed: Option<i64>,
        max_staleness_secs: i64,
    ) -> RosterState {
        let expiry = self.state(now_epoch, grace_secs);
        let staleness = match last_confirmed {
            None => RosterState::Approved,
            Some(lc) => {
                let stale = now_epoch.saturating_sub(lc);
                if stale <= max_staleness_secs {
                    RosterState::Approved
                } else if stale <= max_staleness_secs + grace_secs {
                    RosterState::DegradedGrace
                } else {
                    RosterState::DegradedStopped
                }
            }
        };
        if staleness.severity() >= expiry.severity() {
            staleness
        } else {
            expiry
        }
    }
}

/// Parse an RFC3339 UTC timestamp to epoch seconds. A malformed timestamp is a typed
/// [`RosterError::BadTimestamp`] — NEVER a panic (`chrono::DateTime::parse_from_rfc3339` is in
/// chrono core and works under the crate's `default-features = false, features = ["alloc"]` set).
fn parse_rfc3339(s: &str) -> Result<i64, RosterError> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp())
        .map_err(|e| RosterError::BadTimestamp(format!("{s:?}: {e}")))
}

/// Full validation for INSTALLING a new roster (spec §4.3 rules 1–6, all MUST). On success
/// returns the resolvable [`RosterView`]. `installed_serial` is the current installed serial (0
/// if none); `now_epoch` is wall-clock seconds (a parameter — the caller supplies `epoch_now`).
pub fn validate_for_install(
    roster: &Roster,
    root_pk: &VerifyingKey,
    installed_serial: u64,
    now_epoch: i64,
) -> Result<RosterView, RosterError> {
    // Rule 6 / format: reject any non-`mcpmesh-roster/1` document up front.
    if roster.format != ROSTER_FORMAT {
        return Err(RosterError::BadFormat(roster.format.clone()));
    }
    // Rule 1: signature.
    verify(roster, root_pk)?;
    // Rule 2: strictly-increasing serial (rollback protection).
    if roster.serial <= installed_serial {
        return Err(RosterError::StaleSerial {
            got: roster.serial,
            installed: installed_serial,
        });
    }
    // Rule 3: validity window with ±skew (BOTH bounds).
    let issued = parse_rfc3339(&roster.issued_at)?;
    let expires = parse_rfc3339(&roster.expires_at)?;
    if now_epoch < issued - SKEW_SECS || now_epoch > expires + SKEW_SECS {
        return Err(RosterError::OutOfValidity);
    }
    // Rules 4 + 5 + build the view.
    build_view(roster, expires)
}

/// Re-verify + rebuild the view for LOADING an already-installed roster at startup. Verifies the
/// signature (rule 1) and structural rules (4, 5), but NOT expiry/serial — a legitimately-expired
/// installed roster loads into degraded mode ([RECONCILE-C] install-vs-load).
pub fn load_installed(roster: &Roster, root_pk: &VerifyingKey) -> Result<RosterView, RosterError> {
    if roster.format != ROSTER_FORMAT {
        return Err(RosterError::BadFormat(roster.format.clone()));
    }
    verify(roster, root_pk)?;
    let expires = parse_rfc3339(&roster.expires_at)?;
    build_view(roster, expires)
}

/// Dial-candidate ordering rank for a device role (spec §10.1): `"primary"` first, then `"mirror"`,
/// then any other role. Pure — an unrecognized role sorts last rather than erroring (the roster is
/// org-root-signed; an unknown role is a forward-compat value, not an attack).
fn role_rank(role: &str) -> u8 {
    match role {
        "primary" => 0,
        "mirror" => 1,
        _ => 2,
    }
}

/// Rules 4 (dup/conflicting endpoints) + 5 (flat-namespace disjointness + declared groups) +
/// assemble the view.
fn build_view(roster: &Roster, expires_at_epoch: i64) -> Result<RosterView, RosterError> {
    // Rule 5 (MUST, spec §4.3): user_ids ∪ groups is ONE flat, DECLARED namespace. Two checks:
    //   (5a) no user_id equals a top-level group name (disjointness);
    //   (5b) every group a user carries is DECLARED in the top-level `roster.groups` — so a signed
    //        roster cannot give user A an ad-hoc `groups:["X"]` while user B has `user_id:"X"`,
    //        which would make `allow=["X"]` ambiguous. The full namespace is exactly
    //        `roster.groups ∪ {user_id}` and every reference resolves into it.
    let group_set: HashSet<&str> = roster.groups.iter().map(String::as_str).collect();
    let mut seen_users: HashSet<&str> = HashSet::new();
    for u in &roster.users {
        // Defensive completeness (beyond §4.3 rules 1–6, parallel to rule 4's endpoint uniqueness):
        // a repeated `user_id` makes `allow = ["alice"]` ambiguous (which alice?). The roster is
        // org-root-signed so this is an integrity footgun, not an attack — reject it like a dup
        // endpoint for a single, unambiguous identity per name.
        if !seen_users.insert(u.user_id.as_str()) {
            return Err(RosterError::DuplicateUser(u.user_id.clone()));
        }
        // (5a) disjointness.
        if group_set.contains(u.user_id.as_str()) {
            return Err(RosterError::NamespaceCollision(u.user_id.clone()));
        }
        // (5b) every user group must be declared top-level.
        for g in &u.groups {
            if !group_set.contains(g.as_str()) {
                return Err(RosterError::UndeclaredGroup(g.clone()));
            }
        }
    }

    // Rule 4: revoked set first (revocation wins), then active devices EXCLUDING revoked ones.
    let mut revoked: HashSet<[u8; 32]> = HashSet::new();
    for e in &roster.revoked_endpoints {
        revoked.insert(decode_endpoint_id(e)?);
    }

    let mut devices: HashMap<[u8; 32], ResolvedDevice> = HashMap::new();
    for u in &roster.users {
        for d in &u.devices {
            let eid = decode_endpoint_id(&d.endpoint_id)?;
            if revoked.contains(&eid) {
                // Rule 4b: listed under a user AND revoked → revocation wins; warn, skip as active.
                tracing::warn!(user = %u.user_id, "roster: endpoint is both active and revoked — revocation wins");
                continue;
            }
            // Rule 4a: at most once across users.
            if devices.contains_key(&eid) {
                return Err(RosterError::DuplicateEndpoint);
            }
            devices.insert(
                eid,
                ResolvedDevice {
                    user_id: u.user_id.clone(),
                    groups: u.groups.clone(),
                    role: d.role.clone(),
                    label: d.label.clone(),
                },
            );
        }
    }

    Ok(RosterView {
        org_id: roster.org_id.clone(),
        serial: roster.serial,
        expires_at_epoch,
        devices,
        revoked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::sign::mint_signed;
    use crate::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
    use ed25519_dalek::SigningKey;

    fn root() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    // A valid body: serial 5, wide validity window, alice(team-eng,all)+laptop, nothing revoked.
    fn body(serial: u64) -> Roster {
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
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
            revoked_endpoints: vec![],
            sig: String::new(),
        }
    }
    const NOW: i64 = 1_760_000_000; // inside [2000, 2999]

    #[test] // Rule 1 (belt-and-suspenders over T2): a bad sig fails validate_for_install.
    fn rule1_bad_signature_rejected() {
        let mut r = mint_signed(&root(), body(5));
        r.serial = 6; // tamper AFTER signing → sig no longer matches
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 0, NOW),
            Err(RosterError::BadSignature)
        ));
    }

    #[test] // Rule 2: serial must be strictly greater than installed.
    fn rule2_serial_must_strictly_increase() {
        let r = mint_signed(&root(), body(5));
        // installed=5 → 5 is NOT > 5.
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 5, NOW),
            Err(RosterError::StaleSerial {
                got: 5,
                installed: 5
            })
        ));
        // installed=4 → 5 > 4 passes.
        assert!(validate_for_install(&r, &root().verifying_key(), 4, NOW).is_ok());
    }

    #[test] // Rule 3: now must be within [issued-skew, expires+skew].
    fn rule3_validity_window_with_skew() {
        let mut b = body(5);
        b.issued_at = "2026-07-03T12:00:00Z".into();
        b.expires_at = "2026-07-03T12:00:00Z".into(); // issued == expires
        let issued = 1_783_080_000; // 2026-07-03T12:00:00Z epoch (verified: 2026 is not a leap year)
        let r = mint_signed(&root(), b);
        let pk = root().verifying_key();
        // within skew of the instant → ok.
        assert!(validate_for_install(&r, &pk, 0, issued).is_ok());
        assert!(validate_for_install(&r, &pk, 0, issued + super::super::SKEW_SECS).is_ok());
        // beyond skew (expired) → OutOfValidity.
        assert!(matches!(
            validate_for_install(&r, &pk, 0, issued + super::super::SKEW_SECS + 1),
            Err(RosterError::OutOfValidity)
        ));
        // before issued beyond skew → OutOfValidity.
        assert!(matches!(
            validate_for_install(&r, &pk, 0, issued - super::super::SKEW_SECS - 1),
            Err(RosterError::OutOfValidity)
        ));
    }

    #[test] // Rule 4a: an endpoint_id appearing under two users is rejected.
    fn rule4_duplicate_endpoint_across_users_rejected() {
        let mut b = body(5);
        b.users.push(RosterUser {
            user_id: "bob".into(),
            display_name: "Bob".into(),
            user_pk: encode_b64u(&[3u8; 32]),
            groups: vec!["all".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(&[2u8; 32]), // SAME as alice's
                label: "dup".into(),
                role: "primary".into(),
            }],
        });
        let r = mint_signed(&root(), b);
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 0, NOW),
            Err(RosterError::DuplicateEndpoint)
        ));
    }

    #[test] // Rule 4b: an endpoint both under a user AND revoked → accepted (warn), revocation wins.
    fn rule4_revoked_overlap_is_accepted_and_revocation_wins() {
        let mut b = body(5);
        b.revoked_endpoints = vec![encode_b64u(&[2u8; 32])]; // alice's laptop, also revoked
        let r = mint_signed(&root(), b);
        let view =
            validate_for_install(&r, &root().verifying_key(), 0, NOW).expect("accepted with warn");
        // Revocation wins: the endpoint resolves to NOTHING (not an active device) but IS revoked.
        assert!(view.resolve(&[2u8; 32]).is_none());
        assert!(view.is_revoked(&[2u8; 32]));
    }

    #[test] // Rule 5a: user_ids and top-level groups must be disjoint (no name is both).
    fn rule5_user_id_and_group_names_must_be_disjoint() {
        let mut b = body(5);
        b.groups.push("alice".into()); // "alice" is already a user_id
        let r = mint_signed(&root(), b);
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 0, NOW),
            Err(RosterError::NamespaceCollision(n)) if n == "alice"
        ));
    }

    #[test] // Rule 5b: each user's `groups` MUST be a subset of the top-level `roster.groups`.
    fn rule5_user_groups_must_be_declared_in_top_level_groups() {
        // Ad-hoc group "X" on alice, NOT declared in roster.groups → the whole roster is rejected.
        // This closes the ambiguity where user A gets an ad-hoc `groups:["X"]` while some other user
        // has `user_id:"X"`, making `allow=["X"]` mean two things. One flat, DECLARED namespace.
        let mut b = body(5);
        b.users[0].groups.push("X".into()); // "X" ∉ roster.groups (["team-eng","all"])
        let r = mint_signed(&root(), b);
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 0, NOW),
            Err(RosterError::UndeclaredGroup(n)) if n == "X"
        ));
        // Control: a user group that IS declared passes (alice already has team-eng+all, both declared).
        assert!(
            validate_for_install(
                &mint_signed(&root(), body(5)),
                &root().verifying_key(),
                0,
                NOW
            )
            .is_ok()
        );
    }

    #[test] // The view resolves an active device to (user_id, groups); degraded state tracks expiry.
    fn view_resolves_and_computes_degraded_state() {
        let r = mint_signed(&root(), body(5));
        let view = validate_for_install(&r, &root().verifying_key(), 0, NOW).unwrap();
        let d = view.resolve(&[2u8; 32]).expect("alice's laptop resolves");
        assert_eq!(d.user_id, "alice");
        assert_eq!(d.groups, vec!["team-eng".to_string(), "all".to_string()]);
        assert!(view.resolve(&[42u8; 32]).is_none()); // unknown endpoint

        // Degraded state: expires_at is 2999; grace 72h. now inside → Approved.
        assert_eq!(view.state(NOW, 72 * 3600), RosterState::Approved);
        // Force expiry: now just past expires_at but within grace → DegradedGrace.
        let exp = view.expires_at_epoch();
        assert_eq!(view.state(exp + 1, 72 * 3600), RosterState::DegradedGrace);
        // Past expires_at + grace → DegradedStopped.
        assert_eq!(
            view.state(exp + 72 * 3600 + 1, 72 * 3600),
            RosterState::DegradedStopped
        );
    }

    #[test] // load_installed accepts an EXPIRED-but-valid roster into degraded mode; install rejects it.
    fn load_installed_accepts_expired_into_degraded_but_install_rejects() {
        // A roster whose validity window is entirely in the PAST (issued+expires both < NOW).
        let mut b = body(5);
        b.issued_at = "2000-01-01T00:00:00Z".into();
        b.expires_at = "2020-01-01T00:00:00Z".into(); // long expired relative to NOW (2025-ish)
        let r = mint_signed(&root(), b);
        let pk = root().verifying_key();

        // load_installed: sig + structure valid → SUCCEEDS even though expired (fail-closed load).
        let view =
            load_installed(&r, &pk).expect("expired-but-valid roster loads into degraded mode");
        let exp = view.expires_at_epoch();
        // Past expires_at but within grace → DegradedGrace (keeps serving, warns).
        assert_eq!(view.state(exp + 1, 72 * 3600), RosterState::DegradedGrace);
        // Past expires_at + grace → DegradedStopped (inbound serving stops).
        assert_eq!(
            view.state(exp + 72 * 3600 + 1, 72 * 3600),
            RosterState::DegradedStopped
        );
        // Sanity: it never reports Approved once past expiry.
        assert_ne!(view.state(NOW, 72 * 3600), RosterState::Approved);

        // Control — install-vs-load distinction: validate_for_install on the SAME roster REJECTS
        // (rule 3 validity window; install requires currently-valid, load tolerates expired).
        assert!(matches!(
            validate_for_install(&r, &pk, 0, NOW),
            Err(RosterError::OutOfValidity)
        ));
    }

    #[test] // Defensive completeness (beyond §4.3 1-6): a repeated user_id is rejected (ambiguous identity).
    fn duplicate_user_id_across_entries_rejected() {
        // Two DISTINCT user entries both `user_id="alice"` (distinct endpoints so it's the user_id,
        // not rule-4's endpoint check, that fires) → `allow=["alice"]` would be ambiguous → reject.
        let mut b = body(5);
        b.users.push(RosterUser {
            user_id: "alice".into(), // SAME user_id as the first entry
            display_name: "Alice Two".into(),
            user_pk: encode_b64u(&[3u8; 32]),
            groups: vec!["all".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(&[3u8; 32]), // DIFFERENT endpoint than the first alice
                label: "phone".into(),
                role: "primary".into(),
            }],
        });
        let r = mint_signed(&root(), b);
        assert!(matches!(
            validate_for_install(&r, &root().verifying_key(), 0, NOW),
            Err(RosterError::DuplicateUser(n)) if n == "alice"
        ));

        // Control: a second user with a DISTINCT user_id still passes.
        let mut b2 = body(5);
        b2.users.push(RosterUser {
            user_id: "bob".into(),
            display_name: "Bob".into(),
            user_pk: encode_b64u(&[3u8; 32]),
            groups: vec!["all".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(&[3u8; 32]),
                label: "phone".into(),
                role: "primary".into(),
            }],
        });
        assert!(
            validate_for_install(&mint_signed(&root(), b2), &root().verifying_key(), 0, NOW)
                .is_ok()
        );
    }

    #[test]
    fn devices_for_user_lists_active_devices_with_roles_primary_first() {
        // alice with a primary laptop [2;32] and a mirror desktop [3;32]; a revoked [4;32] excluded.
        let mut b = body(5);
        b.users[0].devices.push(RosterDevice {
            endpoint_id: encode_b64u(&[3u8; 32]),
            label: "desktop".into(),
            role: "mirror".into(),
        });
        b.users[0].devices.push(RosterDevice {
            endpoint_id: encode_b64u(&[4u8; 32]),
            label: "old".into(),
            role: "primary".into(),
        });
        b.revoked_endpoints = vec![encode_b64u(&[4u8; 32])]; // [4;32] revoked → excluded
        let view = validate_for_install(&mint_signed(&root(), b), &root().verifying_key(), 0, NOW)
            .unwrap();
        let devs = view.devices_for_user("alice");
        assert_eq!(
            devs,
            vec![
                ([2u8; 32], "primary".to_string()),
                ([3u8; 32], "mirror".to_string())
            ]
        );
        assert!(view.devices_for_user("nobody").is_empty());
    }

    #[test]
    fn effective_state_folds_expiry_and_staleness_taking_the_worse() {
        // A roster valid far into the future (never expiry-degraded).
        let r = mint_signed(&root(), body(5));
        let view = validate_for_install(&r, &root().verifying_key(), 0, NOW).unwrap();
        let grace = 72 * 3600;
        let max_staleness = 24 * 3600;

        // Freshly confirmed (last_confirmed == now) → Approved.
        assert_eq!(
            view.effective_state(NOW, grace, Some(NOW), max_staleness),
            RosterState::Approved
        );
        // Stale past max_staleness but within grace → DegradedGrace (warn, keep serving).
        let lc = NOW - max_staleness - 10;
        assert_eq!(
            view.effective_state(NOW, grace, Some(lc), max_staleness),
            RosterState::DegradedGrace
        );
        // Stale past max_staleness + grace → DegradedStopped (serving stops, spec §4.3 bound).
        let lc = NOW - max_staleness - grace - 10;
        assert_eq!(
            view.effective_state(NOW, grace, Some(lc), max_staleness),
            RosterState::DegradedStopped
        );
        // last_confirmed None → no freshness constraint (back-compat) → expiry-state only (Approved).
        assert_eq!(
            view.effective_state(NOW, grace, None, max_staleness),
            RosterState::Approved
        );

        // Worse-of: an EXPIRED roster that was freshly confirmed still degrades via EXPIRY.
        let mut b = body(6);
        b.issued_at = "2000-01-01T00:00:00Z".into();
        b.expires_at = "2020-01-01T00:00:00Z".into(); // long expired vs NOW
        let expired = load_installed(&mint_signed(&root(), b), &root().verifying_key()).unwrap();
        assert_eq!(
            expired.effective_state(NOW, grace, Some(NOW), max_staleness),
            RosterState::DegradedStopped
        );
    }
}
