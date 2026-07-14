//! Identity resolution at accept time (spec §3.1, §4, D4/D5).
use std::collections::HashMap;

/// Raw public-key bytes of a device. NOTE: iroh 1.0.1 has its own `iroh::EndpointId`
/// (a type alias to `PublicKey`) — ours is the wire-agnostic byte form; convert via
/// `.as_bytes()` (Task 11, where a newtype is worth revisiting to keep secret bytes
/// and public ids un-crosswirable).
pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The AUTHENTICATED endpoint id (the peer's verified ed25519 pubkey). Stamped by every
    /// `TrustGate::resolve` from the queried key — the rate-limit key (spec §11.2 P7, SECURITY
    /// invariant 1); never a self-asserted value.
    pub endpoint: EndpointId,
    pub name: String,
    // The self-sovereign user_id: the org roster value in roster mode, else the one proven by a
    // verified device->user binding at pairing (`None` only for a pairing peer that presented no
    // binding). Accepter-derived from the trust gate — never self-asserted (spec §6.3).
    pub user_id: Option<String>,
    pub groups: Vec<String>,
}

impl PeerIdentity {
    /// A pairing-mode identity by petname. `endpoint` is zeroed here and STAMPED by the gate's
    /// `resolve` from the queried key (test/bootstrap constructor — production always resolves).
    pub fn petname(name: &str) -> Self {
        Self {
            endpoint: [0u8; 32],
            name: name.into(),
            user_id: None,
            groups: vec![],
        }
    }
}

/// One trait, two production impls later (PairGate M2, RosterGate M3).
pub trait TrustGate: Send + Sync + 'static {
    fn resolve(&self, endpoint: &EndpointId) -> Option<PeerIdentity>;

    /// Is this endpoint revoked by a roster this gate holds? Consulted FIRST by the composed
    /// gate (spec §4.1 precedence 1 — revocation wins over pairing, across all ALPNs) and by the
    /// D8 check-register recheck. Default `false`: pairing/static gates have no revocation
    /// concept (`AllowlistGate`/`StaticGate` inherit this). `RosterGate` OVERRIDES it, honoring
    /// its installed roster's revoked set even when degraded (fail-closed, spec §4.3/§4.5).
    fn is_revoked(&self, _endpoint: &EndpointId) -> bool {
        false
    }

    /// The register-time D8 gate (spec §4.3 rule 6): should a connection from `endpoint` (resolved
    /// with `roster_user`) be severed AS OF the live roster? The generalization of [`is_revoked`] —
    /// it also catches a previously-roster-resolved endpoint now ABSENT from the roster (a benign
    /// departure), closing the dropped-from-roster register-after-sever race symmetrically with the
    /// revoked half. Default `false` (pairing-only gates never sever on a roster). Consulted by
    /// `ConnRegistry::register_checked`'s caller-supplied closure UNDER the registry lock (the
    /// TOCTOU close).
    fn should_sever_now(&self, _endpoint: &EndpointId, _roster_user: Option<&str>) -> bool {
        false
    }

    /// The D8 "roster-resolved" discriminator for a connection from `endpoint`: `Some(user_id)` IFF
    /// this endpoint is a member of the gate's CURRENT roster view (else `None`). This — NOT the
    /// resolved `PeerIdentity::user_id` — is what `register_checked` stores and `should_sever`/
    /// `should_sever_now` key on, because a PAIRING peer now also carries a `user_id` (the verified
    /// self-sovereign device→user binding), so `identity.user_id.is_some()` no longer means
    /// "roster-resolved". Default `None`: pairing/static gates have no roster, so their peers are
    /// never severed by a roster install. `ComposedGate` OVERRIDES it to consult the roster view.
    fn roster_user(&self, _endpoint: &EndpointId) -> Option<String> {
        None
    }
}

/// Test/bootstrap gate: a fixed allowlist.
pub struct StaticGate(HashMap<EndpointId, PeerIdentity>);

impl StaticGate {
    pub fn new(entries: impl IntoIterator<Item = (EndpointId, PeerIdentity)>) -> Self {
        Self(entries.into_iter().collect())
    }
}

impl TrustGate for StaticGate {
    fn resolve(&self, endpoint: &EndpointId) -> Option<PeerIdentity> {
        self.0.get(endpoint).cloned().map(|mut id| {
            id.endpoint = *endpoint; // stamp the authenticated key (SECURITY invariant 1)
            id
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> EndpointId {
        [b; 32]
    }

    #[test]
    fn static_gate_resolves_known_and_refuses_unknown() {
        let gate = StaticGate::new([(id(1), PeerIdentity::petname("bob"))]);
        let got = gate.resolve(&id(1)).expect("known endpoint resolves");
        assert_eq!(got.name, "bob");
        assert_eq!(
            got.endpoint,
            id(1),
            "resolve stamps the AUTHENTICATED endpoint"
        );
        assert!(gate.resolve(&id(2)).is_none());
    }
}
