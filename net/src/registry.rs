//! A generic, trust-agnostic registry of live mesh connections, for D8 revocation-severing
//! (spec §4.3 rule 6, §4.5). `run_mesh_connection` CHECK-REGISTERS each accepted connection (the
//! `// M3: a connection registry attaches here` seam) and holds the returned RAII [`Registration`]
//! for the connection's lifetime; on close (handler return) the guard DEREGISTERS. The roster
//! install path (cli) calls [`ConnRegistry::sever_matching`] with a predicate computed from the
//! new roster — net owns the MECHANISM (handles + close), the cli owns the POLICY (which to sever).
//!
//! **The D8 TOCTOU close (why a to-be-severed peer can never keep a live session).** A connection's
//! `gate.resolve()` may run BEFORE a roster install swaps the view, but its registration lands
//! AFTER the install's `sever_matching` pass — a naive `register` would let that connection escape
//! severing. We close the race with a CHECKED register serialized on the SAME mutex `sever_matching`
//! takes: [`ConnRegistry::register_checked`] re-evaluates, UNDER the registry lock, the caller's
//! recheck predicate against the live gate (`should_sever_now` — since M3c the daemon supplies the
//! FULL `should_sever_now(eid, roster_user)`, both halves of rule 6), and if it fires does NOT insert
//! (the caller self-closes). Combined with the installer's **swap-before-sever** ordering (swap the
//! roster view, THEN sever), every interleaving is safe:
//!  - (i) checked-register wins the mutex, reads the OLD view (swap not yet done) → inserts; the
//!    installer's later `sever_matching` (same mutex, AFTER its swap completed) finds and closes it;
//!  - (ii) swap done, checked-register acquires the mutex, reads the NEW view → should-sever →
//!    self-close, no insert;
//!  - (iii) swap + sever both done, checked-register acquires the mutex, reads the NEW view →
//!    should-sever → self-close, no insert.
//!
//! There is NO interleaving where a to-be-severed endpoint both inserts and survives. (`sever_matching`'s
//! predicate is computed into plain sets BEFORE it takes the mutex, so it holds only the registry
//! lock — no lock cycle with the gate's own lock that the recheck predicate reads.)
//!
//! **Scope — this closes BOTH halves of rule 6 (M3c).** The recheck is the full `should_sever`
//! predicate (via the gate's `should_sever_now(eid, roster_user)`), so the three-case argument above
//! extends unchanged to both severing causes. (1) The REVOKED half — a compromised/lost device
//! handled via `org revoke` → `revoked_endpoints` → `is_revoked` — can never keep a live session
//! (revocation is the AC case, honored even when degraded, fail-closed; closed in M3a). (2) The
//! DROPPED-from-roster half — a previously roster-resolved endpoint (`roster_user.is_some()`) now
//! ABSENT from the installed roster but NOT revoked (a benign DEPARTURE: a user removed from the
//! roster) — is now ALSO closed by the recheck: `should_sever_now` returns `true` for it under the
//! NEW view, so the register-after-sever race can no longer leave such a connection live. Both halves
//! are rechecked under the registry lock, serialized against `sever_matching`; a pairing-only
//! endpoint (`roster_user == None`, not revoked) is never severed by a roster install.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::identity::EndpointId;

/// One tracked live connection.
struct Tracked {
    endpoint_id: EndpointId,
    /// `Some(user_id)` when resolved via the ROSTER (spec §4.3 rule 6 "previously resolved via the
    /// roster" discriminator); `None` for a pairing-resolved connection (never severed by a roster
    /// install unless revoked).
    roster_user: Option<String>,
    conn: iroh::endpoint::Connection, // Clone = another handle to the SAME connection (iroh 1.0.1)
}

/// Live-connection registry. Keyed by a registry-issued monotonic id (NOT iroh's `stable_id`, to
/// avoid any reuse-after-close ambiguity); the RAII guard removes exactly its own entry.
#[derive(Default)]
pub struct ConnRegistry {
    inner: Mutex<HashMap<u64, Tracked>>,
    seq: AtomicU64,
}

/// RAII deregistration guard — held by the connection handler for the connection's lifetime.
pub struct Registration {
    registry: Arc<ConnRegistry>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.registry
            .inner
            .lock()
            .expect("conn registry mutex")
            .remove(&self.id);
    }
}

/// The D8 sever decision (spec §4.3 rule 6), pure + unit-testable: sever iff the endpoint is
/// `revoked` by the new roster, OR it was roster-resolved (`roster_user.is_some()`) AND is absent
/// from the new roster's `active_devices` set. A pairing-only endpoint (`roster_user == None`, not
/// revoked) is NEVER severed by a roster install. The cli wraps this with the concrete sets from
/// the just-installed view (net owns the generic rule; the roster MEANING of the inputs is cli's).
pub fn should_sever(
    endpoint_id: &EndpointId,
    roster_user: Option<&str>,
    revoked: &std::collections::HashSet<EndpointId>,
    active_devices: &std::collections::HashSet<EndpointId>,
) -> bool {
    revoked.contains(endpoint_id)
        || (roster_user.is_some() && !active_devices.contains(endpoint_id))
}

impl ConnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// CHECK-register a live connection (the D8 TOCTOU close — see the module doc). UNDER the
    /// registry lock: if `should_sever_now(endpoint_id)` (the FULL rule-6 sever predicate against
    /// the live gate, possibly just swapped by a concurrent install — revoked OR roster-resolved-
    /// but-dropped) → return `None` WITHOUT inserting (the caller self-closes); else insert
    /// and return the RAII guard. Serializing the recheck+insert on the SAME lock `sever_matching`
    /// takes is what makes the race provably closed. The guard deregisters on drop (connection close).
    pub fn register_checked(
        self: &Arc<Self>,
        conn: &iroh::endpoint::Connection,
        roster_user: Option<String>,
        should_sever_now: impl FnOnce(&EndpointId) -> bool,
    ) -> Option<Registration> {
        let endpoint_id = *conn.remote_id().as_bytes();
        let mut map = self.inner.lock().expect("conn registry mutex");
        if should_sever_now(&endpoint_id) {
            return None; // to-be-severed as of the live gate → refuse; caller self-closes (no insert).
        }
        let id = self.seq.fetch_add(1, Ordering::Relaxed);
        map.insert(
            id,
            Tracked {
                endpoint_id,
                roster_user,
                conn: conn.clone(),
            },
        );
        Some(Registration {
            registry: self.clone(),
            id,
        })
    }

    /// Close every tracked connection for which `should_sever(endpoint_id, roster_user)` is true
    /// (spec §4.3 rule 6 / §4.5, D8). Returns the count severed. The QUIC close (`code`, `reason`)
    /// tears the connection down across every stream/session; each handler task's guard then
    /// deregisters it as it unwinds. Holds ONLY the registry lock (the predicate is precomputed by
    /// the cli into plain sets); `close` is non-blocking.
    pub fn sever_matching(
        &self,
        code: u32,
        reason: &[u8],
        should_sever: impl Fn(&EndpointId, Option<&str>) -> bool,
    ) -> usize {
        let map = self.inner.lock().expect("conn registry mutex");
        let mut n = 0;
        for t in map.values() {
            if should_sever(&t.endpoint_id, t.roster_user.as_deref()) {
                t.conn.close(code.into(), reason);
                n += 1;
            }
        }
        n
    }

    /// Number of tracked live connections (for the T9 integration test's accounting assertions).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("conn registry mutex").len()
    }

    /// Whether no live connection is tracked (clippy's `len_without_is_empty` companion).
    pub fn is_empty(&self) -> bool {
        self.inner.lock().expect("conn registry mutex").is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The D8 sever rule (spec §4.3 rule 6), exhaustively: revoked ∪ {roster-resolved AND absent
    /// from the new device set}; never a pairing-only peer.
    #[test]
    fn should_sever_selects_revoked_and_dropped_roster_but_not_pairing() {
        let revoked: HashSet<EndpointId> = [[3u8; 32]].into_iter().collect(); // endpoint revoked
        let devices: HashSet<EndpointId> = [[2u8; 32]].into_iter().collect(); // still-active device
        // (a) roster-resolved + still a device → KEEP.
        assert!(!should_sever(&[2u8; 32], Some("alice"), &revoked, &devices));
        // (b) revoked (regardless of source — even a pairing peer that got revoked) → SEVER.
        assert!(should_sever(&[3u8; 32], Some("alice"), &revoked, &devices));
        assert!(
            should_sever(&[3u8; 32], None, &revoked, &devices),
            "revocation wins over pairing"
        );
        // (c) roster-resolved but DROPPED from the new roster (absent from devices, not revoked) → SEVER.
        assert!(should_sever(&[9u8; 32], Some("bob"), &revoked, &devices));
        // (d) pairing-only (roster_user None), not revoked → KEEP (never severed by a roster install).
        assert!(!should_sever(&[9u8; 32], None, &revoked, &devices));
    }
}
