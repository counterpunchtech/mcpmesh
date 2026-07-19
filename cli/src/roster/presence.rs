//! Presence (spec §10.1, roster mode only): a device-key-signed heartbeat gossiped on
//! `blake3("mcpmesh/presence/"+org_id)`. ADVISORY — it feeds `status` + the person→device dial
//! ordering; no security decision derives from it (absence never blocks a dial). Message-level
//! verify: sig against the sender's endpoint_id (which IS its device ed25519 pubkey) + `|now-ts|<120s`.
//! The TRACK loop ADDITIONALLY binds the claimed user_id to the roster's AUTHORITATIVE user for that
//! endpoint_id (a rostered device cannot advertise under a peer's user_id). Entries expire after 180s.
//! ≤ 512 B (P9). [RECONCILE-PRESENCE].
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use mcpmesh_trust::roster::validate::RosterView;
use serde::{Deserialize, Serialize};

const PRESENCE_DOMAIN: &[u8] = b"mcpmesh/presence/1";
pub const PRESENCE_SKEW_SECS: i64 = 120;
pub const PRESENCE_TTL_SECS: i64 = 180;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    pub t: String,           // "presence"
    pub endpoint_id: String, // b64u: (the device ed25519 pubkey = the endpoint id)
    pub user_id: String,
    pub ts: i64,            // epoch seconds
    pub roster_serial: u64, // doubles as roster-update discovery (spec §10.1)
    pub sig: String,        // b64u:
}

fn preimage(endpoint_id: &[u8; 32], user_id: &str, ts: i64, serial: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(PRESENCE_DOMAIN.len() + 32 + user_id.len() + 16);
    m.extend_from_slice(PRESENCE_DOMAIN);
    m.extend_from_slice(endpoint_id);
    m.extend_from_slice(user_id.as_bytes());
    m.extend_from_slice(&ts.to_le_bytes());
    m.extend_from_slice(&serial.to_le_bytes());
    m
}

impl Presence {
    /// Sign a heartbeat with this device's key (the ed25519 key whose public half IS the endpoint id).
    pub fn signed(
        device_key: &SigningKey,
        endpoint_id: &[u8; 32],
        user_id: &str,
        ts: i64,
        serial: u64,
    ) -> Self {
        use ed25519_dalek::Signer;
        let sig = device_key.sign(&preimage(endpoint_id, user_id, ts, serial));
        Self {
            t: "presence".into(),
            endpoint_id: mcpmesh_trust::roster::encode_b64u(endpoint_id),
            user_id: user_id.to_string(),
            ts,
            roster_serial: serial,
            sig: mcpmesh_trust::roster::encode_b64u(&sig.to_bytes()),
        }
    }
    /// Message-level verify (sig against the endpoint-as-pubkey + ±120s). Returns the verified
    /// endpoint bytes; never panics on malformed input. The caller then binds the user_id to the roster.
    pub fn verify(&self, now: i64) -> Option<[u8; 32]> {
        // `ts` is deserialized straight from arbitrary gossip bytes, so `now - ts` must not overflow
        // (a crafted `ts == i64::MIN` would panic the plain subtraction/`abs` in debug) — saturate.
        if self.t != "presence"
            || now.saturating_sub(self.ts).saturating_abs() >= PRESENCE_SKEW_SECS
        {
            return None;
        }
        let eid = mcpmesh_trust::roster::decode_endpoint_id(&self.endpoint_id).ok()?;
        let vk = VerifyingKey::from_bytes(&eid).ok()?;
        let sig =
            Signature::from_slice(&mcpmesh_trust::roster::decode_b64u(&self.sig).ok()?).ok()?;
        vk.verify_strict(
            &preimage(&eid, &self.user_id, self.ts, self.roster_serial),
            &sig,
        )
        .ok()?;
        Some(eid)
    }
    /// Full track-side acceptance (\[Minor\] 5): message-valid AND the claimed `user_id` matches the
    /// roster's AUTHORITATIVE user for this endpoint (an active rostered device). Returns the verified
    /// endpoint on success — a rostered device advertising under a PEER's user_id is REJECTED here.
    pub fn accept(&self, now: i64, view: &RosterView) -> Option<[u8; 32]> {
        let eid = self.verify(now)?;
        let resolved = view.resolve(&eid)?; // endpoint_id ∈ roster (active) — else drop (P9)
        if resolved.user_id == self.user_id {
            Some(eid)
        } else {
            None
        } // user_id binding
    }

    /// The compact JSON gossip payload (the ≤512B heartbeat, P9). Infallible for this fixed shape
    /// (Strings + integers always encode), so an `expect` here signals a serde-internal bug.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Presence serializes")
    }

    /// Parse a received presence payload. NEVER panics on hostile/garbage peer bytes (the gossip
    /// receive path is fed arbitrary input) — a malformed payload is `None`, which the track loop
    /// drops. (The signature + user_id binding are checked afterward by [`Self::verify`]/[`Self::accept`].)
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// A tracked peer's most-recent VERIFIED heartbeat (advisory — the user_id was bound to the roster's
/// authoritative user by [`Presence::accept`] before it was recorded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceEntry {
    pub user_id: String,
    pub ts: i64,
}

/// The advisory presence table (spec §10.1): the freshest verified heartbeat per endpoint. Records
/// are ADVISORY-ONLY — NOTHING here feeds a gate, an authz check, or a sever decision. Absence of an
/// entry NEVER blocks or denies anything; T11's dial reads it purely for candidate ORDERING/recency
/// (a peer with no entry is still dialed). Entries older than [`PRESENCE_TTL_SECS`] (180s) are
/// filtered out by [`active`](PresenceTable::active). A plain `std::sync::Mutex` (no await under the
/// lock — every critical section is a quick map op), mirroring the plan's `Mutex<HashMap<..>>`.
#[derive(Debug, Default)]
pub struct PresenceTable {
    inner: std::sync::Mutex<std::collections::HashMap<[u8; 32], PresenceEntry>>,
}

impl PresenceTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a VERIFIED heartbeat (called ONLY after [`Presence::accept`] bound the user_id to the
    /// roster). Keeps the freshest `ts` per endpoint so a reordered/older beat never regresses recency.
    pub fn record(&self, eid: [u8; 32], user_id: String, ts: i64) {
        let mut g = self.inner.lock().expect("presence table mutex poisoned");
        match g.get(&eid) {
            Some(e) if e.ts >= ts => {} // an older/duplicate beat does not regress recency
            _ => {
                g.insert(eid, PresenceEntry { user_id, ts });
            }
        }
    }

    /// The active (non-expired) entries at `now` — `now - ts < 180` ([`PRESENCE_TTL_SECS`]). Advisory
    /// read (status + T11 dial ordering); no security decision consults it.
    pub fn active(&self, now: i64) -> Vec<([u8; 32], PresenceEntry)> {
        let g = self.inner.lock().expect("presence table mutex poisoned");
        g.iter()
            .filter(|(_, e)| now - e.ts < PRESENCE_TTL_SECS)
            .map(|(eid, e)| (*eid, e.clone()))
            .collect()
    }

    /// The endpoints currently advertising `user_id`, MOST-RECENT FIRST (the T11 person→device dial
    /// ordering, spec §10.1). Advisory ONLY — this orders dial candidates; it never authorizes a dial.
    pub fn endpoints_for_user_by_recency(&self, user_id: &str) -> Vec<[u8; 32]> {
        let g = self.inner.lock().expect("presence table mutex poisoned");
        let mut hits: Vec<(&[u8; 32], &PresenceEntry)> =
            g.iter().filter(|(_, e)| e.user_id == user_id).collect();
        hits.sort_by_key(|(_, e)| std::cmp::Reverse(e.ts)); // most recent first
        hits.into_iter().map(|(eid, _)| *eid).collect()
    }
}

/// Presence publish loop (spec §10.1, roster mode only): every `60s ± jitter`, build + sign a
/// heartbeat with this device's key (whose public half IS the endpoint id) and broadcast it on the
/// presence topic. `roster_serial` is read FRESH each beat from the installed view (it doubles as the
/// roster-update discovery hint, §10.1). ADVISORY — a beat authorizes nothing; peers RECORD it only
/// after binding its user_id to their roster. Mirrors [`distribute::spawn_receive_loop`]'s structure
/// (own the sender from `MeshState`); a `None` presence-topic sender (pure-pairing, or subscribe
/// failed) returns immediately.
///
/// [`distribute::spawn_receive_loop`]: crate::roster::distribute::spawn_receive_loop
pub fn publish_loop(
    mesh: std::sync::Arc<crate::daemon::MeshState>,
    device_key: SigningKey,
    user_id: String,
) -> tokio::task::JoinHandle<()> {
    use crate::roster::transport;
    tokio::spawn(async move {
        let endpoint_id = device_key.verifying_key().to_bytes();
        let Some(sender) = mesh.presence_topic_sender().await else {
            return; // pure-pairing daemon, or the presence-topic subscribe failed — no heartbeat
        };
        loop {
            let now = crate::util::epoch_now_i64();
            let serial = mesh.roster.view().map(|v| v.serial()).unwrap_or(0);
            let beat = Presence::signed(&device_key, &endpoint_id, &user_id, now, serial);
            if let Err(e) = transport::broadcast(&sender, beat.to_bytes()).await {
                tracing::debug!(%e, "presence heartbeat broadcast failed; will retry next beat");
            }
            tokio::time::sleep(std::time::Duration::from_secs(next_beat_secs())).await;
        }
    })
}

/// Presence track loop (spec §10.1, roster mode only): pull heartbeats off the presence topic, accept
/// each against the INSTALLED roster ([`Presence::accept`] — the message sig AND the user_id-to-roster
/// binding, \[Minor\] 5), and RECORD the verified beat into the advisory [`PresenceTable`]. This is the
/// ONLY thing the track loop does — it touches NO gate, authz check, or sever decision; a dropped or
/// unrostered beat simply never becomes an entry (and absence never blocks a dial). Malformed peer
/// bytes are dropped without a panic. Mirrors [`distribute::spawn_receive_loop`] (take the receiver
/// once); a `None` receiver (pure-pairing, already taken, or subscribe failed) returns immediately.
///
/// [`distribute::spawn_receive_loop`]: crate::roster::distribute::spawn_receive_loop
pub fn track_loop(mesh: std::sync::Arc<crate::daemon::MeshState>) -> tokio::task::JoinHandle<()> {
    use crate::roster::transport;
    tokio::spawn(async move {
        let Some(mut receiver) = mesh.take_presence_topic_receiver().await else {
            return;
        };
        while let Some(content) = transport::next_message(&mut receiver).await {
            let Some(p) = Presence::from_bytes(&content) else {
                tracing::trace!("malformed presence payload dropped");
                continue;
            };
            let now = crate::util::epoch_now_i64();
            // ADVISORY: bind the claimed user_id to the roster-AUTHORITATIVE user for this endpoint,
            // then RECORD only. No gate/authz/sever consults presence — a peer with no installed
            // roster, or whose beat fails the binding, simply produces no entry (never a denial).
            let Some(view) = mesh.roster.view() else {
                continue; // no roster installed yet: nothing to bind against — drop (advisory)
            };
            if let Some(eid) = p.accept(now, &view) {
                mesh.presence_table.record(eid, p.user_id, p.ts);
            }
        }
    })
}

/// The next beat interval: `60s ± jitter` (spec §10.1) to de-synchronize the swarm (no thundering
/// herd), always ≥ 1s and well within the 180s TTL. Jitter is drawn from the OS CSPRNG — the SAME
/// `rand::rngs::OsRng` source the crate's device-key / pairing-secret mint uses.
fn next_beat_secs() -> u64 {
    use rand::RngCore;
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let span = (2 * PRESENCE_JITTER_SECS + 1) as u32; // inclusive [-JITTER, +JITTER]
    let jitter = (u32::from_le_bytes(buf) % span) as i64 - PRESENCE_JITTER_SECS;
    (PRESENCE_PERIOD_SECS + jitter).max(1) as u64
}

/// The presence heartbeat base period (spec §10.1 "≈60s"); the actual sleep is `± PRESENCE_JITTER_SECS`.
const PRESENCE_PERIOD_SECS: i64 = 60;
/// The heartbeat jitter magnitude (± this many seconds around the 60s base). Keeps beats de-correlated
/// while staying far inside the 180s TTL (worst case 75s ≪ 180s → no false expiry).
const PRESENCE_JITTER_SECS: i64 = 15;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mcpmesh_trust::roster::sign::mint_signed;
    use mcpmesh_trust::roster::validate::load_installed;
    use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};

    #[test]
    fn presence_sign_verify_round_trips_and_forgeries_fail() {
        let dk = SigningKey::from_bytes(&[4u8; 32]);
        let eid = dk.verifying_key().to_bytes();
        let now = 1_760_000_000;
        let p = Presence::signed(&dk, &eid, "alice", now, 7);
        assert_eq!(p.verify(now + 5), Some(eid)); // within skew
        assert!(
            p.verify(now + PRESENCE_SKEW_SECS).is_none(),
            "outside ±120s rejected"
        );
        let mut bad = p.clone();
        bad.user_id = "bob".into();
        assert!(bad.verify(now).is_none()); // tampered field breaks the sig
        let mut swapped = p.clone();
        swapped.endpoint_id = encode_b64u(&[9u8; 32]);
        assert!(swapped.verify(now).is_none()); // can't swap the endpoint (it's the pubkey)
        assert!(serde_json::to_vec(&p).unwrap().len() < 512); // P9 512B cap
    }

    #[test]
    fn verify_does_not_overflow_on_a_crafted_extreme_ts() {
        // `ts` is deserialized straight from arbitrary gossip bytes; a crafted i64::MIN/MAX must be
        // rejected at the skew check WITHOUT overflowing the subtraction (a debug-build panic that
        // would kill the presence track loop). The skew gate runs before any sig check.
        let dk = SigningKey::from_bytes(&[4u8; 32]);
        let eid = dk.verifying_key().to_bytes();
        let mut p = Presence::signed(&dk, &eid, "alice", 1_760_000_000, 7);
        p.ts = i64::MIN;
        assert!(p.verify(1_760_000_000).is_none());
        p.ts = i64::MAX;
        assert!(p.verify(i64::MIN).is_none());
    }

    #[test]
    fn accept_binds_user_id_to_the_roster_authoritative_user() {
        // A roster mapping device [4;32] → user "alice".
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let dk = SigningKey::from_bytes(&[4u8; 32]);
        let eid = dk.verifying_key().to_bytes();
        let roster = mint_signed(
            &root,
            Roster {
                format: "mcpmesh-roster/1".into(),
                org_id: "acme".into(),
                serial: 5,
                issued_at: "2000-01-01T00:00:00Z".into(),
                expires_at: "2999-01-01T00:00:00Z".into(),
                groups: vec!["all".into()],
                users: vec![RosterUser {
                    user_id: "alice".into(),
                    display_name: "Alice".into(),
                    user_pk: encode_b64u(&[1u8; 32]),
                    groups: vec!["all".into()],
                    devices: vec![RosterDevice {
                        endpoint_id: encode_b64u(&eid),
                        label: "l".into(),
                        role: "primary".into(),
                    }],
                }],
                revoked_endpoints: vec![],
                sig: String::new(),
            },
        );
        let view = load_installed(&roster, &root.verifying_key()).unwrap();
        let now = 1_760_000_000;
        // Genuine: alice's device advertises as "alice" → accepted.
        assert_eq!(
            Presence::signed(&dk, &eid, "alice", now, 5).accept(now, &view),
            Some(eid)
        );
        // FORGERY ([Minor] 5): alice's device (validly signed) advertises under "bob" → REJECTED,
        // even though the sig verifies and the endpoint is in the roster.
        assert!(
            Presence::signed(&dk, &eid, "bob", now, 5)
                .accept(now, &view)
                .is_none()
        );
        // A device NOT in the roster → rejected (endpoint ∉ roster).
        let stranger = SigningKey::from_bytes(&[7u8; 32]);
        let seid = stranger.verifying_key().to_bytes();
        assert!(
            Presence::signed(&stranger, &seid, "alice", now, 5)
                .accept(now, &view)
                .is_none()
        );
    }
}
