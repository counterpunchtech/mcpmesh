//! The pair allowlist, persisted in state.redb. Populated by `mcpmesh internal peer add` /
//! config import AND by the pair rendezvous — deliberately the SAME store, so a hand-added
//! peer and a paired peer are indistinguishable to the gate. Entry:
//! `{ endpoint_id, nickname, services }`.
//!
//! redb 2.x shape (reconciled against docs.rs/redb 2.6.3): one table `peers` defined as
//! `TableDefinition<&[u8], &[u8]>` — keyed by the 32-byte endpoint_id passed as a `&[u8]`
//! slice, values are JSON-serialized [`PeerEntry`]. Every mutation is one
//! `begin_write → open_table → insert/remove → commit` transaction, so the store is
//! atomic per redb txn (a torn store is never observable).
//!
//! **Additive-only durable schema.** [`PeerEntry`] is durable on-disk JSON. New fields
//! MUST land as `#[serde(default)]` so entries
//! written by an older binary still deserialize (mirrors the mcpmesh-local-api additive-only
//! convention). A field added without `#[serde(default)]` would make every
//! pre-existing row fail to deserialize; the corrupt-row handling below bounds the blast
//! radius of such a mistake (or of on-disk corruption) per operation.
use anyhow::{Context, Result};
use mcpmesh_net::{EndpointId, PeerIdentity, TrustGate};
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

/// The peer allowlist table: key = 32-byte endpoint_id (as `&[u8]`), value = JSON of a
/// [`PeerEntry`]. Const with an elided (`'static`) name lifetime — the redb-documented
/// pattern for a table definition.
const PEERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("peers");

/// One pair-allowlist entry. `endpoint_id` is the routing key; `nickname` is
/// the local human name the gate resolves peers to; `services` is the set the peer
/// was granted at pairing time. Durable on-disk JSON — see the module additive-only note.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerEntry {
    pub endpoint_id: [u8; 32],
    pub nickname: String,
    pub services: Vec<String>,
    /// When this entry was written by the pair rendezvous, as epoch-seconds-as-`String`
    /// (the daemon supplies it from `SystemTime` — no date crate).
    /// `Option` + `#[serde(default)]` so older rows and non-pairing writes
    /// (`internal peer add`) — which leave it unset — still deserialize (the module
    /// additive-only note). An audit stamp only; the gate never reads it.
    #[serde(default)]
    pub paired_at: Option<String>,
    /// The peer's self-sovereign `user_id` (`b64u:<user_pk>`), proven by a device→user binding it
    /// presented at pairing and verified against its TLS-authenticated endpoint (see
    /// `mcpmesh_trust::binding`). `None` for a peer that presented no binding (backward-compatible) or
    /// an `internal peer add`. Resolved into `PeerIdentity.user_id` so kb audiences can key on the
    /// USER, not just the per-device nickname — first-class multi-device identity in pairing mode
    /// (roster mode already carries `user_id`).
    #[serde(default)]
    pub user_id: Option<String>,
    /// The peer's last-known `iroh::EndpointAddr`, captured at pairing time, as a JSON
    /// **string** — deliberately NOT a nested typed field. [`PeerStore::resolve`] fails
    /// CLOSED on an undeserializable row, so nesting an iroh type here would let any future
    /// iroh serde change poison trust rows and silently unpair peers; a string keeps the row
    /// parseable forever, and an unparseable/stale address degrades gracefully to the
    /// discovery-only dial at use time (mirrors why the invite carries `inviter_addr_json`
    /// as a string). A dial HINT only, never identity: the dial site ignores a stored
    /// address whose embedded id disagrees with `endpoint_id`. `None` for older rows and
    /// `internal peer add`.
    #[serde(default)]
    pub last_addr: Option<String>,
}

/// The peer allowlist store over a redb database file (`state.redb`). Path-agnostic:
/// [`open`](Self::open) takes the file path so the daemon decides where the data
/// dir lives.
pub struct PeerStore {
    db: Database,
}

impl PeerStore {
    /// Open (creating if absent) the store at `path`. Eagerly materializes the `peers`
    /// table inside a committed write txn so reads on a fresh store return empty rather
    /// than erroring on a missing table. The path is carried in the error context: a
    /// corrupt/permission failure on the trust file is exactly when an operator needs it.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)
            .with_context(|| format!("open peer store {}", path.display()))?;
        let txn = db.begin_write()?;
        // open_table creates the table if absent; commit persists the (empty) schema.
        txn.open_table(PEERS)?;
        txn.commit()?;
        Ok(Self { db })
    }

    /// Insert or replace the entry for its `endpoint_id` (idempotent upsert). One atomic
    /// redb transaction.
    pub fn add(&self, e: PeerEntry) -> Result<()> {
        let bytes = serde_json::to_vec(&e)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PEERS)?;
            table.insert(e.endpoint_id.as_slice(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Resolve a peer by its 32-byte endpoint_id, or `None` if not allowlisted.
    ///
    /// Fails CLOSED on a corrupt stored row: a row that will not deserialize (e.g. an
    /// entry written before a non-additive field change, or on-disk corruption) is treated
    /// as unresolvable — `Ok(None)`, i.e. default-DENY — never fail-open.
    /// This is the deliberate opposite of [`list`](Self::list)/[`remove`](Self::remove),
    /// which fail OPEN on admin enumeration: authorization must never be granted off a
    /// row it could not read.
    pub fn resolve(&self, endpoint_id: &[u8; 32]) -> Result<Option<PeerEntry>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PEERS)?;
        match table.get(endpoint_id.as_slice())? {
            Some(v) => match serde_json::from_slice::<PeerEntry>(v.value()) {
                Ok(entry) => Ok(Some(entry)),
                Err(e) => {
                    tracing::warn!(
                        key_prefix = ?&endpoint_id[..8],
                        error = %e,
                        "corrupt peer entry for queried key; treating as unresolved (deny)"
                    );
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    /// Resolve a nickname to its stored entry — the reverse of [`resolve`](Self::resolve)
    /// (which is keyed BY id). The connect proxy's `open_session` dial turns the
    /// user-facing nickname into the 32-byte routing key (plus the entry's `last_addr` dial
    /// hint). Nicknames are NOT unique (see
    /// [`remove`](Self::remove)); the FIRST match in key order wins. Fails OPEN on corrupt
    /// rows (it reuses [`list`](Self::list), which skips-and-logs them) — a poisoned row must
    /// not hide a resolvable peer.
    pub fn entry_for(&self, nickname: &str) -> Result<Option<PeerEntry>> {
        Ok(self.list()?.into_iter().find(|e| e.nickname == nickname))
    }

    /// All stored entries whose proven `user_id` equals `user_id` (a `b64u:` self-sovereign
    /// identifier) — the dial-by-stable-identity lookup (#30). A person's `user_id` spans their
    /// devices, so this can return several entries (one per paired device); the dialer races
    /// them, exactly like the roster person→device path. Entries with no proven `user_id`
    /// (legacy / `internal peer add` rows) never match. Fails OPEN on corrupt rows (reuses
    /// [`list`](Self::list)).
    pub fn entries_for_user(&self, user_id: &str) -> Result<Vec<PeerEntry>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|e| e.user_id.as_deref() == Some(user_id))
            .collect())
    }

    /// All allowlisted peers, in endpoint_id order (redb's key order).
    ///
    /// Fails OPEN on a corrupt stored row: a row that will not deserialize is skipped and
    /// logged (`warn!` with the key prefix) rather than failing the whole scan — a single
    /// poisoned row must not hide every other peer. Conscious trade for an admin READ path
    /// (opposite of [`resolve`](Self::resolve)'s fail-closed authorization).
    pub fn list(&self) -> Result<Vec<PeerEntry>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PEERS)?;
        let mut out = Vec::new();
        for row in table.iter()? {
            let (k, v) = row?;
            match serde_json::from_slice::<PeerEntry>(v.value()) {
                Ok(entry) => out.push(entry),
                Err(e) => {
                    let kb = k.value();
                    tracing::warn!(
                        key_prefix = ?&kb[..kb.len().min(8)],
                        error = %e,
                        "skipping corrupt peer entry during list"
                    );
                }
            }
        }
        Ok(out)
    }

    /// Remove every entry whose `nickname` matches (for `pair --remove`). The table is
    /// keyed by endpoint_id, so this scans within one write txn — find matching keys, then
    /// delete them — keeping the read+delete atomic. No-op if nothing matches.
    ///
    /// NOTE: nicknames are NOT unique (population is `internal peer add` +
    /// `pair`, neither of which enforces uniqueness), so this deletes ALL entries whose
    /// nickname matches — a conscious decision, revisited if a uniqueness invariant lands.
    ///
    /// Fails OPEN on a corrupt row (as [`list`](Self::list)): a row that will not
    /// deserialize can't match the nickname, so it is skipped and logged — unpairing the
    /// other peers must still work.
    ///
    /// Returns whether ANY entry was actually deleted — `false` for an absent nickname (a no-op) — so
    /// callers can distinguish a real removal from a no-op (the `unpair` audit event fires
    /// only on an actual tear-down).
    pub fn remove(&self, nickname: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(PEERS)?;
            let victims: Vec<Vec<u8>> = {
                let mut v = Vec::new();
                for row in table.iter()? {
                    let (k, val) = row?;
                    match serde_json::from_slice::<PeerEntry>(val.value()) {
                        Ok(entry) if entry.nickname == nickname => v.push(k.value().to_vec()),
                        Ok(_) => {}
                        Err(e) => {
                            let kb = k.value();
                            tracing::warn!(
                                key_prefix = ?&kb[..kb.len().min(8)],
                                error = %e,
                                "skipping corrupt peer entry during remove"
                            );
                        }
                    }
                }
                v
            };
            for k in &victims {
                table.remove(k.as_slice())?;
            }
            !victims.is_empty()
        };
        txn.commit()?;
        Ok(removed)
    }
}

/// The production trust gate: a [`TrustGate`] over the
/// [`PeerStore`]. The daemon builds `Arc<AllowlistGate>` and passes it to
/// `mcpmesh_net::serve`; `pair` writes the SAME store this gate reads, so pairing and
/// hand-population converge on one gate.
pub struct AllowlistGate {
    store: Arc<PeerStore>,
}

impl AllowlistGate {
    pub fn new(store: Arc<PeerStore>) -> Self {
        Self { store }
    }
}

impl TrustGate for AllowlistGate {
    /// Resolve an inbound endpoint to a pairing-mode identity (nickname only; groups are a
    /// roster-mode concept), or refuse.
    ///
    /// The store is keyed by the raw 32 bytes of the `EndpointId`. A store read that errors
    /// collapses to `None` = default-deny, logged at `warn!`: a gate read failing is
    /// operationally notable but must NEVER fail open.
    fn resolve(&self, endpoint: &EndpointId) -> Option<PeerIdentity> {
        match self.store.resolve(endpoint.as_bytes()) {
            Ok(Some(e)) => Some(PeerIdentity {
                endpoint: *endpoint,
                user_id: e.user_id, // self-sovereign user_id from a verified pairing binding (else None)
                name: e.nickname,
                groups: vec![],
            }),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(%e, "peer store read failed; refusing (default-deny)");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(eid: [u8; 32], nickname: &str, services: &[&str]) -> PeerEntry {
        PeerEntry {
            endpoint_id: eid,
            nickname: nickname.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            paired_at: None,
            user_id: None,
            last_addr: None,
        }
    }

    /// Write raw value bytes under `eid` in the peers table directly via redb, bypassing
    /// `add`. Used to simulate rows an `add` could not produce: a corrupt (non-JSON) row,
    /// or a valid row in an older on-disk shape (e.g. pre-`paired_at`).
    fn inject_raw(store: &PeerStore, eid: &[u8; 32], bytes: &[u8]) {
        let txn = store.db.begin_write().unwrap();
        {
            let mut table = txn.open_table(PEERS).unwrap();
            table.insert(eid.as_slice(), bytes).unwrap();
        }
        txn.commit().unwrap();
    }

    #[test]
    fn gate_resolves_known_nickname_refuses_unknown() {
        use mcpmesh_net::TrustGate;
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let known_eid = [7u8; 32];
        store.add(entry(known_eid, "bob", &["notes"])).unwrap();
        let gate = AllowlistGate::new(Arc::new(store));
        // Known endpoint resolves to a pairing-mode identity (nickname only).
        let id = gate.resolve(&known_eid.into()).unwrap();
        assert_eq!(id.name, "bob");
        assert_eq!(id.user_id, None);
        assert!(id.groups.is_empty());
        // Unknown endpoint is refused (default-deny).
        assert!(gate.resolve(&[9u8; 32].into()).is_none());
    }

    #[test]
    fn add_then_resolve_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [7u8; 32];
        store.add(entry(eid, "bob", &["notes"])).unwrap();
        assert_eq!(store.resolve(&eid).unwrap().unwrap().nickname, "bob");
        assert!(store.resolve(&[9u8; 32]).unwrap().is_none());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn entry_persists_across_reopen() {
        // The whole reason redb was chosen (durability): an added entry survives the
        // store being dropped and reopened at the same path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let eid = [42u8; 32];
        {
            let store = PeerStore::open(&path).unwrap();
            store.add(entry(eid, "alice", &["notes", "kb"])).unwrap();
        } // store dropped → file closed
        let store = PeerStore::open(&path).unwrap();
        let got = store.resolve(&eid).unwrap().unwrap();
        assert_eq!(got.nickname, "alice");
        assert_eq!(got.services, vec!["notes".to_string(), "kb".to_string()]);
    }

    #[test]
    fn add_upserts_same_endpoint_id() {
        // Same endpoint_id added twice → the second replaces the first; list has ONE entry.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [1u8; 32];
        store.add(entry(eid, "bob", &["notes"])).unwrap();
        store.add(entry(eid, "bob-renamed", &["kb"])).unwrap();
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].nickname, "bob-renamed");
        assert_eq!(all[0].services, vec!["kb".to_string()]);
    }

    #[test]
    fn remove_deletes_match_and_is_a_noop_for_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [3u8; 32];
        store.add(entry(eid, "carol", &[])).unwrap();
        // Removing an absent nickname is a clean no-op (does not touch carol) and reports `false`.
        assert!(
            !store.remove("nobody").unwrap(),
            "removing an absent nickname removes nothing"
        );
        assert!(store.resolve(&eid).unwrap().is_some());
        // Removing the match deletes it and reports `true`.
        assert!(
            store.remove("carol").unwrap(),
            "removing a present nickname reports the deletion"
        );
        assert!(store.resolve(&eid).unwrap().is_none());
    }

    #[test]
    fn remove_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let eid = [5u8; 32];
        {
            let store = PeerStore::open(&path).unwrap();
            store.add(entry(eid, "dave", &[])).unwrap();
            store.remove("dave").unwrap();
        }
        let store = PeerStore::open(&path).unwrap();
        assert!(store.resolve(&eid).unwrap().is_none());
    }

    #[test]
    fn remove_deletes_all_entries_sharing_a_nickname() {
        // Nicknames are not unique: two distinct endpoint_ids under the same nickname are
        // both removed (remove-all-matching).
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        store.add(entry([10u8; 32], "dup", &[])).unwrap();
        store.add(entry([11u8; 32], "dup", &[])).unwrap();
        assert_eq!(store.list().unwrap().len(), 2);
        store.remove("dup").unwrap();
        assert_eq!(store.list().unwrap().len(), 0);
    }

    #[test]
    fn old_row_without_paired_at_still_resolves_defaulting_to_none() {
        // An entry written by an older binary carries NO `paired_at` key. The
        // `#[serde(default)]` on the field must fill it with `None` so the row still
        // deserializes (the module additive-only discipline) — not fail-closed as corrupt.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [7u8; 32];
        // Raw JSON in the exact legacy shape (no `paired_at`), written straight to redb.
        let old_shape = serde_json::json!({
            "endpoint_id": eid.to_vec(),
            "nickname": "old",
            "services": ["notes"],
        });
        inject_raw(&store, &eid, &serde_json::to_vec(&old_shape).unwrap());
        let got = store.resolve(&eid).unwrap().unwrap();
        assert_eq!(got.nickname, "old");
        assert_eq!(got.services, vec!["notes".to_string()]);
        assert_eq!(got.paired_at, None); // #[serde(default)] supplied it
    }

    #[test]
    fn paired_at_round_trips_when_set() {
        // A new pairing write sets `paired_at` (epoch-seconds-as-String); it survives the
        // add → resolve JSON round-trip unchanged.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [8u8; 32];
        let mut e = entry(eid, "bob", &["notes"]);
        e.paired_at = Some("1751760000".into());
        store.add(e).unwrap();
        let got = store.resolve(&eid).unwrap().unwrap();
        assert_eq!(got.paired_at.as_deref(), Some("1751760000"));
    }

    #[test]
    fn old_row_without_last_addr_still_resolves_defaulting_to_none() {
        // An entry written by a pre-`last_addr` binary carries NO `last_addr` key. The
        // `#[serde(default)]` on the field must fill it with `None` so the row still
        // deserializes (the module additive-only discipline) — not fail-closed as corrupt.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [9u8; 32];
        // Raw JSON in the exact immediate-predecessor shape (paired_at/user_id present,
        // no `last_addr`), written straight to redb.
        let old_shape = serde_json::json!({
            "endpoint_id": eid.to_vec(),
            "nickname": "old",
            "services": ["notes"],
            "paired_at": "1751760000",
            "user_id": null,
        });
        inject_raw(&store, &eid, &serde_json::to_vec(&old_shape).unwrap());
        let got = store.resolve(&eid).unwrap().unwrap();
        assert_eq!(got.nickname, "old");
        assert_eq!(got.last_addr, None); // #[serde(default)] supplied it
    }

    #[test]
    fn last_addr_round_trips_when_set() {
        // A pairing write stores the peer's last-known address as an opaque JSON string;
        // it survives the add → resolve round-trip unchanged (byte-for-byte — the store
        // never interprets it).
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [10u8; 32];
        let mut e = entry(eid, "bob", &["notes"]);
        e.last_addr = Some(r#"{"id":"whatever","addrs":[]}"#.into());
        store.add(e).unwrap();
        let got = store.resolve(&eid).unwrap().unwrap();
        assert_eq!(
            got.last_addr.as_deref(),
            Some(r#"{"id":"whatever","addrs":[]}"#)
        );
    }

    #[test]
    fn entry_for_returns_the_full_entry() {
        // The dial site reads the WHOLE entry (id + last_addr hint) by nickname.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let eid = [11u8; 32];
        let mut e = entry(eid, "alice", &["echo"]);
        e.last_addr = Some("{}".into());
        store.add(e).unwrap();
        let got = store.entry_for("alice").unwrap().unwrap();
        assert_eq!(got.endpoint_id, eid);
        assert_eq!(got.last_addr.as_deref(), Some("{}"));
        assert!(store.entry_for("nobody").unwrap().is_none());
    }

    #[test]
    fn entries_for_user_groups_a_persons_devices() {
        // #30: dial-by-user_id resolves every device sharing a proven user_id, so a caller can
        // address a peer by its stable b64u identity instead of a local nickname.
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        // Two devices of the same person (same user_id, different endpoint + nickname)...
        let mut laptop = entry([1u8; 32], "alice", &["notes"]);
        laptop.user_id = Some("b64u:ALICE".into());
        let mut phone = entry([2u8; 32], "alice-phone", &["notes"]);
        phone.user_id = Some("b64u:ALICE".into());
        // ...plus another person, and a legacy row with no proven user_id.
        let mut bob = entry([3u8; 32], "bob", &["kb"]);
        bob.user_id = Some("b64u:BOB".into());
        let legacy = entry([4u8; 32], "carol", &["x"]); // user_id None
        for e in [laptop, phone, bob, legacy] {
            store.add(e).unwrap();
        }

        let alice = store.entries_for_user("b64u:ALICE").unwrap();
        assert_eq!(alice.len(), 2, "both of alice's devices match her user_id");
        let mut eids: Vec<_> = alice.iter().map(|e| e.endpoint_id).collect();
        eids.sort();
        assert_eq!(eids, vec![[1u8; 32], [2u8; 32]]);

        assert_eq!(store.entries_for_user("b64u:BOB").unwrap().len(), 1);
        // A legacy row with no proven user_id never matches, and an unknown id is empty.
        assert!(store.entries_for_user("b64u:NOBODY").unwrap().is_empty());
    }

    #[test]
    fn corrupt_row_is_skipped_on_list_and_denied_on_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("state.redb")).unwrap();
        let good = [1u8; 32];
        let bad = [2u8; 32];
        store.add(entry(good, "good", &["notes"])).unwrap();
        inject_raw(&store, &bad, b"not json at all");
        // list() fails OPEN: skips the corrupt row, still returns the good one.
        let all = store.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].nickname, "good");
        // resolve() fails CLOSED on the corrupt key (deny), OK on the good key.
        assert!(store.resolve(&bad).unwrap().is_none());
        assert_eq!(store.resolve(&good).unwrap().unwrap().nickname, "good");
        // remove() also fails OPEN: a corrupt row can't match, and removing the good one
        // still works despite the corrupt row present.
        store.remove("good").unwrap();
        assert!(store.resolve(&good).unwrap().is_none());
    }
}
