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

/// The pairing-mode REVOCATION table (#85 ask 4): key = 32-byte endpoint_id, value = JSON of a
/// [`RevokedEntry`]. Separate from [`PEERS`] on purpose — a revocation must outlive the pair row it
/// refers to, and must apply to an endpoint this node never paired with at all (a signed revocation
/// can arrive before, or instead of, a pairing).
const REVOKED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("revoked");

/// Revoked IDENTITIES — `b64u:` user ids, not endpoints (#85 ask 3 gate).
///
/// Endpoint revocation cannot express "I no longer trust this person". It was enough while
/// admission was per-device, and attestation broke that: a thief holding a stolen laptop holds the
/// USER KEY, so they mint a brand-new endpoint id, sign a fresh binding over it, and walk past a
/// check keyed on the id they no longer need. The 0.46.0 gate proved it end to end — the admitted
/// device opened a live session.
///
/// So `peer_revoke` on a `b64u:` now records the identity as well as its known endpoints, and
/// attestation refuses it. Future devices of a revoked person are refused too, which is what an
/// operator meant when they revoked the person.
const REVOKED_USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("revoked_users");

/// One revocation: "this endpoint is dead" (#85 ask 4).
///
/// Roster mode has had `revoked_endpoints` since the roster schema; pairing mode had nothing, so
/// whoever held a stolen disk authenticated as its owner until every peer independently ran
/// `peer_remove` — with nothing telling them they should.
///
/// **Additive-only durable JSON, like [`PeerEntry`] — but it fails closed in the OPPOSITE
/// direction.** An unreadable pair row means "not paired" (deny). An unreadable revocation row must
/// also mean deny, i.e. **revoked**, because this table exists to refuse. Both tables fail closed;
/// they just disagree about which answer that is. [`PeerStore::is_revoked`] implements that.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RevokedEntry {
    pub endpoint_id: [u8; 32],
    /// When this node applied the revocation, epoch seconds.
    pub revoked_at: u64,
    /// Free-text operator note. Never interpreted.
    #[serde(default)]
    pub reason: Option<String>,
    /// `"local"` (this operator's own decision about someone else's device) or `"signed"` (a
    /// user-key-signed statement the device's OWNER issued about their own device). The two are
    /// different claims and an operator reading `status` needs to tell them apart.
    #[serde(default)]
    pub source: String,
    /// For `"signed"`: the `b64u:` user_id that signed it.
    #[serde(default)]
    pub signer_user_id: Option<String>,
    /// For `"signed"`: the `issued_at` inside the signature. Lets a later statement supersede an
    /// earlier one about the same endpoint, and makes a replayed older token a no-op.
    #[serde(default)]
    pub issued_at: Option<u64>,
}

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
    /// The path `open` was given, retained for `status.storage.redb_bytes` (#88).
    path: std::path::PathBuf,
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
        txn.open_table(REVOKED)?;
        txn.open_table(REVOKED_USERS)?;
        txn.commit()?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
        })
    }

    /// The on-disk path this store was opened at — `status.storage.redb_bytes` stats it (#88).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Is this endpoint REVOKED (#85 ask 4)?
    ///
    /// **Fails CLOSED as revoked.** Every other read in this file collapses an error to "not
    /// present", which for the pair table means deny. Here "not present" means *allow*, so the same
    /// reflex would fail OPEN on the one table whose entire job is refusal: a corrupt row, a redb
    /// error or a schema surprise would silently resurrect a device its owner has declared stolen.
    /// An error here answers `true` and logs — a node that cannot read its revocation list refuses
    /// the endpoints it cannot read about, and an operator sees why.
    ///
    /// Note what that does NOT do: an error opening the table at all would deny every endpoint,
    /// which is why `open` creates it up front and why the error is scoped to one lookup.
    pub fn is_revoked(&self, endpoint_id: &[u8; 32]) -> bool {
        match self.revoked_entry(endpoint_id) {
            Ok(v) => v.is_some(),
            Err(e) => {
                tracing::warn!(
                    %e,
                    "revocation lookup failed; treating this endpoint as REVOKED (fail-closed)"
                );
                true
            }
        }
    }

    /// The revocation row for an endpoint, or `None`. Errors propagate — [`is_revoked`] is the
    /// fail-closed wrapper; `status` rendering wants the real error.
    pub fn revoked_entry(&self, endpoint_id: &[u8; 32]) -> Result<Option<RevokedEntry>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REVOKED)?;
        let Some(v) = table.get(endpoint_id.as_slice())? else {
            return Ok(None);
        };
        // A row that exists but will not deserialize is still a revocation: SOMETHING was written
        // here, and the only safe reading of "I cannot tell you why this is revoked" is that it is.
        // Synthesized rather than propagated so one bad row cannot make `list_revoked` unusable.
        Ok(Some(serde_json::from_slice(v.value()).unwrap_or_else(|e| {
            tracing::warn!(%e, "unreadable revocation row; still treating the endpoint as revoked");
            RevokedEntry {
                endpoint_id: *endpoint_id,
                revoked_at: 0,
                reason: Some("unreadable revocation row".into()),
                source: "unknown".into(),
                signer_user_id: None,
                issued_at: None,
            }
        })))
    }

    /// Is this `b64u:` IDENTITY revoked (#85 ask 3 gate)?
    ///
    /// Fails CLOSED as revoked, for the same reason [`is_revoked`](Self::is_revoked) does: this
    /// table exists to refuse, so "I cannot read it" must mean "no".
    pub fn is_user_revoked(&self, user_id: &str) -> bool {
        let read = || -> Result<bool> {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(REVOKED_USERS)?;
            Ok(table.get(user_id)?.is_some())
        };
        match read() {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    %e,
                    "identity-revocation lookup failed; treating as REVOKED (fail-closed)"
                );
                true
            }
        }
    }

    /// Revoke a `b64u:` IDENTITY — every device of that person, including ones we have never seen.
    pub fn revoke_user(&self, user_id: &str, e: &RevokedEntry) -> Result<()> {
        let bytes = serde_json::to_vec(e)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(REVOKED_USERS)?;
            table.insert(user_id, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Lift an identity revocation. Returns whether one was present.
    pub fn unrevoke_user(&self, user_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(REVOKED_USERS)?;
            table.remove(user_id)?.is_some()
        };
        txn.commit()?;
        Ok(removed)
    }

    /// Every revoked identity, for `status`.
    pub fn list_revoked_users(&self) -> Result<Vec<(String, RevokedEntry)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REVOKED_USERS)?;
        let mut out = Vec::new();
        for row in table.iter()? {
            let (k, v) = row?;
            let uid = k.value().to_string();
            out.push((
                uid.clone(),
                serde_json::from_slice(v.value()).unwrap_or(RevokedEntry {
                    endpoint_id: [0u8; 32],
                    revoked_at: 0,
                    reason: Some("unreadable revocation row".into()),
                    source: "unknown".into(),
                    signer_user_id: None,
                    issued_at: None,
                }),
            ));
        }
        Ok(out)
    }

    /// Write a revocation (idempotent upsert). One atomic redb transaction.
    pub fn revoke(&self, e: RevokedEntry) -> Result<()> {
        let bytes = serde_json::to_vec(&e)?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(REVOKED)?;
            table.insert(e.endpoint_id.as_slice(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Lift a revocation. Returns whether one was present.
    ///
    /// Reversible because this list is LOCAL and an operator mistake must be fixable — unlike a
    /// roster revocation, which is a signed statement other nodes rely on. Audited by the caller in
    /// both directions.
    pub fn unrevoke(&self, endpoint_id: &[u8; 32]) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let removed = {
            let mut table = txn.open_table(REVOKED)?;
            table.remove(endpoint_id.as_slice())?.is_some()
        };
        txn.commit()?;
        Ok(removed)
    }

    /// Every revocation this node holds, for `status`. A row that will not deserialize is rendered
    /// as an unknown-source revocation rather than dropped — dropping it would show an operator a
    /// list that disagrees with the gate.
    pub fn list_revoked(&self) -> Result<Vec<RevokedEntry>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REVOKED)?;
        let mut out = Vec::new();
        for row in table.iter()? {
            let (k, v) = row?;
            let mut eid = [0u8; 32];
            if k.value().len() == 32 {
                eid.copy_from_slice(k.value());
            }
            out.push(serde_json::from_slice(v.value()).unwrap_or(RevokedEntry {
                endpoint_id: eid,
                revoked_at: 0,
                reason: Some("unreadable revocation row".into()),
                source: "unknown".into(),
                signer_user_id: None,
                issued_at: None,
            }));
        }
        Ok(out)
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

    /// Set `last_addr` on an EXISTING row, atomically, inside ONE write transaction (#124 review).
    ///
    /// `resolve` + mutate + [`add`](Self::add) is TWO transactions with a window between them, and
    /// a lock does not close it: the pairing writes and `add_peer` take no lock, so a
    /// `reload_lock`-guarded refresh excludes only `rename_peer`. Measured at a 33% rate, that
    /// window let a hint refresh revert a concurrent re-pair and DOWNGRADE a verified `user_id` to
    /// `None` — the one thing the pairing path declares must never happen.
    ///
    /// Reading and writing under a single redb write txn excludes every writer, not just the
    /// polite ones. Returns `Ok(false)` when the peer is absent: a dial hint must never CREATE an
    /// allowlist row, or a cache path becomes an authorization path.
    pub fn set_last_addr(&self, endpoint_id: &[u8; 32], last_addr: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let changed = {
            let mut table = txn.open_table(PEERS)?;
            let Some(existing) = table.get(endpoint_id.as_slice())? else {
                return Ok(false); // unknown peer — never invent one
            };
            let mut entry: PeerEntry = serde_json::from_slice(existing.value())?;
            drop(existing);
            if entry.last_addr.as_deref() == Some(last_addr) {
                // Unchanged: ABORT rather than commit. Committing an empty txn still costs a
                // ~6ms fsync and holds redb's global writer lock for it, blocking pairing, peer
                // add and rename — measured 5.9ms vs 21us, ~280x (#124 third review). Dropping
                // the txn uncommitted aborts it, which is redb's documented behaviour.
                return Ok(false);
            } else {
                entry.last_addr = Some(last_addr.to_string());
                let bytes = serde_json::to_vec(&entry)?;
                table.insert(endpoint_id.as_slice(), bytes.as_slice())?;
                true
            }
        };
        txn.commit()?;
        Ok(changed)
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
        // (1) REVOCATION WINS over a live pair row (#85 ask 4), matching `ComposedGate`'s rule 1
        // for the roster. A revoked endpoint that is still in the allowlist is the ordinary case —
        // the whole point is to kill a device you previously paired with — so checking the pair row
        // first and returning early would make the feature a no-op.
        if self.store.is_revoked(endpoint.as_bytes()) {
            return None;
        }
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

    /// The check-register recheck (#85 ask 4) — closes the same TOCTOU window #54 closed for
    /// roster revocation: a connection that registers just after a revoke must self-close rather
    /// than run to completion on a decision that was true when it was accepted.
    fn is_revoked(&self, endpoint: &EndpointId) -> bool {
        self.store.is_revoked(endpoint.as_bytes())
    }

    /// Sever an EXISTING session on revocation, immediately.
    ///
    /// #54 established that a revocation which waits for the peer to disconnect is unbounded — MCP
    /// sessions are long-lived by design, so "eventually" can mean days. `roster_user` is
    /// irrelevant here: a pairing revocation applies whether or not the endpoint is also rostered.
    fn should_sever_now(&self, endpoint: &EndpointId, _roster_user: Option<&str>) -> bool {
        self.store.is_revoked(endpoint.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    /// #124: an UNCHANGED `set_last_addr` must abort its transaction, not commit an empty one.
    ///
    /// Committing costs a ~6ms fsync AND holds redb's process-global writer lock for it, so on a
    /// busy mesh every `Selected` event would block pairing, peer add and rename. The earlier
    /// version committed on both branches while three in-tree comments claimed it skipped — and
    /// nothing could falsify them: the returned bool is `false` either way, so it proves "no
    /// insert", not "no write".
    ///
    /// A wall-clock assertion is normally a bad idea in this repo (loaded machines have produced
    /// confident-and-wrong diagnoses twice). It is right here only because the margin is enormous
    /// — measured ~20ms vs ~5.9s for 1000 iterations, >100x — so the bound below is loose by two
    /// orders of magnitude and still catches a regression.
    #[test]
    fn an_unchanged_set_last_addr_aborts_instead_of_committing() {
        let dir = tempfile::tempdir().unwrap();
        let store = PeerStore::open(&dir.path().join("p.redb")).unwrap();
        let eid = [5u8; 32];
        let addr = r#"{"id":"x","addrs":[]}"#;
        store
            .add(PeerEntry {
                endpoint_id: eid,
                nickname: "bob".into(),
                services: vec![],
                paired_at: None,
                user_id: None,
                last_addr: Some(addr.to_string()),
            })
            .unwrap();

        let started = std::time::Instant::now();
        for _ in 0..1000 {
            assert!(
                !store.set_last_addr(&eid, addr).unwrap(),
                "an unchanged hint must report no write"
            );
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "1000 unchanged refreshes took {elapsed:?} — committing an empty txn per call is a \
             ~6ms fsync holding redb's GLOBAL writer lock, which blocks pairing and peer add on \
             every path event (#124)"
        );

        // Still correct after 1000 aborts: the row survives and a real change still writes.
        assert_eq!(
            store.resolve(&eid).unwrap().unwrap().last_addr.as_deref(),
            Some(addr)
        );
        assert!(
            store
                .set_last_addr(&eid, r#"{"id":"y","addrs":[]}"#)
                .unwrap()
        );
        // An absent peer is never created, and that path aborts too.
        assert!(!store.set_last_addr(&[7u8; 32], addr).unwrap());
        assert!(store.resolve(&[7u8; 32]).unwrap().is_none());
    }

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

    /// #85 ask 4: a REVOCATION beats a live pair row, at every gate entry point.
    ///
    /// The ordinary case is a device you previously paired with — that is what revocation is FOR —
    /// so a gate that consulted the pair row first would make the feature a no-op on exactly the
    /// endpoints it exists for.
    #[test]
    fn a_revoked_endpoint_is_refused_even_with_a_live_pair_row() {
        use mcpmesh_net::TrustGate;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("p.redb")).unwrap());
        let eid = [5u8; 32];
        store
            .add(PeerEntry {
                endpoint_id: eid,
                nickname: "bob".into(),
                services: vec!["notes".into()],
                paired_at: None,
                user_id: Some("b64u:BOB".into()),
                last_addr: None,
            })
            .unwrap();
        let gate = AllowlistGate::new(store.clone());
        let id: EndpointId = eid.into();

        // Precondition: without this the assertions below could pass on a gate that refuses
        // everything.
        assert!(
            gate.resolve(&id).is_some(),
            "precondition: the peer resolves before revocation"
        );
        assert!(!gate.is_revoked(&id));
        assert!(!gate.should_sever_now(&id, None));

        store
            .revoke(RevokedEntry {
                endpoint_id: eid,
                revoked_at: 1_754_300_000,
                reason: Some("laptop stolen".into()),
                source: "local".into(),
                signer_user_id: None,
                issued_at: None,
            })
            .unwrap();

        assert!(
            gate.resolve(&id).is_none(),
            "a revoked endpoint must not resolve, even though its pair row is untouched"
        );
        assert!(
            gate.is_revoked(&id),
            "the check-register recheck must see it — that is the TOCTOU close (#54)"
        );
        assert!(
            gate.should_sever_now(&id, None),
            "and a LIVE session must be severed, not left to end on its own"
        );
        // The pair row itself is untouched: revocation and removal are different acts.
        assert!(
            store.resolve(&eid).unwrap().is_some(),
            "revocation must not delete the pair row — unrevoking has to restore the peer"
        );

        assert!(store.unrevoke(&eid).unwrap(), "the revocation was present");
        assert!(
            gate.resolve(&id).is_some(),
            "unrevoking restores the peer, since the pair row survived"
        );
        assert!(!store.unrevoke(&eid).unwrap(), "idempotent");
    }

    /// A revocation must survive a restart.
    ///
    /// One that evaporated would read as durable and silently revert — the failure #107's
    /// withdrawal tombstone was designed against, and worse here: the endpoint it names is one
    /// somebody has physically taken.
    #[test]
    fn a_revocation_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.redb");
        let eid = [9u8; 32];
        {
            let store = PeerStore::open(&path).unwrap();
            store
                .revoke(RevokedEntry {
                    endpoint_id: eid,
                    revoked_at: 42,
                    reason: Some("stolen".into()),
                    source: "signed".into(),
                    signer_user_id: Some("b64u:BOB".into()),
                    issued_at: Some(1000),
                })
                .unwrap();
        }
        let store = PeerStore::open(&path).unwrap();
        assert!(store.is_revoked(&eid));
        let e = store.revoked_entry(&eid).unwrap().expect("row survives");
        assert_eq!(
            (e.source.as_str(), e.signer_user_id.as_deref(), e.issued_at),
            ("signed", Some("b64u:BOB"), Some(1000)),
            "the PROVENANCE survives too — an operator has to be able to tell a signed revocation \
             from their own local one after a restart"
        );
        assert_eq!(store.list_revoked().unwrap().len(), 1);
    }

    /// An UNREADABLE revocation row still revokes.
    ///
    /// Every other read in this file collapses an error to "not present", which for the pair table
    /// means deny. Here "not present" means ALLOW, so the same reflex fails OPEN on the one table
    /// whose entire job is refusal — a corrupt row would silently resurrect a device its owner
    /// declared stolen. Both tables fail closed; they disagree about which answer that is.
    #[test]
    fn an_unreadable_revocation_row_still_revokes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.redb");
        let eid = [4u8; 32];
        {
            // Write garbage under the endpoint key, exactly as on-disk corruption or an older
            // binary's schema would leave it.
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let mut t = txn.open_table(REVOKED).unwrap();
                t.insert(eid.as_slice(), b"{not json".as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        let store = PeerStore::open(&path).unwrap();
        assert!(
            store.is_revoked(&eid),
            "an unreadable revocation row must still REVOKE — failing open here undoes the only \
             remedy for a stolen device"
        );
        let listed = store.list_revoked().unwrap();
        assert_eq!(listed.len(), 1, "and it must still be VISIBLE in status");
        assert_eq!(
            listed[0].source, "unknown",
            "…rendered as unknown-provenance rather than dropped, so the list cannot disagree with \
             the gate"
        );
    }
}
