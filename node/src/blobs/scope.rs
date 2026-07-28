//! The persisted scope model: a named set of blob hashes + a set of granted principals.
//! An app publishes blobs INTO a scope and grants the scope to principals (a roster group name or a
//! user_id — one flat namespace). The request-time gate ALLOWS a GET iff some
//! scope contains the hash AND grants one of the caller's `{user_id} ∪ groups`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One scope: the blob hashes it contains + the principals it grants. Hashes are bare 64-char blake3
/// hex (`Hash::to_hex()`); principals are stable ids/names: `{eid} ∪ {user_id} ∪ groups` (#38 — never nicknames).
/// `BTreeSet` for deterministic serialization + list ordering.
/// Default cap on how many scopes one `blob_list` returns (#84b).
///
/// NOT unbounded. `blob_list` renders every scope into a single control frame against a 16 MiB cap
/// whose violation closes the connection on the third strike, so an unbounded listing does not
/// degrade at scale — it kills the caller's connection. With one-scope-per-file granularity
/// (#84d) that is reached by ordinary use. A truncated answer the caller can detect and page
/// through is strictly better than a dead connection.
pub const DEFAULT_LIST_LIMIT: usize = 256;

/// One row of a `blob_list` page: `(name, hashes, grants, withdrawn, hash_count, grant_count,
/// withdrawn_count)`. The counts are always present, even when `counts_only` empties the vectors.
pub type ScopePageRow = (
    String,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    usize,
    usize,
    usize,
);

/// Filters + paging for `blob_list` (#84b). All optional; `Default` is "everything, default limit".
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    /// Exact scope name — never a prefix. Under one-scope-per-file, names are derived from hashes
    /// and share prefixes constantly, so a prefix match would return neighbours.
    pub scope: Option<String>,
    /// Only scopes containing this hash. The CALLER's rendering is normalized before comparing.
    pub hash: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// Omit the three vectors, keep the counts.
    pub counts_only: bool,
}

/// One page of a listing, plus what the caller needs to know it is a page.
#[derive(Debug, Clone)]
pub struct ScopePage {
    pub rows: Vec<ScopePageRow>,
    /// Scopes matching the filter BEFORE limit/offset. Without this a caller cannot distinguish a
    /// complete answer from a clipped one.
    pub total: usize,
    pub truncated: bool,
}

/// One row of the scope listing: `(name, hashes, grants, withdrawn)`.
///
/// Named because it grew a fourth member with #107's withdrawal set and an anonymous 4-tuple
/// stopped being readable at the call sites.
pub type ScopeRow = (String, Vec<String>, Vec<String>, Vec<String>);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub hashes: BTreeSet<String>,
    pub grants: BTreeSet<String>,
    /// Hashes deliberately WITHDRAWN from this scope (#107).
    ///
    /// `blob_unpublish` removes reachability but not bytes (#80: no reclaim), so the blob stays
    /// complete in the local store forever and `blob_republish` would re-add it to this scope —
    /// whose grants unpublish never touched — restoring access with no grant call and no warning.
    /// A lock cannot close that: exclusion is in lock-ACQUISITION order, not request-arrival order,
    /// so an unpublish that acquires first is still erased by a republish acquiring second.
    ///
    /// Persisted with the rest of the sidecar. A tombstone that evaporated on restart would be
    /// worse than none: it reads as durable, then silently reverts.
    ///
    /// `#[serde(default)]` so sidecars written before 0.17.0 load unchanged.
    #[serde(default)]
    pub withdrawn: BTreeSet<String>,
}

/// The full scope table: `scope_name -> Scope`. `Default` is the empty table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobScopes {
    #[serde(default)]
    pub scopes: BTreeMap<String, Scope>,
}

impl BlobScopes {
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Add a blob hash INTO a scope (creating the scope if absent).
    pub fn publish_hash(&mut self, scope: &str, hash_hex: &str) {
        let sc = self.scopes.entry(scope.to_string()).or_default();
        // Publishing CLEARS a withdrawal (#107). This is the deliberate act: `blob_publish` names a
        // FILE on disk, so the operator is saying "this content, in this scope, I mean it".
        // `blob_republish` — which names only a hash the node happens to hold, and is the call an
        // embedder is tempted to make as fetch hygiene — is refused instead, and `blob_grant` never
        // touches this, since granting a PRINCIPAL says nothing about a hash.
        sc.withdrawn.remove(hash_hex);
        sc.hashes.insert(hash_hex.to_string());
    }

    /// Grant a scope to a principal (creating the scope if absent).
    pub fn grant(&mut self, scope: &str, principal: &str) {
        self.scopes
            .entry(scope.to_string())
            .or_default()
            .grants
            .insert(principal.to_string());
    }

    /// Remove `principals` from EVERY scope's grant set (unpair hygiene, #38). Returns whether
    /// anything changed. Empty scopes are left in place (they still track published hashes).
    pub fn revoke_principals(&mut self, principals: &[String]) -> bool {
        let mut changed = false;
        for sc in self.scopes.values_mut() {
            for p in principals {
                changed |= sc.grants.remove(p);
            }
        }
        changed
    }

    /// Remove `principals` from ONE scope's grant set (#62, the `blob_revoke` verb). Returns
    /// whether anything changed.
    ///
    /// Deliberately NOT [`revoke_principals`](Self::revoke_principals), which strips from EVERY
    /// scope: that is unpair hygiene, and using it for a per-scope revoke would silently withdraw
    /// access the caller never asked to touch. An absent scope is a clean `false`.
    pub fn revoke_from_scope(&mut self, scope: &str, principals: &[String]) -> bool {
        let Some(sc) = self.scopes.get_mut(scope) else {
            return false;
        };
        let mut changed = false;
        for p in principals {
            changed |= sc.grants.remove(p);
        }
        changed
    }

    /// Remove `hash_hex` from ONE scope (#62, the `blob_unpublish` verb). Returns whether anything
    /// changed.
    ///
    /// This is the AUTHORIZATION boundary: [`allows`](Self::allows) requires the hash to be in some
    /// scope, so a subsequent GET for it is refused. It does NOT delete bytes — the store keeps them and
    /// there is no reclaim verb (#80). A hash published into several scopes stays reachable through
    /// the others, and a transfer already streaming is not interrupted.
    pub fn unpublish_hash(&mut self, scope: &str, hash_hex: &str) -> bool {
        self.scopes.get_mut(scope).is_some_and(|sc| {
            // Record the withdrawal even when the hash was not currently listed: the operator has
            // expressed "not this content, not in this scope", and a republish afterwards must
            // still be refused (#107).
            sc.withdrawn.insert(hash_hex.to_string());
            sc.hashes.remove(hash_hex)
        })
    }

    /// One page of the scope table (#84b), filtered and bounded.
    ///
    /// Order is scope name — the table is a `BTreeMap`, so it is already sorted and stable. Paging
    /// without a stable order returns overlapping or missing rows that look plausible, which is
    /// worse than not paging at all.
    pub fn list_page(&self, q: &ListQuery) -> ScopePage {
        // Normalize the hash filter so a caller's base32 rendering matches a stored canonical hex,
        // matching the rule #83 established for every other hash-taking surface.
        let want_hash = q
            .hash
            .as_deref()
            .and_then(|h| crate::blobs::parse_blob_hash(h).ok())
            .map(|h| h.to_hex().to_string());

        let matching: Vec<(&String, &Scope)> = self
            .scopes
            .iter()
            .filter(|(name, sc)| {
                q.scope.as_deref().is_none_or(|want| want == name.as_str())
                    && want_hash.as_deref().is_none_or(|h| sc.hashes.contains(h))
            })
            .collect();

        let total = matching.len();
        let offset = q.offset.unwrap_or(0);
        let limit = q.limit.unwrap_or(DEFAULT_LIST_LIMIT);
        let rows: Vec<ScopePageRow> = matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|(name, sc)| {
                let (h, g, w) = (sc.hashes.len(), sc.grants.len(), sc.withdrawn.len());
                let take = |set: &BTreeSet<String>| -> Vec<String> {
                    if q.counts_only {
                        Vec::new()
                    } else {
                        set.iter().cloned().collect()
                    }
                };
                (
                    name.clone(),
                    take(&sc.hashes),
                    take(&sc.grants),
                    take(&sc.withdrawn),
                    h,
                    g,
                    w,
                )
            })
            .collect();
        let truncated = offset + rows.len() < total;
        ScopePage {
            rows,
            total,
            truncated,
        }
    }

    /// Was this hash deliberately withdrawn from this scope (#107)?
    pub fn is_withdrawn(&self, scope: &str, hash_hex: &str) -> bool {
        self.scopes
            .get(scope)
            .is_some_and(|sc| sc.withdrawn.contains(hash_hex))
    }

    /// Does this scope exist at all? Lets a caller distinguish "no such scope" (an operator typo,
    /// which must be an ERROR) from "the principal/hash was not there" (genuinely idempotent).
    /// Answering `{}` to both is the #55 defect, and #62 reintroduced it before review caught it.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains_key(scope)
    }

    /// SECURITY LINCHPIN (pure): ALLOW iff SOME scope contains `hash_hex` AND grants one of the
    /// caller's `principals` (`{user_id} ∪ groups`). Default-deny — an in-scope hash with no matching
    /// grant, a hash in no scope, and an empty principal set all return `false`. Hashes are never
    /// capabilities; a hash reachable in scope A does not become reachable via scope B's grant.
    pub fn allows(&self, hash_hex: &str, principals: &HashSet<&str>) -> bool {
        self.scopes.values().any(|sc| {
            // A withdrawal outranks residual membership (#107 review). `hashes` and `withdrawn`
            // are kept disjoint by the API, but this is an AUTHZ gate: if the two ever disagree —
            // a hand-edited sidecar, external tooling, a partial rollback, a future third
            // insertion site — the tombstone must win rather than the leftover row. Cheap
            // belt-and-braces on the one surface where fail-open is unacceptable.
            !sc.withdrawn.contains(hash_hex)
                && sc.hashes.contains(hash_hex)
                && sc.grants.iter().any(|g| principals.contains(g.as_str()))
        })
    }

    /// Deterministic `(name, hashes, grants)` rendering for `list` (sorted by BTree order).
    pub fn list(&self) -> Vec<ScopeRow> {
        self.scopes
            .iter()
            .map(|(name, sc)| {
                (
                    name.clone(),
                    sc.hashes.iter().cloned().collect(),
                    sc.grants.iter().cloned().collect(),
                    // #107: surface withdrawals. Without this a tombstone is discoverable only by
                    // triggering a -32042, and the set — which only `blob_publish` ever prunes —
                    // grows invisibly.
                    sc.withdrawn.iter().cloned().collect(),
                )
            })
            .collect()
    }
}

/// The scope store. An in-RAM `RwLock<BlobScopes>` serves the hot authz read (`snapshot`, a cheap
/// clone taken per GET — no lock held across the async reply); every mutation
/// (`publish_hash`/`grant`/`revoke_*`/`unpublish_hash`) mutates and atomically persists the JSON
/// sidecar (`crate::roster::atomic_write_str` = write-new + rename).
///
/// **`write_lock` serializes mutate-AND-persist as one unit.** An earlier version dropped the
/// `inner` write lock before persisting, which serialized the mutation but NOT the file write: two
/// concurrent revokes could persist out of order and the slower one would write back a snapshot
/// still containing the grant the other had just removed. Memory was correct, disk was not, and the
/// stale grant came back on restart — a fail-OPEN loss of a revocation, on an authorization
/// surface. Control connections are one task each, so concurrent verbs are ordinary usage, not an
/// exotic race (#62 review, reproduced).
pub struct ScopeStore {
    path: PathBuf,
    inner: RwLock<BlobScopes>,
    /// Held across mutate+persist so the file write order matches the mutation order.
    write_lock: std::sync::Mutex<()>,
}

impl ScopeStore {
    /// An EMPTY store bound to `path` (does not read the file). Used for a caller-only fetcher (no
    /// scopes) and by tests.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: RwLock::new(BlobScopes::default()),
            write_lock: std::sync::Mutex::new(()),
        }
    }

    /// Load the persisted sidecar, or an EMPTY store when the file is absent (fresh node). A present
    /// file MUST parse (a corrupt sidecar is a hard error — fail closed, do not silently reset grants).
    pub fn load(path: PathBuf) -> Result<Self> {
        let scopes = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<BlobScopes>(&bytes)
                .with_context(|| format!("parse blob scopes {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BlobScopes::default(),
            Err(e) => {
                return Err(anyhow::Error::new(e))
                    .with_context(|| format!("read blob scopes {}", path.display()));
            }
        };
        Ok(Self {
            path,
            inner: RwLock::new(scopes),
            write_lock: std::sync::Mutex::new(()),
        })
    }

    /// A cheap clone of the current scope table for the hot authz read + `list` rendering.
    /// The read lock is released as the clone returns — NEVER held across an await.
    pub fn snapshot(&self) -> BlobScopes {
        self.inner.read().expect("scope lock not poisoned").clone()
    }

    /// Publish a hash into a scope + persist (single-writer). The write lock is dropped before the
    /// fs write so a slow fsync never blocks a concurrent authz read.
    pub fn publish_hash(&self, scope: &str, hash_hex: &str) -> Result<()> {
        let _w = self
            .write_lock
            .lock()
            .expect("scope write lock not poisoned");
        let snapshot = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            g.publish_hash(scope, hash_hex);
            g.clone()
        };
        self.persist(&snapshot)
    }

    /// Grant a scope to a principal + persist (single-writer). Same lock/persist discipline.
    pub fn grant(&self, scope: &str, principal: &str) -> Result<()> {
        let _w = self
            .write_lock
            .lock()
            .expect("scope write lock not poisoned");
        let snapshot = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            g.grant(scope, principal);
            g.clone()
        };
        self.persist(&snapshot)
    }

    /// Revoke `principals` from ONE scope + persist (#62, `blob_revoke`). Same lock/persist
    /// discipline. Returns whether anything changed.
    pub fn revoke_from_scope(&self, scope: &str, principals: &[String]) -> Result<bool> {
        let _w = self
            .write_lock
            .lock()
            .expect("scope write lock not poisoned");
        let (changed, snapshot) = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            let changed = g.revoke_from_scope(scope, principals);
            (changed, g.clone())
        };
        self.persist(&snapshot)?;
        Ok(changed)
    }

    /// Does this scope exist? See [`BlobScopes::has_scope`].
    /// Was this hash deliberately withdrawn from this scope (#107)? Same lock discipline as
    /// every other authz read.
    pub fn is_withdrawn(&self, scope: &str, hash_hex: &str) -> bool {
        self.inner
            .read()
            .expect("scope lock not poisoned")
            .is_withdrawn(scope, hash_hex)
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.inner
            .read()
            .expect("scope lock not poisoned")
            .has_scope(scope)
    }

    /// Remove a hash from ONE scope + persist (#62, `blob_unpublish`). Returns whether anything
    /// changed. Removes REACHABILITY, not bytes — see [`BlobScopes::unpublish_hash`].
    pub fn unpublish_hash(&self, scope: &str, hash_hex: &str) -> Result<bool> {
        let _w = self
            .write_lock
            .lock()
            .expect("scope write lock not poisoned");
        let (changed, snapshot) = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            let changed = g.unpublish_hash(scope, hash_hex);
            (changed, g.clone())
        };
        self.persist(&snapshot)?;
        Ok(changed)
    }

    /// Revoke `principals` from every scope + persist (single-writer). The unpair-hygiene
    /// inverse of `grant` — same lock/persist discipline. Returns whether anything changed.
    pub fn revoke_principals(&self, principals: &[String]) -> Result<bool> {
        let _w = self
            .write_lock
            .lock()
            .expect("scope write lock not poisoned");
        let (changed, snapshot) = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            let changed = g.revoke_principals(principals);
            (changed, g.clone())
        };
        if changed {
            self.persist(&snapshot)?;
        }
        Ok(changed)
    }

    /// Deterministic list rendering (delegates to `BlobScopes::list`).
    pub fn list(&self) -> Vec<ScopeRow> {
        self.inner.read().expect("scope lock not poisoned").list()
    }

    /// One filtered, bounded page (#84b).
    pub fn list_page(&self, q: &ListQuery) -> ScopePage {
        self.inner
            .read()
            .expect("scope lock not poisoned")
            .list_page(q)
    }

    fn persist(&self, scopes: &BlobScopes) -> Result<()> {
        let json = serde_json::to_string_pretty(scopes).context("serialize blob scopes")?;
        crate::roster::atomic_write_str(&self.path, &json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #62: a per-scope revoke must NOT behave like the global unpair-hygiene revoke. Wiring
    /// `blob_revoke` to `revoke_principals` would silently withdraw access from every other scope
    /// the caller never mentioned — this test is what distinguishes the two.
    #[test]
    fn revoke_from_scope_touches_only_that_scope() {
        let mut s = BlobScopes::default();
        s.grant("photos", "b64u:alice");
        s.grant("notes", "b64u:alice");

        assert!(s.revoke_from_scope("photos", &["b64u:alice".to_string()]));
        assert!(
            !s.scopes["photos"].grants.contains("b64u:alice"),
            "revoked from the named scope"
        );
        assert!(
            s.scopes["notes"].grants.contains("b64u:alice"),
            "the OTHER scope's grant must survive — this is not unpair hygiene"
        );

        // Idempotent, and an unknown scope is a clean no-op rather than an error.
        assert!(!s.revoke_from_scope("photos", &["b64u:alice".to_string()]));
        assert!(!s.revoke_from_scope("nope", &["b64u:alice".to_string()]));
    }

    /// #62: unpublish removes REACHABILITY immediately — the authz property, independent of GC.
    /// The grant is deliberately left alone: the person still has access to the scope, just not to
    /// that blob.
    #[test]
    fn unpublish_denies_the_hash_without_touching_the_grant() {
        let mut s = BlobScopes::default();
        s.publish_hash("photos", "abc123");
        s.grant("photos", "b64u:alice");
        let who: HashSet<&str> = ["b64u:alice"].into_iter().collect();
        assert!(s.allows("abc123", &who), "reachable before");

        assert!(s.unpublish_hash("photos", "abc123"));
        assert!(
            !s.allows("abc123", &who),
            "an unpublished hash must be unfetchable at once — no GC needed for the security half"
        );
        assert!(
            s.scopes["photos"].grants.contains("b64u:alice"),
            "the grant survives: access to the SCOPE is unchanged"
        );
        assert!(!s.unpublish_hash("photos", "abc123"), "idempotent");
    }

    /// #62: the same bytes published into two scopes stay reachable through the other one — so
    /// unpublish is not a global delete, and GC must not reclaim a hash another scope still holds.
    #[test]
    fn unpublish_is_scoped_and_leaves_other_references_live() {
        let mut s = BlobScopes::default();
        s.publish_hash("photos", "abc123");
        s.publish_hash("backup", "abc123");
        s.grant("backup", "b64u:alice");

        s.unpublish_hash("photos", "abc123");
        let who: HashSet<&str> = ["b64u:alice"].into_iter().collect();
        assert!(
            s.allows("abc123", &who),
            "still reachable via the scope that still lists it"
        );
        assert!(
            s.scopes["backup"].hashes.contains("abc123"),
            "the other scope still lists it — unpublish is per-scope, never a global delete"
        );
    }

    use std::collections::HashSet;

    fn principals<'a>(names: &'a [&'a str]) -> HashSet<&'a str> {
        names.iter().copied().collect()
    }

    /// Unpair hygiene (#38): `revoke_principals` strips exactly the named principals from
    /// every scope, leaving other grants and the published hashes intact, so a fetch that
    /// admitted before the revoke is denied after.
    #[test]
    fn revoke_principals_strips_grants_and_denies_after() {
        let mut s = BlobScopes::default();
        let hash = "aa".repeat(32);
        s.publish_hash("docs", &hash);
        s.grant("docs", "eid:beef");
        s.grant("docs", "team-eng");
        assert!(
            s.allows(&hash, &principals(&["eid:beef"])),
            "granted before revoke"
        );

        // Revoke the device principal only — the group grant and the hash survive.
        assert!(s.revoke_principals(&["eid:beef".to_string()]));
        assert!(
            !s.allows(&hash, &principals(&["eid:beef"])),
            "denied after revoke"
        );
        assert!(
            s.allows(&hash, &principals(&["team-eng"])),
            "an unrelated grant is untouched"
        );
        // Idempotent: revoking an absent principal changes nothing.
        assert!(!s.revoke_principals(&["eid:beef".to_string()]));
    }

    #[test]
    fn allows_requires_hash_in_scope_and_a_matching_grant() {
        let mut s = BlobScopes::default();
        s.publish_hash("docs", "aa".repeat(32).as_str());
        s.grant("docs", "alice");
        s.grant("docs", "team-eng");

        // In-scope hash + a granted user_id → allow.
        assert!(s.allows(&"aa".repeat(32), &principals(&["alice"])));
        // In-scope hash + a granted GROUP (the caller carries the group) → allow.
        assert!(s.allows(&"aa".repeat(32), &principals(&["bob", "team-eng"])));
        // In-scope hash but the caller has NO granted principal → deny (SECURITY: default-deny).
        assert!(!s.allows(&"aa".repeat(32), &principals(&["carol", "team-sales"])));
        // A hash in NO scope → deny even for a granted principal (hashes are not capabilities).
        assert!(!s.allows(&"bb".repeat(32), &principals(&["alice"])));
        // An empty principal set (a pairing-only caller) → deny.
        assert!(!s.allows(&"aa".repeat(32), &principals(&[])));
    }

    #[test]
    fn a_hash_in_one_scope_is_not_reachable_via_a_different_scopes_grant() {
        // Cross-scope isolation: scope "a" contains H and grants alice; scope "b" grants bob but
        // does NOT contain H. bob must NOT reach H (P10 hash probing across scopes).
        let mut s = BlobScopes::default();
        s.publish_hash("a", "cc".repeat(32).as_str());
        s.grant("a", "alice");
        s.grant("b", "bob");
        assert!(!s.allows(&"cc".repeat(32), &principals(&["bob"])));
        assert!(s.allows(&"cc".repeat(32), &principals(&["alice"])));
    }

    #[test]
    fn store_persists_and_reloads_the_same_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob-scopes.json");
        let store = ScopeStore::new(path.clone());
        store.publish_hash("docs", &"dd".repeat(32)).unwrap();
        store.grant("docs", "alice").unwrap();

        // A fresh store over the same file sees the persisted scopes.
        let reloaded = ScopeStore::load(path).unwrap();
        let snap = reloaded.snapshot();
        assert!(snap.allows(&"dd".repeat(32), &principals(&["alice"])));
        // list() renders (name, hashes, grants) deterministically sorted.
        let listed = reloaded.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "docs");
        assert_eq!(listed[0].1, vec!["dd".repeat(32)]);
        assert_eq!(listed[0].2, vec!["alice".to_string()]);
    }

    #[test]
    fn loading_a_missing_sidecar_is_an_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = ScopeStore::load(dir.path().join("does-not-exist.json")).unwrap();
        assert!(store.snapshot().is_empty());
    }
}

#[cfg(test)]
mod withdrawal_tests {
    use super::*;

    /// #107: an unpublish must be DURABLE against a later republish on this node. Bytes are never
    /// reclaimed (#80), so `has()` stays true forever and republish would otherwise re-add the hash
    /// to a scope whose grants unpublish never touched — restoring access with no grant call.
    #[test]
    fn unpublish_records_a_withdrawal_that_blocks_republish() {
        let mut s = BlobScopes::default();
        s.publish_hash("room", "aa");
        s.grant("room", "b64u:alice");
        assert!(s.unpublish_hash("room", "aa"), "the hash was there");
        assert!(
            s.is_withdrawn("room", "aa"),
            "unpublish must record the withdrawal, not merely drop the hash"
        );
    }

    /// Per-(scope, hash), not global: withdrawing H from A must not block H in B, nor a different
    /// hash in A. Fails if the set is kept per-store instead of per-scope.
    #[test]
    fn a_withdrawal_is_scoped_to_one_scope_and_one_hash() {
        let mut s = BlobScopes::default();
        s.publish_hash("a", "h1");
        s.publish_hash("b", "h1");
        s.publish_hash("a", "h2");
        s.unpublish_hash("a", "h1");
        assert!(s.is_withdrawn("a", "h1"));
        assert!(!s.is_withdrawn("b", "h1"), "another scope is unaffected");
        assert!(!s.is_withdrawn("a", "h2"), "another hash is unaffected");
    }

    /// The deliberate act clears it: `blob_publish` names a FILE, so it is an operator saying "I
    /// mean this content, in this scope".
    #[test]
    fn publishing_from_a_path_clears_the_withdrawal() {
        let mut s = BlobScopes::default();
        s.publish_hash("room", "aa");
        s.unpublish_hash("room", "aa");
        assert!(s.is_withdrawn("room", "aa"));
        s.publish_hash("room", "aa");
        assert!(
            !s.is_withdrawn("room", "aa"),
            "a deliberate publish-from-path is the un-withdraw"
        );
    }

    /// Granting a PRINCIPAL says nothing about a hash. If it cleared withdrawals, content would
    /// resurrect as a side effect of an unrelated act — the silent widening this issue exists to
    /// stop.
    #[test]
    fn granting_a_principal_does_not_clear_a_withdrawal() {
        let mut s = BlobScopes::default();
        s.publish_hash("room", "aa");
        s.unpublish_hash("room", "aa");
        s.grant("room", "b64u:bob");
        assert!(
            s.is_withdrawn("room", "aa"),
            "a grant must never un-withdraw — it names a principal, not a hash"
        );
    }

    /// #107's load-bearing property: the withdrawal SURVIVES A RESTART. A tombstone that
    /// evaporated on reload would be worse than none — it reads as durable, then silently reverts,
    /// and the operator has no way to notice.
    #[test]
    fn a_withdrawal_survives_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scopes.json");
        {
            let store = ScopeStore::new(path.clone());
            store.publish_hash("room", "aa").unwrap();
            store.grant("room", "b64u:alice").unwrap();
            store.unpublish_hash("room", "aa").unwrap();
            assert!(store.is_withdrawn("room", "aa"));
        }
        let reloaded = ScopeStore::load(path).unwrap();
        assert!(
            reloaded.is_withdrawn("room", "aa"),
            "the withdrawal must persist — a daemon restart must not silently un-revoke"
        );
    }

    /// A sidecar written BEFORE 0.17.0 has no `withdrawn` field; it must load, not fail closed on
    /// deserialization and not fail open by inventing withdrawals.
    #[test]
    fn a_pre_0_17_sidecar_loads_with_no_withdrawals() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.json");
        std::fs::write(
            &path,
            r#"{"scopes":{"room":{"hashes":["aa"],"grants":["b64u:alice"]}}}"#,
        )
        .unwrap();
        let store = ScopeStore::load(path).expect("an old sidecar still loads");
        assert!(!store.is_withdrawn("room", "aa"), "nothing was withdrawn");
        assert!(
            store
                .snapshot()
                .allows("aa", &["b64u:alice"].into_iter().collect()),
            "and the existing grant still works"
        );
    }
}

#[cfg(test)]
mod listing_tests {
    use super::*;

    fn table(n: usize) -> BlobScopes {
        let mut s = BlobScopes::default();
        for i in 0..n {
            s.publish_hash(&format!("file:{i:04}"), &format!("{i:064x}"));
            s.grant(&format!("file:{i:04}"), "b64u:alice");
        }
        s
    }

    /// #84b back-compat: an unfiltered listing still works, and now reports how many matched so a
    /// caller can tell a complete answer from a clipped one.
    #[test]
    fn an_unfiltered_listing_reports_its_total_and_is_not_truncated() {
        let page = table(5).list_page(&ListQuery::default());
        assert_eq!(page.rows.len(), 5);
        assert_eq!(page.total, 5);
        assert!(!page.truncated, "5 scopes fit under any sane default");
    }

    /// The failure #84 reports is a CLOSED CONNECTION, not a slow one: `blob_list` renders every
    /// scope into one frame against a 16 MiB cap whose violation strikes the connection out. A
    /// default limit turns that into a truncated answer the caller can detect and page through.
    #[test]
    fn the_default_limit_truncates_and_says_so() {
        let page = table(300).list_page(&ListQuery::default());
        assert_eq!(page.rows.len(), DEFAULT_LIST_LIMIT, "default limit applies");
        assert_eq!(page.total, 300, "total counts MATCHES, not returned rows");
        assert!(
            page.truncated,
            "a clipped answer must announce itself — a caller that cannot tell is the silent \
             wrong answer this repo keeps re-learning"
        );
    }

    /// Paging must not overlap or skip. The table is a BTreeMap so name order is stable; without a
    /// stable order paging returns garbage that looks plausible.
    #[test]
    fn offset_and_limit_page_without_overlap_or_gaps() {
        let t = table(25);
        let p1 = t.list_page(&ListQuery {
            limit: Some(10),
            ..Default::default()
        });
        let p2 = t.list_page(&ListQuery {
            limit: Some(10),
            offset: Some(10),
            ..Default::default()
        });
        let n1: Vec<&String> = p1.rows.iter().map(|r| &r.0).collect();
        let n2: Vec<&String> = p2.rows.iter().map(|r| &r.0).collect();
        assert_eq!(n1.len(), 10);
        assert_eq!(n2.len(), 10);
        assert!(
            n1.iter().all(|n| !n2.contains(n)),
            "pages must be disjoint: {n1:?} vs {n2:?}"
        );
        let mut union: Vec<String> = n1.iter().chain(n2.iter()).map(|s| (*s).clone()).collect();
        union.sort();
        let expected: Vec<String> = (0..20).map(|i| format!("file:{i:04}")).collect();
        assert_eq!(
            union, expected,
            "and together they are the first 20 in order"
        );
    }

    /// Exact match, not prefix or substring — `file:aa` must not match `file:aabb`. Under
    /// one-scope-per-file the names are derived from hashes and share prefixes constantly.
    #[test]
    fn the_scope_filter_is_exact_not_a_prefix() {
        let mut s = BlobScopes::default();
        s.publish_hash("file:aa", "11");
        s.publish_hash("file:aabb", "22");
        let page = s.list_page(&ListQuery {
            scope: Some("file:aa".into()),
            ..Default::default()
        });
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].0, "file:aa");
        assert_eq!(page.total, 1, "and the total reflects the filter");
    }

    /// `counts_only` answers "how many files / how many withdrawn" in constant response size —
    /// the common question under one-scope-per-file — without shipping every hash.
    #[test]
    fn counts_only_omits_the_vectors_but_keeps_the_counts() {
        let mut s = table(3);
        s.unpublish_hash("file:0000", &format!("{:064x}", 0));
        let page = s.list_page(&ListQuery {
            counts_only: true,
            ..Default::default()
        });
        let row = page.rows.iter().find(|r| r.0 == "file:0000").unwrap();
        assert!(row.1.is_empty(), "hashes omitted");
        assert!(row.2.is_empty(), "grants omitted");
        assert!(row.3.is_empty(), "withdrawn omitted");
        assert_eq!(row.5, 1, "but the grant count survives");
        assert_eq!(row.6, 1, "and the withdrawn count");
    }
}
