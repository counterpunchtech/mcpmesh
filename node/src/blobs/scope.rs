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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub hashes: BTreeSet<String>,
    pub grants: BTreeSet<String>,
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
        self.scopes
            .entry(scope.to_string())
            .or_default()
            .hashes
            .insert(hash_hex.to_string());
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
    /// scope, so an unpublished hash is immediately unfetchable. It does NOT delete bytes — the
    /// store still holds them until `blob_gc` runs. A hash published into several scopes stays
    /// reachable through the others.
    pub fn unpublish_hash(&mut self, scope: &str, hash_hex: &str) -> bool {
        self.scopes
            .get_mut(scope)
            .is_some_and(|sc| sc.hashes.remove(hash_hex))
    }

    /// Every hash any scope references — the GC liveness root (#62). mcpmesh creates no persistent
    /// blob tags, so this is the ONLY root: a blob absent from this set is referenced by nothing.
    pub fn live_hashes(&self) -> std::collections::BTreeSet<String> {
        self.scopes
            .values()
            .flat_map(|sc| sc.hashes.iter().cloned())
            .collect()
    }

    /// SECURITY LINCHPIN (pure): ALLOW iff SOME scope contains `hash_hex` AND grants one of the
    /// caller's `principals` (`{user_id} ∪ groups`). Default-deny — an in-scope hash with no matching
    /// grant, a hash in no scope, and an empty principal set all return `false`. Hashes are never
    /// capabilities; a hash reachable in scope A does not become reachable via scope B's grant.
    pub fn allows(&self, hash_hex: &str, principals: &HashSet<&str>) -> bool {
        self.scopes.values().any(|sc| {
            sc.hashes.contains(hash_hex)
                && sc.grants.iter().any(|g| principals.contains(g.as_str()))
        })
    }

    /// Deterministic `(name, hashes, grants)` rendering for `list` (sorted by BTree order).
    pub fn list(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
        self.scopes
            .iter()
            .map(|(name, sc)| {
                (
                    name.clone(),
                    sc.hashes.iter().cloned().collect(),
                    sc.grants.iter().cloned().collect(),
                )
            })
            .collect()
    }
}

/// The single-writer scope store. An in-RAM `RwLock<BlobScopes>` serves the hot
/// authz read (`snapshot`, a cheap clone taken per GET — no lock held across the async reply); every
/// mutation (`publish_hash`/`grant`) takes the write lock, mutates, and atomically persists the JSON
/// sidecar (`crate::roster::atomic_write_str` = write-new + rename). All mutations flow through
/// the daemon control path, so there is exactly one writer.
pub struct ScopeStore {
    path: PathBuf,
    inner: RwLock<BlobScopes>,
}

impl ScopeStore {
    /// An EMPTY store bound to `path` (does not read the file). Used for a caller-only fetcher (no
    /// scopes) and by tests.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: RwLock::new(BlobScopes::default()),
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
        let snapshot = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            g.publish_hash(scope, hash_hex);
            g.clone()
        };
        self.persist(&snapshot)
    }

    /// Grant a scope to a principal + persist (single-writer). Same lock/persist discipline.
    pub fn grant(&self, scope: &str, principal: &str) -> Result<()> {
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
        let (changed, snapshot) = {
            let mut g = self.inner.write().expect("scope lock not poisoned");
            let changed = g.revoke_from_scope(scope, principals);
            (changed, g.clone())
        };
        self.persist(&snapshot)?;
        Ok(changed)
    }

    /// Remove a hash from ONE scope + persist (#62, `blob_unpublish`). Returns whether anything
    /// changed. Removes REACHABILITY, not bytes — see [`BlobScopes::unpublish_hash`].
    pub fn unpublish_hash(&self, scope: &str, hash_hex: &str) -> Result<bool> {
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
    pub fn list(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
        self.snapshot().list()
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
            s.live_hashes().contains("abc123"),
            "and still LIVE for GC — reclaiming it here would destroy data another scope references"
        );
    }

    /// #62: the GC root is exactly the union of scope hashes.
    #[test]
    fn live_hashes_is_the_union_of_every_scope() {
        let mut s = BlobScopes::default();
        s.publish_hash("a", "h1");
        s.publish_hash("b", "h2");
        s.publish_hash("b", "h1");
        let live = s.live_hashes();
        assert_eq!(live.len(), 2);
        assert!(live.contains("h1") && live.contains("h2"));

        // An emptied scope contributes nothing — this is what makes GC reclaim it.
        s.unpublish_hash("a", "h1");
        s.unpublish_hash("b", "h1");
        assert!(!s.live_hashes().contains("h1"));
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
