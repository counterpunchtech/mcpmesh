//! The persisted scope model (spec §9): a named set of blob hashes + a set of granted principals.
//! An app publishes blobs INTO a scope and grants the scope to principals (a roster group name or a
//! user_id — one flat namespace, §4.3 rule 5). The request-time gate (Task 3) ALLOWS a GET iff some
//! scope contains the hash AND grants one of the caller's `{user_id} ∪ groups`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One scope: the blob hashes it contains + the principals it grants. Hashes are bare 64-char blake3
/// hex (`Hash::to_hex()`); principals are flat names in the roster's `user_id ∪ groups` namespace.
/// `BTreeSet` for deterministic serialization + list ordering.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub hashes: BTreeSet<String>,
    pub grants: BTreeSet<String>,
}

/// The full scope table (spec §9): `scope_name -> Scope`. `Default` is the empty table.
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

/// The single-writer scope store (spec §9 persistence). An in-RAM `RwLock<BlobScopes>` serves the hot
/// authz read (`snapshot`, a cheap clone taken per GET — no lock held across the async reply); every
/// mutation (`publish_hash`/`grant`) takes the write lock, mutates, and atomically persists the JSON
/// sidecar (`crate::roster::atomic_write_str` = write-new + rename, §13). All mutations flow through
/// the daemon control path, so there is exactly one writer ([RECONCILE-SCOPE-PERSIST-SINGLE-WRITER]).
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

    /// A cheap clone of the current scope table for the hot authz read (Task 3) + `list` rendering.
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
    use std::collections::HashSet;

    fn principals<'a>(names: &'a [&'a str]) -> HashSet<&'a str> {
        names.iter().copied().collect()
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
