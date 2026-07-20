//! THE principal-set expansion: the ONE definition of a resolved caller's flat
//! authorization identity — `groups ∪ {nickname} ∪ {user_id}`, empty components skipped,
//! default-deny (no identity ⇒ empty set ⇒ nothing matches).
//!
//! WHY THIS LIVES HERE: three enforcement sites consume this
//! expansion — the mesh service allow check (`mcpmesh-net::endpoint::caller_admits`), the
//! plugin-seam audience expansion (`service::peer_audiences`), and the blob-scope gate
//! (`cli/src/blobs/provider.rs`). They live in crates with no other shared home:
//! `mcpmesh-net` must not pull the seam's tokio/rustix surface, and `mcpmesh-codec` is
//! wire-codec-only by charter. `mcpmesh-local-api`'s DEFAULT (feature-less) surface is the
//! family's dependency-free vocabulary crate — protocol types, serde only — so a pure
//! `principal_set` fn belongs on it, and `mcpmesh-net` takes a default-features-only dep
//! (types-only, no iroh/tokio cycle; local-api depends on nothing in the platform DAG).
//! One implementation, drift impossible.
use std::collections::BTreeSet;

/// Expand a resolved peer identity into its flat principal set:
/// `groups ∪ {name} ∪ {user_id}`. Borrowed — callers match `allow`/grant entries against it.
///
/// - `name` is the device nickname (pairing mode) or roster display handle — a legitimate
///   grant target (nicknames, user_ids, and group names share one flat namespace).
/// - `user_id` is the person's verified id (roster, or a pairing device→user binding);
///   `None` for an unbound pairing peer.
/// - Empty strings are never principals (an absent value must not become a matchable "").
/// - An absent/empty identity yields the EMPTY set — default deny.
pub fn principal_set<'a>(
    name: Option<&'a str>,
    user_id: Option<&'a str>,
    groups: &'a [String],
) -> BTreeSet<&'a str> {
    let mut set: BTreeSet<&'a str> = groups
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    for v in [name, user_id].into_iter().flatten() {
        if !v.is_empty() {
            set.insert(v);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_set_is_groups_union_name_union_user_id() {
        let groups = vec!["eng".to_string(), "ops".to_string()];
        let set = principal_set(Some("bob-laptop"), Some("b64u:BOB"), &groups);
        let want: BTreeSet<&str> = ["eng", "ops", "bob-laptop", "b64u:BOB"].into();
        assert_eq!(set, want);
    }

    #[test]
    fn empty_components_are_skipped_and_absent_identity_is_default_deny() {
        // Empty strings never become principals.
        let groups = vec![String::new(), "eng".to_string()];
        let set = principal_set(Some(""), None, &groups);
        assert_eq!(set, BTreeSet::from(["eng"]));
        // No identity at all ⇒ empty set ⇒ default deny.
        assert!(principal_set(None, None, &[]).is_empty());
    }

    /// A pairing-mode peer (nickname only, no user binding) IS a principal by its nickname —
    /// the flat namespace deliberately includes nicknames.
    #[test]
    fn pairing_mode_nickname_is_a_principal() {
        let set = principal_set(Some("carol"), None, &[]);
        assert_eq!(set, BTreeSet::from(["carol"]));
    }
}
