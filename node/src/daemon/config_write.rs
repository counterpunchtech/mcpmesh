//! The daemon's surgical `config.toml` read-modify-write writers. Every writer here follows
//! one discipline: [`read_config_for_rmw`] → parse as a `toml::Table` → mutate only the
//! touched keys → [`write_config_doc`] (render + the reference-doc header + an atomic
//! per-call-unique temp rename — no torn config). Comments/formatting are not preserved —
//! this is the machine-managed config surface; a `toml_edit` round-trip is a possible later
//! refinement.
//!
//! **Lock discipline (shared by every writer).** These are the LOCK-FREE halves of config
//! mutations: each caller holds `mesh.reload_lock` around its WHOLE critical section (read →
//! validate → write → reload → swap) and calls the writer DIRECTLY — a nested `reload_lock.lock()`
//! on the non-reentrant tokio Mutex would deadlock. The single-writer serialization lives at the
//! call sites (`install_roster` / `org_join` / `set_roster_url` / `register_service` /
//! `grant_service_access` / `revoke_service_access` / `rename_peer`), never here.

use std::path::Path;

use anyhow::{Context, Result};
use mcpmesh_local_api::BackendSpec;

use crate::util::atomic_write;

/// Read a config file for a surgical read-modify-write, DISTINGUISHING a not-yet-created config
/// (legitimately empty — the first write) from a real IO error on an EXISTING file (e.g. its
/// permissions changed mid-life). `NotFound` → `""` (parses to an empty table, so the caller
/// edits from scratch); any other IO error propagates WITH context.
///
/// The bare `read_to_string(path).unwrap_or_default()` this replaces would coerce an unreadable
/// config to `""` → the strip/append silently finds nothing → a no-op returning `changed=false`,
/// i.e. a FALSE SUCCESS on an authorization mutation (a grant/revoke that never touched disk while
/// `pair`/`pair --remove` report success — the very orphan-allow the revoke-first ordering exists
/// to avoid). The allow-append/-remove callers must fail LOUDLY instead; the register path shares
/// the same class, so it uses this too.
pub(crate) fn read_config_for_rmw(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("read config {}", path.display())),
    }
}

/// The one-line comment header every managed write (re)adds to `config.toml`, pointing at the
/// key reference (issue #12). The TOML round-trip above drops comments, so the header is
/// prepended at write time by [`write_config_doc`] rather than stored — it therefore survives
/// every rewrite and never duplicates (the parse strips it, the write re-adds it).
const CONFIG_HEADER: &str = "# mcpmesh config — every table and key is documented in docs/config.md \
     (https://github.com/counterpunchtech/mcpmesh/blob/main/docs/config.md)";

/// Render a mutated config document and atomically replace the file, prepending
/// [`CONFIG_HEADER`] — the single write seam every writer in this module funnels through.
fn write_config_doc(path: &Path, doc: &toml::Table) -> Result<()> {
    let rendered = toml::to_string_pretty(doc).context("serialize config.toml")?;
    atomic_write(path, format!("{CONFIG_HEADER}\n{rendered}").as_bytes())
}

/// Surgically upsert string keys into ONE named top-level `[table]` of the config at `path`,
/// preserving every other key, then atomically replace the file — the shared body of the four
/// identity/roster pin writers below. Creates the table if absent; bails if the existing entry
/// under that name is not a table.
fn upsert_config_strings(path: &Path, table: &str, pairs: &[(&str, &str)]) -> Result<()> {
    let existing = read_config_for_rmw(path)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .with_context(|| format!("parse existing config {}", path.display()))?;
    let entry = doc
        .entry(table.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let toml::Value::Table(entry) = entry else {
        anyhow::bail!("[{table}] in {} is not a table", path.display());
    };
    for (k, v) in pairs {
        entry.insert((*k).into(), toml::Value::String((*v).to_string()));
    }
    write_config_doc(path, &doc)
}

/// Upsert `[identity].org_root_pk` + `[identity].org_id` — the pin write `install_roster` runs
/// AFTER validation succeeds (pin-after-validate, see its doc).
pub(crate) fn write_identity_pin(path: &Path, org_root_pk: &str, org_id: &str) -> Result<()> {
    upsert_config_strings(
        path,
        "identity",
        &[("org_root_pk", org_root_pk), ("org_id", org_id)],
    )
}

/// Upsert `[identity].user_id` — the write `reconcile_user_id_from_roster` runs when the
/// installed roster's authoritative value differs from config's proposal.
pub(crate) fn write_identity_user_id(path: &Path, user_id: &str) -> Result<()> {
    upsert_config_strings(path, "identity", &[("user_id", user_id)])
}

/// Upsert the four `[identity]` join keys (the `org_join` control arm). `user_key` is a LOCAL
/// path string (the key file itself never crosses the API — only its path is recorded).
pub(crate) fn write_join_pin(
    path: &Path,
    org_id: &str,
    org_root_pk: &str,
    user_id: &str,
    user_key: &str,
) -> Result<()> {
    upsert_config_strings(
        path,
        "identity",
        &[
            ("org_id", org_id),
            ("org_root_pk", org_root_pk),
            ("user_id", user_id),
            ("user_key", user_key),
        ],
    )
}

/// Upsert `[roster].url` (the `set_roster_url` control arm). A pre-existing `grace_period` (or
/// any other `[roster]` key) is preserved.
pub(crate) fn write_roster_url(path: &Path, url: &str) -> Result<()> {
    upsert_config_strings(path, "roster", &[("url", url)])
}

/// Upsert `[services.<name>]` (atomic, surgical RMW), updating the backend while UNIONING the
/// incoming `allow` into any grants already on disk. Registration OWNS the backend; the allowlist
/// is co-owned by the pairing grant (`grant_service_access` appends nicknames). A re-registration
/// therefore must never DROP an existing allow entry — otherwise a service that re-registers on
/// every startup (kb does, always with an EMPTY allow) would silently revoke every paired peer.
/// So: keep the existing allow, append incoming names not already present (an explicit
/// `serve --allow bob` still adds a grant; removal is the separate `revoke_service_access` path).
/// Deliberately NOT routed through [`upsert_config_strings`] — this is a real merge, not a
/// string-key upsert.
pub(crate) fn write_service_to_config(
    path: &Path,
    name: &str,
    backend: &BackendSpec,
    allow: &[String],
) -> Result<()> {
    let existing = read_config_for_rmw(path)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .with_context(|| format!("parse existing config {}", path.display()))?;

    let services = doc
        .entry("services".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let toml::Value::Table(services) = services else {
        anyhow::bail!("[services] in {} is not a table", path.display());
    };

    // Union the incoming allow with any grants already on disk (see the fn doc): a re-registration
    // updates the backend but must never silently drop a nickname a prior pairing appended.
    let mut merged_allow: Vec<String> = services
        .get(name)
        .and_then(toml::Value::as_table)
        .and_then(|t| t.get("allow"))
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for a in allow {
        if !merged_allow.iter().any(|existing| existing == a) {
            merged_allow.push(a.clone());
        }
    }

    let mut entry = toml::Table::new();
    match backend {
        BackendSpec::Run { cmd } => {
            entry.insert(
                "run".into(),
                toml::Value::Array(cmd.iter().cloned().map(toml::Value::String).collect()),
            );
        }
        BackendSpec::Socket { path } => {
            entry.insert("socket".into(), toml::Value::String(path.clone()));
        }
    }
    entry.insert(
        "allow".into(),
        toml::Value::Array(merged_allow.into_iter().map(toml::Value::String).collect()),
    );
    services.insert(name.to_string(), toml::Value::Table(entry));

    write_config_doc(path, &doc)
}

/// Append `nickname` to each `[services.<svc>].allow` in the config at `path`, idempotently,
/// and atomically rewrite the file. Returns whether the config actually CHANGED (so the caller
/// can skip a pointless reload).
///
/// A service NOT present in config is logged + skipped: a pairing grant authorizes into an
/// existing service, it never creates one. An already-present nickname is a no-op for that
/// service (idempotent re-pair). Returns `Ok(false)` with no write when nothing changed.
pub(crate) fn append_allow_to_config(
    path: &Path,
    nickname: &str,
    services: &[String],
) -> Result<bool> {
    let existing = read_config_for_rmw(path)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .with_context(|| format!("parse existing config {}", path.display()))?;

    // No `[services]` table at all → nothing to grant into (log each, change nothing).
    let Some(toml::Value::Table(services_tbl)) = doc.get_mut("services") else {
        for svc in services {
            tracing::warn!(service = %svc, "grant: service not in config; skipping allow-append");
        }
        return Ok(false);
    };

    let mut changed = false;
    for svc in services {
        let Some(entry) = services_tbl.get_mut(svc) else {
            tracing::warn!(service = %svc, "grant: service not in config; skipping allow-append");
            continue;
        };
        let toml::Value::Table(entry) = entry else {
            anyhow::bail!("[services.{svc}] in {} is not a table", path.display());
        };
        let allow = entry
            .entry("allow".to_string())
            .or_insert_with(|| toml::Value::Array(Vec::new()));
        let toml::Value::Array(allow_arr) = allow else {
            anyhow::bail!(
                "[services.{svc}].allow in {} is not an array",
                path.display()
            );
        };
        // Idempotent: append only if not already granted.
        if allow_arr.iter().any(|v| v.as_str() == Some(nickname)) {
            continue;
        }
        allow_arr.push(toml::Value::String(nickname.to_string()));
        changed = true;
    }

    if changed {
        write_config_doc(path, &doc)?;
    }
    Ok(changed)
}

/// Remove `nickname` from EVERY `[services.<svc>].allow` in the config at `path`, and atomically
/// rewrite the file. Returns whether the config actually CHANGED (so the caller can skip a
/// pointless reload). The exact inverse of [`append_allow_to_config`].
///
/// **Fail-safe leniency (vs. the grant's strictness).** A malformed service entry (a non-table
/// `[services.<svc>]`, or a non-array `allow`) is SKIPPED, not an error: this is a removal that
/// only ever makes access MORE restricted, and its caller (`remove_peer`) aborts the whole
/// unpair on any error — so bailing on one weird entry would leave the peer LESS restricted (the
/// opposite of fail-safe). A genuinely unparseable config still errors (exceptional corruption,
/// same as the grant path). No `[services]` table → nothing to revoke (`Ok(false)`).
pub(crate) fn remove_allow_from_config(path: &Path, nickname: &str) -> Result<bool> {
    let existing = read_config_for_rmw(path)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .with_context(|| format!("parse existing config {}", path.display()))?;

    let Some(toml::Value::Table(services_tbl)) = doc.get_mut("services") else {
        return Ok(false); // no [services] table → nothing to revoke
    };

    let mut changed = false;
    for (_svc, entry) in services_tbl.iter_mut() {
        // Skip a malformed service entry rather than bail (fail-safe — see the doc note).
        let toml::Value::Table(entry) = entry else {
            continue;
        };
        let Some(toml::Value::Array(allow_arr)) = entry.get_mut("allow") else {
            continue;
        };
        let before = allow_arr.len();
        allow_arr.retain(|v| v.as_str() != Some(nickname));
        if allow_arr.len() != before {
            changed = true;
        }
    }

    if changed {
        write_config_doc(path, &doc)?;
    }
    Ok(changed)
}

/// Replace `from` with `to` in every service's config `[services.<svc>].allow` (dedup — if `to` is
/// already present, `from` is simply dropped). The rename analogue of [`remove_allow_from_config`],
/// so a contact rename carries its grants to the new name. Returns whether the config changed.
pub(crate) fn rename_allow_in_config(path: &Path, from: &str, to: &str) -> Result<bool> {
    let existing = read_config_for_rmw(path)?;
    let mut doc: toml::Table = toml::from_str(&existing)
        .with_context(|| format!("parse existing config {}", path.display()))?;

    let Some(toml::Value::Table(services_tbl)) = doc.get_mut("services") else {
        return Ok(false); // no [services] table → nothing to rewrite
    };

    let mut changed = false;
    for (_svc, entry) in services_tbl.iter_mut() {
        let toml::Value::Table(entry) = entry else {
            continue;
        };
        let Some(toml::Value::Array(allow_arr)) = entry.get_mut("allow") else {
            continue;
        };
        if !allow_arr.iter().any(|v| v.as_str() == Some(from)) {
            continue;
        }
        let has_to = allow_arr.iter().any(|v| v.as_str() == Some(to));
        allow_arr.retain(|v| v.as_str() != Some(from));
        if !has_to {
            allow_arr.push(toml::Value::String(to.to_string()));
        }
        changed = true;
    }

    if changed {
        write_config_doc(path, &doc)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    /// Every managed write prepends the one-line reference header pointing at docs/config.md
    /// (issue #12), a later rewrite does not duplicate it (the parse strips comments, the write
    /// re-adds one), and the headered file still loads.
    #[test]
    fn managed_writes_carry_the_reference_header_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_service_to_config(
            &path,
            "kb",
            &BackendSpec::Socket {
                path: "/run/kb.sock".into(),
            },
            &[],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.starts_with("# mcpmesh config") && text.contains("docs/config.md"),
            "the generated config opens with the reference header: {text}"
        );
        // A second managed write re-adds the header exactly once, and the file still parses.
        assert!(append_allow_to_config(&path, "bob", &["kb".to_string()]).unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.matches("# mcpmesh config").count(),
            1,
            "no duplicated header after a rewrite: {text}"
        );
        assert!(Config::load(&path).is_ok());
    }

    /// `write_join_pin` upserts the FOUR `[identity]` keys while preserving every other config key
    /// (surgical RMW) and lands atomically. Sync (no endpoint) — isolates the write discipline.
    #[test]
    fn write_join_pin_is_surgical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[network]\nrelay_mode = \"disabled\"\n\n[identity]\nnickname = \"mydev\"\n\n\
             [services.notes]\nrun = [\"notes-mcp\"]\nallow = [\"alice\"]\n",
        )
        .unwrap();

        write_join_pin(
            &path,
            "acme",
            "b64u:ANCHOR",
            "alice",
            "/home/alice/user.key",
        )
        .unwrap();

        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let identity = doc["identity"].as_table().unwrap();
        assert_eq!(identity["org_id"].as_str(), Some("acme"));
        assert_eq!(identity["org_root_pk"].as_str(), Some("b64u:ANCHOR"));
        assert_eq!(identity["user_id"].as_str(), Some("alice"));
        assert_eq!(identity["user_key"].as_str(), Some("/home/alice/user.key"));
        // Every pre-existing key is preserved (surgical): nickname, the network table, the service.
        assert_eq!(identity["nickname"].as_str(), Some("mydev"));
        assert_eq!(
            doc["network"]["relay_mode"].as_str(),
            Some("disabled"),
            "unrelated [network] must be preserved"
        );
        assert!(
            doc["services"]["notes"].is_table(),
            "a pre-existing [services.*] must be preserved: {doc:?}"
        );
    }

    /// `write_roster_url` upserts `[roster].url`, creating the table when absent and preserving
    /// every other key (surgical RMW) — the `[roster]` sibling of `write_join_pin`.
    #[test]
    fn write_roster_url_upserts_and_preserves() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-existing [roster] with another key → the key survives, url is added.
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[network]\nrelay_mode = \"disabled\"\n\n[roster]\ngrace_period = \"7d\"\n",
        )
        .unwrap();
        write_roster_url(&path, "https://acme.example/roster.json").unwrap();
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            doc["roster"]["url"].as_str(),
            Some("https://acme.example/roster.json")
        );
        assert_eq!(doc["roster"]["grace_period"].as_str(), Some("7d"));
        assert_eq!(doc["network"]["relay_mode"].as_str(), Some("disabled"));
        // No [roster] table yet → it is created from scratch, other tables untouched.
        let path2 = dir.path().join("c2.toml");
        std::fs::write(&path2, "[identity]\nnickname = \"x\"\n").unwrap();
        write_roster_url(&path2, "https://h/r").unwrap();
        let doc2: toml::Table = toml::from_str(&std::fs::read_to_string(&path2).unwrap()).unwrap();
        assert_eq!(doc2["roster"]["url"].as_str(), Some("https://h/r"));
        assert_eq!(doc2["identity"]["nickname"].as_str(), Some("x"));
    }

    /// `write_identity_user_id` surgically upserts `[identity].user_id`, preserving other keys.
    #[test]
    fn write_identity_user_id_is_surgical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[identity]\nnickname = \"dev\"\norg_id = \"acme\"\n").unwrap();
        write_identity_user_id(&path, "b64u:USER").unwrap();
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(doc["identity"]["user_id"].as_str(), Some("b64u:USER"));
        assert_eq!(doc["identity"]["nickname"].as_str(), Some("dev"));
        assert_eq!(doc["identity"]["org_id"].as_str(), Some("acme"));
    }

    /// The shared upsert bails LOUDLY when the named entry exists but is NOT a table (a corrupt
    /// config must never be silently rewritten around).
    #[test]
    fn upsert_bails_on_a_non_table_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "identity = \"nope\"\n").unwrap();
        let err = write_identity_user_id(&path, "x").unwrap_err();
        assert!(
            format!("{err:#}").contains("[identity]"),
            "bail names the offending table: {err:#}"
        );
        // The file is untouched.
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "identity = \"nope\"\n"
        );
    }

    /// `append_allow_to_config` / `remove_allow_from_config` grant + revoke a nickname in a service's
    /// `allow`, are idempotent, and return `false` (no write) when there is nothing to change.
    #[test]
    fn allow_config_append_and_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[services.kb]\nsocket = \"/run/kb.sock\"\n").unwrap();

        // Grant bob → true, and bob is in the allow list.
        assert!(append_allow_to_config(&path, "bob", &["kb".to_string()]).unwrap());
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let allow = doc["services"]["kb"]["allow"].as_array().unwrap();
        assert!(allow.iter().any(|v| v.as_str() == Some("bob")));
        // Idempotent: re-granting bob is a no-op (false).
        assert!(!append_allow_to_config(&path, "bob", &["kb".to_string()]).unwrap());
        // Granting into a service NOT in config → skipped, no change.
        assert!(!append_allow_to_config(&path, "carol", &["ghost".to_string()]).unwrap());

        // Revoke bob → true, allow becomes empty.
        assert!(remove_allow_from_config(&path, "bob").unwrap());
        let doc: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            doc["services"]["kb"]["allow"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        // Revoking an absent nickname → no change (false).
        assert!(!remove_allow_from_config(&path, "nobody").unwrap());

        // No [services] table at all → both grant + revoke are false (nothing to touch).
        let empty = dir.path().join("empty.toml");
        std::fs::write(&empty, "[identity]\nnickname = \"x\"\n").unwrap();
        assert!(!append_allow_to_config(&empty, "bob", &["kb".to_string()]).unwrap());
        assert!(!remove_allow_from_config(&empty, "bob").unwrap());
    }

    /// Re-registering an existing service (kb does this idempotently on EVERY startup, with an
    /// EMPTY allow) must PRESERVE the grants a prior pairing appended to its `allow`. Otherwise a
    /// kb daemon restart silently revokes every paired peer's access to kb — the bug the Jetson
    /// P2P proof hit (a paired peer then gets `-32054 unknown or unauthorized service`).
    #[test]
    fn reregistering_a_service_preserves_existing_allow_grants() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let socket = BackendSpec::Socket {
            path: "/run/kb.sock".into(),
        };

        // 1. kb registers itself with an empty allow (reachability is a separate user grant).
        write_service_to_config(&path, "kb", &socket, &[]).unwrap();
        // 2. Pairing grants "alice" access (appends to [services.kb].allow).
        append_allow_to_config(&path, "alice", &["kb".to_string()]).unwrap();
        // 3. The kb daemon RESTARTS → re-registers idempotently, again with an empty allow.
        write_service_to_config(&path, "kb", &socket, &[]).unwrap();

        // The grant must survive the re-registration.
        let cfg = Config::load(&path).unwrap();
        assert_eq!(
            cfg.services.get("kb").unwrap().allow,
            vec!["alice".to_string()],
            "a kb re-registration must not wipe the pairing grant"
        );
    }

    /// A re-registration still UPDATES the backend and UNIONS any incoming allow (so an explicit
    /// `serve --allow bob` adds a grant) — it only refuses to silently DROP existing grants.
    #[test]
    fn reregistering_updates_backend_and_unions_incoming_allow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Initial: a socket backend allowing "alice".
        write_service_to_config(
            &path,
            "svc",
            &BackendSpec::Socket {
                path: "/a.sock".into(),
            },
            &["alice".to_string()],
        )
        .unwrap();
        // Re-register: a new socket path + a new allow entry "bob".
        write_service_to_config(
            &path,
            "svc",
            &BackendSpec::Socket {
                path: "/b.sock".into(),
            },
            &["bob".to_string()],
        )
        .unwrap();

        let cfg = Config::load(&path).unwrap();
        let svc = cfg.services.get("svc").unwrap();
        assert_eq!(svc.socket.as_deref(), Some("/b.sock"), "backend updates");
        assert_eq!(
            svc.allow,
            vec!["alice".to_string(), "bob".to_string()],
            "union: existing grant kept, incoming appended"
        );
    }

    #[test]
    fn rename_allow_in_config_replaces_following_grants_and_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        std::fs::write(
            &cfg,
            "[services.kb]\nallow = [\"bob\", \"eng\"]\n[services.notes]\nallow = [\"bob\", \"bobby\"]\n",
        )
        .unwrap();
        assert!(rename_allow_in_config(&cfg, "bob", "bobby").unwrap());
        let after = Config::load(&cfg).unwrap();
        let kb = &after.services.get("kb").unwrap().allow;
        assert!(
            kb.contains(&"bobby".to_string())
                && !kb.contains(&"bob".to_string())
                && kb.contains(&"eng".to_string())
        );
        // notes already had "bobby" → "bob" is dropped without a duplicate.
        assert_eq!(
            after.services.get("notes").unwrap().allow,
            vec!["bobby".to_string()]
        );
        // Renaming an absent name changes nothing.
        assert!(!rename_allow_in_config(&cfg, "nobody", "x").unwrap());
    }
}
