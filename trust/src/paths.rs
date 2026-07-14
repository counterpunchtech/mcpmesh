//! Shared paths rule (spec §13): XDG form, resolved per-platform in one place.
use std::path::PathBuf;

/// The ONE XDG-basedir rule shared by [`config_dir`]/[`data_dir`]/[`state_dir`]:
/// `$<var>/mcpmesh` when the var is set, non-empty, and absolute; otherwise
/// `$HOME/<segments…>/mcpmesh`. A missing/empty `HOME` is a typed error — the same
/// posture as [`runtime_dir`] (never a panic).
fn xdg_dir(var: &str, home_segments: &[&str]) -> std::io::Result<PathBuf> {
    let xdg = std::env::var(var).ok();
    let home = std::env::var("HOME").ok();
    xdg_dir_from(var, xdg.as_deref(), home.as_deref(), home_segments)
}

/// Pure core of the §13 rule (the same env-free split as [`runtime_dir_from`], so it is
/// unit-testable without mutating process env). `xdg` is the raw `$<var>` value if set;
/// `home` is the raw `$HOME` value if set.
fn xdg_dir_from(
    var: &str,
    xdg: Option<&str>,
    home: Option<&str>,
    home_segments: &[&str],
) -> std::io::Result<PathBuf> {
    if let Some(x) = xdg
        && !x.is_empty()
        && std::path::Path::new(x).is_absolute()
    {
        return Ok(PathBuf::from(x).join("mcpmesh"));
    }
    match home {
        Some(h) if !h.is_empty() => {
            let mut dir = PathBuf::from(h);
            for seg in home_segments {
                dir.push(seg);
            }
            dir.push("mcpmesh");
            Ok(dir)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("HOME is not set; set HOME or {var} to an absolute path"),
        )),
    }
}

/// Per-platform config dir (spec §13): `$XDG_CONFIG_HOME/mcpmesh` when that var is set,
/// non-empty, and absolute; otherwise `$HOME/.config/mcpmesh`.
pub fn config_dir() -> std::io::Result<PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", &[".config"])
}

pub fn default_device_key_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("device.key"))
}

pub fn default_config_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// Per-platform runtime dir for the control socket (spec §13): `$XDG_RUNTIME_DIR/mcpmesh`
/// when that var is set, non-empty, and absolute (Linux); otherwise `$TMPDIR/mcpmesh`, or
/// `std::env::temp_dir()/mcpmesh` when `TMPDIR` is unset (macOS — its per-user `$TMPDIR` is
/// itself private). Returns the path only; the daemon creates it 0700 + verifies
/// ownership before binding (a bind-time concern — see cli `ipc::bind_control_socket`).
pub fn runtime_dir() -> std::io::Result<PathBuf> {
    let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let tmp = std::env::var("TMPDIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    runtime_dir_from(xdg.as_deref(), tmp)
}

/// Pure core of the §13 rule, split out so the env logic is unit-testable without
/// mutating process env (no `temp_env` dev-dep). `xdg` is the raw `$XDG_RUNTIME_DIR`
/// value if the var is set; `tmp` is the already-resolved fallback base. Prefers XDG
/// iff it is non-empty and absolute; always returns the `mcpmesh` subdir.
///
/// Guards absoluteness: a relative base (e.g. `TMPDIR=""` with no XDG, where
/// `std::env::temp_dir()` also yields `""`) would place the control socket in the
/// process CWD — a §13 violation and a double-daemon rendezvous hazard. Such a base is
/// an error, not a silent relative path.
fn runtime_dir_from(xdg: Option<&str>, tmp: PathBuf) -> std::io::Result<PathBuf> {
    if let Some(x) = xdg
        && !x.is_empty()
        && std::path::Path::new(x).is_absolute()
    {
        return Ok(PathBuf::from(x).join("mcpmesh"));
    }
    let dir = tmp.join("mcpmesh");
    if !dir.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not resolve a per-user runtime dir; \
             set XDG_RUNTIME_DIR or TMPDIR to an absolute path",
        ));
    }
    Ok(dir)
}

pub fn default_socket_path() -> std::io::Result<PathBuf> {
    Ok(runtime_dir()?.join("mcpmesh.sock"))
}

/// Per-platform data dir for durable state (spec §13/§15): `$XDG_DATA_HOME/mcpmesh` when that
/// var is set, non-empty, and absolute; otherwise `$HOME/.local/share/mcpmesh`. `state.redb`
/// (the peer allowlist) lives here. Unlike the runtime dir (ephemeral, per-boot), this is
/// durable across reboots.
pub fn data_dir() -> std::io::Result<PathBuf> {
    xdg_dir("XDG_DATA_HOME", &[".local", "share"])
}

/// The peer allowlist store path (`<data_dir>/state.redb`, spec §4.2/§15).
pub fn default_state_db_path() -> std::io::Result<PathBuf> {
    Ok(data_dir()?.join("state.redb"))
}

/// The gated app-blob store directory (`<data_dir>/blobs/`, spec §13 "gated iroh-blobs store").
pub fn default_blobs_dir() -> std::io::Result<PathBuf> {
    Ok(data_dir()?.join("blobs"))
}

/// The persisted blob-scope sidecar (`<data_dir>/blob-scopes.json`, spec §9). One JSON document:
/// `scope_name -> { hashes, grants }`, atomic-write single-writer.
pub fn default_blob_scopes_path() -> std::io::Result<PathBuf> {
    Ok(data_dir()?.join("blob-scopes.json"))
}

/// Per-platform STATE dir for durable, per-node runtime state (spec §13/§15): `$XDG_STATE_HOME/mcpmesh`
/// when that var is set, non-empty, and absolute; otherwise `$HOME/.local/state/mcpmesh`. Distinct
/// from `data_dir()` (`~/.local/share`, XDG_DATA_HOME): the XDG basedir spec places *state* data
/// (logs, history — the audit JSONL here) under `~/.local/state`, separate from portable app data.
/// Mirrors the `data_dir()` derivation exactly, swapping the var and the `.local/state` segment.
pub fn state_dir() -> std::io::Result<PathBuf> {
    xdg_dir("XDG_STATE_HOME", &[".local", "state"])
}

/// The append-only audit-log directory (`<state_dir>/audit/`, spec §11.3/§13). One monthly JSONL
/// file per calendar month (`YYYY-MM.jsonl`) lives here; the writer creates the directory lazily on
/// first append. Local-only — nothing here is ever transmitted (§11.3).
pub fn default_audit_dir() -> std::io::Result<PathBuf> {
    Ok(state_dir()?.join("audit"))
}

/// The installed roster document (`<config_dir>/roster.json`, spec §13/§4.3).
pub fn default_roster_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("roster.json"))
}

/// The per-node freshness sidecar (`<config_dir>/roster.confirmed`, spec §4.3 P13). One epoch-seconds
/// integer: the last instant this node validated the installed roster as current via an authenticated
/// channel (a TLS URL poll ≥ installed, a gossip-delivered roster passing validation, or a manual
/// install). Per-node LIVENESS state, NOT a roster-document field — keeps roster.json a pure
/// re-serialization ([RECONCILE-C]).
pub fn default_roster_confirmed_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("roster.confirmed"))
}

/// The org-root key (`<config_dir>/org-root.key`, spec §4.3 "held by operator"). Present ONLY on
/// the operator's node (minted by `org create`); signs rosters.
pub fn default_org_root_key_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("org-root.key"))
}

/// This person's user key (`<config_dir>/user.key`, spec §12/§4.3). Minted by `join`; binds a
/// person's devices. Present on every enrolled person's device (never moves between machines).
pub fn default_user_key_path() -> std::io::Result<PathBuf> {
    Ok(config_dir()?.join("user.key"))
}

#[cfg(test)]
mod path_tests {
    use super::*;

    // Env-scoping approach (declared delta from the plan's `temp_env` suggestion):
    // rather than mutate process env in tests (which would need the `temp_env` dev-dep
    // plus test serialization), the §13 rule lives in the pure `runtime_dir_from`; we
    // unit-test it directly with explicit inputs. `default_socket_path()` is still
    // exercised against the real env, asserting the shape that holds for any env.

    #[test]
    fn runtime_dir_prefers_xdg_when_set() {
        assert_eq!(
            runtime_dir_from(Some("/run/user/1000"), PathBuf::from("/tmp")).unwrap(),
            PathBuf::from("/run/user/1000/mcpmesh")
        );
    }

    #[test]
    fn runtime_dir_falls_back_to_tmp_when_xdg_absent_empty_or_relative() {
        let tmp = PathBuf::from("/var/folders/xx");
        let want = PathBuf::from("/var/folders/xx/mcpmesh");
        assert_eq!(runtime_dir_from(None, tmp.clone()).unwrap(), want);
        assert_eq!(runtime_dir_from(Some(""), tmp.clone()).unwrap(), want);
        // A relative XDG value is rejected (§13: must be absolute) → tmp fallback.
        assert_eq!(runtime_dir_from(Some("relative/dir"), tmp).unwrap(), want);
    }

    #[test]
    fn empty_tmpdir_without_xdg_errors_not_relative() {
        // TMPDIR="" with no XDG resolves the base to "" → a relative "mcpmesh" dir, which
        // would drop the control socket in the process CWD. The guard must Err (§13),
        // never return a relative path.
        let err = runtime_dir_from(None, PathBuf::from("")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn socket_path_is_under_runtime_dir() {
        // Holds for any ambient env: the socket is <runtime_dir>/mcpmesh.sock, runtime_dir
        // always ends in `mcpmesh`, and the resolved path is absolute (§13).
        let sock = default_socket_path().unwrap();
        assert!(sock.ends_with("mcpmesh/mcpmesh.sock"));
        assert!(sock.is_absolute());
    }

    #[test]
    fn audit_dir_is_state_dir_slash_audit() {
        // Holds for any ambient env: the audit dir is <state_dir>/audit, state_dir always ends
        // in `mcpmesh`, and the resolved path is absolute (spec §13 `~/.local/state/mcpmesh/audit`).
        let audit = default_audit_dir().unwrap();
        assert!(audit.ends_with("mcpmesh/audit"));
        assert!(audit.is_absolute());
        // The audit dir is a child of the state dir (durable, distinct from data_dir()).
        assert_eq!(audit.parent().unwrap(), state_dir().unwrap());
    }

    #[test]
    fn state_dir_prefers_xdg_state_home_when_absolute() {
        // Mirror of the data_dir rule for XDG_STATE_HOME (spec §13). Exercised against the
        // real env like the socket test: state_dir always ends in `mcpmesh` and is absolute.
        let sd = state_dir().unwrap();
        assert!(sd.ends_with("mcpmesh"));
        assert!(sd.is_absolute());
    }

    #[test]
    fn xdg_dir_prefers_the_var_when_absolute_else_home_segments() {
        // The var wins when set + non-empty + absolute (§13).
        assert_eq!(
            xdg_dir_from(
                "XDG_DATA_HOME",
                Some("/xdg/data"),
                Some("/home/u"),
                &[".local", "share"]
            )
            .unwrap(),
            PathBuf::from("/xdg/data/mcpmesh")
        );
        // Absent / empty / relative var → $HOME/<segments>/mcpmesh.
        for bad in [None, Some(""), Some("relative/dir")] {
            assert_eq!(
                xdg_dir_from("XDG_DATA_HOME", bad, Some("/home/u"), &[".local", "share"]).unwrap(),
                PathBuf::from("/home/u/.local/share/mcpmesh")
            );
        }
    }

    #[test]
    fn xdg_dir_without_home_errors_never_panics() {
        // M5: the old code `expect("HOME not set")`-panicked here; the rule now matches
        // runtime_dir's typed-error posture. Empty HOME is as unusable as unset HOME.
        for home in [None, Some("")] {
            let err = xdg_dir_from("XDG_CONFIG_HOME", None, home, &[".config"]).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        }
    }
}
