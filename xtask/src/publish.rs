//! `cargo xtask publish` — crates.io publishing for the five mcpmesh crates, in dependency
//! order, resumable. Ported from the monorepo's mirror-era tooling; this repo is the source
//! of truth now, so publishing runs straight from a clean `main` checkout.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// crates.io publish order — a topological order of the internal dep graph
/// (codec ← local-api ← {net, trust} ← cli). Guarded by `publish_order_is_topological`.
pub const PUBLISH_ORDER: [&str; 5] = ["codec", "local-api", "trust", "net", "cli"];

/// crates.io sparse-index sharding (index.crates.io): `1/{name}`, `2/{name}`, `3/{c}/{name}`,
/// else `{name[0..2]}/{name[2..4]}/{name}`. Crate names are ASCII, so byte slicing is safe.
pub fn index_path(name: &str) -> String {
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[0..1]),
        _ => format!("{}/{}/{name}", &name[0..2], &name[2..4]),
    }
}

/// The `[workspace.package] version` line, by section-aware line scan — the workspace
/// manifest is repo-controlled, so a full TOML parser (and its dep tree) buys nothing.
pub fn workspace_version(manifest: &str) -> Result<String> {
    let mut in_section = false;
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_section = t == "[workspace.package]";
            continue;
        }
        if in_section && let Some(rest) = t.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let v = rest.trim().trim_start_matches('"');
                let v = &v[..v.find('"').context("unterminated version string")?];
                return Ok(v.to_string());
            }
        }
    }
    bail!("[workspace.package] version not found");
}

fn run(cmd: &str, args: &[&str], cwd: &Path) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("spawn {cmd}"))?;
    if !out.status.success() {
        bail!(
            "`{cmd} {}` in {} failed:\n{}{}",
            args.join(" "),
            cwd.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Publish the five crates in PUBLISH_ORDER from a clean `main` checkout. Resumable: crates
/// whose current version already sits in the sparse index are skipped, so a run that died
/// mid-sequence just re-runs. cargo (>=1.66) waits for each crate to land in the index
/// before the next dependent publish proceeds.
pub fn publish(repo_root: &Path, dry_run: bool) -> Result<()> {
    let dirty = run("git", &["status", "--porcelain"], repo_root)?;
    if !dirty.is_empty() {
        bail!("tree dirty — publish from a clean tree:\n{dirty}");
    }
    let branch = run("git", &["symbolic-ref", "--short", "HEAD"], repo_root)?;
    if branch != "main" {
        bail!("on branch {branch}, not main");
    }
    if !dry_run {
        // Credentials preflight: CARGO_HOME-aware, and either the modern credentials.toml or
        // the legacy `credentials` counts; CARGO_REGISTRY_TOKEN bypasses the file entirely.
        let cargo_home = std::env::var("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME")
                    .map(|h| Path::new(&h).join(".cargo"))
                    .context("neither CARGO_HOME nor HOME set")
            })?;
        let has_creds =
            cargo_home.join("credentials.toml").exists() || cargo_home.join("credentials").exists();
        if !has_creds && std::env::var("CARGO_REGISTRY_TOKEN").is_err() {
            bail!("no crates.io credentials (`cargo login` first, or set CARGO_REGISTRY_TOKEN)");
        }
    }
    let manifest = std::fs::read_to_string(repo_root.join("Cargo.toml"))
        .with_context(|| format!("read {}/Cargo.toml", repo_root.display()))?;
    let version = workspace_version(&manifest)?;
    for dir in PUBLISH_ORDER {
        let name = if dir == "cli" {
            "mcpmesh".to_string()
        } else {
            format!("mcpmesh-{dir}")
        };
        // Resumability: if this version is already in the sparse index, skip. A curl failure
        // (404 = never published, or network trouble) means UNKNOWN, not published — proceed.
        let url = format!("https://index.crates.io/{}", index_path(&name));
        if let Ok(body) = run("curl", &["-fsS", &url], repo_root) {
            let needle = format!("\"vers\":\"{version}\"");
            if body.lines().any(|l| l.contains(&needle)) {
                println!("{name} {version} already published — skipping");
                continue;
            }
        }
        if dry_run {
            println!(
                "would publish {name} {version} from {}",
                repo_root.join(dir).display()
            );
            continue;
        }
        println!("publishing {name} {version}…");
        run("cargo", &["publish", "--locked"], &repo_root.join(dir))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn index_path_shards_like_the_crates_io_sparse_index() {
        assert_eq!(index_path("mcpmesh"), "mc/pm/mcpmesh");
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
    }

    #[test]
    fn workspace_version_reads_the_workspace_package_section_only() {
        let manifest = r#"
[workspace]
members = ["codec"]

[workspace.package]
version = "9.8.7"          # comment survives
edition = "2024"

[workspace.dependencies]
serde = { version = "1" }
"#;
        assert_eq!(workspace_version(manifest).unwrap(), "9.8.7");
    }

    #[test]
    fn workspace_version_reads_this_repos_real_manifest() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let v = workspace_version(&text).unwrap();
        assert!(
            v.split('.').count() == 3 && v.chars().next().unwrap().is_ascii_digit(),
            "not a semver triple: {v}"
        );
    }

    /// PUBLISH_ORDER must be a topological order of the workspace's internal dep graph —
    /// parsed from the REAL manifests so a new internal edge can't silently invalidate it.
    #[test]
    fn publish_order_is_topological() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        fn dir_of(name: &str) -> &str {
            if name == "mcpmesh" {
                "cli"
            } else {
                name.strip_prefix("mcpmesh-").unwrap()
            }
        }
        for (i, dir) in PUBLISH_ORDER.iter().enumerate() {
            let text = std::fs::read_to_string(root.join(dir).join("Cargo.toml")).unwrap();
            // Line scan: internal deps appear as `mcpmesh-<x>.workspace = true` or
            // `mcpmesh-<x> = { workspace = true, ... }` at line start.
            for line in text.lines() {
                let t = line.trim_start();
                let Some(dep) = t
                    .strip_prefix("mcpmesh-")
                    .and_then(|r| r.split(['.', ' ', '=']).next())
                    .map(|suffix| format!("mcpmesh-{suffix}"))
                else {
                    continue;
                };
                let pos = PUBLISH_ORDER
                    .iter()
                    .position(|d| d == &dir_of(&dep))
                    .unwrap_or_else(|| panic!("unknown internal dep {dep} in {dir}"));
                assert!(pos < i, "{dir} depends on {dep}, which publishes later");
            }
        }
        assert_eq!(PUBLISH_ORDER.len(), 5);
    }
}
