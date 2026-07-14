//! `mcpmesh doctor` end-to-end (spec §1.6/§13): the porcelain drives the read-only, local-only health
//! check against a HERMETIC env (every mcpmesh path resolves under a tempdir) — no daemon is started,
//! no network is touched, the real HOME is never read. Mirrors the `first_run.rs` subprocess idiom
//! (assert_cmd + XDG env; no `predicates` dep).
use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;

/// A `mcpmesh` invocation whose every path resolves under `dir` (config/data/state/runtime + HOME).
fn hermetic(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("mcpmesh").unwrap();
    cmd.env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_RUNTIME_DIR", dir.join("run"))
        .env("TMPDIR", dir.join("tmp"));
    cmd
}

#[test]
fn half_config_self_hosting_warns_but_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let cfgdir = tmp.path().join("config").join("mcpmesh");
    std::fs::create_dir_all(&cfgdir).unwrap();
    // relay self-hosted (disabled), discovery default → the §10.3 half-config WARN. Pairing mode (no
    // org root), so no roster findings muddy the result.
    std::fs::write(
        cfgdir.join("config.toml"),
        "[network]\nrelay_mode = \"disabled\"\ndiscovery_mode = \"default\"\n",
    )
    .unwrap();

    let assert = hermetic(tmp.path()).arg("doctor").assert().success(); // warnings do NOT fail
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("self-hosting"),
        "self-hosting finding present: {out}"
    );
    assert!(
        out.contains("daemon not running"),
        "daemon-down WARN present: {out}"
    );
    // Surface-clean: no transport vocabulary leaks into the report.
    for term in ["b64u:", "EndpointId", "ALPN", "mcpmesh/mcp/1", "ticket"] {
        assert!(!out.contains(term), "doctor leaked '{term}': {out}");
    }
}

#[test]
fn world_writable_device_key_is_an_error_exit_1() {
    let tmp = tempfile::tempdir().unwrap();
    let cfgdir = tmp.path().join("config").join("mcpmesh");
    std::fs::create_dir_all(&cfgdir).unwrap();
    // A device.key that doctor STATS (it never mints/loads it) with world-writable perms → ERROR.
    let key = cfgdir.join("device.key");
    std::fs::write(&key, [0u8; 32]).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o666)).unwrap();

    let assert = hermetic(tmp.path())
        .arg("doctor")
        .assert()
        .failure()
        .code(1);
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("device.key") && out.contains("writable"),
        "{out}"
    );
    // Doctor is read-only: it must NOT have chmod'd the key back to 0600.
    let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666, "doctor must not mutate key permissions");
}
