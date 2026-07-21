//! `mcpmesh completions` + `mcpmesh internal man`: the two commands that render the
//! clap tree itself. No daemon, no keys, no network — pure stdout/filesystem.

use assert_cmd::Command;

#[test]
fn completions_emit_a_script_naming_the_binary() {
    let out = Command::cargo_bin("mcpmesh")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(
        script.contains("mcpmesh"),
        "bash completions name the binary: {script}"
    );
}

#[test]
fn completions_cover_every_supported_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = Command::cargo_bin("mcpmesh")
            .unwrap()
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(out.status.success(), "{shell} completions succeed");
        assert!(!out.stdout.is_empty(), "{shell} completions are non-empty");
    }
}

#[test]
fn man_pages_generate_for_the_command_tree() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("mcpmesh")
        .unwrap()
        .args(["internal", "man"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    // The root page, a porcelain verb, and a nested subcommand all render.
    assert!(dir.path().join("mcpmesh.1").exists());
    assert!(dir.path().join("mcpmesh-pair.1").exists());
    assert!(dir.path().join("mcpmesh-org-create.1").exists());
}
