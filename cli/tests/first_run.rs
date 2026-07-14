use assert_cmd::Command;

/// The local device-identity lifecycle: first use mints the device key, subsequent uses reuse
/// it (a stable identity, never a silent re-mint). M2a exposes this via `mcpmesh internal id` —
/// the no-daemon successor to M0's `status`, which derived the identity straight from the
/// device key. `internal id` prints the machine's full endpoint id in the base32 encoding
/// `internal peer add` parses, derived locally (deterministic from the device key, no daemon),
/// so this stays the lightweight identity test it always was (only `XDG_CONFIG_HOME` needed).
/// (Porcelain `status` — which now drives the control API + auto-starts the daemon — is
/// covered hermetically in `daemon_autostart.rs`.)
#[test]
fn first_run_mints_key_second_run_reuses_it() {
    let dir = tempfile::tempdir().unwrap();

    let out1 = Command::cargo_bin("mcpmesh")
        .unwrap()
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["internal", "id"])
        .assert()
        .success();
    let id1 = String::from_utf8(out1.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert!(!id1.is_empty(), "internal id prints the endpoint id");
    assert!(
        dir.path().join("mcpmesh/device.key").exists(),
        "first run mints the device key"
    );
    // It is the real base32 endpoint id: it round-trips through iroh's `EndpointId` parser
    // (the exact encoding `internal peer add <petname> <id>` accepts on the other machine).
    assert!(
        id1.parse::<iroh::EndpointId>().is_ok(),
        "internal id prints a parseable endpoint id: {id1}"
    );

    let out2 = Command::cargo_bin("mcpmesh")
        .unwrap()
        .env("XDG_CONFIG_HOME", dir.path())
        .args(["internal", "id"])
        .assert()
        .success();
    let id2 = String::from_utf8(out2.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(
        id1, id2,
        "second run reuses the same identity, not a silent re-mint"
    );
}
