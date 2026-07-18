//! M3a Task 10 acceptance: the `internal roster install` porcelain (spec §4.3 manual convergence
//! path). Hermetic subprocess (relay disabled → no network egress, XDG-scoped tempdir):
//!
//!  - **First install** — `mcpmesh internal roster install <minted-file> --org-root-pk <b64u>`
//!    auto-starts a detached daemon, which reads + FULLY validates the signed roster (rules 1–6),
//!    persists it, hot-swaps the gate, and severs any revoked live sessions (D8, none here). We
//!    assert exit 0 + the surface-clean confirmation line + `roster.json` persisted under the temp
//!    config dir + the pinned `org_root_pk`/`org_id` written to config.
//!
//!  - **Rollback rejected** — a SECOND install with a ROLLED-BACK serial, OMITTING `--org-root-pk`
//!    (proving the pinned pk is reused), exits non-zero and leaves the on-disk roster UNCHANGED.
//!
//! Rosters are minted in-test via `mcpmesh_trust::roster::sign::mint_signed` (the production mint
//! path M3b's `org approve` also uses).
// Unix-only: the test process connects to the daemon's control endpoint at a hardcoded
// filesystem socket path (`connect_control(<tmp>/mcpmesh/mcpmesh.sock)`), the path the
// child computes on unix. On windows the endpoint is a hash-derived named pipe the test
// cannot reconstruct without a forbidden windows twin. Windows coverage for the control
// path lives at the transport layer (local-api transport::windows pipe tests) and the
// client protocol layer (local-api client.rs seam tests); a windows daemon-subprocess
// round-trip is deferred — see the plan's Task 6 "Windows coverage gap" note.
#![cfg(unix)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use ed25519_dalek::SigningKey;
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::{Value, json};

/// A hermetic launch env: the built `mcpmesh` binary + a tempdir runtime/config/data (mirrors
/// `pairing_porcelain.rs::launch_in`). `relay_mode = "disabled"` keeps the auto-started daemon's
/// endpoint localhost-only (no relay egress in CI). Returns (exe, socket, config-dir, env-vars).
fn launch_in(dir: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<(OsString, OsString)>) {
    let runtime = dir.join("runtime");
    let config = dir.join("config");
    let data = dir.join("data");
    let config_mcpmesh = config.join("mcpmesh");
    std::fs::create_dir_all(&config_mcpmesh).unwrap();
    std::fs::write(
        config_mcpmesh.join("config.toml"),
        "[network]\nrelay_mode = \"disabled\"\n",
    )
    .unwrap();
    let socket = runtime.join("mcpmesh").join("mcpmesh.sock");
    let env = vec![
        (OsString::from("XDG_RUNTIME_DIR"), runtime.into_os_string()),
        (OsString::from("XDG_CONFIG_HOME"), config.into_os_string()),
        (OsString::from("XDG_DATA_HOME"), data.into_os_string()),
    ];
    (cargo_bin("mcpmesh"), socket, config_mcpmesh, env)
}

/// Run a porcelain subcommand as a subprocess with the hermetic env (the auto-started daemon
/// inherits it). Returns the captured output.
fn run_cmd(exe: &Path, env: &[(OsString, OsString)], args: &[&str]) -> std::process::Output {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run mcpmesh subcommand")
}

/// A valid, currently-live roster body: org "acme", one user "alice" with one device, a validity
/// window that spans any real wall-clock now (issued 2020, expires 2999), nothing revoked. Signed
/// by `root`. The endpoint bytes are immaterial here (no live sessions to sever).
fn signed_roster(root: &SigningKey, serial: u64) -> Roster {
    mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2020-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into()],
            users: vec![RosterUser {
                user_id: "alice".into(),
                display_name: "Alice".into(),
                user_pk: encode_b64u(&[1u8; 32]),
                groups: vec!["team-eng".into()],
                devices: vec![RosterDevice {
                    endpoint_id: encode_b64u(&[2u8; 32]),
                    label: "laptop".into(),
                    role: "primary".into(),
                }],
            }],
            revoked_endpoints: vec![],
            sig: String::new(),
        },
    )
}

fn write_roster(dir: &Path, name: &str, roster: &Roster) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(roster).unwrap()).unwrap();
    path
}

/// The persisted roster's serial (via the on-disk `roster.json`), or `None` when none is installed.
fn persisted_serial(config_dir: &Path) -> Option<u64> {
    let bytes = std::fs::read(config_dir.join("roster.json")).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("serial").and_then(Value::as_u64)
}

async fn shutdown_daemon(socket: &Path) {
    if let Ok(mut client) = connect_control(socket).await {
        let _ = client.request_value(&json!({ "method": "shutdown" })).await;
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while connect_control(socket).await.is_ok() {
        assert!(
            Instant::now() < deadline,
            "daemon still accepting connections after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Read the pinned org_root_pk from the temp config dir's `config.toml`.
fn pinned_org_root_pk(config_dir: &Path) -> Option<String> {
    Config::load(&config_dir.join("config.toml"))
        .expect("reload config")
        .identity
        .org_root_pk
}

/// The full manual-install path end-to-end, exercising every pin-flow branch (spec §4.3):
///  1. FIRST install with `--org-root-pk` → succeeds, pins `org_root_pk` + `org_id`, persists.
///  2. SUBSEQUENT install OMITTING `--org-root-pk` → succeeds using the pinned pk (proves the pin).
///  3. A WRONG `--org-root-pk` → validation fails (sig mismatch), the on-disk roster AND the pinned
///     anchor are BOTH untouched (pin-after-validate: a bad install never corrupts the anchor).
///  4. A ROLLED-BACK serial (pinned pk) → rejected, the on-disk roster unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn roster_install_pins_omits_rejects_wrong_pk_and_rejects_rollback() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, socket, config_dir, env) = launch_in(tmp.path());

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());

        // ── (1) First install (serial 42, pinning the org root) ──
        let f42 = write_roster(tmp.path(), "roster-42.json", &signed_roster(&root, 42));
        let out = run_cmd(
            &exe,
            &env,
            &[
                "internal",
                "roster",
                "install",
                f42.to_str().unwrap(),
                "--org-root-pk",
                &org_root_pk,
            ],
        );
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "first `roster install` must exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The surface-clean confirmation (no live sessions → severed 0).
        assert_eq!(
            stdout.trim_end(),
            "Installed roster for org 'acme' (serial 42). Severed 0 live sessions.",
            "unexpected confirmation:\n{stdout}"
        );
        // `roster.json` persisted at serial 42; the pinned org_root_pk + org_id in config.
        assert_eq!(persisted_serial(&config_dir), Some(42));
        assert_eq!(
            pinned_org_root_pk(&config_dir).as_deref(),
            Some(org_root_pk.as_str()),
            "org_root_pk must be pinned in config"
        );
        assert_eq!(
            Config::load(&config_dir.join("config.toml"))
                .unwrap()
                .identity
                .org_id
                .as_deref(),
            Some("acme"),
            "org_id must be pinned in config"
        );

        // ── (2) Subsequent install (serial 43), OMITTING --org-root-pk → uses the pinned pk ──
        let f43 = write_roster(tmp.path(), "roster-43.json", &signed_roster(&root, 43));
        let out = run_cmd(
            &exe,
            &env,
            &["internal", "roster", "install", f43.to_str().unwrap()],
        );
        assert!(
            out.status.success(),
            "an omitted --org-root-pk must reuse the pinned pk and succeed; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim_end(),
            "Installed roster for org 'acme' (serial 43). Severed 0 live sessions."
        );
        assert_eq!(persisted_serial(&config_dir), Some(43));

        // ── (3) A WRONG --org-root-pk → validation fails; roster + pinned anchor BOTH untouched ──
        let wrong_pk = encode_b64u(
            &SigningKey::from_bytes(&[8u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let f44 = write_roster(tmp.path(), "roster-44.json", &signed_roster(&root, 44));
        let out = run_cmd(
            &exe,
            &env,
            &[
                "internal",
                "roster",
                "install",
                f44.to_str().unwrap(),
                "--org-root-pk",
                &wrong_pk,
            ],
        );
        assert!(
            !out.status.success(),
            "a wrong --org-root-pk must exit non-zero; stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            persisted_serial(&config_dir),
            Some(43),
            "a failed (wrong-pk) install must not touch the on-disk roster"
        );
        assert_eq!(
            pinned_org_root_pk(&config_dir).as_deref(),
            Some(org_root_pk.as_str()),
            "pin-after-validate: a failed install must NOT re-pin the wrong anchor"
        );

        // ── (4) A ROLLED-BACK serial (41), OMITTING --org-root-pk → rejected, roster unchanged ──
        let f41 = write_roster(tmp.path(), "roster-41.json", &signed_roster(&root, 41));
        let out = run_cmd(
            &exe,
            &env,
            &["internal", "roster", "install", f41.to_str().unwrap()],
        );
        assert!(
            !out.status.success(),
            "a rolled-back serial must exit non-zero; stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert_eq!(
            persisted_serial(&config_dir),
            Some(43),
            "the on-disk roster must be untouched by the rejected rollback"
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("roster install test timed out");
}

/// A roster assigning THIS device's endpoint to `user_id`, signed by `root` (org "acme", serial 7,
/// validity 2020..2999, nothing revoked). `device_endpoint` MUST be the daemon's actual endpoint id
/// (the ed25519 pubkey of its device key) so the reconcile resolves our own device in the view.
fn roster_owning_our_device(
    root: &SigningKey,
    user_id: &str,
    device_endpoint: &[u8; 32],
) -> Roster {
    mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial: 7,
            issued_at: "2020-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into()],
            users: vec![RosterUser {
                user_id: user_id.into(),
                display_name: "Alice".into(),
                user_pk: encode_b64u(&[1u8; 32]),
                groups: vec!["team-eng".into()],
                devices: vec![RosterDevice {
                    endpoint_id: encode_b64u(device_endpoint),
                    label: "laptop".into(),
                    role: "primary".into(),
                }],
            }],
            revoked_endpoints: vec![],
            sig: String::new(),
        },
    )
}

/// [RECONCILE-D] (M3c T12, spec §4.6). The roster is AUTHORITATIVE for a device's `user_id`: config's
/// `[identity].user_id` is only a best-effort join-time PROPOSAL. Here config proposes
/// `"alice-proposed"` while the installed roster assigns THIS device's endpoint to
/// `"alice-authoritative"`. After a manual `roster install`, the shared post-install reconcile
/// rewrites config to the roster's authoritative value (never the reverse), and — because
/// `roster_status.state` is computed LIVE from the installed view (M3a) — status flips
/// pending → approved. A no-op stub leaves config at `"alice-proposed"` (RED).
#[tokio::test(flavor = "multi_thread")]
async fn roster_install_reconciles_proposed_user_id_to_the_authoritative_value() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let tmp = tempfile::tempdir().unwrap();
        let (exe, socket, config_dir, env) = launch_in(tmp.path());

        // Seed a KNOWN device key so THIS daemon's endpoint id is predictable — the roster device
        // record must name it for the reconcile to resolve our own endpoint (the enroll_e2e "artifact
        // bridge": endpoint id == the ed25519 pubkey of the device key). Write the 32 raw secret bytes.
        let device_secret = [7u8; 32];
        let device_key_path = config_dir.join("device.key");
        std::fs::write(&device_key_path, device_secret).unwrap();
        let device_endpoint = SigningKey::from_bytes(&device_secret)
            .verifying_key()
            .to_bytes();

        // Config PROPOSES `user_id = "alice-proposed"` and points at the seeded device key. No org
        // root pinned yet (the join-time, pre-approval state) — the install below pins it.
        let config_path = config_dir.join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[network]\nrelay_mode = \"disabled\"\n[identity]\nuser_id = \"alice-proposed\"\ndevice_key = \"{}\"\n",
                device_key_path.display()
            ),
        )
        .unwrap();

        let root = SigningKey::from_bytes(&[9u8; 32]);
        let org_root_pk = encode_b64u(&root.verifying_key().to_bytes());
        let roster = roster_owning_our_device(&root, "alice-authoritative", &device_endpoint);
        let file = write_roster(tmp.path(), "roster-7.json", &roster);

        // Pre-flight: config holds the join-time PROPOSAL.
        assert_eq!(
            Config::load(&config_path).unwrap().identity.user_id.as_deref(),
            Some("alice-proposed"),
            "config must start with the proposed user_id"
        );

        let out = run_cmd(
            &exe,
            &env,
            &[
                "internal",
                "roster",
                "install",
                file.to_str().unwrap(),
                "--org-root-pk",
                &org_root_pk,
            ],
        );
        assert!(
            out.status.success(),
            "roster install must exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // [RECONCILE-D]: config `user_id` is now the roster's AUTHORITATIVE value (the roster won).
        assert_eq!(
            Config::load(&config_path).unwrap().identity.user_id.as_deref(),
            Some("alice-authoritative"),
            "config user_id must be reconciled to the roster's authoritative value"
        );

        // pending → approved: the live view now resolves this device, so `roster_status` reports
        // "approved" (computed live from `mesh.roster.view()`, M3a).
        let mut client = connect_control(&socket).await.expect("connect control");
        let status = client
            .request_value(&json!({ "method": "status", "params": {} }))
            .await
            .expect("status over the control API");
        assert_eq!(
            status["roster"]["state"], "approved",
            "roster_status must flip pending→approved once the view holds this device: {status}"
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("reconcile test timed out");
}
