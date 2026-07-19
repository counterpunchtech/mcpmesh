//! Subprocess porcelain: `org create` mints an org root + installs a signed empty roster, and prints
//! the org invite code + root fingerprint (spec §4.4 step 1). Hermetic (relay disabled, XDG-scoped
//! tempdir). Mirrors `roster_install.rs`'s `launch_in`/`run_cmd`/`shutdown_daemon` harness verbatim.
// Unix-only: the test process connects to the daemon's control endpoint at a hardcoded
// filesystem socket path (`connect_control(<tmp>/mcpmesh/mcpmesh.sock)`), the path the
// child computes on unix. On windows the endpoint is a hash-derived named pipe the test
// cannot reconstruct without a forbidden windows twin. Windows coverage for the control
// path lives at the transport layer (local-api transport::windows pipe tests) and the
// client protocol layer (local-api client.rs seam tests); a windows daemon-subprocess
// round-trip is deferred — see the plan's Task 6 "Windows coverage gap" note. (The
// per-block `#[cfg(unix)]` key-mode asserts below are now redundant under this file gate
// but kept for clarity.)
#![cfg(unix)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use ed25519_dalek::SigningKey;
use mcpmesh::client::connect_control;
use mcpmesh::config::Config;
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::{Roster, encode_b64u, mutate};
use serde_json::json;

/// A hermetic launch env: the built `mcpmesh` binary + a tempdir runtime/config/data (mirrors
/// `roster_install.rs::launch_in`). `relay_mode = "disabled"` keeps the auto-started daemon's
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

/// The `roster.staging.*` temps `install_signed_roster` leaves in `config_dir` — must be empty after
/// EVERY install (success or failure): the RAII `TempFile` guard removes the stage on any exit.
fn staged_temps(config: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(config)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with("roster.staging."))
                .unwrap_or(false)
        })
        .collect()
}

/// Wall-clock now as epoch seconds (i64) — the validity-window anchor for a hand-minted roster.
fn now_epoch_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Write a roster JSON to `dir/name`, returning the path (for `internal roster install`).
fn write_roster(dir: &Path, name: &str, roster: &Roster) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec(roster).unwrap()).unwrap();
    path
}

/// The `word-word-word-word` fingerprint token on the (first) line CONTAINING `label`. Labelled so
/// it distinguishes the org-root-fingerprint line from the join-code-fingerprint line. Splits on
/// whitespace and returns the first token containing '-' — so it works whether the fingerprint ends
/// the line or sits mid-line. Empty string when no such line/token exists.
fn fingerprint_after(label: &str, out: &str) -> String {
    out.lines()
        .find(|l| l.contains(label))
        .and_then(|l| l.split_whitespace().find(|w| w.contains('-')))
        .unwrap_or("")
        .to_string()
}

/// The opaque `mcpmesh-org:…` invite token from `org create` stdout (a single whitespace-free word).
fn org_invite_from(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.split_whitespace().find(|w| w.starts_with("mcpmesh-org:")))
        .expect("an org invite code")
        .to_string()
}

/// The opaque `mcpmesh-join:…` code token from `join` stdout (a single whitespace-free word).
fn join_code_from(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            l.split_whitespace()
                .find(|w| w.starts_with("mcpmesh-join:"))
        })
        .expect("a join code")
        .to_string()
}

/// The opaque `mcpmesh-device:…` code token from `devices code` stdout (a single whitespace-free word).
fn device_code_from(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| {
            l.split_whitespace()
                .find(|w| w.starts_with("mcpmesh-device:"))
        })
        .expect("a device code")
        .to_string()
}

/// Forge a join code: decode it, flip one byte of the b64u `binding_sig`, re-encode. The result is a
/// STRUCTURALLY valid `mcpmesh-join:` code whose device→user-key binding no longer verifies — so
/// `org approve`'s `verify_device_binding` must refuse it BEFORE any roster mutation.
fn tamper_join_binding(code: &str) -> String {
    let mut jc = mcpmesh::roster::enroll::JoinCode::decode(code).expect("decode join code");
    let mut sig = mcpmesh_trust::roster::decode_b64u(&jc.binding_sig).expect("decode binding sig");
    sig[0] ^= 0x01; // flip a bit → the signature no longer verifies against user_pk
    jc.binding_sig = encode_b64u(&sig);
    jc.encode()
}

/// `org create` mints the org root key (0600), signs an EMPTY roster (serial 1), installs it through
/// the daemon (which pins the org root + org_id), and prints the org invite code + root fingerprint.
/// Surface-clean (§1.5): only the opaque code + fingerprint words print — NO raw key / path leak. A
/// SECOND `org create` on the same node REFUSES (one org per node).
#[tokio::test(flavor = "multi_thread")]
async fn org_create_mints_root_signs_empty_roster_and_prints_the_invite() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir = tempfile::tempdir().unwrap();
        let (exe, socket, config, env) = launch_in(dir.path());

        let out = run_cmd(&exe, &env, &["org", "create", "acme", "--expires", "30d"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "org create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        // The org invite code + fingerprint print; NO raw key / EndpointId / path leaks (§1.5).
        assert!(
            stdout.contains("mcpmesh-org:"),
            "prints the org invite code: {stdout}"
        );
        assert!(
            stdout.contains("fingerprint"),
            "prints the root fingerprint: {stdout}"
        );
        assert!(
            !stdout.contains("b64u:") && !stdout.contains("org-root.key"),
            "surface leak: {stdout}"
        );
        // The confirmation carries roster vocabulary (org_id + serial), never a key/path.
        assert!(
            stdout.contains("Created org 'acme' (roster serial 1)."),
            "prints the confirmation: {stdout}"
        );

        // The org-root key exists 0600; the roster is installed (serial 1, org_id acme, no users).
        let key = config.join("org-root.key");
        assert!(key.exists(), "org root key minted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let roster: Roster =
            serde_json::from_slice(&std::fs::read(config.join("roster.json")).unwrap()).unwrap();
        assert_eq!(roster.serial, 1);
        assert_eq!(roster.org_id, "acme");
        assert!(roster.users.is_empty());

        // The daemon pinned the org root anchor + org_id in config (M3a's pin-after-validate).
        let cfg = Config::load(&config.join("config.toml")).expect("reload config");
        assert_eq!(cfg.identity.org_id.as_deref(), Some("acme"));
        assert!(
            cfg.identity
                .org_root_pk
                .as_deref()
                .is_some_and(|pk| pk.starts_with("b64u:")),
            "org_root_pk pinned in config"
        );

        // The staged roster temp is cleaned up (the RAII guard removes it on the success path).
        assert!(
            staged_temps(&config).is_empty(),
            "staged roster temp must be cleaned up on success, found {:?}",
            staged_temps(&config)
        );

        // Re-running `org create` refuses (one org per node — org-root.key already exists).
        let again = run_cmd(&exe, &env, &["org", "create", "acme2"]);
        assert!(
            !again.status.success(),
            "second org create must refuse: {}",
            String::from_utf8_lossy(&again.stdout)
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("org create test timed out");
}

/// The install-ERROR leak path: when the daemon REJECTS the roster `install_signed_roster` staged,
/// the RAII `TempFile` guard must still remove the `roster.staging.*` file (no leak on failure).
/// We pre-install a serial-5 roster (pinning a DIFFERENT org root), then `org create` — whose fresh
/// empty roster is serial 1 — is rejected as a rollback (`StaleSerial`). The command exits non-zero
/// and leaves NO staged temp behind.
#[tokio::test(flavor = "multi_thread")]
async fn org_create_cleans_up_the_staged_temp_when_the_install_is_rejected() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let dir = tempfile::tempdir().unwrap();
        let (exe, socket, config, env) = launch_in(dir.path());

        // Pre-install a valid EMPTY roster at serial 5, pinning root pk_A (its own key). This uses
        // `internal roster install` (the run_roster_install path — it does NOT stage a temp), so the
        // only `roster.staging.*` that could appear later is `org create`'s.
        let root_a = SigningKey::from_bytes(&[9u8; 32]);
        let pk_a = encode_b64u(&root_a.verifying_key().to_bytes());
        let now = now_epoch_i64();
        let roster5 = mint_signed(
            &root_a,
            mutate::empty_roster("acme", 5, now - 3600, now + 86_400),
        );
        let f5 = write_roster(dir.path(), "roster-5.json", &roster5);
        let seed = run_cmd(
            &exe,
            &env,
            &[
                "internal",
                "roster",
                "install",
                f5.to_str().unwrap(),
                "--org-root-pk",
                &pk_a,
            ],
        );
        assert!(
            seed.status.success(),
            "seed install (serial 5) must succeed: {}",
            String::from_utf8_lossy(&seed.stderr)
        );

        // `org create` mints a NEW org root (org-root.key is absent → one-org check passes), signs an
        // empty roster at serial 1, and installs it → the daemon rejects it as a rollback (1 ≤ 5).
        let out = run_cmd(&exe, &env, &["org", "create", "acme"]);
        assert!(
            !out.status.success(),
            "org create must fail when its serial-1 install is a rollback; stdout: {}",
            String::from_utf8_lossy(&out.stdout)
        );
        // The failure is the daemon's install REJECTION (a staged temp was written + handed to the
        // daemon, which rejected the serial-1 rollback) — not some earlier bail, so the cleanup path
        // is genuinely exercised. "roster failed validation" is the install-rejection sentence
        // (install_from_file); the wire's "roster_install failed:" framing is stripped by the
        // porcelain error renderer (issue #10), so it must NOT be asserted here.
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("roster failed validation"),
            "expected a daemon install rejection, got: {stderr}"
        );

        // The RAII guard removed the staged roster even though the install returned an error.
        assert!(
            staged_temps(&config).is_empty(),
            "staged roster temp must be cleaned up on the install-error path, found {:?}",
            staged_temps(&config)
        );

        shutdown_daemon(&socket).await;
    })
    .await
    .expect("org create rejection test timed out");
}

/// `join <org-invite>` mints the user key (0600, local), signs this device's binding, pins the org
/// root through the daemon, and emits the join code + the DUAL enrollment ceremony (spec §4.4 step 2).
/// Hermetic two-node flow: an operator node `org create`s (capturing the invite + its org-root
/// fingerprint), a separate joiner node `join`s. Asserts the joiner's org-root fingerprint EQUALS the
/// operator's (same pk → same words: the person→org-root ceremony works), the join-code fingerprint
/// prints (person→user_pk, the MITM closer), the user key is minted 0600, config pins
/// org_id/org_root_pk/user_id/user_key, `status` shows the pending fingerprint, and NO raw key leaks.
#[tokio::test(flavor = "multi_thread")]
async fn join_mints_user_key_pins_org_root_and_emits_a_join_code() {
    tokio::time::timeout(Duration::from_secs(45), async {
        // Operator side: create the org, capture the invite + its org-root fingerprint.
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, _opcfg, openv) = launch_in(opdir.path());
        let create = run_cmd(&opexe, &openv, &["org", "create", "acme"]);
        assert!(
            create.status.success(),
            "org create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );
        let create_out = String::from_utf8_lossy(&create.stdout);
        let invite = create_out
            .lines()
            .find_map(|l| l.split_whitespace().find(|w| w.starts_with("mcpmesh-org:")))
            .expect("an org invite code")
            .to_string();
        let op_fp = fingerprint_after("Org root fingerprint:", &create_out);
        assert!(!op_fp.is_empty(), "operator prints an org-root fingerprint");

        // Joiner side (separate XDG): join with the invite.
        let jdir = tempfile::tempdir().unwrap();
        let (jexe, jsock, jcfg, jenv) = launch_in(jdir.path());
        let join = run_cmd(&jexe, &jenv, &["join", &invite, "--name", "Alice Nguyen"]);
        let jout = String::from_utf8_lossy(&join.stdout);
        assert!(
            join.status.success(),
            "join failed: {}",
            String::from_utf8_lossy(&join.stderr)
        );
        assert!(jout.contains("mcpmesh-join:"), "prints a join code: {jout}");
        // Ceremony 1 (person→org-root): the joiner's org-root fingerprint MUST equal the operator's.
        assert_eq!(
            fingerprint_after("Org root fingerprint:", &jout),
            op_fp,
            "org-root fingerprint must match the operator's"
        );
        // Ceremony 2 (person→user_pk, the MITM closer): the join code carries a read-back fingerprint.
        assert!(
            jout.contains("Join code fingerprint:"),
            "prints the join-code fingerprint: {jout}"
        );
        assert!(!fingerprint_after("Join code fingerprint:", &jout).is_empty());
        assert!(
            jout.contains("out-of-band"),
            "prints the ceremony instruction"
        );

        // The user key exists 0600; config pinned org_id/org_root_pk/user_id/user_key.
        let ukey = jcfg.join("user.key");
        assert!(ukey.exists(), "user key minted");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&ukey).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let cfg_txt = std::fs::read_to_string(jcfg.join("config.toml")).unwrap();
        assert!(cfg_txt.contains("org_id = \"acme\""));
        assert!(cfg_txt.contains("org_root_pk"));
        assert!(cfg_txt.contains("user_id = \"alice-nguyen\""));
        assert!(cfg_txt.contains("user_key"));

        // No raw key / EndpointId / key-path leak in the join output (§1.5).
        assert!(
            !jout.contains("b64u:") && !jout.contains("user.key"),
            "surface leak: {jout}"
        );

        // `status` now shows the pending fingerprint over the control API (T7's `pending` state).
        let status = run_cmd(&jexe, &jenv, &["status"]);
        assert!(
            String::from_utf8_lossy(&status.stdout).contains(&op_fp),
            "status shows the pinned org-root fingerprint"
        );

        shutdown_daemon(&opsock).await;
        shutdown_daemon(&jsock).await;
    })
    .await
    .expect("join test timed out");
}

/// `org create --roster-url <U>` + `join` (spec §4.3 M3c distribution wiring). The operator's create
/// must (a) CARRY the URL in the printed `mcpmesh-org:` invite (M3b left it None) so a joiner bootstraps
/// its first roster without gossip (D5), AND (b) pin it in the operator's config `[roster].url` (the
/// operator keeps the hosted document current). A joiner's `join` of that invite must STORE the URL in
/// its OWN config `[roster].url` — closing the D5 first-roster bootstrap. Hermetic (relay disabled;
/// the running daemons are pure-pairing at startup, so the fake URL is never actually polled).
#[tokio::test(flavor = "multi_thread")]
async fn org_create_roster_url_lands_in_the_invite_and_config_and_join_stores_it() {
    tokio::time::timeout(Duration::from_secs(45), async {
        const URL: &str = "https://intranet.acme.com/roster.json";

        // Operator: create the org WITH a roster URL.
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, opcfg, openv) = launch_in(opdir.path());
        let create = run_cmd(
            &opexe,
            &openv,
            &["org", "create", "acme", "--roster-url", URL],
        );
        assert!(
            create.status.success(),
            "org create --roster-url failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );

        // (a) The printed invite CARRIES the URL (M3b left it None).
        let invite = org_invite_from(&create);
        let decoded =
            mcpmesh::roster::enroll::OrgInviteCode::decode(&invite).expect("decode org invite");
        assert_eq!(
            decoded.roster_url.as_deref(),
            Some(URL),
            "the invite must carry the roster URL"
        );

        // (b) The operator's config pinned `[roster].url` (through the daemon — single-writer).
        let opcfg_url = Config::load(&opcfg.join("config.toml"))
            .expect("reload operator config")
            .roster
            .url;
        assert_eq!(
            opcfg_url.as_deref(),
            Some(URL),
            "operator config [roster].url must be pinned"
        );

        // Joiner (separate XDG): `join` must STORE the URL in ITS config (D5 first-roster bootstrap).
        let jdir = tempfile::tempdir().unwrap();
        let (jexe, jsock, jcfg, jenv) = launch_in(jdir.path());
        let join = run_cmd(&jexe, &jenv, &["join", &invite, "--name", "Alice"]);
        assert!(
            join.status.success(),
            "join failed: {}",
            String::from_utf8_lossy(&join.stderr)
        );
        let jcfg_url = Config::load(&jcfg.join("config.toml"))
            .expect("reload joiner config")
            .roster
            .url;
        assert_eq!(
            jcfg_url.as_deref(),
            Some(URL),
            "joiner config [roster].url must be stored from the invite (D5)"
        );
        // The joiner also pinned the org root (existing join behavior) — the URL write is additive.
        let jcfg_txt = std::fs::read_to_string(jcfg.join("config.toml")).unwrap();
        assert!(
            jcfg_txt.contains("org_id = \"acme\""),
            "org root still pinned"
        );

        shutdown_daemon(&opsock).await;
        shutdown_daemon(&jsock).await;
    })
    .await
    .expect("org create roster-url test timed out");
}

/// `org approve <join-code> --groups …` (spec §4.4 step 3): verify the join code's device binding,
/// upsert the member+device into the operator's installed roster with the named groups, bump serial,
/// re-sign with the org root, install. Hermetic two-node flow: operator `org create`s, joiner `join`s
/// (capturing the code + its fingerprint), operator `org approve`s. Asserts: the pre-install
/// confirmation surfaces the SAME join-code fingerprint the joiner read back ([Important] A, the
/// substitution-MITM closer); the roster gains alice/team-eng with the joiner's device at serial 2,
/// re-signed (verifies against the org root), the group declared top-level; a FORGED binding is
/// refused BEFORE any mutation (verify-before-mutate — the roster is untouched).
#[tokio::test(flavor = "multi_thread")]
async fn approve_verifies_the_binding_and_adds_the_member_to_the_roster() {
    tokio::time::timeout(Duration::from_secs(45), async {
        // Operator: create the org, capture the invite + the pinned org-root pk (to verify re-sign).
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, opcfg, openv) = launch_in(opdir.path());
        let create = run_cmd(&opexe, &openv, &["org", "create", "acme"]);
        assert!(
            create.status.success(),
            "org create failed: {}",
            String::from_utf8_lossy(&create.stderr)
        );
        let invite = org_invite_from(&create);
        let org_root_pk = {
            let ic =
                mcpmesh::roster::enroll::OrgInviteCode::decode(&invite).expect("decode invite");
            let bytes = mcpmesh_trust::roster::decode_endpoint_id(&ic.org_root_pk)
                .expect("decode org_root_pk");
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).expect("org root pk is a valid key")
        };

        // Joiner (separate XDG): join, capturing the join code + its read-back fingerprint.
        let jdir = tempfile::tempdir().unwrap();
        let (jexe, jsock, _jcfg, jenv) = launch_in(jdir.path());
        let join_out = run_cmd(
            &jexe,
            &jenv,
            &["join", &invite, "--name", "Alice", "--user-id", "alice"],
        );
        assert!(
            join_out.status.success(),
            "join failed: {}",
            String::from_utf8_lossy(&join_out.stderr)
        );
        let join_code = join_code_from(&join_out);
        let joiner_code_fp = fingerprint_after(
            "Join code fingerprint:",
            &String::from_utf8_lossy(&join_out.stdout),
        );
        assert!(
            !joiner_code_fp.is_empty(),
            "joiner prints a join-code fingerprint"
        );
        // The joiner's device endpoint id (verbatim from the join code) — asserted to land in the roster.
        let jc = mcpmesh::roster::enroll::JoinCode::decode(&join_code).expect("decode join code");

        // Operator approves.
        let approve = run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &join_code, "--groups", "team-eng,all"],
        );
        let aout = String::from_utf8_lossy(&approve.stdout);
        assert!(
            approve.status.success(),
            "approve failed: {}",
            String::from_utf8_lossy(&approve.stderr)
        );
        assert!(
            aout.contains("alice") && aout.contains("team-eng") && aout.contains("serial 2"),
            "approve confirmation: {aout}"
        );
        // [Important] A: the operator's pre-install confirmation surfaces the SAME join-code
        // fingerprint the joiner read back — the substitution-MITM closer. (A substituted code, with a
        // different user_pk, would diverge here → operator + joiner read different words → abort.)
        assert!(
            aout.contains("Approving join code"),
            "approve surfaces the join-code fingerprint: {aout}"
        );
        assert_eq!(
            fingerprint_after("Approving join code", &aout),
            joiner_code_fp,
            "operator + joiner must see the SAME join-code fingerprint"
        );

        // The installed roster now has alice/team-eng with the joiner's device, serial 2, sig verifies.
        let roster: Roster =
            serde_json::from_slice(&std::fs::read(opcfg.join("roster.json")).unwrap()).unwrap();
        assert_eq!(roster.serial, 2);
        let alice = roster
            .users
            .iter()
            .find(|u| u.user_id == "alice")
            .expect("alice enrolled");
        assert_eq!(alice.display_name, "Alice");
        assert!(alice.groups.contains(&"team-eng".to_string()));
        assert_eq!(alice.devices.len(), 1);
        // upsert stores the join code's b64u endpoint verbatim → the roster device == the joiner's.
        assert_eq!(alice.devices[0].endpoint_id, jc.device_endpoint_id);
        // The new group is declared at the top level (rule 5b).
        assert!(
            roster.groups.contains(&"team-eng".to_string()),
            "team-eng declared top-level: {:?}",
            roster.groups
        );
        // Re-signed with the org root: the serial-2 roster verifies against the pinned org root.
        mcpmesh_trust::roster::sign::verify(&roster, &org_root_pk)
            .expect("re-signed roster verifies against the org root");

        // A FORGED join code (flip a byte in the binding) is refused BEFORE any mutation.
        let forged = tamper_join_binding(&join_code);
        let bad = run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &forged, "--groups", "team-eng"],
        );
        assert!(!bad.status.success(), "a forged binding must be refused");
        assert!(
            String::from_utf8_lossy(&bad.stderr).contains("device binding"),
            "the refusal names the device-binding check: {}",
            String::from_utf8_lossy(&bad.stderr)
        );
        // verify-before-mutate: the failed approve did NOT touch the installed roster (still serial 2).
        let roster_after: Roster =
            serde_json::from_slice(&std::fs::read(opcfg.join("roster.json")).unwrap()).unwrap();
        assert_eq!(
            roster_after.serial, 2,
            "a forged approve must not bump serial"
        );

        // No staged temp leaks (success + failure both cleaned by the RAII guard).
        assert!(
            staged_temps(&opcfg).is_empty(),
            "staged roster temp leak: {:?}",
            staged_temps(&opcfg)
        );

        shutdown_daemon(&opsock).await;
        shutdown_daemon(&jsock).await;
    })
    .await
    .expect("approve test timed out");
}

/// `org revoke` — the §4.5/§4.6 grammar over the approve flow. Three shapes: `alice/laptop` (one
/// device → its endpoint lands in `revoked_endpoints`, alice's device list empties, serial 3); an
/// unknown target (`ghost`) Errs cleanly (non-zero exit, no panic); `--user-key alice` runs the §4.6
/// rotation (removes alice WITHOUT adding a new revoked endpoint — the count stays 1, not 2 —, serial
/// 4). The already-device-revoked endpoint STAYS revoked (validation rule 4b — no un-revoke path in
/// M3b): a clean same-device re-enroll is the PURE runbook only (a direct `--user-key` with no prior
/// device-revoke); a previously-device-revoked endpoint is an operator/M3c concern.
#[tokio::test(flavor = "multi_thread")]
async fn revoke_person_device_and_user_key_grammar() {
    tokio::time::timeout(Duration::from_secs(45), async {
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, opcfg, openv) = launch_in(opdir.path());
        let invite = org_invite_from(&run_cmd(&opexe, &openv, &["org", "create", "acme"]));
        let jdir = tempfile::tempdir().unwrap();
        let (jexe, jsock, _jcfg, jenv) = launch_in(jdir.path());
        let jc = join_code_from(&run_cmd(
            &jexe,
            &jenv,
            &["join", &invite, "--name", "Alice", "--user-id", "alice"],
        ));
        run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &jc, "--groups", "team-eng"],
        );

        // Device revoke: the endpoint → revoked_endpoints, serial 3, alice's device list empties.
        let dev = run_cmd(&opexe, &openv, &["org", "revoke", "alice/laptop"]);
        assert!(
            dev.status.success(),
            "device revoke: {}",
            String::from_utf8_lossy(&dev.stderr)
        );
        let r3: Roster =
            serde_json::from_slice(&std::fs::read(opcfg.join("roster.json")).unwrap()).unwrap();
        assert_eq!(r3.serial, 3);
        assert_eq!(r3.revoked_endpoints.len(), 1);
        assert!(
            r3.users
                .iter()
                .find(|u| u.user_id == "alice")
                .unwrap()
                .devices
                .is_empty()
        );

        // A revoke of an unknown target Errs (never panics; non-zero exit).
        assert!(
            !run_cmd(&opexe, &openv, &["org", "revoke", "ghost"])
                .status
                .success()
        );

        // --user-key rotation: remove alice WITHOUT adding a NEW revoked endpoint. NOTE: in THIS test
        // the endpoint was already device-revoked above, so it STAYS in revoked_endpoints — a
        // same-device re-enroll would be refused by validation rule 4b (M3b has no un-revoke path).
        // Clean same-device rotation is the PURE runbook (a direct `--user-key` with no prior
        // device-revoke); a previously-device-revoked endpoint is an operator/M3c concern. Here we
        // only assert the rotation REMOVES the user and adds NO new revoked endpoint (count stays 1).
        let rot = run_cmd(&opexe, &openv, &["org", "revoke", "alice", "--user-key"]);
        assert!(rot.status.success());
        assert!(String::from_utf8_lossy(&rot.stdout).contains("re-enroll"));
        let r4: Roster =
            serde_json::from_slice(&std::fs::read(opcfg.join("roster.json")).unwrap()).unwrap();
        assert_eq!(r4.serial, 4);
        assert!(r4.users.iter().all(|u| u.user_id != "alice"));
        // Rotation added NO new revoked endpoint: the count is unchanged from the device step (1).
        assert_eq!(r4.revoked_endpoints.len(), 1);

        shutdown_daemon(&opsock).await;
        shutdown_daemon(&jsock).await;
    })
    .await
    .expect("revoke test timed out");
}

/// `devices code` / `devices add` — bind a SECOND machine to an existing person by user-key signature
/// (spec §4.3/§4.4). Keys never move: the new machine prints only its PUBLIC device endpoint (a
/// `mcpmesh-device:` code, no key material); the ENROLLED device (device 1, which holds alice's user
/// key) signs the new device's binding with THAT user key and emits a join code carrying the SAME
/// user_pk + user_id; `org approve` of that code takes the same-user_pk upsert APPEND path (T4) — so
/// alice ends with TWO devices under ONE user entry, same user_pk, serial bumped. A `devices add` on
/// an UNENROLLED machine (no user_id) Errs cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn devices_add_signs_a_new_device_binding_and_the_operator_appends_it() {
    tokio::time::timeout(Duration::from_secs(45), async {
        // Enroll alice on device 1.
        let opdir = tempfile::tempdir().unwrap();
        let (opexe, opsock, opcfg, openv) = launch_in(opdir.path());
        let invite = org_invite_from(&run_cmd(&opexe, &openv, &["org", "create", "acme"]));
        let d1 = tempfile::tempdir().unwrap();
        let (d1exe, d1sock, _d1cfg, d1env) = launch_in(d1.path());
        let jc = join_code_from(&run_cmd(
            &d1exe,
            &d1env,
            &["join", &invite, "--name", "Alice", "--user-id", "alice"],
        ));
        run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &jc, "--groups", "team-eng"],
        );
        // Device 1's endpoint + alice's user_pk (from the first join code) — the append must preserve both.
        let jc1 = mcpmesh::roster::enroll::JoinCode::decode(&jc).expect("decode join code 1");
        let d1_endpoint = jc1.device_endpoint_id.clone();
        let alice_user_pk = jc1.user_pk.clone();

        // Device 2 (new machine, separate XDG): print its device code — endpoint + label, NO keys.
        let d2 = tempfile::tempdir().unwrap();
        let (d2exe, _d2sock, _d2cfg, d2env) = launch_in(d2.path());
        let code_out = run_cmd(&d2exe, &d2env, &["devices", "code", "--label", "desktop"]);
        assert!(
            code_out.status.success(),
            "devices code: {}",
            String::from_utf8_lossy(&code_out.stderr)
        );
        let dcode = device_code_from(&code_out);
        // The device code carries only the new device's PUBLIC endpoint id + label — no key material.
        let dc = mcpmesh::roster::enroll::DeviceCode::decode(&dcode).expect("decode device code");
        let d2_endpoint = dc.device_endpoint_id.clone();
        assert_ne!(d2_endpoint, d1_endpoint, "device 2 has its own endpoint");
        let code_stdout = String::from_utf8_lossy(&code_out.stdout);
        assert!(
            !code_stdout.contains("mcpmesh-join:") && !code_stdout.contains("user.key"),
            "devices code carries no key material / join code: {code_stdout}"
        );

        // Device 1 (enrolled, holds alice's user key) binds device 2 → a join code + a read-back
        // fingerprint (ceremony consistency with `join`/`approve`). Keys never leave device 1.
        let add = run_cmd(&d1exe, &d1env, &["devices", "add", &dcode]);
        assert!(
            add.status.success(),
            "devices add: {}",
            String::from_utf8_lossy(&add.stderr)
        );
        let add_stdout = String::from_utf8_lossy(&add.stdout);
        assert!(
            add_stdout.contains("Join code fingerprint:"),
            "devices add prints the join-code fingerprint (ceremony): {add_stdout}"
        );
        let jc2 = join_code_from(&add);
        // The emitted join code re-uses alice's user_pk + user_id (the append path), and binds device 2.
        let jc2d = mcpmesh::roster::enroll::JoinCode::decode(&jc2).expect("decode join code 2");
        assert_eq!(
            jc2d.user_pk, alice_user_pk,
            "same user_pk (append, not new user)"
        );
        assert_eq!(jc2d.requested_user_id, "alice");
        assert_eq!(jc2d.device_endpoint_id, d2_endpoint);

        // Operator approves → device 2 APPENDS to alice (same user_pk), serial 3.
        let ap = run_cmd(
            &opexe,
            &openv,
            &["org", "approve", &jc2, "--groups", "team-eng"],
        );
        assert!(
            ap.status.success(),
            "second approve: {}",
            String::from_utf8_lossy(&ap.stderr)
        );
        let r: Roster =
            serde_json::from_slice(&std::fs::read(opcfg.join("roster.json")).unwrap()).unwrap();
        assert_eq!(r.serial, 3);
        // Exactly ONE alice user (the append path, not a duplicate/new user).
        assert_eq!(
            r.users.iter().filter(|u| u.user_id == "alice").count(),
            1,
            "alice is a single user entry (append, not a new user)"
        );
        let alice = r.users.iter().find(|u| u.user_id == "alice").unwrap();
        assert_eq!(
            alice.devices.len(),
            2,
            "the second device is appended to alice"
        );
        assert_eq!(
            alice.user_pk, alice_user_pk,
            "same user_pk after the append"
        );
        // Both endpoints are present under the one user.
        let endpoints: Vec<&str> = alice
            .devices
            .iter()
            .map(|d| d.endpoint_id.as_str())
            .collect();
        assert!(
            endpoints.contains(&d1_endpoint.as_str()),
            "device 1 endpoint present"
        );
        assert!(
            endpoints.contains(&d2_endpoint.as_str()),
            "device 2 endpoint present"
        );

        // `devices add` on an UNENROLLED machine (no user_id) Errs cleanly (never panics).
        let fresh = tempfile::tempdir().unwrap();
        let (fexe, _fsock, _fcfg, fenv) = launch_in(fresh.path());
        let unenrolled = run_cmd(&fexe, &fenv, &["devices", "add", &dcode]);
        assert!(
            !unenrolled.status.success(),
            "devices add on an unenrolled machine must refuse"
        );
        assert!(
            String::from_utf8_lossy(&unenrolled.stderr).contains("not enrolled"),
            "the refusal names the enrollment requirement: {}",
            String::from_utf8_lossy(&unenrolled.stderr)
        );

        shutdown_daemon(&opsock).await;
        shutdown_daemon(&d1sock).await;
    })
    .await
    .expect("devices add test timed out");
}
