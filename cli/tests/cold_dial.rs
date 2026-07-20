//! Issue #27 regression: a COLD daemon must reach a paired peer from the PERSISTED pairing
//! address alone.
//!
//! The bug this pins: `dial_service`'s single-nickname path dialed by bare id
//! (`iroh::EndpointAddr::from(endpoint_id)`) and never persisted or attached the
//! invite-proven direct addresses from pairing. With `relay_mode = "disabled"` (no relay,
//! no discovery), the only thing that made the post-pair dial work was iroh's IN-PROCESS
//! address cache primed by that same lifetime's pairing dial — so a freshly-restarted
//! daemon answered `-32055 peer unreachable` against a live localhost peer. The fix:
//! pairing persists the peer's last-known `EndpointAddr` (`PeerEntry::last_addr`) and the
//! dial attaches it (id-validated) alongside discovery.
//!
//! Harness: the same two-real-daemon hermetic flow as `one_shot_connect.rs` (the shared
//! `harness` module), BUT after `invite` → `pair`, Bob's daemon is SHUT DOWN and a fresh
//! one auto-starts for the connect — its in-process iroh address cache is gone, and with
//! discovery disabled NOTHING except the persisted address can resolve Alice. Pre-fix this
//! exact shape fails with `-32055` (verified live while releasing v0.5.2).
// Unix-only: the harness shuts daemons down via their control endpoints at hardcoded
// filesystem socket paths — see `harness/mod.rs`.
#![cfg(unix)]
mod harness;

use std::process::Stdio;
use std::time::Duration;

use harness::{MCPMESH, STUB, run_cmd, shutdown_daemon, world};
use mcpmesh_net::framing::write_frame;
use serde_json::{Value, json};
use tokio::time::timeout;

/// The decisive #27 flow: serve (Alice) → `invite` → `pair` (Bob) → **restart Bob's
/// daemon** → one-shot `connect alice/echo`. With discovery and relay disabled in BOTH
/// worlds, the restarted daemon's dial can only succeed off the pairing-persisted
/// `last_addr` — and it must yield the backend's real response within the bound (a silent
/// empty exit AND a hang both fail, same discipline as `one_shot_connect.rs`).
#[tokio::test(flavor = "multi_thread")]
async fn cold_daemon_dials_a_paired_peer_from_the_persisted_address() {
    timeout(Duration::from_secs(120), async {
        let alice_dir = tempfile::tempdir().unwrap();
        let bob_dir = tempfile::tempdir().unwrap();

        // Alice: serves `echo` (stub backend, allow=[] until the pairing grant). The stub
        // path uses a TOML literal string (single quotes) so it survives verbatim.
        let (alice_socket, alice_env) = world(
            alice_dir.path(),
            &format!(
                "[identity]\nnickname = \"alice\"\n\n[network]\nrelay_mode = \"disabled\"\n\n\
                 [services.echo]\nrun = ['{STUB}']\nallow = []\n"
            ),
        );
        // Bob: dials only — no services, just the hermetic network posture.
        let (bob_socket, bob_env) = world(
            bob_dir.path(),
            "[identity]\nnickname = \"bob\"\n\n[network]\nrelay_mode = \"disabled\"\n",
        );

        // ── invite (Alice) ── auto-starts her daemon; capture the copyable invite line.
        let out = run_cmd(&alice_env, &["invite", "echo"]);
        assert!(
            out.status.success(),
            "`mcpmesh invite echo` exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let invite_line = stdout
            .split_whitespace()
            .find(|t| t.starts_with("mcpmesh-invite:"))
            .unwrap_or_else(|| panic!("no invite line in:\n{stdout}"))
            .to_string();

        // ── pair (Bob) ── auto-starts his daemon; redeems over pair/1 at the invite's
        // embedded addr, writes the mutual trust + Alice's `allow` grant, and (the fix
        // under test) persists Alice's invite-proven address as `last_addr`.
        let out = run_cmd(&bob_env, &["pair", &invite_line]);
        assert!(
            out.status.success(),
            "`mcpmesh pair <invite>` exit 0; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // ── the COLD restart (the issue's exact shape) ── kill Bob's daemon: the process
        // that performed the pairing dial is gone, and with it iroh's in-process address
        // cache. The `connect` below auto-starts a FRESH daemon in the same world, which
        // reads only the durable store — the persisted address is the sole route to Alice
        // (discovery is disabled; pre-fix this dial answers -32055 against the live peer).
        shutdown_daemon(&bob_socket).await;

        // ── the one-shot connect (Bob, cold) ── exactly one initialize frame, stdin
        // closes immediately, and the backend's response must still come back.
        let mut child = tokio::process::Command::new(MCPMESH)
            .arg("connect")
            .arg("alice/echo")
            .envs(bob_env.iter().map(|(k, v)| (k.clone(), v.clone())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn one-shot mcpmesh connect");
        let mut child_in = child.stdin.take().expect("piped stdin");
        write_frame(
            &mut child_in,
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "cold-dial", "version": "0"}}
            }),
        )
        .await
        .unwrap();
        drop(child_in); // one-shot shape: stdin EOF right behind the request

        // Bounded: pre-fix the failure is a -32055 error frame (or a nonzero exit), but a
        // dial that never resolves would instead hang here — both are regressions.
        let out = timeout(Duration::from_secs(60), child.wait_with_output())
            .await
            .expect("cold-dial connect did not finish within 60s")
            .expect("collect cold-dial connect output");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "cold-dial connect exit 0; stdout: {stdout}; stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // Exactly ONE response frame on stdout, and it is the backend's real answer —
        // not a synthesized -32055 refusal.
        let frames: Vec<Value> = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON line {l:?}: {e}")))
            .collect();
        assert_eq!(
            frames.len(),
            1,
            "the one-shot pipe carries exactly the one response frame:\n{stdout}"
        );
        assert_eq!(
            frames[0]["id"], 1,
            "the response answers our request id: {}",
            frames[0]
        );
        assert_eq!(
            frames[0]["result"]["serverInfo"]["name"], "echo-stub",
            "the COLD daemon's dial reached Alice's real backend from the persisted \
             address alone (not a -32055 refusal): {}",
            frames[0]
        );

        shutdown_daemon(&alice_socket).await;
        shutdown_daemon(&bob_socket).await;
    })
    .await
    .expect("cold-dial e2e timed out");
}
