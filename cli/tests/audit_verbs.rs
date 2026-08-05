//! #88 acceptance: the audit log is boundable, readable, and observable through the control API.
//!
//! In-process control harness (the `reachability.rs` shape): assemble a `MeshState`, install a
//! REAL `AuditSink` over a hermetic temp dir via `set_audit`, serve the control socket, and
//! drive the REAL verbs over `mcpmesh-local/1`. The retention test boots the REAL daemon
//! subprocess instead — retention runs at boot, and a unit test on the helper would not prove
//! the daemon calls it (the shipped-a-tested-helper-nobody-calls class).
// Unix-only: hand-binds the control socket in-process, like reachability.rs.
#![cfg(unix)]
use std::sync::Arc;
use std::time::Duration;

use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::audit::{AuditLog, AuditSink};
use mcpmesh::client::connect_control;
use mcpmesh::control::{DaemonState, serve_control};
use mcpmesh::daemon::{MeshState, STACK_VERSION};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::RosterGate;
use mcpmesh::{Request, StatusResult};
use mcpmesh_local_api::{AuditListParams, AuditPruneParams};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, TrustGate};
use serde_json::json;
use tokio::time::timeout;

async fn local_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind endpoint")
}

/// One seeded audit line. `kind` uses the wire strings (`session_open` / `request` / …); absent
/// options are omitted, matching the writer's `skip_serializing_if`.
fn line(ts: &str, kind: &str, peer: Option<&str>) -> String {
    let mut v = json!({ "ts": ts, "kind": kind });
    if let Some(p) = peer {
        v["peer"] = json!(p);
    }
    format!("{v}\n")
}

/// Assemble a mesh + control server whose audit sink writes to `audit_dir`, and a connected
/// control client. Returns (client, control task, mesh) — the caller keeps the tempdir.
async fn control_over_audit_dir(
    dir: &std::path::Path,
    audit_dir: std::path::PathBuf,
) -> (
    mcpmesh_local_api::client::ControlClient,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    Arc<MeshState>,
) {
    let store = Arc::new(PeerStore::open(&dir.join("state.redb")).unwrap());
    let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
    let ep = local_endpoint().await;
    let mesh = MeshState::new(
        ep,
        gate,
        store,
        Arc::new(LiveInvites::new()),
        "self".into(),
        dir.join("config.toml"),
        Arc::new(RosterGate::empty()),
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    );
    mesh.set_audit(AuditSink::new(AuditLog::spawn(audit_dir)));
    let socket = dir.join("control.sock");
    let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
    let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh.clone()));
    let control = tokio::spawn(serve_control(listener, state));
    let client = connect_control(&socket).await.expect("connect control");
    (client, control, mesh)
}

/// `audit_prune { before }` deletes strictly-older months, keeps the named month, reports what
/// it deleted, and REFUSES a malformed month instead of silently comparing garbage.
#[tokio::test(flavor = "multi_thread")]
async fn audit_prune_deletes_strictly_older_months_and_validates_its_input() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        for m in ["2026-05", "2026-06", "2026-07"] {
            std::fs::write(
                audit_dir.join(format!("{m}.jsonl")),
                line(
                    &format!("{m}-01T00:00:00.000Z"),
                    "session_open",
                    Some("bob"),
                ),
            )
            .unwrap();
        }
        let (mut client, control, _mesh) =
            control_over_audit_dir(dir.path(), audit_dir.clone()).await;

        // Malformed month → an error, not a silent no-op string comparison.
        client
            .request(Request::AuditPrune(AuditPruneParams {
                before: "garbage".into(),
            }))
            .await
            .expect_err("a malformed month must be refused");

        let v = client
            .request(Request::AuditPrune(AuditPruneParams {
                before: "2026-07".into(),
            }))
            .await
            .expect("audit_prune");
        assert_eq!(
            v["deleted_months"],
            json!(["2026-05", "2026-06"]),
            "strictly-older months are deleted and reported: {v}"
        );
        assert!(
            audit_dir.join("2026-07.jsonl").exists(),
            "the named month itself is KEPT (delete-before, not delete-including)"
        );
        assert!(!audit_dir.join("2026-05.jsonl").exists());
        assert!(!audit_dir.join("2026-06.jsonl").exists());

        // Idempotent: pruning again deletes nothing.
        let v = client
            .request(Request::AuditPrune(AuditPruneParams {
                before: "2026-07".into(),
            }))
            .await
            .expect("audit_prune again");
        assert_eq!(v["deleted_months"], json!([]));

        control.abort();
    })
    .await
    .expect("audit_prune test timed out");
}

/// `audit_prune` FAILS CLOSED without a writer-owned audit dir (#88 gate): a mesh whose sink
/// was never installed must error, never fall back to the ENV-DEFAULT dir — that fallback would
/// let a hermetic test or embedder silently delete the real user's audit history. (The
/// read-only verbs keep `audit_summary`'s env-default precedent; deletion does not.)
#[tokio::test(flavor = "multi_thread")]
async fn audit_prune_refuses_to_guess_a_directory_without_a_live_sink() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        let gate: Arc<dyn TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let ep = local_endpoint().await;
        let mesh = MeshState::new(
            ep,
            gate,
            store,
            Arc::new(LiveInvites::new()),
            "self".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()),
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        // Deliberately NO set_audit: the sink defaults to disabled (dir() == None).
        let socket = dir.path().join("control.sock");
        let listener = mcpmesh::ipc::bind_control_socket(&socket).await.unwrap();
        let state = Arc::new(DaemonState::with_mesh(STACK_VERSION, mesh));
        let control = tokio::spawn(serve_control(listener, state));
        let err = connect_control(&socket)
            .await
            .expect("connect control")
            .request(Request::AuditPrune(AuditPruneParams {
                before: "2100-01".into(),
            }))
            .await
            .expect_err("a destructive verb must not guess a directory");
        assert!(
            err.to_string().contains("audit writer"),
            "the refusal names the missing writer, not a generic failure: {err}"
        );
        control.abort();
    })
    .await
    .expect("fail-closed prune test timed out");
}

/// `audit_list` filters by month range / kind / peer, reports the TOTAL match count, and pages
/// with limit+offset — both sides pinned: `total` must not shrink under pagination, and
/// `records` must not exceed the limit.
#[tokio::test(flavor = "multi_thread")]
async fn audit_list_filters_and_pages_with_an_honest_total() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        // 2026-05: two session_opens (bob, carol). 2026-06: three requests (bob ×2, carol).
        std::fs::write(
            audit_dir.join("2026-05.jsonl"),
            [
                line("2026-05-01T00:00:00.000Z", "session_open", Some("bob")),
                line("2026-05-02T00:00:00.000Z", "session_open", Some("carol")),
            ]
            .concat(),
        )
        .unwrap();
        std::fs::write(
            audit_dir.join("2026-06.jsonl"),
            [
                line("2026-06-01T00:00:00.000Z", "request", Some("bob")),
                line("2026-06-02T00:00:00.000Z", "request", Some("bob")),
                line("2026-06-03T00:00:00.000Z", "request", Some("carol")),
            ]
            .concat(),
        )
        .unwrap();
        let (mut client, control, _mesh) =
            control_over_audit_dir(dir.path(), audit_dir.clone()).await;

        let list = |p: AuditListParams| Request::AuditList(p);
        let base = AuditListParams::default();

        // Unfiltered: everything, oldest month first.
        let v = client
            .request(list(base.clone()))
            .await
            .expect("audit_list");
        assert_eq!(v["total"], 5, "{v}");
        assert_eq!(v["records"].as_array().unwrap().len(), 5);
        assert_eq!(v["records"][0]["ts"], "2026-05-01T00:00:00.000Z");

        // kind filter.
        let v = client
            .request(list(AuditListParams {
                kind: Some("request".into()),
                ..base.clone()
            }))
            .await
            .expect("kind filter");
        assert_eq!(v["total"], 3, "{v}");

        // peer filter AND month range: bob's records in 2026-06 only.
        let v = client
            .request(list(AuditListParams {
                peer: Some("bob".into()),
                since: Some("2026-06".into()),
                until: Some("2026-06".into()),
                ..base.clone()
            }))
            .await
            .expect("peer+range filter");
        assert_eq!(v["total"], 2, "{v}");

        // Pagination: limit 2 / offset 2 over the unfiltered 5 → records 3..5, total still 5.
        let v = client
            .request(list(AuditListParams {
                limit: Some(2),
                offset: Some(2),
                ..base.clone()
            }))
            .await
            .expect("paged");
        assert_eq!(v["total"], 5, "total counts ALL matches, not the page: {v}");
        assert_eq!(v["records"].as_array().unwrap().len(), 2);
        assert_eq!(v["records"][0]["ts"], "2026-06-01T00:00:00.000Z");

        // The limit CLAMP is load-bearing (one JSON response frame): a caller asking for 5000
        // over 1100 records gets exactly the 1000 cap, with total still honest. 1100 one-line
        // records is one file write — cheap enough to pin the clamp for real.
        let many: String = (0..1100)
            .map(|i| {
                line(
                    &format!("2026-04-01T00:00:{:02}.{:03}Z", i / 1000, i % 1000),
                    "request",
                    Some("dave"),
                )
            })
            .collect();
        std::fs::write(audit_dir.join("2026-04.jsonl"), many).unwrap();
        let v = client
            .request(list(AuditListParams {
                peer: Some("dave".into()),
                limit: Some(5000),
                ..base.clone()
            }))
            .await
            .expect("clamped");
        assert_eq!(v["total"], 1100, "{}", v["total"]);
        assert_eq!(
            v["records"].as_array().unwrap().len(),
            1000,
            "an oversized limit is clamped to 1000 — the response is one frame"
        );

        // An invalid kind is an ERROR, not silently-match-all — a typo'd filter that returns
        // everything would let a "show me what you hold about X" answer overclaim.
        client
            .request(list(AuditListParams {
                kind: Some("sesion_open".into()),
                ..base.clone()
            }))
            .await
            .expect_err("an unknown kind string must be refused");

        // A malformed month bound is the SAME class (#88 gate): "2026-7" lexicographically
        // excludes every zero-padded month, so without validation the verb answers "nothing is
        // held" on a typo — a silent UNDERCLAIM, worse than the kind case's overclaim.
        client
            .request(list(AuditListParams {
                since: Some("2026-7".into()),
                ..base
            }))
            .await
            .expect_err("a malformed since month must be refused, not silently match nothing");

        control.abort();
    })
    .await
    .expect("audit_list test timed out");
}

/// #80: `status.storage.blobs_gc` distinguishes "not collecting" from "collecting, no sweep yet",
/// and reports the counters live.
///
/// The absent case is the load-bearing one. `None` is the default and the behaviour of every
/// release up to 0.42.0; if it defaulted to a zeroed block instead, an operator reading `runs: 0`
/// could not tell a node that is not collecting from one whose collector has died — and a dead
/// collector reporting `runs: 0` forever is exactly the failure this block exists to make visible.
#[tokio::test(flavor = "multi_thread")]
async fn status_blobs_gc_is_absent_until_collection_is_configured() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let (mut client, control, mesh) =
            control_over_audit_dir(dir.path(), audit_dir.clone()).await;

        let status: StatusResult =
            serde_json::from_value(client.request(Request::Status).await.expect("status"))
                .expect("StatusResult deserializes");
        assert!(
            status.storage.expect("storage block").blobs_gc.is_none(),
            "an unconfigured node reports NO gc block — not a zeroed one"
        );

        // Now as boot wires it when `[blobs].gc_interval` is set and honoured.
        use std::sync::atomic::Ordering;
        let stats = std::sync::Arc::new(mcpmesh::blobs::provider::BlobGcStats::default());
        mesh.set_blobs_gc(3600, stats.clone());

        let status: StatusResult =
            serde_json::from_value(client.request(Request::Status).await.expect("status 2"))
                .expect("StatusResult deserializes");
        let gc = status
            .storage
            .expect("storage")
            .blobs_gc
            .expect("a configured collector reports a block");
        assert_eq!(gc.interval_secs, 3600);
        assert_eq!(gc.runs, 0, "configured, and it has not swept yet");
        assert_eq!(
            gc.last_run_epoch, None,
            "0 is the never-ran sentinel, not a 1970 timestamp"
        );

        // A sweep happens.
        stats.runs.fetch_add(1, Ordering::Relaxed);
        stats.last_run_epoch.store(1_754_300_000, Ordering::Relaxed);
        stats.last_protected.store(41, Ordering::Relaxed);
        stats.aborted.fetch_add(2, Ordering::Relaxed);

        let status: StatusResult =
            serde_json::from_value(client.request(Request::Status).await.expect("status 3"))
                .expect("StatusResult deserializes");
        let gc = status.storage.expect("storage").blobs_gc.expect("block");
        assert_eq!(
            (gc.runs, gc.last_run_epoch, gc.last_protected, gc.aborted),
            (1, Some(1_754_300_000), 41, 2),
            "every counter is a LIVE read — a cached block would report the boot-time zeros, and \
             `runs` failing to advance is the only signal an operator gets that collection died"
        );

        control.abort();
    })
    .await
    .expect("status blobs_gc test timed out");
}

/// `status.storage` reports the bytes actually on disk: audit = the summed month files, redb =
/// the state store, blobs present (0 with no blob store). Mutating the audit dir must move the
/// number — the field is a live read, not a cached boot-time value.
#[tokio::test(flavor = "multi_thread")]
async fn status_reports_live_storage_bytes() {
    timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let body = line("2026-07-01T00:00:00.000Z", "session_open", Some("bob"));
        std::fs::write(audit_dir.join("2026-07.jsonl"), &body).unwrap();
        let (mut client, control, _mesh) =
            control_over_audit_dir(dir.path(), audit_dir.clone()).await;

        let status: StatusResult =
            serde_json::from_value(client.request(Request::Status).await.expect("status"))
                .expect("StatusResult deserializes");
        let storage = status
            .storage
            .expect("status carries a storage block (#88)");
        assert_eq!(
            storage.audit_bytes,
            body.len() as u64,
            "audit_bytes must equal the bytes on disk"
        );
        assert!(
            storage.redb_bytes > 0,
            "the open state store has a real size"
        );

        // A second month doubles the audit bytes on the NEXT status — a live read.
        std::fs::write(audit_dir.join("2026-06.jsonl"), &body).unwrap();
        let status: StatusResult =
            serde_json::from_value(client.request(Request::Status).await.expect("status 2"))
                .expect("StatusResult deserializes");
        assert_eq!(
            status.storage.expect("storage").audit_bytes,
            2 * body.len() as u64,
            "audit_bytes must track the directory live"
        );

        control.abort();
    })
    .await
    .expect("status storage test timed out");
}

/// `[limits].audit_retain_months = N` prunes months older than the window AT BOOT — driven
/// through the REAL daemon subprocess, because the helper being correct does not prove boot
/// calls it. Default (no key) keeps everything: the keep-forever default is a deliberate
/// decision recorded in the spec, and this test pins BOTH sides.
#[tokio::test(flavor = "multi_thread")]
async fn boot_prunes_audit_months_older_than_the_configured_retention() {
    timeout(Duration::from_secs(60), async {
        for (config, old_survives) in [
            (
                "[network]\nrelay_mode = \"disabled\"\n[limits]\naudit_retain_months = 2\n",
                false,
            ),
            ("[network]\nrelay_mode = \"disabled\"\n", true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let runtime = tmp.path().join("runtime");
            let config_home = tmp.path().join("config");
            let data = tmp.path().join("data");
            let state = tmp.path().join("state");
            std::fs::create_dir_all(config_home.join("mcpmesh")).unwrap();
            std::fs::write(config_home.join("mcpmesh/config.toml"), config).unwrap();

            // Seed an ancient month plus the current month into the daemon's audit dir
            // ($XDG_STATE_HOME/mcpmesh/audit).
            let audit_dir = state.join("mcpmesh").join("audit");
            std::fs::create_dir_all(&audit_dir).unwrap();
            let current = &mcpmesh::audit::now_ts()[..7];
            std::fs::write(
                audit_dir.join("2020-01.jsonl"),
                line("2020-01-01T00:00:00.000Z", "session_open", Some("bob")),
            )
            .unwrap();
            std::fs::write(
                audit_dir.join(format!("{current}.jsonl")),
                line("2026-07-01T00:00:00.000Z", "session_open", Some("bob")),
            )
            .unwrap();

            // Kill guard (#88 gate): an assertion panic below must not leak a live daemon —
            // without this, a failing run leaves a real `internal daemon` process behind.
            struct KillOnDrop(std::process::Child);
            impl Drop for KillOnDrop {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let child = std::process::Command::new(env!("CARGO_BIN_EXE_mcpmesh"))
                .args(["internal", "daemon"])
                .env("XDG_RUNTIME_DIR", &runtime)
                .env("XDG_CONFIG_HOME", &config_home)
                .env("XDG_DATA_HOME", &data)
                .env("XDG_STATE_HOME", &state)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn daemon");
            let mut child = KillOnDrop(child);

            // Wait for the daemon to come up (socket answers), then inspect the dir.
            let socket = runtime.join("mcpmesh").join("mcpmesh.sock");
            let mut client = None;
            for _ in 0..200 {
                if let Ok(c) = connect_control(&socket).await {
                    client = Some(c);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let mut client = client.expect("daemon came up");

            assert_eq!(
                audit_dir.join("2020-01.jsonl").exists(),
                old_survives,
                "retention config was: {config:?}"
            );
            assert!(
                audit_dir.join(format!("{current}.jsonl")).exists(),
                "the current month is always inside the window"
            );

            // While the REAL daemon is up: its status carries the storage block, with a real
            // state-store size — pins the daemon-side wiring, not just the in-process harness.
            let status: StatusResult =
                serde_json::from_value(client.request(Request::Status).await.expect("status"))
                    .expect("StatusResult deserializes");
            let storage = status
                .storage
                .expect("a real daemon reports its storage footprint (#88)");
            assert!(storage.redb_bytes > 0, "state.redb has a real size");
            assert!(
                storage.audit_bytes > 0,
                "the seeded current month is visible in audit_bytes"
            );

            let _ = client.request_value(&json!({"method": "shutdown"})).await;
            let _ = child.0.wait();
        }
    })
    .await
    .expect("retention boot test timed out");
}
