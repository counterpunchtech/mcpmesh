//! The supported embedding surface, end to end: a `NodeBuilder` boots a full node in a
//! fresh root and its in-memory control connection speaks real mcpmesh-local/1.
use mcpmesh_node::{NodeBuilder, StartError};

/// A fresh root dir + default config boots to a serving node whose control API answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_starts_in_an_empty_root_and_answers_status() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let mut control = node.control().await.expect("control");
    let status = control.status().await.expect("status");
    assert_eq!(status.stack_version, mcpmesh_node::VERSION);
    assert!(status.services.is_empty());
    node.shutdown().await;
}

/// The live self-rename (#37), end to end through the REAL control path: `set_nickname`
/// persists `[identity].nickname`, `status` reflects it immediately, a freshly minted
/// invite presents it (no restart), and invalid names are refused without side effects.
#[tokio::test(flavor = "multi_thread")]
async fn set_nickname_renames_live_and_persists() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let mut control = node.control().await.expect("control");

    control.set_nickname("workbench").await.expect("rename");

    // Effective immediately: status + a fresh invite present the new name — no restart.
    // (An invite must grant a registered service; an ephemeral socket registration is the
    // lightest — nothing is dialed here.)
    let status = control.status().await.expect("status");
    assert_eq!(status.self_nickname, "workbench");
    control
        .register_service_with(
            "notes",
            mcpmesh_local_api::BackendSpec::Socket {
                path: root.path().join("notes.sock").display().to_string(),
            },
            vec![],
            true,
        )
        .await
        .expect("register ephemeral service");
    let invite = control.invite(vec!["notes".into()]).await.expect("invite");
    let decoded = mcpmesh_node::pairing::Invite::decode(&invite.invite_line).expect("decode");
    assert_eq!(decoded.nickname, "workbench");

    // Persisted through the daemon's own config-write path (not an out-of-band write).
    let cfg_text = std::fs::read_to_string(root.path().join("config/config.toml")).unwrap();
    assert!(
        cfg_text.contains("nickname = \"workbench\""),
        "config must carry the rename: {cfg_text}"
    );

    // Invalid names are refused as JSON-RPC errors and change nothing.
    for bad in ["", "   ", "a/b"] {
        control
            .set_nickname(bad)
            .await
            .expect_err("invalid nickname must be refused");
    }
    let status = control.status().await.expect("status after refusals");
    assert_eq!(status.self_nickname, "workbench");

    node.shutdown().await;
}

/// A live `subscribe()` stream must not outlive `Node::shutdown()` — the embedder scenario:
/// restarting an embedded node (e.g. to apply a config change) while its own events
/// subscription is attached must free the root dir immediately, not whenever that
/// subscription's server task happens to notice its client is gone. Regression for the
/// control-connection-serving-task leak: `subscribe`'s server task only notices a dead client
/// via a subsequent failed WRITE, and with no audit traffic it never writes — so, unlike every
/// OTHER tracked serving loop `shutdown` stops, it (and the `Arc<DaemonState>`/mesh/redb lock
/// it holds) lingers forever. Proven here by the symptom an embedder actually hits: a second
/// `NodeBuilder::start` on the SAME root, right after `shutdown`, must succeed promptly rather
/// than hang/refuse with `DataDirInUse` because the first node's redb lock is still held by
/// the leaked task.
#[tokio::test(flavor = "multi_thread")]
async fn shutdown_frees_the_root_even_with_a_live_subscription_attached() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let control = node.control().await.expect("control");
    // Keep the subscription (and its underlying connection) alive across `shutdown` — never
    // read from it, never drop it — so the only thing that can end its server task is
    // `shutdown` itself closing the connection.
    let _sub = control.subscribe().await.expect("subscribe");
    tokio::time::timeout(std::time::Duration::from_secs(5), node.shutdown())
        .await
        .expect("shutdown must complete promptly even with a live subscription attached");
    // The real proof: a fresh node on the same root must be able to start right away. Today it
    // hangs/refuses (`DataDirInUse`) because the orphaned subscription server task still holds
    // the old node's `Arc<DaemonState>` (and thus its redb lock) open.
    let restarted = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        NodeBuilder::new(root.path()).start(),
    )
    .await
    .expect("restart must not hang")
    .expect("restart must succeed once the old node's resources are released");
    restarted.shutdown().await;
}

/// Two nodes on ONE root must refuse: redb's exclusive lock is the guard, surfaced typed.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_node_on_the_same_root_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let first = NodeBuilder::new(root.path()).start().await.expect("first");
    let err = NodeBuilder::new(root.path())
        .start()
        .await
        .expect_err("second node on the same root must refuse");
    assert!(
        matches!(err, StartError::DataDirInUse { .. }),
        "want DataDirInUse, got: {err:?}"
    );
    first.shutdown().await;
}

/// #80 THROUGH BOOT: `[blobs].gc_interval` in a real config reaches a real store, and a restart on
/// the same root still works.
///
/// Both halves were gaps the 0.43.0 gate found, and each was invisible on a fully green suite:
///
/// - **The wiring.** Every other GC test calls `AppBlobs::load(.., Some(interval))` or
///   `mesh.set_blobs_gc(..)` directly, so severing `boot.rs`'s two lines made #80 a complete no-op
///   in the shipped daemon with 375 lib tests, `audit_verbs` and `start` all still passing. A
///   tested helper nobody calls.
/// - **The release.** `run_gc` runs on the blob store's own runtime and holds a `Store` clone,
///   while the store's actor loop ends only when the last sender drops — a cycle dropping the
///   `FsStore` cannot break. A collecting node therefore held `blobs.db`, its runtime and its
///   worker threads for the life of the PROCESS, and this restart hung forever. Proved by probe:
///   identical path, `gc: None` reopened, `gc: Some(..)` did not.
///
/// `NodeBuilder` shares `boot_node` with `serve_forever`, so this pins the standalone daemon too.
#[tokio::test(flavor = "multi_thread")]
async fn a_configured_gc_interval_reaches_the_store_and_still_frees_the_root() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("config")).unwrap();
    // Deliberately the FLOOR, not something comfortably above it: a boot that silently refused a
    // boundary value would look identical to one that never read the key.
    std::fs::write(
        root.path().join("config/config.toml"),
        "[blobs]\ngc_interval = \"60s\"\n",
    )
    .unwrap();

    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let mut control = node.control().await.expect("control");
    let gc = control
        .status()
        .await
        .expect("status")
        .storage
        .expect("storage block")
        .blobs_gc
        .expect("a configured gc_interval must reach the store and be reported");
    assert_eq!(
        gc.interval_secs, 60,
        "the reported interval must be the one the store is actually on"
    );
    assert_eq!(
        gc.runs, 0,
        "the collector sleeps a full interval before its first run — 0 here is correct, and is why \
         `Some` with runs: 0 has to be distinguishable from absent"
    );

    tokio::time::timeout(std::time::Duration::from_secs(10), node.shutdown())
        .await
        .expect("shutdown must complete promptly on a collecting node");
    let restarted = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        NodeBuilder::new(root.path()).start(),
    )
    .await
    .expect("restart must not hang — a collecting node must release its blob store")
    .expect("restart must succeed");
    restarted.shutdown().await;
}

/// The control: with NO `gc_interval`, boot must report no collector at all.
///
/// Without this, the test above passes on a boot that turns collection on unconditionally — which
/// would make `status.storage.blobs_gc` claim a collector on every node, destroying the one
/// distinction the block exists to carry.
#[tokio::test(flavor = "multi_thread")]
async fn no_gc_interval_means_no_collector_reported() {
    let root = tempfile::tempdir().unwrap();
    let node = NodeBuilder::new(root.path()).start().await.expect("start");
    let mut control = node.control().await.expect("control");
    assert!(
        control
            .status()
            .await
            .expect("status")
            .storage
            .expect("storage block")
            .blobs_gc
            .is_none(),
        "an unconfigured node must report NO collector — the default, and every release <= 0.42.0"
    );
    node.shutdown().await;
}

/// A BAD `gc_interval` must leave collection off rather than guessing an interval — through boot,
/// not just through the config accessor.
///
/// The accessor is unit-tested, but a boot that ignored its `None` and installed a default would
/// start deleting data an operator never authorized, on the strength of a typo.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_gc_interval_boots_with_collection_off() {
    for bad in ["1hh", "30s"] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("config")).unwrap();
        std::fs::write(
            root.path().join("config/config.toml"),
            format!("[blobs]\ngc_interval = \"{bad}\"\n"),
        )
        .unwrap();
        let node = NodeBuilder::new(root.path()).start().await.expect("start");
        let mut control = node.control().await.expect("control");
        assert!(
            control
                .status()
                .await
                .expect("status")
                .storage
                .expect("storage block")
                .blobs_gc
                .is_none(),
            "{bad:?} must leave collection OFF — a knob that deletes bytes must not start on a typo"
        );
        node.shutdown().await;
    }
}
