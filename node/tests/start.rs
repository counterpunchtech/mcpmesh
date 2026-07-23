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
