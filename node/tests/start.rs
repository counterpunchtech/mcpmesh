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
