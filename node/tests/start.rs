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
