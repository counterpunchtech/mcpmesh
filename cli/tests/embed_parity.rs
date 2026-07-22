//! The lockstep guard: the daemon binary and the embeddable crate are the SAME stack
//! version — an embedder pinning `mcpmesh-node` N embeds exactly what `mcpmesh` N ships.
//! (Both take the workspace version today; this guards the day one of them stops.)

#[test]
fn the_binary_and_the_embeddable_crate_are_one_release() {
    let out = assert_cmd::Command::cargo_bin("mcpmesh")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains(mcpmesh_node::VERSION),
        "binary reports `{stdout}` but mcpmesh-node is {}",
        mcpmesh_node::VERSION
    );
}
