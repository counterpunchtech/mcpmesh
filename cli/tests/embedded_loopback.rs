//! The loopback hero flow, EMBEDDED: two in-process nodes in ONE test binary — the full
//! product loop (serve → invite → pair → SAS → live MCP session) with no daemon process
//! anywhere, proving `mcpmesh-node` full parity over the same control vocabulary the
//! sidecar model speaks. Everything is real: real keys minted under two temp roots, a
//! real one-time invite, a real encrypted iroh session over localhost.
//!
//! Hermetic by config: `relay_mode = "disabled"` is the no-relay/no-discovery posture
//! (`NetPlan::Hermetic`) — pairing needs no discovery (the invite line carries the
//! inviter's dialable `EndpointAddr`), and the session dial uses the stored last-addr
//! hint, so nothing ever leaves the machine.
use std::time::Duration;

use mcpmesh_local_api::BackendSpec;
use mcpmesh_node::{Config, NodeBuilder};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

/// The hermetic localhost posture both nodes boot with.
fn hermetic() -> Config {
    Config::from_toml_str("[network]\nrelay_mode = \"disabled\"\n").expect("valid test config")
}

#[tokio::test(flavor = "multi_thread")]
async fn two_embedded_nodes_pair_and_run_an_mcp_session() {
    let (a_root, b_root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = NodeBuilder::new(a_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node a starts");
    let b = NodeBuilder::new(b_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node b starts");

    // a serves the hermetic stdio MCP stub — the same binary the process-level tests spawn.
    let mut a_ctl = a.control().await.expect("a control");
    a_ctl
        .register_service(
            "notes",
            BackendSpec::Run {
                cmd: vec![STUB.into()],
                env: Default::default(),
                cwd: None,
            },
            vec![],
        )
        .await
        .expect("register notes");

    // invite → pair, then assert the SAS programmatically on BOTH sides (the loopback e2e
    // pattern): the redeemer's `PairResult` and the inviter's `recent_pairings` must show
    // the SAME safety code — that is the whole point of the spoken check.
    let invite = a_ctl.invite(vec!["notes".into()]).await.expect("invite");
    let mut b_ctl = b.control().await.expect("b control");
    let paired = timeout(Duration::from_secs(30), b_ctl.pair(&invite.invite_line))
        .await
        .expect("pair within 30s")
        .expect("pair succeeds");
    assert!(!paired.sas_code.is_empty(), "redeemer displays a SAS");
    assert_eq!(paired.services, vec!["notes".to_string()]);
    let a_status = a_ctl.status().await.expect("a status");
    assert_eq!(
        a_status
            .recent_pairings
            .last()
            .expect("a recorded the pairing")
            .sas_code,
        paired.sas_code,
        "both sides display the same safety code"
    );

    // b opens a live MCP session to a's `notes` over real iroh and round-trips the stub:
    // initialize first (the client speaks first), then a tools/call whose reply must echo
    // the text AND the gate-resolved caller identity (MCPMESH_PEER_NAME) — proving the
    // full identity-injection path, embedded.
    let session_ctl = b.control().await.expect("b session control");
    let (reader, mut writer) = session_ctl
        .open_session(paired.peer_nickname.clone(), "notes".into())
        .await
        .expect("open_session");
    // After `open_session` the pipe is raw NDJSON MCP bytes: unwrap the frame reader into
    // its buffered inner (read-ahead travels with it) and speak lines.
    let mut lines = reader.into_inner();
    let mut line = String::new();

    writer
        .write_all(
            (json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).to_string()
                + "\n")
                .as_bytes(),
        )
        .await
        .expect("send initialize");
    timeout(Duration::from_secs(30), lines.read_line(&mut line))
        .await
        .expect("initialize reply within 30s")
        .expect("read initialize reply");
    assert!(
        line.contains("\"result\""),
        "initialize must answer a result: {line}"
    );

    line.clear();
    writer
        .write_all(
            (json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "hello-embedded"}}
            })
            .to_string()
                + "\n")
                .as_bytes(),
        )
        .await
        .expect("send tools/call");
    timeout(Duration::from_secs(30), lines.read_line(&mut line))
        .await
        .expect("echo reply within 30s")
        .expect("read echo reply");
    assert!(
        line.contains("hello-embedded"),
        "the stub must echo the text: {line}"
    );
    assert!(
        line.contains("peer_name"),
        "the stub must see the injected caller identity: {line}"
    );

    b.shutdown().await;
    a.shutdown().await;
}

/// #59: the embedder signing seam, driven through two REAL nodes.
///
/// The unit tests in `mcpmesh-trust` prove the crypto. This proves the WIRING, which is the part
/// they cannot see: that `Node::sign_app` signs with the key whose public half is the
/// `endpoint_id()` this node reports, so a peer holding nothing but that id can attribute the
/// payload.
///
/// The whole point of #59 is a payload that outlives its connection, so the flow here is
/// deliberately NOT a session: A signs, the bytes travel by any means (a `let` here, a relay or a
/// mailbox in a real embedder), and B verifies against A's id alone.
///
/// Signing against a separately-stored key copy — the shape this deliberately avoids — passes every
/// unit test in `app.rs` and fails the first assertion here.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedder_can_attribute_a_payload_to_the_node_that_signed_it() {
    let (a_root, b_root) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = NodeBuilder::new(a_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node a starts");
    let b = NodeBuilder::new(b_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node b starts");

    const DOMAIN: &[u8] = b"embedded-test/message/1";
    let payload = b"a message that outlives its connection";
    let sig = a.sign_app(DOMAIN, payload);

    // B holds A's endpoint id and the bytes. Nothing else.
    assert!(
        mcpmesh_node::Node::verify_app(&a.endpoint_id(), DOMAIN, payload, &sig),
        "a payload must verify against the SIGNER'S endpoint_id — if this fails, sign_app is not \
         using the key that identifies this node and the attribution is worthless"
    );

    // Attribution is to a DEVICE: B's id must not verify A's signature. Without this, "signed by
    // someone on the mesh" would read as "signed by A".
    assert!(
        !mcpmesh_node::Node::verify_app(&b.endpoint_id(), DOMAIN, payload, &sig),
        "another node's id must not verify A's signature"
    );
    // …and B signing the same bytes produces a signature that is B's, not A's.
    let b_sig = b.sign_app(DOMAIN, payload);
    assert!(mcpmesh_node::Node::verify_app(
        &b.endpoint_id(),
        DOMAIN,
        payload,
        &b_sig
    ));
    assert!(
        !mcpmesh_node::Node::verify_app(&a.endpoint_id(), DOMAIN, payload, &b_sig),
        "two nodes must not be interchangeable signers"
    );

    // The domain and the message are covered end to end, not just in the preimage helper.
    assert!(!mcpmesh_node::Node::verify_app(
        &a.endpoint_id(),
        b"other/domain/1",
        payload,
        &sig
    ));
    assert!(!mcpmesh_node::Node::verify_app(
        &a.endpoint_id(),
        DOMAIN,
        b"tampered",
        &sig
    ));

    // The identity SURVIVES a restart: the device key is on disk under the node's root, so a
    // signature made before a restart still verifies after one. An embedder's mailbox is full of
    // payloads signed by processes that have since exited — if this failed, every one of them
    // would become unattributable on the next boot.
    let a_id = a.endpoint_id();
    a.shutdown().await;
    let a2 = NodeBuilder::new(a_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node a restarts on the same root");
    assert_eq!(
        a2.endpoint_id(),
        a_id,
        "the same root must boot the same identity"
    );
    assert!(
        mcpmesh_node::Node::verify_app(&a2.endpoint_id(), DOMAIN, payload, &sig),
        "a signature must outlive the process that made it"
    );
    let sig_after = a2.sign_app(DOMAIN, payload);
    assert_eq!(
        sig, sig_after,
        "and the restarted node must sign identically — same key, deterministic ed25519"
    );

    a2.shutdown().await;
    b.shutdown().await;
}
