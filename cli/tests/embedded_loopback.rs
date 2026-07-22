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
        .register_service("notes", BackendSpec::Run { cmd: vec![STUB.into()] }, vec![])
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
