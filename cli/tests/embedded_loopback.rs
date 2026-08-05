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

/// #67: an embedder serves its OWN protocol on this node's endpoint, behind this node's gate.
///
/// The point of the seam is not "run a second protocol" — an embedder could always stand up its own
/// iroh endpoint. It is that the custom protocol inherits the identity layer: pairing, the trust
/// gate, the connection registry, the relay config. So this test asserts the two things a second
/// endpoint would NOT give you:
///
/// 1. A PAIRED peer reaches the handler, and the handler sees that peer's authenticated
///    `EndpointId` — the same identity the MCP path injects.
/// 2. An UNPAIRED peer does not reach it at all. Its connection is closed by `gate_and_register`
///    before `accept` runs, so the handler is never invoked. Deleting that call makes a stranger's
///    bytes arrive at an embedder's protocol, which is the whole hazard.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedder_protocol_runs_behind_the_nodes_own_trust_gate() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ALPN: &[u8] = b"app/echo/1";

    /// Records every peer that reaches it, then echoes one line.
    #[derive(Debug, Clone)]
    struct Recorder {
        seen: Arc<std::sync::Mutex<Vec<String>>>,
        calls: Arc<AtomicUsize>,
    }

    impl mcpmesh_node::iroh::protocol::ProtocolHandler for Recorder {
        async fn accept(
            &self,
            conn: mcpmesh_node::iroh::endpoint::Connection,
        ) -> Result<(), mcpmesh_node::iroh::protocol::AcceptError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(conn.remote_id().to_string());
            let (mut send, mut recv) = conn.accept_bi().await?;
            let got = recv.read_to_end(64).await.map_err(|e| {
                mcpmesh_node::iroh::protocol::AcceptError::from_err(std::io::Error::other(e))
            })?;
            send.write_all(&got).await.map_err(|e| {
                mcpmesh_node::iroh::protocol::AcceptError::from_err(std::io::Error::other(e))
            })?;
            send.finish().ok();
            conn.closed().await;
            Ok(())
        }
    }

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

    let rec = Recorder {
        seen: Arc::new(std::sync::Mutex::new(Vec::new())),
        calls: Arc::new(AtomicUsize::new(0)),
    };
    a.accept_protocol(ALPN, Arc::new(rec.clone()))
        .expect("a custom ALPN registers");

    // The reserved namespace is refused — a handler there would be dead code today and a
    // silently-broken one after any future mcpmesh protocol lands on that name.
    assert!(
        a.accept_protocol(b"mcpmesh/mcp/1", Arc::new(rec.clone()))
            .is_err(),
        "the mcpmesh/ ALPN namespace must be reserved"
    );
    assert!(a.accept_protocol(b"", Arc::new(rec.clone())).is_err());

    // (2) UNPAIRED first, so a later pass cannot be explained by ordering.
    //
    // A BARE iroh endpoint dialling a's real address, not a `Node` — and that detail is the test.
    // The first version had node b dial by `eid:` before pairing, which never reached a at all:
    // with no stored address and no discovery on a hermetic mesh, the dial died locally. The
    // handler was not called because nothing arrived, so DELETING the gate left this assertion
    // green. Mutation testing caught it. A stranger has to actually complete a handshake and
    // negotiate the ALPN for the gate to be the thing that stops it.
    let a_addr = a.endpoint_addr();
    let stranger =
        mcpmesh_node::iroh::Endpoint::builder(mcpmesh_node::iroh::endpoint::presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .expect("a stranger endpoint binds");
    match timeout(
        Duration::from_secs(20),
        stranger.connect(a_addr.clone(), ALPN),
    )
    .await
    {
        Ok(Ok(conn)) => {
            // The handshake succeeded — a is reachable and the ALPN negotiated. The GATE is what
            // closes it, and no bytes reach the handler.
            let _ = timeout(Duration::from_secs(10), conn.closed()).await;
        }
        _ => panic!(
            "the stranger must REACH node a for this to test the gate — a dial that fails locally              proves nothing, which is exactly how this assertion was vacuous"
        ),
    }
    assert_eq!(
        rec.calls.load(Ordering::SeqCst),
        0,
        "an UNPAIRED peer must never reach an embedder's handler — the gate closes it before \
         accept runs. This is the property a second endpoint could not give you"
    );

    // Now pair them, and try again.
    let mut a_ctl = a.control().await.expect("a control");
    // An invite must grant SOMETHING, so register the stub. Irrelevant to what is under test —
    // the custom protocol is not a service and is not named in any grant.
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
    let invite = a_ctl.invite(vec!["notes".into()]).await.expect("invite");
    let mut b_ctl = b.control().await.expect("b control");
    let paired = timeout(Duration::from_secs(30), b_ctl.pair(&invite.invite_line))
        .await
        .expect("pair within 30s")
        .expect("pair");

    // (1) PAIRED: the handler runs, and sees b's authenticated identity.
    // Dialled by NICKNAME now, through the same resolution `open_session` uses — which is most of
    // what `connect_protocol` buys over a raw endpoint: an embedder holding only "alice" has no
    // other way to turn that into an address.
    let conn = timeout(
        Duration::from_secs(30),
        b.connect_protocol(&paired.peer_nickname, ALPN),
    )
    .await
    .expect("connect within 30s")
    .expect("a paired peer connects on the custom ALPN");
    let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
    send.write_all(b"ping-over-app-alpn").await.expect("write");
    send.finish().ok();
    let echoed = timeout(Duration::from_secs(30), recv.read_to_end(64))
        .await
        .expect("echo within 30s")
        .expect("read echo");
    assert_eq!(
        echoed, b"ping-over-app-alpn",
        "the embedder's own protocol must round-trip on the node's endpoint"
    );
    assert_eq!(rec.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        rec.seen.lock().unwrap().as_slice(),
        &[b.endpoint_id().to_string()],
        "the handler must see the AUTHENTICATED endpoint id — the same identity the MCP path \
         injects, which is what makes this seam worth using"
    );

    b.shutdown().await;
    a.shutdown().await;
}

/// #85 ask 1: an embedder supplies the device key, and NO key file is touched.
///
/// The at-rest posture was 32 raw secret bytes at 0600 in a directory the node owns, and an
/// embedder could not change it from outside — the file lives inside the mesh root it is told not
/// to hand-write, and nothing accepted a decrypted key at boot. This is the seam that lets the key
/// live in the OS keychain instead.
///
/// Three properties, and the second is the one that makes it worth anything:
///
/// 1. The identity IS the supplied key — `endpoint_id()` is its public half, so peers pair with
///    the key the embedder holds rather than one the node invented.
/// 2. **No `device.key` is written.** A seam that supplied the key but still minted a file would
///    leave the exact artifact it exists to remove sitting on disk.
/// 3. It is stable across restarts, since the caller supplies the same key — which is what makes
///    keychain custody usable rather than a new identity every boot.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedder_can_supply_the_device_key_and_no_key_file_is_written() {
    use mcpmesh_trust::ed25519_dalek::SigningKey;

    let root = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[77u8; 32]);
    let expected = mcpmesh_node::iroh::EndpointId::from_bytes(&key.verifying_key().to_bytes())
        .expect("a valid ed25519 public key is a valid endpoint id");

    let node = NodeBuilder::new(root.path())
        .config(hermetic())
        .device_key(key.clone())
        .start()
        .await
        .expect("node starts on a supplied key");

    assert_eq!(
        node.endpoint_id(),
        expected,
        "the node's mesh identity must BE the supplied key — otherwise the embedder holds a key \
         that authenticates nothing"
    );

    let key_file = root.path().join("config").join("device.key");
    assert!(
        !key_file.exists(),
        "no device.key may be written when the embedder supplies the key — the whole point is \
         that the raw secret never lands on disk: {}",
        key_file.display()
    );

    node.shutdown().await;

    // Restart with the SAME key: same identity, still no file. A node that fell back to minting a
    // file key here would boot happily under a DIFFERENT identity, leaving every paired peer
    // unable to reach it — with nothing in the logs saying why.
    let again = NodeBuilder::new(root.path())
        .config(hermetic())
        .device_key(key)
        .start()
        .await
        .expect("node restarts on the same supplied key");
    assert_eq!(again.endpoint_id(), expected);
    assert!(!key_file.exists());
    again.shutdown().await;

    // …and the DEFAULT path is unchanged: no supplied key means the node mints and keeps its own.
    let other = tempfile::tempdir().unwrap();
    let filed = NodeBuilder::new(other.path())
        .config(hermetic())
        .start()
        .await
        .expect("node starts without a supplied key");
    assert!(
        other.path().join("config").join("device.key").exists(),
        "without the seam the node must still mint its own key file — this assertion is what \
         stops the fix from being 'never write a key file at all'"
    );
    filed.shutdown().await;
}
