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
    // …and so are the built-ins that are NOT in that namespace. `/iroh-gossip/1` and
    // `/iroh-bytes/4` are named by iroh-gossip and iroh-blobs, so a prefix-only check accepted
    // them — and both arms sit ABOVE the app arm in the dispatch, so the handler was registered,
    // advertised, and silently dead. On a pairing-mode node it was worse: the registration ADDED
    // the ALPN, and the peer negotiated straight into a "gossip not enabled" close. Found by
    // review, by execution.
    for reserved in [b"/iroh-gossip/1".as_slice(), b"/iroh-bytes/4".as_slice()] {
        assert!(
            a.accept_protocol(reserved, Arc::new(rec.clone())).is_err(),
            "a built-in ALPN must be refused even when it is not in the mcpmesh/ namespace: {}",
            String::from_utf8_lossy(reserved)
        );
    }
    // The refusal must not depend on how THIS node booted — a is pairing-mode and serves no
    // gossip, but an embedder must not be able to write a registration that works here and breaks
    // on a roster node.
    assert!(
        a.accept_protocol(b"app/echo/1", Arc::new(rec.clone()))
            .is_ok(),
        "re-registering an app ALPN replaces the handler and stays allowed"
    );

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
    // Dialled by NICKNAME now — which is most of what `connect_protocol` buys over a raw endpoint:
    // an embedder holding only "alice" has no other way to turn that into an address.
    //
    // Note what this does NOT prove: the stored dial-hint attachment. b dialled a during pairing
    // moments ago, so iroh has a's address cached and the hint is redundant here — review verified
    // that by mutation. The hint matters for a peer this node has not contacted since boot, which
    // this test does not construct.
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

/// #67: revoking a peer SEVERS its live custom-protocol connection, mid-protocol.
///
/// This is the headline claim of the seam — the thing an embedder's own iroh endpoint could not
/// give it — and it was asserted nowhere. Review found it by mutation: changing
/// `let Some(_registration) = gate_and_register(..)` to `let Some(_) = ..` drops the registry
/// entry at the end of the statement instead of holding it for the handler's life, so
/// `sever_matching` can no longer reach the connection. Every other test still passed.
///
/// The handler here holds the connection open until it is cut, so the revocation has something to
/// sever rather than racing a handler that had already returned.
#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_peer_severs_its_live_custom_protocol_connection() {
    use std::sync::Arc;

    const ALPN: &[u8] = b"app/hold/1";

    /// Accepts, then holds the connection until the far side (or a sever) closes it.
    #[derive(Debug, Clone)]
    struct Holder {
        open: Arc<tokio::sync::Notify>,
    }

    impl mcpmesh_node::iroh::protocol::ProtocolHandler for Holder {
        async fn accept(
            &self,
            conn: mcpmesh_node::iroh::endpoint::Connection,
        ) -> Result<(), mcpmesh_node::iroh::protocol::AcceptError> {
            // `notify_one`, NOT `notify_waiters`: the latter wakes only waiters ALREADY registered,
            // so if the handler wins the race to this line the signal is dropped and the test
            // hangs. `notify_one` stores a permit, so a later `notified()` returns immediately.
            // Caught by CI — it passed locally on scheduling luck.
            self.open.notify_one();
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

    let open = Arc::new(tokio::sync::Notify::new());
    a.accept_protocol(ALPN, Arc::new(Holder { open: open.clone() }))
        .expect("register");

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
    let invite = a_ctl.invite(vec!["notes".into()]).await.expect("invite");
    let mut b_ctl = b.control().await.expect("b control");
    let paired = timeout(Duration::from_secs(30), b_ctl.pair(&invite.invite_line))
        .await
        .expect("pair within 30s")
        .expect("pair");

    let conn = timeout(
        Duration::from_secs(30),
        b.connect_protocol(&paired.peer_nickname, ALPN),
    )
    .await
    .expect("connect within 30s")
    .expect("a paired peer connects");
    // The handler must be RUNNING before the revocation, or "it closed" proves nothing.
    timeout(Duration::from_secs(30), open.notified())
        .await
        .expect("a's handler accepted the connection");

    // a revokes b. `peer_remove` is IMMEDIATE (#54): it severs live connections rather than
    // waiting for them to end.
    let a_status = a_ctl.status().await.expect("status");
    let b_name = a_status
        .peers
        .first()
        .map(|p| p.name.clone())
        .expect("a stored b as a peer");
    a_ctl.peer_remove(&b_name).await.expect("peer_remove");

    timeout(Duration::from_secs(30), conn.closed())
        .await
        .expect(
            "the live custom-protocol connection must be SEVERED by the revocation — this is the \
             property an embedder's own endpoint could not give it, and it holds only because the \
             accept arm keeps its registry Registration for the handler's whole life",
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

/// #68: an embedder supplies its OWN peer resolver, and two nodes that cannot otherwise find each
/// other connect through it.
///
/// Peer resolution depends on external infrastructure — the pkarr publisher/resolver a relay
/// provides, or an address someone already handed you in an invite. Two machines on one LAN with no
/// internet cannot find each other, though the network path between them is fine. iroh 1.0.3 ships
/// no mDNS lookup, so mcpmesh cannot switch one on; what it can do is stop the resolver set being
/// closed, so an implementation can live outside this crate.
///
/// The test constructs exactly that situation. Both nodes run `relay_mode = "disabled"` — no relay,
/// no discovery — and node b is given ONLY a nickname to dial, with no stored address for it. So:
///
/// 1. Before the lookup is added, the dial fails: nothing can turn that identity into an address.
/// 2. After it, the same dial succeeds — through the embedder's resolver and nothing else.
///
/// Assertion 1 is what makes assertion 2 mean anything. Without it the test would pass on a node
/// that had cached the address from an earlier dial.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedder_can_supply_its_own_peer_resolver() {
    use std::sync::Arc;

    const ALPN: &[u8] = b"app/resolved/1";

    #[derive(Debug)]
    struct Echo;
    impl mcpmesh_node::iroh::protocol::ProtocolHandler for Echo {
        async fn accept(
            &self,
            conn: mcpmesh_node::iroh::endpoint::Connection,
        ) -> Result<(), mcpmesh_node::iroh::protocol::AcceptError> {
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
    a.accept_protocol(ALPN, Arc::new(Echo)).expect("register");

    // b learns a's IDENTITY only — never its address. `eid:` is the one form that needs no
    // pairing and no stored row, so the dial depends on resolution and nothing else.
    let a_eid = format!("eid:{}", a.endpoint_id());

    // (1) No resolver: the dial cannot succeed, because nothing can turn that id into an address.
    assert!(
        timeout(Duration::from_secs(30), b.connect_protocol(&a_eid, ALPN))
            .await
            .expect("the dial must give up, not hang past its own timeout")
            .is_err(),
        "with no address and no resolver the dial must fail — this is the air-gapped-LAN state \
         #68 describes, and the control that makes the assertion below meaningful"
    );

    // (2) The embedder supplies a resolver. A `MemoryLookup` seeded with a's address stands in for
    // the mDNS implementation an embedder would write: what is under test is the SEAM, not the
    // protocol behind it.
    let lookup = mcpmesh_node::iroh::address_lookup::MemoryLookup::new();
    lookup.add_endpoint_info(a.endpoint_addr());
    b.add_address_lookup(lookup)
        .expect("an embedder's resolver is accepted");

    let conn = timeout(Duration::from_secs(30), b.connect_protocol(&a_eid, ALPN))
        .await
        .expect("connect within 30s")
        .expect("the same dial must now succeed, resolved by the embedder's own lookup");

    // …and the gate STILL applies. b never paired with a, so a closes the connection 401 rather
    // than serving it. Context rather than evidence for THIS seam — it exercises #67's gate, which
    // no mutation of `add_address_lookup` can affect — but worth keeping, because it is the
    // property that makes handing an embedder a resolver safe at all: resolution answers WHERE a
    // peer is, never WHO MAY talk to it, so adding a resolver cannot widen who a node admits.
    // The refusal can surface at EITHER call: the gate closes asynchronously, so `open_bi` may
    // already see the close, or it may succeed and the read see it. Asserting on one of them
    // specifically is a race — CI caught exactly that. What matters is that a 401 arrives.
    let refused = match conn.open_bi().await {
        Err(e) => format!("{e:?}"),
        Ok((mut send, mut recv)) => {
            let _ = send.write_all(b"found-you").await;
            let _ = send.finish();
            let e = timeout(Duration::from_secs(30), recv.read_to_end(64))
                .await
                .expect("the gate answers promptly")
                .expect_err("an UNPAIRED peer must be refused however it was resolved");
            format!("{e:?}")
        }
    };
    assert!(
        refused.contains("401") || refused.contains("unauthorized"),
        "the refusal must be the trust gate's 401, not a transport failure — a resolver that \
         admitted strangers would be a second door into the node: {refused}"
    );

    // (3) ADDITIVE, not replacing. A SECOND lookup — one that knows nothing — is added on top, and
    // resolution still works. Without this the claim was asserted nowhere: both nodes are hermetic
    // and start with ZERO lookups, so nothing could have been shadowed and no assertion would have
    // failed if `add` replaced the service list instead of appending to it.
    b.add_address_lookup(mcpmesh_node::iroh::address_lookup::MemoryLookup::new())
        .expect("a second resolver is accepted");
    let again = timeout(Duration::from_secs(30), b.connect_protocol(&a_eid, ALPN))
        .await
        .expect("connect within 30s")
        .expect(
            "adding a second lookup must not displace the first — `add` appends, and every \
             service is queried",
        );
    drop(again);

    b.shutdown().await;
    a.shutdown().await;
}

/// #85 ask 2: a person's `b64u:` identity survives the hardware.
///
/// It lived in one file on one machine with no export, import, or escrow verb anywhere. Replacing
/// a laptop destroyed it — the new machine mints a fresh user key, presents a new `b64u:`, and is a
/// stranger even to peers that had pinned the old one. The reporter's framing: the equivalent event
/// in a centralized product is a password reset.
///
/// Driven through two SEPARATE node roots, which is the whole claim — a phrase written down on one
/// machine restores the identity on a different one:
///
/// 1. Node a exports a phrase. Node b, a fresh root, has its OWN different identity.
/// 2. b imports a's phrase and now presents a's `user_id`.
/// 3. The change is LIVE — b's pairing identity is the restored one immediately, not after a
///    restart, which is what a peer would actually see.
/// 4. A second import is REFUSED without `replace`, because it would discard a live identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_recovery_phrase_restores_an_identity_on_new_hardware() {
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

    let mut a_ctl = a.control().await.expect("a control");
    let exported = a_ctl
        .user_key_export()
        .await
        .expect("a exports its identity");
    assert_eq!(
        exported.recovery_phrase.split_whitespace().count(),
        33,
        "a phrase is one word per key byte plus a checksum"
    );
    assert!(
        exported.user_id.starts_with("b64u:"),
        "the exported id is the stable b64u: identity peers pin: {}",
        exported.user_id
    );

    // b starts life as somebody else. Without this the restore below could be a no-op.
    let mut b_ctl = b.control().await.expect("b control");
    let b_before = b_ctl
        .user_key_export()
        .await
        .expect("b has its own identity")
        .user_id;
    assert_ne!(
        b_before, exported.user_id,
        "precondition: two fresh roots are two different people"
    );

    // Restoring onto a node that already has a key must be REFUSED — it would discard the identity
    // that node currently presents, irreversibly without that key's own phrase.
    let refused = b_ctl
        .user_key_import(&exported.recovery_phrase, false)
        .await
        .expect_err("importing over a live key must be refused");
    assert!(
        format!("{refused}").contains("already has a user key"),
        "and refused for THAT reason, not some incidental failure: {refused}"
    );

    // With the explicit replace, the identity moves.
    let restored = b_ctl
        .user_key_import(&exported.recovery_phrase, true)
        .await
        .expect("an explicit replace restores the identity");
    assert_eq!(
        restored.user_id, exported.user_id,
        "THE claim: the same person, on different hardware"
    );
    assert!(restored.replaced, "and it reports that it replaced one");

    // LIVE, not at the next restart — and asserted through what a PEER actually sees, not by
    // re-reading the file. Re-exporting only proves the key landed on disk; the binding a node
    // PRESENTS at pairing is separate state, and a node that kept presenting the OLD identity while
    // its operator believed the recovery had taken would go on to pair and have the peer store the
    // wrong person. That is the failure worth pinning, and re-export cannot see it: with the live
    // install deleted, the re-export assertion still passed.
    let c_root = tempfile::tempdir().unwrap();
    let c = NodeBuilder::new(c_root.path())
        .config(hermetic())
        .start()
        .await
        .expect("node c starts");
    b_ctl
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
    let invite = b_ctl.invite(vec!["notes".into()]).await.expect("invite");
    let mut c_ctl = c.control().await.expect("c control");
    let paired = timeout(Duration::from_secs(30), c_ctl.pair(&invite.invite_line))
        .await
        .expect("pair within 30s")
        .expect("pair");
    assert_eq!(
        paired.peer_user_id.as_deref(),
        Some(exported.user_id.as_str()),
        "a peer pairing with b RIGHT NOW must see the RESTORED identity — this is what recovery \
         is for, and it is live state the on-disk key does not prove"
    );
    c.shutdown().await;

    // A mistyped phrase is refused rather than restoring a different identity — the case that
    // otherwise looks exactly like every peer having forgotten you.
    let mut words: Vec<&str> = exported.recovery_phrase.split_whitespace().collect();
    words.swap(0, 1);
    let typo = b_ctl.user_key_import(&words.join(" "), true).await;
    // A swap of two identical words is a no-op, so accept either outcome — but if it DID decode,
    // it must have decoded to the same identity, never a different one.
    if let Ok(r) = typo {
        assert_eq!(
            r.user_id, exported.user_id,
            "a phrase must never restore an identity other than the one it encodes"
        );
    }

    b.shutdown().await;
    a.shutdown().await;
}
