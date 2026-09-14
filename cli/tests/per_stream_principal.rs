//! #222: the dialer's PRINCIPAL is re-resolved per stream, not frozen per connection.
//!
//! `run_mesh_connection` used to resolve the dialing endpoint once, when the connection was
//! accepted, and authorize every later bi-stream against that frozen `PeerIdentity`. Only the
//! service allow lists were live (#54). So a principal change that does not sever the connection —
//! a re-pair rewriting `user_id`, a device re-assigned to another user, a roster update moving a
//! user out of a group — kept being honoured on any connection that was already open. #215 (one
//! client connection per remote) makes holding one connection the normal case.
//!
//! The fixture always seeds BOTH a service the principal change affects (`private`, keyed on the
//! `b64u:` user_id) AND one it does not (`echo`, keyed on the device `eid:`), so a mutation that
//! refuses every stream after a rewrite fails the `echo` half.
//!
//! In-process localhost, driving the daemon's REAL `spawn_accept_loop` (mirrors
//! `allow_revoke_sever.rs` / `roster_sever.rs`).

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerEntry, PeerStore};
use mcpmesh::config::Config;
use mcpmesh::daemon::{
    MeshState, build_services, install_roster_view_and_sever, revoke_service_allow,
    spawn_accept_loop,
};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, MAX_FRAME_BYTES, SessionTransport, TrustGate, framing::write_frame};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use serde_json::json;
use tokio::time::timeout;

const STUB: &str = env!("CARGO_BIN_EXE_echo_mcp_stub");

const OLD: &str = "b64u:OLD";
const NEW: &str = "b64u:NEW";

async fn endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![ALPN_MCP.to_vec()])
        .bind()
        .await
        .expect("bind endpoint")
}

fn initialize_frame(service: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "_meta": {"mcpmesh/service": service},
            "capabilities": {}, "clientInfo": {"name": "tester", "version": "0"}
        }
    })
}

fn tools_call_frame(text: &str) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": text}}
    })
}

/// One accepting mesh plus the dialer's endpoint and the store its row lives in.
struct Fixture {
    mesh: Arc<MeshState>,
    addr: iroh::EndpointAddr,
    store: Arc<PeerStore>,
    dialer: iroh::Endpoint,
    registry: Arc<ConnRegistry>,
    roster: Arc<RosterGate>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// Rewrite the dialer's pair row IN PLACE — the store write a re-pair makes. Deliberately NOT
    /// a daemon verb: none of the reachable causes in #222 severs, so the test must not either.
    fn set_user_id(&self, user_id: Option<&str>) {
        self.store
            .add(PeerEntry {
                endpoint_id: *self.dialer.id().as_bytes(),
                nickname: "alice".into(),
                services: vec!["echo".into(), "private".into()],
                paired_at: None,
                user_id: user_id.map(str::to_string),
                last_addr: None,
            })
            .unwrap();
    }

    fn eid(&self) -> String {
        format!("eid:{}", self.dialer.id())
    }
}

/// `echo` admits the dialer's device `eid:` (unaffected by a `user_id` rewrite); `private` admits
/// only `private_allow`; `carol` admits the roster user `carol` (the promotion test).
async fn fixture(user_id: Option<&str>, private_allow: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
    let dialer = endpoint().await;
    let eid = format!("eid:{}", dialer.id());

    let toml = format!(
        "[services.echo]\nrun = ['{STUB}']\nallow = [\"{eid}\"]\n\
         \n[services.private]\nrun = ['{STUB}']\nallow = [\"{private_allow}\"]\n\
         \n[services.carol]\nrun = ['{STUB}']\nallow = [\"carol\"]\n\
         \n[services.team]\nrun = ['{STUB}']\nallow = [\"team-eng\"]\n"
    );
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, &toml).unwrap();
    let cfg = Config::from_toml_str(&toml).expect("parse config");

    let roster = Arc::new(RosterGate::empty());
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    let gate: Arc<dyn TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
    let registry = Arc::new(ConnRegistry::new());
    let server = endpoint().await;
    let addr = server.addr();
    let mesh = MeshState::new(
        server,
        gate,
        store.clone(),
        Arc::new(LiveInvites::new()),
        "server".into(),
        config_path,
        roster.clone(),
        registry.clone(),
        None,
        None,
        None,
        None,
    );
    mesh.set_accept_task(spawn_accept_loop(
        mesh.clone(),
        Arc::new(build_services(&cfg)),
    ))
    .await;
    let f = Fixture {
        mesh,
        addr,
        store,
        dialer,
        registry,
        roster,
        _dir: dir,
    };
    f.set_user_id(user_id);
    f
}

async fn dial(f: &Fixture) -> iroh::endpoint::Connection {
    f.dialer
        .connect(f.addr.clone(), ALPN_MCP)
        .await
        .expect("dial the mesh ALPN")
}

async fn open_session(conn: &iroh::endpoint::Connection, service: &str) -> SessionTransport {
    let (mut send, recv) = conn.open_bi().await.expect("open a bi-stream");
    write_frame(&mut send, &initialize_frame(service))
        .await
        .expect("write initialize");
    SessionTransport::new(recv, send, MAX_FRAME_BYTES)
}

/// The first reply frame on a session (bounded). A closed stream or a timeout is a test failure:
/// every stream in this file must be ANSWERED, either served or refused with -32054, so that a
/// connection-level close cannot masquerade as a per-stream refusal.
async fn first_reply(t: &mut SessionTransport) -> serde_json::Value {
    timeout(Duration::from_secs(10), t.recv_value())
        .await
        .expect("the session must answer within 10s")
        .expect("transport ok")
        .expect("a reply frame, not EOF")
}

fn is_served(v: &serde_json::Value) -> bool {
    v["result"]["serverInfo"]["name"] == "echo-stub"
}

fn is_refused(v: &serde_json::Value) -> bool {
    v["error"]["code"] == -32054 && v["id"] == 1
}

/// After a -32054 refusal the stream must be DONE: a `tools/call` sent on it gets end-of-stream or a
/// transport error, never a result. Without this, "send -32054, then keep serving the session
/// anyway" passes every refusal assertion in this file.
async fn assert_refused_stream_serves_nothing(t: &mut SessionTransport) {
    let _ = t.send_value(tools_call_frame("after-refusal")).await;
    let next = timeout(Duration::from_secs(10), t.recv_value())
        .await
        .expect("a refused stream must end promptly, not hang");
    assert!(
        matches!(next, Ok(None) | Err(_)),
        "a refused stream must serve NOTHING after its -32054: {next:?}"
    );
}

async fn served(conn: &iroh::endpoint::Connection, service: &str) -> serde_json::Value {
    let mut t = open_session(conn, service).await;
    first_reply(&mut t).await
}

/// THE reproduction from #222. The dialer's row carries `b64u:OLD`; `private` admits only
/// `b64u:OLD`. Session A to `echo` is open on connection C. The row is rewritten to `user_id: None`.
/// A second session to `private` on C must be REFUSED (-32054), while `echo` on C is still served
/// (the principal lost `private`, not everything) and C itself stays up.
#[tokio::test]
async fn a_principal_that_loses_access_is_refused_on_its_open_connection() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(Some(OLD), OLD).await;
        let conn = dial(&f).await;

        let mut session_a = open_session(&conn, "echo").await;
        assert!(is_served(&first_reply(&mut session_a).await), "setup: echo served");
        let before = served(&conn, "private").await;
        assert!(
            is_served(&before),
            "setup: `private` must be served BEFORE the rewrite, or the refusal proves nothing: {before}"
        );

        f.set_user_id(None);

        let mut after_t = open_session(&conn, "private").await;
        let after = first_reply(&mut after_t).await;
        assert!(
            is_refused(&after),
            "a stream on the SAME connection must be authorized against the CURRENT principal — \
             `b64u:OLD` no longer belongs to this device: {after}"
        );
        assert_refused_stream_serves_nothing(&mut after_t).await;
        let still = served(&conn, "echo").await;
        assert!(
            is_served(&still),
            "the device principal still admits `echo` — refusing it would be over-refusal: {still}"
        );
        assert!(
            conn.close_reason().is_none(),
            "a principal change is a per-stream refusal, not a connection close"
        );

        // Session A, admitted before the rewrite, keeps its admit-time snapshot.
        session_a.send_value(tools_call_frame("a-alive")).await.unwrap();
        let a = first_reply(&mut session_a).await;
        assert_eq!(a["result"]["content"][0]["text"], "a-alive", "{a}");

        // Control: a FRESH connection is refused `private` too, and served `echo`.
        let fresh = dial(&f).await;
        let fresh_private = served(&fresh, "private").await;
        assert!(is_refused(&fresh_private), "control: {fresh_private}");
        assert!(is_served(&served(&fresh, "echo").await), "control: echo");
    })
    .await
    .expect("loses-access test timed out");
}

/// The inverse. The device has no user binding, so `private` (admitting `b64u:NEW`) is refused.
/// The row is then bound to `b64u:NEW` — the ALLOW LIST never changes, only the principal — and the
/// NEXT stream on the same connection must be admitted.
#[tokio::test]
async fn a_principal_that_gains_access_is_admitted_on_its_open_connection() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(None, NEW).await;
        let conn = dial(&f).await;

        let before = served(&conn, "private").await;
        assert!(
            is_refused(&before),
            "setup: unbound device is refused: {before}"
        );

        f.set_user_id(Some(NEW));

        let after = served(&conn, "private").await;
        assert!(
            is_served(&after),
            "a principal that GAINED access must be admitted on the next stream of the same \
             connection: {after}"
        );
        assert!(conn.close_reason().is_none());
    })
    .await
    .expect("gains-access test timed out");
}

/// Identity injection is the same bug: the backend of the second stream must see the CURRENT
/// principal (`MCPMESH_PEER_USER`, which the echo stub reflects as `peer_user`).
#[tokio::test]
async fn the_backend_of_the_next_stream_sees_the_current_principal() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(Some(OLD), OLD).await;
        let conn = dial(&f).await;

        let mut first = open_session(&conn, "echo").await;
        assert!(is_served(&first_reply(&mut first).await));
        first.send_value(tools_call_frame("one")).await.unwrap();
        let one = first_reply(&mut first).await;
        assert_eq!(one["result"]["peer_user"], OLD, "setup: {one}");

        f.set_user_id(Some(NEW));

        let mut second = open_session(&conn, "echo").await;
        assert!(is_served(&first_reply(&mut second).await));
        second.send_value(tools_call_frame("two")).await.unwrap();
        let two = first_reply(&mut second).await;
        assert_eq!(
            two["result"]["peer_user"], NEW,
            "the second stream's backend must be handed the CURRENT principal, not the one the \
             connection was accepted with: {two}"
        );
        assert_eq!(two["result"]["peer_eid"], f.eid(), "{two}");

        // The first session keeps the identity it was admitted (and spawned) with.
        first
            .send_value(tools_call_frame("one-again"))
            .await
            .unwrap();
        let again = first_reply(&mut first).await;
        assert_eq!(again["result"]["peer_user"], OLD, "{again}");
    })
    .await
    .expect("identity injection test timed out");
}

/// An endpoint that no longer resolves AT ALL (its row deleted without a sever) gets the per-stream
/// refusal: -32054 on that stream — the same frame an unauthorized service gets — and the
/// connection is not closed by the server.
#[tokio::test]
async fn an_endpoint_that_stops_resolving_is_refused_per_stream() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(Some(OLD), OLD).await;
        let conn = dial(&f).await;
        assert!(is_served(&served(&conn, "echo").await), "setup");

        assert!(f.store.remove("alice").unwrap(), "setup: row removed");

        let mut after_t = open_session(&conn, "echo").await;
        let after = first_reply(&mut after_t).await;
        assert!(
            is_refused(&after),
            "an unresolvable endpoint must not be served on its open connection: {after}"
        );
        assert_refused_stream_serves_nothing(&mut after_t).await;
        assert!(conn.close_reason().is_none());

        // Re-adding the row restores service on the SAME connection (resolution is per stream).
        f.set_user_id(Some(OLD));
        assert!(is_served(&served(&conn, "echo").await));
    })
    .await
    .expect("unresolvable endpoint test timed out");
}

/// The principal is resolved when the stream's `initialize` ARRIVES, not when the stream was
/// accepted. A dialer can open a stream BEFORE a rewrite and send `initialize` AFTER; resolving at
/// accept time would authorize it against the old principal.
///
/// Deterministic: the stream opens with a non-JSON line and the test waits for its -32700 reply,
/// which proves the server has accepted the stream and its session task is reading — before the
/// rewrite, with no sleep.
#[tokio::test]
async fn a_stream_opened_before_the_rewrite_is_resolved_at_initialize() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(Some(OLD), OLD).await;
        let conn = dial(&f).await;
        assert!(is_served(&served(&conn, "echo").await), "setup");

        let (mut send, recv) = conn.open_bi().await.unwrap();
        send.write_all(b"garbage\n").await.unwrap();
        let mut t = SessionTransport::new(recv, send, MAX_FRAME_BYTES);
        let violation = first_reply(&mut t).await;
        assert_eq!(
            violation["error"]["code"], -32700,
            "setup: the session task must be reading this stream before the rewrite: {violation}"
        );

        f.set_user_id(None);

        t.send_value(initialize_frame("private")).await.unwrap();
        let reply = first_reply(&mut t).await;
        assert!(
            is_refused(&reply),
            "a stream whose initialize arrived after the rewrite must see the new principal: {reply}"
        );
    })
    .await
    .expect("opened-before-rewrite test timed out");
}

/// A revoke reaches a session by the principal it was ADMITTED as (#222 review).
///
/// A session to `private` is admitted as `b64u:OLD`. The device's row is then rewritten to
/// `b64u:NEW` (no sever). `service_allow_revoke {private, "b64u:OLD"}` must still cut that session:
/// the store no longer maps `b64u:OLD` to any endpoint, so a sever keyed only on the CURRENT
/// principal→endpoint mapping cuts nothing and the next `tools/call` is served as `b64u:OLD`.
#[tokio::test]
async fn a_revoke_severs_a_session_by_the_principal_it_was_admitted_as() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(Some(OLD), OLD).await;
        let conn = dial(&f).await;

        let mut session = open_session(&conn, "private").await;
        assert!(is_served(&first_reply(&mut session).await), "setup");
        session
            .send_value(tools_call_frame("before"))
            .await
            .unwrap();
        let before = first_reply(&mut session).await;
        assert_eq!(before["result"]["peer_user"], OLD, "setup: {before}");

        f.set_user_id(Some(NEW));

        revoke_service_allow(&f.mesh, "private".into(), OLD.into())
            .await
            .expect("revoke succeeds");

        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("the revoke must SEVER the connection carrying a session admitted as b64u:OLD");
        let _ = session.send_value(tools_call_frame("after")).await;
        let next = timeout(Duration::from_secs(5), session.recv_value())
            .await
            .expect("the severed session must end promptly");
        assert!(
            !matches!(next, Ok(Some(_))),
            "a session admitted as the revoked principal must not answer after the revoke: {next:?}"
        );
    })
    .await
    .expect("admitted-as revoke test timed out");
}

fn mint_view(root: &SigningKey, serial: u64, devices: &[([u8; 32], &str)]) -> RosterView {
    mint_view_in(root, serial, devices, "team-eng")
}

/// [`mint_view`] with every user in `group` (both `team-eng` and `team-ops` are declared).
fn mint_view_in(
    root: &SigningKey,
    serial: u64,
    devices: &[([u8; 32], &str)],
    group: &str,
) -> RosterView {
    let users = devices
        .iter()
        .map(|(eid, uid)| RosterUser {
            user_id: (*uid).into(),
            display_name: (*uid).into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: vec![group.into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(eid),
                label: "device".into(),
                role: "primary".into(),
            }],
        })
        .collect();
    let r = mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into(), "team-ops".into()],
            users,
            revoked_endpoints: vec![],
            successor_root_pk: None,
            successor_sig: None,
            sig: String::new(),
        },
    );
    load_installed(&r, &root.verifying_key()).expect("mint a valid roster view")
}

/// Per-stream resolution lets a connection accepted as PAIRING-only later carry a
/// ROSTER-authorized session. The registry's sever discriminator (`roster_user`) was captured once
/// at register time as `None`, and a roster drop never severs a `None` connection — so the
/// roster-authorized session would outlive the roster that authorized it. Re-resolving per stream
/// must therefore also PROMOTE the connection's tracked `roster_user`.
#[tokio::test]
async fn a_connection_that_gains_a_roster_identity_is_severed_when_the_roster_drops_it() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(None, NEW).await;
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let other = [7u8; 32];
        let conn = dial(&f).await;
        let refused = served(&conn, "carol").await;
        assert!(
            is_refused(&refused),
            "setup: pairing-only, not carol: {refused}"
        );

        // The device joins the roster as `carol` — a swap that severs nothing.
        let joined = install_roster_view_and_sever(
            &f.mesh,
            mint_view(
                &root,
                1,
                &[(*f.dialer.id().as_bytes(), "carol"), (other, "dave")],
            ),
        );
        assert_eq!(joined, 0, "setup: joining the roster severs nothing");
        let mut carol = open_session(&conn, "carol").await;
        let admitted = first_reply(&mut carol).await;
        assert!(
            is_served(&admitted),
            "carol is admitted on the open connection: {admitted}"
        );

        // The device leaves the roster. The roster-authorized session must be cut.
        assert!(f.roster.view().is_some());
        let severed =
            install_roster_view_and_sever(&f.mesh, mint_view(&root, 2, &[(other, "dave")]));
        assert_eq!(
            severed,
            1,
            "the connection carrying a roster-authorized session must be severed when the roster \
             drops the device (registry len {})",
            f.registry.len()
        );
        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("the severed connection closes");
    })
    .await
    .expect("roster promotion test timed out");
}

/// A revoke of a GROUP reaches a session admitted through that group after the device has moved to
/// another group (#222 review). The registry must record the session's FULL principal set — groups
/// included — because the current roster no longer maps `team-eng` to this device, so the
/// endpoint lookup alone cuts nothing.
#[tokio::test]
async fn a_group_revoke_severs_a_session_admitted_through_the_group_it_has_since_left() {
    timeout(Duration::from_secs(90), async {
        let f = fixture(None, NEW).await;
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let me = *f.dialer.id().as_bytes();
        let other = [7u8; 32];
        assert_eq!(
            install_roster_view_and_sever(
                &f.mesh,
                mint_view_in(&root, 1, &[(me, "carol"), (other, "dave")], "team-eng"),
            ),
            0,
            "setup: joining severs nothing"
        );

        let conn = dial(&f).await;
        let mut session = open_session(&conn, "team").await;
        let admitted = first_reply(&mut session).await;
        assert!(
            is_served(&admitted),
            "setup: admitted via team-eng: {admitted}"
        );

        // The device moves to team-ops: still an active roster device, so nothing is severed.
        assert_eq!(
            install_roster_view_and_sever(
                &f.mesh,
                mint_view_in(&root, 2, &[(me, "carol"), (other, "dave")], "team-ops"),
            ),
            0,
            "setup: a group move severs nothing"
        );
        assert!(conn.close_reason().is_none(), "setup: still connected");

        revoke_service_allow(&f.mesh, "team".into(), "team-eng".into())
            .await
            .expect("revoke succeeds");
        timeout(Duration::from_secs(5), conn.closed())
            .await
            .expect("revoking team-eng must sever the session admitted as team-eng");
        let _ = session.send_value(tools_call_frame("after")).await;
        let next = timeout(Duration::from_secs(5), session.recv_value())
            .await
            .expect("the severed session ends promptly");
        assert!(!matches!(next, Ok(Some(_))), "{next:?}");
    })
    .await
    .expect("group revoke test timed out");
}
