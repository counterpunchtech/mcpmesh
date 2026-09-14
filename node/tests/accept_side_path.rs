//! #213: the ACCEPTING side of an app-protocol connection loses its selected path while traffic
//! flows, so `Path::is_selected()` is false on the only open IP path — and `Node::connection_path`
//! must answer `Direct` there anyway.
//!
//! Two full nodes on loopback, relay disabled, paired through the real control API; app-protocol
//! connections carrying datagrams both ways.
//!
//! The `*_stay_selected` tests are the iroh 1.0.3 REPRODUCTION: they read `is_selected()` raw and
//! are `#[ignore]`d because they FAIL on 1.0.3 by design (run with `--ignored` to re-measure; see
//! `docs/superpowers/specs/2026-09-14-213-accept-side-path-design.md`). Whether a given run hits
//! the defect depends on which of the host's addresses each connection settles on, so they are
//! also inherently timing-based. The `connection_path_*` tests are the regression tests for the
//! fix and run in the suite.

use std::sync::Arc;
use std::time::Duration;

use mcpmesh_node::{Config, Node, NodeBuilder, iroh};

const ALPN: &[u8] = b"app/213-repro/1";

/// Hands every accepted connection to the test and echoes datagrams for the connection's life.
#[derive(Debug)]
struct Echo {
    tx: tokio::sync::mpsc::UnboundedSender<iroh::endpoint::Connection>,
}

impl iroh::protocol::ProtocolHandler for Echo {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let _ = self.tx.send(conn.clone());
        while let Ok(d) = conn.read_datagram().await {
            let _ = conn.send_datagram(d);
        }
        Ok(())
    }
}

fn render(conn: &iroh::endpoint::Connection) -> Vec<String> {
    conn.paths()
        .iter()
        .map(|p| {
            format!(
                "{}:{:?}<-{:?}:selected={}",
                p.id(),
                p.remote_addr(),
                p.local_addr(),
                p.is_selected()
            )
        })
        .collect()
}

struct Peer {
    _root: tempfile::TempDir,
    node: Node,
    /// The OTHER peer's nickname as this node knows it.
    other: String,
    accepted: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<iroh::endpoint::Connection>>,
}

impl Peer {
    async fn dial(&self) -> iroh::endpoint::Connection {
        self.node
            .connect_protocol(&self.other, ALPN)
            .await
            .expect("connect_protocol")
    }
    async fn accepted(&self) -> iroh::endpoint::Connection {
        tokio::time::timeout(Duration::from_secs(5), async {
            self.accepted.lock().await.recv().await
        })
        .await
        .expect("accept within 5s")
        .expect("handler ran")
    }
}

async fn boot(name: &str) -> (tempfile::TempDir, Node) {
    let root = tempfile::tempdir().unwrap();
    let cfg = Config::from_toml_str(&format!(
        "[identity]\nnickname = \"{name}\"\n[network]\nrelay_mode = \"disabled\"\n"
    ))
    .unwrap();
    let node = NodeBuilder::new(root.path())
        .config(cfg)
        .start()
        .await
        .expect("start");
    (root, node)
}

/// Two paired nodes, each serving `ALPN`. `a` invited, `b` redeemed.
async fn paired() -> (Peer, Peer) {
    if std::env::var_os("MCPMESH_213_TRACE").is_some() {
        use tracing_subscriber::prelude::*;
        let filter = tracing_subscriber::filter::filter_fn(|m| {
            m.target().starts_with("iroh::_events::path")
                || m.target()
                    .starts_with("iroh::socket::remote_map::remote_state")
        });
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_filter(filter),
            )
            .try_init();
    }
    let (ra, a) = boot("acceptor").await;
    let (rb, b) = boot("dialer").await;
    eprintln!(
        "acceptor endpoint={} dialer endpoint={}",
        a.endpoint_id(),
        b.endpoint_id()
    );
    let mut ca = a.control().await.unwrap();
    ca.register_service_with(
        "notes",
        mcpmesh_local_api::BackendSpec::Socket {
            path: ra.path().join("notes.sock").display().to_string(),
        },
        vec![],
        true,
    )
    .await
    .unwrap();
    let invite = ca.invite(vec!["notes".into()]).await.unwrap();
    let mut cb = b.control().await.unwrap();
    let paired = cb.pair(&invite.invite_line).await.unwrap();
    let b_name = ca.status().await.unwrap().peers[0].name.clone();

    let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
    a.accept_protocol(ALPN, Arc::new(Echo { tx: tx_a }))
        .unwrap();
    let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
    b.accept_protocol(ALPN, Arc::new(Echo { tx: tx_b }))
        .unwrap();
    (
        Peer {
            _root: ra,
            node: a,
            other: b_name,
            accepted: tokio::sync::Mutex::new(rx_a),
        },
        Peer {
            _root: rb,
            node: b,
            other: paired.peer_nickname,
            accepted: tokio::sync::Mutex::new(rx_b),
        },
    )
}

/// Keep datagrams flowing both ways on a client-side connection.
fn pump(client: &iroh::endpoint::Connection) -> tokio::task::JoinHandle<()> {
    let client = client.clone();
    tokio::spawn(async move {
        loop {
            let _ = client.send_datagram(bytes::Bytes::from_static(b"tick"));
            let _ = tokio::time::timeout(Duration::from_millis(50), client.read_datagram()).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
}

/// Sample every labelled connection for `secs`; return, per label, how many samples had NO
/// selected path.
async fn observe(conns: &[(&str, &iroh::endpoint::Connection)], secs: u64) -> Vec<(String, usize)> {
    let start = tokio::time::Instant::now();
    let mut last: Vec<Vec<String>> = vec![Vec::new(); conns.len()];
    let mut unselected = vec![0usize; conns.len()];
    let mut samples = 0usize;
    while start.elapsed() < Duration::from_secs(secs) {
        for (i, (label, conn)) in conns.iter().enumerate() {
            let now = render(conn);
            if now != last[i] {
                println!("t+{:.3}s {label} {now:?}", start.elapsed().as_secs_f64());
                last[i] = now;
            }
            if !conn.paths().iter().any(|p| p.is_selected()) {
                unselected[i] += 1;
            }
        }
        samples += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let out: Vec<_> = conns
        .iter()
        .zip(unselected)
        .map(|((l, _), n)| (l.to_string(), n))
        .collect();
    println!("samples={samples} unselected={out:?}");
    out
}

/// One connection: the accept side keeps a selected path (control case).
#[ignore = "iroh 1.0.3 reproduction: fails by design (#213)"]
#[tokio::test(flavor = "multi_thread")]
async fn single_connection_accept_side_stays_selected() {
    let (a, b) = paired().await;
    let client = b.dial().await;
    let server = a.accepted().await;
    let p = pump(&client);
    let r = observe(&[("server", &server), ("client", &client)], 8).await;
    p.abort();
    a.node.shutdown().await;
    b.node.shutdown().await;
    assert!(r.iter().all(|(_, n)| *n == 0), "{r:?}");
}

/// Two connections dialed by the SAME side (b -> a twice): both accept sides must stay selected.
#[ignore = "iroh 1.0.3 reproduction: fails by design (#213)"]
#[tokio::test(flavor = "multi_thread")]
async fn two_connections_same_direction_accept_sides_stay_selected() {
    let (a, b) = paired().await;
    let c1 = b.dial().await;
    let s1 = a.accepted().await;
    let c2 = b.dial().await;
    let s2 = a.accepted().await;
    let p1 = pump(&c1);
    let p2 = pump(&c2);
    let r = observe(
        &[
            ("server1", &s1),
            ("client1", &c1),
            ("server2", &s2),
            ("client2", &c2),
        ],
        8,
    )
    .await;
    p1.abort();
    p2.abort();
    a.node.shutdown().await;
    b.node.shutdown().await;
    assert!(r.iter().all(|(_, n)| *n == 0), "{r:?}");
}

/// Two connections in OPPOSITE directions (b -> a, then a -> b): each node holds one client-side
/// and one server-side connection to the same remote — the shape a daemon is in when it holds a
/// mesh session one way and an app-protocol connection the other.
#[ignore = "iroh 1.0.3 reproduction: fails by design (#213)"]
#[tokio::test(flavor = "multi_thread")]
async fn two_connections_opposite_directions_accept_sides_stay_selected() {
    let (a, b) = paired().await;
    let c1 = b.dial().await;
    let s1 = a.accepted().await;
    let c2 = a.dial().await;
    let s2 = b.accepted().await;
    let p1 = pump(&c1);
    let p2 = pump(&c2);
    let r = observe(
        &[
            ("a-server1", &s1),
            ("b-client1", &c1),
            ("b-server2", &s2),
            ("a-client2", &c2),
        ],
        8,
    )
    .await;
    p1.abort();
    p2.abort();
    a.node.shutdown().await;
    b.node.shutdown().await;
    assert!(r.iter().all(|(_, n)| *n == 0), "{r:?}");
}

/// Sample `Node::connection_path` on every labelled connection for `secs`; return, per label,
/// every reading that was not `Direct` (with its time).
async fn readings(
    conns: &[(&str, &iroh::endpoint::Connection)],
    secs: u64,
) -> Vec<(String, Vec<String>)> {
    let start = tokio::time::Instant::now();
    let mut off: Vec<Vec<String>> = vec![Vec::new(); conns.len()];
    let mut samples = 0usize;
    while start.elapsed() < Duration::from_secs(secs) {
        for (i, (_, conn)) in conns.iter().enumerate() {
            let path = Node::connection_path(conn).await;
            if path != mcpmesh_local_api::PeerPath::Direct {
                off[i].push(format!("t+{:.2}s {path:?}", start.elapsed().as_secs_f64()));
            }
        }
        samples += 1;
    }
    println!("connection_path samples={samples}");
    conns
        .iter()
        .zip(off)
        .map(|((l, _), v)| (l.to_string(), v))
        .collect()
}

/// #213, the fix: in the shape where the accept side's `is_selected()` is false for the life of
/// the connection (one connection each way between the same two nodes), `Node::connection_path`
/// answers `Direct` on BOTH accept sides, at every reading, for longer than iroh's 5s
/// hole-punch interval — because it measures where the datagrams went.
#[tokio::test(flavor = "multi_thread")]
async fn connection_path_reads_direct_on_a_busy_accept_side() {
    let (a, b) = paired().await;
    let c1 = b.dial().await;
    let s1 = a.accepted().await;
    let c2 = a.dial().await;
    let s2 = b.accepted().await;
    let p1 = pump(&c1);
    let p2 = pump(&c2);
    let r = readings(
        &[
            ("a-server1", &s1),
            ("b-client1", &c1),
            ("b-server2", &s2),
            ("a-client2", &c2),
        ],
        7,
    )
    .await;
    p1.abort();
    p2.abort();
    a.node.shutdown().await;
    b.node.shutdown().await;
    assert!(
        r.iter().all(|(_, off)| off.is_empty()),
        "every reading on every side must be Direct: {r:?}"
    );
}

/// #213, the structural half: the same shape with NO traffic in flight. Nothing moves in the
/// measurement window, so the answer comes from the path list alone — and a single open IP
/// path is `Direct` whether or not iroh calls it selected.
#[tokio::test(flavor = "multi_thread")]
async fn connection_path_reads_direct_on_an_idle_accept_side() {
    let (a, b) = paired().await;
    let c1 = b.dial().await;
    let s1 = a.accepted().await;
    let c2 = a.dial().await;
    let s2 = b.accepted().await;
    let r = readings(&[("a-server1", &s1), ("b-server2", &s2)], 7).await;
    drop((c1, c2));
    a.node.shutdown().await;
    b.node.shutdown().await;
    assert!(
        r.iter().all(|(_, off)| off.is_empty()),
        "every idle reading on the accept sides must be Direct: {r:?}"
    );
}
