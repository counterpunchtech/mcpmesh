//! #125: a dead relay in a `relay_mode = "custom"` list costs a bounded, per-list amount — not a
//! per-entry one, and not a position-dependent one.
//!
//! The report inferred a SEQUENTIAL WALK from "the cost scales with where the dead relay sits", and
//! asked us to race the list instead. Two independent reasons it is not a walk:
//!
//! 1. **Configured ORDER is structurally discarded.** `net_plan` hands `RelayMode::Custom` a
//!    `RelayMap`, which is a `BTreeMap` keyed by URL. The `Vec` order the operator wrote is gone
//!    before iroh ever sees it, so "where the dead relay sits" is not a property the system has.
//!    That is stronger than any measurement, and it is why this suite does NOT assert on position:
//!    such a test cannot fail, which is exactly the trap the first version of it fell into (#125
//!    gate).
//! 2. **Cost does not grow with the NUMBER of dead relays**, which is what a walk would do. That is
//!    measurable, and it is what this suite asserts.
//!
//! It deliberately asserts no latency BUDGET — a tight wall-clock bound is what made #110 flaky,
//! and the absolute figure is iroh's (its `PROBES_TIMEOUT`) to change. It asserts the SHAPE.
//!
//! The value is on the iroh-bump path: the maintainer loop files a bump on every new stable
//! release, and relay selection is exactly the internal behaviour a minor bump can change with no
//! type diff. This catches that here instead of downstream.
use std::time::{Duration, Instant};

use tokio::time::timeout;

/// A TRUE blackhole: accepts the TCP connection, then never writes a byte, so the handshake HANGS
/// instead of failing fast. Strictly worse than an unroutable address, and it is the reporter's
/// stated condition ("blackholes rather than refusing").
///
/// Each call binds its OWN port. That matters: `RelayMap` is keyed by URL, so N clones of one URL
/// collapse to a single entry and would measure nothing — the defect the gate found in the first
/// version of this suite.
async fn blackhole() -> (iroh::RelayUrl, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s); // hold open, never respond
        }
    });
    (format!("https://127.0.0.1:{port}").parse().unwrap(), task)
}

/// Time `Endpoint::online()` for a custom relay map of `dead` entries plus one healthy in-process
/// relay. Asserts the map really holds what we think — a silent collapse is how the first version
/// of this suite measured the same case twice and called it two.
async fn time_online(dead: &[iroh::RelayUrl]) -> Duration {
    let (healthy_map, _url, _guard) = iroh::test_utils::run_relay_server()
        .await
        .expect("run in-process relay");
    let healthy: Vec<std::sync::Arc<iroh::RelayConfig>> = healthy_map.relays();

    let mut cfgs: Vec<iroh::RelayConfig> = dead
        .iter()
        .map(|u| iroh::RelayConfig::new(u.clone(), None))
        .collect();
    cfgs.extend(healthy.iter().map(|c| (**c).clone()));
    let map = iroh::RelayMap::from_iter(cfgs);
    assert_eq!(
        map.len(),
        dead.len() + healthy.len(),
        "the relay map collapsed duplicate URLs — this case is not measuring what it names"
    );

    let ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Custom(map))
        .ca_tls_config(iroh_relay::tls::CaTlsConfig::insecure_skip_verify())
        .bind()
        .await
        .expect("bind endpoint");
    let t = Instant::now();
    let online = timeout(Duration::from_secs(150), ep.online()).await.is_ok();
    let elapsed = t.elapsed();
    ep.close().await;
    assert!(
        online,
        "a healthy relay is present, so the node MUST come online however many dead entries \
         surround it — never coming online would be far worse than a slow boot"
    );
    elapsed
}

/// Median of three — one sample on this machine has produced confident wrong calls in both
/// directions, so never diagnose from one.
async fn median(dead: &[iroh::RelayUrl]) -> Duration {
    let mut v = Vec::new();
    for _ in 0..3 {
        v.push(time_online(dead).await);
    }
    v.sort_unstable();
    v[1]
}

/// The operator's configured ORDER cannot reach iroh, so a position-dependent cost is not
/// representable. Pinned as a property rather than a timing, because a timing test of it is
/// vacuous — which is how the first version of this suite passed while asserting nothing.
#[tokio::test]
async fn configured_relay_order_is_discarded_before_iroh_sees_it() {
    let (a, _ta) = blackhole().await;
    let (b, _tb) = blackhole().await;
    let cfg = |first: &iroh::RelayUrl, second: &iroh::RelayUrl| {
        iroh::RelayMap::from_iter(vec![
            iroh::RelayConfig::new(first.clone(), None),
            iroh::RelayConfig::new(second.clone(), None),
        ])
    };
    let forward: Vec<String> = cfg(&a, &b)
        .relays::<Vec<_>>()
        .iter()
        .map(|c| c.url.to_string())
        .collect();
    let reverse: Vec<String> = cfg(&b, &a)
        .relays::<Vec<_>>()
        .iter()
        .map(|c| c.url.to_string())
        .collect();
    assert_eq!(
        forward, reverse,
        "RelayMap is keyed by URL, so writing the same two relays in either order must yield the \
         same map — 'where the dead relay sits' is not a property this system has (#125)"
    );
}

/// #125 gate, and the finding that actually connects to the reporter's symptom: our own
/// `RELAY_READY_TIMEOUT` must OUTLAST iroh's probe window, or a dead relay silently costs us the
/// invite's relay URL.
///
/// `online()` cannot resolve until iroh's net-report picks a home relay, and that report waits for
/// its slowest probe under `PROBES_TIMEOUT` — 3s in iroh 1.0.3, which is exactly what
/// `RELAY_READY_TIMEOUT` used to be. Measured with a blackholed entry present, `online()` resolves
/// at ~3.01s: just past a 3.00s deadline, so `mint_invite` lost that race essentially always and
/// minted an addr with NO relay URL, on a node that was perfectly online via the healthy relays.
/// A WAN redeemer bootstraps from that URL.
///
/// Asserts the ORDERING against a measured `online()`, not against a hardcoded number, so it stays
/// honest if iroh changes its constant — which is precisely what the iroh-bump path needs.
#[tokio::test(flavor = "multi_thread")]
async fn the_relay_ready_deadline_outlasts_a_dead_relays_probe_window() {
    timeout(Duration::from_secs(300), async {
        let (dead, _t) = blackhole().await;
        let observed = median(&[dead]).await;
        eprintln!("#125 online() with a dead relay = {observed:?}");

        let deadline = mcpmesh::daemon::RELAY_READY_TIMEOUT;
        assert!(
            deadline > observed,
            "RELAY_READY_TIMEOUT is {deadline:?} but online() takes {observed:?} when a configured \
             relay is blackholed — the mint would time out and produce an invite with NO relay \
             URL, on a node that IS online via its healthy relays (#125)"
        );
        // And with real margin, not a photo finish: the two were within ~10ms of each other before
        // this fix, which is a coin flip on a busier box, not a bound.
        assert!(
            deadline.saturating_sub(observed) >= Duration::from_millis(500),
            "only {:?} of margin between the deadline ({deadline:?}) and the observed wait \
             ({observed:?}) — too close to rely on",
            deadline.saturating_sub(observed)
        );
    })
    .await
    .expect("#125 relay-deadline suite timed out");
}

/// The measurable half: a dead relay's cost is per-LIST, not per-ENTRY. A walk would grow it.
#[tokio::test(flavor = "multi_thread")]
async fn dead_relay_cost_does_not_grow_with_their_number() {
    timeout(Duration::from_secs(600), async {
        let (d1, _t1) = blackhole().await;
        let (d2, _t2) = blackhole().await;
        let (d3, _t3) = blackhole().await;
        let (d4, _t4) = blackhole().await;

        let one = median(std::slice::from_ref(&d1)).await;
        let four = median(&[d1, d2, d3, d4]).await;
        eprintln!("#125 one-dead={one:?} four-dead={four:?}");

        // Racing makes these comparable; a walk makes four cost about four timeouts. The 2x
        // tolerance asserts "not per-entry", not a budget.
        assert!(
            four.as_millis() <= one.as_millis().max(1) * 2,
            "four dead relays cost {four:?} vs {one:?} for one — a ~4x growth means each is being \
             awaited in turn, i.e. the sequential walk #125 inferred"
        );
    })
    .await
    .expect("#125 relay-count suite timed out");
}
