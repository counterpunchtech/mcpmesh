//! #125: a dead relay in a `relay_mode = "custom"` list must cost the same wherever it sits.
//!
//! The report inferred a SEQUENTIAL WALK from "the cost scales with where the dead relay sits", and
//! asked us to race the list instead. Measured on the pinned `iroh = "=1.0.3"`, the list is already
//! raced: a blackholed entry costs the same first or last, and four cost the same as one.
//!
//! So this suite does not assert a latency BUDGET — a tight wall-clock bound is what made #110
//! flaky, and the absolute number is iroh's to change. It asserts the SHAPE the report is really
//! about: cost independent of position and of count. A regression to a walk fails it.
//!
//! The value is on the iroh-bump path. The maintainer loop files an `iroh` bump automatically on
//! every new stable release, and relay selection is exactly the kind of internal behaviour a minor
//! bump can change without a type diff. This catches that here instead of downstream.
use std::time::{Duration, Instant};

use tokio::time::timeout;

/// A TRUE blackhole: accepts the TCP connection, then never writes a byte, so the handshake HANGS
/// instead of failing fast. Strictly worse than an unroutable address, and it is the reporter's
/// stated condition ("blackholes rather than refusing"). Loopback, so no DNS and no egress.
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

/// Time `Endpoint::online()` for a custom relay map built from `dead` entries plus one healthy
/// in-process relay, ordered by `dead_first`.
async fn time_online(dead: &[iroh::RelayUrl], dead_first: bool) -> Duration {
    let (healthy_map, _url, _guard) = iroh::test_utils::run_relay_server()
        .await
        .expect("run in-process relay");
    let healthy: Vec<std::sync::Arc<iroh::RelayConfig>> = healthy_map.relays();
    let deads: Vec<iroh::RelayConfig> = dead
        .iter()
        .map(|u| iroh::RelayConfig::new(u.clone(), None))
        .collect();

    let mut cfgs: Vec<iroh::RelayConfig> = Vec::new();
    if dead_first {
        cfgs.extend(deads);
        cfgs.extend(healthy.iter().map(|c| (**c).clone()));
    } else {
        cfgs.extend(healthy.iter().map(|c| (**c).clone()));
        cfgs.extend(deads);
    }

    let ep = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Custom(iroh::RelayMap::from_iter(cfgs)))
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
         surround it — never coming online would be a far worse bug than a slow boot"
    );
    elapsed
}

/// The median of a few samples — one sample on this machine has produced confident wrong calls in
/// both directions, so never diagnose from one.
async fn median(dead: &[iroh::RelayUrl], dead_first: bool) -> Duration {
    let mut v = Vec::new();
    for _ in 0..3 {
        v.push(time_online(dead, dead_first).await);
    }
    v.sort_unstable();
    v[1]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dead_relay_costs_the_same_wherever_it_sits() {
    timeout(Duration::from_secs(600), async {
        let (bh, _task) = blackhole().await;
        let one = vec![bh.clone()];
        let four = vec![bh.clone(), bh.clone(), bh.clone(), bh.clone()];

        let first = median(&one, true).await;
        let last = median(&one, false).await;
        let many = median(&four, true).await;
        eprintln!("#125 dead-first={first:?} dead-last={last:?} 4x-dead-first={many:?}");

        // POSITION independence. A sequential walk makes first-position strictly more expensive
        // than last; racing makes them equal. Generous ratio: this asserts "not a walk", not a
        // latency budget.
        let (lo, hi) = if first <= last {
            (first, last)
        } else {
            (last, first)
        };
        assert!(
            hi.as_millis() <= lo.as_millis().max(1) * 3,
            "a dead relay cost {first:?} first vs {last:?} last — position should not matter if \
             the list is raced (#125). A >3x spread means it is being WALKED."
        );

        // COUNT independence. Under a walk, four dead entries cost about four timeouts.
        assert!(
            many.as_millis() <= first.as_millis().max(1) * 3,
            "four dead relays cost {many:?} vs {first:?} for one — racing makes these comparable; \
             a ~4x growth means each is being awaited in turn (#125)."
        );
    })
    .await
    .expect("#125 relay-race suite timed out");
}
