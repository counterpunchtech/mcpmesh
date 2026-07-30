//! Follow the daemon's live event stream: one line per mesh event, as it happens.
//! Open a session from another terminal (or run `docs/loopback.sh`) to see frames arrive.
//!
//! ```sh
//! cargo run -p mcpmesh-local-api --features client --example watch
//! ```

use mcpmesh_local_api::{StreamFrame, connect_control_default};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mesh = connect_control_default().await?;

    // `subscribe` upgrades the connection: no more requests — just frames to read until we drop
    // the subscription (or the daemon goes away).
    let mut stream = mesh.subscribe().await?;
    while let Some(frame) = stream.next().await? {
        match frame {
            // Always the first frame: a point-in-time picture, so a UI renders immediately.
            StreamFrame::Snapshot {
                active_sessions,
                reachability,
                ..
            } => println!(
                "snapshot: {} active session(s), {} peer(s) probed",
                active_sessions.len(),
                reachability.len()
            ),
            // Then one frame per audit record — sessions opening/closing, proxied requests
            // (names, digests, and counts only — never content), trust changes.
            StreamFrame::Event { record } => println!(
                "{} {:?} peer={} service={}",
                record.ts,
                record.kind,
                record.peer.as_deref().unwrap_or("-"),
                record.service.as_deref().unwrap_or("-"),
            ),
            // A peer went online or offline (#58). Pushed on TRANSITION only, so this is the
            // signal to flip a liveness indicator — or to flush whatever you queued for a peer
            // that was unreachable — without polling `status`.
            StreamFrame::Reachability { peer } => println!(
                "reachability: {} is now {}",
                peer.name,
                if peer.reachable { "online" } else { "offline" }
            ),
            // We read too slowly and the daemon skipped `dropped` records for us; a reconnect
            // would deliver a fresh snapshot to resync from.
            StreamFrame::Lagged { dropped } => println!("(lagged: {dropped} events skipped)"),
            // `StreamFrame` is `#[non_exhaustive]`: a daemon newer than this client may push a
            // frame kind it has never heard of. Ignore it rather than failing — that is the
            // documented contract, and it is what makes new frame kinds additive.
            other => println!("(unrecognized frame: {other:?})"),
        }
    }
    println!("stream closed");
    Ok(())
}
