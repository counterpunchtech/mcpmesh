//! Session backends: the two ways the daemon answers a selected
//! service. Each implements `mcpmesh_net::SessionBackend`, so `mcpmesh_net::serve`
//! hands it the stripped `initialize` frame and the by-value transport, and the
//! backend owns the session's teardown.
//!
//! * [`spawn`] — the `run` backend: fork one child MCP server per session, pump
//!   its stdio to/from the transport, inject the resolved identity as env vars.
//! * [`socket`] — the `socket` backend: dial a long-running local MCP server per
//!   session and inject the resolved identity into the forwarded `initialize`
//!   `_meta["mcpmesh/peer"]` (authoritative — overwrites, never merges).
//!
//! Both backends drive the same session shape once their local MCP server's byte
//! stream exists: forward the `initialize`, then pump frames both directions over
//! `pump` with one codec ([`mcpmesh_net::framing`]) on the server side too. The only
//! thing that differs is HOW the server stream is obtained (fork+stdio vs. dial+UDS)
//! and HOW identity is injected (env vars vs. `_meta`).
//!
//! Fidelity is Value/semantic, not byte-for-byte: every
//! frame round-trips through `serde_json::Value` (object keys re-sorted, no
//! `arbitrary_precision`) — the same caveat as the mesh transport. The platform
//! pumps and never INTERPRETS the MCP method/result semantics; it does re-serialize
//! the JSON.
use anyhow::{Context, Result};
use mcpmesh_net::errors::synthesized_limited;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use mcpmesh_net::transport::NdjsonTransport;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

pub mod socket;
pub mod spawn;

/// Per-session frame cap for the local MCP server's output (16 MiB) — the same
/// bound `mcpmesh_net::serve` applies to the mesh transport.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// NOTE: the per-service spawn cap is fully HANDLED inside
// `SpawnBackend::run_over` — on cap it synthesizes `-32053` on the transport and returns
// `Ok(())` (a clean refusal, not a session error). There is deliberately no returned error
// type: `run_session` lives in `mcpmesh-net`, which cannot depend on a cli error type (a real
// layering constraint), so a "downcast in the daemon" was never possible. The backend owning
// the refusal is the correct seam.

/// Bidirectionally pump one session between the mesh transport and a local MCP
/// server's byte stream (a spawned child's stdio, or a dialed UDS). Shared by both
/// backends (DRY): only the server-side reader/writer types differ, so this is
/// generic over all four byte substrates.
///
/// The (already identity-augmented) `initialize` is the server's first inbound line,
/// then frames flow both ways — one codec: `write_frame`/`FrameReader` on the server
/// side too, exactly as on the mesh side.
///
/// **The two directions run CONCURRENTLY as independent loops**, not as a single
/// `select!` whose write is awaited inside the arm. That matters for correctness, not
/// just throughput: with a single loop, awaiting a blocked write in one direction
/// (e.g. the server's input pipe is full because the peer is not draining the
/// server's output) would prevent reading the other direction — a classic full-duplex
/// pipe deadlock, reachable under 16 MiB frames. Running the directions
/// concurrently means direction B keeps draining the server's output (unblocking a
/// full pipe) while direction A is blocked writing, so neither side can wedge. A
/// wedge would be doubly bad: `run_over` would never return, so the spawn backend's
/// `kill_on_drop` would never fire AND its owned concurrency permit would leak.
///
/// Whichever direction ends first (EOF, IO error, or a framing violation) tears the
/// session down: the `select!` returns, this fn returns, the caller drops the server
/// connection (killing a child), and `transport.shutdown()` flushes any final frame.
/// `FrameReader::next` and `recv_value`/`send_value` are cancellation-safe, so the
/// cancelled direction drops no committed bytes (a half-written frame on teardown is
/// fine — the session is closing).
///
/// A trusted local server that emits a malformed line is a bug, not an attack: the
/// session ends rather than interpreting it (the platform pumps, never interprets).
pub(crate) async fn pump<TR, TW, SR, SW>(
    initialize: Value,
    transport: &mut NdjsonTransport<TR, TW>,
    server_read: SR,
    mut server_write: SW,
    auditor: crate::audit::RequestAuditor,
    rate: crate::limits::RateGate,
) -> Result<()>
where
    TR: AsyncRead + Send + Unpin,
    TW: AsyncWrite + Send + Unpin,
    SR: AsyncRead + Send + Unpin,
    SW: AsyncWrite + Send + Unpin,
{
    write_frame(&mut server_write, &initialize)
        .await
        .context("forward initialize to local MCP server")?;
    // Wrapped so Direction A can DROP the write half at end-of-input: for a spawned child,
    // `AsyncWriteExt::shutdown` on its stdin only flushes — the fd closes (and the child sees
    // EOF) on drop; for a socket backend the drop sends the FIN just as shutdown would.
    let mut server_write = Some(server_write);

    // The outbound direction sends through a cloned writer handle so it does not need
    // `&mut transport` (which the inbound direction holds for `recv_value`). This
    // disjoint split — reader on one side, the Arc'd writer on the other — is what
    // lets the two loops run concurrently without a shared mutable borrow.
    // A second cloned writer so Direction A can send a -32053 throttle reply without borrowing the
    // transport Direction B holds (both send through the same Arc<Mutex> write half — safe).
    let throttle_writer = transport.writer();
    let transport_writer = transport.writer();
    let mut server_out = FrameReader::new(BufReader::new(server_read), MAX_FRAME_BYTES);

    // Direction A: mesh transport → local server. Owns `&mut transport` (recv) and
    // `server_write`; ends on transport EOF/error or the server's input closing.
    let to_server = async {
        loop {
            match transport.recv_value().await {
                Ok(Some(frame)) => {
                    // Per-identity rate limit: consult BEFORE forwarding a
                    // proxied REQUEST/notification (a method-bearing frame). FAIL-SAFE over-limit —
                    // DROP the request (never forward, never queue), reply -32053{retry_after_ms}
                    // for a request id (silent-drop a notification), and CONTINUE the session
                    // (bounded backpressure, not a close).
                    if frame.get("method").is_some()
                        && let Err(retry_after_ms) = rate.admit()
                    {
                        if let Some(id) = frame.get("id").filter(|v| !v.is_null()).cloned() {
                            let _ = throttle_writer
                                .send_value(synthesized_limited(id, retry_after_ms))
                                .await;
                        }
                        continue;
                    }
                    // Proxied-request-line audit hook: hash args + record method/tool BEFORE
                    // forwarding. PRIVACY — sees raw args (the server needs them); stores only blake3.
                    auditor.on_request(&frame);
                    let Some(w) = server_write.as_mut() else {
                        break;
                    };
                    if write_frame(w, &frame).await.is_err() {
                        break; // server input closed — server is gone
                    }
                }
                Ok(None) => break, // transport EOF / clean close
                Err(_) => break,   // transport IO error or framing violation
            }
        }
        // The peer half-closed (no more requests) or the transport failed — either way this
        // direction is done, but the SESSION is not: responses to already-forwarded requests
        // may still be inside the server. Close the server's stdin so it sees end-of-input
        // and can finish, then park: only Direction B draining to the server's output EOF may
        // end the session. Winning the select! here would cancel B and drop those replies —
        // the one-shot client (`printf ... | mcpmesh connect ...`) hits exactly that race.
        if let Some(mut w) = server_write.take() {
            use tokio::io::AsyncWriteExt;
            let _ = w.shutdown().await;
        } // dropped: the child's stdin fd closes / the socket FINs — the backend sees EOF
        std::future::pending::<()>().await
    };

    // Direction B: local server → mesh transport. Owns the FrameReader and the cloned
    // writer handle; ends on the server's output EOF/error/violation or a gone peer.
    let to_transport = async {
        loop {
            match server_out.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    // Response correlation: count the bytes going OUT to the peer (a
                    // COUNT, never the content) and let the auditor emit the completed request record.
                    let bytes_out = serde_json::to_vec(&frame)
                        .map(|v| v.len() as u64)
                        .unwrap_or(0);
                    auditor.on_response(&frame, bytes_out);
                    if transport_writer.send_value(frame).await.is_err() {
                        break; // peer is gone
                    }
                }
                Ok(Some(Inbound::Violation(_))) => break,
                Ok(None) => break, // server output EOF — server closed the session
                Err(_) => break,   // IO error reading the server
            }
        }
    };

    // Direction A parks after end-of-input instead of finishing, so B — the drain toward
    // the peer — is the only branch that can end the session (on the server's output EOF).
    tokio::select! {
        () = to_server => {}
        () = to_transport => {}
    }

    // Flush any final buffered frame (e.g. a last reply) before the write half
    // closes; a no-op once already closed.
    let _ = transport.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Pins the pump's TEARDOWN DISCIPLINE (issue #25): transport EOF ends only the
    //! REQUEST direction — Direction A closes the server's stdin and PARKS, and the
    //! session ends solely when Direction B drains the server's output to EOF. The
    //! pre-fix `select!` let Direction A's completion cancel B, dropping every reply
    //! still inside the server — exactly what a one-shot client (request, then
    //! immediate EOF) provokes. In-memory duplex on all four substrates (the
    //! `proxy::pump_stdio` test pattern); the fake server deliberately withholds its
    //! replies until it sees end-of-input, so a pump that tears down on transport EOF
    //! can never pass.
    //!
    //! Plumbing invariant: each direction is a WHOLE `DuplexStream` used one-way (the
    //! other way stays idle), never a `tokio::io::split` half — dropping a `WriteHalf`
    //! does NOT drop the underlying stream (its `ReadHalf` keeps it alive), so a
    //! split-based harness never delivers the EOFs this test is about.
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::duplex;
    use tokio::time::timeout;

    use super::*;
    use crate::audit::{AuditSink, RequestAuditor};
    use crate::limits::{RateGate, RateLimiter};

    /// The client sends `initialize` + one request and then EOFs the transport; the
    /// server replies to BOTH only after seeing its stdin close. Both replies must
    /// still reach the peer (the old select!-cancel dropped them) and `pump` must
    /// return Ok. Looped because the pre-fix loss was a scheduling coin flip
    /// (`select!` polls branches in random order).
    #[tokio::test]
    async fn transport_eof_does_not_drop_replies_still_inside_the_server() {
        timeout(Duration::from_secs(10), async {
            for _ in 0..25 {
                // Mesh transport, one whole DuplexStream per direction: peer→pump
                // (dropping `peer_w` = the peer's EOF) and pump→peer.
                let (mut peer_w, tr) = duplex(64 * 1024);
                let (tw, peer_r) = duplex(64 * 1024);
                let mut transport = NdjsonTransport::new(tr, tw, MAX_FRAME_BYTES);
                // The server's stdio, likewise: pump→server stdin, server stdout→pump.
                let (server_write, srv_stdin) = duplex(64 * 1024);
                let (srv_stdout, server_read) = duplex(64 * 1024);

                // The fake server: collect every inbound frame, reply ONLY after stdin
                // EOF (so any teardown racing the drain is caught), then close stdout.
                let server = tokio::spawn(async move {
                    let mut srv_w = srv_stdout;
                    let mut reader = FrameReader::new(srv_stdin, MAX_FRAME_BYTES);
                    let mut seen = Vec::new();
                    while let Ok(Some(Inbound::Frame(f))) = reader.next().await {
                        seen.push(f);
                    }
                    // stdin EOF'd — the pump's Direction A closed it. Now echo each
                    // frame back as its "reply" and close stdout (session end).
                    for f in &seen {
                        write_frame(&mut srv_w, &json!({"jsonrpc": "2.0", "id": f["id"]}))
                            .await
                            .unwrap();
                    }
                    seen.len()
                });

                let pump_task = tokio::spawn(async move {
                    pump(
                        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
                        &mut transport,
                        server_read,
                        server_write,
                        RequestAuditor::new(
                            AuditSink::disabled(),
                            Some("bob".into()),
                            "echo".into(),
                        ),
                        RateGate::new(RateLimiter::unlimited_shared(), None),
                    )
                    .await
                });

                // The one-shot client shape: one request behind the initialize, then EOF.
                write_frame(
                    &mut peer_w,
                    &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}),
                )
                .await
                .unwrap();
                drop(peer_w);

                // BOTH replies drain back to the peer, in order, then a clean EOF.
                let mut peer_reader = FrameReader::new(peer_r, MAX_FRAME_BYTES);
                for expect_id in [1, 2] {
                    match peer_reader.next().await.unwrap() {
                        Some(Inbound::Frame(f)) => assert_eq!(
                            f["id"], expect_id,
                            "the reply to request {expect_id} must survive transport EOF: {f}"
                        ),
                        other => panic!("expected the id={expect_id} reply, got {other:?}"),
                    }
                }
                assert!(
                    peer_reader.next().await.unwrap().is_none(),
                    "after the server's output EOF the session closes cleanly"
                );
                assert_eq!(
                    server.await.unwrap(),
                    2,
                    "the server saw initialize + request"
                );
                pump_task.await.unwrap().expect("pump returns Ok");
            }
        })
        .await
        .expect("pump drain test timed out");
    }
}
