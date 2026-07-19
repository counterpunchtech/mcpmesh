//! Session backends (spec §6.2): the two ways the daemon answers a selected
//! service. Each implements `mcpmesh_net::SessionBackend`, so `mcpmesh_net::serve`
//! hands it the stripped `initialize` frame and the by-value transport, and the
//! backend owns the session's teardown.
//!
//! * [`spawn`] — the `run` backend: fork one child MCP server per session, pump
//!   its stdio to/from the transport, inject the resolved identity as env vars.
//! * [`socket`] — the `socket` backend: dial a long-running local MCP server per
//!   session and inject the resolved identity into the forwarded `initialize`
//!   `_meta["mcpmesh/peer"]` (authoritative — overwrites, never merges — §6.3).
//!
//! Both backends drive the same session shape once their local MCP server's byte
//! stream exists: forward the `initialize`, then pump frames both directions over
//! `pump` with one codec ([`mcpmesh_net::framing`]) on the server side too. The only
//! thing that differs is HOW the server stream is obtained (fork+stdio vs. dial+UDS)
//! and HOW identity is injected (env vars vs. `_meta`).
//!
//! Fidelity is Value/semantic, not byte-for-byte (D6, the shared property): every
//! frame round-trips through `serde_json::Value` (object keys re-sorted, no
//! `arbitrary_precision`) — the same caveat as the M1 mesh transport. The platform
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

/// Per-session frame cap for the local MCP server's output (spec §12 default,
/// 16 MiB) — the same bound `mcpmesh_net::serve` applies to the mesh transport.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// NOTE (Task 9 review): the per-service spawn cap (spec §6.2) is fully HANDLED inside
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
/// pipe deadlock, reachable under §7.3's 16 MiB frames. Running the directions
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
/// session ends rather than interpreting it (D6).
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
                    // Per-identity rate limit (spec §7.3 / §11.2 P7): consult BEFORE forwarding a
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
                    // Proxied-request-line hook (spec §11.3): hash args + record method/tool BEFORE
                    // forwarding. PRIVACY — sees raw args (the server needs them); stores only blake3.
                    auditor.on_request(&frame);
                    if write_frame(&mut server_write, &frame).await.is_err() {
                        break; // server input closed — server is gone
                    }
                }
                Ok(None) => break, // transport EOF / clean close
                Err(_) => break,   // transport IO error or framing violation
            }
        }
    };

    // Direction B: local server → mesh transport. Owns the FrameReader and the cloned
    // writer handle; ends on the server's output EOF/error/violation or a gone peer.
    let to_transport = async {
        loop {
            match server_out.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    // Response correlation (spec §11.3): count the bytes going OUT to the peer (a
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

    // First direction to finish cancels the other, tearing down the session.
    tokio::select! {
        () = to_server => {}
        () = to_transport => {}
    }

    // Flush any final buffered frame (e.g. a last reply) before the write half
    // closes; a no-op once already closed.
    let _ = transport.shutdown().await;
    Ok(())
}
