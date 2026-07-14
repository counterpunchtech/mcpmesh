//! The `connect` stdio proxy (spec §8) — the ONLY thing an AI client ever runs:
//! `mcpmesh connect <peer>/<service>`. It is a thin, transparent pipe: `ensure_daemon()`, send
//! one `OpenSession`, then pump the MCP session verbatim between this process's stdin/stdout
//! and the daemon's control socket (which the daemon has turned into a raw session pipe). The
//! daemon owns dialing, the session, and pooling; the proxy interprets nothing (D6). When a
//! session is unreachable or refused pre-response, the daemon relays a `-32055`/`-32054`
//! frame that flows straight to stdout, so the AI client gets a well-formed answer rather
//! than a hang; a session severed mid-stream instead surfaces as a clean EOF (the pipe ends,
//! stdout closes). No mid-session re-dial (§8) — the AI client re-invokes if it wants a fresh
//! session.
//!
//! `setup` (spec §11.1) lives here too as the config-entry authority: [`setup_entry`] mints
//! the `mcpServers` block a client config needs, and [`split_target`] parses the shared
//! `<peer>/<service>` argument.
use anyhow::{Context, Result};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::client::ensure_daemon;
use crate::ipc::MAX_FRAME_BYTES;

/// Parse `<peer>/<service>` — the single argument shape `connect` and `setup` share. Both
/// halves must be non-empty (a bare `alice` or `alice/` is a usage error, not a dial that
/// silently fails later).
pub fn split_target(target: &str) -> Result<(String, String)> {
    let (peer, service) = target
        .split_once('/')
        .with_context(|| format!("target '{target}' must be <peer>/<service>"))?;
    anyhow::ensure!(
        !peer.is_empty() && !service.is_empty(),
        "target '{target}' must be <peer>/<service>"
    );
    Ok((peer.to_string(), service.to_string()))
}

/// The single mcpServers *server object* that mounts `<peer>/<service>` through the proxy
/// (spec §8): `{ "command": "mcpmesh", "args": ["connect", "<peer>/<service>"] }`. The one
/// place this shape is defined — both [`setup_entry`] (for `--print`) and the client-config
/// writer (for the file merge) use it, so they can never drift.
pub fn server_object(peer: &str, service: &str) -> Value {
    json!({ "command": "mcpmesh", "args": ["connect", format!("{peer}/{service}")] })
}

/// The AI-client config entry that mounts `<peer>/<service>` through the proxy (spec §8):
/// ```json
/// { "mcpServers": { "<peer>-<service>": {
///     "command": "mcpmesh", "args": ["connect", "<peer>/<service>"] } } }
/// ```
pub fn setup_entry(peer: &str, service: &str) -> Value {
    json!({ "mcpServers": { format!("{peer}-{service}"): server_object(peer, service) } })
}

/// Run the proxy: connect the daemon, open the session (the shared client's `open_session`
/// sends the frame and hands back the raw framed halves — the socket stops being JSON-RPC),
/// then pump stdio <-> control verbatim.
pub async fn run(peer: String, service: String) -> Result<()> {
    let client = ensure_daemon().await?;
    let (control_reader, control_writer) = client.open_session(peer, service).await?;
    pump_stdio(
        tokio::io::stdin(),
        tokio::io::stdout(),
        control_reader,
        control_writer,
    )
    .await
}

/// Bidirectionally pump MCP frames between the AI client's stdio and the control connection
/// (one codec everywhere, D6). Generic over the four byte substrates so an in-memory variant
/// is testable without a subprocess. The two directions run as independent concurrent loops —
/// the same anti-deadlock discipline as the backends' pump. Teardown is driven by the CONTROL
/// side closing (clean EOF on remote close, spec §8); the stdin direction ending only
/// half-closes toward the daemon and then drains, because a synthesized -32055 can already be
/// buffered on the control socket when the stdin->control write hits the dead pipe — the AI
/// client must still be handed that well-formed answer, not a bare EOF (§8).
pub(crate) async fn pump_stdio<SI, SO, CR, CW>(
    stdin: SI,
    mut stdout: SO,
    mut control_reader: FrameReader<CR>,
    mut control_writer: CW,
) -> Result<()>
where
    SI: AsyncRead + Unpin + Send,
    SO: AsyncWrite + Unpin + Send,
    CR: AsyncRead + Unpin + Send,
    CW: AsyncWrite + Unpin + Send,
{
    let mut stdin = FrameReader::new(BufReader::new(stdin), MAX_FRAME_BYTES);

    // stdin (AI client) -> control (the daemon's session pipe).
    let to_control = async {
        loop {
            match stdin.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    if write_frame(&mut control_writer, &frame).await.is_err() {
                        break; // daemon closed the pipe
                    }
                }
                Ok(Some(Inbound::Violation(_))) => break,
                Ok(None) | Err(_) => break, // stdin EOF / IO error → the AI client is done
            }
        }
        // Half-close toward the daemon (it tears the session down and closes in turn), then
        // park forever: this direction must never win the select! below, so the control ->
        // stdout drain always runs to control EOF.
        let _ = control_writer.shutdown().await;
        std::future::pending::<()>().await
    };
    // control (the daemon's session pipe) -> stdout (AI client). Relays session responses AND
    // a synthesized -32055/-32054 error frame verbatim (spec §8).
    let to_stdout = async {
        loop {
            match control_reader.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    if write_frame(&mut stdout, &frame).await.is_err() {
                        break; // stdout closed
                    }
                }
                Ok(Some(Inbound::Violation(_))) => break,
                Ok(None) | Err(_) => break, // remote closed / IO error → clean EOF (§8)
            }
        }
    };
    tokio::select! {
        () = to_control => {}
        () = to_stdout => {}
    }
    let _ = stdout.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tokio::io::{duplex, split};
    use tokio::time::timeout;

    use super::*;

    #[test]
    fn setup_entry_has_the_exact_wire_shape() {
        // The §8 config block, verbatim (compared as parsed JSON so formatting is irrelevant).
        assert_eq!(
            setup_entry("alice", "notes"),
            json!({
                "mcpServers": {
                    "alice-notes": {
                        "command": "mcpmesh",
                        "args": ["connect", "alice/notes"]
                    }
                }
            })
        );
    }

    #[test]
    fn split_target_requires_both_halves() {
        assert_eq!(
            split_target("alice/notes").unwrap(),
            ("alice".into(), "notes".into())
        );
        assert!(split_target("alice").is_err());
        assert!(split_target("alice/").is_err());
        assert!(split_target("/notes").is_err());
    }

    /// The proxy pump is transparent both ways (D6): a frame written to "stdin" reaches the
    /// control connection unmodified, and a frame the control side sends reaches "stdout"
    /// unmodified — here a synthesized -32055 error frame (the unreachable/severed path, §8),
    /// proving the AI client is handed a well-formed answer rather than a hang. Closing
    /// "stdin" then tears the pump down cleanly.
    #[tokio::test]
    async fn pump_relays_both_directions_verbatim() {
        timeout(Duration::from_secs(10), async {
            // stdin: test writes `a_in`, the pump reads `b_in`.
            let (mut a_in, b_in) = duplex(64 * 1024);
            // stdout: the pump writes `b_out`, the test reads `a_out`.
            let (a_out, b_out) = duplex(64 * 1024);
            // control: pump end `pc` <-> daemon end `dc`; split each into read/write halves.
            let (pc, dc) = duplex(64 * 1024);
            let (pc_r, pc_w) = split(pc);
            let (dc_r, dc_w) = split(dc);

            let pump = tokio::spawn(pump_stdio(
                b_in,
                b_out,
                FrameReader::new(pc_r, MAX_FRAME_BYTES),
                pc_w,
            ));

            let mut daemon_reader = FrameReader::new(dc_r, MAX_FRAME_BYTES);
            let mut dc_w = dc_w;
            let mut a_out_reader = FrameReader::new(a_out, MAX_FRAME_BYTES);

            // stdin -> control: the AI client's initialize arrives on the control side verbatim.
            let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
            write_frame(&mut a_in, &init).await.unwrap();
            match daemon_reader.next().await.unwrap().unwrap() {
                Inbound::Frame(f) => assert_eq!(f, init, "stdin frame must reach control verbatim"),
                other => panic!("expected a frame, got {other:?}"),
            }

            // control -> stdout: a -32055 error frame reaches stdout verbatim.
            let err = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32055,"message":"peer unreachable","data":{"source":"mcpmesh"}}});
            write_frame(&mut dc_w, &err).await.unwrap();
            match a_out_reader.next().await.unwrap().unwrap() {
                Inbound::Frame(f) => assert_eq!(f, err, "control frame must reach stdout verbatim"),
                other => panic!("expected a frame, got {other:?}"),
            }

            // Closing stdin half-closes toward the daemon (the daemon end reads EOF)…
            drop(a_in);
            assert!(
                daemon_reader.next().await.unwrap().is_none(),
                "stdin close must propagate to the daemon as a half-close"
            );
            // …and the daemon closing in turn ends the pump (clean EOF, §8).
            drop(daemon_reader);
            drop(dc_w);
            pump.await.unwrap().unwrap();
        })
        .await
        .expect("pump test timed out");
    }

    /// The unreachable race (spec §8): the daemon can synthesize a -32055 and close the
    /// control connection BEFORE the pump is first polled, while the AI client's initialize
    /// is already sitting in stdin. The stdin->control direction then breaks on a dead pipe —
    /// and the pump must still drain the buffered error frame to stdout rather than tear the
    /// session down around it. Looped because the pre-fix loss was a scheduling coin flip
    /// (select! polls branches in random order).
    #[tokio::test]
    async fn buffered_error_frame_survives_a_dead_control_writer() {
        timeout(Duration::from_secs(10), async {
            for _ in 0..50 {
                let (mut a_in, b_in) = duplex(64 * 1024);
                let (a_out, b_out) = duplex(64 * 1024);
                let (pc, dc) = duplex(64 * 1024);
                let (pc_r, pc_w) = split(pc);
                let (dc_r, mut dc_w) = split(dc);

                // The daemon: -32055 synthesized and connection closed, all pre-pump.
                let err = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32055,"message":"peer unreachable","data":{"source":"mcpmesh"}}});
                write_frame(&mut dc_w, &err).await.unwrap();
                drop(dc_w);
                drop(dc_r);

                // The AI client: initialize already buffered in stdin when the pump starts.
                let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
                write_frame(&mut a_in, &init).await.unwrap();

                let pump = tokio::spawn(pump_stdio(
                    b_in,
                    b_out,
                    FrameReader::new(pc_r, MAX_FRAME_BYTES),
                    pc_w,
                ));

                let mut a_out_reader = FrameReader::new(a_out, MAX_FRAME_BYTES);
                match a_out_reader.next().await.unwrap() {
                    Some(Inbound::Frame(f)) => assert_eq!(
                        f["error"]["code"], -32055,
                        "the buffered -32055 must reach stdout: {f}"
                    ),
                    other => panic!("the -32055 must reach stdout, got {other:?}"),
                }
                drop(a_in);
                pump.await.unwrap().unwrap();
            }
        })
        .await
        .expect("drain test timed out");
    }
}
