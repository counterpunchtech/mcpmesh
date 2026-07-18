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
//! The config-entry authority lives here too: `mcp_servers_entry` mints the one `mcpServers`
//! entry shape a client config needs, [`client_instruction_lines`] renders the plain-language
//! "here is exactly what to do next" block (spec §11.1 — including the trust-boundary line) that
//! `pair` and `use` print, and [`split_target`] parses the shared `<peer>/<service>` argument.
//!
//! We PRINT those instructions rather than writing a third-party app's config file: the config
//! shapes and locations are the AI clients' to change, a half-working writer that silently targets
//! the wrong file is worse than no writer, and a human who pastes the line knows what they mounted.
use anyhow::{Context, Result};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::client::ensure_daemon;
use crate::ipc::MAX_FRAME_BYTES;

/// Parse `<peer>/<service>` — the single argument shape `connect` and `use` share. Both
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

/// One `mcpServers` entry that mounts `<peer>/<service>` through the proxy (spec §8), rendered as
/// the text a human pastes into a client config:
/// `"<peer>-<service>": {"command": "mcpmesh", "args": ["connect", "<peer>/<service>"]}`.
///
/// Rendered rather than `serde_json`-serialized so the keys keep their conventional
/// `command`-then-`args` order (a `serde_json::Value` sorts them alphabetically, which reads
/// backwards in a config file). The two interpolated NAMES still go through `serde_json`, so a
/// petname carrying a quote or a backslash can never produce broken JSON.
fn mcp_servers_entry(peer: &str, service: &str) -> String {
    let name = serde_json::to_string(&format!("{peer}-{service}")).expect("a string serializes");
    let target = serde_json::to_string(&format!("{peer}/{service}")).expect("a string serializes");
    format!(r#"{name}: {{"command": "mcpmesh", "args": ["connect", {target}]}}"#)
}

/// Where Claude Desktop keeps its config, rendered for humans to open. `$HOME` is expanded when
/// known so the line is copy-pasteable as-is; it degrades to `~` rather than failing (this is a
/// display string in an instruction block, never a path we write).
fn claude_desktop_config_path() -> String {
    if cfg!(windows) {
        // Claude Desktop on Windows stores its config under %APPDATA%\Claude. Degrade to the
        // literal `%APPDATA%` (which a Windows shell still expands on paste) rather than failing.
        let base = std::env::var("APPDATA").unwrap_or_else(|_| r"%APPDATA%".to_string());
        return format!(r"{base}\Claude\claude_desktop_config.json");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
    if cfg!(target_os = "macos") {
        format!("{home}/Library/Application Support/Claude/claude_desktop_config.json")
    } else {
        format!("{home}/.config/Claude/claude_desktop_config.json")
    }
}

/// The plain-language block telling a human EXACTLY how to use `<peer>/<service…>` from their AI
/// client — printed by `pair` (right when the grant lands) and by `use` (to see it again). Pure so
/// it is unit-testable.
///
/// Every line is either a sentence or a command to copy: the Claude Code invocation, the Claude
/// Desktop config path + entry + restart step, and the generic stdio command any other MCP client
/// takes. It opens with the §11.1 trust boundary — this is the mount-time moment that line exists
/// for. Surface-clean (§1.5): petnames, service names, and the `mcpmesh connect` command only —
/// never an EndpointId.
///
/// Empty `services` renders NOTHING (no dangling "add this to your config" with no entry under it).
pub fn client_instruction_lines(peer: &str, services: &[String]) -> Vec<String> {
    if services.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        format!(
            "Tools from {peer} run on {peer}'s machine. Treat their output as you would \
             anything else {peer} sends you."
        ),
        String::new(),
        "To use in Claude Code, run:".to_string(),
    ];
    for s in services {
        lines.push(format!(
            "  claude mcp add {peer}-{s} -- mcpmesh connect {peer}/{s}"
        ));
    }
    lines.push(String::new());
    lines.push("To use in Claude Desktop, add this under \"mcpServers\" in".to_string());
    lines.push(format!("  {}", claude_desktop_config_path()));
    lines.push("then quit and restart Claude Desktop:".to_string());
    for (i, s) in services.iter().enumerate() {
        // Compact one-line entries; every one but the last is comma-terminated, so the whole block
        // pastes between the braces of `mcpServers` and is valid JSON.
        let comma = if i + 1 < services.len() { "," } else { "" };
        lines.push(format!("  {}{comma}", mcp_servers_entry(peer, s)));
    }
    lines.push(String::new());
    lines.push(format!(
        "Any other MCP client: add a stdio server with the command `mcpmesh connect {peer}/{}`.",
        services[0]
    ));
    lines
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

    use serde_json::{Value, json};
    use tokio::io::{duplex, split};
    use tokio::time::timeout;

    use super::*;

    #[test]
    fn mcp_servers_entry_parses_back_to_the_exact_wire_shape() {
        // The rendered entry is real JSON with the §8 shape: wrap it in the braces it is pasted
        // between and parse it back (proving both validity and shape, whatever the formatting).
        let doc: Value =
            serde_json::from_str(&format!("{{{}}}", mcp_servers_entry("alice", "notes"))).unwrap();
        assert_eq!(
            doc,
            json!({ "alice-notes": { "command": "mcpmesh", "args": ["connect", "alice/notes"] } })
        );
    }

    #[test]
    fn mcp_servers_entry_escapes_an_exotic_petname() {
        // A petname carrying a quote must not produce broken JSON (it is rendered, not serialized).
        let doc: Value =
            serde_json::from_str(&format!("{{{}}}", mcp_servers_entry(r#"a"b"#, "notes"))).unwrap();
        assert_eq!(
            doc,
            json!({ r#"a"b-notes"#: { "command": "mcpmesh", "args": ["connect", r#"a"b/notes"#] } })
        );
    }

    #[test]
    fn client_instruction_lines_name_both_clients_with_copyable_commands() {
        let lines = client_instruction_lines("alice", &["notes".to_string()]);
        let rendered = lines.join("\n");
        // Claude Code: the exact command, copy-pasteable.
        assert!(
            rendered.contains("claude mcp add alice-notes -- mcpmesh connect alice/notes"),
            "the Claude Code command must be spelled out verbatim:\n{rendered}"
        );
        // Claude Desktop: the exact config path, the exact entry, and the restart step.
        assert!(
            rendered.contains("claude_desktop_config.json"),
            "the Claude Desktop config path must be named:\n{rendered}"
        );
        assert!(
            rendered.contains(
                r#""alice-notes": {"command": "mcpmesh", "args": ["connect", "alice/notes"]}"#
            ),
            "the Claude Desktop entry must be copy-pasteable:\n{rendered}"
        );
        assert!(
            rendered.contains("mcpServers") && rendered.to_lowercase().contains("restart"),
            "the Desktop instructions must say where it goes and to restart:\n{rendered}"
        );
        // §11.1: the trust boundary is stated plainly at mount time.
        assert!(
            rendered.contains("run on alice's machine"),
            "the trust-boundary line must survive:\n{rendered}"
        );
    }

    #[test]
    fn client_instruction_lines_render_every_granted_service() {
        // Multiple grants: one Claude Code line each, and a comma-joined Desktop block (valid JSON
        // once pasted between the braces of `mcpServers` — every entry but the last is comma'd).
        let services = vec!["notes".to_string(), "kb".to_string()];
        let rendered = client_instruction_lines("alice", &services).join("\n");
        assert!(rendered.contains("claude mcp add alice-notes -- mcpmesh connect alice/notes"));
        assert!(rendered.contains("claude mcp add alice-kb -- mcpmesh connect alice/kb"));
        assert!(
            rendered.contains(r#""connect", "alice/notes"]},"#),
            "all but the last Desktop entry are comma-terminated:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""connect", "alice/kb"]}"#)
                && !rendered.contains(r#""connect", "alice/kb"]},"#),
            "the last Desktop entry has no trailing comma:\n{rendered}"
        );
    }

    #[test]
    fn client_instruction_lines_are_empty_without_services() {
        // Nothing granted → nothing to instruct (the caller prints no block at all, rather than a
        // dangling "add this to your config" with no entry under it).
        assert!(client_instruction_lines("alice", &[]).is_empty());
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
