//! The `connect` stdio proxy — the ONLY thing an AI client ever runs:
//! `mcpmesh connect <peer>/<service>`. It is a thin, transparent pipe: `ensure_daemon()`, send
//! one `OpenSession`, then pump the MCP session verbatim between this process's stdin/stdout
//! and the daemon's control socket (which the daemon has turned into a raw session pipe). The
//! daemon owns dialing, the session, and pooling; the proxy interprets nothing (it pumps,
//! never inspects). When a
//! session is unreachable or refused pre-response, the daemon relays a `-32055`/`-32054`
//! frame that flows straight to stdout, so the AI client gets a well-formed answer rather
//! than a hang; a session severed mid-stream instead surfaces as a clean EOF (the pipe ends,
//! stdout closes). No mid-session re-dial — the AI client re-invokes if it wants a fresh
//! session.
//!
//! The config-entry authority lives here too: `mcp_servers_entry` mints the one `mcpServers`
//! entry shape a client config needs, [`client_instruction_lines`] renders the plain-language
//! "here is exactly what to do next" block (including the trust-boundary line) that
//! `pair` and `use` print, and [`split_target`] parses the shared `<peer>/<service>` argument.
//!
//! We PRINT those instructions rather than writing a third-party app's config file: the config
//! shapes and locations are the AI clients' to change, a half-working writer that silently targets
//! the wrong file is worse than no writer, and a human who pastes the line knows what they mounted.
use anyhow::{Context, Result};
use mcpmesh_net::errors::{ERR_SERVICE, ERR_UNREACHABLE};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use serde_json::Value;
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

/// One `mcpServers` entry that mounts `<peer>/<service>` through the proxy, rendered as
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
/// takes. It opens with the trust boundary ("runs on their machine") — this is the mount-time
/// moment that line exists for. Surface-clean (no transport vocabulary): petnames, service
/// names, and the `mcpmesh connect` command only — never an endpoint id.
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
///
/// One human-facing exception to full transparency (issue #10): when stdout is a TERMINAL —
/// so a person, not an MCP client, ran `connect` — and the session ended on a
/// mesh-synthesized refusal frame, one plain hint line goes to STDERR. The stdout protocol,
/// the relayed frame, and the exit-0 semantics the real consumer depends on are untouched.
pub async fn run(peer: String, service: String) -> Result<()> {
    let client = ensure_daemon().await?;
    let (control_reader, control_writer) = client.open_session(peer.clone(), service).await?;
    let ended_on_mesh_error = pump_stdio(
        tokio::io::stdin(),
        tokio::io::stdout(),
        control_reader,
        control_writer,
    )
    .await?;
    if ended_on_mesh_error.is_some() && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        eprintln!("{}", unreachable_hint_line(&peer));
    }
    Ok(())
}

/// The one stderr line a human at a terminal gets when their `connect` session ended on a
/// mesh-synthesized refusal (issue #10). Pure so it is unit-testable. Surface-clean:
/// the peer petname + porcelain commands only.
fn unreachable_hint_line(peer: &str) -> String {
    format!(
        "peer unreachable — is {peer} online? ('mcpmesh status' shows reachability). \
         This command is normally run by your MCP client."
    )
}

/// `Some(code)` when `frame` is a mesh-SYNTHESIZED pre-response refusal — the `-32055`
/// unreachable / `-32054` service-refusal pair carrying the mandatory `data.source ==
/// "mcpmesh"` marker (the platform's synthesized-error signature). A backend's own JSON-RPC
/// errors (no marker) and the other
/// platform codes (e.g. a mid-session rate limit) return `None`: only the two
/// session-refusing shapes warrant the human hint.
fn mesh_error_code(frame: &Value) -> Option<i64> {
    let error = frame.get("error")?;
    if error.get("data")?.get("source")?.as_str()? != "mcpmesh" {
        return None;
    }
    let code = error.get("code")?.as_i64()?;
    (code == ERR_UNREACHABLE || code == ERR_SERVICE).then_some(code)
}

/// Bidirectionally pump MCP frames between the AI client's stdio and the control connection
/// (one codec everywhere). Generic over the four byte substrates so an in-memory variant
/// is testable without a subprocess. The two directions run as independent concurrent loops —
/// the same anti-deadlock discipline as the backends' pump. Teardown is driven by the CONTROL
/// side closing (clean EOF on remote close); the stdin direction ending only
/// half-closes toward the daemon and then drains, because a synthesized -32055 can already be
/// buffered on the control socket when the stdin->control write hits the dead pipe — the AI
/// client must still be handed that well-formed answer, not a bare EOF.
///
/// Returns the [`mesh_error_code`] of the LAST frame relayed to stdout when the session ended
/// on a mesh-synthesized refusal, else `None` — the caller's seam for the human TTY hint
/// (issue #10). Purely observational: every frame still flows verbatim.
pub(crate) async fn pump_stdio<SI, SO, CR, CW>(
    stdin: SI,
    mut stdout: SO,
    mut control_reader: FrameReader<CR>,
    mut control_writer: CW,
) -> Result<Option<i64>>
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
    // a synthesized -32055/-32054 error frame verbatim, remembering whether the
    // LAST relayed frame was such a refusal (reset by any later ordinary frame).
    let to_stdout = async {
        let mut ended_on: Option<i64> = None;
        loop {
            match control_reader.next().await {
                Ok(Some(Inbound::Frame(frame))) => {
                    ended_on = mesh_error_code(&frame);
                    if write_frame(&mut stdout, &frame).await.is_err() {
                        break; // stdout closed
                    }
                }
                Ok(Some(Inbound::Violation(_))) => break,
                Ok(None) | Err(_) => break, // remote closed / IO error → clean EOF
            }
        }
        ended_on
    };
    let ended_on = tokio::select! {
        () = to_control => None, // unreachable: to_control parks forever after its half-close
        ended = to_stdout => ended,
    };
    let _ = stdout.shutdown().await;
    Ok(ended_on)
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
        // The rendered entry is real JSON with the documented wire shape: wrap it in the braces it is pasted
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
        // The trust boundary is stated plainly at mount time.
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

    /// The proxy pump is transparent both ways: a frame written to "stdin" reaches the
    /// control connection unmodified, and a frame the control side sends reaches "stdout"
    /// unmodified — here a synthesized -32055 error frame (the unreachable/severed path),
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
            // …and the daemon closing in turn ends the pump (clean EOF). The last frame
            // relayed was the synthesized -32055, so the pump reports it (the TTY-hint seam).
            drop(daemon_reader);
            drop(dc_w);
            assert_eq!(pump.await.unwrap().unwrap(), Some(-32055));
        })
        .await
        .expect("pump test timed out");
    }

    /// The unreachable race: the daemon can synthesize a -32055 and close the
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
                assert_eq!(pump.await.unwrap().unwrap(), Some(-32055));
            }
        })
        .await
        .expect("drain test timed out");
    }

    /// A session that ends on an ORDINARY frame (a real MCP response, then clean close)
    /// reports no mesh error — the human hint must never fire on a successful session.
    #[tokio::test]
    async fn clean_session_end_reports_no_mesh_error() {
        timeout(Duration::from_secs(10), async {
            let (a_in, b_in) = duplex(64 * 1024);
            let (a_out, b_out) = duplex(64 * 1024);
            let (pc, dc) = duplex(64 * 1024);
            let (pc_r, pc_w) = split(pc);
            let (dc_r, mut dc_w) = split(dc);

            let resp = json!({"jsonrpc":"2.0","id":1,"result":{"ok":true}});
            write_frame(&mut dc_w, &resp).await.unwrap();
            drop(dc_w);
            drop(dc_r);

            let pump = tokio::spawn(pump_stdio(
                b_in,
                b_out,
                FrameReader::new(pc_r, MAX_FRAME_BYTES),
                pc_w,
            ));
            let mut a_out_reader = FrameReader::new(a_out, MAX_FRAME_BYTES);
            match a_out_reader.next().await.unwrap().unwrap() {
                Inbound::Frame(f) => assert_eq!(f, resp),
                other => panic!("expected the response frame, got {other:?}"),
            }
            drop(a_in);
            assert_eq!(pump.await.unwrap().unwrap(), None);
        })
        .await
        .expect("clean-end test timed out");
    }

    #[test]
    fn mesh_error_code_matches_only_the_synthesized_refusal_pair() {
        // The two session-refusing shapes, WITH the synthesized-error marker → Some.
        let unreachable = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32055,
            "message":"peer unreachable","data":{"source":"mcpmesh"}}});
        assert_eq!(mesh_error_code(&unreachable), Some(-32055));
        let refused = json!({"jsonrpc":"2.0","id":null,"error":{"code":-32054,
            "message":"unknown or unauthorized service","data":{"source":"mcpmesh"}}});
        assert_eq!(mesh_error_code(&refused), Some(-32054));
        // A backend's OWN JSON-RPC error (no source marker) is the service's business.
        let backend = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32055,"message":"x"}});
        assert_eq!(mesh_error_code(&backend), None);
        // Another platform code (a mid-session rate limit) does not end a session.
        let limited = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32053,
            "message":"rate limited","data":{"source":"mcpmesh"}}});
        assert_eq!(mesh_error_code(&limited), None);
        // An ordinary response is no error at all.
        assert_eq!(
            mesh_error_code(&json!({"jsonrpc":"2.0","id":1,"result":{}})),
            None
        );
    }

    #[test]
    fn unreachable_hint_line_names_the_peer_and_the_status_command_only() {
        let line = unreachable_hint_line("alice");
        assert!(
            line.contains("is alice online?") && line.contains("'mcpmesh status'"),
            "the hint names the peer and the exact next command: {line}"
        );
        assert!(
            line.contains("normally run by your MCP client"),
            "the hint explains who normally runs connect: {line}"
        );
        // No transport vocabulary in a human-facing line.
        for term in ["ALPN", "endpoint", "iroh", "dial", "-32055"] {
            assert!(!line.contains(term), "hint leaked '{term}': {line}");
        }
    }
}
