//! Hermetic stdio MCP stub for the spawn-backend tests (std-only — no serde, no
//! network, no python3/node). Reads newline-delimited JSON-RPC from stdin and
//! answers two methods, proving the two things the `run` backend must deliver.
//!
//! `initialize` draws a fixed InitializeResult (the pump forwards the first
//! stripped `initialize` line, then relays the reply). `tools/call` draws a result
//! echoing `params.arguments.text` AND the injected identity env — `MCPMESH_PEER_NAME`
//! (`peer_name`), `MCPMESH_PEER_USER` (`peer_user`, roster mode only) and
//! `MCPMESH_PEER_GROUPS` (`peer_groups`, comma-joined) — so the tests prove the full
//! identity env injection (roster user_id + groups, not just the nickname). It loops until
//! stdin EOF.
//!
//! Crude string extraction is deliberate: the test controls the exact wire shape,
//! so a full JSON parser would be dead weight here.
use std::io::{BufRead, Write};

/// The slice of `s` immediately after the first occurrence of `key`.
fn slice_after<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    s.find(key).map(|i| &s[i + key.len()..])
}

/// Raw JSON token after `"id":`, up to the next `,` or `}` (a number or a quoted
/// string — spliced back into the reply verbatim so the id round-trips).
fn extract_id(line: &str) -> String {
    match slice_after(line, "\"id\":") {
        Some(rest) => rest
            .split([',', '}'])
            .next()
            .unwrap_or("null")
            .trim()
            .to_string(),
        None => "null".to_string(),
    }
}

/// Value of `"text":"..."` (no escape handling — the test controls the input).
fn extract_text(line: &str) -> String {
    match slice_after(line, "\"text\":\"") {
        Some(rest) => rest.split('"').next().unwrap_or("").to_string(),
        None => String::new(),
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let id = extract_id(&line);
        let resp = if line.contains("\"method\":\"initialize\"") {
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{}},\"serverInfo\":{{\"name\":\"echo-stub\",\"version\":\"0.1.0\"}}}}}}"
            )
        } else if line.contains("\"method\":\"tools/call\"") {
            let text = extract_text(&line);
            // The injected identity env — `peer_user`/`peer_groups` are empty in pairing mode
            // (no user_id, no groups) and populated in roster mode, proving the superset injection.
            let peer = std::env::var("MCPMESH_PEER_NAME").unwrap_or_default();
            let user = std::env::var("MCPMESH_PEER_USER").unwrap_or_default();
            let groups = std::env::var("MCPMESH_PEER_GROUPS").unwrap_or_default();
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{text}\"}}],\"peer_name\":\"{peer}\",\"peer_user\":\"{user}\",\"peer_groups\":\"{groups}\"}}}}"
            )
        } else {
            continue;
        };
        if writeln!(stdout, "{resp}").is_err() || stdout.flush().is_err() {
            break;
        }
    }
}
