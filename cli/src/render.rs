//! Every string the porcelain prints, as pure unit-tested render functions. The binary's
//! verbs (`main.rs`) do the I/O; this module owns the wording, so every user-facing line is
//! testable without a daemon.
//!
//! Output discipline (the SECURITY.md bar): no transport vocabulary, raw endpoint ids, keys,
//! or protocol names ever reach a human. Nicknames, service names, plain status words, and
//! numbers only — the deliberate exceptions are the opaque copyable artifacts (`mcpmesh-invite:`
//! lines and friends) and the short device/org fingerprints.

use mcpmesh_local_api::{
    AuditKind, BackendKind, Hello, InviteResult, PairResult, PeerInfo, PeerReachability,
    PresencePeer, RecentPairing, RosterInstallResult, RosterStatus, StatusResult, StreamFrame,
};

use crate::{client, proxy, util};

/// The one worked `serve` example the CLI shows — shared by clap's `after_help` and the
/// `status` next-steps footer, so the two cannot drift.
///
/// `serve <name> -- <command>` is mechanism-first: it runs ANY stdio MCP server and has no opinion
/// about which. That generality is a wall for someone who doesn't already have one running, so the
/// example is deliberately a COMPLETE command needing nothing but npx, sharing a folder — the most
/// legible thing mcpmesh does, and a real MCP server rather than an mcpmesh-specific toy.
pub const SERVE_EXAMPLE: &str =
    "mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes";

/// Render an error that is about to reach a human — the ONE rendering path every verb's
/// failure flows through (issue #10). Pure so it is unit-testable.
///
/// A control-API failure prints its `message` as a plain sentence — NEVER the raw JSON-RPC
/// error object (was previously `Error: control API error: {json}`), and known daemon
/// failure shapes are translated to user language at this seam (`control_error_lines`).
/// Everything else keeps the anyhow context chain (context layers that merely duplicated
/// their root cause were dropped at the call sites instead).
pub fn error_lines(err: &anyhow::Error) -> Vec<String> {
    for cause in err.chain() {
        if let Some(client::ClientError::Api(value)) = cause.downcast_ref::<client::ClientError>() {
            return control_error_lines(value);
        }
    }
    let mut lines = vec![format!("Error: {err}")];
    let mut causes = err.chain().skip(1).peekable();
    if causes.peek().is_some() {
        lines.push(String::new());
        lines.push("Caused by:".to_string());
        for cause in causes {
            lines.push(format!("    {cause}"));
        }
    }
    lines
}

/// Render a control-API (JSON-RPC) error object for a human: unwrap `error.message`, mapping
/// the known daemon failure shapes to user language (issue #10). The daemon's failed-dial
/// pair message ("could not dial the inviter's machine") is mechanism-flavored and misses the
/// common self-redeem cause — this porcelain seam owns the human explanation.
/// The wire's `"{method} failed: "` framing (the shape every control arm answers with) is
/// stripped first: `peer_remove` is a method name, not a command the user typed — the
/// remainder is the daemon's own user-facing sentence.
fn control_error_lines(error: &serde_json::Value) -> Vec<String> {
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let message = strip_wire_framing(message);
    if message.contains("dial the inviter") {
        return vec![
            "Error: could not reach the inviter's machine — are they online?".to_string(),
            "(You cannot redeem your own invite on the machine that minted it — run \
             `mcpmesh pair` on the other machine.)"
                .to_string(),
        ];
    }
    if message.is_empty() {
        // A message-less error frame still never prints as raw JSON.
        return vec![
            "Error: the daemon reported an unexpected error — run 'mcpmesh doctor' to diagnose"
                .to_string(),
        ];
    }
    vec![format!("Error: {message}")]
}

/// Strip the control wire's `"{method} failed: "` framing from an error message. The prefix
/// is recognized only when the token before the FIRST `" failed: "` is a bare method name
/// (lowercase + underscores, the `respond` shape in control.rs) — anything else passes
/// through untouched, so a daemon sentence that merely contains the words keeps them.
fn strip_wire_framing(message: &str) -> &str {
    match message.split_once(" failed: ") {
        Some((method, rest))
            if !method.is_empty()
                && !rest.is_empty()
                && method.bytes().all(|b| b == b'_' || b.is_ascii_lowercase()) =>
        {
            rest
        }
        _ => message,
    }
}

/// Render the `mcpmesh invite` output block. Pure so it is unit-testable: the
/// `mcpmesh-invite:` line is the copyable artifact (the one opaque artifact the output
/// discipline deliberately permits printing), and the services are listed from the REQUESTED
/// `services` arg (what the operator asked to grant). No peer endpoint id appears — the only
/// id-bearing artifact is the opaque invite line itself.
pub fn invite_lines(invite: &InviteResult, services: &[String], now: u64) -> Vec<String> {
    vec![
        format!(
            "One-time invite (expires {}). Share it out-of-band:",
            friendly_expiry(invite.expires_at_epoch, now)
        ),
        format!("  {}", invite.invite_line),
        format!("Whoever redeems it can access: {}", services.join(", ")),
        String::new(),
        "Next: send them that line over any channel. They redeem it with `mcpmesh pair <line>`,"
            .to_string(),
        "which prints a short safety code — run `mcpmesh status` to see yours and confirm the two"
            .to_string(),
        "match, out loud. Same words = the pairing is authentic.".to_string(),
    ]
}

/// Render the `mcpmesh pair` success output: the SAS, the ceremony as the next step, what the
/// pairing just unlocked, and EXACTLY how to use it from an AI client (the block
/// [`proxy::client_instruction_lines`] owns). Pure so it is unit-testable. Surface-clean: it
/// carries only the peer nickname, the display-only SAS, the local `<peer>/<service>` mount names,
/// and the `mcpmesh connect` command — NEVER a raw endpoint id (the daemon never sends one in a
/// `PairResult`).
///
/// The ceremony line comes FIRST and says "next" deliberately: confirming the code is what makes
/// the pairing authentic, and it must happen before the service is used, not after.
pub fn pair_lines(result: &PairResult) -> Vec<String> {
    let peer = &result.peer_nickname;
    let mut lines = vec![
        format!("Paired with {peer} — code: {}", result.sas_code),
        format!(
            "Next: confirm this code matches what {peer} sees, out loud (they see it under \
             `mcpmesh status`). Same words = the pairing is authentic."
        ),
    ];
    // Defensive: a real pairing always grants ≥1 service (invite requires one), but never dangle a
    // "You can now use:" with nothing after it.
    if result.services.is_empty() {
        return lines;
    }
    let mounts = result
        .services
        .iter()
        .map(|s| format!("{peer}/{s}"))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(String::new());
    lines.push(format!("You can now use: {mounts}"));
    lines.push(String::new());
    lines.extend(proxy::client_instruction_lines(peer, &result.services));
    lines
}

/// A friendly relative expiry string ("in 24h" / "in 3h" / "in 45m" / "soon") from an absolute
/// epoch-seconds expiry vs. `now`. Hours are ROUNDED to the nearest hour so a freshly minted 24h
/// invite reads "in 24h" despite the second or two of mint→print latency (86398s rounds to 24h,
/// not a jarring "in 23h"). Kept deliberately simple (no date crate).
fn friendly_expiry(expires_at_epoch: u64, now: u64) -> String {
    let remaining = expires_at_epoch.saturating_sub(now);
    if remaining < 60 {
        return "soon".to_string();
    }
    if remaining < 3600 {
        let mins = (remaining + 30) / 60; // round to nearest minute
        return format!("in {mins}m");
    }
    let hours = (remaining + 1800) / 3600; // round to nearest hour
    format!("in {hours}h")
}

/// A friendly relative age ("just now" / "5m ago" / "3h ago" / "2d ago") from an absolute
/// epoch-seconds stamp vs. `now` — the mirror of [`friendly_expiry`], same no-date-crate
/// simplicity. A future stamp (clock skew) saturates to "just now" rather than underflowing.
fn friendly_age(epoch: u64, now: u64) -> String {
    let elapsed = now.saturating_sub(epoch);
    if elapsed < 60 {
        return "just now".to_string();
    }
    if elapsed < 3600 {
        return format!("{}m ago", elapsed / 60);
    }
    if elapsed < 24 * 3600 {
        return format!("{}h ago", elapsed / 3600);
    }
    format!("{}d ago", elapsed / (24 * 3600))
}

/// Render the `roster install` confirmation. Pure so it is unit-testable. Surface-clean:
/// only the org_id, serial, and severed-session COUNT — all roster-status vocabulary — never
/// a key, endpoint id, or path. Pluralizes "session"/"sessions" on the count.
pub fn roster_install_line(result: &RosterInstallResult) -> String {
    let sessions = if result.severed == 1 {
        "session"
    } else {
        "sessions"
    };
    format!(
        "Installed roster for org '{}' (serial {}). Severed {} live {sessions}.",
        result.org_id, result.serial, result.severed
    )
}

/// Render `status` in plain language (see the module doc for the output discipline this
/// upholds). Empty registries read naturally ("no services configured" / "no peers yet").
pub fn render_status(
    fingerprint: &str,
    hello: &Hello,
    status: &StatusResult,
    has_roster_url: bool,
) {
    println!(
        "{} v{} · stack {}",
        hello.api, hello.api_version, hello.stack_version
    );
    println!("device {fingerprint}");
    // This node's own self-sovereign identity (an opaque user id, not a key): the stable
    // id that all of this person's devices resolve to. Absent only when no user key exists.
    if let Some(user_id) = &status.self_user_id {
        println!("identity {user_id}");
    }

    println!();
    if status.services.is_empty() {
        println!("no services configured");
    } else {
        println!("serving:");
        for svc in &status.services {
            let kind = backend_kind_label(svc.backend);
            let allowed = if svc.allow.is_empty() {
                "no one yet".to_owned()
            } else {
                svc.allow.join(", ")
            };
            println!("  {} · {kind} · allowed: {allowed}", svc.name);
        }
    }

    println!();
    if status.peers.is_empty() {
        println!("no peers yet");
    } else {
        println!("peers:");
        for peer in &status.peers {
            let services = if peer.services.is_empty() {
                "none".to_owned()
            } else {
                peer.services.join(", ")
            };
            // Append the peer's proven self-sovereign user_id when it presented a verified binding at
            // pairing — otherwise the peer is nickname-only (nothing extra to show).
            match &peer.user_id {
                Some(user_id) => {
                    println!("  {} · services: {services} · {user_id}", peer.name)
                }
                None => println!("  {} · services: {services}", peer.name),
            }
        }
    }

    // The reachability block (pairing-mode liveness): one line per paired peer with its advisory
    // online/offline flag from the on-demand probe cache, plus the last RTT when online.
    // Empty → nothing prints.
    if !status.reachability.is_empty() {
        println!();
        println!("reachability:");
        for line in reachability_lines(&status.reachability) {
            println!("{line}");
        }
    }

    // The recent-pairings block (the pairing-ceremony surface): the INVITER's half of "both humans
    // compare the code" — each pairing this daemon accepted since it started, newest first, with
    // the SAME display-only SAS the redeemer's `pair` printed. In-memory on the daemon (a restart
    // clears it); empty → nothing prints. Surface-clean: nickname + SAS words + a friendly
    // age ONLY — never an endpoint id.
    if !status.recent_pairings.is_empty() {
        println!();
        println!("recent pairings (confirm the code with the other side):");
        for line in recent_pairing_lines(&status.recent_pairings, util::epoch_now_u64()) {
            println!("{line}");
        }
    }

    // The roster block: printed ONLY in roster mode (a pure-pairing daemon sends `roster: None`,
    // so nothing prints).
    if let Some(roster) = &status.roster {
        println!();
        for line in roster_status_lines(roster, has_roster_url) {
            println!("{line}");
        }
    }

    // The reachable-peers block (the advisory presence read): one line per roster device with
    // its live/offline flag. Printed only when the roster surfaced devices (empty → nothing). ADVISORY
    // — `online` is a display flag; every listed device is a dial candidate regardless of it.
    if !status.presence.is_empty() {
        println!();
        println!("reachable:");
        for line in presence_lines(&status.presence) {
            println!("{line}");
        }
    }

    // The next-steps footer, last: whatever this node can actually DO from here, as exact commands.
    // Empty → nothing prints (a node with nothing to nudge shows a clean status).
    let next = next_steps_lines(status);
    if !next.is_empty() {
        println!();
        for line in next {
            println!("{line}");
        }
    }
}

/// Render the reachability block of `status`: one line per paired peer, `  <nickname> · <state>`
/// with the last RTT when online. Pure so it is unit-testable. A never-probed peer reads
/// "checking…" — a refresh is already in flight, and a bare ellipsis would read as a rendering
/// glitch rather than a state (issue #12). Surface-clean: nickname + a status word + a latency
/// NUMBER only.
pub fn reachability_lines(reachability: &[PeerReachability]) -> Vec<String> {
    reachability
        .iter()
        .map(|r| {
            let label = match (r.reachable, r.age_secs) {
                (_, None) => "checking…", // never probed; the first probe is in flight
                (true, _) => "online",
                (false, _) => "offline",
            };
            match r.rtt_ms {
                Some(ms) if r.reachable => format!("  {} · {label} · {ms}ms", r.name),
                _ => format!("  {} · {label}", r.name),
            }
        })
        .collect()
}

/// The `mcpmesh use <peer>/<service>` refusal message when the target names an unknown peer or
/// a service that peer does not share — or `None` when the target resolves. Pure over the
/// daemon's peer list so the message shapes are unit-testable (issue #12). Mirrors the invite
/// refusal style: state what IS known and name the exact next command.
pub fn use_target_error(peer: &str, service: &str, peers: &[PeerInfo]) -> Option<String> {
    let Some(known) = peers.iter().find(|p| p.name == peer) else {
        let names: Vec<&str> = peers.iter().map(|p| p.name.as_str()).collect();
        return Some(if names.is_empty() {
            format!(
                "no paired peer named '{peer}' — nobody is paired yet; redeem an invite with \
                 'mcpmesh pair <invite>'"
            )
        } else {
            format!(
                "no paired peer named '{peer}' — your peers: {} (see 'mcpmesh status')",
                names.join(", ")
            )
        });
    };
    if known.services.iter().any(|s| s == service) {
        return None;
    }
    Some(if known.services.is_empty() {
        format!(
            "'{peer}' does not share any services with you yet — ask them to send a new invite \
             naming one"
        )
    } else {
        format!(
            "'{peer}' does not share a service named '{service}' — they share: {} \
             (see 'mcpmesh status')",
            known.services.join(", ")
        )
    })
}

/// Render the `status` next-steps footer: the exact command for each thing this node can do from
/// where it currently is. Pure so it is unit-testable. Surface-clean: nicknames + service
/// names + porcelain commands only.
///
/// Each step is offered only when it is genuinely the user's next move, so a fully configured node
/// prints no nag — the footer is guidance, not decoration.
pub fn next_steps_lines(status: &StatusResult) -> Vec<String> {
    let mut steps = Vec::new();

    // Something reachable → how to actually put it in an AI client (the question `use` answers).
    if let Some((peer, service)) = status
        .peers
        .iter()
        .find_map(|p| p.services.first().map(|s| (&p.name, s)))
    {
        steps.push(format!(
            "  Use {peer}/{service} from your AI client: `mcpmesh use {peer}/{service}`"
        ));
    }

    if status.services.is_empty() {
        steps.push(
            "  Share one of your MCP servers: `mcpmesh serve <name> -- <command that runs it>`"
                .to_string(),
        );
        // Don't assume they HAVE one: a complete command that needs nothing but npx.
        steps.push(format!(
            "    No MCP server yet? Share a folder: `{SERVE_EXAMPLE}`"
        ));
    } else if let Some(svc) = status.services.iter().find(|s| s.allow.is_empty()) {
        // Serving, but nobody is admitted — the service is invisible until someone is invited.
        steps.push(format!(
            "  Nobody can reach '{}' yet: `mcpmesh invite {}`",
            svc.name, svc.name
        ));
    }

    if status.peers.is_empty() {
        steps.push("  Someone sent you an invite? `mcpmesh pair mcpmesh-invite:…`".to_string());
    }

    if steps.is_empty() {
        return steps;
    }
    let mut lines = vec!["next steps:".to_string()];
    lines.extend(steps);
    lines
}

/// Render the recent-pairings block of `status`: one line per completed inviter-side pairing,
/// `  <nickname> · code: <sas> · <age>`. Pure so it is unit-testable. Surface-clean:
/// the peer nickname, the display-only SAS words (the pairing-ceremony artifact, like
/// [`pair_lines`]'s), and a friendly age ONLY — a `RecentPairing` carries no endpoint id, so the
/// lines can't either.
pub fn recent_pairing_lines(pairings: &[RecentPairing], now: u64) -> Vec<String> {
    pairings
        .iter()
        .map(|p| {
            format!(
                "  {} · code: {} · {}",
                p.peer_nickname,
                p.sas_code,
                friendly_age(p.paired_at_epoch, now)
            )
        })
        .collect()
}

/// Render the advisory presence block of `status`: one line per reachable roster device,
/// `user_id · device_label · role · (online|offline)`. Pure so it is unit-testable. Surface-clean:
/// FLAT vocabulary ONLY — user_id, device_label, role, and a plain online/offline word;
/// never an endpoint id / key / hash / protocol name.
pub fn presence_lines(presence: &[PresencePeer]) -> Vec<String> {
    presence
        .iter()
        .map(|p| {
            format!(
                "  {} · {} · {} · {}",
                p.user_id,
                p.device_label,
                p.role,
                if p.online { "online" } else { "offline" }
            )
        })
        .collect()
}

/// Render the roster-mode block of `status`. Pure so it is unit-testable. Surface-clean:
/// only roster/ceremony vocabulary — org_id, serial, the plain state word, and the org-root
/// FINGERPRINT in short words. The `org root:` line is OMITTED when the fingerprint is empty (a
/// missing/unparseable pin degrades gracefully), so there is never a dangling label.
pub fn roster_status_lines(roster: &RosterStatus, has_roster_url: bool) -> Vec<String> {
    let mut lines = vec![format!(
        "roster: org {} · serial {} · {}",
        roster.org_id, roster.serial, roster.state
    )];
    if !roster.org_root_fingerprint.is_empty() {
        lines.push(format!(
            "  org root: {} (confirm out-of-band)",
            roster.org_root_fingerprint
        ));
    }
    // URL-less degrade hint: a roster-mode node with NO `[roster].url` has no authenticated
    // channel to re-confirm currency, so it degrades toward stale after `max_staleness`.
    // This is CORRECT (a beaconless node fails toward degraded) — the hint prevents operator surprise.
    if !has_roster_url {
        lines.push(
            "hint: no roster URL configured — this node degrades after max_staleness with no way \
             to re-confirm currency; set [roster].url"
                .to_string(),
        );
    }
    lines
}

/// Plain-language label for a backend kind — the KIND only (never the command/path).
fn backend_kind_label(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Run => "run",
        BackendKind::Socket => "socket",
    }
}

/// The snake_case wire word for an [`AuditKind`] — how a record's class reads on a `watch` line
/// (the same word the JSONL log carries, so the live view and `internal audit` agree).
fn kind_label(kind: AuditKind) -> &'static str {
    match kind {
        AuditKind::SessionOpen => "session_open",
        AuditKind::SessionClose => "session_close",
        AuditKind::Request => "request",
        AuditKind::BlobFetch => "blob_fetch",
        AuditKind::Trust => "trust",
    }
}

/// Render one typed `subscribe` stream frame to a display line. Pure so the rendering is
/// unit-testable without a live daemon. Optional record fields degrade to an empty piece (a bare
/// trust event has no peer/service — never a dangling separator). Surface-clean: only
/// nicknames/service names/user_ids/numbers appear — the stream carries no endpoint id.
pub fn render_frame(frame: &StreamFrame) -> String {
    match frame {
        StreamFrame::Snapshot {
            active_sessions,
            reachability,
        } => format!(
            "snapshot: {} active session(s), {} peer(s) known",
            active_sessions.len(),
            reachability.len(),
        ),
        StreamFrame::Event { record } => {
            let peer = record
                .peer
                .as_deref()
                .map(|p| format!("{p} "))
                .unwrap_or_default();
            let service = record
                .service
                .as_deref()
                .map(|s| format!("→ {s}"))
                .unwrap_or_default();
            // `status` is absent on a normal open/close but present ("error"/"ok"/"denied") on
            // records like a failed dial (a `session_open` with `status:"error"`) — surface it so
            // a failed reach doesn't render identically to a real session open.
            let status = record
                .status
                .as_deref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            let line = format!(
                "[{}] {} {peer}{service}",
                record.ts,
                kind_label(record.kind)
            );
            // A bare event (no peer/service) must not dangle a trailing separator/space; the
            // status suffix (when present) follows the trimmed line.
            format!("{}{status}", line.trim_end())
        }
        StreamFrame::Lagged { dropped } => {
            format!("(lagged {dropped} events — reconnect for a fresh snapshot)")
        }
    }
}

#[cfg(test)]
mod tests {
    use mcpmesh_local_api::{PeerInfo, ServiceInfo};
    use serde_json::json;

    use super::*;

    const DAY: u64 = 24 * 60 * 60;

    #[test]
    fn invite_block_has_the_expected_shape() {
        let invite = InviteResult {
            invite_line: "mcpmesh-invite:MFRGGZDF".into(),
            expires_at_epoch: 1_000_000 + DAY,
        };
        let lines = invite_lines(&invite, &["notes".to_string()], 1_000_000);
        assert_eq!(
            lines[..3],
            [
                "One-time invite (expires in 24h). Share it out-of-band:".to_string(),
                "  mcpmesh-invite:MFRGGZDF".to_string(),
                "Whoever redeems it can access: notes".to_string(),
            ]
        );
        // The next exact instruction — what the OTHER person runs, and the ceremony that follows.
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("Next:") && rendered.contains("mcpmesh pair"),
            "the invite must name the redeemer's exact next command:\n{rendered}"
        );
        assert!(
            rendered.contains("mcpmesh status"),
            "the invite must point at where the inviter confirms the code:\n{rendered}"
        );
    }

    #[test]
    fn invite_block_lists_multiple_services() {
        let invite = InviteResult {
            invite_line: "mcpmesh-invite:X".into(),
            expires_at_epoch: 500 + DAY,
        };
        let lines = invite_lines(&invite, &["notes".to_string(), "kb".to_string()], 500);
        assert_eq!(lines[2], "Whoever redeems it can access: notes, kb");
        // The copyable artifact is present and prefixed by the invite scheme.
        assert!(lines[1].contains("mcpmesh-invite:"));
    }

    #[test]
    fn pair_lines_render_the_sas_and_mount_targets() {
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into()],
            app_label: None,
            peer_user_id: None,
        };
        let lines = pair_lines(&result);
        assert_eq!(lines[0], "Paired with alice — code: tango-fig-42");
        // The SAS line is exactly `... — code: <words>` (the human-checkable ceremony format).
        assert!(lines[0].contains("code: tango-fig-42"));
        let rendered = lines.join("\n");
        // The NEXT exact instruction: the ceremony comes before use.
        assert!(
            rendered.contains("Next: confirm this code matches what alice sees"),
            "pair must name the ceremony as the next step:\n{rendered}"
        );
        assert!(
            rendered.contains("You can now use: alice/notes"),
            "pair must name the mount target:\n{rendered}"
        );
        // …and then EXACTLY how to use it — the block `setup` used to half-write.
        assert!(
            rendered.contains("claude mcp add alice-notes -- mcpmesh connect alice/notes")
                && rendered.contains("claude_desktop_config.json"),
            "pair must print the client instructions inline:\n{rendered}"
        );
    }

    #[test]
    fn pair_lines_join_multiple_mount_targets_as_peer_slash_service() {
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "a-b-c".into(),
            services: vec!["notes".into(), "kb".into()],
            app_label: None,
            peer_user_id: None,
        };
        let rendered = pair_lines(&result).join("\n");
        assert!(
            rendered.contains("You can now use: alice/notes, alice/kb"),
            "both grants are named as mount targets:\n{rendered}"
        );
        // Both get their own copy-pasteable Claude Code line.
        assert!(
            rendered.contains("claude mcp add alice-notes -- mcpmesh connect alice/notes")
                && rendered.contains("claude mcp add alice-kb -- mcpmesh connect alice/kb"),
            "every granted service gets its own instruction:\n{rendered}"
        );
    }

    #[test]
    fn pair_lines_leak_no_endpoint_id() {
        // The pair porcelain shows the nickname, the SAS, and the local `<peer>/<service>`
        // mount names — all permitted pairing artifacts. It must NEVER contain a raw base32
        // endpoint id. A PairResult carries none, so the rendered lines can't either; assert it.
        let alice_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string();
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into()],
            app_label: None,
            peer_user_id: None,
        };
        let rendered = pair_lines(&result).join("\n");
        assert!(
            !rendered.contains(&alice_id),
            "pair output must not leak an EndpointId: {rendered}"
        );
        // No transport vocabulary either.
        for term in ["ALPN", "ticket", "mcpmesh/pair/1", "mcpmesh/mcp/1"] {
            assert!(!rendered.contains(term), "pair output leaked '{term}'");
        }
    }

    #[test]
    fn pair_lines_tolerate_an_empty_service_grant() {
        // Defensive shape: no dangling "You can mount:" when services is empty.
        let result = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "a-b-c".into(),
            services: vec![],
            app_label: None,
            peer_user_id: None,
        };
        let lines = pair_lines(&result);
        assert_eq!(lines[0], "Paired with alice — code: a-b-c");
        let rendered = lines.join("\n");
        // The ceremony still gets named — it is the one step that always applies.
        assert!(rendered.contains("Next: confirm this code matches what alice sees"));
        // But nothing was granted, so there is nothing to mount and nothing to instruct.
        assert!(
            !rendered.contains("You can now use") && !rendered.contains("claude mcp add"),
            "no dangling mount/instruction block with nothing granted:\n{rendered}"
        );
    }

    fn status_with(services: Vec<ServiceInfo>, peers: Vec<PeerInfo>) -> StatusResult {
        StatusResult {
            stack_version: "0".into(),
            services,
            peers,
            roster: None,
            presence: Vec::new(),
            self_user_id: None,
            recent_pairings: Vec::new(),
            reachability: Vec::new(),
        }
    }

    fn service(name: &str, allow: &[&str]) -> ServiceInfo {
        ServiceInfo {
            name: name.into(),
            allow: allow.iter().map(|s| s.to_string()).collect(),
            backend: BackendKind::Run,
        }
    }

    fn peer(name: &str, services: &[&str]) -> PeerInfo {
        PeerInfo {
            name: name.into(),
            services: services.iter().map(|s| s.to_string()).collect(),
            user_id: None,
        }
    }

    #[test]
    fn next_steps_on_a_fresh_node_name_both_directions() {
        // Nothing served, nobody paired: the two things a new user can actually do, spelled out.
        let rendered = next_steps_lines(&status_with(vec![], vec![])).join("\n");
        assert!(
            rendered.contains("mcpmesh serve <name> --"),
            "a fresh node must be told how to share:\n{rendered}"
        );
        assert!(
            rendered.contains("mcpmesh pair"),
            "a fresh node must be told how to redeem an invite:\n{rendered}"
        );
    }

    #[test]
    fn next_steps_offer_a_runnable_serve_example_to_someone_with_no_mcp_server() {
        // `serve <name> -- <command>` assumes you already HAVE an MCP server to point it at. Most
        // people do not, so the fresh-node footer also carries one complete, runnable command that
        // needs nothing but npx — a folder share, the thing mcpmesh is most obviously for.
        let rendered = next_steps_lines(&status_with(vec![], vec![])).join("\n");
        assert!(
            rendered.contains(SERVE_EXAMPLE),
            "a fresh node must offer a runnable serve example:\n{rendered}"
        );
        // It is a whole command, not a fragment: name, the `--` separator, and the server command.
        assert!(
            SERVE_EXAMPLE.contains("mcpmesh serve notes --")
                && SERVE_EXAMPLE.contains("@modelcontextprotocol/server-filesystem"),
            "the example must be complete and copy-pasteable: {SERVE_EXAMPLE}"
        );
    }

    #[test]
    fn next_steps_point_a_served_but_ungranted_service_at_invite() {
        // Serving, but nobody can reach it — the exact command that fixes that, naming the service.
        let rendered =
            next_steps_lines(&status_with(vec![service("notes", &[])], vec![])).join("\n");
        assert!(
            rendered.contains("mcpmesh invite notes"),
            "an ungranted service must be pointed at `invite <name>`:\n{rendered}"
        );
        // Already granted → nothing to nag about.
        let granted = next_steps_lines(&status_with(
            vec![service("notes", &["bob"])],
            vec![peer("bob", &[])],
        ))
        .join("\n");
        assert!(
            !granted.contains("mcpmesh invite notes"),
            "a granted service needs no invite nag:\n{granted}"
        );
    }

    #[test]
    fn next_steps_point_a_reachable_peer_service_at_use() {
        // Something is reachable → the exact command that turns it into a working AI-client mount.
        let rendered =
            next_steps_lines(&status_with(vec![], vec![peer("alice", &["notes"])])).join("\n");
        assert!(
            rendered.contains("mcpmesh use alice/notes"),
            "a reachable peer service must be pointed at `use`:\n{rendered}"
        );
        // A peer granting nothing yet has no `use` step to offer.
        let bare = next_steps_lines(&status_with(vec![], vec![peer("alice", &[])])).join("\n");
        assert!(
            !bare.contains("mcpmesh use"),
            "a peer with no grants offers no use step:\n{bare}"
        );
    }

    #[test]
    fn next_steps_are_silent_on_a_fully_configured_node() {
        // Serving to a real peer AND able to reach one: nothing to nudge — no footer at all.
        let lines = next_steps_lines(&status_with(
            vec![service("notes", &["bob"])],
            vec![peer("bob", &["code"])],
        ));
        // The only step left is the `use` hint for bob/code; the serve/invite/pair nags are gone.
        let rendered = lines.join("\n");
        assert!(rendered.contains("mcpmesh use bob/code"));
        assert!(!rendered.contains("mcpmesh serve") && !rendered.contains("mcpmesh pair"));
    }

    #[test]
    fn reachability_lines_render_online_offline_and_checking() {
        let lines = reachability_lines(&[
            PeerReachability {
                name: "alice".into(),
                reachable: true,
                rtt_ms: Some(23),
                age_secs: Some(4),
            },
            PeerReachability {
                name: "bob".into(),
                reachable: false,
                rtt_ms: None,
                age_secs: Some(90),
            },
            PeerReachability {
                name: "carol".into(),
                reachable: false,
                rtt_ms: None,
                age_secs: None, // never probed
            },
        ]);
        assert_eq!(lines[0], "  alice · online · 23ms");
        assert_eq!(lines[1], "  bob · offline");
        // A never-probed peer reads as a STATE, not a bare ellipsis (issue #12).
        assert_eq!(lines[2], "  carol · checking…");
    }

    #[test]
    fn use_target_error_names_the_known_peers_and_services() {
        let peers = vec![peer("alice", &["notes", "kb"]), peer("bob", &[])];
        // A resolvable target → no error.
        assert_eq!(use_target_error("alice", "notes", &peers), None);
        // Unknown peer → the known list, invite-refusal style.
        let msg = use_target_error("carol", "notes", &peers).unwrap();
        assert!(
            msg.contains("no paired peer named 'carol'")
                && msg.contains("your peers: alice, bob")
                && msg.contains("mcpmesh status"),
            "unknown peer names the known list: {msg}"
        );
        // Known peer, unknown service → what they DO share.
        let msg = use_target_error("alice", "code", &peers).unwrap();
        assert!(
            msg.contains("'alice' does not share a service named 'code'")
                && msg.contains("they share: notes, kb"),
            "unknown service names the shared list: {msg}"
        );
        // Known peer sharing nothing → no dangling empty list.
        let msg = use_target_error("bob", "notes", &peers).unwrap();
        assert!(
            msg.contains("'bob' does not share any services with you yet"),
            "a grantless peer gets a plain explanation: {msg}"
        );
        // No peers at all → the pair next step, not an empty list.
        let msg = use_target_error("alice", "notes", &[]).unwrap();
        assert!(
            msg.contains("nobody is paired yet") && msg.contains("mcpmesh pair"),
            "a peerless node is pointed at pair: {msg}"
        );
    }

    #[test]
    fn roster_install_line_renders_org_serial_and_pluralized_sever_count() {
        // The canonical single-session confirmation shape.
        let one = RosterInstallResult {
            org_id: "acme".into(),
            serial: 42,
            severed: 1,
        };
        assert_eq!(
            roster_install_line(&one),
            "Installed roster for org 'acme' (serial 42). Severed 1 live session."
        );
        // Zero + plural (a manual install on a daemon with no live sessions to cut).
        let none = RosterInstallResult {
            org_id: "acme".into(),
            serial: 7,
            severed: 0,
        };
        assert_eq!(
            roster_install_line(&none),
            "Installed roster for org 'acme' (serial 7). Severed 0 live sessions."
        );
        // Many → plural.
        let many = RosterInstallResult {
            org_id: "acme".into(),
            serial: 100,
            severed: 3,
        };
        assert_eq!(
            roster_install_line(&many),
            "Installed roster for org 'acme' (serial 100). Severed 3 live sessions."
        );
    }

    #[test]
    fn roster_install_line_leaks_no_transport_vocabulary() {
        // The confirmation carries roster-status vocabulary (org_id, serial, severed count)
        // ONLY — never a key, endpoint id, path, or any transport term. org_id is operator-chosen;
        // assert none of the blocklist vocabulary appears.
        let result = RosterInstallResult {
            org_id: "acme".into(),
            serial: 42,
            severed: 1,
        };
        let line = roster_install_line(&result);
        for term in [
            "b64u:",
            "endpoint",
            "EndpointId",
            "ALPN",
            "roster.json",
            "/",
            "key",
        ] {
            assert!(
                !line.contains(term),
                "roster install output leaked '{term}': {line}"
            );
        }
    }

    #[test]
    fn roster_status_lines_render_org_serial_state_and_fingerprint() {
        // The canonical roster block: a summary line + an org-root fingerprint line.
        let roster = RosterStatus {
            org_id: "acme".into(),
            serial: 42,
            state: "approved".into(),
            org_root_fingerprint: "tango-fig-cabbage-anchor".into(),
        };
        let lines = roster_status_lines(&roster, true); // url configured → no hint
        assert_eq!(lines[0], "roster: org acme · serial 42 · approved");
        assert_eq!(
            lines[1],
            "  org root: tango-fig-cabbage-anchor (confirm out-of-band)"
        );
    }

    #[test]
    fn roster_status_lines_omit_the_org_root_line_when_the_fingerprint_is_absent() {
        // A missing/unparseable pin degrades to an empty fingerprint — no dangling "org root:" line.
        let roster = RosterStatus {
            org_id: "acme".into(),
            serial: 7,
            state: "degraded".into(),
            org_root_fingerprint: String::new(),
        };
        let lines = roster_status_lines(&roster, true); // url configured → no hint
        assert_eq!(lines, vec!["roster: org acme · serial 7 · degraded"]);
    }

    #[test]
    fn roster_status_lines_append_url_less_hint_when_no_roster_url() {
        // Roster-mode but no `[roster].url`: the node has no way to re-confirm currency, so it
        // degrades toward stale after max_staleness (correct, not a bug). Surface the advisory hint.
        let roster = RosterStatus {
            org_id: "acme".into(),
            serial: 7,
            state: "approved".into(),
            org_root_fingerprint: String::new(),
        };
        let lines = roster_status_lines(&roster, false); // no url configured
        assert!(
            lines
                .iter()
                .any(|l| l.contains("no roster URL configured") && l.contains("set [roster].url")),
            "expected the URL-less degrade hint: {lines:?}"
        );
        // A configured url → NO hint (the poll re-confirms currency).
        let lines = roster_status_lines(&roster, true);
        assert!(
            !lines.iter().any(|l| l.contains("hint:")),
            "no hint when a roster url is configured: {lines:?}"
        );
    }

    #[test]
    fn presence_lines_render_user_label_role_and_online_flag() {
        let presence = vec![
            PresencePeer {
                user_id: "alice".into(),
                device_label: "laptop".into(),
                role: "primary".into(),
                online: true,
            },
            PresencePeer {
                user_id: "alice".into(),
                device_label: "desktop".into(),
                role: "mirror".into(),
                online: false,
            },
        ];
        let lines = presence_lines(&presence);
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains("alice")
                && lines[0].contains("laptop")
                && lines[0].contains("primary")
                && lines[0].contains("online"),
            "the online primary renders user·label·role·online: {lines:?}"
        );
        assert!(
            lines[1].contains("desktop")
                && lines[1].contains("mirror")
                && lines[1].contains("offline"),
            "the dead mirror renders offline: {lines:?}"
        );
    }

    #[test]
    fn presence_lines_leak_no_transport_vocabulary() {
        // The reachable block carries FLAT vocabulary ONLY (user_id/device_label/role/
        // online) — never a raw key, endpoint id, hash, or protocol name.
        let presence = vec![PresencePeer {
            user_id: "alice".into(),
            device_label: "laptop".into(),
            role: "primary".into(),
            online: true,
        }];
        let rendered = presence_lines(&presence).join("\n");
        for term in ["b64u:", "EndpointId", "endpoint", "ALPN", "pubkey", "hash"] {
            assert!(
                !rendered.contains(term),
                "presence output leaked '{term}': {rendered}"
            );
        }
    }

    #[test]
    fn roster_status_lines_leak_no_transport_vocabulary() {
        // The roster block carries roster/ceremony vocabulary ONLY (org_id, serial, the state
        // word, and the fingerprint WORDS) — never a raw key, endpoint id, roster path, or ALPN.
        let roster = RosterStatus {
            org_id: "acme".into(),
            serial: 42,
            state: "approved".into(),
            org_root_fingerprint: "tango-fig-cabbage-anchor".into(),
        };
        let rendered = roster_status_lines(&roster, true).join("\n");
        for term in [
            "b64u:",
            "EndpointId",
            "endpoint",
            "ALPN",
            "ticket",
            "roster.json",
        ] {
            assert!(
                !rendered.contains(term),
                "roster status output leaked '{term}': {rendered}"
            );
        }
    }

    #[test]
    fn recent_pairing_lines_render_nickname_code_and_age() {
        let pairings = vec![
            RecentPairing {
                peer_nickname: "bob".into(),
                sas_code: "tango-fig-cabbage".into(),
                paired_at_epoch: 1_000_000,
            },
            RecentPairing {
                peer_nickname: "carol".into(),
                sas_code: "anchor-bean-cable".into(),
                paired_at_epoch: 1_000_000 - 5 * 60,
            },
        ];
        let lines = recent_pairing_lines(&pairings, 1_000_010);
        assert_eq!(lines[0], "  bob · code: tango-fig-cabbage · just now");
        assert_eq!(lines[1], "  carol · code: anchor-bean-cable · 5m ago");
    }

    #[test]
    fn recent_pairing_lines_leak_no_endpoint_id_or_transport_vocabulary() {
        // The recent-pairings block carries the nickname, the SAS words, and a friendly age
        // ONLY. A RecentPairing carries no endpoint id, so the lines can't either — assert it,
        // and assert no transport vocabulary.
        let bob_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string();
        let pairings = vec![RecentPairing {
            peer_nickname: "bob".into(),
            sas_code: "tango-fig-cabbage".into(),
            paired_at_epoch: 100,
        }];
        let rendered = recent_pairing_lines(&pairings, 200).join("\n");
        assert!(
            !rendered.contains(&bob_id),
            "recent pairings must not leak an EndpointId: {rendered}"
        );
        for term in [
            "endpoint",
            "ticket",
            "ALPN",
            "iroh",
            "pubkey",
            "mcpmesh/pair/1",
        ] {
            assert!(
                !rendered.to_lowercase().contains(&term.to_lowercase()),
                "recent pairings leaked '{term}': {rendered}"
            );
        }
    }

    #[test]
    fn friendly_age_buckets_and_saturates_sensibly() {
        assert_eq!(friendly_age(1_000, 1_030), "just now"); // sub-minute
        assert_eq!(friendly_age(1_000, 1_000 + 5 * 60), "5m ago");
        assert_eq!(friendly_age(1_000, 1_000 + 3 * 3600), "3h ago");
        assert_eq!(friendly_age(1_000, 1_000 + 2 * 24 * 3600), "2d ago");
        // A future stamp (clock skew) saturates — no underflow/panic.
        assert_eq!(friendly_age(2_000, 1_000), "just now");
    }

    #[test]
    fn friendly_expiry_rounds_and_degrades_sensibly() {
        // A freshly minted 24h invite reads "in 24h" even after a second or two of latency.
        assert_eq!(friendly_expiry(1_000 + DAY, 1_002), "in 24h");
        // A few hours out.
        assert_eq!(friendly_expiry(3 * 3600, 0), "in 3h");
        // Sub-hour → minutes.
        assert_eq!(friendly_expiry(45 * 60, 0), "in 45m");
        // Sub-minute → "soon" (no negative/zero-hour weirdness).
        assert_eq!(friendly_expiry(30, 0), "soon");
        // Already past → saturating, "soon" not a panic/underflow.
        assert_eq!(friendly_expiry(100, 1_000), "soon");
    }

    /// Parse a wire-shaped frame into the published [`StreamFrame`] type — the same path
    /// `internal watch`'s typed subscription takes, so these tests pin BOTH that the documented
    /// wire JSON deserializes and how it renders.
    fn frame(v: serde_json::Value) -> StreamFrame {
        serde_json::from_value(v).expect("wire frame deserializes into StreamFrame")
    }

    #[test]
    fn render_frame_summarizes_a_snapshot() {
        let v = frame(json!({
            "type": "snapshot",
            "active_sessions": [
                {"peer": "bob", "service": "notes", "opened_at": 1},
                {"peer": "carol", "service": "kb", "opened_at": 2},
            ],
            "reachability": [{"name": "bob", "reachable": true}],
        }));
        assert_eq!(
            render_frame(&v),
            "snapshot: 2 active session(s), 1 peer(s) known"
        );
        // A daemon with nothing live still summarizes cleanly (no panic on empty arrays).
        let empty = frame(json!({ "type": "snapshot", "active_sessions": [], "reachability": [] }));
        assert_eq!(
            render_frame(&empty),
            "snapshot: 0 active session(s), 0 peer(s) known"
        );
    }

    #[test]
    fn render_frame_renders_an_event_line() {
        let v = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "session_open",
                        "peer": "bob", "service": "notes" },
        }));
        assert_eq!(
            render_frame(&v),
            "[2026-07-17T14:02:11.480Z] session_open bob → notes"
        );
    }

    #[test]
    fn render_frame_marks_a_failed_dial_with_its_status() {
        // A failed dial arrives as a `session_open` carrying `status:"error"` — the line must
        // append the status so it doesn't render identically to a real (statusless) open.
        let failed = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "session_open",
                        "peer": "bob", "service": "notes", "status": "error" },
        }));
        assert_eq!(
            render_frame(&failed),
            "[2026-07-17T14:02:11.480Z] session_open bob → notes (error)"
        );
        // A normal open has no `status` field, so no suffix is appended.
        let normal = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "session_open",
                        "peer": "bob", "service": "notes" },
        }));
        assert!(!render_frame(&normal).contains('('));
    }

    #[test]
    fn render_frame_tolerates_a_bare_event_record() {
        // A trust/roster event may carry no peer/service — the optional fields degrade to an
        // empty piece, and the line doesn't dangle a trailing separator.
        let v = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "trust", "event": "unpair" },
        }));
        assert_eq!(render_frame(&v), "[2026-07-17T14:02:11.480Z] trust");
    }

    #[test]
    fn render_frame_tolerates_asymmetric_event_records() {
        // peer present, service absent (a real shape — `blob_fetch` records carry a peer, no
        // service): the peer renders with no dangling "→ " and no trailing space.
        let peer_only = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "blob_fetch", "peer": "bob" },
        }));
        assert_eq!(
            render_frame(&peer_only),
            "[2026-07-17T14:02:11.480Z] blob_fetch bob"
        );
        // service present, peer absent: the arrow renders with no phantom peer, no leading space.
        let service_only = frame(json!({
            "type": "event",
            "record": { "ts": "2026-07-17T14:02:11.480Z", "kind": "session_open", "service": "notes" },
        }));
        assert_eq!(
            render_frame(&service_only),
            "[2026-07-17T14:02:11.480Z] session_open → notes"
        );
    }

    #[test]
    fn render_frame_renders_a_lagged_notice() {
        let v = frame(json!({ "type": "lagged", "dropped": 7 }));
        assert_eq!(
            render_frame(&v),
            "(lagged 7 events — reconnect for a fresh snapshot)"
        );
    }

    /// Wrap a JSON-RPC error object the way every porcelain verb receives it: a
    /// `ClientError::Api` converted into the verb's `anyhow::Result` by `?`.
    fn api_error(value: serde_json::Value) -> anyhow::Error {
        anyhow::Error::from(client::ClientError::Api(value))
    }

    #[test]
    fn control_api_errors_render_the_message_never_the_json_object() {
        // Issue #10 style 2: the raw error object must never reach a human — only its message.
        let err = api_error(json!({"code": -32000, "message": "invite expired"}));
        let lines = error_lines(&err);
        assert_eq!(lines, vec!["Error: invite expired".to_string()]);
        let rendered = lines.join("\n");
        assert!(
            !rendered.contains('{') && !rendered.contains("-32000"),
            "no JSON-RPC object/code may leak: {rendered}"
        );
    }

    #[test]
    fn wire_method_framing_is_stripped_from_control_errors() {
        // The wire answers `"{method} failed: {reason}"` (respond() in control.rs); the method
        // token is not user language — the daemon's own sentence is what a human gets. These
        // are the end-to-end shapes for issues #8 and #9.
        let err = api_error(json!({"code": -32000, "message":
            "peer_remove failed: no paired peer named 'nobody' — 'mcpmesh status' lists your peers"}));
        assert_eq!(
            error_lines(&err),
            vec![
                "Error: no paired peer named 'nobody' — 'mcpmesh status' lists your peers"
                    .to_string()
            ]
        );
        let err = api_error(json!({"code": -32000, "message":
            "invite failed: no service named 'nosuchsvc' — you serve: notes (see 'mcpmesh status')"}));
        assert_eq!(
            error_lines(&err),
            vec![
                "Error: no service named 'nosuchsvc' — you serve: notes (see 'mcpmesh status')"
                    .to_string()
            ]
        );
        // No framing → untouched; a non-method token before " failed: " → untouched.
        assert_eq!(strip_wire_framing("invite expired"), "invite expired");
        assert_eq!(
            strip_wire_framing("the Frobnicator failed: twice"),
            "the Frobnicator failed: twice"
        );
    }

    #[test]
    fn failed_pair_dial_renders_in_user_language() {
        // The daemon-side message (its exact shape in pairing/rendezvous.rs) is terse; the
        // porcelain seam maps it to the human explanation (issue #10).
        let err = api_error(json!({
            "code": -32000,
            "message": "pair failed: could not dial the inviter's machine"
        }));
        let rendered = error_lines(&err).join("\n");
        assert!(
            rendered.contains("could not reach the inviter's machine")
                && rendered.contains("are they online?"),
            "the failure states what happened in user language: {rendered}"
        );
        assert!(
            rendered.contains("cannot redeem your own invite on the machine that minted it"),
            "the self-redeem case is explained: {rendered}"
        );
        for term in ["ALPN", "dial", "{"] {
            assert!(!rendered.contains(term), "leaked '{term}': {rendered}");
        }
    }

    #[test]
    fn a_message_less_control_error_degrades_to_doctor_not_json() {
        let err = api_error(json!({"code": -32000}));
        let rendered = error_lines(&err).join("\n");
        assert!(
            rendered.contains("mcpmesh doctor") && !rendered.contains('{'),
            "degrades to a next step, never raw JSON: {rendered}"
        );
    }

    #[test]
    fn non_control_errors_keep_their_context_chain() {
        // The generic path renders like anyhow's chain: top line + Caused by. (Redundant
        // layers were dropped at the call sites, not collapsed here.)
        let err = anyhow::Error::from(std::io::Error::other("disk full"))
            .context("write staged roster /tmp/x");
        let lines = error_lines(&err);
        assert_eq!(lines[0], "Error: write staged roster /tmp/x");
        assert!(
            lines.iter().any(|l| l == "Caused by:")
                && lines.iter().any(|l| l.contains("disk full")),
            "the cause survives: {lines:?}"
        );
        // …and a single-layer error is a single sentence.
        let single = anyhow::anyhow!("bad --expires: unknown unit");
        assert_eq!(
            error_lines(&single),
            vec!["Error: bad --expires: unknown unit".to_string()]
        );
    }
}
