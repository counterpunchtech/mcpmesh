use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mcpmesh::enrollcmd::{load_device_key, split_csv, with_daemon};
use mcpmesh::{client, config, daemon, doctor, enrollcmd, proxy, util};
use mcpmesh_local_api::{
    AuditKind, BackendKind, BackendSpec, Hello, InviteResult, PairResult, PeerAddParams,
    PresencePeer, RecentPairing, RosterInstallResult, RosterStatus, StatusResult, StreamFrame,
};
use mcpmesh_trust::paths;

/// The one worked `serve` example the CLI shows, as a macro so the runtime constant
/// ([`SERVE_EXAMPLE`], for `status`'s next-steps footer) and clap's compile-time `after_help`
/// (which takes only literals, hence `concat!`, hence not a `const`) come from ONE source and
/// cannot drift.
///
/// `serve <name> -- <command>` is mechanism-first: it runs ANY stdio MCP server and has no opinion
/// about which. That generality is a wall for someone who doesn't already have one running, so the
/// example is deliberately a COMPLETE command needing nothing but npx, sharing a folder — the most
/// legible thing mcpmesh does, and a real MCP server rather than an mcpmesh-specific toy.
macro_rules! serve_example {
    () => {
        "mcpmesh serve notes -- npx -y @modelcontextprotocol/server-filesystem ~/notes"
    };
}

/// The [`serve_example!`] command as a runtime string (see that macro for why it is one).
const SERVE_EXAMPLE: &str = serve_example!();

#[derive(Parser)]
#[command(name = "mcpmesh", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serving what, to whom; reachable peers; trust freshness.
    Status,
    /// Local health check (spec §1.6/§13): lint the config, key permissions, roster freshness, the
    /// relay/discovery self-hosting combination (§10.3), and the runtime dir; optionally ping the
    /// daemon. Read-only + local-only — it inspects and reports, never mutates trust/config and never
    /// touches the network. Exits non-zero on ERROR.
    Doctor,
    /// Register and serve a local MCP server to allowlisted peers (spec §6.1). Auto-starts
    /// the daemon, writes the `[services.<name>]` config entry, and hot-reloads serving.
    ///
    /// Everything after `--` is just the command that runs a stdio MCP server — any one, under a
    /// name you pick. No MCP server of your own? The example below shares a folder and needs
    /// nothing but npx.
    #[command(after_help = concat!(
        "Example — share a folder of notes (needs npx; no MCP server of your own required):\n  ",
        serve_example!(),
        "\n\nThen `mcpmesh invite notes` mints an invite to send whoever you're sharing with."
    ))]
    Serve {
        /// Service name — how peers address it (`connect <peer>/<name>`).
        name: String,
        /// Comma-separated petnames/groups admitted to this service.
        #[arg(long)]
        allow: Option<String>,
        /// The command to run per session, after `--` (a stdio MCP server).
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Stdio proxy an AI client runs to reach a peer's service (spec §8). Auto-starts the
    /// daemon, opens the mesh session, and pipes MCP frames stdin<->daemon<->stdout verbatim.
    Connect {
        /// The service to reach, as `<peer>/<service>`.
        target: String,
    },
    /// Mint a one-time pairing invite granting one or more services (spec §4.2). Auto-starts the
    /// daemon and prints the copyable `mcpmesh-invite:` line to share out-of-band; whoever redeems
    /// it can access the listed services on this machine.
    Invite {
        /// One or more service names the redeemer is granted (space-separated). At least one is
        /// required — an invite granting nothing is useless.
        services: Vec<String>,
    },
    /// Redeem a pairing invite to gain access to a peer's services, or (with `--remove`) unpair a
    /// peer (spec §4.2). Auto-starts the daemon. `--remove <petname>` drops the peer's trust entry
    /// and revokes its access to YOUR services; it does NOT sever live in-flight sessions (those
    /// run to completion — session severing is M3/D8), only the ability to open NEW ones.
    Pair {
        /// The `mcpmesh-invite:...` string to redeem. Omit when using `--remove`.
        invite: Option<String>,
        /// Unpair a peer by petname instead of redeeming an invite.
        #[arg(long, value_name = "petname")]
        remove: Option<String>,
    },
    /// Print the exact steps to use a peer's service from your AI client — the Claude Code command,
    /// the Claude Desktop config entry + where it goes, and the generic stdio command any other MCP
    /// client takes (spec §8/§11.1). `pair` prints this automatically; run `use` to see it again.
    Use {
        /// The service to mount, as `<peer>/<service>`.
        target: String,
    },
    /// Roster mode: join an org from its invite (spec §4.4 step 2). Mints your user key, pins the
    /// org root, and prints the join code to send the operator plus the org-root fingerprint to
    /// confirm out-of-band.
    Join {
        /// The `mcpmesh-org:…` invite from the operator's `org create`.
        org_invite: String,
        /// Your display name in the roster; a generic id is used if omitted — pass --name.
        #[arg(long)]
        name: Option<String>,
        /// A requested stable user_id (the operator confirms/overrides at approve). Defaults to a
        /// slug of `--name`.
        #[arg(long)]
        user_id: Option<String>,
        /// A label for THIS device in the roster (e.g. "laptop").
        #[arg(long, default_value = "laptop")]
        label: String,
    },
    /// Roster mode: create an org — mint the org root key, sign an empty roster, and print the org
    /// invite code operators hand to joiners (spec §4.4). One-time per node.
    Org {
        #[command(subcommand)]
        command: OrgCmd,
    },
    /// Roster mode: manage this person's devices (spec §4.3/§4.4). Keys never move between machines.
    Devices {
        #[command(subcommand)]
        command: DevicesCmd,
    },
    /// Internal, non-porcelain subcommands (auto-started by the CLI; not for direct use).
    Internal {
        #[command(subcommand)]
        command: Internal,
    },
}

#[derive(Subcommand)]
enum OrgCmd {
    /// Mint the org root key + sign+install an EMPTY roster (spec §4.4 step 1). Prints the org
    /// invite code (`mcpmesh-org:…`) to hand to joiners, plus the org-root fingerprint for the
    /// enrollment ceremony. Refuses if this node already holds an org root (one org per node).
    Create {
        /// The org id (also the roster `org_id`).
        name: String,
        /// Roster validity window from now (e.g. `90d`, `12h`; default `90d`, §4.3 operator-managed).
        #[arg(long)]
        expires: Option<String>,
        /// The pinned HTTPS roster URL joiners poll for their FIRST + ongoing roster (spec §4.3).
        /// Carried in the org invite (so joiners bootstrap without gossip, D5) AND stored in this
        /// operator's config `[roster].url` (the operator keeps the hosted document current).
        #[arg(long)]
        roster_url: Option<String>,
    },
    /// Approve a joiner (spec §4.4 step 3): verify the join code's device binding, add the member +
    /// device to the roster with the named groups, re-sign, and install (severing nothing new). Run
    /// this AFTER confirming the person out-of-band (the human ceremony).
    Approve {
        /// The `mcpmesh-join:…` code from the joiner's `join`.
        join_code: String,
        /// Comma-separated groups to grant (e.g. `team-eng,all`). Declared in the roster if new.
        #[arg(long)]
        groups: String,
        /// Override the joiner's requested stable user_id (§4.6). Defaults to the join code's value.
        #[arg(long)]
        user_id: Option<String>,
    },
    /// Revoke access (spec §4.5/§4.6). `<person>` removes a departing person (and revokes all their
    /// devices); `<person>/<device>` revokes one device; `--user-key <person>` runs the user-key
    /// rotation runbook (removes the person so they re-enroll with a fresh user key — the SAME devices).
    Revoke {
        /// `alice` (person) or `alice/laptop` (device). With `--user-key`, a bare person.
        target: String,
        /// User-key rotation (§4.6): remove the person WITHOUT permanently revoking their device
        /// endpoints, so the same machine re-enrolls with a new user key.
        #[arg(long)]
        user_key: bool,
    },
}

#[derive(Subcommand)]
enum DevicesCmd {
    /// On a NEW machine (not yet enrolled): print this device's code to hand to an already-enrolled
    /// device, which runs `devices add`.
    Code {
        /// A label for this device in the roster (e.g. "desktop").
        #[arg(long, default_value = "desktop")]
        label: String,
    },
    /// On an ENROLLED device (holds the user key): bind the new device from its code — sign the
    /// binding with YOUR user key and print a join code for the operator (spec §4.4).
    Add {
        /// The `mcpmesh-device:…` code from the new machine's `devices code`.
        device_code: String,
    },
}

#[derive(Subcommand)]
enum Internal {
    /// Run the long-lived daemon: bind the control socket and serve the local API.
    /// Auto-started by any porcelain verb; a redundant instance exits 0 (flock singleton).
    Daemon,
    /// Print this machine's full endpoint id (iroh base32) — the OTHER machine's `internal
    /// peer add <petname> <id>` parses exactly this. The §1.5 verbose/doctor-class raw-id
    /// surface, deliberately NOT in plain `status`. Derived locally from the device key
    /// (the id is deterministic; no daemon round-trip).
    Id,
    /// Peer allowlist management (M2a trust-population stand-in for pairing).
    Peer {
        #[command(subcommand)]
        command: PeerCmd,
    },
    /// Installed-roster management (spec §4.3). The manual convergence path when no roster URL /
    /// gossip is configured — the operator obtains the signed roster + org-root pk out-of-band.
    Roster {
        #[command(subcommand)]
        command: RosterCmd,
    },
    /// Gated app-blob operations (spec §9, M4a): publish a file into a scope, grant a scope, list
    /// scopes, fetch a ticket through the daemon. Auto-starts the daemon (roster mode only).
    Blob {
        #[command(subcommand)]
        command: BlobCmd,
    },
    /// View or rotate the LOCAL append-only audit log (spec §11.3). Reads
    /// `~/.local/state/mcpmesh/audit/*.jsonl` DIRECTLY — no daemon, no network (nothing is
    /// transmitted anywhere). `tail` prints recent records (optionally filtered); `list` shows the
    /// monthly files; `prune --before YYYY-MM` deletes older months (the rotation boundary).
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },
    /// Subscribe to the daemon's live event stream and pretty-print it (pairing liveness & health
    /// telemetry). A thin reference consumer of the `subscribe` surface — the UAT/dogfood window on
    /// the mesh. Auto-starts the daemon, prints a one-line snapshot summary, then a line per event
    /// (and a lagged notice if a consumer falls behind). Runs until interrupted (Ctrl-C).
    Watch,
}

#[derive(Subcommand)]
enum BlobCmd {
    /// Publish a LOCAL file INTO a scope. Prints the `mcpmesh/blob/1` ticket + hash.
    Publish {
        /// The scope name (create-on-first-publish).
        scope: String,
        /// Path to the local file to publish.
        file: PathBuf,
    },
    /// Grant a scope to a principal (a roster group name or a user_id).
    Grant { scope: String, principal: String },
    /// List the daemon's blob scopes (name → hashes + grants).
    List,
    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (BLAKE3-verified) and write it to `dest`.
    Fetch {
        /// The ticket string (from `blob publish`).
        ticket: String,
        /// Local path to write the verified blob to.
        dest: PathBuf,
    },
}

#[derive(clap::Subcommand)]
enum AuditCmd {
    /// Print the most recent audit records as JSONL (newest last), optionally filtered.
    Tail {
        /// How many records to print (after filtering). Default 20.
        #[arg(long, default_value_t = 20)]
        lines: usize,
        /// Only records of this kind: session_open|session_close|request|blob_fetch|trust.
        #[arg(long)]
        kind: Option<String>,
        /// Only records attributed to this peer.
        #[arg(long)]
        peer: Option<String>,
    },
    /// List the monthly audit files (month, size).
    List,
    /// Delete monthly files STRICTLY older than `--before YYYY-MM` (rotation/prune).
    Prune {
        #[arg(long, value_name = "YYYY-MM")]
        before: String,
    },
}

#[derive(Subcommand)]
enum RosterCmd {
    /// Install a signed roster from a local FILE (spec §4.3 manual path). Auto-starts the daemon,
    /// which reads + fully validates the file (signature, serial, validity window, structure),
    /// persists it, hot-swaps the trust gate, and severs any live sessions it revokes (D8).
    /// `--org-root-pk` pins the org root on the FIRST install; omit it once pinned.
    Install {
        /// Path to the signed `mcpmesh-roster/1` JSON document.
        file: PathBuf,
        /// The pinned org-root public key (`b64u:…`), required on the first install. Omit on later
        /// installs — the pinned value in config is reused.
        #[arg(long)]
        org_root_pk: Option<String>,
    },
}

#[derive(Subcommand)]
enum PeerCmd {
    /// Add a peer to the allowlist by petname + endpoint id (base32). Routes through the
    /// daemon (which owns the open store), so it auto-starts the daemon if needed.
    Add {
        /// Local human name the gate resolves this peer to.
        petname: String,
        /// The peer's endpoint id (iroh base32).
        endpoint_id: String,
        /// Comma-separated services recorded as this peer's grant. NOTE: this list is
        /// informational (shown in `status`) — actual access to a service is gated by that
        /// service's own `allow` (the `[services.*].allow ∋ petname` check, spec §5/D-C).
        #[arg(long)]
        allow: Option<String>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            for line in error_lines(&err) {
                eprintln!("{line}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// Render an error that is about to reach a human — the ONE rendering path every verb's
/// failure flows through (issue #10). Pure so it is unit-testable.
///
/// A control-API failure prints its `message` as a plain sentence — NEVER the raw JSON-RPC
/// error object (was previously `Error: control API error: {json}`), and known daemon
/// failure shapes are translated to user language at this seam ([`control_error_lines`]).
/// Everything else keeps the anyhow context chain (context layers that merely duplicated
/// their root cause were dropped at the call sites instead).
fn error_lines(err: &anyhow::Error) -> Vec<String> {
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

/// Dispatch the parsed command — split from [`main`] so every verb's failure flows through
/// the one rendering path ([`error_lines`]).
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        // The daemon owns its own runtime; dispatch it before the porcelain preamble.
        Some(Cmd::Internal {
            command: Internal::Daemon,
        }) => daemon::run(),
        Some(Cmd::Internal {
            command: Internal::Id,
        }) => run_internal_id(),
        Some(Cmd::Serve { name, allow, cmd }) => run_serve(name, allow, cmd),
        Some(Cmd::Connect { target }) => run_connect(target),
        Some(Cmd::Invite { services }) => run_invite(services),
        Some(Cmd::Pair { invite, remove }) => run_pair(invite, remove),
        Some(Cmd::Use { target }) => run_use(target),
        Some(Cmd::Join {
            org_invite,
            name,
            user_id,
            label,
        }) => enrollcmd::run_join(org_invite, name, user_id, label),
        Some(Cmd::Org {
            command:
                OrgCmd::Create {
                    name,
                    expires,
                    roster_url,
                },
        }) => enrollcmd::run_org_create(name, expires, roster_url),
        Some(Cmd::Org {
            command:
                OrgCmd::Approve {
                    join_code,
                    groups,
                    user_id,
                },
        }) => enrollcmd::run_org_approve(join_code, groups, user_id),
        Some(Cmd::Org {
            command: OrgCmd::Revoke { target, user_key },
        }) => enrollcmd::run_org_revoke(target, user_key),
        Some(Cmd::Devices {
            command: DevicesCmd::Code { label },
        }) => enrollcmd::run_devices_code(label),
        Some(Cmd::Devices {
            command: DevicesCmd::Add { device_code },
        }) => enrollcmd::run_devices_add(device_code),
        Some(Cmd::Internal {
            command:
                Internal::Peer {
                    command:
                        PeerCmd::Add {
                            petname,
                            endpoint_id,
                            allow,
                        },
                },
        }) => run_peer_add(petname, endpoint_id, allow),
        Some(Cmd::Internal {
            command:
                Internal::Roster {
                    command: RosterCmd::Install { file, org_root_pk },
                },
        }) => run_roster_install(file, org_root_pk),
        Some(Cmd::Internal {
            command: Internal::Blob { command },
        }) => run_internal_blob(command),
        Some(Cmd::Internal {
            command: Internal::Audit { command },
        }) => run_internal_audit(command),
        Some(Cmd::Internal {
            command: Internal::Watch,
        }) => run_watch(),
        Some(Cmd::Doctor) => doctor::run_doctor(),
        Some(Cmd::Status) | None => run_status(),
    }
}

/// `mcpmesh serve <name> [--allow a,b] -- <cmd...>`: auto-start the daemon and register the
/// service over the control API (which persists it + hot-reloads serving).
fn run_serve(name: String, allow: Option<String>, cmd: Vec<String>) -> anyhow::Result<()> {
    let allow = split_csv(allow);
    with_daemon(async move |mut client| {
        client
            .register_service(&name, BackendSpec::Run { cmd }, allow)
            .await?;
        println!("serving '{name}'");
        // The next exact instruction. Nothing is shared until someone is granted access, so the
        // invite is ALWAYS the next step — `--allow` names petnames, but only a redeemed invite
        // (or a roster) makes a petname resolve to a real peer.
        println!(
            "Next: run `mcpmesh invite {name}` to mint a one-time invite, and send it to the \
             person you want to share it with."
        );
        Ok(())
    })
}

/// `mcpmesh connect <peer>/<service>`: the stdio proxy an AI client runs (spec §8). Blocks
/// pumping the session until stdin closes or the remote ends.
fn run_connect(target: String) -> anyhow::Result<()> {
    let (peer, service) = proxy::split_target(&target)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(proxy::run(peer, service))
}

/// `mcpmesh invite [services…]`: auto-start the daemon, mint a one-time pairing invite granting
/// `services`, and print the copyable `mcpmesh-invite:` line (spec §1.5 surface #2 — the ONE
/// pairing artifact carved out of the transport-vocabulary blocklist, so printing it plainly is
/// permitted) plus a plain-language expiry and the granted services.
///
/// Empty `services` is an ERROR (DECLARED): an invite that grants nothing is useless, and
/// erroring here is friendlier than minting a dead invite the redeemer can do nothing with.
fn run_invite(services: Vec<String>) -> anyhow::Result<()> {
    if services.is_empty() {
        anyhow::bail!("specify at least one service to grant (e.g. `mcpmesh invite notes`)");
    }
    with_daemon(async move |mut client| {
        let invite = client.invite(services.clone()).await?;
        for line in invite_lines(&invite, &services, util::epoch_now_u64()) {
            println!("{line}");
        }
        Ok(())
    })
}

/// `mcpmesh pair <invite>` / `mcpmesh pair --remove <petname>`: auto-start the daemon, then either
/// redeem an invite (printing the SAS + mountable `<peer>/<service>` targets) or unpair a peer.
/// Exactly one of the invite arg / `--remove` must be given.
///
/// A control-API error (a pair refused/expired/id-mismatch, or a peer_remove failure) propagates
/// out of `main` → the process prints the message to stderr and exits non-zero (the plain
/// surfacing the task asks for).
fn run_pair(invite: Option<String>, remove: Option<String>) -> anyhow::Result<()> {
    match (invite, remove) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide an invite to redeem OR --remove <petname>, not both")
        }
        (None, None) => {
            anyhow::bail!("provide an invite to redeem, or --remove <petname> to unpair")
        }
        (Some(invite_line), None) => with_daemon(async move |mut client| {
            let paired = client.pair(&invite_line).await?;
            for line in pair_lines(&paired) {
                println!("{line}");
            }
            Ok(())
        }),
        (None, Some(petname)) => with_daemon(async move |mut client| {
            client.peer_remove(&petname).await?;
            // Live in-flight sessions are NOT severed (M3/D8) — only new authorized sessions
            // are blocked from here on. The petname just stops resolving + being admitted.
            println!("Unpaired {petname}.");
            Ok(())
        }),
    }
}

/// Render the `mcpmesh invite` output block (spec §1.5 surface #2). Pure so it is unit-testable:
/// the `mcpmesh-invite:` line is the copyable artifact, and the services are listed from the
/// REQUESTED `services` arg (what the operator asked to grant). No peer EndpointId appears —
/// the only id-bearing artifact is the opaque invite line itself (permitted, §1.5).
fn invite_lines(invite: &InviteResult, services: &[String], now: u64) -> Vec<String> {
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
/// pairing just unlocked, and EXACTLY how to use it from an AI client (spec §8/§11.1 — the block
/// [`proxy::client_instruction_lines`] owns). Pure so it is unit-testable. Surface-clean (§1.5): it
/// carries only the peer petname, the display-only SAS, the local `<peer>/<service>` mount names,
/// and the `mcpmesh connect` command — NEVER a raw EndpointId (the daemon never sends one in a
/// `PairResult`).
///
/// The ceremony line comes FIRST and says "next" deliberately: confirming the code is what makes
/// the pairing authentic, and it must happen before the service is used, not after.
fn pair_lines(result: &PairResult) -> Vec<String> {
    let peer = &result.peer_petname;
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

/// `mcpmesh use <peer>/<service>`: print the exact steps to mount the service in an AI client
/// (spec §8/§11.1) — the same block `pair` prints, on demand. Local + read-only: it renders
/// instructions from the target NAME, so it needs no daemon and never asserts the grant exists
/// (a typo'd target simply produces instructions whose `connect` refuses later, plainly).
fn run_use(target: String) -> anyhow::Result<()> {
    let (peer, service) = proxy::split_target(&target)?;
    for line in proxy::client_instruction_lines(&peer, &[service]) {
        println!("{line}");
    }
    Ok(())
}

/// `mcpmesh internal peer add <petname> <endpoint_id> [--allow a,b]`: auto-start the daemon and
/// write the peer entry through it (redb is single-process; the daemon owns the open store).
fn run_peer_add(petname: String, endpoint_id: String, allow: Option<String>) -> anyhow::Result<()> {
    let allow = split_csv(allow);
    with_daemon(async move |mut client| {
        client
            .request(mcpmesh::Request::PeerAdd(PeerAddParams {
                petname: petname.clone(),
                endpoint_id,
                allow,
            }))
            .await?;
        println!("added peer '{petname}'");
        Ok(())
    })
}

/// `mcpmesh internal roster install <file> [--org-root-pk b64u:…]`: auto-start the daemon and install
/// a signed roster over the control API (spec §4.3 manual path). The daemon reads + fully validates
/// the LOCAL file (P12/P14: same-uid, so passing a path not the bytes is within the trust boundary),
/// persists it, hot-swaps the gate, and severs any revoked live sessions (D8). Prints a plain,
/// surface-clean confirmation (§1.5): org_id + serial + severed count (roster-status vocabulary) —
/// NEVER a key / EndpointId / path. A control error (bad signature, rollback serial, no pinned root)
/// propagates out of `main` → the message prints to stderr and the process exits non-zero.
fn run_roster_install(file: PathBuf, org_root_pk: Option<String>) -> anyhow::Result<()> {
    let path = file.to_string_lossy().into_owned();
    with_daemon(async move |mut client| {
        let installed = client.roster_install(&path, org_root_pk).await?;
        println!("{}", roster_install_line(&installed));
        Ok(())
    })
}

/// `mcpmesh internal blob <publish|grant|list|fetch>`: auto-start the daemon and drive the gated
/// app-blob provider over `mcpmesh-local/1`. Surface-clean output (§1.5): tickets/hashes are the §9
/// blob-reference vocabulary; scope names / principals are flat. Errors propagate → non-zero exit.
fn run_internal_blob(command: BlobCmd) -> anyhow::Result<()> {
    with_daemon(async move |mut client| {
        match command {
            BlobCmd::Publish { scope, file } => {
                let path = file.to_string_lossy().into_owned();
                let r = client.blob_publish(&scope, &path).await?;
                println!("Published (hash {}).", r.hash);
                println!("{}", r.ticket);
            }
            BlobCmd::Grant { scope, principal } => {
                client.blob_grant(&scope, &principal).await?;
                println!("Granted scope '{scope}' to '{principal}'.");
            }
            BlobCmd::List => {
                let r = client.blob_list().await?;
                for s in r.scopes {
                    println!(
                        "{}: {} blob(s), granted to [{}]",
                        s.name,
                        s.hashes.len(),
                        s.grants.join(", ")
                    );
                }
            }
            BlobCmd::Fetch { ticket, dest } => {
                let dest_path = dest.to_string_lossy().into_owned();
                let r = client.blob_fetch(&ticket, &dest_path).await?;
                println!(
                    "Fetched {} bytes (hash {}) → {}",
                    r.bytes_len,
                    r.hash,
                    dest.display()
                );
            }
        }
        Ok(())
    })
}

/// `mcpmesh internal audit <tail|list|prune>`: read/rotate the LOCAL audit log directly (spec §11.3 —
/// nothing is transmitted anywhere; no daemon round-trip). Errors propagate → non-zero exit.
fn run_internal_audit(command: AuditCmd) -> anyhow::Result<()> {
    use mcpmesh::audit;
    let dir = paths::default_audit_dir()?;
    match command {
        AuditCmd::Tail { lines, kind, peer } => {
            let kind_filter = match kind.as_deref() {
                Some(s) => {
                    Some(audit::parse_kind(s).with_context(|| format!("unknown --kind '{s}'"))?)
                }
                None => None,
            };
            let all = audit::read_all_records(&dir)?;
            let filtered = audit::filter_records(&all, kind_filter, peer.as_deref());
            let start = filtered.len().saturating_sub(lines);
            for rec in &filtered[start..] {
                println!("{}", serde_json::to_string(rec)?);
            }
        }
        AuditCmd::List => {
            for (month, _, size) in audit::list_month_files(&dir)? {
                println!("{month}  {size} bytes");
            }
        }
        AuditCmd::Prune { before } => {
            let deleted = audit::prune_before(&dir, &before)?;
            if deleted.is_empty() {
                println!("Nothing to prune before {before}.");
            } else {
                println!("Pruned {} month(s): {}.", deleted.len(), deleted.join(", "));
            }
        }
    }
    Ok(())
}

/// Render the `roster install` confirmation (spec §4.3). Pure so it is unit-testable. Surface-clean
/// (§1.5): only the org_id, serial, and severed-session COUNT — all roster-status vocabulary — never
/// a key, EndpointId, or path. Pluralizes "session"/"sessions" on the count.
fn roster_install_line(result: &RosterInstallResult) -> String {
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

/// `mcpmesh status`: auto-start the daemon and drive the control API (spec §6.1). Prints the
/// api/version line from the server's `Hello`, this device's own short fingerprint, then the
/// services and known peers in plain language. Surface-leak discipline (§1.5/§17): the output
/// carries NO transport vocabulary — services show only the backend KIND (never the
/// command/path), peers only their petname (never the EndpointId), and the device's own
/// identity appears only as a short fingerprint (the §1.5 carve-out), never the raw id.
fn run_status() -> anyhow::Result<()> {
    // The device's own short fingerprint (the §1.5 status carve-out) is deterministic from the
    // local device key — derive it directly rather than round-tripping the daemon.
    let fingerprint = load_device_key()?.fingerprint();
    // Whether this node has a `[roster].url` (read from LOCAL config, same-uid). Drives the URL-less
    // degrade hint (§4.3/P13). A config read error degrades to `false` (show the advisory) — never a
    // status failure.
    let has_roster_url = paths::default_config_path()
        .ok()
        .and_then(|p| config::Config::load(&p).ok())
        .map(|c| c.roster.url.is_some())
        .unwrap_or(false);
    with_daemon(async move |mut client| {
        let hello = client.hello().clone();
        let status = client.status().await?;
        render_status(&fingerprint, &hello, &status, has_roster_url);
        Ok(())
    })
}

/// Render `status` in plain language (see [`run_status`] for the surface-leak discipline this
/// upholds). Empty registries read naturally ("no services configured" / "no peers yet").
fn render_status(fingerprint: &str, hello: &Hello, status: &StatusResult, has_roster_url: bool) {
    println!(
        "{} v{} · stack {}",
        hello.api, hello.api_version, hello.stack_version
    );
    println!("device {fingerprint}");
    // This node's own self-sovereign identity (a §1.5-clean opaque user id, not a key): the stable
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
            // pairing — otherwise the peer is petname-only (nothing extra to show).
            match &peer.user_id {
                Some(user_id) => {
                    println!("  {} · services: {services} · {user_id}", peer.name)
                }
                None => println!("  {} · services: {services}", peer.name),
            }
        }
    }

    // The reachability block (pairing-mode liveness): one line per paired peer with its advisory
    // online/offline flag from the on-demand probe cache, plus the last RTT when online. A
    // never-probed peer shows "…" (a refresh is already in flight). Empty → nothing prints.
    // Surface-clean (§1.5): petname + a status word + a latency NUMBER only.
    if !status.reachability.is_empty() {
        println!();
        println!("reachability:");
        for r in &status.reachability {
            let label = match (r.reachable, r.age_secs) {
                (_, None) => "…", // never probed
                (true, _) => "online",
                (false, _) => "offline",
            };
            match r.rtt_ms {
                Some(ms) if r.reachable => println!("  {} · {label} · {ms}ms", r.name),
                _ => println!("  {} · {label}", r.name),
            }
        }
    }

    // The recent-pairings block (spec §4.2 ceremony surface): the INVITER's half of "both humans
    // compare the code" — each pairing this daemon accepted since it started, newest first, with
    // the SAME display-only SAS the redeemer's `pair` printed. In-memory on the daemon (a restart
    // clears it); empty → nothing prints. Surface-clean (§1.5): petname + SAS words + a friendly
    // age ONLY — never an EndpointId.
    if !status.recent_pairings.is_empty() {
        println!();
        println!("recent pairings (confirm the code with the other side):");
        for line in recent_pairing_lines(&status.recent_pairings, util::epoch_now_u64()) {
            println!("{line}");
        }
    }

    // The roster block: printed ONLY in roster mode (a pure-pairing daemon sends `roster: None`,
    // so nothing prints — byte-identical to M2b status).
    if let Some(roster) = &status.roster {
        println!();
        for line in roster_status_lines(roster, has_roster_url) {
            println!("{line}");
        }
    }

    // The reachable-peers block (spec §10.1 advisory presence read): one line per roster device with
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

/// Render the `status` next-steps footer: the exact command for each thing this node can do from
/// where it currently is. Pure so it is unit-testable. Surface-clean (§1.5): petnames + service
/// names + porcelain commands only.
///
/// Each step is offered only when it is genuinely the user's next move, so a fully configured node
/// prints no nag — the footer is guidance, not decoration.
fn next_steps_lines(status: &StatusResult) -> Vec<String> {
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
/// `  <petname> · code: <sas> · <age>`. Pure so it is unit-testable. Surface-clean (§1.5/§17):
/// the peer petname, the display-only SAS words (the pairing-ceremony artifact, like
/// [`pair_lines`]'s), and a friendly age ONLY — a `RecentPairing` carries no EndpointId, so the
/// lines can't either.
fn recent_pairing_lines(pairings: &[RecentPairing], now: u64) -> Vec<String> {
    pairings
        .iter()
        .map(|p| {
            format!(
                "  {} · code: {} · {}",
                p.peer_petname,
                p.sas_code,
                friendly_age(p.paired_at_epoch, now)
            )
        })
        .collect()
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

/// Render the advisory presence block of `status` (spec §10.1): one line per reachable roster device,
/// `user_id · device_label · role · (online|offline)`. Pure so it is unit-testable. Surface-clean
/// (§1.5/§17): FLAT vocabulary ONLY — user_id, device_label, role, and a plain online/offline word;
/// never an EndpointId / key / hash / ALPN.
fn presence_lines(presence: &[PresencePeer]) -> Vec<String> {
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

/// Render the roster-mode block of `status` (spec §4.4). Pure so it is unit-testable. Surface-clean
/// (§1.5): only roster/ceremony vocabulary — org_id, serial, the plain state word, and the org-root
/// FINGERPRINT in short words. The `org root:` line is OMITTED when the fingerprint is empty (a
/// missing/unparseable pin degrades gracefully), so there is never a dangling label.
fn roster_status_lines(roster: &RosterStatus, has_roster_url: bool) -> Vec<String> {
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
    // URL-less degrade hint (spec §4.3/P13): a roster-mode node with NO `[roster].url` has no
    // authenticated channel to re-confirm currency, so it degrades toward stale after `max_staleness`.
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

/// Plain-language label for a backend kind — the KIND only (never the command/path, §17).
fn backend_kind_label(kind: BackendKind) -> &'static str {
    match kind {
        BackendKind::Run => "run",
        BackendKind::Socket => "socket",
    }
}

/// `mcpmesh internal watch`: subscribe to the daemon's live event stream and pretty-print it
/// (pairing liveness & health telemetry). A thin reference consumer of the TYPED `subscribe`
/// surface ([`client::ControlClient::subscribe`] → [`StreamFrame`]) — the UAT/dogfood window on
/// the mesh. Auto-starts the daemon, opens the stream (the same connection-upgrade as
/// `open_session`, one-way after the request), and loops printing frames until the stream ends or
/// the process is interrupted. Surface-clean (§1.5): the output carries only the
/// petnames/user_ids/service names/numbers the frames themselves carry — never a raw endpoint-id
/// (the frames don't carry one).
fn run_watch() -> anyhow::Result<()> {
    with_daemon(async move |client| {
        let mut stream = client.subscribe().await?;
        println!("watching the mesh — Ctrl-C to stop");
        while let Some(frame) = stream.next().await? {
            println!("{}", render_frame(&frame));
        }
        Ok(())
    })
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
/// trust event has no peer/service — never a dangling separator). Surface-clean (§1.5): only
/// petnames/service names/user_ids/numbers appear — the stream carries no endpoint-id.
fn render_frame(frame: &StreamFrame) -> String {
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

/// `mcpmesh internal id`: print this machine's full endpoint id in iroh's base32 encoding — the
/// same encoding `internal peer add <petname> <endpoint_id>` parses (`EndpointId` Display /
/// `parse::<iroh::EndpointId>()`). This is the §1.5 "--verbose/doctor-class" raw-id surface
/// (deliberately NOT in plain `status`): a human on machine A copies A's id and runs
/// `internal peer add A <id>` on machine B. Derived LOCALLY from the device key — the id is
/// deterministic (`SecretKey::from_bytes(device.secret).public()`, and `EndpointId` is a
/// `PublicKey` alias), so no daemon round-trip is needed.
fn run_internal_id() -> anyhow::Result<()> {
    let key = load_device_key()?;
    let endpoint_id = iroh::SecretKey::from_bytes(&key.secret_bytes()).public();
    println!("{endpoint_id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use mcpmesh::roster;
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
            peer_petname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into()],
        };
        let lines = pair_lines(&result);
        assert_eq!(lines[0], "Paired with alice — code: tango-fig-42");
        // The SAS line is exactly `... — code: <words>` (the §4.2 human-checkable format).
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
            peer_petname: "alice".into(),
            sas_code: "a-b-c".into(),
            services: vec!["notes".into(), "kb".into()],
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
        // §1.5: the pair porcelain shows the petname, the SAS, and the local `<peer>/<service>`
        // mount names — all permitted pairing artifacts. It must NEVER contain a raw base32
        // EndpointId. A PairResult carries none, so the rendered lines can't either; assert it.
        let alice_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string();
        let result = PairResult {
            peer_petname: "alice".into(),
            sas_code: "tango-fig-42".into(),
            services: vec!["notes".into()],
        };
        let rendered = pair_lines(&result).join("\n");
        assert!(
            !rendered.contains(&alice_id),
            "pair output must not leak an EndpointId: {rendered}"
        );
        // No transport vocabulary either (§17).
        for term in ["ALPN", "ticket", "mcpmesh/pair/1", "mcpmesh/mcp/1"] {
            assert!(!rendered.contains(term), "pair output leaked '{term}'");
        }
    }

    #[test]
    fn pair_lines_tolerate_an_empty_service_grant() {
        // Defensive shape: no dangling "You can mount:" when services is empty.
        let result = PairResult {
            peer_petname: "alice".into(),
            sas_code: "a-b-c".into(),
            services: vec![],
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
    fn roster_install_line_renders_org_serial_and_pluralized_sever_count() {
        // The task's canonical single-session confirmation shape.
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
        // §1.5: the confirmation carries roster-status vocabulary (org_id, serial, severed count)
        // ONLY — never a key, EndpointId, path, or any transport term. org_id is operator-chosen;
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
        // The task's canonical roster block: a summary line + an org-root fingerprint line.
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
        // Roster-mode but no `[roster].url`: the node has no way to re-confirm currency, so it degrades
        // toward stale after max_staleness (§4.3/P13 — correct, not a bug). Surface the advisory hint.
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
        // §1.5/§17: the reachable block carries FLAT vocabulary ONLY (user_id/device_label/role/
        // online) — never a raw key, EndpointId, hash, or ALPN.
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
        // §1.5: the roster block carries roster/ceremony vocabulary ONLY (org_id, serial, the state
        // word, and the fingerprint WORDS) — never a raw key, EndpointId, roster path, or ALPN.
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
    fn org_invite_carries_and_round_trips_the_roster_url() {
        // `org create --roster-url U` populates `OrgInviteCode.roster_url` (M3b left it None); the
        // opaque `mcpmesh-org:` codec round-trips it so a joiner reads the SAME URL back (D5 bootstrap).
        let url = "https://intranet.acme.com/roster.json";
        let code = roster::enroll::OrgInviteCode {
            org_id: "acme".into(),
            org_root_pk: "b64u:AAAA".into(),
            roster_url: Some(url.to_string()),
        };
        let decoded = roster::enroll::OrgInviteCode::decode(&code.encode()).unwrap();
        assert_eq!(decoded.roster_url.as_deref(), Some(url));
        assert_eq!(decoded.org_id, "acme");
        // A URL-less create still round-trips to None (byte-identical to M3b — the additive field).
        let bare = roster::enroll::OrgInviteCode {
            org_id: "acme".into(),
            org_root_pk: "b64u:AAAA".into(),
            roster_url: None,
        };
        assert!(
            roster::enroll::OrgInviteCode::decode(&bare.encode())
                .unwrap()
                .roster_url
                .is_none()
        );
    }

    #[test]
    fn recent_pairing_lines_render_petname_code_and_age() {
        let pairings = vec![
            RecentPairing {
                peer_petname: "bob".into(),
                sas_code: "tango-fig-cabbage".into(),
                paired_at_epoch: 1_000_000,
            },
            RecentPairing {
                peer_petname: "carol".into(),
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
        // §1.5: the recent-pairings block carries the petname, the SAS words, and a friendly age
        // ONLY. A RecentPairing carries no EndpointId, so the lines can't either — assert it, and
        // assert no transport vocabulary (§17).
        let bob_id = iroh::SecretKey::from_bytes(&[7u8; 32]).public().to_string();
        let pairings = vec![RecentPairing {
            peer_petname: "bob".into(),
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
    /// `run_watch`'s typed subscription takes, so these tests pin BOTH that the documented wire
    /// JSON deserializes and how it renders.
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

    #[test]
    fn a_garbage_org_invite_is_a_single_sentence() {
        // Issue #10 style 3 (the join-garbage two-line case): the decode error IS the user
        // sentence; no context layer repeats it.
        let err = roster::enroll::OrgInviteCode::decode("garbage").unwrap_err();
        let lines = error_lines(&err);
        assert_eq!(
            lines,
            vec!["Error: not an mcpmesh-org: code (missing scheme)".to_string()]
        );
    }
}
