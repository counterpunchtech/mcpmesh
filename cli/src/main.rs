use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mcpmesh::enrollcmd::{load_device_key, split_csv, with_daemon};
use mcpmesh::render::{self, SERVE_EXAMPLE};
use mcpmesh::{config, daemon, doctor, enrollcmd, proxy, util};
use mcpmesh_local_api::{BackendSpec, PeerAddParams};
use mcpmesh_trust::paths;

/// The `serve` after-help block: one COMPLETE worked example (see
/// [`render::SERVE_EXAMPLE`] for why it is a folder share) plus the next step.
fn serve_after_help() -> String {
    format!(
        "Example — share a folder of notes (needs npx; no MCP server of your own required):\n  \
         {SERVE_EXAMPLE}\n\nThen `mcpmesh invite notes` mints an invite to send whoever you're \
         sharing with."
    )
}

#[derive(Parser)]
#[command(name = "mcpmesh", version)]
struct Cli {
    /// Run against an isolated PROFILE rooted at this directory — all keys, config, data, state,
    /// and the control socket live under it, instead of the standard per-user locations. One flag
    /// replaces overriding five XDG_* env vars to sandbox an instance. The spawned daemon inherits
    /// it (via MCPMESH_HOME), so every verb in this profile rendezvous on the same socket.
    #[arg(long, value_name = "dir", global = true, visible_alias = "home")]
    profile: Option<PathBuf>,
    /// Print machine-readable JSON instead of prose: one JSON value on stdout, and a
    /// failure becomes a single `{"error":{"code":…,"message":…}}` line on stderr
    /// (`code` is the control API's error code when the daemon refused, else null).
    /// Shapes mirror the mcpmesh-local/1 result types — see AGENTS.md. No effect on
    /// `connect` (a byte pipe) or `internal daemon`.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serving what, to whom; reachable peers; trust freshness.
    Status,
    /// Check this machine's mcpmesh health (read-only).
    ///
    /// Lints the config, key file permissions, trust freshness, the relay/discovery
    /// self-hosting combination, and the runtime dir; optionally pings the daemon.
    /// Local-only — it inspects and reports, never changes anything and never touches
    /// the network. Exits non-zero on ERROR.
    Doctor,
    /// Share a local MCP server with people you choose.
    ///
    /// Auto-starts the daemon, writes the `[services.<name>]` config entry, and
    /// hot-reloads serving. Everything after `--` is just the command that runs a
    /// stdio MCP server — any one, under a name you pick. No MCP server of your own?
    /// The example below shares a folder and needs nothing but npx.
    #[command(after_help = serve_after_help())]
    Serve {
        /// Service name — how peers address it (`connect <peer>/<name>`).
        name: String,
        /// Comma-separated nicknames/groups admitted to this service.
        #[arg(long)]
        allow: Option<String>,
        /// The command to run per session, after `--` (a stdio MCP server).
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Ensure the daemon is running and ready, then print its control-socket path.
    ///
    /// For embedders and scripts: a first-class, synchronous "bring the daemon up"
    /// that blocks until it actually accepts connections (or is already running → a
    /// fast no-op), prints the endpoint path on success, and exits non-zero with a
    /// useful message on failure (bad config, permissions, socket in use). Unlike
    /// bringing the daemon up as a side effect of `status`, readiness here is the
    /// command's contract, not something to infer by probing.
    Up {
        /// Seconds to wait for a freshly-started daemon to become ready (default 10).
        #[arg(long, value_name = "secs")]
        timeout: Option<u64>,
    },
    /// The stdio proxy an AI client runs to reach a peer's service.
    ///
    /// Auto-starts the daemon, opens the session, and pipes MCP frames
    /// stdin<->daemon<->stdout verbatim. This is the command an AI client's MCP
    /// config points at — `mcpmesh use <peer>/<service>` prints the exact entry.
    Connect {
        /// The service to reach, as `<peer>/<service>`.
        target: String,
    },
    /// Mint a one-time invite granting access to your services.
    ///
    /// Auto-starts the daemon and prints the copyable `mcpmesh-invite:` line to
    /// share out-of-band; whoever redeems it can access the listed services on this
    /// machine.
    Invite {
        /// One or more service names the redeemer is granted (space-separated). At least one is
        /// required — an invite granting nothing is useless.
        services: Vec<String>,
        /// An opaque application label carried through to the redeemer's pair result. mcpmesh
        /// never interprets it — a slot for an embedding app to pass its own identity/metadata.
        #[arg(long, value_name = "text")]
        label: Option<String>,
    },
    /// Redeem an invite to access a peer's services, or unpair a peer.
    ///
    /// Auto-starts the daemon. `--remove <nickname>` drops the peer's trust entry and
    /// revokes its access to YOUR services; it does NOT cut sessions already in
    /// flight (those run to completion), only the ability to open new ones.
    Pair {
        /// The `mcpmesh-invite:...` string to redeem. Omit when using `--remove`.
        invite: Option<String>,
        /// Unpair a peer by nickname instead of redeeming an invite.
        #[arg(long, value_name = "nickname")]
        remove: Option<String>,
    },
    /// Print the steps to use a peer's service from your AI client.
    ///
    /// Shows the Claude Code command, the Claude Desktop config entry + where it
    /// goes, and the generic stdio command any other MCP client takes. `pair` prints
    /// this automatically; run `use` to see it again.
    Use {
        /// The service to mount, as `<peer>/<service>`.
        target: String,
    },
    /// Join an org from its invite (roster mode).
    ///
    /// Mints your user key, pins the org root, and prints the join code to send the
    /// operator plus the org-root fingerprint to confirm out-of-band.
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
    /// Create and operate an org: approve joiners, revoke access (roster mode).
    Org {
        #[command(subcommand)]
        command: OrgCmd,
    },
    /// Link this person's other devices into the roster (roster mode).
    ///
    /// Keys never move between machines: the new device prints a code, an
    /// already-enrolled device signs it, and the operator approves the result.
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
    /// Mint the org root key and sign an empty roster (one-time per node).
    ///
    /// Prints the org invite code (`mcpmesh-org:…`) to hand to joiners, plus the
    /// org-root fingerprint for the enrollment ceremony. Refuses if this node
    /// already holds an org root (one org per node).
    Create {
        /// The org id (also the roster `org_id`).
        name: String,
        /// Roster validity window from now (e.g. `90d`, `12h`; default `90d`).
        #[arg(long)]
        expires: Option<String>,
        /// The pinned HTTPS roster URL joiners poll for their FIRST + ongoing roster.
        /// Carried in the org invite (so joiners bootstrap without waiting on a peer)
        /// AND stored in this operator's config `[roster].url` (the operator keeps
        /// the hosted document current).
        #[arg(long)]
        roster_url: Option<String>,
    },
    /// Approve a joiner: add the person + device to the roster and re-sign.
    ///
    /// Verifies the join code's device binding, grants the named groups, and
    /// installs the updated roster (severing nothing new). Run this AFTER
    /// confirming the person out-of-band — that confirmation is the ceremony.
    Approve {
        /// The `mcpmesh-join:…` code from the joiner's `join`.
        join_code: String,
        /// Comma-separated groups to grant (e.g. `team-eng,all`). Declared in the roster if new.
        #[arg(long)]
        groups: String,
        /// Override the joiner's requested stable user_id. Defaults to the join code's value.
        #[arg(long)]
        user_id: Option<String>,
    },
    /// Revoke access for a person or one device, or rotate a user key.
    ///
    /// `<person>` removes a departing person (and revokes all their devices);
    /// `<person>/<device>` revokes one device; `--user-key <person>` runs the
    /// user-key rotation runbook (removes the person so they re-enroll with a fresh
    /// user key — the SAME devices).
    Revoke {
        /// `alice` (person) or `alice/laptop` (device). With `--user-key`, a bare person.
        target: String,
        /// User-key rotation: remove the person WITHOUT permanently revoking their
        /// devices, so the same machine re-enrolls with a new user key.
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
    /// binding with YOUR user key and print a join code for the operator.
    Add {
        /// The `mcpmesh-device:…` code from the new machine's `devices code`.
        device_code: String,
    },
}

#[derive(Subcommand)]
enum Internal {
    /// Run the long-lived daemon: bind the control socket and serve the local API.
    /// Auto-started by any porcelain verb; a redundant instance exits 0.
    Daemon,
    /// Print this machine's full endpoint id.
    ///
    /// The raw-id surface deliberately kept OUT of plain `status`: the OTHER
    /// machine's `internal peer add <nickname> <id>` parses exactly this. Derived
    /// locally from the device key (the id is deterministic; no daemon round-trip).
    Id,
    /// Peer allowlist management — an internal stand-in for pairing (prefer `mcpmesh pair`).
    Peer {
        #[command(subcommand)]
        command: PeerCmd,
    },
    /// Installed-roster management.
    ///
    /// The manual convergence path when no roster URL is configured — the operator
    /// obtains the signed roster + org-root key out-of-band.
    Roster {
        #[command(subcommand)]
        command: RosterCmd,
    },
    /// Gated app-blob operations (roster mode only).
    ///
    /// Publish a file into a scope, grant a scope to a group or person, list
    /// scopes, fetch a ticket through the daemon. Auto-starts the daemon.
    Blob {
        #[command(subcommand)]
        command: BlobCmd,
    },
    /// View or rotate the LOCAL append-only audit log.
    ///
    /// Reads `~/.local/state/mcpmesh/audit/*.jsonl` DIRECTLY — no daemon, no
    /// network (nothing is transmitted anywhere). `tail` prints recent records
    /// (optionally filtered); `list` shows the monthly files; `prune --before
    /// YYYY-MM` deletes older months (the rotation boundary).
    Audit {
        #[command(subcommand)]
        command: AuditCmd,
    },
    /// Watch the daemon's live event stream (pairing liveness + health telemetry).
    ///
    /// Auto-starts the daemon, prints a one-line snapshot summary, then a line per
    /// event (and a lagged notice if a consumer falls behind). Runs until
    /// interrupted (Ctrl-C).
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
    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (hash-verified) and write it to `dest`.
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
    /// Install a signed roster from a local FILE.
    ///
    /// Auto-starts the daemon, which reads + fully validates the file (signature,
    /// serial, validity window, structure), persists it, hot-swaps the trust gate,
    /// and severs any live sessions it revokes. `--org-root-pk` pins the org root
    /// on the FIRST install; omit it once pinned.
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
    /// Add a peer to the allowlist by nickname + endpoint id.
    ///
    /// Routes through the daemon (which owns the open store), so it auto-starts
    /// the daemon if needed.
    Add {
        /// Local human name the gate resolves this peer to.
        nickname: String,
        /// The peer's endpoint id (from that machine's `internal id`).
        endpoint_id: String,
        /// Comma-separated services recorded as this peer's grant. NOTE: this list is
        /// informational (shown in `status`) — actual access to a service is gated by that
        /// service's own `allow` list.
        #[arg(long)]
        allow: Option<String>,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // Pin the profile root BEFORE any path resolves (keys, config, socket) — an in-process
    // override, since `set_var` is barred under `forbid(unsafe_code)`. Absolute-ize a relative
    // `--profile` against the cwd so the value handed to the spawned daemon is unambiguous.
    if let Some(dir) = &cli.profile {
        let abs = if dir.is_absolute() {
            dir.clone()
        } else {
            std::env::current_dir()
                .map(|c| c.join(dir))
                .unwrap_or_else(|_| dir.clone())
        };
        let _ = paths::set_root(abs);
    }
    let json = cli.json;
    match run(cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            if json {
                eprintln!("{}", mcpmesh::json::error_json(&err));
            } else {
                for line in render::error_lines(&err) {
                    eprintln!("{line}");
                }
            }
            std::process::ExitCode::FAILURE
        }
    }
}

/// Dispatch the parsed command — split from [`main`] so every verb's failure flows through
/// the one rendering path ([`render::error_lines`]).
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        // The daemon owns its own runtime; dispatch it before the porcelain preamble.
        Some(Cmd::Internal {
            command: Internal::Daemon,
        }) => daemon::run(),
        Some(Cmd::Internal {
            command: Internal::Id,
        }) => run_internal_id(),
        Some(Cmd::Serve { name, allow, cmd }) => run_serve(name, allow, cmd, cli.json),
        Some(Cmd::Connect { target }) => run_connect(target),
        Some(Cmd::Invite { services, label }) => run_invite(services, label, cli.json),
        Some(Cmd::Pair { invite, remove }) => run_pair(invite, remove, cli.json),
        Some(Cmd::Use { target }) => run_use(target, cli.json),
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
                            nickname,
                            endpoint_id,
                            allow,
                        },
                },
        }) => run_peer_add(nickname, endpoint_id, allow),
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
        Some(Cmd::Doctor) => doctor::run_doctor(cli.json),
        Some(Cmd::Up { timeout }) => run_up(timeout, cli.json),
        Some(Cmd::Status) | None => run_status(cli.json),
    }
}

/// `mcpmesh up [--timeout N]`: bring the daemon up synchronously and print its control-socket
/// path. Readiness is the contract — `ensure_daemon_with_timeout` returns only once the daemon
/// answers its `Hello`, so a script needs no post-hoc socket probe. A start failure surfaces the
/// daemon's own captured reason and exits non-zero (via the normal error path). The socket path
/// goes to stdout alone, so `SOCK=$(mcpmesh up)` is a clean one-liner.
fn run_up(timeout: Option<u64>, json: bool) -> anyhow::Result<()> {
    let launch = mcpmesh::client::DaemonLaunch::ambient()?;
    let ready = timeout
        .map(std::time::Duration::from_secs)
        .unwrap_or(mcpmesh::client::DEFAULT_READY_TIMEOUT);
    let socket = launch.socket.clone();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        // Connects if live (fast no-op), else spawns and blocks until it answers Hello.
        let _client = mcpmesh::client::ensure_daemon_with_timeout(&launch, ready).await?;
        Ok::<(), anyhow::Error>(())
    })?;
    if json {
        println!("{}", mcpmesh::json::up_json(&socket));
    } else {
        println!("{}", socket.display());
    }
    Ok(())
}

/// `mcpmesh serve <name> [--allow a,b] -- <cmd...>`: auto-start the daemon and register the
/// service over the control API (which persists it + hot-reloads serving).
fn run_serve(
    name: String,
    allow: Option<String>,
    cmd: Vec<String>,
    json: bool,
) -> anyhow::Result<()> {
    let allow = split_csv(allow);
    with_daemon(async move |mut client| {
        client
            .register_service(&name, BackendSpec::Run { cmd }, allow)
            .await?;
        if json {
            println!("{}", mcpmesh::json::serve_json(&name));
            return Ok(());
        }
        println!("serving '{name}'");
        // The next exact instruction. Nothing is shared until someone is granted access, so the
        // invite is ALWAYS the next step — `--allow` names nicknames, but only a redeemed invite
        // (or a roster) makes a nickname resolve to a real peer.
        println!(
            "Next: run `mcpmesh invite {name}` to mint a one-time invite, and send it to the \
             person you want to share it with."
        );
        Ok(())
    })
}

/// `mcpmesh connect <peer>/<service>`: the stdio proxy an AI client runs. Blocks
/// pumping the session until stdin closes or the remote ends.
fn run_connect(target: String) -> anyhow::Result<()> {
    let (peer, service) = proxy::split_target(&target)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(proxy::run(peer, service))
}

/// `mcpmesh invite [services…]`: auto-start the daemon, mint a one-time pairing invite granting
/// `services`, and print the copyable `mcpmesh-invite:` line (the one opaque pairing artifact
/// the output discipline permits printing plainly) plus a plain-language expiry and the granted
/// services.
///
/// Empty `services` is an ERROR: an invite that grants nothing is useless, and erroring here is
/// friendlier than minting a dead invite the redeemer can do nothing with.
fn run_invite(services: Vec<String>, label: Option<String>, json: bool) -> anyhow::Result<()> {
    if services.is_empty() {
        anyhow::bail!("specify at least one service to grant (e.g. `mcpmesh invite notes`)");
    }
    with_daemon(async move |mut client| {
        let invite = client.invite_with(services.clone(), label).await?;
        if json {
            println!("{}", mcpmesh::json::invite_json(&invite, &services));
            return Ok(());
        }
        for line in render::invite_lines(&invite, &services, util::epoch_now_u64()) {
            println!("{line}");
        }
        Ok(())
    })
}

/// `mcpmesh pair <invite>` / `mcpmesh pair --remove <nickname>`: auto-start the daemon, then either
/// redeem an invite (printing the SAS + mountable `<peer>/<service>` targets) or unpair a peer.
/// Exactly one of the invite arg / `--remove` must be given.
///
/// A control-API error (a pair refused/expired/id-mismatch, or a peer_remove failure) propagates
/// out of `main` → the process prints the message to stderr and exits non-zero.
fn run_pair(invite: Option<String>, remove: Option<String>, json: bool) -> anyhow::Result<()> {
    match (invite, remove) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide an invite to redeem OR --remove <nickname>, not both")
        }
        (None, None) => {
            anyhow::bail!("provide an invite to redeem, or --remove <nickname> to unpair")
        }
        (Some(invite_line), None) => with_daemon(async move |mut client| {
            let paired = client.pair(&invite_line).await?;
            if json {
                println!("{}", mcpmesh::json::pair_json(&paired));
                return Ok(());
            }
            for line in render::pair_lines(&paired) {
                println!("{line}");
            }
            Ok(())
        }),
        (None, Some(nickname)) => with_daemon(async move |mut client| {
            client.peer_remove(&nickname).await?;
            // Sessions already in flight are NOT severed (they run to completion) — only new
            // authorized sessions are blocked from here on. The nickname just stops resolving
            // + being admitted.
            if json {
                println!("{}", mcpmesh::json::unpair_json(&nickname));
            } else {
                println!("Unpaired {nickname}.");
            }
            Ok(())
        }),
    }
}

/// `mcpmesh use <peer>/<service>`: print the exact steps to mount the service in an AI client —
/// the same block `pair` prints, on demand. Validates the target against the daemon's known
/// peers/services first (issue #12): a typo'd target gets the known list NOW, not a refusal
/// later when the AI client first runs `connect`.
fn run_use(target: String, json: bool) -> anyhow::Result<()> {
    let (peer, service) = proxy::split_target(&target)?;
    with_daemon(async move |mut client| {
        let status = client.status().await?;
        if let Some(message) = render::use_target_error(&peer, &service, &status.peers) {
            anyhow::bail!("{message}");
        }
        if json {
            println!("{}", mcpmesh::json::use_json(&peer, &[service]));
            return Ok(());
        }
        for line in proxy::client_instruction_lines(&peer, &[service]) {
            println!("{line}");
        }
        Ok(())
    })
}

/// `mcpmesh internal peer add <nickname> <endpoint_id> [--allow a,b]`: auto-start the daemon and
/// write the peer entry through it (redb is single-process; the daemon owns the open store).
fn run_peer_add(
    nickname: String,
    endpoint_id: String,
    allow: Option<String>,
) -> anyhow::Result<()> {
    let allow = split_csv(allow);
    with_daemon(async move |mut client| {
        client
            .request(mcpmesh::Request::PeerAdd(PeerAddParams {
                nickname: nickname.clone(),
                endpoint_id,
                allow,
            }))
            .await?;
        println!("added peer '{nickname}'");
        Ok(())
    })
}

/// `mcpmesh internal roster install <file> [--org-root-pk b64u:…]`: auto-start the daemon and
/// install a signed roster over the control API. The daemon reads + fully validates the LOCAL
/// file (same-uid, so passing a path not the bytes is within the trust boundary), persists it,
/// hot-swaps the gate, and severs any revoked live sessions. Prints a plain, surface-clean
/// confirmation: org_id + serial + severed count (roster-status vocabulary) — NEVER a key /
/// endpoint id / path. A control error (bad signature, rollback serial, no pinned root)
/// propagates out of `main` → the message prints to stderr and the process exits non-zero.
fn run_roster_install(file: PathBuf, org_root_pk: Option<String>) -> anyhow::Result<()> {
    let path = file.to_string_lossy().into_owned();
    with_daemon(async move |mut client| {
        let installed = client.roster_install(&path, org_root_pk).await?;
        println!("{}", render::roster_install_line(&installed));
        Ok(())
    })
}

/// `mcpmesh internal blob <publish|grant|list|fetch>`: auto-start the daemon and drive the gated
/// app-blob provider over the control API. Surface-clean output: tickets/hashes are the
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

/// `mcpmesh internal audit <tail|list|prune>`: read/rotate the LOCAL audit log directly —
/// nothing is transmitted anywhere; no daemon round-trip. Errors propagate → non-zero exit.
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

/// `mcpmesh status`: auto-start the daemon and drive the control API. Prints the api/version
/// line from the server's `Hello`, this device's own short fingerprint, then the services and
/// known peers in plain language. Surface-leak discipline (the SECURITY.md bar): the output
/// carries NO transport vocabulary — services show only the backend KIND (never the
/// command/path), peers only their nickname (never the endpoint id), and the device's own
/// identity appears only as a short fingerprint, never the raw id.
fn run_status(json: bool) -> anyhow::Result<()> {
    // The device's own short fingerprint (the deliberate identity carve-out from the raw-id
    // ban) is deterministic from the local device key — derive it directly rather than
    // round-tripping the daemon.
    let fingerprint = load_device_key()?.fingerprint();
    // Whether this node has a `[roster].url` (read from LOCAL config, same-uid). Drives the
    // URL-less degrade hint. A config read error degrades to `false` (show the advisory) —
    // never a status failure.
    let has_roster_url = paths::default_config_path()
        .ok()
        .and_then(|p| config::Config::load(&p).ok())
        .map(|c| c.roster.url.is_some())
        .unwrap_or(false);
    with_daemon(async move |mut client| {
        let hello = client.hello().clone();
        let status = client.status().await?;
        if json {
            println!("{}", mcpmesh::json::status_json(&fingerprint, &hello, &status));
        } else {
            render::render_status(&fingerprint, &hello, &status, has_roster_url);
        }
        Ok(())
    })
}

/// `mcpmesh internal watch`: subscribe to the daemon's live event stream and pretty-print it
/// (pairing liveness & health telemetry). A thin reference consumer of the TYPED `subscribe`
/// surface — the dogfood window on the mesh. Auto-starts the daemon, opens the stream (the same
/// connection-upgrade as `open_session`, one-way after the request), and loops printing frames
/// until the stream ends or the process is interrupted. Surface-clean: the output carries only
/// the nicknames/user_ids/service names/numbers the frames themselves carry — never a raw
/// endpoint id (the frames don't carry one).
fn run_watch() -> anyhow::Result<()> {
    with_daemon(async move |client| {
        let mut stream = client.subscribe().await?;
        println!("watching the mesh — Ctrl-C to stop");
        while let Some(frame) = stream.next().await? {
            println!("{}", render::render_frame(&frame));
        }
        Ok(())
    })
}

/// `mcpmesh internal id`: print this machine's full endpoint id — the same encoding
/// `internal peer add <nickname> <endpoint_id>` parses. This is the doctor-class raw-id surface
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

    #[test]
    fn org_invite_carries_and_round_trips_the_roster_url() {
        // `org create --roster-url U` populates `OrgInviteCode.roster_url`; the opaque
        // `mcpmesh-org:` codec round-trips it so a joiner reads the SAME URL back and can
        // bootstrap its first roster without waiting on a peer.
        let url = "https://intranet.acme.com/roster.json";
        let code = roster::enroll::OrgInviteCode {
            org_id: "acme".into(),
            org_root_pk: "b64u:AAAA".into(),
            roster_url: Some(url.to_string()),
        };
        let decoded = roster::enroll::OrgInviteCode::decode(&code.encode()).unwrap();
        assert_eq!(decoded.roster_url.as_deref(), Some(url));
        assert_eq!(decoded.org_id, "acme");
        // A URL-less create still round-trips to None (the additive field).
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
}
