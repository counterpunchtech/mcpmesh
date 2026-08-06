use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mcpmesh::enrollcmd::{load_device_key, split_csv, with_daemon};
use mcpmesh::render::{self, SERVE_EXAMPLE};
use mcpmesh::{config, doctor, enrollcmd, proxy, util};
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
        /// Comma-separated principals admitted to this service: paired-peer nicknames
        /// (resolved to stable principals at write time), `b64u:` user_ids, `eid:` device
        /// principals, or roster group names.
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
    /// Mint an invite granting access to your services. Single-use unless `--uses` says otherwise.
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
        /// How many people may redeem this one invite (#87). Default 1.
        ///
        /// Each redemption is its OWN pairing — its own code to compare, its own trust entry. One
        /// link onboards a team instead of one ceremony per person.
        ///
        /// It is a bearer credential for that many redemptions until it expires, so it is capped;
        /// the value actually applied is printed back.
        #[arg(long, value_name = "n")]
        uses: Option<u32>,
        /// Enroll another of YOUR OWN devices instead of pairing with someone else (#86).
        ///
        /// The redeeming device becomes another device of you: both present the same identity, so
        /// every peer sees one person. Nothing is granted and neither side becomes the other's
        /// contact — your own devices are not peers of each other.
        ///
        /// **Compare the SAS words.** The inviter signs an identity binding for whichever device
        /// redeems, so this matters more here than in an ordinary pairing.
        ///
        /// Single-use only, and grants no services. Enroll every device from the one that holds
        /// your user key — an enrolled device cannot enroll a third.
        #[arg(long, conflicts_with_all = ["uses", "peer_name"])]
        as_self: bool,
        /// YOUR name for whoever redeems this invite, instead of the name their machine claims
        /// (#87).
        ///
        /// Two same-model laptops both call themselves the same thing, and the second pairing is
        /// refused. This is the fix that does not need them to rename their machine. It is local:
        /// they never see it, and it does not change what they call themselves. Cannot be combined
        /// with `--uses` above 1 — one name for every redeemer collides on the second.
        #[arg(long, value_name = "name")]
        peer_name: Option<String>,
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
        /// YOUR name for the inviter, instead of the one their invite suggests (#87).
        ///
        /// Use it when you already call a different peer by that name — otherwise the pairing is
        /// refused and the only other fixes are asking them to send a new invite, or unpairing
        /// whoever holds the name. It is local: they never see it.
        #[arg(long = "as", value_name = "name")]
        as_nickname: Option<String>,
        /// Redeem a `mcpmesh-enroll:` link, adding THIS device to the inviter's identity (#178).
        ///
        /// Required for an enrollment link, refused for anything else. Without it `pair` declines
        /// the link and tells you what it was — because the two artifacts look alike and do very
        /// different things. An ordinary invite makes you contacts; an enrollment link makes this
        /// machine another device of that person, so everyone who trusts them starts admitting it,
        /// and undoing that means rotating a key you do not hold.
        ///
        /// Use it on YOUR second machine, with a link YOUR other machine minted
        /// (`mcpmesh invite --as-self`).
        #[arg(long = "as-self")]
        as_self: bool,
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
    /// Print a shell completion script to stdout.
    ///
    /// Install e.g. `mcpmesh completions zsh > "${fpath[1]}/_mcpmesh"` or
    /// `mcpmesh completions bash > /etc/bash_completion.d/mcpmesh`.
    Completions {
        /// The shell to emit a script for.
        shell: clap_complete::Shell,
    },
    /// Back up or restore THIS person's identity — the `b64u:` user id peers pin (#85).
    Identity {
        #[command(subcommand)]
        command: IdentityCmd,
    },
    /// Get a replacement machine admitted by the peers you already pair with (#85).
    ///
    /// After `mcpmesh identity import` restores your identity on new hardware, your peers still do
    /// not know that machine — they authorize per device. This is how it gets in, without an
    /// in-person ceremony with each of them.
    Attest {
        #[command(subcommand)]
        command: AttestCmd,
    },
    /// Mark a device DEAD — locally, or with a signed statement your peers can apply (#85).
    ///
    /// Not the same as `pair --remove`. Removal says "we are not working together"; a re-pair
    /// afterwards is normal. Revocation says "this device is compromised", outlives the pair row,
    /// and cuts live sessions immediately.
    Revoke {
        #[command(subcommand)]
        command: RevokeCmd,
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
    /// Rotate the org root key, so a compromised or aging anchor can be replaced.
    ///
    /// Publishes a roster signed by the NEW key and cross-signed by the current one. Members adopt
    /// the new anchor as they receive it — including members that were offline when you ran this,
    /// because the bridge rides every later roster.
    ///
    /// A member two rotations behind needs a fresh `join`. And this is NOT recovery for a LOST key:
    /// with nothing to cross-sign, there is no bridge. Copy `org-root.key` to a second operator
    /// machine for that.
    Rotate {
        /// Where to read or write the successor key. Defaults to `<config>/org_root_next.key`.
        ///
        /// Reused if it exists, so you can prepare the key on a machine that is not this one.
        #[arg(long)]
        new_key: Option<String>,
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
enum IdentityCmd {
    /// Print the recovery phrase for this node's user key.
    ///
    /// WRITE IT DOWN. The phrase IS the private key: anyone who reads it can present this
    /// identity, and mcpmesh cannot recover it for you if you lose it. It is not stored anywhere
    /// else, not logged, and not written to the audit file.
    Export,
    /// Restore a user key from a recovery phrase, on a new machine.
    ///
    /// Restores the `b64u:` identity — the one peers pinned, kb audiences key on, and a roster
    /// names. It does NOT get this machine admitted by your peers: they authorize per device, and
    /// this device is not in their allowlists. You still pair (or re-pair) with each of them.
    Import {
        /// The phrase, quoted. **Omit it to read from stdin instead, which is what you want.**
        ///
        /// An argument is visible in `ps` to every process on the machine and lands in your shell
        /// history — for a value that IS the private key, that is the wrong channel. Piping it
        /// (`… | mcpmesh identity import`) avoids both.
        phrase: Option<String>,
        /// Replace an existing user key on this node.
        ///
        /// Refused without it, because importing over a live key discards the identity this
        /// machine currently presents — irreversibly, unless you have THAT key's phrase too.
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum AttestCmd {
    /// Print a `mcpmesh-attest:` line for another of YOUR devices to dial.
    ///
    /// Run this on a node that already pairs with you. It carries nothing secret — just where to
    /// reach this node — and only works if this node has `[identity].admit_attested_devices` on.
    Offer,
    /// Present this device's identity to a peer, using their `mcpmesh-attest:` line.
    ///
    /// They admit this machine only if they already pair with you, have opted in, and have not
    /// revoked it. Nothing here can get a stranger in.
    #[command(name = "to")]
    To {
        /// The `mcpmesh-attest:...` line. Omit to read from stdin.
        offer: Option<String>,
    },
}

#[derive(Subcommand)]
enum RevokeCmd {
    /// Refuse a peer's device on THIS node.
    ///
    /// Your own local decision about someone else's device. Live sessions are severed now, not when
    /// the peer next disconnects — an MCP session can stay open for days.
    ///
    /// A `b64u:` user id revokes EVERY device you know of that person's, which is what you want
    /// when the answer is "not on any of their machines".
    Peer {
        /// A nickname, an `eid:` device principal, or a `b64u:` user id.
        peer: String,
        /// A note for yourself, shown in `mcpmesh status`.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a local revocation (`revoke peer`), restoring the peer if its pair row survives.
    Undo {
        /// The same nickname, `eid:`, or `b64u:` you revoked.
        peer: String,
    },
    /// Sign a revocation of ONE OF YOUR OWN devices, and print a token to send your peers.
    ///
    /// This is the one that matters when a machine is lost or stolen: your peers cannot discover
    /// it, and until they act, whoever holds that disk authenticates as you. Run it from a machine
    /// that still has your user key, naming the device you no longer have.
    ///
    /// The token is not a secret — it grants nothing and only asks that an endpoint be treated as
    /// dead. Send it however you sent them the invite; mcpmesh has no channel of its own for it in
    /// pairing mode.
    Device {
        /// The `eid:` principal of your lost device, from `mcpmesh status` on a peer, or your own
        /// records.
        endpoint: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Apply a `mcpmesh-revoke:` token a peer sent you.
    ///
    /// Honoured only from someone you have already paired with, and only for their OWN devices.
    Import {
        /// The `mcpmesh-revoke:...` token. Omit to read from stdin.
        token: Option<String>,
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
    /// Generate roff man pages for every command into DIR (one file per command).
    Man {
        /// Directory to write the `*.1` files into (created if missing).
        dir: PathBuf,
    },
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
    /// Grant a scope to a principal: a `b64u:` user_id, an `eid:` device principal, a roster
    /// group name, or a paired peer's nickname (resolved to its stable principal at write time).
    Grant { scope: String, principal: String },
    /// List the daemon's blob scopes (name → hashes + grants). A DEFAULT LIMIT applies; the
    /// output says so when it truncates.
    List {
        /// Only this scope (exact name, never a prefix).
        #[arg(long)]
        scope: Option<String>,
        /// Return at most N scopes (capped by the daemon).
        #[arg(long)]
        limit: Option<usize>,
        /// Skip N scopes — page with this after seeing a truncation notice.
        #[arg(long)]
        offset: Option<usize>,
        /// Counts only: omit the hash/grant lists, keep the totals.
        #[arg(long)]
        counts_only: bool,
    },
    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (hash-verified) and write it to `dest`.
    Fetch {
        /// The ticket string (from `blob publish`).
        ticket: String,
        /// Local path to write the verified blob to.
        dest: PathBuf,
        /// Also try these peers if the publisher does not answer (#83). Repeatable.
        ///
        /// A ticket names ONE address, so a file shared with a group becomes unfetchable the
        /// moment the sender closes their laptop — even though others already hold the identical
        /// verified bytes. Name them here and the fetch falls back, in order, after the publisher.
        ///
        /// Takes a paired nickname or an `eid:`/`b64u:` principal. They can only help if they have
        /// republished the blob into a scope that grants you; the bytes are hash-verified whoever
        /// serves them, so none of them can substitute a different file.
        #[arg(long = "from", value_name = "peer")]
        from: Vec<String>,
    },
    /// Stop an in-flight `blob fetch` of this hash (#172).
    ///
    /// Run it from a SECOND terminal: the fetching command holds its own control connection for the
    /// transfer's duration, so the cancel necessarily arrives on a different one. The fetch exits
    /// non-zero with a "cancelled" error; partial chunks stay in the store, and are reclaimed
    /// only if this node configured `[blobs].gc_interval` (#80).
    Cancel {
        /// The blob's hash, as printed by `blob fetch`/`blob list` or carried on transfer frames.
        hash: String,
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
    /// Vouch for a peer so someone you are paired with can install them (#65).
    ///
    /// Prints the two values they pass to `internal peer introduce`. It is a statement for THEM —
    /// it changes nothing about your own trust in the subject.
    Endorse {
        /// The subject's endpoint id (from that machine's `internal id`).
        subject: String,
        /// The subject's user id, when you are vouching for that too. The recipient will
        /// additionally require the SUBJECT's own binding before trusting it.
        #[arg(long)]
        subject_user_id: Option<String>,
    },
    /// Install a peer from an endorsement by someone you are already paired with (#65).
    ///
    /// Onboards a small group in O(N) rather than O(N²) pairing ceremonies. It installs IDENTITY,
    /// not authorization — grant services separately, as you would for any peer.
    Introduce {
        /// The subject's endpoint id.
        subject: String,
        /// Your local name for them.
        nickname: String,
        /// The endorser's user id, from their `internal peer endorse`.
        #[arg(long)]
        endorsed_by: String,
        /// The endorsement signature, from their `internal peer endorse`.
        #[arg(long)]
        evidence: String,
        /// The subject's user id. Requires `--subject-binding`.
        #[arg(long)]
        subject_user_id: Option<String>,
        /// The SUBJECT's own device→user binding for `--subject-user-id`.
        #[arg(long)]
        subject_binding: Option<String>,
    },
    /// Dump the DURABLE state this node stores for one peer (#140) — a diagnostic.
    ///
    /// Answers "what is this node about to dial, and where did that come from": the
    /// persisted dial hint verbatim, whether it is actually usable (an unparseable or
    /// mismatched hint is silently discarded at every dial), the addresses inside it, the
    /// pairing stamp, and the live reachability row.
    ///
    /// UNLIKE every other surface this PRINTS TRANSPORT VOCABULARY — IP addresses — because
    /// that is the question. It is your own store's record of your own peers; read it before
    /// pasting it anywhere public.
    ///
    /// Read-only: probes nothing, dials nothing, writes nothing, so running it cannot perturb
    /// the state being diagnosed. Intended as a paired capture — run it on BOTH ends of a
    /// stuck pairing and compare.
    State {
        /// The peer: a nickname or an `eid:` device principal.
        peer: String,
        /// Emit the raw `PeerDiagnosticsResult` as JSON (the shape to attach to an issue).
        #[arg(long)]
        json: bool,
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
        }) => mcpmesh::daemonshell::run(),
        Some(Cmd::Internal {
            command: Internal::Id,
        }) => run_internal_id(),
        Some(Cmd::Serve { name, allow, cmd }) => run_serve(name, allow, cmd, cli.json),
        Some(Cmd::Connect { target }) => run_connect(target),
        Some(Cmd::Invite {
            services,
            label,
            uses,
            peer_name,
            as_self,
        }) => run_invite(services, label, uses, peer_name, as_self, cli.json),
        Some(Cmd::Pair {
            invite,
            remove,
            as_nickname,
            as_self,
        }) => run_pair(invite, remove, as_nickname, as_self, cli.json),
        Some(Cmd::Use { target }) => run_use(target, cli.json),
        Some(Cmd::Identity {
            command: IdentityCmd::Export,
        }) => enrollcmd::run_identity_export(cli.json),
        Some(Cmd::Identity {
            command: IdentityCmd::Import { phrase, replace },
        }) => enrollcmd::run_identity_import(phrase, replace, cli.json),
        Some(Cmd::Attest {
            command: AttestCmd::Offer,
        }) => enrollcmd::run_attest_offer(cli.json),
        Some(Cmd::Attest {
            command: AttestCmd::To { offer },
        }) => enrollcmd::run_attest_to(offer, cli.json),
        Some(Cmd::Revoke {
            command: RevokeCmd::Peer { peer, reason },
        }) => enrollcmd::run_revoke_peer(peer, reason, cli.json),
        Some(Cmd::Revoke {
            command: RevokeCmd::Undo { peer },
        }) => enrollcmd::run_revoke_undo(peer, cli.json),
        Some(Cmd::Revoke {
            command: RevokeCmd::Device { endpoint, reason },
        }) => enrollcmd::run_revoke_device(endpoint, reason, cli.json),
        Some(Cmd::Revoke {
            command: RevokeCmd::Import { token },
        }) => enrollcmd::run_revoke_import(token, cli.json),
        Some(Cmd::Join {
            org_invite,
            name,
            user_id,
            label,
        }) => enrollcmd::run_join(org_invite, name, user_id, label, cli.json),
        Some(Cmd::Org {
            command:
                OrgCmd::Create {
                    name,
                    expires,
                    roster_url,
                },
        }) => enrollcmd::run_org_create(name, expires, roster_url, cli.json),
        Some(Cmd::Org {
            command: OrgCmd::Rotate { new_key },
        }) => enrollcmd::run_org_rotate(new_key, cli.json),
        Some(Cmd::Org {
            command:
                OrgCmd::Approve {
                    join_code,
                    groups,
                    user_id,
                },
        }) => enrollcmd::run_org_approve(join_code, groups, user_id, cli.json),
        Some(Cmd::Org {
            command: OrgCmd::Revoke { target, user_key },
        }) => enrollcmd::run_org_revoke(target, user_key, cli.json),
        Some(Cmd::Devices {
            command: DevicesCmd::Code { label },
        }) => enrollcmd::run_devices_code(label, cli.json),
        Some(Cmd::Devices {
            command: DevicesCmd::Add { device_code },
        }) => enrollcmd::run_devices_add(device_code, cli.json),
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
        }) => run_peer_add(nickname, endpoint_id, allow, cli.json),
        Some(Cmd::Internal {
            command:
                Internal::Peer {
                    command:
                        PeerCmd::Endorse {
                            subject,
                            subject_user_id,
                        },
                },
        }) => run_peer_endorse(subject, subject_user_id, cli.json),
        Some(Cmd::Internal {
            command:
                Internal::Peer {
                    command:
                        PeerCmd::Introduce {
                            subject,
                            nickname,
                            endorsed_by,
                            evidence,
                            subject_user_id,
                            subject_binding,
                        },
                },
        }) => run_peer_introduce(
            subject,
            nickname,
            endorsed_by,
            evidence,
            subject_user_id,
            subject_binding,
            cli.json,
        ),
        Some(Cmd::Internal {
            command:
                Internal::Peer {
                    command: PeerCmd::State { peer, json },
                },
        }) => run_peer_state(peer, json || cli.json),
        Some(Cmd::Internal {
            command:
                Internal::Roster {
                    command: RosterCmd::Install { file, org_root_pk },
                },
        }) => run_roster_install(file, org_root_pk, cli.json),
        Some(Cmd::Internal {
            command: Internal::Blob { command },
        }) => run_internal_blob(command, cli.json),
        Some(Cmd::Internal {
            command: Internal::Audit { command },
        }) => run_internal_audit(command, cli.json),
        Some(Cmd::Internal {
            command: Internal::Watch,
        }) => run_watch(cli.json),
        Some(Cmd::Completions { shell }) => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "mcpmesh",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Some(Cmd::Internal {
            command: Internal::Man { dir },
        }) => run_internal_man(dir),
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
            .register_service(
                &name,
                BackendSpec::Run {
                    cmd,
                    env: Default::default(),
                    cwd: None,
                },
                allow,
            )
            .await?;
        if json {
            println!("{}", mcpmesh::json::serve_json(&name));
            return Ok(());
        }
        println!("serving '{name}'");
        // The next exact instruction. Nothing is shared until someone is granted access, so the
        // invite is ALWAYS the next step — `--allow` input resolves through your paired peers to
        // stable principals at write time (#38), but only a redeemed invite (or a roster) makes
        // a peer real in the first place.
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
fn run_invite(
    services: Vec<String>,
    label: Option<String>,
    uses: Option<u32>,
    peer_name: Option<String>,
    as_self: bool,
    json: bool,
) -> anyhow::Result<()> {
    // #86: a self-enrollment invite grants nothing by design, so the "name a service" requirement
    // inverts — naming one is the error.
    if as_self && !services.is_empty() {
        anyhow::bail!(
            "--as-self grants nothing: your own devices are not peers of each other. Drop the \
             service arguments."
        );
    }
    if services.is_empty() && !as_self {
        anyhow::bail!("specify at least one service to grant (e.g. `mcpmesh invite notes`)");
    }
    with_daemon(async move |mut client| {
        let invite = client
            .invite_full(services.clone(), label, uses, peer_name, as_self)
            .await?;
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
fn run_pair(
    invite: Option<String>,
    remove: Option<String>,
    as_nickname: Option<String>,
    as_self: bool,
    json: bool,
) -> anyhow::Result<()> {
    // `--as-self` names the ceremony you are redeeming; with `--remove` there is no redemption.
    // Refused rather than ignored, for the same reason `--as` is below.
    if remove.is_some() && as_self {
        anyhow::bail!(
            "--as-self names the enrollment you are redeeming; it has no meaning with --remove"
        )
    }
    match (invite, remove) {
        (Some(_), Some(_)) => {
            anyhow::bail!("provide an invite to redeem OR --remove <nickname>, not both")
        }
        (None, None) => {
            anyhow::bail!("provide an invite to redeem, or --remove <nickname> to unpair")
        }
        // `--as` names the inviter you are about to pair with; with `--remove` there is nobody to
        // name. Refused rather than ignored — silently dropping a flag is how someone believes
        // they renamed a peer.
        (None, Some(_)) if as_nickname.is_some() => {
            anyhow::bail!(
                "--as names the inviter you are redeeming from; it has no meaning with --remove"
            )
        }
        (Some(invite_line), None) => with_daemon(async move |mut client| {
            // #178: the CLI is an embedder too, and gets the same default. It was tempting to pass
            // `true` unconditionally on the grounds that the person typing this is the one
            // deciding — but they are deciding from a line someone else handed them, the two
            // schemes look alike, and `render::pair_lines` only says which ceremony ran AFTER the
            // binding is written. Requiring `--as-self` costs one flag in a flow that is already
            // two commands, and is the difference between choosing this and being walked into it.
            //
            // It also keeps the field OFF the wire unless asked (`skip_serializing_if`), so a
            // freshly-upgraded binary still pairs against a not-yet-restarted pre-45 daemon
            // instead of failing `-32602 unknown field`.
            let paired = client
                .pair_opts(&invite_line, as_nickname.clone(), as_self)
                .await?;
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
    json: bool,
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
        if json {
            println!("{}", serde_json::json!({"peer": nickname, "added": true}));
        } else {
            println!("added peer '{nickname}'");
        }
        Ok(())
    })
}

/// `mcpmesh internal peer state <peer> [--json]` (#140): dump the durable per-peer state.
///
/// The human form is laid out to be READ SIDE BY SIDE with the same output from the other end of a
/// stuck pairing, which is how the state that differs becomes visible. `--json` is the shape to
/// attach to an issue.
/// #65: produce an endorsement for someone else to redeem.
fn run_peer_endorse(
    subject: String,
    subject_user_id: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    with_daemon(async move |mut client| {
        let res = client.endorse_peer(&subject, subject_user_id).await?;
        if json {
            println!("{}", serde_json::to_string(&res)?);
            return Ok(());
        }
        println!("Endorsement created. Give BOTH of these to the person installing:");
        println!("  --endorsed-by {}", res.endorsed_by);
        println!("  --evidence    {}", res.evidence);
        println!();
        println!("They must already be paired with you, or it will not resolve.");
        Ok(())
    })
}

/// #65: install a peer from an endorsement.
#[allow(clippy::too_many_arguments)]
fn run_peer_introduce(
    subject: String,
    nickname: String,
    endorsed_by: String,
    evidence: String,
    subject_user_id: Option<String>,
    subject_binding: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    with_daemon(async move |mut client| {
        client
            .introduce_peer(mcpmesh_local_api::PeerIntroduceParams {
                subject,
                endorsed_by,
                evidence,
                subject_user_id,
                subject_binding,
                nickname: nickname.clone(),
            })
            .await?;
        if json {
            println!("{}", serde_json::json!({"ok": true, "peer": nickname}));
            return Ok(());
        }
        println!("Installed '{nickname}' from an endorsement.");
        println!();
        println!("They are now resolvable but have access to NOTHING — an introduction installs");
        println!("identity, not authorization. Grant a service explicitly when you mean to.");
        Ok(())
    })
}

/// `mcpmesh internal peer state <peer>` — dump the durable state for one peer (#140).
fn run_peer_state(peer: String, json: bool) -> anyhow::Result<()> {
    with_daemon(async move |mut client| {
        let v = client
            .request(mcpmesh::Request::PeerDiagnostics(
                mcpmesh_local_api::PeerDiagnosticsParams { peer: peer.clone() },
            ))
            .await?;
        if json {
            println!("{v}");
            return Ok(());
        }
        let d: mcpmesh_local_api::PeerDiagnosticsResult = serde_json::from_value(v)?;
        println!("peer:       {} ({})", d.nickname, d.principal);
        if let Some(u) = &d.user_id {
            println!("user:       {u}");
        }
        println!(
            "paired_at:  {}",
            d.paired_at.as_deref().unwrap_or("(not recorded)")
        );
        match (&d.last_addr, d.hint_usable) {
            (None, _) => println!(
                "dial hint:  (none) — this node dials by id alone, exactly as a freshly paired \
                 identity does"
            ),
            (Some(_), false) => println!(
                "dial hint:  PRESENT BUT UNUSABLE — it does not parse, or its embedded id is not \
                 this peer, so every dial silently discards it and falls back to id-only"
            ),
            (Some(_), true) => {
                println!("dial hint:  {}", d.hint_addrs.join(", "));
                if !d.hint_addrs.iter().any(|a| !a.starts_with("relay ")) {
                    println!(
                        "            RELAY-ONLY — this hint can never punch. It is what an invite \
                         minted while only the relay path was up leaves behind."
                    );
                }
                println!(
                    "            merged with discovery as an extra candidate — but iroh SKIPS \
                     that lookup while a path is already selected, so on a pair holding an open \
                     relayed connection this hint is the only addressing a dial contributes."
                );
            }
        }
        // #140 (api_minor 56): what IROH holds, next to what we stored. The differences are the
        // reason this verb exists — printed as their own lines rather than left for a reader to
        // diff two comma-separated lists by eye.
        match &d.known_addrs {
            None => println!(
                "iroh knows: (no entry) — iroh holds no remote state for this peer right now. It \
                 reaps that state ~60s after the last connection closes, so this is the normal \
                 answer both for a peer never dialled AND for one talked to minutes ago. The two \
                 comparison lines below are omitted: there is no view to compare the hint against."
            ),
            Some(known) if known.is_empty() => println!(
                "iroh knows: (none) — iroh has an entry for this peer and no address in it"
            ),
            Some(known) => {
                let rendered: Vec<String> = known
                    .iter()
                    .map(|k| {
                        if k.active {
                            format!("{} [active]", k.addr)
                        } else {
                            k.addr.clone()
                        }
                    })
                    .collect();
                println!("iroh knows: {}", rendered.join(", "));
                let active_relay = known
                    .iter()
                    .any(|k| k.active && k.addr.starts_with("relay "));
                let idle_direct = known
                    .iter()
                    .any(|k| !k.active && !k.addr.starts_with("relay "));
                if active_relay && idle_direct {
                    println!(
                        "            relay active, direct address present but not carrying \
                         traffic. Consistent with #140 — and equally consistent with an ordinary \
                         failed hole-punch: iroh renders 'attempted and unusable' and 'not yet \
                         attempted' identically here, so this one bit cannot tell them apart."
                    );
                }
            }
        }
        if !d.hint_addrs_unknown_to_iroh.is_empty() {
            println!(
                "  not held: {} — in this node's stored hint, NOT in iroh's current view. The hint \
                 is written whole from the last connection's open paths, so these were real then \
                 and are absent now.",
                d.hint_addrs_unknown_to_iroh.join(", ")
            );
        }
        if !d.iroh_addrs_not_in_hint.is_empty() {
            println!(
                "  extra:    {} — in iroh's view, NOT named by the stored hint.",
                d.iroh_addrs_not_in_hint.join(", ")
            );
        }
        match &d.reachability {
            None => println!(
                "live:       never probed (this is a cache read — it does not dial, so a fresh \
                 daemon reports this until something else probes)"
            ),
            Some(r) => {
                let path = match &r.path {
                    mcpmesh_local_api::PeerPath::Direct => "direct".to_string(),
                    mcpmesh_local_api::PeerPath::Relay { url } => match url {
                        Some(u) => format!("relay ({u})"),
                        None => "relay".to_string(),
                    },
                    _ => "unknown".to_string(),
                };
                println!(
                    "live:       {} via {path}{}",
                    if r.reachable {
                        "reachable"
                    } else {
                        "UNREACHABLE"
                    },
                    match r.rtt_ms {
                        Some(ms) => format!(", {ms} ms"),
                        None => String::new(),
                    }
                );
            }
        }
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
fn run_roster_install(
    file: PathBuf,
    org_root_pk: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let path = file.to_string_lossy().into_owned();
    with_daemon(async move |mut client| {
        let installed = client.roster_install(&path, org_root_pk).await?;
        if json {
            println!("{}", serde_json::to_value(&installed)?);
        } else {
            println!("{}", render::roster_install_line(&installed));
        }
        Ok(())
    })
}

/// `mcpmesh internal blob <publish|grant|list|fetch>`: auto-start the daemon and drive the gated
/// app-blob provider over the control API. Surface-clean output: tickets/hashes are the
/// blob-reference vocabulary; scope names / principals are flat. Errors propagate → non-zero exit.
fn run_internal_blob(command: BlobCmd, json: bool) -> anyhow::Result<()> {
    with_daemon(async move |mut client| {
        match command {
            BlobCmd::Publish { scope, file } => {
                let path = file.to_string_lossy().into_owned();
                let r = client.blob_publish(&scope, &path).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"hash": r.hash, "ticket": r.ticket})
                    );
                } else {
                    println!("Published (hash {}).", r.hash);
                    println!("{}", r.ticket);
                }
            }
            BlobCmd::Grant { scope, principal } => {
                client.blob_grant(&scope, &principal).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"scope": scope, "principal": principal, "granted": true})
                    );
                } else {
                    println!("Granted scope '{scope}' to '{principal}'.");
                }
            }
            BlobCmd::List {
                limit,
                offset,
                counts_only,
                scope,
            } => {
                let r = client
                    .blob_list_paged(mcpmesh_local_api::BlobListParams {
                        scope,
                        hash: None,
                        limit,
                        offset,
                        counts_only,
                    })
                    .await?;
                if json {
                    println!("{}", serde_json::to_value(&r)?);
                } else {
                    let shown = r.scopes.len();
                    for s in r.scopes {
                        // Surface discipline (#38): a raw `eid:`/`b64u:` device/person
                        // principal is a machine id — redact it to a neutral placeholder in
                        // human output (roster group/user_id names show as-is). `--json`
                        // carries the raw grants for tooling.
                        let grants: Vec<String> = s
                            .grants
                            .iter()
                            .map(|g| {
                                if g.starts_with("eid:") || g.starts_with("b64u:") {
                                    "a paired peer".to_owned()
                                } else {
                                    g.clone()
                                }
                            })
                            .collect();
                        println!(
                            "{}: {} blob(s), granted to [{}]",
                            s.name,
                            // The AUTHORITATIVE count — `hashes` is empty under `--counts-only`
                            // and would read as 0 (#84b review).
                            s.hash_count,
                            grants.join(", ")
                        );
                    }
                    // NEVER truncate silently (#84b). A default limit applies, so a bare
                    // `blob list` on a busy daemon shows a page — say so, and say how to see
                    // the rest, or the CLI ships the exact silent wrong answer the paging work
                    // exists to remove.
                    if r.truncated {
                        println!(
                            "\n… showing {} of {} scope(s). Use --offset to page, or --limit to \
                             raise the cap.",
                            shown, r.total
                        );
                    }
                }
            }
            BlobCmd::Fetch { ticket, dest, from } => {
                let dest_path = dest.to_string_lossy().into_owned();
                let r = client.blob_fetch_from(&ticket, &dest_path, from).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "bytes_len": r.bytes_len,
                            "hash": r.hash,
                            "dest": dest.display().to_string(),
                        })
                    );
                } else {
                    println!(
                        "Fetched {} bytes (hash {}) → {}",
                        r.bytes_len,
                        r.hash,
                        dest.display()
                    );
                }
            }
            BlobCmd::Cancel { hash } => {
                let r = client.blob_fetch_cancel(&hash).await?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({ "cancelled": r.cancelled, "hash": hash })
                    );
                } else if r.cancelled {
                    println!("Cancelling fetch of {hash}");
                } else {
                    // Not an error, and worth saying why: it is the same answer a cancel gets when
                    // it loses the race to a fetch that just finished.
                    println!("No fetch of {hash} is in flight here (it may have just finished)");
                }
            }
        }
        Ok(())
    })
}

/// `mcpmesh internal audit <tail|list|prune>`: read/rotate the LOCAL audit log directly —
/// nothing is transmitted anywhere; no daemon round-trip. Errors propagate → non-zero exit.
fn run_internal_audit(command: AuditCmd, json: bool) -> anyhow::Result<()> {
    use mcpmesh::audit;
    let dir = paths::default_audit_dir()?;
    match command {
        // `tail` is already JSONL in both modes (the records ARE the machine face).
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
            if json {
                let months: Vec<serde_json::Value> = audit::list_month_files(&dir)?
                    .into_iter()
                    .map(|(month, _, size)| serde_json::json!({"month": month, "bytes": size}))
                    .collect();
                println!("{}", serde_json::Value::Array(months));
            } else {
                for (month, _, size) in audit::list_month_files(&dir)? {
                    println!("{month}  {size} bytes");
                }
            }
        }
        AuditCmd::Prune { before } => {
            // Same validation as the control verb (#88): `prune_before` string-compares, so a
            // malformed month would print "Nothing to prune" instead of erroring on the typo.
            anyhow::ensure!(
                audit::valid_month_key(&before),
                "--before must be a zero-padded YYYY-MM month key, got '{before}'"
            );
            let deleted = audit::prune_before(&dir, &before)?;
            if json {
                println!("{}", serde_json::json!({"pruned": deleted}));
            } else if deleted.is_empty() {
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
            println!(
                "{}",
                mcpmesh::json::status_json(&fingerprint, &hello, &status)
            );
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
fn run_watch(json: bool) -> anyhow::Result<()> {
    with_daemon(async move |client| {
        let mut stream = client.subscribe().await?;
        // JSON mode is pure JSONL of the typed StreamFrame wire shape — no banner,
        // so stdout stays parseable line-by-line.
        if !json {
            println!("watching the mesh — Ctrl-C to stop");
        }
        while let Some(frame) = stream.next().await? {
            if json {
                println!("{}", serde_json::to_string(&frame)?);
            } else {
                println!("{}", render::render_frame(&frame));
            }
        }
        Ok(())
    })
}

/// `mcpmesh internal man <dir>`: render the whole clap command tree as roff man pages,
/// one file per command (`mcpmesh.1`, `mcpmesh-pair.1`, `mcpmesh-org-create.1`, …). The
/// same source of truth as `--help` — pages can never drift from the CLI itself.
fn run_internal_man(dir: PathBuf) -> anyhow::Result<()> {
    use clap::CommandFactory;
    std::fs::create_dir_all(&dir)?;
    let mut count = 0usize;
    write_man_tree(&dir, &Cli::command(), "mcpmesh", &mut count)?;
    println!("wrote {count} man pages to {}", dir.display());
    Ok(())
}

fn write_man_tree(
    dir: &std::path::Path,
    cmd: &clap::Command,
    stem: &str,
    count: &mut usize,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone().name(stem.to_string())).render(&mut buf)?;
    std::fs::write(dir.join(format!("{stem}.1")), buf)?;
    *count += 1;
    for sub in cmd
        .get_subcommands()
        .filter(|s| !s.is_hide_set() && s.get_name() != "help")
    {
        write_man_tree(dir, sub, &format!("{stem}-{}", sub.get_name()), count)?;
    }
    Ok(())
}

/// `mcpmesh internal id`: print this machine's full endpoint id — the same encoding
/// `internal peer add <nickname> <endpoint_id>` parses. This is the doctor-class raw-id surface
/// (deliberately NOT in plain `status`): a human on machine A copies A's id and runs
/// `internal peer add A <id>` on machine B. Derived LOCALLY from the device key — the id is
/// deterministic (`SecretKey::from_bytes(device.secret).public()`, and `EndpointId` is a
/// `PublicKey` alias), so no daemon round-trip is needed.
fn run_internal_id() -> anyhow::Result<()> {
    let key = load_device_key()?;
    let endpoint_id = mcpmesh_net::iroh::SecretKey::from_bytes(&key.secret_bytes()).public();
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
