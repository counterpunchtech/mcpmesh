//! `mcpmesh doctor`: a local-only, read-only health diagnostic. It inspects the on-disk
//! config/keys/runtime dir and OPTIONALLY pings the local daemon, then reports actionable WARN/ERROR
//! findings. It NEVER mutates trust/config, NEVER mints a key (it STATS key files, never
//! `load_or_generate`), NEVER auto-starts the daemon (`connect_control`, not `ensure_daemon`), and
//! NEVER touches the network — a diagnostic, not an actuator.
//!
//! Surface-clean: findings carry flat vocabulary, file PATHS (doctor is the one surface allowed
//! to print the resolved paths), plain state words, and octal mode strings ONLY — never an
//! endpoint id / pubkey / ALPN / blob hash / raw key bytes. The raw-id surface stays at
//! `mcpmesh internal id`.
//!
//! Every verdict is produced by a PURE `check_*` fn (unit-tested with literal inputs, no daemon); the
//! only impure code is `gather`/`probe_daemon`/`run_doctor`.

/// The severity of one check. `Info` is below `Ok` for exit purposes (purely advisory, never
/// warns): it carries a platform note such as the Windows "permission lints don't apply here"
/// line, and must never flip the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Ok,
    Warn,
    Error,
}

/// One check's verdict: a severity plus a short, surface-clean human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub level: Level,
    pub message: String,
}

impl Level {
    /// The machine word for this level (`doctor --json`).
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

impl Verdict {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: Level::Info,
            message: message.into(),
        }
    }
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            level: Level::Ok,
            message: message.into(),
        }
    }
    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            level: Level::Warn,
            message: message.into(),
        }
    }
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            level: Level::Error,
            message: message.into(),
        }
    }
}

/// The `[network]` posture, checked against what ACTUALLY ships. Validation is the
/// daemon's own `net_plan` (one validator — doctor can never bless a config the daemon
/// refuses): an unknown mode or a `custom` without URLs is an ERROR. On a valid config:
/// hermetic (`relay_mode = "disabled"`) is OK — no relay AND no discovery — with a WARN when
/// discovery knobs are set (they are ignored); a mesh config WARNs when EXACTLY ONE of
/// relay/discovery is self-hosted (`"custom"`) — "self-hosting only one of the two is an
/// incomplete mitigation".
pub fn check_network(net: &crate::config::NetworkCfg) -> Verdict {
    // #116: `relay_only` is checked FIRST and reported through `doctor`, because the daemon's
    // `tracing::warn!` reaches nobody — no `tracing_subscriber` is installed in the shipped
    // binary, so a warning about an ignored testing flag is emitted into the void. `doctor` is
    // pure, `--json`, and agent-facing, which makes it the one channel a CI harness can actually
    // assert on. Without this, "flag set, feature forgotten" is a green run that never touched
    // the relay — the exact belief #116 was filed about.
    if net.relay_only {
        if !cfg!(feature = "unstable-relay-only") {
            return Verdict::warn(
                "[network] relay_only = true is IGNORED — this binary lacks the                  `unstable-relay-only` cargo feature. Traffic takes whatever path iroh selects,                  which on a LAN with IPv6 is usually DIRECT. Do NOT treat this run as having                  exercised the relay.",
            );
        }
        if net.relay_mode == "disabled" {
            return Verdict::warn(
                "[network] relay_only = true with a hermetic relay_mode — hermetic mode opens NO \
                 relay path, so there is nothing to select and traffic stays direct. relay_only \
                 cannot be honoured here.",
            );
        }
    }
    // #56: these are validated inside `build_endpoint`, which doctor never calls. Without this,
    // `keep_alive_secs = 60` gets a clean [network] verdict and then refuses to boot on restart —
    // doctor blessing a config the daemon rejects is worse than no check at all.
    if let Err(e) = crate::daemon::validate_transport_config(net) {
        return Verdict::error(format!(
            "[network] invalid — the daemon will refuse to start: {e:#}"
        ));
    }
    match crate::daemon::net_plan(net) {
        Err(e) => Verdict::error(format!(
            "[network] invalid — the daemon will refuse to start: {e}"
        )),
        Ok(crate::daemon::NetPlan::Hermetic) => {
            if net.discovery_mode != "default" || !net.discovery_urls.is_empty() {
                Verdict::warn(
                    "relay_mode = \"disabled\" is hermetic (no relay, no discovery) — the \
                     discovery_mode/discovery_urls knobs are ignored",
                )
            } else {
                Verdict::ok("networking disabled (hermetic) — no relay, no discovery")
            }
        }
        Ok(crate::daemon::NetPlan::Mesh { .. }) => {
            let relay_self = net.relay_mode == "custom";
            let disc_self = net.discovery_mode == "custom";
            if relay_self ^ disc_self {
                let (on, off) = if relay_self {
                    ("relay", "discovery")
                } else {
                    ("discovery", "relay")
                };
                Verdict::warn(format!(
                    "self-hosting {on} but not {off} — an incomplete metadata mitigation (\u{a7}10.3); \
                     self-host both or neither"
                ))
            } else if relay_self && disc_self {
                Verdict::ok("self-hosting relay and discovery")
            } else {
                Verdict::ok("using default relay and discovery")
            }
        }
    }
}

/// Report whether another endpoint has been seen presenting this node's identity (#134).
///
/// Two nodes booted from COPIES of one mesh root share an endpoint id; a relay serves only one, and
/// the displaced node's peers go unreachable with nothing saying why. `doctor` is where that gets
/// said, for the same reason #125's relay check lives here: the daemon's own `error!` reaches
/// nobody in the shipped binary.
///
/// `epoch` is `status.self_network.identity_conflict_epoch`. `None` means NOT OBSERVED — which on
/// an embedded node without an `IdentityConflictLayer` also means not observable — so it reports
/// nothing rather than a green "identity is unique" it cannot support.
pub fn check_identity_conflict(epoch: Option<i64>, now: i64) -> Option<Verdict> {
    let seen = epoch?;
    let mins = (now - seen).max(0) / 60;
    let ago = match mins {
        0 => "less than a minute".to_string(),
        1 => "1 minute".to_string(),
        m if m < 60 => format!("{m} minutes"),
        m if m < 120 => "1 hour".to_string(),
        m if m < 1440 => format!("{} hours", m / 60),
        m => format!("{} days", m / 1440),
    };
    Some(Verdict::warn(format!(
        "another endpoint was seen presenting this node's identity {ago} ago — two nodes booted \
         from COPIES of one mesh root cannot both use the relay, and this node's peers will \
         appear unreachable while that lasts. Stop the duplicate, or give it its own identity. \
         (Advisory: the report comes from a relay and is not authenticated.)"
    )))
}

/// Report the LIVE connection state of each configured relay (#125).
///
/// `status --json` has carried `self_network.relays[].connected` since #90, but no HUMAN surface
/// did — not the `status` line, not `doctor` — so it was there only for an embedder that already
/// knew to look.
/// A node whose pinned relay is dead keeps working — the healthy entries behind it carry traffic —
/// but every boot pays a penalty, and the operator has no way to see why. That invisibility is the
/// part of #125 that is ours: relay SELECTION is iroh's, and it already races the list (measured:
/// a dead entry costs the same first or last, and four cost the same as one).
///
/// `live` is `None` when the daemon is not reachable — live state needs a running daemon, and
/// saying so beats implying the relays are fine.
///
/// Only meaningful for `relay_mode = "custom"`: with no configured URLs there is nothing to name,
/// and the caller omits the finding entirely.
pub fn check_relays(
    configured: &[String],
    live: Option<&[mcpmesh_local_api::RelayInfo]>,
) -> Verdict {
    let Some(live) = live else {
        // `None` covers three cases and must not name only one: the daemon is down, it answered
        // without a `self_network` block (control-only, no mesh), or `status` errored. Saying
        // "needs a running daemon" beside a green `daemon: OK` line was its own small lie.
        return Verdict::info(format!(
            "{} relay(s) configured — live connection state unavailable (no running mesh daemon \
             to ask)",
            configured.len()
        ));
    };
    // Match on the URL the daemon REPORTS, which is sanitized to scheme+host+port (#90) and so may
    // not be byte-identical to the configured string, so compare NORMALIZED — through the daemon's
    // own `sanitize_relay_url`, the very function that produced `RelayInfo.url`, so the two cannot
    // drift.
    //
    // Exact equality, deliberately. The first version prefix-matched, which reported a DEAD relay
    // as connected whenever it was a strict prefix of a different healthy one
    // (`https://relay.acme.com` masked by `https://relay.acme.com:8443`) — precisely the failure
    // this check exists to prevent (#125 gate).
    //
    // A configured URL that does not parse, or that the daemon never mentions, counts as NOT
    // connected: silence is the failure mode being fixed, so it must never read as healthy.
    let norm = crate::daemon::normalize_relay_url;
    let connected: std::collections::BTreeSet<String> = live
        .iter()
        .filter(|r| r.connected)
        .map(|r| norm(&r.url).unwrap_or_else(|| r.url.clone()))
        .collect();
    let dead: Vec<&str> = configured
        .iter()
        .filter(|u| !norm(u).is_some_and(|n| connected.contains(&n)))
        .map(String::as_str)
        .collect();

    if dead.is_empty() {
        return Verdict::ok(format!(
            "all {} configured relay(s) connected",
            configured.len()
        ));
    }
    if dead.len() == configured.len() {
        return Verdict::warn(format!(
            "NO configured relay is connected ({}) — this node has no relay path right now, so \
             WAN peers are unreachable until one answers. LAN/direct paths are unaffected.",
            dead.join(", ")
        ));
    }
    Verdict::warn(format!(
        "{} of {} configured relay(s) not connected ({}) — traffic still flows over the healthy \
         ones, but every boot pays a bounded penalty waiting on the dead entry. Remove it, or fix \
         it, to get that time back (#125).",
        dead.len(),
        configured.len(),
        dead.join(", ")
    ))
}

/// WARN when the node is roster-mode (`org_root_pinned`) but has no `[roster].url` — it
/// degrades to stale after `max_staleness` with no authenticated channel to re-confirm
/// currency. The full-diagnostic version of the hint the one-liner `status` already
/// surfaces. Pairing mode (no org root) → OK; roster mode with a URL → OK.
pub fn check_roster_url(org_root_pinned: bool, roster_url: Option<&str>) -> Verdict {
    match (org_root_pinned, roster_url) {
        (false, _) => Verdict::ok("pairing mode — no roster URL needed"),
        (true, Some(_)) => Verdict::ok("roster URL configured"),
        (true, None) => Verdict::warn(
            "roster mode but no [roster].url — this node degrades after max_staleness with no way to \
             re-confirm currency; set [roster].url",
        ),
    }
}

/// Allow-vocabulary lint (#38, 0.8.0): `allow` entries are STABLE principals — `b64u:`,
/// `eid:`, or (roster mode) bare group/user_id names. On a PURE-PAIRING node (no org root
/// pinned) a bare entry can only be a dead pre-0.8.0 nickname grant, which no longer admits
/// anyone — WARN with the migration pointer. Roster mode → bare entries are legitimate
/// vocabulary → OK. `bare` carries `(service, entry)` pairs for the message.
pub fn check_allow_principals(org_root_pinned: bool, bare: &[(String, String)]) -> Verdict {
    if bare.is_empty() {
        return Verdict::ok("allow entries are stable principals");
    }
    if org_root_pinned {
        // On a mixed (roster + pairing) node a bare entry is AMBIGUOUS — a legitimate
        // roster group/user_id, OR a dead pre-0.8.0 pairing nickname grant. We cannot tell
        // them apart from config alone, so this is advisory, not OK-silent.
        return Verdict::info(
            "bare allow entries are treated as roster names; any that were pre-0.8.0              pairing-nickname grants no longer admit — re-pair those peers",
        );
    }
    let listed: Vec<String> = bare
        .iter()
        .map(|(svc, entry)| format!("{svc}:\"{entry}\""))
        .collect();
    Verdict::warn(format!(
        "nickname-keyed grants no longer admit anyone (0.8.0): {} — re-pair the peer \
         (grants are now written as stable principals) or replace the entry with the \
         peer's b64u:/eid: principal",
        listed.join(", ")
    ))
}

/// A private ed25519 key file's permission verdict. `present` = the file exists;
/// `mode` = its `st_mode & 0o777`. A key must be 0600. Group/world-WRITABLE (`mode & 0o022`) → ERROR
/// (an attacker could replace the key → identity takeover, catastrophic for org-root/user keys).
/// Group/world-READABLE but not writable (`mode & 0o044`) → WARN (exfiltration risk). Absent →
/// OK (a key not yet minted is not a finding). Doctor NEVER chmods — it only reports.
pub fn check_key_perms(present: bool, mode: u32) -> Verdict {
    if !present {
        return Verdict::ok("absent (not yet created)");
    }
    if mode & 0o022 != 0 {
        return Verdict::error(format!(
            "group/world-writable (mode {mode:04o}) — an attacker could replace this key; run `chmod 600`"
        ));
    }
    if mode & 0o044 != 0 {
        return Verdict::warn(format!(
            "group/world-readable (mode {mode:04o}) — a private key should be 0600; run `chmod 600`"
        ));
    }
    Verdict::ok(format!("0600 (mode {mode:04o})"))
}

/// The daemon's runtime dir must be mode 0700 and owned by us (it houses the 0600 control
/// socket). `present` = the dir exists; `mode` = its `st_mode & 0o777`; `uid` = its owner; `our_uid` =
/// this process's euid. Absent → OK (the daemon has not started). Foreign owner → ERROR (the daemon
/// refuses to bind under `ipc::ensure_runtime_dir`). Any group/world bit (`mode & 0o077`) → ERROR
/// (0700 is the contract). Doctor only STATS — it never chmods/chowns. (Deliberately re-derives
/// the `ipc.rs` expectation so a drift there becomes a failing doctor test.)
pub fn check_runtime_dir(present: bool, mode: u32, uid: u32, our_uid: u32) -> Verdict {
    if !present {
        return Verdict::ok("not present (daemon not started)");
    }
    if uid != our_uid {
        return Verdict::error(format!(
            "owned by uid {uid}, not you (uid {our_uid}) — the daemon refuses to bind here; investigate"
        ));
    }
    if mode & 0o077 != 0 {
        return Verdict::error(format!(
            "mode {mode:04o} is group/world-accessible — the control-socket dir must be 0700; run `chmod 700`"
        ));
    }
    Verdict::ok(format!("0700, owned by you (mode {mode:04o})"))
}

/// A compact human age ("45s" / "90m" / "36h" / "3d") from a seconds count. Negative (clock skew)
/// clamps to 0. Pure; sibling of `main.rs`'s `friendly_expiry`, but absolute-age not relative.
fn friendly_age(secs: i64) -> String {
    let s = secs.max(0);
    if s >= 86_400 {
        format!("{}d", s / 86_400)
    } else if s >= 3_600 {
        format!("{}h", s / 3_600)
    } else if s >= 60 {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

/// Surface the roster's effective state + freshness. `roster_mode` = an org root is
/// pinned; `daemon_state` = the live state word from the daemon (`"approved"|"degraded"|"stopped"|
/// "pending"`), or `None` when the daemon is unreachable; `staleness_secs` = age since `last_confirmed`
/// (from the local sidecar, `None` when unknown); `max_staleness_secs` = the configured bound. The
/// state word is the daemon's OWN `RosterGate::effective_state` (expiry ∨ staleness) — so this reflects
/// staleness, not just expiry. Surface-clean: only roster vocabulary + a compact age.
pub fn check_roster_freshness(
    roster_mode: bool,
    daemon_state: Option<&str>,
    staleness_secs: Option<i64>,
    max_staleness_secs: i64,
) -> Verdict {
    if !roster_mode {
        return Verdict::ok("pairing mode — no roster");
    }
    match daemon_state {
        Some("stopped") => Verdict::error(
            "roster serving STOPPED — stale/expired past grace; re-confirm currency \
             (URL poll / gossip / manual install)",
        ),
        Some("degraded") => {
            Verdict::warn("roster DEGRADED — serving in the grace window; re-confirm currency soon")
        }
        Some("pending") => Verdict::warn(
            "joined but not yet approved — no roster installed; ask your operator to approve your join code",
        ),
        Some("approved") => match staleness_secs {
            Some(age) if age > max_staleness_secs => Verdict::warn(format!(
                "roster approved but last confirmed {} ago (> max_staleness {}) — a refresh is due",
                friendly_age(age),
                friendly_age(max_staleness_secs)
            )),
            Some(age) => Verdict::ok(format!(
                "roster approved — last confirmed {} ago",
                friendly_age(age)
            )),
            None => Verdict::ok("roster approved"),
        },
        Some(other) => Verdict::warn(format!("roster state '{other}' — check `mcpmesh status`")),
        None => Verdict::warn(
            "roster mode but the daemon is not running — install/freshness state unknown; \
             start it to check",
        ),
    }
}

/// Config validity + required-fields-for-mode. `parse_ok` = `Config::load` succeeded; `roster_mode` =
/// an org root is pinned; `has_org_id` = the org id is present. A parse failure is ERROR (nothing else
/// can be trusted); a roster node whose org root is pinned but org_id is missing is WARN (a genuinely
/// incomplete pin). It does NOT check `user_id`: an OPERATOR node (`org create` pins org_root_pk +
/// org_id but leaves user_id = None — operators aren't roster members; the daemon tolerates it,
/// daemon.rs:629 "presence publish skipped: no user_id") is healthy, so warning on absent user_id would
/// falsely flag the org-root holder and wrongly tell them to re-run `join`.
pub fn check_config(parse_ok: bool, roster_mode: bool, has_org_id: bool) -> Verdict {
    if !parse_ok {
        return Verdict::error(
            "config.toml does not parse — fix the syntax (run `mcpmesh status` to see the error)",
        );
    }
    if roster_mode && !has_org_id {
        return Verdict::warn(
            "roster mode (org root pinned) but [identity].org_id is missing — the pin is incomplete; \
             re-run `mcpmesh join` (joiner) or `mcpmesh org create` (operator)",
        );
    }
    Verdict::ok("config parses; required fields present")
}

/// Whether the local daemon answered. `reachable` = a `Hello` came back over the UDS. Read-only,
/// local-only — doctor NEVER auto-starts the daemon. Not-running is a WARN (a serving node expects a
/// live daemon; any porcelain verb starts one), never an ERROR.
pub fn check_daemon(reachable: bool) -> Verdict {
    if reachable {
        Verdict::ok("daemon running and reachable")
    } else {
        Verdict::warn(
            "daemon not running — start it with any porcelain verb (e.g. `mcpmesh status`)",
        )
    }
}

/// The worst severity across findings (Ok when empty). Drives the process exit code.
pub fn worst_level(findings: &[(&str, Verdict)]) -> Level {
    if findings.iter().any(|(_, v)| v.level == Level::Error) {
        Level::Error
    } else if findings.iter().any(|(_, v)| v.level == Level::Warn) {
        Level::Warn
    } else {
        Level::Ok
    }
}

/// Render the report. Pure → unit-testable. One `[OK  |WARN|ERR ] <label>: <message>` line per
/// finding, then a blank line + a summary. Surface-clean: it adds NO vocabulary of its own —
/// every message the checks pass is already flat/path/fingerprint-only.
pub fn render_report(findings: &[(&str, Verdict)]) -> Vec<String> {
    let mut lines: Vec<String> = findings
        .iter()
        .map(|(label, v)| {
            let tag = match v.level {
                Level::Info => "INFO",
                Level::Ok => "OK  ",
                Level::Warn => "WARN",
                Level::Error => "ERR ",
            };
            format!("[{tag}] {label}: {}", v.message)
        })
        .collect();
    let warns = findings
        .iter()
        .filter(|(_, v)| v.level == Level::Warn)
        .count();
    let errors = findings
        .iter()
        .filter(|(_, v)| v.level == Level::Error)
        .count();
    lines.push(String::new());
    lines.push(match (errors, warns) {
        (0, 0) => "doctor: all checks passed".to_string(),
        (0, w) => format!("doctor: {w} warning(s) — see above"),
        (e, w) => format!("doctor: {e} error(s), {w} warning(s) — see above"),
    });
    lines
}

use crate::util::epoch_now_i64 as epoch_now;

/// Stat a file's `(present, mode & 0o777)` WITHOUT following symlinks and WITHOUT mutating anything.
/// A missing file (or any stat error) → `(false, 0)` — doctor degrades, never panics. `symlink_metadata`
/// judges a symlinked key by the link itself (a symlinked private key is itself worth surfacing).
/// Unix-only: the `mode` bits are a POSIX concept — on Windows `stat_present` supplies the
/// presence half and the permission lints are skipped entirely (see the `findings` builder).
#[cfg(unix)]
fn stat_mode(path: &std::path::Path) -> (bool, u32) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(path) {
        Ok(m) => (true, m.permissions().mode() & 0o777),
        Err(_) => (false, 0),
    }
}

/// Stat a dir's `(present, mode & 0o777, uid)` — the runtime-dir posture inputs. Missing/error →
/// `(false, 0, 0)`. Unix-only for the same reason as [`stat_mode`].
#[cfg(unix)]
fn stat_dir(path: &std::path::Path) -> (bool, u32, u32) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) => (true, m.permissions().mode() & 0o777, m.uid()),
        Err(_) => (false, 0, 0),
    }
}

/// The Windows presence half of a stat: `true` iff the path exists (WITHOUT following symlinks).
/// There is no mode/uid to report — user-profile ACLs, not POSIX bits, protect the key files —
/// so doctor reports presence only and skips the permission lints (see the `findings` builder).
#[cfg(windows)]
fn stat_present(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The plain inputs the pure checks run on — gathered once, read-only, from the local filesystem/config
/// plus an optional daemon ping.
struct DoctorInputs {
    parse_ok: bool,
    org_root_pinned: bool,
    has_org_id: bool,
    network: crate::config::NetworkCfg,
    roster_url: Option<String>,
    /// `(service, entry)` pairs for allow entries that are neither `b64u:` nor `eid:` (#38).
    bare_allow_entries: Vec<(String, String)>,
    max_staleness_secs: i64,
    device_key: (bool, u32),
    user_key: (bool, u32),
    org_root_key: (bool, u32),
    runtime_dir: (bool, u32, u32),
    our_uid: u32,
    /// Whether POSIX file-permission lints (0600 key mode, 0700 runtime dir, owner uid) are
    /// meaningful on this platform. `cfg!(unix)` — false on Windows, where user-profile ACLs
    /// protect the key files and there is no mode/uid to check; the findings builder then emits
    /// one Info line instead of the per-file/dir permission findings.
    perm_lints_apply: bool,
    staleness_secs: Option<i64>,
    daemon_reachable: bool,
    daemon_roster_state: Option<String>,
    /// The daemon's LIVE relay connection states (#125), or `None` when it is unreachable or
    /// mesh-less. Distinct from `network.relay_urls`, which is what the CONFIG asks for.
    live_relays: Option<Vec<mcpmesh_local_api::RelayInfo>>,
    /// When another endpoint was last seen presenting this node's identity (#134), or `None` for
    /// "not observed" — which also covers "no detector installed".
    identity_conflict_epoch: Option<i64>,
    /// `(present, mode)` for the outstanding-invite file (#87b). It holds BEARER SECRETS, and the
    /// case for writing them at all rests on it getting the same protection as the device key —
    /// which has to include being LINTED like the device key, or the equivalence is only half
    /// true and permission drift (a `cp -r` under a loose umask, a restore) goes unnoticed.
    invites_file: (bool, u32),
}

/// Ping the local daemon over the control socket WITHOUT auto-starting it (read-only, local-only).
/// Returns `(reachable, roster_state_word, live_relays)`. A dead socket / any error →
/// `(false, None, None)`.
///
/// `live_relays` is `Some` only when `status` answered AND carried a `self_network` block (#90) —
/// `None` covers both an unreachable daemon and a mesh-less control-only one, and `check_relays`
/// reports that honestly instead of implying the relays are fine (#125).
fn probe_daemon() -> (
    bool,
    Option<String>,
    Option<Vec<mcpmesh_local_api::RelayInfo>>,
    Option<i64>,
) {
    let Ok(socket) = mcpmesh_trust::paths::default_endpoint() else {
        return (false, None, None, None);
    };
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return (false, None, None, None);
    };
    rt.block_on(async move {
        match crate::client::connect_control(&socket).await {
            Ok(mut client) => match client.status().await {
                Ok(s) => {
                    let net = s.self_network;
                    (
                        true,
                        s.roster.map(|r| r.state),
                        net.as_ref().map(|n| n.relays.clone()),
                        net.and_then(|n| n.identity_conflict_epoch),
                    )
                }
                Err(_) => (true, None, None, None),
            },
            Err(_) => (false, None, None, None),
        }
    })
}

/// Read config + stat key files/runtime dir + load the freshness sidecar + ping the daemon. Read-only:
/// key files are STATTED (never `load_or_generate` → no mint); the daemon is CONNECTED to (never
/// auto-started); the network is never touched.
fn gather() -> DoctorInputs {
    use mcpmesh_trust::paths;

    // The euid is a POSIX concept — used only by the runtime-dir owner check, which is gated off
    // on Windows (`perm_lints_apply` is false there), so the placeholder 0 is never read.
    #[cfg(unix)]
    let our_uid = rustix::process::geteuid().as_raw();
    #[cfg(windows)]
    let our_uid = 0u32;

    // Parse VALIDITY is all doctor reports (`check_config`); the parse error's text is the
    // daemon/porcelain paths' to render — so no config-error type crosses this seam.
    let cfg_result = paths::default_config_path()
        .ok()
        .and_then(|p| crate::config::Config::load(&p).ok());
    let parse_ok = cfg_result.is_some();
    let cfg = cfg_result.unwrap_or_default();

    // Diagnostics never fail on an unresolvable default path (no HOME): an empty
    // placeholder path stats as missing, which is what the report should show anyway.
    let device_key_path = cfg
        .identity
        .device_key
        .clone()
        .or_else(|| paths::default_device_key_path().ok())
        .unwrap_or_default();
    let user_key_path = cfg
        .identity
        .user_key
        .clone()
        .or_else(|| paths::default_user_key_path().ok())
        .unwrap_or_default();

    // Key/dir permission inputs are POSIX (mode + uid) on unix; on Windows we can only report
    // presence (the mode/uid halves are 0 placeholders the gated-off perm checks never read).
    #[cfg(unix)]
    let device_key = stat_mode(&device_key_path);
    #[cfg(windows)]
    let device_key = (stat_present(&device_key_path), 0u32);
    #[cfg(unix)]
    let user_key = stat_mode(&user_key_path);
    #[cfg(windows)]
    let user_key = (stat_present(&user_key_path), 0u32);
    let org_root_key_path = paths::default_org_root_key_path().unwrap_or_default();
    #[cfg(unix)]
    let org_root_key = stat_mode(&org_root_key_path);
    #[cfg(windows)]
    let org_root_key = (stat_present(&org_root_key_path), 0u32);

    let runtime_dir = match paths::runtime_dir() {
        Ok(d) => {
            #[cfg(unix)]
            {
                stat_dir(&d)
            }
            #[cfg(windows)]
            {
                (stat_present(&d), 0u32, 0u32)
            }
        }
        Err(_) => (false, 0, 0),
    };

    // Freshness sidecar (`last_confirmed`) → staleness age. Local read-only; absent → None.
    let staleness_secs = crate::roster::freshness::FreshnessStore::new(
        paths::default_roster_confirmed_path().unwrap_or_default(),
    )
    .load()
    .ok()
    .flatten()
    .map(|lc| epoch_now() - lc);

    // #87b: the outstanding-invite file holds bearer secrets and is written 0600. Stat it the
    // same way the keys are stated, so drift is reported rather than assumed away.
    #[cfg(unix)]
    let invites_file = stat_mode(&mcpmesh_trust::paths::default_invites_path().unwrap_or_default());
    #[cfg(windows)]
    let invites_file = (
        stat_present(&mcpmesh_trust::paths::default_invites_path().unwrap_or_default()),
        0u32,
    );

    let (daemon_reachable, daemon_roster_state, live_relays, identity_conflict_epoch) =
        probe_daemon();

    DoctorInputs {
        parse_ok,
        org_root_pinned: cfg.identity.org_root_pk.is_some(),
        bare_allow_entries: cfg
            .services
            .iter()
            .flat_map(|(name, svc)| {
                svc.allow
                    .iter()
                    .filter(|a| !a.starts_with("b64u:") && !a.starts_with("eid:"))
                    .map(|a| (name.clone(), a.clone()))
                    .collect::<Vec<_>>()
            })
            .collect(),
        has_org_id: cfg.identity.org_id.is_some(),
        network: cfg.network.clone(),
        roster_url: cfg.roster.url.clone(),
        max_staleness_secs: cfg.roster.max_staleness_seconds(),
        device_key,
        user_key,
        org_root_key,
        runtime_dir,
        our_uid,
        perm_lints_apply: cfg!(unix),
        staleness_secs,
        daemon_reachable,
        daemon_roster_state,
        live_relays,
        identity_conflict_epoch,
        invites_file,
    }
}

/// Assemble the ordered finding list from gathered inputs (the single place labels + check order live).
///
/// The platform-independent checks (config, daemon, network, roster) run everywhere. The trailing
/// permission checks are POSIX-only: when `perm_lints_apply` is false (Windows), the four
/// per-file/dir permission findings collapse to ONE Info line — user-profile ACLs, not 0600/0700
/// bits, protect the key files there, so a mode/uid lint would be noise. Nothing diagnostic is
/// lost: key ABSENCE was never a finding on any platform (`check_key_perms` reports a missing key
/// as "absent (not yet created)"), and the daemon probe runs in the cross-platform checks above —
/// the dropped checks carried only the POSIX mode/uid lint.
fn findings(inp: &DoctorInputs) -> Vec<(&'static str, Verdict)> {
    let mut out = vec![
        (
            "config",
            check_config(inp.parse_ok, inp.org_root_pinned, inp.has_org_id),
        ),
        ("daemon", check_daemon(inp.daemon_reachable)),
        ("self-hosting", check_network(&inp.network)),
        (
            "roster-url",
            check_roster_url(inp.org_root_pinned, inp.roster_url.as_deref()),
        ),
        (
            "allow vocabulary",
            check_allow_principals(inp.org_root_pinned, &inp.bare_allow_entries),
        ),
        (
            "roster-freshness",
            check_roster_freshness(
                inp.org_root_pinned,
                inp.daemon_roster_state.as_deref(),
                inp.staleness_secs,
                inp.max_staleness_secs,
            ),
        ),
    ];
    // #125: only for `relay_mode = "custom"`. `relay_urls` is IGNORED in every other mode
    // (`net_plan` reads it only there) and nothing rejects leftovers, so gating on the list alone
    // warned "NO configured relay is connected — this node has no relay path" at a perfectly
    // healthy node running on the default relays, and flatly contradicted the hermetic finding
    // under `relay_mode = "disabled"` (#125 gate). A confidently wrong line in a diagnostic costs
    // more than a missing one.
    if inp.network.relay_mode == "custom" && !inp.network.relay_urls.is_empty() {
        out.push((
            "relays",
            check_relays(&inp.network.relay_urls, inp.live_relays.as_deref()),
        ));
    }
    // #134: only when there is something to report. An absent stamp means "not observed" — and on
    // an embedded node with no detector installed, "not observable" — so a green line here would
    // be a uniqueness claim nothing supports.
    if let Some(v) = check_identity_conflict(inp.identity_conflict_epoch, epoch_now()) {
        out.push(("identity", v));
    }
    // #87b: only when the file exists — a node that has never minted an invite has none, and a
    // finding about an absent file is noise.
    if inp.perm_lints_apply && inp.invites_file.0 {
        out.push((
            "invites",
            check_key_perms(inp.invites_file.0, inp.invites_file.1),
        ));
    }
    if inp.perm_lints_apply {
        out.push((
            "device.key",
            check_key_perms(inp.device_key.0, inp.device_key.1),
        ));
        out.push(("user.key", check_key_perms(inp.user_key.0, inp.user_key.1)));
        out.push((
            "org-root.key",
            check_key_perms(inp.org_root_key.0, inp.org_root_key.1),
        ));
        out.push((
            "runtime-dir",
            check_runtime_dir(
                inp.runtime_dir.0,
                inp.runtime_dir.1,
                inp.runtime_dir.2,
                inp.our_uid,
            ),
        ));
    } else {
        out.push((
            "file-permission lints",
            Verdict::info("n/a on Windows (user-profile ACLs protect %APPDATA%/%LOCALAPPDATA%)"),
        ));
    }
    out
}

/// `mcpmesh doctor` — gather local inputs (+ optionally ping the daemon), run every check, print the
/// report, and exit non-zero iff any check is ERROR. Read-only + local-only + network-free. Prints all
/// findings (greens included) so the report reads as a full health summary. On ERROR it prints the
/// report THEN `std::process::exit(1)` — the report lines are already flushed (Rust stdout is
/// line-buffered), and this avoids anyhow's trailing "Error:" line polluting the clean report.
pub fn run_doctor(json: bool) -> anyhow::Result<()> {
    let inputs = gather();
    let findings = findings(&inputs);
    if json {
        println!("{}", crate::json::doctor_json(&findings));
    } else {
        for line in render_report(&findings) {
            println!("{line}");
        }
    }
    if worst_level(&findings) == Level::Error {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `[network]` config from plain strings for the check tests.
    fn net(
        relay: &str,
        relay_urls: &[&str],
        disc: &str,
        disc_urls: &[&str],
    ) -> crate::config::NetworkCfg {
        crate::config::NetworkCfg {
            relay_mode: relay.into(),
            relay_urls: relay_urls.iter().map(|s| s.to_string()).collect(),
            discovery_mode: disc.into(),
            discovery_urls: disc_urls.iter().map(|s| s.to_string()).collect(),
            relay_only: false,
            ..Default::default()
        }
    }

    /// A minimal all-green `DoctorInputs` for tests that only care which findings are EMITTED.
    fn base_inputs() -> DoctorInputs {
        DoctorInputs {
            parse_ok: true,
            bare_allow_entries: Vec::new(),
            org_root_pinned: false,
            has_org_id: false,
            network: net("default", &[], "default", &[]),
            roster_url: None,
            max_staleness_secs: 86_400,
            device_key: (true, 0o600),
            user_key: (true, 0o600),
            org_root_key: (true, 0o600),
            runtime_dir: (true, 0o700, 0),
            our_uid: 0,
            perm_lints_apply: false,
            staleness_secs: None,
            daemon_reachable: true,
            daemon_roster_state: None,
            live_relays: None,
            identity_conflict_epoch: None,
            invites_file: (false, 0),
        }
    }

    fn relay(url: &str, connected: bool) -> mcpmesh_local_api::RelayInfo {
        mcpmesh_local_api::RelayInfo {
            url: url.into(),
            connected,
        }
    }

    /// #125: `doctor` names a configured relay that is not connected.
    ///
    /// This is the part of #125 that is ours. Relay SELECTION is iroh's and it already races the
    /// list — measured on the pinned 1.0.3, a dead entry costs the same first or last and four cost
    /// the same as one, which is the opposite of the sequential walk the report inferred. What was
    /// missing is that while `status --json` has carried `self_network.relays[].connected` since
    /// #90, no HUMAN surface did — so a node whose pinned relay is dead paid the penalty silently
    /// unless an embedder already knew to look.
    #[test]
    fn relay_check_names_a_dead_relay() {
        let urls = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // Live state needs a daemon. Say so — do not imply the relays are fine.
        let v = check_relays(&urls(&["https://a.example"]), None);
        assert_eq!(v.level, Level::Info, "{v:?}");
        assert!(
            v.message.contains("unavailable"),
            "and must not imply the relays are fine: {}",
            v.message
        );

        // All connected → Ok, and no noise.
        let v = check_relays(
            &urls(&["https://a.example", "https://b.example"]),
            Some(&[
                relay("https://a.example", true),
                relay("https://b.example", true),
            ]),
        );
        assert_eq!(v.level, Level::Ok, "{v:?}");

        // The reporter's shape: one dead, healthy ones behind it. Must WARN and must NAME it —
        // an operator cannot act on "a relay is down".
        let v = check_relays(
            &urls(&["https://dead.example", "https://ok.example"]),
            Some(&[
                relay("https://dead.example", false),
                relay("https://ok.example", true),
            ]),
        );
        assert_eq!(v.level, Level::Warn, "{v:?}");
        assert!(
            v.message.contains("https://dead.example"),
            "the dead relay must be NAMED, not counted: {}",
            v.message
        );
        assert!(
            !v.message.contains("https://ok.example"),
            "and the healthy one must not be blamed: {}",
            v.message
        );

        // A configured relay the daemon does not mention at all counts as not connected —
        // silence is the failure mode being fixed, so it must not read as healthy.
        let v = check_relays(
            &urls(&["https://ghost.example", "https://ok.example"]),
            Some(&[relay("https://ok.example", true)]),
        );
        assert_eq!(v.level, Level::Warn, "{v:?}");
        assert!(v.message.contains("https://ghost.example"), "{}", v.message);

        // None connected is a different sentence: this node has no relay path at all.
        let v = check_relays(
            &urls(&["https://a.example"]),
            Some(&[relay("https://a.example", false)]),
        );
        assert_eq!(v.level, Level::Warn, "{v:?}");
        assert!(
            v.message.contains("NO configured relay"),
            "no-path is not the same finding as one-of-several down: {}",
            v.message
        );

        // #125 gate: a DEAD relay must not be masked by a healthy one it is a prefix of. The first
        // version matched with `starts_with` in both directions, so `https://relay.acme.com`
        // (dead) was reported connected because `https://relay.acme.com:8443` (healthy) starts
        // with it — the check silently answering "all connected" in exactly the situation it
        // exists to catch.
        let v = check_relays(
            &urls(&["https://relay.acme.com", "https://relay.acme.com:8443"]),
            Some(&[
                relay("https://relay.acme.com", false),
                relay("https://relay.acme.com:8443", true),
            ]),
        );
        assert_eq!(
            v.level,
            Level::Warn,
            "a dead relay must not be masked by a healthy one it prefixes: {v:?}"
        );
        assert!(
            v.message.contains("https://relay.acme.com,")
                || v.message.ends_with("relay.acme.com)")
                || v.message.contains("(https://relay.acme.com)"),
            "and the DEAD one is the one named: {}",
            v.message
        );

        // Normalization, not string equality: the configured spelling and the daemon's sanitized
        // rendering are rarely byte-identical (trailing slash, default port, host case).
        let v = check_relays(
            &urls(&["https://Relay.Example.COM/"]),
            Some(&[relay("https://relay.example.com", true)]),
        );
        assert_eq!(
            v.level,
            Level::Ok,
            "a re-spelling of the same relay must not read as a second, dead one: {v:?}"
        );
    }

    /// #87b gate: the invite file is linted like the device key, because the case for writing
    /// bearer secrets to disk at all rests on that equivalence.
    ///
    /// `docs/operator.md` and the persistence module both argue "0600, the same protection the
    /// device key gets". That was only half true: `chmod 644 device.key` warned, `chmod 644
    /// invites.json` was silent. Permission drift is realistic — a `cp -r` of the data dir under
    /// a loose umask, a restore from backup, a container build — and an unlinted claim of
    /// equivalence is worse than no claim.
    ///
    /// Absent file → NO finding: a node that has never minted an invite has none, and a line
    /// about a file that does not exist is noise.
    #[test]
    fn the_invite_file_is_linted_like_the_device_key() {
        let mut inp = base_inputs();
        inp.perm_lints_apply = true;

        inp.invites_file = (false, 0);
        assert!(
            !findings(&inp).iter().any(|(l, _)| *l == "invites"),
            "a node that never minted an invite gets no finding"
        );

        inp.invites_file = (true, 0o600);
        let f = findings(&inp);
        let v = &f.iter().find(|(l, _)| *l == "invites").expect("linted").1;
        assert_eq!(v.level, Level::Ok, "0600 is the expected state: {v:?}");

        // The half that was missing: drift must be reported, exactly as it is for device.key.
        inp.invites_file = (true, 0o644);
        let f = findings(&inp);
        let v = &f.iter().find(|(l, _)| *l == "invites").expect("linted").1;
        assert_ne!(
            v.level,
            Level::Ok,
            "a world-readable file of BEARER SECRETS must not pass silently: {v:?}"
        );
    }

    /// #134: `doctor` says it when another endpoint is using this identity — and says NOTHING
    /// when it has not been observed.
    ///
    /// The silence is the load-bearing half. An absent stamp means "not observed", and on an
    /// embedded node without an `IdentityConflictLayer` it means "not observable" — so a green
    /// "identity is unique" line would be a claim nothing supports, on the surface an operator
    /// trusts most.
    #[test]
    fn the_identity_check_speaks_only_when_it_has_seen_something() {
        assert!(
            check_identity_conflict(None, 1_753_900_000).is_none(),
            "no observation must produce NO finding — never a green uniqueness claim"
        );

        let v = check_identity_conflict(Some(1_753_900_000), 1_753_900_120)
            .expect("an observation must produce a finding");
        assert_eq!(v.level, Level::Warn, "{v:?}");
        assert!(
            v.message.contains("2 minutes"),
            "the age tells an operator whether this is live or historical: {}",
            v.message
        );
        assert!(
            v.message.contains("not authenticated"),
            "the claim is relay-attested; saying so is what stops it being trusted as proof: {}",
            v.message
        );

        // It appears in the assembled report only when observed.
        let mut inp = base_inputs();
        assert!(
            !findings(&inp).iter().any(|(l, _)| *l == "identity"),
            "an unobserved node gets no identity line at all"
        );
        inp.identity_conflict_epoch = Some(1_753_900_000);
        assert!(
            findings(&inp).iter().any(|(l, _)| *l == "identity"),
            "an observed conflict must reach the report"
        );
    }

    /// #125 gate: the relay finding is for `relay_mode = "custom"` ONLY.
    ///
    /// `relay_urls` is ignored in every other mode — `net_plan` reads it only under `custom` — and
    /// nothing rejects leftovers. Gating on the list alone told a perfectly healthy node running on
    /// the DEFAULT relays that it had "no relay path right now", and contradicted the hermetic
    /// finding under `relay_mode = "disabled"`.
    #[test]
    fn the_relay_finding_is_custom_mode_only() {
        let labels = |n: crate::config::NetworkCfg| {
            let mut inp = base_inputs();
            inp.network = n;
            findings(&inp)
                .into_iter()
                .map(|(l, _)| l)
                .collect::<Vec<_>>()
        };
        let leftovers = &["https://stale.example"];
        assert!(
            !labels(net("default", leftovers, "default", &[])).contains(&"relays"),
            "leftover relay_urls under relay_mode=default are IGNORED by the daemon — a finding \
             about them is a confidently wrong line"
        );
        assert!(
            !labels(net("disabled", leftovers, "default", &[])).contains(&"relays"),
            "hermetic mode opens no relay path at all"
        );
        assert!(
            labels(net("custom", leftovers, "default", &[])).contains(&"relays"),
            "and custom mode — where the URLs are actually used — must report"
        );
        assert!(
            !labels(net("custom", &[], "default", &[])).contains(&"relays"),
            "custom with no URLs cannot boot a mesh; nothing to name"
        );
    }

    /// #116: `doctor` must SAY when `relay_only` cannot be honoured.
    ///
    /// The daemon's `tracing::warn!` reaches nobody — no subscriber is installed in the shipped
    /// binary — so a warning about an ignored testing flag goes into the void. That made the
    /// "loud ignore" a SILENT ignore, which is the failure #116 is about: believing you tested
    /// the relay when you did not. `doctor` is pure, `--json`, and agent-facing, so a CI harness
    /// can assert on it.
    #[test]
    fn doctor_warns_when_relay_only_cannot_be_honoured() {
        // Built WITHOUT the feature (the default, and how CI runs): the flag does nothing.
        #[cfg(not(feature = "unstable-relay-only"))]
        {
            let v = check_network(&cfg_with_relay_only("default", true));
            assert_eq!(
                v.level,
                Level::Warn,
                "an ignored relay_only must warn: {v:?}"
            );
            assert!(
                v.message.contains("IGNORED"),
                "and must say so plainly: {}",
                v.message
            );
        }
        // Hermetic mode opens no relay path, so relay_only cannot be honoured on ANY build.
        let v = check_network(&cfg_with_relay_only("disabled", true));
        assert_eq!(
            v.level,
            Level::Warn,
            "relay_only + hermetic must warn: {v:?}"
        );

        // And an ordinary config is untouched — no new noise for anyone not using the flag.
        let plain = check_network(&cfg_with_relay_only("disabled", false));
        assert!(
            !plain.message.contains("relay_only"),
            "no relay_only noise when unset: {}",
            plain.message
        );
    }

    fn cfg_with_relay_only(relay_mode: &str, relay_only: bool) -> crate::config::NetworkCfg {
        crate::config::NetworkCfg {
            relay_mode: relay_mode.into(),
            relay_urls: vec![],
            discovery_mode: "default".into(),
            discovery_urls: vec![],
            relay_only,
            ..Default::default()
        }
    }

    /// #56 gate: doctor must not bless a `[network]` the daemon will refuse to boot on. The
    /// transport knobs are validated inside `build_endpoint`, which doctor never calls — so
    /// without an explicit pre-flight, `keep_alive_secs = 60` passed doctor and then failed the
    /// restart.
    #[test]
    fn network_check_catches_transport_knobs_the_daemon_will_reject() {
        let with = |idle: Option<u64>, keep: Option<u64>| crate::config::NetworkCfg {
            idle_timeout_secs: idle,
            keep_alive_secs: keep,
            ..net("default", &[], "default", &[])
        };

        // Above iroh's per-path cap: refused at boot, so refused here.
        let over = check_network(&with(Some(1200), Some(60)));
        assert_eq!(
            over.level,
            Level::Error,
            "doctor must report an over-cap keepalive as an ERROR, not bless it: {}",
            over.message
        );
        assert!(
            over.message.contains("refuse to start") && over.message.contains("60"),
            "and must say the daemon will refuse to start, naming their value: {}",
            over.message
        );

        // #89: an unknown presence_mode is a startup error, so doctor must catch it too — a
        // privacy knob the daemon rejects must not read as healthy.
        let bad_presence = crate::config::NetworkCfg {
            presence_mode: "of".into(),
            ..net("default", &[], "default", &[])
        };
        let v = check_network(&bad_presence);
        assert_eq!(v.level, Level::Error, "{}", v.message);
        assert!(
            v.message.contains("presence_mode") && v.message.contains("refuse to start"),
            "and must name the key: {}",
            v.message
        );
        for good in ["paired", "granted", "off"] {
            let ok = crate::config::NetworkCfg {
                presence_mode: good.into(),
                ..net("default", &[], "default", &[])
            };
            assert_eq!(
                check_network(&ok).level,
                Level::Ok,
                "{good:?} is legal and must not be flagged"
            );
        }

        // Zero: the PING storm, not "disabled".
        assert_eq!(
            check_network(&with(Some(1200), Some(0))).level,
            Level::Error
        );
        // Keepalive at/above the idle timeout.
        assert_eq!(check_network(&with(Some(3), Some(5))).level, Level::Error);
        // A VALID pairing must stay OK — this check must not reject what boots fine.
        assert_eq!(check_network(&with(Some(1200), Some(3))).level, Level::Ok);
        // And an unconfigured node is untouched.
        assert_eq!(check_network(&with(None, None)).level, Level::Ok);
    }

    #[test]
    fn network_check_reports_only_real_states() {
        const RELAY: &[&str] = &["https://relay.acme.com"];
        const DISC: &[&str] = &["https://dns.acme.com/pkarr"];
        // Both default → OK.
        assert_eq!(
            check_network(&net("default", &[], "default", &[])).level,
            Level::Ok
        );
        // Both self-hosted → OK.
        assert_eq!(
            check_network(&net("custom", RELAY, "custom", DISC)).level,
            Level::Ok
        );
        // Exactly one self-hosted → WARN (both directions).
        let relay_only = check_network(&net("custom", RELAY, "default", &[]));
        assert_eq!(relay_only.level, Level::Warn);
        assert!(relay_only.message.contains("relay") && relay_only.message.contains("discovery"));
        assert_eq!(
            check_network(&net("default", &[], "custom", DISC)).level,
            Level::Warn
        );
        // Hermetic (relay disabled) → OK; it is NOT "half self-hosted" — discovery is off too.
        assert_eq!(
            check_network(&net("disabled", &[], "default", &[])).level,
            Level::Ok
        );
        // …but discovery knobs set alongside "disabled" are ignored → WARN, truthfully.
        assert_eq!(
            check_network(&net("disabled", &[], "custom", DISC)).level,
            Level::Warn
        );
        // Configs the daemon refuses are ERRORS here too (one validator: net_plan).
        assert_eq!(
            check_network(&net("custom", &[], "default", &[])).level,
            Level::Error
        );
        assert_eq!(
            check_network(&net("default", &[], "custom", &[])).level,
            Level::Error
        );
        assert_eq!(
            check_network(&net("default", &[], "local", &[])).level,
            Level::Error
        );
        assert_eq!(
            check_network(&net("relayless", &[], "default", &[])).level,
            Level::Error
        );
    }

    #[test]
    fn roster_url_warns_only_for_a_urlless_roster_node() {
        // Pairing mode (no org root) → OK regardless of url.
        assert_eq!(check_roster_url(false, None).level, Level::Ok);
        // #38 allow-vocabulary lint: bare entries warn ONLY on a pure-pairing node.
        let bare = vec![("kb".to_string(), "bob".to_string())];
        assert_eq!(check_allow_principals(false, &[]).level, Level::Ok);
        assert_eq!(check_allow_principals(true, &bare).level, Level::Info);
        let v = check_allow_principals(false, &bare);
        assert_eq!(v.level, Level::Warn);
        assert!(
            v.message.contains("re-pair") && v.message.contains("kb:\"bob\""),
            "actionable + names the entry: {}",
            v.message
        );
        assert_eq!(check_roster_url(false, Some("https://x")).level, Level::Ok);
        // Roster mode WITH a url → OK.
        assert_eq!(
            check_roster_url(true, Some("https://intranet/roster.json")).level,
            Level::Ok
        );
        // Roster mode WITHOUT a url → WARN (the [Minor] 7 freshness hint).
        let w = check_roster_url(true, None);
        assert_eq!(w.level, Level::Warn);
        assert!(w.message.contains("max_staleness") && w.message.contains("[roster].url"));
    }

    #[test]
    fn key_perms_tiers_absent_ok_readable_warn_writable_error() {
        // Absent → OK (a key not yet minted is not a finding).
        assert_eq!(check_key_perms(false, 0).level, Level::Ok);
        // 0600 → OK.
        assert_eq!(check_key_perms(true, 0o600).level, Level::Ok);
        // Group-readable (0640), not writable → WARN (exfiltration risk).
        let r = check_key_perms(true, 0o640);
        assert_eq!(r.level, Level::Warn);
        assert!(r.message.contains("readable") && r.message.contains("0640"));
        // World-readable (0604), not writable → WARN.
        assert_eq!(check_key_perms(true, 0o604).level, Level::Warn);
        // Group-writable (0660) → ERROR (attacker can REPLACE the key → identity takeover).
        let w = check_key_perms(true, 0o660);
        assert_eq!(w.level, Level::Error);
        assert!(w.message.contains("writable") && w.message.contains("0660"));
        // World-writable (0666) → ERROR.
        assert_eq!(check_key_perms(true, 0o666).level, Level::Error);
    }

    #[test]
    fn runtime_dir_absent_ok_foreign_owner_error_loose_mode_error() {
        // Absent → OK (the daemon has not started; nothing to secure yet).
        assert_eq!(check_runtime_dir(false, 0, 0, 1000).level, Level::Ok);
        // Present, 0700, owned by us → OK.
        assert_eq!(check_runtime_dir(true, 0o700, 1000, 1000).level, Level::Ok);
        // Owned by another uid → ERROR (the daemon refuses to bind here).
        let foreign = check_runtime_dir(true, 0o700, 0, 1000);
        assert_eq!(foreign.level, Level::Error);
        assert!(foreign.message.contains("uid"));
        // Group/world-accessible (0755) → ERROR (P12 wants 0700).
        let loose = check_runtime_dir(true, 0o755, 1000, 1000);
        assert_eq!(loose.level, Level::Error);
        assert!(loose.message.contains("0755"));
    }

    #[test]
    fn friendly_age_compacts_seconds_to_the_largest_unit() {
        // Monotonic thresholds (>=86400→d, >=3600→h, >=60→m, else s): the shipping `friendly_age`
        // and the `check_roster_freshness` test (which needs friendly_age(3600)=="1h") are consistent
        // with THIS bucketing — no monotonic bucketing can render 3600s as "1h" yet 5400s as "90m".
        assert_eq!(friendly_age(45), "45s");
        assert_eq!(friendly_age(30 * 60), "30m");
        assert_eq!(friendly_age(90 * 60), "1h");
        assert_eq!(friendly_age(36 * 3600), "1d");
        assert_eq!(friendly_age(3 * 86_400), "3d");
        // Negative (clock skew) clamps to 0s, never a panic/underflow.
        assert_eq!(friendly_age(-5), "0s");
    }

    #[test]
    fn roster_freshness_maps_state_words_and_staleness() {
        let max = 24 * 3600;
        // Pairing mode → OK (no roster).
        assert_eq!(
            check_roster_freshness(false, Some("approved"), None, max).level,
            Level::Ok
        );
        // stopped → ERROR (stale/expired past grace; serving stopped).
        assert_eq!(
            check_roster_freshness(true, Some("stopped"), None, max).level,
            Level::Error
        );
        // degraded → WARN.
        assert_eq!(
            check_roster_freshness(true, Some("degraded"), None, max).level,
            Level::Warn
        );
        // pending → WARN (joined, not yet approved).
        assert_eq!(
            check_roster_freshness(true, Some("pending"), None, max).level,
            Level::Warn
        );
        // approved + fresh → OK, and it names the confirmation age.
        let fresh = check_roster_freshness(true, Some("approved"), Some(3600), max);
        assert_eq!(fresh.level, Level::Ok);
        assert!(fresh.message.contains("1h"));
        // approved but last_confirmed older than max_staleness → WARN (a refresh is due).
        assert_eq!(
            check_roster_freshness(true, Some("approved"), Some(max + 3600), max).level,
            Level::Warn
        );
        // Roster mode but the daemon is down (state unknown) → WARN.
        assert_eq!(
            check_roster_freshness(true, None, None, max).level,
            Level::Warn
        );
    }

    #[test]
    fn config_check_flags_parse_failure_and_missing_org_id() {
        // Parse failure → ERROR.
        assert_eq!(check_config(false, false, false).level, Level::Error);
        // Pairing mode, parses → OK (org_id not required).
        assert_eq!(check_config(true, false, false).level, Level::Ok);
        // Roster mode with org_id present → OK, REGARDLESS of user_id: an operator node (`org create`
        // pins org_root_pk + org_id but leaves user_id = None — operators aren't roster members, and
        // the daemon tolerates it, daemon.rs:629) is HEALTHY, not warned. This is the review fix — the
        // old `has_user_id` arm falsely WARNed the org-root holder and told them to "re-run `join`".
        assert_eq!(check_config(true, true, true).level, Level::Ok);
        // Roster mode but org_id missing → WARN (a genuinely incomplete pin).
        assert_eq!(check_config(true, true, false).level, Level::Warn);
    }

    #[test]
    fn daemon_check_reports_running_or_not() {
        assert_eq!(check_daemon(true).level, Level::Ok);
        let down = check_daemon(false);
        assert_eq!(down.level, Level::Warn);
        assert!(down.message.contains("not running"));
    }

    #[test]
    fn worst_level_is_the_max_severity() {
        let ok = [("a", Verdict::ok("x")), ("b", Verdict::ok("y"))];
        assert_eq!(worst_level(&ok), Level::Ok);
        let warn = [("a", Verdict::ok("x")), ("b", Verdict::warn("y"))];
        assert_eq!(worst_level(&warn), Level::Warn);
        let err = [("a", Verdict::warn("x")), ("b", Verdict::error("y"))];
        assert_eq!(worst_level(&err), Level::Error);
        assert_eq!(worst_level(&[]), Level::Ok);
    }

    #[test]
    fn render_report_tags_each_line_and_summarizes() {
        let findings = vec![
            (
                "config",
                Verdict::ok("config parses; required fields present"),
            ),
            (
                "device.key",
                Verdict::error("group/world-writable (mode 0666) — run `chmod 600`"),
            ),
            (
                "self-hosting",
                Verdict::warn("self-hosting relay but not discovery"),
            ),
        ];
        let lines = render_report(&findings);
        assert!(lines[0].starts_with("[OK  ] config:"));
        assert!(lines[1].starts_with("[ERR ] device.key:"));
        assert!(lines[2].starts_with("[WARN] self-hosting:"));
        // A blank line then a summary counting errors + warnings.
        let summary = lines.last().unwrap();
        assert!(
            summary.contains("1 error") && summary.contains("1 warning"),
            "{summary}"
        );
    }

    #[test]
    fn report_leaks_no_transport_vocabulary() {
        // A real base32 EndpointId — doctor must NEVER render one (surface-clean).
        let sample_id = mcpmesh_net::iroh::SecretKey::from_bytes(&[9u8; 32])
            .public()
            .to_string();
        // Build the full finding set the way `findings()` does, with adversarial inputs that exercise
        // every branch (warns + an error), then assert the rendered report is clean.
        let findings = vec![
            ("config", check_config(true, true, true)),
            ("daemon", check_daemon(false)),
            (
                "self-hosting",
                check_network(&net(
                    "custom",
                    &["https://relay.example.com"],
                    "default",
                    &[],
                )),
            ),
            ("roster-url", check_roster_url(true, None)),
            (
                "roster-freshness",
                check_roster_freshness(true, Some("degraded"), Some(90_000), 86_400),
            ),
            ("device.key", check_key_perms(true, 0o644)),
            ("user.key", check_key_perms(true, 0o666)),
            ("org-root.key", check_key_perms(false, 0)),
            ("runtime-dir", check_runtime_dir(true, 0o755, 1000, 1000)),
        ];
        let rendered = render_report(&findings).join("\n");
        assert!(
            !rendered.contains(&sample_id),
            "doctor leaked an EndpointId: {rendered}"
        );
        for term in [
            "b64u:",
            "EndpointId",
            "ALPN",
            "ticket",
            "mcpmesh/mcp/1",
            "mcpmesh/blob/1",
            "pubkey",
            "blake3:",
        ] {
            assert!(
                !rendered.contains(term),
                "doctor leaked '{term}': {rendered}"
            );
        }
    }

    #[test]
    fn windows_shaped_inputs_replace_perm_findings_with_one_info_line() {
        // Windows: `perm_lints_apply = false`. The findings builder must drop ALL four
        // per-file/dir permission findings and emit exactly one Info line in their place, while
        // keeping the platform-independent checks (config, daemon, network, roster). Pure over
        // `DoctorInputs`, so this runs on macOS/Linux CI unchanged (it does not touch the FS).
        let inp = DoctorInputs {
            parse_ok: true,
            bare_allow_entries: Vec::new(),
            org_root_pinned: false,
            has_org_id: false,
            network: net("default", &[], "default", &[]),
            roster_url: None,
            max_staleness_secs: 86_400,
            // Deliberately group/world-writable modes: on unix these would be ERROR findings, so a
            // clean report here proves the perm checks were skipped, not merely passed.
            device_key: (true, 0o666),
            user_key: (true, 0o666),
            org_root_key: (true, 0o666),
            runtime_dir: (true, 0o777, 1000),
            our_uid: 0,
            perm_lints_apply: false,
            staleness_secs: None,
            // Reachable so the platform-independent checks are all green — proving the Info line
            // (advisory) does not by itself flip the exit code below.
            daemon_reachable: true,
            daemon_roster_state: None,
            live_relays: None,
            identity_conflict_epoch: None,
            invites_file: (false, 0),
        };
        let out = findings(&inp);

        for label in ["device.key", "user.key", "org-root.key", "runtime-dir"] {
            assert!(
                !out.iter().any(|(l, _)| *l == label),
                "windows report must not carry the '{label}' permission finding"
            );
        }
        let info: Vec<_> = out.iter().filter(|(_, v)| v.level == Level::Info).collect();
        assert_eq!(info.len(), 1, "expected exactly one Info line: {out:?}");
        let (label, verdict) = info[0];
        assert_eq!(*label, "file-permission lints");
        assert!(
            verdict.message.contains("n/a on Windows"),
            "unexpected Info message: {}",
            verdict.message
        );
        // The Info line is advisory only — with all real checks green it must not flip the exit.
        assert_eq!(worst_level(&out), Level::Ok);
    }
}
