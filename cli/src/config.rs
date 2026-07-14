//! Config per spec §12 — only the M0/M1 subset; grows with the milestones.
use figment::{
    Figment,
    providers::{Format, Toml},
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub identity: IdentityCfg,
    pub network: NetworkCfg,
    pub limits: LimitsCfg,
    /// Roster-mode tunables (spec §4.3 `[roster]`). Currently just the degraded-expiry grace
    /// window; M3c grows it with freshness (`max_staleness`) tunables on the SAME state machine.
    pub roster: RosterCfg,
    /// `[services.<name>]` registry — each entry is a served MCP server plus its allow
    /// list (spec §12/§6.2). Peers do NOT live in config; they live in state.redb
    /// (§4.2/§13), so there is no `[peers]` table here.
    pub services: std::collections::BTreeMap<String, ServiceCfg>,
}

/// A `[services.<name>]` entry: exactly one backend kind (`run` xor `socket`) plus the
/// petnames/groups admitted to it. The xor is validated at access time via
/// [`ServiceCfg::backend_result`] rather than at parse time, so a malformed entry is a
/// per-service error, not a whole-config load failure.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ServiceCfg {
    /// `run`: spawn this command per session (a stdio MCP server).
    pub run: Option<Vec<String>>,
    /// `socket`: dial this local UDS (an already-running MCP server).
    pub socket: Option<String>,
    /// Petnames/groups admitted to this service (flat namespace, §5).
    pub allow: Vec<String>,
}

/// The resolved backend kind of a [`ServiceCfg`], borrowing the config as slices (no
/// clone). `&[String]`/`&str` rather than `&Vec`/`&String` — idiomatic and gives Task 9's
/// backend builders the most flexible borrow.
#[derive(Debug)]
pub enum Backend<'a> {
    Run(&'a [String]),
    Socket(&'a str),
}

impl ServiceCfg {
    /// Resolve the backend, enforcing exactly-one-of `run`/`socket`. Both or neither is an
    /// error — surfaced to the operator, never a silent default.
    #[allow(dead_code)] // consumed by the daemon service wiring (Task 9)
    pub fn backend_result(&self) -> Result<Backend<'_>, String> {
        match (&self.run, &self.socket) {
            (Some(cmd), None) => Ok(Backend::Run(cmd.as_slice())),
            (None, Some(p)) => Ok(Backend::Socket(p.as_str())),
            (Some(_), Some(_)) => Err("service has both run and socket".into()),
            (None, None) => Err("service has neither run nor socket".into()),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct IdentityCfg {
    pub device_key: Option<PathBuf>, // None → paths::default_device_key_path()
    /// This device's suggested name for itself, carried in a minted pairing invite
    /// (spec §4.2). `None` → the daemon defaults to a short base32 fingerprint of the
    /// endpoint id (M2b Task 5). Additive (`#[serde(default)]` at the struct level).
    pub petname: Option<String>,
    /// Roster mode: the org id this node joined (spec §12; pinned at install/join).
    pub org_id: Option<String>,
    /// Roster mode: the pinned org-root public key, `b64u:` (spec §12/§4.3). The single trust
    /// anchor roster signatures verify against. Pinned on first install (M3a) / `join` (M3b).
    pub org_root_pk: Option<String>,
    /// Roster mode: this node's stable user_id in the org (spec §12/§4.6). Pinned at `join`
    /// (proposed) and reconciled to the roster's authoritative value once installed (M3c).
    pub user_id: Option<String>,
    /// Roster mode: path to this person's user key (spec §12/§4.3). Minted by `join`; binds this
    /// person's devices. `None` → paths::default_user_key_path() when needed.
    pub user_key: Option<PathBuf>,
}

/// `[network]` (spec §12/§10.3). The knobs are exactly what `daemon::net_plan` implements —
/// no aspirational surface:
/// - `relay_mode = "default" | "custom" | "disabled"`. `"custom"` requires `relay_urls`
///   (self-hosted iroh relays); `"disabled"` is the HERMETIC mode — no relay AND no
///   discovery (localhost/tests).
/// - `discovery_mode = "default" | "custom"`. `"custom"` requires `discovery_urls` —
///   self-hosted pkarr relay URLs (e.g. an iroh-dns-server), used for BOTH publishing and
///   resolving peer addresses in place of n0's DNS/pkarr. Ignored (off) when
///   `relay_mode = "disabled"`.
///
/// Unknown modes or a `custom` without URLs are startup ERRORS (`net_plan`), never a silent
/// fallback — a metadata-privacy knob must not quietly revert to public infrastructure.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkCfg {
    pub relay_mode: String,
    /// Self-hosted relay URLs, required when `relay_mode = "custom"`.
    pub relay_urls: Vec<String>,
    pub discovery_mode: String,
    /// Self-hosted pkarr relay URLs, required when `discovery_mode = "custom"`.
    pub discovery_urls: Vec<String>,
}
impl Default for NetworkCfg {
    fn default() -> Self {
        Self {
            relay_mode: "default".into(),
            relay_urls: Vec::new(),
            discovery_mode: "default".into(),
            discovery_urls: Vec::new(),
        }
    }
}

/// `[limits]` (spec §12). NOTE — the frame cap is deliberately NOT here: the spec-default
/// 16 MiB `max_frame` is a fixed CONSTANT at each wire (`mcpmesh_net::endpoint` for the mesh,
/// `ipc::MAX_FRAME_BYTES` for the control socket, `backends::MAX_FRAME_BYTES` for local MCP
/// servers), not a config tunable. A `max_frame` config field existed through M4 but was never
/// threaded into any `FrameReader` (dead surface); threading it into the mesh path would widen
/// `mcpmesh-net`'s public API for no demonstrated need, so the field was removed instead (serde
/// ignores an unknown `max_frame` key in existing configs).
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct LimitsCfg {
    pub rate_limit_per_min: u32,
    pub max_inflight: u32,
    pub max_sessions: u32,
}
impl Default for LimitsCfg {
    fn default() -> Self {
        Self {
            rate_limit_per_min: 120,
            max_inflight: 16,
            max_sessions: 4,
        }
    }
}

/// The default degraded-expiry grace window (spec §4.3 `[roster].grace_period` default "72h").
/// A stale roster keeps serving for this window past `expires_at` (with a warning) before it
/// stops granting roster identity. Kept here so [`RosterCfg::default`] and the parse fallback
/// share one source; the gate mirrors it as `roster::gate::DEFAULT_GRACE_SECS`.
const DEFAULT_GRACE_SECS: i64 = 72 * 3600;

/// The default freshness bound (spec §4.3 P13 `[roster].max_staleness`, default "24h" = 86400s). A
/// roster this node has not re-confirmed current within this window degrades on the SAME `RosterState`
/// machine as expiry (warnings within `grace`, then serving stops) — bounding adversarial staleness at
/// `max_staleness + grace` independent of `expires_at`. Shared by [`RosterCfg::default`] + the parse
/// fallback.
const DEFAULT_MAX_STALENESS_SECS: i64 = 24 * 3600;

/// `[roster]` config table (spec §4.3). `grace_period` is the degraded-expiry grace window — how
/// long a roster past `expires_at` keeps serving (degraded, warning) before it stops. Additive
/// (`#[serde(default)]`): a config with no `[roster]` table gets the 72h default. M3c adds the
/// freshness (`max_staleness`) tunables here on the SAME `RosterState` machine.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct RosterCfg {
    /// Degraded-expiry grace window: `"72h"` / `"24h"` / plain seconds (spec §4.3, default "72h").
    pub grace_period: String,
    /// The pinned roster URL for the HTTPS poll (spec §4.3). Operator-managed static hosting; the
    /// joiner's FIRST roster bootstrap (D5). `None` → no URL poll (gossip/manual only). Additive
    /// (`#[serde(default)]`): a config with no `url` key gets `None`, byte-identical to M3b.
    pub url: Option<String>,
    /// How often to poll `url` (spec §4.3 default "1h"). Total-parse like `grace_period` — an
    /// unparseable value falls back to the hourly default rather than disabling the poll.
    pub poll_interval: String,
    /// The freshness bound (spec §4.3 P13, default "24h"): how long this node may go without
    /// re-confirming the installed roster current (via a TLS URL poll ≥ installed, a gossip install,
    /// or a manual install) before it degrades on the SAME `RosterState` machine as expiry. Total-parse
    /// like `grace_period` (an unparseable value falls back to the 24h default — a typo never disables
    /// the bound). Additive (`#[serde(default)]`): a config with no `max_staleness` key gets 24h.
    pub max_staleness: String,
}
impl Default for RosterCfg {
    fn default() -> Self {
        Self {
            grace_period: "72h".into(),
            url: None,
            poll_interval: "1h".into(),
            max_staleness: "24h".into(),
        }
    }
}

impl RosterCfg {
    /// The grace window in SECONDS. An absent or unparseable `grace_period` falls back to the 72h
    /// default rather than erroring — an operator typo must never disable degraded serving, and a
    /// grace window is advisory (spec §4.3), not a security bound (revocation is enforced regardless
    /// of degraded state).
    ///
    /// **M3a/M3c degraded split (DECLARED).** M3a implements the EXPIRY-driven degraded core: the
    /// `RosterState` machine (`RosterView::state`) computed from `expires_at` + THIS grace window
    /// (Approved → DegradedGrace → DegradedStopped), the gate that stops granting roster identity once
    /// DegradedStopped (fail-closed — revocation is still enforced), and the degraded-grace serving
    /// warning (`daemon::warn_if_degraded_grace`). M3c layers the `last_confirmed`/`max_staleness`
    /// FRESHNESS path (§4.3 P13) onto the SAME `RosterState` (a stale-but-unexpired roster degrades
    /// identically).
    pub fn grace_seconds(&self) -> i64 {
        parse_duration(&self.grace_period).unwrap_or(DEFAULT_GRACE_SECS)
    }

    /// The URL poll interval in SECONDS (default 3600). Like [`grace_seconds`](Self::grace_seconds)
    /// it is TOTAL — an absent/unparseable value falls back to the hourly default rather than
    /// erroring, so an operator typo slows the poll to hourly instead of disabling freshness.
    pub fn poll_interval_seconds(&self) -> i64 {
        parse_duration(&self.poll_interval).unwrap_or(3600)
    }

    /// The freshness bound in SECONDS (default 86400 = 24h). Like [`grace_seconds`](Self::grace_seconds)
    /// it is TOTAL — an absent/unparseable value falls back to the 24h default rather than erroring, so
    /// an operator typo tightens/loosens to 24h instead of disabling the freshness bound (spec §4.3 P13).
    pub fn max_staleness_seconds(&self) -> i64 {
        parse_duration(&self.max_staleness).unwrap_or(DEFAULT_MAX_STALENESS_SECS)
    }
}

/// Parse a duration string to SECONDS: a `d`/`h`/`m`/`s` suffix (days/hours/minutes/seconds) or a
/// bare number (seconds). Trim + suffix-strip + checked multiply; rejects a
/// negative/overflowing/garbage value as `Err` (the caller supplies the
/// default). `u64` parse then a checked `i64` conversion: a negative grace is meaningless, so `-1`
/// fails the `u64` parse and falls back to the default rather than becoming a negative window.
// `pub` (not `pub(crate)`): the `org create --expires` porcelain lives in the BIN crate (`main.rs`),
// a distinct crate from this lib, so it must reach `parse_duration` across the crate boundary (spec
// §4.3 operator-managed validity window). Pure parser — no state, no behavior change.
pub fn parse_duration(s: &str) -> Result<i64, String> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('d') {
        (n, 24 * 3600)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else {
        (s, 1)
    };
    num.trim()
        .parse::<u64>()
        .ok()
        .and_then(|v| v.checked_mul(mult))
        .and_then(|v| i64::try_from(v).ok())
        .ok_or_else(|| format!("unparseable duration: {s}"))
}

// figment::Error is ~208 bytes; boxing it would churn the API for a cold path.
#[allow(clippy::result_large_err)]
impl Config {
    #[allow(dead_code)] // exercised by unit tests; config-string entry point for later tooling
    pub fn from_toml_str(s: &str) -> Result<Self, figment::Error> {
        Figment::new().merge(Toml::string(s)).extract()
    }

    /// Missing file → defaults (first run); malformed file → Err.
    /// Callers must surface the Err — swallowing it silently reverts user choices.
    pub fn load(path: &std::path::Path) -> Result<Self, figment::Error> {
        Figment::new().merge(Toml::file(path)).extract()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_yields_spec_defaults() {
        let c = Config::from_toml_str("").unwrap();
        assert_eq!(c.network.relay_mode, "default");
        assert_eq!(c.network.discovery_mode, "default");
        assert_eq!(c.limits.rate_limit_per_min, 120);
        assert_eq!(c.limits.max_inflight, 16);
        assert_eq!(c.limits.max_sessions, 4);
    }

    #[test]
    fn values_override_defaults() {
        let c = Config::from_toml_str(
            "[network]\nrelay_mode = \"disabled\"\n[limits]\nrate_limit_per_min = 60\n",
        )
        .unwrap();
        assert_eq!(c.network.relay_mode, "disabled");
        assert_eq!(c.limits.rate_limit_per_min, 60);
        assert_eq!(c.limits.max_inflight, 16);
    }

    /// A legacy config carrying the removed `max_frame` key still loads (serde ignores unknown
    /// fields) — the frame cap is a fixed constant now, not a tunable (see the `LimitsCfg` doc).
    #[test]
    fn legacy_max_frame_key_is_ignored_not_an_error() {
        let c =
            Config::from_toml_str("[limits]\nmax_frame = \"1MiB\"\nmax_sessions = 2\n").unwrap();
        assert_eq!(c.limits.max_sessions, 2);
    }

    /// §10.3 self-hosting knobs parse: `custom` modes with their URL lists. (Validation —
    /// custom-without-urls, unknown modes — lives in `daemon::net_plan`, tested there.)
    #[test]
    fn network_relay_and_discovery_urls_parse() {
        let c = Config::from_toml_str(
            "[network]\nrelay_mode = \"custom\"\nrelay_urls = [\"https://relay.acme.com\"]\n\
             discovery_mode = \"custom\"\ndiscovery_urls = [\"https://dns.acme.com/pkarr\"]\n",
        )
        .unwrap();
        assert_eq!(c.network.relay_mode, "custom");
        assert_eq!(
            c.network.relay_urls,
            vec!["https://relay.acme.com".to_string()]
        );
        assert_eq!(c.network.discovery_mode, "custom");
        assert_eq!(
            c.network.discovery_urls,
            vec!["https://dns.acme.com/pkarr".to_string()]
        );
        // Absent → empty lists (the defaults need no URLs).
        let c = Config::from_toml_str("").unwrap();
        assert!(c.network.relay_urls.is_empty() && c.network.discovery_urls.is_empty());
    }

    #[test]
    fn missing_file_loads_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::load(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(c.network.relay_mode, "default");
    }

    #[test]
    fn roster_url_and_poll_interval_parse_with_defaults() {
        // No [roster] table → url None, poll 1h default.
        let c = Config::from_toml_str("").unwrap();
        assert!(c.roster.url.is_none());
        assert_eq!(c.roster.poll_interval_seconds(), 3600);
        // A configured url + poll interval.
        let c = Config::from_toml_str(
            "[roster]\nurl = \"https://intranet.acme.com/roster.json\"\npoll_interval = \"30m\"\n",
        )
        .unwrap();
        assert_eq!(
            c.roster.url.as_deref(),
            Some("https://intranet.acme.com/roster.json")
        );
        assert_eq!(c.roster.poll_interval_seconds(), 30 * 60);
        // An unparseable poll_interval falls back to the hourly default (never disables the poll).
        let c = Config::from_toml_str("[roster]\npoll_interval = \"never\"\n").unwrap();
        assert_eq!(c.roster.poll_interval_seconds(), 3600);
        // The url is additive: setting only grace_period keeps url None + the default poll.
        let c = Config::from_toml_str("[roster]\ngrace_period = \"24h\"\n").unwrap();
        assert!(c.roster.url.is_none());
        assert_eq!(c.roster.poll_interval_seconds(), 3600);
    }

    #[test]
    fn roster_max_staleness_defaults_to_24h_and_parses() {
        // No [roster] table → the 24h freshness bound (spec §4.3 P13 default).
        let c = Config::from_toml_str("").unwrap();
        assert_eq!(c.roster.max_staleness_seconds(), 24 * 3600);
        // A configured value parses (units, like grace_period).
        let c = Config::from_toml_str("[roster]\nmax_staleness = \"6h\"\n").unwrap();
        assert_eq!(c.roster.max_staleness_seconds(), 6 * 3600);
        // An unparseable value falls back to the 24h default (never disables the freshness bound).
        let c = Config::from_toml_str("[roster]\nmax_staleness = \"forever\"\n").unwrap();
        assert_eq!(c.roster.max_staleness_seconds(), 24 * 3600);
        // Additive: setting only grace_period keeps the 24h max_staleness default.
        let c = Config::from_toml_str("[roster]\ngrace_period = \"48h\"\n").unwrap();
        assert_eq!(c.roster.max_staleness_seconds(), 24 * 3600);
    }

    #[test]
    fn roster_grace_defaults_to_72h_and_parses_units() {
        // Absent `[roster]` → the 72h default.
        let c = Config::from_toml_str("").unwrap();
        assert_eq!(c.roster.grace_seconds(), 72 * 3600);
        // Hours / days / minutes / seconds / bare-seconds all resolve to seconds.
        for (body, want) in [
            ("[roster]\ngrace_period = \"24h\"\n", 24 * 3600),
            ("[roster]\ngrace_period = \"72h\"\n", 72 * 3600),
            ("[roster]\ngrace_period = \"1d\"\n", 24 * 3600),
            ("[roster]\ngrace_period = \"30m\"\n", 30 * 60),
            ("[roster]\ngrace_period = \"90s\"\n", 90),
            ("[roster]\ngrace_period = \"3600\"\n", 3600), // bare seconds
        ] {
            assert_eq!(
                Config::from_toml_str(body).unwrap().roster.grace_seconds(),
                want,
                "{body}"
            );
        }
    }

    #[test]
    fn roster_grace_unparseable_or_negative_falls_back_to_default() {
        // A garbage / negative / overflowing grace never disables degraded serving — it defaults.
        for body in [
            "[roster]\ngrace_period = \"seventy-two hours\"\n",
            "[roster]\ngrace_period = \"-5h\"\n",
            "[roster]\ngrace_period = \"18446744073709551615d\"\n", // overflows the checked_mul
            "[roster]\ngrace_period = \"\"\n",
        ] {
            assert_eq!(
                Config::from_toml_str(body).unwrap().roster.grace_seconds(),
                72 * 3600,
                "{body}"
            );
        }
    }

    #[test]
    fn services_parse_run_and_socket() {
        let c = Config::from_toml_str(concat!(
            "[services.notes]\nrun = [\"npx\", \"server\"]\nallow = [\"bob\"]\n",
            "[services.kb]\nsocket = \"/run/kb.sock\"\nallow = [\"team-eng\"]\n",
        ))
        .unwrap();
        let notes = c.services.get("notes").unwrap();
        assert!(
            matches!(notes.backend_result(), Ok(Backend::Run(cmd)) if cmd == &["npx".to_string(), "server".to_string()][..])
        );
        assert_eq!(notes.allow, vec!["bob".to_string()]);
        assert!(
            matches!(c.services.get("kb").unwrap().backend_result(), Ok(Backend::Socket(p)) if p == "/run/kb.sock")
        );
    }

    #[test]
    fn service_with_both_run_and_socket_is_an_error() {
        let e = Config::from_toml_str("[services.x]\nrun=[\"a\"]\nsocket=\"/s\"\nallow=[]\n");
        // exactly one backend kind is required — validate at access time.
        assert!(
            e.unwrap()
                .services
                .get("x")
                .unwrap()
                .backend_result()
                .is_err()
        );
    }

    #[test]
    fn identity_reads_user_id_and_user_key() {
        let toml = "[identity]\n\
            org_id = \"acme\"\n\
            org_root_pk = \"b64u:AAAA\"\n\
            user_id = \"alice\"\n\
            user_key = \"/home/alice/.config/mcpmesh/user.key\"\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.identity.user_id.as_deref(), Some("alice"));
        assert_eq!(
            cfg.identity.user_key.as_deref(),
            Some(std::path::Path::new("/home/alice/.config/mcpmesh/user.key"))
        );
        // Absent → None (pure-pairing / operator-only node).
        let bare: Config = toml::from_str("[identity]\n").unwrap();
        assert!(bare.identity.user_id.is_none() && bare.identity.user_key.is_none());
    }
}
