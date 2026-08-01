//! mcpmesh-local/1 protocol types. Shared vocabulary between the daemon
//! and its clients (porcelain, connect proxy, later the host shell). Wire framing
//! is the family NDJSON codec — carried by the caller, not defined here.
//!
//! Request/response asymmetry: requests are one typed, closed enum (`Request`);
//! responses are per-method typed structs deserialized from the JSON-RPC `result`
//! Value — `Status` → [`StatusResult`], `RegisterService` → an ack, `OpenSession` →
//! no JSON-RPC result at all: the socket STOPS being JSON-RPC and becomes a raw
//! byte pipe.
//!
//! Additive-only: new fields (capabilities on `Hello`, groups/user_id on
//! `PeerInfo`, device on `OpenSession`) MUST land as
//! `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The first exchange on any `*-local/N` socket (the family's hello convention).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub api: String,         // "mcpmesh-local/1"
    pub api_version: String, // "MAJOR.MINOR" of the protocol surface (see API_MINOR)
    /// The protocol-compatibility MINOR as an integer, for a trivial machine comparison
    /// (`api_minor >= N`) without string parsing. Distinct from `stack_version` (the crate
    /// release train). Additive: an older daemon omits it and it defaults to 0.
    #[serde(default)]
    pub api_minor: u32,
    pub stack_version: String,
}

/// The kind of backend answering a service — the two valid values, enforced at the
/// type level and kept in lockstep with `BackendSpec`'s variants. Status reports the
/// kind only, never the command/path (no transport vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Run,
    Socket,
}

/// A registered service as reported by `status` (no transport vocabulary).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub allow: Vec<String>, // STABLE principals (b64u:/eid:) or roster names (#38) — never nicknames
    /// The HUMAN rendering of `allow`, index-aligned: each principal resolved to its peer's
    /// display nickname by the daemon (which owns the store); an unresolvable stable
    /// principal renders as a neutral placeholder — porcelain must show THESE, never raw
    /// ids (surface discipline). Additive: default + skip-if-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_display: Vec<String>,
    pub backend: BackendKind, // "run" | "socket" (kind only, never the command/path)
    /// True if this registration is ephemeral (#36): in-memory only, tied to the registering
    /// control connection's lifetime, absent from config, gone on restart. Additive — an older
    /// daemon omits it and it reads as `false` (the persistent default).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

/// A known peer as reported by `status` (nickname only — never the EndpointId).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub services: Vec<String>,
    /// The peer's PROVEN self-sovereign `user_id` (`b64u:<user_pk>`) if it presented a verified
    /// device->user binding at pairing (roster peers carry it too), else `None` (nickname-only). This
    /// is a surface-clean identity (an opaque user id, NOT an EndpointId). Additive:
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so older payloads round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The peer's stable DEVICE principal `eid:<hex>` (#41) — the SAME rendering the socket
    /// backend injects into `_meta["mcpmesh/peer"]` and that appears in `[services.*].allow`.
    /// Always present for a real peer (`Option` only for additive round-trip). Distinct from
    /// `user_id` (the person-level `b64u:`, present only when the peer proved a binding): a
    /// nickname is not unique, so an embedder keys caller-scoped decisions (dial the caller
    /// back, "the requester's own data") on THIS, the authenticated endpoint. Machine-surface
    /// authz vocabulary (like the allow lists) — human porcelain still shows the nickname.
    /// Additive: `#[serde(default, skip_serializing_if = "Option::is_none")]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

/// HOW a peer is reached (#64): a direct/hole-punched QUIC path, or through a relay.
///
/// `rtt_ms` is NOT a proxy for this — a fast relay beats a slow direct path — and iroh's own
/// distinction was being dropped at the mcpmesh boundary. Three things depend on it: a truthful
/// locality claim ("this traffic never left the building"), honest disclosure that a relayed path
/// depends on third-party infrastructure, and diagnostics, since "slow" has a different cause and
/// fix in each case.
///
/// **Only `Direct` supports a locality claim.** `Unknown` means "we do not know", NOT "private" —
/// rendering it as private is the one misuse that turns this field into a false privacy statement.
/// The daemon errs the same way: when a relay path is active it reports [`Relay`](Self::Relay) even
/// if a direct path is live too, because overstating privacy is worse than understating it.
///
/// `#[non_exhaustive]`: iroh already has a third address kind (a custom transport) that could
/// warrant a variant, and adding one to a public enum later breaks every downstream exhaustive
/// `match` — the lesson #58 paid for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PeerPath {
    /// A direct or hole-punched QUIC path: the bytes did not transit a relay.
    Direct,
    /// Through a relay server. `url` is the relay in use when known.
    Relay {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    /// Not known: never probed, no selected path, or a transport mcpmesh does not model.
    ///
    /// `#[serde(other)]` makes this the landing spot for a `kind` a client has never heard of. That
    /// is what actually buys wire-additivity: `#[non_exhaustive]` only protects the Rust `match`,
    /// and without this an older client hits `unknown variant` and fails to deserialize the WHOLE
    /// `PeerReachability` — one new path kind would break every `status` response it reads.
    #[default]
    #[serde(other)]
    Unknown,
}

/// Advisory reachability of a paired peer (pairing-mode liveness). Surface-clean: a nickname, a
/// bool, latency/age NUMBERS, the stable `eid:` principal (#42), and since #64 the PATH KIND —
/// direct vs relay, plus the relay URL when relayed. Never a socket address, an IP, or a key: the
/// path field says WHICH KIND of route is in use, never where the peer is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReachability {
    pub name: String,    // the peer's nickname
    pub reachable: bool, // result of the last probe (false if never probed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Last measured round-trip, if reachable: dial + ping/pong, stamped AT THE PONG.
    ///
    /// It EXCLUDES the window the daemon spends afterwards determining which path the connection
    /// settled on. Before 0.20.1 it included that window, so a relayed peer could never report
    /// under 600ms and most of the figure was a deliberate wait rather than time on the wire —
    /// an embedder read ~820ms across one LAN hop and reported it as a 66x latency regression
    /// (#123). It is a wire-latency measurement now, so "relayed AND low rtt_ms" is a reachable
    /// state and a usable diagnostic.
    pub rtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>, // None = never probed (consumer shows "checking…")
    /// The peer's OPTIONAL app metadata (#40) — the same opaque ≤256B blob #39 exposes via
    /// presence, here carried on the pairing-mode `mcpmesh/ping/1` probe pong so PAIRED peers
    /// (which have no presence gossip) see it too. Empty when the peer set none. Advisory
    /// display data; never an authz input. Near-real-time when `status` is read (the probe
    /// cache has a ~20s TTL), not a steady push. Additive: default + skip-if-empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub meta: String,
    /// The peer's stable DEVICE principal `eid:<hex>` (#42) — the SAME rendering as
    /// [`PeerInfo::principal`], so an embedder joins probe result + `meta` (app version) to a
    /// peer by the AUTHENTICATED endpoint rather than the non-unique nickname. Always present
    /// for a real row (`Option` only for additive round-trip). Machine-surface authz
    /// vocabulary — the human `status` reachability line is unchanged. Additive:
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
    /// HOW this peer is reached (#64) — see [`PeerPath`]. Captured by the same probe that sets
    /// `reachable`/`rtt_ms`, so it shares their freshness: one TTL, one `age_secs`. `Unknown` for a
    /// peer never probed. Additive (`#[serde(default)]`), so older rows and clients are unaffected.
    #[serde(default)]
    pub path: PeerPath,
}

/// WHICH producer emitted a [`StreamFrame::Reachability`] (#150). The two say different things
/// about the world and license different user-facing statements, and until API 1.30 the frame
/// carried no way to tell them apart.
///
/// Advisory attribution, never an authz input: it says where an observation CAME FROM, never who a
/// peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReachabilitySource {
    /// A **probe** completed — a fresh throwaway dial (`status`/`subscribe` refreshing a stale
    /// entry). It describes that dial and nothing else: a `Probe` frame saying `Relay` does NOT
    /// mean any live connection is relayed.
    Probe,
    /// A **live session**'s selected path changed under it (#92 item 2). This is a claim about the
    /// link a peer's traffic is actually on — the frame an embedder wants when warning that a call
    /// which WAS direct silently is not any more.
    Session,
    /// The daemon did not say (`api_minor < 30`), or it named a producer this client predates.
    ///
    /// The DEFAULT, deliberately — see [`StreamFrame::Reachability`]. Like [`PeerPath::Unknown`] it
    /// means "we do not know" and must never be collapsed into either confident case.
    #[default]
    Unknown,
}

/// Hand-written so an unrecognized producer lands on [`ReachabilitySource::Unknown`] instead of
/// failing the whole frame. [`PeerPath`] gets this from `#[serde(other)]`, which serde allows only
/// on an internally/adjacently tagged enum; this one is a plain string, so it is spelled out. The
/// stakes are the same as there: without it, adding a third producer later would break every
/// `Reachability` frame an older pinned client reads, not just the new field.
///
/// It accepts ANY input, not just an unrecognized string — `null`, a number, an object all read as
/// `Unknown`. `#[serde(default)]` covers an ABSENT key and nothing else, so without this a proxy or
/// non-Rust daemon that normalizes optional fields to `null` would fail every reachability frame
/// while this module's doc promised the field could not break a parse. A degraded attribution is
/// the fail-safe: `Unknown` already means "we do not know", which is exactly true of a value we
/// could not read.
impl<'de> Deserialize<'de> for ReachabilitySource {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct AnySource;

        /// Every hook answers `Unknown` except `visit_str`, so a shape we do not model degrades
        /// instead of erroring. `visit_map`/`visit_seq` must DRAIN their input — leaving it
        /// unconsumed desynchronizes the parser and fails the enclosing frame, which is the
        /// failure this impl exists to avoid.
        impl<'de> serde::de::Visitor<'de> for AnySource {
            type Value = ReachabilitySource;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a reachability producer name")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(match s {
                    "probe" => ReachabilitySource::Probe,
                    "session" => ReachabilitySource::Session,
                    _ => ReachabilitySource::Unknown,
                })
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<Self::Value, D::Error> {
                d.deserialize_any(AnySource)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Self::Value, A::Error> {
                while m
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(ReachabilitySource::Unknown)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<Self::Value, A::Error> {
                while s.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(ReachabilitySource::Unknown)
            }
        }

        d.deserialize_any(AnySource)
    }
}

/// Roster-mode status. Surface-clean roster VOCABULARY only: org_id, serial, a plain
/// state word, and the pinned org-root FINGERPRINT in short words — never raw keys/EndpointIds/serials-
/// as-transport-vocab. Absent in a pure-pairing daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterStatus {
    pub org_id: String,
    pub serial: u64,
    pub state: String, // "pending" | "approved" | "degraded" | "stopped"
    pub org_root_fingerprint: String, // short-word form
}

/// One reachable roster peer device as reported by `status` (the advisory presence read).
/// ADVISORY — this is a display convenience, never an authorization surface. Surface-clean:
/// FLAT vocabulary ONLY — a `user_id`, a human `device_label`, its `role` word, and an `online`
/// boolean. It carries NO EndpointId / pubkey / hash / ALPN or any transport vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresencePeer {
    pub user_id: String,
    pub device_label: String,
    pub role: String, // "primary" | "mirror" (roster vocabulary)
    /// Whether the device has a live presence heartbeat (advisory — absence never blocks a dial).
    pub online: bool,
    /// The device's OPTIONAL embedder-set app metadata (#39) — an opaque ≤256B blob carried
    /// (signed) on its presence heartbeat, empty when the device set none. Advisory display
    /// data; never an authz input. Additive: default + skip-if-empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub meta: String,
}

/// One recently completed INVITER-side pairing, surfaced by `status` so the inviter's human can
/// read the short authentication code (SAS) and compare it with the redeemer's out-of-band —
/// the pairing ceremony is "both humans compare the code": the redeemer sees it in its
/// [`PairResult`]; this is the inviter's porcelain surface for the same words. DISPLAY-ONLY
/// ceremony state: held in-memory by the daemon (a small ring), lost on restart, NEVER an
/// authorization input or trust data. Surface-clean: a nickname + the SAS wordlist words +
/// an epoch — never an EndpointId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentPairing {
    /// The peer's nickname as stored by the inviter (its local name for the redeemer).
    pub peer_nickname: String,
    /// The display-only SAS words (e.g. `"tango-fig-cabbage"`) — the same code the redeemer's
    /// `PairResult.sas_code` carried. Never checked programmatically.
    pub sas_code: String,
    /// When the pairing completed (epoch seconds) — the porcelain renders a friendly age.
    pub paired_at_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub stack_version: String,
    pub services: Vec<ServiceInfo>,
    pub peers: Vec<PeerInfo>,
    /// Roster-mode status, absent in a pure-pairing daemon. Additive:
    /// `#[serde(default, skip_serializing_if = ...)]` so a daemon/client without it round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster: Option<RosterStatus>,
    /// The reachable roster peer devices (the advisory presence read), each with an `online`
    /// flag. Empty in a pure-pairing daemon / when no roster is installed. Additive:
    /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<PresencePeer>,
    /// THIS daemon's own self-sovereign `user_id` (`b64u:<user_pk>`), if it has a user key (auto-
    /// minted at boot; shared by pairing AND roster mode). Lets the operator see + share their stable
    /// identity that multiple devices resolve to. `None` only when no user key exists. Additive:
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_user_id: Option<String>,
    /// Recent INVITER-side pairing completions, newest first (display-only pairing-ceremony aids —
    /// see [`RecentPairing`]; in-memory on the daemon, cleared by a restart). Empty on a daemon
    /// that has accepted no pairing since it started. Additive:
    /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_pairings: Vec<RecentPairing>,
    /// Advisory reachability of paired peers, from the on-demand probe cache. Empty until the
    /// first probe completes. Additive: default + skip-if-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reachability: Vec<PeerReachability>,
    /// This node's EFFECTIVE self-nickname — what a freshly minted invite would present
    /// (config `[identity].nickname`, else the hostname, else a fingerprint; live-updated by
    /// `set_nickname`, #37). Empty only in mesh-less control-only mode. Additive: default +
    /// skip-if-empty so an older payload round-trips.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub self_nickname: String,
    /// On-disk footprint of this node's own state (#88), so an embedder can warn a user before
    /// ENOSPC rather than after — the audit log's write rate is driven by inbound peer traffic,
    /// and it shares a filesystem with `state.redb` and the device key. A LIVE read (computed
    /// per `status` call), not a boot-time snapshot. `None` only in mesh-less control-only mode.
    /// Additive: default + skip-if-none so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageInfo>,
    /// THIS node's own reachability posture (#90) — see [`SelfNetwork`]. Computed live per
    /// call; `None` in mesh-less control-only mode. Additive: default + skip-if-none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_network: Option<SelfNetwork>,
}

/// The `status.self_network` block (#90): THIS node's own reachability posture — the first
/// question in every "my message never arrived" investigation, previously unanswerable from
/// either side of the API. Self-facing only: everything here is the node's own information
/// (relay URLs come from its own config, sanitized; direct addresses already ride its invites).
///
/// `online` is iroh's own semantics — a home-relay connection is established. In
/// `relay_mode = "disabled"` it is ALWAYS `false` with an empty `relays` list: that is a
/// configuration, not an outage — render it as "LAN-only", never as a health warning.
///
/// Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfNetwork {
    /// A home-relay connection is established (iroh's `online` definition). The signal #53's
    /// `set_relays` never had: when this goes false on a relay-enabled node, the relay set is
    /// the thing to look at.
    pub online: bool,
    /// The CONNECTED home relay's URL, sanitized to scheme + host + port (operator-supplied
    /// relay URLs can carry userinfo tokens; `status` output gets screenshotted). `None` when
    /// no relay is connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_relay: Option<String>,
    /// Every known home relay and its current connection state. Empty when no relays are
    /// configured, or before the endpoint has selected any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<RelayInfo>,
    /// This endpoint's direct (non-relay) socket addresses — its own dialable coordinates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_addrs: Vec<String>,
    /// When the daemon's watcher last observed a TRANSITION (epoch seconds) — a change of
    /// `online`, `home_relay`, or a relay's connection state; `direct_addrs` drift alone does
    /// not stamp (nor emit a frame). OMITTED (not `null`) until the first observed transition
    /// after boot, and from a point-in-time computation with no watcher running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_change_epoch: Option<i64>,
}

/// One home relay's connection state (#90). No latency — per-relay RTT needs iroh's
/// `net_report`, which is unstable-feature-gated as of 1.0.3; `connected` is the stable truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Sanitized (scheme + host + port), like `home_relay`.
    pub url: String,
    pub connected: bool,
}

/// The `status.storage` block (#88): bytes actually on disk, by subsystem. Counts, never
/// content. Additive-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageInfo {
    /// Summed sizes of the monthly audit files (`<state>/audit/*.jsonl`).
    pub audit_bytes: u64,
    /// Size of the peer/trust state store (`state.redb`).
    pub redb_bytes: u64,
    /// Total size under the app-blob store directory; 0 when no blob store exists.
    pub blobs_bytes: u64,
}

/// Params of [`Request::RegisterService`]: the `[services.*]` entry to write/update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterServiceParams {
    pub name: String,
    pub backend: BackendSpec,
    pub allow: Vec<String>,
    /// When true (#36), the registration is EPHEMERAL: kept in daemon memory only, never written
    /// to the on-disk config, and automatically unregistered when the control connection that
    /// registered it closes (and gone on daemon restart). For an embedder that serves a
    /// `socket` backend from a fresh path each run, this removes the need to derive a stable
    /// socket path solely to keep a persisted registration valid, and the stale-registration
    /// accumulation that comes with no unregister. Default false = the persistent behavior.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ephemeral: bool,
}

/// Params of [`Request::Invite`]: the services the minted invite grants. Rejects unknown
/// fields (so `{service: "kb"}` — a singular typo — is a loud error, not a silently
/// grants-nothing invite), and the daemon additionally rejects an empty/absent `services`
/// list (an invite that grants nothing is useless — #34).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteParams {
    #[serde(default)]
    pub services: Vec<String>,
    /// An OPAQUE, caller-chosen label carried through to the redeemer in the `pair` result (#31).
    /// mcpmesh never interprets it (not a nickname, never resolved or authorized) — a per-pairing
    /// metadata slot for the embedder (e.g. its own URN). Capped at the daemon; omit for none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_label: Option<String>,
}

/// Params of [`Request::Pair`]: the copyable `mcpmesh-invite:` line. Defaultable — an
/// absent field reads as an empty line, which simply fails to decode (a clean pair error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairParams {
    #[serde(default)]
    pub invite_line: String,
}

/// Params of [`Request::PeerRemove`]: the nickname to unpair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRemoveParams {
    pub nickname: String,
}

/// Params of [`Request::PeerRename`]: the contact to rename — every device sharing `user_id`
/// when given, else the single provisional `nickname` entry — and the new nickname `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRenameParams {
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub nickname: Option<String>,
    pub to: String,
}

/// Params of [`Request::PeerAdd`] (reserved/internal — see the variant): a raw `endpoint_id`
/// (iroh base32) plus the nickname and service allow list to install it under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerAddParams {
    pub nickname: String,
    pub endpoint_id: String,
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Params of [`Request::OpenSession`]: the `peer/service` target to dial. Both fields are
/// defaultable — an empty target simply fails the dial (a clean `-32055` error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenSessionParams {
    #[serde(default)]
    pub peer: String,
    #[serde(default)]
    pub service: String,
}

/// Params of [`Request::RosterInstall`]: the LOCAL roster file `path`, plus the org-root pin
/// on FIRST install (`b64u:`; omit once pinned — config carries it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterInstallParams {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_root_pk: Option<String>,
}

/// Params of [`Request::OrgJoin`]: the `[identity]` pin. `user_key` is a LOCAL path — the key
/// never crosses the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgJoinParams {
    pub org_id: String,
    pub org_root_pk: String,
    pub user_id: String,
    pub user_key: String,
}

/// Params of [`Request::SetAppMetadata`]: this node's opaque app-metadata blob (#39). The
/// daemon NEVER interprets it — the embedder structures its own bytes (a version string,
/// small JSON, …). Capped at 256 bytes; `""` clears it. Roster-mode only (it rides the
/// signed presence heartbeat); a pure-pairing daemon accepts + stores it but never gossips it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetAppMetadataParams {
    pub metadata: String,
}

/// Params of [`Request::PeerServices`] (#52): the peer to query — a nickname, an `eid:` device
/// principal, or a `b64u:` user_id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerServicesParams {
    pub peer: String,
}

/// Result of [`Request::PeerServices`] (#52): the services the queried peer CURRENTLY grants the
/// caller — computed authoritatively on the peer (which owns the truth), always current, only
/// the caller's own admitted services (never the peer's full registry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerServicesResult {
    pub services: Vec<String>,
}

/// Params of [`Request::UnregisterService`] (#50): the persistent (or ephemeral) service name
/// to remove — the deregistration mirror of `register_service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnregisterServiceParams {
    pub name: String,
}

/// Params of [`Request::ServiceAllowGrant`] / [`Request::ServiceAllowRevoke`] (#44): toggle a
/// single stable `principal` (`b64u:`/`eid:`) on a single `service`'s allow list, WITHOUT
/// unpairing. The per-peer "sharing" switch primitive the embedder drives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAllowParams {
    pub service: String,
    pub principal: String,
}

/// Params of [`Request::SetNickname`]: this node's new self-nickname (#37). Display-only
/// semantics: it names this node in FUTURE invites/presentations; peers keep the nickname
/// they stored at pairing time until a re-invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetNicknameParams {
    pub nickname: String,
}

/// Params of [`Request::SetRosterUrl`]: the HTTPS roster URL to pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRosterUrlParams {
    pub url: String,
}

/// Params of [`Request::SetRelays`] (#53): the node's desired CUSTOM relay set. Declarative —
/// "make the custom relay set exactly this" — applied as a live insert/remove diff against the
/// running endpoint (iroh 1.0.3 `Endpoint::insert_relay`/`remove_relay`) when the node is already
/// in `relay_mode = "custom"`, then persisted to `[network]`. Each entry must parse as an iroh
/// `RelayUrl`; an empty list is rejected (custom mode requires ≥1 relay — fully disabling relays
/// is a `relay_mode = "disabled"` restart, not this verb). Switching a node that is currently
/// `default`/`disabled` onto custom persists the config but needs a restart to take effect (iroh
/// cannot live-transition the relay MODE) — signalled by [`SetRelaysResult::restart_required`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetRelaysParams {
    pub relay_urls: Vec<String>,
}

/// Result of [`Request::SetRelays`] (#53).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetRelaysResult {
    /// The persisted `relay_urls` differed from the prior config (a no-op edit → `false`).
    pub changed: bool,
    /// `true` iff the node's current `relay_mode` is not `custom`, so the new set was persisted
    /// but NOT applied live — a node restart is required for it to take effect. `false` on the
    /// live custom→custom path (already applied to the running endpoint).
    pub restart_required: bool,
}

/// Params of [`Request::BlobPublish`]: the scope to publish into and the LOCAL file to add.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPublishParams {
    pub scope: String,
    pub path: String,
}

/// Params of [`Request::BlobGrant`]: the scope and the flat-namespace principal to grant it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobGrantParams {
    pub scope: String,
    pub principal: String,
}

/// Params of [`Request::BlobRevoke`] (#62): the scope and the principals to withdraw from it.
///
/// SCOPED, unlike unpair hygiene: only the named scope's grants change. A principal that also holds
/// grants on other scopes keeps them — withdrawing access to one thing must not silently withdraw
/// access to everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRevokeParams {
    pub scope: String,
    pub principals: Vec<String>,
}

/// Params of [`Request::BlobUnpublish`] (#62): the scope and the blake3 hex to remove from it.
///
/// Removes REACHABILITY, not bytes. The scope gate requires a hash to be listed in some scope, so
/// this takes effect immediately for authorization — but the bytes stay in the local store, and
/// there is no reclaim verb yet. Do not surface this to a user as deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobUnpublishParams {
    pub scope: String,
    pub hash: String,
}

/// Params of [`Request::BlobRepublish`] (#83): the scope and the blake3 hex to add to it.
///
/// The blob must already be held COMPLETE by this daemon — republish makes a fetched blob servable
/// FROM this node, it does not fetch. A hash that is absent, or only partially present from an
/// interrupted fetch, is refused with [`ERR_NO_SUCH_BLOB`]: advertising bytes we cannot serve would
/// turn the original publisher going offline into a hang at every fetcher.
///
/// It grants NOBODY. The republisher names a scope they already control; inheriting the original
/// publisher's grants would be a silent authorization transfer. Share with `blob_grant`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobRepublishParams {
    pub scope: String,
    pub hash: String,
}

/// Params of [`Request::BlobFetch`]: the `mcpmesh/blob/1` ticket and the LOCAL export path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobFetchParams {
    pub ticket: String,
    pub dest_path: String,
}

/// Control-API requests. Serialized as `{ "method": "...", "params": {...} }`
/// (JSON-RPC-shaped; the id/jsonrpc envelope is added by the transport layer).
///
/// Each param-carrying variant wraps its named `*Params` struct — the ONE wire truth for that
/// method's params, shared by clients (which serialize whole `Request`s) and the daemon (which
/// deserializes `params` into the same struct after its method-string dispatch). Adjacent
/// tagging serializes a newtype variant's content as the struct's fields, so the wire shape is
/// identical to inline variant bodies.
///
/// **Servers dispatch on the `method` string and deserialize `params` per-method** — tolerating
/// omitted / null / empty-object params for parameterless methods — rather than deserializing a
/// whole message into `Request` (adjacent tagging rejects `params:{}` for unit variants).
/// This keeps the wire tolerant for third-party clients (the versioned, additive-only surface).
/// Use [`method_of`] to extract the tag, then match + deserialize `params` per-method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    /// Register/update a `[services.*]` entry idempotently.
    RegisterService(RegisterServiceParams),
    Status,
    /// Mint a one-time pairing invite granting `services`. The daemon
    /// answers an [`InviteResult`] carrying the copyable `mcpmesh-invite:` line. Tag
    /// `"invite"` (snake_case). `method_of` needs no per-variant arm — it reads the
    /// `method` string generically; the tag comes from `rename_all`.
    Invite(InviteParams),
    /// Redeem a pairing invite. The daemon dials the inviter named by
    /// `invite_line` on `mcpmesh/pair/1`, proves the secret, writes the mutual
    /// (dial-back) `PeerEntry`, and answers a [`PairResult`]. Tag `"pair"`
    /// (snake_case); `method_of` reads the `method` string generically.
    ///
    /// `PeerEntry` — the durable allowlist row — lives in the daemon crate.
    Pair(PairParams),
    /// Remove a paired peer by nickname (`mcpmesh pair --remove`). The daemon drops the
    /// peer's `PeerEntry` (identity) AND revokes its access by stripping its stable principals from every
    /// `[services.*].allow` (authorization) — the inverse of the pairing grant. Idempotent: a
    /// nickname with no entry / no allow membership is a clean no-op. Live in-flight sessions are
    /// NOT severed here: existing sessions run to completion; the peer only loses the
    /// ability to establish NEW authorized sessions. Tag `"peer_remove"` (snake_case);
    /// `method_of` reads the `method` string generically (no per-variant arm).
    ///
    /// `PeerEntry` — the durable allowlist row — lives in the daemon crate.
    PeerRemove(PeerRemoveParams),
    /// Rename a contact's nickname (nickname) authoritatively. Renames the
    /// PERSON — every `PeerEntry` sharing `user_id` when given (one op for all their devices), else the
    /// single `nickname` entry (a provisional, no-`user_id` contact) — to `to`, AND rewrites the old
    /// nickname → `to` in every `[services.*].allow` so grants follow the rename. Refuses (error frame)
    /// when `to` is empty or already names/grants a DIFFERENT identity — the same collision guard the
    /// pairing rendezvous uses, so a rename can't inherit another peer's access. Tag `"peer_rename"`;
    /// host-privileged like the other pair ops.
    PeerRename(PeerRenameParams),
    /// RESERVED / INTERNAL (`docs/local-protocol.md` "Reserved / internal methods"): install a
    /// peer directly from a raw `endpoint_id` — the trust-population stand-in for pairing behind
    /// `mcpmesh internal peer add`. A deliberate, documented exception to the surface discipline
    /// (raw endpoint identifiers otherwise never cross this socket); NOT part of the stable
    /// vocabulary — do not build on it. Tag `"peer_add"`.
    PeerAdd(PeerAddParams),
    /// Open a mesh session to `peer/service`; the daemon dials and pipes.
    /// Distinct from the proxy's job: this returns a session the client streams.
    /// Named `open_session` rather than `connect` to avoid colliding
    /// with the `connect` porcelain.
    OpenSession(OpenSessionParams),
    /// Install a signed roster from a local file (the manual `internal roster install` path).
    /// `path` is a LOCAL file the same-uid daemon reads (the daemon runs as the caller's own
    /// uid, so passing a path rather than the bytes crosses no trust boundary). `org_root_pk`
    /// pins the org root on FIRST install (`b64u:`); omit it
    /// once pinned (config carries it). Tag `"roster_install"`.
    RosterInstall(RosterInstallParams),
    /// Pin the org root on a JOINER — WITHOUT a roster (the joiner has none yet; its poll loop
    /// fetches the first one). Records `[identity]` org_id / org_root_pk / user_id / user_key.
    /// `user_key` is a LOCAL path
    /// (the key never crosses the API). Tag `"org_join"`.
    OrgJoin(OrgJoinParams),
    /// Pin the HTTPS roster URL (`[roster].url`) in config. Written by `org create
    /// --roster-url` (the operator keeps it current) AND by `join` when the org invite carries one —
    /// so the joiner's poll loop bootstraps its FIRST roster. The daemon writes it under
    /// `reload_lock` (single-writer), then the poll loop picks it up on the next daemon start. Tag
    /// `"set_roster_url"`.
    SetRosterUrl(SetRosterUrlParams),
    /// Rename this node LIVE (#37): validate + upsert `[identity].nickname` through the
    /// daemon's own serialized config-write path (no lost-update window against a
    /// concurrent grant/registration) and update the in-memory name future invites
    /// present — no restart. Ack result. Tag `"set_nickname"` (snake_case).
    SetNickname(SetNicknameParams),
    /// Set this node's opaque app-metadata blob (#39): validated (≤256B) and folded, signed,
    /// into each outgoing presence heartbeat, so paired roster peers see it in their `status`
    /// presence — no per-peer session. Ack result. Tag `"set_app_metadata"`. In-memory (lost
    /// on restart; the embedder re-sets on startup).
    SetAppMetadata(SetAppMetadataParams),
    /// Set this node's CUSTOM relay set LIVE (#53): validate each URL as an iroh `RelayUrl`, diff
    /// against the running endpoint's current custom relays and apply the delta via iroh 1.0.3
    /// `Endpoint::insert_relay`/`remove_relay` (no endpoint rebuild, no dropped sessions), then
    /// persist `[network] relay_mode="custom" relay_urls=[…]` under `reload_lock`. When the node
    /// is currently `default`/`disabled`, the config is persisted but the live mode transition
    /// isn't possible — [`SetRelaysResult::restart_required`] is `true`. Answers a
    /// [`SetRelaysResult`]. Tag `"set_relays"`.
    SetRelays(SetRelaysParams),
    /// Grant a single stable principal access to a single service's allow (#44) — the per-peer
    /// "sharing on" toggle, idempotent + serialized under the config lock. Ack result.
    /// Remove a service registration (#50) — the deregistration mirror of `register_service`.
    /// Removes the whole `[services.<name>]` entry (allow included) + any ephemeral one, then
    /// hot-reloads. Idempotent. Ack result.
    UnregisterService(UnregisterServiceParams),
    /// Discover which services a paired peer CURRENTLY grants the caller (#52) — dials the peer
    /// and returns the service names whose allow admits the caller's principal. Answers
    /// [`PeerServicesResult`].
    PeerServices(PeerServicesParams),
    ServiceAllowGrant(ServiceAllowParams),
    /// Revoke a single stable principal from a single service's allow (#44) — "sharing off"
    /// WITHOUT unpairing (the peer's identity row is untouched; only NEW sessions are refused).
    /// Idempotent. Ack result.
    ServiceAllowRevoke(ServiceAllowParams),
    /// Publish a LOCAL file INTO a scope: the daemon adds the bytes to its gated
    /// app-blob store and records the hash in `scope`. `path` is a local file the same-uid daemon
    /// reads. Answers a [`BlobPublishResult`] carrying the `mcpmesh/blob/1` ticket + hash.
    /// Tag `"blob_publish"`.
    BlobPublish(BlobPublishParams),
    /// Grant a scope to a principal — any flat-namespace entry: a group name, a user_id, or a
    /// nickname (the shared `principal_set` expansion). Tag
    /// `"blob_grant"`.
    BlobGrant(BlobGrantParams),
    /// Tag `"blob_revoke"`: withdraw principals from ONE scope's grants (#62).
    BlobRevoke(BlobRevokeParams),
    /// Tag `"blob_unpublish"`: remove a hash from ONE scope (#62). Withdraws reachability, not
    /// bytes.
    BlobUnpublish(BlobUnpublishParams),
    /// #83: make a blob this daemon already holds servable from HERE, in a scope it controls.
    /// Answers a [`BlobPublishResult`] — same shape as `blob_publish`, so a client can treat the
    /// two interchangeably after a fetch.
    BlobRepublish(BlobRepublishParams),
    /// List the daemon's blob scopes (name → hashes + grants). Tag `"blob_list"`.
    BlobList(BlobListParams),
    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (BLAKE3-verified streaming) and export the
    /// verified blob to `dest_path` (a local file the same-uid daemon writes). Answers a
    /// [`BlobFetchResult`] with the verified hash + byte length. Tag `"blob_fetch"`.
    BlobFetch(BlobFetchParams),
    /// Summarize this node's LOCAL audit log into per-peer / per-service SESSION counts
    /// (local-only — the daemon reads its OWN audit dir, nothing is transmitted). The host Mesh surface
    /// renders these as "who serves me / whom I serve / session counts". Parameterless (like `Status`);
    /// the server dispatches on the `method` string. Tag `"audit_summary"` (snake_case);
    /// `method_of` reads the `method` string generically (no per-variant arm).
    AuditSummary,
    /// Delete audit months strictly older than `before` (#88) — the retention lever the log
    /// never had. Local-only and owner-only (the control socket is the daemon owner's). Answers
    /// [`AuditPruneResult`]. Tag `"audit_prune"`.
    AuditPrune(AuditPruneParams),
    /// Read this node's LOCAL audit records, filtered and paged (#88) — the "show me everything
    /// you hold about me" verb. Local-only; nothing is transmitted. Answers
    /// [`AuditListResult`]. Tag `"audit_list"`.
    AuditList(AuditListParams),
    /// Open a live event stream (pairing liveness & health telemetry). Like `open_session`, the
    /// connection STOPS being request/response after this call and becomes a one-way push stream
    /// of `StreamFrame`s. Parameterless. Tag `"subscribe"`.
    Subscribe,
}

/// Result of [`Request::OrgJoin`] — the pinned org id echoed back (surface-clean; the fingerprint is
/// computed porcelain-side from the invite's org_root_pk). Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgJoinResult {
    pub org_id: String,
}

/// Result of a [`Request::RosterInstall`] request (the manual install path): the installed roster's
/// org id + serial (roster-status vocabulary the confirmation line is permitted to render) plus how
/// many live sessions the install severed. Surface-clean: NO keys / EndpointIds / paths.
///
/// Additive-only: any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterInstallResult {
    pub org_id: String,
    pub serial: u64,
    /// How many live sessions were severed, for the porcelain's confirmation line.
    #[serde(default)]
    pub severed: u32,
}

/// Result of [`Request::BlobPublish`]: the copyable `mcpmesh/blob/1` ticket + the blob's blake3 hash.
/// A ticket/hash here is blob-reference vocabulary (NOT a transport-vocab leak — the same
/// carve-out as the pairing invite line). Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobPublishResult {
    pub ticket: String,
    pub hash: String, // bare blake3 hex
}

/// One scope in a [`BlobScopeList`]: its name + the hashes it contains + the principals it
/// grants. Flat vocabulary ONLY — no EndpointId/pubkey/ALPN. Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeInfo {
    pub name: String,
    pub hashes: Vec<String>,
    pub grants: Vec<String>,
    /// Hashes deliberately WITHDRAWN from this scope (#107): `blob_unpublish` was called, and
    /// `blob_republish` of these into THIS scope is refused with [`ERR_BLOB_WITHDRAWN`]. Cleared
    /// only by a deliberate `blob_publish {scope, path}`. Additive — omitted when empty, so a
    /// pre-`api_minor` 19 client sees exactly what it saw before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withdrawn: Vec<String>,
    /// Size of `hashes` — always present, even when `counts_only` empties the vector (#84b).
    #[serde(default)]
    pub hash_count: usize,
    /// Size of `grants`.
    #[serde(default)]
    pub grant_count: usize,
    /// Size of `withdrawn`.
    #[serde(default)]
    pub withdrawn_count: usize,
}

/// Params of [`Request::BlobList`] (#84b). ALL optional — `blob_list {}` still works, which
/// matters because the verb took no params before `api_minor` 20.
///
/// A DEFAULT LIMIT applies when `limit` is absent. Deliberate: unpaged, `blob_list` renders every
/// scope into one frame against the 16 MiB cap; past it the CLIENT rejects the frame as malformed.
/// The control surface carries no strike bound, so the connection survives — but the caller gets an
/// opaque failure with no way to page, which is unusable rather than merely large.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlobListParams {
    /// EXACT scope name, never a prefix.
    pub scope: Option<String>,
    /// Only scopes containing this hash; the rendering you send is normalized first.
    pub hash: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    /// Omit `hashes`/`grants`/`withdrawn`, keep the counts.
    pub counts_only: bool,
}

/// Result of [`Request::BlobList`]: the daemon's scopes. Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobScopeList {
    pub scopes: Vec<ScopeInfo>,
    /// Scopes matching the filter BEFORE `limit`/`offset` (#84b). Without this you cannot tell a
    /// complete answer from a clipped one.
    #[serde(default)]
    pub total: usize,
    /// True when more scopes matched than were returned. Page with `offset` to see the rest.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
}

/// Result of [`Request::BlobFetch`]: the verified hash + byte length written to `dest_path`.
/// Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFetchResult {
    pub hash: String,
    pub bytes_len: u64,
}

/// Params of [`Request::AuditPrune`] (#88): delete monthly audit files STRICTLY older than
/// `before` (that month itself is kept — delete-before, not delete-including). Rejects unknown
/// fields, and the daemon validates the `YYYY-MM` shape up front: a malformed month errors
/// loudly instead of string-comparing to nothing and reporting a clean no-op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPruneParams {
    /// A zero-padded `YYYY-MM` month key.
    pub before: String,
}

/// Result of [`Request::AuditPrune`]: the month keys actually deleted, ascending. Empty when
/// nothing was older than `before` (idempotent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPruneResult {
    pub deleted_months: Vec<String>,
}

/// Params of [`Request::AuditList`] (#88). All filters optional and AND-combined; every field
/// absent lists everything (paged). Rejects unknown fields — a typo'd filter that silently
/// matched everything would let a "what do you hold about X" answer overclaim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditListParams {
    /// Inclusive `YYYY-MM` lower bound — month-file granularity (the rotation unit), so an
    /// out-of-range month is skipped without parsing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Inclusive `YYYY-MM` upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
    /// One of the wire kind strings (`session_open` / `session_close` / `request` /
    /// `blob_fetch` / `trust`). An UNKNOWN string is an error, never silently-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The record's attributed peer nickname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Page size, default 500, clamped to 1000 — a month file can be arbitrarily large and the
    /// response is ONE JSON frame under the transport's frame cap, so the clamp is load-bearing
    /// (the same lesson as `blob_list`'s, minor 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Records to skip (after filtering), for paging.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

/// Result of [`Request::AuditList`]: one page of matching records in chronological order
/// (oldest month first, in-file order within a month), plus the TOTAL match count so a caller
/// can page without a second counting call. `total` counts ALL matches, not the page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditListResult {
    pub records: Vec<AuditRecord>,
    pub total: u64,
}

/// Result of [`Request::AuditSummary`]: LOCAL per-peer / per-service session counts
/// aggregated from this node's OWN audit log — NEVER transmitted (local-only). Surface-clean:
/// peer names are nicknames / user_ids (NEVER EndpointIds), service names are the registered
/// service names (NEVER transport vocabulary). A "session" is one `SessionOpen` record. `per_peer` /
/// `per_service` are sorted ascending by name (deterministic). Tuples mirror kb's
/// `InsightResponse::per_peer_contribution` — `["bob", 2]` on the wire.
///
/// Additive-only: any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummaryResult {
    /// Sessions opened per peer (nickname). A session with no attributed peer is NOT counted here (no
    /// peer to attribute) but IS in `total_sessions`.
    pub per_peer: Vec<(String, u64)>,
    /// Sessions opened per registered service name.
    pub per_service: Vec<(String, u64)>,
    /// Total sessions opened (every `SessionOpen` record, including peer-less ones).
    #[serde(default)]
    pub total_sessions: u64,
}

/// Result of an [`Request::Invite`] request: the copyable `mcpmesh-invite:` artifact
/// (the ONE pairing artifact deliberately carved out of the
/// transport-vocabulary blocklist, so this is NOT a transport-vocab leak) plus its
/// absolute expiry in epoch seconds (≤ now + 24h).
///
/// `invite` returns BEFORE any redemption, so the SAS — which is derived from the redeemer's
/// endpoint id, unknown until they redeem — cannot appear here. The inviter reads its side of
/// the SAS from [`StatusResult::recent_pairings`] once a redemption completes (a `trust`/`pair`
/// frame on the live [`StreamFrame`] stream signals that moment). See the "embedding the pairing
/// ceremony" note in `docs/local-protocol.md` (#35).
///
/// Additive-only: any future field MUST land as `#[serde(default, skip_serializing_if = ...)]`
/// so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResult {
    /// The `mcpmesh-invite:<base32>` line, copied out-of-band to the redeemer.
    pub invite_line: String,
    /// When the invite expires (epoch seconds); the daemon burns it at redemption or expiry.
    pub expires_at_epoch: u64,
}

/// Result of a [`Request::Pair`] request: the inviter's suggested nickname (the
/// redeemer's local name for the new peer) plus the display-only short authentication
/// code (SAS) — a few words the human reads aloud to a second channel to
/// catch a whole-invite forgery / address-swap MITM. The SAS is a pairing-ceremony
/// artifact (like the invite line), NOT a transport-vocabulary leak.
///
/// Additive-only: any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResult {
    /// The inviter's suggested nickname (from the invite) — the redeemer's local name for it.
    pub peer_nickname: String,
    /// The display-only short authentication code (e.g. `"tango-fig-42"`), shown on both
    /// sides for the out-of-band human check. Never sent on the wire, never checked
    /// programmatically.
    pub sas_code: String,
    /// The services this pairing granted the redeemer — each mountable as `<peer>/<service>`.
    /// Populated from the invite (`invite.services`) by the redeemer-side `redeem_invite`, so
    /// the porcelain can print the "You can mount: alice/notes" line without re-decoding the
    /// invite. Additive: `#[serde(default, skip_serializing_if = ...)]` so a `PairResult`
    /// minted by an older daemon (which omits `services`) still deserializes — to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    /// The opaque `app_label` the inviter attached at `invite` time (#31), echoed verbatim — or
    /// absent if none was set. mcpmesh never interprets it; the embedder does. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_label: Option<String>,
    /// The inviter's proven self-sovereign `user_id` (`b64u:<user_pk>`), when it presented a
    /// device→user binding at pairing (#30). This is the STABLE, portable identity the redeemer
    /// can align with its own — and the same value it may later pass to `open_session` to dial
    /// this peer by identity rather than by local nickname. `None` if the inviter presented no
    /// binding (a legacy/keyless peer). Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_user_id: Option<String>,
}

/// The event class of an [`AuditRecord`] (the four audit event classes). An additive discriminant on
/// top of the base record schema: it removes no field and makes the JSONL self-describing so
/// a consumer can filter by class without guessing from which optional fields are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A mesh session opened (a backend was selected for an authenticated peer).
    /// (A `session_open` with `status:"error"` is a synthesized FAILED-dial marker — no backend
    /// was reached; it records an attempted-and-failed reach for the telemetry stream.)
    SessionOpen,
    /// A mesh session closed (the backend returned / the session tore down).
    SessionClose,
    /// One proxied MCP request line (method + tool NAME + args_hash). NEVER carries raw arguments.
    Request,
    /// A peer fetched a blob from this node's gated provider (peer + hash + allow/deny).
    BlobFetch,
    /// A trust mutation (pair, unpair, roster install/swap, revoke).
    Trust,
}

/// One audit record — the union of the event classes, and the `record` payload of a
/// [`StreamFrame::Event`]. ONE schema for the on-disk JSONL log and the live stream. Every field
/// beyond `ts`/`kind` is optional and elided when absent (`skip_serializing_if`), so each class
/// serializes to just its relevant keys (a session record has no `method`; a trust record has no
/// `bytes_out`).
///
/// PRIVACY: the proxied-request record carries `method` + `tool` (NAME only) +
/// `args_hash` (`"blake3:<hex>"`), and NEVER the raw arguments, the request/response content, or
/// any tool-output bytes — only a `bytes_out` COUNT and a `status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC3339 UTC with millisecond precision, e.g. `"2026-07-03T14:02:11.480Z"`. The `YYYY-MM`
    /// prefix also selects the monthly file (the rotation boundary), so it is always present.
    pub ts: String,
    pub kind: AuditKind,
    /// The gate-resolved authenticated peer (attributed by the endpoint_id-keyed trust gate). Absent on
    /// local-only events with no remote peer (a manual roster install).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The tool NAME only (never its arguments or output) — e.g. `"read_file"` for a `tools/call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// `"blake3:<hex>"` of the request arguments. The raw arguments are NEVER stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_hash: Option<String>,
    /// Byte COUNT of the response sent back to the peer — a count, never the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    /// `"ok"` / `"error"` (proxied request) or `"ok"` / `"denied"` (blob fetch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// Trust-event verb: `"pair"` / `"unpair"` / `"roster_install"` / `"revoke"` (kind == Trust).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    /// A reference, NEVER content: a blob hash (`BlobFetch`) or a trust-event target such as a
    /// nickname or `org/serial` (`Trust`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The subject's STABLE principal, from the same gate resolution that produced `peer`
    /// (#57, `api_minor >= 29`). `peer` is a display name and collides — two devices under one
    /// nickname were indistinguishable in the stream and the on-disk log. Same argument and
    /// shape as `PeerInfo` (#41), `PeerReachability` (#42), and `ActiveSession` (#73).
    ///
    /// TWO NAMESPACES, deliberately: session/request/blob records attribute the DEVICE
    /// (`eid:<hex>`, like `ActiveSession` — the exact authenticated endpoint), while the trust
    /// `pair` record carries the value the grant appended to the allow (`b64u:<pk>` when the
    /// device presented a user binding, else `eid:`, #38). Joining a bound peer's sessions to
    /// its allow entry therefore goes through the `status` peers list (which carries BOTH the
    /// device principal and the `user_id`), not string equality on this field alone.
    ///
    /// Deliberately absent on: `unpair` (may tear down several devices — no single subject),
    /// `roster_install` (purely local), and the failed-outbound-dial session record (our own
    /// dial, not a gate-resolved caller). Absent on every record written before 0.24.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

impl AuditRecord {
    fn base(ts: String, kind: AuditKind) -> Self {
        Self {
            ts,
            kind,
            peer: None,
            service: None,
            method: None,
            tool: None,
            args_hash: None,
            bytes_out: None,
            status: None,
            latency_ms: None,
            event: None,
            target: None,
            principal: None,
        }
    }

    /// `principal` is an EXPLICIT parameter on every constructor (#57, kept from the original
    /// #72 design): a builder would let a call site silently omit it and reintroduce the
    /// collapsed-identity bug for that one event class. Pass `None` only for the documented
    /// no-single-subject records (see the field doc).
    pub fn session_open(
        ts: String,
        peer: Option<String>,
        service: String,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionOpen);
        r.peer = peer;
        r.service = Some(service);
        r.principal = principal;
        r
    }

    /// Set the record's `status` (`"ok"`/`"error"`/`"denied"`), returning `self` for chaining.
    /// Marks a synthesized failure record — e.g. the `session_open` for a FAILED dial, which
    /// reaches no backend and so is never audited by the far side's session guard — without a
    /// dedicated constructor. DRY: reuses the existing optional `status` field.
    pub fn with_status(mut self, status: &str) -> Self {
        self.status = Some(status.into());
        self
    }

    pub fn session_close(
        ts: String,
        peer: Option<String>,
        service: String,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionClose);
        r.peer = peer;
        r.service = Some(service);
        r.principal = principal;
        r
    }

    /// A completed (request→response correlated) proxied line: method + tool NAME + args_hash, plus
    /// the response's `bytes_out` COUNT, `status`, and `latency_ms`. PRIVACY: `args_hash` is a digest;
    /// no raw arguments, request/response content, or tool-output bytes are ever passed in.
    #[allow(clippy::too_many_arguments)]
    pub fn proxied_request(
        ts: String,
        peer: Option<String>,
        service: String,
        method: String,
        tool: Option<String>,
        args_hash: String,
        bytes_out: u64,
        status: String,
        latency_ms: u64,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Request);
        r.peer = peer;
        r.service = Some(service);
        r.method = Some(method);
        r.tool = tool;
        r.args_hash = Some(args_hash);
        r.bytes_out = Some(bytes_out);
        r.status = Some(status);
        r.latency_ms = Some(latency_ms);
        r.principal = principal;
        r
    }

    /// A proxied NOTIFICATION line (no `id`, so no response correlates): method + tool + args_hash,
    /// no `bytes_out`/`status`/`latency_ms`. The line is still recorded — every proxied request is audited.
    pub fn proxied_notification(
        ts: String,
        peer: Option<String>,
        service: String,
        method: String,
        tool: Option<String>,
        args_hash: String,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Request);
        r.peer = peer;
        r.service = Some(service);
        r.method = Some(method);
        r.tool = tool;
        r.args_hash = Some(args_hash);
        r.principal = principal;
        r
    }

    pub fn blob_fetch(
        ts: String,
        peer: Option<String>,
        hash: String,
        status: String,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::BlobFetch);
        r.peer = peer;
        r.target = Some(hash);
        r.status = Some(status);
        r.principal = principal;
        r
    }

    pub fn trust(
        ts: String,
        event: String,
        target: Option<String>,
        principal: Option<String>,
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Trust);
        r.event = Some(event);
        r.target = target;
        r.principal = principal;
        r
    }
}

/// One live mesh session, in a [`StreamFrame::Snapshot`]. Surface-clean: `peer` is the
/// user_id-or-nickname the audit records carry, never an endpoint-id. `opened_at` is epoch seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSession {
    pub peer: String,
    pub service: String,
    pub opened_at: i64,
    /// The caller's STABLE device principal, `eid:<hex>` (#73).
    ///
    /// `peer` is a display nickname and collides: two devices under one nickname, or two contacts
    /// sharing a display name, are indistinguishable in the live-session view. So "who is using my
    /// service right now", per-peer session counts, and any UI that lets a user act on a live
    /// session (revoke, disconnect, inspect) were all keyed on a collidable string.
    ///
    /// Same argument and same shape as [`PeerInfo`] (#41) and [`PeerReachability`] (#42).
    /// Nicknames NEVER authorize; this is the value to key on.
    ///
    /// **Snapshot only, for now.** `ActiveSession` appears in [`StreamFrame::Snapshot`] — there is
    /// no `active_sessions` on `StatusResult`. A client that keeps its view current by applying
    /// subsequent `session_open`/`session_close` events still has a collision problem: those are
    /// [`AuditRecord`]s and carry no principal (#57, unmerged). So the snapshot distinguishes two
    /// same-nickname devices and the next `session_close` for that nickname does not say which row
    /// to drop. Re-subscribe for an authoritative view until #57 lands.
    ///
    /// Always present for a real row — `Option` only so an older client round-trips. Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

/// One frame of the [`Request::Subscribe`] stream (pairing liveness & health telemetry). Tagged on
/// `type` (snake_case), so a frame is `{"type":"snapshot",...}` / `{"type":"event",...}` /
/// `{"type":"lagged",...}`. `Event.record` is the [`AuditRecord`] verbatim, so the stream and the
/// on-disk log carry ONE schema. The daemon serializes these; an embedding consumer deserializes
/// them (see `docs/local-protocol.md` "Live event stream").
/// **`#[non_exhaustive]`**: a future frame kind must not break a downstream `match`. Adding
/// `Reachability` in 0.13.0 DID break exhaustive matches — which is why that release is a MINOR,
/// per `RELEASING.md`'s pre-1.0 rule that breaking changes bump the minor. Consumers now write a
/// `_ =>` arm and later additions are additive for Rust as well as for JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum StreamFrame {
    /// The FIRST frame: a point-in-time picture of the mesh (open sessions + paired-peer
    /// reachability) so a fresh subscriber renders immediately without replaying history.
    Snapshot {
        active_sessions: Vec<ActiveSession>,
        reachability: Vec<PeerReachability>,
        /// THIS node's own reachability posture (#90), so a fresh subscriber renders it without
        /// a `status` poll. `None` in mesh-less control-only mode. Additive: default +
        /// skip-if-none so an older payload round-trips.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        self_network: Option<SelfNetwork>,
    },
    /// A live audit event (session open/close, request, blob fetch, trust) — the tap on the hub.
    /// Boxed so this (much larger) variant does not bloat every frame; serde delegates through the
    /// `Box`, so the wire shape is the record's fields verbatim.
    Event { record: Box<AuditRecord> },
    /// A peer's reachability TRANSITIONED (#58): it became reachable, became unreachable, or was
    /// probed for the first time. Pushed so an embedder does not have to poll `status` for a live
    /// online/offline indicator — and so work queued for an unreachable peer can flush the moment
    /// it returns, rather than on the next poll tick.
    ///
    /// Emitted on a change of `reachable` **or of `path`**. A refresh with the same verdict AND the
    /// same path emits nothing, so a peer that stays up does not produce a frame per TTL refresh;
    /// `rtt_ms`/`meta`/`services` drift is advisory detail and is not a transition. `age_secs` is
    /// `0` — the observation just completed.
    ///
    /// **Do not treat this as an up/down toggle.** It carried that meaning through 0.18, and this
    /// doc said "on a CHANGE of `reachable` only" until 1.22 — which stopped being true in 0.19.0
    /// (#92 item 1), when `path` joined the transition rule. A consumer that assumed same-verdict
    /// frames were impossible was reading a stale guarantee.
    ///
    /// Two producers, as of API 1.22 — and since 1.30 `source` says WHICH ONE, so the distinction
    /// is readable rather than inferred:
    ///
    /// - [`ReachabilitySource::Probe`] — a probe completing (`status`/`subscribe` refreshing a
    ///   stale entry). It describes a throwaway dial, not anyone's live connection.
    /// - [`ReachabilitySource::Session`] — a live session whose selected path changed under it
    ///   (#92 item 2). A claim about the link in use.
    ///
    /// The second producer is why `path` is trustworthy for a long-lived session: a session that
    /// degrades Direct→Relay mid-call now says so when it happens, rather than staying silently
    /// mislabelled until something probes. `path` is a truth claim about where user data went, so
    /// `Unknown` means "we do not know" and must never be rendered as private.
    ///
    /// **`rtt_ms` is not a discriminator, and never was** (#150). Until 1.30 this doc said a
    /// session-sourced frame carries `rtt_ms: None` — true only of a FIRST observation, where no
    /// round trip was measured and none is invented. A session-sourced frame for an
    /// already-probed peer carries that probe's `rtt_ms: Some(..)`, because the path watcher
    /// deliberately leaves `rtt_ms`/`meta`/`probed_at` alone (refreshing them would stamp a stale
    /// RTT as fresh and suppress the corrective probe — #92 review). That is the common case for a
    /// peer probed at pairing time and then watched through a long call. Read `source`.
    Reachability {
        peer: PeerReachability,
        /// Which producer emitted this frame (#150). `api_minor >= 30`.
        ///
        /// Additive: `#[serde(default)]`, landing on [`ReachabilitySource::Unknown`] — NOT on
        /// `Probe`. A daemon at `api_minor` 22–29 already has both producers, so an absent field
        /// genuinely does not say which one ran; defaulting to `Probe` would assert the wrong
        /// producer for every session-sourced frame such a daemon emits, which is the exact
        /// ambiguity this field exists to remove.
        #[serde(default)]
        source: ReachabilitySource,
    },
    /// THIS node's own network posture CHANGED (#90): `online` flipped, the home relay moved,
    /// or a relay's connection state changed — pushed so an embedder learns "you just went
    /// unreachable" the moment it happens instead of on a poll tick, and so #53's `set_relays`
    /// finally has a signal telling someone to use it. `direct_addrs` drift alone does not
    /// emit (address churn is chatty and not a decision point; it rides the next frame).
    /// `api_minor >= 28`.
    SelfNetwork { self_network: SelfNetwork },
    /// The subscriber fell `dropped` records behind the broadcast ring; the stream continues (a
    /// fresh reconnect would re-`Snapshot`). Never drops the subscriber — lag is reported, never fatal.
    Lagged { dropped: u64 },
}

/// Extract the `method` tag from a raw request value without deserializing the whole
/// message. The daemon's dispatcher uses this: match on the method string, then deserialize
/// `params` per-method — which tolerates omitted / null / `{}` params for parameterless
/// methods (adjacent tagging rejects `params:{}` on unit variants).
pub fn method_of(v: &serde_json::Value) -> Option<&str> {
    v.get("method").and_then(serde_json::Value::as_str)
}

/// How a service is answered. Mirrors the config `[services.*]` *kinds*;
/// Config→BackendSpec is a hand-written match, not a serde passthrough.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendSpec {
    Run {
        cmd: Vec<String>,
        /// Per-service environment variables (#51) for the spawned child. Overlaid on the
        /// daemon's inherited env; the injected `MCPMESH_PEER_*` identity vars ALWAYS win over
        /// these (identity is not spoofable by a service definition). Default empty.
        #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
        env: BTreeMap<String, String>,
        /// Working directory to spawn the child in (#51). Default: inherit the daemon's cwd.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
    },
    Socket {
        path: String,
    },
}

/// Control-API error code: the named service exists in neither `config.toml` nor the ephemeral
/// registry (#55). Distinct from the generic `-32000` so a caller can BRANCH on "no such service"
/// instead of parsing a message — `service_allow_grant`/`service_allow_revoke` previously answered
/// `{}` (success) for an unknown name, which silently included every ephemeral service.
pub const ERR_NO_SUCH_SERVICE: i64 = -32040;
/// The named blob is not held COMPLETE by this daemon (#83, `blob_republish`). Distinct from
/// [`ERR_NO_SUCH_SERVICE`] because the remedy differs: fetch the blob first.
pub const ERR_NO_SUCH_BLOB: i64 = -32041;
/// The blob was deliberately withdrawn from this scope (#107). Distinct from
/// [`ERR_NO_SUCH_BLOB`]: that means "fetch it first", this means "someone un-shared this on
/// purpose — `blob_publish` from the file if the re-share is intended".
pub const ERR_BLOB_WITHDRAWN: i64 = -32042;
/// `pair` was refused because the redeemer's nickname is already held by a DIFFERENT paired peer
/// (#87), so an embedder can branch on the one refusal that has a self-service remedy — rename and
/// redeem the same invite again — without reading the prose (#147).
///
/// Reading the prose was the only option before this code, and it does not survive translation: the
/// message is generated on the INVITER's side and travels to the redeemer, so the embedder that
/// DISPLAYS it cannot rewrite it into its own vocabulary except by substring-matching our copy.
/// Branch on this and write your own sentence naming your own rename affordance.
///
/// Deliberately narrow. It rides ONLY this refusal, which is sent exclusively to a caller that
/// proved possession of a live invite secret. The generic refusal keeps `-32000` and its opaque
/// reason: distinguishing unknown-vs-expired-vs-wrong-secret would be a redemption oracle.
pub const ERR_NICKNAME_TAKEN: i64 = -32043;

pub const API_NAME: &str = "mcpmesh-local/1";
/// The protocol-compatibility version as `"MAJOR.MINOR"`, distinct from the crate/stack version.
///
/// - **MAJOR** matches the `/N` in [`API_NAME`] and changes only on a breaking wire change (the
///   transport already rejects a mismatched `api`, so an equality check on that is redundant).
/// - **MINOR** ([`API_MINOR`]) increments on a surface change within a major — additive fields, new
///   methods, or a strictness change like params validation — bumped in the same change that makes
///   it. A client can guard with `api_minor >= N` for a feature it needs, or refuse a daemon older
///   than a minor it requires. It never resets except on a MAJOR bump.
///
///   It also bumps for a change to what a field MEANS with no change to its shape — six of the
///   thirty have, see [`API_MINOR`]'s history. "Every surface change" is what this line used
///   to claim, and it was wrong in both directions: minor 9's entry records surface changes that
///   shipped WITHOUT a bump, and six bumps changed no type at all. Read the history, not the rule.
pub const API_VERSION: &str = "1.31";
/// The integer MINOR of [`API_VERSION`] — see there. Bumped from 0 to 1 when params validation
/// became strict (#34); to 2 with the `set_nickname` verb + `StatusResult.self_nickname` (#37);
/// to 3 when `allow`/grant strings became STABLE principals — `b64u:`/`eid:`/roster names,
/// never nicknames (#38); to 4 with the `set_app_metadata` verb + `PresencePeer.meta` (#39);
/// to 5 with `PeerReachability.meta` — pairing-mode app metadata on the probe pong (#40);
/// to 6 with `PeerInfo.principal` — the peer's eid: device principal on `status` (#41);
/// to 7 with `PeerReachability.principal` — the same on reachability rows (#42); to 8 with the
/// `service_allow_grant`/`service_allow_revoke` per-peer access verbs (#44); to 9 covering the
/// `unregister_service` (#50) / `peer_services` (#52) / Run `env`+`cwd` (#51) surface that shipped
/// in 0.10.1 without a bump, PLUS the `set_relays` live relay-set verb (#53); to 10 when
/// `service_allow_revoke`/`peer_remove` became IMMEDIATE — no verb shape changed, but their
/// observable contract did: a revoked principal's next session is refused even on a connection it
/// already holds, and its live connections are severed. Previously both waited for the peer to
/// disconnect on its own, which is unbounded (#54). A consumer can guard on
/// `api_minor >= 10` before telling a user that revocation has taken effect; to 11 when
/// `service_allow_grant`/`service_allow_revoke` gained EPHEMERAL-service support and became strict
/// about an unknown service name — a name in neither the config nor the ephemeral registry now
/// answers [`ERR_NO_SUCH_SERVICE`] instead of a silent `{}` (#55, #69); to 12 with the pushed
/// [`StreamFrame::Reachability`] liveness transition frame (#58); to 13 with
/// [`PeerReachability::path`] — direct-vs-relay attribution on every reachability row (#64); to 14
/// with the `run`-backend `MCPMESH_PEER_EID` identity var — the caller's stable device principal,
/// unconditionally present, so a `run` server can scope per caller without keying on a nickname
/// (#60); to 15 with the `blob_revoke` / `blob_unpublish` verbs — per-scope withdrawal of a grant
/// and of a published hash, so un-sharing a file no longer requires unpairing the person (#62); to
/// 16 when the app-blob provider became available in PAIRING mode — the blob verbs previously
/// errored on any daemon without an org root key, though their scope gate never needed one (#61);
/// to 17 when the service answer began coming from the LIVE registry rather than config + overlay,
/// so a grant the accept path would refuse is no longer advertised. Three surfaces share that
/// resolver and all changed together: `status`'s `services[].allow`, `peer_services`' name list,
/// and the `mcpmesh/ping/1` probe's `services`. No wire shape changed, only the source of truth —
/// exactly the class of change a downstream cannot see in a type diff (#100); to 18 with `blob_republish`, so a fetched blob can
/// be re-served and every recipient becomes a source (#83); to 19 with durable blob revocation — an
/// unpublish now survives a later republish via a per-scope withdrawal set, and
/// [`ERR_BLOB_WITHDRAWN`] distinguishes "deliberately withdrawn" from "never had it" (#107); to 20
/// with `blob_list` filters + paging AND a DEFAULT limit of 256 scopes (the clamp is 4096) — a
/// daemon with more scopes than that previously answered with
/// everything, and past the 16 MiB frame cap the CLIENT rejected the response as malformed, leaving
/// the caller an opaque failure with no way to page. The connection survived: the control surface
/// carries no strike bound. This is a behaviour change for existing callers, detectable via the new
/// `total`/`truncated` (#84b); to 21 when a
/// PATH change became a reachability transition — [`StreamFrame::Reachability`] stopped being an
/// up/down toggle and same-verdict frames became possible (#92); to 22 with a SECOND producer for
/// that frame: a live per-session watcher that pushes when a session's selected path changes,
/// rather than waiting for a probe, at a cadence probes never had (#92); to 23 when
/// [`PeerReachability::rtt_ms`] stopped including the path-settle window — a relayed peer could
/// previously never report under 600ms, so "relayed AND fast" was unreachable by construction
/// (#123); to 24 when `reachable` stopped sharing a deadline with path classification — a relayed
/// peer whose pong arrived after ~2.4s was reported OFFLINE while it was answering (#128); to 25
/// with [`ActiveSession::principal`] — the live-session view was keyed on a display nickname, so
/// two devices under one nickname were indistinguishable and any UI acting on a session (revoke,
/// disconnect, inspect) keyed on a collidable string (#73); to 26 when a
/// rate-limited inbound NOTIFICATION stopped being silently dropped and became a recorded audit
/// event — no type changed; the observable audit stream did (#76, #139); to 27 with the `audit_prune` /
/// `audit_list` verbs, `StatusResult::storage`, and the opt-in `[limits].audit_retain_months`
/// boot retention — the audit log stopped being a permanent, unbounded, unreadable record (#88);
/// to 28 with `StatusResult::self_network` / `StreamFrame::SelfNetwork` / the snapshot's copy —
/// the node's OWN reachability posture, previously unanswerable from either side of the API
/// (#90); to 29 with [`AuditRecord::principal`] — stable identity on the event stream and the
/// on-disk log, resolving #57's parked docs conflict in favour of the #41/#42/#73 line (the
/// audit surface bans secrets and raw hex, not the prefixed principal rendering); to 30 with
/// [`StreamFrame::Reachability`]'s `source` — the frame has had TWO producers since 22 with no way
/// to tell them apart, so an embedder could not distinguish "a throwaway dial went via a relay"
/// from "the link this call is on just degraded", and had to hedge every message down to the
/// weaker claim. `rtt_ms: None` was never the discriminator the doc implied (#150); to 31 with
/// [`ERR_NICKNAME_TAKEN`] — the nickname-collision `pair` refusal is branchable instead of
/// `-32000`, so an embedder writes its own recovery copy rather than substring-matching ours. The
/// prose changed with it: it named the `set_nickname` CONTROL VERB as the remedy, which a GUI user
/// cannot type, and the refusal is generated inviter-side so the embedder displaying it could not
/// rewrite it (#147).
///
/// **Not every semantic change gets a minor, and that is the gap to watch (#122).** A minor marks a
/// change to this *surface*. A change to behaviour BEHIND the surface — same fields, same shapes,
/// different meaning — may not bump it, and is invisible to a type diff. 17 and 24 above happen to
/// be that class and did bump; do not infer from them that every such change will. When bumping
/// several minors at once, read this block end to end AND the release notes, not the diff.
///
/// That class is bigger than it looks: **10, 17, 21, 22, 23 and 24 all shipped with no change to
/// any type in this file** — they moved meaning, not shape. Six of the thirty. A downstream
/// that diffs types across a multi-minor bump sees nothing for any of them.
pub const API_MINOR: u32 = 31;

#[cfg(test)]
mod tests {
    use super::*;

    /// #64: the path field's wire shape, and its ADDITIVE default. A row from an older daemon has
    /// no `path` key at all and must land on `Unknown` — never on `Direct`, which would invent a
    /// privacy guarantee that daemon never made.
    #[test]
    fn peer_path_tags_and_defaults_to_unknown() {
        let tagged = |p: PeerPath| serde_json::to_value(p).unwrap();
        assert_eq!(tagged(PeerPath::Direct)["kind"], "direct");
        assert_eq!(tagged(PeerPath::Unknown)["kind"], "unknown");
        let relay = tagged(PeerPath::Relay {
            url: Some("https://relay.example/".into()),
        });
        assert_eq!(relay["kind"], "relay");
        assert_eq!(relay["url"], "https://relay.example/");
        // A relay whose URL we do not know still tags as relay, with the key elided.
        let bare = tagged(PeerPath::Relay { url: None });
        assert_eq!(bare["kind"], "relay");
        assert!(bare.get("url").is_none(), "elided, not null: {bare}");

        // #64 review: a path kind from a NEWER daemon must degrade to Unknown, not fail the whole
        // row. Without `#[serde(other)]` an unknown `kind` errors out of
        // `PeerReachability` entirely, so one new variant would break every `status` read an
        // older pinned client does.
        let future: PeerPath =
            serde_json::from_value(serde_json::json!({"kind": "quantum", "id": "x"})).unwrap();
        assert_eq!(future, PeerPath::Unknown);
        let row: PeerReachability = serde_json::from_value(serde_json::json!({
            "name": "bob", "reachable": true, "path": {"kind": "quantum"}
        }))
        .expect("an unknown path kind must not fail the whole row");
        assert_eq!(row.path, PeerPath::Unknown);
        assert!(row.reachable, "the rest of the row survives");

        // A pre-#64 row: no `path` key.
        let old = serde_json::json!({"name": "bob", "reachable": true});
        let parsed: PeerReachability = serde_json::from_value(old).unwrap();
        assert_eq!(
            parsed.path,
            PeerPath::Unknown,
            "an older daemon's row must never imply a direct path"
        );
    }

    /// #58: the pushed liveness frame tags as `{"type":"reachability","peer":{…}}` and carries a
    /// whole `PeerReachability` row — the SAME shape the opening snapshot's list holds, so a
    /// consumer projects both through one code path.
    #[test]
    fn reachability_frame_tags_and_round_trips() {
        let frame = StreamFrame::Reachability {
            peer: PeerReachability {
                name: "bob".into(),
                reachable: true,
                rtt_ms: Some(12),
                age_secs: Some(0),
                meta: String::new(),
                principal: Some("eid:beef".into()),
                path: Default::default(),
            },
            source: ReachabilitySource::Probe,
        };
        let v = serde_json::to_value(&frame).unwrap();
        assert_eq!(v["type"], "reachability");
        assert_eq!(v["peer"]["name"], "bob");
        assert_eq!(v["peer"]["reachable"], true);
        assert_eq!(
            v["peer"]["age_secs"], 0,
            "a transition frame is fresh by construction: {v}"
        );
        assert_eq!(v["source"], "probe", "#150: the producer is named: {v}");
        let back: StreamFrame = serde_json::from_value(v).unwrap();
        assert_eq!(back, frame);
    }

    /// #150: the frame's `source` wire shape, and the two ways it must degrade.
    ///
    /// The default is the load-bearing part. An absent key comes from a daemon at `api_minor`
    /// 22–29, which ALREADY has both producers — so it must land on `Unknown`, never on `Probe`.
    /// Defaulting to `Probe` would tell a consumer "a throwaway dial saw this" about frames that
    /// were a live session degrading, which is the ambiguity the field exists to remove.
    #[test]
    fn reachability_source_tags_and_defaults_to_unknown() {
        let tagged = |s: ReachabilitySource| serde_json::to_value(s).unwrap();
        assert_eq!(tagged(ReachabilitySource::Probe), "probe");
        assert_eq!(tagged(ReachabilitySource::Session), "session");
        assert_eq!(tagged(ReachabilitySource::Unknown), "unknown");
        for s in [
            ReachabilitySource::Probe,
            ReachabilitySource::Session,
            ReachabilitySource::Unknown,
        ] {
            let back: ReachabilitySource = serde_json::from_value(tagged(s)).unwrap();
            assert_eq!(back, s, "round trip");
        }

        let peer = serde_json::json!({"name": "bob", "reachable": true});

        // A pre-#150 frame: no `source` key at all.
        let old: StreamFrame =
            serde_json::from_value(serde_json::json!({"type": "reachability", "peer": peer}))
                .expect("an older daemon's frame must still parse");
        let StreamFrame::Reachability { source, .. } = old else {
            panic!("expected a reachability frame");
        };
        assert_eq!(
            source,
            ReachabilitySource::Unknown,
            "an api_minor 22-29 daemon has BOTH producers, so an absent key must not claim Probe"
        );

        // A producer from a NEWER daemon must degrade to Unknown, not fail the whole frame — the
        // same stake `PeerPath` buys with `#[serde(other)]`. Without the hand-written Deserialize
        // a third producer would break every Reachability frame an older pinned client reads.
        let future: StreamFrame = serde_json::from_value(
            serde_json::json!({"type": "reachability", "peer": peer, "source": "telemetry"}),
        )
        .expect("an unknown producer must not fail the whole frame");
        let StreamFrame::Reachability { source, peer } = future else {
            panic!("expected a reachability frame");
        };
        assert_eq!(source, ReachabilitySource::Unknown);
        assert!(peer.reachable, "the rest of the frame survives");
    }

    /// #150 gate: "an unrecognized value reads as `unknown`" must hold for any VALUE, not just an
    /// unrecognized string.
    ///
    /// `#[serde(default)]` covers an absent key and nothing else, so `"source": null` — what a
    /// proxy or non-Rust daemon that normalizes optional fields produces — went through the
    /// deserializer and failed the WHOLE frame, silently dropping a liveness transition while the
    /// protocol doc promised the field could not break a parse. The container shapes matter
    /// separately: a visitor that answers without draining a map/seq desynchronizes the parser and
    /// fails the frame anyway, which looks identical from outside.
    #[test]
    fn a_malformed_source_degrades_instead_of_failing_the_frame() {
        let peer = serde_json::json!({"name": "bob", "reachable": true});
        for bad in [
            serde_json::Value::Null,
            serde_json::json!(7),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!(true),
            serde_json::json!({"kind": "probe", "nested": {"deep": [1, 2]}}),
            serde_json::json!(["probe", "session"]),
        ] {
            let frame: StreamFrame = serde_json::from_value(
                serde_json::json!({"type": "reachability", "peer": peer, "source": bad}),
            )
            .unwrap_or_else(|e| panic!("`source: {bad}` must not fail the whole frame: {e}"));
            let StreamFrame::Reachability { source, peer } = frame else {
                panic!("expected a reachability frame");
            };
            assert_eq!(source, ReachabilitySource::Unknown, "for source: {bad}");
            assert!(peer.reachable, "the rest of the frame survives: {bad}");
        }
    }

    /// #90: the self-network frame tags as `{"type":"self_network","self_network":{…}}` — the
    /// SAME block `status` and the snapshot carry. Pinned explicitly (like the reachability
    /// tag) so a variant rename cannot slip past a suite whose two ends share the type while
    /// breaking every doc-following third-party client.
    #[test]
    fn self_network_frame_tags_and_round_trips() {
        let frame = StreamFrame::SelfNetwork {
            self_network: SelfNetwork {
                online: true,
                home_relay: Some("https://relay.example:443".into()),
                relays: vec![RelayInfo {
                    url: "https://relay.example:443".into(),
                    connected: true,
                }],
                direct_addrs: vec!["192.168.1.2:4444".into()],
                last_change_epoch: Some(1_753_842_000),
            },
        };
        let v = serde_json::to_value(&frame).unwrap();
        assert_eq!(v["type"], "self_network");
        assert_eq!(v["self_network"]["online"], true);
        assert_eq!(v["self_network"]["home_relay"], "https://relay.example:443");
        assert_eq!(v["self_network"]["relays"][0]["connected"], true);
        let back: StreamFrame = serde_json::from_value(v).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn peer_reachability_serde_is_additive() {
        let r = PeerReachability {
            name: "bob".into(),
            reachable: true,
            rtt_ms: Some(42),
            age_secs: Some(3),
            meta: String::new(),
            principal: None,
            path: Default::default(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["name"], "bob");
        assert_eq!(v["reachable"], true);
        assert_eq!(v["rtt_ms"], 42);
        assert_eq!(v["age_secs"], 3);
        // Never-probed peer: optionals elided, not null.
        let unknown = PeerReachability {
            name: "carol".into(),
            reachable: false,
            rtt_ms: None,
            age_secs: None,
            meta: String::new(),
            principal: None,
            path: Default::default(),
        };
        let uv = serde_json::to_value(&unknown).unwrap();
        assert!(uv.get("rtt_ms").is_none() && uv.get("age_secs").is_none());
        // An older StatusResult (no reachability field) still deserializes.
        let old = serde_json::json!({"stack_version":"0.1.0","services":[],"peers":[]});
        let s: StatusResult = serde_json::from_value(old).unwrap();
        assert!(s.reachability.is_empty());
    }

    #[test]
    fn subscribe_method_tag_resolves() {
        let req = serde_json::to_value(Request::Subscribe).unwrap();
        assert_eq!(method_of(&req), Some("subscribe"));
    }

    // --- #34: params structs reject unknown fields (the `{service: "kb"}` silent-accept bug) ---

    #[test]
    fn invite_params_reject_singular_service_typo() {
        // The reported bug: `{"service":"kb"}` (singular) used to deserialize to
        // InviteParams { services: [] } and mint a grants-nothing invite that looked
        // successful. With deny_unknown_fields the typo is a loud parse error instead.
        let err = serde_json::from_value::<InviteParams>(serde_json::json!({"service": "kb"}));
        assert!(
            err.is_err(),
            "an unknown `service` key must be rejected, not silently ignored"
        );
        // The correct plural shape still parses.
        let ok: InviteParams =
            serde_json::from_value(serde_json::json!({"services": ["kb"]})).unwrap();
        assert_eq!(ok.services, vec!["kb".to_string()]);
    }

    #[test]
    fn open_session_params_reject_unknown_field() {
        let err = serde_json::from_value::<OpenSessionParams>(
            serde_json::json!({"peer": "a", "service": "b", "nonsense": 1}),
        );
        assert!(err.is_err(), "unknown params keys must be rejected");
    }

    #[test]
    fn set_app_metadata_request_carries_the_method_tag() {
        let r = Request::SetAppMetadata(SetAppMetadataParams {
            metadata: "v=1.2.3".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "set_app_metadata");
        assert_eq!(v["params"]["metadata"], "v=1.2.3");
        assert_eq!(method_of(&v), Some("set_app_metadata"));
    }

    #[test]
    fn set_app_metadata_params_reject_unknown_field() {
        let err = serde_json::from_value::<SetAppMetadataParams>(
            serde_json::json!({"metadata": "x", "nonsense": 1}),
        );
        assert!(err.is_err(), "unknown params keys must be rejected");
    }

    /// `PresencePeer.meta` is additive — an older payload (no meta) still deserializes, and an
    /// empty meta does not serialize.
    #[test]
    fn peer_info_principal_is_additive() {
        // An older payload (no principal) still deserializes; empty does not serialize.
        let old = serde_json::json!({"name": "bob", "services": ["notes"]});
        let p: PeerInfo = serde_json::from_value(old).unwrap();
        assert_eq!(p.principal, None);
        assert!(serde_json::to_value(&p).unwrap().get("principal").is_none());
        // A bound peer carries BOTH the person user_id AND the device principal (#41).
        let full = PeerInfo {
            name: "bob".into(),
            services: vec!["notes".into()],
            user_id: Some("b64u:BOB".into()),
            principal: Some("eid:0707".into()),
        };
        let back: PeerInfo = serde_json::from_value(serde_json::to_value(&full).unwrap()).unwrap();
        assert_eq!(back.user_id.as_deref(), Some("b64u:BOB"));
        assert_eq!(back.principal.as_deref(), Some("eid:0707"));
    }

    #[test]
    fn active_session_principal_is_additive() {
        // An OLD payload (no `principal`) must still deserialize — #73 is additive.
        let old: ActiveSession =
            serde_json::from_str(r#"{"peer":"bob","service":"notes","opened_at":7}"#).unwrap();
        assert_eq!(old.principal, None, "serde(default) supplies it");

        // And a `None` must not serialize, so an old client sees the shape it expects.
        let json = serde_json::to_string(&old).unwrap();
        assert!(
            !json.contains("principal"),
            "skip_serializing_if must omit it: {json}"
        );

        // A real row round-trips the principal.
        let new = ActiveSession {
            peer: "bob".into(),
            service: "notes".into(),
            opened_at: 7,
            principal: Some("eid:1f0a".into()),
        };
        let back: ActiveSession =
            serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
        assert_eq!(back.principal.as_deref(), Some("eid:1f0a"));
    }

    #[test]
    fn peer_reachability_principal_is_additive() {
        // Older payload (no principal) still deserializes; empty does not serialize; a set
        // value round-trips alongside the #40 meta so an embedder joins on the principal.
        let old = serde_json::json!({"name": "bob", "reachable": true});
        let r: PeerReachability = serde_json::from_value(old).unwrap();
        assert_eq!(r.principal, None);
        assert!(serde_json::to_value(&r).unwrap().get("principal").is_none());
        let full = PeerReachability {
            name: "bob".into(),
            reachable: true,
            rtt_ms: Some(12),
            age_secs: Some(3),
            meta: "v=1.2.3".into(),
            principal: Some("eid:0707".into()),
            path: Default::default(),
        };
        let back: PeerReachability =
            serde_json::from_value(serde_json::to_value(&full).unwrap()).unwrap();
        assert_eq!(back.principal.as_deref(), Some("eid:0707"));
        assert_eq!(back.meta, "v=1.2.3");
    }

    #[test]
    fn peer_reachability_meta_is_additive() {
        // An older payload (no meta) still deserializes; an empty meta does not serialize.
        let old = serde_json::json!({"name": "bob", "reachable": true});
        let r: PeerReachability = serde_json::from_value(old).unwrap();
        assert_eq!(r.meta, "");
        assert!(serde_json::to_value(&r).unwrap().get("meta").is_none());
        // A set value round-trips.
        let with = PeerReachability {
            name: "bob".into(),
            reachable: true,
            rtt_ms: Some(12),
            age_secs: Some(3),
            meta: "v=1.2.3".into(),
            principal: None,
            path: Default::default(),
        };
        let back: PeerReachability =
            serde_json::from_value(serde_json::to_value(&with).unwrap()).unwrap();
        assert_eq!(back.meta, "v=1.2.3");
    }

    #[test]
    fn presence_peer_meta_is_additive() {
        let old = serde_json::json!({
            "user_id": "b64u:A", "device_label": "laptop", "role": "primary", "online": true
        });
        let p: PresencePeer = serde_json::from_value(old).unwrap();
        assert_eq!(p.meta, "");
        assert!(serde_json::to_value(&p).unwrap().get("meta").is_none());
    }

    #[test]
    fn set_nickname_request_carries_the_method_tag() {
        let r = Request::SetNickname(SetNicknameParams {
            nickname: "workbench".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "set_nickname");
        assert_eq!(v["params"]["nickname"], "workbench");
        assert_eq!(method_of(&v), Some("set_nickname"));
    }

    #[test]
    fn set_nickname_params_reject_unknown_field() {
        let err = serde_json::from_value::<SetNicknameParams>(
            serde_json::json!({"nickname": "x", "nonsense": 1}),
        );
        assert!(err.is_err(), "unknown params keys must be rejected");
    }

    /// An OLDER daemon's status payload (no `self_nickname`) must still deserialize —
    /// the additive-only contract — and an empty name must not serialize at all.
    #[test]
    fn status_self_nickname_is_additive() {
        let old = serde_json::json!({
            "stack_version": "0.7.0", "services": [], "peers": []
        });
        let s: StatusResult = serde_json::from_value(old).unwrap();
        assert_eq!(s.self_nickname, "");
        let v = serde_json::to_value(&s).unwrap();
        assert!(v.get("self_nickname").is_none(), "empty name is skipped");
    }

    #[test]
    fn api_minor_is_present_and_monotonic_from_hello() {
        // #34 part 2: a machine-comparable protocol-compat minor, distinct from the
        // crate/stack version, additive on the Hello frame.
        let h = Hello {
            api: API_NAME.into(),
            api_version: API_VERSION.into(),
            api_minor: API_MINOR,
            stack_version: "9.9.9".into(),
        };
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["api_minor"], API_MINOR);
        // An OLD Hello without api_minor still deserializes (additive contract).
        let old = serde_json::json!({
            "api": API_NAME, "api_version": "1.0", "stack_version": "0.4.0"
        });
        let back: Hello = serde_json::from_value(old).unwrap();
        assert_eq!(back.api_minor, 0, "absent api_minor defaults to 0");
    }

    #[test]
    fn hello_result_roundtrips() {
        let h = Hello {
            api: "mcpmesh-local/1".into(),
            api_version: "1.0".into(),
            api_minor: 0,
            stack_version: "0.1.0".into(),
        };
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["api"], "mcpmesh-local/1");
        let back: Hello = serde_json::from_value(v).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn request_tagged_by_method() {
        let r = Request::Status;
        assert_eq!(serde_json::to_value(&r).unwrap()["method"], "status");
        let r = Request::OpenSession(OpenSessionParams {
            peer: "alice".into(),
            service: "notes".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "open_session");
        assert_eq!(v["params"]["peer"], "alice");
    }

    #[test]
    fn parameterless_method_tolerates_params_forms() {
        // Omitted and null params deserialize straight into the unit variant.
        let omitted: Request =
            serde_json::from_value(serde_json::json!({"method": "status"})).unwrap();
        assert_eq!(omitted, Request::Status);
        let null: Request =
            serde_json::from_value(serde_json::json!({"method": "status", "params": null}))
                .unwrap();
        assert_eq!(null, Request::Status);

        // Known limitation: adjacent tagging rejects `params:{}` for a unit variant, so
        // the server MUST dispatch on the method string rather than deserialize the whole
        // message into `Request`. This is the pattern the daemon's dispatcher uses.
        let empty = serde_json::json!({"method": "status", "params": {}});
        assert!(serde_json::from_value::<Request>(empty.clone()).is_err());
        match method_of(&empty) {
            Some("status") => {} // dispatcher resolves Status via the method string
            other => panic!("method_of failed to resolve status: {other:?}"),
        }
    }

    #[test]
    fn backend_spec_roundtrips() {
        let run = BackendSpec::Run {
            cmd: vec!["notes-mcp".into(), "--stdio".into()],
            env: Default::default(),
            cwd: None,
        };
        let v = serde_json::to_value(&run).unwrap();
        assert_eq!(v["run"]["cmd"][0], "notes-mcp");
        assert_eq!(serde_json::from_value::<BackendSpec>(v).unwrap(), run);

        let sock = BackendSpec::Socket {
            path: "/run/notes.sock".into(),
        };
        let v = serde_json::to_value(&sock).unwrap();
        assert_eq!(v["socket"]["path"], "/run/notes.sock");
        assert_eq!(serde_json::from_value::<BackendSpec>(v).unwrap(), sock);
    }

    #[test]
    fn register_service_wire_shape() {
        let r = Request::RegisterService(RegisterServiceParams {
            name: "notes".into(),
            backend: BackendSpec::Run {
                cmd: vec!["notes-mcp".into()],
                env: Default::default(),
                cwd: None,
            },
            allow: vec!["alice".into()],
            ephemeral: false,
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "method": "register_service",
                "params": {
                    "name": "notes",
                    "backend": {"run": {"cmd": ["notes-mcp"]}},
                    "allow": ["alice"],
                }
            })
        );
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
    }

    #[test]
    fn invite_request_and_result_roundtrip() {
        // Request::Invite → `{ "method": "invite", "params": { "services": [...] } }`.
        let r = Request::Invite(InviteParams {
            services: vec!["notes".into(), "kb".into()],
            app_label: None,
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "invite");
        assert_eq!(v["params"]["services"][0], "notes");
        assert_eq!(v["params"]["services"][1], "kb");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "invite", "params": {"services": []}})),
            Some("invite")
        );

        // InviteResult carries the copyable line + expiry (surface #2 pairing artifact).
        let res = InviteResult {
            invite_line: "mcpmesh-invite:ABCDEF".into(),
            expires_at_epoch: 1_800_000_000,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["invite_line"], "mcpmesh-invite:ABCDEF");
        assert_eq!(v["expires_at_epoch"], 1_800_000_000u64);
        assert_eq!(serde_json::from_value::<InviteResult>(v).unwrap(), res);
    }

    #[test]
    fn pair_request_and_result_roundtrip() {
        // Request::Pair → `{ "method": "pair", "params": { "invite_line": "..." } }`.
        let r = Request::Pair(PairParams {
            invite_line: "mcpmesh-invite:ABCDEF".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "pair");
        assert_eq!(v["params"]["invite_line"], "mcpmesh-invite:ABCDEF");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "pair", "params": {"invite_line": "x"}})),
            Some("pair")
        );

        // PairResult carries the inviter's suggested nickname + the display-only SAS words +
        // the granted services (the porcelain renders each as `<peer>/<service>`).
        let res = PairResult {
            peer_nickname: "alice".into(),
            sas_code: "tango-fig-cabbage".into(),
            services: vec!["notes".into(), "kb".into()],
            app_label: None,
            peer_user_id: None,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["peer_nickname"], "alice");
        assert_eq!(v["sas_code"], "tango-fig-cabbage");
        assert_eq!(v["services"][0], "notes");
        assert_eq!(v["services"][1], "kb");
        assert_eq!(serde_json::from_value::<PairResult>(v).unwrap(), res);

        // Additive-only: a PairResult minted by an older daemon (no `services` key) still
        // deserializes — the `#[serde(default)]` fills it with an empty list.
        let old_shape = serde_json::json!({
            "peer_nickname": "alice",
            "sas_code": "tango-fig-cabbage",
        });
        let back: PairResult = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.peer_nickname, "alice");
        assert!(back.services.is_empty());
    }

    #[test]
    fn roster_install_request_and_result_roundtrip() {
        // Request::RosterInstall → `{ "method": "roster_install", "params": { "path": ...,
        // "org_root_pk": ... } }`. The optional pk is present on the first-install shape.
        let r = Request::RosterInstall(RosterInstallParams {
            path: "/tmp/roster.json".into(),
            org_root_pk: Some("b64u:AAAA".into()),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "roster_install");
        assert_eq!(v["params"]["path"], "/tmp/roster.json");
        assert_eq!(v["params"]["org_root_pk"], "b64u:AAAA");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "roster_install", "params": {"path": "/x"}})),
            Some("roster_install")
        );

        // When the pk is omitted (a subsequent install using the pinned value), it is
        // `skip_serializing_if`-dropped from the wire and deserializes back to `None`.
        let omit = Request::RosterInstall(RosterInstallParams {
            path: "/tmp/roster.json".into(),
            org_root_pk: None,
        });
        let v = serde_json::to_value(&omit).unwrap();
        assert!(
            v["params"].get("org_root_pk").is_none(),
            "an omitted org_root_pk must not appear on the wire: {v}"
        );
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), omit);

        // RosterInstallResult carries org_id + serial + severed count (roster-status vocabulary).
        let res = RosterInstallResult {
            org_id: "acme".into(),
            serial: 42,
            severed: 1,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["org_id"], "acme");
        assert_eq!(v["serial"], 42u64);
        assert_eq!(v["severed"], 1u32);
        assert_eq!(
            serde_json::from_value::<RosterInstallResult>(v).unwrap(),
            res
        );

        // Additive-only: a result minted by an older daemon (no `severed` key) still
        // deserializes — the `#[serde(default)]` fills it with 0.
        let old_shape = serde_json::json!({ "org_id": "acme", "serial": 7 });
        let back: RosterInstallResult = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.serial, 7);
        assert_eq!(back.severed, 0);
    }

    #[test]
    fn org_join_request_and_result_roundtrip() {
        // Request::OrgJoin → `{ "method": "org_join", "params": { org_id, org_root_pk, user_id,
        // user_key } }`. `user_key` is a LOCAL path string (the key never crosses the API).
        let r = Request::OrgJoin(OrgJoinParams {
            org_id: "acme".into(),
            org_root_pk: "b64u:AAAA".into(),
            user_id: "alice".into(),
            user_key: "/home/alice/.config/mcpmesh/user.key".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "org_join");
        assert_eq!(v["params"]["org_id"], "acme");
        assert_eq!(v["params"]["org_root_pk"], "b64u:AAAA");
        assert_eq!(v["params"]["user_id"], "alice");
        assert_eq!(
            v["params"]["user_key"],
            "/home/alice/.config/mcpmesh/user.key"
        );
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "org_join", "params": {"org_id": "x"}})),
            Some("org_join")
        );

        // OrgJoinResult echoes the pinned org id (surface-clean; the fingerprint is porcelain-side).
        let res = OrgJoinResult {
            org_id: "acme".into(),
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["org_id"], "acme");
        assert_eq!(serde_json::from_value::<OrgJoinResult>(v).unwrap(), res);
    }

    #[test]
    fn set_roster_url_request_roundtrip() {
        // Request::SetRosterUrl → `{ "method": "set_roster_url", "params": { "url": "..." } }`.
        let r = Request::SetRosterUrl(SetRosterUrlParams {
            url: "https://intranet.acme.com/roster.json".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "set_roster_url");
        assert_eq!(v["params"]["url"], "https://intranet.acme.com/roster.json");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        assert_eq!(
            method_of(&serde_json::json!({"method": "set_roster_url", "params": {"url": "x"}})),
            Some("set_roster_url")
        );
    }

    #[test]
    fn peer_remove_request_roundtrip() {
        // Request::PeerRemove → `{ "method": "peer_remove", "params": { "nickname": "..." } }`.
        let r = Request::PeerRemove(PeerRemoveParams {
            nickname: "bob".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "peer_remove");
        assert_eq!(v["params"]["nickname"], "bob");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "peer_remove", "params": {"nickname": "bob"}})),
            Some("peer_remove")
        );
    }

    /// The reserved/internal `peer_add` rides the SAME typed vocabulary as every other method —
    /// `{ "method": "peer_add", "params": { nickname, endpoint_id, allow } }` — with `allow`
    /// defaulting to empty when absent.
    #[test]
    fn peer_add_request_roundtrip() {
        let r = Request::PeerAdd(PeerAddParams {
            nickname: "bob".into(),
            endpoint_id: "96246d3f".into(),
            allow: vec!["notes".into()],
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "peer_add");
        assert_eq!(v["params"]["nickname"], "bob");
        assert_eq!(v["params"]["endpoint_id"], "96246d3f");
        assert_eq!(v["params"]["allow"][0], "notes");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // An absent allow list deserializes to empty (the server-side tolerance).
        let p: PeerAddParams =
            serde_json::from_value(serde_json::json!({"nickname": "bob", "endpoint_id": "x"}))
                .unwrap();
        assert!(p.allow.is_empty());
    }

    #[test]
    fn peer_rename_request_roundtrip() {
        // By user_id (renames all of a person's devices in one op).
        let r = Request::PeerRename(PeerRenameParams {
            user_id: Some("b64u:BOB".into()),
            nickname: None,
            to: "Bobby".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "peer_rename");
        assert_eq!(v["params"]["user_id"], "b64u:BOB");
        assert_eq!(v["params"]["to"], "Bobby");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // A provisional contact is renamed by nickname; omitted user_id defaults to None.
        assert_eq!(
            method_of(
                &serde_json::json!({"method": "peer_rename", "params": {"nickname": "carol", "to": "Carol"}})
            ),
            Some("peer_rename")
        );
    }

    #[test]
    fn status_result_roundtrips() {
        // Pure-pairing daemon: `roster` is None — absent from the wire (skip_serializing_if) and an
        // older payload with no `roster` key still deserializes to None (serde default).
        let s = StatusResult {
            stack_version: "0.1.0".into(),
            services: vec![ServiceInfo {
                name: "notes".into(),
                allow: vec!["alice".into()],
                allow_display: vec![],
                backend: BackendKind::Run,
                ephemeral: false,
            }],
            peers: vec![PeerInfo {
                name: "alice".into(),
                services: vec!["notes".into()],
                // A paired peer that proved a self-sovereign user_id at pairing (surface-clean id).
                user_id: Some("b64u:alicepk".into()),
                principal: None,
            }],
            roster: None,
            presence: vec![],
            self_user_id: Some("b64u:selfpk".into()),
            recent_pairings: vec![],
            reachability: vec![],
            self_nickname: String::new(),
            storage: None,
            self_network: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["services"][0]["backend"], "run");
        // The additive identity fields ride the wire when present.
        assert_eq!(v["peers"][0]["user_id"], "b64u:alicepk");
        assert_eq!(v["self_user_id"], "b64u:selfpk");
        assert!(
            v.get("roster").is_none(),
            "an absent roster must not appear on the wire: {v}"
        );
        assert!(
            v.get("presence").is_none(),
            "an empty presence must not appear on the wire: {v}"
        );
        assert!(
            v.get("recent_pairings").is_none(),
            "an empty recent_pairings must not appear on the wire: {v}"
        );
        assert_eq!(serde_json::from_value::<StatusResult>(v).unwrap(), s);

        // A payload minted by an older daemon (no `roster`/`presence`/identity keys) still
        // deserializes — the identity fields default to None / a nickname-only peer.
        let old_shape = serde_json::json!({
            "stack_version": "0.1.0",
            "services": [],
            "peers": [{ "name": "bob", "services": [] }],
        });
        let back: StatusResult = serde_json::from_value(old_shape).unwrap();
        assert!(back.roster.is_none());
        assert!(back.presence.is_empty());
        assert!(back.self_user_id.is_none());
        assert!(back.peers[0].user_id.is_none());
        assert!(back.recent_pairings.is_empty());

        // Roster daemon: a Some(RosterStatus) + an advisory presence list round-trip. `presence`
        // carries FLAT vocabulary only (user_id/device_label/role/online) — no EndpointId/key.
        let s = StatusResult {
            stack_version: "0.1.0".into(),
            services: vec![],
            peers: vec![],
            roster: Some(RosterStatus {
                org_id: "acme".into(),
                serial: 42,
                state: "approved".into(),
                org_root_fingerprint: "tango-fig-cabbage-anchor".into(),
            }),
            presence: vec![
                PresencePeer {
                    user_id: "alice".into(),
                    device_label: "laptop".into(),
                    role: "primary".into(),
                    online: true,
                    meta: String::new(),
                },
                PresencePeer {
                    user_id: "alice".into(),
                    device_label: "desktop".into(),
                    role: "mirror".into(),
                    online: false,
                    meta: String::new(),
                },
            ],
            self_user_id: None,
            recent_pairings: vec![],
            reachability: vec![],
            self_nickname: String::new(),
            storage: None,
            self_network: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["roster"]["org_id"], "acme");
        assert_eq!(v["roster"]["serial"], 42u64);
        assert_eq!(v["roster"]["state"], "approved");
        assert_eq!(
            v["roster"]["org_root_fingerprint"],
            "tango-fig-cabbage-anchor"
        );
        assert_eq!(v["presence"][0]["user_id"], "alice");
        assert_eq!(v["presence"][0]["device_label"], "laptop");
        assert_eq!(v["presence"][0]["role"], "primary");
        assert_eq!(v["presence"][0]["online"], true);
        assert_eq!(v["presence"][1]["online"], false);
        assert_eq!(serde_json::from_value::<StatusResult>(v).unwrap(), s);
    }

    /// The `recent_pairings` status field is ADDITIVE: a populated list round-trips with
    /// the flat `{peer_nickname, sas_code, paired_at_epoch}` shape (nickname + SAS words + epoch —
    /// never an EndpointId), an empty list is dropped from the wire, and a payload minted by an
    /// older daemon (no key at all) still deserializes to empty.
    #[test]
    fn recent_pairings_are_additive_on_status() {
        let s = StatusResult {
            stack_version: "0.1.0".into(),
            services: vec![],
            peers: vec![],
            roster: None,
            presence: vec![],
            self_user_id: None,
            recent_pairings: vec![RecentPairing {
                peer_nickname: "bob".into(),
                sas_code: "tango-fig-cabbage".into(),
                paired_at_epoch: 1_800_000_000,
            }],
            reachability: vec![],
            self_nickname: String::new(),
            storage: None,
            self_network: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["recent_pairings"][0]["peer_nickname"], "bob");
        assert_eq!(v["recent_pairings"][0]["sas_code"], "tango-fig-cabbage");
        assert_eq!(v["recent_pairings"][0]["paired_at_epoch"], 1_800_000_000u64);
        assert_eq!(serde_json::from_value::<StatusResult>(v).unwrap(), s);

        // A payload minted by an OLDER daemon (no `recent_pairings` key) still deserializes —
        // the `#[serde(default)]` fills it with an empty list.
        let old_shape = serde_json::json!({
            "stack_version": "0.1.0",
            "services": [],
            "peers": [],
        });
        let back: StatusResult = serde_json::from_value(old_shape).unwrap();
        assert!(back.recent_pairings.is_empty());
    }

    #[test]
    fn blob_requests_and_results_roundtrip() {
        // BlobPublish → { method, params: { scope, path } }.
        let r = Request::BlobPublish(BlobPublishParams {
            scope: "docs".into(),
            path: "/tmp/a.bin".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "blob_publish");
        assert_eq!(v["params"]["scope"], "docs");
        assert_eq!(v["params"]["path"], "/tmp/a.bin");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);

        // BlobGrant → { method, params: { scope, principal } }.
        // #62: the two withdrawal verbs' wire tags. A wrong dispatch string or a swapped param
        // would otherwise ship undetected — the e2e test calls the provider directly and never
        // crosses JSON-RPC.
        let rev = Request::BlobRevoke(BlobRevokeParams {
            scope: "photos".into(),
            principals: vec!["alice".into()],
        });
        let v = serde_json::to_value(&rev).unwrap();
        assert_eq!(v["method"], "blob_revoke");
        assert_eq!(v["params"]["principals"][0], "alice");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), rev);

        let unp = Request::BlobUnpublish(BlobUnpublishParams {
            scope: "photos".into(),
            hash: "abc123".into(),
        });
        let v = serde_json::to_value(&unp).unwrap();
        assert_eq!(v["method"], "blob_unpublish");
        assert_eq!(v["params"]["hash"], "abc123");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), unp);

        let r = Request::BlobGrant(BlobGrantParams {
            scope: "docs".into(),
            principal: "alice".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "blob_grant");
        assert_eq!(v["params"]["principal"], "alice");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);

        // BlobList is parameterless (method_of resolves it).
        assert_eq!(
            method_of(&serde_json::json!({"method": "blob_list"})),
            Some("blob_list")
        );

        // BlobFetch → { method, params: { ticket, dest_path } }.
        let r = Request::BlobFetch(BlobFetchParams {
            ticket: "blobAAA".into(),
            dest_path: "/tmp/out.bin".into(),
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "blob_fetch");
        assert_eq!(v["params"]["ticket"], "blobAAA");
        assert_eq!(v["params"]["dest_path"], "/tmp/out.bin");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);

        // BlobPublishResult carries the ticket + hash (blob-reference vocabulary).
        let res = BlobPublishResult {
            ticket: "blobAAA".into(),
            hash: "ab".repeat(32),
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["ticket"], "blobAAA");
        assert_eq!(serde_json::from_value::<BlobPublishResult>(v).unwrap(), res);

        // BlobScopeList carries flat (name, hashes, grants) — no EndpointId/key leakage.
        let res = BlobScopeList {
            scopes: vec![ScopeInfo {
                name: "docs".into(),
                hashes: vec!["ab".repeat(32)],
                grants: vec!["alice".into()],
                withdrawn: vec![],
                hash_count: 1,
                grant_count: 1,
                withdrawn_count: 0,
            }],
            total: 1,
            truncated: false,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["scopes"][0]["name"], "docs");
        assert_eq!(v["scopes"][0]["grants"][0], "alice");
        assert_eq!(serde_json::from_value::<BlobScopeList>(v).unwrap(), res);

        // BlobFetchResult carries the verified hash + byte length.
        let res = BlobFetchResult {
            hash: "ab".repeat(32),
            bytes_len: 4194304,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["bytes_len"], 4194304u64);
        assert_eq!(serde_json::from_value::<BlobFetchResult>(v).unwrap(), res);
    }

    /// The three `subscribe` frame shapes round-trip with the documented `type`-tagged wire form
    /// (docs/local-protocol.md "Live event stream"): `snapshot` carries the flat session/reachability
    /// lists, `event` delegates through the `Box` so the record's fields sit VERBATIM under
    /// `record` (one schema with the JSONL log), and `lagged` carries the dropped count.
    #[test]
    fn stream_frames_roundtrip_with_the_documented_tags() {
        let snap = StreamFrame::Snapshot {
            self_network: None,
            active_sessions: vec![ActiveSession {
                peer: "bob".into(),
                service: "notes".into(),
                opened_at: 1_751_760_000,
                principal: None,
            }],
            reachability: vec![PeerReachability {
                name: "bob".into(),
                reachable: true,
                rtt_ms: Some(42),
                age_secs: Some(3),
                meta: String::new(),
                principal: None,
                path: Default::default(),
            }],
        };
        let v = serde_json::to_value(&snap).unwrap();
        assert_eq!(v["type"], "snapshot");
        assert_eq!(v["active_sessions"][0]["peer"], "bob");
        assert_eq!(v["active_sessions"][0]["opened_at"], 1_751_760_000i64);
        assert_eq!(v["reachability"][0]["name"], "bob");
        assert_eq!(serde_json::from_value::<StreamFrame>(v).unwrap(), snap);

        let event = StreamFrame::Event {
            record: Box::new(AuditRecord::session_open(
                "2026-07-03T14:02:11.480Z".into(),
                Some("bob".into()),
                "notes".into(),
                None,
            )),
        };
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["type"], "event");
        // The record's fields ride verbatim under `record` — no Box indirection on the wire.
        assert_eq!(v["record"]["kind"], "session_open");
        assert_eq!(v["record"]["peer"], "bob");
        assert_eq!(v["record"]["service"], "notes");
        assert_eq!(serde_json::from_value::<StreamFrame>(v).unwrap(), event);

        let lagged = StreamFrame::Lagged { dropped: 12 };
        let v = serde_json::to_value(&lagged).unwrap();
        assert_eq!(v, serde_json::json!({ "type": "lagged", "dropped": 12 }));
        assert_eq!(serde_json::from_value::<StreamFrame>(v).unwrap(), lagged);
    }

    /// A frame minted by a NEWER daemon (an unknown `type`) fails to deserialize rather than
    /// mis-parsing — the typed stream surface is closed; a forward-compatible consumer reads the
    /// raw `Value` stream instead (`ControlClient::open_stream`).
    #[test]
    fn unknown_stream_frame_type_is_rejected() {
        let future = serde_json::json!({ "type": "future_kind", "x": 1 });
        assert!(serde_json::from_value::<StreamFrame>(future).is_err());
    }

    #[test]
    fn audit_summary_request_and_result_roundtrip() {
        // Request::AuditSummary is parameterless → `{ "method": "audit_summary" }`. Like Status, it
        // tolerates omitted/null params; the server dispatches on the method string (method_of).
        let r = Request::AuditSummary;
        assert_eq!(serde_json::to_value(&r).unwrap()["method"], "audit_summary");
        assert_eq!(
            method_of(&serde_json::json!({"method": "audit_summary"})),
            Some("audit_summary")
        );

        // AuditSummaryResult carries LOCAL per-peer / per-service session counts (nicknames + service
        // names only — never endpoints/transport terms) + a total. Tuples mirror kb's
        // InsightResponse.per_peer_contribution: `["bob", 2]` on the wire.
        let res = AuditSummaryResult {
            per_peer: vec![("alice".into(), 1), ("bob".into(), 2)],
            per_service: vec![("kb".into(), 1), ("notes".into(), 3)],
            total_sessions: 4,
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["per_peer"][1][0], "bob");
        assert_eq!(v["per_peer"][1][1], 2u64);
        assert_eq!(v["per_service"][1][0], "notes");
        assert_eq!(v["total_sessions"], 4u64);
        assert_eq!(
            serde_json::from_value::<AuditSummaryResult>(v).unwrap(),
            res
        );

        // Additive-only: a result minted by an older daemon (no `total_sessions` key) still
        // deserializes — the `#[serde(default)]` fills it with 0.
        let old_shape = serde_json::json!({ "per_peer": [], "per_service": [] });
        let back: AuditSummaryResult = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.total_sessions, 0);
        assert!(back.per_peer.is_empty());
    }
}
