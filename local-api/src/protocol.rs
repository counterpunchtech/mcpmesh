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
    pub allow: Vec<String>,   // nicknames/groups (flat namespace)
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
}

/// Advisory reachability of a paired peer (pairing-mode liveness). Surface-clean:
/// a nickname + a bool + latency/age NUMBERS — never an endpoint-id, key, or transport path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerReachability {
    pub name: String,    // the peer's nickname
    pub reachable: bool, // result of the last probe (false if never probed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>, // last measured round-trip, if reachable
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub age_secs: Option<u64>, // None = never probed (consumer shows "checking…")
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
    /// peer's `PeerEntry` (identity) AND revokes its access by removing the nickname from every
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
    /// Publish a LOCAL file INTO a scope: the daemon adds the bytes to its gated
    /// app-blob store and records the hash in `scope`. `path` is a local file the same-uid daemon
    /// reads. Answers a [`BlobPublishResult`] carrying the `mcpmesh/blob/1` ticket + hash.
    /// Tag `"blob_publish"`.
    BlobPublish(BlobPublishParams),
    /// Grant a scope to a principal — any flat-namespace entry: a group name, a user_id, or a
    /// nickname (the shared `principal_set` expansion). Tag
    /// `"blob_grant"`.
    BlobGrant(BlobGrantParams),
    /// List the daemon's blob scopes (name → hashes + grants). Tag `"blob_list"`.
    BlobList,
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
}

/// Result of [`Request::BlobList`]: the daemon's scopes. Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobScopeList {
    pub scopes: Vec<ScopeInfo>,
}

/// Result of [`Request::BlobFetch`]: the verified hash + byte length written to `dest_path`.
/// Additive-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFetchResult {
    pub hash: String,
    pub bytes_len: u64,
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
        }
    }

    pub fn session_open(ts: String, peer: Option<String>, service: String) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionOpen);
        r.peer = peer;
        r.service = Some(service);
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

    pub fn session_close(ts: String, peer: Option<String>, service: String) -> Self {
        let mut r = Self::base(ts, AuditKind::SessionClose);
        r.peer = peer;
        r.service = Some(service);
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
    ) -> Self {
        let mut r = Self::base(ts, AuditKind::Request);
        r.peer = peer;
        r.service = Some(service);
        r.method = Some(method);
        r.tool = tool;
        r.args_hash = Some(args_hash);
        r
    }

    pub fn blob_fetch(ts: String, peer: Option<String>, hash: String, status: String) -> Self {
        let mut r = Self::base(ts, AuditKind::BlobFetch);
        r.peer = peer;
        r.target = Some(hash);
        r.status = Some(status);
        r
    }

    pub fn trust(ts: String, event: String, target: Option<String>) -> Self {
        let mut r = Self::base(ts, AuditKind::Trust);
        r.event = Some(event);
        r.target = target;
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
}

/// One frame of the [`Request::Subscribe`] stream (pairing liveness & health telemetry). Tagged on
/// `type` (snake_case), so a frame is `{"type":"snapshot",...}` / `{"type":"event",...}` /
/// `{"type":"lagged",...}`. `Event.record` is the [`AuditRecord`] verbatim, so the stream and the
/// on-disk log carry ONE schema. The daemon serializes these; an embedding consumer deserializes
/// them (see `docs/local-protocol.md` "Live event stream").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamFrame {
    /// The FIRST frame: a point-in-time picture of the mesh (open sessions + paired-peer
    /// reachability) so a fresh subscriber renders immediately without replaying history.
    Snapshot {
        active_sessions: Vec<ActiveSession>,
        reachability: Vec<PeerReachability>,
    },
    /// A live audit event (session open/close, request, blob fetch, trust) — the tap on the hub.
    /// Boxed so this (much larger) variant does not bloat every frame; serde delegates through the
    /// `Box`, so the wire shape is the record's fields verbatim.
    Event { record: Box<AuditRecord> },
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
    Run { cmd: Vec<String> },
    Socket { path: String },
}

pub const API_NAME: &str = "mcpmesh-local/1";
/// The protocol-compatibility version as `"MAJOR.MINOR"`, distinct from the crate/stack version.
///
/// - **MAJOR** matches the `/N` in [`API_NAME`] and changes only on a breaking wire change (the
///   transport already rejects a mismatched `api`, so an equality check on that is redundant).
/// - **MINOR** ([`API_MINOR`]) increments on EVERY surface change within a major — additive fields,
///   new methods, or a strictness change like params validation — bumped in the same change that
///   makes it. A client can guard with `api_minor >= N` for a feature it needs, or refuse a daemon
///   older than a minor it requires. It never resets except on a MAJOR bump.
pub const API_VERSION: &str = "1.2";
/// The integer MINOR of [`API_VERSION`] — see there. Bumped from 0 to 1 when params validation
/// became strict (#34); to 2 with the `set_nickname` verb + `StatusResult.self_nickname` (#37).
pub const API_MINOR: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_reachability_serde_is_additive() {
        let r = PeerReachability {
            name: "bob".into(),
            reachable: true,
            rtt_ms: Some(42),
            age_secs: Some(3),
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
                backend: BackendKind::Run,
                ephemeral: false,
            }],
            peers: vec![PeerInfo {
                name: "alice".into(),
                services: vec!["notes".into()],
                // A paired peer that proved a self-sovereign user_id at pairing (surface-clean id).
                user_id: Some("b64u:alicepk".into()),
            }],
            roster: None,
            presence: vec![],
            self_user_id: Some("b64u:selfpk".into()),
            recent_pairings: vec![],
            reachability: vec![],
            self_nickname: String::new(),
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
                },
                PresencePeer {
                    user_id: "alice".into(),
                    device_label: "desktop".into(),
                    role: "mirror".into(),
                    online: false,
                },
            ],
            self_user_id: None,
            recent_pairings: vec![],
            reachability: vec![],
            self_nickname: String::new(),
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
            }],
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
            active_sessions: vec![ActiveSession {
                peer: "bob".into(),
                service: "notes".into(),
                opened_at: 1_751_760_000,
            }],
            reachability: vec![PeerReachability {
                name: "bob".into(),
                reachable: true,
                rtt_ms: Some(42),
                age_secs: Some(3),
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
