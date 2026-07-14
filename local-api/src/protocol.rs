//! mcpmesh-local/1 protocol types (spec §6.1). Shared vocabulary between the daemon
//! and its clients (porcelain, connect proxy, later the host shell). Wire framing
//! is the family NDJSON codec — carried by the caller, not defined here (D-A).
//!
//! Request/response asymmetry: requests are one typed, closed enum (`Request`);
//! responses are per-method typed structs deserialized from the JSON-RPC `result`
//! Value — `Status` → [`StatusResult`], `RegisterService` → an ack, `OpenSession` →
//! no JSON-RPC result at all: the socket STOPS being JSON-RPC and becomes a raw
//! byte pipe.
//!
//! Additive-only (§6.1): new fields (capabilities on `Hello`, groups/user_id on
//! `PeerInfo`, device on `OpenSession` — M3+) MUST land as
//! `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
use serde::{Deserialize, Serialize};

/// The first exchange on any `*-local/N` socket (spec §6.1 "hello convention").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub api: String,         // "mcpmesh-local/1"
    pub api_version: String, // semver of the API major.minor
    pub stack_version: String,
}

/// The kind of backend answering a service — the two valid values, enforced at the
/// type level and kept in lockstep with `BackendSpec`'s variants. Status reports the
/// kind only, never the command/path (§17 no transport vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Run,
    Socket,
}

/// A registered service as reported by `status` (no transport vocabulary — §17).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub allow: Vec<String>,   // petnames/groups (flat namespace)
    pub backend: BackendKind, // "run" | "socket" (kind only, never the command/path)
}

/// A known peer as reported by `status` (petname only — never the EndpointId, §1.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub name: String,
    pub services: Vec<String>,
    /// The peer's PROVEN self-sovereign `user_id` (`b64u:<user_pk>`) if it presented a verified
    /// device->user binding at pairing (roster peers carry it too), else `None` (petname-only). This
    /// is a §1.5-clean identity (an opaque user id, NOT an EndpointId). Additive (§6.1):
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so older payloads round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// Roster-mode status (spec §4.4). Surface-clean roster VOCABULARY only: org_id, serial, a plain
/// state word, and the pinned org-root FINGERPRINT in short words — never raw keys/EndpointIds/serials-
/// as-transport-vocab (§1.5). Absent in a pure-pairing daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterStatus {
    pub org_id: String,
    pub serial: u64,
    pub state: String, // "pending" | "approved" | "degraded" | "stopped"
    pub org_root_fingerprint: String, // short-word form (§4.4)
}

/// One reachable roster peer device as reported by `status` (spec §10.1 advisory presence read).
/// ADVISORY — this is a display convenience, never an authorization surface. Surface-clean (§1.5/§17):
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
/// spec §4.2's ceremony is "both humans compare the code": the redeemer sees it in its
/// [`PairResult`]; this is the inviter's porcelain surface for the same words. DISPLAY-ONLY
/// ceremony state: held in-memory by the daemon (a small ring), lost on restart, NEVER an
/// authorization input or trust data. Surface-clean (§1.5): a petname + the SAS wordlist words +
/// an epoch — never an EndpointId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentPairing {
    /// The peer's petname as stored by the inviter (its local name for the redeemer).
    pub peer_petname: String,
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
    /// Roster-mode status (§4.4), absent in a pure-pairing daemon. Additive (§6.1):
    /// `#[serde(default, skip_serializing_if = ...)]` so a daemon/client without it round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster: Option<RosterStatus>,
    /// The reachable roster peer devices (spec §10.1 advisory presence read), each with an `online`
    /// flag. Empty in a pure-pairing daemon / when no roster is installed. Additive (§6.1):
    /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<PresencePeer>,
    /// THIS daemon's own self-sovereign `user_id` (`b64u:<user_pk>`), if it has a user key (auto-
    /// minted at boot; shared by pairing AND roster mode). Lets the operator see + share their stable
    /// identity that multiple devices resolve to. `None` only when no user key exists. Additive (§6.1):
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_user_id: Option<String>,
    /// Recent INVITER-side pairing completions, newest first (display-only §4.2 ceremony aids —
    /// see [`RecentPairing`]; in-memory on the daemon, cleared by a restart). Empty on a daemon
    /// that has accepted no pairing since it started. Additive (§6.1):
    /// `#[serde(default, skip_serializing_if = "Vec::is_empty")]` so an older payload round-trips.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent_pairings: Vec<RecentPairing>,
}

/// Control-API requests. Serialized as `{ "method": "...", "params": {...} }`
/// (JSON-RPC-shaped; the id/jsonrpc envelope is added by the transport layer).
///
/// Clients construct and serialize requests via this enum. **Servers dispatch on the
/// `method` string and deserialize `params` per-method** — tolerating omitted / null /
/// empty-object params for parameterless methods — rather than deserializing a whole
/// message into `Request` (adjacent tagging rejects `params:{}` for unit variants).
/// This keeps the wire tolerant for third-party clients (§6.1 versioned surface).
/// Use [`method_of`] to extract the tag, then match + deserialize `params` per-method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    /// Register/update a `[services.*]` entry idempotently (spec §6.1).
    RegisterService {
        name: String,
        backend: BackendSpec,
        allow: Vec<String>,
    },
    Status,
    /// Mint a one-time pairing invite granting `services` (spec §4.2). The daemon
    /// answers an [`InviteResult`] carrying the copyable `mcpmesh-invite:` line. Tag
    /// `"invite"` (snake_case). `method_of` needs no per-variant arm — it reads the
    /// `method` string generically; the tag comes from `rename_all`.
    Invite {
        services: Vec<String>,
    },
    /// Redeem a pairing invite (spec §4.2). The daemon dials the inviter named by
    /// `invite_line` on `mcpmesh/pair/1`, proves the secret, writes the mutual
    /// (dial-back) [`PeerEntry`], and answers a [`PairResult`]. Tag `"pair"`
    /// (snake_case); `method_of` reads the `method` string generically.
    ///
    /// [`PeerEntry`]: crate — the durable allowlist row lives in the daemon crate.
    Pair {
        invite_line: String,
    },
    /// Remove a paired peer by petname (spec §4.2, `mcpmesh pair --remove`). The daemon drops the
    /// peer's [`PeerEntry`] (identity) AND revokes its access by removing the petname from every
    /// `[services.*].allow` (authorization) — the inverse of the pairing grant. Idempotent: a
    /// petname with no entry / no allow membership is a clean no-op. Live in-flight sessions are
    /// NOT severed here (M3/D8): existing sessions run to completion; the peer only loses the
    /// ability to establish NEW authorized sessions. Tag `"peer_remove"` (snake_case);
    /// `method_of` reads the `method` string generically (no per-variant arm).
    ///
    /// [`PeerEntry`]: crate — the durable allowlist row lives in the daemon crate.
    PeerRemove {
        petname: String,
    },
    /// Rename a contact's nickname (petname) authoritatively (Contacts rename spec). Renames the
    /// PERSON — every `PeerEntry` sharing `user_id` when given (one op for all their devices), else the
    /// single `petname` entry (a provisional, no-`user_id` contact) — to `to`, AND rewrites the old
    /// petname → `to` in every `[services.*].allow` so grants follow the rename. Refuses (error frame)
    /// when `to` is empty or already names/grants a DIFFERENT identity — the same collision guard the
    /// pairing rendezvous uses, so a rename can't inherit another peer's access. Tag `"peer_rename"`;
    /// host-privileged like the other pair ops.
    PeerRename {
        #[serde(default)]
        user_id: Option<String>,
        #[serde(default)]
        petname: Option<String>,
        to: String,
    },
    /// Open a mesh session to `peer/service`; the daemon dials and pipes.
    /// Distinct from the proxy's job: this returns a session the client streams.
    /// Spec §6.1's `connect(peer[,device],service)` — renamed to avoid colliding
    /// with the `connect` porcelain.
    OpenSession {
        peer: String,
        service: String,
    },
    /// Install a signed roster from a local file (spec §4.3 manual `internal roster install`).
    /// `path` is a LOCAL file the same-uid daemon reads (P12/P14 trust boundary — passing a path
    /// not the bytes is fine). `org_root_pk` pins the org root on FIRST install (`b64u:`); omit it
    /// once pinned (config carries it). Tag `"roster_install"`.
    RosterInstall {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        org_root_pk: Option<String>,
    },
    /// Pin the org root on a JOINER (spec §4.4 step 2) — WITHOUT a roster (the joiner has none yet,
    /// D5). Records `[identity]` org_id / org_root_pk / user_id / user_key. `user_key` is a LOCAL path
    /// (the key never crosses the API). Tag `"org_join"`.
    OrgJoin {
        org_id: String,
        org_root_pk: String,
        user_id: String,
        user_key: String,
    },
    /// Pin the HTTPS roster URL (`[roster].url`) in config (spec §4.3 M3c). Written by `org create
    /// --roster-url` (the operator keeps it current) AND by `join` when the org invite carries one —
    /// so the joiner's poll loop bootstraps its FIRST roster (D5). The daemon writes it under
    /// `reload_lock` (single-writer), then the poll loop picks it up on the next daemon start. Tag
    /// `"set_roster_url"`.
    SetRosterUrl {
        url: String,
    },
    /// Publish a LOCAL file INTO a scope (spec §9, M4a): the daemon adds the bytes to its gated
    /// app-blob store and records the hash in `scope`. `path` is a local file the same-uid daemon
    /// reads (P12/P14). Answers a [`BlobPublishResult`] carrying the `mcpmesh/blob/1` ticket + hash.
    /// Tag `"blob_publish"`.
    BlobPublish {
        scope: String,
        path: String,
    },
    /// Grant a scope to a principal — any §5 flat-namespace entry: a group name, a user_id, or a
    /// petname (the shared `principal_set` expansion). Tag
    /// `"blob_grant"`.
    BlobGrant {
        scope: String,
        principal: String,
    },
    /// List the daemon's blob scopes (name → hashes + grants). Tag `"blob_list"`.
    BlobList,
    /// Fetch a `mcpmesh/blob/1` ticket THROUGH the daemon (BLAKE3-verified streaming) and export the
    /// verified blob to `dest_path` (a local file the same-uid daemon writes). Answers a
    /// [`BlobFetchResult`] with the verified hash + byte length. Tag `"blob_fetch"`.
    BlobFetch {
        ticket: String,
        dest_path: String,
    },
    /// Summarize this node's LOCAL audit log into per-peer / per-service SESSION counts (spec §11.3
    /// local-only — the daemon reads its OWN audit dir, nothing is transmitted). The host Mesh surface
    /// renders these as "who serves me / whom I serve / session counts". Parameterless (like `Status`);
    /// the server dispatches on the `method` string. Tag `"audit_summary"` (snake_case);
    /// `method_of` reads the `method` string generically (no per-variant arm).
    AuditSummary,
}

/// Result of [`Request::OrgJoin`] — the pinned org id echoed back (surface-clean; the fingerprint is
/// computed porcelain-side from the invite's org_root_pk). Additive-only (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgJoinResult {
    pub org_id: String,
}

/// Result of a [`Request::RosterInstall`] request (spec §4.3 manual path): the installed roster's
/// org id + serial (roster-status vocabulary the confirmation line is permitted to render) plus how
/// many live sessions the install severed (D8). Surface-clean: NO keys / EndpointIds / paths.
///
/// Additive-only (§6.1): any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterInstallResult {
    pub org_id: String,
    pub serial: u64,
    /// How many live sessions were severed (D8), for the porcelain's confirmation line.
    #[serde(default)]
    pub severed: u32,
}

/// Result of [`Request::BlobPublish`]: the copyable `mcpmesh/blob/1` ticket + the blob's blake3 hash.
/// A ticket/hash here is the §9 blob-reference vocabulary (NOT a §1.5 transport-vocab leak — the same
/// carve-out as the pairing invite line). Additive-only (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobPublishResult {
    pub ticket: String,
    pub hash: String, // bare blake3 hex
}

/// One scope in a [`BlobScopeList`] (spec §9): its name + the hashes it contains + the principals it
/// grants. Flat vocabulary ONLY (§1.5) — no EndpointId/pubkey/ALPN. Additive-only (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeInfo {
    pub name: String,
    pub hashes: Vec<String>,
    pub grants: Vec<String>,
}

/// Result of [`Request::BlobList`]: the daemon's scopes. Additive-only (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobScopeList {
    pub scopes: Vec<ScopeInfo>,
}

/// Result of [`Request::BlobFetch`]: the verified hash + byte length written to `dest_path`.
/// Additive-only (§6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobFetchResult {
    pub hash: String,
    pub bytes_len: u64,
}

/// Result of [`Request::AuditSummary`] (spec §11.3): LOCAL per-peer / per-service session counts
/// aggregated from this node's OWN audit log — NEVER transmitted (§11.3 local-only). Surface-clean
/// (§1.5): peer names are petnames / user_ids (NEVER EndpointIds), service names are the registered
/// service names (NEVER transport vocabulary). A "session" is one `SessionOpen` record. `per_peer` /
/// `per_service` are sorted ascending by name (deterministic). Tuples mirror kb's
/// `InsightResponse::per_peer_contribution` — `["bob", 2]` on the wire.
///
/// Additive-only (§6.1): any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummaryResult {
    /// Sessions opened per peer (petname). A session with no attributed peer is NOT counted here (no
    /// peer to attribute) but IS in `total_sessions`.
    pub per_peer: Vec<(String, u64)>,
    /// Sessions opened per registered service name.
    pub per_service: Vec<(String, u64)>,
    /// Total sessions opened (every `SessionOpen` record, including peer-less ones).
    #[serde(default)]
    pub total_sessions: u64,
}

/// Result of an [`Request::Invite`] request: the copyable `mcpmesh-invite:` artifact
/// (spec §1.5 surface #2 — the ONE pairing artifact deliberately carved out of the
/// transport-vocabulary blocklist, so this is NOT a transport-vocab leak) plus its
/// absolute expiry in epoch seconds (≤ now + 24h).
///
/// Additive-only (§6.1): any future field (e.g. the computed SAS, once the inviter side
/// surfaces it) MUST land as `#[serde(default, skip_serializing_if = ...)]` so older
/// payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResult {
    /// The `mcpmesh-invite:<base32>` line, copied out-of-band to the redeemer.
    pub invite_line: String,
    /// When the invite expires (epoch seconds); the daemon burns it at redemption or expiry.
    pub expires_at_epoch: u64,
}

/// Result of a [`Request::Pair`] request: the inviter's suggested petname (the
/// redeemer's local name for the new peer) plus the display-only short authentication
/// code (SAS, spec §4.2) — a few words the human reads aloud to a second channel to
/// catch a whole-invite forgery / address-swap MITM. The SAS is a pairing-ceremony
/// artifact (like the invite line), NOT a §1.5 transport-vocabulary leak.
///
/// Additive-only (§6.1): any future field MUST land as
/// `#[serde(default, skip_serializing_if = ...)]` so older payloads still deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairResult {
    /// The inviter's suggested petname (from the invite) — the redeemer's local name for it.
    pub peer_petname: String,
    /// The display-only short authentication code (e.g. `"tango-fig-42"`), shown on both
    /// sides for the out-of-band human check. Never sent on the wire, never checked
    /// programmatically.
    pub sas_code: String,
    /// The services this pairing granted the redeemer — each mountable as `<peer>/<service>`.
    /// Populated from the invite (`invite.services`) by the redeemer-side `redeem_invite`, so
    /// the porcelain can print the "You can mount: alice/notes" line without re-decoding the
    /// invite. Additive (§6.1): `#[serde(default, skip_serializing_if = ...)]` so a `PairResult`
    /// minted by an older daemon (which omits `services`) still deserializes — to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
}

/// Extract the `method` tag from a raw request value without deserializing the whole
/// message. Task 3's dispatcher uses this: match on the method string, then deserialize
/// `params` per-method — which tolerates omitted / null / `{}` params for parameterless
/// methods (adjacent tagging rejects `params:{}` on unit variants).
pub fn method_of(v: &serde_json::Value) -> Option<&str> {
    v.get("method").and_then(serde_json::Value::as_str)
}

/// How a service is answered (spec §6.2). Mirrors the config `[services.*]` *kinds*;
/// Config→BackendSpec is a hand-written match (Task 4/9), not a serde passthrough.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendSpec {
    Run { cmd: Vec<String> },
    Socket { path: String },
}

pub const API_NAME: &str = "mcpmesh-local/1";
pub const API_VERSION: &str = "1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_result_roundtrips() {
        let h = Hello {
            api: "mcpmesh-local/1".into(),
            api_version: "1.0".into(),
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
        let r = Request::OpenSession {
            peer: "alice".into(),
            service: "notes".into(),
        };
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
        // message into `Request`. This is the pattern the Task 3 dispatcher uses.
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
        let r = Request::RegisterService {
            name: "notes".into(),
            backend: BackendSpec::Run {
                cmd: vec!["notes-mcp".into()],
            },
            allow: vec!["alice".into()],
        };
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
        let r = Request::Invite {
            services: vec!["notes".into(), "kb".into()],
        };
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
        let r = Request::Pair {
            invite_line: "mcpmesh-invite:ABCDEF".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "pair");
        assert_eq!(v["params"]["invite_line"], "mcpmesh-invite:ABCDEF");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "pair", "params": {"invite_line": "x"}})),
            Some("pair")
        );

        // PairResult carries the inviter's suggested petname + the display-only SAS words +
        // the granted services (the porcelain renders each as `<peer>/<service>`).
        let res = PairResult {
            peer_petname: "alice".into(),
            sas_code: "tango-fig-cabbage".into(),
            services: vec!["notes".into(), "kb".into()],
        };
        let v = serde_json::to_value(&res).unwrap();
        assert_eq!(v["peer_petname"], "alice");
        assert_eq!(v["sas_code"], "tango-fig-cabbage");
        assert_eq!(v["services"][0], "notes");
        assert_eq!(v["services"][1], "kb");
        assert_eq!(serde_json::from_value::<PairResult>(v).unwrap(), res);

        // Additive-only: a PairResult minted by an older daemon (no `services` key) still
        // deserializes — the `#[serde(default)]` fills it with an empty list.
        let old_shape = serde_json::json!({
            "peer_petname": "alice",
            "sas_code": "tango-fig-cabbage",
        });
        let back: PairResult = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.peer_petname, "alice");
        assert!(back.services.is_empty());
    }

    #[test]
    fn roster_install_request_and_result_roundtrip() {
        // Request::RosterInstall → `{ "method": "roster_install", "params": { "path": ...,
        // "org_root_pk": ... } }`. The optional pk is present on the first-install shape.
        let r = Request::RosterInstall {
            path: "/tmp/roster.json".into(),
            org_root_pk: Some("b64u:AAAA".into()),
        };
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
        let omit = Request::RosterInstall {
            path: "/tmp/roster.json".into(),
            org_root_pk: None,
        };
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
        let r = Request::OrgJoin {
            org_id: "acme".into(),
            org_root_pk: "b64u:AAAA".into(),
            user_id: "alice".into(),
            user_key: "/home/alice/.config/mcpmesh/user.key".into(),
        };
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
        let r = Request::SetRosterUrl {
            url: "https://intranet.acme.com/roster.json".into(),
        };
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
        // Request::PeerRemove → `{ "method": "peer_remove", "params": { "petname": "..." } }`.
        let r = Request::PeerRemove {
            petname: "bob".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "peer_remove");
        assert_eq!(v["params"]["petname"], "bob");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // method_of resolves the tag generically (no per-variant arm).
        assert_eq!(
            method_of(&serde_json::json!({"method": "peer_remove", "params": {"petname": "bob"}})),
            Some("peer_remove")
        );
    }

    #[test]
    fn peer_rename_request_roundtrip() {
        // By user_id (renames all of a person's devices in one op).
        let r = Request::PeerRename {
            user_id: Some("b64u:BOB".into()),
            petname: None,
            to: "Bobby".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "peer_rename");
        assert_eq!(v["params"]["user_id"], "b64u:BOB");
        assert_eq!(v["params"]["to"], "Bobby");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);
        // A provisional contact is renamed by petname; omitted user_id defaults to None.
        assert_eq!(
            method_of(
                &serde_json::json!({"method": "peer_rename", "params": {"petname": "carol", "to": "Carol"}})
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
            }],
            peers: vec![PeerInfo {
                name: "alice".into(),
                services: vec!["notes".into()],
                // A paired peer that proved a self-sovereign user_id at pairing (§1.5-clean id).
                user_id: Some("b64u:alicepk".into()),
            }],
            roster: None,
            presence: vec![],
            self_user_id: Some("b64u:selfpk".into()),
            recent_pairings: vec![],
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
        // deserializes — the identity fields default to None / a petname-only peer.
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

    /// The `recent_pairings` status field is ADDITIVE (§6.1): a populated list round-trips with
    /// the flat `{peer_petname, sas_code, paired_at_epoch}` shape (petname + SAS words + epoch —
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
                peer_petname: "bob".into(),
                sas_code: "tango-fig-cabbage".into(),
                paired_at_epoch: 1_800_000_000,
            }],
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["recent_pairings"][0]["peer_petname"], "bob");
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
        let r = Request::BlobPublish {
            scope: "docs".into(),
            path: "/tmp/a.bin".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "blob_publish");
        assert_eq!(v["params"]["scope"], "docs");
        assert_eq!(v["params"]["path"], "/tmp/a.bin");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);

        // BlobGrant → { method, params: { scope, principal } }.
        let r = Request::BlobGrant {
            scope: "docs".into(),
            principal: "alice".into(),
        };
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
        let r = Request::BlobFetch {
            ticket: "blobAAA".into(),
            dest_path: "/tmp/out.bin".into(),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["method"], "blob_fetch");
        assert_eq!(v["params"]["ticket"], "blobAAA");
        assert_eq!(v["params"]["dest_path"], "/tmp/out.bin");
        assert_eq!(serde_json::from_value::<Request>(v).unwrap(), r);

        // BlobPublishResult carries the ticket + hash (blob-reference vocabulary, §9).
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

        // AuditSummaryResult carries LOCAL per-peer / per-service session counts (petnames + service
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

        // Additive-only (§6.1): a result minted by an older daemon (no `total_sessions` key) still
        // deserializes — the `#[serde(default)]` fills it with 0.
        let old_shape = serde_json::json!({ "per_peer": [], "per_service": [] });
        let back: AuditSummaryResult = serde_json::from_value(old_shape).unwrap();
        assert_eq!(back.total_sessions, 0);
        assert!(back.per_peer.is_empty());
    }
}
