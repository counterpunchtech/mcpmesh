//! mcpmesh-local-api: the mcpmesh-local/1 seam (mcpmesh §6.1) — protocol types (always) plus,
//! behind the `client` feature, the family NDJSON codec + a no-iroh UnixStream client.
//! The `client` feature is the D-A extraction: a non-net mcpmesh-local/1 client (kb's
//! self-registration, the host shell) links this WITHOUT pulling iroh via mcpmesh-net.
/// Platform paths + endpoint resolution (spec §13) — featureless/std-only, so plugins
/// (barred from `mcpmesh-trust`) resolve the daemon endpoint from the ONE rule.
pub mod paths;
pub mod principals;
pub mod protocol;
pub use principals::principal_set;
// DEVIATION (declared): the plan's Task 1 only edited protocol.rs, but the Task 2 import
// `use mcpmesh_local_api::AuditSummaryResult;` needs the type re-exported at the crate root like its
// siblings — added `AuditSummaryResult` to this list (minimal fix).
pub use protocol::{
    API_NAME, API_VERSION, AuditSummaryResult, BackendKind, BackendSpec, BlobFetchResult,
    BlobPublishResult, BlobScopeList, Hello, InviteResult, OrgJoinResult, PairResult, PeerInfo,
    PeerReachability, PresencePeer, RecentPairing, Request, RosterInstallResult, RosterStatus,
    ScopeInfo, ServiceInfo, StatusResult, method_of,
};

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod codec;

/// The platform local-endpoint seam (design 2026-07-18): connect/bind/accept/authorize.
#[cfg(feature = "client")]
pub mod transport;
#[cfg(feature = "client")]
pub use client::{ControlClient, connect_control, connect_control_default};

/// The shared plugin-platform seam (kb, loc, …): UDS faces, THE audience-authz expansion,
/// `[services.*]` self-registration, and the `*-local/1` JSON-RPC conventions.
#[cfg(feature = "service")]
pub mod service;
