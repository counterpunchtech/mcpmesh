//! mcpmesh-net: the session kernel of the mcpmesh workspace — endpoint identity,
//! framed transports, trust-gated serving, and connection severing over iroh/QUIC.
//!
//! This crate is shared by the mcpmesh daemon (the serving side) and anything that
//! dials mesh services with full identity control. It deliberately excludes trust
//! POLICY (rosters, pairing, key storage — `mcpmesh-trust` and the daemon own
//! those; this crate only defines the [`TrustGate`] trait they implement) and the
//! wire codec's implementation (owned by `mcpmesh-codec`, re-exported here as
//! [`framing`]). Most integrators talking to a locally-running mesh want
//! `mcpmesh-local-api` instead — it needs no iroh at all.
//!
//! # The iroh pin
//!
//! This crate exact-pins its iroh version and exposes iroh types throughout its
//! public API (`iroh::Endpoint`, `iroh::EndpointAddr`, the stream types inside
//! [`SessionTransport`]). Use the re-export — `mcpmesh_net::iroh::…` — and never
//! add your own `iroh` dependency: any other version is a different crate to the
//! type system, and the first floating requirement breaks the build.
pub use iroh;

pub mod endpoint;
pub mod errors;
pub mod framing;
pub mod identity;
pub mod registry;
pub mod service;
pub mod transport;
pub use endpoint::{
    ALPN_MCP, ALPN_PAIR, ALPN_PING, CLOSE_UNAUTHORIZED, ConnectError, ServeHandle, ServiceEntry,
    Services, SessionBackend, SessionTransport, connect, run_mesh_connection, serve,
};
pub use framing::{
    FrameReader, Inbound, MAX_FRAME_BYTES, StrikeOutcome, Strikes, Violation, write_frame,
};
pub use identity::{EndpointId, PeerIdentity, StaticGate, TrustGate};
pub use registry::{ConnRegistry, Registration, should_sever};
pub use transport::{NdjsonTransport, RecvError, TransportWriter};
