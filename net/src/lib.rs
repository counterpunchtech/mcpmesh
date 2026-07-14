//! mcpmesh-net: the platform kernel — endpoint management, framing, sessions.
//! Populated by M1 tasks; see spec §3.1.

pub mod endpoint;
pub mod errors;
pub mod framing;
pub mod identity;
pub mod registry;
pub mod service;
pub mod transport;
pub use endpoint::{
    ALPN_MCP, ALPN_PAIR, CLOSE_UNAUTHORIZED, ServeHandle, ServiceEntry, Services, SessionBackend,
    SessionTransport, connect, run_mesh_connection, serve,
};
pub use identity::{EndpointId, PeerIdentity, StaticGate, TrustGate};
pub use registry::{ConnRegistry, Registration, should_sever};
