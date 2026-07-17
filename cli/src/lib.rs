//! mcpmesh CLI internals exposed as a library so integration tests (and, post-M2a, the host
//! shell) can drive the daemon/control/client machinery directly. A bin-only crate exposes
//! no API to its `tests/*.rs` integration crates, so the auto-start path (which must be
//! exercised against a real detached daemon) lives here; the `mcpmesh` binary (`main.rs`) is
//! a thin clap shim over these modules.
pub mod allowlist;
pub mod audit;
pub mod backends;
pub mod blobs;
pub mod client;
pub mod config;
pub mod control;
pub mod daemon;
pub mod doctor;
pub mod ipc;
pub mod limits;
pub mod pairing;
pub mod proxy;
pub mod roster;
pub mod stream;
pub mod util;

pub use mcpmesh_local_api::{Hello, Request, StatusResult};
