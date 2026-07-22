//! Internals of the `mcpmesh` binary. **Not a supported SDK** — no stability promise is
//! made for anything in this crate; modules are `pub` only so the binary's integration
//! tests and the embedding shell can link them, and they may change or vanish in any
//! release without a major version bump.
//!
//! Building on mcpmesh? Depend on [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api)
//! instead — that crate is the supported integration surface.
#[doc(hidden)]
pub mod client;
#[doc(hidden)]
pub mod control;
#[doc(hidden)]
pub mod daemon;
#[doc(hidden)]
pub mod doctor;
#[doc(hidden)]
pub mod enrollcmd;
pub mod json;
#[doc(hidden)]
pub mod proxy;
#[doc(hidden)]
pub mod render;
#[doc(hidden)]
pub use mcpmesh_local_api::{Hello, Request, StatusResult};
// Daemon-core modules now live in mcpmesh-node; re-exported so the shell's remaining
// `crate::x` paths and the integration tests' `mcpmesh::x` paths resolve unchanged.
#[doc(hidden)]
pub use mcpmesh_node::{
    allowlist, audit, backends, blobs, config, ipc, limits, pairing, roster, stream, util,
};
