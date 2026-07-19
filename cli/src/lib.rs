//! Internals of the `mcpmesh` binary. **Not a supported SDK** — no stability promise is
//! made for anything in this crate; modules are `pub` only so the binary's integration
//! tests and the embedding shell can link them, and they may change or vanish in any
//! release without a major version bump.
//!
//! Building on mcpmesh? Depend on [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api)
//! instead — that crate is the supported integration surface.
#[doc(hidden)]
pub mod allowlist;
#[doc(hidden)]
pub mod audit;
#[doc(hidden)]
pub mod backends;
#[doc(hidden)]
pub mod blobs;
#[doc(hidden)]
pub mod client;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod control;
#[doc(hidden)]
pub mod daemon;
#[doc(hidden)]
pub mod doctor;
#[doc(hidden)]
pub mod enrollcmd;
#[doc(hidden)]
pub mod ipc;
#[doc(hidden)]
pub mod limits;
#[doc(hidden)]
pub mod pairing;
#[doc(hidden)]
pub mod proxy;
#[doc(hidden)]
pub mod render;
#[doc(hidden)]
pub mod roster;
#[doc(hidden)]
pub mod stream;
#[doc(hidden)]
pub mod util;

#[doc(hidden)]
pub use mcpmesh_local_api::{Hello, Request, StatusResult};
