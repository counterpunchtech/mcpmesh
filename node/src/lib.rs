//! Embed a full [mcpmesh](https://github.com/counterpunchtech/mcpmesh) node in-process.
//!
//! The supported surface is [`NodeBuilder`]/[`Node`] plus the `mcpmesh-local/1` control
//! protocol [`Node::control`] speaks (see `docs/local-protocol.md`). Every other module in
//! this crate is `#[doc(hidden)]` internals of the mcpmesh daemon — no stability promise is
//! made for them; they may change or vanish in any release without a major version bump.
//!
//! Only driving a RUNNING daemon (the sidecar model)? Depend on
//! [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api) instead — it links no
//! networking stack at all.

/// This crate's version — the mcpmesh release-train version the daemon binary ships on.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
