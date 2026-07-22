//! Embed a full [mcpmesh](https://github.com/counterpunchtech/mcpmesh) node in-process.
//!
//! The supported surface is [`NodeBuilder`]/[`Node`] plus the `mcpmesh-local/1` control
//! protocol [`Node::control`] speaks (see `docs/local-protocol.md`). Every other module in
//! this crate is `#[doc(hidden)]` internals of the mcpmesh daemon — no stability promise is
//! made for them; they may change or vanish in any release without a major version bump.
//!
//! Only driving a RUNNING daemon (the sidecar model)? Depend on
//! [`mcpmesh-local-api`](https://docs.rs/mcpmesh-local-api) instead — it links no
//! networking stack at all. The full embedding guide (root-dir layout, host contract,
//! sidecar-vs-embedded) is
//! [`docs/embedding.md`](https://github.com/counterpunchtech/mcpmesh/blob/main/docs/embedding.md).
//!
//! # Quickstart
//!
//! ```no_run
//! # async fn quickstart() -> anyhow::Result<()> {
//! let node = mcpmesh_node::NodeBuilder::new("/var/lib/myapp/mesh").start().await?;
//! let mut control = node.control().await?;
//! control.register_service(
//!     "notes",
//!     mcpmesh_local_api::BackendSpec::Run { cmd: vec!["my-mcp-server".into()] },
//!     vec![],
//! ).await?;
//! let invite = control.invite(vec!["notes".into()]).await?;
//! println!("send this to a friend: {}", invite.invite_line);
//! # Ok(())
//! # }
//! ```
//!
//! The node is a full peer: everything the mcpmesh daemon can do — pairing, live MCP
//! sessions (`open_session`), roster/org mode, blobs, audit — works through
//! [`Node::control`], because it runs the daemon's own handlers.

/// This crate's version — the mcpmesh release-train version the daemon binary ships on.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use config::Config;
pub use node::{Node, NodeBuilder, StartError};
pub use paths::NodePaths;

#[doc(hidden)]
pub mod allowlist;
#[doc(hidden)]
pub mod audit;
#[doc(hidden)]
pub mod backends;
#[doc(hidden)]
pub mod blobs;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod control;
#[doc(hidden)]
pub mod daemon;
#[doc(hidden)]
pub mod ipc;
#[doc(hidden)]
pub mod limits;
pub mod node;
#[doc(hidden)]
pub mod pairing;
pub mod paths;
#[doc(hidden)]
pub mod roster;
#[doc(hidden)]
pub mod stream;
#[doc(hidden)]
pub mod util;
