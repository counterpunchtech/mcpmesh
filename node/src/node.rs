//! The supported embedding surface: build ([`NodeBuilder`]) and drive ([`Node`]) a full
//! in-process mesh node. The node is its OWN mesh identity under its OWN root directory —
//! it never touches the per-user daemon's state, socket, or singleton lock, so it coexists
//! freely with a running `mcpmesh` daemon (and with other embedded nodes under other roots).
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcpmesh_local_api::client::ClientError;
use mcpmesh_local_api::{ControlClient, connect_control_io};

use crate::config::Config;
use crate::control::serve_control_io;
use crate::daemon::boot::{BootedNode, start_node};
use crate::paths::NodePaths;

/// Everything that can refuse a [`NodeBuilder::start`]. Embedders branch on
/// [`DataDirInUse`](StartError::DataDirInUse) (another node owns this root — one node per
/// root, enforced by redb's exclusive database lock) and [`Config`](StartError::Config)
/// (a malformed `config.toml` / programmatic config, worth showing to a human); everything
/// else is opaque infrastructure failure.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("config error: {0:#}")]
    Config(#[source] anyhow::Error),
    #[error("data dir already in use by another node: {path}")]
    DataDirInUse { path: PathBuf },
    #[error(transparent)]
    Other(anyhow::Error),
}

impl StartError {
    /// Classify a boot error by its CHAIN (the boot body stays plain-`anyhow`, so inner
    /// `?` sites never re-wrap): a `redb` open refusal on the peer store → `DataDirInUse`
    /// (its exact variant differs by platform/lock path, so any database-open error on the
    /// store path counts); a `figment` error anywhere → `Config`; else `Other`.
    pub(crate) fn classify(e: anyhow::Error, _config_path: &Path, db_path: &Path) -> StartError {
        if e.chain()
            .any(|c| c.downcast_ref::<redb::DatabaseError>().is_some())
        {
            return StartError::DataDirInUse {
                path: db_path.to_path_buf(),
            };
        }
        if e.chain()
            .any(|c| c.downcast_ref::<figment::Error>().is_some())
        {
            return StartError::Config(e);
        }
        StartError::Other(e)
    }
}

/// Build a [`Node`]: pick a root directory, optionally inject a [`Config`], then
/// [`start`](NodeBuilder::start).
pub struct NodeBuilder {
    root: PathBuf,
    config: Option<Config>,
}

impl NodeBuilder {
    /// A node rooted at `root` — the ONE directory holding its whole world (`config/`,
    /// `data/`, `state/`; layout-identical to a `mcpmesh --profile <root>` profile dir).
    /// Missing pieces are created on start: the first start mints the device key, and an
    /// absent `config/config.toml` boots the spec defaults.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            config: None,
        }
    }

    /// Use this configuration instead of reading `<root>/config/config.toml`. The type IS
    /// the config-file vocabulary (`docs/config.md`) — one schema, two front doors.
    /// Config-persisting control verbs (a non-ephemeral `register_service`, pairing
    /// grants) still write `<root>/config/config.toml`.
    pub fn config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Boot the node: identity, stores, gates, the iroh endpoint, and every serving loop
    /// the daemon runs. Requires a multi-thread tokio runtime (the node spawns its serving
    /// loops onto the ambient runtime). Installs a process-default rustls `CryptoProvider`
    /// (ring) if the host application has not installed one — idempotent, the host's wins.
    pub async fn start(self) -> Result<Node, StartError> {
        let paths = NodePaths::under_root(&self.root);
        let booted = start_node(paths, self.config).await?;
        Ok(Node { booted })
    }
}

/// A running in-process node. Dropping it does NOT stop serving — call
/// [`shutdown`](Node::shutdown).
pub struct Node {
    booted: BootedNode,
}

/// Hand-rolled: the boot internals are not `Debug`; the identity is the one diagnostic
/// a `{:?}` needs.
impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("endpoint_id", &self.endpoint_id())
            .finish_non_exhaustive()
    }
}

impl Node {
    /// A control connection to THIS node: the same typed `mcpmesh-local/1` client a
    /// sidecar consumer gets from `connect_control_default`, over an in-memory pipe.
    /// Cheap; open one per concurrent conversation — a session/stream upgrade
    /// (`open_session`, `subscribe`) consumes its connection, exactly as on the socket.
    pub async fn control(&self) -> Result<ControlClient, ClientError> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server_io);
        let state = self.booted.state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_control_io(server_read, server_write, state).await {
                tracing::debug!(%e, "in-process control connection ended");
            }
        });
        let (client_read, client_write) = tokio::io::split(client_io);
        connect_control_io(client_read, client_write).await
    }

    /// This node's mesh identity — what a peer's invite/pair flow binds to.
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.mesh().endpoint.id()
    }

    /// Resolves once shutdown has been requested — by [`shutdown`](Node::shutdown) from
    /// another handle, or by the control protocol's `shutdown` verb (e.g. an operator
    /// driving this node's control connection).
    pub async fn wait(&self) {
        self.booted.state.shutdown_requested().await;
    }

    /// Stop serving: raise the shutdown signal, stop the accept/poll/background loops,
    /// and close the endpoint (a graceful QUIC close — live sessions end cleanly).
    pub async fn shutdown(self) {
        let state = &self.booted.state;
        state.request_shutdown();
        let mesh = self
            .booted
            .state
            .mesh()
            .expect("a started Node always owns a mesh")
            .clone();
        if let Some(task) = mesh.accept_task.lock().await.take() {
            task.abort();
        }
        if let Some(task) = mesh.poll_loop.lock().await.take() {
            task.abort();
        }
        for task in self.booted.background {
            task.abort();
        }
        mesh.endpoint.close().await;
    }

    fn mesh(&self) -> &Arc<crate::daemon::MeshState> {
        self.booted
            .state
            .mesh()
            .expect("a started Node always owns a mesh")
    }
}
