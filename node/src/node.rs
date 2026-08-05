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
use crate::daemon::boot::{BootOverrides, BootedNode, start_node};
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
    identity_conflict: Option<std::sync::Arc<crate::diag::IdentityConflict>>,
    overrides: BootOverrides,
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
            identity_conflict: None,
            overrides: BootOverrides::default(),
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

    /// Share the duplicate-identity observation with the host's `tracing` subscriber (#134).
    ///
    /// Two nodes booted from COPIES of one mesh root present the same endpoint id; the relay can
    /// serve only one, and the displaced node's peers go unreachable with nothing saying why. iroh
    /// 1.0.3 exposes that report **only as a log event**, so detecting it needs a layer in the
    /// process's subscriber — and an embedded node cannot install one, because the subscriber is
    /// global and your application owns it.
    ///
    /// Pass the SAME `Arc` you gave [`IdentityConflictLayer`](crate::diag::IdentityConflictLayer),
    /// so that what the layer records is what this node's `status` reports:
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use tracing_subscriber::prelude::*;
    /// use mcpmesh_node::diag::{IdentityConflict, IdentityConflictLayer};
    ///
    /// let conflict = Arc::new(IdentityConflict::default());
    /// tracing_subscriber::registry()
    ///     .with(my_fmt_layer)
    ///     .with(IdentityConflictLayer::new(conflict.clone()))
    ///     .init();
    ///
    /// let node = NodeBuilder::new(root).identity_conflict(conflict).start().await?;
    /// ```
    ///
    /// Without it, `status.self_network.identity_conflict_epoch` is always absent — which means
    /// "not observable here", NOT "this identity is unique". Nothing else changes: the node boots,
    /// serves, and behaves identically either way.
    pub fn identity_conflict(
        mut self,
        shared: std::sync::Arc<crate::diag::IdentityConflict>,
    ) -> Self {
        self.identity_conflict = Some(shared);
        self
    }

    /// Run as `key` instead of reading (or minting) `<root>/config/device.key` (#85).
    ///
    /// **What this is for.** The default posture is 32 raw ed25519 secret bytes at 0600, in a
    /// directory the node owns — no passphrase, no keychain, no hardware seam. An embedder could
    /// not fix that from outside: the file is inside the mesh root it is told not to hand-write,
    /// and there was no way to supply a decrypted key at boot. This is that way — unwrap the key
    /// from wherever your platform keeps secrets and hand it over.
    ///
    /// **When set, no DEVICE key file is read, minted, or written.** So that secret never lands on
    /// disk. (The node still mints `<root>/config/user.key` — the pairing-identity key — which this
    /// seam does not cover; #85 asks 2-3 are about that one and are not shipped.) The on-disk key
    /// never exists to be
    /// stolen — and a node whose embedder holds the key cannot silently fall back to a file one,
    /// which would boot happily under a DIFFERENT identity and leave every peer unable to reach it.
    ///
    /// **Custody moves to you.** mcpmesh cannot recover this identity if you lose the key: there is
    /// no escrow and no recovery path (#85 asks 2-3, not shipped). It is also the identity every
    /// peer pinned at pairing, so replacing it makes this node a stranger to all of them.
    ///
    /// The key must stay STABLE across restarts of the same node — passing a fresh one each boot
    /// mints a new identity every time.
    pub fn device_key(mut self, key: mcpmesh_trust::ed25519_dalek::SigningKey) -> Self {
        self.overrides.device_key = Some(key);
        self
    }

    /// Boot the node: identity, stores, gates, the iroh endpoint, and every serving loop
    /// the daemon runs. Requires a multi-thread tokio runtime (the node spawns its serving
    /// loops onto the ambient runtime). Installs a process-default rustls `CryptoProvider`
    /// (ring) if the host application has not installed one — idempotent, the host's wins.
    pub async fn start(self) -> Result<Node, StartError> {
        let paths = NodePaths::under_root(&self.root);
        let booted = start_node(paths, self.config, self.overrides).await?;
        // #134: adopt the host's shared observation, so the layer IN THEIR subscriber and this
        // node's `status` read the same cell. Set after boot rather than threaded through it —
        // the field is only ever read by the status projection, never during construction.
        if let (Some(shared), Some(mesh)) = (self.identity_conflict, booted.state.mesh()) {
            mesh.adopt_identity_conflict(shared);
        }
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
        let track_state = state.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = serve_control_io(server_read, server_write, state).await {
                tracing::debug!(%e, "in-process control connection ended");
            }
        });
        // Tracked like a socket connection's serving task (`serve_control`'s per-connection
        // spawn): without this, an attached `subscribe()` stream never notices `shutdown` (see
        // `Node::shutdown`) and outlives the node, holding its `Arc<DaemonState>`/mesh/redb lock
        // open.
        track_state.track_control_task(handle);
        let (client_read, client_write) = tokio::io::split(client_io);
        connect_control_io(client_read, client_write).await
    }

    /// This node's mesh identity — what a peer's invite/pair flow binds to.
    pub fn endpoint_id(&self) -> iroh::EndpointId {
        self.mesh().endpoint.id()
    }

    /// Serve a custom protocol on `alpn`, through this node's existing trust gate (#67).
    ///
    /// **What this is for.** mcpmesh has already built the hard parts of a P2P application
    /// platform — identity, pairing, a trust gate, relay fallback, discovery, rate limiting, a
    /// connection registry — and exposes one protocol shape on top: request/response MCP over
    /// bi-streams. Anything that does not fit (realtime media wanting datagrams, efficient bulk
    /// transfer, an app-level overlay) was out of reach however well the identity layer suited it.
    /// The alternative was a SECOND endpoint with a second identity, which discards the gate, the
    /// pairing relationship and the relay config — and makes your users pair twice.
    ///
    /// **Your handler runs behind the same gate as every built-in protocol.** An unauthorized or
    /// revoked peer is closed before `accept` is called; the connection is entered in the registry,
    /// so revoking that peer SEVERS it mid-protocol rather than waiting for it to end. You get the
    /// authenticated `EndpointId` from `connection.remote_id()`, and it is the same identity
    /// `_meta["mcpmesh/peer"]` names on the MCP path.
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use mcpmesh_node::iroh;
    ///
    /// #[derive(Debug)]
    /// struct MyProto;
    ///
    /// impl iroh::protocol::ProtocolHandler for MyProto {
    ///     async fn accept(
    ///         &self,
    ///         conn: iroh::endpoint::Connection,
    ///     ) -> Result<(), iroh::protocol::AcceptError> {
    ///         let _peer = conn.remote_id(); // the AUTHENTICATED caller
    ///         Ok(())
    ///     }
    /// }
    ///
    /// # fn f(node: &mcpmesh_node::Node) -> anyhow::Result<()> {
    /// node.accept_protocol(b"app/myproto/1", Arc::new(MyProto))?;
    /// # Ok(()) }
    /// ```
    ///
    /// **The `mcpmesh/` prefix is reserved** and registering under it is an error — the accept loop
    /// dispatches its own protocols by exact ALPN before consulting this registry, so a handler
    /// there would be silently dead, and one on a name mcpmesh adds later would flip from working
    /// to dead on an upgrade. `app/…` is the suggested convention.
    ///
    /// **Takes effect for connections negotiated from now on.** ALPN is chosen at handshake, so a
    /// peer already connected cannot use the new protocol. Register during startup, before you
    /// announce the node as ready, unless that is genuinely what you want.
    ///
    /// Registering the same `alpn` twice replaces the handler; connections already running under
    /// the old one continue on it.
    pub fn accept_protocol(
        &self,
        alpn: &[u8],
        handler: Arc<dyn iroh::protocol::DynProtocolHandler>,
    ) -> anyhow::Result<()> {
        self.mesh().register_app_protocol(alpn, handler)
    }

    /// This node's currently-dialable address (#67) — its endpoint id plus whatever direct
    /// addresses and relay it has, exactly what a pairing invite embeds.
    ///
    /// For handing an address to a peer OUT-OF-BAND, when your application has its own channel for
    /// that and does not want a pairing invite. Carries transport vocabulary by nature, which is
    /// why it is a typed accessor rather than anything on the control surface.
    ///
    /// A snapshot: addresses change as the network does, and immediately after boot it may hold
    /// only local ones. It authorizes nothing — a peer dialling this still faces the trust gate.
    pub fn endpoint_addr(&self) -> iroh::EndpointAddr {
        self.mesh().endpoint.addr()
    }

    /// Dial `peer` on a custom `alpn` — the client half of [`accept_protocol`](Self::accept_protocol)
    /// (#67).
    ///
    /// `peer` may be a paired nickname, a `b64u:` user_id, an `eid:` device principal, or — in
    /// roster mode — a rostered user_id. That resolution, plus the stored dial-address hint and
    /// this node's relay configuration, is most of what makes this worth using over a raw endpoint:
    /// an embedder holding only "alice" has no way to turn that into an address, and one that stood
    /// up its own endpoint would not have the pairing that produced it.
    ///
    /// For a person with several devices the candidates are tried IN ORDER — roster candidates
    /// first, primary before mirror — and the first that connects wins. That is weaker than
    /// `open_session`'s staggered race, which this deliberately does not reproduce: racing means
    /// opening connections you then abandon, and an embedder's protocol may not be safe to
    /// half-open. Each attempt is bounded by the same `DIAL_TIMEOUT` the service dial uses, so an
    /// unreachable first device costs that timeout rather than hanging.
    ///
    /// ```no_run
    /// # async fn f(node: &mcpmesh_node::Node) -> anyhow::Result<()> {
    /// let conn = node.connect_protocol("alice", b"app/myproto/1").await?;
    /// let (send, recv) = conn.open_bi().await?;
    /// # Ok(()) }
    /// ```
    ///
    ///
    /// **This does not authorize anything.** It dials; the REMOTE side's gate decides whether to
    /// admit you, and will close the connection if you are not paired with them. Symmetrically,
    /// your own handler is protected by your gate — see `accept_protocol`.
    ///
    /// Errors when `peer` resolves to nobody, or when the dial fails. A peer that is simply offline
    /// is a dial failure, not a distinct condition.
    pub async fn connect_protocol(
        &self,
        peer: &str,
        alpn: &[u8],
    ) -> anyhow::Result<iroh::endpoint::Connection> {
        let mesh = self.mesh();
        let candidates = crate::daemon::dial::protocol_candidates(mesh, peer).await?;
        anyhow::ensure!(
            !candidates.is_empty(),
            "no peer '{peer}' — 'status' lists your peers and roster members"
        );
        let mut last: Option<anyhow::Error> = None;
        for endpoint_id in candidates {
            let Ok(id) = iroh::EndpointId::from_bytes(&endpoint_id) else {
                continue; // a corrupt stored id is skipped, not fatal — another device may work
            };
            // The stored last-addr hint, attached exactly as the service dial attaches it. It is
            // what lets a hermetic/localhost mesh with no discovery reach a peer it has never
            // dialled, and a hint recorded for a DIFFERENT id is discarded rather than dialled.
            let store = mesh.store.clone();
            let entry = crate::util::blocking("join connect_protocol store read", move || {
                store.resolve(&endpoint_id)
            })
            .await??;
            let addr = crate::daemon::dial::stored_dial_addr(
                entry.and_then(|e| e.last_addr).as_deref(),
                id,
            );
            // Bounded, like every other dial in the codebase: an unreachable candidate must cost a
            // timeout, not the caller's future.
            match tokio::time::timeout(
                crate::daemon::dial::DIAL_TIMEOUT,
                mesh.endpoint.connect(addr, alpn),
            )
            .await
            {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last = Some(anyhow::Error::new(e)),
                Err(_) => last = Some(anyhow::anyhow!("dial timed out")),
            }
        }
        Err(match last {
            Some(e) => e.context(format!("dial '{peer}' on a custom protocol")),
            None => anyhow::anyhow!("dial '{peer}' on a custom protocol: no usable candidate"),
        })
    }

    /// Sign an application payload with this node's DEVICE key, under the embedder's own
    /// `domain` (#59).
    ///
    /// **What this is for.** mcpmesh authenticates the transport: inside a session,
    /// `_meta["mcpmesh/peer"]` says who is calling. That answers nothing about a payload which
    /// outlives its connection — anything store-and-forward (offline delivery, a relay, a mailbox,
    /// an app-level overlay) handles bytes whose author is not the peer that delivered them, and
    /// the transport authenticated the FORWARDER. This attributes the ORIGIN, against the same
    /// identity the transport already proves, so an embedder needs no second key, no second
    /// backup/revocation story, and no binding protocol tying the two together.
    ///
    /// **`domain` is yours; pick one per statement KIND** (`b"chat/message/1"`,
    /// `b"mailbox/receipt/1"`). A signature is only as narrow as its domain, and sharing one across
    /// two shapes lets a value from either be read as the other. mcpmesh's own domains are out of
    /// reach whatever you choose — see [`mcpmesh_trust::app`] for why that is a property of the
    /// preimage rather than of your discipline.
    ///
    /// Verify with [`verify_app`](Self::verify_app), which needs no node.
    ///
    /// **Not a control verb, deliberately.** Signing over the JSON-RPC socket would put the device
    /// key's authority behind an IPC surface shared by every consumer of that socket. This is an
    /// in-process seam for the embedder that owns the node.
    pub fn sign_app(&self, domain: &[u8], msg: &[u8]) -> [u8; 64] {
        // Derived from the endpoint rather than held as a field: the signing key is then the one
        // whose public half IS `endpoint_id()`, by construction. A separately-stored copy could be
        // absent or stale, and a signing API that fails open or signs under the wrong identity is
        // worse than none.
        //
        // Hardening note, the same residual `DeviceKey::secret_bytes` documents: `to_bytes()` hands
        // back a plain `[u8; 32]` that is not zeroized, and the `SigningKey` built from it is
        // scrubbed on drop but the array is not. Per call rather than once — accepted, because the
        // alternative is caching the key material for the node's whole life, which is a larger
        // residual, not a smaller one.
        let signing = mcpmesh_trust::ed25519_dalek::SigningKey::from_bytes(
            &self.mesh().endpoint.secret_key().to_bytes(),
        );
        mcpmesh_trust::sign_app(&signing, domain, msg)
    }

    /// Verify an application payload signed by `endpoint_id` under `domain` (#59).
    ///
    /// An associated function: verification needs no node, which is the point — a consumer checking
    /// a relayed payload has the peer's `EndpointId` and nothing else.
    ///
    /// Returns `false` for a bad signature, a mismatched domain/message, or malformed bytes. It
    /// never panics: every input is attacker-supplied by construction.
    ///
    /// It answers "which device produced these bytes" and nothing else. Whether that device was
    /// ENTITLED to make the statement is the embedder's authorization question, answered from the
    /// embedder's own state.
    pub fn verify_app(
        endpoint_id: &iroh::EndpointId,
        domain: &[u8],
        msg: &[u8],
        sig: &[u8; 64],
    ) -> bool {
        mcpmesh_trust::verify_app(endpoint_id.as_bytes(), domain, msg, sig)
    }

    /// Resolves once shutdown has been requested — by [`shutdown`](Node::shutdown) from
    /// another handle, or by the control protocol's `shutdown` verb (e.g. an operator
    /// driving this node's control connection).
    pub async fn wait(&self) {
        self.booted.state.shutdown_requested().await;
    }

    /// Stop serving: raise the shutdown signal, stop the accept/poll/background loops and
    /// every live control connection (subscription streams end immediately; in-flight control
    /// requests get a dropped connection — acceptable, shutdown means shutdown), and close the
    /// endpoint (a graceful QUIC close — live sessions end cleanly).
    pub async fn shutdown(self) {
        // One teardown path, shared with the boot tests (#105) so neither can drift from the other.
        crate::daemon::boot::shutdown_booted(self.booted).await;
    }

    fn mesh(&self) -> &Arc<crate::daemon::MeshState> {
        self.booted
            .state
            .mesh()
            .expect("a started Node always owns a mesh")
    }
}
