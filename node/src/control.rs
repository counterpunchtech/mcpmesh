//! Server-side mcpmesh-local/1 dispatch. On each accepted connection the SERVER
//! writes a `Hello` frame FIRST ("the first exchange ... identifies the api"), then reads
//! request frames, dispatches on the `method` string, and writes JSON-RPC-shaped response
//! frames back. Same-uid peers only (the seam's platform gate — peer-euid on unix, owner-only
//! pipe DACL on windows) — the gate runs before the hello.
//!
//! Dispatch discipline: the method is extracted with
//! [`mcpmesh_local_api::method_of`] and params are deserialized PER-METHOD into the typed
//! param structs local-api defines (`protocol.rs` — the one wire truth, so daemon/client
//! shape drift is a compile error) — never by deserializing the whole message into
//! `Request` (adjacent tagging rejects `params:{}` for parameterless methods, which a
//! conforming third-party client may send). Most verbs are plain request/response;
//! `open_session` and `subscribe` are special: after those requests the connection stops
//! being JSON-RPC and becomes a raw MCP byte pipe / a one-way event stream.
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use mcpmesh_local_api::transport::{LocalListener, LocalStream};
use mcpmesh_local_api::{
    API_NAME, API_VERSION, BlobFetchParams, BlobGrantParams, BlobPublishParams, Hello,
    InviteParams, OpenSessionParams, OrgJoinParams, PairParams, RosterInstallParams,
    SetNicknameParams, SetRosterUrlParams, StatusResult, method_of,
};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use serde_json::{Value, json};
use tokio::sync::Notify;

use crate::daemon::MeshState;
use crate::ipc::{self, MAX_FRAME_BYTES};

/// Live daemon state behind the control API. `mesh` is the endpoint + gate + serve handle
/// the real daemon owns; it is `None` in control-only construction (unit tests),
/// in which case `register_service`/`peer_add` fail gracefully. The `status` service/peer
/// lists are read LIVE from the mesh's config + store on each call — there is no cached
/// snapshot here. `shutdown` is the internal signal a `shutdown` request raises so the
/// accept loop can stop cleanly.
pub struct DaemonState {
    pub stack_version: String,
    pub(crate) mesh: Option<Arc<MeshState>>,
    shutdown: Notify,
}

impl DaemonState {
    /// Control-only state (no mesh) — used by unit tests. `register_service`/`peer_add`
    /// return an error against this construction.
    pub fn new(stack_version: impl Into<String>) -> Self {
        Self {
            stack_version: stack_version.into(),
            mesh: None,
            shutdown: Notify::new(),
        }
    }

    /// The full daemon state: the control server over the mesh half.
    ///
    /// `pub` (like [`MeshState::new`](crate::daemon::MeshState::new)) so integration tests can
    /// assemble a serving `DaemonState` around a HERMETIC `MeshState` (temp config + store +
    /// endpoint) and drive the real control handlers — e.g. the `pair --remove` test calls
    /// `daemon::remove_peer` over a state built this way, asserting on the store + config truth.
    pub fn with_mesh(stack_version: impl Into<String>, mesh: Arc<MeshState>) -> Self {
        Self {
            stack_version: stack_version.into(),
            mesh: Some(mesh),
            shutdown: Notify::new(),
        }
    }

    /// Wait until a shutdown has been requested — the control `shutdown` verb, or an
    /// embedder's `Node::shutdown`. (`notify_one` stores a permit, so a request that
    /// landed before this call still resolves it.)
    pub(crate) async fn shutdown_requested(&self) {
        self.shutdown.notified().await;
    }

    /// Raise the shutdown signal — the programmatic form of the control `shutdown` verb.
    pub(crate) fn request_shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// The mesh half, if this daemon owns an endpoint (always, except control-only tests).
    /// Returns `&Arc<MeshState>` so callers that must reload the accept loop (the pairing
    /// grant, `register_service`) can cheaply clone the shared handle.
    pub(crate) fn mesh(&self) -> Option<&Arc<MeshState>> {
        self.mesh.as_ref()
    }

    /// The mesh half, or the one control-only-mode refusal every mesh-requiring control verb
    /// answers — the single home of the "daemon has no mesh (control-only mode)" guard.
    pub(crate) fn mesh_required(&self) -> Result<&Arc<MeshState>> {
        self.mesh()
            .context("daemon has no mesh (control-only mode)")
    }
}

/// Accept control connections until a `shutdown` request stops the loop. Each connection is
/// handled in its own task so independent clients never head-of-line-block one another.
pub async fn serve_control(mut listener: LocalListener, state: Arc<DaemonState>) -> Result<()> {
    loop {
        tokio::select! {
            // `notify_one` stores a permit if the loop is momentarily between iterations, so
            // a fresh `notified()` here still resolves — the shutdown signal is never lost.
            () = state.shutdown.notified() => {
                tracing::info!("shutdown requested; control server stopping");
                return Ok(());
            }
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok(s) => s,
                    Err(e) => {
                        // Back off before retrying: a persistent accept error (e.g. EMFILE
                        // under fd exhaustion) would otherwise busy-spin the loop at 100% CPU.
                        tracing::warn!(%e, "control accept failed; backing off");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, state).await {
                        tracing::debug!(%e, "control connection ended");
                    }
                });
            }
        }
    }
}

async fn handle_conn(stream: LocalStream, state: Arc<DaemonState>) -> Result<()> {
    // Same-user gate BEFORE any frame: refuse other users pre-hello (peer-euid
    // on unix; on windows the pipe DACL already enforced this at connect). A cross-user
    // connection attempt is security-relevant, so it is logged at `warn!` here (returning Ok
    // keeps the normal clean-close path at `debug!` in `serve_control`).
    if let Err(e) = ipc::check_peer(&stream) {
        tracing::warn!(%e, "refused unauthorized control connection");
        return Ok(());
    }
    let (read_half, write_half) = mcpmesh_local_api::transport::split_local(stream);
    serve_control_io(read_half, write_half, state).await
}

/// Serve one mcpmesh-local/1 connection over ALREADY-AUTHORIZED byte halves — the
/// transport-agnostic body of `handle_conn`, and what an embedded node's in-memory
/// control connection runs (`Node::control` — a tokio duplex needs no peer gate: it
/// never leaves the process).
pub async fn serve_control_io(
    read_half: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    mut write_half: impl tokio::io::AsyncWrite + Unpin + Send + 'static,
    state: Arc<DaemonState>,
) -> Result<()> {
    // The server speaks first: a `Hello` frame identifies the api.
    let hello = Hello {
        api: API_NAME.into(),
        api_version: API_VERSION.into(),
        api_minor: mcpmesh_local_api::API_MINOR,
        stack_version: state.stack_version.clone(),
    };
    write_frame(&mut write_half, &serde_json::to_value(&hello)?).await?;

    let reader = FrameReader::new(tokio::io::BufReader::new(read_half), MAX_FRAME_BYTES);
    // NOTE: control connections carry no framing-violation strike bound (unlike the
    // mesh path in net::endpoint). Acceptable — the peer is same-uid, already inside
    // the trust boundary; a strike/close budget lands if/when this surface widens.

    // #36: names this connection registered EPHEMERALLY, torn down when it closes. Shared with
    // the request loop via an Arc so the loop (which owns `reader`/`write_half`) can record into
    // it while this frame keeps a handle to drain after the loop ends, on ANY exit path.
    let ephemeral_registered = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let loop_state = state.clone();
    let eph = ephemeral_registered.clone();
    let outcome: Result<()> = async move {
        let mut reader = reader;
        let mut write_half = write_half;
        loop {
            match reader.next().await? {
                None => return Ok(()), // client closed the connection
                Some(Inbound::Violation(v)) => {
                    // A malformed/oversized request frame carries no recoverable id: answer a
                    // JSON-RPC parse error and keep the connection open for the next frame.
                    let resp = error(Value::Null, -32700, format!("invalid request frame: {v:?}"));
                    write_frame(&mut write_half, &resp).await?;
                }
                Some(Inbound::Frame(req)) => {
                    // NOTE: the "shutdown" method string is matched here and in `dispatch`;
                    // the small duplication is deliberate (the ack shape stays in `dispatch`).
                    if method_of(&req) == Some("shutdown") {
                        // An explicit stop must ALWAYS stop: raise the shutdown signal FIRST
                        // (unconditionally), THEN best-effort ack. A client that sends `shutdown`
                        // and closes without reading the ack must still stop the daemon.
                        loop_state.shutdown.notify_one();
                        let resp = dispatch(&req, &loop_state);
                        let _ = write_frame(&mut write_half, &resp).await;
                        return Ok(());
                    }
                    if method_of(&req) == Some("open_session") {
                        // After this request the connection STOPS being JSON-RPC and becomes a raw
                        // MCP byte pipe (protocol.rs `OpenSession`): hand the framed halves to the
                        // daemon's dial + pipe, which consumes the connection for the session's
                        // lifetime. The loop cannot continue — `reader`/`write_half` move away.
                        // (A malformed params SHAPE — not merely absent fields, which default —
                        // answers an error frame and keeps the connection JSON-RPC.)
                        let params = req.get("params").cloned().unwrap_or(Value::Null);
                        let p: OpenSessionParams = match params_of(&params) {
                            Ok(p) => p,
                            Err(e) => {
                                let id = req.get("id").cloned().unwrap_or(Value::Null);
                                // Params shape error → -32602 (invalid params), matching `respond`.
                                let resp = error(id, -32602, format!("open_session failed: {e}"));
                                write_frame(&mut write_half, &resp).await?;
                                continue;
                            }
                        };
                        return crate::daemon::open_session(
                            &loop_state,
                            &p.peer,
                            &p.service,
                            reader,
                            write_half,
                        )
                        .await;
                    }
                    if method_of(&req) == Some("subscribe") {
                        // Like `open_session`, this upgrades the connection: after `subscribe` it
                        // STOPS being request/response and becomes a one-way push stream of
                        // `StreamFrame`s (`crate::stream`). The loop cannot continue — `write_half`
                        // moves into the stream driver for the subscription's lifetime.
                        return run_subscription(&loop_state, write_half).await;
                    }
                    let resp = handle_request(&req, &loop_state).await;
                    // #36: remember a SUCCESSFUL ephemeral register_service so it is torn down
                    // when this connection closes. Peeked from the request/response (register is a
                    // normal request/response verb; only these upgrade paths above are special).
                    if method_of(&req) == Some("register_service")
                        && resp.get("result").is_some()
                        && req
                            .get("params")
                            .and_then(|p| p.get("ephemeral"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        && let Some(name) = req
                            .get("params")
                            .and_then(|p| p.get("name"))
                            .and_then(|v| v.as_str())
                    {
                        eph.lock()
                            .expect("ephemeral_registered lock not poisoned")
                            .push(name.to_string());
                    }
                    write_frame(&mut write_half, &resp).await?;
                }
            }
        }
    }
    .await;

    // Teardown on ANY exit path (clean close, IO error, or the open_session/subscribe upgrades
    // returning): unregister every service this connection registered ephemerally (#36). A no-op
    // when it registered none.
    if let Some(mesh) = state.mesh() {
        let names = ephemeral_registered
            .lock()
            .expect("ephemeral_registered lock not poisoned")
            .clone();
        crate::daemon::unregister_ephemeral(mesh, &names).await;
    }
    outcome
}

/// Drive a live event stream over a subscribed control connection. Mirrors
/// [`open_session`](crate::daemon::open_session)'s upgrade: it consumes the write half for the
/// subscription's lifetime. Sends the initial [`Snapshot`](crate::stream::StreamFrame::Snapshot)
/// FIRST, then forwards every broadcast [`AuditRecord`](crate::audit::AuditRecord) as an
/// [`Event`](crate::stream::StreamFrame::Event) frame until the client disconnects.
///
/// Backpressure (spec): a subscriber that falls behind the broadcast ring surfaces as
/// `RecvError::Lagged(n)` → one [`Lagged`](crate::stream::StreamFrame::Lagged) frame, then the loop
/// CONTINUES (the subscriber is never dropped on lag). A closed broadcast → clean return. A failed
/// `write_frame` (the client is gone) → clean return. No lock is held across the `recv().await`.
///
/// When auditing is disabled (control-only daemon, or a mesh with no audit sink), `subscribe()`
/// yields `None`: the snapshot is sent and the stream ends (no events will ever flow).
async fn run_subscription(
    state: &Arc<DaemonState>,
    mut w: impl tokio::io::AsyncWrite + Unpin,
) -> Result<()> {
    use crate::stream::StreamFrame;
    // The audit sink is the telemetry hub; the mesh (if any) feeds the reachability snapshot.
    let (audit, mesh) = match state.mesh() {
        Some(mesh) => (mesh.audit(), Some(mesh)),
        None => (crate::audit::AuditSink::disabled(), None),
    };
    // Register the live receiver BEFORE snapshotting. If we snapshotted first, any record
    // broadcast in the gap between `active_sessions()` and `subscribe()` would be LOST — absent from
    // the snapshot (captured earlier) AND from the stream (receiver not yet registered), so a
    // consumer could see a `session_close` for a session it never saw open. Subscribing first turns
    // that race into an at-most-idempotent DOUBLE (a session may appear both in `active_sessions`
    // and as a live `session_open`), which a state-projecting consumer absorbs harmlessly.
    let rx = audit.subscribe();
    let snapshot = StreamFrame::Snapshot {
        active_sessions: audit.active_sessions(),
        reachability: mesh.map(crate::daemon::reachability_of).unwrap_or_default(),
    };
    write_frame(&mut w, &serde_json::to_value(&snapshot)?).await?;

    // Disabled sink → no live tap: the snapshot stands alone, then the stream ends.
    let Some(mut rx) = rx else {
        return Ok(());
    };
    use tokio::sync::broadcast::error::RecvError;
    loop {
        let frame = match rx.recv().await {
            Ok(record) => StreamFrame::Event {
                record: Box::new(record),
            },
            // Fell behind the ring: tell the subscriber, then KEEP streaming (never drop it).
            Err(RecvError::Lagged(n)) => StreamFrame::Lagged { dropped: n },
            Err(RecvError::Closed) => return Ok(()),
        };
        if write_frame(&mut w, &serde_json::to_value(&frame)?)
            .await
            .is_err()
        {
            return Ok(()); // client gone
        }
    }
}

/// Dispatch one request, handling the async control methods (`register_service`, `peer_add`)
/// that touch the config file / redb store, and delegating the parameterless synchronous
/// methods (`status`, `shutdown`) to [`dispatch`]. Params are deserialized per-method into
/// the local-api param structs via [`with_params`] (never `from_value::<Request>` on the
/// whole message).
async fn handle_request(req: &Value, state: &DaemonState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    match method_of(req) {
        Some("register_service") => respond(
            id,
            "register_service",
            with_params(&params, |p| crate::daemon::register_service(state, p))
                .await
                .map(unit),
        ),
        Some("peer_add") => respond(
            id,
            "peer_add",
            with_params(&params, |p| crate::daemon::add_peer(state, p))
                .await
                .map(unit),
        ),
        // Unpair a peer: the nickname to drop.
        // `remove_peer` revokes the peer's service authorization AND drops its identity row
        // (the inverse of the pairing grant) — see its fail-safe ordering.
        Some("peer_remove") => respond(
            id,
            "peer_remove",
            with_params(&params, |p| crate::daemon::remove_peer(state, p))
                .await
                .map(unit),
        ),
        // Rename a contact's nickname (Contacts rename): the person's `user_id` (or a
        // provisional `nickname`) + the new nickname `to`. `rename_peer` guards the collision
        // (no inheriting another identity's grants), rewrites allow lists, and reloads.
        Some("peer_rename") => respond(
            id,
            "peer_rename",
            with_params(&params, |p| crate::daemon::rename_peer(state, p))
                .await
                .map(unit),
        ),
        Some("invite") => {
            // Mint a pairing invite granting a service list ([`InviteParams`]
            // tolerates an absent list).
            let mesh = match state.mesh_required() {
                Ok(mesh) => mesh,
                Err(e) => return error(id, -32000, e.to_string()),
            };
            respond(
                id,
                "invite",
                with_params(&params, |p: InviteParams| {
                    crate::daemon::mint_invite(p.services, p.app_label, mesh)
                })
                .await,
            )
        }
        // Redeem a pairing invite: the copyable `mcpmesh-invite:` line
        // ([`PairParams`] tolerates an absent field — an empty line simply fails to decode
        // → a clean pair error).
        Some("pair") => respond(
            id,
            "pair",
            with_params(&params, |p: PairParams| {
                crate::daemon::redeem(state, p.invite_line)
            })
            .await,
        ),
        // Install a signed roster from a local file: the file `path`
        // (a local file the same-uid daemon reads) and an OPTIONAL `org_root_pk`
        // that pins the org root on first install. `install_roster` validates (rules 1–6),
        // persists, hot-swaps the gate, and severs revoked sessions.
        Some("roster_install") => respond(
            id,
            "roster_install",
            with_params(&params, |p: RosterInstallParams| {
                crate::daemon::install_roster(state, p.path, p.org_root_pk)
            })
            .await,
        ),
        // Pin the org root on a JOINER without a roster. `user_key` is
        // a LOCAL path (the key never crosses the API). `org_join` validates the pk BEFORE
        // writing, then surgically pins the four `[identity]` keys under `reload_lock`. No
        // roster is installed.
        Some("org_join") => respond(
            id,
            "org_join",
            with_params(&params, |p: OrgJoinParams| {
                crate::daemon::org_join(state, p.org_id, p.org_root_pk, p.user_id, p.user_key)
            })
            .await,
        ),
        // Pin the HTTPS roster URL (`[roster].url`) in config. Written by
        // `org create --roster-url` (operator) and by `join` when the org invite carries one
        // (the joiner's FIRST-roster bootstrap). `set_roster_url` writes it atomically
        // under `reload_lock` (single-writer).
        Some("set_roster_url") => respond(
            id,
            "set_roster_url",
            with_params(&params, |p: SetRosterUrlParams| {
                crate::daemon::set_roster_url(state, p.url)
            })
            .await
            .map(unit),
        ),
        // Rename this node LIVE (#37): validated + persisted under `reload_lock`, then the
        // in-memory name updates — future invites present it immediately, no restart.
        Some("set_nickname") => respond(
            id,
            "set_nickname",
            with_params(&params, |p: SetNicknameParams| {
                crate::daemon::set_nickname(state, p.nickname)
            })
            .await
            .map(unit),
        ),
        Some("blob_publish") => respond(
            id,
            "blob_publish",
            with_params(&params, |p: BlobPublishParams| {
                crate::daemon::blob_publish(state, p.scope, p.path)
            })
            .await,
        ),
        Some("blob_grant") => respond(
            id,
            "blob_grant",
            with_params(&params, |p: BlobGrantParams| {
                crate::daemon::blob_grant(state, p.scope, p.principal)
            })
            .await
            .map(unit),
        ),
        Some("blob_list") => respond(id, "blob_list", crate::daemon::blob_list(state).await),
        Some("blob_fetch") => respond(
            id,
            "blob_fetch",
            with_params(&params, |p: BlobFetchParams| {
                crate::daemon::blob_fetch(state, p.ticket, p.dest_path)
            })
            .await,
        ),
        Some("audit_summary") => {
            // Summarize THIS node's LOCAL audit log: read the daemon's OWN
            // audit dir off the runtime (spawn_blocking — the fs house rule) and aggregate to
            // per-peer / per-service session counts. Never touches the network; params are ignored
            // (parameterless, like `status`). Works in control-only mode (an empty/absent dir → an
            // empty summary). The dir is THE one this node's audit writer was spawned over
            // (per-node — an embedded node roots it under its own root dir); the env default
            // remains only for the mesh-less control-only mode, which has no writer to ask.
            let sink_dir = state
                .mesh
                .as_ref()
                .and_then(|m| m.audit().dir().map(std::path::Path::to_path_buf));
            match tokio::task::spawn_blocking(move || {
                let dir = match sink_dir {
                    Some(d) => d,
                    None => mcpmesh_trust::paths::default_audit_dir()?,
                };
                crate::audit::read_all_records(&dir)
                    .map(|recs| crate::audit::summarize_sessions(&recs))
            })
            .await
            {
                Ok(r) => respond(id, "audit_summary", r.map_err(anyhow::Error::from)),
                Err(e) => error(id, -32000, format!("audit_summary task failed: {e}")),
            }
        }
        _ => dispatch(req, state),
    }
}

/// A params-deserialization failure, distinguished from a handler failure so [`respond`] can map
/// it to the JSON-RPC standard `-32602` "invalid params" (a param typo / unknown field / bad shape
/// is the caller's error), while a handler failure stays `-32000`. Carried through the shared
/// `anyhow::Result` surface and recovered by downcast.
#[derive(Debug)]
struct InvalidParams(String);
impl std::fmt::Display for InvalidParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for InvalidParams {}

/// Fold one control call's `Result` into the JSON-RPC response frame — the boilerplate every
/// dispatch arm shared: `Ok(v)` → `{"result": v}` (a `()`-returning verb maps itself to `json!({})`
/// via [`unit`] first), a params error → `-32602`, any other `Err(e)` → `-32000`, both with the
/// `"{method} failed: {e}"` message shape every arm used.
fn respond<T: serde::Serialize>(id: Value, method: &str, r: anyhow::Result<T>) -> Value {
    match r {
        Ok(v) => ok(
            id,
            serde_json::to_value(v).expect("control result serializes"),
        ),
        Err(e) if e.downcast_ref::<InvalidParams>().is_some() => {
            error(id, -32602, format!("{method} failed: {e}"))
        }
        Err(e) => error(id, -32000, format!("{method} failed: {e}")),
    }
}

/// Map a `()`-returning control verb's success to the empty-object result the wire always carried
/// (`serde_json::to_value(())` would yield `null`, not `{}`).
fn unit((): ()) -> Value {
    json!({})
}

/// Dispatch one control request on its `method` string (never `from_value::<Request>` on
/// the whole message — that rejects `params:{}` for parameterless methods). Returns a
/// JSON-RPC-shaped response frame. Params are read per-method; the methods dispatched here
/// are parameterless, so `status` ignores whatever `params` shape the client sent (omitted
/// / null / `{}` all answered) — the tolerance a third-party client depends on.
fn dispatch(req: &Value, state: &DaemonState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    match method_of(req) {
        Some("status") => respond(id, "status", status_result(state)),
        Some("shutdown") => ok(id, json!({})),
        Some(other) => error(id, -32601, format!("unknown method: {other}")),
        None => error(id, -32600, "request is missing a `method`"),
    }
}

pub(crate) fn status_result(state: &DaemonState) -> Result<StatusResult> {
    // Services + peers are read LIVE from the mesh's config + store (like `roster`/`presence`
    // below) — there is no cached snapshot: the pairing grant (grant_service_access) and the
    // rendezvous PeerEntry write land durably without touching `DaemonState`, so only a live
    // read shows a just-paired peer / its grant immediately. A live read is always-current and
    // cheap (status is a human-invoked command). An unreadable config is an explicit ERROR —
    // never silently-stale data. A control-only daemon (no mesh → no config/store to read)
    // answers empty lists.
    // The config is loaded ONCE per status call and shared by the live service list AND
    // `roster_status` (which reads only the pinned org anchor from it) — the host polls status,
    // so a load-twice would be a real per-poll cost.
    let (services, peers, roster) = match state.mesh() {
        Some(mesh) => {
            let cfg = crate::config::Config::load(&mesh.config_path).map_err(|e| {
                anyhow::anyhow!("config unreadable at {}: {e}", mesh.config_path.display())
            })?;
            // Roster status is computed LIVE from `mesh.roster.view()` (never a cached snapshot —
            // the gate view is already hot-swapped on install; a live read is cheap + always-
            // current). A pure-pairing daemon (no mesh, or an empty roster gate) yields None → no
            // roster block.
            let roster = crate::daemon::roster_status(mesh, Some(&cfg));
            let ephemeral = mesh
                .ephemeral_services
                .lock()
                .expect("ephemeral_services lock not poisoned")
                .clone();
            (
                crate::daemon::service_infos(&cfg, &ephemeral),
                crate::daemon::peer_infos(&mesh.store),
                roster,
            )
        }
        None => (Vec::new(), Vec::new(), None),
    };
    // Advisory presence read: the installed roster's devices joined with the live
    // presence table (online = a non-expired heartbeat). ADVISORY — a display convenience; a device
    // with no heartbeat is `online: false` yet still a dial candidate. Empty (→ omitted) without a
    // roster. Surface-clean: flat vocabulary only (user_id/device_label/role/online).
    let presence = state
        .mesh()
        .map(crate::daemon::presence_peers)
        .unwrap_or_default();
    // This daemon's own self-sovereign user_id (`b64u:<user_pk>`), read from its precomputed
    // self-binding (auto-minted at boot; shared by pairing + roster mode). `None` in a control-only
    // daemon or when no user key exists.
    let self_user_id = state
        .mesh()
        .and_then(|mesh| mesh.self_binding())
        .map(|binding| binding.user_pk);
    // Recent inviter-side pairing completions (display-only ceremony aids, newest first):
    // a snapshot of the mesh's in-memory ring. Empty in a control-only daemon and after a
    // restart (in-memory by design — not trust data).
    let recent_pairings = state
        .mesh()
        .map(|mesh| mesh.recent_pairings())
        .unwrap_or_default();
    // Advisory reachability of paired peers, from the on-demand probe cache (spec: pairing-mode
    // liveness). Mirrors the `presence` read above: cached values returned immediately, with any
    // stale/missing entry refreshed on a background probe `reachability_of` spawns — status stays a
    // non-blocking hot path. Surface-clean: nicknames + numbers only.
    let reachability = state
        .mesh()
        .map(crate::daemon::reachability_of)
        .unwrap_or_default();
    Ok(StatusResult {
        stack_version: state.stack_version.clone(),
        services,
        peers,
        roster,
        presence,
        self_user_id,
        recent_pairings,
        reachability,
        // The EFFECTIVE self-nickname (live — reflects a `set_nickname` immediately);
        // empty in mesh-less control-only mode, which the additive field skips.
        self_nickname: state
            .mesh()
            .map(|mesh| mesh.self_nickname())
            .unwrap_or_default(),
    })
}

/// Deserialize a request's `params` into a method's typed param struct — the local-api wire
/// truth (`protocol.rs`), so param-shape drift between the daemon and its clients is a compile
/// error, not silent divergence. Omitted/`null` params read as `{}`, preserving the leniency
/// for methods whose params are all defaultable (`invite`, `pair`, `open_session`).
fn params_of<T: serde::de::DeserializeOwned>(params: &Value) -> anyhow::Result<T> {
    let v = match params {
        Value::Null => json!({}),
        p => p.clone(),
    };
    serde_json::from_value(v)
        .map_err(|e| anyhow::Error::new(InvalidParams(format!("invalid params: {e}"))))
}

/// The shared parse-then-handle shape of every param-carrying dispatch arm: deserialize
/// `params` into the method's typed struct ([`params_of`]) and run the handler on it. A parse
/// failure folds into the same anyhow error surface as a handler failure (→ `-32000` via
/// [`respond`]).
async fn with_params<P, R, F>(params: &Value, f: impl FnOnce(P) -> F) -> anyhow::Result<R>
where
    P: serde::de::DeserializeOwned,
    F: Future<Output = anyhow::Result<R>>,
{
    f(params_of(params)?).await
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_only() -> Arc<DaemonState> {
        Arc::new(DaemonState::new("0.1.0-test"))
    }
    fn req(method: &str, params: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    /// The transport-agnostic serve body speaks full mcpmesh-local/1 over a plain duplex —
    /// what an embedded node's `Node::control` runs (no socket, no peer gate: the pipe
    /// never leaves the process). Proves hello + a typed request round-trip end to end
    /// against the REAL `connect_control_io` client.
    #[tokio::test]
    async fn serve_control_io_speaks_the_protocol_over_a_duplex() {
        let state = control_only();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (sr, sw) = tokio::io::split(server_io);
        tokio::spawn(serve_control_io(sr, sw, state));
        let (cr, cw) = tokio::io::split(client_io);
        let mut client = mcpmesh_local_api::connect_control_io(cr, cw)
            .await
            .expect("hello handshake");
        assert_eq!(client.hello().stack_version, "0.1.0-test");
        let status = client.status().await.expect("status");
        assert_eq!(status.stack_version, "0.1.0-test");
        assert!(status.services.is_empty());
    }

    /// `status` on a control-only daemon answers version + empty service/peer lists and no
    /// roster/presence block. Exercises `status_result`'s no-mesh branch.
    #[test]
    fn dispatch_status_answers_empty_lists_without_a_mesh() {
        let st = control_only();
        let r = dispatch(&req("status", json!({})), &st);
        assert_eq!(r["result"]["stack_version"], "0.1.0-test");
        assert!(r["result"]["peers"].as_array().unwrap().is_empty());
        assert!(r["result"]["services"].as_array().unwrap().is_empty());
        assert!(r["result"]["roster"].is_null());
    }

    /// `status` tolerates whatever `params` shape a third-party client sends (omitted / null / {}) —
    /// the parameterless-method leniency the spec guarantees.
    #[test]
    fn dispatch_status_tolerates_any_params_shape() {
        let st = control_only();
        for p in [json!({}), Value::Null, json!({ "junk": true })] {
            assert!(dispatch(&req("status", p), &st).get("result").is_some());
        }
        // Params omitted entirely.
        let omitted = json!({ "jsonrpc": "2.0", "id": 1, "method": "status" });
        assert!(dispatch(&omitted, &st).get("result").is_some());
    }

    #[test]
    fn dispatch_shutdown_acks_and_unknown_methods_error() {
        let st = control_only();
        assert_eq!(
            dispatch(&req("shutdown", json!({})), &st)["result"],
            json!({})
        );
        // An unimplemented method → -32601.
        assert_eq!(
            dispatch(&req("frobnicate", json!({})), &st)["error"]["code"],
            -32601
        );
        // A request missing a `method` → -32600.
        let no_method = json!({ "jsonrpc": "2.0", "id": 1 });
        assert_eq!(dispatch(&no_method, &st)["error"]["code"], -32600);
    }

    /// Every mesh-requiring control method fails GRACEFULLY (a -32000 error, never a panic) in
    /// control-only mode — the per-method error arms of `handle_request`.
    #[tokio::test]
    async fn mesh_methods_error_gracefully_without_a_mesh() {
        let st = control_only();
        for method in [
            "register_service",
            "peer_add",
            "peer_remove",
            "peer_rename",
            "invite",
            "pair",
            "roster_install",
            "org_join",
            "set_roster_url",
            "blob_publish",
            "blob_grant",
            "blob_list",
            "blob_fetch",
        ] {
            let r = handle_request(&req(method, json!({})), &st).await;
            // Graceful error, never a panic or a success. With empty params, a method whose
            // params carry required fields is rejected at parse (-32602, #34); a method whose
            // params are all defaultable reaches the handler and reports the missing mesh
            // (-32000). Both are clean errors — assert it's one of the two and never a result.
            let code = r["error"]["code"].as_i64();
            assert!(
                matches!(code, Some(-32000) | Some(-32602)),
                "method {method} should error gracefully in control-only mode, got {r}"
            );
            assert!(
                r.get("result").is_none(),
                "method {method} must not succeed: {r}"
            );
        }
    }

    /// A param-carrying method with a malformed `params` shape answers a `-32000` error whose
    /// message carries the invalid-params detail — the typed per-method deserialization into the
    /// local-api param structs (never a panic, and the connection-level envelope stays lenient).
    #[tokio::test]
    async fn malformed_params_answer_an_invalid_params_error() {
        let st = control_only();
        // Wrong field type (nickname must be a string) → the JSON-RPC standard -32602
        // "invalid params" (#34: params shape errors are the caller's error, distinct from a
        // handler failure's -32000).
        let r = handle_request(&req("peer_remove", json!({ "nickname": 42 })), &st).await;
        assert_eq!(r["error"]["code"], -32602);
        assert!(
            r["error"]["message"]
                .as_str()
                .unwrap()
                .contains("invalid params"),
            "message names the params problem: {r}"
        );
        // Missing required field → also -32602.
        let r = handle_request(&req("peer_rename", json!({ "user_id": "u" })), &st).await;
        assert_eq!(r["error"]["code"], -32602);
        // An unknown field is now rejected too (deny_unknown_fields), not silently ignored.
        let r = handle_request(
            &req("peer_remove", json!({ "nickname": "a", "extra": true })),
            &st,
        )
        .await;
        assert_eq!(
            r["error"]["code"], -32602,
            "unknown params field is rejected: {r}"
        );
    }

    /// `audit_summary` works WITHOUT a mesh (a local-only read; an empty/absent audit dir yields an
    /// empty summary) — the one non-parameterless method answerable in control-only mode.
    #[tokio::test]
    async fn audit_summary_works_in_control_only_mode() {
        let st = control_only();
        let r = handle_request(&req("audit_summary", json!({})), &st).await;
        assert!(
            r.get("result").is_some(),
            "audit_summary should succeed: {r}"
        );
    }

    /// `handle_request` delegates the parameterless synchronous methods to `dispatch`.
    #[tokio::test]
    async fn handle_request_delegates_status_to_dispatch() {
        let st = control_only();
        let r = handle_request(&req("status", json!({})), &st).await;
        assert_eq!(r["result"]["stack_version"], "0.1.0-test");
    }
}
