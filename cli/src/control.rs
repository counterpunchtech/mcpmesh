//! Server-side mcpmesh-local/1 dispatch (spec §6.1). On each accepted connection the SERVER
//! writes a `Hello` frame FIRST ("the first exchange ... identifies the api"), then reads
//! request frames, dispatches on the `method` string, and writes JSON-RPC-shaped response
//! frames back. Same-uid peers only — the peer-uid gate runs before the hello.
//!
//! Dispatch discipline (Task 1 carry-forward): the method is extracted with
//! [`mcpmesh_local_api::method_of`] and params are read PER-METHOD — never by deserializing
//! the whole message into `Request` (adjacent tagging rejects `params:{}` for
//! parameterless methods, which a conforming third-party client may send). M2a answers
//! `status`, `register_service`/`peer_add` (Task 9), and an internal `shutdown`.
//! `open_session` (Task 10) is special: after that request the connection stops being
//! JSON-RPC and becomes a raw MCP byte pipe the daemon dials + pumps (spec §8).
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use mcpmesh_local_api::{
    API_NAME, API_VERSION, Hello, PeerInfo, ServiceInfo, StatusResult, method_of,
};
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
use serde_json::{Value, json};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

use crate::daemon::MeshState;
use crate::ipc::{self, MAX_FRAME_BYTES};

/// Live daemon state behind the control API. `services`/`peers` are the `status` snapshots,
/// refreshed by `register_service`/`peer_add`. `mesh` is the endpoint + gate + serve handle
/// the real daemon owns (Task 9); it is `None` in control-only construction (unit tests),
/// in which case `register_service`/`peer_add` fail gracefully. `shutdown` is the internal
/// signal a `shutdown` request raises so the accept loop can stop cleanly.
pub struct DaemonState {
    pub stack_version: String,
    pub services: RwLock<Vec<ServiceInfo>>,
    pub peers: RwLock<Vec<PeerInfo>>,
    pub(crate) mesh: Option<Arc<MeshState>>,
    shutdown: Notify,
}

impl DaemonState {
    /// Control-only state (no mesh) — used by unit tests. `register_service`/`peer_add`
    /// return an error against this construction.
    pub fn new(stack_version: impl Into<String>) -> Self {
        Self {
            stack_version: stack_version.into(),
            services: RwLock::new(Vec::new()),
            peers: RwLock::new(Vec::new()),
            mesh: None,
            shutdown: Notify::new(),
        }
    }

    /// The full daemon state: control snapshots + the mesh half (Task 9).
    ///
    /// `pub` (like [`MeshState::new`](crate::daemon::MeshState::new)) so integration tests can
    /// assemble a serving `DaemonState` around a HERMETIC `MeshState` (temp config + store +
    /// endpoint) and drive the real control handlers — e.g. the M2b `pair --remove` test calls
    /// `daemon::remove_peer` over a state built this way, asserting on the store + config truth.
    pub fn with_mesh(
        stack_version: impl Into<String>,
        mesh: Arc<MeshState>,
        services: Vec<ServiceInfo>,
        peers: Vec<PeerInfo>,
    ) -> Self {
        Self {
            stack_version: stack_version.into(),
            services: RwLock::new(services),
            peers: RwLock::new(peers),
            mesh: Some(mesh),
            shutdown: Notify::new(),
        }
    }

    /// The mesh half, if this daemon owns an endpoint (always, except control-only tests).
    /// Returns `&Arc<MeshState>` so callers that must reload the accept loop (the pairing
    /// grant, `register_service`) can cheaply clone the shared handle.
    pub(crate) fn mesh(&self) -> Option<&Arc<MeshState>> {
        self.mesh.as_ref()
    }
}

/// Accept control connections until a `shutdown` request stops the loop. Each connection is
/// handled in its own task so independent clients never head-of-line-block one another.
pub async fn serve_control(listener: UnixListener, state: Arc<DaemonState>) -> Result<()> {
    loop {
        tokio::select! {
            // `notify_one` stores a permit if the loop is momentarily between iterations, so
            // a fresh `notified()` here still resolves — the shutdown signal is never lost.
            () = state.shutdown.notified() => {
                tracing::info!("shutdown requested; control server stopping");
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _addr) = match accepted {
                    Ok(pair) => pair,
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

async fn handle_conn(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    // Same-uid gate BEFORE any frame (spec §11.2 P12): refuse other users pre-hello. A
    // cross-uid connection attempt is security-relevant, so it is logged at `warn!` here
    // (returning Ok keeps the normal clean-close path at `debug!` in `serve_control`).
    if let Err(e) = ipc::check_peer_uid(&stream) {
        tracing::warn!(%e, "refused control connection from a different uid");
        return Ok(());
    }
    let (read_half, mut write_half) = stream.into_split();

    // The server speaks first: a `Hello` frame identifies the api (spec §6.1).
    let hello = Hello {
        api: API_NAME.into(),
        api_version: API_VERSION.into(),
        stack_version: state.stack_version.clone(),
    };
    write_frame(&mut write_half, &serde_json::to_value(&hello)?).await?;

    let mut reader = FrameReader::new(tokio::io::BufReader::new(read_half), MAX_FRAME_BYTES);
    // M2a note: control connections carry no framing-violation strike bound (unlike the
    // mesh path in net::endpoint). Acceptable for M2a — the peer is same-uid, already
    // trusted under P12/P14; a strike/close budget lands if/when this surface widens.
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
                // M2a note: the "shutdown" method string is matched here and in `dispatch`;
                // the small duplication is acceptable for M2a.
                if method_of(&req) == Some("shutdown") {
                    // An explicit stop must ALWAYS stop: raise the shutdown signal FIRST
                    // (unconditionally), THEN best-effort ack. A client that sends `shutdown`
                    // and closes without reading the ack must still stop the daemon.
                    state.shutdown.notify_one();
                    let resp = dispatch(&req, &state);
                    let _ = write_frame(&mut write_half, &resp).await;
                    return Ok(());
                }
                if method_of(&req) == Some("open_session") {
                    // After this request the connection STOPS being JSON-RPC and becomes a raw
                    // MCP byte pipe (protocol.rs `OpenSession`): hand the framed halves to the
                    // daemon's dial + pipe, which consumes the connection for the session's
                    // lifetime. The loop cannot continue — `reader`/`write_half` move away.
                    let params = req.get("params").cloned().unwrap_or(Value::Null);
                    let peer = str_param(&params, "peer");
                    let service = str_param(&params, "service");
                    return crate::daemon::open_session(
                        &state, &peer, &service, reader, write_half,
                    )
                    .await;
                }
                if method_of(&req) == Some("subscribe") {
                    // Like `open_session`, this upgrades the connection: after `subscribe` it STOPS
                    // being request/response and becomes a one-way push stream of `StreamFrame`s
                    // (`crate::stream`). The loop cannot continue — `write_half` moves into the
                    // stream driver, which consumes the connection for the subscription's lifetime.
                    return run_subscription(&state, write_half).await;
                }
                let resp = handle_request(&req, &state).await;
                write_frame(&mut write_half, &resp).await?;
            }
        }
    }
}

/// Drive a live event stream over a subscribed control connection (Task 6). Mirrors
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
/// methods (`status`, `shutdown`) to [`dispatch`]. Params are read per-method (never
/// `from_value::<Request>` on the whole message).
async fn handle_request(req: &Value, state: &DaemonState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    match method_of(req) {
        Some("register_service") => respond(
            id,
            "register_service",
            crate::daemon::register_service(state, &params)
                .await
                .map(unit),
        ),
        Some("peer_add") => respond(
            id,
            "peer_add",
            crate::daemon::add_peer(state, &params).await.map(unit),
        ),
        // Unpair a peer (spec §4.2, `mcpmesh pair --remove`). Params read per-method: the
        // petname to drop. `remove_peer` revokes the peer's service authorization AND drops
        // its identity row (the inverse of the pairing grant) — see its fail-safe ordering.
        Some("peer_remove") => respond(
            id,
            "peer_remove",
            crate::daemon::remove_peer(state, &params).await.map(unit),
        ),
        // Rename a contact's nickname (Contacts rename). Params read per-method: the person's
        // `user_id` (or a provisional `petname`) + the new nickname `to`. `rename_peer` guards the
        // collision (no inheriting another identity's grants), rewrites allow lists, and reloads.
        Some("peer_rename") => respond(
            id,
            "peer_rename",
            crate::daemon::rename_peer(state, &params).await.map(unit),
        ),
        Some("invite") => {
            // Mint a pairing invite (spec §4.2). Params read per-method (never
            // `from_value::<Request>`): the granted service list, tolerating an absent list.
            let services: Vec<String> = params
                .get("services")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let Some(mesh) = state.mesh() else {
                return error(id, -32000, "daemon has no mesh (control-only mode)");
            };
            respond(
                id,
                "invite",
                crate::daemon::mint_invite(services, mesh).await,
            )
        }
        Some("pair") => {
            // Redeem a pairing invite (spec §4.2). Params read per-method: the copyable
            // `mcpmesh-invite:` line, tolerating an absent/non-string field (an empty line simply
            // fails to decode → a clean pair error).
            let invite_line = str_param(&params, "invite_line");
            respond(id, "pair", crate::daemon::redeem(state, invite_line).await)
        }
        Some("roster_install") => {
            // Install a signed roster from a local file (spec §4.3 manual path). Params read
            // per-method: the file `path` (a local file the same-uid daemon reads, P12/P14) and an
            // OPTIONAL `org_root_pk` that pins the org root on first install. `install_roster`
            // validates (rules 1–6), persists, hot-swaps the gate, and severs revoked sessions (D8).
            let path = str_param(&params, "path");
            let org_root_pk = params
                .get("org_root_pk")
                .and_then(Value::as_str)
                .map(String::from);
            respond(
                id,
                "roster_install",
                crate::daemon::install_roster(state, path, org_root_pk).await,
            )
        }
        // Pin the org root on a JOINER without a roster (spec §4.4 step 2, D5). Params read
        // per-method: org_id / org_root_pk / user_id / user_key. `user_key` is a LOCAL path (the
        // key never crosses the API). `org_join` validates the pk BEFORE writing, then surgically
        // pins the four `[identity]` keys under `reload_lock`. No roster is installed.
        Some("org_join") => respond(
            id,
            "org_join",
            crate::daemon::org_join(
                state,
                str_param(&params, "org_id"),
                str_param(&params, "org_root_pk"),
                str_param(&params, "user_id"),
                str_param(&params, "user_key"),
            )
            .await,
        ),
        // Pin the HTTPS roster URL (`[roster].url`) in config (spec §4.3 M3c). Params read
        // per-method: the `url` string. Written by `org create --roster-url` (operator) and by
        // `join` when the org invite carries one (the joiner's FIRST-roster bootstrap, D5).
        // `set_roster_url` writes it atomically under `reload_lock` (single-writer).
        Some("set_roster_url") => respond(
            id,
            "set_roster_url",
            crate::daemon::set_roster_url(state, str_param(&params, "url"))
                .await
                .map(unit),
        ),
        Some("blob_publish") => respond(
            id,
            "blob_publish",
            crate::daemon::blob_publish(
                state,
                str_param(&params, "scope"),
                str_param(&params, "path"),
            )
            .await,
        ),
        Some("blob_grant") => respond(
            id,
            "blob_grant",
            crate::daemon::blob_grant(
                state,
                str_param(&params, "scope"),
                str_param(&params, "principal"),
            )
            .await
            .map(unit),
        ),
        Some("blob_list") => respond(id, "blob_list", crate::daemon::blob_list(state).await),
        Some("blob_fetch") => respond(
            id,
            "blob_fetch",
            crate::daemon::blob_fetch(
                state,
                str_param(&params, "ticket"),
                str_param(&params, "dest_path"),
            )
            .await,
        ),
        Some("audit_summary") => {
            // Summarize THIS node's LOCAL audit log (spec §11.3 local-only): read the daemon's OWN
            // audit dir off the runtime (spawn_blocking — the fs house rule) and aggregate to
            // per-peer / per-service session counts. Never touches the network; params are ignored
            // (parameterless, like `status`). Works in control-only mode (an empty/absent dir → an
            // empty summary).
            match tokio::task::spawn_blocking(|| {
                let dir = mcpmesh_trust::paths::default_audit_dir()?;
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

/// Fold one control call's `Result` into the JSON-RPC response frame — the boilerplate every
/// dispatch arm shared: `Ok(v)` → `{"result": v}` (a `()`-returning verb maps itself to `json!({})`
/// via [`unit`] first), `Err(e)` → `-32000` with the `"{method} failed: {e}"` message shape every
/// arm used. Wire-identical to the per-arm match blocks it replaces (pinned by the daemon_dispatch
/// / control tests).
fn respond<T: serde::Serialize>(id: Value, method: &str, r: anyhow::Result<T>) -> Value {
    match r {
        Ok(v) => ok(
            id,
            serde_json::to_value(v).expect("control result serializes"),
        ),
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
/// JSON-RPC-shaped response frame. Params are read per-method; M2a's implemented methods
/// are parameterless, so `status` ignores whatever `params` shape the client sent (omitted
/// / null / `{}` all answered) — the tolerance a third-party client depends on.
fn dispatch(req: &Value, state: &DaemonState) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    match method_of(req) {
        Some("status") => {
            let result =
                serde_json::to_value(status_result(state)).expect("StatusResult serializes");
            ok(id, result)
        }
        Some("shutdown") => ok(id, json!({})),
        Some(other) => error(id, -32601, format!("unknown method: {other}")),
        None => error(id, -32600, "request is missing a `method`"),
    }
}

pub(crate) fn status_result(state: &DaemonState) -> StatusResult {
    // Services + peers are read LIVE from the mesh's config + store (like `roster`/`presence`
    // below), NOT from the cached snapshot: the pairing grant (grant_service_access) and the
    // rendezvous PeerEntry write are durable but do NOT refresh the snapshot, so a cached read
    // showed a just-paired peer as absent / its grant as `no one yet` until the next
    // register/restart. A live read is always-current and cheap (status is a human-invoked
    // command). The cached snapshot remains the fallback for a rare config-read error and for a
    // control-only daemon (no mesh → no config/store to read). std RwLock guards are cloned out
    // and dropped inside this sync fn — no lock is ever held across an await.
    // The config is loaded ONCE per status call and shared by the live service list AND
    // `roster_status` (which reads only the pinned org anchor from it) — the host polls status,
    // so the previous load-twice was a real per-poll cost.
    let (services, peers, roster) = match state.mesh() {
        Some(mesh) => {
            let cfg = crate::config::Config::load(&mesh.config_path).ok();
            let services = cfg
                .as_ref()
                .map(crate::daemon::service_infos)
                .unwrap_or_else(|| {
                    state
                        .services
                        .read()
                        .expect("services lock not poisoned")
                        .clone()
                });
            // Roster status is computed LIVE from `mesh.roster.view()` (never a cached snapshot —
            // the gate view is already hot-swapped on install; a live read is cheap + always-
            // current). A pure-pairing daemon (no mesh, or an empty roster gate) yields None → no
            // roster block.
            let roster = crate::daemon::roster_status(mesh, cfg.as_ref());
            (services, crate::daemon::peer_infos(&mesh.store), roster)
        }
        None => (
            state
                .services
                .read()
                .expect("services lock not poisoned")
                .clone(),
            state.peers.read().expect("peers lock not poisoned").clone(),
            None,
        ),
    };
    // Advisory presence read (spec §10.1): the installed roster's devices joined with the live
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
    // Recent inviter-side pairing completions (display-only §4.2 ceremony aids, newest first):
    // a snapshot of the mesh's in-memory ring. Empty in a control-only daemon and after a
    // restart (in-memory by design — not trust data).
    let recent_pairings = state
        .mesh()
        .map(|mesh| mesh.recent_pairings())
        .unwrap_or_default();
    // Advisory reachability of paired peers, from the on-demand probe cache (spec: pairing-mode
    // liveness). Mirrors the `presence` read above: cached values returned immediately, with any
    // stale/missing entry refreshed on a background probe `reachability_of` spawns — status stays a
    // non-blocking hot path. Surface-clean (§1.5): petnames + numbers only.
    let reachability = state
        .mesh()
        .map(crate::daemon::reachability_of)
        .unwrap_or_default();
    StatusResult {
        stack_version: state.stack_version.clone(),
        services,
        peers,
        roster,
        presence,
        self_user_id,
        recent_pairings,
        reachability,
    }
}

/// Extract a string field from a request's `params` object, defaulting to `""` when absent
/// or non-string (an empty peer/service simply fails the dial → a clean -32055, spec §8).
fn str_param(params: &Value, key: &str) -> String {
    params
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
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

    /// `status` on a control-only daemon answers from the (empty) snapshot: version + empty peers,
    /// no roster/presence block. Exercises `status_result`'s no-mesh fallback branch.
    #[test]
    fn dispatch_status_answers_from_the_snapshot() {
        let st = control_only();
        let r = dispatch(&req("status", json!({})), &st);
        assert_eq!(r["result"]["stack_version"], "0.1.0-test");
        assert!(r["result"]["peers"].as_array().unwrap().is_empty());
        assert!(r["result"]["services"].as_array().unwrap().is_empty());
        assert!(r["result"]["roster"].is_null());
    }

    /// `status` tolerates whatever `params` shape a third-party client sends (omitted / null / {}) —
    /// the parameterless-method leniency the spec guarantees (§6.1).
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
            assert_eq!(
                r["error"]["code"], -32000,
                "method {method} should error in control-only mode, got {r}"
            );
        }
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
