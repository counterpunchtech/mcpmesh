//! The daemon's ALPN-dispatch accept loop (spec §7.1): one loop routing each inbound
//! connection to the mesh / pairing / ping / gossip / blob handlers, the shared D8
//! gate-and-register discipline for the roster-mode arms, and the hot-reload abort/respawn
//! that swaps the loop with a rebuilt service registry.

use std::sync::Arc;

use mcpmesh_net::framing::write_frame;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR, ALPN_PING, Services, run_mesh_connection};
use tokio::task::JoinHandle;

use crate::pairing;

use super::{MeshState, STACK_VERSION};

/// The shared D8 gate + CHECK-register for the roster-mode ALPN accept arms (gossip, roster-blob,
/// app-blob): resolve the remote against the composed trust gate — an unresolved peer is refused
/// 401 — then `register_checked` the connection so a revocation/roster-drop severs it live
/// (`should_sever_now`, T4). Returns the RAII registration the arm holds for the connection's
/// lifetime, or `None` AFTER closing the connection (the arm just returns). Extracting this keeps
/// the D8 discipline in exactly ONE place across ALL gated ALPNs.
///
/// The D8 sever discriminator is ROSTER membership (`gate.roster_user`, `None` for pairing),
/// captured at resolve time — NOT `identity.user_id`, which a paired peer also carries.
///
/// `blob_conn_limit` (the app-blob arm only): the per-endpoint app-blob connection rate-limit
/// (spec §9, the M4a-deferred DoS bound). Consulted AFTER resolve so ONLY AUTHENTICATED endpoints
/// allocate a bucket — a stranger was already refused above (SECURITY invariant 4: strangers stay
/// cheap, no allocation, no make_room work) — and BEFORE the registry insert. The real threat is a
/// valid roster member with no scope grant (a STABLE roster id) churning blob connections whose
/// GETs are denied. FAIL-SAFE: over-limit → close (the accept-time 401 + request-time Permission
/// gates are unchanged; this only bounds connection churn).
fn gate_and_register(
    mesh: &Arc<MeshState>,
    conn: &iroh::endpoint::Connection,
    blob_conn_limit: bool,
) -> Option<mcpmesh_net::registry::Registration> {
    let remote = mcpmesh_net::EndpointId::from(conn.remote_id());
    if mesh.gate.resolve(&remote).is_none() {
        conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
        return None;
    }
    if blob_conn_limit && !mesh.limits().admit_blob_conn(&remote) {
        conn.close(0u32.into(), b"blob rate limited");
        return None;
    }
    let roster_user = mesh.gate.roster_user(&remote);
    let registration = mesh
        .conn_registry
        .register_checked(conn, roster_user.clone(), |eid| {
            mesh.gate.should_sever_now(eid, roster_user.as_deref())
        });
    if registration.is_none() {
        conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
    }
    registration
}

/// Spawn the daemon's own ALPN-dispatch accept loop on `endpoint`, returning its task handle.
///
/// The daemon runs THIS instead of [`mcpmesh_net::serve`] so it can route each accepted
/// connection by its negotiated ALPN (spec §7.1): `mcpmesh/mcp/1` goes through net's gated
/// per-connection handler [`run_mesh_connection`]; `mcpmesh/pair/1` goes to the pairing
/// rendezvous — GATE-EXEMPT (D8 exception), authenticated by the invite secret, NOT the trust
/// gate (that is precisely why the mesh-only `serve` is not enough). An unknown ALPN is closed
/// cleanly.
///
/// Both the initial start (`serve_forever`) and the hot-reload swap (`reload_accept_loop`,
/// shared by `register_service` and the pairing `grant_service_access`) call this ONE function,
/// so the loop is defined in exactly one place; the reload path aborts the returned handle and
/// spawns a fresh loop carrying the rebuilt `services`.
///
/// Takes `Arc<MeshState>` (not the individual parts): the arms read the gate/limits/handles off
/// it, and the `mcpmesh/pair/1` branch hands the rendezvous the narrow per-connection
/// [`InviterCtx`](crate::pairing::rendezvous::InviterCtx) the mesh composes (`inviter_ctx` —
/// store + invites + the grant hook into the reload machinery). Only `services` is passed
/// alongside because a hot-reload swaps the registry without rebuilding the rest of the mesh.
///
/// `pub` (like [`build_services`](crate::daemon::build_services)) so integration tests can drive the SAME accept loop the daemon
/// runs against in-process endpoints, proving mesh vs. pair ALPN routing.
pub fn spawn_accept_loop(mesh: Arc<MeshState>, services: Arc<Services>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = mesh.endpoint.accept().await {
            let (mesh, services) = (mesh.clone(), services.clone());
            tokio::spawn(async move {
                // M2a inbound-handshake discipline (preserved from net's `serve`): a failed
                // handshake drops the connection. The handshake ERROR is logged at debug (a
                // transport/TLS/ALPN-negotiation error — the handshake never completed, so it
                // carries NO peer identity; logging `%e` is thus no surface leak, spec §1.5)
                // and will help debug pairing dials in T5-T8.
                let conn = match incoming.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::debug!(%e, "inbound handshake failed");
                        return;
                    }
                };
                // iroh 1.0.1 [RECONCILE — verified]: on an accepted
                // `Connection<HandshakeCompleted>`, `alpn() -> &[u8]` returns the negotiated
                // ALPN (NOT `Option<Vec<u8>>` — that form exists only on the 0-RTT states).
                // Copy it out so `conn` is free to move into the selected handler.
                let alpn = conn.alpn().to_vec();
                match alpn.as_slice() {
                    a if a == ALPN_MCP => {
                        run_mesh_connection(
                            conn,
                            mesh.gate.clone(),
                            services,
                            mesh.conn_registry.clone(),
                        )
                        .await;
                    }
                    a if a == ALPN_PAIR => {
                        // Live-invite accept-gate (spec §7.1/§4.2/D8: the pair rendezvous is only
                        // "open" while an invite is live). iroh can't cheaply toggle an advertised
                        // ALPN on a live endpoint, so the pair ALPN stays advertised and we realize
                        // the windowed-listener semantics HERE — a dial with NO outstanding invite
                        // is closed immediately (no bi-stream, no hello, no handler task spawned to
                        // consume). `count()` is advisory (any-invite-live, coarse): if another
                        // conn burns the last invite first, this one still reaches `try_redeem` and
                        // gets `Unknown` → refused — so per-invite expiry/burn stays authoritative
                        // there, and this is a cheap front-door close, not the security boundary.
                        if mesh.invites.count() == 0 {
                            conn.close(0u32.into(), b"no pairing in progress");
                            return;
                        }
                        // Per-connection rate-limit of the by-design-open pair ALPN (spec §7.1/§4.2,
                        // the M2b-deferred bound). A SINGLE global bucket — the pair ALPN accepts
                        // strangers who pick fresh ids, so a per-endpoint map would be defeated by
                        // fresh ids. Placed AFTER the no-invite fast-close so it bounds only the
                        // attempts that would proceed to the (more expensive) rendezvous while an
                        // invite is live. FAIL-SAFE: over-rate → close (a client retries as tokens
                        // refill). NOT the removed per-invite attempt cap; the 32-byte secret is the
                        // security.
                        if !mesh.limits().admit_pair_accept() {
                            conn.close(0u32.into(), b"pair rate limited");
                            return;
                        }
                        // The real inviter-side rendezvous, run against the narrow context the
                        // mesh composes: store + invites + the grant hook, so a successful pair
                        // can also GRANT service access (config-append + reload) without the
                        // module seeing the mesh. The error is a transport/protocol error (a
                        // malformed hello, a dropped stream) or a grant failure — it carries NO
                        // peer identity, so `%e` is no surface leak. Logged at debug.
                        if let Err(e) =
                            pairing::rendezvous::handle_inviter_side(conn, mesh.inviter_ctx())
                                .await
                        {
                            tracing::debug!(%e, "pair rendezvous error");
                        }
                    }
                    a if a == ALPN_PING => {
                        // Reachability pong (pairing-mode liveness) — TRUST-GATED: only pong to a
                        // resolvable (paired) peer, so an unpaired scanner's dial is closed with NO
                        // pong and learns nothing (no presence leak, spec §1.5). THIS gate is the
                        // security boundary of the probe (mirrors the `gate.resolve` refusal in
                        // `gate_and_register`). The EndpointId is not logged (surface-leak discipline).
                        let remote = mcpmesh_net::EndpointId::from(conn.remote_id());
                        if mesh.gate.resolve(&remote).is_none() {
                            conn.close(mcpmesh_net::CLOSE_UNAUTHORIZED.into(), b"unauthorized");
                            return;
                        }
                        // The dialer opens the bi-stream and sends one ping frame (which is what
                        // makes `accept_bi` resolve — a silent QUIC stream is invisible to the peer);
                        // we ignore its content and write the single pong. `finish()` + `stopped()`
                        // ensure the pong is ACKed before `conn` drops (the pairing `send_reply`
                        // discipline — a bare drop could preempt the un-acked reply).
                        if let Ok((mut send, _recv)) = conn.accept_bi().await {
                            let pong = serde_json::json!({ "stack_version": STACK_VERSION });
                            if write_frame(&mut send, &pong).await.is_ok() {
                                let _ = send.finish();
                                let _ = send.stopped().await;
                            }
                        }
                    }
                    a if a == crate::roster::transport::GOSSIP_ALPN => {
                        // Roster/presence gossip (spec §4.3/§10, roster mode only). Gate + register
                        // via [`gate_and_register`] (the shared D8 discipline: unresolved → 401,
                        // revocation/roster-drop severs live gossip connections too); only THEN is
                        // the connection handed to the gossip `ProtocolHandler`. A pure-pairing
                        // daemon never advertised this ALPN → `gossip` is `None` → close.
                        let Some(gossip) = mesh.gossip.clone() else {
                            conn.close(0u32.into(), b"gossip not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, false) else {
                            return;
                        };
                        if let Err(e) = iroh::protocol::ProtocolHandler::accept(&gossip, conn).await
                        {
                            tracing::debug!(%e, "gossip accept error");
                        }
                    }
                    a if a == crate::roster::transport::BLOB_ALPN => {
                        // Roster-blob provider (spec §4.3/§9 — the signed roster document only; ungated per
                        // scope, that is M4). The [`gate_and_register`] D8 gate on THIS arm is the access
                        // boundary — same gate + register + hand-off as the gossip arm, so a revocation
                        // severs blob connections too. `None` blobs (pure-pairing) → close.
                        let Some(blobs) = mesh.blobs.clone() else {
                            conn.close(0u32.into(), b"blobs not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, false) else {
                            return;
                        };
                        let blob_proto = blobs.protocol();
                        if let Err(e) =
                            iroh::protocol::ProtocolHandler::accept(&blob_proto, conn).await
                        {
                            tracing::debug!(%e, "blob accept error");
                        }
                    }
                    a if a == crate::blobs::APP_BLOB_ALPN => {
                        // The GATED per-scope app-blob provider (spec §9, M4a). TWO-LAYER D7/D8:
                        // (1) ACCEPT-TIME gate — the SAME [`gate_and_register`] resolve → 401 +
                        //     register_checked/should_sever_now as the roster BLOB_ALPN arm — PLUS
                        //     the per-endpoint connection rate-limit (`blob_conn_limit`, see the
                        //     helper doc): a revoked/unknown endpoint gets nothing regardless of the
                        //     ticket/hash it holds, and a revocation severs live app-blob
                        //     connections too.
                        // (2) REQUEST-TIME gate — inside the provider's Intercept drain loop (Task 3):
                        //     a valid-but-ungranted caller is refused with Permission before any bytes.
                        // `None` app_blobs (pure-pairing / build failed) → close cleanly.
                        let Some(app_blobs) = mesh.app_blobs().await else {
                            conn.close(0u32.into(), b"app blobs not enabled");
                            return;
                        };
                        let Some(_registration) = gate_and_register(&mesh, &conn, true) else {
                            return;
                        };
                        let blob_proto = app_blobs.protocol();
                        if let Err(e) =
                            iroh::protocol::ProtocolHandler::accept(&blob_proto, conn).await
                        {
                            tracing::debug!(%e, "app-blob accept error");
                        }
                    }
                    // An endpoint we never advertised should be unreachable (ALPN negotiation
                    // rejects it at handshake), but close defensively rather than hang.
                    _ => conn.close(0u32.into(), b"unknown alpn"),
                }
            });
        }
    })
}

/// Abort the running accept loop and spawn a fresh one on the same endpoint carrying the
/// rebuilt `services`. Shared by [`register_service`] and [`grant_service_access`] so the
/// abort/respawn discipline lives in exactly ONE place (DRY). The CALLER holds
/// `mesh.reload_lock` for the whole config→reload→swap section; this helper only takes the
/// short-lived `accept_task` lock for the swap itself.
pub(crate) async fn reload_accept_loop(mesh: &Arc<MeshState>, services: Services) {
    let mut guard = mesh.accept_task.lock().await;
    if let Some(old) = guard.take() {
        old.abort();
    }
    *guard = Some(spawn_accept_loop(mesh.clone(), Arc::new(services)));
}
