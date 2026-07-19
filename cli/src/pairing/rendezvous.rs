//! The pairing rendezvous over ALPN `mcpmesh/pair/1` (spec §4.2/§7.1). Gate-EXEMPT (D8): a
//! pairing peer is by definition not yet in the allowlist; it is authenticated by possession
//! of the invite secret, not by the trust gate. This module holds BOTH sides:
//! [`handle_inviter_side`] (the accept-time handler) and [`redeem_invite`] (the dialer, T6).
//!
//! **The two writes that make a pairing functional (the load-bearing fact, M2b §5/§4.2).**
//! Admitting a paired peer to a service needs TWO independent facts on the inviter:
//!  1. a [`PeerEntry`] `{ endpoint_id → petname }` so the [`AllowlistGate`] RESOLVES the peer's
//!     mesh dial to its petname (identity/trust); and
//!  2. the peer's petname in the service's config `[services.<svc>].allow`, so `select_service`
//!     (M2a two-layer §5) ADMITS that resolved petname (authorization) — this allow is baked
//!     into the [`Services`] snapshot at `build_services` time, so it takes effect only after a
//!     RELOAD.
//!
//! A [`PeerEntry`] alone leaves the peer KNOWN-BUT-FORBIDDEN. T6's [`handle_inviter_side`]
//! writes (1) then calls [`grant_service_access`] for (2) — see the success arm below.
//!
//! **Asymmetric grant (spec §4.2).** `invite notes` gives the REDEEMER access to `notes` and
//! gives the INVITER a dial-back entry with NO service grants. So:
//!
//!  - the redeemer's alice-entry has `services = invite.services` (what the redeemer may DIAL);
//!  - the inviter's bob-entry has `services = []` (a dial-back identity row — the inviter may
//!    dial nothing on the redeemer). `PeerEntry.services` is a client-side DIRECTORY of what to
//!    dial, never an authorization input (nothing reads it for admission), so the `[]` here is
//!    semantic cleanliness — but it is the correct encoding of §4.2.
//!
//! **Second pairings MERGE, never clobber.** `PeerStore::add` is a replace-on-endpoint_id upsert
//! (a contract other callers rely on), so BOTH rendezvous write sites resolve-then-merge before
//! adding: the redeemer UNIONs a repeat grant into its dial directory and takes the new invite's
//! suggested petname (rename-by-fresh-invite); the inviter PRESERVES its stored petname + dial
//! directory (a reverse pairing must not wipe what an earlier redeem granted us) — and neither
//! side ever downgrades a verified `user_id` to `None`. See the per-site comments for the rules.
//!
//! [`AllowlistGate`]: crate::allowlist::AllowlistGate
//! [`Services`]: mcpmesh_net::Services
//! [`grant_service_access`]: crate::daemon::grant_service_access
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use tokio::io::BufReader;

use mcpmesh_local_api::PairResult;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};

use crate::allowlist::{PeerEntry, PeerStore};
use crate::daemon::{MeshState, grant_service_access};
use crate::pairing::sas::short_auth_code;
use crate::pairing::{Invite, Redeem};
use crate::util::epoch_now_u64 as epoch_now;

/// Frame cap for the pair rendezvous. The redeemer's hello is a tiny JSON object (two 32-byte
/// arrays + a short petname), so a small cap is ample and bounds a hostile stranger's frame
/// (the pair ALPN accepts strangers by design, spec §4.2/P7).
const MAX_PAIR_FRAME: usize = 64 * 1024;

/// Generic wire refusal reason. Deliberately does NOT distinguish unknown-vs-expired-vs-wrong
/// secret: a specific reason would be a redemption oracle an attacker could probe (spec §4.2,
/// P3). The specific [`Redeem`] variant is logged SERVER-side only. A malformed frame and an
/// id mismatch get their own reasons — neither is a secret oracle.
const REASON_REFUSED: &str = "pairing refused";
const REASON_MALFORMED: &str = "malformed request";
const REASON_ID_MISMATCH: &str = "id mismatch";

/// The redeemer's first (and only) frame: the secret it is redeeming plus its self-claimed id
/// and suggested petname. `[u8; 32]` fields serde-round-trip as JSON arrays (same as `Invite`).
/// The claimed `redeemer_id` is NOT trusted — the TLS-authenticated `conn.remote_id()` is
/// authoritative and must match it (P3).
#[derive(serde::Serialize, serde::Deserialize)]
struct RedeemerHello {
    secret: [u8; 32],
    redeemer_id: [u8; 32],
    redeemer_petname: String,
    /// Optional self-sovereign identity: the redeemer's user public key (`b64u`) and a device→user
    /// binding signature over ITS OWN endpoint (`b64u`), proving this device belongs to that user
    /// (`mcpmesh_trust::binding`). `#[serde(default)]` so a peer with no user key OMITS them
    /// (backward-compatible) and the inviter stores the entry with `user_id: None`. NEVER trusted
    /// unverified — the inviter re-verifies the binding against the TLS-authenticated `redeemer_id`.
    #[serde(default)]
    user_pk: Option<String>,
    #[serde(default)]
    binding_sig: Option<String>,
}

/// The inviter's reply. On success it carries the inviter's identity so the redeemer can write
/// its dial-back entry (T6); on failure a generic reason.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum PairReply {
    Ok {
        inviter_id: [u8; 32],
        inviter_petname: String,
        /// The inviter's optional self-sovereign identity — same shape/semantics as
        /// [`RedeemerHello`]'s, verified by the redeemer against the invite's `inviter_id`.
        #[serde(default)]
        user_pk: Option<String>,
        #[serde(default)]
        binding_sig: Option<String>,
    },
    Refused {
        reason: String,
    },
}

/// This daemon's own self-sovereign identity presentation for a pairing exchange: its user public
/// key and a device→user binding signature over ITS OWN endpoint (both `b64u`), precomputed once at
/// serve time from the daemon's [`UserKey`](mcpmesh_trust::UserKey) via
/// [`binding::present`](mcpmesh_trust::binding::present). A `None` at a call site means this daemon has
/// no user key and presents no identity, so the peer stores `user_id: None` (M2b parity).
#[derive(Clone, Debug)]
pub struct SelfBinding {
    pub user_pk: String,
    pub sig: String,
}

/// Verify a peer's OPTIONAL presented binding against the TLS-authenticated peer id, returning the
/// peer's proven `user_id` if — and only if — it presented a binding that verifies. Absent fields →
/// `None` (a backward-compatible pre-binding peer). A PRESENT-but-INVALID binding is rejected (a
/// `warn` + `None`): a peer asserting a `user_id` must PROVE ownership of that user key AND that the
/// binding is for its authenticated endpoint (`binding::verify_presented`'s two invariants), so an
/// unprovable id is never stored. It does not FAIL the pairing — identity is ADDITIVE to the petname
/// trust grant, and an invalid binding conveys no privilege (it cannot forge a `user_id`), so the
/// pairing still succeeds with `user_id: None` rather than burning the invite on a crypto hiccup.
fn verified_user_id(
    user_pk: &Option<String>,
    binding_sig: &Option<String>,
    authenticated_id: &[u8; 32],
) -> Option<String> {
    match (user_pk, binding_sig) {
        (Some(pk), Some(sig)) => {
            match mcpmesh_trust::binding::verify_presented(pk, sig, authenticated_id) {
                Ok(uid) => Some(uid),
                Err(e) => {
                    tracing::warn!(
                        %e,
                        "peer presented an invalid device->user binding; storing entry without a user_id"
                    );
                    None
                }
            }
        }
        // No binding presented (or a half-presented one) — no self-sovereign id to store.
        _ => None,
    }
}

/// Inviter-side handler for one inbound pair connection (spec §4.2). The redeemer opens a
/// bi-stream and sends a `RedeemerHello`; we verify the P3 EndpointId binding, redeem the
/// secret against the live registry, and on success write the [`PeerEntry`] trust grant, GRANT
/// service authorization ([`grant_service_access`]), reply with our identity, and log the short
/// authentication code (SAS). Every attempt is logged (§4.2 "each attempt logged"); no peer
/// EndpointId is ever logged (surface discipline, §1.5).
///
/// Takes the whole `Arc<MeshState>` (T6): the redeem reads `mesh.invites` + `mesh.store`, and
/// the authorization grant needs `mesh`'s config/reload machinery.
///
/// **Reentrancy (why the grant can reload the loop that spawned this handler).** This handler
/// is a DETACHED child `tokio::spawn` of the accept loop (spawned per-connection in
/// [`spawn_accept_loop`](crate::daemon::spawn_accept_loop)). [`grant_service_access`] aborts the
/// OLD `accept_task` (the loop) and spawns a NEW one — aborting a JoinHandle aborts only THAT
/// task, never its already-spawned children, so this handler keeps running and finishes its
/// reply over the still-live `conn`. `mesh.reload_lock` serializes the grant against
/// `register_service`; this handler holds no daemon lock when it calls grant. No self-abort, no
/// deadlock.
pub async fn handle_inviter_side(
    conn: iroh::endpoint::Connection,
    mesh: Arc<MeshState>,
) -> anyhow::Result<()> {
    // The redeemer opens the bi-stream; we accept it. `accept_bi` resolves once the redeemer
    // has sent its first bytes (the hello).
    let (mut send, recv) = conn.accept_bi().await?;
    let mut reader = FrameReader::new(BufReader::new(recv), MAX_PAIR_FRAME);

    // Read exactly one hello frame. A framing violation, an EOF, or a JSON that is not a
    // RedeemerHello → refuse (best-effort) and return; the connection is not a valid redeemer.
    let hello: RedeemerHello = match reader.next().await? {
        Some(Inbound::Frame(v)) => match serde_json::from_value(v) {
            Ok(h) => h,
            Err(_) => return refuse(&mut send, REASON_MALFORMED, "malformed hello").await,
        },
        _ => return refuse(&mut send, REASON_MALFORMED, "malformed hello").await,
    };

    // P3 EndpointId-binding: `conn.remote_id()` is the TLS-authenticated redeemer id and is
    // AUTHORITATIVE — a redeemer cannot lie about its own id. Reject a hello whose claimed id
    // disagrees, and use the TLS id (NOT the message field) everywhere below.
    let tls_id = *conn.remote_id().as_bytes();
    if tls_id != hello.redeemer_id {
        return refuse(&mut send, REASON_ID_MISMATCH, "id mismatch").await;
    }

    let now = epoch_now();
    match mesh.invites.try_redeem(&hello.secret, now) {
        Redeem::Ok(invite) => {
            // Resolve any EXISTING entry for the TLS-authenticated redeemer id FIRST — a same-id
            // re-pair, or the REVERSE pairing of an earlier redeem (we redeemed THEIR invite
            // once, so our entry for them carries a real dial directory). The merge rules below
            // preserve what that entry already knows instead of replace-clobbering it.
            //
            // Identity-confusion guard (privilege-escalation defense) — BEFORE any write/grant,
            // and only for a NEW peer. The redeemer's self-asserted petname becomes BOTH its
            // resolved identity (the gate maps endpoint_id → petname) AND the string appended to
            // config `allow`, so a name that matches an EXISTING identity would let the redeemer
            // assume that identity's access (beyond `invite.services`). Refuse: (a) a name held
            // by a DIFFERENT store peer (impersonation), or (b) a name backed by NO store peer
            // but already sitting in some service's config `allow` (an orphan pre-provisioned
            // grant). For an EXISTING same-id entry the self-suggested name is DISCARDED entirely
            // (the stored petname is preserved below), so no authority can derive from the
            // suggestion and the guard has nothing to guard — same-id re-pairs keep passing.
            // Blocking (redb + config read) → spawn_blocking.
            let store_c = mesh.store.clone();
            let config_path_c = mesh.config_path.clone();
            let petname_c = hello.redeemer_petname.clone();
            let (existing, collides) = tokio::task::spawn_blocking(move || {
                let existing = store_c.resolve(&tls_id)?;
                let collides = existing.is_none()
                    && petname_collision(&store_c, &config_path_c, &petname_c, &tls_id)?;
                anyhow::Ok((existing, collides))
            })
            .await
            .context("join petname collision check")??;
            if collides {
                // Generic wire reason (no oracle — same as every other failure); the specific
                // cause is logged SERVER-side with the petname (a pairing artifact, not a §1.5
                // surface leak) — NO endpoint id, NO secret. The invite is already burned by
                // try_redeem; a deliberate collision attack does not deserve preservation, and an
                // accidental collision is rare + re-mintable.
                tracing::warn!(
                    petname = %hello.redeemer_petname,
                    "pairing refused: petname collision"
                );
                let _ = send_reply(
                    &mut send,
                    &PairReply::Refused {
                        reason: REASON_REFUSED.into(),
                    },
                )
                .await;
                return Ok(());
            }

            // (1) TRUST/identity grant (spec §4.2): record who this peer is so the AllowlistGate
            // RESOLVES its later mesh dial to this petname. `endpoint_id` is the TLS id (P3).
            //
            // For a NEW peer: the redeemer's suggested petname, `services = []` — the INVITER's
            // dial-back entry carries NO service grants (§4.2 asymmetric grant);
            // `PeerEntry.services` is a dial-directory, never an admission input, so this is the
            // correct encoding, not a functional lever. (Authorization is fact (2) below.)
            //
            // For an EXISTING same-id entry, MERGE — a second pairing must not clobber it:
            //  - petname: PRESERVE the stored name. The inviter's chosen name for a peer is never
            //    renamed by the OTHER side's self-suggestion (a rename is the inviter's own act —
            //    `peer_rename` / re-REDEEMING a fresh invite on the naming side).
            //  - services: PRESERVE the dial directory. If we previously REDEEMED an invite from
            //    this peer, `services` records what WE may dial on THEM; the fresh `[]` applies
            //    only to a brand-new entry and must not wipe that directory (the reverse-pairing
            //    clobber bug).
            //  - user_id: a newly VERIFIED binding wins; otherwise keep the existing proven id —
            //    a verified user_id is never downgraded to `None` by a binding-less re-pair.
            //  - paired_at: keep the ORIGINAL stamp — the entry records when trust with this peer
            //    was FIRST established on this side (the re-pair itself is auditable via the §11.3
            //    trust event); stamp `now` only when the entry never had one (`internal peer add`).
            let petname = existing
                .as_ref()
                .map_or_else(|| hello.redeemer_petname.clone(), |e| e.petname.clone());
            let entry = PeerEntry {
                endpoint_id: tls_id,
                petname: petname.clone(),
                services: existing
                    .as_ref()
                    .map(|e| e.services.clone())
                    .unwrap_or_default(),
                paired_at: existing
                    .as_ref()
                    .and_then(|e| e.paired_at.clone())
                    .or_else(|| Some(now.to_string())),
                // The redeemer's PROVEN self-sovereign user_id, verified against its TLS id (P3) —
                // falling back to the already-proven stored id, else `None` (no/invalid binding,
                // M2b parity).
                user_id: verified_user_id(&hello.user_pk, &hello.binding_sig, &tls_id)
                    .or_else(|| existing.and_then(|e| e.user_id)),
            };
            // redb writes block + fsync — run on a blocking thread (M2a seam; mirrors
            // `daemon::add_peer`'s spawn_blocking + `.context(...)` + double-`?` join). A store
            // write failure returns here → the connection drops with a bare close (no explicit
            // Refused frame), which the redeemer treats as a refusal — acceptable for a rare
            // disk error; the write is one atomic redb txn, so no half-grant results.
            let store2 = mesh.store.clone();
            tokio::task::spawn_blocking(move || store2.add(entry))
                .await
                .context("join pair store write")??;

            // (2) AUTHORIZATION grant (T6, the load-bearing step): append the redeemer's
            // EFFECTIVE petname — the one the entry stores and the gate will resolve its dials
            // to (for an existing peer that is the PRESERVED name, not the self-suggestion) —
            // to each granted service's config `[services.<svc>].allow` and RELOAD, so
            // `select_service` actually admits it. Fail-closed: propagate a grant failure so the
            // pair FAILS rather than silently leaving the peer known-but-forbidden. The invite is
            // already burned (try_redeem removed it), so on failure the redeemer must re-mint —
            // acceptable, and correct: no half-authorized peer.
            grant_service_access(&mesh, &petname, &invite.services).await?;

            // Audit + P3 completion notice — AFTER the durable trust write AND the durable grant,
            // BEFORE the network reply: the SAS (§4.2, order-independent over both ids + the
            // secret; display-only, a pairing artifact not a §1.5 surface leak) and the §11.3
            // "paired" trust event. Ordering it ahead of the reply means a committed pairing can
            // never exist un-audited (a reply-write failure must not swallow the notice).
            let sas = short_auth_code(&invite.inviter_id, &tls_id, &hello.secret);
            tracing::info!(peer = %petname, code = %sas, "paired");
            // Park the SAS in the daemon's in-memory recent-pairings ring so the INVITER's human
            // can read it via `mcpmesh status` and compare it with the redeemer's (§4.2 — the
            // redeemer got the same words in its PairResult). Display-only ceremony state, lost
            // on restart by design; NOT trust data.
            mesh.record_pairing(petname, sas, now);

            // The pairing is now durable + authorized + audited, so the reply is best-effort:
            // reply with OUR identity (both fields from the redeemed invite — no extra daemon
            // state) PLUS our self-sovereign device->user binding, if this daemon has a user key,
            // so the redeemer can store our user_id symmetrically (verified against our TLS id).
            // A failed write leaves the redeemer to re-check via a dial-back / the human noticing
            // the "paired" notice (§11, P3).
            let (inviter_pk, inviter_sig) = match mesh.self_binding() {
                Some(b) => (Some(b.user_pk), Some(b.sig)),
                None => (None, None),
            };
            let _ = send_reply(
                &mut send,
                &PairReply::Ok {
                    inviter_id: invite.inviter_id,
                    inviter_petname: invite.petname.clone(),
                    user_pk: inviter_pk,
                    binding_sig: inviter_sig,
                },
            )
            .await;
            Ok(())
        }
        // Expired / Unknown: refuse with a GENERIC reason (no redemption oracle — do not leak
        // which). The specific variant is logged server-side only (no peer id, no secret). No
        // PeerEntry is written; an unknown secret did not burn a live invite.
        other => {
            tracing::info!(outcome = ?other, "pair attempt refused");
            let _ = send_reply(
                &mut send,
                &PairReply::Refused {
                    reason: REASON_REFUSED.into(),
                },
            )
            .await;
            Ok(())
        }
    }
}

/// Best-effort refusal: log the attempt (§4.2), send the refusal (ignoring any write error —
/// the redeemer treats a bare close as a refusal too), and return `Ok`.
async fn refuse(
    send: &mut iroh::endpoint::SendStream,
    reason: &str,
    log: &str,
) -> anyhow::Result<()> {
    tracing::info!("pair attempt refused: {log}");
    let _ = send_reply(
        send,
        &PairReply::Refused {
            reason: reason.into(),
        },
    )
    .await;
    Ok(())
}

/// Write one reply frame and ensure it reaches the peer BEFORE the connection drops.
/// `write_frame` flushes into the QUIC send buffer; `finish()` signals stream end; `stopped()`
/// then resolves once the peer has ACKed receipt of every byte (noq: `Ok(None)`). Without the
/// `stopped()` wait, dropping `conn` at handler return could preempt the un-acked reply and the
/// redeemer would observe a bare close instead of the reply. `finish`/`stopped` are best-effort
/// (a vanished peer is not our problem); the meaningful error is the `write_frame` itself.
async fn send_reply(
    send: &mut iroh::endpoint::SendStream,
    reply: &PairReply,
) -> anyhow::Result<()> {
    write_frame(send, &serde_json::to_value(reply)?).await?;
    let _ = send.finish();
    let _ = send.stopped().await;
    Ok(())
}

/// Redeemer-side dial (spec §4.2, `mcpmesh pair <invite>`): decode the invite, dial the inviter it
/// names on `mcpmesh/pair/1`, VERIFY the TLS-authenticated peer id binds the invite's `inviter_id`
/// (P3 address-swap defense) BEFORE revealing the secret, prove the secret, and — on the
/// inviter's `Ok` — write OUR dial-back [`PeerEntry`] and return the inviter's petname + the SAS.
///
/// Asymmetric grant (§4.2): OUR entry for the inviter carries `services = invite.services` — the
/// services we were granted and may DIAL on it (a client-side directory). The inviter's entry for
/// US carries no service grants (written on its side). The authorization that actually admits us
/// to those services is the inviter appending our petname to its config `allow` — done in ITS
/// [`handle_inviter_side`] via [`grant_service_access`], not here.
///
/// Fail-closed: the P3 identity check happens BEFORE `open_bi`/sending the secret, so a redeemer
/// that reaches a swapped address never reveals the bearer credential to the wrong peer.
///
/// [`grant_service_access`]: crate::daemon::grant_service_access
pub async fn redeem_invite(
    endpoint: iroh::Endpoint,
    self_petname: String,
    invite_line: String,
    store: Arc<PeerStore>,
    self_binding: Option<SelfBinding>,
) -> anyhow::Result<PairResult> {
    let invite = Invite::decode(&invite_line)?;

    // Client-side pre-check: a friendly early error for an expired invite (the inviter also
    // enforces at redeem — this just avoids a pointless dial).
    if invite.expires_at_epoch < epoch_now() {
        bail!("invite expired");
    }

    // Dial the inviter at the exact address the invite embeds — pairing needs no discovery
    // (the invite carries the dialable `EndpointAddr`, so this works on localhost too).
    let addr: iroh::EndpointAddr = serde_json::from_str(&invite.inviter_addr_json)
        .context("invite carries an undecodable inviter address")?;
    let conn = endpoint
        .connect(addr, mcpmesh_net::ALPN_PAIR)
        .await
        .context("could not dial the inviter's machine")?;

    // P3 address-swap defense: the TLS-authenticated peer id is AUTHORITATIVE. If it is not the
    // id the invite names, we reached a substituted/MITM endpoint — refuse BEFORE revealing the
    // secret. (A whole-invite forgery that also swapped `inviter_id` still diverges the SAS,
    // which the human catches out-of-band.)
    if *conn.remote_id().as_bytes() != invite.inviter_id {
        bail!("inviter id mismatch — refusing (address-swap defense)");
    }

    // We (the redeemer) OPEN the bi-stream; the inviter `accept_bi`s. Send the hello proving the
    // secret. `redeemer_id` is our own TLS id (the inviter re-verifies it against remote_id).
    let (mut send, recv) = conn.open_bi().await.context("open the pairing bi-stream")?;
    let (redeemer_pk, redeemer_sig) = match self_binding {
        Some(b) => (Some(b.user_pk), Some(b.sig)),
        None => (None, None),
    };
    let hello = RedeemerHello {
        secret: invite.secret,
        redeemer_id: *endpoint.id().as_bytes(),
        redeemer_petname: self_petname,
        user_pk: redeemer_pk,
        binding_sig: redeemer_sig,
    };
    write_frame(&mut send, &serde_json::to_value(&hello)?)
        .await
        .context("send the pairing hello")?;

    // Read exactly ONE reply frame (same cap as the inviter side).
    let mut reader = FrameReader::new(BufReader::new(recv), MAX_PAIR_FRAME);
    let reply: PairReply = match reader.next().await? {
        Some(Inbound::Frame(v)) => {
            serde_json::from_value(v).context("inviter reply is not a PairReply")?
        }
        _ => bail!("no reply from the inviter (connection closed before a reply)"),
    };
    // On Ok, verify the inviter's presented binding against `invite.inviter_id` (which we proved
    // equals the TLS-authenticated id above) → its PROVEN user_id, or `None` if it presented none.
    let inviter_user_id = match &reply {
        PairReply::Refused { reason } => bail!("pairing refused: {reason}"),
        PairReply::Ok {
            user_pk,
            binding_sig,
            ..
        } => verified_user_id(user_pk, binding_sig, &invite.inviter_id),
    };

    // Our dial-back entry: the inviter, named by the invite's suggested petname, granting the
    // services WE may dial on it (§4.2 asymmetric) — MERGED with any existing entry for this
    // inviter (a repeat grant: Alice grants notes, later invites again granting kb):
    //  - services: UNION(existing, invite.services) — the client-side dial directory ACCUMULATES
    //    grants (dedup; stable order: existing entries first, new grants appended);
    //  - petname: the NEW invite's suggested petname — renaming a peer by redeeming a fresh
    //    invite is a deliberate feature (no unpair needed), so the new suggestion wins here;
    //  - user_id: the newly VERIFIED binding wins, else keep the existing proven id — a verified
    //    user_id is never downgraded to `None` by a binding-less re-pair;
    //  - paired_at: now — this side stamps each redeem (each is a fresh ceremony we performed).
    // `endpoint_id` is `invite.inviter_id`, which we verified above equals the TLS id (P3).
    // Resolve + merge + add run in ONE blocking closure (redb reads/writes block + fsync).
    let inviter_id = invite.inviter_id;
    let petname = invite.petname.clone();
    let granted = invite.services.clone();
    let paired_at = Some(epoch_now().to_string());
    tokio::task::spawn_blocking(move || {
        let existing = store.resolve(&inviter_id)?;
        let mut services = existing
            .as_ref()
            .map(|e| e.services.clone())
            .unwrap_or_default();
        for svc in granted {
            if !services.contains(&svc) {
                services.push(svc);
            }
        }
        store.add(PeerEntry {
            endpoint_id: inviter_id,
            petname,
            services,
            paired_at,
            user_id: inviter_user_id.or_else(|| existing.and_then(|e| e.user_id)),
        })
    })
    .await
    .context("join redeemer store write")??;

    // Display-only SAS (§4.2), order-independent → equals the inviter's. Both humans read it
    // aloud to catch a whole-invite forgery out-of-band.
    let self_id = *endpoint.id().as_bytes();
    let sas_code = short_auth_code(&invite.inviter_id, &self_id, &invite.secret);
    Ok(PairResult {
        peer_petname: invite.petname,
        sas_code,
        // The services WE were granted (from the invite) — the porcelain renders each as
        // `<peer>/<service>` for the "You can mount:" line. Same list written into our
        // dial-back `PeerEntry.services` above (a client-side dial directory).
        services: invite.services,
    })
}

/// Identity-confusion guard for pairing (privilege escalation, T6). Returns `true` = REFUSE when
/// a redeemer's self-asserted `petname` would let it assume an EXISTING identity's access:
///  - **(a) impersonation** — a store peer with this petname exists under a DIFFERENT
///    `endpoint_id` than the redeemer's authenticated `tls_id`; or
///  - **(b) orphan-allow** — NO store peer has this petname AND the name already appears in some
///    config `[services.*].allow` (a pre-provisioned grant the redeemer would inherit).
///
/// A same-id re-pair (every same-name entry shares `tls_id`) passes both: that peer's own name is
/// neither impersonation nor an orphan — which is precisely why (b) is gated on there being NO
/// backing store peer. Blocking (redb read + config file read) — call on a blocking thread.
fn petname_collision(
    store: &PeerStore,
    config_path: &Path,
    petname: &str,
    tls_id: &[u8; 32],
) -> anyhow::Result<bool> {
    let same_name: Vec<PeerEntry> = store
        .list()?
        .into_iter()
        .filter(|e| e.petname == petname)
        .collect();
    // (a) impersonation: any same-name entry belongs to a DIFFERENT endpoint.
    if same_name.iter().any(|e| &e.endpoint_id != tls_id) {
        return Ok(true);
    }
    // (b) orphan-allow: an unbacked name already sitting in some service's config allow.
    if same_name.is_empty() && petname_in_any_service_allow(config_path, petname)? {
        return Ok(true);
    }
    Ok(false)
}

/// Does `petname` appear in ANY config `[services.*].allow`? Reads the CURRENT config on disk (the
/// same file the grant appends to). A missing/empty config → `false` (nothing granted yet). Shared
/// with the daemon's rename collision guard (`rename_plan`).
pub(crate) fn petname_in_any_service_allow(
    config_path: &Path,
    petname: &str,
) -> anyhow::Result<bool> {
    let cfg = crate::config::Config::load(config_path)
        .map_err(|e| anyhow::anyhow!("load config for petname collision check: {e}"))?;
    Ok(cfg
        .services
        .values()
        .any(|svc| svc.allow.iter().any(|a| a == petname)))
}
