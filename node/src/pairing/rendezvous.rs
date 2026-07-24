//! The pairing rendezvous over ALPN `mcpmesh/pair/1`. GATE-EXEMPT by design: a pairing peer is
//! by definition not yet in the allowlist; it is authenticated by possession of the invite
//! secret, not by the trust gate. This module holds BOTH sides: [`handle_inviter_side`] (the
//! accept-time handler) and [`redeem_invite`] (the dialer).
//!
//! **The two writes that make a pairing functional (the load-bearing fact).**
//! Admitting a paired peer to a service needs TWO independent facts on the inviter:
//!  1. a [`PeerEntry`] `{ endpoint_id → nickname }` so the [`AllowlistGate`] RESOLVES the peer's
//!     mesh dial to its nickname (identity/trust); and
//!  2. the peer's nickname in the service's config `[services.<svc>].allow`, so `select_service`
//!     ADMITS that resolved nickname (authorization) — this allow is baked into the [`Services`]
//!     snapshot at `build_services` time, so it takes effect only after a RELOAD.
//!
//! A [`PeerEntry`] alone leaves the peer KNOWN-BUT-FORBIDDEN. [`handle_inviter_side`]
//! writes (1) then calls the [`InviterCtx::grant`] hook for (2) — see the success arm below.
//!
//! **Asymmetric grant.** `invite notes` gives the REDEEMER access to `notes` and
//! gives the INVITER a dial-back entry with NO service grants. So:
//!
//!  - the redeemer's alice-entry has `services = invite.services` (what the redeemer may DIAL);
//!  - the inviter's bob-entry has `services = []` (a dial-back identity row — the inviter may
//!    dial nothing on the redeemer). `PeerEntry.services` is a client-side DIRECTORY of what to
//!    dial, never an authorization input (nothing reads it for admission), so the `[]` here is
//!    semantic cleanliness — but it is the correct encoding of the asymmetry.
//!
//! **Second pairings MERGE, never clobber.** `PeerStore::add` is a replace-on-endpoint_id upsert
//! (a contract other callers rely on), so BOTH rendezvous write sites resolve-then-merge before
//! adding: the redeemer UNIONs a repeat grant into its dial directory and takes the new invite's
//! suggested nickname (rename-by-fresh-invite); the inviter PRESERVES its stored nickname + dial
//! directory (a reverse pairing must not wipe what an earlier redeem granted us) — and neither
//! side ever downgrades a verified `user_id` to `None`, nor a stored `last_addr` (a fresh
//! pairing REFRESHES the dial hint; a merge never replaces `Some` with `None`). See the
//! per-site comments for the rules.
//!
//! This module deliberately never sees the daemon's state: the inviter side runs against the
//! narrow [`InviterCtx`] the daemon assembles (peer store + invite ring + the grant hook), so
//! pairing can be read and tested on its own.
//!
//! [`AllowlistGate`]: crate::allowlist::AllowlistGate
//! [`Services`]: mcpmesh_net::Services
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, bail};
use tokio::io::BufReader;

use mcpmesh_local_api::PairResult;
use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};

use crate::allowlist::{PeerEntry, PeerStore};
use crate::pairing::sas::short_auth_code;
use crate::pairing::{Invite, LiveInvites, Redeem};
use crate::util::epoch_now_u64 as epoch_now;

/// Frame cap for the pair rendezvous. The redeemer's hello is a tiny JSON object (two 32-byte
/// arrays + a short nickname), so a small cap is ample and bounds a hostile stranger's frame
/// (the pair ALPN accepts strangers by design).
const MAX_PAIR_FRAME: usize = 64 * 1024;

/// Generic wire refusal reason. Deliberately does NOT distinguish unknown-vs-expired-vs-wrong
/// secret: a specific reason would be a redemption oracle an attacker could probe. The specific [`Redeem`] variant is logged SERVER-side only. A malformed frame and an
/// id mismatch get their own reasons — neither is a secret oracle.
const REASON_REFUSED: &str = "pairing refused";
const REASON_MALFORMED: &str = "malformed request";
const REASON_ID_MISMATCH: &str = "id mismatch";

/// The redeemer's first (and only) frame: the secret it is redeeming plus its self-claimed id
/// and suggested nickname. `[u8; 32]` fields serde-round-trip as JSON arrays (same as `Invite`).
/// The claimed `redeemer_id` is NOT trusted — the TLS-authenticated `conn.remote_id()` is
/// authoritative and must match it.
#[derive(serde::Serialize, serde::Deserialize)]
struct RedeemerHello {
    secret: [u8; 32],
    redeemer_id: [u8; 32],
    redeemer_nickname: String,
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
/// its dial-back entry; on failure a generic reason.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum PairReply {
    Ok {
        inviter_id: [u8; 32],
        inviter_nickname: String,
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
/// [`binding::present`](mcpmesh_trust::binding::present). A `None` at a call site means this daemon
/// has no user key and presents no identity, so the peer stores `user_id: None` — exactly how a
/// pre-identity peer is stored.
#[derive(Clone, Debug)]
pub struct SelfBinding {
    pub user_pk: String,
    pub sig: String,
}

/// The inviter-side AUTHORIZATION hook: `(principal, display_nickname, services)` → append the
/// redeemer's STABLE principal (#38: its verified `b64u:` user_id when it presented a binding,
/// else its `eid:` device principal — never the rewritable display nickname) to each granted
/// service's config `allow` and hot-reload the serving registry so the peer is actually
/// admitted. The display nickname rides along for the audit/log lines only. Boxed so this
/// module never depends on the daemon's config/reload machinery — the daemon hands the hook in
/// via [`InviterCtx`].
pub type GrantFn = Box<
    dyn Fn(String, String, Vec<String>) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// The ceremony-surface hook: `(peer_nickname, sas_code, paired_at_epoch)` → park the completed
/// pairing where `status` can show the inviter's human the short authentication code. Display-only
/// state, never a trust input.
pub type RecordPairingFn = Box<dyn Fn(String, String, u64) + Send + Sync>;

/// Everything the inviter-side rendezvous needs from the daemon hosting it — the narrow seam that
/// keeps this module free of daemon state. The daemon assembles one per accepted pair connection
/// (`MeshState::inviter_ctx`); tests can assemble one from parts.
///
/// **Reentrancy (why [`grant`](Self::grant) may reload the accept loop that spawned this
/// handler).** The handler runs as a DETACHED child `tokio::spawn` of the accept loop (spawned
/// per-connection). The grant hook aborts the OLD accept-loop task and spawns a NEW one —
/// aborting a `JoinHandle` aborts only THAT task, never its already-spawned children, so the
/// handler keeps running and finishes its reply over the still-live connection. The daemon's
/// reload lock serializes the grant against every other config mutation; the handler holds no
/// daemon lock when it invokes the hook. No self-abort, no deadlock.
pub struct InviterCtx {
    /// The peer allowlist store (the same open database the live trust gate reads).
    pub store: Arc<PeerStore>,
    /// The in-RAM ring of outstanding invites the redeemed secret is looked up in.
    pub invites: Arc<LiveInvites>,
    /// The daemon's config path — read (not written) by the nickname-collision guard.
    pub config_path: PathBuf,
    /// This daemon's own identity presentation, if it has a user key.
    pub self_binding: Option<SelfBinding>,
    /// The authorization hook (see [`GrantFn`]).
    pub grant: GrantFn,
    /// The ceremony-surface hook (see [`RecordPairingFn`]).
    pub record_pairing: RecordPairingFn,
}

/// Verify a peer's OPTIONAL presented binding against the TLS-authenticated peer id, returning the
/// peer's proven `user_id` if — and only if — it presented a binding that verifies. Absent fields →
/// `None` (a backward-compatible pre-binding peer). A PRESENT-but-INVALID binding is rejected (a
/// `warn` + `None`): a peer asserting a `user_id` must PROVE ownership of that user key AND that the
/// binding is for its authenticated endpoint (`binding::verify_presented`'s two invariants), so an
/// unprovable id is never stored. It does not FAIL the pairing — identity is ADDITIVE to the nickname
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

/// Inviter-side handler for one inbound pair connection. The redeemer opens a bi-stream and
/// sends a `RedeemerHello`; we verify the EndpointId binding (the TLS-authenticated id must
/// match the claimed one), redeem the secret against the live registry, and on success write
/// the [`PeerEntry`] trust grant, GRANT service authorization ([`InviterCtx::grant`]), reply
/// with our identity, and log the short authentication code (SAS). Every attempt is logged; no
/// peer EndpointId is ever logged (the surface discipline: porcelain and logs speak nicknames).
///
/// Takes an [`InviterCtx`]: the redeem reads `ctx.invites` + `ctx.store`, and the authorization
/// grant runs through the `ctx.grant` hook the daemon supplied (see the [`InviterCtx`] doc for
/// the reload-reentrancy argument).
pub async fn handle_inviter_side(
    conn: iroh::endpoint::Connection,
    ctx: InviterCtx,
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

    // EndpointId binding: `conn.remote_id()` is the TLS-authenticated redeemer id and is
    // AUTHORITATIVE — a redeemer cannot lie about its own id. Reject a hello whose claimed id
    // disagrees, and use the TLS id (NOT the message field) everywhere below.
    let tls_id = *conn.remote_id().as_bytes();
    if tls_id != hello.redeemer_id {
        return refuse(&mut send, REASON_ID_MISMATCH, "id mismatch").await;
    }

    let now = epoch_now();
    match ctx.invites.try_redeem(&hello.secret, now) {
        Redeem::Ok(invite) => {
            // Resolve any EXISTING entry for the TLS-authenticated redeemer id FIRST — a same-id
            // re-pair, or the REVERSE pairing of an earlier redeem (we redeemed THEIR invite
            // once, so our entry for them carries a real dial directory). The merge rules below
            // preserve what that entry already knows instead of replace-clobbering it.
            //
            // Display-uniqueness guard — BEFORE any write/grant, and only for a NEW peer. The
            // redeemer's self-asserted nickname becomes its resolved DISPLAY identity (the gate
            // maps endpoint_id → nickname); grants are principal-keyed (#38), so no access can
            // derive from the name — but a duplicate display name would make this inviter's own
            // records/routing ambiguous, so a name held by a DIFFERENT store peer is refused.
            // For an EXISTING same-id entry the self-suggested name is DISCARDED entirely (the
            // stored nickname is preserved below) — same-id re-pairs keep passing.
            // Blocking (redb read) → spawn_blocking.
            let store_c = ctx.store.clone();
            let nickname_c = hello.redeemer_nickname.clone();
            let (existing, collides) = tokio::task::spawn_blocking(move || {
                let existing = store_c.resolve(&tls_id)?;
                let collides = existing.is_none()
                    && nickname_collision(&store_c, &nickname_c, &tls_id)?;
                anyhow::Ok((existing, collides))
            })
            .await
            .context("join nickname collision check")??;
            if collides {
                // Generic wire reason (no oracle — same as every other failure); the specific
                // cause is logged SERVER-side with the nickname (a pairing artifact, not a
                // surface leak) — NO endpoint id, NO secret. The invite is already burned by
                // try_redeem; a deliberate collision attack does not deserve preservation, and an
                // accidental collision is rare + re-mintable.
                tracing::warn!(
                    nickname = %hello.redeemer_nickname,
                    "pairing refused: nickname collision"
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

            // (1) TRUST/identity grant: record who this peer is so the AllowlistGate RESOLVES
            // its later mesh dial to this nickname. `endpoint_id` is the TLS-authenticated id.
            //
            // For a NEW peer: the redeemer's suggested nickname, `services = []` — the INVITER's
            // dial-back entry carries NO service grants (the asymmetric grant);
            // `PeerEntry.services` is a dial-directory, never an admission input, so this is the
            // correct encoding, not a functional lever. (Authorization is fact (2) below.)
            //
            // For an EXISTING same-id entry, MERGE — a second pairing must not clobber it:
            //  - nickname: PRESERVE the stored name. The inviter's chosen name for a peer is never
            //    renamed by the OTHER side's self-suggestion (a rename is the inviter's own act —
            //    `peer_rename` / re-REDEEMING a fresh invite on the naming side).
            //  - services: PRESERVE the dial directory. If we previously REDEEMED an invite from
            //    this peer, `services` records what WE may dial on THEM; the fresh `[]` applies
            //    only to a brand-new entry and must not wipe that directory (the reverse-pairing
            //    clobber bug).
            //  - user_id: a newly VERIFIED binding wins; otherwise keep the existing proven id —
            //    a verified user_id is never downgraded to `None` by a binding-less re-pair.
            //  - paired_at: keep the ORIGINAL stamp — the entry records when trust with this peer
            //    was FIRST established on this side (the re-pair itself is auditable via the
            //    trust event); stamp `now` only when the entry never had one (`internal peer add`).
            let nickname = existing
                .as_ref()
                .map_or_else(|| hello.redeemer_nickname.clone(), |e| e.nickname.clone());
            // The redeemer's OBSERVED transport address(es), from the live connection's
            // path snapshot — the pairing-proven dial-back hint. Synthesized as an
            // `EndpointAddr { id: <TLS-authenticated redeemer id>, addrs: <observed> }` and
            // stored as an opaque JSON string (see `PeerEntry::last_addr` for why a string).
            // Merge rule: a fresh observation REFRESHES the hint; an empty path snapshot
            // (or a serialize failure) preserves the stored one — never downgrade `Some`
            // to `None`.
            let observed_addr = {
                let addrs: Vec<iroh::TransportAddr> = conn
                    .paths()
                    .iter()
                    .map(|p| p.remote_addr().clone())
                    .collect();
                if addrs.is_empty() {
                    None
                } else {
                    serde_json::to_string(&iroh::EndpointAddr::from_parts(conn.remote_id(), addrs))
                        .ok()
                }
            };
            let last_addr =
                observed_addr.or_else(|| existing.as_ref().and_then(|e| e.last_addr.clone()));
            let entry = PeerEntry {
                endpoint_id: tls_id,
                nickname: nickname.clone(),
                services: existing
                    .as_ref()
                    .map(|e| e.services.clone())
                    .unwrap_or_default(),
                paired_at: existing
                    .as_ref()
                    .and_then(|e| e.paired_at.clone())
                    .or_else(|| Some(now.to_string())),
                // The redeemer's PROVEN self-sovereign user_id, verified against its TLS id —
                // falling back to the already-proven stored id, else `None` (no/invalid binding:
                // the peer is stored nickname-only).
                user_id: verified_user_id(&hello.user_pk, &hello.binding_sig, &tls_id)
                    .or_else(|| existing.and_then(|e| e.user_id)),
                last_addr,
            };
            // The redeemer's STABLE principal, captured BEFORE the entry moves into the store:
            // the verified `b64u:` user_id when a binding was presented (or already proven),
            // else the `eid:` device principal of the TLS-AUTHENTICATED endpoint (#38).
            let principal = entry.user_id.clone().unwrap_or_else(|| {
                mcpmesh_net::EndpointId::from_bytes(tls_id).principal()
            });
            // redb writes block + fsync — run on a blocking thread (mirrors `daemon::add_peer`'s
            // spawn_blocking + `.context(...)` + double-`?` join). A store write failure returns
            // here → the connection drops with a bare close (no explicit Refused frame), which
            // the redeemer treats as a refusal — acceptable for a rare disk error; the write is
            // one atomic redb txn, so no half-grant results.
            let store2 = ctx.store.clone();
            tokio::task::spawn_blocking(move || store2.add(entry))
                .await
                .context("join pair store write")??;

            // (2) AUTHORIZATION grant (the load-bearing step): append the redeemer's STABLE
            // principal — computed above from the verified binding / authenticated TLS id,
            // NEVER the display nickname (#38: names are rewritable, so a rename or re-pair
            // must not be able to desync a grant) — to each granted service's config
            // `[services.<svc>].allow` and RELOAD, so `select_service` actually admits it.
            // Fail-closed: propagate a grant failure so the pair FAILS rather than silently
            // leaving the peer known-but-forbidden. The invite is already burned (try_redeem
            // removed it), so on failure the redeemer must re-mint — acceptable, and correct:
            // no half-authorized peer.
            (ctx.grant)(principal, nickname.clone(), invite.services.clone()).await?;

            // Audit + completion notice — AFTER the durable trust write AND the durable grant,
            // BEFORE the network reply: the SAS (order-independent over both ids + the secret;
            // display-only, a pairing artifact not a surface leak) and the "paired" trust event.
            // Ordering it ahead of the reply means a committed pairing can never exist
            // un-audited (a reply-write failure must not swallow the notice).
            let sas = short_auth_code(&invite.inviter_id, &tls_id, &hello.secret);
            tracing::info!(peer = %nickname, code = %sas, "paired");
            // Park the SAS in the daemon's in-memory recent-pairings ring so the INVITER's human
            // can read it via `mcpmesh status` and compare it with the redeemer's (who got the
            // same words in its PairResult). Display-only ceremony state, lost on restart by
            // design; NOT trust data.
            (ctx.record_pairing)(nickname, sas, now);

            // The pairing is now durable + authorized + audited, so the reply is best-effort:
            // reply with OUR identity (both fields from the redeemed invite — no extra daemon
            // state) PLUS our self-sovereign device->user binding, if this daemon has a user key,
            // so the redeemer can store our user_id symmetrically (verified against our TLS id).
            // A failed write leaves the redeemer to re-check via a dial-back / the human noticing
            // the "paired" notice.
            let (inviter_pk, inviter_sig) = match ctx.self_binding {
                Some(b) => (Some(b.user_pk), Some(b.sig)),
                None => (None, None),
            };
            let _ = send_reply(
                &mut send,
                &PairReply::Ok {
                    inviter_id: invite.inviter_id,
                    inviter_nickname: invite.nickname.clone(),
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

/// Best-effort refusal: log the attempt, send the refusal (ignoring any write error —
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

/// Redeemer-side dial (`mcpmesh pair <invite>`): decode the invite, dial the inviter it
/// names on `mcpmesh/pair/1`, VERIFY the TLS-authenticated peer id binds the invite's `inviter_id`
/// (the address-swap defense) BEFORE revealing the secret, prove the secret, and — on the
/// inviter's `Ok` — write OUR dial-back [`PeerEntry`] and return the inviter's nickname + the SAS.
///
/// Asymmetric grant: OUR entry for the inviter carries `services = invite.services` — the
/// services we were granted and may DIAL on it (a client-side directory). The inviter's entry for
/// US carries no service grants (written on its side). The authorization that actually admits us
/// to those services is the inviter appending our nickname to its config `allow` — done in ITS
/// [`handle_inviter_side`] via [`grant_service_access`], not here.
///
/// Fail-closed: the identity check happens BEFORE `open_bi`/sending the secret, so a redeemer
/// that reaches a swapped address never reveals the bearer credential to the wrong peer.
///
/// [`grant_service_access`]: crate::daemon::grant_service_access
pub async fn redeem_invite(
    endpoint: iroh::Endpoint,
    self_nickname: String,
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

    // Client-side nickname-squatting check — the mirror of the inviter side's
    // [`nickname_collision`], and enforced BEFORE the dial so a squatting invite never reaches
    // the wire. `invite.nickname` is a stranger's SUGGESTION for what we should call them, and
    // applying it verbatim is what makes the name our gate resolves to (and our
    // `[services.*].allow` authorizes) point at THEIR endpoint. Refusing here keeps the
    // invariant that redeeming an invite grants the other side nothing.
    if let Some(conflict) =
        nickname_squat(&store, &invite.nickname, &invite.inviter_id)?
    {
        bail!(
            "this invite asks to be called '{}', but {conflict} \
             Ask them for an invite suggesting a different name.",
            invite.nickname,
        );
    }

    // Dial the inviter at the exact address the invite embeds — pairing needs no discovery
    // (the invite carries the dialable `EndpointAddr`, so this works on localhost too).
    let addr: iroh::EndpointAddr = serde_json::from_str(&invite.inviter_addr_json)
        .context("invite carries an undecodable inviter address")?;
    let conn = endpoint
        .connect(addr, mcpmesh_net::ALPN_PAIR)
        .await
        .context("could not dial the inviter's machine")?;

    // Address-swap defense: the TLS-authenticated peer id is AUTHORITATIVE. If it is not the
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
        redeemer_nickname: self_nickname,
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
    // Returned to the redeemer in PairResult (#30) so it learns the peer's STABLE identity at
    // pair time — cloned before `inviter_user_id` is moved into the stored PeerEntry below.
    let peer_user_id = inviter_user_id.clone();

    // Our dial-back entry: the inviter, named by the invite's suggested nickname, granting the
    // services WE may dial on it (the asymmetric grant) — MERGED with any existing entry for this
    // inviter (a repeat grant: Alice grants notes, later invites again granting kb):
    //  - services: UNION(existing, invite.services) — the client-side dial directory ACCUMULATES
    //    grants (dedup; stable order: existing entries first, new grants appended);
    //  - nickname: the NEW invite's suggested nickname — renaming a peer by redeeming a fresh
    //    invite is a deliberate feature (no unpair needed), so the new suggestion wins here;
    //  - user_id: the newly VERIFIED binding wins, else keep the existing proven id — a verified
    //    user_id is never downgraded to `None` by a binding-less re-pair;
    //  - paired_at: now — this side stamps each redeem (each is a fresh ceremony we performed);
    //  - last_addr: the invite's `inviter_addr_json` — the pairing-PROVEN dialable address (we
    //    just reached the inviter through it, id-verified). A fresh pairing always carries one,
    //    so this REFRESHES the hint and can never downgrade a stored `Some` to `None`.
    // `endpoint_id` is `invite.inviter_id`, which we verified above equals the TLS id.
    // Resolve + merge + add run in ONE blocking closure (redb reads/writes block + fsync).
    let inviter_id = invite.inviter_id;
    let nickname = invite.nickname.clone();
    let granted = invite.services.clone();
    let paired_at = Some(epoch_now().to_string());
    let last_addr = Some(invite.inviter_addr_json.clone());
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
            nickname,
            services,
            paired_at,
            user_id: inviter_user_id.or_else(|| existing.and_then(|e| e.user_id)),
            last_addr,
        })
    })
    .await
    .context("join redeemer store write")??;

    // Display-only SAS, order-independent → equals the inviter's. Both humans read it
    // aloud to catch a whole-invite forgery out-of-band.
    let self_id = *endpoint.id().as_bytes();
    let sas_code = short_auth_code(&invite.inviter_id, &self_id, &invite.secret);
    Ok(PairResult {
        peer_nickname: invite.nickname,
        sas_code,
        // The services WE were granted (from the invite) — the porcelain renders each as
        // `<peer>/<service>` for the "You can mount:" line. Same list written into our
        // dial-back `PeerEntry.services` above (a client-side dial directory).
        services: invite.services,
        // The opaque app label the inviter attached (#31), echoed to the embedder verbatim.
        // mcpmesh never interpreted it — it is display/metadata only.
        app_label: invite.app_label,
        // The inviter's proven stable user_id (#30) — the redeemer's portable handle for it, and
        // what it may pass to open_session to dial by identity rather than nickname.
        peer_user_id,
    })
}

/// Display-uniqueness guard for pairing. Returns `true` = REFUSE when a redeemer's
/// self-asserted `nickname` is already held by a DIFFERENT stored peer: a duplicate display
/// name would make the inviter's own records ambiguous (status shows two peers as one, and
/// outbound routing by name is first-match). NOT a privilege defense anymore (#38): grants
/// are principal-keyed, so no name can inherit or confer access — this protects display and
/// routing clarity only.
///
/// A same-id re-pair (every same-name entry shares `tls_id`) passes: that peer's own name is
/// no duplicate. Blocking (redb read) — call on a blocking thread.
fn nickname_collision(
    store: &PeerStore,
    nickname: &str,
    tls_id: &[u8; 32],
) -> anyhow::Result<bool> {
    Ok(store
        .list()?
        .into_iter()
        .any(|e| e.nickname == nickname && &e.endpoint_id != tls_id))
}

/// Redeemer-side name-squatting guard — the mirror of [`nickname_collision`], run before we
/// adopt an invite's *suggested* nickname. Returns `Some(reason)` = REFUSE when a stored peer
/// already holds this nickname under a DIFFERENT `endpoint_id`: adopting it would make OUR
/// outbound `<peer>/<service>` routing ambiguous (first-match by name) and our records show
/// two peers as one. NOT an access defense anymore (#38): grants are principal-keyed, so a
/// name confers nothing — this protects the redeemer's own routing/display clarity.
///
/// Re-pairing with the SAME endpoint passes, so rename-by-a-fresh-invite keeps working — and
/// post-#38 that rename is fully SAFE: no grant keys on the name it rewrites.
///
/// The returned string is a reason phrase, spliced into the caller's guidance message.
fn nickname_squat(
    store: &PeerStore,
    nickname: &str,
    inviter_id: &[u8; 32],
) -> anyhow::Result<Option<String>> {
    let clashes = store
        .list()?
        .into_iter()
        .any(|e| e.nickname == nickname && &e.endpoint_id != inviter_id);
    Ok(clashes.then(|| {
        "you already use that name for a different peer — \
         accepting it would make your own dials to that name ambiguous. \
         Unpair the existing peer first if you no longer need it."
            .to_string()
    }))
}
