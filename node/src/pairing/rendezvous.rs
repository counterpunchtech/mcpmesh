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
use crate::pairing::{Invite, LiveInvites, Redeem, SelfEnroll};
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

/// The accept gate's fast-close reason when NO invite is live (#87b) — ONE constant for both
/// sides: the daemon's `ALPN_PAIR` accept arm writes it, [`redeem_invite`] matches it off
/// `close_reason()` and turns it into an actionable error instead of a bare connection failure.
pub(crate) const NO_LIVE_INVITE_CLOSE: &[u8] = b"no pairing in progress";

/// The distinguishable nickname-collision refusal (#87). Only ever sent to a caller that proved
/// possession of a live secret (the peek pre-check) or spent one (the post-redeem race guard) —
/// never to an unproven dialer, or it becomes a store-contents oracle. `invite_survived` selects
/// the recovery guidance: the pre-check path preserves the invite, the race-guard path burned it.
///
/// The redeemer carries this string VERBATIM into [`NicknameTaken`] (under a `pairing refused: `
/// prefix) rather than rebuilding the sentence, so there is one source for the wording — the
/// inviter is also the only side that knows whether the invite survived.
///
/// **Names the action, never a control verb (#147).** The recovery clause used to say "pick a
/// different nickname (`set_nickname`)". That verb is control-API vocabulary a GUI user cannot
/// type, see, or find — and because this string is built INVITER-side and travels to the redeemer,
/// the embedder that displays it could not rewrite it into its own words without substring-matching
/// our prose. The sibling clause "ask the inviter for a fresh invite" was already the model: it
/// names an action. An embedder wanting its own copy should branch on
/// [`ERR_NICKNAME_TAKEN`](mcpmesh_local_api::ERR_NICKNAME_TAKEN) instead of reading this at all.
fn reason_nickname_taken(nickname: &str, invite_survived: bool) -> String {
    let recovery = if invite_survived {
        "the invite was NOT consumed — rename this node and redeem the same invite again"
    } else {
        "ask the inviter for a fresh invite"
    };
    format!("nickname '{nickname}' is already taken by another paired peer; {recovery}")
}

/// The complete nickname-collision refusal: the prose AND its code, chosen together (#147).
///
/// Both send sites go through here rather than building a `PairReply` each, because the two are
/// ONE decision. The code means "rename and redeem the SAME invite again", so it is exactly the
/// `invite_survived` case — and the first implementation of #147 stamped it on both sites, which
/// would have had an embedder send a race-guard loser back to an invite that no longer exists.
///
/// A test over a helper could not have caught that: the bug was at the call site. Keeping the two
/// fields inseparable is what makes it unrepresentable.
fn collision_refusal(nickname: &str, invite_survived: bool) -> PairReply {
    PairReply::Refused {
        reason: reason_nickname_taken(nickname, invite_survived),
        code: invite_survived.then_some(RefusalCode::NicknameTaken),
    }
}

/// A machine-readable refusal kind on [`PairReply::Refused`] (#147), so the REDEEMER can raise a
/// typed error without parsing the inviter's prose — the same anti-pattern we are asking embedders
/// to stop doing, and it would break the moment we improved the wording.
///
/// Daemon-to-daemon only; the control API sees the mapped
/// [`ERR_NICKNAME_TAKEN`](mcpmesh_local_api::ERR_NICKNAME_TAKEN) instead.
///
/// **Deliberately narrow.** It rides only the nickname-collision refusal, which is already
/// distinguishable and already sent exclusively to a caller that proved possession of a live
/// secret. The generic [`REASON_REFUSED`] path gains NO code: it withholds
/// unknown-vs-expired-vs-wrong-secret on purpose, and labelling it would build the redemption
/// oracle that reason exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum RefusalCode {
    /// The redeemer's nickname is held by a DIFFERENT paired peer AND the invite survived, so
    /// renaming and redeeming the same invite again works (#87).
    ///
    /// **The surviving invite is part of the meaning, not a coincidence.** It is what the remedy
    /// every consumer writes off this code depends on. The post-redeem race guard refuses the
    /// same collision with the invite already BURNED, and deliberately sends no code: an embedder
    /// branching on one would tell the user to retry an invite that is gone.
    NicknameTaken,
    /// A refusal kind this node predates. Never sent — only reached on receive.
    Unknown,
}

/// Hand-written so a refusal kind from a NEWER inviter lands on [`RefusalCode::Unknown`] instead of
/// failing the whole reply, which would turn an informative refusal into an opaque parse error on a
/// pinned redeemer. Same reasoning (and same shape) as `ReachabilitySource` in #150; accepts any
/// value, not just an unrecognized string, since `#[serde(default)]` covers an absent key alone.
impl<'de> serde::Deserialize<'de> for RefusalCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct AnyCode;

        impl<'de> serde::de::Visitor<'de> for AnyCode {
            type Value = RefusalCode;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a refusal code")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Ok(match s {
                    "nickname_taken" => RefusalCode::NicknameTaken,
                    _ => RefusalCode::Unknown,
                })
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<Self::Value, D::Error> {
                d.deserialize_any(AnyCode)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(RefusalCode::Unknown)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Self::Value, A::Error> {
                // Drained deliberately: answering without consuming desynchronizes the parser and
                // fails the enclosing reply, which is the failure this impl exists to avoid.
                while m
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(RefusalCode::Unknown)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<Self::Value, A::Error> {
                while s.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(RefusalCode::Unknown)
            }
        }

        d.deserialize_any(AnyCode)
    }
}

/// A pairing refusal that carries its own JSON-RPC code (#159).
///
/// One type rather than a marker struct per condition: `respond` downcasts once and reads `.code`,
/// so adding the seventh onboarding condition is a constant plus a call site, not another arm.
///
/// The point is that an embedder can decide PER CASE whether to render our prose or replace it.
/// Before this, `ERR_NICKNAME_TAKEN` was the only coded pairing failure, so the choice was
/// all-or-nothing: forward every sentence verbatim to end users, or substring-match them.
#[derive(Debug)]
pub struct PairRefusal {
    code: i64,
    message: String,
}

impl PairRefusal {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The JSON-RPC code `respond` should answer with.
    pub fn code(&self) -> i64 {
        self.code
    }
}

impl std::fmt::Display for PairRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PairRefusal {}

/// The redeemer-side typed error for a nickname-collision refusal (#147), which `respond` downcasts
/// to [`ERR_NICKNAME_TAKEN`](mcpmesh_local_api::ERR_NICKNAME_TAKEN). Same shape as
/// [`NoSuchService`](crate::daemon::NoSuchService): a type, a downcast, a stable code.
///
/// It carries the inviter's reason VERBATIM rather than rebuilding the sentence: the inviter is the
/// side that knows whether the invite survived, and re-deriving that here would be a second source
/// of truth for a string this issue exists to make single-sourced.
#[derive(Debug)]
pub struct NicknameTaken(pub String);

impl std::fmt::Display for NicknameTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NicknameTaken {}

/// Did the inviter close this connection with the accept gate's no-live-invite reason (#87b)?
/// The `redeem_invite` mirror of the #89 probe-throttle detection: read off the CONNECTION, not
/// parsed out of whichever stream error surfaced first.
fn no_live_invite_close(conn: &iroh::endpoint::Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(iroh::endpoint::ConnectionError::ApplicationClosed(ac))
            if ac.reason.as_ref() == NO_LIVE_INVITE_CLOSE
    )
}

/// The shared #87 collision check: resolve any EXISTING entry for the TLS-authenticated
/// redeemer id, and whether its self-asserted nickname collides with a DIFFERENT stored peer.
/// ONE helper for the pre-burn check and the post-redeem race guard, so the two cannot drift.
/// Blocking (redb read) → spawn_blocking.
async fn resolve_and_check_collision(
    store: &Arc<PeerStore>,
    nickname: &str,
    tls_id: [u8; 32],
) -> anyhow::Result<(Option<PeerEntry>, bool)> {
    let store_c = store.clone();
    let nickname_c = nickname.to_string();
    tokio::task::spawn_blocking(move || {
        let existing = store_c.resolve(&tls_id)?;
        let collides = existing.is_none() && nickname_collision(&store_c, &nickname_c, &tls_id)?;
        anyhow::Ok((existing, collides))
    })
    .await
    .context("join nickname collision check")?
}

/// Choose the collision refusal, given whether OUR OWN alias is what collided (#87 gate).
///
/// Two different failures wear the same shape and must not wear the same reply:
///
/// - **No alias.** The colliding name is the one the redeemer claimed for itself. It can rename and
///   retry, so name it and answer [`RefusalCode::NicknameTaken`] — the documented
///   rename-and-retry code.
/// - **Alias set.** The colliding name is OURS, chosen on OUR machine, over a name the redeemer
///   cannot see or influence. The first draft interpolated it into the reply, which sent the
///   inviter's private name for that peer — and when the clash was with a third party, disclosed
///   that name too. Worse, it carried `NicknameTaken`, so an embedder following the documented
///   contract would rename and retry forever: every attempt collides identically, because the name
///   is not theirs to change. It answers with the GENERIC refusal instead — byte-identical to every
///   other opaque one, so it discloses nothing, not even that a collision is what happened. The
///   operator gets the detail in the server-side log line.
fn collision_reply(alias: Option<&str>, hello: &RedeemerHello, invite_survived: bool) -> PairReply {
    match alias {
        None => collision_refusal(&hello.redeemer_nickname, invite_survived),
        Some(_) => PairReply::Refused {
            reason: REASON_REFUSED.into(),
            code: None,
        },
    }
}

/// The name the inviter will actually store for a redeemer (#87).
///
/// The inviter's own `peer_nickname` alias when the invite carries one, else the redeemer's
/// self-claim. ONE function, used by the collision pre-check, the post-burn race guard, and the
/// store write — so the name that is checked and the name that is written cannot diverge. They
/// diverging is the whole failure mode: a check against a name nobody stores proves nothing.
fn effective_redeemer_nickname<'a>(alias: Option<&'a str>, claimed: &'a str) -> &'a str {
    alias.unwrap_or(claimed)
}

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
        /// The machine-readable refusal kind (#147), so the redeemer raises a typed error instead
        /// of parsing `reason`. Additive: an inviter older than 0.25.1 sends none, and the
        /// redeemer falls back to today's generic error — a mixed-version pairing still refuses
        /// correctly, just without the branchable code. `None` on every refusal that is
        /// deliberately opaque (see [`RefusalCode`]).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<RefusalCode>,
    },
}

/// This daemon's own self-sovereign identity presentation for a pairing exchange: its user public
/// key and a device→user binding signature over ITS OWN endpoint (both `b64u`), precomputed once at
/// serve time from the daemon's [`UserKey`](mcpmesh_trust::UserKey) via
/// [`binding::present`](mcpmesh_trust::binding::present). A `None` at a call site means this daemon
/// has no user key and presents no identity, so the peer stores `user_id: None` — exactly how a
/// pre-identity peer is stored.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

/// The redeemer-side MUTUAL grant hook (#43): `(inviter_principal, inviter_display)` → grant
/// the inviter access to ALL services THIS node serves. Symmetric with [`GrantFn`] (the
/// inviter side); the daemon supplies it (`None` in tests, which assert only the store write).
pub type GrantBackFn = Box<
    dyn Fn(String, String) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>
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
    /// #86: record a durable trust event. `(event, target)`.
    pub audit_trust: AuditTrustFn,
    /// #86: sign a device→user binding for another device of THIS person, given that device's
    /// TLS-authenticated endpoint id. `None` when this daemon has no user key — there is then no
    /// identity to enroll into, and a self-enrollment is refused rather than silently completing.
    ///
    /// A hook rather than the key itself, so this module never learns where the key lives.
    pub sign_binding: SignBindingFn,
}

/// Persist an adopted self-enrollment binding (#86) — the ONLY copy, since the enrolled device
/// cannot re-derive it (it holds no user key).
pub type AdoptBindingFn = Box<
    dyn Fn(SelfBinding) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>> + Send + Sync,
>;

/// See [`InviterCtx::audit_trust`] (#86).
pub type AuditTrustFn = Box<dyn Fn(String, Option<String>) + Send + Sync>;

/// See [`InviterCtx::sign_binding`] (#86). `endpoint_id` → the `b64u:` signature, or `None`.
pub type SignBindingFn = Box<dyn Fn(&[u8; 32]) -> Option<String> + Send + Sync>;

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

    // #87: collision pre-check BEFORE the burn — but ONLY behind a live-secret peek. Order is
    // the whole design: checking the nickname first for every caller would let a stranger with
    // a garbage secret probe which names exist in the store, so the unproven path must stay on
    // the generic `try_redeem` refusals below, byte-for-byte. A caller that proves possession
    // of a live secret may be told the truth: the name is taken, the invite was NOT consumed,
    // rename and redeem it again — which turns two same-hostname machines' first pairing from
    // a burned invite plus a generic refusal into a self-service retry.
    // #86: skip for a self-enrollment — it stores no nickname on either side, so refusing over a
    // name neither party will write is nonsense, and its remedy ("rename and redeem again") is
    // advice for a problem the caller does not have.
    let self_enrolling = ctx.invites.peek_is_self(&hello.secret, now);
    if !self_enrolling && let Some(alias) = ctx.invites.peek_live_alias(&hello.secret, now) {
        // #87: check the name we will actually STORE. With a `peer_nickname` on the invite, the
        // redeemer's self-claim is never used, so checking it here would refuse over a name we
        // were never going to write — and admit over the one we were.
        let claimed = effective_redeemer_nickname(alias.as_deref(), &hello.redeemer_nickname);
        let (_, collides) = resolve_and_check_collision(&ctx.store, claimed, tls_id).await?;
        if collides {
            // Logged SERVER-side with the nickname (a pairing artifact, not a surface leak) —
            // NO endpoint id, NO secret.
            tracing::warn!(
                nickname = %claimed,
                aliased = alias.is_some(),
                "pairing refused: nickname collision (invite preserved)"
            );
            let _ = send_reply(&mut send, &collision_reply(alias.as_deref(), &hello, true)).await;
            return Ok(());
        }
    }

    match ctx.invites.try_redeem(&hello.secret, now).await {
        // A self-invite must ALSO be single-use HERE, not only at mint. `Invite` is `pub` with `pub`
        // fields and `LiveInvites::mint` is `pub`, so a hand-edited invite file or an embedder
        // building one directly can present a multi-use identity invite — the standing offer to
        // become this person that the mint guard exists to refuse. The repo's own `checked_sub`
        // burn establishes the discipline: an invariant on a bearer credential fails closed
        // WHEREVER it is violated (#86 gate).
        Redeem::Ok(invite) if invite.as_self && invite.uses_remaining > 0 => {
            tracing::warn!("refusing a MULTI-USE self-enrollment invite");
            let _ = send_reply(
                &mut send,
                &PairReply::Refused {
                    reason: REASON_REFUSED.into(),
                    code: None,
                },
            )
            .await;
            Ok(())
        }
        Redeem::Ok(invite) if invite.as_self => {
            // #86 SELF-ENROLLMENT. The redeemer is another DEVICE of this person, so the whole
            // peer-row/grant path below is skipped: writing a row would put this person in their
            // own contact list and — worse — make their own second device an authorizable
            // principal in their own allow lists.
            //
            // What we hand over is a device→user binding for the redeemer's TLS-AUTHENTICATED
            // endpoint, signed with our user key. The KEY NEVER MOVES: `present` signs an arbitrary
            // endpoint id, so the new device can present this signature as its own and every peer
            // resolves both devices to one `user_id`.
            //
            // Signed for `tls_id`, never a self-asserted id: a binding for an endpoint the redeemer
            // does not control would be useless to them and dangerous to issue.
            let Some(self_binding) = ctx.self_binding.as_ref() else {
                // No user key here means there is no identity to enroll INTO. Refuse rather than
                // complete a ceremony that silently achieves nothing.
                let _ = send_reply(
                    &mut send,
                    &PairReply::Refused {
                        reason: "this device has no user identity to enroll into".into(),
                        code: None,
                    },
                )
                .await;
                return Ok(());
            };
            let sig = match (ctx.sign_binding)(&tls_id) {
                Some(sig) => sig,
                None => {
                    let _ = send_reply(
                        &mut send,
                        &PairReply::Refused {
                            reason: REASON_REFUSED.into(),
                            code: None,
                        },
                    )
                    .await;
                    return Ok(());
                }
            };
            // #86 gate: enrollment mints IDENTITY irrevocably, so it must leave a DURABLE record —
            // `record_pairing` below is the display ring, documented as "lost on restart, NOT trust
            // data". `pair`/`unpair`/`roster_install` all audit; this was the highest-value trust
            // act in the system and the only one that did not. Exactly the #65 finding, recurring.
            (ctx.audit_trust)(
                "self_enroll".into(),
                Some(mcpmesh_net::EndpointId::from_bytes(tls_id).principal()),
            );
            let sas = short_auth_code(&invite.inviter_id, &tls_id, &hello.secret);
            tracing::info!(code = %sas, "enrolled another device of this person (#86)");
            // Recorded on the ceremony surface like any pairing, so the inviter's human can read
            // the SAS off `status` and compare it — the check that makes this safe.
            (ctx.record_pairing)("(this person's device)".into(), sas.clone(), epoch_now());
            let _ = send_reply(
                &mut send,
                &PairReply::Ok {
                    inviter_id: invite.inviter_id,
                    inviter_nickname: invite.nickname.clone(),
                    user_pk: Some(self_binding.user_pk.clone()),
                    binding_sig: Some(sig),
                },
            )
            .await;
            Ok(())
        }
        Redeem::Ok(invite) => {
            // Resolve any EXISTING entry for the TLS-authenticated redeemer id FIRST — a same-id
            // re-pair, or the REVERSE pairing of an earlier redeem (we redeemed THEIR invite
            // once, so our entry for them carries a real dial directory). The merge rules below
            // preserve what that entry already knows instead of replace-clobbering it.
            //
            // Display-uniqueness guard — the AUTHORITATIVE re-run of the #87 pre-check above,
            // AFTER winning the burn: two racing redeemers claiming the same NEW nickname can
            // both pass the pre-check (neither stored yet), so the loser must be caught here,
            // post-write-ordering. Burning in that race is rare and acceptable. Same shared
            // helper as the pre-check so the two cannot drift; no seam exists to interleave a
            // store write between peek and burn in a test, so this arm is a stated gap pinned
            // only through the helper (see the spec).
            //
            // The redeemer's self-asserted nickname becomes its resolved DISPLAY identity (the
            // gate maps endpoint_id → nickname); grants are principal-keyed (#38), so no access
            // can derive from the name — but a duplicate display name would make this inviter's
            // own records/routing ambiguous, so a name held by a DIFFERENT store peer is
            // refused. For an EXISTING same-id entry the self-suggested name is DISCARDED
            // entirely (the stored nickname is preserved below) — same-id re-pairs keep passing.
            // #87: the alias, when the invite carries one, is the name that gets stored.
            let claimed = effective_redeemer_nickname(
                invite.peer_nickname.as_deref(),
                &hello.redeemer_nickname,
            )
            .to_string();
            let (existing, collides) =
                resolve_and_check_collision(&ctx.store, &claimed, tls_id).await?;
            if collides {
                // #87: whether the invite SURVIVED is now a fact about this invite, not a
                // constant. `try_redeem` returns the count AFTER decrementing, so uses remaining
                // means the redeemer can rename and retry with the very same line.
                //
                // Hardcoding `false` here shipped the #147 defect straight back: a multi-use
                // invite makes this race routine (two colleagues redeeming one link, the #87(a)
                // same-hostname case), and the loser was told "ask the inviter for a fresh invite"
                // while holding one with four uses left — AND lost the branchable
                // ERR_NICKNAME_TAKEN precisely where the recovery is self-service.
                let survived = invite.uses_remaining > 0;
                tracing::warn!(
                    nickname = %claimed,
                    aliased = invite.peer_nickname.is_some(),
                    uses_remaining = invite.uses_remaining,
                    "pairing refused: nickname collision (post-redeem race guard)"
                );
                let _ = send_reply(
                    &mut send,
                    &collision_reply(invite.peer_nickname.as_deref(), &hello, survived),
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
            // A same-id re-pair KEEPS its stored name (never renamed behind the operator's back);
            // a brand-new peer gets `claimed`, which is the alias when the invite carried one.
            let nickname = existing
                .as_ref()
                .map_or_else(|| claimed.clone(), |e| e.nickname.clone());
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
            let principal = entry
                .user_id
                .clone()
                .unwrap_or_else(|| mcpmesh_net::EndpointId::from_bytes(tls_id).principal());
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
                    // No code, on purpose (#147): this reason withholds
                    // unknown-vs-expired-vs-wrong-secret so it is not a redemption oracle, and a
                    // code labelling it would rebuild exactly that oracle.
                    code: None,
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
            // The malformed-frame / id-mismatch refusals. Neither is a secret oracle, but neither
            // has a self-service remedy an embedder would write copy for, so neither is coded.
            code: None,
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
// Nine collaborators, each a distinct capability the redeemer needs (endpoint, our name, the line,
// our alias for them, whether we offered self-enrollment, the adopt hook, the store, our binding,
// the grant-back hook). A params struct
// would rename them without reducing them, and the signature is pinned by the integration tests.
#[allow(clippy::too_many_arguments)]
pub async fn redeem_invite(
    endpoint: iroh::Endpoint,
    self_nickname: String,
    invite_line: String,
    // #87: OUR local name for the inviter, overriding the one its invite suggests. Local only —
    // never sent, and it does not bypass the squat check below.
    as_nickname: Option<String>,
    // #178: which ceremony this caller is willing to complete. REQUIRED — see [`SelfEnroll`] for
    // why it is not defaulted.
    self_enroll: SelfEnroll,
    // #86: install an adopted self-enrollment binding. `None` = a caller that cannot persist one
    // (a fixture), in which case a self-enrollment still verifies but is not retained.
    adopt_binding: Option<AdoptBindingFn>,
    store: Arc<PeerStore>,
    self_binding: Option<SelfBinding>,
    grant_back: Option<GrantBackFn>,
) -> anyhow::Result<PairResult> {
    let invite = Invite::decode(&invite_line)?;
    // #178: refuse a ceremony the caller never offered, HERE — before the nickname check, before
    // the dial, before the secret is on the wire. The outcome of a self-enrollment is a device→user
    // binding admitting this device to everyone who trusts the inviter's `user_id`, and #86 gives
    // no revocation short of rotating that user key. So it cannot be a thing a caller observes
    // afterwards on `enrolled_as_self` and declines: by then it is done.
    //
    // Refusing before the dial is what keeps the invite USABLE. Nothing is contacted and nothing is
    // burned, so the identical line still works the moment the person is offered the real choice —
    // a refusal here costs a round trip, not the credential.
    if invite.as_self && self_enroll == SelfEnroll::Refuse {
        bail!(PairRefusal::new(
            mcpmesh_local_api::ERR_SELF_ENROLL_NOT_OFFERED,
            "this is a device-enrollment link, not a pairing invite: redeeming it would make this \
             device another device of that person's identity, which this application did not offer \
             — retry with allow_self_enroll if that is what you meant",
        ));
    }
    // ONE binding for the name we will use everywhere below — the squat check, the stored entry,
    // the grant-back display name, and the result. Computing it per-site is how a check ends up
    // running against a different name than the one written.
    let as_nickname_used = as_nickname.is_some();
    let local_name = as_nickname.unwrap_or_else(|| invite.nickname.clone());

    // Client-side pre-check: a friendly early error for an expired invite (the inviter also
    // enforces at redeem — this just avoids a pointless dial).
    if invite.expires_at_epoch < epoch_now() {
        // #159: decided from the line in hand, before any dial — so it reveals nothing about the
        // inviter and is safe to name precisely.
        bail!(PairRefusal::new(
            mcpmesh_local_api::ERR_INVITE_EXPIRED,
            "invite expired",
        ));
    }

    // Client-side nickname-squatting check — the mirror of the inviter side's
    // [`nickname_collision`], and enforced BEFORE the dial so a squatting invite never reaches
    // the wire. `invite.nickname` is a stranger's SUGGESTION for what we should call them, and
    // applying it verbatim is what our gate resolves the inviter's DISPLAY name to (and what
    // our own outbound `<peer>/<service>` routing keys on — first-match by name). Grants are
    // principal-keyed (#38), so no access can follow the name; refusing here keeps the
    // invariant that redeeming an invite grants the other side nothing.
    if !invite.as_self
        && let Some(conflict) = nickname_squat(&store, &local_name, &invite.inviter_id)?
    {
        // The wording has to follow WHOSE name collided (#87 gate). With `as_nickname` set, the
        // invite asked for nothing of the sort — the local user picked it — and "ask them for a
        // different name" is advice for a problem they do not have.
        let reason = if as_nickname_used {
            format!(
                "you asked to call this peer '{local_name}', but {conflict} \
                 Redeem the same invite again with a different name."
            )
        } else {
            // BYTE-IDENTICAL to before this change. A downstream forwards this prose to end
            // users, and #159 shipped `-32048` precisely so the code — not a reword — is how a
            // consumer offers the better remedy. Only the NEW aliased case above gets new wording,
            // because it has no existing consumer.
            format!(
                "this invite asks to be called '{local_name}', but {conflict} \
                 Ask them for an invite suggesting a different name."
            )
        };
        bail!(PairRefusal::new(
            mcpmesh_local_api::ERR_INVITE_NAME_CONFLICT,
            reason,
        ));
    }

    // Dial the inviter at the exact address the invite embeds — pairing needs no discovery
    // (the invite carries the dialable `EndpointAddr`, so this works on localhost too).
    let addr: iroh::EndpointAddr = serde_json::from_str(&invite.inviter_addr_json)
        .context("invite carries an undecodable inviter address")?;
    // #159: unreachable is its own condition — the invite is untouched, so the remedy is "check
    // they are running and retry the same line", not "get a new one".
    let conn = endpoint
        .connect(addr, mcpmesh_net::ALPN_PAIR)
        .await
        // #159: the CODE is added; the message and its cause chain are untouched. The porcelain
        // owns the human explanation for this one (`render.rs` turns a self-redeem into "you
        // cannot redeem your own invite on the machine that minted it"), it MATCHES ON THIS
        // STRING, and it needs iroh's cause underneath. Rewording it here made that branch dead
        // code and replaced a correct explanation with advice — "retry this same invite" — that
        // can never work for the most common newcomer mistake (#159 gate).
        .map_err(|e| {
            // `.context(PairRefusal)` rather than `Error::new(PairRefusal).context(e)`: context
            // goes on TOP, so this keeps our message as the Display (the porcelain matches on it)
            // AND keeps iroh's error as the source, so `{:#}` still carries the cause for
            // diagnostics. Wrapping the other way round hid our message behind iroh's.
            anyhow::Error::new(e).context(PairRefusal::new(
                mcpmesh_local_api::ERR_INVITER_UNREACHABLE,
                "could not dial the inviter's machine",
            ))
        })?;

    // Address-swap defense: the TLS-authenticated peer id is AUTHORITATIVE. If it is not the
    // id the invite names, we reached a substituted/MITM endpoint — refuse BEFORE revealing the
    // secret. (A whole-invite forgery that also swapped `inviter_id` still diverges the SAS,
    // which the human catches out-of-band.)
    if *conn.remote_id().as_bytes() != invite.inviter_id {
        // #159: the ONE onboarding refusal that must not be rendered as "try again". Something
        // answered in place of the machine this invite names.
        bail!(PairRefusal::new(
            mcpmesh_local_api::ERR_INVITER_MISMATCH,
            "inviter id mismatch — refusing (address-swap defense)",
        ));
    }

    // We (the redeemer) OPEN the bi-stream; the inviter `accept_bi`s. Send the hello proving the
    // secret. `redeemer_id` is our own TLS id (the inviter re-verifies it against remote_id).
    //
    // The whole open→write→read exchange is ONE async block so its failure is classified against
    // `close_reason()` at ONE site (the #89 `exchange()` shape): the accept gate's fast-close
    // races all three stream calls, and on a real link the close can land before `open_bi` or
    // the hello write completes — a first version guarded only the read arm, which the second
    // #142-style gate caught as an intermittent recurrence of the bare-connection-failure UX
    // this exists to remove. On localhost the read always loses the race, so only the
    // single-site SHAPE guarantees the other two; the dead-invite test pins this site.
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
    let exchange = async {
        let (mut send, recv) = conn.open_bi().await.context("open the pairing bi-stream")?;
        write_frame(&mut send, &serde_json::to_value(&hello)?)
            .await
            .context("send the pairing hello")?;
        // Read exactly ONE reply frame (same cap as the inviter side).
        let mut reader = FrameReader::new(BufReader::new(recv), MAX_PAIR_FRAME);
        match reader.next().await.context("read the pairing reply")? {
            Some(Inbound::Frame(v)) => {
                serde_json::from_value::<PairReply>(v).context("inviter reply is not a PairReply")
            }
            _ => bail!("no reply from the inviter (connection closed before a reply)"),
        }
    };
    let reply: PairReply = match exchange.await {
        Ok(reply) => reply,
        // The exchange failed. If the inviter's accept gate fast-closed us (#87b), say what
        // that MEANS — the invite line in hand may still advertise a live TTL, but invites are
        // in-memory on the inviter, so this is the everyday shape of "expired, already used,
        // or the inviter cancelled it", not a network problem.
        //
        // It used to say "the inviter's daemon restarted (invites do not survive a restart)".
        // #87b made them survive, so that sentence became a false explanation handed to a user in
        // the one place they are trying to work out what went wrong.
        Err(_) if no_live_invite_close(&conn) => {
            bail!(PairRefusal::new(
                mcpmesh_local_api::ERR_INVITE_NOT_LIVE,
                "the invite is no longer live on the inviter: it expired, was already \
                 redeemed, or the inviter cancelled it — ask for a fresh invite",
            ));
        }
        Err(e) => return Err(e),
    };
    // On Ok, verify the inviter's presented binding against `invite.inviter_id` (which we proved
    // equals the TLS-authenticated id above) → its PROVEN user_id, or `None` if it presented none.
    let inviter_user_id = match &reply {
        PairReply::Refused { reason, code } => return Err(refusal_error(reason, *code)),
        PairReply::Ok {
            user_pk,
            binding_sig,
            ..
        } => verified_user_id(user_pk, binding_sig, &invite.inviter_id),
    };
    // #86 SELF-ENROLLMENT: this was not a pairing at all — we are another DEVICE of the inviter's
    // person. Adopt the binding they signed for OUR endpoint and write NO peer row: a row would put
    // this person in their own contact list and make their own other device an authorizable
    // principal here.
    //
    // The binding is verified against OUR endpoint (`self_id`), not the inviter's — it is ours to
    // present from now on, and one signed for anyone else would be useless to us.
    if invite.as_self {
        let self_id = *endpoint.id().as_bytes();
        let PairReply::Ok {
            user_pk,
            binding_sig,
            ..
        } = &reply
        else {
            unreachable!("the Refused arm returned above")
        };
        let (Some(user_pk), Some(sig)) = (user_pk, binding_sig) else {
            bail!(PairRefusal::new(
                mcpmesh_local_api::ERR_INVITE_REFUSED,
                "the inviter completed a self-enrollment without issuing a binding",
            ));
        };
        mcpmesh_trust::binding::verify_presented(user_pk, sig, &self_id).map_err(|_| {
            // Coded like every sibling refusal on this path (#159): a consumer branches on the
            // code rather than matching prose. The inner error is a roster-layer string and says
            // nothing useful to a redeemer, so it is not interpolated.
            anyhow::Error::from(PairRefusal::new(
                mcpmesh_local_api::ERR_INVITE_REFUSED,
                "the enrollment binding does not verify for this device",
            ))
        })?;
        if let Some(adopt) = adopt_binding {
            adopt(SelfBinding {
                user_pk: user_pk.clone(),
                sig: sig.clone(),
            })
            .await?;
        }
        let sas_code = short_auth_code(&invite.inviter_id, &self_id, &invite.secret);
        return Ok(PairResult {
            peer_nickname: local_name,
            sas_code,
            enrolled_as_self: true,
            services: vec![],
            app_label: invite.app_label,
            peer_user_id: Some(user_pk.clone()),
        });
    }

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
    let nickname = local_name.clone();
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

    // #43: MUTUAL grant. The inviter granted us its services on its side (its `GrantFn`);
    // symmetrically we now grant the INVITER access to ALL services WE serve, under the SAME
    // stable-principal rule (its verified `b64u:` when it presented a binding, else its
    // `eid:`). One ceremony ⇒ both directions admitted; the SAS already covered both humans.
    // The daemon supplies the hook; tests pass `None` (they assert the store write only).
    if let Some(grant_back) = grant_back {
        let inviter_principal = peer_user_id
            .clone()
            .unwrap_or_else(|| mcpmesh_net::EndpointId::from_bytes(invite.inviter_id).principal());
        // `local_name`, not `invite.nickname`: the grant-back display name is OURS.
        grant_back(inviter_principal, local_name.clone()).await?;
    }

    // Display-only SAS, order-independent → equals the inviter's. Both humans read it
    // aloud to catch a whole-invite forgery out-of-band.
    let self_id = *endpoint.id().as_bytes();
    let sas_code = short_auth_code(&invite.inviter_id, &self_id, &invite.secret);
    Ok(PairResult {
        peer_nickname: local_name,
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
        enrolled_as_self: false,
    })
}

/// Turn an inviter's refusal into the redeemer's error (#147).
///
/// A CODED refusal becomes a typed [`NicknameTaken`], which `respond` downcasts to
/// [`ERR_NICKNAME_TAKEN`](mcpmesh_local_api::ERR_NICKNAME_TAKEN) — so an embedder branches on a
/// number instead of substring-matching prose that is generated on the other side of the wire and
/// that it cannot rewrite. Everything else stays an opaque `-32000`, including a refusal from an
/// inviter older than 0.25.1 (which sends no code) and one whose kind this node predates.
///
/// The reason is carried VERBATIM rather than rebuilt: the inviter is the side that knows whether
/// the invite survived, so re-deriving the sentence here would be a second source of truth for it.
fn refusal_error(reason: &str, code: Option<RefusalCode>) -> anyhow::Error {
    let msg = format!("pairing refused: {reason}");
    match code {
        Some(RefusalCode::NicknameTaken) => anyhow::Error::new(NicknameTaken(msg)),
        // #159: branchable as "that invite did not work" WITHOUT saying why. The inviter answers
        // one reason for unknown / expired / wrong secret on purpose — telling them apart is a
        // redemption oracle — so this code carries exactly as much as the prose already did.
        _ => anyhow::Error::new(PairRefusal::new(mcpmesh_local_api::ERR_INVITE_REFUSED, msg)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #147: the refusal states the ACTION, not a control verb.
    ///
    /// `set_nickname` is control-API vocabulary. A GUI user cannot type it, and the embedder that
    /// DISPLAYS this string is not the one that could rewrite it — the message is built on the
    /// inviter and travels to the redeemer, so a downstream fix means substring-matching our prose.
    /// The burned-invite sibling was always the model and is asserted here so it stays that way.
    #[test]
    fn the_refusal_names_an_action_not_a_control_verb() {
        let survived = reason_nickname_taken("studio-mac", true);
        assert!(
            !survived.contains("set_nickname"),
            "no control verb may appear in a string a human is shown: {survived}"
        );
        assert!(survived.contains("rename this node"), "got {survived}");
        assert!(
            survived.contains("the invite was NOT consumed"),
            "the recoverable case must still say the invite survived — that is what makes the \
             advice actionable (#87): {survived}"
        );
        assert!(survived.contains("studio-mac"), "got {survived}");

        let burned = reason_nickname_taken("studio-mac", false);
        assert!(
            burned.contains("ask the inviter for a fresh invite"),
            "the burned-invite clause names an action already; it must not regress: {burned}"
        );
        assert!(!burned.contains("set_nickname"), "got {burned}");
    }

    /// #147: `code` is additive both ways — absent on an older inviter's reply, and unrecognized
    /// from a newer one. Either must degrade rather than fail the whole reply, or an informative
    /// refusal becomes an opaque parse error on a pinned redeemer.
    #[test]
    fn a_refusal_code_is_additive_and_degrades() {
        // An inviter older than 0.25.1: no `code` key at all.
        let old: PairReply = serde_json::from_value(
            serde_json::json!({"result": "refused", "reason": "pairing refused"}),
        )
        .expect("an older inviter's refusal must still parse");
        let PairReply::Refused { code, reason } = old else {
            panic!("expected a refusal");
        };
        assert_eq!(code, None, "absent means absent — never a guessed kind");
        assert_eq!(reason, "pairing refused");

        // A refusal kind from a NEWER inviter, and every non-string shape a proxy might produce.
        for bad in [
            serde_json::json!("invite_expired"),
            serde_json::Value::Null,
            serde_json::json!(7),
            serde_json::json!(true),
            serde_json::json!({"kind": "nickname_taken", "nested": [1, 2]}),
            serde_json::json!(["nickname_taken"]),
        ] {
            let v = serde_json::json!({"result": "refused", "reason": "r", "code": bad});
            let reply: PairReply = serde_json::from_value(v)
                .unwrap_or_else(|e| panic!("`code: {bad}` must not fail the whole reply: {e}"));
            let PairReply::Refused { code, reason } = reply else {
                panic!("expected a refusal");
            };
            assert_eq!(reason, "r", "the rest of the reply survives: {bad}");
            // `null` is an ABSENT code, not an unknown one — `Option` absorbs it first.
            assert!(
                matches!(code, Some(RefusalCode::Unknown) | None),
                "an unreadable code must degrade, not claim a kind: {bad} -> {code:?}"
            );
        }
    }

    /// #147: the serialized wire SHAPE of a coded and an uncoded refusal — the `snake_case`
    /// rendering and `skip_serializing_if` eliding the key rather than sending `null`.
    ///
    /// Scope note, because the first version of this test overreached: it builds its own
    /// `PairReply`, so it pins the SERIALIZER, not the branch that chooses a code. The
    /// oracle boundary — that an unproven caller's refusal carries none — is pinned on the real
    /// send site by `a_wrong_secret_with_a_colliding_nickname_gets_only_the_generic_refusal` in
    /// `cli/tests/pairing_rendezvous.rs`. A mutation stamping the code at that send site passed
    /// THIS test.
    #[test]
    fn only_the_collision_refusal_is_coded() {
        let coded = serde_json::to_value(PairReply::Refused {
            reason: reason_nickname_taken("bob", true),
            code: Some(RefusalCode::NicknameTaken),
        })
        .unwrap();
        assert_eq!(coded["code"], "nickname_taken", "got {coded}");

        let generic = serde_json::to_value(PairReply::Refused {
            reason: REASON_REFUSED.into(),
            code: None,
        })
        .unwrap();
        assert!(
            generic.get("code").is_none(),
            "the opaque refusal must carry NO code — one would make it a redemption oracle: \
             {generic}"
        );
        assert_eq!(
            generic["reason"], REASON_REFUSED,
            "and its reason stays opaque: {generic}"
        );
    }

    /// #147: ONLY a coded collision refusal becomes the typed error `respond` maps to
    /// `ERR_NICKNAME_TAKEN`. This is the branch the whole issue turns on: if the generic refusal
    /// also downcast, an embedder branching on the code would tell a user "rename and retry" for a
    /// wrong-or-expired secret; if the coded one did NOT, the embedder is back to reading prose.
    ///
    /// The `None` case is an inviter older than 0.25.1 — it must land on the generic arm, not be
    /// guessed into a kind.
    #[test]
    fn only_a_coded_collision_refusal_becomes_the_typed_error() {
        let wire = reason_nickname_taken("studio-mac", true);
        let coded = refusal_error(&wire, Some(RefusalCode::NicknameTaken));
        assert!(
            coded.downcast_ref::<NicknameTaken>().is_some(),
            "respond's downcast arm is what maps this to ERR_NICKNAME_TAKEN: {coded}"
        );
        assert!(coded.to_string().contains("rename this node"), "{coded}");

        for opaque in [None, Some(RefusalCode::Unknown)] {
            let e = refusal_error(REASON_REFUSED, opaque);
            assert!(
                e.downcast_ref::<NicknameTaken>().is_none(),
                "an opaque refusal must NOT claim the collision code — an embedder would tell a                  user to rename after a wrong or expired secret: {opaque:?} -> {e}"
            );
            assert_eq!(e.to_string(), format!("pairing refused: {REASON_REFUSED}"));
        }
    }

    /// A minimal invite naming `inviter`, for the refusal-code call-site tests.
    fn sample_invite_for(inviter: iroh::EndpointId, expires_at_epoch: u64) -> Invite {
        Invite {
            secret: [5u8; 32],
            inviter_id: *inviter.as_bytes(),
            inviter_addr_json: serde_json::to_string(&iroh::EndpointAddr::from(inviter)).unwrap(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch,
            app_label: None,
            uses_remaining: 1,
            peer_nickname: None,
            as_self: false,
        }
    }

    /// #159 gate: each refusal carries its own code AT ITS CALL SITE.
    ///
    /// The first version tested this by handing `respond` a `PairRefusal::new(code, ..)` and
    /// checking it returned that number — i.e. that `respond` can read a field. Rewriting all six
    /// call sites to the SAME wrong code left the entire workspace green: five of the six were
    /// pinned by nothing, and could have been wired to each other's codes unnoticed.
    ///
    /// These drive the real functions. The two that need a live inviter (`ERR_INVITE_NOT_LIVE`,
    /// `ERR_INVITE_REFUSED`) are covered by the rendezvous integration suite; the rest are decided
    /// locally and are covered here.
    #[tokio::test]
    async fn each_refusal_call_site_uses_its_own_code() {
        use mcpmesh_local_api as api;
        let code_of = |e: &anyhow::Error| e.downcast_ref::<PairRefusal>().map(|r| r.code());

        let store = || {
            std::sync::Arc::new(
                crate::allowlist::PeerStore::open(
                    &tempfile::tempdir().unwrap().keep().join("s.redb"),
                )
                .unwrap(),
            )
        };
        let ep = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap()
        };
        let inviter = iroh::SecretKey::from_bytes(&[41u8; 32]).public();

        // EXPIRED — decided from the line in hand, before any dial.
        let mut expired = sample_invite_for(inviter, 1);
        expired.expires_at_epoch = 1;
        let e = redeem_invite(
            ep().await,
            "me".into(),
            expired.encode(),
            None,
            SelfEnroll::Refuse,
            None,
            store(),
            None,
            None,
        )
        .await
        .expect_err("an expired line must refuse");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITE_EXPIRED),
            "the local expiry pre-check owns ERR_INVITE_EXPIRED: {e:#}"
        );

        // NAME CONFLICT — the invite's suggested name is already ours for a different peer.
        let s = store();
        s.add(crate::allowlist::PeerEntry {
            endpoint_id: [0xAB; 32],
            nickname: "taken".into(),
            services: vec![],
            paired_at: None,
            user_id: None,
            last_addr: None,
        })
        .unwrap();
        let mut named = sample_invite_for(inviter, 9_999_999_999);
        named.nickname = "taken".into();
        let e = redeem_invite(
            ep().await,
            "me".into(),
            named.encode(),
            None,
            SelfEnroll::Refuse,
            None,
            s.clone(),
            None,
            None,
        )
        .await
        .expect_err("a squatting invite must refuse");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITE_NAME_CONFLICT),
            "the redeemer-side squat check owns ERR_INVITE_NAME_CONFLICT: {e:#}"
        );

        // #87: the SAME squatting invite succeeds past the name check when the redeemer supplies
        // its own local alias. This is the whole point — before it, the only fixes were to ask the
        // inviter to re-mint or to unpair whoever holds the name. It still fails afterwards (the
        // sample invite is undialable), but with a DIFFERENT code: the name check is behind it.
        let e = redeem_invite(
            ep().await,
            "me".into(),
            named.encode(),
            Some("their-laptop".into()),
            SelfEnroll::Refuse,
            None,
            s.clone(),
            None,
            None,
        )
        .await
        .expect_err("the sample invite is undialable, so this still fails — just not on the name");
        assert_ne!(
            code_of(&e),
            Some(api::ERR_INVITE_NAME_CONFLICT),
            "an alias must RESOLVE the collision, not merely rename the error: {e:#}"
        );

        // …but an alias that ITSELF collides is refused identically. The alias does not bypass the
        // check — a duplicate display name makes our own `<peer>/<service>` routing ambiguous
        // whoever chose it, which is just as true of a name the local user picked.
        let fresh = sample_invite_for(inviter, 9_999_999_999);
        let e = redeem_invite(
            ep().await,
            "me".into(),
            fresh.encode(),
            Some("taken".into()),
            SelfEnroll::Refuse,
            None,
            s,
            None,
            None,
        )
        .await
        .expect_err("an alias that collides must still refuse");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITE_NAME_CONFLICT),
            "the collision check runs on the name we will STORE, alias or not: {e:#}"
        );

        // UNREACHABLE — an id-only address on the Minimal preset (no relay, no discovery), so
        // there is nothing to dial and it fails immediately. An unroutable IP would exercise the
        // same branch but spend 30s on a connect timeout in every CI run.
        let dead = sample_invite_for(inviter, 9_999_999_999);
        let e = redeem_invite(
            ep().await,
            "me".into(),
            dead.encode(),
            None,
            SelfEnroll::Refuse,
            None,
            store(),
            None,
            None,
        )
        .await
        .expect_err("an undialable inviter must refuse");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITER_UNREACHABLE),
            "the dial failure owns ERR_INVITER_UNREACHABLE: {e:#}"
        );
        assert!(
            e.to_string().contains("dial the inviter"),
            "and its MESSAGE must stay the string the porcelain matches on to explain a \
             self-redeem — rewording it made that branch dead code (#159 gate): {e}"
        );
    }

    /// #178: an enrollment line is refused when the caller did not offer that ceremony — and the
    /// refusal happens BEFORE the dial.
    ///
    /// The two halves are one test on purpose, because each alone is satisfiable by a wrong
    /// implementation:
    ///
    /// - Asserting only the refusal is satisfied by refusing enrollment lines outright, which
    ///   breaks #86. So the SAME line under `Allow` must get past the guard.
    /// - Asserting only "it errors" proves nothing about ORDER — every path through this function
    ///   errors on an undialable inviter. `sample_invite_for` names an id-only address on the
    ///   Minimal preset, so a line that reaches the dial fails with `ERR_INVITER_UNREACHABLE`.
    ///   Getting `ERR_SELF_ENROLL_NOT_OFFERED` instead is what proves nothing was contacted.
    ///
    /// Order is the security property, not a nicety: past the dial the secret is on the wire and
    /// the invite is burned, so a refusal there would cost the credential. Moving the guard below
    /// the `connect` flips this test's first code to `ERR_INVITER_UNREACHABLE`.
    #[tokio::test]
    async fn an_unoffered_self_enrollment_is_refused_before_the_dial() {
        use mcpmesh_local_api as api;
        let code_of = |e: &anyhow::Error| e.downcast_ref::<PairRefusal>().map(|r| r.code());
        let store = || {
            std::sync::Arc::new(
                crate::allowlist::PeerStore::open(
                    &tempfile::tempdir().unwrap().keep().join("s.redb"),
                )
                .unwrap(),
            )
        };
        let ep = || async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .bind()
                .await
                .unwrap()
        };
        let inviter = iroh::SecretKey::from_bytes(&[43u8; 32]).public();

        let mut enroll = sample_invite_for(inviter, 9_999_999_999);
        enroll.as_self = true;
        enroll.services = vec![]; // an enrollment grants nothing
        let line = enroll.encode();

        let e = redeem_invite(
            ep().await,
            "me".into(),
            line.clone(),
            None,
            SelfEnroll::Refuse,
            None,
            store(),
            None,
            None,
        )
        .await
        .expect_err("an enrollment line must be refused when the caller did not offer it");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_SELF_ENROLL_NOT_OFFERED),
            "the guard must own its own code — and getting ERR_INVITER_UNREACHABLE here would \
             mean we dialled first, revealing the secret before deciding: {e:#}"
        );

        // The SAME line, offered: past the guard, so it now fails on the undialable inviter like
        // any other invite. Without this the guard could be a blanket refusal of every
        // `mcpmesh-enroll:` line — which passes the assertion above and breaks #86 entirely.
        let e = redeem_invite(
            ep().await,
            "me".into(),
            line,
            None,
            SelfEnroll::Allow,
            None,
            store(),
            None,
            None,
        )
        .await
        .expect_err("the sample inviter is undialable, so this still fails — just not on consent");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITER_UNREACHABLE),
            "with the ceremony offered, the guard must be OUT of the way: {e:#}"
        );

        // And the guard must not touch an ORDINARY invite: `Refuse` is the default every embedder
        // gets, so if it refused plain pairing lines it would break every caller.
        let plain = sample_invite_for(inviter, 9_999_999_999);
        let e = redeem_invite(
            ep().await,
            "me".into(),
            plain.encode(),
            None,
            SelfEnroll::Refuse,
            None,
            store(),
            None,
            None,
        )
        .await
        .expect_err("still undialable");
        assert_eq!(
            code_of(&e),
            Some(api::ERR_INVITER_UNREACHABLE),
            "an ordinary invite must be unaffected by the self-enrollment guard: {e:#}"
        );
    }

    /// #159, and the load-bearing half: the OPAQUE refusal gains a code without gaining
    /// information.
    ///
    /// The inviter answers one reason for unknown / expired / wrong secret deliberately —
    /// distinguishing them is a redemption oracle, since a prober would learn which guessed
    /// secrets were ever real. #159 asked for "expired vs already consumed" as separate codes;
    /// this is why the answer is no, and `ERR_INVITE_NOT_LIVE` (a fact about the INVITER, not the
    /// secret) is as close as it is safe to get.
    ///
    /// So: same code, same prose, whatever the underlying cause.
    #[test]
    fn the_opaque_refusal_gains_a_code_but_not_information() {
        // The three causes the inviter refuses to distinguish all arrive here identically — an
        // uncoded `PairReply::Refused` carrying REASON_REFUSED.
        let seen: Vec<(i64, String)> = [None, Some(RefusalCode::Unknown)]
            .into_iter()
            .map(|code| {
                let e = refusal_error(REASON_REFUSED, code);
                let refusal = e
                    .downcast_ref::<PairRefusal>()
                    .expect("the opaque refusal must still be branchable");
                (refusal.code(), e.to_string())
            })
            .collect();

        assert!(
            seen.iter()
                .all(|(c, _)| *c == mcpmesh_local_api::ERR_INVITE_REFUSED),
            "one code for the whole opaque family: {seen:?}"
        );
        assert!(
            seen.iter().all(|(_, m)| *m == seen[0].1),
            "and one MESSAGE — a per-cause message would rebuild the oracle in prose that the \
             code refuses to build in a number: {seen:?}"
        );
        assert!(
            !seen[0].1.contains("expired") && !seen[0].1.contains("unknown"),
            "the opaque reason must not name a cause at all: {}",
            seen[0].1
        );

        // And the collision refusal is NOT swallowed into it — that one is safe to distinguish,
        // because it only reaches a caller that already proved possession of a live secret.
        let collision = refusal_error("nickname taken", Some(RefusalCode::NicknameTaken));
        assert!(
            collision.downcast_ref::<NicknameTaken>().is_some(),
            "the recoverable collision keeps its own typed error"
        );
        assert!(
            collision.downcast_ref::<PairRefusal>().is_none(),
            "and must not be re-coded as the opaque refusal"
        );
    }

    /// #147 gate: the code means "rename and redeem the SAME invite again", so it may ride ONLY a
    /// refusal whose invite survived.
    ///
    /// The post-redeem race guard refuses the same collision with the invite already burned. The
    /// first implementation coded it too — every doc then told an embedder to send that user back
    /// to an invite that no longer exists, which is worse than the prose it replaced. This pairs
    /// the two send sites' prose with their coding decision so they cannot drift apart again.
    #[test]
    fn only_a_surviving_invite_earns_the_rename_and_retry_code() {
        // Through `collision_refusal`, which is what BOTH send sites call — not through the
        // pieces. Asserting on `reason_nickname_taken` + `refusal_error` separately passes even
        // when a send site pairs the wrong two, which is precisely the defect this pins.
        let PairReply::Refused { reason, code } = collision_refusal("studio-mac", true) else {
            panic!("expected a refusal");
        };
        assert!(reason.contains("redeem the same invite again"), "{reason}");
        assert_eq!(
            code,
            Some(RefusalCode::NicknameTaken),
            "the recoverable collision is the one that earns the code"
        );

        // The burned-invite collision. Its prose sends the user to a NEW invite, so a consumer
        // acting on the rename-and-retry code here would give the opposite of correct advice.
        let PairReply::Refused { reason, code } = collision_refusal("studio-mac", false) else {
            panic!("expected a refusal");
        };
        assert!(
            reason.contains("ask the inviter for a fresh invite"),
            "{reason}"
        );
        assert!(
            !reason.contains("redeem the same invite again"),
            "the two remedies must stay distinguishable: {reason}"
        );
        assert_eq!(
            code, None,
            "a burned invite must NOT carry the rename-and-retry code — an embedder writing copy \
             off it would send the user back to an invite that no longer exists"
        );
    }

    /// #147: the typed error's `Display` is the inviter's reason verbatim, so the wire message and
    /// the one `respond` renders into `ERR_NICKNAME_TAKEN` cannot drift. Re-deriving the sentence
    /// redeemer-side would be a second source of truth for the string this change exists to
    /// single-source — and the redeemer does not know whether the invite survived.
    #[test]
    fn the_typed_error_displays_the_inviters_reason_verbatim() {
        let wire = reason_nickname_taken("studio-mac", true);
        let e = NicknameTaken(format!("pairing refused: {wire}"));
        assert_eq!(e.to_string(), format!("pairing refused: {wire}"));
        assert!(e.to_string().contains("rename this node"));
    }
}
