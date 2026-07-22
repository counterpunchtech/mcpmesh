//! Pairing invites. An invite is a one-time bearer credential the inviter
//! mints and hands out-of-band; the redeemer dials the inviter's addr on ALPN
//! `mcpmesh/pair/1`, proves the secret, and both write mutual [`PeerEntry`] rows.
//!
//! This module is pure types + logic (no iroh, no daemon): the [`Invite`] wire type + its
//! `mcpmesh-invite:` line codec, and [`LiveInvites`] — the daemon's in-RAM registry of
//! outstanding invites. The rendezvous handler mints into and redeems out of it.
//!
//! [`PeerEntry`]: crate::allowlist::PeerEntry
pub mod rendezvous;
pub mod sas;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// The scheme prefix of the single copyable pairing artifact.
const INVITE_SCHEME: &str = "mcpmesh-invite:";

/// A one-time pairing invite. Serialized to the `mcpmesh-invite:` line, carried
/// out-of-band, and redeemed once over `mcpmesh/pair/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Single-use bearer credential (32 CSPRNG bytes).
    pub secret: [u8; 32],
    /// The redeemer verifies the TLS peer id == this (the address-swap defense).
    pub inviter_id: [u8; 32],
    /// The inviter's iroh `EndpointAddr` as `serde_json` — dialable, so pairing needs NO
    /// discovery (works on localhost).
    pub inviter_addr_json: String,
    /// Suggested nickname for the inviter (the redeemer's local name for it).
    pub nickname: String,
    /// Services the redeemer is granted (may dial on the inviter).
    pub services: Vec<String>,
    /// Absolute expiry, epoch seconds; `≤ now + 24h`. The daemon enforces it.
    pub expires_at_epoch: u64,
    /// An OPAQUE, caller-chosen application label the inviter attaches at `invite` time, echoed
    /// to the redeemer in the `pair` result (#31). mcpmesh NEVER interprets it: it is never a
    /// nickname, never resolved by `open_session`, never an `allow` authorization token — purely
    /// a per-pairing metadata slot (e.g. the inviter's app-level URN, a manifest hint). Additive:
    /// `#[serde(default)]` so an old invite line decodes to `None` and an old daemon ignores it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_label: Option<String>,
}

/// The maximum length of [`Invite::app_label`], in bytes. The invite line is a human-copied
/// base32 artifact, so the opaque label is kept modest; the daemon rejects a longer one at mint.
pub const MAX_APP_LABEL_LEN: usize = 256;

impl Invite {
    /// One `mcpmesh-invite:<payload>` line. Payload = base32(no-pad) of the JSON-serialized
    /// invite (opaque to humans; the only artifact copied out-of-band — surface
    /// #2). Base32-nopad keeps the line to `[A-Z2-7]` — copy/paste-safe, case-forgiving,
    /// no `=` padding.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serializes");
        format!(
            "{INVITE_SCHEME}{}",
            data_encoding::BASE32_NOPAD.encode(&json)
        )
    }

    /// Parse a `mcpmesh-invite:` line: strip the scheme, base32-decode, JSON-deserialize.
    /// Errors on a missing scheme, an undecodable payload, or JSON that is not an [`Invite`].
    pub fn decode(line: &str) -> anyhow::Result<Self> {
        let payload = line.strip_prefix(INVITE_SCHEME).ok_or_else(|| {
            anyhow::anyhow!("not an mcpmesh invite (missing {INVITE_SCHEME} scheme)")
        })?;
        let json = data_encoding::BASE32_NOPAD
            .decode(payload.as_bytes())
            .context("invite payload is not valid base32")?;
        serde_json::from_slice(&json).context("invite payload is not a valid invite")
    }
}

/// The outcome of a redemption attempt against [`LiveInvites`].
///
/// A pure lookup: an unknown/wrong secret is not in the map → [`Redeem::Unknown`] with NO state
/// change; a matched-but-stale secret → [`Redeem::Expired`] (removed); a matched live secret →
/// [`Redeem::Ok`] (BURNED). There is deliberately no "wrong guess" outcome — see [`LiveInvites`]
/// for why the security model is the secret's entropy, not an attempt cap.
#[derive(Debug)]
pub enum Redeem {
    /// The secret matched a live, unexpired invite; it is now BURNED (removed).
    Ok(Invite),
    /// The secret matched an invite that had already expired; it was removed.
    Expired,
    /// The secret matches no outstanding invite (no state changed).
    Unknown,
}

/// The daemon's in-RAM registry of outstanding invites, keyed by secret.
///
/// **Model.** The redeemer SENDS a secret; the daemon LOOKS IT UP. A wrong/absent secret is
/// simply not in the map → [`Redeem::Unknown`], NO state change — so probing random secrets can
/// never burn or perturb a real invite. A matched live invite is BURNED on redemption
/// (single-use). Security rests ENTIRELY on the 32-byte CSPRNG secret (2^256), NOT on any
/// attempt cap: a per-invite guess counter would be both useless here (a stranger's garbage
/// secret is unattributable to any invite → `Unknown`) AND harmful (attributing garbage to
/// invites would let a stranger invalidate every live invite), so there is none. Map growth is
/// bounded by expiry — [`remove_expired`](Self::remove_expired) is reaped before each production
/// mint (`daemon::mint_invite`). Stranger-flood hardening of the by-design-open pair ALPN (rate
/// limit / read timeout / accept-gate) lives in the accept loop, not in a per-invite cap.
#[derive(Default)]
pub struct LiveInvites {
    inner: Mutex<HashMap<[u8; 32], Invite>>,
}

impl LiveInvites {
    /// A fresh, empty registry — equivalent to [`Default::default`], provided so daemon call
    /// sites read `LiveInvites::new()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the registry. The mutex is only ever held for the duration of a single
    /// map operation (never across `.await`), so poisoning means a prior holder panicked
    /// mid-mutation — unrecoverable; propagate it rather than risk a torn map.
    fn guard(&self) -> MutexGuard<'_, HashMap<[u8; 32], Invite>> {
        self.inner.lock().expect("LiveInvites mutex poisoned")
    }

    /// Insert an outstanding invite (keyed by its secret; a re-mint of the same secret would
    /// replace, but secrets are CSPRNG-unique in practice).
    pub fn mint(&self, invite: Invite) {
        self.guard().insert(invite.secret, invite);
    }

    /// Redeem `secret` at `now_epoch`. Unknown secret → [`Redeem::Unknown`] (no state
    /// change). Known but expired → [`Redeem::Expired`] (removed). Known + live → SUCCESS:
    /// the invite is BURNED (removed) and returned as [`Redeem::Ok`].
    pub fn try_redeem(&self, secret: &[u8; 32], now_epoch: u64) -> Redeem {
        let mut map = self.guard();
        match map.get(secret) {
            None => Redeem::Unknown,
            Some(inv) if inv.expires_at_epoch < now_epoch => {
                map.remove(secret);
                Redeem::Expired
            }
            Some(_) => {
                let inv = map.remove(secret).expect("present under lock");
                Redeem::Ok(inv)
            }
        }
    }

    /// Number of outstanding invites — the live-invite ACCEPT-GATE check: the pair
    /// rendezvous is only "open" while an invite is live. The daemon's
    /// `spawn_accept_loop` `ALPN_PAIR` branch calls this BEFORE `handle_inviter_side`: `count() == 0`
    /// → the pair dial is closed immediately (no bi-stream, no hello, no handler task). Advisory /
    /// coarse (any-invite-live): a racing burn of the last invite is caught authoritatively by
    /// [`try_redeem`](Self::try_redeem) returning `Unknown`, so this is a cheap front-door close
    /// realizing the windowed listener over a permanently-advertised ALPN, not the security boundary.
    pub fn count(&self) -> usize {
        self.guard().len()
    }

    /// Drop every invite that has expired as of `now_epoch`. Reaped before each production mint
    /// ([`daemon::mint_invite`](crate::daemon)) so a long-lived daemon's registry cannot grow
    /// unboundedly with never-redeemed invites.
    pub fn remove_expired(&self, now_epoch: u64) {
        self.guard()
            .retain(|_, inv| inv.expires_at_epoch >= now_epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_invite(secret: u8, expires_at_epoch: u64) -> Invite {
        Invite {
            secret: [secret; 32],
            inviter_id: [3u8; 32],
            inviter_addr_json: "{\"id\":\"abc\",\"addrs\":[]}".into(),
            nickname: "alice".into(),
            services: vec!["notes".into()],
            expires_at_epoch,
            app_label: None,
        }
    }

    #[test]
    fn invite_roundtrips_through_the_line_encoding() {
        let inv = sample_invite(7, 1_800_000_000);
        let line = inv.encode(); // "mcpmesh-invite:<base32 payload>"
        assert!(line.starts_with("mcpmesh-invite:"));
        let back = Invite::decode(&line).unwrap();
        assert_eq!(back, inv);
        // A payload that is not valid base32 for the scheme is rejected.
        assert!(Invite::decode("mcpmesh-invite:!!!not-valid").is_err());
        // A line missing the scheme is rejected.
        assert!(Invite::decode("notaninvite").is_err());
    }

    #[test]
    fn invite_carries_an_opaque_app_label_additively() {
        // #31: an inviter-attached opaque label round-trips through the invite line.
        let mut inv = sample_invite(9, 1_800_000_000);
        inv.app_label = Some("urn:kb-mesh:node:abc123".into());
        let back = Invite::decode(&inv.encode()).unwrap();
        assert_eq!(back.app_label.as_deref(), Some("urn:kb-mesh:node:abc123"));
        assert_eq!(back, inv);

        // An OLD invite line (JSON without the field) decodes to None — additive both ways.
        let no_label = sample_invite(9, 1_800_000_000);
        assert!(no_label.app_label.is_none());
        let json = serde_json::to_vec(&no_label).unwrap();
        // The serialized form omits the field entirely (skip_serializing_if), so it reads like a
        // pre-#31 invite; it still decodes.
        assert!(!String::from_utf8_lossy(&json).contains("app_label"));
        let line = format!(
            "mcpmesh-invite:{}",
            data_encoding::BASE32_NOPAD.encode(&json)
        );
        assert_eq!(Invite::decode(&line).unwrap().app_label, None);
    }

    #[test]
    fn decode_rejects_hostile_payloads_without_panicking() {
        // decode() is the bearer-credential parse path — hostile input must Err, never panic.
        // Empty payload after the scheme → Err (not a panic).
        assert!(Invite::decode("mcpmesh-invite:").is_err());
        // Valid base32 that decodes to well-formed-but-wrong JSON → Err (exercises the
        // serde_json::from_slice error branch, distinct from the base32 branch).
        let not_invite = data_encoding::BASE32_NOPAD.encode(b"{\"nope\":1}");
        assert!(Invite::decode(&format!("mcpmesh-invite:{not_invite}")).is_err());
    }

    #[test]
    fn mint_then_redeem_valid_burns_the_invite() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_800_000_000);
        let secret = inv.secret;
        live.mint(inv.clone());
        assert_eq!(live.count(), 1);
        // First redeem succeeds and returns the invite.
        match live.try_redeem(&secret, 1_000_000_000) {
            Redeem::Ok(got) => assert_eq!(got, inv),
            other => panic!("expected Ok, got {other:?}"),
        }
        // The invite is burned: a second redeem of the same secret is now Unknown.
        assert!(matches!(
            live.try_redeem(&secret, 1_000_000_000),
            Redeem::Unknown
        ));
        assert_eq!(live.count(), 0);
    }

    #[test]
    fn redeem_unknown_secret_is_unknown_and_leaves_other_invites_untouched() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_800_000_000);
        live.mint(inv);
        // An unknown/wrong secret consumes NOTHING — no invite's state changes.
        assert!(matches!(
            live.try_redeem(&[9u8; 32], 1_000_000_000),
            Redeem::Unknown
        ));
        assert_eq!(
            live.count(),
            1,
            "unknown secret must not burn a live invite"
        );
    }

    #[test]
    fn redeem_expired_secret_is_expired_and_removed() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_000);
        let secret = inv.secret;
        live.mint(inv);
        // now is past expiry → Expired, and the stale invite is removed.
        assert!(matches!(live.try_redeem(&secret, 2_000), Redeem::Expired));
        assert_eq!(live.count(), 0);
    }

    #[test]
    fn remove_expired_drops_only_the_stale_invites() {
        let live = LiveInvites::default();
        live.mint(sample_invite(1, 1_000)); // expires early
        live.mint(sample_invite(2, 9_000)); // still live at now=2_000
        assert_eq!(live.count(), 2);
        live.remove_expired(2_000);
        assert_eq!(live.count(), 1);
        // The surviving one is still redeemable.
        assert!(matches!(live.try_redeem(&[2u8; 32], 2_000), Redeem::Ok(_)));
    }
}
