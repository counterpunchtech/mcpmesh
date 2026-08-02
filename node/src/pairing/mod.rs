//! Pairing invites. An invite is a one-time bearer credential the inviter
//! mints and hands out-of-band; the redeemer dials the inviter's addr on ALPN
//! `mcpmesh/pair/1`, proves the secret, and both write mutual [`PeerEntry`] rows.
//!
//! This module is pure types + logic (no iroh, no daemon): the [`Invite`] wire type + its
//! `mcpmesh-invite:` line codec, and [`LiveInvites`] — the daemon's in-RAM registry of
//! outstanding invites. The rendezvous handler mints into and redeems out of it.
//!
//! [`PeerEntry`]: crate::allowlist::PeerEntry
/// On-disk persistence for outstanding invites (#87b) — see the module doc for why a bearer
/// secret is written to disk at all, and why it is not the redb trust store.
pub mod persist;
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
///
/// **Durable since #87b.** The registry was RAM-only, so every restart dropped every outstanding
/// invite while the invite advertised a 24h TTL — an invite emailed to a colleague was reliably
/// dead within a couple of hours on a node that auto-updates. With a [`persist::InviteFile`]
/// attached, every mutation is written through, and [`load`](Self::load) restores the live set at
/// boot. Without one (tests, a control-only node) it behaves exactly as before.
#[derive(Default)]
pub struct LiveInvites {
    inner: Mutex<HashMap<[u8; 32], Invite>>,
    /// Where mutations are written through, if anywhere. `None` = RAM-only (the old behaviour),
    /// which is what every test that does not care about durability gets.
    file: Option<persist::InviteFile>,
    /// Serializes WRITERS, and is the reason the mutating methods are `async`.
    ///
    /// The mutation and its write both happen under this, so two concurrent mints cannot land
    /// their snapshots out of order and lose one. It is a tokio mutex because it is held across
    /// the `spawn_blocking` that does the actual fsync — the `inner` std mutex is still only ever
    /// held for the map operation itself, never across an await.
    writes: tokio::sync::Mutex<()>,
}

impl LiveInvites {
    /// A fresh, empty RAM-only registry — equivalent to [`Default::default`], provided so daemon
    /// call sites read `LiveInvites::new()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry backed by `path`, restored from whatever is still live at `now_epoch`.
    ///
    /// Expired invites are dropped AND the file is rewritten without them, so it cannot accumulate
    /// dead entries across restarts. A rewrite failure here is not fatal — the live set is already
    /// correct in memory, and the next mint will surface a persistent write problem as an error
    /// where it actually matters.
    pub fn load(path: impl Into<std::path::PathBuf>, now_epoch: u64) -> Self {
        let file = persist::InviteFile::new(path);
        // `load` applies the expiry filter, so compare against what is ACTUALLY on disk to decide
        // whether a rewrite is owed.
        //
        // The first version used `!live.is_empty()`, which reads as "something was reaped" and
        // means "something survived" — inverted in both directions (#87b gate). It rewrote on
        // every boot when nothing had expired, and — the one that matters — rewrote NOTHING when
        // everything had. A node whose invites had all expired then held their secrets at rest
        // indefinitely, because with zero live invites no later mutation ever rewrites the file.
        let on_disk = file.load(0).len();
        let live = file.load(now_epoch);
        let reaped = live.len() != on_disk;
        let map: HashMap<[u8; 32], Invite> = live.into_iter().map(|i| (i.secret, i)).collect();
        if reaped && let Err(e) = file.store(&map.values().collect::<Vec<_>>()) {
            tracing::warn!(%e, "could not rewrite the invite file after reaping expired invites");
        }
        Self {
            inner: Mutex::new(map),
            file: Some(file),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    /// Write `snapshot` through to disk, OFF the runtime worker.
    ///
    /// `fsync` is blocking, and this repo's house rule is that blocking work never runs on a
    /// runtime worker — the same rule that already sends a redb READ in the rendezvous through
    /// `spawn_blocking`, which is strictly cheaper than this. It matters more here than usual: the
    /// ALPN_PAIR accept gate takes `inner` on every inbound pair connection, so an fsync held
    /// under that lock on a slow or network-mounted data dir would park workers on a path whose
    /// job is to accept connections.
    ///
    /// Callers hold `writes` across this, so the snapshot they took and the write it produces
    /// cannot be reordered against another writer's.
    async fn persist(&self, snapshot: Vec<Invite>) -> std::io::Result<()> {
        let Some(file) = self.file.clone() else {
            return Ok(());
        };
        crate::util::blocking("join invite persist", move || {
            file.store(&snapshot.iter().collect::<Vec<_>>())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    /// Lock the registry. The mutex is only ever held for the duration of a single
    /// map operation (never across `.await`), so poisoning means a prior holder panicked
    /// mid-mutation — unrecoverable; propagate it rather than risk a torn map.
    fn guard(&self) -> MutexGuard<'_, HashMap<[u8; 32], Invite>> {
        self.inner.lock().expect("LiveInvites mutex poisoned")
    }

    /// Insert an outstanding invite (keyed by its secret; a re-mint of the same secret would
    /// replace, but secrets are CSPRNG-unique in practice).
    ///
    /// **Fails if the invite cannot be persisted (#87b).** The advertised TTL is part of the
    /// invite's contract, and handing someone an invite we already know will not survive the next
    /// restart is exactly the defect this issue filed. A write failure in the data directory is
    /// also a real problem the operator needs to see — the trust store lives there too.
    ///
    /// The in-memory insert is rolled back on a write failure, so the registry never holds an
    /// invite the caller was told it does not have.
    pub async fn mint(&self, invite: Invite) -> std::io::Result<()> {
        let _w = self.writes.lock().await;
        let secret = invite.secret;
        // The std mutex is taken ONLY for the map op and the snapshot — never across the await.
        let (displaced, snapshot) = {
            let mut map = self.guard();
            let displaced = map.insert(secret, invite);
            (displaced, map.values().cloned().collect::<Vec<_>>())
        };
        match self.persist(snapshot).await {
            Ok(()) => Ok(()),
            Err(e) => {
                let mut map = self.guard();
                match displaced {
                    Some(prev) => map.insert(secret, prev),
                    None => map.remove(&secret),
                };
                Err(e)
            }
        }
    }

    /// Is `secret` a LIVE invite at `now_epoch`, without redeeming it? NON-MUTATING — never
    /// burns, never reaps. The #87 collision pre-check runs behind this so a nickname collision
    /// can be refused BEFORE [`try_redeem`](Self::try_redeem) spends the secret: the check is
    /// only reached by a caller holding a live secret, so answering it is not an oracle, and
    /// the invite survives for a retry under a different name. Advisory only — `try_redeem`
    /// stays the authoritative (and racing-safe) redemption.
    pub fn peek_live(&self, secret: &[u8; 32], now_epoch: u64) -> bool {
        self.guard()
            .get(secret)
            .is_some_and(|inv| inv.expires_at_epoch >= now_epoch)
    }

    /// Redeem `secret` at `now_epoch`. Unknown secret → [`Redeem::Unknown`] (no state
    /// change). Known but expired → [`Redeem::Expired`] (removed). Known + live → SUCCESS:
    /// the invite is BURNED (removed) and returned as [`Redeem::Ok`].
    pub async fn try_redeem(&self, secret: &[u8; 32], now_epoch: u64) -> Redeem {
        let _w = self.writes.lock().await;
        // Decide and mutate under the std mutex, then release it BEFORE the write. `Unknown`
        // changes nothing, so it never touches the disk — probing random secrets stays free.
        let (outcome, snapshot) = {
            let mut map = self.guard();
            match map.get(secret) {
                None => return Redeem::Unknown,
                Some(inv) if inv.expires_at_epoch < now_epoch => {
                    map.remove(secret);
                    (Redeem::Expired, map.values().cloned().collect::<Vec<_>>())
                }
                Some(_) => {
                    let inv = map.remove(secret).expect("present under lock");
                    (Redeem::Ok(inv), map.values().cloned().collect::<Vec<_>>())
                }
            }
        };
        inv_persist_burn(self, snapshot).await;
        outcome
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
    /// Persists the reap (#87b gate). The first version mutated memory only, so a reaped invite's
    /// secret stayed on disk until some LATER mutation happened to rewrite the file — and if the
    /// mint that follows the reap failed, nothing ever did. Silent memory/disk divergence on a
    /// file of bearer credentials is not a state to leave reachable.
    pub async fn remove_expired(&self, now_epoch: u64) {
        let _w = self.writes.lock().await;
        let (changed, snapshot) = {
            let mut map = self.guard();
            let before = map.len();
            map.retain(|_, inv| inv.expires_at_epoch >= now_epoch);
            (
                map.len() != before,
                map.values().cloned().collect::<Vec<_>>(),
            )
        };
        if changed {
            inv_persist_burn(self, snapshot).await;
        }
    }
}

/// Persist a BURN (a redemption or an expiry reap) — a removal, so a write failure cannot be rolled
/// back into anything meaningful: the invite is spent either way, and re-adding it would resurrect
/// a credential the peer has already used.
///
/// So this warns rather than failing, deliberately, and it is the OPPOSITE trade from
/// [`LiveInvites::mint`]. The worst case is an invite that survives a restart it should not have —
/// bounded by its own TTL, and still refused by the collision/expiry checks on the next attempt.
/// Failing the redemption instead would deny a pairing that has already legitimately succeeded.
async fn inv_persist_burn(reg: &LiveInvites, snapshot: Vec<Invite>) {
    if let Err(e) = reg.persist(snapshot).await {
        tracing::warn!(
            %e,
            "could not persist an invite burn; it may reappear after a restart until it expires"
        );
    }
}

#[cfg(test)]
mod tests {
    /// #87b: an invite outlives the registry that minted it. This is the whole issue — the
    /// registry was RAM-only while the invite line advertised a 24h TTL, so a node that
    /// auto-updates every couple of hours voided invites its users had already mailed out.
    #[tokio::test]
    async fn an_invite_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.json");
        let inv = sample_invite(1, 9_000);

        let first = LiveInvites::load(&path, 1_000);
        first.mint(inv.clone()).await.unwrap();
        drop(first); // the daemon exits — an update, a crash, a reboot

        let after = LiveInvites::load(&path, 2_000);
        assert_eq!(after.count(), 1, "the invite must still be outstanding");
        assert!(
            matches!(after.try_redeem(&inv.secret, 2_000).await, Redeem::Ok(_)),
            "and must still be redeemable — an invite that survives but cannot be spent is no \
             better than one that did not survive"
        );
    }

    /// #87b: a REDEMPTION is durable too. A burn that lived only in RAM would let a restart
    /// resurrect a spent single-use bearer credential.
    #[tokio::test]
    async fn a_redemption_is_not_undone_by_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.json");
        let inv = sample_invite(2, 9_000);

        let first = LiveInvites::load(&path, 1_000);
        first.mint(inv.clone()).await.unwrap();
        assert!(matches!(
            first.try_redeem(&inv.secret, 1_000).await,
            Redeem::Ok(_)
        ));
        drop(first);

        let after = LiveInvites::load(&path, 1_000);
        assert_eq!(after.count(), 0);
        assert!(
            matches!(after.try_redeem(&inv.secret, 1_000).await, Redeem::Unknown),
            "a spent single-use credential must not be resurrected by a restart"
        );
    }

    /// #87b: an EXPIRED invite does not come back, and the file does not accumulate.
    #[tokio::test]
    async fn an_expired_invite_is_dropped_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.json");
        let dead = sample_invite(3, 5_000);
        let live = sample_invite(4, 9_000);

        let first = LiveInvites::load(&path, 1_000);
        first.mint(dead.clone()).await.unwrap();
        first.mint(live.clone()).await.unwrap();
        drop(first);

        let after = LiveInvites::load(&path, 6_000); // dead has expired
        assert_eq!(after.count(), 1, "only the live one survives");
        assert!(matches!(
            after.try_redeem(&dead.secret, 6_000).await,
            Redeem::Unknown
        ));
        assert!(matches!(
            after.try_redeem(&live.secret, 6_000).await,
            Redeem::Ok(_)
        ));
    }

    /// #87b: a mint that cannot be persisted FAILS, and leaves no phantom in memory.
    ///
    /// Returning `Ok` here would hand back an invite carrying a 24h TTL that we already know will
    /// not survive the next restart — the exact defect this issue filed, re-created one layer
    /// down. The rollback matters just as much: a registry holding an invite the caller was told
    /// it does not have would accept a redemption nobody believes exists.
    #[tokio::test]
    async fn a_mint_that_cannot_persist_fails_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        // The invite path is a DIRECTORY, so the atomic rename can never succeed.
        let path = dir.path().join("invites.json");
        std::fs::create_dir(&path).unwrap();

        let reg = LiveInvites::load(&path, 1_000);
        let inv = sample_invite(5, 9_000);
        assert!(
            reg.mint(inv.clone()).await.is_err(),
            "a mint that cannot promise the TTL it advertises must not report success"
        );
        assert_eq!(reg.count(), 0, "and must leave no phantom behind");
        assert!(matches!(
            reg.try_redeem(&inv.secret, 1_000).await,
            Redeem::Unknown
        ));
    }

    /// #87b gate: a file where EVERYTHING has expired is rewritten empty.
    ///
    /// The first `load` decided "did I reap?" with `!live.is_empty()`, which actually means "did
    /// anything survive" — inverted in both directions. The consequence that matters: with zero
    /// live invites the file was never rewritten, and since no later mutation can happen on a
    /// registry with nothing in it, the expired invites' SECRETS stayed on disk indefinitely.
    ///
    /// The earlier test masked this by keeping one live invite in the fixture, which is the
    /// "empty fixture defaults hide the mutation" shape: seed only what the code exists to remove.
    #[tokio::test]
    async fn an_all_expired_file_is_rewritten_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.json");

        let first = LiveInvites::load(&path, 1_000);
        first.mint(sample_invite(7, 5_000)).await.unwrap();
        first.mint(sample_invite(8, 5_000)).await.unwrap();
        drop(first);

        let after = LiveInvites::load(&path, 9_000); // both expired
        assert_eq!(after.count(), 0);

        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            on_disk, "[]",
            "expired bearer secrets must not sit at rest — with nothing live, no later mutation \
             will ever rewrite this file: {on_disk}"
        );
    }

    /// #87b gate: reaping expired invites is PERSISTED.
    ///
    /// `remove_expired` mutated memory only, so a reap survived on disk until some later mutation
    /// happened to rewrite the file — and if the mint that follows it failed, nothing ever did.
    /// Silent memory/disk divergence on a file of bearer credentials is not a reachable state
    /// worth leaving.
    #[tokio::test]
    async fn reaping_expired_invites_is_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.json");
        let reg = LiveInvites::load(&path, 1_000);
        reg.mint(sample_invite(9, 5_000)).await.unwrap();
        reg.mint(sample_invite(10, 9_000)).await.unwrap();

        reg.remove_expired(6_000).await;
        assert_eq!(reg.count(), 1, "memory drops the expired one");

        let on_disk = persist::InviteFile::new(&path).load(0);
        assert_eq!(
            on_disk.len(),
            1,
            "and so must DISK — otherwise the reaped secret is still readable: {on_disk:?}"
        );
        assert_eq!(on_disk[0].expires_at_epoch, 9_000);
    }

    /// A RAM-only registry still behaves exactly as it did before #87b — the seam is opt-in, and
    /// every test that does not care about durability keeps working unchanged.
    #[tokio::test]
    async fn a_ram_only_registry_is_unchanged() {
        let reg = LiveInvites::new();
        let inv = sample_invite(6, 9_000);
        reg.mint(inv.clone())
            .await
            .expect("a RAM-only mint cannot fail");
        assert_eq!(reg.count(), 1);
        assert!(matches!(
            reg.try_redeem(&inv.secret, 1_000).await,
            Redeem::Ok(_)
        ));
    }

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

    #[tokio::test]
    async fn mint_then_redeem_valid_burns_the_invite() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_800_000_000);
        let secret = inv.secret;
        live.mint(inv.clone()).await.unwrap();
        assert_eq!(live.count(), 1);
        // First redeem succeeds and returns the invite.
        match live.try_redeem(&secret, 1_000_000_000).await {
            Redeem::Ok(got) => assert_eq!(got, inv),
            other => panic!("expected Ok, got {other:?}"),
        }
        // The invite is burned: a second redeem of the same secret is now Unknown.
        assert!(matches!(
            live.try_redeem(&secret, 1_000_000_000).await,
            Redeem::Unknown
        ));
        assert_eq!(live.count(), 0);
    }

    #[tokio::test]
    async fn redeem_unknown_secret_is_unknown_and_leaves_other_invites_untouched() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_800_000_000);
        live.mint(inv).await.unwrap();
        // An unknown/wrong secret consumes NOTHING — no invite's state changes.
        assert!(matches!(
            live.try_redeem(&[9u8; 32], 1_000_000_000).await,
            Redeem::Unknown
        ));
        assert_eq!(
            live.count(),
            1,
            "unknown secret must not burn a live invite"
        );
    }

    #[tokio::test]
    async fn redeem_expired_secret_is_expired_and_removed() {
        let live = LiveInvites::default();
        let inv = sample_invite(7, 1_000);
        let secret = inv.secret;
        live.mint(inv).await.unwrap();
        // now is past expiry → Expired, and the stale invite is removed.
        assert!(matches!(
            live.try_redeem(&secret, 2_000).await,
            Redeem::Expired
        ));
        assert_eq!(live.count(), 0);
    }

    #[tokio::test]
    async fn remove_expired_drops_only_the_stale_invites() {
        let live = LiveInvites::default();
        live.mint(sample_invite(1, 1_000)).await.unwrap(); // expires early
        live.mint(sample_invite(2, 9_000)).await.unwrap(); // still live at now=2_000
        assert_eq!(live.count(), 2);
        live.remove_expired(2_000).await;
        assert_eq!(live.count(), 1);
        // The surviving one is still redeemable.
        assert!(matches!(
            live.try_redeem(&[2u8; 32], 2_000).await,
            Redeem::Ok(_)
        ));
    }
}
