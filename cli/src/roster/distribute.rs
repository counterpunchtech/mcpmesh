//! Roster DISTRIBUTION convergence (spec §4.3): the gossip receive loop that, on a higher-serial
//! announcement, fetches the roster blob (iroh-blobs), then funnels it through the SINGLE
//! convergence point M3a built — `RosterStore::install_from_file` → `install_roster_view_and_sever`
//! (validate rules 1–6 → persist → hot-swap → D8 sever). Every accepting node re-seeds its blob +
//! re-announces, so propagation does not depend on the operator staying online (§4.3 publication).
//! The URL poll (T7) and the manual install (M3a) converge on the SAME code — this module owns the
//! gossip channel; none of the three re-validates independently.
//!
//! **The trust boundary is the org-root signature — nothing else.** A gossip announce, the blob it
//! points at, and the `roster_hash` are content-addressed conveniences that only TRIGGER a fetch;
//! they are NOT trust inputs. A stale/equal serial, a hash mismatch, or a validation failure is
//! logged and IGNORED (fail-safe). There is exactly ONE validator in this path — `install_from_file`
//! (no second `validate_for_install`) — reached under `mesh.reload_lock` (the SAME single-writer
//! discipline as the manual install), re-checking `serial > installed` inside the lock so a racing
//! URL poll / concurrent announce cannot double-install.
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh_blobs::ticket::BlobTicket;

use crate::daemon::{
    MeshState, install_roster_view_and_sever, installed_roster_path, mesh_config_org_root_pk,
    reconcile_user_id_from_roster, write_temp_roster,
};
use crate::roster::RosterStore;
use crate::roster::transport::{self, RosterAnnounce};
use std::time::{Duration, Instant};

/// Per-fetch timeout (spec §11.2 P7): a hung/stalling blob provider can't hold a fetch slot forever;
/// on timeout the announce is dropped fail-safe (a re-announce / the URL poll re-converges).
const GOSSIP_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded off-loop fetch concurrency: the single-consumer receive loop SPAWNS each fetch+install
/// holding one of these permits, so a stalling provider never wedges gossip convergence. A full pool
/// DROPS the announce (fail-safe). Bounds concurrent in-flight fetches (no unbounded spawn).
const GOSSIP_FETCH_CONCURRENCY: usize = 4;
/// Announce-processing rate: bounds how often the loop TRIGGERS a fetch, so an announce-spam flood
/// cannot drive unbounded fetches. A single-consumer bucket on the loop (no lock needed).
const GOSSIP_ANNOUNCE_PER_MIN: u32 = 60;
/// The pinned roster-poll timeout (spec §4.3 HTTPS fallback): a hung host must not wedge the poll.
const POLL_TIMEOUT: Duration = Duration::from_secs(10);
/// The roster-body size cap (spec §4.3): a signed roster for a 20-peer org is a few KiB; 4 MiB is
/// generous. Bounds memory from an oversized/compromised host (the URL is operator-pinned → lower
/// risk, but bounded regardless — no OOM).
const MAX_ROSTER_BYTES: usize = 4 * 1024 * 1024;

/// Announce the CURRENTLY-installed roster on the roster topic (spec §4.3): add its bytes to the
/// local blob store (so this node serves it onward), then broadcast `{serial, roster_hash,
/// blob_ticket}`. Called (a) by the operator's publish path after a serial bump (org approve/revoke,
/// wired in `install_roster`), and (b) by a node that just ACCEPTED a gossip roster (re-seed +
/// re-announce). A pure-pairing daemon (no gossip/blobs) no-ops.
pub async fn announce_roster(mesh: &Arc<MeshState>) -> Result<()> {
    let (Some(_gossip), Some(blobs)) = (mesh.gossip.as_ref(), mesh.blobs.as_ref()) else {
        return Ok(()); // pure-pairing daemon: nothing to announce
    };
    let Some(view) = mesh.roster.view() else {
        return Ok(()); // no roster installed yet (a joiner pre-approval, D5)
    };
    let serial = view.serial();
    let path = installed_roster_path(mesh);
    let bytes = crate::util::blocking("join roster read", move || std::fs::read(path))
        .await?
        .context("read installed roster for announce")?;
    let (ticket, roster_hash) = blobs.publish(&bytes, &mesh.endpoint).await?;
    let announce = RosterAnnounce {
        serial,
        roster_hash,
        blob_ticket: ticket,
    };
    if let Some(sender) = mesh.roster_topic_sender().await {
        transport::broadcast(&sender, announce.to_bytes()).await?;
    }
    Ok(())
}

/// Handle ONE received roster announcement (spec §4.3): if `serial > installed`, fetch the blob,
/// verify its hash, and CONVERGE through the single install path; then re-seed + re-announce.
/// Serialized under `mesh.reload_lock` (the SAME single-writer discipline as the manual install —
/// two channels must not race installs). A stale/equal serial, a hash mismatch, or a validation
/// failure is logged + ignored (fail-safe — the org-root signature is the trust boundary).
pub async fn on_announce(mesh: &Arc<MeshState>, announce: RosterAnnounce) -> Result<()> {
    if announce.serial <= mesh.roster.view().map(|v| v.serial()).unwrap_or(0) {
        return Ok(()); // not newer (also the re-announce idempotence) — fail-safe ignore
    }
    let Some(blobs) = mesh.blobs.as_ref() else {
        return Ok(()); // pure-pairing daemon (defensive — this loop only spawns in roster mode)
    };
    // [RECONCILE-BLOB-API forward note] Seed the ticket's provider addr into THIS endpoint's address
    // book BEFORE the fetch: `blobs.fetch` resolves the provider by `ticket.addr().id` via the
    // endpoint's address lookup, and the provider (the operator, or a re-seeder) may be a node whose
    // addr we do not already know. The ticket embeds the full `EndpointAddr`, so a per-fetch
    // `MemoryLookup` add makes the fetch resolve. A malformed ticket string falls through to `fetch`,
    // which returns a typed Err (fail-safe). This add is idempotent + additive (never removes a
    // known addr), so it is safe even when the addr is already known (the localhost test case).
    if let Ok(ticket) = announce.blob_ticket.parse::<BlobTicket>() {
        // Seed the ticket's provider addr into this endpoint's address book BEFORE the fetch. Bounded
        // (spec §11.2 P7): the shared RosterAddrBook dedups by id under a cap; the per-fetch fallback
        // (tests without a registered book) is the M3c behavior.
        if let Some(book) = mesh.roster_addr_book() {
            book.note(ticket.addr().clone());
        } else {
            let mem = iroh::address_lookup::MemoryLookup::new();
            mem.add_endpoint_info(ticket.addr().clone());
            if let Ok(lookup) = mesh.endpoint.address_lookup() {
                lookup.add(mem);
            }
        }
    }
    let bytes = match tokio::time::timeout(
        GOSSIP_FETCH_TIMEOUT,
        blobs.fetch(&announce.blob_ticket, &announce.roster_hash, &mesh.endpoint),
    )
    .await
    {
        Ok(r) => r.context("fetch announced roster blob")?,
        Err(_) => {
            tracing::debug!("gossip roster fetch timed out; dropping (will re-converge)");
            return Ok(()); // FAIL-SAFE: a re-announce or the URL poll re-converges
        }
    };

    if converge_roster_bytes(mesh, &bytes, announce.serial, "gossip").await? {
        // Re-seed + re-announce so propagation does not depend on the operator staying online (§4.3).
        return announce_roster(mesh).await;
    }
    Ok(())
}

/// Converge fetched roster BYTES through the SINGLE install path — the shared convergence tail of
/// BOTH distribution channels ([`on_announce`] gossip + [`poll_roster_url_once`] URL): serialized
/// under `mesh.reload_lock` (the SAME single-writer discipline as the manual install), re-check
/// `serial > installed` INSIDE the lock (a racing channel may have installed it — idempotent
/// no-op), resolve the pinned org-root anchor, bridge the bytes to a temp file, and converge via
/// `RosterStore::install_from_file` — the ONLY validator (rules 1–6 incl. the org-root SIG +
/// serial>installed; the announce/blob/hash/served-body only TRIGGERED the fetch) — then confirm
/// freshness (T9: a validated roster from an authenticated channel is proof of currency),
/// hot-swap + D8-sever ([`install_roster_view_and_sever`]), and reconcile the config user_id
/// ([RECONCILE-D]).
///
/// Returns whether an install actually happened (`false` = lost the under-lock serial race — a
/// fail-safe no-op). The CALLER re-seeds/re-announces on `true` (the channels differ in how they
/// treat an announce failure). The MANUAL `install_roster` deliberately does NOT route through
/// here: it takes a PATH (not bytes), resolves/pins an EXPLICIT trust anchor under its own held
/// `reload_lock`, and returns the severed count to the operator — a different contract.
async fn converge_roster_bytes(
    mesh: &Arc<MeshState>,
    bytes: &[u8],
    serial: u64,
    channel: &'static str,
) -> Result<bool> {
    let _reload = mesh.reload_lock.lock().await;
    if serial <= mesh.roster.view().map(|v| v.serial()).unwrap_or(0) {
        return Ok(false);
    }
    let pk = crate::roster::parse_org_root_pk(
        &mesh_config_org_root_pk(mesh)?.context("no pinned org root; cannot accept roster")?,
    )?;
    let tmp = write_temp_roster(bytes)?;
    let rstore = RosterStore::new(installed_roster_path(mesh));
    let now = crate::util::epoch_now_i64();
    // `tmp` moves into the closure: its guard removes the temp file when the install returns
    // (success and failure alike).
    let view = crate::util::blocking("join roster install", move || {
        rstore.install_from_file(tmp.path(), &pk, now)
    })
    .await??;
    mesh.confirm_roster_current(now).await;
    let severed = install_roster_view_and_sever(mesh, view);
    reconcile_user_id_from_roster(mesh).await;
    drop(_reload);
    tracing::info!(serial, severed, channel, "installed roster");
    Ok(true)
}

/// GET `url` with a total `timeout` and a hard body `max` (spec §4.3 HTTPS fallback hardening). FAIL-
/// SAFE: a slow host errors (the caller retries next interval, failing toward degraded, D5); an
/// oversized body errors BEFORE the whole thing is buffered (no OOM). [RECONCILE R5]: uses
/// `Response::chunk()` under `reqwest default-features=false, rustls-no-provider`.
pub(crate) async fn fetch_capped(url: &str, max: usize, timeout: Duration) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("build roster poll client")?;
    let mut resp = client
        .get(url)
        .send()
        .await
        .context("GET roster url")?
        .error_for_status()
        .context("roster url status")?;
    // Fast reject on an honest Content-Length; the streaming cap below catches a lying/absent one.
    if let Some(len) = resp.content_length() {
        anyhow::ensure!(
            len as usize <= max,
            "roster body exceeds {max} bytes (content-length {len})"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("read roster url body chunk")? {
        anyhow::ensure!(
            body.len() + chunk.len() <= max,
            "roster body exceeds {max} bytes (streamed)"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Poll the pinned roster URL over TLS ONCE (spec §4.3 HTTPS fallback). GET the URL → body bytes →
/// parse the served roster's serial. If it is NEWER than installed, CONVERGE through the SAME single
/// install path [`on_announce`] uses — `RosterStore::install_from_file` → `install_roster_view_and_sever`
/// (validate rules 1–6 incl. the org-root SIG → persist → hot-swap → D8 sever); no second validator.
/// On an EQUAL served serial (no new roster) CONFIRM currency (`MeshState::confirm_roster_current`,
/// the freshness bump, T9) — the URL poll is the ONLY channel that confirms freshness without a serial
/// bump — but ONLY when the served body is genuinely the operator's org-root-SIGNED roster (rule 1
/// re-verified against the pinned pk, `equal_serial_body_is_authentic`): the HTTPS host is UNTRUSTED,
/// so an unsigned / wrong-org body at the installed serial is logged and IGNORED (invariant #1 — the
/// org-root sig is the sole trust input across ALL channels, uniform with the gossip + newer-serial
/// paths, so an unauthenticated body can never forge currency, P13 fail-safe). A blocked / failed poll
/// returns `Err` (the loop logs it and retries next interval, failing toward degraded, D5); an
/// unparseable body or a stale served serial is logged HERE (at warn / debug) and ignored — the
/// announce/blob/hash are NOT trust inputs; the org-root signature is the sole trust boundary.
///
/// Serialized under `mesh.reload_lock` (the SAME single-writer discipline as the manual + gossip
/// installs). The convergence re-checks `serial > installed` INSIDE the lock (idempotent against a
/// racing gossip announce), and `install_from_file`'s own `StaleSerial` is the on-disk backstop. The
/// roster path is derived from `config_path` via `installed_roster_path` (the DECLARED T6 deviation),
/// so this install path is per-node in the multi-daemon integration tests — consistent with `on_announce`.
pub async fn poll_roster_url_once(mesh: &Arc<MeshState>, url: &str) -> Result<()> {
    let body = fetch_capped(url, MAX_ROSTER_BYTES, POLL_TIMEOUT)
        .await
        .context("poll roster url")?;
    let now = crate::util::epoch_now_i64();
    let installed = mesh.roster.view().map(|v| v.serial()).unwrap_or(0);
    // Keep the WHOLE parsed roster (not just its serial): the equal-serial confirm re-verifies the
    // served body's org-root signature (rule 1) before it accepts the body as proof of currency.
    let parsed = serde_json::from_slice::<mcpmesh_trust::roster::Roster>(&body).ok();
    let parsed_serial = parsed.as_ref().map(|r| r.serial);
    if let Some(s) = parsed_serial.filter(|s| *s > installed) {
        // Converge through the SHARED single-writer tail (the announce side runs the identical
        // thing — the SAME install_from_file, no second validator; serial re-checked under the lock).
        if converge_roster_bytes(mesh, &body, s, "url-poll").await? {
            // Re-seed + re-announce onto gossip too (operator-offline-safe propagation, §4.3).
            let _ = announce_roster(mesh).await;
        }
    } else if let Some(s) = parsed_serial {
        // `s <= installed` (the newer branch caught `s > installed`).
        if s == installed {
            // Equal serial: CONFIRM currency without a bump — the freshness signal gossip/manual cannot
            // give (they only fire on a NEW serial). But ONLY on org-root-AUTHENTICATED bytes: the
            // pinned HTTPS host is UNTRUSTED, so the served body must re-verify rule 1 (the org-root
            // signature — the SOLE trust input, uniform across ALL channels, invariant #1) against the
            // pinned pk before it can bump `last_confirmed`. Otherwise a compromised/spoofed host could
            // serve an unsigned body at the installed serial and forge currency, defeating the P13
            // staleness fail-safe. A parse-success is NOT authentication. (Note `installed == 0` — no
            // roster yet — with a served serial 0 never reaches here: a valid roster is serial ≥ 1, so
            // serial 0 lands in the stale branch.)
            if equal_serial_body_is_authentic(mesh, parsed.as_ref()) {
                mesh.confirm_roster_current(now).await;
            } else {
                // Fail-safe: DON'T refresh currency from an unauthenticated body — but never degrade or
                // error the node. The existing `last_confirmed` stands and degrades normally if no
                // authenticated confirm arrives (P13). The newer + stale branches are unchanged.
                tracing::warn!(
                    serial = s,
                    "roster URL served an unauthenticated/mismatched body at the installed serial; \
                     not confirming currency (org-root sig is the sole trust input)"
                );
            }
        } else {
            // Stale served serial (`s < installed`): the host is serving an OLDER roster than we hold.
            // Never installed, never confirms — but surface it (a misconfigured/rolled-back host).
            tracing::debug!(
                serial = s,
                installed,
                "roster URL served a stale (older) serial; ignoring"
            );
        }
    } else {
        // The body did not parse as a signed roster: a garbage / misconfigured / wrong-content URL.
        // Was previously a SILENT `Ok(())` — now surfaced at warn so a bad `[roster].url` is visible.
        tracing::warn!("roster URL body did not parse as a signed roster; check [roster].url");
    }
    Ok(())
}

/// Is `parsed` genuinely the operator's org-root-SIGNED roster — the authentication the equal-serial
/// currency confirm REQUIRES before it bumps `last_confirmed` (spec §4.3 P13, invariant #1)? The
/// pinned HTTPS host is UNTRUSTED; the org-root signature is the SOLE trust input across ALL channels.
/// The gossip + newer-serial paths already enforce it (via `install_from_file` → rule 1); this closes
/// the equal-serial confirm so a compromised/spoofed host serving an UNSIGNED or WRONG-ORG body at the
/// installed serial cannot forge currency and defeat the staleness fail-safe. Re-runs the EXACT rule-1
/// verify ([`mcpmesh_trust::roster::sign::verify`]) `install_from_file` uses, against the LIVE-pinned
/// org-root pk ([`mesh_config_org_root_pk`], read fresh). The caller invokes this only in the
/// equal-serial branch, where the parsed serial already equals the installed serial — so a passing
/// rule-1 check means the host served genuinely the operator's signed roster AT the installed serial.
/// Returns false — NEVER errors — on a parse-fail body, no pinned pk, an unreadable/invalid pk, or a
/// bad signature; the caller then logs + skips, leaving `last_confirmed` to degrade normally (P13).
fn equal_serial_body_is_authentic(
    mesh: &Arc<MeshState>,
    parsed: Option<&mcpmesh_trust::roster::Roster>,
) -> bool {
    let Some(roster) = parsed else {
        return false;
    };
    let Ok(Some(pk_b64)) = mesh_config_org_root_pk(mesh) else {
        return false;
    };
    let Ok(pk) = crate::roster::parse_org_root_pk(&pk_b64) else {
        return false;
    };
    mcpmesh_trust::roster::sign::verify(roster, &pk).is_ok()
}

/// Spawn the URL-poll loop (spec §4.3 HTTPS fallback) — roster mode with a `[roster].url` set. Calls
/// [`poll_roster_url_once`] immediately (so a joiner bootstraps its FIRST roster at startup, D5) and
/// then every `interval_secs` (config `[roster].poll_interval`, default hourly). A failed poll is
/// logged at debug and retried next interval (fails toward degraded, never crashes the loop). The
/// detached handle runs for the daemon lifetime.
pub fn spawn_poll_loop(
    mesh: Arc<MeshState>,
    url: String,
    interval_secs: i64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let period = std::time::Duration::from_secs(interval_secs.max(1) as u64);
        loop {
            if let Err(e) = poll_roster_url_once(&mesh, &url).await {
                tracing::debug!(%e, "roster URL poll failed; will retry next interval");
            }
            tokio::time::sleep(period).await;
        }
    })
}

/// Spawn the roster-topic receive loop: pull announcements off the receiver and dispatch each to
/// [`on_announce`]. Runs for the daemon lifetime (the loop ends when the topic stream closes). A
/// malformed payload is dropped without a panic (the receive path is fed arbitrary peer bytes); a
/// `None` receiver (pure-pairing daemon, or already taken) returns immediately.
pub fn spawn_receive_loop(mesh: Arc<MeshState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(mut receiver) = mesh.take_roster_topic_receiver().await else {
            return;
        };
        // Bounded off-loop fetch concurrency (spec §11.2 P7): a stalling provider must not wedge the
        // loop, so each accepted announce SPAWNS its fetch+install holding one of these permits.
        let fetch_slots =
            std::sync::Arc::new(tokio::sync::Semaphore::new(GOSSIP_FETCH_CONCURRENCY));
        // Single-consumer announce rate bucket (this loop is the ONLY consumer — a plain owned bucket,
        // no lock). Bounds how often we TRIGGER a fetch.
        let mut announce_bucket = crate::limits::TokenBucket::new(
            f64::from(GOSSIP_ANNOUNCE_PER_MIN),
            f64::from(GOSSIP_ANNOUNCE_PER_MIN) / 60.0,
            Instant::now(),
        );
        while let Some(content) = transport::next_message(&mut receiver).await {
            let announce = match RosterAnnounce::from_bytes(&content) {
                Ok(a) => a,
                Err(e) => {
                    tracing::debug!(%e, "malformed roster announce dropped");
                    continue;
                }
            };
            // Rate-limit announce PROCESSING (fail-safe drop over-limit).
            if announce_bucket.try_take(Instant::now()).is_err() {
                tracing::debug!("gossip announce rate limit engaged; dropping announce");
                continue;
            }
            // Bounded concurrency: a free permit → spawn the fetch+install; a full pool DROPS the
            // announce (a re-announce / the URL poll re-converges). The loop keeps pulling announces.
            // [RECONCILE R1]: `on_announce` still installs under `mesh.reload_lock` with a
            // `serial > installed` recheck, so concurrent handlers are idempotent (single-convergence
            // preserved) and `reload_lock` is only ever a source here (no cycle).
            let Ok(permit) = fetch_slots.clone().try_acquire_owned() else {
                tracing::debug!("gossip fetch pool full; dropping announce (will re-converge)");
                continue;
            };
            let mesh2 = mesh.clone();
            tokio::spawn(async move {
                let _permit = permit; // held for the whole fetch+install
                if let Err(e) = on_announce(&mesh2, announce).await {
                    tracing::debug!(%e, "gossip roster announce handling failed");
                }
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// A one-shot HTTP/1.1 server: sends `status` + `body`, optionally sleeping first (a hung host).
    fn serve_once(body: Vec<u8>, sleep_ms: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                if sleep_ms > 0 {
                    std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/roster.json")
    }

    /// reqwest 0.13.4 (`default-features=false, rustls-no-provider`) resolves the rustls
    /// `CryptoProvider` at `Client::builder().build()` and PANICS ("No rustls crypto provider is
    /// configured") if none is installed — scheme-INDEPENDENT, so even an http:// test URL panics.
    /// Same requirement as M3c T7 + the existing `tests/roster_distribute.rs` polls; the daemon's
    /// `serve_forever` installs it process-wide once. `install_default` errors if already installed,
    /// so `let _ =` makes repeated test calls idempotent.
    fn install_ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[tokio::test]
    async fn fetch_capped_reads_a_small_body() {
        install_ring();
        let url = serve_once(b"{\"format\":\"mcpmesh-roster/1\"}".to_vec(), 0);
        let got = fetch_capped(&url, 1024, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(got.starts_with(b"{\"format\""));
    }

    #[tokio::test]
    async fn fetch_capped_rejects_an_oversized_body_without_oom() {
        install_ring();
        // 2 MiB body, cap 64 KiB → rejected before the whole body is buffered.
        let url = serve_once(vec![b'x'; 2 * 1024 * 1024], 0);
        let err = fetch_capped(&url, 64 * 1024, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("exceeds"),
            "size cap rejects: {err:#}"
        );
    }

    #[tokio::test]
    async fn fetch_capped_times_out_a_hung_host() {
        install_ring();
        let url = serve_once(b"late".to_vec(), 2000);
        let err = fetch_capped(&url, 1024, Duration::from_millis(200))
            .await
            .unwrap_err();
        // A timeout is an Err (the poll loop logs + retries next interval, failing toward degraded).
        let _ = err;
    }
}
