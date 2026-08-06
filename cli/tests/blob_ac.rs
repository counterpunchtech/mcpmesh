//! M4a acceptance (spec §16 M4). AC1: a large blob published into a granted scope is fetched by a
//! GRANTED caller through a REAL localhost mesh (the daemon's accept loop, both D7/D8 layers) and
//! BLAKE3-verifies (content-address integrity). AC2 (Task 8) proves the same fetch is refused after
//! revocation and for an ungranted scope.
//!
//! Blob size: 32 MiB in CI (2× the §7.3 16 MiB inline frame cap → unambiguously multi-frame,
//! resumable, BLAKE3-verified streaming — the property under test), overridable to the literal 100
//! MiB via `MCPMESH_AC_BLOB_MB` for the milestone demo. Published via `add_path` on a temp file.
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use mcpmesh::allowlist::{AllowlistGate, PeerStore};
use mcpmesh::blobs::APP_BLOB_ALPN;
use mcpmesh::blobs::provider::AppBlobs;
use mcpmesh::blobs::scope::ScopeStore;
use mcpmesh::daemon::{MeshState, build_services, spawn_accept_loop};
use mcpmesh::pairing::LiveInvites;
use mcpmesh::roster::gate::{ComposedGate, RosterGate};
use mcpmesh_net::registry::ConnRegistry;
use mcpmesh_net::{ALPN_MCP, ALPN_PAIR};
use mcpmesh_trust::roster::sign::mint_signed;
use mcpmesh_trust::roster::validate::{RosterView, load_installed};
use mcpmesh_trust::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
use tokio::time::timeout;

fn ac_blob_bytes() -> usize {
    std::env::var("MCPMESH_AC_BLOB_MB")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32)
        * 1024
        * 1024
}

fn mint_view(
    root: &SigningKey,
    serial: u64,
    users: &[([u8; 32], &str)],
    revoked: &[[u8; 32]],
) -> RosterView {
    let roster_users = users
        .iter()
        .map(|(eid, uid)| RosterUser {
            user_id: (*uid).into(),
            display_name: (*uid).into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: vec!["team-eng".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(eid),
                label: "device".into(),
                role: "primary".into(),
            }],
        })
        .collect();
    let r = mint_signed(
        root,
        Roster {
            format: "mcpmesh-roster/1".into(),
            org_id: "acme".into(),
            serial,
            issued_at: "2000-01-01T00:00:00Z".into(),
            expires_at: "2999-01-01T00:00:00Z".into(),
            groups: vec!["team-eng".into()],
            users: roster_users,
            revoked_endpoints: revoked.iter().map(|e| encode_b64u(e)).collect(),
            successor_root_pk: None,
            successor_sig: None,
            sig: String::new(),
        },
    );
    load_installed(&r, &root.verifying_key()).expect("valid roster view")
}

async fn provider_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            ALPN_MCP.to_vec(),
            ALPN_PAIR.to_vec(),
            APP_BLOB_ALPN.to_vec(),
        ])
        .bind()
        .await
        .expect("bind provider")
}

async fn caller_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![APP_BLOB_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind caller")
}

/// Assemble a serving provider MeshState with the real accept loop + an installed AppBlobs.
pub(crate) async fn serving_provider(
    provider_ep: iroh::Endpoint,
    roster: Arc<RosterGate>,
    view: RosterView,
) -> (Arc<MeshState>, tempfile::TempDir) {
    roster.install(view);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
    let pairs = Arc::new(AllowlistGate::new(store.clone()));
    let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(ComposedGate::new(roster.clone(), pairs));
    let mesh = MeshState::new(
        provider_ep.clone(),
        gate.clone(),
        store,
        Arc::new(LiveInvites::new()),
        "provider".into(),
        dir.path().join("config.toml"),
        roster,
        Arc::new(ConnRegistry::new()),
        None,
        None,
        None,
        None,
    );
    let scopes = Arc::new(ScopeStore::new(dir.path().join("scopes.json")));
    let provider = AppBlobs::load(
        dir.path().join("blobs"),
        scopes,
        gate,
        provider_ep,
        mcpmesh::audit::AuditSink::disabled(),
        mcpmesh::limits::MeshLimiters::unlimited(),
        // #82: the mesh's transfer ring, exactly as `boot` wires it — so a test can observe the
        // frames a real served transfer produces.
        Some(mesh.blob_bcast_for_test().clone()),
        None,
    )
    .await
    .unwrap();
    mesh.set_app_blobs(provider).await;
    let accept = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&Default::default())));
    mesh.set_accept_task(accept).await;
    (mesh, dir)
}

/// Seed `caller` with `provider`'s direct address (localhost has no discovery).
pub(crate) fn seed_addr(caller: &iroh::Endpoint, provider: &iroh::Endpoint) {
    let mem = iroh::address_lookup::MemoryLookup::new();
    mem.add_endpoint_info(provider.addr());
    caller.address_lookup().expect("lookup").add(mem);
}

#[tokio::test]
async fn ac1_granted_caller_fetches_large_blob_and_blake3_verifies() {
    timeout(Duration::from_secs(120), async {
        let root = SigningKey::from_bytes(&[11u8; 32]);
        let provider_ep = provider_endpoint().await;
        let caller_ep = caller_endpoint().await;
        let caller_id = *caller_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(caller_id, "alice")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster, view).await;
        seed_addr(&caller_ep, &provider_ep);

        // Materialize a large temp file with a non-trivial pattern, and record its blake3.
        let size = ac_blob_bytes();
        let src = dir.path().join("large.bin");
        {
            let mut buf = vec![0u8; size];
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            std::fs::write(&src, &buf).unwrap();
        }
        let source_hash = blake3::hash(&std::fs::read(&src).unwrap());

        // Publish into "docs" and grant to the user_id "alice".
        let provider = mesh.app_blobs().await.unwrap();
        let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();

        // The GRANTED caller fetches through the mesh; iroh-blobs BLAKE3-verifies against the ticket
        // hash during streaming. Assert the received bytes match the source (independent blake3).
        let cdir = tempfile::tempdir().unwrap();
        let caller = AppBlobs::open_fetcher(cdir.path().join("b"), caller_ep.clone())
            .await
            .unwrap();
        let hash = caller.fetch(&ticket).await.expect("granted caller fetches");
        let got = caller.read_bytes(hash).await.unwrap();
        assert_eq!(got.len(), size, "full blob streamed");
        assert_eq!(
            blake3::hash(&got),
            source_hash,
            "fetched bytes BLAKE3-verify against the source (content-address integrity)"
        );
    })
    .await
    .expect("AC1 timed out");
}

/// #82 gate: the transfer frames must actually be PRODUCED by a real transfer, on BOTH sides.
///
/// The unit tests exercise `apply_transfer_update` as a pure function, which proves the coalescing
/// arithmetic and nothing about the wiring. Five mutations escaped the whole workspace: deleting
/// `emit_fetch`'s body, making the serve side report `direction: Fetch`, and severing the drain
/// task's call to `apply_transfer_update` all passed. This drives a real
/// publish → grant → fetch and asserts on what came out of both rings.
#[tokio::test]
async fn a_real_transfer_emits_progress_on_both_sides() {
    timeout(Duration::from_secs(120), async {
        let root = SigningKey::from_bytes(&[13u8; 32]);
        let provider_ep = provider_endpoint().await;
        let caller_ep = caller_endpoint().await;
        let caller_id = *caller_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(caller_id, "alice")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster, view).await;
        seed_addr(&caller_ep, &provider_ep);

        // Subscribe to the SERVE ring before anything moves.
        let mut serve_rx = mesh.blob_bcast_for_test().subscribe();

        let size = ac_blob_bytes();
        let src = dir.path().join("progress.bin");
        std::fs::write(&src, vec![7u8; size]).unwrap();
        let provider = mesh.app_blobs().await.unwrap();
        let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();

        // The FETCH side gets its own ring.
        let (fetch_tx, mut fetch_rx) = tokio::sync::broadcast::channel(1024);
        let cdir = tempfile::tempdir().unwrap();
        let caller = AppBlobs::open_fetcher_with_progress(
            cdir.path().join("b"),
            caller_ep.clone(),
            Some(fetch_tx),
        )
        .await
        .unwrap();
        caller.fetch(&ticket).await.expect("granted caller fetches");

        let drain = |rx: &mut tokio::sync::broadcast::Receiver<mcpmesh::daemon::BlobTransfer>| {
            let mut v = Vec::new();
            while let Ok(f) = rx.try_recv() {
                v.push(f);
            }
            v
        };
        let fetch_frames = drain(&mut fetch_rx);
        let serve_frames = drain(&mut serve_rx);

        // --- FETCH side ---
        assert!(
            !fetch_frames.is_empty(),
            "the fetching node must emit progress — `emit_fetch`'s body could be deleted and the \
             whole workspace stayed green"
        );
        assert!(
            fetch_frames
                .iter()
                .all(|f| f.direction == mcpmesh_local_api::BlobDirection::Fetch),
            "every fetch-side frame must be direction=Fetch: {fetch_frames:?}"
        );
        assert!(
            fetch_frames.iter().all(|f| f.bytes_total.is_none()),
            "the fetch side does not learn the size, so bytes_total must be None rather than a \
             guess: {fetch_frames:?}"
        );
        assert_eq!(
            fetch_frames.last().unwrap().state,
            mcpmesh_local_api::BlobTransferState::Completed,
            "a successful fetch ends Completed: {fetch_frames:?}"
        );

        // --- SERVE side ---
        assert!(
            !serve_frames.is_empty(),
            "the serving node must emit progress too — severing the drain task's call to \
             apply_transfer_update passed the whole workspace"
        );
        assert!(
            serve_frames
                .iter()
                .all(|f| f.direction == mcpmesh_local_api::BlobDirection::Serve),
            "every serve-side frame must be direction=Serve: {serve_frames:?}"
        );
        assert_eq!(
            serve_frames.first().unwrap().state,
            mcpmesh_local_api::BlobTransferState::Started
        );
        assert_eq!(
            serve_frames.first().unwrap().bytes_total,
            Some(size as u64),
            "the serving side KNOWS the size from Started"
        );
        assert!(
            serve_frames
                .iter()
                .any(|f| f.peer.as_deref().is_some_and(|p| p.starts_with("eid:"))),
            "the serving side attributes the STABLE principal (#38): {serve_frames:?}"
        );
    })
    .await
    .expect("progress test timed out");
}

#[tokio::test]
async fn ac2_revoked_and_ungranted_fetches_are_refused() {
    timeout(Duration::from_secs(90), async {
        let root = SigningKey::from_bytes(&[13u8; 32]);
        let provider_ep = provider_endpoint().await;

        // alice = granted; bob = rostered (team-eng) but NOT granted "docs".
        let alice_ep = caller_endpoint().await;
        let bob_ep = caller_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();
        let bob_id = *bob_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice"), (bob_id, "bob")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster.clone(), view).await;
        seed_addr(&alice_ep, &provider_ep);
        seed_addr(&bob_ep, &provider_ep);

        // A representative (small) blob into "docs" granted to alice only.
        let src = dir.path().join("scoped.bin");
        std::fs::write(&src, vec![7u8; 4096]).unwrap();
        let provider = mesh.app_blobs().await.unwrap();
        let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();

        // Sanity: alice (granted) CAN fetch first — proves the ticket + mesh are live.
        let a_dir = tempfile::tempdir().unwrap();
        let alice = AppBlobs::open_fetcher(a_dir.path().join("b"), alice_ep.clone())
            .await
            .unwrap();
        alice.fetch(&ticket).await.expect("granted alice fetches");

        // (a) UNGRANTED scope (request-time gate): bob is a valid roster member NOT granted "docs" →
        //     the request Intercept hook denies with Permission → the fetch errors (bounded).
        let b_dir = tempfile::tempdir().unwrap();
        let bob = AppBlobs::open_fetcher(b_dir.path().join("b"), bob_ep.clone())
            .await
            .unwrap();
        let bob_res = timeout(Duration::from_secs(15), bob.fetch(&ticket)).await;
        assert!(
            matches!(bob_res, Ok(Err(_))),
            "ungranted bob refused at the request hook: {bob_res:?}"
        );

        // (b) REVOKED device (accept-time gate): install a roster revoking alice's endpoint → the
        //     blob ALPN accept arm's resolve → None → 401; alice's NEW fetch errors (bounded).
        let revoked = mint_view(
            &root,
            2,
            &[(alice_id, "alice"), (bob_id, "bob")],
            &[alice_id],
        );
        roster.install(revoked);
        let a2_dir = tempfile::tempdir().unwrap();
        let alice2 = AppBlobs::open_fetcher(a2_dir.path().join("b"), alice_ep.clone())
            .await
            .unwrap();
        let revoked_res = timeout(Duration::from_secs(15), alice2.fetch(&ticket)).await;
        assert!(
            matches!(revoked_res, Ok(Err(_))),
            "revoked alice refused at accept: {revoked_res:?}"
        );
    })
    .await
    .expect("AC2 timed out");
}

/// #62: `blob_unpublish` and `blob_revoke` withdraw access OVER THE WIRE, without unpairing.
///
/// The scope gate requires a hash to be listed in some scope AND that scope to grant a caller
/// principal. So removing either the hash (unpublish) or the grant (revoke) must refuse a fetch that
/// worked a moment earlier — and must leave everything else alone, which is the whole point of the
/// per-scope form versus unpair hygiene.
#[tokio::test(flavor = "multi_thread")]
async fn unpublish_and_revoke_withdraw_access_per_scope() {
    timeout(Duration::from_secs(90), async {
        let root = SigningKey::from_bytes(&[19u8; 32]);
        let provider_ep = provider_endpoint().await;
        let alice_ep = caller_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster.clone(), view).await;
        seed_addr(&alice_ep, &provider_ep);

        // Two blobs in two scopes, both granted to alice.
        let doomed_src = dir.path().join("doomed.bin");
        let kept_src = dir.path().join("kept.bin");
        std::fs::write(&doomed_src, vec![1u8; 4096]).unwrap();
        std::fs::write(&kept_src, vec![2u8; 4096]).unwrap();
        let provider = mesh.app_blobs().await.unwrap();
        let (doomed_ticket, doomed_hash) =
            provider.publish_scope("docs", &doomed_src).await.unwrap();
        let (kept_ticket, _) = provider.publish_scope("photos", &kept_src).await.unwrap();
        provider.grant("docs", "alice").unwrap();
        provider.grant("photos", "alice").unwrap();

        let fetch = |ticket: String, tag: &'static str| {
            let ep = alice_ep.clone();
            async move {
                let d = tempfile::tempdir().unwrap();
                let f = AppBlobs::open_fetcher(d.path().join(tag), ep)
                    .await
                    .unwrap();
                timeout(Duration::from_secs(15), f.fetch(&ticket)).await
            }
        };

        // Setup: both fetch.
        assert!(
            matches!(fetch(doomed_ticket.clone(), "a").await, Ok(Ok(_))),
            "granted blob fetches before unpublish"
        );
        assert!(matches!(fetch(kept_ticket.clone(), "b").await, Ok(Ok(_))));

        // UNPUBLISH the first: its hash leaves "docs", so the gate denies it.
        provider.unpublish("docs", &doomed_hash).await.unwrap();
        let after = fetch(doomed_ticket.clone(), "c").await;
        assert!(
            matches!(after, Ok(Err(_))),
            "an unpublished hash must be refused at the request hook: {after:?}"
        );
        // ...and the OTHER scope's blob is untouched — unpublish is not a global delete.
        assert!(
            matches!(fetch(kept_ticket.clone(), "d").await, Ok(Ok(_))),
            "unpublishing from one scope must not affect another"
        );

        // A THIRD blob in a third scope, so the revoke below has something to over-withdraw FROM.
        // Without it this test cannot distinguish a per-scope revoke from the global unpair-hygiene
        // sweep — review proved the whole suite stayed green with `blob_revoke` wired to the global
        // form, because every other scope had already been made unreachable by the unpublish above.
        let other_src = dir.path().join("other.bin");
        std::fs::write(&other_src, vec![3u8; 4096]).unwrap();
        let (other_ticket, _) = provider.publish_scope("audio", &other_src).await.unwrap();
        provider.grant("audio", "alice").unwrap();
        assert!(matches!(fetch(other_ticket.clone(), "e0").await, Ok(Ok(_))));

        // REVOKE alice from "photos" ONLY.
        provider
            .revoke_from_scope("photos", &["alice".to_string()])
            .unwrap();
        let revoked = fetch(kept_ticket, "e").await;
        assert!(
            matches!(revoked, Ok(Err(_))),
            "a revoked grant must refuse the fetch: {revoked:?}"
        );
        // THE over-withdrawal assertion: the untouched scope must still serve. This is what fails
        // if `blob_revoke` is wired to `revoke_principals` (every scope) instead of the scoped form.
        let untouched = fetch(other_ticket, "f").await;
        assert!(
            matches!(untouched, Ok(Ok(_))),
            "revoking one scope must not withdraw grants on another: {untouched:?}"
        );
        assert!(
            roster
                .view()
                .is_some_and(|v| v.resolve(&alice_id).is_some()),
            "alice is still rostered — access was withdrawn, the relationship was not"
        );
    })
    .await
    .expect("blob unpublish/revoke AC timed out");
}

/// #61: a PURE-PAIRING daemon serves app blobs. No org root key, no roster — the trust gate is the
/// pairing `AllowlistGate` alone, and the grant is the caller's `eid:` device principal.
///
/// Before this, the provider was only constructed and the ALPN only advertised inside
/// `if roster_mode`, so content-addressed transfer was unavailable in the mode the quickstart
/// teaches — even though the scope gate never needed a roster.
#[tokio::test(flavor = "multi_thread")]
async fn a_pairing_mode_daemon_serves_app_blobs() {
    timeout(Duration::from_secs(90), async {
        let provider_ep = provider_endpoint().await;
        let caller_ep = caller_endpoint().await;
        let caller_id = *caller_ep.id().as_bytes();

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(PeerStore::open(&dir.path().join("state.redb")).unwrap());
        // The caller is PAIRED — the only trust relationship in play.
        store
            .add(mcpmesh::allowlist::PeerEntry {
                endpoint_id: caller_id,
                nickname: "carol".into(),
                services: vec![],
                paired_at: None,
                user_id: None, // unbound: the eid: principal is the ONLY one she has
                last_addr: None,
            })
            .unwrap();
        // NOT a ComposedGate — a bare pairing gate, exactly what a no-org daemon runs.
        let gate: Arc<dyn mcpmesh_net::TrustGate> = Arc::new(AllowlistGate::new(store.clone()));
        let mesh = MeshState::new(
            provider_ep.clone(),
            gate.clone(),
            store,
            Arc::new(LiveInvites::new()),
            "provider".into(),
            dir.path().join("config.toml"),
            Arc::new(RosterGate::empty()), // no roster installed, ever
            Arc::new(ConnRegistry::new()),
            None,
            None,
            None,
            None,
        );
        let scopes = Arc::new(ScopeStore::new(dir.path().join("scopes.json")));
        let provider = AppBlobs::load(
            dir.path().join("blobs"),
            scopes,
            gate,
            provider_ep.clone(),
            mcpmesh::audit::AuditSink::disabled(),
            mcpmesh::limits::MeshLimiters::unlimited(),
            None,
            None,
        )
        .await
        .unwrap();
        mesh.set_app_blobs(provider).await;
        let accept = spawn_accept_loop(mesh.clone(), Arc::new(build_services(&Default::default())));
        mesh.set_accept_task(accept).await;
        seed_addr(&caller_ep, &provider_ep);

        let src = dir.path().join("attachment.bin");
        std::fs::write(&src, vec![9u8; 4096]).unwrap();
        let p = mesh.app_blobs().await.unwrap();
        let (ticket, _hash) = p.publish_scope("attachments", &src).await.unwrap();
        p.grant("attachments", &format!("eid:{}", caller_ep.id()))
            .unwrap();

        let cdir = tempfile::tempdir().unwrap();
        let carol = AppBlobs::open_fetcher(cdir.path().join("c"), caller_ep.clone())
            .await
            .unwrap();
        carol
            .fetch(&ticket)
            .await
            .expect("a paired peer granted by eid: fetches from a pairing-mode daemon");

        // And the gate still bites: an UNPAIRED endpoint is refused at accept time (401), before
        // any request — advertising the ALPN in pairing mode must not open it to strangers.
        let stranger_ep = caller_endpoint().await;
        seed_addr(&stranger_ep, &provider_ep);
        let sdir = tempfile::tempdir().unwrap();
        let stranger = AppBlobs::open_fetcher(sdir.path().join("s"), stranger_ep)
            .await
            .unwrap();
        let res = timeout(Duration::from_secs(15), stranger.fetch(&ticket)).await;
        assert!(
            matches!(res, Ok(Err(_))),
            "an unpaired stranger must be refused pre-request: {res:?}"
        );
    })
    .await
    .expect("pairing-mode app-blob test timed out");
}

/// #82: the daemon's fetch path STREAMS a blob to disk instead of materializing it in memory.
///
/// The `read_bytes` + `fs::write` path this replaces held the whole blob as one `Bytes` before a
/// byte landed — `get_bytes`' own iroh doc warns it "will run out of memory when called for very
/// large blobs" — so a multi-GB fetch OOM-killed a small node rather than being slow.
///
/// **What this proves and what it does not.** It proves the export path is correct at a non-trivial
/// size: the returned length and the on-disk bytes both match the source. It does NOT prove peak
/// memory is size-independent — that property comes from `Blobs::export` streaming incrementally,
/// and a regression to `read_bytes` would still pass this. Asserting RSS would be platform-specific
/// and flaky; the guarantee rests on the API contract.
#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_fetch_path_exports_to_disk_without_buffering() {
    timeout(Duration::from_secs(120), async {
        let root = SigningKey::from_bytes(&[23u8; 32]);
        let provider_ep = provider_endpoint().await;
        let alice_ep = caller_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster, view).await;
        seed_addr(&alice_ep, &provider_ep);

        // Well past any plausible frame or chunk buffer, but deliberately NOT the 32 MiB the
        // large-transfer AC uses: this test is about export CORRECTNESS at size, and a third
        // 32 MiB blob in a parallel suite starved `blob_gate`'s timeouts into failing. Size the
        // fixture to what it proves.
        const EXPORT_TEST_BYTES: usize = 4 * 1024 * 1024;
        let payload: Vec<u8> = (0..EXPORT_TEST_BYTES).map(|i| (i % 251) as u8).collect();
        let src = dir.path().join("large.bin");
        std::fs::write(&src, &payload).unwrap();
        let provider = mesh.app_blobs().await.unwrap();
        let (ticket, _hash) = provider.publish_scope("media", &src).await.unwrap();
        provider.grant("media", "alice").unwrap();

        // Caller pulls it into its own store, then exports to a destination path — the same two
        // steps `blob_fetch` performs, with the export replacing read_bytes + fs::write.
        let cdir = tempfile::tempdir().unwrap();
        let alice = AppBlobs::open_fetcher(cdir.path().join("c"), alice_ep.clone())
            .await
            .unwrap();
        let hash = alice.fetch(&ticket).await.expect("granted caller fetches");

        let dest = cdir.path().join("exported.bin");
        let written = alice
            .export_to(hash, &dest)
            .await
            .expect("export streams the blob to disk");

        assert_eq!(
            written,
            payload.len() as u64,
            "export reports the full byte count"
        );
        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk.len(), payload.len(), "whole blob landed");
        assert_eq!(on_disk, payload, "and byte-for-byte intact");
    })
    .await
    .expect("streaming fetch test timed out");
}

/// #107 OVER THE WIRE: a withdrawn hash stays refused by the GATE even after a `blob_republish`
/// that would previously have restored it.
///
/// The unit tests prove `republish` returns `BlobWithdrawn`. That is not the security property —
/// the property is that a granted peer's GET is refused on the ALPN. Those are different
/// guarantees, and only this one is the promise made to an operator who ran `blob_unpublish`.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_blob_stays_refused_over_the_wire_after_a_republish_attempt() {
    timeout(Duration::from_secs(90), async {
        let root = SigningKey::from_bytes(&[23u8; 32]);
        let provider_ep = provider_endpoint().await;
        let alice_ep = caller_endpoint().await;
        let alice_id = *alice_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice")], &[]);
        let (mesh, dir) = serving_provider(provider_ep.clone(), roster.clone(), view).await;
        seed_addr(&alice_ep, &provider_ep);

        let src = dir.path().join("withdrawn.bin");
        std::fs::write(&src, vec![7u8; 4096]).unwrap();
        let provider = mesh.app_blobs().await.unwrap();
        let (ticket, hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();

        let fetch = |tag: &'static str| {
            let (ep, ticket) = (alice_ep.clone(), ticket.clone());
            async move {
                let d = tempfile::tempdir().unwrap();
                let f = AppBlobs::open_fetcher(d.path().join(tag), ep)
                    .await
                    .unwrap();
                timeout(Duration::from_secs(15), f.fetch(&ticket)).await
            }
        };

        assert!(
            matches!(fetch("a").await, Ok(Ok(_))),
            "setup: alice fetches before the withdrawal"
        );

        provider.unpublish("docs", &hash).await.unwrap();
        assert!(
            matches!(fetch("b").await, Ok(Err(_))),
            "the gate refuses a withdrawn hash"
        );

        // The bytes are still in the store (#80: no reclaim), so republish is the route that used
        // to bring them back. It must be refused...
        let err = provider
            .republish("docs", &hash)
            .await
            .expect_err("republishing a withdrawn hash must fail");
        assert!(
            err.downcast_ref::<mcpmesh::daemon::BlobWithdrawn>()
                .is_some(),
            "with BlobWithdrawn, so a client can tell it from 'fetch it first': {err}"
        );

        // ...and, the part that actually matters, the peer must STILL be refused on the wire.
        let after = fetch("c").await;
        assert!(
            matches!(after, Ok(Err(_))),
            "a withdrawn blob must remain unfetchable after a republish attempt — the API error is \
             not the guarantee, this is: {after:?}"
        );
    })
    .await
    .expect("withdrawn-over-the-wire test timed out");
}

/// #83 ask 2: a fetch survives the publisher going offline, by falling back to a RECIPIENT that
/// republished the blob.
///
/// The scenario the issue describes is ordinary, not exotic: someone posts a file to a room and
/// closes their laptop. Content addressing makes every recipient a potential source, and the
/// single-address ticket made that unusable — the only address anyone held pointed at the sleeping
/// publisher.
///
/// Three real endpoints, one hard shutdown, and the assertions that matter:
///
/// 1. With the publisher DOWN and no alternates, the fetch fails. Without this the test could pass
///    on a fetch that never needed a fallback at all.
/// 2. With the same dead publisher and a live alternate, it succeeds — and the bytes BLAKE3-verify
///    against the ORIGINAL source, so the fallback served the same blob rather than merely
///    something.
/// #83 follow-up: an UNREACHABLE first source must not cost a full `DIAL_TIMEOUT` before the live
/// alternate is tried.
///
/// This is the property the hedging exists for, and the only one that distinguishes it from the
/// sequential walk it replaced — every other assertion in this file passes either way. #83 was left
/// open on exactly this: *"if a room of eight means walking eight timeouts behind a dead publisher,
/// a bounded parallel race is the obvious follow-up."* At `DIAL_TIMEOUT` = 20s, eight sources is
/// 160 seconds of an indeterminate progress bar that a user cannot tell from a hang.
///
/// The publisher's address is a BLACKHOLE (`127.0.0.1:1` with a live endpoint's id): QUIC is UDP,
/// so packets go nowhere and the dial hangs for the full timeout rather than being refused. Same
/// device `reach.rs` uses to make a probe hang deterministically.
///
/// **The margin is 20x, not a stopwatch.** Hedging starts the alternate after `HEDGE_DELAY` (1s);
/// the sequential walk starts it after `DIAL_TIMEOUT` (20s). Asserting "under 10s" cannot be
/// flake-sensitive at that separation, and it fails unambiguously if hedging is removed — which is
/// the point, since a timing assertion with a tight margin measures the machine rather than the
/// code, and this repo has twice been misled by exactly that.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_first_source_does_not_cost_a_full_dial_timeout() {
    timeout(Duration::from_secs(90), async {
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let pub_ep = provider_endpoint().await;
        let relay_ep = provider_endpoint().await;
        let caller_ep = caller_endpoint().await;
        let (relay_id, caller_id) = (*relay_ep.id().as_bytes(), *caller_ep.id().as_bytes());

        let pub_roster = Arc::new(RosterGate::empty());
        let pub_view = mint_view(&root, 1, &[(relay_id, "bob"), (caller_id, "alice")], &[]);
        let (pub_mesh, pub_dir) = serving_provider(pub_ep.clone(), pub_roster, pub_view).await;

        let relay_roster = Arc::new(RosterGate::empty());
        let relay_view = mint_view(&root, 1, &[(caller_id, "alice")], &[]);
        let (relay_mesh, _relay_dir) =
            serving_provider(relay_ep.clone(), relay_roster, relay_view).await;

        seed_addr(&relay_ep, &pub_ep);
        seed_addr(&caller_ep, &relay_ep);

        let src = pub_dir.path().join("shared.bin");
        let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let source_hash = blake3::hash(&payload);
        let publisher = pub_mesh.app_blobs().await.unwrap();
        let (ticket, hash_hex) = publisher.publish_scope("room", &src).await.unwrap();
        publisher.grant("room", "alice").unwrap();
        publisher.grant("room", "bob").unwrap();

        // The recipient takes a copy and re-serves it, as in the fallback test above.
        let relay_blobs = relay_mesh.app_blobs().await.unwrap();
        relay_blobs.fetch(&ticket).await.unwrap();
        relay_blobs.grant("room", "alice").unwrap();
        relay_blobs.republish("room", &hash_hex).await.unwrap();

        // The publisher's laptop closes. Its id stays valid; its address now goes nowhere.
        pub_ep.close().await;
        drop(pub_mesh);
        let blackhole = iroh::EndpointAddr::from_parts(
            pub_ep.id(),
            [iroh::TransportAddr::Ip("127.0.0.1:1".parse().unwrap())],
        );

        let cdir = tempfile::tempdir().unwrap();
        let caller = AppBlobs::open_fetcher(cdir.path().join("c"), caller_ep.clone())
            .await
            .unwrap();

        let started = std::time::Instant::now();
        let got_hash = caller
            .fetch_from(&ticket, &[blackhole, relay_ep.addr()])
            .await
            .expect("the live recipient must serve it despite the dead publisher");
        let elapsed = started.elapsed();

        assert_eq!(
            blake3::hash(&caller.read_bytes(got_hash).await.unwrap()),
            source_hash,
            "the alternate must serve the SAME blob"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the alternate must be raced against the dead publisher, not started after its \
             20s DIAL_TIMEOUT expires — took {elapsed:?}. A room of eight behind a sleeping \
             publisher is what #83 was left open on.",
        );
    })
    .await
    .expect("hedged blob fetch test timed out");
}

#[tokio::test]
async fn a_fetch_falls_back_to_a_recipient_when_the_publisher_is_gone() {
    timeout(Duration::from_secs(180), async {
        let root = SigningKey::from_bytes(&[23u8; 32]);
        let pub_ep = provider_endpoint().await;
        let relay_ep = provider_endpoint().await; // the recipient that will re-serve
        let caller_ep = caller_endpoint().await;
        let (relay_id, caller_id) = (*relay_ep.id().as_bytes(), *caller_ep.id().as_bytes());

        // The publisher admits both the recipient and the final caller.
        let pub_roster = Arc::new(RosterGate::empty());
        let pub_view = mint_view(&root, 1, &[(relay_id, "bob"), (caller_id, "alice")], &[]);
        let (pub_mesh, pub_dir) = serving_provider(pub_ep.clone(), pub_roster, pub_view).await;

        // The recipient serves too, and admits the caller.
        let relay_roster = Arc::new(RosterGate::empty());
        let relay_view = mint_view(&root, 1, &[(caller_id, "alice")], &[]);
        let (relay_mesh, _relay_dir) =
            serving_provider(relay_ep.clone(), relay_roster, relay_view).await;

        seed_addr(&relay_ep, &pub_ep);
        seed_addr(&caller_ep, &pub_ep);
        seed_addr(&caller_ep, &relay_ep);

        // Publish a blob and grant both readers.
        let src = pub_dir.path().join("shared.bin");
        let payload: Vec<u8> = (0..64_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &payload).unwrap();
        let source_hash = blake3::hash(&payload);
        let publisher = pub_mesh.app_blobs().await.unwrap();
        let (ticket, hash_hex) = publisher.publish_scope("room", &src).await.unwrap();
        publisher.grant("room", "alice").unwrap();
        publisher.grant("room", "bob").unwrap();

        // The recipient fetches it while the publisher is still up, then REPUBLISHES it into a
        // scope of its own that grants the caller. That republish is what makes it a source —
        // #83 ask 1, already shipped; ask 2 is being able to USE it.
        let relay_blobs = relay_mesh.app_blobs().await.unwrap();
        relay_blobs
            .fetch(&ticket)
            .await
            .expect("the recipient fetches from the publisher");
        // Grant first: the scope is created by the grant, and the recipient chooses a scope IT
        // controls rather than inheriting the publisher's grant list — republishing grants nobody
        // (#83), which is why this line is separate and deliberate.
        relay_blobs.grant("room", "alice").unwrap();
        relay_blobs
            .republish("room", &hash_hex)
            .await
            .expect("the recipient re-serves what it holds");

        // The publisher goes away — the closed laptop.
        pub_ep.close().await;
        drop(pub_mesh);

        // (1) No alternates: the fetch must FAIL. Otherwise assertion (2) proves nothing about
        // fallback — it could be succeeding against a publisher that never actually went down.
        let cdir = tempfile::tempdir().unwrap();
        let caller = AppBlobs::open_fetcher(cdir.path().join("c"), caller_ep.clone())
            .await
            .unwrap();
        assert!(
            caller.fetch(&ticket).await.is_err(),
            "with the publisher down and no alternate, the fetch must fail — this is the state \
             #83 describes, and the control for the assertion below"
        );

        // (2) The same dead ticket, with the recipient named as a source — and, AHEAD of it, a
        // source that is perfectly dialable and simply cannot serve this blob.
        //
        // That ordering is the test. The first version of `fetch_from` broke out of its loop the
        // moment a dial SUCCEEDED, so an online-but-ungranted peer ended the whole fetch with the
        // live alternate sitting untried — and that is the ORDINARY case for the room this feature
        // exists for, where some recipients republished and some did not. Review found it by
        // running it. Putting the useless source first means a fetch that only falls back on
        // unreachable dials fails here.
        let useless_ep = provider_endpoint().await;
        let useless_roster = Arc::new(RosterGate::empty());
        let useless_view = mint_view(&root, 1, &[(caller_id, "alice")], &[]);
        let (_useless_mesh, _useless_dir) =
            serving_provider(useless_ep.clone(), useless_roster, useless_view).await;
        seed_addr(&caller_ep, &useless_ep);

        let hash = caller
            .fetch_from(&ticket, &[useless_ep.addr(), relay_ep.addr()])
            .await
            .expect(
                "the fetch must pass OVER a dialable source that cannot serve the blob and fall \
                 back to the recipient that republished it",
            );
        let got = caller.read_bytes(hash).await.unwrap();
        assert_eq!(
            blake3::hash(&got),
            source_hash,
            "and the fallback must serve the SAME blob — the bytes are BLAKE3-verified against \
             the ticket's hash whoever supplies them, so a source can fail but never substitute"
        );
    })
    .await
    .expect("blob source fallback test timed out");
}
