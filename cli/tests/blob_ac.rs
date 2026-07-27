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
        provider.unpublish("docs", &doomed_hash).unwrap();
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
