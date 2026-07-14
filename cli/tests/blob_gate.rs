//! M4a two-layer D7/D8 composition (spec §9): the accept-time trust gate composes with the
//! request-time scope Intercept gate over the daemon's REAL accept loop. A revoked caller is refused
//! at accept (resolve → None → 401); a valid-but-ungranted roster member is refused at the request
//! hook (Permission). In-process localhost, the same style as `roster_sever.rs`.
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh_blobs::protocol::GetManyRequest;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::ticket::BlobTicket;
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

/// Mint a roster view: each `(endpoint_id, user_id)` is a one-device user in group `team-eng`;
/// `revoked` lists revoked endpoints. Far-future expiry so the gate resolves it.
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

async fn app_alpn_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![
            ALPN_MCP.to_vec(),
            ALPN_PAIR.to_vec(),
            APP_BLOB_ALPN.to_vec(),
        ])
        .bind()
        .await
        .expect("bind provider endpoint")
}

async fn caller_endpoint() -> iroh::Endpoint {
    iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .relay_mode(iroh::RelayMode::Disabled)
        .alpns(vec![APP_BLOB_ALPN.to_vec()])
        .bind()
        .await
        .expect("bind caller endpoint")
}

/// Assemble a serving MeshState with a RosterGate holding `view`, an installed AppBlobs, and the real
/// accept loop running. Returns the mesh + a temp dir kept alive for the store.
async fn serving_provider(
    provider_ep: iroh::Endpoint,
    view: RosterView,
    roster: Arc<RosterGate>,
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

#[tokio::test]
async fn revoked_at_accept_and_ungranted_at_request_are_both_refused() {
    timeout(Duration::from_secs(40), async {
        let root = SigningKey::from_bytes(&[7u8; 32]);
        let provider_ep = app_alpn_endpoint().await;

        let alice_ep = caller_endpoint().await; // granted
        let bob_ep = caller_endpoint().await; // rostered, ungranted
        let alice_id = *alice_ep.id().as_bytes();
        let bob_id = *bob_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice"), (bob_id, "bob")], &[]);
        let (mesh, _dir) = serving_provider(provider_ep.clone(), view, roster.clone()).await;

        // Publish into "docs" and grant to alice ONLY.
        let provider = mesh.app_blobs().await.unwrap();
        let src = _dir.path().join("secret.bin");
        std::fs::write(&src, b"scoped secret").unwrap();
        let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();

        // Seed each caller with the provider's direct address (localhost has no discovery).
        for ep in [&alice_ep, &bob_ep] {
            let mem = iroh::address_lookup::MemoryLookup::new();
            mem.add_endpoint_info(provider_ep.addr());
            ep.address_lookup().expect("lookup").add(mem);
        }

        // (1) GRANTED alice fetches + verifies.
        let alice_dir = tempfile::tempdir().unwrap();
        let alice = AppBlobs::open_fetcher(alice_dir.path().join("b"), alice_ep.clone())
            .await
            .unwrap();
        let hash = alice.fetch(&ticket).await.expect("granted alice fetches");
        assert_eq!(&alice.read_bytes(hash).await.unwrap()[..], b"scoped secret");

        // (2) UNGRANTED bob (rostered → passes accept) is refused at the request hook.
        let bob_dir = tempfile::tempdir().unwrap();
        let bob = AppBlobs::open_fetcher(bob_dir.path().join("b"), bob_ep.clone())
            .await
            .unwrap();
        let bob_res = timeout(Duration::from_secs(10), bob.fetch(&ticket)).await;
        assert!(
            matches!(bob_res, Ok(Err(_))),
            "ungranted bob refused: {bob_res:?}"
        );

        // (3) REVOKE alice's device → the accept-time gate now refuses her at 401.
        let revoked = mint_view(
            &root,
            2,
            &[(alice_id, "alice"), (bob_id, "bob")],
            &[alice_id],
        );
        roster.install(revoked);
        let alice2_dir = tempfile::tempdir().unwrap();
        let alice2 = AppBlobs::open_fetcher(alice2_dir.path().join("b"), alice_ep.clone())
            .await
            .unwrap();
        let revoked_res = timeout(Duration::from_secs(10), alice2.fetch(&ticket)).await;
        assert!(
            matches!(revoked_res, Ok(Err(_))),
            "revoked alice refused at accept: {revoked_res:?}"
        );
    })
    .await
    .expect("blob gate composition timed out");
}

/// M4a hardening (defense-in-depth): the app-blob store serves ONLY single-blob GETs. A `get_many`
/// (hash-sequence) request — issued by a rostered, scope-GRANTED caller who CAN single-GET the very
/// same hash — is REFUSED as a request TYPE (deny-by-default), not as an authz miss. This locks
/// `APP_BLOB_EVENT_MASK`'s `get_many = Disabled` plus the drain loop's explicit
/// `GetManyRequestReceived` deny arm end-to-end over the REAL accept loop, so a future regression
/// that serves get_many ungated (e.g. an iroh-blobs bump that routes get_many past `mask.get`) is
/// caught. The single-blob GET path (the AC fetch) is asserted to still succeed alongside it.
#[tokio::test]
async fn get_many_against_gated_provider_is_refused_even_for_a_granted_caller() {
    timeout(Duration::from_secs(40), async {
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let provider_ep = app_alpn_endpoint().await;
        let alice_ep = caller_endpoint().await; // rostered + granted
        let alice_id = *alice_ep.id().as_bytes();

        let roster = Arc::new(RosterGate::empty());
        let view = mint_view(&root, 1, &[(alice_id, "alice")], &[]);
        let (mesh, _dir) = serving_provider(provider_ep.clone(), view, roster.clone()).await;

        // Publish into "docs" and grant it to alice — she is fully authorized for this hash.
        let provider = mesh.app_blobs().await.unwrap();
        let src = _dir.path().join("secret.bin");
        std::fs::write(&src, b"scoped secret").unwrap();
        let (ticket, _hash) = provider.publish_scope("docs", &src).await.unwrap();
        provider.grant("docs", "alice").unwrap();
        let hash = ticket.parse::<BlobTicket>().unwrap().hash();

        // Seed alice with the provider's direct address (localhost has no discovery).
        let mem = iroh::address_lookup::MemoryLookup::new();
        mem.add_endpoint_info(provider_ep.addr());
        alice_ep.address_lookup().expect("lookup").add(mem);

        // Sanity: the single-blob GET (the AC fetch path) SUCCEEDS for granted alice — unaffected.
        let ok_dir = tempfile::tempdir().unwrap();
        let alice_ok = AppBlobs::open_fetcher(ok_dir.path().join("b"), alice_ep.clone())
            .await
            .unwrap();
        let got = alice_ok
            .fetch(&ticket)
            .await
            .expect("granted single-GET works");
        assert_eq!(got, hash);
        assert_eq!(
            &alice_ok.read_bytes(got).await.unwrap()[..],
            b"scoped secret"
        );

        // The hardening: a `get_many` for the SAME hash by the SAME granted caller is REFUSED.
        // A fresh caller store (no local copy) forces the request onto the wire to the provider.
        let gm_dir = tempfile::tempdir().unwrap();
        let caller_store = FsStore::load(gm_dir.path().join("blobs")).await.unwrap();
        let conn = alice_ep
            .connect(provider_ep.addr(), APP_BLOB_ALPN)
            .await
            .expect("dial app-blob provider");
        let req = GetManyRequest::from_iter([hash]);
        let res = timeout(
            Duration::from_secs(10),
            caller_store.remote().execute_get_many(conn, req).complete(),
        )
        .await;
        assert!(
            matches!(res, Ok(Err(_))),
            "get_many must be refused end-to-end: {res:?}"
        );
    })
    .await
    .expect("get_many refusal test timed out");
}
