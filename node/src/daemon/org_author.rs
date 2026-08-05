//! Org AUTHORING as control verbs (#66): `org_create`, `org_approve`, `org_revoke`.
//!
//! Roster mode's operator side used to exist only as CLI porcelain. `Request` carried
//! `roster_install` and `org_join` — both CONSUMER verbs — so an embedded node could read a roster
//! someone else authored and nothing more. An embedder that wanted managed group membership had to
//! shell out to the `mcpmesh` binary, which means shipping and version-matching a second artifact
//! and reproducing the enrollment UX in a terminal beside its own UI. Concretely, it could not
//! build an "approve this person" button, which is the single most obvious control a group product
//! needs.
//!
//! These are the same three operations the porcelain performed, moved behind the control seam so
//! both front doors run ONE implementation. `cli/src/enrollcmd.rs` now calls them.
//!
//! # What moved, and what did not
//!
//! The org root key stays exactly where it was — `<config_dir>/org-root.key`, 0600, derived here
//! from `mesh.config_path` the same way [`installed_roster_path`] derives `roster.json`, so a
//! `--profile` root and an embedded node each keep their own. The daemon runs as the caller's own
//! uid and the control socket is same-uid gated, so reading it here crosses no boundary the
//! porcelain did not already cross. What changes is that the key is now read by the process that
//! already owns every other piece of durable trust state, instead of by a second process racing it.
//!
//! The HUMAN half of each ceremony does not move and cannot: verifying that a join code came from
//! the person you think it did is an out-of-band conversation. What the verb returns is the
//! `join_code_fingerprint` the two humans compare — see [`OrgApproveResult`].
use anyhow::{Context, Result};
use mcpmesh_local_api::{OrgApproveResult, OrgCreateResult, OrgRevokeResult};
use mcpmesh_trust::keys::OrgRootKey;
use mcpmesh_trust::roster::sign::{mint_signed, sign, verify_device_binding};
use mcpmesh_trust::roster::{Roster, decode_b64u, decode_endpoint_id, encode_b64u, mutate};

use crate::control::DaemonState;
use crate::daemon::MeshState;
use crate::pairing;
use crate::roster::enroll::{JoinCode, OrgInviteCode};
use crate::util::{blocking, epoch_now_i64};

use super::roster_install::installed_roster_path;

/// The roster validity an `org_create` mints when the caller names none: 90 days.
///
/// Operator-grade, and a sharp edge at small scale — see [`OrgCreateParams::expires_secs`].
///
/// [`OrgCreateParams::expires_secs`]: mcpmesh_local_api::OrgCreateParams::expires_secs
pub(crate) const DEFAULT_EXPIRES_SECS: i64 = 90 * 86_400;

/// This node's org-root key path, derived from `config_path` exactly as
/// [`installed_roster_path`] derives the roster — so the key co-locates with the roster it signs
/// and stays per-node under a `--profile` root or an embedded node's directory.
///
/// Derived rather than stored: a separately-held path could be unset or stale, and an authoring
/// verb that signed with the wrong key — or minted a second root beside an existing one — would
/// orphan every roster already issued.
pub(crate) fn org_root_key_path(mesh: &MeshState) -> std::path::PathBuf {
    mesh.config_path
        .parent()
        .map(|dir| dir.join("org-root.key"))
        .unwrap_or_else(|| std::path::PathBuf::from("org-root.key"))
}

/// Load this operator's org root key + the installed roster — the two artifacts `approve` and
/// `revoke` mutate, re-sign, and install.
///
/// Refuses when either is absent, rather than creating one: an authoring verb on a node that is
/// not an operator is a caller mistake, and minting a root here would silently fork the org.
fn load_operator_roster(mesh: &MeshState) -> Result<(OrgRootKey, Roster)> {
    let key_path = org_root_key_path(mesh);
    anyhow::ensure!(
        key_path.exists(),
        "this node is not an org operator (no org root key); run org_create first"
    );
    let (root, _) = OrgRootKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("org root key error at {}: {e}", key_path.display()))?;
    let roster_path = installed_roster_path(mesh);
    let bytes = std::fs::read(&roster_path)
        .with_context(|| format!("no installed roster at {}", roster_path.display()))?;
    let roster: Roster = serde_json::from_slice(&bytes).context("parse installed roster")?;
    Ok((root, roster))
}

/// Install a roster this node just SIGNED, through the one convergence path every other channel
/// uses ([`install_roster`]) — so an authored roster is validated, persisted, hot-swapped, severed,
/// and AUDITED identically to one that arrived by gossip or URL poll.
///
/// Staged through a temp file because `install_from_file` takes a path; the guard removes it on
/// every return, including the `?` early exits.
///
/// [`install_roster`]: super::roster_install::install_roster
async fn install_authored(
    state: &DaemonState,
    roster: &Roster,
    org_root_pk: Option<String>,
) -> Result<mcpmesh_local_api::RosterInstallResult> {
    let bytes = serde_json::to_vec(roster).context("serialize the authored roster")?;
    // The guard must outlive the install call, so it is bound here rather than in a helper.
    let staged = super::roster_install::write_temp_roster(&bytes)?;
    let path = staged.path().to_string_lossy().into_owned();
    let out = super::roster_install::install_roster(state, path, org_root_pk).await;
    drop(staged);
    out
}

/// `org_create`: mint the org root, sign an EMPTY roster at serial 1, install it (which pins the
/// root), and return the copyable invite + the root's fingerprint.
///
/// **One-time per node.** A second call is refused rather than replacing the key. Replacing it
/// would orphan every roster this node has already signed and silently invalidate every member's
/// pinned anchor — an outcome no caller could have wanted, arriving with no error.
pub(crate) async fn org_create(
    state: &DaemonState,
    name: String,
    expires_secs: Option<i64>,
    roster_url: Option<String>,
) -> Result<OrgCreateResult> {
    let mesh = state.mesh_required()?;
    anyhow::ensure!(!name.trim().is_empty(), "org_create: the org name is empty");
    // The org_id is the string every `allow` entry may name alongside groups and user_ids; a `/`
    // would collide with the `<user>/<device>` revoke grammar.
    anyhow::ensure!(
        !name.contains('/'),
        "org_create: the org name must not contain '/'"
    );
    let key_path = org_root_key_path(mesh);
    let (root, created) = blocking("org_create root key", {
        let key_path = key_path.clone();
        move || OrgRootKey::load_or_generate(&key_path)
    })
    .await?
    .map_err(|e| anyhow::anyhow!("org root key error at {}: {e}", key_path.display()))?;
    anyhow::ensure!(
        created,
        "this node already holds an org root key ({}); org_create is one-time per node",
        key_path.display()
    );

    let expires_secs = expires_secs.unwrap_or(DEFAULT_EXPIRES_SECS);
    anyhow::ensure!(
        expires_secs > 0,
        "org_create: expires_secs must be positive"
    );
    let now = epoch_now_i64();
    let roster = mint_signed(
        root.signing_key(),
        mutate::empty_roster(&name, 1, now, now.saturating_add(expires_secs)),
    );
    let org_root_pk = encode_b64u(&root.public_bytes());
    let installed = install_authored(state, &roster, Some(org_root_pk.clone())).await?;
    // Pin the roster URL through the same single-writer path the `set_roster_url` verb uses, so an
    // operator's poll loop keeps the hosted document current.
    if let Some(url) = &roster_url {
        super::roster_install::set_roster_url(state, url.clone()).await?;
    }
    Ok(OrgCreateResult {
        org_id: installed.org_id,
        serial: installed.serial,
        org_invite: OrgInviteCode {
            org_id: name,
            org_root_pk,
            roster_url,
        }
        .encode(),
        org_root_fingerprint: pairing::sas::fingerprint_words(&root.public_bytes()),
    })
}

/// `org_approve`: verify a join code's device→user-key binding, upsert the member, bump the serial,
/// re-sign, install.
///
/// **The binding is verified BEFORE any mutation.** A forged or corrupt code is refused while the
/// roster is still untouched, so a bad approval cannot leave a half-written document behind.
///
/// What this does NOT verify is that the code came from the person the operator believes it did —
/// nothing in the code binds it to a human. That check is the out-of-band read-back of
/// [`OrgApproveResult::join_code_fingerprint`], which is why the fingerprint is returned rather
/// than merely computed.
pub(crate) async fn org_approve(
    state: &DaemonState,
    join_code: String,
    groups: Vec<String>,
    user_id: Option<String>,
) -> Result<OrgApproveResult> {
    let mesh = state.mesh_required()?;
    // No added context: the decode error is already the user-facing sentence.
    let jc = JoinCode::decode(&join_code)?;
    let user_pk = decode_endpoint_id(&jc.user_pk).context("join code has an invalid user_pk")?;
    let device_id = decode_endpoint_id(&jc.device_endpoint_id)
        .context("join code has an invalid device endpoint")?;
    let sig = decode_b64u(&jc.binding_sig).context("join code has an invalid signature")?;
    verify_device_binding(&user_pk, &device_id, &sig).map_err(|_| {
        anyhow::anyhow!("join code device binding failed — the code is forged or corrupt")
    })?;

    let (root, mut roster) = load_operator_roster(mesh)?;
    let uid = user_id.unwrap_or_else(|| jc.requested_user_id.clone());
    anyhow::ensure!(!uid.trim().is_empty(), "org_approve: the user_id is empty");
    let code_fp = pairing::sas::join_code_fingerprint(&user_pk, &device_id);

    roster.serial += 1;
    mutate::upsert_member(
        &mut roster,
        &uid,
        &jc.display_name,
        &jc.user_pk,
        &groups,
        &jc.device_endpoint_id,
        &jc.device_label,
    )
    .map_err(|e| anyhow::anyhow!("roster mutation rejected: {e}"))?;
    sign(root.signing_key(), &mut roster).map_err(|e| anyhow::anyhow!("sign roster: {e}"))?;

    let installed = install_authored(state, &roster, None).await?; // root already pinned
    Ok(OrgApproveResult {
        user_id: uid,
        groups,
        org_id: installed.org_id,
        serial: installed.serial,
        join_code_fingerprint: code_fp,
    })
}

/// `org_revoke`: mutate the installed roster per the target grammar, bump, re-sign, install — which
/// SEVERS the cut devices' live sessions (#54), not merely refuses their next one.
///
/// Three readings, and the difference between them is destructive, so `mode` is reported back:
/// `"<user>/<device>"` cuts one device; a bare `user_id` removes the person AND revokes every
/// device; `user_key = true` removes the person while leaving their devices un-revoked, which is
/// the rotation case — the same hardware re-enrolls under a fresh user key.
pub(crate) async fn org_revoke(
    state: &DaemonState,
    target: String,
    user_key: bool,
) -> Result<OrgRevokeResult> {
    let mesh = state.mesh_required()?;
    anyhow::ensure!(!target.trim().is_empty(), "org_revoke: the target is empty");
    let (root, mut roster) = load_operator_roster(mesh)?;
    roster.serial += 1;
    let mode = if user_key {
        // Rotation: remove the person, keep the devices un-revoked so the same hardware can
        // re-enroll. Revoking them here is the difference between "rotate a key" and "lock this
        // person out of their own laptop".
        mutate::remove_user(&mut roster, &target, false).map_err(|e| anyhow::anyhow!("{e}"))?;
        "user-key-rotation"
    } else if let Some((person, device)) = target.split_once('/') {
        mutate::revoke_device(&mut roster, person, device).map_err(|e| anyhow::anyhow!("{e}"))?;
        "device"
    } else {
        // Departing: remove AND revoke every device (the hard cut).
        mutate::remove_user(&mut roster, &target, true).map_err(|e| anyhow::anyhow!("{e}"))?;
        "person"
    };
    sign(root.signing_key(), &mut roster).map_err(|e| anyhow::anyhow!("sign roster: {e}"))?;

    let installed = install_authored(state, &roster, None).await?;
    Ok(OrgRevokeResult {
        target,
        mode: mode.to_string(),
        org_id: installed.org_id,
        serial: installed.serial,
        severed: installed.severed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::testutil::hermetic_mesh;
    use mcpmesh_trust::ed25519_dalek::SigningKey;

    async fn operator_state(dir: &std::path::Path) -> DaemonState {
        let config_path = dir.join("config.toml");
        std::fs::write(&config_path, "").unwrap();
        let mesh = hermetic_mesh(config_path).await;
        DaemonState::with_mesh("test", mesh)
    }

    fn join_code_signed_by(
        signer: &SigningKey,
        claimed_user_pk: &[u8; 32],
        device: &[u8; 32],
    ) -> String {
        let sig = mcpmesh_trust::roster::sign::sign_device_binding(signer, device);
        JoinCode {
            display_name: "Alice".into(),
            requested_user_id: "alice".into(),
            user_pk: encode_b64u(claimed_user_pk),
            device_endpoint_id: encode_b64u(device),
            device_label: "laptop".into(),
            binding_sig: encode_b64u(&sig),
        }
        .encode()
    }

    /// #66: an embedder can author an org end to end — create, approve, revoke — over the control
    /// seam alone, with no `mcpmesh` binary anywhere.
    ///
    /// This is the whole issue: the operator side existed only as porcelain, so an embedded node
    /// could consume a roster and never author one. The assertions follow the membership through
    /// `roster_members`, which is what an "approve this person" button would actually render.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_embedder_can_create_approve_and_revoke_over_the_control_seam() {
        let dir = tempfile::tempdir().unwrap();
        let state = operator_state(dir.path()).await;

        let created = org_create(&state, "acme".into(), Some(86_400), None)
            .await
            .expect("org_create mints the root and installs an empty roster");
        assert_eq!(created.org_id, "acme");
        assert_eq!(created.serial, 1, "a fresh org starts at serial 1");
        assert!(
            created.org_invite.starts_with("mcpmesh-org:"),
            "the copyable invite must be the artifact a joiner pastes: {}",
            created.org_invite
        );
        assert!(
            !created.org_root_fingerprint.is_empty(),
            "the fingerprint anchors every joiner's trust and must be shown to the operator"
        );

        // One-time per node: a second create must REFUSE, not replace the key. Replacing it would
        // orphan every roster already signed and silently invalidate every member's pinned anchor.
        let again = org_create(&state, "acme2".into(), None, None)
            .await
            .expect_err("a second org_create must be refused");
        assert!(
            format!("{again:#}").contains("one-time per node"),
            "it must be refused BY THE ONE-TIME GUARD, naming the existing key. Asserting only \
             `is_err()` here proved nothing: without the guard the second create still fails, on \
             the roster serial check, for a reason that has nothing to do with the orphaned root \
             — and the orphaning would already have happened. Got: {again:#}"
        );

        // The org must declare a group before anyone can be approved into it: rule 5b refuses a
        // roster whose user carries an undeclared group, which would make `allow = ["eng"]`
        // ambiguous. So approve with NO groups here, which is the shape a fresh org supports.
        let alice_key = SigningKey::from_bytes(&[9u8; 32]);
        let alice_pk = alice_key.verifying_key().to_bytes();
        let device = [42u8; 32];
        let code = join_code_signed_by(&alice_key, &alice_pk, &device);

        let approved = org_approve(&state, code, vec![], None)
            .await
            .expect("a well-formed join code is approved");
        assert_eq!(
            approved.user_id, "alice",
            "the requested user_id is accepted by default"
        );
        assert_eq!(approved.serial, 2, "an approval bumps the serial");
        assert!(
            !approved.join_code_fingerprint.is_empty(),
            "the fingerprint is the ONLY thing binding this code to a person, and only a human can \
             check it — so it must be returned, not merely computed"
        );

        // …and it is visible through the READ surface an embedder renders (#93).
        let mesh = state.mesh_required().unwrap();
        let members = crate::daemon::roster_members(mesh);
        let alice = members
            .users
            .iter()
            .find(|u| u.user_id == "alice")
            .expect("the approved member appears in the membership read");
        assert_eq!(
            alice.display_name, "Alice",
            "the join code's display name is carried through"
        );
        assert_eq!(alice.devices.len(), 1);
        assert_eq!(alice.devices[0].label, "laptop");

        // Revoke the person: removed AND every device revoked (the hard cut).
        let revoked = org_revoke(&state, "alice".into(), false)
            .await
            .expect("revoke installs");
        assert_eq!(
            revoked.mode, "person",
            "a bare user_id is the departing-person grammar"
        );
        assert_eq!(revoked.serial, 3);
        let after = crate::daemon::roster_members(mesh);
        assert!(
            after.users.is_empty(),
            "the revoked person must be gone from the membership read: {:?}",
            after.users
        );
    }

    /// #66: the user-key ROTATION grammar is not the departure grammar, and the difference is
    /// destructive.
    ///
    /// Both remove the person. Only the departure revokes their devices — a rotation must leave
    /// them un-revoked so the SAME hardware re-enrolls under a fresh user key. Getting this
    /// backwards locks someone out of their own laptop, or leaves a departed employee's device
    /// admissible; `mode` is reported back so a caller can confirm which reading it got.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_key_rotation_leaves_the_devices_usable_and_a_departure_does_not() {
        let alice_key = SigningKey::from_bytes(&[9u8; 32]);
        let alice_pk = alice_key.verifying_key().to_bytes();
        let device = [42u8; 32];

        // Rotation.
        let d1 = tempfile::tempdir().unwrap();
        let s1 = operator_state(d1.path()).await;
        org_create(&s1, "acme".into(), None, None).await.unwrap();
        org_approve(
            &s1,
            join_code_signed_by(&alice_key, &alice_pk, &device),
            vec![],
            None,
        )
        .await
        .unwrap();
        let rot = org_revoke(&s1, "alice".into(), true).await.unwrap();
        assert_eq!(rot.mode, "user-key-rotation");
        let m1 = s1.mesh_required().unwrap();
        assert!(
            !m1.roster.view().unwrap().is_revoked(&device),
            "a ROTATION must leave the device un-revoked — the same hardware re-enrolls under a \
             fresh user key, and revoking it here locks the person out of their own machine"
        );

        // Departure, same starting state.
        let d2 = tempfile::tempdir().unwrap();
        let s2 = operator_state(d2.path()).await;
        org_create(&s2, "acme".into(), None, None).await.unwrap();
        org_approve(
            &s2,
            join_code_signed_by(&alice_key, &alice_pk, &device),
            vec![],
            None,
        )
        .await
        .unwrap();
        let dep = org_revoke(&s2, "alice".into(), false).await.unwrap();
        assert_eq!(dep.mode, "person");
        let m2 = s2.mesh_required().unwrap();
        assert!(
            m2.roster.view().unwrap().is_revoked(&device),
            "a DEPARTURE must revoke the device — otherwise the person's hardware stays admissible \
             after they are removed"
        );
    }

    /// #66: a forged join code dies on the BINDING check, before any roster or operator state is
    /// touched.
    ///
    /// Relocated from the porcelain when the logic moved behind the seam — the property is the
    /// same, and it is about ORDER: this node has no org root key at all, so if the binding check
    /// ran after `load_operator_roster` the error would be "not an org operator". Getting the
    /// binding error instead proves a substituted code is refused while the roster is untouched.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_forged_binding_is_refused_before_any_operator_state_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let state = operator_state(dir.path()).await; // NO org_create — not an operator

        // Mallory signs the binding with HER key while the code claims Alice's user_pk — exactly
        // the substitution the binding check exists to catch.
        let mallory = SigningKey::from_bytes(&[7u8; 32]);
        let alice_pk = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let code = join_code_signed_by(&mallory, &alice_pk, &[42u8; 32]);

        let err = org_approve(&state, code, vec![], None).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("device binding failed"),
            "the forged binding must be the failure — not 'not an org operator', which would mean \
             the check runs after the roster load: {msg}"
        );
    }

    /// #66: authoring verbs on a node that never ran `org_create` must refuse clearly rather than
    /// minting a root and silently forking the org.
    #[tokio::test(flavor = "multi_thread")]
    async fn authoring_on_a_non_operator_node_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let state = operator_state(dir.path()).await;

        let err = org_revoke(&state, "alice".into(), false).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("not an org operator"),
            "revoke on a non-operator must say so: {err:#}"
        );
        // A VALID join code, so this cannot pass on the binding check instead.
        let alice = SigningKey::from_bytes(&[9u8; 32]);
        let code = join_code_signed_by(&alice, &alice.verifying_key().to_bytes(), &[42u8; 32]);
        let err = org_approve(&state, code, vec![], None).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("not an org operator"),
            "approve on a non-operator must say so once the code itself is valid: {err:#}"
        );
    }
}
