//! Enrollment porcelain — the `join` / `org create|approve|revoke` / `devices code|add`
//! verbs: user-key minting, device-binding signing/verification, roster mutation +
//! re-signing, and the staged-temp-install pipeline. Lives in the lib so the flow is reachable
//! by unit tests and an embedding shell; the binary's clap layer dispatches here, one line per
//! verb, and keeps only the pure render helpers.

use anyhow::Context;
use mcpmesh_local_api::RosterInstallResult;
use mcpmesh_trust::{DeviceKey, paths};

use crate::{client, config, pairing, roster, util};

/// Build a runtime, auto-start/connect the daemon, and run `f` against the connected control
/// client — the shared preamble every daemon-backed porcelain verb repeated (runtime build +
/// `ensure_daemon` + block_on). One runtime per call is fine: each verb is a short-lived CLI
/// process (and `install_signed_roster` may run it once per org mutation).
pub fn with_daemon<T>(
    f: impl AsyncFnOnce(client::ControlClient) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let client = client::ensure_daemon().await?;
        f(client).await
    })
}

/// Default roster validity window when `--expires` is omitted (a modest, operator-managed
/// default; freshness is bounded separately by `[roster].max_staleness`). 90 days.
const DEFAULT_EXPIRES_SECS: i64 = 90 * 86_400;

/// Slug a display name to a stable, human-legible user_id: lowercase, non-[a-z0-9] → '-', collapse
/// and trim '-'. `"Alice Nguyen"` → `"alice-nguyen"`. Empty → "user".
fn slug(name: &str) -> String {
    let mut s = String::new();
    let mut last_dash = true; // trims a leading dash
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            s.push('-');
            last_dash = true;
        }
    }
    while s.ends_with('-') {
        s.pop();
    }
    if s.is_empty() { "user".to_string() } else { s }
}

/// `mcpmesh join <org-invite>`: mint the user key (0600, local), sign this device's binding, pin the
/// org root through the daemon, and print the join code + the DUAL trust ceremony.
/// The user key never crosses the API — only its PUBLIC half (in the join code) + its path (via
/// `OrgJoin`) leave this function; the private key stays 0600 on disk. Surface-clean: only
/// the opaque join code + the two ceremony fingerprints print — no raw keys / endpoint ids / paths.
pub fn run_join(
    org_invite: String,
    name: Option<String>,
    user_id: Option<String>,
    label: String,
    json: bool,
) -> anyhow::Result<()> {
    use mcpmesh_trust::keys::UserKey;
    use mcpmesh_trust::roster::encode_b64u;
    use mcpmesh_trust::roster::sign::sign_device_binding;

    // No added context: the decode error is already the user-facing sentence ("not an
    // mcpmesh-org: code (missing scheme)") — a wrapper here just repeated it (issue #10).
    let invite = roster::enroll::OrgInviteCode::decode(&org_invite)?;
    // Confirm the pinned org root parses (so we can render its fingerprint for the ceremony).
    let root_pk = mcpmesh_trust::roster::decode_endpoint_id(&invite.org_root_pk)
        .context("org invite carries an invalid org_root_pk")?;
    // Display name defaults to "user" when --name is omitted; the operator normally sets a real name.
    let display_name = name.unwrap_or_else(|| "user".to_string());
    let requested_user_id = user_id.unwrap_or_else(|| slug(&display_name));

    // Mint the user key locally (0600; never leaves the machine — only its public half + the binding
    // signature ride in the join code, and only its PATH crosses the API via OrgJoin).
    let user_key_path = paths::default_user_key_path()?;
    let (user_key, _created) = UserKey::load_or_generate(&user_key_path)
        .map_err(|e| anyhow::anyhow!("user key error at {}: {e}", user_key_path.display()))?;

    // This device's endpoint id (derived locally from the device key, no daemon round-trip — the same
    // value `internal id` renders: the ed25519 public half of the device key).
    let device_key = load_device_key()?;
    let device_id = device_key.public_bytes();

    // The device→user-key binding the operator verifies at approve.
    let binding = sign_device_binding(user_key.signing_key(), &device_id);
    // The join-code fingerprint the operator reads BACK to confirm they received THIS code, not a
    // substituted one (nothing else binds person→user_pk — the enrollment MITM closer).
    let code_fp = pairing::sas::join_code_fingerprint(&user_key.public_bytes(), &device_id);
    let join = roster::enroll::JoinCode {
        display_name: display_name.clone(),
        requested_user_id: requested_user_id.clone(),
        user_pk: encode_b64u(&user_key.public_bytes()),
        device_endpoint_id: encode_b64u(&device_id),
        device_label: label,
        binding_sig: encode_b64u(&binding),
    }
    .encode();

    // Pin the org root (+ user id/key path) through the daemon (single-writer; no roster yet).
    with_daemon(async |mut client| {
        client
            .org_join(
                &invite.org_id,
                &invite.org_root_pk,
                &requested_user_id,
                &user_key_path.to_string_lossy(),
            )
            .await?;
        // If the invite carried a roster URL, pin it to config `[roster].url` so the joiner's poll
        // loop fetches its FIRST roster on the next daemon start (the joiner has no other way to
        // obtain one before it holds a roster). Same daemon connection, immediately after the
        // org-root pin.
        if let Some(url) = &invite.roster_url {
            client.set_roster_url(url).await?;
        }
        Ok(())
    })?;

    let fingerprint = pairing::sas::fingerprint_words(&root_pk);
    if json {
        println!(
            "{}",
            serde_json::json!({
                "org_id": invite.org_id,
                "user_id": requested_user_id,
                "join_code": join,
                "join_code_fingerprint": code_fp,
                "org_root_fingerprint": fingerprint,
            })
        );
        return Ok(());
    }
    println!("Joined org '{}' as '{requested_user_id}'.", invite.org_id);
    println!("Org root fingerprint: {fingerprint}");
    println!(
        "  → Confirm this matches what the operator reads back, out-of-band, before they approve you."
    );
    println!("Send the operator your join code: {join}");
    println!("Join code fingerprint: {code_fp}");
    println!(
        "  → Read this back to your operator out-of-band so they confirm they received YOUR join code (not a substituted one)."
    );
    Ok(())
}

/// `mcpmesh org create <name> [--roster-url <url>]`: mint the org root key (one-time per node), sign
/// an EMPTY roster (serial 1), install it through the daemon (which pins the org root), and print the
/// org invite code + the root fingerprint (both deliberate carve-outs from the no-opaque-output
/// rule — no raw keys). With `--roster-url`, the HTTPS poll URL is BOTH carried in the invite
/// (so a joiner bootstraps its first roster directly) AND pinned in this operator's config
/// `[roster].url` (the operator keeps the hosted document current).
pub fn run_org_create(
    name: String,
    expires: Option<String>,
    roster_url: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    use mcpmesh_trust::keys::OrgRootKey;
    use mcpmesh_trust::roster::sign::mint_signed;
    use mcpmesh_trust::roster::{encode_b64u, mutate};

    let key_path = paths::default_org_root_key_path()?;
    let (root, created) = OrgRootKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("org root key error at {}: {e}", key_path.display()))?;
    if !created {
        anyhow::bail!(
            "this node already holds an org root key ({}); `org create` is one-time per node",
            key_path.display()
        );
    }
    let expires_secs = match &expires {
        Some(s) => config::parse_duration(s).map_err(|e| anyhow::anyhow!("bad --expires: {e}"))?,
        None => DEFAULT_EXPIRES_SECS,
    };
    let now = util::epoch_now_i64();
    let roster = mint_signed(
        root.signing_key(),
        mutate::empty_roster(&name, 1, now, now.saturating_add(expires_secs)),
    );
    let org_root_pk = encode_b64u(&root.public_bytes());
    let result = install_signed_roster(&roster, Some(org_root_pk.clone()))?;
    // Pin the roster URL in the operator's config `[roster].url` (through the daemon — single-writer)
    // so the daemon's poll loop keeps the hosted document current on the next start.
    if let Some(url) = &roster_url {
        with_daemon(async |mut client| {
            client.set_roster_url(url).await?;
            Ok(())
        })?;
    }
    // The two permitted opaque artifacts: the org invite code (copyable) + the root fingerprint
    // (words). The invite CARRIES the roster URL so a joiner bootstraps its first roster.
    let invite = roster::enroll::OrgInviteCode {
        org_id: name.clone(),
        org_root_pk,
        roster_url: roster_url.clone(),
    }
    .encode();
    let fingerprint = pairing::sas::fingerprint_words(&root.public_bytes());
    if json {
        println!(
            "{}",
            serde_json::json!({
                "org_id": result.org_id,
                "serial": result.serial,
                "org_invite": invite,
                "org_root_fingerprint": fingerprint,
            })
        );
        return Ok(());
    }
    println!(
        "Created org '{}' (roster serial {}).",
        result.org_id, result.serial
    );
    println!("Invite someone: {invite}");
    println!("Org root fingerprint: {fingerprint} (read this aloud when you approve joiners)");
    Ok(())
}

/// Load this operator's org root key (the node must have run `org create`) + the installed roster
/// document (`roster.json`). The two artifacts `approve`/`revoke` mutate then re-sign + install.
fn load_operator_roster() -> anyhow::Result<(
    mcpmesh_trust::keys::OrgRootKey,
    mcpmesh_trust::roster::Roster,
)> {
    let key_path = paths::default_org_root_key_path()?;
    if !key_path.exists() {
        anyhow::bail!(
            "this node is not an org operator (no org root key); run `mcpmesh org create` first"
        );
    }
    let (root, _) = mcpmesh_trust::keys::OrgRootKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("org root key error at {}: {e}", key_path.display()))?;
    let roster_path = paths::default_roster_path()?;
    let bytes = std::fs::read(&roster_path).with_context(|| {
        format!(
            "no installed roster at {} — run `org create`",
            roster_path.display()
        )
    })?;
    let roster: mcpmesh_trust::roster::Roster =
        serde_json::from_slice(&bytes).context("parse installed roster")?;
    Ok((root, roster))
}

/// `mcpmesh org approve <join-code> --groups …`: verify the device binding, upsert the member, bump
/// serial, re-sign, install. The human ceremony (verifying the PERSON) is the operator's out-of-band
/// step; this command trusts it ran and adds the cryptographic DEVICE-binding check.
pub fn run_org_approve(
    join_code: String,
    groups: String,
    user_id: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    use mcpmesh_trust::roster::sign::{sign, verify_device_binding};
    use mcpmesh_trust::roster::{decode_endpoint_id, mutate};

    // No added context — the decode error is already the user-facing sentence (issue #10).
    let jc = roster::enroll::JoinCode::decode(&join_code)?;
    // Verify the device→user-key binding (the device provably belongs to this user key)
    // BEFORE any mutation — a forged/corrupt code is rejected before the roster is touched.
    let user_pk = decode_endpoint_id(&jc.user_pk).context("join code has an invalid user_pk")?;
    let device_id = decode_endpoint_id(&jc.device_endpoint_id)
        .context("join code has an invalid device endpoint")?;
    let sig = mcpmesh_trust::roster::decode_b64u(&jc.binding_sig)
        .context("join code has an invalid signature")?;
    verify_device_binding(&user_pk, &device_id, &sig).map_err(|_| {
        anyhow::anyhow!("join code device binding failed — the code is forged or corrupt")
    })?;

    let (root, mut roster) = load_operator_roster()?;
    let uid = user_id.unwrap_or(jc.requested_user_id);
    let groups = split_csv(Some(groups));
    // Pre-install confirmation ([Important] A): surface the join-code fingerprint so the operator
    // can confirm — out-of-band — they are approving the SAME code the joiner read back (catching a
    // substituted code). Same derivation as `join`'s output (over user_pk ∥ device endpoint).
    let code_fp = pairing::sas::join_code_fingerprint(&user_pk, &device_id);
    if !json {
        println!(
            "Approving join code {code_fp} for '{}' as user '{uid}', groups [{}].",
            jc.display_name,
            groups.join(", ")
        );
        println!(
            "  → Verify {code_fp} matches what the joiner read back to you out-of-band; if it doesn't, \
             run `org revoke` on this device."
        );
    }
    roster.serial += 1;
    mutate::upsert_member(
        &mut roster,
        &uid,
        &jc.display_name,
        &jc.user_pk, // b64u: straight into the roster device/user record
        &groups,
        &jc.device_endpoint_id, // b64u: straight into the roster device record
        &jc.device_label,
    )
    .map_err(|e| anyhow::anyhow!("roster mutation rejected: {e}"))?;
    sign(root.signing_key(), &mut roster).map_err(|e| anyhow::anyhow!("sign roster: {e}"))?;

    let result = install_signed_roster(&roster, None)?; // org root already pinned
    if json {
        println!(
            "{}",
            serde_json::json!({
                "user_id": uid,
                "groups": groups,
                "org_id": result.org_id,
                "serial": result.serial,
                "join_code_fingerprint": code_fp,
            })
        );
        return Ok(());
    }
    println!(
        "Approved '{}' into [{}] (org '{}', serial {}).",
        uid,
        groups.join(", "),
        result.org_id,
        result.serial
    );
    Ok(())
}

/// `mcpmesh org revoke <person|device> [--user-key]`: mutate the installed roster per the
/// target grammar, bump serial, re-sign, install (which severs the cut devices' live sessions).
pub fn run_org_revoke(target: String, user_key: bool, json: bool) -> anyhow::Result<()> {
    use mcpmesh_trust::roster::mutate;
    use mcpmesh_trust::roster::sign::sign;

    let (root, mut roster) = load_operator_roster()?;
    roster.serial += 1;
    let mode: &str;
    let action: String = if user_key {
        // Rotation: remove the person, keep their devices un-revoked (same device re-enrolls).
        mutate::remove_user(&mut roster, &target, false).map_err(|e| anyhow::anyhow!("{e}"))?;
        mode = "user-key-rotation";
        format!(
            "Rotated '{target}': removed from the roster. They re-enroll with a fresh user key \
             (same device), then re-approve with the same user_id"
        )
    } else if let Some((person, device)) = target.split_once('/') {
        // One device.
        mutate::revoke_device(&mut roster, person, device).map_err(|e| anyhow::anyhow!("{e}"))?;
        mode = "device";
        format!("Revoked device '{person}/{device}'")
    } else {
        // Person departing — remove + revoke every device (hard cut).
        mutate::remove_user(&mut roster, &target, true).map_err(|e| anyhow::anyhow!("{e}"))?;
        mode = "person";
        format!("Revoked person '{target}' (all devices)")
    };
    sign(root.signing_key(), &mut roster).map_err(|e| anyhow::anyhow!("sign roster: {e}"))?;
    let result = install_signed_roster(&roster, None)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "target": target,
                "mode": mode,
                "org_id": result.org_id,
                "serial": result.serial,
                "severed": result.severed,
            })
        );
        return Ok(());
    }
    println!(
        "{action} (org '{}', serial {}). Severed {} live session{}.",
        result.org_id,
        result.serial,
        result.severed,
        if result.severed == 1 { "" } else { "s" }
    );
    Ok(())
}

/// `mcpmesh devices code`: print THIS (new, not-yet-enrolled) machine's device code — its PUBLIC
/// endpoint id + a label. NO key material rides in it (the endpoint id is derived locally from the
/// device key, exactly like `internal id`); the already-enrolled device signs the binding with the
/// SHARED user key it holds. Surface-clean: only the opaque `mcpmesh-device:` code prints.
pub fn run_devices_code(label: String, json: bool) -> anyhow::Result<()> {
    use mcpmesh_trust::roster::encode_b64u;
    let device_id = load_device_key()?.public_bytes();
    let code = roster::enroll::DeviceCode {
        device_endpoint_id: encode_b64u(&device_id),
        device_label: label,
    }
    .encode();
    if json {
        println!("{}", serde_json::json!({"device_code": code}));
        return Ok(());
    }
    println!("Give this to an already-enrolled device (`mcpmesh devices add`): {code}");
    Ok(())
}

/// `mcpmesh devices add <device-code>`: on an ENROLLED device, bind the new machine — sign its endpoint
/// with YOUR user key and emit a join code the operator approves (which APPENDS the device to your
/// existing person via the same-user_pk upsert path, T4). Keys never leave this machine: only the new
/// device's PUBLIC endpoint id came in via the device code, and the user key stays 0600 on disk (only
/// its PUBLIC half + the binding signature ride out in the join code). Requires enrollment — this
/// device must know its `user_id` (config) AND hold the user key; else a clean error ("run join first").
/// Prints the join code + the join-code fingerprint for the operator to read back (ceremony
/// consistency with `join`/`org approve` — over the SAME user_pk ∥ NEW device endpoint).
pub fn run_devices_add(device_code: String, json: bool) -> anyhow::Result<()> {
    use mcpmesh_trust::keys::UserKey;
    use mcpmesh_trust::roster::encode_b64u;
    use mcpmesh_trust::roster::sign::sign_device_binding;

    // No added context — the decode error is already the user-facing sentence (issue #10).
    let dc = roster::enroll::DeviceCode::decode(&device_code)?;
    let new_device_id = mcpmesh_trust::roster::decode_endpoint_id(&dc.device_endpoint_id)
        .context("device code has an invalid endpoint id")?;

    // This device must be enrolled: know its stable user_id (config) AND hold the user key locally.
    let cfg = config::Config::load(&paths::default_config_path()?)
        .map_err(|e| anyhow::anyhow!("config: {e}"))?;
    let user_id = cfg
        .identity
        .user_id
        .clone()
        .context("this device is not enrolled (no user_id); run `mcpmesh join` first")?;
    let user_key_path = match cfg.identity.user_key.clone() {
        Some(p) => p,
        None => paths::default_user_key_path()?,
    };
    if !user_key_path.exists() {
        anyhow::bail!(
            "this device is not enrolled (no user key at {}); run `mcpmesh join` first",
            user_key_path.display()
        );
    }
    let (user_key, _) = UserKey::load_or_generate(&user_key_path)
        .map_err(|e| anyhow::anyhow!("user key error at {}: {e}", user_key_path.display()))?;
    let user_pk = user_key.public_bytes();

    // Sign the NEW device's binding with the shared user key; emit a join code carrying the SAME
    // user_pk + user_id (so `org approve` takes the same-user_pk upsert APPEND path, T4).
    let binding = sign_device_binding(user_key.signing_key(), &new_device_id);
    let join = roster::enroll::JoinCode {
        display_name: user_id.clone(),
        requested_user_id: user_id,
        user_pk: encode_b64u(&user_pk),
        device_endpoint_id: dc.device_endpoint_id,
        device_label: dc.device_label,
        binding_sig: encode_b64u(&binding),
    }
    .encode();
    // The join-code fingerprint (over user_pk ∥ NEW device endpoint) — the operator reads it back at
    // `org approve`, the same ceremony `join` uses (the substitution-MITM closer).
    let code_fp = pairing::sas::join_code_fingerprint(&user_pk, &new_device_id);
    if json {
        println!(
            "{}",
            serde_json::json!({"join_code": join, "join_code_fingerprint": code_fp})
        );
        return Ok(());
    }
    println!("Send the operator this join code to add the device: {join}");
    println!("Join code fingerprint: {code_fp}");
    println!(
        "  → Read this back to your operator out-of-band so they confirm they received THIS device's \
         join code (not a substituted one)."
    );
    Ok(())
}

/// Sign+persist a roster to a per-call-unique temp under `config_dir()` (same-uid; the daemon
/// reads it — path-not-bytes is within the local trust boundary), install it via the existing
/// `RosterInstall` control method (the single-writer discipline), and return the result. The
/// temp is removed on every exit — success, install error, or an early `?`-return — by the
/// [`util::TempPathGuard`] RAII guard. `org_root_pk` is `Some` only on the FIRST install
/// (`org create`) to pin the
/// anchor; `None` afterwards (the pinned config value is reused). Shared by org create / approve / revoke.
fn install_signed_roster(
    roster: &mcpmesh_trust::roster::Roster,
    org_root_pk: Option<String>,
) -> anyhow::Result<RosterInstallResult> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let temp = paths::config_dir()?.join(format!(
        "roster.staging.{}.{}.json",
        std::process::id(),
        seq
    ));
    // The guard removes `temp` on ANY return below (including the `?` early-exits that follow).
    let _guard = util::TempPathGuard::new(temp.clone());
    if let Some(parent) = temp.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&temp, serde_json::to_vec(roster)?)
        .with_context(|| format!("write staged roster {}", temp.display()))?;
    let path = temp.to_string_lossy().into_owned();
    with_daemon(async move |mut client| Ok(client.roster_install(&path, org_root_pk).await?))
}

/// Split a comma-separated `--allow` flag into trimmed, non-empty entries.
pub fn split_csv(value: Option<String>) -> Vec<String> {
    value
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Load (or mint) the device key from the configured path. Every identity-deriving verb reads it —
/// `status` (fingerprint), `internal id` (endpoint id), `join`/`devices code` (the device endpoint
/// in the enrollment codes) — each deriving its identity value deterministically from it.
pub fn load_device_key() -> anyhow::Result<DeviceKey> {
    let cfg_path = paths::default_config_path()?;
    let cfg = config::Config::load(&cfg_path)
        .map_err(|e| anyhow::anyhow!("config error in {}: {e}", cfg_path.display()))?;
    let key_path = match cfg.identity.device_key.clone() {
        Some(p) => p,
        None => paths::default_device_key_path()?,
    };
    let (key, _created) = DeviceKey::load_or_generate(&key_path)
        .map_err(|e| anyhow::anyhow!("device key error at {}: {e}", key_path.display()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use mcpmesh_trust::roster::encode_b64u;

    use super::*;

    #[test]
    fn slug_lowercases_collapses_and_trims() {
        assert_eq!(slug("Alice Nguyen"), "alice-nguyen");
        // Runs of non-alphanumerics collapse to ONE dash; leading/trailing junk trims clean.
        assert_eq!(slug("  --Bob!! Q.  "), "bob-q");
        // Nothing usable degrades to the generic id, never an empty user_id.
        assert_eq!(slug(""), "user");
        assert_eq!(slug("---"), "user");
    }

    #[test]
    fn a_forged_join_code_binding_is_rejected_before_any_roster_access() {
        // `org approve` verifies the device→user-key binding BEFORE touching any
        // operator state, so a substituted code dies on the signature check itself — this test runs
        // on a machine with NO org root key and still gets the binding error, not "not an operator".
        let mallory = mcpmesh_trust::ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let alice_pk = mcpmesh_trust::ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let device_id = [42u8; 32];
        // Mallory signs the binding with HER key but the code claims Alice's user_pk — the
        // substitution the binding check exists to catch.
        let sig = mcpmesh_trust::roster::sign::sign_device_binding(&mallory, &device_id);
        let code = roster::enroll::JoinCode {
            display_name: "Alice".into(),
            requested_user_id: "alice".into(),
            user_pk: encode_b64u(&alice_pk),
            device_endpoint_id: encode_b64u(&device_id),
            device_label: "laptop".into(),
            binding_sig: encode_b64u(&sig),
        }
        .encode();
        let err = run_org_approve(code, "team-eng".into(), None, false).unwrap_err();
        assert!(
            err.to_string().contains("device binding failed"),
            "the forged binding must be the failure, not roster/operator state: {err}"
        );
    }

    #[test]
    fn a_garbage_device_code_fails_on_decode_not_enrollment_state() {
        // `devices add` decodes the code BEFORE reading config/keys, so garbage fails with the
        // codec's own sentence — never a misleading "this device is not enrolled".
        let err = run_devices_add("garbage".into(), false).unwrap_err();
        assert!(
            err.to_string().contains("mcpmesh-device:"),
            "the decode error names the expected scheme: {err}"
        );
    }
}
