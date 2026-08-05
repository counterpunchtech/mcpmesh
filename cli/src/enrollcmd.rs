//! Enrollment porcelain — the `join` / `org create|approve|revoke` / `devices code|add`
//! verbs: user-key minting, device-binding signing/verification, roster mutation +
//! re-signing, and the staged-temp-install pipeline. Lives in the lib so the flow is reachable
//! by unit tests and an embedding shell; the binary's clap layer dispatches here, one line per
//! verb, and keeps only the pure render helpers.

use anyhow::Context;
use mcpmesh_trust::roster::encode_b64u;
use mcpmesh_trust::{DeviceKey, paths};

use crate::{client, config, pairing, roster};

/// Build a runtime, auto-start/connect the daemon, and run `f` against the connected control
/// client — the shared preamble every daemon-backed porcelain verb repeated (runtime build +
/// `ensure_daemon` + block_on). One runtime per call is fine: each verb is a short-lived CLI
/// process (and an org mutation runs one).
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
    // #93b: the daemon reports whether its roster TRANSPORT is running. A daemon that booted in
    // pairing mode has now pinned the org root but bound no gossip/blob ALPNs, so presence stays
    // empty and blobs hard-close until it restarts — carried out so the porcelain can say so.
    let restart_required = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let restart_flag = restart_required.clone();
    let (join_org_id, join_root_pk, join_user_id, join_key_path) = (
        invite.org_id.clone(),
        invite.org_root_pk.clone(),
        requested_user_id.clone(),
        user_key_path.to_string_lossy().into_owned(),
    );
    let join_url = invite.roster_url.clone();
    with_daemon(async move |mut client| {
        let joined = client
            .org_join(&join_org_id, &join_root_pk, &join_user_id, &join_key_path)
            .await?;
        restart_flag.store(
            joined.restart_required,
            std::sync::atomic::Ordering::Relaxed,
        );
        // If the invite carried a roster URL, pin it to config `[roster].url` so the joiner's poll
        // loop fetches its FIRST roster on the next daemon start (the joiner has no other way to
        // obtain one before it holds a roster). Same daemon connection, immediately after the
        // org-root pin.
        if let Some(url) = &join_url {
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
                "restart_required": restart_required.load(std::sync::atomic::Ordering::Relaxed),
            })
        );
        return Ok(());
    }
    println!("Joined org '{}' as '{requested_user_id}'.", invite.org_id);
    // #93b: stated BEFORE the approval instructions, because it changes what the user should do
    // next. Without it the join looked wholly successful and the missing presence/file sharing
    // surfaced later as an unexplained absence.
    if restart_required.load(std::sync::atomic::Ordering::Relaxed) {
        println!(
            "  → Restart the daemon before this fully takes effect: this one started in pairing \
             mode, so presence and file sharing stay off until it does. The join itself is saved."
        );
    }
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
    let expires_secs = match &expires {
        Some(s) => {
            Some(config::parse_duration(s).map_err(|e| anyhow::anyhow!("bad --expires: {e}"))?)
        }
        None => None,
    };
    // #66: the whole ceremony is now the `org_create` verb — one implementation behind the
    // control seam, shared with every embedder. This function is porcelain: flags in, words out.
    // It used to mint the key, sign the roster, and stage an install here, which meant the
    // operator path and the embedder path were two copies free to drift.
    let out = with_daemon(async move |mut client| {
        Ok(client.org_create(&name, expires_secs, roster_url).await?)
    })?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "org_id": out.org_id,
                "serial": out.serial,
                "org_invite": out.org_invite,
                "org_root_fingerprint": out.org_root_fingerprint,
            })
        );
        return Ok(());
    }
    println!(
        "Created org '{}' (roster serial {}).",
        out.org_id, out.serial
    );
    println!("Invite someone: {}", out.org_invite);
    println!(
        "Org root fingerprint: {} (read this aloud when you approve joiners)",
        out.org_root_fingerprint
    );
    Ok(())
}

pub fn run_org_approve(
    join_code: String,
    groups: String,
    user_id: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let groups = split_csv(Some(groups));
    // #66: the binding check, the mutation, the re-sign and the install all happen in the daemon
    // now. What stays here is the human step it cannot do.
    //
    // The confirmation is printed BEFORE the call, deliberately. It is the substitution-MITM
    // closer ([Important] A): the operator compares these words with what the joiner read back,
    // and a substituted code — carrying a different user_pk — diverges here. Printing it after the
    // install would demote the remedy from "don't approve this" to "now go revoke it", which is a
    // strictly worse position to put an operator in, and the roster would already carry the
    // attacker's device.
    //
    // Routed through the `org_join_code` VERB, not a local decode. Same reason the rest of this
    // function moved: the daemon owns the decode+verify+fingerprint path, and computing the
    // confirmation words a second way here would let the code an operator confirms drift from the
    // code the approval acts on.
    //
    // It also means the binding is VERIFIED before these words print, so a forged code fails here
    // instead of being announced as a person awaiting approval.
    if !json {
        let seen = with_daemon({
            let join_code = join_code.clone();
            async move |mut client| Ok(client.org_join_code(&join_code).await?)
        })?;
        println!(
            "Approving join code {} for '{}' as user '{}', groups [{}].",
            seen.join_code_fingerprint,
            seen.display_name,
            user_id
                .clone()
                .unwrap_or_else(|| seen.requested_user_id.clone()),
            groups.join(", ")
        );
        println!(
            "  → Verify {} matches what the joiner read back to you out-of-band; if it doesn't, \
             stop now and ask them for a fresh join code.",
            seen.join_code_fingerprint
        );
    }
    let out = with_daemon({
        let groups = groups.clone();
        async move |mut client| Ok(client.org_approve(&join_code, groups, user_id).await?)
    })?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "user_id": out.user_id,
                "groups": out.groups,
                "org_id": out.org_id,
                "serial": out.serial,
                "join_code_fingerprint": out.join_code_fingerprint,
            })
        );
        return Ok(());
    }
    println!(
        "Approved '{}' into [{}] (org '{}', serial {}).",
        out.user_id,
        out.groups.join(", "),
        out.org_id,
        out.serial
    );
    Ok(())
}

/// `mcpmesh org revoke <person|device> [--user-key]`: mutate the installed roster per the
/// target grammar, bump serial, re-sign, install (which severs the cut devices' live sessions).
pub fn run_org_revoke(target: String, user_key: bool, json: bool) -> anyhow::Result<()> {
    // #66: the target grammar is the daemon's to interpret now — and it reports which `mode` it
    // applied, because the three readings differ in what they destroy.
    let out = with_daemon({
        let target = target.clone();
        async move |mut client| Ok(client.org_revoke(&target, user_key).await?)
    })?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "target": out.target,
                "mode": out.mode,
                "org_id": out.org_id,
                "serial": out.serial,
                "severed": out.severed,
            })
        );
        return Ok(());
    }
    let action = match out.mode.as_str() {
        "user-key-rotation" => format!(
            "Rotated '{}': removed from the roster. They re-enroll with a fresh user key (same \
             device), then re-approve with the same user_id",
            out.target
        ),
        "device" => format!("Revoked device '{}'", out.target),
        "person" => format!("Revoked person '{}' (all devices)", out.target),
        // A mode this porcelain does not know — a newer daemon. Report it VERBATIM rather than
        // falling through to the person wording: that is the most destructive sentence of the
        // three, and printing it for an unknown mode would tell an operator something worse
        // happened than did (or something milder, if the new mode is worse). Neither is safe to
        // guess about a revocation.
        other => format!("Revoked '{}' (mode: {other})", out.target),
    };
    println!(
        "{action} (org '{}', serial {}). Severed {} live session{}.",
        out.org_id,
        out.serial,
        out.severed,
        if out.severed == 1 { "" } else { "s" }
    );
    Ok(())
}

/// `mcpmesh devices code`: print THIS (new, not-yet-enrolled) machine's device code — its PUBLIC
/// endpoint id + a label. NO key material rides in it (the endpoint id is derived locally from the
/// device key, exactly like `internal id`); the already-enrolled device signs the binding with the
/// SHARED user key it holds. Surface-clean: only the opaque `mcpmesh-device:` code prints.
pub fn run_devices_code(label: String, json: bool) -> anyhow::Result<()> {
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
