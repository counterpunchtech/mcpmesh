//! JCS canonicalization (RFC 8785) + Ed25519 org-root sign/verify (validation
//! rule 1). Signature-critical: canonicalize the doc with `sig` REMOVED, sign/verify over those
//! bytes. `sign`/`mint_signed` are production API — `org approve` signs the same way; tests
//! share the same mint path.
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

use super::{Roster, RosterError, decode_b64u, encode_b64u};

/// Canonical (RFC 8785 JCS) bytes of `value` with any top-level `"sig"` key removed. THE signing
/// input. Removing `sig` before canonicalization is what makes the signature cover everything-but-
/// itself. `serde_jcs::to_vec` is the pinned canonicalizer.
pub fn canonical_bytes_without_sig(value: &serde_json::Value) -> Result<Vec<u8>, RosterError> {
    let mut v = value.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("sig");
    }
    serde_jcs::to_vec(&v).map_err(|e| RosterError::Jcs(e.to_string()))
}

/// The signing input for a `Roster` (serialize → JCS-without-sig).
pub fn canonical_bytes(roster: &Roster) -> Result<Vec<u8>, RosterError> {
    canonical_bytes_without_sig(&serde_json::to_value(roster)?)
}

/// Rule 1: verify `roster.sig` (Ed25519, `b64u:`) against `root_pk` over the canonical form.
/// `verify_strict` rejects the malleable/degenerate edge cases dalek documents.
pub fn verify(roster: &Roster, root_pk: &VerifyingKey) -> Result<(), RosterError> {
    let canon = canonical_bytes(roster)?;
    let sig_bytes = decode_b64u(&roster.sig)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| RosterError::BadSignature)?;
    root_pk
        .verify_strict(&canon, &sig)
        .map_err(|_| RosterError::BadSignature)
}

/// Sign `roster` in place with the org root: canonicalize (with the existing `sig` ignored/removed),
/// sign, set `roster.sig = b64u:<signature>`. Production API (operator-side `org approve`).
pub fn sign(root: &SigningKey, roster: &mut Roster) -> Result<(), RosterError> {
    use ed25519_dalek::Signer;
    let canon = canonical_bytes(roster)?;
    let sig = root.sign(&canon);
    roster.sig = encode_b64u(&sig.to_bytes());
    Ok(())
}

/// Convenience: sign a fresh roster body and return it (the shared mint helper).
pub fn mint_signed(root: &SigningKey, mut body: Roster) -> Roster {
    sign(root, &mut body).expect("mint signs a well-formed body");
    body
}

/// Domain string for the join-code device→user-key binding. DISTINCT from the roster
/// `sig` and the SAS/fingerprint domains, so a signature can never be replayed across purposes.
const DEVICE_BINDING_DOMAIN: &[u8] = b"mcpmesh/join/device-binding/1";

/// The bytes a user key signs to bind a device endpoint to itself: domain ∥ user_pk ∥ endpoint_id.
fn device_binding_preimage(user_pk: &[u8; 32], device_endpoint_id: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DEVICE_BINDING_DOMAIN.len() + 64);
    m.extend_from_slice(DEVICE_BINDING_DOMAIN);
    m.extend_from_slice(user_pk);
    m.extend_from_slice(device_endpoint_id);
    m
}

/// Sign a device→user-key binding with the USER key (the join code's `binding_sig`).
/// Proves `device_endpoint_id` belongs to the holder of `user_key` WITHOUT trusting the transport —
/// the human ceremony verifies the PERSON, this verifies the DEVICE. Returns raw 64-byte signature.
pub fn sign_device_binding(user_key: &SigningKey, device_endpoint_id: &[u8; 32]) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let user_pk = user_key.verifying_key().to_bytes();
    let msg = device_binding_preimage(&user_pk, device_endpoint_id);
    user_key.sign(&msg).to_bytes()
}

/// Verify a device→user-key binding (`org approve`). `user_pk` + `device_endpoint_id`
/// come from the join code; `sig` is its `binding_sig`. `verify_strict` (conservative, matches the
/// roster `verify`). `Ok(())` iff the binding holds. Never panics on a malformed key/sig.
pub fn verify_device_binding(
    user_pk: &[u8; 32],
    device_endpoint_id: &[u8; 32],
    sig: &[u8],
) -> Result<(), RosterError> {
    let vk = VerifyingKey::from_bytes(user_pk).map_err(|_| RosterError::BadSignature)?;
    let sig = Signature::from_slice(sig).map_err(|_| RosterError::BadSignature)?;
    let msg = device_binding_preimage(user_pk, device_endpoint_id);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| RosterError::BadSignature)
}

// A small body builder shared by the tests (a valid, unsigned-ready roster body).
#[cfg(test)]
fn sample_body() -> crate::roster::Roster {
    use crate::roster::{Roster, RosterDevice, RosterUser, encode_b64u};
    Roster {
        format: "mcpmesh-roster/1".into(),
        org_id: "acme".into(),
        serial: 1,
        issued_at: "2026-07-03T12:00:00Z".into(),
        expires_at: "2026-10-01T00:00:00Z".into(),
        groups: vec!["team-eng".into(), "all".into()],
        users: vec![RosterUser {
            user_id: "alice".into(),
            display_name: "Alice".into(),
            user_pk: encode_b64u(&[1u8; 32]),
            groups: vec!["team-eng".into(), "all".into()],
            devices: vec![RosterDevice {
                endpoint_id: encode_b64u(&[2u8; 32]),
                label: "laptop".into(),
                role: "primary".into(),
            }],
        }],
        revoked_endpoints: vec![],
        sig: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn sign_then_verify_round_trips_and_a_tamper_fails() {
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let mut roster = mint_signed(&root, sample_body());
        // A freshly signed roster verifies against the exact pinned root.
        verify(&roster, &root.verifying_key()).expect("valid signature verifies");
        // A wrong root rejects.
        let other = SigningKey::from_bytes(&[8u8; 32]);
        assert!(matches!(
            verify(&roster, &other.verifying_key()),
            Err(RosterError::BadSignature)
        ));
        // Any content tamper (bump serial) invalidates the signature.
        roster.serial += 1;
        assert!(matches!(
            verify(&roster, &root.verifying_key()),
            Err(RosterError::BadSignature)
        ));
    }

    #[test]
    fn canonicalization_is_key_order_independent() {
        // JCS sorts keys, so two Values with the same content in different key orders produce
        // identical canonical bytes → identical signatures (the whole point of RFC 8785).
        let a = serde_json::json!({ "b": 1, "a": 2, "sig": "b64u:ZZZZ" });
        let b = serde_json::json!({ "a": 2, "sig": "b64u:YYYY", "b": 1 });
        assert_eq!(
            canonical_bytes_without_sig(&a).unwrap(),
            canonical_bytes_without_sig(&b).unwrap()
        );
    }

    #[test]
    fn malformed_or_empty_sig_is_rejected_and_never_panics() {
        // An empty or wrong-length signature is a rejection, never a panic or a bypass. The two
        // cases reject at DIFFERENT pipeline stages: an empty (no `b64u:` prefix) sig fails at
        // decode (`RosterError::Encoding`); a valid-b64u but wrong-length sig fails at
        // `Signature::from_slice`/`verify_strict` (`RosterError::BadSignature`). Both are `is_err`
        // — assert the rejection, not one specific variant (don't over-tighten).
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let mut roster = mint_signed(&root, sample_body());
        roster.sig = String::new(); // no `b64u:` prefix → decode fails first (Encoding)
        assert!(verify(&roster, &root.verifying_key()).is_err());
        roster.sig = "b64u:AAAA".into(); // valid b64u, decodes to 3 bytes ≠ 64 → BadSignature
        assert!(verify(&roster, &root.verifying_key()).is_err());
    }

    #[test]
    fn a_sig_from_another_roster_cannot_be_transplanted() {
        // A valid signature over roster A must not verify when copied onto a DIFFERENT roster B
        // (distinct from the in-place serial+1 tamper): B's canonical bytes differ from what A.sig
        // signed, so `verify_strict` rejects. Pins that a signature is bound to its exact content.
        let root = SigningKey::from_bytes(&[9u8; 32]);
        let a = mint_signed(&root, sample_body());
        let mut b = sample_body(); // different content than A ...
        b.serial = 999;
        b.org_id = "evil-corp".into();
        b.sig = a.sig.clone(); // ... but wearing A's valid signature
        assert!(matches!(
            verify(&b, &root.verifying_key()),
            Err(RosterError::BadSignature)
        ));
    }

    #[test]
    fn device_binding_sign_then_verify_and_forgeries_fail() {
        let user = SigningKey::from_bytes(&[5u8; 32]);
        let user_pk = user.verifying_key().to_bytes();
        let device = [7u8; 32];
        let sig = sign_device_binding(&user, &device);
        // The genuine binding verifies.
        assert!(verify_device_binding(&user_pk, &device, &sig).is_ok());
        // A DIFFERENT device endpoint fails (the whole point: the sig binds THIS endpoint).
        assert!(verify_device_binding(&user_pk, &[8u8; 32], &sig).is_err());
        // A DIFFERENT user_pk fails (a device claimed by the wrong user key).
        let other_pk = SigningKey::from_bytes(&[6u8; 32])
            .verifying_key()
            .to_bytes();
        assert!(verify_device_binding(&other_pk, &device, &sig).is_err());
        // A tampered / malformed sig fails, never panics.
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(verify_device_binding(&user_pk, &device, &bad).is_err());
        assert!(verify_device_binding(&user_pk, &device, b"short").is_err());
    }
}
