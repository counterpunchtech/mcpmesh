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

/// Domain for a peer INTRODUCTION (#65): C vouching for B's endpoint to A.
///
/// Separate from [`DEVICE_BINDING_DOMAIN`] so an endorsement can never be replayed as a binding or
/// the reverse — a device binding says "this endpoint is MINE", an introduction says "this endpoint
/// is SOMEONE ELSE'S and I vouch for it". Signed by the same `UserKey`, so without separation a
/// binding C made for its own device would verify as C endorsing that device to anyone.
const INTRODUCE_DOMAIN: &[u8] = b"mcpmesh/introduce/1";

/// The bytes an endorser's user key signs to introduce a subject:
/// domain ∥ endorser_pk ∥ subject_endpoint_id ∥ subject_user_pk (32 zero bytes when absent).
///
/// The endorser's own key is in the preimage as **defence in depth**, not as the primary binding —
/// `verify_strict` already binds the statement to that key, because the key IS the verifier. (An
/// earlier draft of the spec claimed the preimage was what stopped a signature being lifted onto
/// another identity; that was overstated, and removing the field symmetrically from sign+verify
/// escaped the whole suite. The golden vector below is what actually pins this layout.)
fn introduce_preimage(
    endorser_pk: &[u8; 32],
    subject_endpoint_id: &[u8; 32],
    subject_user_pk: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(INTRODUCE_DOMAIN.len() + 96);
    m.extend_from_slice(INTRODUCE_DOMAIN);
    m.extend_from_slice(endorser_pk);
    m.extend_from_slice(subject_endpoint_id);
    // A FIXED-WIDTH slot rather than an omitted field: a variable-length preimage would let
    // "subject_user_pk absent" and some other framing collide.
    m.extend_from_slice(subject_user_pk.unwrap_or(&[0u8; 32]));
    m
}

/// Sign an introduction (#65) with the endorser's user key.
pub fn sign_introduction(
    endorser_key: &SigningKey,
    subject_endpoint_id: &[u8; 32],
    subject_user_pk: Option<&[u8; 32]>,
) -> [u8; 64] {
    use ed25519_dalek::Signer;
    let endorser_pk = endorser_key.verifying_key().to_bytes();
    let msg = introduce_preimage(&endorser_pk, subject_endpoint_id, subject_user_pk);
    endorser_key.sign(&msg).to_bytes()
}

/// Verify an introduction (#65). `verify_strict`, matching the roster path. Never panics on a
/// malformed key or signature.
pub fn verify_introduction(
    endorser_pk: &[u8; 32],
    subject_endpoint_id: &[u8; 32],
    subject_user_pk: Option<&[u8; 32]>,
    sig: &[u8],
) -> Result<(), RosterError> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(endorser_pk)
        .map_err(|_| RosterError::BadSignature)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| RosterError::BadSignature)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    let msg = introduce_preimage(endorser_pk, subject_endpoint_id, subject_user_pk);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| RosterError::BadSignature)
}

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
    /// #65: a GOLDEN VECTOR for the introduction preimage.
    ///
    /// The domain string and the field layout are wire format: a peer signing with one layout and a
    /// peer verifying with another simply cannot interoperate, and a domain change silently makes
    /// every existing endorsement unverifiable. Round-trip tests cannot catch either, because
    /// sign and verify share the same function — changing it symmetrically keeps them agreeing
    /// with each other and disagreeing with every other build. Two such mutations escaped the
    /// whole suite before this test existed.
    #[test]
    fn the_introduction_preimage_layout_is_pinned() {
        let endorser = [1u8; 32];
        let subject = [2u8; 32];
        let subject_user = [3u8; 32];

        let without = super::introduce_preimage(&endorser, &subject, None);
        assert_eq!(
            &without[..super::INTRODUCE_DOMAIN.len()],
            b"mcpmesh/introduce/1",
            "the DOMAIN is wire format — changing it invalidates every endorsement in existence"
        );
        assert_eq!(
            without.len(),
            super::INTRODUCE_DOMAIN.len() + 96,
            "domain ∥ endorser_pk ∥ subject ∥ subject_user_pk(32 zero bytes) — a FIXED width, so \
             'absent' cannot collide with some other framing"
        );
        assert_eq!(&without[super::INTRODUCE_DOMAIN.len()..][..32], &endorser);
        assert_eq!(
            &without[super::INTRODUCE_DOMAIN.len() + 32..][..32],
            &subject
        );
        assert_eq!(
            &without[super::INTRODUCE_DOMAIN.len() + 64..][..32],
            &[0u8; 32],
            "the absent subject user key is 32 ZERO bytes, not an omission"
        );

        let with = super::introduce_preimage(&endorser, &subject, Some(&subject_user));
        assert_eq!(
            &with[super::INTRODUCE_DOMAIN.len() + 64..][..32],
            &subject_user
        );
        assert_ne!(
            without, with,
            "present and absent must not produce one preimage"
        );

        // And the two domains are distinct — the separation the device-binding test relies on.
        assert_ne!(super::INTRODUCE_DOMAIN, super::DEVICE_BINDING_DOMAIN);
    }

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
