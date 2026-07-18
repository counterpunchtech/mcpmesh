//! Self-sovereign device→user binding for PAIRING mode (no org roster).
//!
//! Roster mode already gives a peer a first-class `user_id` (an org root signs a roster of
//! devices→user_id+groups). Pairing mode did not — every device was just a petname. This module
//! closes that gap WITHOUT an org: a peer proves its endpoint belongs to a self-minted [`UserKey`]
//! by presenting a device→user binding at pairing, so multiple devices sharing one `UserKey` resolve
//! to the SAME `user_id` and kb audiences can key on the user rather than the per-device petname.
//!
//! The idea is adopted from an earlier internal device-cert design; the crypto is mcpmesh's OWN — this is a thin
//! wrapper over [`roster::sign::sign_device_binding`]/[`verify_device_binding`] (domain
//! `mcpmesh/join/device-binding/1`) and [`roster::encode_b64u`], not a second cert implementation.
use crate::keys::UserKey;
use crate::roster::RosterError;
use crate::roster::sign::{sign_device_binding, verify_device_binding};
use crate::roster::{decode_b64u, encode_b64u};

/// This user's self-sovereign `user_id`: `encode_b64u(user_pk)`. Stable across device re-keying —
/// the endpoint key can rotate, the user key (and id) does not — and an opaque audience id for
/// consumers (kb `effective_audiences`).
pub fn user_id(user_key: &UserKey) -> String {
    encode_b64u(&user_key.public_bytes())
}

/// Sign THIS device's binding to `user_key` for presentation at pairing. `device_endpoint_id` is
/// this device's own endpoint id. Returns `(user_pk_b64u, binding_sig_b64u)` for the wire.
pub fn present(user_key: &UserKey, device_endpoint_id: &[u8; 32]) -> (String, String) {
    let sig = sign_device_binding(user_key.signing_key(), device_endpoint_id);
    (encode_b64u(&user_key.public_bytes()), encode_b64u(&sig))
}

/// Verify a peer's PRESENTED binding, BOUND to the authenticated transport id. The two invariants:
/// (1) the signature chains to the presented `user_pk`, and (2) it binds THAT device to the
/// TLS-authenticated `authenticated_endpoint` (never a self-asserted id — a transplanted binding for
/// a different endpoint fails). Returns the peer's `user_id` (`encode_b64u(user_pk)`) on success.
pub fn verify_presented(
    user_pk_b64u: &str,
    binding_sig_b64u: &str,
    authenticated_endpoint: &[u8; 32],
) -> Result<String, RosterError> {
    let user_pk: [u8; 32] = decode_b64u(user_pk_b64u)?
        .as_slice()
        .try_into()
        .map_err(|_| RosterError::BadSignature)?;
    let sig = decode_b64u(binding_sig_b64u)?;
    verify_device_binding(&user_pk, authenticated_endpoint, &sig)?;
    Ok(encode_b64u(&user_pk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_key() -> UserKey {
        let dir = tempfile::tempdir().unwrap();
        UserKey::load_or_generate(&dir.path().join("user.key"))
            .unwrap()
            .0
    }

    #[test]
    fn user_id_is_stable_b64u_of_the_pubkey() {
        let uk = user_key();
        assert_eq!(user_id(&uk), encode_b64u(&uk.public_bytes()));
        assert_eq!(user_id(&uk), user_id(&uk)); // deterministic
    }

    #[test]
    fn present_then_verify_round_trips_bound_to_the_device() {
        let uk = user_key();
        let device = [7u8; 32];
        let (upk, sig) = present(&uk, &device);
        // Verifying against the SAME (authenticated) endpoint yields the user's id.
        assert_eq!(verify_presented(&upk, &sig, &device).unwrap(), user_id(&uk));
    }

    #[test]
    fn a_binding_for_one_device_does_not_verify_for_another() {
        // Invariant 2: the binding must bind to the AUTHENTICATED transport id. A binding minted for
        // device A, replayed by device B, fails — no self-asserted endpoint.
        let uk = user_key();
        let (upk, sig) = present(&uk, &[7u8; 32]);
        assert!(verify_presented(&upk, &sig, &[9u8; 32]).is_err());
    }

    #[test]
    fn a_forged_user_pk_fails() {
        // Invariant 1: the signature must chain to the PRESENTED user_pk. Swapping in a different
        // user_pk (that didn't sign) fails.
        let uk = user_key();
        let (_upk, sig) = present(&uk, &[7u8; 32]);
        let other = encode_b64u(&[3u8; 32]);
        assert!(verify_presented(&other, &sig, &[7u8; 32]).is_err());
    }

    #[test]
    fn malformed_inputs_error_not_panic() {
        assert!(verify_presented("not b64u!!", "also bad", &[7u8; 32]).is_err());
    }
}
