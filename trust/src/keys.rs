//! Ed25519 operator-local keys at rest as 32 raw secret bytes, 0600 (spec §4.1/§4.3/§13).
//!
//! One file-io discipline (`load_or_generate_signing_key` / `mint_signing_key_at`) backs three
//! semantically DISTINCT key types: [`DeviceKey`] (§4.1, per-device), [`OrgRootKey`] (§4.3, the
//! operator's roster-signing anchor), and [`UserKey`] (§4.3, a person's device-binding key). The
//! newtypes keep the io DRY while making the type system forbid signing a roster with a device key
//! (a real security surface — a type confusion here would be a genuine bug).
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed key file: {0}")]
    Malformed(String),
}

/// Shared Ed25519 key-file discipline (spec §4.1/§4.3/§13): 0600, atomic, EEXIST-race-safe. The
/// single implementation behind [`DeviceKey`] (§4.1), [`OrgRootKey`], and [`UserKey`] (§4.3) — one
/// io path, three semantic types. Returns (key, created); created=true iff this call minted it.
fn load_or_generate_signing_key(path: &Path) -> Result<(SigningKey, bool), KeyError> {
    // Bounded: an EEXIST publish race loops back to load the winner's key; anything
    // that keeps EEXISTing past the budget is surfaced rather than spun on.
    for _ in 0..4 {
        // Reload trusts the stored mode; a loosened-permissions lint belongs to `mcpmesh doctor` (spec §13).
        match std::fs::read(path) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyError::Malformed(format!("{} bytes, want 32", bytes.len())))?;
                return Ok((SigningKey::from_bytes(&arr), false));
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            Err(_) => {}
        }
        match mint_signing_key_at(path) {
            Ok(key) => return Ok((key, true)),
            // Another same-uid process published first: loop back and load theirs.
            Err(KeyError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(KeyError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "key mint retry budget exhausted (racing writers?)",
    )))
}

/// Mint via same-directory temp file (0600 at create), fsync, then publish with hard_link — the key
/// file either exists complete or not at all (spec §13), and an existing key is never overwritten.
/// On Windows the key file inherits the user-profile ACL of %APPDATA% (owner-only by default);
/// there is no mode bit to set.
fn mint_signing_key_at(path: &Path) -> Result<SigningKey, KeyError> {
    // Parent dir is umask-default (typically 0755); a 0700-dir lint also belongs to `mcpmesh doctor`.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Per-call-unique temp name: create_new on it can never EEXIST (no stale-litter
    // collisions, and remove_file below can only ever touch our own temp).
    static MINT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = MINT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), seq));
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| -> Result<(), KeyError> {
        let mut f = opts.open(&tmp)?;
        use std::io::Write;
        f.write_all(&key.to_bytes())?;
        f.sync_all()?;
        std::fs::hard_link(&tmp, path)?;
        Ok(())
    })();
    // The temp file is removed on every path — success, publish-race loss, or write failure.
    let _ = std::fs::remove_file(&tmp);
    result.map(|_| key)
}

pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Returns (key, created): created=true iff this call minted the key.
    pub fn load_or_generate(path: &Path) -> Result<(Self, bool), KeyError> {
        let (key, created) = load_or_generate_signing_key(path)?;
        Ok((Self(key), created))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    // Q3 hardening note: this copy is not zeroized; dalek scrubs SigningKey on drop (default feature), the copy is the residual (spec P14 boundary).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Short human fingerprint for status output (never the raw key — spec §1.5).
    pub fn fingerprint(&self) -> String {
        let b = self.public_bytes();
        format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
    }
}

/// The operator's roster-signing key (spec §4.3 org root key). Only on the operator's node. Same
/// 0600/atomic/race-safe discipline as [`DeviceKey`]; a DISTINCT type so it can never be confused
/// with a device or user key at a signing call site.
///
/// **Highest-value secret in the system (spec P5).** Compromise = the ability to forge ANY roster —
/// the sole trust anchor every joiner pins — so it is catastrophic by design (spec P4/P5). Posture:
/// stored 0600, minted ONLY on the operator's node (never on a joiner), read ONLY by the local
/// porcelain to sign in-process, and NEVER crossing the control API or any wire — the daemon is not
/// an online signing oracle (P4/P5's offline-root requirement); only the PUBLIC half + finished
/// signatures ever leave. Future hardening (offline/HSM storage, threshold signing) is spec Q4/P5;
/// v1's single offline key + an operator runbook is the accepted posture.
pub struct OrgRootKey(SigningKey);

impl OrgRootKey {
    pub fn load_or_generate(path: &Path) -> Result<(Self, bool), KeyError> {
        let (key, created) = load_or_generate_signing_key(path)?;
        Ok((Self(key), created))
    }
    /// The signing key for `roster::sign::sign` (operator signs rosters with this).
    pub fn signing_key(&self) -> &SigningKey {
        &self.0
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
    /// The org-root PUBLIC key bytes — pinned by joiners (`org_root_pk` b64u), never the secret.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

/// A person's user key (spec §4.3): binds their devices, proves device additions. One per person,
/// on their first device; never moves between machines. Same discipline; a DISTINCT type. Second-tier
/// secret (compromise = bind devices as that person until the operator rotates — spec §4.6).
pub struct UserKey(SigningKey);

impl UserKey {
    pub fn load_or_generate(path: &Path) -> Result<(Self, bool), KeyError> {
        let (key, created) = load_or_generate_signing_key(path)?;
        Ok((Self(key), created))
    }
    /// The signing key for `roster::sign::sign_device_binding` (a device→user-key binding).
    pub fn signing_key(&self) -> &SigningKey {
        &self.0
    }
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }
    /// The user PUBLIC key bytes — carried in the join code (`user_pk` b64u) + the roster.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_call_mints_and_second_call_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        let (k1, created1) = DeviceKey::load_or_generate(&path).unwrap();
        let (k2, created2) = DeviceKey::load_or_generate(&path).unwrap();
        assert!(created1);
        assert!(!created2);
        assert_eq!(k1.public_bytes(), k2.public_bytes());
    }

    // Unix-only: asserts the 0600 mode bits, which windows key files carry via
    // user-profile ACLs instead of a POSIX mode.
    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        DeviceKey::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_key_file_is_an_error_not_a_regenerate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device.key");
        std::fs::write(&path, b"short").unwrap();
        assert!(matches!(
            DeviceKey::load_or_generate(&path),
            Err(KeyError::Malformed(_))
        ));
    }

    #[test]
    fn org_root_and_user_keys_mint_0600_reload_and_expose_signing_keys() {
        use ed25519_dalek::Signer;
        let dir = tempfile::tempdir().unwrap();

        // OrgRootKey: mint → 0600 → reload same public half.
        let op = dir.path().join("org-root.key");
        let (root1, created1) = OrgRootKey::load_or_generate(&op).unwrap();
        assert!(created1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&op).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let (root2, created2) = OrgRootKey::load_or_generate(&op).unwrap();
        assert!(!created2);
        assert_eq!(root1.public_bytes(), root2.public_bytes());
        // signing_key() is usable (roster signing reuses ed25519_dalek::Signer).
        let sig = root1.signing_key().sign(b"hello");
        assert!(root1.verifying_key().verify_strict(b"hello", &sig).is_ok());

        // UserKey: same discipline, a DISTINCT type + key.
        let up = dir.path().join("user.key");
        let (user, _) = UserKey::load_or_generate(&up).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&up).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_ne!(user.public_bytes(), root1.public_bytes());
    }
}
