//! Framed UDS transport for mcpmesh-local/1 (spec §6.1, §13). Reuses the family
//! NDJSON codec (`mcpmesh_net::framing`) — "one codec everywhere". Same-uid clients
//! are fully trusted (P12/P14); the peer-uid check bounds OTHER users only.
//!
//! [RECONCILE settled] Peer-uid API: `tokio::net::UnixStream::peer_cred()` supplies the
//! connecting process's uid cross-platform (Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED`
//! / `getpeereid`) with tokio owning the platform `unsafe` internally — so our code needs
//! neither the `nix` crate nor inline `unsafe`. Our own uid comes from
//! `rustix::process::geteuid()` (a safe wrapper; rustix is already in the tree via iroh).
//! Net delta from the plan: no `nix` dependency, no `deny.toml` change (rustix's licenses
//! were already vetted for the iroh tree). The invariant is unchanged — refuse other users.
use anyhow::{Context, Result};
use std::path::Path;
use tokio::net::{UnixListener, UnixStream};

/// Per-connection frame cap for the control wire (spec §12 default, 16 MiB). Shared by the
/// control server and client so both size the `FrameReader` identically.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Create + security-check the runtime dir: `create_dir_all`, refuse a symlink, chmod 0700,
/// verify we own it (spec §13). Idempotent — safe to call from both the singleton-lock
/// acquisition (which must place a lock file here before the bind) and `bind_control_socket`.
///
/// D3 parity: the implementation is the plugin seam's [`ensure_private_dir`] — ONE hardened
/// rule for every UDS face in the family (the daemon control socket AND every plugin
/// daemon's socket), so the checks can never drift apart again.
///
/// [`ensure_private_dir`]: mcpmesh_local_api::service::ensure_private_dir
pub fn ensure_runtime_dir(dir: &Path) -> Result<()> {
    mcpmesh_local_api::service::ensure_private_dir(dir)
        .with_context(|| format!("secure runtime dir {}", dir.display()))
}

/// Bind the control socket: security-check the runtime dir (symlink-refused, 0700, owned by
/// us), remove a stale socket, bind, chmod 0600. Returns the listener. The implementation is
/// the seam's [`bind_uds`] (D3 — one hardened rule, both faces).
///
/// The stale-socket unlink has NO liveness guard of its own — Task 3's single-daemon flock
/// runs BEFORE this, so no LIVE daemon can hold the socket when we reach here; the unlink
/// can therefore only ever clear a dead daemon's leftover stub (spec §13).
///
/// [`bind_uds`]: mcpmesh_local_api::service::bind_uds
pub async fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    mcpmesh_local_api::service::bind_uds(path)
        .with_context(|| format!("bind control socket {}", path.display()))
}

/// Peer-uid check on an accepted connection (spec §11.2 P12). Returns `Ok(())` iff the
/// connecting process runs as our (effective) uid; refuses other users pre-any-request.
/// Delegates to the seam's [`check_peer_uid`] (D3 — one same-uid rule, both faces; the seam
/// logs the refusal detail).
///
/// [`check_peer_uid`]: mcpmesh_local_api::service::check_peer_uid
pub fn check_peer_uid(stream: &UnixStream) -> Result<()> {
    anyhow::ensure!(
        mcpmesh_local_api::service::check_peer_uid(stream),
        "refusing local connection: peer uid mismatch or unreadable credentials"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpmesh_local_api::{API_NAME, API_VERSION, Hello};
    use mcpmesh_net::framing::{FrameReader, Inbound, write_frame};
    use std::time::Duration;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn hello_frame_roundtrips_over_real_uds_and_peer_uid_passes() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let dir = tempfile::tempdir().unwrap();
            // Nest under a `mcpmesh` subdir so bind_control_socket exercises the real
            // create-dir-0700 + ownership path.
            let path = dir.path().join("mcpmesh").join("mcpmesh.sock");
            let listener = bind_control_socket(&path).await.unwrap();

            // The security guarantees every client depends on (spec §13): the runtime
            // dir is 0700 and the control socket 0600 — no other user can traverse in or
            // connect.
            {
                use std::os::unix::fs::PermissionsExt;
                let dir_mode = std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(dir_mode & 0o777, 0o700, "runtime dir must be 0700");
                let sock_mode = std::fs::metadata(&path).unwrap().permissions().mode();
                assert_eq!(sock_mode & 0o777, 0o600, "control socket must be 0600");
            }

            let expected = Hello {
                api: API_NAME.into(),
                api_version: API_VERSION.into(),
                stack_version: "0.1.0".into(),
            };
            let server_hello = expected.clone();
            let accept = tokio::spawn(async move {
                let (stream, _addr) = listener.accept().await.unwrap();
                // The connecting client is this same test process → same uid → must pass.
                check_peer_uid(&stream).unwrap();
                let (_r, mut w) = stream.into_split();
                let frame = serde_json::to_value(&server_hello).unwrap();
                write_frame(&mut w, &frame).await.unwrap();
            });

            let client = UnixStream::connect(&path).await.unwrap();
            let (r, _w) = client.into_split();
            let mut reader = FrameReader::new(BufReader::new(r), 16 * 1024 * 1024);
            let got: Hello = match reader.next().await.unwrap().unwrap() {
                Inbound::Frame(v) => serde_json::from_value(v).unwrap(),
                other => panic!("expected a hello frame, got {other:?}"),
            };
            assert_eq!(got.api, "mcpmesh-local/1");
            assert_eq!(got.stack_version, "0.1.0");
            assert_eq!(got, expected);
            accept.await.unwrap();
        })
        .await
        .expect("hello round-trip timed out");
    }
}
