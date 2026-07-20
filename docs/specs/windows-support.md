# mcpmesh Windows support — design

**Date:** 2026-07-18
**Scope:** the `mcpmesh/` workspace (codec, net, trust, local-api, cli) — the public OSS surface.
**Out of scope:** the Windows milestone for downstream bundlers that embed mcpmesh (desktop packaging, sidecar staging, updater manifests) — see "Follow-on seam" below.

## Goal and definition of parity

Windows becomes a supported platform *exactly the way macOS and Linux are supported today*:
the workspace compiles, the full test suite runs green in CI on `windows-latest`,
`cargo install mcpmesh` works, and the docs say so. Today's Mac/Linux support is
source-based (no prebuilt binaries anywhere; Homebrew formula is HEAD-only), so Windows
parity deliberately does **not** include winget/scoop/MSI/prebuilt `.exe`s. That gets
revisited when the first tagged release adds prebuilt artifacts for every platform.

## Why Windows fails today

All Windows-hostility is first-party and concentrated in the local control plane:

- `trust/src/lib.rs` hard-gates non-Unix with `compile_error!` (deliberate).
- The `mcpmesh-local/1` control plane is NDJSON over a Unix domain socket, hardened by
  one shared rule in `local-api/src/service.rs`: 0700 symlink-refused runtime dir,
  0600 socket, and `peer_cred().uid() == geteuid()` on every accept.
- Satellites: XDG-only path resolution (`trust/src/paths.rs`), `flock` daemon singleton,
  Unix `process_group(0)` autostart, perm-bit lints in `doctor`, perm-asserting tests.

`codec` and `net` are already portable; every dependency (iroh, rustls-ring, redb, …)
builds on Windows. The codec and all RPC layers are transport-agnostic
(`AsyncRead + AsyncWrite`), and every socket face already funnels through the one
hardened seam — so the port swaps what's *under* the seam, not the callers.

## Alternatives rejected

- **TCP loopback + token auth everywhere** (one transport, zero `cfg`): downgrades
  kernel peer-credential security to a bearer-token file on the platforms that are
  already right; SECURITY.md names local-socket bypass a top-priority break. Rejected.
- **WSL2 docs only:** not Windows support; no Claude-Desktop-on-Windows story. Rejected.

## Design

**Principle: platform divergence lives in exactly two places — the local-transport seam
in `local-api` and `trust/src/paths.rs`. Everything above them is untouched and
platform-identical.**

### 1. Local endpoint abstraction (`local-api`)

New cfg-selected types `LocalListener` / `LocalStream` with one narrow API:
`bind_local(endpoint) -> LocalListener`, `LocalListener::accept() -> LocalStream`,
`connect_local(endpoint) -> LocalStream`. `LocalStream: AsyncRead + AsyncWrite`.

- **Unix impl:** the existing `bind_uds` / `ensure_private_dir` / `check_peer_uid`
  code moved verbatim. Zero behavior change; the existing suite proves it.
- **Windows impl:** a named-pipe server at `\\.\pipe\mcpmesh-<user-sid>` using
  `tokio::net::windows::named_pipe`. The pipe is created with a DACL granting access
  to the owner SID only — the kernel enforces same-user at connect, which is the
  Windows-native equivalent of 0700 dir + 0600 socket + `peer_cred` combined (same
  trust outcome: same-user fully trusted per spec P12/P14, cross-user denied by
  default). The wrapper hides the named-pipe idiom: create the next server instance
  *before* handing off the connected one (no connect race), map `ERROR_PIPE_BUSY` on
  the client side to a short bounded retry.
- The user SID is already in hand for the DACL; it doubles as the per-user pipe-name
  suffix (usernames can be renamed; SIDs can't).

Endpoint values stay `Path`-typed everywhere: `\\.\pipe\…` is a valid `Path` on
Windows, so `connect_control(&Path)` and the `[services.*]` backend config keep their
signatures — downstream consumers recompile without change.

Callers routed through the seam (mechanical): `cli/src/ipc.rs`, `cli/src/control.rs`,
`cli/src/backends/socket.rs`, `local-api/src/client.rs`. Plugin daemons inherit the
port for free because they bind through the same seam.

### 2. Paths (`trust/src/paths.rs`)

Extend the existing hand-rolled resolver (no new dirs-crate dependency):

| concept | Unix (unchanged) | Windows |
|---|---|---|
| config | `$XDG_CONFIG_HOME` else `~/.config/mcpmesh` | `%APPDATA%\mcpmesh` |
| data / state | XDG data/state | `%LOCALAPPDATA%\mcpmesh\{data,state}` |
| local endpoint | `<runtime_dir>/mcpmesh.sock` | `\\.\pipe\mcpmesh-<user-sid>` |
| runtime/temp | `$XDG_RUNTIME_DIR` else `$TMPDIR` | `std::env::temp_dir()` (already the fallback) |

Missing `%APPDATA%`/`%LOCALAPPDATA%` → the same typed error as missing `HOME`.
Then delete the `compile_error!` in `trust/src/lib.rs`.

### 3. Satellites (`cli`)

- **Singleton:** Unix keeps `flock` untouched. On Windows, `first_pipe_instance(true)`
  makes the pipe bind itself the one-daemon-per-user lock — bind failure maps to the
  same "daemon already running" error the flock `WOULDBLOCK` path produces. No lock
  file on Windows at all.
- **Autostart** (`cli/src/client.rs` `spawn_detached`): Windows uses
  `creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)` via
  `std::os::windows::process::CommandExt` (safe, stable) mirroring `process_group(0)`.
- **Key files** (`trust/src/keys.rs`): the `mode(0o600)` is already `cfg(unix)`.
  On Windows keys live under `%LOCALAPPDATA%`, protected by the user-profile ACL.
  Documented in SECURITY.md; `doctor` checks the key path is under the profile dir.
- **Doctor:** perm-bit lints report explicitly "n/a on Windows (user-profile ACLs)"
  rather than silently passing; add an endpoint-reachability check that works on both.
- **Proxy** (`cli/src/proxy.rs`): add the `%APPDATA%\Claude` Claude Desktop config
  path branch.

### 4. The `forbid(unsafe_code)` question

Building the owner-only security descriptor requires Win32 calls that are `unsafe` in
Rust. Resolution, in order:

1. Evaluate the `interprocess` crate (safe wrapper, tokio support, security-descriptor
   API). Adopt it iff it passes the cargo-deny audit (licenses, advisories, dep weight)
   for the Windows target.
2. Otherwise: one `#[cfg(windows)]` leaf module in `local-api` opts out of the
   workspace `forbid(unsafe_code)` lint (crate-level `[lints]` override, scoped deny +
   targeted allow) holding the ~30 audited lines of descriptor plumbing. The rest of
   the workspace stays forbid-clean — the same posture already taken toward tokio's
   internals.

Either way the seam API is identical; the choice is invisible above the seam.

### 5. Error handling

- Pipe bind conflict → typed "daemon already running" (parity with flock path).
- Client connect to absent pipe → same typed "daemon not running / autostart" flow as
  UDS `ECONNREFUSED`/`ENOENT` today.
- `ERROR_PIPE_BUSY` (instance momentarily unavailable) → bounded retry inside
  `connect_local`, invisible to callers.
- Missing `%APPDATA%`/`%LOCALAPPDATA%` → typed config error (parity with missing HOME).

### 6. Testing

- **Seam refactor safety:** land the Unix-side seam extraction first as a pure
  refactor; the full existing suite must stay green on macOS/Linux before any Windows
  code lands.
- **Windows correctness:** the full test suite runs on `windows-latest` in
  CI (`.github/workflows/ci.yml` gains one matrix entry). Integration tests
  that hand-build `XDG_RUNTIME_DIR`/socket paths become platform-aware through the
  same paths API; perm-bit assertions stay `cfg(unix)`.
- **Windows security tests:** assert the created pipe's DACL is owner-only; assert
  same-user connect succeeds; assert second-daemon bind fails (singleton).
- **Local verification** (development happens on macOS): `rustup target add
  x86_64-pc-windows-msvc` + `cargo check --target x86_64-pc-windows-msvc` as far as
  native build scripts allow; the CI leg is the authoritative gate.
- cargo-deny re-evaluates the Windows transitive dep set; `deny.toml` updated for any
  new Windows-only crates (`windows-sys` etc.).

### 7. Docs

- README: rewrite "Platform support" (currently "Windows is not supported … not
  planned for v1"); add `cargo install mcpmesh` as the Windows install path.
- `docs/local-protocol.md`: "same-user Unix socket" → "same-user local endpoint
  (Unix domain socket on macOS/Linux; owner-only named pipe on Windows)".
- SECURITY.md: a paragraph on the Windows gate (DACL = the peer-credential
  equivalent; profile ACLs for key files).

## Follow-on seam (downstream embedders, not this work)

A downstream bundler that embeds mcpmesh (e.g. a GUI shell) may keep its own copy of
socket-path resolution rather than depend on `mcpmesh-trust`; a Windows branch would
duplicate the pipe-name rule there too. Such embedders already link `mcpmesh-local-api`,
so their Windows milestone should consume endpoint resolution from that crate's exported
resolver (`service::mcpmesh_control_socket_from`, deliberately replicated from
`mcpmesh-trust`) and delete their own copy. Extending that resolver with the Windows
pipe-name rule is the follow-on's first step; the pure name-derivation helpers this
design adds to `trust/src/paths.rs` are the reference implementation to mirror.
