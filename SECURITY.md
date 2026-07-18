# Security policy

mcpmesh moves MCP traffic between machines — reports are taken seriously.

## Reporting a vulnerability

- Preferred: GitHub private vulnerability reporting — the **Report a vulnerability** button under
  this repository's Security tab.
- Email: knotanotsea@protonmail.com

Please do NOT open a public issue for a suspected vulnerability. You'll get an acknowledgement
within a few days; coordinated disclosure preferred.

## Trust model (what counts as a break)

The org-root / pairing signature is the trust boundary. The HTTPS host serving a roster, the chat
channel carrying an invite, and the gossip/relay network are all UNTRUSTED transport — tampering
is caught by signatures, rollback by the strictly-increasing serial + freshness rule. Reports
that break that model (forgery, downgrade, cross-peer data leakage, local endpoint permission
bypass, transport-vocabulary leaks into user-facing surfaces) are top priority.

Local endpoint permission bypass covers both platforms: on macOS/Linux the daemon's control socket
lives in a `0700` directory it owns and checks the connecting process's uid; on Windows the
equivalent is the control pipe's owner-only DACL, which grants access only to the owning user's SID.
A report that defeats either — letting another local user reach the daemon — is top priority on
either platform.

Key material and config also live under user-profile protection rather than Unix mode bits on
Windows: `%APPDATA%`/`%LOCALAPPDATA%` (device keys, roster, config) rely on the user profile's ACLs
instead of `0600`/`0700`. A report showing those ACLs don't actually restrict access to the owning
user is the Windows analogue of a Unix permission-bit bypass.

### Known limitation: named-pipe squatting on Windows

Windows pipe names are a global, cross-user namespace. Before the daemon starts, another local
process (running as a different user) could pre-create a pipe with the mcpmesh daemon's name. The
owner-only DACL still protects the *daemon's own* pipe from cross-user clients once it binds — but a
client that connects before the real daemon is up, or that is otherwise tricked into dialing a
squatted name, is not authenticating the server end of that connection.

This is a documented limitation, not a silent gap:

- The daemon binds at login / first use, so the window in which a name could be squatted ahead of it
  is small.
- Clients connect with `SECURITY_IDENTIFICATION` impersonation level (tokio's default for named-pipe
  clients), which limits what a malicious server could do with the client's identity even if a
  connection reached one.
- Same-user squatting is a non-issue: a squatter running as the same user is already inside the trust
  domain the daemon protects.

Authenticating the server end of the pipe (so a client can positively confirm it reached the real
daemon, not a squatter) is tracked as a hardening follow-up rather than fixed today. Reports that
demonstrate concrete impact beyond this documented shape are still welcome.

## Supported versions

Pre-1.0: the latest published minor version receives fixes.
