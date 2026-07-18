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
that break that model (forgery, downgrade, cross-peer data leakage, local socket permission
bypass, transport-vocabulary leaks into user-facing surfaces) are top priority.

## Supported versions

Pre-1.0: the latest published minor version receives fixes.
