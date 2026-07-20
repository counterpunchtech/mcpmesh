# Contributing to mcpmesh

Thanks for your interest — a few things to know up front.

## Where development happens

Right here. This repository is the source of truth for mcpmesh: issues, PRs, releases, and
the `mcpmesh*` crates on crates.io all come from this repo. (Early history was mirrored from
a private monorepo — the `Monorepo-Ref:` trailers on old commits are that era's bookkeeping.)

## Pull requests

PRs are welcome and merge directly.

- small, focused PRs with tests review fastest;
- CI (fmt, clippy `-D warnings`, tests, cargo-deny; Linux/macOS/Windows) must be green;
- breaking changes to a wire protocol (`mcpmesh/mcp/1`, `mcpmesh-local/1`) need an issue first —
  compatibility between peers on different versions is the project's spine.

## Issues

File issues here. For bugs, `mcpmesh doctor` output, OS, and how the peers are connected
(same LAN / NAT / relay) make reports actionable. Suspected vulnerabilities: see
[SECURITY.md](SECURITY.md) — not the public tracker.

## About `spec §x.y` comments

Code comments cite sections of the design spec, published at [docs/specs/](docs/specs/).

## Releases

Maintainers: see [RELEASING.md](RELEASING.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). By contributing you agree
your contribution may be distributed under both.
