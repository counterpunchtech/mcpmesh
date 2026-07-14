# Contributing to mcpmesh

Thanks for your interest — a few things to know up front.

## Where development happens

mcpmesh is developed inside a private monorepo, alongside the desktop stack that consumes it;
this repository is its public face. Snapshots are mirrored here (the `Monorepo-Ref:` trailer on
each commit is the internal reference), releases are tagged here, and the `mcpmesh*` crates are
published to crates.io from here.

## Pull requests

PRs are welcome. A maintainer imports accepted patches into the monorepo (authorship is preserved
— `git am`, with `Co-authored-by:` credit on the mirrored snapshot), and the change flows back
out in the next snapshot. Practical consequences:

- your change may land as part of a snapshot commit rather than a direct merge of your branch;
- small, focused PRs with tests import fastest;
- CI (fmt, clippy `-D warnings`, tests, cargo-deny) must be green.

## Issues

File issues here. For bugs, `mcpmesh doctor` output, OS, and how the peers are connected
(same LAN / NAT / relay) make reports actionable. Suspected vulnerabilities: see
[SECURITY.md](SECURITY.md) — not the public tracker.

## About `spec §x.y` comments

Code comments cite sections of the internal design spec. Publishing it is on the roadmap; until
then treat the citations as internal cross-references — every behavior they pin is also pinned by
a test.

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). By contributing you agree
your contribution may be distributed under both.
