# Releasing mcpmesh

Maintainer procedure. Pre-1.0 semver: BREAKING changes bump the MINOR (0.5.x → 0.6.0),
everything else bumps the PATCH.

## 1. Bump the version

Edit `[workspace.package] version` and the five `mcpmesh-*` pins in `[workspace.dependencies]`
of `Cargo.toml` to `X.Y.Z`. One version drives everything: the pins (`mcpmesh-codec`/`-net`/
`-trust`/`-local-api`/`-node`) move with it because crates.io refuses version-less path deps. Then:

    cargo update -w
    cargo test --workspace --locked

Gotcha: tests asserting the daemon's reported `stack_version` must compare against
`mcpmesh::daemon::STACK_VERSION`, never a literal.

## 2. Tag

Before tagging, run the two-machine smoke test — [`docs/dev-two-machine-smoke.md`](docs/dev-two-machine-smoke.md)
is pre-release-mandatory (CI cannot exercise the real-NAT path). For a milestone release,
also run the load soak in [`docs/load-soak.md`](docs/load-soak.md).

    git commit -am "release: X.Y.Z — <summary>"
    git push                        # wait for CI green
    git tag vX.Y.Z && git push origin vX.Y.Z

## 3. Publish the crates

    cargo xtask publish --dry-run    # review the plan
    cargo xtask publish

Publishes codec → local-api → trust → net → cli in dependency order from a clean `main`
checkout. Resumable: versions already in the crates.io index are skipped, so an interrupted
run just re-runs. Verify the crates.io pages + docs.rs builds afterwards.

## 4. GitHub release

Every tag gets a titled GitHub Release (v0.5.0 onward all have one):

    gh release create vX.Y.Z --title "mcpmesh X.Y.Z" --notes "<summary>"

## 5. Homebrew formula

Update the stable stanza in `Formula/mcpmesh.rb` — a post-tag commit on `main` (the tarball
cannot contain its own hash):

    curl -sL https://github.com/counterpunchtech/mcpmesh/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

Set `url` to the new tag, `sha256` to that digest; commit and push.

## Embedders

Downstream bundlers (e.g. the bolo host) pin a released version and follow on their own
cadence; nothing here waits for them.
