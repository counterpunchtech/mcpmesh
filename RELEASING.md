# Releasing mcpmesh

Maintainer procedure. Pre-1.0 semver: BREAKING changes bump the MINOR (0.5.x → 0.6.0),
everything else bumps the PATCH.

## 1. Bump the version

One version drives everything: `[workspace.package] version` in `Cargo.toml`, plus the four
internal dep pins in `[workspace.dependencies]` (`mcpmesh-codec`/`-net`/`-trust`/`-local-api`
— crates.io refuses version-less path deps, so the pins move with the version). Then:

    cargo update -w
    cargo test --workspace --locked

Gotcha: tests asserting the daemon's reported `stack_version` must compare against
`mcpmesh::daemon::STACK_VERSION`, never a literal.

## 2. Tag

    git commit -am "release: X.Y.Z — <summary>"
    git push                        # wait for CI green
    git tag vX.Y.Z && git push origin vX.Y.Z

## 3. Publish the crates

    cargo xtask publish --dry-run    # review the plan
    cargo xtask publish

Publishes codec → local-api → trust → net → cli in dependency order from a clean `main`
checkout. Resumable: versions already in the crates.io index are skipped, so an interrupted
run just re-runs. Verify the crates.io pages + docs.rs builds afterwards.

## 4. Homebrew formula

Update the stable stanza in `Formula/mcpmesh.rb` — a post-tag commit on `main` (the tarball
cannot contain its own hash):

    curl -sL https://github.com/counterpunchtech/mcpmesh/archive/refs/tags/vX.Y.Z.tar.gz | shasum -a 256

Set `url` to the new tag, `sha256` to that digest; commit and push.

## Embedders

Downstream bundlers (e.g. the bolo host) pin a released version and follow on their own
cadence; nothing here waits for them.
