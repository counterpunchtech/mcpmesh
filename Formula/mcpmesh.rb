# Homebrew formula for the mcpmesh platform binary (spec §16 M4 packaging).
#
# `head`-only by design: it builds `mcpmesh` from the current `main` via `cargo install`, so it needs no
# release-tarball `url`/`sha256` yet. At the first tagged release, add a stable `url` + `sha256` stanza
# (the release runbook step) so `brew install mcpmesh` (no `--HEAD`) works from the tarball.
#
# NOT a CI blocker: `brew install` cannot run end-to-end in CI. Validation here is `ruby -c` (syntax);
# a real tap + `brew install --HEAD counterpunchtech/mcpmesh/mcpmesh` is a runbook step (the repo
# doubles as its own tap: this formula lives at Formula/mcpmesh.rb).
class Mcpmesh < Formula
  desc "Peer-to-peer MCP transport — serve and mount MCP servers across machines"
  homepage "https://runbolo.com"
  license "MIT OR Apache-2.0"
  head "https://github.com/counterpunchtech/mcpmesh.git", branch: "main"

  depends_on "rust" => :build

  def install
    # The porcelain binary is the `mcpmesh` crate at cli (bin name `mcpmesh`).
    system "cargo", "install", *std_cargo_args(path: "cli")
  end

  test do
    # `--version` prints "mcpmesh <version>" (clap `#[command(version)]`) — a smoke that the binary runs.
    assert_match "mcpmesh", shell_output("#{bin}/mcpmesh --version")
  end
end
