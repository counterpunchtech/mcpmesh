# Homebrew formula for the mcpmesh platform binary (spec §16 M4 packaging).
#
# Stable installs build the tagged release tarball (`url` + `sha256` below — updated by the
# release runbook at each tag); `--HEAD` builds the current `main`. Both go through
# `cargo install` on the `cli` crate.
#
# NOT a CI blocker: `brew install` cannot run end-to-end in CI. Validation here is `ruby -c` (syntax);
# a real `brew install` from the local formula is the release-runbook step (the repo
# doubles as its own tap: this formula lives at Formula/mcpmesh.rb).
class Mcpmesh < Formula
  desc "Peer-to-peer MCP transport — serve and mount MCP servers across machines"
  homepage "https://github.com/counterpunchtech/mcpmesh"
  url "https://github.com/counterpunchtech/mcpmesh/archive/refs/tags/v0.5.0.tar.gz"
  sha256 "a9ad4a54f27e7a7c48f668a4865f1dd25f8c0824c6087afa2e6a2fdbd3513e02"
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
