class Agentshield < Formula
  desc "Local-first runtime security gateway for AI agents"
  homepage "https://github.com/gzhole/agentshield"
  url "https://github.com/gzhole/agentshield/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256_AFTER_RELEASE"
  license "MIT"

  depends_on "go" => :build

  def install
    ldflags = %W[
      -s -w
      -X github.com/gzhole/agentshield/internal/cli.Version=#{version}
      -X github.com/gzhole/agentshield/internal/cli.GitCommit=#{tap.user}
      -X github.com/gzhole/agentshield/internal/cli.BuildDate=#{time.iso8601}
    ]
    system "go", "build", *std_go_args(ldflags:), "./cmd/agentshield"
  end

  test do
    assert_match "AgentShield #{version}", shell_output("#{bin}/agentshield version")
  end
end
