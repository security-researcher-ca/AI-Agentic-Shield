# AgentShield

**Local-first runtime security gateway for AI agents** — Audit, block, and govern every command your AI agent executes.

## Why AgentShield?

AI coding agents (Windsurf, Claude Code, OpenClaw, Cursor, etc.) execute shell commands with real side effects. This creates security risks:

- **Prompt injection becomes operational** — Malicious content can steer agent actions
- **Over-permissioned tools** — Agents have access to shell, files, tokens
- **No audit trail** — "What did the agent do while I was away?"
- **Credential exfiltration** — Agents can read `~/.ssh`, `~/.aws`, environment variables

AgentShield sits between the agent and the OS, enforcing **deterministic policy rules** and logging every action.

## Install

```bash
# Homebrew (macOS / Linux)
brew tap gzhole/tap
brew install agentshield

# Or build from source
make build
sudo make install

# Or curl installer
curl -sSL https://raw.githubusercontent.com/gzhole/agentshield/main/scripts/install.sh | bash
```

## Quick Start

```bash
# Run a command through AgentShield
agentshield run -- echo "hello world"

# View the audit trail
agentshield log

# View summary stats
agentshield log --summary

# Show only flagged (AUDIT) entries
agentshield log --flagged

# Show only blocked commands
agentshield log --decision BLOCK
```

## Demo

```bash
# ✅ Safe commands execute normally
$ agentshield run -- ls -la
total 48
drwxr-xr-x  12 user  staff  384 Feb  8 10:00 .
...

# 🛑 Destructive commands are BLOCKED
$ agentshield run -- rm -rf /
🛑 BLOCKED by AgentShield
Decision: BLOCK
Triggered rules: block-rm-root
Reasons:
  - Destructive remove at filesystem root is not allowed.

# 🛑 Credential access is BLOCKED
$ agentshield run -- cat ~/.ssh/id_rsa
🛑 BLOCKED by AgentShield
Decision: BLOCK
Triggered rules: protected-path
Reasons:
  - Access to protected path denied: ~/.ssh/**

# 🔍 Risky commands are AUDITED (executed + flagged for review)
$ agentshield run -- npm install lodash
added 2 packages in 0.8s
# (flagged in audit log for review)

# 📊 Review what happened
$ agentshield log --summary
═══════════════════════════════════════════
  AgentShield Audit Summary
═══════════════════════════════════════════
  Total events:    6
  ALLOW:           2
  AUDIT (flagged): 2
  BLOCK:           2
═══════════════════════════════════════════
```

## Decisions

| Decision | Behavior |
|----------|----------|
| `ALLOW` | Execute, log normally |
| `AUDIT` | Execute, flag in log for review |
| `BLOCK` | Deny with explanation, log |

## Configuration

AgentShield creates `~/.agentshield/` with:
- `policy.yaml` — Policy rules (ALLOW / AUDIT / BLOCK)
- `audit.jsonl` — Append-only audit log (with automatic secret redaction)

### Policy Example

```yaml
version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths:
    - "~/.ssh/**"
    - "~/.aws/**"
    - "~/.gnupg/**"

rules:
  - id: "block-rm-root"
    match:
      command_regex: "^(rm|sudo rm)\\s+-rf\\s+/(\\s|$)"
    decision: "BLOCK"
    reason: "Destructive remove at filesystem root is not allowed."

  - id: "audit-package-installs"
    match:
      command_prefix: ["npm install", "pip install", "brew install"]
    decision: "AUDIT"
    reason: "Package installs flagged for supply-chain review."

  - id: "allow-safe-readonly"
    match:
      command_prefix: ["ls", "pwd", "whoami", "git status", "git diff"]
    decision: "ALLOW"
    reason: "Read-only / low-risk command."
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | `~/.agentshield/policy.yaml` | Path to policy file |
| `--log` | `~/.agentshield/audit.jsonl` | Path to audit log |
| `--mode` | `policy-only` | Execution mode |

## Security Features

- **Protected paths** — Block access to `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`
- **Automatic redaction** — Secrets never logged (AWS keys, GitHub tokens, passwords)
- **Fail-safe** — Unknown commands default to AUDIT, not ALLOW
- **Audit trail** — Every decision logged with timestamp, rule, and reason
- **Agent-agnostic** — Works with Windsurf, OpenClaw, Claude Code, or any shell-based agent

## Development

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
make clean    # Clean artifacts
```

## Architecture

See [`Design/`](Design/) for architecture diagrams, competitive analysis, and growth strategy.

## License

Apache 2.0
