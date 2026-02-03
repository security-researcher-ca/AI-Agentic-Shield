# AgentShield

**Local-first security gateway for AI agents** — Prevent prompt-injection-driven damage, data exfiltration, and destructive actions.

## Why AgentShield?

AI coding agents (Windsurf, Claude Code, Copilot, etc.) increasingly execute commands with real side effects. This creates security risks:

- **Prompt injection becomes operational** — Malicious content can steer agent actions
- **Over-permissioned tools** — Agents have access to shell, files, tokens
- **Human approve fatigue** — "Just click yes" becomes dangerous
- **No audit trail** — "What ran, why, and when?"

AgentShield gates every command through **deterministic policy rules** before execution.

## Quick Start

```bash
# Build and install
make build
sudo make install

# Copy default policy
mkdir -p ~/.agentshield
cp configs/default_policy.yaml ~/.agentshield/policy.yaml

# Run a command through AgentShield
agentshield run -- echo "hello world"

# Check version
agentshield version
```

## Demo

```bash
# This gets BLOCKED
$ agentshield run -- rm -rf /
❌ BLOCKED by AgentShield
Triggered rules: block-rm-root
Reasons: Destructive remove at filesystem root is never allowed.

# This requires APPROVAL
$ agentshield run -- npm install lodash
⚠️  APPROVAL REQUIRED
Command: npm install lodash
Reasons: Package installs can introduce supply-chain risk.
[a] Approve once  [d] Deny

# This runs in SANDBOX first
$ agentshield run -- sed -i 's/foo/bar/g' file.txt
🔒 SANDBOX MODE
Running command in sandbox to preview changes...
📋 Sandbox Results:
1 file(s) changed:
  ~ file.txt (+5 bytes)
[a] Approve once  [d] Deny
```

## Configuration

AgentShield creates `~/.agentshield/` with:
- `policy.yaml` — Policy rules (allow/deny/approve/sandbox)
- `audit.jsonl` — Append-only audit log (with automatic redaction)

### Policy Example

```yaml
version: "0.1"
defaults:
  decision: "REQUIRE_APPROVAL"
  protected_paths:
    - "~/.ssh/**"
    - "~/.aws/**"

rules:
  - id: "block-rm-root"
    match:
      command_regex: "^rm\\s+-rf\\s+/"
    decision: "BLOCK"
    reason: "Never delete root"

  - id: "allow-ls"
    match:
      command_prefix: ["ls", "pwd"]
    decision: "ALLOW"
```

## Decisions

| Decision | Behavior |
|----------|----------|
| `ALLOW` | Execute immediately |
| `REQUIRE_APPROVAL` | Prompt user for approval |
| `SANDBOX` | Run in sandbox, show diff, then approve |
| `BLOCK` | Deny with explanation |

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | `~/.agentshield/policy.yaml` | Path to policy file |
| `--log` | `~/.agentshield/audit.jsonl` | Path to audit log |
| `--mode` | `policy-only` | Execution mode |

## Security Features

- **Protected paths** — Block access to `~/.ssh`, `~/.aws`, etc.
- **Automatic redaction** — Secrets never logged (AWS keys, tokens, passwords)
- **Fail-safe** — Unknown commands require approval, not auto-allow
- **Sandbox preview** — See what changes before applying
- **Audit trail** — Every decision logged with timestamp and rule

## Development

```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
make clean    # Clean artifacts
```

## Architecture

See `Design/` folder for C4 architecture diagrams and design decisions.

## License

Apache 2.0
